//! Gateway reconciler.
//!
//! Watches Gateway resources and translates them into Zentinel listener
//! configurations. Updates Gateway status with addresses, listener conditions,
//! and attached route counts.

use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::{Gateway, GatewayListeners};
use gateway_api::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;
use crate::reconcilers::ReferenceGrantIndex;

/// Reconciler for Gateway resources.
pub struct GatewayReconciler {
    client: Client,
    reference_grants: Arc<ReferenceGrantIndex>,
}

impl GatewayReconciler {
    pub fn new(client: Client, reference_grants: Arc<ReferenceGrantIndex>) -> Self {
        Self {
            client,
            reference_grants,
        }
    }

    pub async fn reconcile(
        &self,
        gateway: Arc<Gateway>,
    ) -> Result<Action, GatewayError> {
        let name = gateway.name_any();
        let namespace = gateway.namespace().unwrap_or_else(|| "default".into());
        let class_name = &gateway.spec.gateway_class_name;

        if !self.is_our_gateway_class(class_name).await? {
            debug!(name = %name, class = %class_name, "Ignoring Gateway for unowned GatewayClass");
            return Ok(Action::await_change());
        }

        let generation = gateway.metadata.generation.unwrap_or(0);

        info!(
            name = %name,
            namespace = %namespace,
            listeners = gateway.spec.listeners.len(),
            generation,
            "Reconciling Gateway"
        );

        self.update_status(&gateway, &namespace).await?;

        // Requeue to pick up route count and address changes
        Ok(Action::requeue(std::time::Duration::from_secs(10)))
    }

    async fn is_our_gateway_class(&self, class_name: &str) -> Result<bool, GatewayError> {
        let api: Api<GatewayClass> = Api::all(self.client.clone());
        match api.get(class_name).await {
            Ok(gc) => Ok(gc.spec.controller_name == CONTROLLER_NAME),
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Count attached HTTPRoutes per listener section name.
    async fn count_attached_routes(
        &self,
        gw_name: &str,
        gw_namespace: &str,
    ) -> Result<HashMap<String, i32>, GatewayError> {
        let route_api: Api<HTTPRoute> = Api::all(self.client.clone());
        let routes = route_api.list(&ListParams::default()).await?;

        let mut counts: HashMap<String, i32> = HashMap::new();

        for route in &routes.items {
            if let Some(refs) = route.spec.parent_refs.as_ref() {
                for pr in refs {
                    let route_ns = route.namespace().unwrap_or_default();
                    let pr_ns = pr.namespace.as_deref().unwrap_or(&route_ns);
                    if pr.name == gw_name && pr_ns == gw_namespace {
                        if let Some(ref section) = pr.section_name {
                            *counts.entry(section.clone()).or_insert(0) += 1;
                        } else {
                            *counts.entry(String::new()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }

        Ok(counts)
    }

    /// Look up the proxy Service to find its external address.
    ///
    /// Searches all namespaces for Services with the zentinel-gateway label,
    /// since the proxy runs in the controller's namespace, not the Gateway's.
    async fn get_gateway_addresses(
        &self,
        _namespace: &str,
    ) -> Vec<serde_json::Value> {
        // Check for override via environment variable (for kind/test environments)
        if let Ok(addr) = std::env::var("GATEWAY_ADDRESS") {
            return vec![json!({"type": "IPAddress", "value": addr})];
        }

        // Search all namespaces for our proxy Service (labeled by Helm)
        let svc_api: Api<Service> = Api::all(self.client.clone());
        let params = ListParams::default()
            .labels("app.kubernetes.io/name=zentinel-gateway");
        let services = match svc_api.list(&params).await {
            Ok(s) => s,
            Err(_) => return vec![],
        };

        let mut addresses = Vec::new();

        for svc in &services.items {
            // Only check LoadBalancer or NodePort services (skip metrics ClusterIP)
            let svc_type = svc
                .spec
                .as_ref()
                .and_then(|s| s.type_.as_deref())
                .unwrap_or("ClusterIP");
            if svc_type == "ClusterIP" {
                continue;
            }

            // Check LoadBalancer ingress
            if let Some(ref status) = svc.status {
                if let Some(ref lb) = status.load_balancer {
                    if let Some(ref ingress) = lb.ingress {
                        for ig in ingress {
                            if let Some(ref ip) = ig.ip {
                                addresses.push(json!({
                                    "type": "IPAddress",
                                    "value": ip,
                                }));
                            }
                            if let Some(ref hostname) = ig.hostname {
                                addresses.push(json!({
                                    "type": "Hostname",
                                    "value": hostname,
                                }));
                            }
                        }
                    }
                }
            }

            if !addresses.is_empty() {
                break;
            }
        }

        addresses
    }

    /// Validate a listener's TLS certificateRefs.
    /// Returns (resolved: bool, reason: &str, message: String).
    async fn validate_listener_tls(
        &self,
        listener: &GatewayListeners,
        gw_namespace: &str,
    ) -> (bool, &'static str, String) {
        let tls = match &listener.tls {
            Some(t) => t,
            None => return (true, "ResolvedRefs", "No TLS refs to resolve".into()),
        };

        let cert_refs = match &tls.certificate_refs {
            Some(refs) if !refs.is_empty() => refs,
            _ => return (true, "ResolvedRefs", "No certificate refs".into()),
        };

        for cert_ref in cert_refs {
            // Check group/kind validity
            let group = cert_ref.group.as_deref().unwrap_or("");
            let kind = cert_ref.kind.as_deref().unwrap_or("Secret");

            if !group.is_empty() && group != "core" {
                return (
                    false,
                    "InvalidCertificateRef",
                    format!("Unsupported certificateRef group: {group}"),
                );
            }
            if kind != "Secret" {
                return (
                    false,
                    "InvalidCertificateRef",
                    format!("Unsupported certificateRef kind: {kind}"),
                );
            }

            let secret_ns = cert_ref
                .namespace
                .as_deref()
                .unwrap_or(gw_namespace);

            // Cross-namespace check
            if secret_ns != gw_namespace
                && !self.reference_grants.is_permitted(
                    gw_namespace,
                    "Gateway",
                    secret_ns,
                    "Secret",
                    &cert_ref.name,
                )
            {
                return (
                    false,
                    "RefNotPermitted",
                    format!(
                        "Cross-namespace reference to Secret {}/{} not permitted",
                        secret_ns, cert_ref.name
                    ),
                );
            }

            // Check Secret exists
            let secret_api: Api<Secret> = Api::namespaced(self.client.clone(), secret_ns);
            match secret_api.get(&cert_ref.name).await {
                Ok(secret) => {
                    // Verify it has tls.crt and tls.key
                    let data = secret.data.as_ref();
                    let has_keys = data
                        .is_some_and(|d| d.contains_key("tls.crt") && d.contains_key("tls.key"));
                    if !has_keys {
                        return (
                            false,
                            "InvalidCertificateRef",
                            format!(
                                "Secret {}/{} missing tls.crt or tls.key",
                                secret_ns, cert_ref.name
                            ),
                        );
                    }

                    // Validate PEM content (must start with -----BEGIN)
                    if let Some(d) = data {
                        if let Some(cert_bytes) = d.get("tls.crt") {
                            let cert_str = String::from_utf8_lossy(&cert_bytes.0);
                            if !cert_str.trim_start().starts_with("-----BEGIN") {
                                return (
                                    false,
                                    "InvalidCertificateRef",
                                    format!(
                                        "Secret {}/{} tls.crt is not valid PEM",
                                        secret_ns, cert_ref.name
                                    ),
                                );
                            }
                        }
                    }
                }
                Err(kube::Error::Api(err)) if err.code == 404 => {
                    return (
                        false,
                        "InvalidCertificateRef",
                        format!("Secret {}/{} not found", secret_ns, cert_ref.name),
                    );
                }
                Err(e) => {
                    warn!(error = %e, "Error checking TLS Secret");
                    return (
                        false,
                        "InvalidCertificateRef",
                        format!("Error resolving Secret: {e}"),
                    );
                }
            }
        }

        (true, "ResolvedRefs", "All certificate references resolved".into())
    }

    async fn update_status(
        &self,
        gateway: &Gateway,
        namespace: &str,
    ) -> Result<(), GatewayError> {
        let name = gateway.name_any();
        let generation = gateway.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        let attached_counts = self.count_attached_routes(&name, namespace).await?;
        let wildcard_count = attached_counts.get("").copied().unwrap_or(0);
        let addresses = self.get_gateway_addresses(namespace).await;

        // Build listener statuses with per-listener validation
        let mut listener_statuses = Vec::new();
        for l in &gateway.spec.listeners {
            let listener_count = attached_counts
                .get(&l.name)
                .copied()
                .unwrap_or(0)
                + wildcard_count;

            // Validate TLS certificate refs
            let (tls_resolved, tls_reason, tls_message) =
                self.validate_listener_tls(l, namespace).await;

            // Validate allowed route kinds
            let (kinds_valid, kinds_reason, kinds_message, filtered_kinds) =
                validate_listener_route_kinds(l);

            // Combine: refs are resolved only if both TLS and kinds are valid
            let (refs_resolved, refs_reason, refs_message) = if !kinds_valid {
                (false, kinds_reason, kinds_message)
            } else if !tls_resolved {
                (false, tls_reason, tls_message)
            } else {
                (true, "ResolvedRefs", "All references resolved".to_string())
            };

            let programmed = refs_resolved;

            listener_statuses.push(json!({
                "name": l.name,
                "attachedRoutes": listener_count,
                "supportedKinds": filtered_kinds,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Listener accepted",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }, {
                    "type": "Programmed",
                    "status": if programmed { "True" } else { "False" },
                    "reason": if programmed { "Programmed" } else { &refs_reason },
                    "message": if programmed { "Listener programmed" } else { &refs_message },
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }, {
                    "type": "ResolvedRefs",
                    "status": if refs_resolved { "True" } else { "False" },
                    "reason": refs_reason,
                    "message": refs_message,
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }]
            }));
        }

        let mut status = json!({
            "status": {
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Gateway accepted by Zentinel controller",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }, {
                    "type": "Programmed",
                    "status": "True",
                    "reason": "Programmed",
                    "message": "Gateway programmed, listeners active",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }],
                "listeners": listener_statuses,
            }
        });

        // Add addresses if available
        if !addresses.is_empty() {
            status["status"]["addresses"] = json!(addresses);
        }

        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(())
    }

    pub fn error_policy(
        _obj: Arc<Gateway>,
        error: &GatewayError,
        _ctx: Arc<()>,
    ) -> Action {
        warn!(error = %error, "Gateway reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(30))
    }
}

/// Validate allowed route kinds on a listener.
///
/// If the listener specifies `allowedRoutes.kinds`, check that they reference
/// valid route types. Returns (valid, reason, message, filtered_supported_kinds).
fn validate_listener_route_kinds(
    listener: &GatewayListeners,
) -> (bool, &'static str, String, Vec<serde_json::Value>) {
    let default_kinds = supported_route_kinds(&listener.protocol);

    let allowed = listener
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.kinds.as_ref());

    let Some(kinds) = allowed else {
        // No explicit kinds = use defaults, all valid
        return (true, "ResolvedRefs", "All references resolved".into(), default_kinds);
    };

    if kinds.is_empty() {
        return (true, "ResolvedRefs", "All references resolved".into(), default_kinds);
    }

    let valid_kinds = ["HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute"];
    let mut has_invalid = false;
    let mut filtered = Vec::new();

    for kind in kinds {
        let kind_name = &kind.kind;
        let group = kind.group.as_deref().unwrap_or("gateway.networking.k8s.io");

        if group == "gateway.networking.k8s.io" && valid_kinds.contains(&kind_name.as_str()) {
            filtered.push(json!({
                "group": group,
                "kind": kind_name,
            }));
        } else {
            has_invalid = true;
        }
    }

    if has_invalid {
        (
            false,
            "InvalidRouteKinds",
            "One or more route kinds are not supported".into(),
            filtered,
        )
    } else {
        (true, "ResolvedRefs", "All references resolved".into(), filtered)
    }
}

fn supported_route_kinds(protocol: &str) -> Vec<serde_json::Value> {
    match protocol {
        "HTTP" | "HTTPS" => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}),
        ],
        "TLS" => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "TLSRoute"}),
        ],
        _ => vec![
            json!({"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}),
        ],
    }
}
