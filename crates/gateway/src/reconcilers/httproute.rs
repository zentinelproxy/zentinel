//! HTTPRoute reconciler.
//!
//! Watches HTTPRoute resources and triggers config translation when
//! routes change. Validates parent refs and backend refs, setting
//! appropriate status conditions.

use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::httproutes::HTTPRoute;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;
use crate::reconcilers::ReferenceGrantIndex;
use crate::translator::ConfigTranslator;

/// Reconciler for HTTPRoute resources.
pub struct HttpRouteReconciler {
    client: Client,
    translator: Arc<ConfigTranslator>,
    reference_grants: Arc<ReferenceGrantIndex>,
}

impl HttpRouteReconciler {
    pub fn new(
        client: Client,
        translator: Arc<ConfigTranslator>,
        reference_grants: Arc<ReferenceGrantIndex>,
    ) -> Self {
        Self {
            client,
            translator,
            reference_grants,
        }
    }

    pub async fn reconcile(&self, route: Arc<HTTPRoute>) -> Result<Action, GatewayError> {
        let name = route.name_any();
        let namespace = route.namespace().unwrap_or_else(|| "default".into());

        info!(
            name = %name,
            namespace = %namespace,
            rules = route.spec.rules.as_ref().map_or(0, |r| r.len()),
            "Reconciling HTTPRoute"
        );

        let parent_refs = route.spec.parent_refs.as_ref().cloned().unwrap_or_default();
        let generation = route.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        let mut parent_statuses = Vec::new();
        let mut any_accepted = false;

        for parent_ref in &parent_refs {
            let gw_namespace = parent_ref.namespace.as_deref().unwrap_or(&namespace);
            let gw_name = &parent_ref.name;

            // Check if Gateway belongs to us
            let gw = match self.get_our_gateway(gw_name, gw_namespace).await? {
                Some(gw) => gw,
                None => continue,
            };

            // Check sectionName matches a listener
            if let Some(ref section_name) = parent_ref.section_name {
                let has_listener = gw.spec.listeners.iter().any(|l| l.name == *section_name);
                if !has_listener {
                    parent_statuses.push(json!({
                        "parentRef": {
                            "group": "gateway.networking.k8s.io",
                            "kind": "Gateway",
                            "name": gw_name,
                            "namespace": gw_namespace,
                            "sectionName": section_name,
                        },
                        "controllerName": CONTROLLER_NAME,
                        "conditions": [{
                            "type": "Accepted",
                            "status": "False",
                            "reason": "NoMatchingParent",
                            "message": format!("No listener named '{section_name}' found on Gateway"),
                            "observedGeneration": generation,
                            "lastTransitionTime": now,
                        }]
                    }));
                    continue;
                }
            }

            // Check cross-namespace parent ref permission
            if gw_namespace != namespace {
                let allowed = self.is_parent_ref_allowed(&gw, &namespace).await;
                if !allowed {
                    parent_statuses.push(json!({
                        "parentRef": {
                            "group": "gateway.networking.k8s.io",
                            "kind": "Gateway",
                            "name": gw_name,
                            "namespace": gw_namespace,
                        },
                        "controllerName": CONTROLLER_NAME,
                        "conditions": [{
                            "type": "Accepted",
                            "status": "False",
                            "reason": "NotAllowedByListeners",
                            "message": "Cross-namespace parent ref not allowed by Gateway",
                            "observedGeneration": generation,
                            "lastTransitionTime": now,
                        }, {
                            "type": "ResolvedRefs",
                            "status": "True",
                            "reason": "ResolvedRefs",
                            "message": "References resolved (route not accepted)",
                            "observedGeneration": generation,
                            "lastTransitionTime": now,
                        }]
                    }));
                    continue;
                }
            }

            // Check hostname intersection with Gateway listeners
            let route_hostnames: Vec<&str> = route
                .spec
                .hostnames
                .as_ref()
                .map(|h| h.iter().map(|s| s.as_str()).collect())
                .unwrap_or_default();

            if !route_hostnames.is_empty() {
                let has_intersection = gw.spec.listeners.iter().any(|l| {
                    let listener_host = l.hostname.as_deref();
                    match listener_host {
                        None => true, // unspecified listener matches all
                        Some(lh) => route_hostnames.iter().any(|rh| hostnames_intersect(lh, rh)),
                    }
                });

                if !has_intersection {
                    parent_statuses.push(json!({
                        "parentRef": {
                            "group": "gateway.networking.k8s.io",
                            "kind": "Gateway",
                            "name": gw_name,
                            "namespace": gw_namespace,
                        },
                        "controllerName": CONTROLLER_NAME,
                        "conditions": [{
                            "type": "Accepted",
                            "status": "False",
                            "reason": "NoMatchingListenerHostname",
                            "message": "No listener hostname intersects with route hostnames",
                            "observedGeneration": generation,
                            "lastTransitionTime": now,
                        }, {
                            "type": "ResolvedRefs",
                            "status": "True",
                            "reason": "ResolvedRefs",
                            "message": "References resolved (route not accepted)",
                            "observedGeneration": generation,
                            "lastTransitionTime": now,
                        }]
                    }));
                    continue;
                }
            }

            // Validate backend refs
            let (refs_resolved, refs_reason, refs_message) =
                self.validate_backend_refs(&route, &namespace).await;

            parent_statuses.push(json!({
                "parentRef": {
                    "group": "gateway.networking.k8s.io",
                    "kind": "Gateway",
                    "name": gw_name,
                    "namespace": gw_namespace,
                },
                "controllerName": CONTROLLER_NAME,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "Route accepted by Zentinel",
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

            any_accepted = true;
        }

        if parent_statuses.is_empty() {
            debug!(route = %name, "No parent Gateways belong to us, skipping");
            return Ok(Action::await_change());
        }

        // Trigger config rebuild if any parent accepted
        if any_accepted {
            if let Err(e) = self.translator.rebuild(&self.client).await {
                warn!(error = %e, "Config translation failed");
            }
        }

        // Update status
        let status = json!({ "status": { "parents": parent_statuses } });
        let api: Api<HTTPRoute> = Api::namespaced(self.client.clone(), &namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(Action::await_change())
    }

    /// Get a Gateway if it belongs to our GatewayClass.
    async fn get_our_gateway(
        &self,
        name: &str,
        namespace: &str,
    ) -> Result<Option<Gateway>, GatewayError> {
        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);
        let gw = match api.get(name).await {
            Ok(gw) => gw,
            Err(kube::Error::Api(err)) if err.code == 404 => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let class_api: Api<GatewayClass> = Api::all(self.client.clone());
        match class_api.get(&gw.spec.gateway_class_name).await {
            Ok(gc) if gc.spec.controller_name == CONTROLLER_NAME => Ok(Some(gw)),
            _ => Ok(None),
        }
    }

    /// Check if a Gateway allows routes from the given namespace.
    async fn is_parent_ref_allowed(&self, gw: &Gateway, route_namespace: &str) -> bool {
        use gateway_api::gateways::GatewayListenersAllowedRoutesNamespacesFrom;

        let gw_ns = gw.namespace().unwrap_or_default();

        for listener in &gw.spec.listeners {
            if let Some(ref allowed) = listener.allowed_routes {
                if let Some(ref namespaces) = allowed.namespaces {
                    if let Some(ref from) = namespaces.from {
                        match from {
                            GatewayListenersAllowedRoutesNamespacesFrom::All => return true,
                            GatewayListenersAllowedRoutesNamespacesFrom::Same => {
                                if gw_ns == route_namespace {
                                    return true;
                                }
                            }
                            GatewayListenersAllowedRoutesNamespacesFrom::Selector => {
                                if let Some(ref selector) = namespaces.selector {
                                    if self
                                        .namespace_matches_selector(route_namespace, selector)
                                        .await
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                // No allowedRoutes = Same namespace only (default)
                if gw_ns == route_namespace {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a namespace's labels match a label selector.
    async fn namespace_matches_selector(
        &self,
        namespace: &str,
        selector: &gateway_api::gateways::GatewayListenersAllowedRoutesNamespacesSelector,
    ) -> bool {
        let Some(ref match_labels) = selector.match_labels else {
            return true; // Empty selector matches all
        };

        let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(self.client.clone());
        match ns_api.get(namespace).await {
            Ok(ns) => {
                let ns_labels = ns.metadata.labels.unwrap_or_default();
                match_labels.iter().all(|(k, v)| ns_labels.get(k) == Some(v))
            }
            Err(e) => {
                warn!(
                    namespace = namespace,
                    error = %e,
                    "Failed to fetch namespace for label selector check"
                );
                false
            }
        }
    }

    /// Validate backend refs for an HTTPRoute.
    /// Returns (resolved, reason, message).
    async fn validate_backend_refs(
        &self,
        route: &HTTPRoute,
        route_ns: &str,
    ) -> (bool, &'static str, String) {
        let rules = route.spec.rules.as_ref();
        let rules = match rules {
            Some(r) => r,
            None => return (true, "ResolvedRefs", "No rules".into()),
        };

        for rule in rules {
            let backends = match &rule.backend_refs {
                Some(b) => b,
                None => continue,
            };

            for backend in backends {
                // Check kind (must be Service or empty)
                let kind = backend.kind.as_deref().unwrap_or("Service");
                let group = backend.group.as_deref().unwrap_or("");

                if kind != "Service" || (!group.is_empty() && group != "core") {
                    return (
                        false,
                        "InvalidKind",
                        format!("Backend ref has unsupported kind: {group}/{kind}"),
                    );
                }

                // Check cross-namespace permission
                let backend_ns = backend.namespace.as_deref().unwrap_or(route_ns);
                let backend_name = &backend.name;
                if backend_ns != route_ns
                    && !self.reference_grants.is_permitted(
                        route_ns,
                        "HTTPRoute",
                        backend_ns,
                        "Service",
                        backend_name,
                    )
                {
                    return (
                        false,
                        "RefNotPermitted",
                        format!(
                            "Cross-namespace reference to {backend_ns}/{backend_name} not permitted"
                        ),
                    );
                }

                // Check Service exists
                let svc_api: Api<k8s_openapi::api::core::v1::Service> =
                    Api::namespaced(self.client.clone(), backend_ns);
                match svc_api.get(backend_name).await {
                    Ok(_) => {}
                    Err(kube::Error::Api(err)) if err.code == 404 => {
                        return (
                            false,
                            "BackendNotFound",
                            format!("Service {backend_ns}/{backend_name} not found"),
                        );
                    }
                    Err(_) => {
                        // Non-fatal API error, treat as resolved
                    }
                }
            }
        }

        (
            true,
            "ResolvedRefs",
            "All backend references resolved".into(),
        )
    }

    pub fn error_policy(_obj: Arc<HTTPRoute>, error: &GatewayError, _ctx: Arc<()>) -> Action {
        warn!(error = %error, "HTTPRoute reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(15))
    }
}

/// Check if two hostnames intersect (one matches the other, accounting for wildcards).
fn hostnames_intersect(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    // Wildcard matching: *.example.com matches foo.example.com
    if let Some(suffix) = a.strip_prefix("*.") {
        if b.ends_with(suffix) && b.len() > suffix.len() + 1 {
            return true;
        }
    }
    if let Some(suffix) = b.strip_prefix("*.") {
        if a.ends_with(suffix) && a.len() > suffix.len() + 1 {
            return true;
        }
    }
    false
}
