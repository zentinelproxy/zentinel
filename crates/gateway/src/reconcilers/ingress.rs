//! Legacy Ingress compatibility shim.
//!
//! Watches `networking.k8s.io/v1` Ingress resources annotated with
//! `kubernetes.io/ingress.class: zentinel` (or the `ingressClassName` field)
//! and translates them into Zentinel config — the same way we handle
//! Gateway API resources.
//!
//! This lowers the migration barrier for users coming from NGINX Ingress
//! who haven't yet adopted Gateway API.

use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

use zentinel_common::types::{HealthCheckType, LoadBalancingAlgorithm, Priority};
use zentinel_config::{
    ConnectionPoolConfig, HealthCheck, HttpVersionConfig, MatchCondition, RouteConfig,
    RoutePolicies, ServiceType, UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
};

use crate::error::GatewayError;

/// The ingress class name that this controller handles.
pub const INGRESS_CLASS: &str = "zentinel";

/// Reconciler for legacy Ingress resources.
pub struct IngressReconciler {
    _client: Client,
}

impl IngressReconciler {
    pub fn new(client: Client) -> Self {
        Self { _client: client }
    }

    /// Reconcile an Ingress resource.
    ///
    /// Only processes Ingress resources with `ingressClassName: zentinel`
    /// or the annotation `kubernetes.io/ingress.class: zentinel`.
    pub async fn reconcile(&self, ingress: Arc<Ingress>) -> Result<Action, GatewayError> {
        let name = ingress.name_any();
        let namespace = ingress.namespace().unwrap_or_else(|| "default".into());

        // Check if this Ingress targets us
        if !is_our_ingress(&ingress) {
            debug!(name = %name, "Ignoring Ingress for different class");
            return Ok(Action::await_change());
        }

        info!(
            name = %name,
            namespace = %namespace,
            "Reconciling legacy Ingress"
        );

        // Translation happens in the translator's rebuild() via list_ingresses
        Ok(Action::await_change())
    }

    pub fn error_policy(_obj: Arc<Ingress>, error: &GatewayError, _ctx: Arc<()>) -> Action {
        warn!(error = %error, "Ingress reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(30))
    }
}

/// Check if an Ingress resource targets our controller.
fn is_our_ingress(ingress: &Ingress) -> bool {
    // Check ingressClassName field
    if let Some(ref spec) = ingress.spec {
        if let Some(ref class) = spec.ingress_class_name {
            return class == INGRESS_CLASS;
        }
    }

    // Check annotation fallback
    if let Some(ref annotations) = ingress.metadata.annotations {
        if let Some(class) = annotations.get("kubernetes.io/ingress.class") {
            return class == INGRESS_CLASS;
        }
    }

    false
}

/// Translate a list of Ingress resources into Zentinel routes and upstreams.
///
/// This is called by the ConfigTranslator during rebuild to include legacy
/// Ingress resources alongside Gateway API resources.
pub fn translate_ingresses(
    ingresses: &[Ingress],
) -> (Vec<RouteConfig>, HashMap<String, UpstreamConfig>) {
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();

    for ingress in ingresses {
        if !is_our_ingress(ingress) {
            continue;
        }

        let ing_name = ingress.name_any();
        let ing_ns = ingress.namespace().unwrap_or_else(|| "default".into());

        let spec = match &ingress.spec {
            Some(s) => s,
            None => continue,
        };

        // Process each rule
        for (rule_idx, rule) in spec
            .rules
            .as_ref()
            .cloned()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let host = rule.host.clone();

            let http = match &rule.http {
                Some(h) => h,
                None => continue,
            };

            for (path_idx, path) in http.paths.iter().enumerate() {
                let rule_id = format!("{ing_ns}-{ing_name}-rule{rule_idx}-path{path_idx}");

                // Build match conditions
                let mut matches = Vec::new();
                if let Some(ref h) = host {
                    matches.push(MatchCondition::Host(h.clone()));
                }

                let path_value = path.path.as_deref().unwrap_or("/");
                match path.path_type.as_str() {
                    "Exact" => matches.push(MatchCondition::Path(path_value.to_string())),
                    _ => {
                        matches.push(MatchCondition::PathPrefix(path_value.to_string()));
                    }
                }

                // Build upstream from backend
                if let Some(ref backend) = path.backend.service {
                    let svc_name = &backend.name;
                    let svc_port = backend.port.as_ref().and_then(|p| p.number).unwrap_or(80);
                    let upstream_id = format!("{rule_id}-upstream");

                    let address = format!("{svc_name}.{ing_ns}.svc.cluster.local:{svc_port}");

                    let upstream = UpstreamConfig {
                        id: upstream_id.clone(),
                        targets: vec![UpstreamTarget {
                            address,
                            weight: 1,
                            max_requests: None,
                            metadata: HashMap::from([
                                ("k8s-service".to_string(), svc_name.clone()),
                                ("k8s-namespace".to_string(), ing_ns.clone()),
                                ("source".to_string(), "ingress".to_string()),
                            ]),
                        }],
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        sticky_session: None,
                        health_check: Some(HealthCheck {
                            check_type: HealthCheckType::Http {
                                path: "/".to_string(),
                                expected_status: 200,
                                host: None,
                            },
                            interval_secs: 10,
                            timeout_secs: 5,
                            healthy_threshold: 2,
                            unhealthy_threshold: 3,
                        }),
                        connection_pool: ConnectionPoolConfig::default(),
                        timeouts: UpstreamTimeouts::default(),
                        tls: None,
                        http_version: HttpVersionConfig::default(),
                    };

                    upstreams.insert(upstream_id.clone(), upstream);

                    routes.push(RouteConfig {
                        id: rule_id,
                        priority: Priority::NORMAL,
                        matches,
                        upstream: Some(upstream_id),
                        service_type: ServiceType::Web,
                        policies: RoutePolicies::default(),
                        filters: vec![],
                        builtin_handler: None,
                        waf_enabled: false,
                        circuit_breaker: None,
                        retry_policy: None,
                        static_files: None,
                        api_schema: None,
                        inference: None,
                        error_pages: None,
                        websocket: false,
                        websocket_inspection: false,
                        shadow: None,
                        fallback: None,
                    });
                }
            }
        }

        // Handle default backend
        if let Some(ref default_backend) = spec.default_backend {
            if let Some(ref svc) = default_backend.service {
                let svc_name = &svc.name;
                let svc_port = svc.port.as_ref().and_then(|p| p.number).unwrap_or(80);
                let rule_id = format!("{ing_ns}-{ing_name}-default");
                let upstream_id = format!("{rule_id}-upstream");

                let address = format!("{svc_name}.{ing_ns}.svc.cluster.local:{svc_port}");

                upstreams.insert(
                    upstream_id.clone(),
                    UpstreamConfig {
                        id: upstream_id.clone(),
                        targets: vec![UpstreamTarget {
                            address,
                            weight: 1,
                            max_requests: None,
                            metadata: HashMap::from([
                                ("k8s-service".to_string(), svc_name.clone()),
                                ("k8s-namespace".to_string(), ing_ns.clone()),
                            ]),
                        }],
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        sticky_session: None,
                        health_check: None,
                        connection_pool: ConnectionPoolConfig::default(),
                        timeouts: UpstreamTimeouts::default(),
                        tls: None,
                        http_version: HttpVersionConfig::default(),
                    },
                );

                routes.push(RouteConfig {
                    id: rule_id,
                    priority: Priority::LOW,
                    matches: vec![MatchCondition::PathPrefix("/".to_string())],
                    upstream: Some(upstream_id),
                    service_type: ServiceType::Web,
                    policies: RoutePolicies::default(),
                    filters: vec![],
                    builtin_handler: None,
                    waf_enabled: false,
                    circuit_breaker: None,
                    retry_policy: None,
                    static_files: None,
                    api_schema: None,
                    inference: None,
                    error_pages: None,
                    websocket: false,
                    websocket_inspection: false,
                    shadow: None,
                    fallback: None,
                });
            }
        }
    }

    (routes, upstreams)
}
