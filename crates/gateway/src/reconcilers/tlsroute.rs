//! TLSRoute reconciler.
//!
//! Watches TLSRoute resources for SNI-based TLS passthrough routing.
//! TLSRoutes match on SNI hostnames and forward the raw TLS connection
//! to backends without termination.

use gateway_api::experimental::tlsroutes::TLSRoute;
use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;
use crate::translator::ConfigTranslator;

/// Reconciler for TLSRoute resources.
pub struct TlsRouteReconciler {
    client: Client,
    translator: Arc<ConfigTranslator>,
}

impl TlsRouteReconciler {
    pub fn new(client: Client, translator: Arc<ConfigTranslator>) -> Self {
        Self { client, translator }
    }

    /// Reconcile a TLSRoute resource.
    pub async fn reconcile(&self, route: Arc<TLSRoute>) -> Result<Action, GatewayError> {
        let name = route.name_any();
        let namespace = route.namespace().unwrap_or_else(|| "default".into());

        info!(
            name = %name,
            namespace = %namespace,
            rules = route.spec.rules.len(),
            "Reconciling TLSRoute"
        );

        let parent_refs = route.spec.parent_refs.as_ref().cloned().unwrap_or_default();

        let mut accepted_parents = Vec::new();

        for parent_ref in &parent_refs {
            let gw_namespace = parent_ref.namespace.as_deref().unwrap_or(&namespace);
            let gw_name = &parent_ref.name;

            match self.is_our_gateway(gw_name, gw_namespace).await {
                Ok(true) => {
                    accepted_parents.push((gw_name.clone(), gw_namespace.to_string()));
                }
                Ok(false) => {
                    debug!(gateway = %gw_name, "Ignoring parent ref to unowned Gateway");
                }
                Err(e) => {
                    warn!(gateway = %gw_name, error = %e, "Error checking Gateway ownership");
                }
            }
        }

        if accepted_parents.is_empty() {
            return Ok(Action::await_change());
        }

        if let Err(e) = self.translator.rebuild(&self.client).await {
            warn!(error = %e, "Config translation failed for TLSRoute");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }

        self.update_status(&route, &namespace, &accepted_parents)
            .await?;

        Ok(Action::await_change())
    }

    async fn is_our_gateway(&self, name: &str, namespace: &str) -> Result<bool, GatewayError> {
        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);
        let gw = match api.get(name).await {
            Ok(gw) => gw,
            Err(kube::Error::Api(err)) if err.code == 404 => return Ok(false),
            Err(e) => return Err(e.into()),
        };

        let class_api: Api<GatewayClass> = Api::all(self.client.clone());
        match class_api.get(&gw.spec.gateway_class_name).await {
            Ok(gc) => Ok(gc.spec.controller_name == CONTROLLER_NAME),
            Err(kube::Error::Api(err)) if err.code == 404 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn update_status(
        &self,
        route: &TLSRoute,
        namespace: &str,
        parents: &[(String, String)],
    ) -> Result<(), GatewayError> {
        let name = route.name_any();
        let generation = route.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        let parent_statuses: Vec<serde_json::Value> = parents
            .iter()
            .map(|(gw_name, gw_ns)| {
                json!({
                    "parentRef": {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": gw_name,
                        "namespace": gw_ns,
                    },
                    "controllerName": CONTROLLER_NAME,
                    "conditions": [{
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "TLSRoute accepted by Zentinel",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }, {
                        "type": "ResolvedRefs",
                        "status": "True",
                        "reason": "ResolvedRefs",
                        "message": "All backend references resolved",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }]
                })
            })
            .collect();

        let status = json!({ "status": { "parents": parent_statuses } });

        let api: Api<TLSRoute> = Api::namespaced(self.client.clone(), namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(())
    }

    pub fn error_policy(_obj: Arc<TLSRoute>, error: &GatewayError, _ctx: Arc<()>) -> Action {
        warn!(error = %error, "TLSRoute reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(15))
    }
}
