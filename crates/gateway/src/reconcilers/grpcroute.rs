//! GRPCRoute reconciler.
//!
//! Watches GRPCRoute resources and triggers config translation when
//! routes change. GRPCRoutes are translated into Zentinel routes with
//! path-based matching on the gRPC service/method pattern.

use gateway_api::gatewayclasses::GatewayClass;
use gateway_api::gateways::Gateway;
use gateway_api::grpcroutes::GRPCRoute;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;
use crate::translator::ConfigTranslator;

/// Reconciler for GRPCRoute resources.
pub struct GrpcRouteReconciler {
    client: Client,
    translator: Arc<ConfigTranslator>,
}

impl GrpcRouteReconciler {
    pub fn new(client: Client, translator: Arc<ConfigTranslator>) -> Self {
        Self { client, translator }
    }

    /// Reconcile a GRPCRoute resource.
    pub async fn reconcile(&self, route: Arc<GRPCRoute>) -> Result<Action, GatewayError> {
        let name = route.name_any();
        let namespace = route.namespace().unwrap_or_else(|| "default".into());

        info!(
            name = %name,
            namespace = %namespace,
            rules = route.spec.rules.as_ref().map_or(0, |r| r.len()),
            "Reconciling GRPCRoute"
        );

        // Find parent Gateways that belong to us
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
                    debug!(
                        gateway = %gw_name,
                        "Ignoring parent ref to unowned Gateway"
                    );
                }
                Err(e) => {
                    warn!(gateway = %gw_name, error = %e, "Error checking Gateway ownership");
                }
            }
        }

        if accepted_parents.is_empty() {
            return Ok(Action::await_change());
        }

        // Trigger config rebuild
        if let Err(e) = self.translator.rebuild(&self.client).await {
            warn!(error = %e, "Config translation failed for GRPCRoute");
            return Ok(Action::requeue(std::time::Duration::from_secs(15)));
        }

        // Update status
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
        route: &GRPCRoute,
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
                        "message": "GRPCRoute accepted by Zentinel",
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

        let api: Api<GRPCRoute> = Api::namespaced(self.client.clone(), namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(())
    }

    /// Handle errors during reconciliation.
    pub fn error_policy(_obj: Arc<GRPCRoute>, error: &GatewayError, _ctx: Arc<()>) -> Action {
        warn!(error = %error, "GRPCRoute reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(15))
    }
}
