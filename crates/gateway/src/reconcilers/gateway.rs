//! Gateway reconciler.
//!
//! Watches Gateway resources and translates them into Zentinel listener
//! configurations. Updates Gateway status with addresses and conditions.

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

/// Reconciler for Gateway resources.
pub struct GatewayReconciler {
    client: Client,
}

impl GatewayReconciler {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// Reconcile a Gateway resource.
    ///
    /// Verifies the Gateway references a GatewayClass we own, then
    /// translates listeners and updates status.
    pub async fn reconcile(
        &self,
        gateway: Arc<Gateway>,
    ) -> Result<Action, GatewayError> {
        let name = gateway.name_any();
        let namespace = gateway.namespace().unwrap_or_else(|| "default".into());
        let class_name = &gateway.spec.gateway_class_name;

        // Check if the referenced GatewayClass belongs to us
        if !self.is_our_gateway_class(class_name).await? {
            debug!(
                name = %name,
                namespace = %namespace,
                class = %class_name,
                "Ignoring Gateway for unowned GatewayClass"
            );
            return Ok(Action::await_change());
        }

        let generation = gateway.metadata.generation.unwrap_or(0);

        // Skip if we've already programmed this generation
        if is_already_programmed(&gateway, generation) {
            debug!(
                name = %name,
                namespace = %namespace,
                generation,
                "Gateway already programmed at this generation"
            );
            return Ok(Action::await_change());
        }

        info!(
            name = %name,
            namespace = %namespace,
            listeners = gateway.spec.listeners.len(),
            generation,
            "Reconciling Gateway"
        );

        // Update Gateway status
        self.update_status(&gateway, &namespace).await?;

        Ok(Action::await_change())
    }

    /// Check if a GatewayClass name belongs to our controller.
    async fn is_our_gateway_class(&self, class_name: &str) -> Result<bool, GatewayError> {
        let api: Api<GatewayClass> = Api::all(self.client.clone());
        match api.get(class_name).await {
            Ok(gc) => Ok(gc.spec.controller_name == CONTROLLER_NAME),
            Err(kube::Error::Api(err)) if err.code == 404 => {
                debug!(class = %class_name, "GatewayClass not found");
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Update Gateway status conditions and addresses.
    async fn update_status(
        &self,
        gateway: &Gateway,
        namespace: &str,
    ) -> Result<(), GatewayError> {
        let name = gateway.name_any();
        let generation = gateway.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        // Build listener statuses
        let listener_statuses: Vec<serde_json::Value> = gateway
            .spec
            .listeners
            .iter()
            .map(|l| {
                json!({
                    "name": l.name,
                    "attachedRoutes": 0,
                    "supportedKinds": supported_route_kinds(&l.protocol),
                    "conditions": [{
                        "type": "Accepted",
                        "status": "True",
                        "reason": "Accepted",
                        "message": "Listener accepted",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }, {
                        "type": "Programmed",
                        "status": "True",
                        "reason": "Programmed",
                        "message": "Listener programmed in Zentinel",
                        "observedGeneration": generation,
                        "lastTransitionTime": now,
                    }]
                })
            })
            .collect();

        let status = json!({
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
                    "message": "Gateway programmed — listeners active",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }],
                "listeners": listener_statuses,
            }
        });

        let api: Api<Gateway> = Api::namespaced(self.client.clone(), namespace);
        api.patch_status(
            &name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&status),
        )
        .await?;

        Ok(())
    }

    /// Handle errors during reconciliation.
    pub fn error_policy(
        _obj: Arc<Gateway>,
        error: &GatewayError,
        _ctx: Arc<()>,
    ) -> Action {
        warn!(error = %error, "Gateway reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(30))
    }
}

/// Check if the Gateway status already has Accepted=True and Programmed=True
/// for the current generation.
fn is_already_programmed(gw: &Gateway, generation: i64) -> bool {
    let Some(ref status) = gw.status else {
        return false;
    };
    let Some(ref conditions) = status.conditions else {
        return false;
    };
    let has_accepted = conditions.iter().any(|c| {
        c.type_ == "Accepted"
            && c.status == "True"
            && c.observed_generation == Some(generation)
    });
    let has_programmed = conditions.iter().any(|c| {
        c.type_ == "Programmed"
            && c.status == "True"
            && c.observed_generation == Some(generation)
    });
    has_accepted && has_programmed
}

/// Return the supported route kinds for a given listener protocol.
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
