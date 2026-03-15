//! BackendTLSPolicy reconciler.
//!
//! Watches BackendTLSPolicy resources that define TLS validation
//! requirements for backend connections. When a policy targets a
//! Service used as an HTTPRoute backend, the proxy should verify
//! the backend's TLS certificate.

use gateway_api::backendtlspolicies::BackendTLSPolicy;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

use super::gateway_class::CONTROLLER_NAME;
use crate::error::GatewayError;
use crate::translator::ConfigTranslator;

/// Reconciler for BackendTLSPolicy resources.
pub struct BackendTlsPolicyReconciler {
    client: Client,
    translator: Arc<ConfigTranslator>,
}

impl BackendTlsPolicyReconciler {
    pub fn new(client: Client, translator: Arc<ConfigTranslator>) -> Self {
        Self { client, translator }
    }

    pub async fn reconcile(
        &self,
        policy: Arc<BackendTLSPolicy>,
    ) -> Result<Action, GatewayError> {
        let name = policy.name_any();
        let namespace = policy.namespace().unwrap_or_else(|| "default".into());

        info!(
            name = %name,
            namespace = %namespace,
            targets = policy.spec.target_refs.len(),
            "Reconciling BackendTLSPolicy"
        );

        // Trigger config rebuild so the translator can pick up TLS settings
        if let Err(e) = self.translator.rebuild(&self.client).await {
            warn!(error = %e, "Config translation failed for BackendTLSPolicy");
        }

        // Update policy status
        let generation = policy.metadata.generation.unwrap_or(0);
        let now = chrono::Utc::now().to_rfc3339();

        let ancestors: Vec<serde_json::Value> = policy
            .spec
            .target_refs
            .iter()
            .map(|target| json!({
                "ancestorRef": {
                    "group": &target.group,
                    "kind": &target.kind,
                    "name": &target.name,
                    "namespace": &namespace,
                },
                "controllerName": CONTROLLER_NAME,
                "conditions": [{
                    "type": "Accepted",
                    "status": "True",
                    "reason": "Accepted",
                    "message": "BackendTLSPolicy accepted by Zentinel",
                    "observedGeneration": generation,
                    "lastTransitionTime": now,
                }]
            }))
            .collect();

        let status = json!({ "status": { "ancestors": ancestors } });
        let api: Api<BackendTLSPolicy> = Api::namespaced(self.client.clone(), &namespace);
        let _ = api
            .patch_status(&name, &PatchParams::apply(CONTROLLER_NAME), &Patch::Merge(&status))
            .await;

        Ok(Action::await_change())
    }

    pub fn error_policy(_obj: Arc<BackendTLSPolicy>, error: &GatewayError, _ctx: Arc<()>) -> Action {
        warn!(error = %error, "BackendTLSPolicy reconciliation failed");
        Action::requeue(std::time::Duration::from_secs(30))
    }
}
