//! Kubernetes Lease-based leader election for HA controller deployments.
//!
//! Only one controller replica should actively reconcile at a time. This
//! module implements leader election using the Kubernetes `Lease` API in
//! the `coordination.k8s.io/v1` group — the same mechanism used by
//! kube-scheduler and kube-controller-manager.
//!
//! The non-leader replicas run in standby, watching the Lease and taking
//! over if the leader fails to renew within the lease duration.

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::chrono::Utc;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::core::ObjectMeta;
use kube::Client;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::error::GatewayError;
use crate::reconcilers::gateway_class::CONTROLLER_NAME;

/// Configuration for leader election.
pub struct LeaderElectionConfig {
    /// Name of the Lease resource.
    pub lease_name: String,
    /// Namespace for the Lease resource.
    pub lease_namespace: String,
    /// Identity of this candidate (typically pod name).
    pub identity: String,
    /// How long the lease is valid before it must be renewed.
    pub lease_duration: Duration,
    /// How often the leader renews the lease.
    pub renew_interval: Duration,
    /// How long a candidate waits before trying to acquire an expired lease.
    pub retry_interval: Duration,
}

impl Default for LeaderElectionConfig {
    fn default() -> Self {
        Self {
            lease_name: "zentinel-gateway-controller".to_string(),
            lease_namespace: "zentinel-system".to_string(),
            identity: std::env::var("POD_NAME")
                .unwrap_or_else(|_| format!("zentinel-gateway-{}", uuid_short())),
            lease_duration: Duration::from_secs(15),
            renew_interval: Duration::from_secs(10),
            retry_interval: Duration::from_secs(5),
        }
    }
}

/// Leader election handle.
///
/// Call `run()` to start the election loop. Check `is_leader()` to
/// determine if this instance is the current leader before reconciling.
pub struct LeaderElector {
    client: Client,
    config: LeaderElectionConfig,
    is_leader: Arc<AtomicBool>,
}

impl LeaderElector {
    pub fn new(client: Client, config: LeaderElectionConfig) -> Self {
        Self {
            client,
            config,
            is_leader: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Returns `true` if this instance is currently the leader.
    pub fn is_leader(&self) -> bool {
        self.is_leader.load(Ordering::Relaxed)
    }

    /// Get a shared handle to the leader flag (for passing to reconcilers).
    pub fn leader_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.is_leader)
    }

    /// Run the leader election loop. This never returns unless cancelled.
    pub async fn run(&self) -> Result<(), GatewayError> {
        let api: Api<Lease> = Api::namespaced(self.client.clone(), &self.config.lease_namespace);

        info!(
            identity = %self.config.identity,
            lease = %self.config.lease_name,
            namespace = %self.config.lease_namespace,
            "Starting leader election"
        );

        loop {
            match self.try_acquire_or_renew(&api).await {
                Ok(true) => {
                    if !self.is_leader.swap(true, Ordering::Relaxed) {
                        info!(
                            identity = %self.config.identity,
                            "Acquired leadership"
                        );
                    }
                    tokio::time::sleep(self.config.renew_interval).await;
                }
                Ok(false) => {
                    if self.is_leader.swap(false, Ordering::Relaxed) {
                        warn!(
                            identity = %self.config.identity,
                            "Lost leadership"
                        );
                    }
                    tokio::time::sleep(self.config.retry_interval).await;
                }
                Err(e) => {
                    error!(error = %e, "Leader election error");
                    self.is_leader.store(false, Ordering::Relaxed);
                    tokio::time::sleep(self.config.retry_interval).await;
                }
            }
        }
    }

    /// Try to acquire or renew the lease.
    ///
    /// Returns `true` if this instance is (now) the leader.
    async fn try_acquire_or_renew(&self, api: &Api<Lease>) -> Result<bool, GatewayError> {
        let now = Utc::now();

        // Try to get existing lease
        match api.get(&self.config.lease_name).await {
            Ok(lease) => {
                let spec = lease.spec.as_ref();
                let holder = spec.and_then(|s| s.holder_identity.as_deref());
                let renew_time = spec.and_then(|s| s.renew_time.as_ref());
                let duration_secs = spec.and_then(|s| s.lease_duration_seconds);

                // Check if we already hold the lease
                if holder == Some(&self.config.identity) {
                    // Renew
                    debug!(identity = %self.config.identity, "Renewing lease");
                    self.update_lease(api, &lease).await?;
                    return Ok(true);
                }

                // Check if the lease has expired
                let expired = match (renew_time, duration_secs) {
                    (Some(MicroTime(last_renew)), Some(duration)) => {
                        let expiry = *last_renew + chrono::Duration::seconds(i64::from(duration));
                        now > expiry
                    }
                    _ => true, // No renew time = treat as expired
                };

                if expired {
                    info!(
                        identity = %self.config.identity,
                        previous_holder = ?holder,
                        "Lease expired, acquiring"
                    );
                    self.update_lease(api, &lease).await?;
                    Ok(true)
                } else {
                    debug!(
                        identity = %self.config.identity,
                        holder = ?holder,
                        "Lease held by another instance"
                    );
                    Ok(false)
                }
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                // Lease doesn't exist — create it
                info!(
                    identity = %self.config.identity,
                    "Creating new lease"
                );
                self.create_lease(api).await?;
                Ok(true)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Create a new Lease resource.
    async fn create_lease(&self, api: &Api<Lease>) -> Result<(), GatewayError> {
        let now = Utc::now();
        let lease = Lease {
            metadata: ObjectMeta {
                name: Some(self.config.lease_name.clone()),
                namespace: Some(self.config.lease_namespace.clone()),
                ..Default::default()
            },
            spec: Some(k8s_openapi::api::coordination::v1::LeaseSpec {
                holder_identity: Some(self.config.identity.clone()),
                lease_duration_seconds: Some(self.config.lease_duration.as_secs() as i32),
                acquire_time: Some(MicroTime(now)),
                renew_time: Some(MicroTime(now)),
                lease_transitions: Some(0),
                preferred_holder: None,
                strategy: None,
            }),
        };

        api.create(&PostParams::default(), &lease).await?;
        Ok(())
    }

    /// Update an existing Lease with our identity and renew time.
    async fn update_lease(&self, api: &Api<Lease>, existing: &Lease) -> Result<(), GatewayError> {
        let now = Utc::now();
        let previous_holder = existing
            .spec
            .as_ref()
            .and_then(|s| s.holder_identity.as_deref());
        let is_new_leader = previous_holder != Some(&self.config.identity);

        let transitions = existing
            .spec
            .as_ref()
            .and_then(|s| s.lease_transitions)
            .unwrap_or(0)
            + if is_new_leader { 1 } else { 0 };

        let patch = serde_json::json!({
            "spec": {
                "holderIdentity": self.config.identity,
                "leaseDurationSeconds": self.config.lease_duration.as_secs(),
                "renewTime": MicroTime(now),
                "leaseTransitions": transitions,
                "acquireTime": if is_new_leader {
                    Some(MicroTime(now))
                } else {
                    existing.spec.as_ref().and_then(|s| s.acquire_time.clone())
                },
            }
        });

        api.patch(
            &self.config.lease_name,
            &PatchParams::apply(CONTROLLER_NAME),
            &Patch::Merge(&patch),
        )
        .await?;

        Ok(())
    }
}

/// Generate a short random suffix for default identity.
fn uuid_short() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::time::SystemTime::now().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}
