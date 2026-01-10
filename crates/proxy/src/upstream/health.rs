//! Active health checking using Pingora's HttpHealthCheck
//!
//! This module provides active health probing for upstream backends using
//! Pingora's built-in health check infrastructure. It complements the passive
//! health tracking in load balancers by periodically probing backends.

use pingora_load_balancing::{
    discovery::Static,
    health_check::{HealthCheck as PingoraHealthCheck, HttpHealthCheck, TcpHealthCheck},
    Backend, Backends,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::grpc_health::GrpcHealthCheck;

use sentinel_common::types::HealthCheckType;
use sentinel_config::{HealthCheck as HealthCheckConfig, UpstreamConfig};

/// Active health checker for an upstream pool
///
/// This wraps Pingora's `Backends` struct with health checking enabled.
/// It runs periodic health probes and reports status back to the load balancer.
pub struct ActiveHealthChecker {
    /// Upstream ID
    upstream_id: String,
    /// Pingora backends with health checking
    backends: Arc<Backends>,
    /// Health check interval
    interval: Duration,
    /// Whether to run checks in parallel
    parallel: bool,
    /// Callback to notify load balancer of health changes
    health_callback: Arc<RwLock<Option<HealthChangeCallback>>>,
}

/// Callback type for health status changes
pub type HealthChangeCallback = Box<dyn Fn(&str, bool) + Send + Sync>;

impl ActiveHealthChecker {
    /// Create a new active health checker from upstream config
    pub fn new(config: &UpstreamConfig) -> Option<Self> {
        let health_config = config.health_check.as_ref()?;

        info!(
            upstream_id = %config.id,
            check_type = ?health_config.check_type,
            interval_secs = health_config.interval_secs,
            "Creating active health checker"
        );

        // Create backends from targets
        let mut backend_set = BTreeSet::new();
        for target in &config.targets {
            match Backend::new_with_weight(&target.address, target.weight as usize) {
                Ok(backend) => {
                    debug!(
                        upstream_id = %config.id,
                        target = %target.address,
                        weight = target.weight,
                        "Added backend for health checking"
                    );
                    backend_set.insert(backend);
                }
                Err(e) => {
                    warn!(
                        upstream_id = %config.id,
                        target = %target.address,
                        error = %e,
                        "Failed to create backend for health checking"
                    );
                }
            }
        }

        if backend_set.is_empty() {
            warn!(
                upstream_id = %config.id,
                "No backends created for health checking"
            );
            return None;
        }

        // Create static discovery (Static::new returns Box<Self>)
        let discovery = Static::new(backend_set);
        let mut backends = Backends::new(discovery);

        // Create and configure health check
        let health_check: Box<dyn PingoraHealthCheck + Send + Sync> =
            Self::create_health_check(health_config, &config.id);

        backends.set_health_check(health_check);

        Some(Self {
            upstream_id: config.id.clone(),
            backends: Arc::new(backends),
            interval: Duration::from_secs(health_config.interval_secs),
            parallel: true,
            health_callback: Arc::new(RwLock::new(None)),
        })
    }

    /// Create the appropriate health check based on config
    fn create_health_check(
        config: &HealthCheckConfig,
        upstream_id: &str,
    ) -> Box<dyn PingoraHealthCheck + Send + Sync> {
        match &config.check_type {
            HealthCheckType::Http {
                path,
                expected_status,
                host,
            } => {
                let hostname = host.as_deref().unwrap_or("localhost");
                let mut hc = HttpHealthCheck::new(hostname, false);

                // Configure thresholds
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                // Configure request path
                // Note: HttpHealthCheck sends GET to / by default
                // We customize by modifying hc.req for non-root paths
                if path != "/" {
                    // Create custom request header for the health check path
                    if let Ok(req) =
                        pingora_http::RequestHeader::build("GET", path.as_bytes(), None)
                    {
                        hc.req = req;
                    }
                }

                // Note: health_changed_callback requires implementing HealthObserve trait
                // We use polling via run_health_check() and get_health_statuses() instead

                debug!(
                    upstream_id = %upstream_id,
                    path = %path,
                    expected_status = expected_status,
                    host = hostname,
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created HTTP health check"
                );

                Box::new(hc)
            }
            HealthCheckType::Tcp => {
                // TcpHealthCheck::new() returns Box<Self>
                let mut hc = TcpHealthCheck::new();
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                debug!(
                    upstream_id = %upstream_id,
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created TCP health check"
                );

                hc
            }
            HealthCheckType::Grpc { service } => {
                let timeout = Duration::from_secs(config.timeout_secs);
                let mut hc = GrpcHealthCheck::new(service.clone(), timeout);
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                info!(
                    upstream_id = %upstream_id,
                    service = %service,
                    timeout_secs = config.timeout_secs,
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created gRPC health check"
                );

                Box::new(hc)
            }
            HealthCheckType::Inference {
                endpoint,
                expected_models,
                readiness,
            } => {
                // Inference health check uses HTTP under the hood
                // It probes the models endpoint (typically /v1/models)
                let mut hc = HttpHealthCheck::new("localhost", false);
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                // Set the endpoint path
                if let Ok(req) =
                    pingora_http::RequestHeader::build("GET", endpoint.as_bytes(), None)
                {
                    hc.req = req;
                }

                info!(
                    upstream_id = %upstream_id,
                    endpoint = %endpoint,
                    expected_models = ?expected_models,
                    has_readiness = readiness.is_some(),
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created inference health check"
                );

                // Note: Full model availability checking including readiness probes
                // is implemented in the ActiveHealthChecker in crates/proxy/src/health.rs.
                // This Pingora-based health check provides basic HTTP 200 verification.

                Box::new(hc)
            }
        }
    }

    /// Set callback for health status changes
    pub async fn set_health_callback(&self, callback: HealthChangeCallback) {
        *self.health_callback.write().await = Some(callback);
    }

    /// Run a single health check cycle
    pub async fn run_health_check(&self) {
        trace!(
            upstream_id = %self.upstream_id,
            parallel = self.parallel,
            "Running health check cycle"
        );

        self.backends.run_health_check(self.parallel).await;
    }

    /// Check if a specific backend is healthy
    pub fn is_backend_healthy(&self, address: &str) -> bool {
        let backends = self.backends.get_backend();
        for backend in backends.iter() {
            if backend.addr.to_string() == address {
                return self.backends.ready(backend);
            }
        }
        // Unknown backend, assume healthy
        true
    }

    /// Get all backend health statuses
    pub fn get_health_statuses(&self) -> Vec<(String, bool)> {
        let backends = self.backends.get_backend();
        backends
            .iter()
            .map(|b| {
                let addr = b.addr.to_string();
                let healthy = self.backends.ready(b);
                (addr, healthy)
            })
            .collect()
    }

    /// Get the health check interval
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Get the upstream ID
    pub fn upstream_id(&self) -> &str {
        &self.upstream_id
    }
}

/// Health check runner that manages multiple upstream health checkers
pub struct HealthCheckRunner {
    /// Health checkers per upstream
    checkers: Vec<ActiveHealthChecker>,
    /// Whether the runner is active
    running: Arc<RwLock<bool>>,
}

impl HealthCheckRunner {
    /// Create a new health check runner
    pub fn new() -> Self {
        Self {
            checkers: Vec::new(),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Add a health checker for an upstream
    pub fn add_checker(&mut self, checker: ActiveHealthChecker) {
        info!(
            upstream_id = %checker.upstream_id,
            interval_secs = checker.interval.as_secs(),
            "Added health checker to runner"
        );
        self.checkers.push(checker);
    }

    /// Get the number of health checkers
    pub fn checker_count(&self) -> usize {
        self.checkers.len()
    }

    /// Start the health check loop (runs until stopped)
    pub async fn run(&self) {
        if self.checkers.is_empty() {
            info!("No health checkers configured, skipping health check loop");
            return;
        }

        *self.running.write().await = true;

        info!(
            checker_count = self.checkers.len(),
            "Starting health check runner"
        );

        // Find minimum interval
        let min_interval = self
            .checkers
            .iter()
            .map(|c| c.interval)
            .min()
            .unwrap_or(Duration::from_secs(10));

        let mut interval = tokio::time::interval(min_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if !*self.running.read().await {
                info!("Health check runner stopped");
                break;
            }

            // Run health checks for all upstreams
            for checker in &self.checkers {
                checker.run_health_check().await;

                // Log current health statuses
                let statuses = checker.get_health_statuses();
                for (addr, healthy) in &statuses {
                    trace!(
                        upstream_id = %checker.upstream_id,
                        backend = %addr,
                        healthy = healthy,
                        "Backend health status"
                    );
                }
            }
        }
    }

    /// Stop the health check loop
    pub async fn stop(&self) {
        info!("Stopping health check runner");
        *self.running.write().await = false;
    }

    /// Get health status for a specific upstream and backend
    pub fn get_health(&self, upstream_id: &str, address: &str) -> Option<bool> {
        self.checkers
            .iter()
            .find(|c| c.upstream_id == upstream_id)
            .map(|c| c.is_backend_healthy(address))
    }

    /// Get all health statuses for an upstream
    pub fn get_upstream_health(&self, upstream_id: &str) -> Option<Vec<(String, bool)>> {
        self.checkers
            .iter()
            .find(|c| c.upstream_id == upstream_id)
            .map(|c| c.get_health_statuses())
    }
}

impl Default for HealthCheckRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::types::LoadBalancingAlgorithm;
    use sentinel_config::{
        ConnectionPoolConfig, HttpVersionConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use std::collections::HashMap;

    fn create_test_config() -> UpstreamConfig {
        UpstreamConfig {
            id: "test-upstream".to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8081".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            health_check: Some(HealthCheckConfig {
                check_type: HealthCheckType::Http {
                    path: "/health".to_string(),
                    expected_status: 200,
                    host: None,
                },
                interval_secs: 5,
                timeout_secs: 2,
                healthy_threshold: 2,
                unhealthy_threshold: 3,
            }),
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
        }
    }

    #[test]
    fn test_create_health_checker() {
        let config = create_test_config();
        let checker = ActiveHealthChecker::new(&config);
        assert!(checker.is_some());

        let checker = checker.unwrap();
        assert_eq!(checker.upstream_id, "test-upstream");
        assert_eq!(checker.interval, Duration::from_secs(5));
    }

    #[test]
    fn test_no_health_check_config() {
        let mut config = create_test_config();
        config.health_check = None;

        let checker = ActiveHealthChecker::new(&config);
        assert!(checker.is_none());
    }

    #[test]
    fn test_health_check_runner() {
        let mut runner = HealthCheckRunner::new();
        assert_eq!(runner.checker_count(), 0);

        let config = create_test_config();
        if let Some(checker) = ActiveHealthChecker::new(&config) {
            runner.add_checker(checker);
            assert_eq!(runner.checker_count(), 1);
        }
    }
}
