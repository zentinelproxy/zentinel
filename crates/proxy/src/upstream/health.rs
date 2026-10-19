//! Active health checking using Pingora's HttpHealthCheck
//!
//! This module provides active health probing for upstream backends using
//! Pingora's built-in health check infrastructure. It complements the passive
//! health tracking in load balancers by periodically probing backends.

use pingora_load_balancing::{
    health_check::{HealthCheck as PingoraHealthCheck, HttpHealthCheck, TcpHealthCheck},
    Backends,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::grpc_health::GrpcHealthCheck;
use crate::upstream::active_health::{ActiveHealthView, HostResolutions, ViewDiscovery};
use crate::upstream::inference_health::InferenceHealthCheck;
use crate::upstream::mcp_health::McpHealthCheck;

use zentinel_common::types::HealthCheckType;
use zentinel_config::{HealthCheck as HealthCheckConfig, UpstreamConfig};

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
    /// Where probe results are published for the upstream's pools
    view: Arc<ActiveHealthView>,
    /// What hostname targets resolved to in the last cycle
    resolutions: HostResolutions,
    /// Consecutive failed resolutions after which a hostname is unhealthy
    unhealthy_threshold: u32,
}

/// Callback type for health status changes
pub type HealthChangeCallback = Box<dyn Fn(&str, bool) + Send + Sync>;

impl ActiveHealthChecker {
    /// Create a new active health checker from upstream config
    pub fn new(config: &UpstreamConfig) -> Option<Self> {
        Self::with_view(config, Arc::new(ActiveHealthView::new()))
    }

    /// Create a checker that publishes its results to `view`, and probes the
    /// targets the upstream's pools publish there (falling back to the
    /// configured targets until a pool has).
    pub fn with_view(config: &UpstreamConfig, view: Arc<ActiveHealthView>) -> Option<Self> {
        let health_config = config.health_check.as_ref()?;

        info!(
            upstream_id = %config.id,
            check_type = ?health_config.check_type,
            interval_secs = health_config.interval_secs,
            "Creating active health checker"
        );

        // Collect the targets to probe. Socket addresses are probed as they
        // are; `host:port` targets are resolved by the discovery at every
        // cycle (see `ViewDiscovery`), so only their shape is checked here.
        let mut configured = Vec::new();
        for target in &config.targets {
            let valid = target.address.parse::<std::net::SocketAddr>().is_ok()
                || target
                    .address
                    .rsplit_once(':')
                    .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
            if valid {
                debug!(
                    upstream_id = %config.id,
                    target = %target.address,
                    weight = target.weight,
                    "Added backend for health checking"
                );
                configured.push(target.address.clone());
            } else {
                warn!(
                    upstream_id = %config.id,
                    target = %target.address,
                    "Failed to create backend for health checking"
                );
            }
        }

        // A discovery-backed upstream may have no configured targets at all:
        // its targets arrive through the view once its pool publishes them.
        if configured.is_empty() && config.discovery.is_none() {
            warn!(
                upstream_id = %config.id,
                "No backends created for health checking"
            );
            return None;
        }

        let weights = config
            .targets
            .iter()
            .map(|t| (t.address.clone(), t.weight as usize))
            .collect();
        let resolutions = HostResolutions::default();
        let discovery = Box::new(ViewDiscovery {
            view: view.clone(),
            configured,
            weights,
            resolutions: resolutions.clone(),
            resolve_timeout: Duration::from_secs(health_config.timeout_secs.max(1)),
        });
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
            view,
            resolutions,
            unhealthy_threshold: health_config.unhealthy_threshold,
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

                // Configure request path. The request is rebuilt for the path,
                // so the Host header `HttpHealthCheck::new` set has to be
                // carried over: without it an HTTP/1.1 server may answer 400,
                // which now takes the target out of rotation.
                if path != "/" {
                    if let Ok(mut req) =
                        pingora_http::RequestHeader::build("GET", path.as_bytes(), None)
                    {
                        if req.append_header("Host", hostname).is_ok() {
                            hc.req = req;
                        }
                    }
                }

                // `expected-status` and `timeout-secs` were accepted and
                // ignored: Pingora's default accepts only 200 and waits 1 s.
                let expected = *expected_status;
                hc.validator = Some(Box::new(move |resp: &pingora_http::ResponseHeader| {
                    if resp.status.as_u16() == expected {
                        Ok(())
                    } else {
                        pingora_core::Error::e_explain(
                            pingora_core::ErrorType::CustomCode(
                                "unexpected health check status",
                                resp.status.as_u16(),
                            ),
                            "during http healthcheck",
                        )
                    }
                }));
                let timeout = Duration::from_secs(config.timeout_secs.max(1));
                hc.peer_template.options.connection_timeout = Some(timeout);
                hc.peer_template.options.read_timeout = Some(timeout);

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
                readiness: _,
            } => {
                // Inference health check that verifies expected models are available
                let timeout = Duration::from_secs(config.timeout_secs);
                let mut hc =
                    InferenceHealthCheck::new(endpoint.clone(), expected_models.clone(), timeout);
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                info!(
                    upstream_id = %upstream_id,
                    endpoint = %endpoint,
                    expected_models = ?expected_models,
                    timeout_secs = config.timeout_secs,
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created inference health check with model verification"
                );

                Box::new(hc)
            }
            HealthCheckType::Mcp {
                path,
                expected_tools,
            } => {
                let timeout = Duration::from_secs(config.timeout_secs);
                let mut hc = McpHealthCheck::new(path.clone(), expected_tools.clone(), timeout);
                hc.consecutive_success = config.healthy_threshold as usize;
                hc.consecutive_failure = config.unhealthy_threshold as usize;

                info!(
                    upstream_id = %upstream_id,
                    path = %path,
                    expected_tools = ?expected_tools,
                    timeout_secs = config.timeout_secs,
                    consecutive_success = hc.consecutive_success,
                    consecutive_failure = hc.consecutive_failure,
                    "Created MCP health check"
                );

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

        // Populate the backend set from discovery before probing it.
        //
        // `Backends::run_health_check` iterates the set that `update()` fills,
        // and nothing else fills it -- so without this the runner ticks on
        // schedule, logs that it is running, and probes nothing at all. It
        // fails silently in both directions: no probe is sent, and no backend
        // is ever marked unhealthy, so an upstream that is down stays in
        // rotation while the configuration says it is being checked.
        //
        // Cheap to repeat: discovery here is `Static`, and `update` only
        // invokes its callback when the resolved set actually differs.
        if let Err(e) = self.backends.update(|_| {}).await {
            warn!(
                upstream_id = %self.upstream_id,
                error = %e,
                "Failed to refresh backends before health check"
            );
            return;
        }

        self.backends.run_health_check(self.parallel).await;

        // Publish the outcome for the pools. `ready()` already applies
        // healthy-threshold / unhealthy-threshold. Probes are per address;
        // pools key hostname targets by name, so those get one folded status
        // each, alongside the per-address ones the request path uses to pick
        // a healthy address for the name.
        let statuses = self.get_health_statuses();
        let probed: HashMap<String, bool> = statuses.iter().cloned().collect();
        let hosts =
            ViewDiscovery::host_statuses(&self.resolutions, &probed, self.unhealthy_threshold);
        self.view.record(statuses.into_iter().chain(hosts));
    }

    /// The view this checker publishes to
    pub fn view(&self) -> &Arc<ActiveHealthView> {
        &self.view
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

/// Health check runner that manages one probing task per upstream.
///
/// The set of checkers is not fixed at startup: [`HealthCheckRunner::apply`]
/// reconciles it against a configuration, so a reload that adds, changes or
/// removes a `health-check` starts, restarts or stops the matching probe loop.
/// Before this, checkers were collected once at startup into a `Vec` that a
/// reload never touched -- a check added by SIGHUP never probed, a changed
/// interval or path kept the old one, and a removed check kept probing.
///
/// Checkers are keyed by the upstream's canonical id, so an upstream can only
/// ever have one probe loop. Startup used to register every global upstream
/// twice (once from `config.upstreams`, once from the flattened config, where
/// global upstreams appear again under `Scope::Global`), which probed every
/// target twice per interval.
///
/// Each upstream runs on its own interval. The old single loop ticked at the
/// minimum interval across all upstreams and probed every upstream on each
/// tick, so one upstream with `interval-secs 1` made all others probe every
/// second too.
pub struct HealthCheckRunner {
    checkers: parking_lot::Mutex<HashMap<String, RunningChecker>>,
    /// Probe results per upstream id, shared with the pools. Kept for the
    /// runner's lifetime so pools built before, during or after a reload all
    /// see the same results.
    views: parking_lot::Mutex<HashMap<String, Arc<ActiveHealthView>>>,
}

/// A checker together with the task that drives it.
struct RunningChecker {
    /// What the probe loop was built from; a change means a restart.
    fingerprint: String,
    checker: Arc<ActiveHealthChecker>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RunningChecker {
    fn drop(&mut self) {
        // Dropping a `JoinHandle` detaches the task rather than stopping it,
        // which is exactly how a removed check would keep probing.
        self.task.abort();
    }
}

/// What [`HealthCheckRunner::apply`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HealthCheckChanges {
    /// Upstreams that gained a health check
    pub started: usize,
    /// Upstreams whose health check (or targets) changed
    pub restarted: usize,
    /// Upstreams that lost their health check, or were removed
    pub stopped: usize,
    /// Upstreams whose probe loop was left running untouched
    pub unchanged: usize,
}

impl HealthCheckRunner {
    /// Create a runner with no checkers
    pub fn new() -> Self {
        Self {
            checkers: parking_lot::Mutex::new(HashMap::new()),
            views: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The health view for an upstream id, created on first use. Pools attach
    /// to it to have probe results applied to their target selection.
    pub fn view(&self, upstream_id: &str) -> Arc<ActiveHealthView> {
        self.views
            .lock()
            .entry(upstream_id.to_string())
            .or_insert_with(|| Arc::new(ActiveHealthView::new()))
            .clone()
    }

    /// Everything a probe loop is built from. Two configs with the same
    /// fingerprint produce identical probing, so the running loop (and the
    /// health state it has accumulated) is kept.
    fn fingerprint(config: &UpstreamConfig) -> Option<String> {
        let hc = config.health_check.as_ref()?;
        let targets: Vec<(&str, u32)> = config
            .targets
            .iter()
            .map(|t| (t.address.as_str(), t.weight))
            .collect();
        Some(format!("{hc:?}|{targets:?}"))
    }

    /// Reconcile the running checkers with `upstreams`.
    ///
    /// Each upstream's `id` must already be its canonical id. Upstreams with a
    /// health check get exactly one probe loop; a loop whose upstream is gone,
    /// or no longer has a health check, is stopped. A loop is restarted only
    /// when what it probes changed. Must be called within a Tokio runtime.
    pub fn apply<I>(&self, upstreams: I) -> HealthCheckChanges
    where
        I: IntoIterator<Item = UpstreamConfig>,
    {
        let mut changes = HealthCheckChanges::default();
        let mut desired: HashMap<String, (String, UpstreamConfig)> = HashMap::new();
        for config in upstreams {
            if let Some(fp) = Self::fingerprint(&config) {
                desired.insert(config.id.clone(), (fp, config));
            }
        }

        let mut checkers = self.checkers.lock();

        let before = checkers.len();
        checkers.retain(|id, _| {
            let keep = desired.contains_key(id);
            if !keep {
                // No check any more: nothing may stay out of rotation on the
                // strength of an old probe result.
                self.view(id).reset();
            }
            keep
        });
        changes.stopped = before - checkers.len();

        for (id, (fingerprint, config)) in desired {
            let existed = match checkers.get(&id) {
                Some(running) if running.fingerprint == fingerprint => {
                    changes.unchanged += 1;
                    continue;
                }
                Some(_) => true,
                None => false,
            };

            // Remove (and so abort) the old loop before deciding about the
            // new one, so a check that can no longer be built stops probing.
            // Results of the old check do not carry over to the new one.
            checkers.remove(&id);
            let view = self.view(&id);
            view.reset();

            let Some(checker) = ActiveHealthChecker::with_view(&config, view) else {
                if existed {
                    changes.stopped += 1;
                }
                continue;
            };
            let checker = Arc::new(checker);
            let task = tokio::spawn(Self::probe_loop(checker.clone()));
            checkers.insert(
                id,
                RunningChecker {
                    fingerprint,
                    checker,
                    task,
                },
            );
            if existed {
                changes.restarted += 1;
            } else {
                changes.started += 1;
            }
        }

        changes
    }

    /// Probe one upstream on its own interval until aborted.
    async fn probe_loop(checker: Arc<ActiveHealthChecker>) {
        // `tokio::time::interval` panics on a zero period.
        let period = checker.interval.max(Duration::from_secs(1));
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        debug!(
            upstream_id = %checker.upstream_id,
            interval_secs = period.as_secs(),
            "Health check loop started"
        );

        loop {
            ticker.tick().await;
            checker.run_health_check().await;

            for (addr, healthy) in checker.get_health_statuses() {
                trace!(
                    upstream_id = %checker.upstream_id,
                    backend = %addr,
                    healthy = healthy,
                    "Backend health status"
                );
            }
        }
    }

    /// Number of upstreams with a running health check
    pub fn checker_count(&self) -> usize {
        self.checkers.lock().len()
    }

    /// Ids of the upstreams with a running health check, sorted
    pub fn upstream_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.checkers.lock().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Interval of the running health check for an upstream
    pub fn interval_of(&self, upstream_id: &str) -> Option<Duration> {
        self.checkers
            .lock()
            .get(upstream_id)
            .map(|r| r.checker.interval)
    }

    /// Stop every probe loop
    pub fn stop(&self) {
        info!("Stopping health check runner");
        self.checkers.lock().clear();
    }

    /// Get health status for a specific upstream and backend
    pub fn get_health(&self, upstream_id: &str, address: &str) -> Option<bool> {
        self.checkers
            .lock()
            .get(upstream_id)
            .map(|r| r.checker.is_backend_healthy(address))
    }

    /// Get all health statuses for an upstream
    pub fn get_upstream_health(&self, upstream_id: &str) -> Option<Vec<(String, bool)>> {
        self.checkers
            .lock()
            .get(upstream_id)
            .map(|r| r.checker.get_health_statuses())
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Once;
    use zentinel_common::types::LoadBalancingAlgorithm;
    use zentinel_config::{
        ConnectionPoolConfig, HttpVersionConfig, UpstreamTarget, UpstreamTimeouts,
    };

    static INIT: Once = Once::new();

    fn init_crypto_provider() {
        INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

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
            sticky_session: None,
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
            circuit_breaker: None,
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
            discovery: None,
        }
    }

    /// The runner ticked on schedule, logged that it was running, and probed
    /// nothing: `Backends::run_health_check` iterates the set that `update()`
    /// fills, and nothing called `update()`. Every health check in every
    /// configuration was inert, in both directions -- no probe sent, and no
    /// backend ever marked unhealthy.
    ///
    /// Asserts against a real socket, because the defect was invisible to any
    /// test that only inspected configuration.
    #[tokio::test]
    async fn a_health_check_cycle_actually_probes_the_backend() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();

        let probed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = probed.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let mut config = create_test_config();
        config.targets[0].address = addr;
        config.health_check = Some(HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval_secs: 1,
            timeout_secs: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        });

        let checker = ActiveHealthChecker::new(&config).expect("checker built");
        checker.run_health_check().await;

        // The probe has connected by the time the cycle returns, but the
        // accept loop above only counts it once the runtime polls that task,
        // and whether that has happened yet depends on scheduler ordering
        // (Pingora 0.9.0's JoinSet-driven pass changed it). Give the counter
        // a bounded window rather than asserting on the very next line.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while probed.load(std::sync::atomic::Ordering::SeqCst) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            probed.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "a health check cycle connected to nothing"
        );
    }

    #[test]
    fn test_create_health_checker() {
        init_crypto_provider();
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

    #[tokio::test]
    async fn test_health_check_runner() {
        init_crypto_provider();
        let runner = HealthCheckRunner::new();
        assert_eq!(runner.checker_count(), 0);

        let changes = runner.apply([create_test_config()]);
        assert_eq!(changes.started, 1);
        assert_eq!(runner.checker_count(), 1);
        assert_eq!(runner.upstream_ids(), vec!["test-upstream".to_string()]);
    }

    /// A TCP listener that counts the connections made to it, and a config
    /// whose TCP health check points at it.
    async fn counting_backend(interval_secs: u64) -> (UpstreamConfig, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let probes = Arc::new(AtomicUsize::new(0));
        let seen = probes.clone();
        tokio::spawn(async move {
            while listener.accept().await.is_ok() {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        });

        let mut config = create_test_config();
        config.targets[0].address = addr;
        config.health_check = Some(HealthCheckConfig {
            check_type: HealthCheckType::Tcp,
            interval_secs,
            timeout_secs: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        });
        (config, probes)
    }

    async fn wait(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }

    /// Startup registered every global upstream twice -- once from
    /// `config.upstreams` and once from the flattened config, where global
    /// upstreams appear again -- and every target was probed twice per
    /// interval. Keyed by upstream id, the same upstream can only ever own one
    /// probe loop; measured at the backend, not by counting checkers.
    #[tokio::test]
    async fn an_upstream_registered_twice_is_probed_once_per_interval() {
        init_crypto_provider();
        let (config, probes) = counting_backend(1).await;
        let runner = HealthCheckRunner::new();

        let changes = runner.apply([config.clone(), config]);
        assert_eq!(runner.checker_count(), 1);
        assert_eq!(changes.started, 1);

        // Ticks at ~0 s, 1 s, 2 s, 3 s: four probes, never eight.
        wait(3500).await;
        let n = probes.load(Ordering::SeqCst);
        assert!((3..=5).contains(&n), "expected ~4 probes in 3.5 s, got {n}");
    }

    /// A reload used to leave the checker set exactly as startup built it. The
    /// runner now reconciles: a new check starts probing, a changed one is
    /// restarted with its new settings, and a removed one stops.
    #[tokio::test]
    async fn apply_starts_restarts_and_stops_probe_loops() {
        init_crypto_provider();
        let (with_check, probes) = counting_backend(1).await;
        let mut without_check = with_check.clone();
        without_check.health_check = None;

        let runner = HealthCheckRunner::new();

        // No check configured: nothing probes.
        assert_eq!(
            runner.apply([without_check.clone()]),
            HealthCheckChanges::default()
        );
        wait(1200).await;
        assert_eq!(probes.load(Ordering::SeqCst), 0);

        // Added: probing starts.
        let changes = runner.apply([with_check.clone()]);
        assert_eq!(changes.started, 1);
        wait(1500).await;
        assert!(
            probes.load(Ordering::SeqCst) >= 1,
            "added check never probed"
        );

        // Same config again: the running loop is kept.
        let changes = runner.apply([with_check.clone()]);
        assert_eq!(changes.unchanged, 1);
        assert_eq!(changes.restarted, 0);

        // Changed interval: restarted with the new interval.
        let mut slower = with_check.clone();
        slower.health_check.as_mut().unwrap().interval_secs = 7;
        let changes = runner.apply([slower]);
        assert_eq!(changes.restarted, 1);
        assert_eq!(
            runner.interval_of("test-upstream"),
            Some(Duration::from_secs(7))
        );

        // Removed: probing stops.
        let changes = runner.apply([without_check]);
        assert_eq!(changes.stopped, 1);
        assert_eq!(runner.checker_count(), 0);
        wait(200).await;
        let after_stop = probes.load(Ordering::SeqCst);
        wait(2500).await;
        assert_eq!(
            probes.load(Ordering::SeqCst),
            after_stop,
            "a removed health check kept probing"
        );
    }

    /// Each upstream probes on its own interval. The old single loop ticked at
    /// the smallest interval of all upstreams and probed every one of them on
    /// each tick.
    #[tokio::test]
    async fn each_upstream_probes_on_its_own_interval() {
        init_crypto_provider();
        let (mut fast, fast_probes) = counting_backend(1).await;
        fast.id = "fast".to_string();
        let (mut slow, slow_probes) = counting_backend(10).await;
        slow.id = "slow".to_string();

        let runner = HealthCheckRunner::new();
        runner.apply([fast, slow]);
        wait(3500).await;

        assert!(fast_probes.load(Ordering::SeqCst) >= 3);
        assert_eq!(slow_probes.load(Ordering::SeqCst), 1);
    }

    /// An HTTP backend on 127.0.0.1 only, answering every request with the
    /// status in the returned handle.
    async fn status_backend() -> (u16, Arc<std::sync::atomic::AtomicU16>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
        let current = status.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let code = current.load(Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 {code} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, status)
    }

    fn hostname_config(target: String) -> UpstreamConfig {
        let mut config = create_test_config();
        config.targets[0].address = target;
        config.health_check = Some(HealthCheckConfig {
            check_type: HealthCheckType::Http {
                path: "/health".to_string(),
                expected_status: 200,
                host: None,
            },
            interval_secs: 1,
            timeout_secs: 1,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
        });
        config
    }

    /// A hostname target could not become a Pingora `Backend`, so it was
    /// never probed and always counted as healthy -- and an upstream with only
    /// hostname targets got no checker at all. It is now resolved and probed
    /// at the addresses it resolves to, and reported under its own name,
    /// which is what the pools look up.
    #[tokio::test]
    async fn a_hostname_target_is_probed_and_reported_by_name() {
        init_crypto_provider();
        let (port, status) = status_backend().await;
        let target = format!("localhost:{port}");
        let checker = ActiveHealthChecker::new(&hostname_config(target.clone()))
            .expect("a checker for a hostname-only upstream");

        status.store(500, Ordering::SeqCst);
        checker.run_health_check().await;
        assert!(
            checker.view().is_unhealthy(&target),
            "a failing hostname target stayed healthy: {:?}",
            checker.view().snapshot()
        );

        status.store(200, Ordering::SeqCst);
        checker.run_health_check().await;
        assert!(
            !checker.view().is_unhealthy(&target),
            "a recovered hostname target stayed unhealthy: {:?}",
            checker.view().snapshot()
        );
        // Every address the name resolved to was probed individually too.
        assert!(!checker.view().is_unhealthy(&format!("127.0.0.1:{port}")));
    }

    /// `localhost` resolves to `::1` first on many systems. The backend here
    /// only listens on IPv4, so the checker holds `[::1]` unhealthy while the
    /// name stays healthy -- and the request path has to connect to the
    /// healthy address rather than the first one.
    #[tokio::test]
    async fn requests_go_to_a_healthy_address_of_a_hostname_target() {
        use pingora_core::upstreams::peer::Peer;
        init_crypto_provider();
        let (port, _status) = status_backend().await;
        let config = hostname_config(format!("localhost:{port}"));
        let checker = ActiveHealthChecker::new(&config).expect("checker");
        checker.run_health_check().await;

        let pool = crate::upstream::UpstreamPool::new(config)
            .await
            .expect("pool")
            .with_active_health(checker.view().clone());
        for _ in 0..4 {
            let peer = pool.select_peer(None).await.expect("a peer");
            assert_eq!(peer.address().to_string(), format!("127.0.0.1:{port}"));
        }
    }

    /// A name that does not resolve has nothing to probe, and requests to it
    /// fail too: after `unhealthy-threshold` failed resolutions it is out.
    #[tokio::test]
    async fn an_unresolvable_hostname_becomes_unhealthy_after_the_threshold() {
        init_crypto_provider();
        // `.invalid` never resolves (RFC 2606).
        let target = "zentinel-test.invalid:80".to_string();
        let mut config = hostname_config(target.clone());
        config.health_check.as_mut().unwrap().unhealthy_threshold = 2;
        let checker = ActiveHealthChecker::new(&config).expect("checker");

        checker.run_health_check().await;
        assert!(
            !checker.view().is_unhealthy(&target),
            "one failure is below the threshold"
        );
        checker.run_health_check().await;
        assert!(checker.view().is_unhealthy(&target));
    }
}
