//! Upstream pool management module for Sentinel proxy
//!
//! This module handles upstream server pools, load balancing, health checking,
//! connection pooling, and retry logic with circuit breakers.

use async_trait::async_trait;
use pingora::upstreams::peer::HttpPeer;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::{CircuitBreakerConfig, CircuitBreakerState, LoadBalancingAlgorithm, RetryPolicy, UpstreamId},
};
use sentinel_config::{HealthCheck as HealthCheckConfig, UpstreamConfig};

use crate::types::UpstreamTarget;

// Load balancing algorithm implementations
pub mod adaptive;
pub mod consistent_hash;
pub mod p2c;

// Re-export commonly used types from sub-modules
pub use adaptive::{AdaptiveBalancer, AdaptiveConfig};
pub use consistent_hash::{
    ConsistentHashBalancer, ConsistentHashConfig,
};
pub use p2c::{P2cBalancer, P2cConfig};

/// Request context for load balancer decisions
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub client_ip: Option<std::net::SocketAddr>,
    pub headers: HashMap<String, String>,
    pub path: String,
    pub method: String,
}

/// Load balancer trait for different algorithms
#[async_trait]
pub trait LoadBalancer: Send + Sync {
    /// Select next upstream target
    async fn select(&self, context: Option<&RequestContext>) -> SentinelResult<TargetSelection>;

    /// Report target health status
    async fn report_health(&self, address: &str, healthy: bool);

    /// Get all healthy targets
    async fn healthy_targets(&self) -> Vec<String>;

    /// Release connection (for connection tracking)
    async fn release(&self, _selection: &TargetSelection) {
        // Default implementation - no-op
    }

    /// Report request result (for adaptive algorithms)
    async fn report_result(
        &self,
        _selection: &TargetSelection,
        _success: bool,
        _latency: Option<Duration>,
    ) {
        // Default implementation - no-op
    }
}

/// Selected upstream target
#[derive(Debug, Clone)]
pub struct TargetSelection {
    /// Target address
    pub address: String,
    /// Target weight
    pub weight: u32,
    /// Target metadata
    pub metadata: HashMap<String, String>,
}

/// Upstream pool managing multiple backend servers
pub struct UpstreamPool {
    /// Pool identifier
    id: UpstreamId,
    /// Configured targets
    targets: Vec<UpstreamTarget>,
    /// Load balancer implementation
    load_balancer: Arc<dyn LoadBalancer>,
    /// Health checker
    health_checker: Option<Arc<HealthChecker>>,
    /// Connection pool
    connection_pool: Arc<ConnectionPool>,
    /// Circuit breakers per target
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    /// Retry policy
    retry_policy: Option<RetryPolicy>,
    /// Pool statistics
    stats: Arc<PoolStats>,
}

/// Health checker for upstream targets
pub struct HealthChecker {
    /// Check configuration
    config: HealthCheckConfig,
    /// Health status per target
    health_status: Arc<RwLock<HashMap<String, HealthStatus>>>,
    /// Check tasks handles
    check_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

impl HealthChecker {
    /// Create a new health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            health_status: Arc::new(RwLock::new(HashMap::new())),
            check_handles: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

/// Health status for a target
#[derive(Debug, Clone)]
struct HealthStatus {
    /// Is target healthy
    healthy: bool,
    /// Consecutive successes
    consecutive_successes: u32,
    /// Consecutive failures
    consecutive_failures: u32,
    /// Last check time
    last_check: Instant,
    /// Last successful check
    last_success: Option<Instant>,
    /// Last error message
    last_error: Option<String>,
}

/// Connection pool for upstream connections
pub struct ConnectionPool {
    /// Pool configuration
    max_connections: usize,
    max_idle: usize,
    idle_timeout: Duration,
    max_lifetime: Option<Duration>,
    /// Active connections per target
    connections: Arc<RwLock<HashMap<String, Vec<PooledConnection>>>>,
    /// Connection statistics
    stats: Arc<ConnectionPoolStats>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(
        max_connections: usize,
        max_idle: usize,
        idle_timeout: Duration,
        max_lifetime: Option<Duration>,
    ) -> Self {
        Self {
            max_connections,
            max_idle,
            idle_timeout,
            max_lifetime,
            connections: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(ConnectionPoolStats::default()),
        }
    }

    /// Acquire a connection from the pool
    pub async fn acquire(&self, _address: &str) -> SentinelResult<Option<HttpPeer>> {
        // TODO: Implement actual connection pooling logic
        // For now, return None to always create new connections
        Ok(None)
    }

    /// Close all connections in the pool
    pub async fn close_all(&self) {
        let mut connections = self.connections.write().await;
        connections.clear();
    }
}

/// Pooled connection wrapper
struct PooledConnection {
    /// The actual connection/peer
    peer: HttpPeer,
    /// Creation time
    created: Instant,
    /// Last used time
    last_used: Instant,
    /// Is currently in use
    in_use: bool,
}

/// Connection pool statistics
#[derive(Default)]
struct ConnectionPoolStats {
    /// Total connections created
    created: AtomicU64,
    /// Total connections reused
    reused: AtomicU64,
    /// Total connections closed
    closed: AtomicU64,
    /// Current active connections
    active: AtomicU64,
    /// Current idle connections
    idle: AtomicU64,
}

/// Circuit breaker for upstream protection
pub struct CircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// Current state
    state: Arc<RwLock<CircuitBreakerState>>,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Consecutive successes
    consecutive_successes: AtomicU64,
    /// Last state change time
    last_state_change: Arc<RwLock<Instant>>,
    /// Half-open requests count
    half_open_requests: AtomicU64,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
            half_open_requests: AtomicU64::new(0),
        }
    }

    async fn is_closed(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                let last_change = *self.last_state_change.read().await;
                if last_change.elapsed() >= Duration::from_secs(self.config.timeout_seconds) {
                    self.transition_to_half_open().await;
                    false
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => {
                self.half_open_requests.fetch_add(1, Ordering::Relaxed)
                    < self.config.half_open_max_requests.into()
            }
        }
    }

    async fn record_success(&self) {
        let state = *self.state.read().await;

        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

        if let CircuitBreakerState::HalfOpen = state {
            if successes >= self.config.success_threshold.into() {
                self.transition_to_closed().await;
            }
        }
    }

    async fn record_failure(&self) {
        let state = *self.state.read().await;

        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        match state {
            CircuitBreakerState::Closed => {
                if failures >= self.config.failure_threshold.into() {
                    self.transition_to_open().await;
                }
            }
            CircuitBreakerState::HalfOpen => {
                self.transition_to_open().await;
            }
            _ => {}
        }
    }

    async fn transition_to_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::Open;
        *self.last_state_change.write().await = Instant::now();
        warn!("Circuit breaker opened");
    }

    async fn transition_to_closed(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::Closed;
        *self.last_state_change.write().await = Instant::now();
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.half_open_requests.store(0, Ordering::Relaxed);
        info!("Circuit breaker closed");
    }

    async fn transition_to_half_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::HalfOpen;
        *self.last_state_change.write().await = Instant::now();
        self.half_open_requests.store(0, Ordering::Relaxed);
        info!("Circuit breaker half-open");
    }
}

/// Pool statistics
#[derive(Default)]
pub struct PoolStats {
    /// Total requests
    pub requests: AtomicU64,
    /// Successful requests
    pub successes: AtomicU64,
    /// Failed requests
    pub failures: AtomicU64,
    /// Retried requests
    pub retries: AtomicU64,
    /// Circuit breaker trips
    pub circuit_breaker_trips: AtomicU64,
}

/// Round-robin load balancer
struct RoundRobinBalancer {
    targets: Vec<UpstreamTarget>,
    current: AtomicUsize,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}

impl RoundRobinBalancer {
    fn new(targets: Vec<UpstreamTarget>) -> Self {
        let mut health_status = HashMap::new();
        for target in &targets {
            health_status.insert(target.full_address(), true);
        }

        Self {
            targets,
            current: AtomicUsize::new(0),
            health_status: Arc::new(RwLock::new(health_status)),
        }
    }
}

#[async_trait]
impl LoadBalancer for RoundRobinBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        let health = self.health_status.read().await;
        let healthy_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();

        if healthy_targets.is_empty() {
            return Err(SentinelError::NoHealthyUpstream);
        }

        let index = self.current.fetch_add(1, Ordering::Relaxed) % healthy_targets.len();
        let target = healthy_targets[index];

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);
    }

    async fn healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(addr, &healthy)| if healthy { Some(addr.clone()) } else { None })
            .collect()
    }
}

/// Least connections load balancer
struct LeastConnectionsBalancer {
    targets: Vec<UpstreamTarget>,
    connections: Arc<RwLock<HashMap<String, usize>>>,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}

impl LeastConnectionsBalancer {
    fn new(targets: Vec<UpstreamTarget>) -> Self {
        let mut health_status = HashMap::new();
        let mut connections = HashMap::new();

        for target in &targets {
            let addr = target.full_address();
            health_status.insert(addr.clone(), true);
            connections.insert(addr, 0);
        }

        Self {
            targets,
            connections: Arc::new(RwLock::new(connections)),
            health_status: Arc::new(RwLock::new(health_status)),
        }
    }
}

#[async_trait]
impl LoadBalancer for LeastConnectionsBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        let health = self.health_status.read().await;
        let conns = self.connections.read().await;

        let mut best_target = None;
        let mut min_connections = usize::MAX;

        for target in &self.targets {
            let addr = target.full_address();
            if !*health.get(&addr).unwrap_or(&true) {
                continue;
            }

            let conn_count = *conns.get(&addr).unwrap_or(&0);
            if conn_count < min_connections {
                min_connections = conn_count;
                best_target = Some(target);
            }
        }

        best_target
            .map(|target| TargetSelection {
                address: target.full_address(),
                weight: target.weight,
                metadata: HashMap::new(),
            })
            .ok_or(SentinelError::NoHealthyUpstream)
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);
    }

    async fn healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(addr, &healthy)| if healthy { Some(addr.clone()) } else { None })
            .collect()
    }
}

/// Weighted load balancer
struct WeightedBalancer {
    targets: Vec<UpstreamTarget>,
    weights: Vec<u32>,
    current_index: AtomicUsize,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}

#[async_trait]
impl LoadBalancer for WeightedBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        let health = self.health_status.read().await;
        let healthy_indices: Vec<_> = self
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| *health.get(&t.full_address()).unwrap_or(&true))
            .map(|(i, _)| i)
            .collect();

        if healthy_indices.is_empty() {
            return Err(SentinelError::NoHealthyUpstream);
        }

        let idx = self.current_index.fetch_add(1, Ordering::Relaxed) % healthy_indices.len();
        let target_idx = healthy_indices[idx];
        let target = &self.targets[target_idx];

        Ok(TargetSelection {
            address: target.full_address(),
            weight: self.weights.get(target_idx).copied().unwrap_or(1),
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);
    }

    async fn healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(addr, &healthy)| if healthy { Some(addr.clone()) } else { None })
            .collect()
    }
}

/// IP hash load balancer
struct IpHashBalancer {
    targets: Vec<UpstreamTarget>,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}

#[async_trait]
impl LoadBalancer for IpHashBalancer {
    async fn select(&self, context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        let health = self.health_status.read().await;
        let healthy_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();

        if healthy_targets.is_empty() {
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Hash the client IP to select a target
        let hash = if let Some(ctx) = context {
            if let Some(ip) = &ctx.client_ip {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                ip.hash(&mut hasher);
                hasher.finish()
            } else {
                0
            }
        } else {
            0
        };

        let idx = (hash as usize) % healthy_targets.len();
        let target = healthy_targets[idx];

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);
    }

    async fn healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(addr, &healthy)| if healthy { Some(addr.clone()) } else { None })
            .collect()
    }
}

impl UpstreamPool {
    /// Create new upstream pool from configuration
    pub async fn new(config: UpstreamConfig) -> SentinelResult<Self> {
        let id = UpstreamId::new(&config.id);

        // Convert config targets to internal targets
        let targets: Vec<UpstreamTarget> = config
            .targets
            .iter()
            .filter_map(|t| UpstreamTarget::from_config(t))
            .collect();

        if targets.is_empty() {
            return Err(SentinelError::Config {
                message: "No valid upstream targets".to_string(),
                source: None,
            });
        }

        // Create load balancer
        let load_balancer = Self::create_load_balancer(&config.load_balancing, &targets)?;

        // Create health checker if configured
        let health_checker = config
            .health_check
            .as_ref()
            .map(|hc_config| Arc::new(HealthChecker::new(hc_config.clone())));

        // Create connection pool
        let connection_pool = Arc::new(ConnectionPool::new(
            config.connection_pool.max_connections,
            config.connection_pool.max_idle,
            Duration::from_secs(config.connection_pool.idle_timeout_secs),
            config
                .connection_pool
                .max_lifetime_secs
                .map(Duration::from_secs),
        ));

        // Initialize circuit breakers for each target
        let mut circuit_breakers = HashMap::new();
        for target in &targets {
            circuit_breakers.insert(
                target.full_address(),
                CircuitBreaker::new(CircuitBreakerConfig::default()),
            );
        }

        let pool = Self {
            id,
            targets,
            load_balancer,
            health_checker,
            connection_pool,
            circuit_breakers: Arc::new(RwLock::new(circuit_breakers)),
            retry_policy: None,
            stats: Arc::new(PoolStats::default()),
        };

        Ok(pool)
    }

    /// Create load balancer based on algorithm
    fn create_load_balancer(
        algorithm: &LoadBalancingAlgorithm,
        targets: &[UpstreamTarget],
    ) -> SentinelResult<Arc<dyn LoadBalancer>> {
        let balancer: Arc<dyn LoadBalancer> = match algorithm {
            LoadBalancingAlgorithm::RoundRobin => {
                Arc::new(RoundRobinBalancer::new(targets.to_vec()))
            }
            LoadBalancingAlgorithm::LeastConnections => {
                Arc::new(LeastConnectionsBalancer::new(targets.to_vec()))
            }
            LoadBalancingAlgorithm::Weighted => {
                let weights: Vec<u32> = targets.iter().map(|t| t.weight).collect();
                Arc::new(WeightedBalancer {
                    targets: targets.to_vec(),
                    weights,
                    current_index: AtomicUsize::new(0),
                    health_status: Arc::new(RwLock::new(HashMap::new())),
                })
            }
            LoadBalancingAlgorithm::IpHash => Arc::new(IpHashBalancer {
                targets: targets.to_vec(),
                health_status: Arc::new(RwLock::new(HashMap::new())),
            }),
            LoadBalancingAlgorithm::Random => {
                Arc::new(RoundRobinBalancer::new(targets.to_vec()))
            }
            LoadBalancingAlgorithm::ConsistentHash => Arc::new(ConsistentHashBalancer::new(
                targets.to_vec(),
                ConsistentHashConfig::default(),
            )),
            LoadBalancingAlgorithm::PowerOfTwoChoices => {
                Arc::new(P2cBalancer::new(targets.to_vec(), P2cConfig::default()))
            }
            LoadBalancingAlgorithm::Adaptive => Arc::new(AdaptiveBalancer::new(
                targets.to_vec(),
                AdaptiveConfig::default(),
            )),
        };
        Ok(balancer)
    }

    /// Select next upstream peer
    pub async fn select_peer(&self, context: Option<&RequestContext>) -> SentinelResult<HttpPeer> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);

        let mut attempts = 0;
        let max_attempts = self.targets.len() * 2;

        while attempts < max_attempts {
            attempts += 1;

            let selection = self.load_balancer.select(context).await?;

            // Check circuit breaker
            let breakers = self.circuit_breakers.read().await;
            if let Some(breaker) = breakers.get(&selection.address) {
                if !breaker.is_closed().await {
                    debug!(
                        target = %selection.address,
                        "Circuit breaker is open, skipping target"
                    );
                    continue;
                }
            }

            // Try to get connection from pool
            if let Some(peer) = self.connection_pool.acquire(&selection.address).await? {
                debug!(target = %selection.address, "Reusing pooled connection");
                return Ok(peer);
            }

            // Create new connection
            debug!(target = %selection.address, "Creating new connection");
            let peer = self.create_peer(&selection)?;

            self.stats.successes.fetch_add(1, Ordering::Relaxed);
            return Ok(peer);
        }

        self.stats.failures.fetch_add(1, Ordering::Relaxed);
        Err(SentinelError::upstream(
            &self.id.to_string(),
            "Failed to select upstream after max attempts",
        ))
    }

    /// Create new peer connection
    fn create_peer(&self, selection: &TargetSelection) -> SentinelResult<HttpPeer> {
        let peer = HttpPeer::new(
            &selection.address,
            false,
            String::new(),
        );
        Ok(peer)
    }

    /// Report connection result for a target
    pub async fn report_result(&self, target: &str, success: bool) {
        if success {
            if let Some(breaker) = self.circuit_breakers.read().await.get(target) {
                breaker.record_success().await;
            }
            self.load_balancer.report_health(target, true).await;
        } else {
            if let Some(breaker) = self.circuit_breakers.read().await.get(target) {
                breaker.record_failure().await;
            }
            self.load_balancer.report_health(target, false).await;
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Shutdown the pool
    pub async fn shutdown(&self) {
        info!("Shutting down upstream pool: {}", self.id);
        self.connection_pool.close_all().await;
    }
}
