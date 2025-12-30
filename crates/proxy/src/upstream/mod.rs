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
use tracing::{debug, error, info, trace, warn};

use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::{CircuitBreakerConfig, LoadBalancingAlgorithm},
    CircuitBreaker, UpstreamId,
};
use sentinel_config::UpstreamConfig;

// ============================================================================
// Internal Upstream Target Type
// ============================================================================

/// Internal upstream target representation for load balancers
///
/// This is a simplified representation used internally by load balancers,
/// separate from the user-facing config UpstreamTarget.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// Target IP address or hostname
    pub address: String,
    /// Target port
    pub port: u16,
    /// Weight for weighted load balancing
    pub weight: u32,
}

impl UpstreamTarget {
    /// Create a new upstream target
    pub fn new(address: impl Into<String>, port: u16, weight: u32) -> Self {
        Self {
            address: address.into(),
            port,
            weight,
        }
    }

    /// Create from a "host:port" string with default weight
    pub fn from_address(addr: &str) -> Option<Self> {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port = parts[0].parse().ok()?;
            let address = parts[1].to_string();
            Some(Self {
                address,
                port,
                weight: 100,
            })
        } else {
            None
        }
    }

    /// Convert from config UpstreamTarget
    pub fn from_config(config: &sentinel_config::UpstreamTarget) -> Option<Self> {
        Self::from_address(&config.address).map(|mut t| {
            t.weight = config.weight;
            t
        })
    }

    /// Get the full address string
    pub fn full_address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

// ============================================================================
// Load Balancing
// ============================================================================

// Load balancing algorithm implementations
pub mod adaptive;
pub mod consistent_hash;
pub mod health;
pub mod p2c;

// Re-export commonly used types from sub-modules
pub use adaptive::{AdaptiveBalancer, AdaptiveConfig};
pub use consistent_hash::{
    ConsistentHashBalancer, ConsistentHashConfig,
};
pub use health::{ActiveHealthChecker, HealthCheckRunner};
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
    /// Connection pool configuration (Pingora handles actual pooling)
    pool_config: ConnectionPoolConfig,
    /// HTTP version configuration
    http_version: HttpVersionOptions,
    /// Whether TLS is enabled for this upstream
    tls_enabled: bool,
    /// SNI for TLS connections
    tls_sni: Option<String>,
    /// Circuit breakers per target
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    /// Pool statistics
    stats: Arc<PoolStats>,
}

// Note: Active health checking is handled by the PassiveHealthChecker in health.rs
// and via load balancer health reporting. A future enhancement could add active
// HTTP/TCP health probes here.

/// Connection pool configuration for Pingora's built-in pooling
///
/// Note: Actual connection pooling is handled by Pingora internally.
/// This struct holds configuration that is applied to peer options.
pub struct ConnectionPoolConfig {
    /// Maximum idle timeout for pooled connections
    pub idle_timeout: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
}

/// HTTP version configuration for upstream connections
pub struct HttpVersionOptions {
    /// Minimum HTTP version (1 or 2)
    pub min_version: u8,
    /// Maximum HTTP version (1 or 2)
    pub max_version: u8,
    /// H2 ping interval (0 to disable)
    pub h2_ping_interval: Duration,
    /// Maximum concurrent H2 streams per connection
    pub max_h2_streams: usize,
}

impl ConnectionPoolConfig {
    /// Create a new connection pool configuration
    pub fn new(idle_timeout_secs: u64) -> Self {
        Self {
            idle_timeout: Duration::from_secs(idle_timeout_secs),
            connection_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
        }
    }
}

// CircuitBreaker is imported from sentinel_common

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
        trace!(
            total_targets = self.targets.len(),
            algorithm = "round_robin",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let healthy_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();

        if healthy_targets.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "round_robin",
                "No healthy upstream targets available"
            );
            return Err(SentinelError::NoHealthyUpstream);
        }

        let index = self.current.fetch_add(1, Ordering::Relaxed) % healthy_targets.len();
        let target = healthy_targets[index];

        trace!(
            selected_target = %target.full_address(),
            healthy_count = healthy_targets.len(),
            index = index,
            algorithm = "round_robin",
            "Selected target via round robin"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "round_robin",
            "Updating target health status"
        );
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
        trace!(
            total_targets = self.targets.len(),
            algorithm = "least_connections",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let conns = self.connections.read().await;

        let mut best_target = None;
        let mut min_connections = usize::MAX;

        for target in &self.targets {
            let addr = target.full_address();
            if !*health.get(&addr).unwrap_or(&true) {
                trace!(
                    target = %addr,
                    algorithm = "least_connections",
                    "Skipping unhealthy target"
                );
                continue;
            }

            let conn_count = *conns.get(&addr).unwrap_or(&0);
            trace!(
                target = %addr,
                connections = conn_count,
                "Evaluating target connection count"
            );
            if conn_count < min_connections {
                min_connections = conn_count;
                best_target = Some(target);
            }
        }

        match best_target {
            Some(target) => {
                trace!(
                    selected_target = %target.full_address(),
                    connections = min_connections,
                    algorithm = "least_connections",
                    "Selected target with fewest connections"
                );
                Ok(TargetSelection {
                    address: target.full_address(),
                    weight: target.weight,
                    metadata: HashMap::new(),
                })
            }
            None => {
                warn!(
                    total_targets = self.targets.len(),
                    algorithm = "least_connections",
                    "No healthy upstream targets available"
                );
                Err(SentinelError::NoHealthyUpstream)
            }
        }
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "least_connections",
            "Updating target health status"
        );
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
        trace!(
            total_targets = self.targets.len(),
            algorithm = "weighted",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let healthy_indices: Vec<_> = self
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| *health.get(&t.full_address()).unwrap_or(&true))
            .map(|(i, _)| i)
            .collect();

        if healthy_indices.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "weighted",
                "No healthy upstream targets available"
            );
            return Err(SentinelError::NoHealthyUpstream);
        }

        let idx = self.current_index.fetch_add(1, Ordering::Relaxed) % healthy_indices.len();
        let target_idx = healthy_indices[idx];
        let target = &self.targets[target_idx];
        let weight = self.weights.get(target_idx).copied().unwrap_or(1);

        trace!(
            selected_target = %target.full_address(),
            weight = weight,
            healthy_count = healthy_indices.len(),
            algorithm = "weighted",
            "Selected target via weighted round robin"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight,
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "weighted",
            "Updating target health status"
        );
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
        trace!(
            total_targets = self.targets.len(),
            algorithm = "ip_hash",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let healthy_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();

        if healthy_targets.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "ip_hash",
                "No healthy upstream targets available"
            );
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Hash the client IP to select a target
        let (hash, client_ip_str) = if let Some(ctx) = context {
            if let Some(ip) = &ctx.client_ip {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                ip.hash(&mut hasher);
                (hasher.finish(), Some(ip.to_string()))
            } else {
                (0, None)
            }
        } else {
            (0, None)
        };

        let idx = (hash as usize) % healthy_targets.len();
        let target = healthy_targets[idx];

        trace!(
            selected_target = %target.full_address(),
            client_ip = client_ip_str.as_deref().unwrap_or("unknown"),
            hash = hash,
            index = idx,
            healthy_count = healthy_targets.len(),
            algorithm = "ip_hash",
            "Selected target via IP hash"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "ip_hash",
            "Updating target health status"
        );
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

        info!(
            upstream_id = %config.id,
            target_count = config.targets.len(),
            algorithm = ?config.load_balancing,
            "Creating upstream pool"
        );

        // Convert config targets to internal targets
        let targets: Vec<UpstreamTarget> = config
            .targets
            .iter()
            .filter_map(|t| UpstreamTarget::from_config(t))
            .collect();

        if targets.is_empty() {
            error!(
                upstream_id = %config.id,
                "No valid upstream targets configured"
            );
            return Err(SentinelError::Config {
                message: "No valid upstream targets".to_string(),
                source: None,
            });
        }

        for target in &targets {
            debug!(
                upstream_id = %config.id,
                target = %target.full_address(),
                weight = target.weight,
                "Registered upstream target"
            );
        }

        // Create load balancer
        debug!(
            upstream_id = %config.id,
            algorithm = ?config.load_balancing,
            "Creating load balancer"
        );
        let load_balancer = Self::create_load_balancer(&config.load_balancing, &targets)?;

        // Create connection pool configuration (Pingora handles actual pooling)
        debug!(
            upstream_id = %config.id,
            idle_timeout_secs = config.connection_pool.idle_timeout_secs,
            "Creating connection pool configuration"
        );
        let pool_config = ConnectionPoolConfig::new(config.connection_pool.idle_timeout_secs);

        // Create HTTP version configuration
        let http_version = HttpVersionOptions {
            min_version: config.http_version.min_version,
            max_version: config.http_version.max_version,
            h2_ping_interval: if config.http_version.h2_ping_interval_secs > 0 {
                Duration::from_secs(config.http_version.h2_ping_interval_secs)
            } else {
                Duration::ZERO
            },
            max_h2_streams: config.http_version.max_h2_streams,
        };

        // TLS configuration
        let tls_enabled = config.tls.is_some();
        let tls_sni = config.tls.as_ref().and_then(|t| t.sni.clone());

        if http_version.max_version >= 2 && tls_enabled {
            info!(
                upstream_id = %config.id,
                "HTTP/2 enabled for upstream (via ALPN)"
            );
        }

        // Initialize circuit breakers for each target
        let mut circuit_breakers = HashMap::new();
        for target in &targets {
            trace!(
                upstream_id = %config.id,
                target = %target.full_address(),
                "Initializing circuit breaker for target"
            );
            circuit_breakers.insert(
                target.full_address(),
                CircuitBreaker::new(CircuitBreakerConfig::default()),
            );
        }

        let pool = Self {
            id: id.clone(),
            targets,
            load_balancer,
            pool_config,
            http_version,
            tls_enabled,
            tls_sni,
            circuit_breakers: Arc::new(RwLock::new(circuit_breakers)),
            stats: Arc::new(PoolStats::default()),
        };

        info!(
            upstream_id = %id,
            target_count = pool.targets.len(),
            "Upstream pool created successfully"
        );

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
        let request_num = self.stats.requests.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            upstream_id = %self.id,
            request_num = request_num,
            target_count = self.targets.len(),
            "Starting peer selection"
        );

        let mut attempts = 0;
        let max_attempts = self.targets.len() * 2;

        while attempts < max_attempts {
            attempts += 1;

            trace!(
                upstream_id = %self.id,
                attempt = attempts,
                max_attempts = max_attempts,
                "Attempting to select peer"
            );

            let selection = match self.load_balancer.select(context).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(
                        upstream_id = %self.id,
                        attempt = attempts,
                        error = %e,
                        "Load balancer selection failed"
                    );
                    continue;
                }
            };

            trace!(
                upstream_id = %self.id,
                target = %selection.address,
                attempt = attempts,
                "Load balancer selected target"
            );

            // Check circuit breaker
            let breakers = self.circuit_breakers.read().await;
            if let Some(breaker) = breakers.get(&selection.address) {
                if !breaker.is_closed().await {
                    debug!(
                        upstream_id = %self.id,
                        target = %selection.address,
                        attempt = attempts,
                        "Circuit breaker is open, skipping target"
                    );
                    self.stats.circuit_breaker_trips.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }

            // Create peer with pooling options
            // Note: Pingora handles actual connection pooling internally based on
            // peer.options.idle_timeout and ServerConf.upstream_keepalive_pool_size
            trace!(
                upstream_id = %self.id,
                target = %selection.address,
                "Creating peer for upstream (Pingora handles connection reuse)"
            );
            let peer = self.create_peer(&selection)?;

            debug!(
                upstream_id = %self.id,
                target = %selection.address,
                attempt = attempts,
                "Selected upstream peer"
            );

            self.stats.successes.fetch_add(1, Ordering::Relaxed);
            return Ok(peer);
        }

        self.stats.failures.fetch_add(1, Ordering::Relaxed);
        error!(
            upstream_id = %self.id,
            attempts = attempts,
            max_attempts = max_attempts,
            "Failed to select upstream after max attempts"
        );
        Err(SentinelError::upstream(
            &self.id.to_string(),
            "Failed to select upstream after max attempts",
        ))
    }

    /// Create new peer connection with connection pooling options
    ///
    /// Pingora handles actual connection pooling internally. When idle_timeout
    /// is set on the peer options, Pingora will keep the connection alive and
    /// reuse it for subsequent requests to the same upstream.
    fn create_peer(&self, selection: &TargetSelection) -> SentinelResult<HttpPeer> {
        // Determine SNI hostname for TLS connections
        let sni_hostname = self.tls_sni.clone().unwrap_or_else(|| {
            // Extract hostname from address (strip port)
            selection.address.split(':').next().unwrap_or(&selection.address).to_string()
        });

        let mut peer = HttpPeer::new(
            &selection.address,
            self.tls_enabled,
            sni_hostname.clone(),
        );

        // Configure connection pooling options for better performance
        // idle_timeout enables Pingora's connection pooling - connections are
        // kept alive and reused for this duration
        peer.options.idle_timeout = Some(self.pool_config.idle_timeout);

        // Connection timeouts
        peer.options.connection_timeout = Some(self.pool_config.connection_timeout);
        peer.options.total_connection_timeout = Some(Duration::from_secs(10));

        // Read/write timeouts
        peer.options.read_timeout = Some(self.pool_config.read_timeout);
        peer.options.write_timeout = Some(self.pool_config.write_timeout);

        // Enable TCP keepalive for long-lived connections
        peer.options.tcp_keepalive = Some(pingora::protocols::TcpKeepalive {
            idle: Duration::from_secs(60),
            interval: Duration::from_secs(10),
            count: 3,
            // user_timeout is Linux-only
            #[cfg(target_os = "linux")]
            user_timeout: Duration::from_secs(60),
        });

        // Configure HTTP version and ALPN for TLS connections
        if self.tls_enabled {
            // Set ALPN protocols based on configured HTTP version range
            let alpn = match (self.http_version.min_version, self.http_version.max_version) {
                (2, _) => {
                    // HTTP/2 only - use h2 ALPN
                    pingora::upstreams::peer::ALPN::H2
                }
                (1, 2) | (_, 2) => {
                    // Prefer HTTP/2 but fall back to HTTP/1.1
                    pingora::upstreams::peer::ALPN::H2H1
                }
                _ => {
                    // HTTP/1.1 only
                    pingora::upstreams::peer::ALPN::H1
                }
            };
            peer.options.alpn = alpn;

            trace!(
                upstream_id = %self.id,
                target = %selection.address,
                alpn = ?peer.options.alpn,
                min_version = self.http_version.min_version,
                max_version = self.http_version.max_version,
                "Configured ALPN for HTTP version negotiation"
            );
        }

        // Configure H2-specific settings when HTTP/2 is enabled
        if self.http_version.max_version >= 2 {
            // H2 ping interval for connection health monitoring
            if !self.http_version.h2_ping_interval.is_zero() {
                peer.options.h2_ping_interval = Some(self.http_version.h2_ping_interval);
                trace!(
                    upstream_id = %self.id,
                    target = %selection.address,
                    h2_ping_interval_secs = self.http_version.h2_ping_interval.as_secs(),
                    "Configured H2 ping interval"
                );
            }
        }

        trace!(
            upstream_id = %self.id,
            target = %selection.address,
            tls = self.tls_enabled,
            sni = %sni_hostname,
            idle_timeout_secs = self.pool_config.idle_timeout.as_secs(),
            http_max_version = self.http_version.max_version,
            "Created peer with Pingora connection pooling enabled"
        );

        Ok(peer)
    }

    /// Report connection result for a target
    pub async fn report_result(&self, target: &str, success: bool) {
        trace!(
            upstream_id = %self.id,
            target = %target,
            success = success,
            "Reporting connection result"
        );

        if success {
            if let Some(breaker) = self.circuit_breakers.read().await.get(target) {
                breaker.record_success().await;
                trace!(
                    upstream_id = %self.id,
                    target = %target,
                    "Recorded success in circuit breaker"
                );
            }
            self.load_balancer.report_health(target, true).await;
        } else {
            if let Some(breaker) = self.circuit_breakers.read().await.get(target) {
                breaker.record_failure().await;
                debug!(
                    upstream_id = %self.id,
                    target = %target,
                    "Recorded failure in circuit breaker"
                );
            }
            self.load_balancer.report_health(target, false).await;
            self.stats.failures.fetch_add(1, Ordering::Relaxed);
            warn!(
                upstream_id = %self.id,
                target = %target,
                "Connection failure reported for target"
            );
        }
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolStats {
        &self.stats
    }

    /// Shutdown the pool
    ///
    /// Note: Pingora manages connection pooling internally, so we just log stats.
    pub async fn shutdown(&self) {
        info!(
            upstream_id = %self.id,
            target_count = self.targets.len(),
            total_requests = self.stats.requests.load(Ordering::Relaxed),
            total_successes = self.stats.successes.load(Ordering::Relaxed),
            total_failures = self.stats.failures.load(Ordering::Relaxed),
            "Shutting down upstream pool"
        );
        // Pingora handles connection cleanup internally
        debug!(upstream_id = %self.id, "Upstream pool shutdown complete");
    }
}
