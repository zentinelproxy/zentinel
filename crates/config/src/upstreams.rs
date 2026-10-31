//! Upstream configuration types
//!
//! This module contains configuration types for upstream backends
//! including load balancing, health checks, and connection pooling.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

use zentinel_common::{
    types::{HealthCheckType, LoadBalancingAlgorithm},
    CircuitBreakerConfig,
};

// ============================================================================
// Sticky Session Configuration
// ============================================================================

/// Cookie SameSite policy for sticky session cookies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SameSitePolicy {
    /// Lax - Cookies sent with top-level navigations and GET from third-party sites
    #[default]
    Lax,
    /// Strict - Cookies only sent in first-party context
    Strict,
    /// None - Cookies sent in all contexts (requires Secure)
    None,
}

impl std::fmt::Display for SameSitePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSitePolicy::Lax => write!(f, "Lax"),
            SameSitePolicy::Strict => write!(f, "Strict"),
            SameSitePolicy::None => write!(f, "None"),
        }
    }
}

/// Configuration for cookie-based sticky sessions
///
/// When enabled, the load balancer will set an affinity cookie on responses
/// and use it to route subsequent requests to the same backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickySessionConfig {
    /// Cookie name for session affinity (e.g., "SERVERID")
    pub cookie_name: String,

    /// Cookie TTL in seconds (e.g., 3600 for 1 hour)
    pub cookie_ttl_secs: u64,

    /// Cookie path (e.g., "/")
    #[serde(default = "default_cookie_path")]
    pub cookie_path: String,

    /// Whether to set Secure and HttpOnly flags on the cookie
    #[serde(default = "default_cookie_secure")]
    pub cookie_secure: bool,

    /// SameSite policy for the cookie
    #[serde(default)]
    pub cookie_same_site: SameSitePolicy,

    /// Fallback load balancing algorithm when no cookie or target unavailable
    #[serde(default = "default_sticky_fallback")]
    pub fallback: LoadBalancingAlgorithm,
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_cookie_secure() -> bool {
    true
}

fn default_sticky_fallback() -> LoadBalancingAlgorithm {
    LoadBalancingAlgorithm::RoundRobin
}

// ============================================================================
// Upstream Configuration
// ============================================================================

/// Upstream configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpstreamConfig {
    /// Unique upstream identifier
    pub id: String,

    /// Upstream targets.
    ///
    /// May be empty when `discovery` is set; the emptiness check lives in
    /// `validate_targets_present` rather than a `length(min = 1)` attribute so
    /// it can take `discovery` into account.
    pub targets: Vec<UpstreamTarget>,

    /// Load balancing algorithm
    #[serde(default = "default_lb_algorithm")]
    pub load_balancing: LoadBalancingAlgorithm,

    /// Sticky session configuration (for cookie-based session affinity)
    pub sticky_session: Option<StickySessionConfig>,

    /// Health check configuration
    pub health_check: Option<HealthCheck>,

    /// Optional circuit breaker configuration
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Connection pool settings
    #[serde(default)]
    pub connection_pool: ConnectionPoolConfig,

    /// Timeouts
    #[serde(default)]
    pub timeouts: UpstreamTimeouts,

    /// TLS configuration for upstream connections
    pub tls: Option<UpstreamTlsConfig>,

    /// HTTP version configuration
    #[serde(default)]
    pub http_version: HttpVersionConfig,

    /// Service discovery source for this upstream's targets.
    ///
    /// When set, `targets` may be left empty in the configuration: the pool is
    /// populated from the discovery source at startup and refreshed on the
    /// source's interval. Statically configured targets are kept and the
    /// discovered ones are added to them, so a fixed target can be pinned
    /// alongside a discovered set.
    #[serde(default)]
    pub discovery: Option<UpstreamDiscovery>,
}

// ============================================================================
// Service Discovery
// ============================================================================

/// Where an upstream's targets come from, when they are not listed statically.
///
/// This mirrors the discovery backends implemented in `zentinel-proxy`'s
/// `discovery` module. It is a separate type because `zentinel-config` may not
/// depend on the proxy crate, and because the configuration surface is
/// deliberately narrower than the runtime one: intervals are plain seconds
/// here and become `Duration`s on conversion.
///
/// Every variant carries its own refresh interval. The pool is populated once
/// before it starts serving traffic and re-resolved on that interval for as
/// long as the proxy runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum UpstreamDiscovery {
    /// A fixed list of backends. Equivalent to listing `target` nodes, and
    /// present so that a config can be moved between discovery backends
    /// without changing shape.
    Static {
        /// Backend addresses in `host:port` form.
        backends: Vec<String>,
    },

    /// A/AAAA records for a hostname, one target per address returned.
    Dns {
        /// Hostname to resolve.
        hostname: String,
        /// Port to pair with every resolved address.
        port: u16,
        /// Seconds between re-resolutions.
        #[serde(default = "default_refresh_interval")]
        refresh_interval_secs: u64,
    },

    /// SRV records, which carry the port and weight themselves.
    DnsSrv {
        /// Full SRV name, e.g. `_http._tcp.example.com`.
        service: String,
        /// Seconds between re-resolutions.
        #[serde(default = "default_refresh_interval")]
        refresh_interval_secs: u64,
    },

    /// Healthy instances of a Consul service.
    Consul {
        /// Consul HTTP API base URL.
        address: String,
        /// Service name to look up.
        service: String,
        /// Datacenter, when not the agent's own.
        datacenter: Option<String>,
        /// Restrict to instances passing all their health checks.
        #[serde(default = "default_only_passing")]
        only_passing: bool,
        /// Seconds between re-resolutions.
        #[serde(default = "default_refresh_interval")]
        refresh_interval_secs: u64,
        /// Restrict to instances carrying this tag.
        tag: Option<String>,
    },

    /// Endpoints backing a Kubernetes service.
    Kubernetes {
        /// Namespace holding the service.
        namespace: String,
        /// Service name.
        service: String,
        /// Named port to select, when the service exposes more than one.
        port_name: Option<String>,
        /// Seconds between re-resolutions.
        #[serde(default = "default_refresh_interval")]
        refresh_interval_secs: u64,
        /// Explicit kubeconfig path; in-cluster config is used when absent.
        kubeconfig: Option<String>,
    },

    /// A file listing one `host:port` per line, re-read on an interval.
    File {
        /// Path to the backend list.
        path: String,
        /// Seconds between re-reads.
        #[serde(default = "default_watch_interval")]
        watch_interval_secs: u64,
    },
}

impl UpstreamDiscovery {
    /// How often this source is re-resolved.
    ///
    /// `Static` never changes, so it reports zero and the proxy skips
    /// scheduling a refresh task for it.
    pub fn refresh_interval_secs(&self) -> u64 {
        match self {
            Self::Static { .. } => 0,
            Self::Dns {
                refresh_interval_secs,
                ..
            }
            | Self::DnsSrv {
                refresh_interval_secs,
                ..
            }
            | Self::Consul {
                refresh_interval_secs,
                ..
            }
            | Self::Kubernetes {
                refresh_interval_secs,
                ..
            } => *refresh_interval_secs,
            Self::File {
                watch_interval_secs,
                ..
            } => *watch_interval_secs,
        }
    }

    /// The discovery backend's name as written in KDL, for logs and errors.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Static { .. } => "static",
            Self::Dns { .. } => "dns",
            Self::DnsSrv { .. } => "dns-srv",
            Self::Consul { .. } => "consul",
            Self::Kubernetes { .. } => "kubernetes",
            Self::File { .. } => "file",
        }
    }
}

fn default_refresh_interval() -> u64 {
    30
}

fn default_watch_interval() -> u64 {
    5
}

fn default_only_passing() -> bool {
    true
}

/// HTTP version configuration for upstream connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpVersionConfig {
    /// Minimum HTTP version (1 or 2)
    #[serde(default = "default_min_http_version")]
    pub min_version: u8,

    /// Maximum HTTP version (1 or 2)
    #[serde(default = "default_max_http_version")]
    pub max_version: u8,

    /// H2 ping interval in seconds (0 to disable)
    #[serde(default)]
    pub h2_ping_interval_secs: u64,

    /// Maximum concurrent H2 streams per connection
    #[serde(default = "default_max_h2_streams")]
    pub max_h2_streams: usize,

    /// Speak HTTP/2 over cleartext TCP with prior knowledge (`h2c #true` on
    /// the upstream). Only for upstreams without `tls`; there is no
    /// negotiation and no fallback to HTTP/1.1.
    #[serde(default)]
    pub h2c: bool,
}

impl Default for HttpVersionConfig {
    fn default() -> Self {
        Self {
            min_version: default_min_http_version(),
            max_version: default_max_http_version(),
            h2_ping_interval_secs: 0,
            max_h2_streams: default_max_h2_streams(),
            h2c: false,
        }
    }
}

fn default_min_http_version() -> u8 {
    1
}

fn default_max_http_version() -> u8 {
    2 // Enable HTTP/2 by default when TLS is used
}

fn default_max_h2_streams() -> usize {
    100
}

/// Individual upstream target
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpstreamTarget {
    /// Target address (host:port)
    pub address: String,

    /// Weight for weighted load balancing
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Maximum concurrent requests
    pub max_requests: Option<u32>,

    /// Target metadata/tags
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

// ============================================================================
// Health Check Configuration
// ============================================================================

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Health check type
    #[serde(rename = "type")]
    pub check_type: HealthCheckType,

    /// Interval between checks
    #[serde(default = "default_health_check_interval")]
    pub interval_secs: u64,

    /// Timeout for health check
    #[serde(default = "default_health_check_timeout")]
    pub timeout_secs: u64,

    /// Number of successes to mark healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,

    /// Number of failures to mark unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

// ============================================================================
// Connection Pool Configuration
// ============================================================================

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per target
    #[serde(default = "default_max_connections_per_target")]
    pub max_connections: usize,

    /// Maximum idle connections
    #[serde(default = "default_max_idle_connections")]
    pub max_idle: usize,

    /// Idle timeout
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Connection lifetime
    pub max_lifetime_secs: Option<u64>,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections_per_target(),
            max_idle: default_max_idle_connections(),
            idle_timeout_secs: default_idle_timeout(),
            max_lifetime_secs: None,
        }
    }
}

// ============================================================================
// Upstream Timeouts
// ============================================================================

/// Upstream timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTimeouts {
    /// Connection timeout
    #[serde(default = "default_connect_timeout")]
    pub connect_secs: u64,

    /// Request timeout
    #[serde(default = "default_upstream_request_timeout")]
    pub request_secs: u64,

    /// Read timeout
    #[serde(default = "default_read_timeout")]
    pub read_secs: u64,

    /// Write timeout
    #[serde(default = "default_write_timeout")]
    pub write_secs: u64,
}

impl Default for UpstreamTimeouts {
    fn default() -> Self {
        Self {
            connect_secs: default_connect_timeout(),
            request_secs: default_upstream_request_timeout(),
            read_secs: default_read_timeout(),
            write_secs: default_write_timeout(),
        }
    }
}

// ============================================================================
// Upstream TLS Configuration
// ============================================================================

/// Upstream TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTlsConfig {
    /// SNI hostname
    pub sni: Option<String>,

    /// Skip certificate verification (DANGEROUS - testing only)
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// Client certificate for mTLS
    pub client_cert: Option<PathBuf>,

    /// Client key for mTLS
    pub client_key: Option<PathBuf>,

    /// CA certificates
    pub ca_cert: Option<PathBuf>,
}

// ============================================================================
// Upstream Peer (for Phase 0 testing)
// ============================================================================

/// Simple upstream peer for Phase 0 testing
#[derive(Debug, Clone)]
pub struct UpstreamPeer {
    pub address: String,
    pub tls: bool,
    pub host: String,
    pub connect_timeout_secs: u64,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_lb_algorithm() -> LoadBalancingAlgorithm {
    LoadBalancingAlgorithm::RoundRobin
}

fn default_weight() -> u32 {
    1
}

fn default_health_check_interval() -> u64 {
    10
}

fn default_health_check_timeout() -> u64 {
    5
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_max_connections_per_target() -> usize {
    100
}

fn default_max_idle_connections() -> usize {
    20
}

fn default_idle_timeout() -> u64 {
    60
}

pub(crate) fn default_connect_timeout() -> u64 {
    10
}

fn default_upstream_request_timeout() -> u64 {
    60
}

pub(crate) fn default_read_timeout() -> u64 {
    30
}

pub(crate) fn default_write_timeout() -> u64 {
    30
}
