//! Upstream configuration types
//!
//! This module contains configuration types for upstream backends
//! including load balancing, health checks, and connection pooling.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

use sentinel_common::types::{HealthCheckType, LoadBalancingAlgorithm};

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

    /// Upstream targets
    #[validate(length(min = 1, message = "At least one target is required"))]
    pub targets: Vec<UpstreamTarget>,

    /// Load balancing algorithm
    #[serde(default = "default_lb_algorithm")]
    pub load_balancing: LoadBalancingAlgorithm,

    /// Sticky session configuration (for cookie-based session affinity)
    pub sticky_session: Option<StickySessionConfig>,

    /// Health check configuration
    pub health_check: Option<HealthCheck>,

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
}

impl Default for HttpVersionConfig {
    fn default() -> Self {
        Self {
            min_version: default_min_http_version(),
            max_version: default_max_http_version(),
            h2_ping_interval_secs: 0,
            max_h2_streams: default_max_h2_streams(),
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
