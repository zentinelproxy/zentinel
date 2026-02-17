//! Filter chain configuration for Zentinel proxy
//!
//! Filters provide an ordered pipeline for request/response processing.
//! They can be built-in (rate-limit, headers, compress) or external agents.
//!
//! Filter instances are defined centrally in the `filters` block with unique IDs,
//! then referenced by name in route configurations. This allows reuse of filter
//! configurations across multiple routes.
//!
//! Example:
//! ```kdl
//! filters {
//!     filter "strict-auth" {
//!         type "agent"
//!         agent "auth-agent"
//!         timeout-ms 100
//!         failure-mode "closed"
//!     }
//!     filter "api-rate-limit" {
//!         type "rate-limit"
//!         max-rps 100
//!         key "client-ip"
//!     }
//! }
//!
//! routes {
//!     route "api" {
//!         filters ["strict-auth" "api-rate-limit"]
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::FailureMode;

// =============================================================================
// Filter Instance Configuration
// =============================================================================

/// A named filter instance that can be referenced by routes.
///
/// Filter instances are defined in the top-level `filters` block and
/// referenced by ID in route configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Unique identifier for this filter instance
    pub id: String,

    /// The filter type and its configuration
    #[serde(flatten)]
    pub filter: Filter,
}

impl FilterConfig {
    /// Create a new filter configuration
    pub fn new(id: impl Into<String>, filter: Filter) -> Self {
        Self {
            id: id.into(),
            filter,
        }
    }

    /// Get the execution phase for this filter
    pub fn phase(&self) -> FilterPhase {
        self.filter.phase()
    }

    /// Get the filter type name for logging/metrics
    pub fn filter_type(&self) -> &'static str {
        self.filter.type_name()
    }

    /// Validate this filter configuration
    pub fn validate(&self, available_agents: &[String]) -> Result<(), String> {
        self.filter.validate(available_agents)
    }
}

// =============================================================================
// Filter Types
// =============================================================================

/// Filter execution phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FilterPhase {
    /// Execute during request processing (before upstream)
    #[default]
    Request,
    /// Execute during response processing (after upstream)
    Response,
    /// Execute during both request and response
    Both,
}

/// A filter type with its configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Filter {
    /// Rate limiting filter (built-in)
    RateLimit(RateLimitFilter),

    /// Header manipulation filter (built-in)
    Headers(HeadersFilter),

    /// Response compression filter (built-in)
    Compress(CompressFilter),

    /// CORS handling filter (built-in)
    Cors(CorsFilter),

    /// Timeout override filter (built-in)
    Timeout(TimeoutFilter),

    /// Request/response logging filter (built-in)
    Log(LogFilter),

    /// GeoIP filtering (built-in)
    Geo(GeoFilter),

    /// External agent filter
    Agent(AgentFilter),
}

impl Filter {
    /// Get the execution phase for this filter
    pub fn phase(&self) -> FilterPhase {
        match self {
            Filter::RateLimit(_) => FilterPhase::Request,
            Filter::Headers(h) => h.phase,
            Filter::Compress(_) => FilterPhase::Response,
            Filter::Cors(_) => FilterPhase::Both,
            Filter::Timeout(_) => FilterPhase::Request,
            Filter::Log(l) => {
                match (l.log_request, l.log_response) {
                    (true, true) => FilterPhase::Both,
                    (true, false) => FilterPhase::Request,
                    (false, true) => FilterPhase::Response,
                    (false, false) => FilterPhase::Request, // default to request
                }
            }
            Filter::Geo(_) => FilterPhase::Request,
            Filter::Agent(a) => a.phase.unwrap_or(FilterPhase::Request),
        }
    }

    /// Get the filter type name for logging/metrics
    pub fn type_name(&self) -> &'static str {
        match self {
            Filter::RateLimit(_) => "rate-limit",
            Filter::Headers(_) => "headers",
            Filter::Compress(_) => "compress",
            Filter::Cors(_) => "cors",
            Filter::Timeout(_) => "timeout",
            Filter::Log(_) => "log",
            Filter::Geo(_) => "geo",
            Filter::Agent(_) => "agent",
        }
    }

    /// Check if this filter executes during request phase
    pub fn runs_on_request(&self) -> bool {
        matches!(self.phase(), FilterPhase::Request | FilterPhase::Both)
    }

    /// Check if this filter executes during response phase
    pub fn runs_on_response(&self) -> bool {
        matches!(self.phase(), FilterPhase::Response | FilterPhase::Both)
    }

    /// Validate the filter configuration
    pub fn validate(&self, available_agents: &[String]) -> Result<(), String> {
        match self {
            Filter::RateLimit(r) => {
                if r.max_rps == 0 {
                    return Err("rate-limit max-rps must be > 0".into());
                }
            }
            Filter::Compress(c) => {
                if c.algorithms.is_empty() {
                    return Err("compress filter requires at least one algorithm".into());
                }
            }
            Filter::Geo(g) => {
                if g.database_path.is_empty() {
                    return Err("geo filter requires 'database-path'".into());
                }
                // Validate country codes are uppercase and 2 characters
                for code in &g.countries {
                    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_uppercase()) {
                        return Err(format!(
                            "geo filter: invalid country code '{}' (expected ISO 3166-1 alpha-2 like 'US', 'CN')",
                            code
                        ));
                    }
                }
            }
            Filter::Agent(a) => {
                if !available_agents.contains(&a.agent) {
                    return Err(format!(
                        "agent filter references unknown agent '{}'. Available: {:?}",
                        a.agent, available_agents
                    ));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// =============================================================================
// Rate Limit Filter
// =============================================================================

/// Rate limiting configuration using token bucket algorithm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitFilter {
    /// Maximum requests per second
    #[serde(rename = "max-rps")]
    pub max_rps: u32,

    /// Burst size (number of tokens in bucket)
    #[serde(default = "default_burst")]
    pub burst: u32,

    /// Key to rate limit by
    #[serde(default)]
    pub key: RateLimitKey,

    /// Action when rate limit is exceeded
    #[serde(default, rename = "on-limit")]
    pub on_limit: RateLimitAction,

    /// Custom response status code when limited
    #[serde(default = "default_limit_status", rename = "status-code")]
    pub status_code: u16,

    /// Custom response message when limited
    #[serde(rename = "limit-message")]
    pub limit_message: Option<String>,

    /// Backend for rate limiting storage
    #[serde(default)]
    pub backend: RateLimitBackend,

    /// Maximum delay in milliseconds before rejecting (for Delay action)
    #[serde(default = "default_max_delay_ms", rename = "max-delay-ms")]
    pub max_delay_ms: u64,
}

fn default_max_delay_ms() -> u64 {
    5000 // 5 seconds max delay
}

// =============================================================================
// Global Rate Limit Configuration
// =============================================================================

/// Global rate limit configuration applied server-wide
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalRateLimitConfig {
    /// Default requests per second for routes without explicit rate limiting
    #[serde(default, rename = "default-rps")]
    pub default_rps: Option<u32>,

    /// Default burst size for routes without explicit rate limiting
    #[serde(default, rename = "default-burst")]
    pub default_burst: Option<u32>,

    /// Default rate limit key
    #[serde(default)]
    pub key: RateLimitKey,

    /// Global rate limit applied to all requests before route-specific limits
    #[serde(default)]
    pub global: Option<GlobalLimitConfig>,
}

/// Global rate limit that applies to all requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalLimitConfig {
    /// Maximum requests per second globally
    #[serde(rename = "max-rps")]
    pub max_rps: u32,

    /// Burst size for global limit
    #[serde(default = "default_burst")]
    pub burst: u32,

    /// Key for global rate limiting (usually client-ip)
    #[serde(default)]
    pub key: RateLimitKey,
}

/// Backend storage for rate limit state
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitBackend {
    /// Local in-memory storage (single-instance only)
    #[default]
    Local,
    /// Redis backend for distributed rate limiting
    Redis(RedisBackendConfig),
    /// Memcached backend for distributed rate limiting
    Memcached(MemcachedBackendConfig),
}

/// Redis backend configuration for distributed rate limiting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedisBackendConfig {
    /// Redis connection URL (e.g., "redis://127.0.0.1:6379")
    pub url: String,

    /// Key prefix for rate limit keys (default: "zentinel:ratelimit:")
    #[serde(default = "default_redis_prefix", rename = "key-prefix")]
    pub key_prefix: String,

    /// Connection pool size
    #[serde(default = "default_redis_pool_size", rename = "pool-size")]
    pub pool_size: u32,

    /// Connection timeout in milliseconds
    #[serde(default = "default_redis_timeout_ms", rename = "timeout-ms")]
    pub timeout_ms: u64,

    /// Fallback to local rate limiting if Redis is unavailable
    #[serde(default = "default_true", rename = "fallback-local")]
    pub fallback_local: bool,
}

impl Default for RedisBackendConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: default_redis_prefix(),
            pool_size: default_redis_pool_size(),
            timeout_ms: default_redis_timeout_ms(),
            fallback_local: true,
        }
    }
}

fn default_redis_prefix() -> String {
    "zentinel:ratelimit:".to_string()
}

fn default_redis_pool_size() -> u32 {
    10
}

fn default_redis_timeout_ms() -> u64 {
    50
}

/// Memcached backend configuration for distributed rate limiting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemcachedBackendConfig {
    /// Memcached server URL (e.g., "memcache://127.0.0.1:11211")
    pub url: String,

    /// Key prefix for rate limit keys (default: "zentinel:ratelimit:")
    #[serde(default = "default_memcached_prefix", rename = "key-prefix")]
    pub key_prefix: String,

    /// Connection pool size
    #[serde(default = "default_memcached_pool_size", rename = "pool-size")]
    pub pool_size: u32,

    /// Connection timeout in milliseconds
    #[serde(default = "default_memcached_timeout_ms", rename = "timeout-ms")]
    pub timeout_ms: u64,

    /// Fallback to local rate limiting if Memcached is unavailable
    #[serde(default = "default_true", rename = "fallback-local")]
    pub fallback_local: bool,

    /// TTL for rate limit keys in seconds (default: 2 seconds, covers the window)
    #[serde(default = "default_memcached_ttl", rename = "ttl-secs")]
    pub ttl_secs: u32,
}

impl Default for MemcachedBackendConfig {
    fn default() -> Self {
        Self {
            url: "memcache://127.0.0.1:11211".to_string(),
            key_prefix: default_memcached_prefix(),
            pool_size: default_memcached_pool_size(),
            timeout_ms: default_memcached_timeout_ms(),
            fallback_local: true,
            ttl_secs: default_memcached_ttl(),
        }
    }
}

fn default_memcached_prefix() -> String {
    "zentinel:ratelimit:".to_string()
}

fn default_memcached_pool_size() -> u32 {
    10
}

fn default_memcached_timeout_ms() -> u64 {
    50
}

fn default_memcached_ttl() -> u32 {
    2
}

fn default_burst() -> u32 {
    10
}

fn default_limit_status() -> u16 {
    429
}

/// Key for rate limit bucketing
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitKey {
    /// Rate limit by client IP address
    #[default]
    ClientIp,
    /// Rate limit by specific header value
    Header(String),
    /// Rate limit by request path
    Path,
    /// Rate limit by route ID (global per-route limit)
    Route,
    /// Combination of client IP and path
    ClientIpAndPath,
}

/// Action to take when rate limit is exceeded
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitAction {
    /// Reject the request with 429 status
    #[default]
    Reject,
    /// Delay the request (queue it)
    Delay,
    /// Log but allow the request
    LogOnly,
}

// =============================================================================
// Headers Filter
// =============================================================================

/// Header manipulation filter
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeadersFilter {
    /// Phase to apply header modifications
    #[serde(default)]
    pub phase: FilterPhase,

    /// Headers to set (overwrites existing values)
    #[serde(default)]
    pub set: HashMap<String, String>,

    /// Headers to add (appends to existing)
    #[serde(default)]
    pub add: HashMap<String, String>,

    /// Headers to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

// =============================================================================
// Compress Filter
// =============================================================================

/// Response compression filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressFilter {
    /// Compression algorithms in preference order
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<CompressionAlgorithm>,

    /// Minimum response size to compress (bytes)
    #[serde(default = "default_min_size", rename = "min-size")]
    pub min_size: usize,

    /// Content types to compress (MIME types)
    #[serde(default = "default_content_types", rename = "content-types")]
    pub content_types: Vec<String>,

    /// Compression level (1-9, algorithm-specific)
    #[serde(default = "default_compression_level")]
    pub level: u8,
}

impl Default for CompressFilter {
    fn default() -> Self {
        Self {
            algorithms: default_algorithms(),
            min_size: default_min_size(),
            content_types: default_content_types(),
            level: default_compression_level(),
        }
    }
}

fn default_algorithms() -> Vec<CompressionAlgorithm> {
    vec![CompressionAlgorithm::Gzip, CompressionAlgorithm::Brotli]
}

fn default_min_size() -> usize {
    1024 // 1KB
}

fn default_content_types() -> Vec<String> {
    vec![
        "text/html".into(),
        "text/css".into(),
        "text/plain".into(),
        "text/xml".into(),
        "application/json".into(),
        "application/javascript".into(),
        "application/xml".into(),
        "image/svg+xml".into(),
    ]
}

fn default_compression_level() -> u8 {
    6
}

/// Compression algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    Deflate,
    Zstd,
}

// =============================================================================
// CORS Filter
// =============================================================================

/// CORS (Cross-Origin Resource Sharing) filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsFilter {
    /// Allowed origins (use "*" for any)
    #[serde(default, rename = "allowed-origins")]
    pub allowed_origins: Vec<String>,

    /// Allowed HTTP methods
    #[serde(default = "default_cors_methods", rename = "allowed-methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed request headers
    #[serde(default, rename = "allowed-headers")]
    pub allowed_headers: Vec<String>,

    /// Headers to expose to the client
    #[serde(default, rename = "exposed-headers")]
    pub exposed_headers: Vec<String>,

    /// Allow credentials (cookies, auth headers)
    #[serde(default, rename = "allow-credentials")]
    pub allow_credentials: bool,

    /// Max age for preflight cache (seconds)
    #[serde(default = "default_cors_max_age", rename = "max-age-secs")]
    pub max_age_secs: u64,
}

impl Default for CorsFilter {
    fn default() -> Self {
        Self {
            allowed_origins: vec!["*".into()],
            allowed_methods: default_cors_methods(),
            allowed_headers: vec![],
            exposed_headers: vec![],
            allow_credentials: false,
            max_age_secs: default_cors_max_age(),
        }
    }
}

fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "POST".into(),
        "PUT".into(),
        "DELETE".into(),
        "OPTIONS".into(),
        "HEAD".into(),
        "PATCH".into(),
    ]
}

fn default_cors_max_age() -> u64 {
    86400 // 24 hours
}

// =============================================================================
// Timeout Filter
// =============================================================================

/// Timeout override filter
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TimeoutFilter {
    /// Request timeout override (seconds)
    #[serde(rename = "request-timeout-secs")]
    pub request_timeout_secs: Option<u64>,

    /// Upstream/backend timeout override (seconds)
    #[serde(rename = "upstream-timeout-secs")]
    pub upstream_timeout_secs: Option<u64>,

    /// Connect timeout override (seconds)
    #[serde(rename = "connect-timeout-secs")]
    pub connect_timeout_secs: Option<u64>,
}

// =============================================================================
// Log Filter
// =============================================================================

/// Request/response logging filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFilter {
    /// Log request details
    #[serde(default = "default_true", rename = "log-request")]
    pub log_request: bool,

    /// Log response details
    #[serde(default = "default_true", rename = "log-response")]
    pub log_response: bool,

    /// Log request/response body (up to max size)
    #[serde(default, rename = "log-body")]
    pub log_body: bool,

    /// Maximum body size to log (bytes)
    #[serde(default = "default_max_body_log", rename = "max-body-log-size")]
    pub max_body_log_size: usize,

    /// Additional fields to include in log
    #[serde(default)]
    pub fields: Vec<String>,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogFilter {
    fn default() -> Self {
        Self {
            log_request: true,
            log_response: true,
            log_body: false,
            max_body_log_size: default_max_body_log(),
            fields: vec![],
            level: default_log_level(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_max_body_log() -> usize {
    4096 // 4KB
}

fn default_log_level() -> String {
    "info".into()
}

// =============================================================================
// Geo Filter
// =============================================================================

/// GeoIP database type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GeoDatabaseType {
    /// MaxMind GeoLite2/GeoIP2 database (.mmdb format)
    MaxMind,
    /// IP2Location database (.bin format)
    Ip2Location,
}

/// Action to take based on geo filter result
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GeoFilterAction {
    /// Block requests from matching countries (blocklist mode)
    #[default]
    Block,
    /// Allow only requests from matching countries (allowlist mode)
    Allow,
    /// Log country info but don't block (monitoring mode)
    LogOnly,
}

/// Behavior when geo lookup fails
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GeoFailureMode {
    /// Allow request on lookup failure (fail-open)
    #[default]
    Open,
    /// Block request on lookup failure (fail-closed)
    Closed,
}

/// GeoIP filtering configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoFilter {
    /// Path to GeoIP database file (.mmdb or .bin)
    #[serde(rename = "database-path")]
    pub database_path: String,

    /// Database type (auto-detected from extension if not specified)
    #[serde(default, rename = "database-type")]
    pub database_type: Option<GeoDatabaseType>,

    /// Filter action (block, allow, log-only)
    #[serde(default)]
    pub action: GeoFilterAction,

    /// ISO 3166-1 alpha-2 country codes to match
    #[serde(default)]
    pub countries: Vec<String>,

    /// Behavior when lookup fails
    #[serde(default, rename = "on-failure")]
    pub on_failure: GeoFailureMode,

    /// HTTP status code for blocked requests
    #[serde(default = "default_geo_status", rename = "status-code")]
    pub status_code: u16,

    /// Custom response message for blocked requests
    #[serde(rename = "block-message")]
    pub block_message: Option<String>,

    /// Cache TTL for IP lookups (seconds)
    #[serde(default = "default_geo_cache_ttl", rename = "cache-ttl-secs")]
    pub cache_ttl_secs: u64,

    /// Add X-GeoIP-Country header to response
    #[serde(default = "default_true", rename = "add-country-header")]
    pub add_country_header: bool,
}

impl Default for GeoFilter {
    fn default() -> Self {
        Self {
            database_path: String::new(),
            database_type: None,
            action: GeoFilterAction::Block,
            countries: Vec::new(),
            on_failure: GeoFailureMode::Open,
            status_code: default_geo_status(),
            block_message: None,
            cache_ttl_secs: default_geo_cache_ttl(),
            add_country_header: true,
        }
    }
}

fn default_geo_status() -> u16 {
    403
}

fn default_geo_cache_ttl() -> u64 {
    3600 // 1 hour
}

// =============================================================================
// Agent Filter
// =============================================================================

/// External agent filter - references an agent defined in the agents section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentFilter {
    /// Agent ID (must match an agent in the agents configuration)
    pub agent: String,

    /// Execution phase for this agent filter
    #[serde(default)]
    pub phase: Option<FilterPhase>,

    /// Timeout override for this filter invocation (milliseconds)
    #[serde(rename = "timeout-ms")]
    pub timeout_ms: Option<u64>,

    /// Failure mode override for this filter invocation
    #[serde(rename = "failure-mode")]
    pub failure_mode: Option<FailureMode>,

    /// Whether to inspect request body
    #[serde(default, rename = "inspect-body")]
    pub inspect_body: bool,

    /// Maximum request body bytes to send to agent
    #[serde(rename = "max-body-bytes")]
    pub max_body_bytes: Option<usize>,
}

impl AgentFilter {
    /// Create a new agent filter referencing an agent
    pub fn new(agent: impl Into<String>) -> Self {
        Self {
            agent: agent.into(),
            phase: None,
            timeout_ms: None,
            failure_mode: None,
            inspect_body: false,
            max_body_bytes: None,
        }
    }

    /// Get the referenced agent ID
    pub fn agent_id(&self) -> &str {
        &self.agent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_phases() {
        assert_eq!(
            Filter::RateLimit(RateLimitFilter {
                max_rps: 100,
                burst: 10,
                key: RateLimitKey::ClientIp,
                on_limit: RateLimitAction::Reject,
                status_code: 429,
                limit_message: None,
                backend: RateLimitBackend::Local,
                max_delay_ms: 5000,
            })
            .phase(),
            FilterPhase::Request
        );

        assert_eq!(
            Filter::Compress(CompressFilter::default()).phase(),
            FilterPhase::Response
        );

        assert_eq!(
            Filter::Cors(CorsFilter::default()).phase(),
            FilterPhase::Both
        );
    }

    #[test]
    fn test_agent_filter_validation() {
        let filter = Filter::Agent(AgentFilter::new("auth-agent"));
        assert!(filter.validate(&["auth-agent".into()]).is_ok());
        assert!(filter.validate(&["other-agent".into()]).is_err());
    }

    #[test]
    fn test_filter_config() {
        let config = FilterConfig::new(
            "my-rate-limit",
            Filter::RateLimit(RateLimitFilter {
                max_rps: 100,
                burst: 10,
                key: RateLimitKey::ClientIp,
                on_limit: RateLimitAction::Reject,
                status_code: 429,
                limit_message: None,
                backend: RateLimitBackend::Local,
                max_delay_ms: 5000,
            }),
        );

        assert_eq!(config.id, "my-rate-limit");
        assert_eq!(config.filter_type(), "rate-limit");
        assert_eq!(config.phase(), FilterPhase::Request);
    }

    #[test]
    fn test_redis_backend_config() {
        let config = RedisBackendConfig::default();
        assert_eq!(config.url, "redis://127.0.0.1:6379");
        assert_eq!(config.key_prefix, "zentinel:ratelimit:");
        assert_eq!(config.pool_size, 10);
        assert_eq!(config.timeout_ms, 50);
        assert!(config.fallback_local);
    }

    #[test]
    fn test_global_rate_limit_config_default() {
        let config = GlobalRateLimitConfig::default();
        assert!(config.default_rps.is_none());
        assert!(config.default_burst.is_none());
        assert_eq!(config.key, RateLimitKey::ClientIp);
        assert!(config.global.is_none());
    }

    #[test]
    fn test_global_rate_limit_config_with_values() {
        let config = GlobalRateLimitConfig {
            default_rps: Some(100),
            default_burst: Some(20),
            key: RateLimitKey::Path,
            global: Some(GlobalLimitConfig {
                max_rps: 10000,
                burst: 1000,
                key: RateLimitKey::ClientIp,
            }),
        };

        assert_eq!(config.default_rps, Some(100));
        assert_eq!(config.default_burst, Some(20));
        assert_eq!(config.key, RateLimitKey::Path);
        assert!(config.global.is_some());

        let global = config.global.unwrap();
        assert_eq!(global.max_rps, 10000);
        assert_eq!(global.burst, 1000);
        assert_eq!(global.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn test_rate_limit_filter_max_delay_ms() {
        let filter = RateLimitFilter {
            max_rps: 100,
            burst: 10,
            key: RateLimitKey::ClientIp,
            on_limit: RateLimitAction::Delay,
            status_code: 429,
            limit_message: None,
            backend: RateLimitBackend::Local,
            max_delay_ms: 3000,
        };

        assert_eq!(filter.max_delay_ms, 3000);
        assert_eq!(filter.on_limit, RateLimitAction::Delay);
    }

    #[test]
    fn test_rate_limit_filter_default_max_delay() {
        // When creating with default, max_delay_ms should be 5000
        let filter = RateLimitFilter {
            max_rps: 100,
            burst: 10,
            key: RateLimitKey::ClientIp,
            on_limit: RateLimitAction::Reject,
            status_code: 429,
            limit_message: None,
            backend: RateLimitBackend::Local,
            max_delay_ms: 5000, // default value
        };

        assert_eq!(filter.max_delay_ms, 5000);
    }

    #[test]
    fn test_geo_filter_default() {
        let filter = GeoFilter::default();
        assert!(filter.database_path.is_empty());
        assert!(filter.database_type.is_none());
        assert_eq!(filter.action, GeoFilterAction::Block);
        assert!(filter.countries.is_empty());
        assert_eq!(filter.on_failure, GeoFailureMode::Open);
        assert_eq!(filter.status_code, 403);
        assert!(filter.block_message.is_none());
        assert_eq!(filter.cache_ttl_secs, 3600);
        assert!(filter.add_country_header);
    }

    #[test]
    fn test_geo_filter_action_enum() {
        assert_eq!(GeoFilterAction::default(), GeoFilterAction::Block);
        assert_ne!(GeoFilterAction::Allow, GeoFilterAction::Block);
        assert_ne!(GeoFilterAction::LogOnly, GeoFilterAction::Block);
    }

    #[test]
    fn test_geo_failure_mode_enum() {
        assert_eq!(GeoFailureMode::default(), GeoFailureMode::Open);
        assert_ne!(GeoFailureMode::Closed, GeoFailureMode::Open);
    }

    #[test]
    fn test_geo_database_type_enum() {
        let maxmind = GeoDatabaseType::MaxMind;
        let ip2loc = GeoDatabaseType::Ip2Location;
        assert_ne!(maxmind, ip2loc);
    }

    #[test]
    fn test_geo_filter_validation_missing_path() {
        let filter = Filter::Geo(GeoFilter::default());
        let result = filter.validate(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("database-path"));
    }

    #[test]
    fn test_geo_filter_validation_invalid_country_code() {
        let filter = Filter::Geo(GeoFilter {
            database_path: "/path/to/db.mmdb".to_string(),
            countries: vec!["invalid".to_string()],
            ..Default::default()
        });
        let result = filter.validate(&[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid country code"));
    }

    #[test]
    fn test_geo_filter_validation_valid() {
        let filter = Filter::Geo(GeoFilter {
            database_path: "/path/to/db.mmdb".to_string(),
            countries: vec!["US".to_string(), "CA".to_string()],
            ..Default::default()
        });
        assert!(filter.validate(&[]).is_ok());
    }

    #[test]
    fn test_geo_filter_phase() {
        let filter = Filter::Geo(GeoFilter::default());
        assert_eq!(filter.phase(), FilterPhase::Request);
    }

    #[test]
    fn test_geo_filter_type_name() {
        let filter = Filter::Geo(GeoFilter::default());
        assert_eq!(filter.type_name(), "geo");
    }

    #[test]
    fn test_geo_filter_config() {
        let config = FilterConfig::new(
            "block-countries",
            Filter::Geo(GeoFilter {
                database_path: "/etc/zentinel/GeoLite2-Country.mmdb".to_string(),
                database_type: Some(GeoDatabaseType::MaxMind),
                action: GeoFilterAction::Block,
                countries: vec!["RU".to_string(), "CN".to_string()],
                on_failure: GeoFailureMode::Closed,
                status_code: 403,
                block_message: Some("Access denied from your region".to_string()),
                cache_ttl_secs: 7200,
                add_country_header: true,
            }),
        );

        assert_eq!(config.id, "block-countries");
        assert_eq!(config.filter_type(), "geo");
        assert_eq!(config.phase(), FilterPhase::Request);
    }
}
