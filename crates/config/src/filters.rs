//! Filter chain configuration for Sentinel proxy
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
            }),
        );

        assert_eq!(config.id, "my-rate-limit");
        assert_eq!(config.filter_type(), "rate-limit");
        assert_eq!(config.phase(), FilterPhase::Request);
    }
}
