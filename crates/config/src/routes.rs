//! Route configuration types
//!
//! This module contains configuration types for routing requests
//! to upstreams or static file handlers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

use sentinel_common::types::{ByteSize, CircuitBreakerConfig, Priority, RetryPolicy};

use crate::filters::RateLimitKey;

// ============================================================================
// Route Configuration
// ============================================================================

/// Route configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RouteConfig {
    /// Unique route identifier
    pub id: String,

    /// Route priority (higher = evaluated first)
    #[serde(default)]
    pub priority: Priority,

    /// Match conditions
    pub matches: Vec<MatchCondition>,

    /// Target upstream (optional for static file serving)
    pub upstream: Option<String>,

    /// Service type for this route
    #[serde(default)]
    pub service_type: ServiceType,

    /// Route-specific policies
    #[serde(default)]
    pub policies: RoutePolicies,

    /// Filter chain for this route - list of filter IDs (executed in order)
    /// References filters defined in the top-level `filters` block
    #[serde(default)]
    pub filters: Vec<String>,

    /// Built-in handler (for service_type = Builtin)
    #[serde(default, rename = "builtin-handler")]
    pub builtin_handler: Option<BuiltinHandler>,

    /// WAF enabled for this route (shorthand for adding WAF agent filter)
    #[serde(default)]
    pub waf_enabled: bool,

    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,

    /// Static file serving configuration (for service_type = Static)
    #[serde(default)]
    pub static_files: Option<StaticFileConfig>,

    /// API schema validation configuration (for service_type = Api)
    #[serde(default)]
    pub api_schema: Option<ApiSchemaConfig>,

    /// Error page configuration
    #[serde(default)]
    pub error_pages: Option<ErrorPageConfig>,

    /// Enable WebSocket upgrade support for this route (default: false)
    /// When enabled, HTTP Upgrade requests with "websocket" protocol are allowed.
    /// Pingora handles the actual WebSocket tunneling transparently.
    #[serde(default)]
    pub websocket: bool,
}

// ============================================================================
// Match Conditions
// ============================================================================

/// Match condition for route selection
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchCondition {
    /// Match by path prefix
    PathPrefix(String),

    /// Match by exact path
    Path(String),

    /// Match by regex pattern
    PathRegex(String),

    /// Match by host header
    Host(String),

    /// Match by header presence
    Header { name: String, value: Option<String> },

    /// Match by method
    Method(Vec<String>),

    /// Match by query parameter
    QueryParam { name: String, value: Option<String> },
}

// ============================================================================
// Service Types
// ============================================================================

/// Service type for route handling
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// Traditional web service (default)
    Web,
    /// REST API service with JSON responses
    Api,
    /// Static file hosting
    Static,
    /// Built-in handler (status page, health check, etc.)
    Builtin,
}

impl Default for ServiceType {
    fn default() -> Self {
        ServiceType::Web
    }
}

/// Built-in handler types for ServiceType::Builtin routes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinHandler {
    /// JSON status page with version and uptime
    Status,
    /// Health check endpoint (returns 200 OK if healthy)
    Health,
    /// Prometheus metrics endpoint
    Metrics,
    /// 404 Not Found handler
    NotFound,
    /// Configuration dump endpoint (admin only)
    Config,
    /// Upstream health status endpoint (admin only)
    Upstreams,
    /// Cache purge endpoint (admin only, accepts PURGE method)
    CachePurge,
    /// Cache statistics endpoint (admin only)
    CacheStats,
}

// ============================================================================
// Route Policies
// ============================================================================

/// Route-specific policies
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutePolicies {
    /// Request header modifications
    #[serde(default)]
    pub request_headers: HeaderModifications,

    /// Response header modifications
    #[serde(default)]
    pub response_headers: HeaderModifications,

    /// Request timeout override
    pub timeout_secs: Option<u64>,

    /// Body size limit override
    pub max_body_size: Option<ByteSize>,

    /// Rate limit override
    pub rate_limit: Option<RateLimitPolicy>,

    /// Failure mode (fail-open or fail-closed)
    #[serde(default = "default_failure_mode")]
    pub failure_mode: FailureMode,

    /// Enable request buffering
    #[serde(default)]
    pub buffer_requests: bool,

    /// Enable response buffering
    #[serde(default)]
    pub buffer_responses: bool,

    /// HTTP caching configuration
    #[serde(default)]
    pub cache: Option<RouteCacheConfig>,
}

// ============================================================================
// Cache Configuration
// ============================================================================

/// Route-level HTTP caching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCacheConfig {
    /// Enable caching for this route
    #[serde(default)]
    pub enabled: bool,

    /// Default TTL in seconds if no Cache-Control header
    #[serde(default = "default_cache_ttl")]
    pub default_ttl_secs: u64,

    /// Maximum cacheable response size in bytes
    #[serde(default = "default_max_cache_size")]
    pub max_size_bytes: usize,

    /// Whether to cache private responses
    #[serde(default)]
    pub cache_private: bool,

    /// Stale-while-revalidate grace period in seconds
    #[serde(default = "default_stale_while_revalidate")]
    pub stale_while_revalidate_secs: u64,

    /// Stale-if-error grace period in seconds
    #[serde(default = "default_stale_if_error")]
    pub stale_if_error_secs: u64,

    /// HTTP methods that are cacheable
    #[serde(default = "default_cacheable_methods")]
    pub cacheable_methods: Vec<String>,

    /// Status codes that are cacheable
    #[serde(default = "default_cacheable_status_codes")]
    pub cacheable_status_codes: Vec<u16>,

    /// Vary headers to include in cache key
    #[serde(default)]
    pub vary_headers: Vec<String>,

    /// Query parameters to exclude from cache key
    #[serde(default)]
    pub ignore_query_params: Vec<String>,
}

impl Default for RouteCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_ttl_secs: default_cache_ttl(),
            max_size_bytes: default_max_cache_size(),
            cache_private: false,
            stale_while_revalidate_secs: default_stale_while_revalidate(),
            stale_if_error_secs: default_stale_if_error(),
            cacheable_methods: default_cacheable_methods(),
            cacheable_status_codes: default_cacheable_status_codes(),
            vary_headers: Vec::new(),
            ignore_query_params: Vec::new(),
        }
    }
}

fn default_cache_ttl() -> u64 {
    3600 // 1 hour
}

fn default_max_cache_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_stale_while_revalidate() -> u64 {
    60 // 1 minute
}

fn default_stale_if_error() -> u64 {
    300 // 5 minutes
}

fn default_cacheable_methods() -> Vec<String> {
    vec!["GET".to_string(), "HEAD".to_string()]
}

fn default_cacheable_status_codes() -> Vec<u16> {
    vec![200, 203, 204, 206, 300, 301, 308, 404, 410]
}

/// Header modification rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderModifications {
    /// Headers to add/set
    #[serde(default)]
    pub set: HashMap<String, String>,

    /// Headers to append
    #[serde(default)]
    pub add: HashMap<String, String>,

    /// Headers to remove
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Rate limit policy (legacy - prefer using rate-limit filter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Requests per second
    pub requests_per_second: u32,

    /// Burst size
    pub burst: u32,

    /// Key to rate limit by
    pub key: RateLimitKey,
}

/// Failure mode for degraded operation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    Open,   // Allow traffic through on failure
    Closed, // Block traffic on failure (default for security)
}

impl Default for FailureMode {
    fn default() -> Self {
        Self::Closed // Default to safe/closed behavior
    }
}

pub(crate) fn default_failure_mode() -> FailureMode {
    FailureMode::Closed
}

// ============================================================================
// Static File Configuration
// ============================================================================

/// Static file serving configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFileConfig {
    /// Root directory for static files
    pub root: PathBuf,

    /// Index file name (default: index.html)
    #[serde(default = "default_index_file")]
    pub index: String,

    /// Enable directory listing
    #[serde(default)]
    pub directory_listing: bool,

    /// Cache control header value
    #[serde(default = "default_cache_control")]
    pub cache_control: String,

    /// Compress responses
    #[serde(default = "default_true")]
    pub compress: bool,

    /// Additional MIME type mappings
    #[serde(default)]
    pub mime_types: HashMap<String, String>,

    /// Fallback file for SPA routing (e.g., index.html)
    pub fallback: Option<String>,
}

fn default_index_file() -> String {
    "index.html".to_string()
}

fn default_cache_control() -> String {
    "public, max-age=3600".to_string()
}

fn default_true() -> bool {
    true
}

// ============================================================================
// API Schema Configuration
// ============================================================================

/// API schema validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSchemaConfig {
    /// OpenAPI/Swagger schema file path
    pub schema_file: Option<PathBuf>,

    /// JSON Schema for request validation
    pub request_schema: Option<serde_json::Value>,

    /// JSON Schema for response validation
    pub response_schema: Option<serde_json::Value>,

    /// Validate requests against schema
    #[serde(default = "default_true")]
    pub validate_requests: bool,

    /// Validate responses against schema
    #[serde(default)]
    pub validate_responses: bool,

    /// Strict validation mode (fail on additional properties)
    #[serde(default)]
    pub strict_mode: bool,
}

// ============================================================================
// Error Page Configuration
// ============================================================================

/// Error page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPageConfig {
    /// Custom error pages by status code
    #[serde(default)]
    pub pages: HashMap<u16, ErrorPage>,

    /// Default error page format
    #[serde(default)]
    pub default_format: ErrorFormat,

    /// Include stack traces in errors (development only)
    #[serde(default)]
    pub include_stack_trace: bool,

    /// Custom error template directory
    pub template_dir: Option<PathBuf>,
}

/// Individual error page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPage {
    /// Error page format
    pub format: ErrorFormat,

    /// Custom template or static file path
    pub template: Option<PathBuf>,

    /// Custom error message
    pub message: Option<String>,

    /// Additional headers to include
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

/// Error response format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorFormat {
    /// HTML error page
    Html,
    /// JSON error response
    Json,
    /// Plain text error
    Text,
    /// XML error response
    Xml,
}

impl Default for ErrorFormat {
    fn default() -> Self {
        ErrorFormat::Html
    }
}
