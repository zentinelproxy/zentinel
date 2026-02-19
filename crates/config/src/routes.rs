//! Route configuration types
//!
//! This module contains configuration types for routing requests
//! to upstreams or static file handlers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::Validate;

use zentinel_common::budget::{CostAttributionConfig, TokenBudgetConfig};
use zentinel_common::types::{ByteSize, CircuitBreakerConfig, Priority, RetryPolicy};

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

    /// Inference configuration (for service_type = Inference)
    #[serde(default)]
    pub inference: Option<InferenceConfig>,

    /// Error page configuration
    #[serde(default)]
    pub error_pages: Option<ErrorPageConfig>,

    /// Enable WebSocket upgrade support for this route (default: false)
    /// When enabled, HTTP Upgrade requests with "websocket" protocol are allowed.
    /// Pingora handles the actual WebSocket tunneling transparently.
    #[serde(default)]
    pub websocket: bool,

    /// Enable WebSocket frame inspection (default: false)
    /// When enabled, individual WebSocket frames are sent to agents for inspection.
    /// Agents can allow, drop, or close the connection based on frame content.
    /// Requires `websocket: true` to have any effect.
    /// Note: If `permessage-deflate` compression is negotiated, inspection is skipped.
    #[serde(default)]
    pub websocket_inspection: bool,

    /// Traffic mirroring / shadowing configuration
    /// Mirrors requests to a shadow upstream for safe canary testing
    #[serde(default)]
    pub shadow: Option<ShadowConfig>,

    /// Fallback routing configuration
    /// Enables automatic failover to alternative upstreams on failure
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
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
#[derive(Default)]
pub enum ServiceType {
    /// Traditional web service (default)
    #[default]
    Web,
    /// REST API service with JSON responses
    Api,
    /// Static file hosting
    Static,
    /// Built-in handler (status page, health check, etc.)
    Builtin,
    /// LLM/AI inference endpoint with token-based rate limiting
    Inference,
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

// ============================================================================
// Global Cache Storage Configuration
// ============================================================================

/// Global cache storage configuration
///
/// Controls the underlying storage backend for HTTP caching.
/// This is separate from per-route cache policies which control
/// what gets cached and for how long.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStorageConfig {
    /// Enable HTTP caching globally (default: true when cache block is present)
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,

    /// Storage backend type
    #[serde(default)]
    pub backend: CacheBackend,

    /// Maximum cache size in bytes (default: 100MB)
    #[serde(default = "default_cache_storage_size")]
    pub max_size_bytes: usize,

    /// Eviction limit in bytes (when to start evicting, default: same as max_size)
    #[serde(default)]
    pub eviction_limit_bytes: Option<usize>,

    /// Cache lock timeout in seconds (prevents thundering herd)
    #[serde(default = "default_cache_lock_timeout")]
    pub lock_timeout_secs: u64,

    /// Path for disk-based cache (only used with Disk backend)
    #[serde(default)]
    pub disk_path: Option<PathBuf>,

    /// Number of shards for disk cache (improves concurrent access)
    #[serde(default = "default_disk_shards")]
    pub disk_shards: u32,

    /// Add Cache-Status response header (RFC 9211) for cache observability
    #[serde(default)]
    pub status_header: bool,
}

impl Default for CacheStorageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backend: CacheBackend::Memory,
            max_size_bytes: default_cache_storage_size(),
            eviction_limit_bytes: None,
            lock_timeout_secs: default_cache_lock_timeout(),
            disk_path: None,
            disk_shards: default_disk_shards(),
            status_header: false,
        }
    }
}

/// Cache storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheBackend {
    /// In-memory cache (fast, but lost on restart)
    #[default]
    Memory,
    /// Disk-based cache (persistent, larger capacity)
    Disk,
    /// Hybrid: memory for hot entries, disk for cold
    Hybrid,
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_storage_size() -> usize {
    100 * 1024 * 1024 // 100MB
}

fn default_cache_lock_timeout() -> u64 {
    10 // 10 seconds
}

fn default_disk_shards() -> u32 {
    16
}

/// Header modification rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderModifications {
    /// Headers to rename (old_name -> new_name, applied before set/add/remove)
    #[serde(default)]
    pub rename: HashMap<String, String>,

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    Open, // Allow traffic through on failure
    #[default]
    Closed, // Block traffic on failure (default for security)
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
    /// OpenAPI/Swagger schema file path (mutually exclusive with schema_content)
    pub schema_file: Option<PathBuf>,

    /// Inline OpenAPI/Swagger schema content (YAML or JSON string)
    /// Mutually exclusive with schema_file
    pub schema_content: Option<String>,

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
#[derive(Default)]
pub enum ErrorFormat {
    /// HTML error page
    #[default]
    Html,
    /// JSON error response
    Json,
    /// Plain text error
    Text,
    /// XML error response
    Xml,
}

// ============================================================================
// Shadow / Traffic Mirroring Configuration
// ============================================================================

/// Traffic mirroring (shadow) configuration
///
/// Enables fire-and-forget request duplication to a shadow upstream
/// for safe canary deployments and testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowConfig {
    /// Shadow target upstream ID
    pub upstream: String,

    /// Sampling percentage (0.0-100.0)
    /// Only this percentage of requests will be mirrored
    #[serde(default = "default_shadow_percentage")]
    pub percentage: f64,

    /// Only shadow requests with this header match
    /// Format: (header_name, header_value)
    pub sample_header: Option<(String, String)>,

    /// Shadow request timeout in milliseconds
    #[serde(default = "default_shadow_timeout_ms")]
    pub timeout_ms: u64,

    /// Whether to buffer request bodies for mirroring
    /// Required for POST/PUT/PATCH requests with bodies
    #[serde(default)]
    pub buffer_body: bool,

    /// Maximum body size to mirror (bytes)
    #[serde(default = "default_shadow_max_body_bytes")]
    pub max_body_bytes: usize,
}

fn default_shadow_percentage() -> f64 {
    100.0 // Mirror all requests by default
}

fn default_shadow_timeout_ms() -> u64 {
    5000 // 5 seconds
}

fn default_shadow_max_body_bytes() -> usize {
    1048576 // 1 MB
}

// ============================================================================
// Inference Configuration (for ServiceType::Inference)
// ============================================================================

/// Inference routing configuration for LLM/AI endpoints
///
/// Provides token-based rate limiting, model-aware load balancing,
/// and multi-provider support for inference traffic.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InferenceConfig {
    /// Inference provider (determines token extraction strategy)
    #[serde(default)]
    pub provider: InferenceProvider,

    /// Header containing model name (optional, provider-specific default)
    pub model_header: Option<String>,

    /// Token-based rate limiting configuration (per-minute)
    pub rate_limit: Option<TokenRateLimit>,

    /// Token budget configuration (per-period cumulative tracking)
    pub budget: Option<TokenBudgetConfig>,

    /// Cost attribution configuration (per-model pricing)
    pub cost_attribution: Option<CostAttributionConfig>,

    /// Inference-aware routing configuration
    pub routing: Option<InferenceRouting>,

    /// Model-based upstream routing configuration
    pub model_routing: Option<ModelRoutingConfig>,

    /// Semantic guardrails configuration (prompt injection, PII detection)
    pub guardrails: Option<GuardrailsConfig>,
}

/// Inference provider type (determines token counting strategy)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InferenceProvider {
    /// Generic provider (uses x-tokens-used header or estimation)
    #[default]
    Generic,
    /// OpenAI API (uses x-ratelimit-remaining-tokens header)
    OpenAi,
    /// Anthropic API (uses anthropic-ratelimit-tokens-remaining header)
    Anthropic,
}

impl InferenceProvider {
    /// Returns the string label for this provider (for metrics and logging).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }
}

/// Token-based rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRateLimit {
    /// Maximum tokens per minute
    pub tokens_per_minute: u64,

    /// Maximum requests per minute (optional, dual tracking)
    pub requests_per_minute: Option<u64>,

    /// Burst tokens allowed above rate
    #[serde(default = "default_burst_tokens")]
    pub burst_tokens: u64,

    /// Token estimation method (fallback when headers unavailable)
    #[serde(default)]
    pub estimation_method: TokenEstimation,
}

fn default_burst_tokens() -> u64 {
    10000
}

/// Token estimation method for request sizing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenEstimation {
    /// Character count / 4 (fast, rough estimate)
    #[default]
    Chars,
    /// Word count * 1.3 (slightly more accurate)
    Words,
    /// Actual tiktoken encoding (accurate but slower, feature-gated)
    Tiktoken,
}

/// Inference-aware routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRouting {
    /// Load balancing strategy for inference traffic
    #[serde(default)]
    pub strategy: InferenceRoutingStrategy,

    /// Header to read queue depth from upstream (optional)
    pub queue_depth_header: Option<String>,
}

/// Inference-specific load balancing strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InferenceRoutingStrategy {
    /// Route to upstream with least tokens queued (default)
    #[default]
    LeastTokensQueued,
    /// Standard round-robin
    RoundRobin,
    /// Route to upstream with lowest observed latency
    LeastLatency,
}

// ============================================================================
// Model-Based Routing Configuration
// ============================================================================

/// Model-based routing configuration for inference requests.
///
/// Routes requests to different upstreams based on the model name in the request.
/// Supports glob patterns for flexible model matching (e.g., `gpt-4*`, `claude-*`).
///
/// # Example KDL Configuration
/// ```kdl
/// model-routing {
///     model "gpt-4" upstream="openai-primary"
///     model "gpt-4*" upstream="openai-primary"
///     model "claude-*" upstream="anthropic-backend" provider="anthropic"
///     default-upstream "openai-primary"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModelRoutingConfig {
    /// Ordered list of model-to-upstream mappings (first match wins).
    /// Supports exact matches and glob patterns with `*` wildcard.
    #[serde(default)]
    pub mappings: Vec<ModelUpstreamMapping>,

    /// Default upstream when no mapping matches (overrides route's upstream).
    /// If not set, falls back to the route's configured upstream.
    pub default_upstream: Option<String>,
}

/// A single model-to-upstream mapping.
///
/// Maps a model name (or pattern) to a specific upstream pool.
/// Optionally overrides the inference provider for cross-provider routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelUpstreamMapping {
    /// Model name pattern. Can be:
    /// - Exact match: `"gpt-4"`, `"claude-3-opus"`
    /// - Glob pattern: `"gpt-4*"`, `"claude-*"`, `"*-turbo"`
    pub model_pattern: String,

    /// Target upstream pool for requests matching this model.
    pub upstream: String,

    /// Optional provider override for cross-provider routing.
    /// When set, the inference provider will be switched for token
    /// extraction and rate limiting purposes.
    pub provider: Option<InferenceProvider>,
}

// ============================================================================
// Fallback Routing Configuration
// ============================================================================

/// Fallback routing configuration for automatic failover
///
/// Enables requests to automatically fail over to alternative upstreams
/// when the primary upstream is unhealthy, exhausted, or returns errors.
/// Supports cross-provider failback with model mapping.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FallbackConfig {
    /// Ordered list of fallback upstreams (tried in order)
    #[serde(default)]
    pub upstreams: Vec<FallbackUpstream>,

    /// Triggers that activate fallback behavior
    #[serde(default)]
    pub triggers: FallbackTriggers,

    /// Maximum number of fallback attempts before giving up
    #[serde(default = "default_max_fallback_attempts")]
    pub max_attempts: u32,
}

/// A single fallback upstream with optional model mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackUpstream {
    /// Upstream pool ID to fallback to
    pub upstream: String,

    /// Provider type for this upstream (for correct token extraction)
    #[serde(default)]
    pub provider: InferenceProvider,

    /// Model mapping from primary model to this provider's equivalent
    /// Key: original model name (or pattern with * wildcard), Value: replacement model name
    #[serde(default)]
    pub model_mapping: HashMap<String, String>,

    /// Skip this fallback if its health check reports unhealthy
    #[serde(default)]
    pub skip_if_unhealthy: bool,
}

/// Triggers that activate fallback routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackTriggers {
    /// Trigger on health check failure of primary upstream
    #[serde(default = "default_true")]
    pub on_health_failure: bool,

    /// Trigger when token budget is exhausted
    #[serde(default)]
    pub on_budget_exhausted: bool,

    /// Trigger when latency exceeds threshold (milliseconds)
    #[serde(default)]
    pub on_latency_threshold_ms: Option<u64>,

    /// Trigger on specific HTTP error codes from upstream
    #[serde(default)]
    pub on_error_codes: Vec<u16>,

    /// Trigger on connection errors (refused, timeout, etc.)
    #[serde(default = "default_true")]
    pub on_connection_error: bool,
}

impl Default for FallbackTriggers {
    fn default() -> Self {
        Self {
            on_health_failure: true,
            on_budget_exhausted: false,
            on_latency_threshold_ms: None,
            on_error_codes: Vec::new(),
            on_connection_error: true,
        }
    }
}

fn default_max_fallback_attempts() -> u32 {
    3
}

// ============================================================================
// Semantic Guardrails Configuration
// ============================================================================

/// Semantic guardrails configuration for inference routes.
///
/// Enables content inspection via external agents for security:
/// - Prompt injection detection on requests
/// - PII detection on responses
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GuardrailsConfig {
    /// Prompt injection detection configuration
    pub prompt_injection: Option<PromptInjectionConfig>,

    /// PII detection configuration
    pub pii_detection: Option<PiiDetectionConfig>,
}

/// Prompt injection detection configuration.
///
/// Detects and optionally blocks requests containing prompt injection attempts.
/// Uses an external agent for content analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptInjectionConfig {
    /// Enable prompt injection detection
    #[serde(default)]
    pub enabled: bool,

    /// Name of the agent to use for inspection
    pub agent: String,

    /// Action to take when injection is detected
    #[serde(default)]
    pub action: GuardrailAction,

    /// HTTP status code when blocking (default: 400)
    #[serde(default = "default_guardrail_block_status")]
    pub block_status: u16,

    /// Custom message when blocking
    pub block_message: Option<String>,

    /// Agent timeout in milliseconds (default: 500)
    #[serde(default = "default_prompt_injection_timeout_ms")]
    pub timeout_ms: u64,

    /// Behavior when agent times out or fails
    #[serde(default)]
    pub failure_mode: GuardrailFailureMode,
}

/// PII detection configuration.
///
/// Detects sensitive data (SSN, credit cards, emails, etc.) in responses.
/// Uses an external agent for content analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiDetectionConfig {
    /// Enable PII detection
    #[serde(default)]
    pub enabled: bool,

    /// Name of the agent to use for inspection
    pub agent: String,

    /// Action to take when PII is detected
    #[serde(default)]
    pub action: PiiAction,

    /// PII categories to detect (e.g., "ssn", "credit-card", "email", "phone")
    #[serde(default)]
    pub categories: Vec<String>,

    /// Agent timeout in milliseconds (default: 1000)
    #[serde(default = "default_pii_detection_timeout_ms")]
    pub timeout_ms: u64,

    /// Behavior when agent times out or fails
    #[serde(default)]
    pub failure_mode: GuardrailFailureMode,
}

/// Action to take when a guardrail detects an issue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GuardrailAction {
    /// Block the request and return an error
    Block,
    /// Log the detection but allow the request (default)
    #[default]
    Log,
    /// Allow request but add warning header to response
    Warn,
}

/// Action to take when PII is detected in responses
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PiiAction {
    /// Log the detection only (default)
    #[default]
    Log,
    /// Redact PII in response (non-streaming only)
    Redact,
    /// Block response (non-streaming only)
    Block,
}

/// Failure mode for guardrail agents (when agent times out or errors)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GuardrailFailureMode {
    /// Allow request to proceed on agent failure (fail-open, default)
    #[default]
    Open,
    /// Block request on agent failure (fail-closed)
    Closed,
}

fn default_guardrail_block_status() -> u16 {
    400
}

fn default_prompt_injection_timeout_ms() -> u64 {
    500
}

fn default_pii_detection_timeout_ms() -> u64 {
    1000
}
