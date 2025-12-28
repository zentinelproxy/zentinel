//! Configuration module for Sentinel proxy
//!
//! This module provides configuration parsing, validation, and hot-reload support
//! with a focus on safety, security-first defaults, and operational clarity.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use validator::Validate;

use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    limits::Limits,
    types::{
        ByteSize, CircuitBreakerConfig, HealthCheckType, LoadBalancingAlgorithm, Priority,
        RetryPolicy, TlsVersion,
    },
};

mod defaults;
mod filters;
mod multi_file;

pub use defaults::{create_default_config, DEFAULT_CONFIG_KDL};
pub use filters::*;
pub use multi_file::{ConfigDirectory, MultiFileLoader};

/// Main configuration structure for Sentinel proxy
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_config_semantics"))]
pub struct Config {
    /// Global server configuration
    pub server: ServerConfig,

    /// Listener configurations
    #[validate(length(min = 1, message = "At least one listener is required"))]
    pub listeners: Vec<ListenerConfig>,

    /// Route configurations
    pub routes: Vec<RouteConfig>,

    /// Upstream pool configurations (can be empty if all routes are static)
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Named filter configurations (referenced by routes)
    #[serde(default)]
    pub filters: HashMap<String, FilterConfig>,

    /// Agent configurations
    #[serde(default)]
    pub agents: Vec<AgentConfig>,

    /// WAF configuration
    #[serde(default)]
    pub waf: Option<WafConfig>,

    /// Global limits configuration
    #[serde(default)]
    pub limits: Limits,

    /// Observability configuration
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Default upstream for Phase 0 testing
    #[serde(skip)]
    pub default_upstream: Option<UpstreamPeer>,
}

/// Server-wide configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerConfig {
    /// Number of worker threads (0 = number of CPU cores)
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Maximum number of connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Graceful shutdown timeout
    #[serde(default = "default_graceful_shutdown_timeout")]
    pub graceful_shutdown_timeout_secs: u64,

    /// Enable daemon mode
    #[serde(default)]
    pub daemon: bool,

    /// PID file path
    pub pid_file: Option<PathBuf>,

    /// User to switch to after binding
    pub user: Option<String>,

    /// Group to switch to after binding
    pub group: Option<String>,

    /// Working directory
    pub working_directory: Option<PathBuf>,
}

/// Listener configuration (port binding)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ListenerConfig {
    /// Unique identifier for this listener
    pub id: String,

    /// Socket address to bind to
    #[validate(custom(function = "validate_socket_addr"))]
    pub address: String,

    /// Protocol (http, https)
    pub protocol: ListenerProtocol,

    /// TLS configuration (required for https)
    pub tls: Option<TlsConfig>,

    /// Default route if no other matches
    pub default_route: Option<String>,

    /// Request timeout
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,

    /// Keep-alive timeout
    #[serde(default = "default_keepalive_timeout")]
    pub keepalive_timeout_secs: u64,

    /// Maximum concurrent streams (HTTP/2)
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
}

/// Listener protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerProtocol {
    Http,
    Https,
    #[serde(rename = "h2")]
    Http2,
    #[serde(rename = "h3")]
    Http3,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_file: PathBuf,

    /// Private key file path
    pub key_file: PathBuf,

    /// CA certificate file path for client verification
    pub ca_file: Option<PathBuf>,

    /// Minimum TLS version
    #[serde(default = "default_min_tls_version")]
    pub min_version: TlsVersion,

    /// Maximum TLS version
    pub max_version: Option<TlsVersion>,

    /// Cipher suites (empty = use defaults)
    #[serde(default)]
    pub cipher_suites: Vec<String>,

    /// Require client certificates
    #[serde(default)]
    pub client_auth: bool,

    /// OCSP stapling
    #[serde(default = "default_ocsp_stapling")]
    pub ocsp_stapling: bool,

    /// Session resumption
    #[serde(default = "default_session_resumption")]
    pub session_resumption: bool,
}

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
    #[serde(default = "default_service_type")]
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
}

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
}

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

/// Error page configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPageConfig {
    /// Custom error pages by status code
    #[serde(default)]
    pub pages: HashMap<u16, ErrorPage>,

    /// Default error page format
    #[serde(default = "default_error_format")]
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
    pub key: filters::RateLimitKey,
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

/// Upstream timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTimeouts {
    /// Connection timeout
    #[serde(default = "default_connect_timeout")]
    pub connect_secs: u64,

    /// Request timeout
    #[serde(default = "default_request_timeout")]
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
            request_secs: default_request_timeout(),
            read_secs: default_read_timeout(),
            write_secs: default_write_timeout(),
        }
    }
}

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

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub id: String,

    /// Agent type
    #[serde(rename = "type")]
    pub agent_type: AgentType,

    /// Transport configuration
    pub transport: AgentTransport,

    /// Events this agent handles
    pub events: Vec<AgentEvent>,

    /// Timeout for agent calls
    #[serde(default = "default_agent_timeout")]
    pub timeout_ms: u64,

    /// Failure mode when agent is unavailable
    #[serde(default = "default_failure_mode")]
    pub failure_mode: FailureMode,

    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Maximum request body to send
    pub max_request_body_bytes: Option<usize>,

    /// Maximum response body to send
    pub max_response_body_bytes: Option<usize>,
}

/// Agent type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Waf,
    Auth,
    RateLimit,
    Custom(String),
}

/// Agent transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransport {
    /// Unix domain socket
    UnixSocket { path: PathBuf },

    /// gRPC over TCP
    Grpc {
        address: String,
        tls: Option<AgentTlsConfig>,
    },

    /// HTTP REST API
    Http {
        url: String,
        tls: Option<AgentTlsConfig>,
    },
}

/// Agent TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTlsConfig {
    /// Skip certificate verification
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// CA certificate
    pub ca_cert: Option<PathBuf>,

    /// Client certificate for mTLS
    pub client_cert: Option<PathBuf>,

    /// Client key for mTLS
    pub client_key: Option<PathBuf>,
}

/// Agent events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEvent {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Log,
}

/// WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// WAF engine type
    pub engine: WafEngine,

    /// Rule set configuration
    pub ruleset: WafRuleset,

    /// Global WAF mode
    #[serde(default = "default_waf_mode")]
    pub mode: WafMode,

    /// Audit logging
    #[serde(default = "default_waf_audit")]
    pub audit_log: bool,

    /// Body inspection policy
    #[serde(default)]
    pub body_inspection: BodyInspectionPolicy,
}

/// WAF engine type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafEngine {
    ModSecurity,
    Coraza,
    Custom(String),
}

/// WAF ruleset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRuleset {
    /// CRS version
    pub crs_version: String,

    /// Custom rules directory
    pub custom_rules_dir: Option<PathBuf>,

    /// Paranoia level (1-4)
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,

    /// Anomaly threshold
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,

    /// Rule exclusions
    #[serde(default)]
    pub exclusions: Vec<RuleExclusion>,
}

/// WAF rule exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExclusion {
    /// Rule IDs to exclude
    pub rule_ids: Vec<String>,

    /// Exclusion scope
    pub scope: ExclusionScope,
}

/// Exclusion scope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionScope {
    Global,
    Path(String),
    Host(String),
}

/// WAF mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    Detection,
    Prevention,
}

/// Body inspection policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyInspectionPolicy {
    /// Enable request body inspection
    #[serde(default = "default_inspect_request_body")]
    pub inspect_request_body: bool,

    /// Enable response body inspection
    #[serde(default)]
    pub inspect_response_body: bool,

    /// Maximum body size to inspect
    #[serde(default = "default_max_inspection_size")]
    pub max_inspection_bytes: usize,

    /// Content types to inspect
    #[serde(default = "default_inspected_content_types")]
    pub content_types: Vec<String>,

    /// Enable decompression for inspection
    #[serde(default)]
    pub decompress: bool,

    /// Maximum decompression ratio
    #[serde(default = "default_max_decompression_ratio")]
    pub max_decompression_ratio: f32,
}

impl Default for BodyInspectionPolicy {
    fn default() -> Self {
        Self {
            inspect_request_body: default_inspect_request_body(),
            inspect_response_body: false,
            max_inspection_bytes: default_max_inspection_size(),
            content_types: default_inspected_content_types(),
            decompress: false,
            max_decompression_ratio: default_max_decompression_ratio(),
        }
    }
}

/// Observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Tracing configuration
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig::default(),
            logging: LoggingConfig::default(),
            tracing: None,
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint address
    #[serde(default = "default_metrics_address")]
    pub address: String,

    /// Metrics path
    #[serde(default = "default_metrics_path")]
    pub path: String,

    /// Include high-cardinality metrics
    #[serde(default)]
    pub high_cardinality: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            address: default_metrics_address(),
            path: default_metrics_path(),
            high_cardinality: false,
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format (json, pretty)
    #[serde(default = "default_log_format")]
    pub format: String,

    /// Include timestamps
    #[serde(default = "default_true")]
    pub timestamps: bool,

    /// Log file path (stdout if not specified)
    pub file: Option<PathBuf>,

    /// Access log configuration
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            timestamps: default_true(),
            file: None,
            access_log: None,
        }
    }
}

/// Access log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogConfig {
    /// Enable access logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Access log file path
    pub file: PathBuf,

    /// Log format
    #[serde(default = "default_access_log_format")]
    pub format: String,

    /// Buffer size
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Tracing backend
    pub backend: TracingBackend,

    /// Sampling rate (0.0 - 1.0)
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f64,

    /// Service name
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

/// Tracing backend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracingBackend {
    Jaeger { endpoint: String },
    Zipkin { endpoint: String },
    Otlp { endpoint: String },
}

// For Phase 0 testing
#[derive(Debug, Clone)]
pub struct UpstreamPeer {
    pub address: String,
    pub tls: bool,
    pub host: String,
    pub connect_timeout_secs: u64,
    pub read_timeout_secs: u64,
    pub write_timeout_secs: u64,
}

// Default value functions
fn default_worker_threads() -> usize {
    0
}
fn default_max_connections() -> usize {
    10000
}
fn default_graceful_shutdown_timeout() -> u64 {
    30
}
fn default_request_timeout() -> u64 {
    60
}
fn default_keepalive_timeout() -> u64 {
    75
}
fn default_max_concurrent_streams() -> u32 {
    100
}
fn default_min_tls_version() -> TlsVersion {
    TlsVersion::Tls12
}
fn default_ocsp_stapling() -> bool {
    true
}
fn default_session_resumption() -> bool {
    true
}
fn default_failure_mode() -> FailureMode {
    FailureMode::Closed
}
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
fn default_connect_timeout() -> u64 {
    10
}
fn default_read_timeout() -> u64 {
    30
}
fn default_write_timeout() -> u64 {
    30
}
fn default_agent_timeout() -> u64 {
    1000
}
fn default_waf_mode() -> WafMode {
    WafMode::Prevention
}
fn default_waf_audit() -> bool {
    true
}
fn default_paranoia_level() -> u8 {
    1
}
fn default_anomaly_threshold() -> u32 {
    5
}
fn default_inspect_request_body() -> bool {
    true
}
fn default_max_inspection_size() -> usize {
    1024 * 1024
}
fn default_inspected_content_types() -> Vec<String> {
    vec![
        "application/x-www-form-urlencoded".to_string(),
        "multipart/form-data".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
    ]
}
fn default_max_decompression_ratio() -> f32 {
    100.0
}
fn default_true() -> bool {
    true
}
fn default_metrics_address() -> String {
    "0.0.0.0:9090".to_string()
}
fn default_metrics_path() -> String {
    "/metrics".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_access_log_format() -> String {
    "combined".to_string()
}
fn default_buffer_size() -> usize {
    8192
}
fn default_sampling_rate() -> f64 {
    0.01
}
fn default_service_name() -> String {
    "sentinel".to_string()
}
fn default_service_type() -> ServiceType {
    ServiceType::Web
}
fn default_index_file() -> String {
    "index.html".to_string()
}
fn default_cache_control() -> String {
    "public, max-age=3600".to_string()
}
fn default_error_format() -> ErrorFormat {
    ErrorFormat::Html
}

// Validation functions
fn validate_socket_addr(addr: &str) -> Result<(), validator::ValidationError> {
    addr.parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| {
            let mut err = validator::ValidationError::new("invalid_socket_address");
            err.message = Some(std::borrow::Cow::Owned(format!(
                "Invalid socket address '{}'. Expected format: IP:PORT (e.g., '127.0.0.1:8080' or '0.0.0.0:443')",
                addr
            )));
            err
        })
}

/// Comprehensive semantic validation for the entire configuration
fn validate_config_semantics(config: &Config) -> Result<(), validator::ValidationError> {
    let mut errors: Vec<String> = Vec::new();

    // Collect route information for validation
    let route_ids: std::collections::HashSet<_> = config.routes.iter().map(|r| r.id.as_str()).collect();
    let upstream_ids: std::collections::HashSet<_> = config.upstreams.keys().map(|s| s.as_str()).collect();
    let agent_ids: std::collections::HashSet<_> = config.agents.iter().map(|a| a.id.as_str()).collect();

    // Determine which routes need upstreams (non-static routes)
    let routes_needing_upstreams: Vec<_> = config
        .routes
        .iter()
        .filter(|r| r.service_type != ServiceType::Static && r.upstream.is_some())
        .collect();

    let routes_missing_upstream_config: Vec<_> = config
        .routes
        .iter()
        .filter(|r| {
            r.service_type != ServiceType::Static
            && r.service_type != ServiceType::Builtin
            && r.upstream.is_none()
            && r.static_files.is_none()
        })
        .collect();

    // === Validate routes have necessary upstream references ===
    for route in &routes_needing_upstreams {
        if let Some(ref upstream_id) = route.upstream {
            if !upstream_ids.contains(upstream_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references upstream '{}' which doesn't exist.\n\
                     Available upstreams: {}\n\
                     Hint: Add an upstream block or fix the reference:\n\
                     \n\
                     upstreams {{\n\
                         upstream \"{}\" {{\n\
                             target \"127.0.0.1:8080\" weight=1\n\
                         }}\n\
                     }}",
                    route.id,
                    upstream_id,
                    if upstream_ids.is_empty() { "(none defined)".to_string() } else { upstream_ids.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ") },
                    upstream_id
                ));
            }
        }
    }

    // === Validate non-static routes without upstream or static-files ===
    for route in &routes_missing_upstream_config {
        errors.push(format!(
            "Route '{}' has no upstream and no static-files configuration.\n\
             Each route must either:\n\
             1. Reference an upstream: upstream \"my-backend\"\n\
             2. Serve static files: static-files {{ root \"/var/www/html\" }}\n\
             \n\
             Example with upstream:\n\
             route \"{}\" {{\n\
                 matches {{ path-prefix \"/\" }}\n\
                 upstream \"my-backend\"\n\
             }}\n\
             \n\
             Example with static files:\n\
             route \"{}\" {{\n\
                 matches {{ path-prefix \"/\" }}\n\
                 static-files {{\n\
                     root \"/var/www/html\"\n\
                     index \"index.html\"\n\
                 }}\n\
             }}",
            route.id, route.id, route.id
        ));
    }

    // === Validate listener default-route references ===
    for listener in &config.listeners {
        if let Some(ref default_route) = listener.default_route {
            if !route_ids.contains(default_route.as_str()) {
                errors.push(format!(
                    "Listener '{}' references default-route '{}' which doesn't exist.\n\
                     Available routes: {}\n\
                     Hint: Either create the route or update the listener's default-route.",
                    listener.id,
                    default_route,
                    if route_ids.is_empty() { "(none defined)".to_string() } else { route_ids.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ") }
                ));
            }
        }
    }

    // === Validate filter references in routes ===
    let filter_ids: std::collections::HashSet<_> = config.filters.keys().map(|s| s.as_str()).collect();

    for route in &config.routes {
        for filter_id in &route.filters {
            if !filter_ids.contains(filter_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references filter '{}' which doesn't exist.\n\
                     Available filters: {}\n\
                     Hint: Define the filter in the top-level filters block:\n\
                     \n\
                     filters {{\n\
                         filter \"{}\" {{\n\
                             type \"agent\"\n\
                             agent \"my-agent\"\n\
                         }}\n\
                     }}",
                    route.id,
                    filter_id,
                    if filter_ids.is_empty() { "(none defined)".to_string() } else { filter_ids.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ") },
                    filter_id
                ));
            }
        }
    }

    // === Validate agent references in filter definitions ===
    for (filter_id, filter_config) in &config.filters {
        if let Filter::Agent(agent_filter) = &filter_config.filter {
            if !agent_ids.contains(agent_filter.agent.as_str()) {
                errors.push(format!(
                    "Filter '{}' references agent '{}' which doesn't exist.\n\
                     Available agents: {}\n\
                     Hint: Add an agent configuration or update the filter.",
                    filter_id,
                    agent_filter.agent,
                    if agent_ids.is_empty() { "(none defined)".to_string() } else { agent_ids.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(", ") }
                ));
            }
        }
    }

    // === Validate duplicate route IDs ===
    let mut seen_routes = std::collections::HashSet::new();
    for route in &config.routes {
        if !seen_routes.insert(&route.id) {
            errors.push(format!(
                "Duplicate route ID '{}'. Each route must have a unique identifier.",
                route.id
            ));
        }
    }

    // === Validate duplicate listener IDs ===
    let mut seen_listeners = std::collections::HashSet::new();
    for listener in &config.listeners {
        if !seen_listeners.insert(&listener.id) {
            errors.push(format!(
                "Duplicate listener ID '{}'. Each listener must have a unique identifier.",
                listener.id
            ));
        }
    }

    // === Validate duplicate listener addresses ===
    let mut seen_addresses = std::collections::HashSet::new();
    for listener in &config.listeners {
        if !seen_addresses.insert(&listener.address) {
            errors.push(format!(
                "Duplicate listener address '{}'. Multiple listeners cannot bind to the same address.\n\
                 Hint: Use different ports or IP addresses for each listener.",
                listener.address
            ));
        }
    }

    // === Warn about orphaned upstreams (upstreams not referenced by any route) ===
    // Note: This is a warning, not an error - logged but doesn't fail validation
    let referenced_upstreams: std::collections::HashSet<_> = config
        .routes
        .iter()
        .filter_map(|r| r.upstream.as_ref())
        .map(|s| s.as_str())
        .collect();

    for upstream_id in &upstream_ids {
        if !referenced_upstreams.contains(*upstream_id) {
            // Log warning but don't add to errors
            tracing::warn!(
                upstream_id = %upstream_id,
                "Upstream '{}' is defined but not referenced by any route. Consider removing it or adding a route that uses it.",
                upstream_id
            );
        }
    }

    // === Validate upstream targets ===
    for (upstream_id, upstream) in &config.upstreams {
        if upstream.targets.is_empty() {
            errors.push(format!(
                "Upstream '{}' has no targets defined.\n\
                 Each upstream must have at least one target:\n\
                 \n\
                 upstream \"{}\" {{\n\
                     target \"127.0.0.1:8080\" weight=1\n\
                     target \"127.0.0.1:8081\" weight=1\n\
                 }}",
                upstream_id, upstream_id
            ));
        }

        for (i, target) in upstream.targets.iter().enumerate() {
            if target.address.parse::<SocketAddr>().is_err() {
                // Try parsing as host:port (could be a hostname)
                let parts: Vec<&str> = target.address.rsplitn(2, ':').collect();
                if parts.len() != 2 || parts[0].parse::<u16>().is_err() {
                    errors.push(format!(
                        "Upstream '{}' target #{} has invalid address '{}'.\n\
                         Expected format: HOST:PORT (e.g., '127.0.0.1:8080' or 'backend.local:8080')",
                        upstream_id,
                        i + 1,
                        target.address
                    ));
                }
            }
        }
    }

    // === Validate routes have at least one match condition (unless it's a catch-all) ===
    for route in &config.routes {
        if route.matches.is_empty() && route.priority != Priority::Low {
            errors.push(format!(
                "Route '{}' has no match conditions.\n\
                 Add at least one match condition (path-prefix, path, host, etc.) or set priority to \"low\" for catch-all routes:\n\
                 \n\
                 matches {{\n\
                     path-prefix \"/api\"\n\
                 }}",
                route.id
            ));
        }
    }

    // === Validate static file configurations ===
    for route in &config.routes {
        if let Some(ref static_config) = route.static_files {
            if !static_config.root.exists() {
                errors.push(format!(
                    "Route '{}' static files root directory '{}' does not exist.\n\
                     Create the directory or update the configuration:\n\
                     \n\
                     # Create the directory:\n\
                     mkdir -p {}\n\
                     \n\
                     # Or update the config:\n\
                     static-files {{\n\
                         root \"/path/to/existing/directory\"\n\
                     }}",
                    route.id,
                    static_config.root.display(),
                    static_config.root.display()
                ));
            } else if !static_config.root.is_dir() {
                errors.push(format!(
                    "Route '{}' static files root '{}' exists but is not a directory.\n\
                     The 'root' must be a directory path, not a file.",
                    route.id,
                    static_config.root.display()
                ));
            }

            // Check if route has both upstream and static-files (ambiguous)
            if route.upstream.is_some() {
                errors.push(format!(
                    "Route '{}' has both 'upstream' and 'static-files' configured.\n\
                     A route can only serve one type of content. Choose either:\n\
                     - Remove 'upstream' to serve static files\n\
                     - Remove 'static-files' to proxy to an upstream backend",
                    route.id
                ));
            }
        }
    }

    // === Build final error ===
    if errors.is_empty() {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("config_validation_failed");
        let error_summary = if errors.len() == 1 {
            errors[0].clone()
        } else {
            format!(
                "Configuration has {} issues:\n\n{}",
                errors.len(),
                errors.iter().enumerate()
                    .map(|(i, e)| format!("{}. {}", i + 1, e))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            )
        };
        err.message = Some(std::borrow::Cow::Owned(error_summary));
        Err(err)
    }
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("kdl");

        match extension {
            "kdl" => Self::from_kdl(&content),
            "json" => Self::from_json(&content),
            "toml" => Self::from_toml(&content),
            _ => Err(anyhow::anyhow!("Unsupported config format: {}", extension)),
        }
    }

    /// Load the default embedded configuration.
    ///
    /// This is used when no configuration file is provided. It parses the
    /// embedded KDL configuration, falling back to the programmatic default
    /// if KDL parsing fails for any reason.
    pub fn default_embedded() -> Result<Self> {
        Self::from_kdl(DEFAULT_CONFIG_KDL).or_else(|e| {
            tracing::warn!(
                "Failed to parse embedded KDL config, using programmatic default: {}",
                e
            );
            Ok(create_default_config())
        })
    }

    /// Parse configuration from KDL format
    pub fn from_kdl(content: &str) -> Result<Self> {
        let doc: kdl::KdlDocument = content.parse().map_err(|e: kdl::KdlError| {
            // KDL 6.0 uses miette for error reporting
            // Extract diagnostic information from the error
            use miette::Diagnostic;

            let mut error_msg = String::new();
            error_msg.push_str("KDL configuration parse error:\n\n");

            // Get related diagnostics from the error
            let mut found_details = false;
            if let Some(related) = e.related() {
                for diagnostic in related {
                    // Each diagnostic is a KdlDiagnostic with span, message, help, label
                    let diag_str = format!("{}", diagnostic);
                    error_msg.push_str(&format!("  {}\n", diag_str));
                    found_details = true;

                    // Try to get source location from the diagnostic's labels
                    if let Some(labels) = diagnostic.labels() {
                        for label in labels {
                            let offset = label.offset();
                            let (line, col) = offset_to_line_col(content, offset);
                            error_msg.push_str(&format!("\n  --> at line {}, column {}\n", line, col));

                            // Show the problematic line with context
                            let lines: Vec<&str> = content.lines().collect();

                            // Show context before
                            if line > 1 {
                                if let Some(lc) = lines.get(line.saturating_sub(2)) {
                                    error_msg.push_str(&format!("{:>4} | {}\n", line - 1, lc));
                                }
                            }

                            // Show the problematic line
                            if let Some(line_content) = lines.get(line.saturating_sub(1)) {
                                error_msg.push_str(&format!("{:>4} | {}\n", line, line_content));
                                error_msg.push_str(&format!("     | {}^", " ".repeat(col.saturating_sub(1))));
                                if let Some(label_msg) = label.label() {
                                    error_msg.push_str(&format!(" {}", label_msg));
                                }
                                error_msg.push('\n');
                            }

                            // Show context after
                            if let Some(lc) = lines.get(line) {
                                error_msg.push_str(&format!("{:>4} | {}\n", line + 1, lc));
                            }
                        }
                    }

                    // Include help from diagnostic if available
                    if let Some(help) = diagnostic.help() {
                        error_msg.push_str(&format!("\n  Help: {}\n", help));
                    }
                }
            }

            // If no related diagnostics, show the main error
            if !found_details {
                error_msg.push_str(&format!("  {}\n", e));
                error_msg.push_str("\n  Note: Check your KDL syntax. Common issues:\n");
                error_msg.push_str("    - Unclosed strings (missing closing quote)\n");
                error_msg.push_str("    - Unclosed blocks (missing closing brace)\n");
                error_msg.push_str("    - Invalid node names or values\n");
                error_msg.push_str("    - Incorrect indentation or whitespace\n");
            }

            // Include top-level help if available
            if let Some(help) = e.help() {
                error_msg.push_str(&format!("\n  Help: {}\n", help));
            }

            anyhow::anyhow!("{}", error_msg)
        })?;

        Self::from_kdl_document(doc)
    }

    /// Convert a parsed KDL document to Config
    fn from_kdl_document(doc: kdl::KdlDocument) -> Result<Self> {
        // Parse the KDL document into configuration
        let mut server = None;
        let mut listeners = Vec::new();
        let mut routes = Vec::new();
        let mut upstreams = HashMap::new();
        let mut filters = HashMap::new();
        let mut agents = Vec::new();
        let mut waf = None;
        let mut limits = None;
        let mut observability = None;

        for node in doc.nodes() {
            match node.name().value() {
                "server" => {
                    server = Some(parse_server_config(node)?);
                }
                "listeners" => {
                    listeners = parse_listeners(node)?;
                }
                "routes" => {
                    routes = parse_routes(node)?;
                }
                "upstreams" => {
                    upstreams = parse_upstreams(node)?;
                }
                "filters" => {
                    filters = parse_filter_definitions(node)?;
                }
                "agents" => {
                    agents = parse_agents(node)?;
                }
                "waf" => {
                    waf = Some(parse_waf_config(node)?);
                }
                "limits" => {
                    limits = Some(parse_limits_config(node)?);
                }
                "observability" => {
                    observability = Some(parse_observability_config(node)?);
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "Unknown top-level configuration block: '{}'\n\
                         Valid blocks are: server, listeners, routes, upstreams, filters, agents, waf, limits, observability",
                        other
                    ));
                }
            }
        }

        // Validate required sections
        let server = server.ok_or_else(|| {
            anyhow::anyhow!(
                "Missing required 'server' configuration block\n\
                 Example:\n\
                 server {{\n\
                     worker-threads 4\n\
                     max-connections 10000\n\
                 }}"
            )
        })?;

        if listeners.is_empty() {
            return Err(anyhow::anyhow!(
                "Missing required 'listeners' configuration block\n\
                 Example:\n\
                 listeners {{\n\
                     listener \"http\" {{\n\
                         address \"0.0.0.0:8080\"\n\
                         protocol \"http\"\n\
                     }}\n\
                 }}"
            ));
        }

        // Note: Semantic validation (route-upstream relationships, etc.) is handled
        // by validate_config_semantics which runs when config.validate() is called

        Ok(Config {
            server,
            listeners,
            routes,
            upstreams,
            filters,
            agents,
            waf,
            limits: limits.unwrap_or_default(),
            observability: observability.unwrap_or_default(),
            default_upstream: None,
        })
    }

    /// Parse configuration from JSON format
    pub fn from_json(content: &str) -> Result<Self> {
        serde_json::from_str(content).context("Failed to parse JSON configuration")
    }

    /// Parse configuration from TOML format
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).context("Failed to parse TOML configuration")
    }

    /// Validate the configuration
    pub fn validate(&self) -> SentinelResult<()> {
        // Use the validator crate for structural validation
        Validate::validate(self).map_err(|e| SentinelError::Config {
            message: format!("Configuration validation failed: {}", e),
            source: None,
        })?;

        // Additional semantic validation
        self.validate_routes()?;
        self.validate_upstreams()?;
        self.validate_agents()?;
        self.limits.validate()?;

        Ok(())
    }

    fn validate_routes(&self) -> SentinelResult<()> {
        for route in &self.routes {
            // Check that upstream exists (if specified)
            if let Some(upstream) = &route.upstream {
                if !self.upstreams.contains_key(upstream) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' references non-existent upstream '{}'",
                            route.id, upstream
                        ),
                        source: None,
                    });
                }
            }

            // Check that referenced filter IDs exist
            for filter_id in &route.filters {
                if !self.filters.contains_key(filter_id) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' references non-existent filter '{}'",
                            route.id, filter_id
                        ),
                        source: None,
                    });
                }
            }
        }

        // Validate agent references in filter definitions
        for (filter_id, filter_config) in &self.filters {
            if let Filter::Agent(agent_filter) = &filter_config.filter {
                if !self.agents.iter().any(|a| a.id == agent_filter.agent) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Filter '{}' references non-existent agent '{}'",
                            filter_id, agent_filter.agent
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    fn validate_upstreams(&self) -> SentinelResult<()> {
        for (id, upstream) in &self.upstreams {
            if upstream.targets.is_empty() {
                return Err(SentinelError::Config {
                    message: format!("Upstream '{}' has no targets", id),
                    source: None,
                });
            }
        }
        Ok(())
    }

    fn validate_agents(&self) -> SentinelResult<()> {
        for agent in &self.agents {
            // Validate agent timeout is reasonable
            if agent.timeout_ms == 0 {
                return Err(SentinelError::Config {
                    message: format!("Agent '{}' has invalid timeout", agent.id),
                    source: None,
                });
            }

            // Validate transport configuration
            match &agent.transport {
                AgentTransport::UnixSocket { path } => {
                    if !path.exists() && !path.parent().map_or(false, |p| p.exists()) {
                        return Err(SentinelError::Config {
                            message: format!(
                                "Agent '{}' unix socket path parent directory doesn't exist: {:?}",
                                agent.id, path
                            ),
                            source: None,
                        });
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Create a default configuration for testing
    pub fn default_for_testing() -> Self {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "default".to_string(),
            UpstreamConfig {
                id: "default".to_string(),
                targets: vec![UpstreamTarget {
                    address: "127.0.0.1:8081".to_string(),
                    weight: 1,
                    max_requests: None,
                    metadata: HashMap::new(),
                }],
                load_balancing: LoadBalancingAlgorithm::RoundRobin,
                health_check: None,
                connection_pool: ConnectionPoolConfig::default(),
                timeouts: UpstreamTimeouts::default(),
                tls: None,
            },
        );

        Self {
            server: ServerConfig {
                worker_threads: 4,
                max_connections: 1000,
                graceful_shutdown_timeout_secs: 30,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                working_directory: None,
            },
            listeners: vec![ListenerConfig {
                id: "http".to_string(),
                address: "0.0.0.0:8080".to_string(),
                protocol: ListenerProtocol::Http,
                tls: None,
                default_route: Some("default".to_string()),
                request_timeout_secs: 60,
                keepalive_timeout_secs: 75,
                max_concurrent_streams: 100,
            }],
            routes: vec![RouteConfig {
                id: "default".to_string(),
                priority: Priority::Normal,
                matches: vec![MatchCondition::PathPrefix("/".to_string())],
                upstream: Some("default".to_string()),
                service_type: ServiceType::Web,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: None,
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
            }],
            upstreams,
            filters: HashMap::new(),
            agents: vec![],
            waf: None,
            limits: Limits::for_testing(),
            observability: ObservabilityConfig::default(),
            default_upstream: Some(UpstreamPeer {
                address: "127.0.0.1:8081".to_string(),
                tls: false,
                host: "localhost".to_string(),
                connect_timeout_secs: 10,
                read_timeout_secs: 30,
                write_timeout_secs: 30,
            }),
        }
    }

    /// Reload configuration from the same file path
    pub fn reload(&mut self, path: impl AsRef<Path>) -> SentinelResult<()> {
        let new_config = Self::from_file(path).map_err(|e| SentinelError::Config {
            message: format!("Failed to reload configuration: {}", e),
            source: None,
        })?;

        new_config.validate()?;

        // Atomically replace the configuration
        *self = new_config;
        Ok(())
    }

    /// Get a route by ID
    pub fn get_route(&self, id: &str) -> Option<&RouteConfig> {
        self.routes.iter().find(|r| r.id == id)
    }

    /// Get an upstream by ID
    pub fn get_upstream(&self, id: &str) -> Option<&UpstreamConfig> {
        self.upstreams.get(id)
    }

    /// Get an agent by ID
    pub fn get_agent(&self, id: &str) -> Option<&AgentConfig> {
        self.agents.iter().find(|a| a.id == id)
    }
}

// ============================================================================
// KDL Parsing Helper Functions
// ============================================================================

/// Convert a byte offset to line and column numbers (1-indexed)
fn offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in content.chars().enumerate() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Helper to get a string entry from a KDL node
fn get_string_entry(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Helper to get an integer entry from a KDL node
fn get_int_entry(node: &kdl::KdlNode, name: &str) -> Option<i128> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer())
}

/// Helper to get a boolean entry from a KDL node
fn get_bool_entry(node: &kdl::KdlNode, name: &str) -> Option<bool> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool())
}

/// Helper to get the first argument of a node as a string
fn get_first_arg_string(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Parse server configuration block
fn parse_server_config(node: &kdl::KdlNode) -> Result<ServerConfig> {
    Ok(ServerConfig {
        worker_threads: get_int_entry(node, "worker-threads")
            .map(|v| v as usize)
            .unwrap_or_else(default_worker_threads),
        max_connections: get_int_entry(node, "max-connections")
            .map(|v| v as usize)
            .unwrap_or_else(default_max_connections),
        graceful_shutdown_timeout_secs: get_int_entry(node, "graceful-shutdown-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or_else(default_graceful_shutdown_timeout),
        daemon: get_bool_entry(node, "daemon").unwrap_or(false),
        pid_file: get_string_entry(node, "pid-file").map(PathBuf::from),
        user: get_string_entry(node, "user"),
        group: get_string_entry(node, "group"),
        working_directory: get_string_entry(node, "working-directory").map(PathBuf::from),
    })
}

/// Parse listeners configuration block
fn parse_listeners(node: &kdl::KdlNode) -> Result<Vec<ListenerConfig>> {
    let mut listeners = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "listener" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener requires an ID argument, e.g., listener \"http\" {{ ... }}"
                    )
                })?;

                let address = get_string_entry(child, "address").ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener '{}' requires an 'address' field, e.g., address \"0.0.0.0:8080\"",
                        id
                    )
                })?;

                let protocol_str = get_string_entry(child, "protocol").unwrap_or_else(|| "http".to_string());
                let protocol = match protocol_str.to_lowercase().as_str() {
                    "http" => ListenerProtocol::Http,
                    "https" => ListenerProtocol::Https,
                    "h2" => ListenerProtocol::Http2,
                    "h3" => ListenerProtocol::Http3,
                    other => {
                        return Err(anyhow::anyhow!(
                            "Invalid protocol '{}' for listener '{}'. Valid protocols: http, https, h2, h3",
                            other,
                            id
                        ));
                    }
                };

                listeners.push(ListenerConfig {
                    id,
                    address,
                    protocol,
                    tls: None, // TODO: Parse TLS config
                    default_route: get_string_entry(child, "default-route"),
                    request_timeout_secs: get_int_entry(child, "request-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_request_timeout),
                    keepalive_timeout_secs: get_int_entry(child, "keepalive-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_keepalive_timeout),
                    max_concurrent_streams: get_int_entry(child, "max-concurrent-streams")
                        .map(|v| v as u32)
                        .unwrap_or_else(default_max_concurrent_streams),
                });
            }
        }
    }

    Ok(listeners)
}

/// Parse routes configuration block
fn parse_routes(node: &kdl::KdlNode) -> Result<Vec<RouteConfig>> {
    let mut routes = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "route" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Route requires an ID argument, e.g., route \"api\" {{ ... }}"
                    )
                })?;

                // Parse matches
                let mut matches = Vec::new();
                if let Some(route_children) = child.children() {
                    if let Some(matches_node) = route_children.get("matches") {
                        if let Some(match_children) = matches_node.children() {
                            for match_node in match_children.nodes() {
                                match match_node.name().value() {
                                    "path-prefix" => {
                                        if let Some(prefix) = get_first_arg_string(match_node) {
                                            matches.push(MatchCondition::PathPrefix(prefix));
                                        }
                                    }
                                    "path" => {
                                        if let Some(path) = get_first_arg_string(match_node) {
                                            matches.push(MatchCondition::Path(path));
                                        }
                                    }
                                    "host" => {
                                        if let Some(host) = get_first_arg_string(match_node) {
                                            matches.push(MatchCondition::Host(host));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }

                // Parse priority
                let priority_str = get_string_entry(child, "priority");
                let priority = match priority_str.as_deref() {
                    Some("high") => Priority::High,
                    Some("low") => Priority::Low,
                    _ => Priority::Normal,
                };

                // Parse upstream (can be null for static routes)
                let upstream = if let Some(route_children) = child.children() {
                    if let Some(upstream_node) = route_children.get("upstream") {
                        let entry = upstream_node.entries().first();
                        match entry.and_then(|e| e.value().as_string()) {
                            Some(s) => Some(s.to_string()),
                            None => {
                                // Check if it's explicitly null
                                if entry.map(|e| e.value().is_null()).unwrap_or(false) {
                                    None
                                } else {
                                    None
                                }
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse static-files configuration if present
                let static_files = if let Some(route_children) = child.children() {
                    if let Some(static_node) = route_children.get("static-files") {
                        Some(parse_static_file_config(static_node)?)
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse filters - list of filter IDs referencing top-level filter definitions
                // Syntax: filters ["filter-id-1" "filter-id-2"]
                let filters = if let Some(route_children) = child.children() {
                    if let Some(filters_node) = route_children.get("filters") {
                        parse_route_filter_refs(filters_node)?
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };

                // Parse builtin-handler for Builtin service types
                let builtin_handler = get_string_entry(child, "builtin-handler")
                    .and_then(|s| match s.as_str() {
                        "status" => Some(BuiltinHandler::Status),
                        "health" => Some(BuiltinHandler::Health),
                        "metrics" => Some(BuiltinHandler::Metrics),
                        "not-found" | "not_found" => Some(BuiltinHandler::NotFound),
                        _ => None,
                    });

                // Determine service type based on config
                let service_type = if static_files.is_some() {
                    ServiceType::Static
                } else if builtin_handler.is_some() {
                    ServiceType::Builtin
                } else {
                    ServiceType::Web
                };

                routes.push(RouteConfig {
                    id,
                    priority,
                    matches,
                    upstream,
                    service_type,
                    policies: RoutePolicies::default(),
                    filters,
                    builtin_handler,
                    waf_enabled: get_bool_entry(child, "waf-enabled").unwrap_or(false),
                    circuit_breaker: None,
                    retry_policy: None,
                    static_files,
                    api_schema: None,
                    error_pages: None,
                });
            }
        }
    }

    Ok(routes)
}

/// Parse filter ID references from a route
/// Syntax: filters ["auth" "rate-limit" "waf"]
/// Order is significant - filters execute in array order
fn parse_route_filter_refs(node: &kdl::KdlNode) -> Result<Vec<String>> {
    let mut filter_ids = Vec::new();

    // Parse array of filter IDs from node arguments
    for entry in node.entries() {
        if let Some(id) = entry.value().as_string() {
            filter_ids.push(id.to_string());
        }
    }

    Ok(filter_ids)
}

/// Parse top-level filter definitions block
/// Syntax:
/// ```kdl
/// filters {
///     filter "strict-auth" {
///         type "agent"
///         agent "auth-agent"
///         timeout-ms 100
///     }
///     filter "api-rate-limit" {
///         type "rate-limit"
///         max-rps 100
///     }
/// }
/// ```
fn parse_filter_definitions(node: &kdl::KdlNode) -> Result<HashMap<String, FilterConfig>> {
    let mut filters = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "filter" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Filter requires an ID argument, e.g., filter \"my-rate-limit\" {{ ... }}"
                    )
                })?;

                let filter = parse_single_filter_definition(child)?;
                filters.insert(id.clone(), FilterConfig::new(id, filter));
            }
        }
    }

    Ok(filters)
}

/// Parse a single filter definition
fn parse_single_filter_definition(node: &kdl::KdlNode) -> Result<Filter> {
    let filter_type = get_string_entry(node, "type").ok_or_else(|| {
        anyhow::anyhow!(
            "Filter definition requires a 'type' field. Valid types: rate-limit, agent, headers, compress, cors, timeout, log"
        )
    })?;

    match filter_type.as_str() {
        "rate-limit" => {
            let max_rps = get_int_entry(node, "max-rps")
                .map(|v| v as u32)
                .unwrap_or(100);
            let burst = get_int_entry(node, "burst")
                .map(|v| v as u32)
                .unwrap_or(10);
            let status_code = get_int_entry(node, "status-code")
                .map(|v| v as u16)
                .unwrap_or(429);

            let key = get_string_entry(node, "key")
                .map(|s| match s.as_str() {
                    "client-ip" => RateLimitKey::ClientIp,
                    "path" => RateLimitKey::Path,
                    "route" => RateLimitKey::Route,
                    "client-ip-and-path" => RateLimitKey::ClientIpAndPath,
                    header if header.starts_with("header:") => {
                        RateLimitKey::Header(header.trim_start_matches("header:").to_string())
                    }
                    _ => RateLimitKey::ClientIp,
                })
                .unwrap_or(RateLimitKey::ClientIp);

            let on_limit = get_string_entry(node, "on-limit")
                .map(|s| match s.as_str() {
                    "reject" => RateLimitAction::Reject,
                    "delay" => RateLimitAction::Delay,
                    "log-only" => RateLimitAction::LogOnly,
                    _ => RateLimitAction::Reject,
                })
                .unwrap_or(RateLimitAction::Reject);

            Ok(Filter::RateLimit(RateLimitFilter {
                max_rps,
                burst,
                key,
                on_limit,
                status_code,
                limit_message: get_string_entry(node, "message"),
            }))
        }
        "agent" => {
            let agent = get_string_entry(node, "agent").ok_or_else(|| {
                anyhow::anyhow!(
                    "Agent filter requires an 'agent' field referencing an agent definition"
                )
            })?;

            let timeout_ms = get_int_entry(node, "timeout-ms").map(|v| v as u64);
            let failure_mode = get_string_entry(node, "failure-mode")
                .and_then(|s| match s.as_str() {
                    "open" => Some(FailureMode::Open),
                    "closed" => Some(FailureMode::Closed),
                    _ => None,
                });

            let phase = get_string_entry(node, "phase")
                .and_then(|s| match s.as_str() {
                    "request" => Some(FilterPhase::Request),
                    "response" => Some(FilterPhase::Response),
                    "both" => Some(FilterPhase::Both),
                    _ => None,
                });

            Ok(Filter::Agent(AgentFilter {
                agent,
                phase,
                timeout_ms,
                failure_mode,
                inspect_body: get_bool_entry(node, "inspect-body").unwrap_or(false),
                max_body_bytes: get_int_entry(node, "max-body-bytes").map(|v| v as usize),
            }))
        }
        "headers" => {
            let mut set = std::collections::HashMap::new();
            let mut add = std::collections::HashMap::new();
            let mut remove = Vec::new();

            if let Some(node_children) = node.children() {
                if let Some(set_node) = node_children.get("set") {
                    if let Some(set_children) = set_node.children() {
                        for entry_node in set_children.nodes() {
                            let name = entry_node.name().value().to_string();
                            if let Some(value) = get_first_arg_string(entry_node) {
                                set.insert(name, value);
                            }
                        }
                    }
                }
                if let Some(add_node) = node_children.get("add") {
                    if let Some(add_children) = add_node.children() {
                        for entry_node in add_children.nodes() {
                            let name = entry_node.name().value().to_string();
                            if let Some(value) = get_first_arg_string(entry_node) {
                                add.insert(name, value);
                            }
                        }
                    }
                }
                if let Some(remove_node) = node_children.get("remove") {
                    for entry in remove_node.entries() {
                        if let Some(name) = entry.value().as_string() {
                            remove.push(name.to_string());
                        }
                    }
                }
            }

            let phase = get_string_entry(node, "phase")
                .and_then(|s| match s.as_str() {
                    "request" => Some(FilterPhase::Request),
                    "response" => Some(FilterPhase::Response),
                    "both" => Some(FilterPhase::Both),
                    _ => None,
                })
                .unwrap_or(FilterPhase::Request);

            Ok(Filter::Headers(HeadersFilter { phase, set, add, remove }))
        }
        "compress" => {
            let algorithms_str = get_string_entry(node, "algorithms")
                .unwrap_or_else(|| "gzip,br".to_string());
            let algorithms: Vec<CompressionAlgorithm> = algorithms_str
                .split(',')
                .filter_map(|s| match s.trim() {
                    "gzip" => Some(CompressionAlgorithm::Gzip),
                    "br" | "brotli" => Some(CompressionAlgorithm::Brotli),
                    "deflate" => Some(CompressionAlgorithm::Deflate),
                    "zstd" => Some(CompressionAlgorithm::Zstd),
                    _ => None,
                })
                .collect();

            let min_size = get_int_entry(node, "min-size")
                .map(|v| v as usize)
                .unwrap_or(1024);

            Ok(Filter::Compress(CompressFilter {
                algorithms,
                min_size,
                content_types: vec![
                    "text/html".into(),
                    "text/css".into(),
                    "application/json".into(),
                    "application/javascript".into(),
                ],
                level: get_int_entry(node, "level").map(|v| v as u8).unwrap_or(6),
            }))
        }
        "cors" => Ok(Filter::Cors(CorsFilter::default())),
        "timeout" => Ok(Filter::Timeout(TimeoutFilter {
            request_timeout_secs: get_int_entry(node, "request-timeout-secs").map(|v| v as u64),
            upstream_timeout_secs: get_int_entry(node, "upstream-timeout-secs").map(|v| v as u64),
            connect_timeout_secs: get_int_entry(node, "connect-timeout-secs").map(|v| v as u64),
        })),
        "log" => Ok(Filter::Log(LogFilter {
            log_request: get_bool_entry(node, "log-request").unwrap_or(true),
            log_response: get_bool_entry(node, "log-response").unwrap_or(true),
            log_body: get_bool_entry(node, "log-body").unwrap_or(false),
            max_body_log_size: get_int_entry(node, "max-body-log-size")
                .map(|v| v as usize)
                .unwrap_or(4096),
            fields: vec![],
            level: get_string_entry(node, "level").unwrap_or_else(|| "info".to_string()),
        })),
        other => Err(anyhow::anyhow!(
            "Unknown filter type: '{}'. Valid types: rate-limit, agent, headers, compress, cors, timeout, log",
            other
        )),
    }
}

/// Parse filters configuration block within a route (legacy inline format)
/// Kept for backward compatibility during migration
fn parse_filters(node: &kdl::KdlNode) -> Result<Vec<Filter>> {
    let mut filters = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            let filter = match child.name().value() {
                "rate-limit" => {
                    let max_rps = get_int_entry(child, "max-rps")
                        .map(|v| v as u32)
                        .unwrap_or(100);
                    let burst = get_int_entry(child, "burst")
                        .map(|v| v as u32)
                        .unwrap_or(10);
                    let status_code = get_int_entry(child, "status-code")
                        .map(|v| v as u16)
                        .unwrap_or(429);

                    // Parse rate limit key (what to bucket by)
                    let key = get_string_entry(child, "key")
                        .map(|s| match s.as_str() {
                            "client-ip" => RateLimitKey::ClientIp,
                            "path" => RateLimitKey::Path,
                            "route" => RateLimitKey::Route,
                            "client-ip-and-path" => RateLimitKey::ClientIpAndPath,
                            header if header.starts_with("header:") => {
                                RateLimitKey::Header(header.trim_start_matches("header:").to_string())
                            }
                            _ => RateLimitKey::ClientIp,
                        })
                        .unwrap_or(RateLimitKey::ClientIp);

                    // Parse action when limit is exceeded
                    let on_limit = get_string_entry(child, "on-limit")
                        .map(|s| match s.as_str() {
                            "reject" => RateLimitAction::Reject,
                            "delay" => RateLimitAction::Delay,
                            "log-only" => RateLimitAction::LogOnly,
                            _ => RateLimitAction::Reject,
                        })
                        .unwrap_or(RateLimitAction::Reject);

                    Filter::RateLimit(RateLimitFilter {
                        max_rps,
                        burst,
                        key,
                        on_limit,
                        status_code,
                        limit_message: get_string_entry(child, "message"),
                    })
                }
                "agent" => {
                    let agent = get_first_arg_string(child).ok_or_else(|| {
                        anyhow::anyhow!("agent filter requires an agent ID")
                    })?;
                    let timeout_ms = get_int_entry(child, "timeout-ms").map(|v| v as u64);
                    let failure_mode = get_string_entry(child, "failure-mode")
                        .and_then(|s| match s.as_str() {
                            "open" => Some(FailureMode::Open),
                            "closed" => Some(FailureMode::Closed),
                            _ => None,
                        });

                    Filter::Agent(AgentFilter {
                        agent,
                        phase: None,
                        timeout_ms,
                        failure_mode,
                        inspect_body: get_bool_entry(child, "inspect-body").unwrap_or(false),
                        max_body_bytes: get_int_entry(child, "max-body-bytes").map(|v| v as usize),
                    })
                }
                "headers" => {
                    let mut set = std::collections::HashMap::new();
                    let mut add = std::collections::HashMap::new();
                    let mut remove = Vec::new();

                    if let Some(header_children) = child.children() {
                        for header_child in header_children.nodes() {
                            match header_child.name().value() {
                                "set" => {
                                    // set "Header-Name" "value"
                                    if let (Some(name), Some(value)) = (
                                        header_child.entries().first().and_then(|e| e.value().as_string()),
                                        header_child.entries().get(1).and_then(|e| e.value().as_string()),
                                    ) {
                                        set.insert(name.to_string(), value.to_string());
                                    }
                                }
                                "add" => {
                                    if let (Some(name), Some(value)) = (
                                        header_child.entries().first().and_then(|e| e.value().as_string()),
                                        header_child.entries().get(1).and_then(|e| e.value().as_string()),
                                    ) {
                                        add.insert(name.to_string(), value.to_string());
                                    }
                                }
                                "remove" => {
                                    if let Some(name) = get_first_arg_string(header_child) {
                                        remove.push(name);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    let phase = get_string_entry(child, "phase")
                        .and_then(|s| match s.as_str() {
                            "request" => Some(FilterPhase::Request),
                            "response" => Some(FilterPhase::Response),
                            "both" => Some(FilterPhase::Both),
                            _ => None,
                        })
                        .unwrap_or(FilterPhase::Request);

                    Filter::Headers(HeadersFilter { phase, set, add, remove })
                }
                "compress" => {
                    let algorithms_str = get_string_entry(child, "algorithms")
                        .unwrap_or_else(|| "gzip,br".to_string());
                    let algorithms: Vec<CompressionAlgorithm> = algorithms_str
                        .split(',')
                        .filter_map(|s| match s.trim() {
                            "gzip" => Some(CompressionAlgorithm::Gzip),
                            "br" | "brotli" => Some(CompressionAlgorithm::Brotli),
                            "deflate" => Some(CompressionAlgorithm::Deflate),
                            "zstd" => Some(CompressionAlgorithm::Zstd),
                            _ => None,
                        })
                        .collect();

                    let min_size = get_int_entry(child, "min-size")
                        .map(|v| v as usize)
                        .unwrap_or(1024);

                    Filter::Compress(CompressFilter {
                        algorithms,
                        min_size,
                        content_types: vec![
                            "text/html".into(),
                            "text/css".into(),
                            "application/json".into(),
                            "application/javascript".into(),
                        ],
                        level: 6,
                    })
                }
                "cors" => {
                    Filter::Cors(CorsFilter::default())
                }
                "timeout" => {
                    Filter::Timeout(TimeoutFilter {
                        request_timeout_secs: get_int_entry(child, "request-timeout-secs").map(|v| v as u64),
                        upstream_timeout_secs: get_int_entry(child, "upstream-timeout-secs").map(|v| v as u64),
                        connect_timeout_secs: get_int_entry(child, "connect-timeout-secs").map(|v| v as u64),
                    })
                }
                "log" => {
                    Filter::Log(LogFilter {
                        log_request: get_bool_entry(child, "log-request").unwrap_or(true),
                        log_response: get_bool_entry(child, "log-response").unwrap_or(true),
                        log_body: get_bool_entry(child, "log-body").unwrap_or(false),
                        max_body_log_size: get_int_entry(child, "max-body-log-size")
                            .map(|v| v as usize)
                            .unwrap_or(4096),
                        fields: vec![],
                        level: get_string_entry(child, "level").unwrap_or_else(|| "info".to_string()),
                    })
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "Unknown filter type: '{}'. Valid types: rate-limit, agent, headers, compress, cors, timeout, log",
                        other
                    ));
                }
            };
            filters.push(filter);
        }
    }

    Ok(filters)
}

/// Parse upstreams configuration block
fn parse_upstreams(node: &kdl::KdlNode) -> Result<HashMap<String, UpstreamConfig>> {
    let mut upstreams = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "upstream" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Upstream requires an ID argument, e.g., upstream \"backend\" {{ ... }}"
                    )
                })?;

                // Parse targets
                let mut targets = Vec::new();
                if let Some(upstream_children) = child.children() {
                    for target_node in upstream_children.nodes() {
                        if target_node.name().value() == "target" {
                            if let Some(address) = get_first_arg_string(target_node) {
                                // Get weight from named argument
                                let weight = target_node
                                    .entries()
                                    .iter()
                                    .find(|e| e.name().map(|n| n.value()) == Some("weight"))
                                    .and_then(|e| e.value().as_integer())
                                    .map(|v| v as u32)
                                    .unwrap_or(1);

                                targets.push(UpstreamTarget {
                                    address,
                                    weight,
                                    max_requests: None,
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }

                if targets.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Upstream '{}' requires at least one target, e.g., target \"127.0.0.1:8081\"",
                        id
                    ));
                }

                upstreams.insert(
                    id.clone(),
                    UpstreamConfig {
                        id,
                        targets,
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        health_check: None,
                        connection_pool: ConnectionPoolConfig::default(),
                        timeouts: UpstreamTimeouts::default(),
                        tls: None,
                    },
                );
            }
        }
    }

    Ok(upstreams)
}

/// Parse agents configuration block
fn parse_agents(_node: &kdl::KdlNode) -> Result<Vec<AgentConfig>> {
    // TODO: Implement full agent parsing
    Ok(vec![])
}

/// Parse WAF configuration block
fn parse_waf_config(_node: &kdl::KdlNode) -> Result<WafConfig> {
    // TODO: Implement full WAF config parsing
    Err(anyhow::anyhow!("WAF configuration parsing not yet implemented"))
}

/// Parse limits configuration block
fn parse_limits_config(node: &kdl::KdlNode) -> Result<Limits> {
    let mut limits = Limits::default();

    // Override defaults with any values from the config
    if let Some(v) = get_int_entry(node, "max-header-size") {
        limits.max_header_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-header-count") {
        limits.max_header_count = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-body-size") {
        limits.max_body_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-connections-per-client") {
        limits.max_connections_per_client = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-total-connections") {
        limits.max_total_connections = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-in-flight-requests") {
        limits.max_in_flight_requests = v as usize;
    }

    Ok(limits)
}

/// Parse observability configuration block
fn parse_observability_config(_node: &kdl::KdlNode) -> Result<ObservabilityConfig> {
    // TODO: Implement full observability config parsing
    Ok(ObservabilityConfig::default())
}

/// Parse static file configuration block
fn parse_static_file_config(node: &kdl::KdlNode) -> Result<StaticFileConfig> {
    let root = get_string_entry(node, "root").ok_or_else(|| {
        anyhow::anyhow!(
            "Static files configuration requires a 'root' directory, e.g., root \"/var/www/html\""
        )
    })?;

    Ok(StaticFileConfig {
        root: PathBuf::from(root),
        index: get_string_entry(node, "index").unwrap_or_else(|| "index.html".to_string()),
        directory_listing: get_bool_entry(node, "directory-listing").unwrap_or(false),
        cache_control: get_string_entry(node, "cache-control")
            .unwrap_or_else(|| "public, max-age=3600".to_string()),
        compress: get_bool_entry(node, "compress").unwrap_or(true),
        mime_types: HashMap::new(), // TODO: Parse custom MIME types
        fallback: get_string_entry(node, "fallback"),
    })
}
