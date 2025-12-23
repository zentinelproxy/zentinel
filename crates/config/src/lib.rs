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

mod multi_file;
pub use multi_file::{ConfigDirectory, MultiFileLoader};

/// Main configuration structure for Sentinel proxy
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Config {
    /// Global server configuration
    pub server: ServerConfig,

    /// Listener configurations
    #[validate(length(min = 1, message = "At least one listener is required"))]
    pub listeners: Vec<ListenerConfig>,

    /// Route configurations
    pub routes: Vec<RouteConfig>,

    /// Upstream pool configurations
    #[validate(length(min = 1, message = "At least one upstream is required"))]
    pub upstreams: HashMap<String, UpstreamConfig>,

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

    /// Target upstream
    pub upstream: String,

    /// Route-specific policies
    #[serde(default)]
    pub policies: RoutePolicies,

    /// Agents to apply to this route
    #[serde(default)]
    pub agents: Vec<String>,

    /// WAF enabled for this route
    #[serde(default)]
    pub waf_enabled: bool,

    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy
    #[serde(default)]
    pub retry_policy: Option<RetryPolicy>,
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

/// Rate limit policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Requests per second
    pub requests_per_second: u32,

    /// Burst size
    pub burst: u32,

    /// Key to rate limit by
    pub key: RateLimitKey,
}

/// Rate limit key
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    ClientIp,
    Header(String),
    Cookie(String),
    Path,
    Method,
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

// Validation functions
fn validate_socket_addr(addr: &str) -> Result<(), validator::ValidationError> {
    addr.parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| validator::ValidationError::new("invalid_socket_address"))
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

    /// Parse configuration from KDL format
    pub fn from_kdl(content: &str) -> Result<Self> {
        let _doc: kdl::KdlDocument = content
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse KDL: {}", e))?;
        // TODO: Implement KDL to Config conversion
        // For now, return a default config for testing
        Ok(Self::default_for_testing())
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
            // Check that upstream exists
            if !self.upstreams.contains_key(&route.upstream) {
                return Err(SentinelError::Config {
                    message: format!(
                        "Route '{}' references non-existent upstream '{}'",
                        route.id, route.upstream
                    ),
                    source: None,
                });
            }

            // Check that referenced agents exist
            for agent_id in &route.agents {
                if !self.agents.iter().any(|a| a.id == *agent_id) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' references non-existent agent '{}'",
                            route.id, agent_id
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
                upstream: "default".to_string(),
                policies: RoutePolicies::default(),
                agents: vec![],
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
            }],
            upstreams,
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
