use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use validator::{Validate, ValidationError};

/// WAF agent configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// ModSecurity engine configuration
    #[serde(default)]
    pub engine: EngineConfig,

    /// Rules configuration
    #[serde(default)]
    pub rules: RulesConfig,

    /// Body inspection configuration
    #[serde(default)]
    pub body_inspection: BodyInspectionConfig,

    /// Audit logging configuration
    #[serde(default)]
    pub audit: AuditConfig,

    /// Performance tuning
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Exclusions and exceptions
    #[serde(default)]
    pub exclusions: Vec<ExclusionRule>,

    /// Agent listener configuration
    #[serde(default)]
    pub listener: ListenerConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            engine: EngineConfig::default(),
            rules: RulesConfig::default(),
            body_inspection: BodyInspectionConfig::default(),
            audit: AuditConfig::default(),
            performance: PerformanceConfig::default(),
            exclusions: Vec::new(),
            listener: ListenerConfig::default(),
            metrics: MetricsConfig::default(),
        }
    }
}

/// ModSecurity engine configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct EngineConfig {
    /// Enable ModSecurity engine
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Detection only mode (no blocking)
    #[serde(default)]
    pub detection_only: bool,

    /// ModSecurity version (v2 or v3)
    #[serde(default = "default_modsec_version")]
    pub version: String,

    /// Request body access
    #[serde(default = "default_true")]
    pub request_body_access: bool,

    /// Response body access
    #[serde(default)]
    pub response_body_access: bool,

    /// Debug log level (0-9)
    #[validate(range(min = 0, max = 9))]
    #[serde(default)]
    pub debug_level: u8,

    /// Paranoia level for CRS (1-4)
    #[validate(range(min = 1, max = 4))]
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,

    /// Anomaly scoring threshold
    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,

    /// Enable PCRE JIT compilation
    #[serde(default = "default_true")]
    pub pcre_jit: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            enabled: true,
            detection_only: false,
            version: default_modsec_version(),
            request_body_access: true,
            response_body_access: false,
            debug_level: 0,
            paranoia_level: default_paranoia_level(),
            anomaly_threshold: default_anomaly_threshold(),
            pcre_jit: true,
        }
    }
}

/// Rules configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RulesConfig {
    /// Load OWASP Core Rule Set
    #[serde(default = "default_true")]
    pub load_crs: bool,

    /// CRS version
    #[serde(default = "default_crs_version")]
    pub crs_version: String,

    /// Path to CRS rules directory
    pub crs_path: Option<PathBuf>,

    /// Custom rules files
    #[serde(default)]
    pub custom_rules_files: Vec<PathBuf>,

    /// Inline custom rules
    #[serde(default)]
    pub custom_rules: Vec<String>,

    /// Rule exclusions by ID
    #[serde(default)]
    pub exclude_rule_ids: Vec<u32>,

    /// Rule exclusions by tag
    #[serde(default)]
    pub exclude_rule_tags: Vec<String>,

    /// Hot reload rules on file change
    #[serde(default = "default_true")]
    pub hot_reload: bool,

    /// Reload check interval in seconds
    #[validate(range(min = 1, max = 3600))]
    #[serde(default = "default_reload_interval")]
    pub reload_interval_seconds: u32,
}

impl Default for RulesConfig {
    fn default() -> Self {
        RulesConfig {
            load_crs: true,
            crs_version: default_crs_version(),
            crs_path: None,
            custom_rules_files: Vec::new(),
            custom_rules: Vec::new(),
            exclude_rule_ids: Vec::new(),
            exclude_rule_tags: Vec::new(),
            hot_reload: true,
            reload_interval_seconds: default_reload_interval(),
        }
    }
}

/// Body inspection configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BodyInspectionConfig {
    /// Maximum request body size to inspect (bytes)
    #[validate(range(min = 1024, max = 104857600))] // 1KB to 100MB
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: usize,

    /// Maximum response body size to inspect (bytes)
    #[validate(range(min = 1024, max = 104857600))]
    #[serde(default = "default_max_response_body_size")]
    pub max_response_body_size: usize,

    /// Request body buffer limit (bytes)
    #[validate(range(min = 1024, max = 10485760))] // 1KB to 10MB
    #[serde(default = "default_body_buffer_limit")]
    pub request_body_buffer_limit: usize,

    /// Response body buffer limit (bytes)
    #[validate(range(min = 1024, max = 10485760))]
    #[serde(default = "default_body_buffer_limit")]
    pub response_body_buffer_limit: usize,

    /// Content types to inspect for requests
    #[serde(default = "default_request_content_types")]
    pub inspect_request_content_types: Vec<String>,

    /// Content types to inspect for responses
    #[serde(default = "default_response_content_types")]
    pub inspect_response_content_types: Vec<String>,

    /// Enable request body decompression
    #[serde(default = "default_true")]
    pub decompress_request: bool,

    /// Enable response body decompression
    #[serde(default)]
    pub decompress_response: bool,

    /// Maximum decompression ratio
    #[validate(range(min = 1, max = 1000))]
    #[serde(default = "default_decompression_ratio")]
    pub max_decompression_ratio: u32,

    /// Enable multipart parsing
    #[serde(default = "default_true")]
    pub parse_multipart: bool,

    /// Enable JSON parsing
    #[serde(default = "default_true")]
    pub parse_json: bool,

    /// Enable XML parsing
    #[serde(default = "default_true")]
    pub parse_xml: bool,
}

impl Default for BodyInspectionConfig {
    fn default() -> Self {
        BodyInspectionConfig {
            max_request_body_size: default_max_request_body_size(),
            max_response_body_size: default_max_response_body_size(),
            request_body_buffer_limit: default_body_buffer_limit(),
            response_body_buffer_limit: default_body_buffer_limit(),
            inspect_request_content_types: default_request_content_types(),
            inspect_response_content_types: default_response_content_types(),
            decompress_request: true,
            decompress_response: false,
            max_decompression_ratio: default_decompression_ratio(),
            parse_multipart: true,
            parse_json: true,
            parse_xml: true,
        }
    }
}

/// Audit logging configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Audit log directory
    #[serde(default = "default_audit_dir")]
    pub log_dir: PathBuf,

    /// Log all transactions
    #[serde(default)]
    pub log_all: bool,

    /// Log only relevant transactions (with alerts)
    #[serde(default = "default_true")]
    pub log_relevant: bool,

    /// Include request headers in audit log
    #[serde(default = "default_true")]
    pub include_request_headers: bool,

    /// Include request body in audit log
    #[serde(default)]
    pub include_request_body: bool,

    /// Include response headers in audit log
    #[serde(default = "default_true")]
    pub include_response_headers: bool,

    /// Include response body in audit log
    #[serde(default)]
    pub include_response_body: bool,

    /// Maximum audit log file size (bytes)
    #[validate(range(min = 1048576, max = 1073741824))] // 1MB to 1GB
    #[serde(default = "default_max_audit_file_size")]
    pub max_file_size: usize,

    /// Audit log format (JSON, Native, or Concurrent)
    #[serde(default = "default_audit_format")]
    pub format: AuditFormat,

    /// Include rule metadata in logs
    #[serde(default = "default_true")]
    pub include_rule_metadata: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            enabled: true,
            log_dir: default_audit_dir(),
            log_all: false,
            log_relevant: true,
            include_request_headers: true,
            include_request_body: false,
            include_response_headers: true,
            include_response_body: false,
            max_file_size: default_max_audit_file_size(),
            format: default_audit_format(),
            include_rule_metadata: true,
        }
    }
}

/// Audit log format
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditFormat {
    Json,
    Native,
    Concurrent,
}

impl Default for AuditFormat {
    fn default() -> Self {
        AuditFormat::Json
    }
}

/// Performance tuning configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct PerformanceConfig {
    /// Maximum number of concurrent transactions
    #[validate(range(min = 1, max = 100000))]
    #[serde(default = "default_max_concurrent_transactions")]
    pub max_concurrent_transactions: usize,

    /// Transaction pool size
    #[validate(range(min = 10, max = 10000))]
    #[serde(default = "default_transaction_pool_size")]
    pub transaction_pool_size: usize,

    /// Enable request caching
    #[serde(default)]
    pub enable_request_cache: bool,

    /// Request cache size (entries)
    #[validate(range(min = 100, max = 100000))]
    #[serde(default = "default_cache_size")]
    pub request_cache_size: usize,

    /// Cache TTL in seconds
    #[validate(range(min = 1, max = 3600))]
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u32,

    /// Enable rule optimizations
    #[serde(default = "default_true")]
    pub optimize_rules: bool,

    /// Worker threads for async operations
    #[validate(range(min = 1, max = 256))]
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Request timeout in milliseconds
    #[validate(range(min = 10, max = 60000))]
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: u32,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        PerformanceConfig {
            max_concurrent_transactions: default_max_concurrent_transactions(),
            transaction_pool_size: default_transaction_pool_size(),
            enable_request_cache: false,
            request_cache_size: default_cache_size(),
            cache_ttl_seconds: default_cache_ttl(),
            optimize_rules: true,
            worker_threads: default_worker_threads(),
            request_timeout_ms: default_request_timeout(),
        }
    }
}

/// Exclusion rule for bypassing WAF
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ExclusionRule {
    /// Rule name for identification
    pub name: String,

    /// Description of the exclusion
    pub description: Option<String>,

    /// Match conditions
    #[validate]
    pub conditions: Vec<ExclusionCondition>,

    /// Rules to exclude (IDs)
    #[serde(default)]
    pub exclude_rule_ids: Vec<u32>,

    /// Rules to exclude (tags)
    #[serde(default)]
    pub exclude_rule_tags: Vec<String>,

    /// Completely bypass WAF for matching requests
    #[serde(default)]
    pub bypass_waf: bool,

    /// Enable/disable this exclusion
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Exclusion condition
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExclusionCondition {
    /// Match by client IP
    ClientIp {
        #[validate(custom = "validate_ip_or_cidr")]
        value: String,
    },
    /// Match by path
    Path {
        pattern: String,
        #[serde(default)]
        regex: bool,
    },
    /// Match by header
    Header {
        name: String,
        value: String,
        #[serde(default)]
        regex: bool,
    },
    /// Match by query parameter
    QueryParam { name: String, value: Option<String> },
    /// Match by method
    Method { value: String },
    /// Match by host
    Host { value: String },
}

/// Agent listener configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ListenerConfig {
    /// Unix socket path
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Socket permissions (octal)
    #[serde(default = "default_socket_permissions")]
    pub socket_permissions: u32,

    /// Socket owner user
    pub socket_user: Option<String>,

    /// Socket owner group
    pub socket_group: Option<String>,

    /// Maximum concurrent connections
    #[validate(range(min = 1, max = 10000))]
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Connection timeout in milliseconds
    #[validate(range(min = 10, max = 60000))]
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_ms: u32,

    /// Read buffer size
    #[validate(range(min = 4096, max = 1048576))]
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig {
            socket_path: default_socket_path(),
            socket_permissions: default_socket_permissions(),
            socket_user: None,
            socket_group: None,
            max_connections: default_max_connections(),
            connection_timeout_ms: default_connection_timeout(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics endpoint port
    #[validate(range(min = 1024, max = 65535))]
    #[serde(default = "default_metrics_port")]
    pub port: u16,

    /// Metrics endpoint bind address
    #[serde(default = "default_metrics_bind")]
    pub bind_address: String,

    /// Include detailed rule metrics
    #[serde(default)]
    pub detailed_rule_metrics: bool,

    /// Metrics path
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig {
            enabled: true,
            port: default_metrics_port(),
            bind_address: default_metrics_bind(),
            detailed_rule_metrics: false,
            path: default_metrics_path(),
        }
    }
}

// Default value functions
fn default_true() -> bool {
    true
}

fn default_modsec_version() -> String {
    "v3".to_string()
}

fn default_paranoia_level() -> u8 {
    1
}

fn default_anomaly_threshold() -> u32 {
    5
}

fn default_crs_version() -> String {
    "4.0.0".to_string()
}

fn default_reload_interval() -> u32 {
    60
}

fn default_max_request_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_max_response_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_body_buffer_limit() -> usize {
    1024 * 1024 // 1MB
}

fn default_request_content_types() -> Vec<String> {
    vec![
        "application/x-www-form-urlencoded".to_string(),
        "multipart/form-data".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
        "application/soap+xml".to_string(),
    ]
}

fn default_response_content_types() -> Vec<String> {
    vec![
        "text/html".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
    ]
}

fn default_decompression_ratio() -> u32 {
    100
}

fn default_audit_dir() -> PathBuf {
    PathBuf::from("/var/log/sentinel-waf")
}

fn default_max_audit_file_size() -> usize {
    100 * 1024 * 1024 // 100MB
}

fn default_audit_format() -> AuditFormat {
    AuditFormat::Json
}

fn default_max_concurrent_transactions() -> usize {
    10000
}

fn default_transaction_pool_size() -> usize {
    1000
}

fn default_cache_size() -> usize {
    10000
}

fn default_cache_ttl() -> u32 {
    300 // 5 minutes
}

fn default_worker_threads() -> usize {
    num_cpus::get().min(16)
}

fn default_request_timeout() -> u32 {
    5000 // 5 seconds
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/sentinel/waf.sock")
}

fn default_socket_permissions() -> u32 {
    0o660
}

fn default_max_connections() -> usize {
    1000
}

fn default_connection_timeout() -> u32 {
    5000 // 5 seconds
}

fn default_buffer_size() -> usize {
    65536 // 64KB
}

fn default_metrics_port() -> u16 {
    9094
}

fn default_metrics_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

// Custom validation functions
fn validate_ip_or_cidr(value: &str) -> Result<(), ValidationError> {
    // Simple validation - could be enhanced
    if value.contains('/') {
        // CIDR notation
        let parts: Vec<&str> = value.split('/').collect();
        if parts.len() != 2 {
            return Err(ValidationError::new("invalid_cidr"));
        }
    }
    Ok(())
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path))?;

        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))?;

        config
            .validate()
            .context("Configuration validation failed")?;

        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("WAF"))
            .build()
            .context("Failed to load environment configuration")?;

        let config: Config = config
            .try_deserialize()
            .context("Failed to deserialize environment configuration")?;

        config
            .validate()
            .context("Configuration validation failed")?;

        Ok(config)
    }

    /// Merge with another configuration (other takes precedence)
    pub fn merge(self, other: Config) -> Self {
        // Simple merge - could be enhanced with more sophisticated merging
        other
    }

    /// Get default CRS path based on common installation locations
    pub fn find_crs_path(&self) -> Option<PathBuf> {
        if let Some(ref path) = self.rules.crs_path {
            return Some(path.clone());
        }

        let possible_paths = vec![
            "/usr/share/modsecurity-crs",
            "/usr/local/share/modsecurity-crs",
            "/opt/modsecurity-crs",
            "/etc/modsecurity/crs",
            "/usr/local/modsecurity-crs",
        ];

        for path_str in possible_paths {
            let path = PathBuf::from(path_str);
            if path.exists() && path.is_dir() {
                return Some(path);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        config.validate().unwrap();
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        parsed.validate().unwrap();
    }

    #[test]
    fn test_exclusion_condition() {
        let condition = ExclusionCondition::ClientIp {
            value: "192.168.1.0/24".to_string(),
        };
        let yaml = serde_yaml::to_string(&condition).unwrap();
        let parsed: ExclusionCondition = serde_yaml::from_str(&yaml).unwrap();
        match parsed {
            ExclusionCondition::ClientIp { value } => assert_eq!(value, "192.168.1.0/24"),
            _ => panic!("Wrong condition type"),
        }
    }
}
