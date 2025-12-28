//! Observability configuration types
//!
//! This module contains configuration types for metrics, logging,
//! and distributed tracing.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// Observability Configuration
// ============================================================================

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

// ============================================================================
// Metrics Configuration
// ============================================================================

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

// ============================================================================
// Logging Configuration
// ============================================================================

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

    /// Application log file path (stdout if not specified)
    pub file: Option<PathBuf>,

    /// Access log configuration
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,

    /// Error log configuration
    #[serde(default)]
    pub error_log: Option<ErrorLogConfig>,

    /// Audit log configuration (security events)
    #[serde(default)]
    pub audit_log: Option<AuditLogConfig>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            timestamps: default_true(),
            file: None,
            access_log: None,
            error_log: None,
            audit_log: None,
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
    #[serde(default = "default_access_log_file")]
    pub file: PathBuf,

    /// Log format (combined, json, custom)
    #[serde(default = "default_access_log_format")]
    pub format: String,

    /// Buffer size for writes
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Include trace_id in logs
    #[serde(default = "default_true")]
    pub include_trace_id: bool,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: default_access_log_file(),
            format: default_access_log_format(),
            buffer_size: default_buffer_size(),
            include_trace_id: true,
        }
    }
}

/// Error log configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLogConfig {
    /// Enable error logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Error log file path
    #[serde(default = "default_error_log_file")]
    pub file: PathBuf,

    /// Minimum level for error log (warn, error)
    #[serde(default = "default_error_log_level")]
    pub level: String,

    /// Buffer size for writes
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
}

impl Default for ErrorLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: default_error_log_file(),
            level: default_error_log_level(),
            buffer_size: default_buffer_size(),
        }
    }
}

/// Audit log configuration (security events)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogConfig {
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Audit log file path
    #[serde(default = "default_audit_log_file")]
    pub file: PathBuf,

    /// Buffer size for writes
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Log blocked requests
    #[serde(default = "default_true")]
    pub log_blocked: bool,

    /// Log agent decisions
    #[serde(default = "default_true")]
    pub log_agent_decisions: bool,

    /// Log WAF events
    #[serde(default = "default_true")]
    pub log_waf_events: bool,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: default_audit_log_file(),
            buffer_size: default_buffer_size(),
            log_blocked: true,
            log_agent_decisions: true,
            log_waf_events: true,
        }
    }
}

// ============================================================================
// Tracing Configuration
// ============================================================================

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

// ============================================================================
// Default Value Functions
// ============================================================================

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
    "json".to_string()
}

fn default_buffer_size() -> usize {
    8192
}

fn default_access_log_file() -> PathBuf {
    PathBuf::from("/var/log/sentinel/access.log")
}

fn default_error_log_file() -> PathBuf {
    PathBuf::from("/var/log/sentinel/error.log")
}

fn default_error_log_level() -> String {
    "warn".to_string()
}

fn default_audit_log_file() -> PathBuf {
    PathBuf::from("/var/log/sentinel/audit.log")
}

fn default_sampling_rate() -> f64 {
    0.01
}

fn default_service_name() -> String {
    "sentinel".to_string()
}
