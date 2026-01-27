//! Logging infrastructure for Sentinel proxy
//!
//! This module provides structured logging to files for:
//! - Access logs (request/response data with trace_id)
//! - Error logs (errors and warnings)
//! - Audit logs (security events)
//!
//! Access log formats supported:
//! - `json` (default): Structured JSON with all fields
//! - `combined`: Apache/nginx Combined Log Format with trace_id extension

use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Arc;
use tracing::{error, warn};

use sentinel_config::{AuditLogConfig, LoggingConfig};

/// Access log format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLogFormat {
    /// Structured JSON format (default)
    Json,
    /// Apache/nginx Combined Log Format with trace_id extension
    Combined,
}

/// Access log entry with trace_id for request correlation
#[derive(Debug, Serialize)]
pub struct AccessLogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Unique trace ID for request correlation
    pub trace_id: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Query string (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// HTTP protocol version
    pub protocol: String,
    /// Response status code
    pub status: u16,
    /// Response body size in bytes
    pub body_bytes: u64,
    /// Request duration in milliseconds
    pub duration_ms: u64,
    /// Client IP address
    pub client_ip: String,
    /// User-Agent header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// Referer header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referer: Option<String>,
    /// Host header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Matched route ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Selected upstream
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Number of upstream attempts
    pub upstream_attempts: u32,
    /// Instance ID of the proxy
    pub instance_id: String,
    /// Namespace (for scoped requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service (for scoped requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Response body size in bytes (bytes sent to client)
    pub body_bytes_sent: u64,
    /// Upstream address that handled the request (IP:port)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_addr: Option<String>,
    /// Whether the connection to upstream was reused (connection pooling)
    pub connection_reused: bool,
    /// Whether the request hit a rate limit (429 response)
    pub rate_limit_hit: bool,
    /// GeoIP country code (ISO 3166-1 alpha-2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
}

impl AccessLogEntry {
    /// Format the entry as a string based on the specified format
    pub fn format(&self, format: AccessLogFormat) -> String {
        match format {
            AccessLogFormat::Json => self.format_json(),
            AccessLogFormat::Combined => self.format_combined(),
        }
    }

    /// Format as JSON
    fn format_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as Combined Log Format with trace_id extension
    /// Format: client_ip - - [timestamp] "method path?query protocol" status bytes "referer" "user_agent" trace_id duration_ms
    fn format_combined(&self) -> String {
        // Parse RFC3339 timestamp to CLF format [day/month/year:hour:min:sec zone]
        let clf_timestamp = self.format_clf_timestamp();

        // Build request line
        let request_line = if let Some(ref query) = self.query {
            format!("{} {}?{} {}", self.method, self.path, query, self.protocol)
        } else {
            format!("{} {} {}", self.method, self.path, self.protocol)
        };

        // Escape and format optional fields
        let referer = self.referer.as_deref().unwrap_or("-");
        let user_agent = self.user_agent.as_deref().unwrap_or("-");

        // Combined format with trace_id and duration extensions
        format!(
            "{} - - [{}] \"{}\" {} {} \"{}\" \"{}\" {} {}ms",
            self.client_ip,
            clf_timestamp,
            request_line,
            self.status,
            self.body_bytes,
            referer,
            user_agent,
            self.trace_id,
            self.duration_ms
        )
    }

    /// Convert RFC3339 timestamp to Common Log Format timestamp
    fn format_clf_timestamp(&self) -> String {
        // Try to parse and reformat, fallback to original if parsing fails
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&self.timestamp) {
            dt.format("%d/%b/%Y:%H:%M:%S %z").to_string()
        } else {
            self.timestamp.clone()
        }
    }
}

/// Error log entry
#[derive(Debug, Serialize)]
pub struct ErrorLogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Trace ID for correlation
    pub trace_id: String,
    /// Log level (warn, error)
    pub level: String,
    /// Error message
    pub message: String,
    /// Route ID if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Upstream if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Error details/context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Audit event type for categorizing security events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Request blocked by policy
    Blocked,
    /// Agent made a decision
    AgentDecision,
    /// WAF rule matched
    WafMatch,
    /// WAF blocked request
    WafBlock,
    /// Rate limit exceeded
    RateLimitExceeded,
    /// Authentication event
    AuthEvent,
    /// Configuration change
    ConfigChange,
    /// Certificate reload
    CertReload,
    /// Circuit breaker state change
    CircuitBreakerChange,
    /// Cache purge request
    CachePurge,
    /// Admin action
    AdminAction,
    /// Custom event
    Custom,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditEventType::Blocked => write!(f, "blocked"),
            AuditEventType::AgentDecision => write!(f, "agent_decision"),
            AuditEventType::WafMatch => write!(f, "waf_match"),
            AuditEventType::WafBlock => write!(f, "waf_block"),
            AuditEventType::RateLimitExceeded => write!(f, "rate_limit_exceeded"),
            AuditEventType::AuthEvent => write!(f, "auth_event"),
            AuditEventType::ConfigChange => write!(f, "config_change"),
            AuditEventType::CertReload => write!(f, "cert_reload"),
            AuditEventType::CircuitBreakerChange => write!(f, "circuit_breaker_change"),
            AuditEventType::CachePurge => write!(f, "cache_purge"),
            AuditEventType::AdminAction => write!(f, "admin_action"),
            AuditEventType::Custom => write!(f, "custom"),
        }
    }
}

/// Audit log entry for security events
#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,
    /// Trace ID for correlation
    pub trace_id: String,
    /// Event type (blocked, agent_decision, waf_match, etc.)
    pub event_type: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Client IP
    pub client_ip: String,
    /// Route ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Block reason if blocked
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Agent that made the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// WAF rule IDs matched
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
    /// Additional tags
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Action taken (allow, block, challenge, redirect)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Response status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// User ID if authenticated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Session ID if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Additional metadata as key-value pairs
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub metadata: std::collections::HashMap<String, String>,
    /// Namespace (for scoped requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service (for scoped requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

impl AuditLogEntry {
    /// Create a new audit log entry with required fields
    pub fn new(
        trace_id: impl Into<String>,
        event_type: AuditEventType,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            trace_id: trace_id.into(),
            event_type: event_type.to_string(),
            method: method.into(),
            path: path.into(),
            client_ip: client_ip.into(),
            route_id: None,
            reason: None,
            agent_id: None,
            rule_ids: Vec::new(),
            tags: Vec::new(),
            action: None,
            status_code: None,
            user_id: None,
            session_id: None,
            metadata: std::collections::HashMap::new(),
            namespace: None,
            service: None,
        }
    }

    /// Builder: set namespace
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Builder: set service
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Builder: set scope from namespace and service
    pub fn with_scope(mut self, namespace: Option<String>, service: Option<String>) -> Self {
        self.namespace = namespace;
        self.service = service;
        self
    }

    /// Builder: set route ID
    pub fn with_route_id(mut self, route_id: impl Into<String>) -> Self {
        self.route_id = Some(route_id.into());
        self
    }

    /// Builder: set reason
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Builder: set agent ID
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Builder: add rule IDs
    pub fn with_rule_ids(mut self, rule_ids: Vec<String>) -> Self {
        self.rule_ids = rule_ids;
        self
    }

    /// Builder: add tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Builder: set action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Builder: set status code
    pub fn with_status_code(mut self, status_code: u16) -> Self {
        self.status_code = Some(status_code);
        self
    }

    /// Builder: set user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Builder: set session ID
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Builder: add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Create an entry for a blocked request
    pub fn blocked(
        trace_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(trace_id, AuditEventType::Blocked, method, path, client_ip)
            .with_reason(reason)
            .with_action("block")
    }

    /// Create an entry for rate limit exceeded
    pub fn rate_limited(
        trace_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
        limit_key: impl Into<String>,
    ) -> Self {
        Self::new(
            trace_id,
            AuditEventType::RateLimitExceeded,
            method,
            path,
            client_ip,
        )
        .with_reason("Rate limit exceeded")
        .with_action("block")
        .with_metadata("limit_key", limit_key)
    }

    /// Create an entry for WAF block
    pub fn waf_blocked(
        trace_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
        rule_ids: Vec<String>,
    ) -> Self {
        Self::new(trace_id, AuditEventType::WafBlock, method, path, client_ip)
            .with_rule_ids(rule_ids)
            .with_action("block")
    }

    /// Create an entry for configuration change
    pub fn config_change(
        trace_id: impl Into<String>,
        change_type: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self::new(
            trace_id,
            AuditEventType::ConfigChange,
            "-",
            "/-/config",
            "internal",
        )
        .with_reason(change_type)
        .with_metadata("details", details)
    }

    /// Create an entry for certificate reload
    pub fn cert_reload(
        trace_id: impl Into<String>,
        listener_id: impl Into<String>,
        success: bool,
    ) -> Self {
        Self::new(
            trace_id,
            AuditEventType::CertReload,
            "-",
            "/-/certs",
            "internal",
        )
        .with_metadata("listener_id", listener_id)
        .with_metadata("success", success.to_string())
    }

    /// Create an entry for cache purge
    pub fn cache_purge(
        trace_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
        pattern: impl Into<String>,
    ) -> Self {
        Self::new(
            trace_id,
            AuditEventType::CachePurge,
            method,
            path,
            client_ip,
        )
        .with_metadata("pattern", pattern)
        .with_action("purge")
    }

    /// Create an entry for admin action
    pub fn admin_action(
        trace_id: impl Into<String>,
        method: impl Into<String>,
        path: impl Into<String>,
        client_ip: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self::new(
            trace_id,
            AuditEventType::AdminAction,
            method,
            path,
            client_ip,
        )
        .with_action(action)
    }
}

/// Buffered file writer for log files
struct LogFileWriter {
    writer: BufWriter<File>,
}

impl LogFileWriter {
    fn new(path: &Path, buffer_size: usize) -> Result<Self> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {:?}", parent))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;

        Ok(Self {
            writer: BufWriter::with_capacity(buffer_size, file),
        })
    }

    fn write_line(&mut self, line: &str) -> Result<()> {
        writeln!(self.writer, "{}", line)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Log manager handling all log file writers
pub struct LogManager {
    access_log: Option<Mutex<LogFileWriter>>,
    access_log_format: AccessLogFormat,
    access_log_config: Option<sentinel_config::AccessLogConfig>,
    error_log: Option<Mutex<LogFileWriter>>,
    audit_log: Option<Mutex<LogFileWriter>>,
    audit_config: Option<AuditLogConfig>,
}

impl LogManager {
    /// Create a new log manager from configuration
    pub fn new(config: &LoggingConfig) -> Result<Self> {
        let (access_log, access_log_format) = if let Some(ref access_config) = config.access_log {
            if access_config.enabled {
                let format = Self::parse_access_format(&access_config.format);
                let writer = Mutex::new(LogFileWriter::new(
                    &access_config.file,
                    access_config.buffer_size,
                )?);
                (Some(writer), format)
            } else {
                (None, AccessLogFormat::Json)
            }
        } else {
            (None, AccessLogFormat::Json)
        };

        let error_log = if let Some(ref error_config) = config.error_log {
            if error_config.enabled {
                Some(Mutex::new(LogFileWriter::new(
                    &error_config.file,
                    error_config.buffer_size,
                )?))
            } else {
                None
            }
        } else {
            None
        };

        let audit_log = if let Some(ref audit_config) = config.audit_log {
            if audit_config.enabled {
                Some(Mutex::new(LogFileWriter::new(
                    &audit_config.file,
                    audit_config.buffer_size,
                )?))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            access_log,
            access_log_format,
            access_log_config: config.access_log.clone(),
            error_log,
            audit_log,
            audit_config: config.audit_log.clone(),
        })
    }

    /// Create a disabled log manager (no file logging)
    pub fn disabled() -> Self {
        Self {
            access_log: None,
            access_log_format: AccessLogFormat::Json,
            access_log_config: None,
            error_log: None,
            audit_log: None,
            audit_config: None,
        }
    }

    /// Parse access log format from config string
    fn parse_access_format(format: &str) -> AccessLogFormat {
        match format.to_lowercase().as_str() {
            "combined" | "clf" | "common" => AccessLogFormat::Combined,
            _ => AccessLogFormat::Json, // Default to JSON
        }
    }

    /// Write an access log entry
    pub fn log_access(&self, entry: &AccessLogEntry) {
        if let Some(ref writer) = self.access_log {
            // Check sampling if config is available
            if let Some(ref config) = self.access_log_config {
                // Determine if we should log this entry
                let should_log = if config.sample_errors_always && entry.status >= 400 {
                    // Always log errors (4xx/5xx)
                    true
                } else {
                    // Sample based on sample_rate (0.0-1.0)
                    // Generate random number and check if it's less than sample_rate
                    use rand::Rng;
                    let mut rng = rand::rng();
                    rng.random::<f64>() < config.sample_rate
                };

                if !should_log {
                    return; // Skip logging this entry
                }
            }

            let formatted = entry.format(self.access_log_format);
            let mut guard = writer.lock();
            if let Err(e) = guard.write_line(&formatted) {
                error!("Failed to write access log: {}", e);
            }
        }
    }

    /// Write an error log entry
    pub fn log_error(&self, entry: &ErrorLogEntry) {
        if let Some(ref writer) = self.error_log {
            match serde_json::to_string(entry) {
                Ok(json) => {
                    let mut guard = writer.lock();
                    if let Err(e) = guard.write_line(&json) {
                        error!("Failed to write error log: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to serialize error log entry: {}", e);
                }
            }
        }
    }

    /// Write an audit log entry
    pub fn log_audit(&self, entry: &AuditLogEntry) {
        if let Some(ref writer) = self.audit_log {
            if let Some(ref config) = self.audit_config {
                // Check if we should log this event type
                let should_log = match entry.event_type.as_str() {
                    "blocked" => config.log_blocked,
                    "agent_decision" => config.log_agent_decisions,
                    "waf_match" | "waf_block" => config.log_waf_events,
                    _ => true, // Log other event types by default
                };

                if !should_log {
                    return;
                }
            }

            match serde_json::to_string(entry) {
                Ok(json) => {
                    let mut guard = writer.lock();
                    if let Err(e) = guard.write_line(&json) {
                        error!("Failed to write audit log: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to serialize audit log entry: {}", e);
                }
            }
        }
    }

    /// Flush all log buffers
    pub fn flush(&self) {
        if let Some(ref writer) = self.access_log {
            if let Err(e) = writer.lock().flush() {
                warn!("Failed to flush access log: {}", e);
            }
        }
        if let Some(ref writer) = self.error_log {
            if let Err(e) = writer.lock().flush() {
                warn!("Failed to flush error log: {}", e);
            }
        }
        if let Some(ref writer) = self.audit_log {
            if let Err(e) = writer.lock().flush() {
                warn!("Failed to flush audit log: {}", e);
            }
        }
    }

    /// Check if access logging is enabled
    pub fn access_log_enabled(&self) -> bool {
        self.access_log.is_some()
    }

    /// Check if error logging is enabled
    pub fn error_log_enabled(&self) -> bool {
        self.error_log.is_some()
    }

    /// Check if audit logging is enabled
    pub fn audit_log_enabled(&self) -> bool {
        self.audit_log.is_some()
    }
}

/// Shared log manager that can be passed around
pub type SharedLogManager = Arc<LogManager>;

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_config::{AccessLogConfig, ErrorLogConfig};
    use tempfile::tempdir;

    #[test]
    fn test_access_log_entry_serialization() {
        let entry = AccessLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            trace_id: "abc123".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query: Some("page=1".to_string()),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 1024,
            duration_ms: 50,
            client_ip: "192.168.1.1".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: None,
            host: Some("example.com".to_string()),
            route_id: Some("api-route".to_string()),
            upstream: Some("backend-1".to_string()),
            upstream_attempts: 1,
            instance_id: "instance-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 2048,
            upstream_addr: Some("10.0.1.5:8080".to_string()),
            connection_reused: true,
            rate_limit_hit: false,
            geo_country: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"trace_id\":\"abc123\""));
        assert!(json.contains("\"status\":200"));
    }

    #[test]
    fn test_access_log_entry_with_scope() {
        let entry = AccessLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            trace_id: "abc123".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query: None,
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 1024,
            duration_ms: 50,
            client_ip: "192.168.1.1".to_string(),
            user_agent: None,
            referer: None,
            host: None,
            route_id: Some("api-route".to_string()),
            upstream: Some("backend-1".to_string()),
            upstream_attempts: 1,
            instance_id: "instance-1".to_string(),
            namespace: Some("api".to_string()),
            service: Some("payments".to_string()),
            body_bytes_sent: 2048,
            upstream_addr: None,
            connection_reused: false,
            rate_limit_hit: false,
            geo_country: Some("US".to_string()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"namespace\":\"api\""));
        assert!(json.contains("\"service\":\"payments\""));
    }

    #[test]
    fn test_log_manager_creation() {
        let dir = tempdir().unwrap();
        let access_log_path = dir.path().join("access.log");
        let error_log_path = dir.path().join("error.log");
        let audit_log_path = dir.path().join("audit.log");

        let config = LoggingConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            timestamps: true,
            file: None,
            access_log: Some(AccessLogConfig {
                enabled: true,
                file: access_log_path.clone(),
                format: "json".to_string(),
                buffer_size: 8192,
                include_trace_id: true,
                sample_rate: 1.0,
                sample_errors_always: true,
                fields: sentinel_config::AccessLogFields::default(),
            }),
            error_log: Some(ErrorLogConfig {
                enabled: true,
                file: error_log_path.clone(),
                level: "warn".to_string(),
                buffer_size: 8192,
            }),
            audit_log: Some(AuditLogConfig {
                enabled: true,
                file: audit_log_path.clone(),
                buffer_size: 8192,
                log_blocked: true,
                log_agent_decisions: true,
                log_waf_events: true,
            }),
        };

        let manager = LogManager::new(&config).unwrap();
        assert!(manager.access_log_enabled());
        assert!(manager.error_log_enabled());
        assert!(manager.audit_log_enabled());
    }

    #[test]
    fn test_access_log_combined_format() {
        let entry = AccessLogEntry {
            timestamp: "2024-01-15T10:30:00+00:00".to_string(),
            trace_id: "trace-abc123".to_string(),
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            query: Some("page=1".to_string()),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 1024,
            duration_ms: 50,
            client_ip: "192.168.1.1".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            referer: Some("https://example.com/".to_string()),
            host: Some("api.example.com".to_string()),
            route_id: Some("api-route".to_string()),
            upstream: Some("backend-1".to_string()),
            upstream_attempts: 1,
            instance_id: "instance-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 2048,
            upstream_addr: Some("10.0.1.5:8080".to_string()),
            connection_reused: true,
            rate_limit_hit: false,
            geo_country: Some("US".to_string()),
        };

        let combined = entry.format(AccessLogFormat::Combined);

        // Check Combined format structure
        assert!(combined.starts_with("192.168.1.1 - - ["));
        assert!(combined.contains("\"GET /api/users?page=1 HTTP/1.1\""));
        assert!(combined.contains(" 200 1024 "));
        assert!(combined.contains("\"https://example.com/\""));
        assert!(combined.contains("\"Mozilla/5.0\""));
        assert!(combined.contains("trace-abc123"));
        assert!(combined.ends_with("50ms"));
    }

    #[test]
    fn test_access_log_format_parsing() {
        assert_eq!(
            LogManager::parse_access_format("json"),
            AccessLogFormat::Json
        );
        assert_eq!(
            LogManager::parse_access_format("JSON"),
            AccessLogFormat::Json
        );
        assert_eq!(
            LogManager::parse_access_format("combined"),
            AccessLogFormat::Combined
        );
        assert_eq!(
            LogManager::parse_access_format("COMBINED"),
            AccessLogFormat::Combined
        );
        assert_eq!(
            LogManager::parse_access_format("clf"),
            AccessLogFormat::Combined
        );
        assert_eq!(
            LogManager::parse_access_format("unknown"),
            AccessLogFormat::Json
        ); // Default to JSON
    }
}
