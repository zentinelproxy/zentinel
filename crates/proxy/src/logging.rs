//! Logging infrastructure for Zentinel proxy
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
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, warn};

use zentinel_config::{AuditLogConfig, LoggingConfig};

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
    /// Format the entry as a string based on the specified format.
    ///
    /// When `fields` is provided, disabled fields are omitted from JSON output.
    pub fn format(
        &self,
        format: AccessLogFormat,
        fields: Option<&zentinel_config::AccessLogFields>,
    ) -> String {
        match format {
            AccessLogFormat::Json => self.format_json(fields),
            AccessLogFormat::Combined => self.format_combined(),
        }
    }

    /// Format as JSON, optionally filtering fields based on config
    fn format_json(&self, fields: Option<&zentinel_config::AccessLogFields>) -> String {
        let fields = match fields {
            Some(f) => f,
            None => return serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string()),
        };

        // Build a filtered JSON object based on enabled fields
        let mut map = serde_json::Map::new();
        if fields.timestamp {
            map.insert(
                "timestamp".to_string(),
                serde_json::Value::String(self.timestamp.clone()),
            );
        }
        if fields.trace_id {
            map.insert(
                "trace_id".to_string(),
                serde_json::Value::String(self.trace_id.clone()),
            );
        }
        if fields.method {
            map.insert(
                "method".to_string(),
                serde_json::Value::String(self.method.clone()),
            );
        }
        if fields.path {
            map.insert(
                "path".to_string(),
                serde_json::Value::String(self.path.clone()),
            );
        }
        if fields.query {
            if let Some(ref q) = self.query {
                map.insert("query".to_string(), serde_json::Value::String(q.clone()));
            }
        }
        if fields.status {
            map.insert("status".to_string(), serde_json::json!(self.status));
        }
        if fields.latency_ms {
            map.insert(
                "duration_ms".to_string(),
                serde_json::json!(self.duration_ms),
            );
        }
        if fields.client_ip {
            map.insert(
                "client_ip".to_string(),
                serde_json::Value::String(self.client_ip.clone()),
            );
        }
        if fields.user_agent {
            if let Some(ref ua) = self.user_agent {
                map.insert(
                    "user_agent".to_string(),
                    serde_json::Value::String(ua.clone()),
                );
            }
        }
        if fields.referer {
            if let Some(ref r) = self.referer {
                map.insert("referer".to_string(), serde_json::Value::String(r.clone()));
            }
        }
        if fields.body_bytes_sent {
            map.insert(
                "body_bytes_sent".to_string(),
                serde_json::json!(self.body_bytes_sent),
            );
        }
        if fields.upstream_addr {
            if let Some(ref addr) = self.upstream_addr {
                map.insert(
                    "upstream_addr".to_string(),
                    serde_json::Value::String(addr.clone()),
                );
            }
        }
        if fields.connection_reused {
            map.insert(
                "connection_reused".to_string(),
                serde_json::json!(self.connection_reused),
            );
        }
        if fields.rate_limit_hit {
            map.insert(
                "rate_limit_hit".to_string(),
                serde_json::json!(self.rate_limit_hit),
            );
        }
        if fields.geo_country {
            if let Some(ref cc) = self.geo_country {
                map.insert(
                    "geo_country".to_string(),
                    serde_json::Value::String(cc.clone()),
                );
            }
        }
        // Always include these core fields (not configurable)
        if let Some(ref route) = self.route_id {
            map.insert(
                "route_id".to_string(),
                serde_json::Value::String(route.clone()),
            );
        }
        if let Some(ref upstream) = self.upstream {
            map.insert(
                "upstream".to_string(),
                serde_json::Value::String(upstream.clone()),
            );
        }
        map.insert(
            "instance_id".to_string(),
            serde_json::Value::String(self.instance_id.clone()),
        );

        serde_json::to_string(&map).unwrap_or_else(|_| "{}".to_string())
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
    path: PathBuf,
    buffer_size: usize,
    writer: BufWriter<File>,
}

impl LogFileWriter {
    fn new(path: &Path, buffer_size: usize) -> Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            buffer_size,
            writer: Self::open(path, buffer_size)?,
        })
    }

    fn open(path: &Path, buffer_size: usize) -> Result<BufWriter<File>> {
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {:?}", parent))?;
        }

        let mut options = OpenOptions::new();
        // A file created here is not world-readable (the mode of an existing
        // file is left alone), and the umask can only narrow it further.
        #[cfg(unix)]
        options.mode(0o640);
        let file = options
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open log file: {:?}", path))?;

        Ok(BufWriter::with_capacity(buffer_size, file))
    }

    /// Flush what is buffered, then open the path again. After a log rotation
    /// the path names a new file while the old handle still points at the
    /// rotated one. If the path cannot be opened, the old handle is kept.
    fn reopen(&mut self) -> Result<()> {
        let fresh = Self::open(&self.path, self.buffer_size)?;
        self.writer.flush()?;
        self.writer = fresh;
        Ok(())
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
    access_log_config: Option<zentinel_config::AccessLogConfig>,
    error_log: Option<Mutex<LogFileWriter>>,
    error_log_level: String,
    audit_log: Option<Mutex<LogFileWriter>>,
    audit_config: Option<AuditLogConfig>,
}

impl LogManager {
    /// Create a new log manager from configuration
    ///
    /// Each log file is opened on its own. An access or error log that cannot
    /// be opened is reported, naming the log and its path, and left off; the
    /// other logs are unaffected. An audit log that cannot be opened is an
    /// error, because running without a configured audit trail is not a
    /// failure an operator should discover after the fact.
    pub fn new(config: &LoggingConfig) -> Result<Self> {
        let (access_log, access_log_format) = match config.access_log {
            Some(ref access_config) if access_config.enabled => (
                Self::open_or_report("access", &access_config.file, access_config.buffer_size),
                Self::parse_access_format(&access_config.format),
            ),
            _ => (None, AccessLogFormat::Json),
        };

        let (error_log, error_log_level) = match config.error_log {
            Some(ref error_config) if error_config.enabled => (
                Self::open_or_report("error", &error_config.file, error_config.buffer_size),
                error_config.level.clone(),
            ),
            _ => (None, "warn".to_string()),
        };

        let audit_log = match config.audit_log {
            Some(ref audit_config) if audit_config.enabled => Some(Mutex::new(
                LogFileWriter::new(&audit_config.file, audit_config.buffer_size)
                    .with_context(|| format!("Failed to open audit log {:?}", audit_config.file))?,
            )),
            _ => None,
        };

        Ok(Self {
            access_log,
            access_log_format,
            access_log_config: config.access_log.clone(),
            error_log,
            error_log_level,
            audit_log,
            audit_config: config.audit_log.clone(),
        })
    }

    /// Open a log file, reporting a failure instead of returning it so that
    /// one log that cannot be opened does not take the others down with it.
    fn open_or_report(kind: &str, path: &Path, buffer_size: usize) -> Option<Mutex<LogFileWriter>> {
        match LogFileWriter::new(path, buffer_size) {
            Ok(writer) => Some(Mutex::new(writer)),
            Err(e) => {
                error!(
                    log = kind,
                    path = %path.display(),
                    "Failed to open {} log, it is disabled: {:#}",
                    kind,
                    e
                );
                None
            }
        }
    }

    /// Create a disabled log manager (no file logging)
    pub fn disabled() -> Self {
        Self {
            access_log: None,
            access_log_format: AccessLogFormat::Json,
            access_log_config: None,
            error_log: None,
            error_log_level: "warn".to_string(),
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

    /// Check whether an access log entry with the given status should be logged,
    /// accounting for sampling rate. Call this before constructing `AccessLogEntry`
    /// to avoid allocating fields that would be discarded.
    pub fn should_log_access(&self, status: u16) -> bool {
        if self.access_log.is_none() {
            return false;
        }
        if let Some(ref config) = self.access_log_config {
            if config.sample_errors_always && status >= 400 {
                return true;
            }
            use rand::RngExt;
            let mut rng = rand::rng();
            return rng.random::<f64>() < config.sample_rate;
        }
        true
    }

    /// Write an access log entry. Callers should check `should_log_access` first
    /// to avoid building the entry when it would be discarded by sampling.
    pub fn log_access(&self, entry: &AccessLogEntry) {
        if let Some(ref writer) = self.access_log {
            let fields = self.access_log_config.as_ref().map(|c| &c.fields);
            let formatted = entry.format(self.access_log_format, fields);
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

    /// Reopen the access, error and audit log files at their configured
    /// paths, so that a rotated file is let go and the new one is written to.
    ///
    /// A log whose path cannot be opened keeps writing to the file it has.
    /// Returns the number of logs reopened.
    pub fn reopen(&self) -> usize {
        let mut reopened = 0;
        for (name, writer) in [
            ("access", &self.access_log),
            ("error", &self.error_log),
            ("audit", &self.audit_log),
        ] {
            let Some(writer) = writer else { continue };
            match writer.lock().reopen() {
                Ok(()) => reopened += 1,
                Err(e) => warn!(
                    "Failed to reopen {} log, keeping the old file: {:#}",
                    name, e
                ),
            }
        }
        reopened
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

    /// Check if the given level meets the configured minimum error log level.
    /// Level hierarchy: "warn" logs both warn and error, "error" logs only error.
    fn should_log_error_level(&self, level: &str) -> bool {
        match self.error_log_level.as_str() {
            "error" => level == "error",
            _ => level == "warn" || level == "error", // "warn" (default) logs both
        }
    }

    /// Convenience method to construct an ErrorLogEntry and write it to the error log.
    /// Checks both that error logging is enabled and that the level meets the configured minimum.
    pub fn log_request_error(
        &self,
        level: &str,
        message: &str,
        trace_id: &str,
        route_id: Option<&str>,
        upstream: Option<&str>,
        details: Option<String>,
    ) {
        if self.error_log.is_none() || !self.should_log_error_level(level) {
            return;
        }
        let entry = ErrorLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            level: level.to_string(),
            message: message.to_string(),
            route_id: route_id.map(|s| s.to_string()),
            upstream: upstream.map(|s| s.to_string()),
            details,
        };
        self.log_error(&entry);
    }
}

impl Drop for LogManager {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Shared log manager that can be passed around
pub type SharedLogManager = Arc<LogManager>;

/// Log lines the log subscriber could not write, see [`DropOnWriteError`].
static DROPPED_LOG_WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Number of log lines dropped because stdout or stderr could not be written.
pub fn dropped_log_writes() -> u64 {
    DROPPED_LOG_WRITES.load(std::sync::atomic::Ordering::Relaxed)
}

/// A [`MakeWriter`](tracing_subscriber::fmt::MakeWriter) for the log
/// subscriber whose writes never fail: a line that cannot be written is
/// dropped and counted in [`dropped_log_writes`].
///
/// When a write fails, tracing-subscriber reports it with `eprintln!`, and
/// `eprintln!` panics if stderr cannot be written either. With stdout and
/// stderr on a broken pipe (`zentinel 2>&1 | head` after `head` exits, or a
/// dead log shipper) every log call panicked, killing whichever thread logged:
/// the signal thread among them, so SIGTERM never stopped the proxy (#576).
#[derive(Debug, Clone, Copy, Default)]
pub struct DropOnWriteError<M>(pub M);

impl<'a, M: tracing_subscriber::fmt::MakeWriter<'a>> tracing_subscriber::fmt::MakeWriter<'a>
    for DropOnWriteError<M>
{
    type Writer = DropOnWriteError<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        DropOnWriteError(self.0.make_writer())
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        DropOnWriteError(self.0.make_writer_for(meta))
    }
}

impl<W: Write> Write for DropOnWriteError<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.write(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Err(e),
            Err(_) => {
                DROPPED_LOG_WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Report the rest of the line as written, so it is dropped
                // rather than retried.
                Ok(buf.len())
            }
            written => written,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = self.0.flush();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use zentinel_config::{AccessLogConfig, ErrorLogConfig};

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
                fields: zentinel_config::AccessLogFields::default(),
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
    fn reopen_writes_to_the_file_now_at_the_path() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("error.log");
        let rotated = dir.path().join("error.log.1");
        let config = LoggingConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            timestamps: true,
            file: None,
            access_log: None,
            error_log: Some(ErrorLogConfig {
                enabled: true,
                file: path.clone(),
                level: "warn".to_string(),
                buffer_size: 8192,
            }),
            audit_log: None,
        };
        let manager = LogManager::new(&config).unwrap();

        manager.log_request_error("error", "before", "t1", None, None, None);
        // What logrotate does: move the file away and leave the path empty.
        std::fs::rename(&path, &rotated).unwrap();
        assert_eq!(manager.reopen(), 1);
        manager.log_request_error("error", "after", "t2", None, None, None);
        manager.flush();

        let old = std::fs::read_to_string(&rotated).unwrap();
        let new = std::fs::read_to_string(&path).unwrap();
        assert!(old.contains("before") && !old.contains("after"), "{old}");
        assert!(new.contains("after") && !new.contains("before"), "{new}");
    }

    #[test]
    fn reopen_keeps_the_old_file_when_the_path_cannot_be_opened() {
        let dir = tempdir().unwrap();
        let logs = dir.path().join("logs");
        let path = logs.join("error.log");
        let config = LoggingConfig {
            level: "info".to_string(),
            format: "json".to_string(),
            timestamps: true,
            file: None,
            access_log: None,
            error_log: Some(ErrorLogConfig {
                enabled: true,
                file: path.clone(),
                level: "warn".to_string(),
                buffer_size: 8192,
            }),
            audit_log: None,
        };
        let manager = LogManager::new(&config).unwrap();
        manager.log_request_error("error", "one", "t1", None, None, None);

        // A directory where the file should be: the path cannot be opened.
        let moved = dir.path().join("moved.log");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(manager.reopen(), 0);

        manager.log_request_error("error", "two", "t2", None, None, None);
        manager.flush();
        let kept = std::fs::read_to_string(&moved).unwrap();
        assert!(kept.contains("one") && kept.contains("two"), "{kept}");
    }

    #[cfg(unix)]
    #[test]
    fn new_log_files_are_not_world_readable_and_existing_ones_keep_their_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let dir = tempdir().unwrap();
        let created = dir.path().join("created.log");
        LogFileWriter::new(&created, 8192).unwrap();
        // 0640, narrowed further by a stricter umask but never widened.
        assert_eq!(mode(&created) & !0o640, 0, "{:o}", mode(&created));

        let existing = dir.path().join("existing.log");
        std::fs::write(&existing, "").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o664)).unwrap();
        let mut writer = LogFileWriter::new(&existing, 8192).unwrap();
        writer.reopen().unwrap();
        assert_eq!(mode(&existing), 0o664);

        // Reopening after a rotation creates the file again, also at 0640.
        std::fs::rename(&created, dir.path().join("created.log.1")).unwrap();
        let mut writer = LogFileWriter::new(&created, 8192).unwrap();
        std::fs::remove_file(&created).unwrap();
        writer.reopen().unwrap();
        assert_eq!(mode(&created) & !0o640, 0, "{:o}", mode(&created));
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

        let combined = entry.format(AccessLogFormat::Combined, None);

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

    // =========================================================================
    // Field Filtering Tests
    // =========================================================================

    fn test_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2026-03-01T12:00:00Z".to_string(),
            trace_id: "trace-xyz".to_string(),
            method: "POST".to_string(),
            path: "/api/submit".to_string(),
            query: Some("v=2".to_string()),
            protocol: "HTTP/2.0".to_string(),
            status: 201,
            body_bytes: 512,
            duration_ms: 25,
            client_ip: "10.0.0.1".to_string(),
            user_agent: Some("curl/8.0".to_string()),
            referer: Some("https://example.com".to_string()),
            host: Some("api.example.com".to_string()),
            route_id: Some("submit-route".to_string()),
            upstream: Some("backend-2".to_string()),
            upstream_attempts: 1,
            instance_id: "inst-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 100,
            upstream_addr: Some("10.1.0.5:9090".to_string()),
            connection_reused: false,
            rate_limit_hit: true,
            geo_country: Some("DE".to_string()),
        }
    }

    #[test]
    fn test_json_format_with_all_fields_enabled() {
        let entry = test_entry();
        let fields = zentinel_config::AccessLogFields::default(); // All true

        let json_str = entry.format(AccessLogFormat::Json, Some(&fields));
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["method"], "POST");
        assert_eq!(parsed["status"], 201);
        assert_eq!(parsed["client_ip"], "10.0.0.1");
        assert_eq!(parsed["duration_ms"], 25);
        assert_eq!(parsed["upstream_addr"], "10.1.0.5:9090");
        assert_eq!(parsed["rate_limit_hit"], true);
    }

    #[test]
    fn test_json_format_with_fields_disabled() {
        let entry = test_entry();
        let fields = zentinel_config::AccessLogFields {
            timestamp: true,
            method: true,
            path: true,
            status: true,
            // Disable everything else
            trace_id: false,
            query: false,
            latency_ms: false,
            body_bytes_sent: false,
            upstream_addr: false,
            connection_reused: false,
            rate_limit_hit: false,
            geo_country: false,
            user_agent: false,
            referer: false,
            client_ip: false,
        };

        let json_str = entry.format(AccessLogFormat::Json, Some(&fields));
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Enabled fields present
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("method").is_some());
        assert!(parsed.get("path").is_some());
        assert!(parsed.get("status").is_some());

        // Disabled fields absent
        assert!(
            parsed.get("trace_id").is_none(),
            "trace_id should be filtered out"
        );
        assert!(
            parsed.get("query").is_none(),
            "query should be filtered out"
        );
        assert!(
            parsed.get("duration_ms").is_none(),
            "duration_ms should be filtered out"
        );
        assert!(
            parsed.get("client_ip").is_none(),
            "client_ip should be filtered out"
        );
        assert!(
            parsed.get("user_agent").is_none(),
            "user_agent should be filtered out"
        );
        assert!(
            parsed.get("referer").is_none(),
            "referer should be filtered out"
        );
        assert!(
            parsed.get("upstream_addr").is_none(),
            "upstream_addr should be filtered out"
        );
        assert!(
            parsed.get("rate_limit_hit").is_none(),
            "rate_limit_hit should be filtered out"
        );
    }

    #[test]
    fn test_json_format_without_field_filter() {
        let entry = test_entry();

        // When no field filter provided, full serialization is used
        let json_str = entry.format(AccessLogFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Full serialization includes all fields
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("trace_id").is_some());
        assert!(parsed.get("method").is_some());
        assert!(parsed.get("status").is_some());
        assert!(parsed.get("duration_ms").is_some());
    }

    #[test]
    fn test_combined_format_with_missing_optional_fields() {
        let entry = AccessLogEntry {
            timestamp: "2026-03-01T12:00:00Z".to_string(),
            trace_id: "trace-001".to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            query: None,
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 0,
            duration_ms: 1,
            client_ip: "127.0.0.1".to_string(),
            user_agent: None,
            referer: None,
            host: None,
            route_id: None,
            upstream: None,
            upstream_attempts: 0,
            instance_id: "inst-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 0,
            upstream_addr: None,
            connection_reused: false,
            rate_limit_hit: false,
            geo_country: None,
        };

        let combined = entry.format(AccessLogFormat::Combined, None);

        assert!(combined.starts_with("127.0.0.1 - - ["));
        assert!(combined.contains("\"GET /health HTTP/1.1\""));
        assert!(combined.contains(" 200 0 "));
        // Missing user-agent and referer should show as "-"
        assert!(combined.contains("\"-\""));
    }

    #[test]
    fn test_json_skips_none_optional_fields() {
        let entry = AccessLogEntry {
            timestamp: "2026-03-01T12:00:00Z".to_string(),
            trace_id: "trace-002".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 0,
            duration_ms: 0,
            client_ip: "127.0.0.1".to_string(),
            user_agent: None,
            referer: None,
            host: None,
            route_id: None,
            upstream: None,
            upstream_attempts: 0,
            instance_id: "inst-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 0,
            upstream_addr: None,
            connection_reused: false,
            rate_limit_hit: false,
            geo_country: None,
        };

        // Full serialization (no field filter) uses skip_serializing_if
        let json_str = entry.format(AccessLogFormat::Json, None);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // None fields should be absent (skip_serializing_if)
        assert!(parsed.get("query").is_none());
        assert!(parsed.get("user_agent").is_none());
        assert!(parsed.get("referer").is_none());
        assert!(parsed.get("host").is_none());
        assert!(parsed.get("route_id").is_none());
        assert!(parsed.get("upstream").is_none());
        assert!(parsed.get("namespace").is_none());
        assert!(parsed.get("service").is_none());
        assert!(parsed.get("upstream_addr").is_none());
    }

    /// A path no process can open: its parent is a regular file, so creating
    /// the log directory fails even when the tests run as root.
    fn unopenable_path(dir: &Path, name: &str) -> std::path::PathBuf {
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"").unwrap();
        blocker.join(name)
    }

    fn access_log_config(file: std::path::PathBuf) -> AccessLogConfig {
        AccessLogConfig {
            file,
            ..AccessLogConfig::default()
        }
    }

    /// #574: an error log that cannot be opened used to make `new` fail, and
    /// the proxy then dropped every file log, including the access log the
    /// user had configured.
    #[test]
    fn test_unopenable_error_log_leaves_access_log_working() {
        let dir = tempdir().unwrap();
        let access_log_path = dir.path().join("access.log");

        let config = LoggingConfig {
            access_log: Some(access_log_config(access_log_path.clone())),
            error_log: Some(ErrorLogConfig {
                file: unopenable_path(dir.path(), "error.log"),
                ..ErrorLogConfig::default()
            }),
            ..LoggingConfig::default()
        };

        let manager = LogManager::new(&config).expect("an error log failure is not fatal");
        assert!(manager.access_log_enabled());
        assert!(!manager.error_log_enabled());

        let mut entry = AccessLogEntry {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            trace_id: "trace-574".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            body_bytes: 0,
            duration_ms: 1,
            client_ip: "127.0.0.1".to_string(),
            user_agent: None,
            referer: None,
            host: None,
            route_id: None,
            upstream: None,
            upstream_attempts: 0,
            instance_id: "inst-1".to_string(),
            namespace: None,
            service: None,
            body_bytes_sent: 0,
            upstream_addr: None,
            connection_reused: false,
            rate_limit_hit: false,
            geo_country: None,
        };
        manager.log_access(&entry);
        entry.trace_id = "trace-574-2".to_string();
        manager.log_access(&entry);
        manager.flush();

        let written = std::fs::read_to_string(&access_log_path).unwrap();
        assert_eq!(written.lines().count(), 2);
        assert!(written.contains("trace-574"));
    }

    /// The same independence the other way round: an access log that cannot
    /// be opened does not disable the error log.
    #[test]
    fn test_unopenable_access_log_leaves_error_log_working() {
        let dir = tempdir().unwrap();
        let error_log_path = dir.path().join("error.log");

        let config = LoggingConfig {
            access_log: Some(access_log_config(unopenable_path(dir.path(), "access.log"))),
            error_log: Some(ErrorLogConfig {
                file: error_log_path.clone(),
                ..ErrorLogConfig::default()
            }),
            ..LoggingConfig::default()
        };

        let manager = LogManager::new(&config).expect("an access log failure is not fatal");
        assert!(!manager.access_log_enabled());
        assert!(manager.error_log_enabled());

        manager.log_request_error("error", "upstream down", "trace-574", None, None, None);
        manager.flush();
        assert!(std::fs::read_to_string(&error_log_path)
            .unwrap()
            .contains("upstream down"));
    }

    /// A configured audit log that cannot be opened is fatal, and the error
    /// names the audit log and its path so the operator can fix it.
    #[test]
    fn test_unopenable_audit_log_is_an_error() {
        let dir = tempdir().unwrap();
        let audit_log_path = unopenable_path(dir.path(), "audit.log");

        let config = LoggingConfig {
            access_log: Some(access_log_config(dir.path().join("access.log"))),
            audit_log: Some(AuditLogConfig {
                file: audit_log_path.clone(),
                ..AuditLogConfig::default()
            }),
            ..LoggingConfig::default()
        };

        let err = match LogManager::new(&config) {
            Ok(_) => panic!("an audit log that cannot be opened must not be skipped"),
            Err(e) => format!("{:#}", e),
        };
        assert!(err.contains("audit log"), "{err}");
        assert!(err.contains(&format!("{:?}", audit_log_path)), "{err}");
    }

    /// A log that is not configured is not opened, so the default config
    /// touches no file at all.
    #[test]
    fn test_default_config_opens_no_log_files() {
        let manager = LogManager::new(&LoggingConfig::default()).unwrap();
        assert!(!manager.access_log_enabled());
        assert!(!manager.error_log_enabled());
        assert!(!manager.audit_log_enabled());
    }

    #[test]
    fn drop_on_write_error_drops_failed_writes() {
        struct BrokenPipe;
        impl Write for BrokenPipe {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
        }

        let before = dropped_log_writes();
        let mut writer = DropOnWriteError(BrokenPipe);
        writer.write_all(b"a log line\n").unwrap();
        writer.flush().unwrap();
        assert!(dropped_log_writes() > before);
    }
}
