//! Server and listener configuration types
//!
//! This module contains configuration types for the proxy server itself
//! and its listeners (ports/addresses it binds to).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use validator::Validate;

use sentinel_common::types::{TlsVersion, TraceIdFormat};

// ============================================================================
// Server Configuration
// ============================================================================

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

    /// Trace ID format for request tracing
    ///
    /// - `tinyflake` (default): 11-char Base58, operator-friendly
    /// - `uuid`: 36-char UUID v4, guaranteed unique
    #[serde(default)]
    pub trace_id_format: TraceIdFormat,

    /// Enable automatic configuration reload on file changes
    ///
    /// When enabled, the proxy will watch the configuration file for changes
    /// and automatically reload when modifications are detected.
    #[serde(default)]
    pub auto_reload: bool,
}

// ============================================================================
// Listener Configuration
// ============================================================================

/// Listener configuration (port binding)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ListenerConfig {
    /// Unique identifier for this listener
    pub id: String,

    /// Socket address to bind to
    #[validate(custom(function = "crate::validation::validate_socket_addr"))]
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

// ============================================================================
// TLS Configuration
// ============================================================================

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

// ============================================================================
// Default Value Functions
// ============================================================================

pub(crate) fn default_worker_threads() -> usize {
    0
}

pub(crate) fn default_max_connections() -> usize {
    10000
}

pub(crate) fn default_graceful_shutdown_timeout() -> u64 {
    30
}

pub(crate) fn default_request_timeout() -> u64 {
    60
}

pub(crate) fn default_keepalive_timeout() -> u64 {
    75
}

pub(crate) fn default_max_concurrent_streams() -> u32 {
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
