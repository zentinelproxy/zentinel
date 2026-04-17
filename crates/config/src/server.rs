//! Server and listener configuration types
//!
//! This module contains configuration types for the proxy server itself
//! and its listeners (ports/addresses it binds to).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use validator::Validate;

use zentinel_common::types::{TlsVersion, TraceIdFormat};

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

    /// Maximum requests per downstream connection before closing.
    /// Equivalent to nginx's keepalive_requests. None = unlimited.
    #[serde(default)]
    pub keepalive_max_requests: Option<u32>,
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
    /// Default certificate file path (used when no SNI match)
    /// Optional when ACME is configured
    pub cert_file: Option<PathBuf>,

    /// Default private key file path
    /// Optional when ACME is configured
    pub key_file: Option<PathBuf>,

    /// Additional certificates for SNI support
    /// Maps hostname patterns to certificate configurations
    #[serde(default)]
    pub additional_certs: Vec<SniCertificate>,

    /// CA certificate file path for client verification (mTLS)
    pub ca_file: Option<PathBuf>,

    /// Minimum TLS version
    #[serde(default = "default_min_tls_version")]
    pub min_version: TlsVersion,

    /// Maximum TLS version
    pub max_version: Option<TlsVersion>,

    /// Cipher suites (empty = use defaults)
    #[serde(default)]
    pub cipher_suites: Vec<String>,

    /// Require client certificates (mTLS)
    #[serde(default)]
    pub client_auth: bool,

    /// OCSP stapling
    #[serde(default = "default_ocsp_stapling")]
    pub ocsp_stapling: bool,

    /// Session resumption
    #[serde(default = "default_session_resumption")]
    pub session_resumption: bool,

    /// ACME automatic certificate management
    /// When configured, cert_file and key_file become optional
    pub acme: Option<AcmeConfig>,
}

/// ACME automatic certificate configuration
///
/// Enables zero-config TLS via Let's Encrypt and compatible CAs.
/// When configured, Zentinel will automatically obtain, renew, and
/// manage TLS certificates for the specified domains.
///
/// # Example
///
/// ```kdl
/// tls {
///     acme {
///         email "admin@example.com"
///         domains "example.com" "www.example.com"
///         staging false
///         storage "/var/lib/zentinel/acme"
///         renew-before-days 30
///         challenge-type "http-01"  // or "dns-01" for wildcards
///
///         // Required for DNS-01 challenges
///         dns-provider {
///             type "hetzner"
///             credentials-file "/etc/zentinel/secrets/hetzner-dns.json"
///             api-timeout-secs 30
///
///             propagation {
///                 initial-delay-secs 10
///                 check-interval-secs 5
///                 timeout-secs 120
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AcmeConfig {
    /// Contact email for account registration and recovery
    #[validate(email)]
    pub email: String,

    /// Domain names to obtain certificates for
    #[validate(length(min = 1, message = "at least one domain is required"))]
    pub domains: Vec<String>,

    /// Optional custom ACME directory URL (e.g., ZeroSSL)
    /// If not provided, defaults to Let's Encrypt
    #[validate(url)]
    pub server_url: Option<String>,

    /// Use Let's Encrypt staging environment
    /// Only used if server_url is not provided
    #[serde(default)]
    pub staging: bool,

    /// External Account Binding (EAB) credentials
    /// Required by some providers like ZeroSSL
    pub eab: Option<ExternalAccountBinding>,

    /// Directory for storing certificates and account keys
    #[serde(default = "default_acme_storage")]
    pub storage: PathBuf,

    /// Days before expiry to trigger renewal
    /// Let's Encrypt certificates are valid for 90 days
    /// Default is 30 days before expiry
    #[serde(default = "default_renewal_days")]
    pub renew_before_days: u32,

    /// Challenge type to use for domain validation
    /// Defaults to HTTP-01, use DNS-01 for wildcard certificates
    #[serde(default)]
    pub challenge_type: AcmeChallengeType,

    /// DNS provider configuration (required for DNS-01 challenges)
    pub dns_provider: Option<DnsProviderConfig>,
}

/// External Account Binding (EAB) credentials for ACME
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    /// Key ID (KID) provided by the ACME CA
    pub kid: String,
    /// HMAC Key (base64url-encoded) provided by the ACME CA
    pub hmac_key: String,
}

/// ACME challenge type
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeChallengeType {
    /// HTTP-01 challenge (default)
    /// Requires HTTP access on port 80
    #[default]
    Http01,

    /// DNS-01 challenge
    /// Required for wildcard certificates
    /// Requires DNS provider configuration
    Dns01,
}

impl AcmeChallengeType {
    /// Check if this is DNS-01 challenge type
    pub fn is_dns01(&self) -> bool {
        matches!(self, Self::Dns01)
    }

    /// Check if this is HTTP-01 challenge type
    pub fn is_http01(&self) -> bool {
        matches!(self, Self::Http01)
    }
}

/// DNS provider configuration for DNS-01 challenges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    /// DNS provider type
    pub provider: DnsProviderType,

    /// Path to credentials file
    /// File should contain JSON: {"token": "..."} or {"api_key": "...", "api_secret": "..."}
    pub credentials_file: Option<PathBuf>,

    /// Environment variable containing credentials
    pub credentials_env: Option<String>,

    /// API request timeout in seconds
    #[serde(default = "default_dns_api_timeout")]
    pub api_timeout_secs: u64,

    /// Propagation check configuration
    #[serde(default)]
    pub propagation: PropagationCheckConfig,
}

/// DNS provider type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsProviderType {
    /// Hetzner DNS API
    Hetzner,

    /// Cloudflare DNS API
    Cloudflare,

    /// Generic webhook provider
    Webhook {
        /// Webhook URL
        url: String,
        /// Optional custom auth header name
        auth_header: Option<String>,
    },
}

/// Configuration for DNS propagation checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationCheckConfig {
    /// Initial delay before first check (seconds)
    #[serde(default = "default_propagation_initial_delay")]
    pub initial_delay_secs: u64,

    /// Interval between propagation checks (seconds)
    #[serde(default = "default_propagation_check_interval")]
    pub check_interval_secs: u64,

    /// Maximum time to wait for propagation (seconds)
    #[serde(default = "default_propagation_timeout")]
    pub timeout_secs: u64,

    /// Custom nameservers to query (optional)
    /// Defaults to Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9)
    #[serde(default)]
    pub nameservers: Vec<String>,
}

impl Default for PropagationCheckConfig {
    fn default() -> Self {
        Self {
            initial_delay_secs: default_propagation_initial_delay(),
            check_interval_secs: default_propagation_check_interval(),
            timeout_secs: default_propagation_timeout(),
            nameservers: Vec::new(),
        }
    }
}

/// SNI certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniCertificate {
    /// Hostname patterns to match (e.g., "example.com", "*.example.com").
    /// When set, only these hostnames are registered and SAN auto-extraction is skipped.
    pub hostnames: Vec<String>,

    /// Priority hostnames for tie-breaking when multiple certs match the same SNI.
    /// When set, all SANs are still auto-extracted, but these hostnames win if
    /// another cert also claims them. Mutually exclusive with `hostnames`.
    pub priority_hostnames: Vec<String>,

    /// Certificate file path
    pub cert_file: PathBuf,

    /// Private key file path
    pub key_file: PathBuf,
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

pub(crate) fn default_acme_storage() -> PathBuf {
    PathBuf::from("/var/lib/zentinel/acme")
}

pub(crate) fn default_renewal_days() -> u32 {
    30
}

fn default_dns_api_timeout() -> u64 {
    30
}

fn default_propagation_initial_delay() -> u64 {
    10
}

fn default_propagation_check_interval() -> u64 {
    5
}

fn default_propagation_timeout() -> u64 {
    120
}
