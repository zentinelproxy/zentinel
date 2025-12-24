//! HTTP/3 and QUIC support module for Sentinel proxy
//!
//! This module provides HTTP/3 support using QUIC as the transport protocol.
//! HTTP/3 offers improved performance over lossy networks and eliminates
//! head-of-line blocking issues present in HTTP/2 over TCP.
//!
//! Note: This module is prepared for future integration when Pingora adds
//! native HTTP/3 support or when using alternative QUIC implementations.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode, Version};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info};

use sentinel_config::{ListenerConfig, TlsConfig};

/// HTTP/3 server configuration
#[derive(Debug, Clone)]
pub struct Http3Config {
    /// Listen address for QUIC
    pub listen_addr: SocketAddr,

    /// TLS configuration
    pub tls: Http3TlsConfig,

    /// QUIC transport parameters
    pub transport: QuicTransportConfig,

    /// HTTP/3 specific settings
    pub http3: Http3Settings,

    /// Alt-Svc header configuration
    pub alt_svc: AltSvcConfig,

    /// Enable 0-RTT (early data)
    pub enable_0rtt: bool,

    /// Migration support
    pub enable_migration: bool,
}

/// TLS configuration for HTTP/3
#[derive(Debug, Clone)]
pub struct Http3TlsConfig {
    /// Certificate chain file
    pub cert_file: PathBuf,

    /// Private key file
    pub key_file: PathBuf,

    /// ALPN protocols
    pub alpn_protocols: Vec<String>,

    /// Minimum TLS version (1.3 required for QUIC)
    pub min_version: TlsVersion,

    /// Cipher suites for TLS 1.3
    pub cipher_suites: Vec<String>,

    /// Enable OCSP stapling
    pub ocsp_stapling: bool,

    /// Session ticket configuration
    pub session_tickets: bool,
}

/// QUIC transport configuration
#[derive(Debug, Clone)]
pub struct QuicTransportConfig {
    /// Maximum idle timeout
    pub max_idle_timeout: Duration,

    /// Maximum UDP payload size
    pub max_udp_payload_size: u16,

    /// Initial maximum data
    pub initial_max_data: u64,

    /// Initial maximum stream data (bidirectional)
    pub initial_max_stream_data_bidi: u64,

    /// Initial maximum stream data (unidirectional)
    pub initial_max_stream_data_uni: u64,

    /// Initial maximum streams (bidirectional)
    pub initial_max_streams_bidi: u64,

    /// Initial maximum streams (unidirectional)
    pub initial_max_streams_uni: u64,

    /// ACK delay exponent
    pub ack_delay_exponent: u8,

    /// Maximum ACK delay
    pub max_ack_delay: Duration,

    /// Disable active migration
    pub disable_active_migration: bool,

    /// Enable DATAGRAM frames
    pub enable_datagram: bool,

    /// Congestion control algorithm
    pub congestion_control: CongestionControl,
}

/// HTTP/3 specific settings
#[derive(Debug, Clone)]
pub struct Http3Settings {
    /// Maximum header list size
    pub max_header_list_size: u32,

    /// QPACK maximum table capacity
    pub qpack_max_table_capacity: u32,

    /// QPACK blocked streams
    pub qpack_blocked_streams: u32,

    /// Enable WebTransport
    pub enable_webtransport: bool,

    /// Enable extended CONNECT
    pub enable_extended_connect: bool,

    /// Maximum field section size
    pub max_field_section_size: u32,
}

/// Alt-Svc header configuration
#[derive(Debug, Clone)]
pub struct AltSvcConfig {
    /// Enable Alt-Svc header
    pub enabled: bool,

    /// Max age for Alt-Svc
    pub max_age: u32,

    /// Port for HTTP/3
    pub port: u16,

    /// Include draft versions
    pub include_draft: bool,

    /// Persist to disk
    pub persist: bool,
}

/// Congestion control algorithms
#[derive(Debug, Clone, Copy)]
pub enum CongestionControl {
    /// Cubic (default)
    Cubic,
    /// BBR (Bottleneck Bandwidth and RTT)
    Bbr,
    /// New Reno
    NewReno,
}

/// TLS version
#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    /// TLS 1.3 (required for QUIC)
    Tls13,
}

/// HTTP/3 server instance
pub struct Http3Server {
    /// Configuration
    config: Arc<Http3Config>,

    /// Connection manager
    connections: Arc<RwLock<ConnectionManager>>,

    /// Metrics collector
    metrics: Arc<Http3Metrics>,

    /// Whether server is running
    running: Arc<RwLock<bool>>,
}

/// Connection manager for HTTP/3 connections
struct ConnectionManager {
    /// Active connections
    connections: HashMap<ConnectionId, Connection>,

    /// Maximum connections
    max_connections: usize,

    /// Connection timeout
    timeout: Duration,
}

/// HTTP/3 connection
struct Connection {
    /// Connection ID
    id: ConnectionId,

    /// Remote address
    remote_addr: SocketAddr,

    /// Connection state
    state: ConnectionState,

    /// Active streams
    streams: HashMap<StreamId, Stream>,

    /// Connection metrics
    metrics: ConnectionMetrics,

    /// Established time
    established_at: std::time::Instant,
}

/// Connection identifier
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnectionId(Vec<u8>);

/// Stream identifier
type StreamId = u64;

/// HTTP/3 stream
struct Stream {
    /// Stream ID
    id: StreamId,

    /// Stream type
    stream_type: StreamType,

    /// Stream state
    state: StreamState,

    /// Request data
    request: Option<Request<()>>,

    /// Response data
    response: Option<Response<Bytes>>,
}

/// Stream types
#[derive(Debug, Clone)]
enum StreamType {
    /// Request stream
    Request,
    /// Push stream
    Push,
    /// Control stream
    Control,
    /// QPACK encoder stream
    QpackEncoder,
    /// QPACK decoder stream
    QpackDecoder,
    /// WebTransport stream
    WebTransport,
}

/// Connection state
#[derive(Debug, Clone)]
enum ConnectionState {
    /// Handshaking
    Handshaking,
    /// Established
    Established,
    /// Closing
    Closing,
    /// Closed
    Closed,
}

/// Stream state
#[derive(Debug, Clone)]
enum StreamState {
    /// Idle
    Idle,
    /// Open
    Open,
    /// Half closed (local)
    HalfClosedLocal,
    /// Half closed (remote)
    HalfClosedRemote,
    /// Closed
    Closed,
}

/// Connection metrics
#[derive(Debug, Clone, Default)]
struct ConnectionMetrics {
    /// Bytes sent
    bytes_sent: u64,

    /// Bytes received
    bytes_received: u64,

    /// Packets sent
    packets_sent: u64,

    /// Packets received
    packets_received: u64,

    /// Packets lost
    packets_lost: u64,

    /// RTT (round-trip time)
    rtt: Option<Duration>,

    /// Congestion window
    cwnd: u64,

    /// Streams opened
    streams_opened: u64,

    /// Streams closed
    streams_closed: u64,
}

/// HTTP/3 metrics
pub struct Http3Metrics {
    /// Total connections
    total_connections: std::sync::atomic::AtomicU64,

    /// Active connections
    active_connections: std::sync::atomic::AtomicU64,

    /// Total requests
    total_requests: std::sync::atomic::AtomicU64,

    /// Failed requests
    failed_requests: std::sync::atomic::AtomicU64,

    /// 0-RTT accepts
    zero_rtt_accepts: std::sync::atomic::AtomicU64,

    /// 0-RTT rejects
    zero_rtt_rejects: std::sync::atomic::AtomicU64,

    /// Connection migrations
    connection_migrations: std::sync::atomic::AtomicU64,
}

impl Http3Server {
    /// Create a new HTTP/3 server
    pub fn new(config: Http3Config) -> Result<Self> {
        info!("Initializing HTTP/3 server on {}", config.listen_addr);

        // Validate configuration
        config.validate()?;

        Ok(Self {
            config: Arc::new(config),
            connections: Arc::new(RwLock::new(ConnectionManager::new())),
            metrics: Arc::new(Http3Metrics::new()),
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Start the HTTP/3 server
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Err(anyhow::anyhow!("HTTP/3 server is already running"));
        }

        info!("Starting HTTP/3 server on {}", self.config.listen_addr);

        // Note: This is a placeholder for actual QUIC/HTTP3 implementation
        // When Pingora supports HTTP/3 or when integrating with quinn/quiche,
        // the actual server initialization would go here

        *running = true;

        // Start background tasks
        self.start_background_tasks().await;

        Ok(())
    }

    /// Stop the HTTP/3 server
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }

        info!("Stopping HTTP/3 server");

        // Gracefully close all connections
        self.close_all_connections().await?;

        *running = false;

        Ok(())
    }

    /// Handle an incoming HTTP/3 request
    pub async fn handle_request(&self, req: Request<Bytes>) -> Result<Response<Bytes>> {
        debug!("Handling HTTP/3 request: {} {}", req.method(), req.uri());

        // Update metrics
        self.metrics.increment_requests();

        // Check if this is a WebTransport upgrade
        if self.is_webtransport_request(&req) && self.config.http3.enable_webtransport {
            return self.handle_webtransport_upgrade(req).await;
        }

        // Process normal HTTP/3 request
        // This would integrate with the main proxy logic

        Ok(Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_3)
            .header("alt-svc", self.get_alt_svc_header())
            .body(Bytes::from("HTTP/3 response"))?)
    }

    /// Check if request is a WebTransport upgrade
    fn is_webtransport_request(&self, req: &Request<Bytes>) -> bool {
        req.headers()
            .get(":protocol")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "webtransport")
            .unwrap_or(false)
    }

    /// Handle WebTransport upgrade
    async fn handle_webtransport_upgrade(&self, _req: Request<Bytes>) -> Result<Response<Bytes>> {
        info!("Handling WebTransport upgrade");

        Ok(Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_3)
            .header("sec-webtransport-http3-draft", "draft02")
            .body(Bytes::new())?)
    }

    /// Generate Alt-Svc header
    fn get_alt_svc_header(&self) -> String {
        if !self.config.alt_svc.enabled {
            return String::new();
        }

        let mut alt_svc = format!("h3=\":{}\"", self.config.alt_svc.port);

        if self.config.alt_svc.include_draft {
            alt_svc.push_str(&format!(", h3-29=\":{}\"", self.config.alt_svc.port));
        }

        alt_svc.push_str(&format!("; ma={}", self.config.alt_svc.max_age));

        if self.config.alt_svc.persist {
            alt_svc.push_str("; persist=1");
        }

        alt_svc
    }

    /// Start background tasks
    async fn start_background_tasks(&self) {
        // Connection cleanup task
        let connections = Arc::clone(&self.connections);
        let metrics = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;

                // Clean up idle connections
                let mut manager = connections.write().await;
                manager.cleanup_idle_connections();

                // Update metrics
                metrics.update_active_connections(manager.connections.len());
            }
        });

        info!("Started HTTP/3 background tasks");
    }

    /// Close all connections gracefully
    async fn close_all_connections(&self) -> Result<()> {
        let mut manager = self.connections.write().await;

        for (id, mut conn) in manager.connections.drain() {
            debug!("Closing connection {:?}", id);
            conn.state = ConnectionState::Closing;
            // Send CONNECTION_CLOSE frame
            // Actual implementation would send proper QUIC close
        }

        Ok(())
    }

    /// Get server metrics
    pub fn metrics(&self) -> Http3MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Check if server supports 0-RTT
    pub fn supports_0rtt(&self) -> bool {
        self.config.enable_0rtt
    }

    /// Check if server supports migration
    pub fn supports_migration(&self) -> bool {
        self.config.enable_migration
    }
}

impl Http3Config {
    /// Validate configuration
    fn validate(&self) -> Result<()> {
        // Ensure TLS 1.3 is used (required for QUIC)
        if !matches!(self.tls.min_version, TlsVersion::Tls13) {
            return Err(anyhow::anyhow!("HTTP/3 requires TLS 1.3"));
        }

        // Ensure ALPN includes h3
        if !self.tls.alpn_protocols.iter().any(|p| p == "h3") {
            return Err(anyhow::anyhow!("HTTP/3 requires 'h3' ALPN protocol"));
        }

        // Validate transport parameters
        if self.transport.max_idle_timeout < Duration::from_secs(1) {
            return Err(anyhow::anyhow!("max_idle_timeout too short"));
        }

        if self.transport.max_udp_payload_size < 1200 {
            return Err(anyhow::anyhow!(
                "max_udp_payload_size must be at least 1200"
            ));
        }

        Ok(())
    }
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".parse().unwrap(),
            tls: Http3TlsConfig::default(),
            transport: QuicTransportConfig::default(),
            http3: Http3Settings::default(),
            alt_svc: AltSvcConfig::default(),
            enable_0rtt: false,
            enable_migration: false,
        }
    }
}

impl Default for Http3TlsConfig {
    fn default() -> Self {
        Self {
            cert_file: PathBuf::from("/etc/sentinel/certs/cert.pem"),
            key_file: PathBuf::from("/etc/sentinel/certs/key.pem"),
            alpn_protocols: vec!["h3".to_string(), "h3-29".to_string()],
            min_version: TlsVersion::Tls13,
            cipher_suites: vec![
                "TLS_AES_128_GCM_SHA256".to_string(),
                "TLS_AES_256_GCM_SHA384".to_string(),
                "TLS_CHACHA20_POLY1305_SHA256".to_string(),
            ],
            ocsp_stapling: true,
            session_tickets: true,
        }
    }
}

impl Default for QuicTransportConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout: Duration::from_secs(30),
            max_udp_payload_size: 1350,
            initial_max_data: 10 * 1024 * 1024,
            initial_max_stream_data_bidi: 1024 * 1024,
            initial_max_stream_data_uni: 1024 * 1024,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
            enable_datagram: false,
            congestion_control: CongestionControl::Cubic,
        }
    }
}

impl Default for Http3Settings {
    fn default() -> Self {
        Self {
            max_header_list_size: 16 * 1024,
            qpack_max_table_capacity: 16 * 1024,
            qpack_blocked_streams: 100,
            enable_webtransport: false,
            enable_extended_connect: false,
            max_field_section_size: 16 * 1024,
        }
    }
}

impl Default for AltSvcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_age: 86400, // 24 hours
            port: 443,
            include_draft: false,
            persist: false,
        }
    }
}

impl ConnectionManager {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
            max_connections: 10000,
            timeout: Duration::from_secs(30),
        }
    }

    fn cleanup_idle_connections(&mut self) {
        let now = std::time::Instant::now();

        self.connections.retain(|id, conn| {
            let idle_time = now.duration_since(conn.established_at);
            if idle_time > self.timeout {
                debug!("Removing idle connection {:?}", id);
                false
            } else {
                true
            }
        });
    }
}

impl Http3Metrics {
    fn new() -> Self {
        use std::sync::atomic::AtomicU64;

        Self {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            zero_rtt_accepts: AtomicU64::new(0),
            zero_rtt_rejects: AtomicU64::new(0),
            connection_migrations: AtomicU64::new(0),
        }
    }

    fn increment_requests(&self) {
        self.total_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn update_active_connections(&self, count: usize) {
        self.active_connections
            .store(count as u64, std::sync::atomic::Ordering::Relaxed);
    }

    fn snapshot(&self) -> Http3MetricsSnapshot {
        use std::sync::atomic::Ordering;

        Http3MetricsSnapshot {
            total_connections: self.total_connections.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            zero_rtt_accepts: self.zero_rtt_accepts.load(Ordering::Relaxed),
            zero_rtt_rejects: self.zero_rtt_rejects.load(Ordering::Relaxed),
            connection_migrations: self.connection_migrations.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of HTTP/3 metrics
#[derive(Debug, Clone)]
pub struct Http3MetricsSnapshot {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_requests: u64,
    pub failed_requests: u64,
    pub zero_rtt_accepts: u64,
    pub zero_rtt_rejects: u64,
    pub connection_migrations: u64,
}

/// Enable HTTP/3 for a listener
pub async fn enable_http3(
    listener_config: &ListenerConfig,
    tls_config: Option<&TlsConfig>,
) -> Result<Option<Http3Server>> {
    // Check if listener protocol is HTTP/3
    if !matches!(
        listener_config.protocol,
        sentinel_config::ListenerProtocol::Http3
    ) {
        return Ok(None);
    }

    // Ensure TLS configuration is provided
    let tls = tls_config.ok_or_else(|| anyhow::anyhow!("HTTP/3 requires TLS configuration"))?;

    // Parse listen address
    let listen_addr: SocketAddr = listener_config
        .address
        .parse()
        .context("Invalid listener address")?;

    // Build HTTP/3 configuration
    let config = Http3Config {
        listen_addr,
        tls: Http3TlsConfig {
            cert_file: PathBuf::from(&tls.cert_file),
            key_file: PathBuf::from(&tls.key_file),
            alpn_protocols: vec!["h3".to_string()],
            min_version: TlsVersion::Tls13,
            cipher_suites: if tls.cipher_suites.is_empty() {
                vec![
                    "TLS_AES_128_GCM_SHA256".to_string(),
                    "TLS_AES_256_GCM_SHA384".to_string(),
                ]
            } else {
                tls.cipher_suites.clone()
            },
            ocsp_stapling: tls.ocsp_stapling,
            session_tickets: tls.session_resumption,
        },
        transport: QuicTransportConfig::default(),
        http3: Http3Settings::default(),
        alt_svc: AltSvcConfig::default(),
        enable_0rtt: false,
        enable_migration: false,
    };

    // Create and start the server
    let server = Http3Server::new(config)?;
    server.start().await?;

    info!(
        "HTTP/3 server enabled on {} for listener {}",
        listen_addr, listener_config.id
    );

    Ok(Some(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http3_config_validation() {
        let config = Http3Config::default();
        assert!(config.validate().is_ok());

        // Test with invalid ALPN
        let mut bad_config = Http3Config::default();
        bad_config.tls.alpn_protocols = vec!["h2".to_string()];
        assert!(bad_config.validate().is_err());
    }

    #[test]
    fn test_alt_svc_header_generation() {
        let config = Http3Config::default();
        let server = Http3Server::new(config).unwrap();

        let header = server.get_alt_svc_header();
        assert!(header.contains("h3=\":443\""));
        assert!(header.contains("ma=86400"));
    }

    #[tokio::test]
    async fn test_server_lifecycle() {
        let config = Http3Config::default();
        let server = Http3Server::new(config).unwrap();

        // Start server
        assert!(server.start().await.is_ok());
        assert!(*server.running.read().await);

        // Try to start again (should fail)
        assert!(server.start().await.is_err());

        // Stop server
        assert!(server.stop().await.is_ok());
        assert!(!*server.running.read().await);
    }

    #[test]
    fn test_metrics() {
        let metrics = Http3Metrics::new();

        metrics.increment_requests();
        metrics.increment_requests();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_requests, 2);
    }
}
