//! WebSocket proxying support for Sentinel
//!
//! This module provides WebSocket protocol support including HTTP/1.1 upgrade handling,
//! bidirectional streaming, frame inspection, and connection management.

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures::{SinkExt, StreamExt};
use hyper::{Body, Request, Response, StatusCode};
use pingora::protocols::http::{v1::client::HttpSession as Http1Session, HttpTask};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::{interval, timeout};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::frame::coding::CloseCode,
    tungstenite::protocol::CloseFrame, tungstenite::protocol::Message,
    tungstenite::protocol::WebSocketConfig, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, warn};

use crate::types::{SentinelError, SentinelResult};

/// WebSocket magic string for handshake
const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket configuration
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Enable WebSocket support
    pub enabled: bool,
    /// Maximum frame size in bytes
    pub max_frame_size: usize,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Idle timeout for connections
    pub idle_timeout: Duration,
    /// Ping interval
    pub ping_interval: Option<Duration>,
    /// Enable compression (permessage-deflate)
    pub compression: bool,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Buffer size for frames
    pub buffer_size: usize,
    /// Enable frame inspection
    pub inspect_frames: bool,
    /// Close timeout
    pub close_timeout: Duration,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_frame_size: 1024 * 1024,        // 1MB
            max_message_size: 10 * 1024 * 1024, // 10MB
            idle_timeout: Duration::from_secs(300),
            ping_interval: Some(Duration::from_secs(30)),
            compression: true,
            allowed_origins: vec!["*".to_string()],
            max_connections: 10000,
            buffer_size: 65536,
            inspect_frames: false,
            close_timeout: Duration::from_secs(5),
        }
    }
}

/// WebSocket frame for inspection
#[derive(Debug, Clone)]
pub struct WsFrame {
    /// Frame opcode
    pub opcode: Opcode,
    /// Frame payload
    pub payload: Vec<u8>,
    /// Is final frame
    pub is_final: bool,
    /// Timestamp
    pub timestamp: Instant,
}

/// WebSocket opcode types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

/// WebSocket connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Open,
    Closing,
    Closed,
}

/// WebSocket proxy handler
pub struct WebSocketProxy {
    config: Arc<WebSocketConfig>,
    connections: Arc<RwLock<HashMap<String, WsConnection>>>,
    connection_limit: Arc<Semaphore>,
    metrics: Arc<WsMetrics>,
}

impl WebSocketProxy {
    /// Create a new WebSocket proxy
    pub fn new(config: WebSocketConfig) -> Self {
        let connection_limit = Arc::new(Semaphore::new(config.max_connections));

        Self {
            config: Arc::new(config),
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_limit,
            metrics: Arc::new(WsMetrics::default()),
        }
    }

    /// Check if request is a WebSocket upgrade
    pub fn is_websocket_upgrade(headers: &HashMap<String, String>) -> bool {
        headers
            .get("upgrade")
            .map(|v| v.to_lowercase() == "websocket")
            .unwrap_or(false)
            && headers
                .get("connection")
                .map(|v| v.to_lowercase().contains("upgrade"))
                .unwrap_or(false)
    }

    /// Validate WebSocket handshake
    pub fn validate_handshake(&self, headers: &HashMap<String, String>) -> SentinelResult<String> {
        // Check required headers
        let key = headers
            .get("sec-websocket-key")
            .ok_or_else(|| SentinelError::InvalidRequest("Missing Sec-WebSocket-Key".into()))?;

        let version = headers
            .get("sec-websocket-version")
            .ok_or_else(|| SentinelError::InvalidRequest("Missing Sec-WebSocket-Version".into()))?;

        if version != "13" {
            return Err(SentinelError::InvalidRequest(format!(
                "Unsupported WebSocket version: {}",
                version
            )));
        }

        // Validate origin if configured
        if !self.config.allowed_origins.contains(&"*".to_string()) {
            if let Some(origin) = headers.get("origin") {
                if !self.config.allowed_origins.contains(origin) {
                    return Err(SentinelError::Forbidden(format!(
                        "Origin not allowed: {}",
                        origin
                    )));
                }
            }
        }

        // Calculate accept key
        let accept_key = self.calculate_accept_key(key);
        Ok(accept_key)
    }

    /// Calculate WebSocket accept key
    fn calculate_accept_key(&self, key: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_MAGIC.as_bytes());
        let result = hasher.finalize();
        BASE64.encode(result)
    }

    /// Handle WebSocket connection
    pub async fn handle_connection(
        &self,
        connection_id: String,
        client_stream: TcpStream,
        upstream_addr: String,
        headers: HashMap<String, String>,
    ) -> SentinelResult<()> {
        // Acquire connection permit
        let _permit = self
            .connection_limit
            .acquire()
            .await
            .map_err(|_| SentinelError::ResourceExhausted("Connection limit reached".into()))?;

        self.metrics
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.metrics
            .total_connections
            .fetch_add(1, Ordering::Relaxed);

        let result = self
            .proxy_websocket(connection_id.clone(), client_stream, upstream_addr, headers)
            .await;

        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        self.connections.write().await.remove(&connection_id);

        if let Err(e) = &result {
            self.metrics.errors.fetch_add(1, Ordering::Relaxed);
            error!("WebSocket proxy error for {}: {}", connection_id, e);
        }

        result
    }

    /// Proxy WebSocket connection between client and upstream
    async fn proxy_websocket(
        &self,
        connection_id: String,
        client_stream: TcpStream,
        upstream_addr: String,
        headers: HashMap<String, String>,
    ) -> SentinelResult<()> {
        info!(
            "Establishing WebSocket connection {} to {}",
            connection_id, upstream_addr
        );

        // Create WebSocket configuration
        let ws_config = WebSocketConfig {
            max_send_queue: Some(1000),
            max_message_size: Some(self.config.max_message_size),
            max_frame_size: Some(self.config.max_frame_size),
            accept_unmasked_frames: false,
        };

        // Connect to upstream
        let upstream_url = format!(
            "ws://{}{}",
            upstream_addr,
            headers.get("path").unwrap_or(&"/".to_string())
        );
        let (upstream_stream, _) = connect_async(&upstream_url)
            .await
            .context("Failed to connect to upstream")?;

        // Accept client connection
        let client_stream =
            tokio_tungstenite::accept_async_with_config(client_stream, Some(ws_config))
                .await
                .context("Failed to accept client WebSocket")?;

        // Create connection tracking
        let connection = WsConnection {
            id: connection_id.clone(),
            state: ConnectionState::Open,
            created_at: Instant::now(),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            messages_sent: Arc::new(AtomicU64::new(0)),
            messages_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
        };

        self.connections
            .write()
            .await
            .insert(connection_id.clone(), connection.clone());

        // Split streams for bidirectional proxying
        let (mut client_sink, mut client_stream) = client_stream.split();
        let (mut upstream_sink, mut upstream_stream) = upstream_stream.split();

        // Start ping task if configured
        let ping_handle = if let Some(ping_interval) = self.config.ping_interval {
            let client_sink_clone = client_sink.clone();
            let connection_id_clone = connection_id.clone();
            Some(tokio::spawn(async move {
                let mut interval = interval(ping_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = client_sink_clone.send(Message::Ping(vec![])).await {
                        debug!("Failed to send ping to {}: {}", connection_id_clone, e);
                        break;
                    }
                }
            }))
        } else {
            None
        };

        // Proxy messages bidirectionally
        let client_to_upstream = self.proxy_messages(
            &mut client_stream,
            &mut upstream_sink,
            connection.clone(),
            Direction::ClientToUpstream,
        );

        let upstream_to_client = self.proxy_messages(
            &mut upstream_stream,
            &mut client_sink,
            connection.clone(),
            Direction::UpstreamToClient,
        );

        // Wait for either direction to complete
        tokio::select! {
            result = client_to_upstream => {
                if let Err(e) = result {
                    warn!("Client to upstream error: {}", e);
                }
            }
            result = upstream_to_client => {
                if let Err(e) = result {
                    warn!("Upstream to client error: {}", e);
                }
            }
        }

        // Cancel ping task
        if let Some(handle) = ping_handle {
            handle.abort();
        }

        // Close connections gracefully
        self.close_connection(&mut client_sink, &mut upstream_sink)
            .await;

        info!("WebSocket connection {} closed", connection_id);
        Ok(())
    }

    /// Proxy messages between streams
    async fn proxy_messages<S, D>(
        &self,
        source: &mut S,
        dest: &mut D,
        connection: WsConnection,
        direction: Direction,
    ) -> Result<()>
    where
        S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
        D: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    {
        let idle_timeout = self.config.idle_timeout;

        while let Ok(Some(msg)) = timeout(idle_timeout, source.next()).await {
            let msg = msg.context("Failed to read message")?;

            // Update activity timestamp
            *connection.last_activity.write().await = Instant::now();

            // Update metrics based on direction
            match direction {
                Direction::ClientToUpstream => {
                    connection.messages_received.fetch_add(1, Ordering::Relaxed);
                    connection
                        .bytes_received
                        .fetch_add(msg.len(), Ordering::Relaxed);
                    self.metrics
                        .messages_received
                        .fetch_add(1, Ordering::Relaxed);
                }
                Direction::UpstreamToClient => {
                    connection.messages_sent.fetch_add(1, Ordering::Relaxed);
                    connection
                        .bytes_sent
                        .fetch_add(msg.len(), Ordering::Relaxed);
                    self.metrics.messages_sent.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Inspect frame if configured
            if self.config.inspect_frames {
                self.inspect_frame(&msg, direction);
            }

            // Handle different message types
            match &msg {
                Message::Close(frame) => {
                    debug!("Received close frame: {:?}", frame);
                    dest.send(msg).await.context("Failed to forward close")?;
                    break;
                }
                Message::Ping(data) => {
                    // Respond with pong
                    if direction == Direction::ClientToUpstream {
                        dest.send(Message::Pong(data.clone()))
                            .await
                            .context("Failed to send pong")?;
                    }
                }
                Message::Pong(_) => {
                    // Pong frames are not forwarded
                    continue;
                }
                _ => {
                    // Forward other messages
                    dest.send(msg).await.context("Failed to forward message")?;
                }
            }
        }

        Ok(())
    }

    /// Inspect WebSocket frame
    fn inspect_frame(&self, message: &Message, direction: Direction) {
        let frame = match message {
            Message::Text(data) => WsFrame {
                opcode: Opcode::Text,
                payload: data.as_bytes().to_vec(),
                is_final: true,
                timestamp: Instant::now(),
            },
            Message::Binary(data) => WsFrame {
                opcode: Opcode::Binary,
                payload: data.clone(),
                is_final: true,
                timestamp: Instant::now(),
            },
            Message::Ping(data) => WsFrame {
                opcode: Opcode::Ping,
                payload: data.clone(),
                is_final: true,
                timestamp: Instant::now(),
            },
            Message::Pong(data) => WsFrame {
                opcode: Opcode::Pong,
                payload: data.clone(),
                is_final: true,
                timestamp: Instant::now(),
            },
            Message::Close(_) => WsFrame {
                opcode: Opcode::Close,
                payload: vec![],
                is_final: true,
                timestamp: Instant::now(),
            },
            Message::Frame(_) => return,
        };

        debug!(
            "Frame inspection - Direction: {:?}, Opcode: {:?}, Size: {} bytes",
            direction,
            frame.opcode,
            frame.payload.len()
        );

        // Here you could implement additional frame inspection logic
        // such as content filtering, logging, or statistics collection
    }

    /// Close WebSocket connection gracefully
    async fn close_connection<C, U>(&self, client: &mut C, upstream: &mut U)
    where
        C: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
        U: SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
    {
        let close_frame = CloseFrame {
            code: CloseCode::Normal,
            reason: "Connection closing".into(),
        };

        let close_msg = Message::Close(Some(close_frame));

        // Send close to both ends
        let _ = timeout(self.config.close_timeout, client.send(close_msg.clone())).await;

        let _ = timeout(self.config.close_timeout, upstream.send(close_msg)).await;
    }

    /// Get connection statistics
    pub async fn get_connection_stats(&self, connection_id: &str) -> Option<ConnectionStats> {
        let connections = self.connections.read().await;
        connections.get(connection_id).map(|conn| ConnectionStats {
            id: conn.id.clone(),
            state: conn.state,
            duration: conn.created_at.elapsed(),
            messages_sent: conn.messages_sent.load(Ordering::Relaxed),
            messages_received: conn.messages_received.load(Ordering::Relaxed),
            bytes_sent: conn.bytes_sent.load(Ordering::Relaxed),
            bytes_received: conn.bytes_received.load(Ordering::Relaxed),
        })
    }

    /// Get global metrics
    pub fn metrics(&self) -> WsMetricsSnapshot {
        WsMetricsSnapshot {
            active_connections: self.metrics.active_connections.load(Ordering::Relaxed),
            total_connections: self.metrics.total_connections.load(Ordering::Relaxed),
            messages_sent: self.metrics.messages_sent.load(Ordering::Relaxed),
            messages_received: self.metrics.messages_received.load(Ordering::Relaxed),
            errors: self.metrics.errors.load(Ordering::Relaxed),
        }
    }
}

/// WebSocket connection tracking
#[derive(Debug, Clone)]
struct WsConnection {
    id: String,
    state: ConnectionState,
    created_at: Instant,
    last_activity: Arc<RwLock<Instant>>,
    messages_sent: Arc<AtomicU64>,
    messages_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub id: String,
    pub state: ConnectionState,
    pub duration: Duration,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Message direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToUpstream,
    UpstreamToClient,
}

/// WebSocket metrics
#[derive(Debug, Default)]
struct WsMetrics {
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    messages_sent: AtomicU64,
    messages_received: AtomicU64,
    errors: AtomicU64,
}

/// WebSocket metrics snapshot
#[derive(Debug, Clone)]
pub struct WsMetricsSnapshot {
    pub active_connections: usize,
    pub total_connections: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_detection() {
        let mut headers = HashMap::new();
        headers.insert("upgrade".to_string(), "websocket".to_string());
        headers.insert("connection".to_string(), "upgrade".to_string());

        assert!(WebSocketProxy::is_websocket_upgrade(&headers));

        headers.remove("upgrade");
        assert!(!WebSocketProxy::is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_accept_key_calculation() {
        let proxy = WebSocketProxy::new(WebSocketConfig::default());
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

        assert_eq!(proxy.calculate_accept_key(key), expected);
    }

    #[tokio::test]
    async fn test_origin_validation() {
        let mut config = WebSocketConfig::default();
        config.allowed_origins = vec!["https://example.com".to_string()];
        let proxy = WebSocketProxy::new(config);

        let mut headers = HashMap::new();
        headers.insert("sec-websocket-key".to_string(), "test".to_string());
        headers.insert("sec-websocket-version".to_string(), "13".to_string());
        headers.insert("origin".to_string(), "https://evil.com".to_string());

        assert!(proxy.validate_handshake(&headers).is_err());

        headers.insert("origin".to_string(), "https://example.com".to_string());
        assert!(proxy.validate_handshake(&headers).is_ok());
    }
}
