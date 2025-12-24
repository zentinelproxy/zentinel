//! Agent protocol for Sentinel proxy
//!
//! This module defines the protocol for communication between the proxy dataplane
//! and external processing agents (WAF, auth, rate limiting, custom logic).
//!
//! The protocol is inspired by SPOE (Stream Processing Offload Engine) and Envoy's ext_proc,
//! designed for bounded, predictable behavior with strong failure isolation.

#![allow(dead_code)]

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info};


/// Agent protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Agent protocol errors
#[derive(Error, Debug)]
pub enum AgentProtocolError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Message too large: {size} bytes (max: {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    #[error("Timeout after {0:?}")]
    Timeout(Duration),

    #[error("Agent unavailable")]
    Unavailable,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Agent event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Request headers received
    RequestHeaders,
    /// Request body chunk received
    RequestBodyChunk,
    /// Response headers received
    ResponseHeaders,
    /// Response body chunk received
    ResponseBodyChunk,
    /// Request/response complete (for logging)
    RequestComplete,
}

/// Agent decision
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow the request/response to continue
    Allow,
    /// Block the request/response
    Block {
        /// HTTP status code to return
        status: u16,
        /// Optional response body
        body: Option<String>,
        /// Optional response headers
        headers: Option<HashMap<String, String>>,
    },
    /// Redirect the request
    Redirect {
        /// Redirect URL
        url: String,
        /// HTTP status code (301, 302, 303, 307, 308)
        status: u16,
    },
    /// Challenge the client (e.g., CAPTCHA)
    Challenge {
        /// Challenge type
        challenge_type: String,
        /// Challenge parameters
        params: HashMap<String, String>,
    },
}

impl Default for Decision {
    fn default() -> Self {
        Self::Allow
    }
}

/// Header modification operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOp {
    /// Set a header (replace if exists)
    Set { name: String, value: String },
    /// Add a header (append if exists)
    Add { name: String, value: String },
    /// Remove a header
    Remove { name: String },
}

/// Request metadata sent to agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Correlation ID for request tracing
    pub correlation_id: String,
    /// Request ID (internal)
    pub request_id: String,
    /// Client IP address
    pub client_ip: String,
    /// Client port
    pub client_port: u16,
    /// Server name (SNI or Host header)
    pub server_name: Option<String>,
    /// Protocol (HTTP/1.1, HTTP/2, etc.)
    pub protocol: String,
    /// TLS version if applicable
    pub tls_version: Option<String>,
    /// TLS cipher suite if applicable
    pub tls_cipher: Option<String>,
    /// Route ID that matched
    pub route_id: Option<String>,
    /// Upstream ID
    pub upstream_id: Option<String>,
    /// Request start timestamp (RFC3339)
    pub timestamp: String,
}

/// Request headers event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestHeadersEvent {
    /// Event metadata
    pub metadata: RequestMetadata,
    /// HTTP method
    pub method: String,
    /// Request URI
    pub uri: String,
    /// HTTP headers
    pub headers: HashMap<String, Vec<String>>,
}

/// Request body chunk event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBodyChunkEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// Body chunk data (base64 encoded for JSON transport)
    pub data: String,
    /// Is this the last chunk?
    pub is_last: bool,
    /// Total body size if known
    pub total_size: Option<usize>,
}

/// Response headers event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseHeadersEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// HTTP status code
    pub status: u16,
    /// HTTP headers
    pub headers: HashMap<String, Vec<String>>,
}

/// Response body chunk event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseBodyChunkEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// Body chunk data (base64 encoded for JSON transport)
    pub data: String,
    /// Is this the last chunk?
    pub is_last: bool,
    /// Total body size if known
    pub total_size: Option<usize>,
}

/// Request complete event (for logging/audit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestCompleteEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// Final HTTP status code
    pub status: u16,
    /// Request duration in milliseconds
    pub duration_ms: u64,
    /// Request body size
    pub request_body_size: usize,
    /// Response body size
    pub response_body_size: usize,
    /// Upstream attempts
    pub upstream_attempts: u32,
    /// Error if any
    pub error: Option<String>,
}

/// Agent request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRequest {
    /// Protocol version
    pub version: u32,
    /// Event type
    pub event_type: EventType,
    /// Event payload (JSON)
    pub payload: serde_json::Value,
}

/// Agent response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    /// Protocol version
    pub version: u32,
    /// Decision
    pub decision: Decision,
    /// Header modifications for request
    #[serde(default)]
    pub request_headers: Vec<HeaderOp>,
    /// Header modifications for response
    #[serde(default)]
    pub response_headers: Vec<HeaderOp>,
    /// Routing metadata modifications
    #[serde(default)]
    pub routing_metadata: HashMap<String, String>,
    /// Audit metadata
    #[serde(default)]
    pub audit: AuditMetadata,
}

/// Audit metadata from agent
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditMetadata {
    /// Tags for logging/metrics
    #[serde(default)]
    pub tags: Vec<String>,
    /// Rule IDs that matched
    #[serde(default)]
    pub rule_ids: Vec<String>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: Option<f32>,
    /// Reason codes
    #[serde(default)]
    pub reason_codes: Vec<String>,
    /// Custom metadata
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Agent client for communicating with external agents
pub struct AgentClient {
    /// Agent ID
    id: String,
    /// Connection to agent
    connection: AgentConnection,
    /// Timeout for agent calls
    timeout: Duration,
    /// Maximum retries
    max_retries: u32,
}

/// Agent connection type
enum AgentConnection {
    UnixSocket(UnixStream),
    Grpc(tonic::transport::Channel),
}

impl AgentClient {
    /// Create a new Unix socket agent client
    pub async fn unix_socket(
        id: impl Into<String>,
        path: impl AsRef<std::path::Path>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let stream = UnixStream::connect(path.as_ref())
            .await
            .map_err(|e| AgentProtocolError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            id: id.into(),
            connection: AgentConnection::UnixSocket(stream),
            timeout,
            max_retries: 3,
        })
    }

    /// Send an event to the agent and get a response
    pub async fn send_event(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let request = AgentRequest {
            version: PROTOCOL_VERSION,
            event_type,
            payload: serde_json::to_value(payload)
                .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?,
        };

        // Serialize request
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        // Check message size
        if request_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(AgentProtocolError::MessageTooLarge {
                size: request_bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Send with timeout
        let response = tokio::time::timeout(self.timeout, async {
            self.send_raw(&request_bytes).await?;
            self.receive_raw().await
        })
        .await
        .map_err(|_| AgentProtocolError::Timeout(self.timeout))??;

        // Parse response
        let agent_response: AgentResponse = serde_json::from_slice(&response)
            .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;

        // Verify protocol version
        if agent_response.version != PROTOCOL_VERSION {
            return Err(AgentProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: agent_response.version,
            });
        }

        Ok(agent_response)
    }

    /// Send raw bytes to agent
    async fn send_raw(&mut self, data: &[u8]) -> Result<(), AgentProtocolError> {
        match &mut self.connection {
            AgentConnection::UnixSocket(stream) => {
                // Write message length (4 bytes, big-endian)
                let len_bytes = (data.len() as u32).to_be_bytes();
                stream.write_all(&len_bytes).await?;
                // Write message data
                stream.write_all(data).await?;
                stream.flush().await?;
                Ok(())
            }
            AgentConnection::Grpc(_channel) => {
                // TODO: Implement gRPC transport
                unimplemented!("gRPC transport not yet implemented")
            }
        }
    }

    /// Receive raw bytes from agent
    async fn receive_raw(&mut self) -> Result<Vec<u8>, AgentProtocolError> {
        match &mut self.connection {
            AgentConnection::UnixSocket(stream) => {
                // Read message length (4 bytes, big-endian)
                let mut len_bytes = [0u8; 4];
                stream.read_exact(&mut len_bytes).await?;
                let message_len = u32::from_be_bytes(len_bytes) as usize;

                // Check message size
                if message_len > MAX_MESSAGE_SIZE {
                    return Err(AgentProtocolError::MessageTooLarge {
                        size: message_len,
                        max: MAX_MESSAGE_SIZE,
                    });
                }

                // Read message data
                let mut buffer = vec![0u8; message_len];
                stream.read_exact(&mut buffer).await?;
                Ok(buffer)
            }
            AgentConnection::Grpc(_channel) => {
                // TODO: Implement gRPC transport
                unimplemented!("gRPC transport not yet implemented")
            }
        }
    }

    /// Close the agent connection
    pub async fn close(self) -> Result<(), AgentProtocolError> {
        match self.connection {
            AgentConnection::UnixSocket(mut stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            AgentConnection::Grpc(_) => Ok(()),
        }
    }
}

/// Agent server for testing and reference implementations
pub struct AgentServer {
    /// Agent ID
    id: String,
    /// Unix socket path
    socket_path: std::path::PathBuf,
    /// Request handler
    handler: Arc<dyn AgentHandler>,
}

/// Trait for implementing agent logic
#[async_trait]
pub trait AgentHandler: Send + Sync {
    /// Handle a request headers event
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a request body chunk event
    async fn on_request_body_chunk(&self, _event: RequestBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a response headers event
    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a response body chunk event
    async fn on_response_body_chunk(&self, _event: ResponseBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a request complete event
    async fn on_request_complete(&self, _event: RequestCompleteEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }
}

impl AgentResponse {
    /// Create a default allow response
    pub fn default_allow() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            decision: Decision::Allow,
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: AuditMetadata::default(),
        }
    }

    /// Create a block response
    pub fn block(status: u16, body: Option<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            decision: Decision::Block {
                status,
                body,
                headers: None,
            },
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: AuditMetadata::default(),
        }
    }

    /// Create a redirect response
    pub fn redirect(url: String, status: u16) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            decision: Decision::Redirect { url, status },
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: AuditMetadata::default(),
        }
    }

    /// Add a request header modification
    pub fn add_request_header(mut self, op: HeaderOp) -> Self {
        self.request_headers.push(op);
        self
    }

    /// Add a response header modification
    pub fn add_response_header(mut self, op: HeaderOp) -> Self {
        self.response_headers.push(op);
        self
    }

    /// Add audit metadata
    pub fn with_audit(mut self, audit: AuditMetadata) -> Self {
        self.audit = audit;
        self
    }
}

impl AgentServer {
    /// Create a new agent server
    pub fn new(
        id: impl Into<String>,
        socket_path: impl Into<std::path::PathBuf>,
        handler: Box<dyn AgentHandler>,
    ) -> Self {
        Self {
            id: id.into(),
            socket_path: socket_path.into(),
            handler: Arc::from(handler),
        }
    }

    /// Start the agent server
    pub async fn run(&self) -> Result<(), AgentProtocolError> {
        // Remove existing socket file if it exists
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Create Unix socket listener
        let listener = UnixListener::bind(&self.socket_path)?;

        info!(
            "Agent server '{}' listening on {:?}",
            self.id, self.socket_path
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let handler = Arc::clone(&self.handler);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(stream, handler.as_ref()).await {
                            error!("Error handling agent connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }

    /// Handle a single connection
    async fn handle_connection(
        mut stream: UnixStream,
        handler: &dyn AgentHandler,
    ) -> Result<(), AgentProtocolError> {
        loop {
            // Read message length
            let mut len_bytes = [0u8; 4];
            match stream.read_exact(&mut len_bytes).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Client disconnected
                    return Ok(());
                }
                Err(e) => return Err(e.into()),
            }

            let message_len = u32::from_be_bytes(len_bytes) as usize;

            // Check message size
            if message_len > MAX_MESSAGE_SIZE {
                return Err(AgentProtocolError::MessageTooLarge {
                    size: message_len,
                    max: MAX_MESSAGE_SIZE,
                });
            }

            // Read message data
            let mut buffer = vec![0u8; message_len];
            stream.read_exact(&mut buffer).await?;

            // Parse request
            let request: AgentRequest = serde_json::from_slice(&buffer)
                .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;

            // Handle request based on event type
            let response = match request.event_type {
                EventType::RequestHeaders => {
                    let event: RequestHeadersEvent = serde_json::from_value(request.payload)
                        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;
                    handler.on_request_headers(event).await
                }
                EventType::RequestBodyChunk => {
                    let event: RequestBodyChunkEvent = serde_json::from_value(request.payload)
                        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;
                    handler.on_request_body_chunk(event).await
                }
                EventType::ResponseHeaders => {
                    let event: ResponseHeadersEvent = serde_json::from_value(request.payload)
                        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;
                    handler.on_response_headers(event).await
                }
                EventType::ResponseBodyChunk => {
                    let event: ResponseBodyChunkEvent = serde_json::from_value(request.payload)
                        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;
                    handler.on_response_body_chunk(event).await
                }
                EventType::RequestComplete => {
                    let event: RequestCompleteEvent = serde_json::from_value(request.payload)
                        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;
                    handler.on_request_complete(event).await
                }
            };

            // Send response
            let response_bytes = serde_json::to_vec(&response)
                .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

            // Write message length
            let len_bytes = (response_bytes.len() as u32).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            // Write message data
            stream.write_all(&response_bytes).await?;
            stream.flush().await?;
        }
    }
}

/// Reference implementation: Echo agent (for testing)
pub struct EchoAgent;

#[async_trait]
impl AgentHandler for EchoAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        debug!("Echo agent: request headers for {}", event.metadata.correlation_id);

        // Echo back correlation ID as a header
        AgentResponse::default_allow()
            .add_request_header(HeaderOp::Set {
                name: "X-Echo-Agent".to_string(),
                value: event.metadata.correlation_id.clone(),
            })
            .with_audit(AuditMetadata {
                tags: vec!["echo".to_string()],
                ..Default::default()
            })
    }
}

/// Reference implementation: Denylist agent
pub struct DenylistAgent {
    blocked_paths: Vec<String>,
    blocked_ips: Vec<String>,
}

impl DenylistAgent {
    pub fn new(blocked_paths: Vec<String>, blocked_ips: Vec<String>) -> Self {
        Self {
            blocked_paths,
            blocked_ips,
        }
    }
}

#[async_trait]
impl AgentHandler for DenylistAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Check if path is blocked
        for blocked_path in &self.blocked_paths {
            if event.uri.starts_with(blocked_path) {
                return AgentResponse::block(403, Some("Forbidden path".to_string()))
                    .with_audit(AuditMetadata {
                        tags: vec!["denylist".to_string(), "blocked_path".to_string()],
                        reason_codes: vec!["PATH_BLOCKED".to_string()],
                        ..Default::default()
                    });
            }
        }

        // Check if IP is blocked
        if self.blocked_ips.contains(&event.metadata.client_ip) {
            return AgentResponse::block(403, Some("Forbidden IP".to_string()))
                .with_audit(AuditMetadata {
                    tags: vec!["denylist".to_string(), "blocked_ip".to_string()],
                    reason_codes: vec!["IP_BLOCKED".to_string()],
                    ..Default::default()
                });
        }

        AgentResponse::default_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_agent_protocol_echo() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Start echo agent server
        let server = AgentServer::new(
            "test-echo",
            socket_path.clone(),
            Box::new(EchoAgent),
        );

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client = AgentClient::unix_socket(
            "test-client",
            &socket_path,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Send request headers event
        let event = RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some("default".to_string()),
                upstream_id: Some("backend".to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers: HashMap::new(),
        };

        let response = client.send_event(EventType::RequestHeaders, &event)
            .await
            .unwrap();

        // Check response
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.request_headers.len(), 1);

        // Clean up
        client.close().await.unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_agent_protocol_denylist() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("denylist.sock");

        // Start denylist agent server
        let agent = DenylistAgent::new(
            vec!["/admin".to_string()],
            vec!["10.0.0.1".to_string()],
        );
        let server = AgentServer::new(
            "test-denylist",
            socket_path.clone(),
            Box::new(agent),
        );

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client = AgentClient::unix_socket(
            "test-client",
            &socket_path,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        // Test blocked path
        let event = RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some("default".to_string()),
                upstream_id: Some("backend".to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            method: "GET".to_string(),
            uri: "/admin/secret".to_string(),
            headers: HashMap::new(),
        };

        let response = client.send_event(EventType::RequestHeaders, &event)
            .await
            .unwrap();

        // Check response is blocked
        match response.decision {
            Decision::Block { status, .. } => assert_eq!(status, 403),
            _ => panic!("Expected block decision"),
        }

        // Clean up
        client.close().await.unwrap();
        server_handle.abort();
    }
}
