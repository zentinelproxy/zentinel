//! Reverse connection support for Agent Protocol v2.
//!
//! This module allows agents to connect to the proxy instead of the proxy
//! connecting to agents. This is useful for:
//!
//! - Agents behind NAT or firewalls
//! - Dynamic agent scaling (agents register on startup)
//! - Simpler agent deployment (no need to expose agent ports)
//!
//! # Protocol
//!
//! 1. Proxy starts a listener (UDS or TCP)
//! 2. Agent connects and sends a `RegistrationRequest`
//! 3. Proxy validates and responds with `RegistrationResponse`
//! 4. On success, the connection is added to the AgentPool
//! 5. The connection is used bidirectionally like a normal connection
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_protocol::v2::{AgentPool, ReverseConnectionListener};
//!
//! let pool = AgentPool::new();
//! let listener = ReverseConnectionListener::bind_uds("/var/run/zentinel/agents.sock").await?;
//!
//! // Accept connections in background
//! listener.accept_loop(pool).await;
//! ```

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::v2::client::FlowState;
use crate::v2::pool::CHANNEL_BUFFER_SIZE;
use crate::v2::uds::{read_message, write_message, MessageType, UdsCapabilities};
use crate::v2::{AgentCapabilities, AgentPool, PROTOCOL_VERSION_2};
use crate::{AgentProtocolError, AgentResponse};

/// Configuration for the reverse connection listener.
#[derive(Debug, Clone)]
pub struct ReverseConnectionConfig {
    /// Maximum number of pending connections in the accept queue
    pub backlog: u32,
    /// Timeout for the registration handshake
    pub handshake_timeout: Duration,
    /// Maximum number of connections per agent
    pub max_connections_per_agent: usize,
    /// Allowed agent IDs (empty = allow all)
    pub allowed_agents: HashSet<String>,
    /// Whether to require agent authentication
    pub require_auth: bool,
    /// Request timeout for accepted connections
    pub request_timeout: Duration,
}

impl Default for ReverseConnectionConfig {
    fn default() -> Self {
        Self {
            backlog: 128,
            handshake_timeout: Duration::from_secs(10),
            max_connections_per_agent: 4,
            allowed_agents: HashSet::new(),
            require_auth: false,
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Registration request sent by agent when connecting to proxy.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistrationRequest {
    /// Protocol version the agent supports
    pub protocol_version: u32,
    /// Agent's unique identifier
    pub agent_id: String,
    /// Agent capabilities
    pub capabilities: UdsCapabilities,
    /// Optional authentication token
    pub auth_token: Option<String>,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Registration response sent by proxy to agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegistrationResponse {
    /// Whether registration was successful
    pub success: bool,
    /// Error message if registration failed
    pub error: Option<String>,
    /// Proxy identifier
    pub proxy_id: String,
    /// Proxy version
    pub proxy_version: String,
    /// Assigned connection ID (for debugging)
    pub connection_id: String,
}

/// Listener for reverse agent connections over Unix Domain Socket.
pub struct ReverseConnectionListener {
    listener: UnixListener,
    config: ReverseConnectionConfig,
    socket_path: String,
}

impl ReverseConnectionListener {
    /// Bind to a Unix Domain Socket path.
    pub async fn bind_uds(
        path: impl AsRef<Path>,
        config: ReverseConnectionConfig,
    ) -> Result<Self, AgentProtocolError> {
        let path = path.as_ref();
        let socket_path = path.to_string_lossy().to_string();

        // Remove existing socket file if present
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!(
                    "Failed to remove existing socket {}: {}",
                    socket_path, e
                ))
            })?;
        }

        let listener = UnixListener::bind(path).map_err(|e| {
            AgentProtocolError::ConnectionFailed(format!(
                "Failed to bind to {}: {}",
                socket_path, e
            ))
        })?;

        info!(path = %socket_path, "Reverse connection listener bound");

        Ok(Self {
            listener,
            config,
            socket_path,
        })
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Accept a single connection and register it with the pool.
    ///
    /// Returns the agent_id of the registered agent on success.
    pub async fn accept_one(&self, pool: &AgentPool) -> Result<String, AgentProtocolError> {
        let (stream, _addr) =
            self.listener.accept().await.map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!("Accept failed: {}", e))
            })?;

        debug!("Accepted reverse connection");

        self.handle_connection(stream, pool).await
    }

    /// Run the accept loop, registering connections with the pool.
    ///
    /// This method runs forever, accepting connections and spawning tasks
    /// to handle them.
    pub async fn accept_loop(self: Arc<Self>, pool: Arc<AgentPool>) {
        info!(path = %self.socket_path, "Starting reverse connection accept loop");

        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let listener = Arc::clone(&self);
                    let pool = Arc::clone(&pool);

                    tokio::spawn(async move {
                        match listener.handle_connection(stream, &pool).await {
                            Ok(agent_id) => {
                                info!(agent_id = %agent_id, "Reverse connection registered");
                            }
                            Err(e) => {
                                warn!(error = %e, "Failed to handle reverse connection");
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "Accept failed");
                    // Brief delay before retrying
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Handle an accepted connection.
    async fn handle_connection(
        &self,
        stream: UnixStream,
        pool: &AgentPool,
    ) -> Result<String, AgentProtocolError> {
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        // Read registration request with timeout
        let registration = tokio::time::timeout(
            self.config.handshake_timeout,
            self.read_registration(&mut reader),
        )
        .await
        .map_err(|_| AgentProtocolError::Timeout(self.config.handshake_timeout))??;

        let agent_id = registration.agent_id.clone();

        // Validate registration
        if let Err(e) = self.validate_registration(&registration) {
            let response = RegistrationResponse {
                success: false,
                error: Some(e.to_string()),
                proxy_id: "zentinel-proxy".to_string(),
                proxy_version: env!("CARGO_PKG_VERSION").to_string(),
                connection_id: String::new(),
            };
            self.send_registration_response(&mut writer, &response)
                .await?;
            return Err(e);
        }

        // Generate connection ID
        let connection_id = format!(
            "{}-{:x}",
            agent_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0)
        );

        // Send success response
        let response = RegistrationResponse {
            success: true,
            error: None,
            proxy_id: "zentinel-proxy".to_string(),
            proxy_version: env!("CARGO_PKG_VERSION").to_string(),
            connection_id: connection_id.clone(),
        };
        self.send_registration_response(&mut writer, &response)
            .await?;

        info!(
            agent_id = %agent_id,
            connection_id = %connection_id,
            "Agent registration successful"
        );

        // Convert capabilities
        let capabilities: AgentCapabilities = registration.capabilities.into();

        // Create the reverse connection client wrapper
        let client = ReverseConnectionClient::new(
            agent_id.clone(),
            connection_id,
            capabilities.clone(),
            reader,
            writer,
            self.config.request_timeout,
        )
        .await;

        // Add to pool
        pool.add_reverse_connection(&agent_id, client, capabilities)
            .await?;

        Ok(agent_id)
    }

    /// Read registration request from stream.
    async fn read_registration<R: AsyncReadExt + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<RegistrationRequest, AgentProtocolError> {
        let (msg_type, payload) = read_message(reader).await?;

        if msg_type != MessageType::HandshakeRequest {
            return Err(AgentProtocolError::InvalidMessage(format!(
                "Expected registration request (HandshakeRequest), got {:?}",
                msg_type
            )));
        }

        serde_json::from_slice(&payload)
            .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))
    }

    /// Send registration response.
    async fn send_registration_response<W: AsyncWriteExt + Unpin>(
        &self,
        writer: &mut W,
        response: &RegistrationResponse,
    ) -> Result<(), AgentProtocolError> {
        let payload = serde_json::to_vec(response)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        write_message(writer, MessageType::HandshakeResponse, &payload).await
    }

    /// Validate a registration request.
    fn validate_registration(
        &self,
        registration: &RegistrationRequest,
    ) -> Result<(), AgentProtocolError> {
        // Check protocol version
        if registration.protocol_version != PROTOCOL_VERSION_2 {
            return Err(AgentProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION_2,
                actual: registration.protocol_version,
            });
        }

        // Check agent ID is not empty
        if registration.agent_id.is_empty() {
            return Err(AgentProtocolError::InvalidMessage(
                "Agent ID cannot be empty".to_string(),
            ));
        }

        // Check if agent is in allowed list (if configured)
        if !self.config.allowed_agents.is_empty()
            && !self.config.allowed_agents.contains(&registration.agent_id)
        {
            return Err(AgentProtocolError::InvalidMessage(format!(
                "Agent '{}' is not in the allowed list",
                registration.agent_id
            )));
        }

        // Check authentication if required
        if self.config.require_auth && registration.auth_token.is_none() {
            return Err(AgentProtocolError::InvalidMessage(
                "Authentication required but no token provided".to_string(),
            ));
        }

        Ok(())
    }
}

impl Drop for ReverseConnectionListener {
    fn drop(&mut self) {
        // Clean up socket file
        if let Err(e) = std::fs::remove_file(&self.socket_path) {
            debug!(path = %self.socket_path, error = %e, "Failed to remove socket file on drop");
        }
    }
}

/// Client wrapper for a reverse connection.
///
/// This wraps an accepted connection and provides the same interface
/// as AgentClientV2Uds but for inbound connections.
pub struct ReverseConnectionClient {
    agent_id: String,
    connection_id: String,
    capabilities: RwLock<Option<AgentCapabilities>>,
    pending: Arc<Mutex<std::collections::HashMap<String, oneshot::Sender<AgentResponse>>>>,
    #[allow(clippy::type_complexity)]
    outbound_tx: Mutex<Option<mpsc::Sender<(MessageType, Vec<u8>)>>>,
    connected: RwLock<bool>,
    timeout: Duration,
    in_flight: std::sync::atomic::AtomicU64,
    /// Flow control state - tracks if agent has requested pause
    flow_state: Arc<RwLock<FlowState>>,
}

impl ReverseConnectionClient {
    /// Create a new reverse connection client from an accepted stream.
    async fn new<R, W>(
        agent_id: String,
        connection_id: String,
        capabilities: AgentCapabilities,
        mut reader: BufReader<R>,
        mut writer: BufWriter<W>,
        timeout: Duration,
    ) -> Self
    where
        R: AsyncReadExt + Unpin + Send + 'static,
        W: AsyncWriteExt + Unpin + Send + 'static,
    {
        let pending: Arc<Mutex<std::collections::HashMap<String, oneshot::Sender<AgentResponse>>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));

        // Create message channel
        let (tx, mut rx) = mpsc::channel::<(MessageType, Vec<u8>)>(CHANNEL_BUFFER_SIZE);

        // Spawn writer task
        let agent_id_clone = agent_id.clone();
        tokio::spawn(async move {
            while let Some((msg_type, payload)) = rx.recv().await {
                if let Err(e) = write_message(&mut writer, msg_type, &payload).await {
                    error!(
                        agent_id = %agent_id_clone,
                        error = %e,
                        "Failed to write to reverse connection"
                    );
                    break;
                }
            }
            debug!(agent_id = %agent_id_clone, "Reverse connection writer ended");
        });

        // Spawn reader task
        let pending_clone = Arc::clone(&pending);
        let agent_id_clone = agent_id.clone();
        tokio::spawn(async move {
            loop {
                match read_message(&mut reader).await {
                    Ok((msg_type, payload)) => {
                        if msg_type == MessageType::AgentResponse {
                            if let Ok(response) = serde_json::from_slice::<AgentResponse>(&payload)
                            {
                                let correlation_id = response
                                    .audit
                                    .custom
                                    .get("correlation_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();

                                if let Some(sender) =
                                    pending_clone.lock().await.remove(&correlation_id)
                                {
                                    let _ = sender.send(response);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if !matches!(e, AgentProtocolError::ConnectionClosed) {
                            error!(
                                agent_id = %agent_id_clone,
                                error = %e,
                                "Error reading from reverse connection"
                            );
                        }
                        break;
                    }
                }
            }
            debug!(agent_id = %agent_id_clone, "Reverse connection reader ended");
        });

        Self {
            agent_id,
            connection_id,
            capabilities: RwLock::new(Some(capabilities)),
            pending,
            outbound_tx: Mutex::new(Some(tx)),
            connected: RwLock::new(true),
            timeout,
            in_flight: std::sync::atomic::AtomicU64::new(0),
            flow_state: Arc::new(RwLock::new(FlowState::Normal)),
        }
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    /// Get the connection ID.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Check if connected.
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Get capabilities.
    pub async fn capabilities(&self) -> Option<AgentCapabilities> {
        self.capabilities.read().await.clone()
    }

    /// Check if the agent has requested flow control pause.
    ///
    /// Returns true if the agent sent a `FlowAction::Pause` signal,
    /// indicating it cannot accept more requests.
    pub async fn is_paused(&self) -> bool {
        matches!(*self.flow_state.read().await, FlowState::Paused)
    }

    /// Check if the transport can accept new requests.
    ///
    /// Returns false if the agent has requested a flow control pause.
    pub async fn can_accept_requests(&self) -> bool {
        !self.is_paused().await
    }

    /// Send a request headers event.
    pub async fn send_request_headers(
        &self,
        correlation_id: &str,
        event: &crate::RequestHeadersEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        self.send_event(MessageType::RequestHeaders, correlation_id, event)
            .await
    }

    /// Send a request body chunk event.
    pub async fn send_request_body_chunk(
        &self,
        correlation_id: &str,
        event: &crate::RequestBodyChunkEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        self.send_event(MessageType::RequestBodyChunk, correlation_id, event)
            .await
    }

    /// Send a response headers event.
    pub async fn send_response_headers(
        &self,
        correlation_id: &str,
        event: &crate::ResponseHeadersEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        self.send_event(MessageType::ResponseHeaders, correlation_id, event)
            .await
    }

    /// Send a response body chunk event.
    pub async fn send_response_body_chunk(
        &self,
        correlation_id: &str,
        event: &crate::ResponseBodyChunkEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        self.send_event(MessageType::ResponseBodyChunk, correlation_id, event)
            .await
    }

    /// Send an event and wait for response.
    async fn send_event<T: serde::Serialize>(
        &self,
        msg_type: MessageType,
        correlation_id: &str,
        event: &T,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(correlation_id.to_string(), tx);

        // Serialize event with correlation ID
        let mut payload = serde_json::to_value(event)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "correlation_id".to_string(),
                serde_json::Value::String(correlation_id.to_string()),
            );
        }

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        // Send message
        {
            let outbound = self.outbound_tx.lock().await;
            if let Some(tx) = outbound.as_ref() {
                tx.send((msg_type, payload_bytes))
                    .await
                    .map_err(|_| AgentProtocolError::ConnectionClosed)?;
            } else {
                return Err(AgentProtocolError::ConnectionClosed);
            }
        }

        self.in_flight
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Wait for response with timeout
        let response = tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| {
                self.pending
                    .try_lock()
                    .ok()
                    .map(|mut p| p.remove(correlation_id));
                AgentProtocolError::Timeout(self.timeout)
            })?
            .map_err(|_| AgentProtocolError::ConnectionClosed)?;

        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        Ok(response)
    }

    /// Cancel a specific request.
    pub async fn cancel_request(
        &self,
        correlation_id: &str,
        reason: super::client::CancelReason,
    ) -> Result<(), AgentProtocolError> {
        let cancel = serde_json::json!({
            "correlation_id": correlation_id,
            "reason": reason as i32,
            "timestamp_ms": now_ms(),
        });

        let payload = serde_json::to_vec(&cancel)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        let outbound = self.outbound_tx.lock().await;
        if let Some(tx) = outbound.as_ref() {
            tx.send((MessageType::Cancel, payload))
                .await
                .map_err(|_| AgentProtocolError::ConnectionClosed)?;
        }

        self.pending.lock().await.remove(correlation_id);
        Ok(())
    }

    /// Cancel all in-flight requests.
    pub async fn cancel_all(
        &self,
        reason: super::client::CancelReason,
    ) -> Result<usize, AgentProtocolError> {
        let pending_ids: Vec<String> = self.pending.lock().await.keys().cloned().collect();
        let count = pending_ids.len();

        for correlation_id in pending_ids {
            let _ = self.cancel_request(&correlation_id, reason).await;
        }

        Ok(count)
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), AgentProtocolError> {
        *self.connected.write().await = false;
        *self.outbound_tx.lock().await = None;
        Ok(())
    }

    /// Get in-flight request count.
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = ReverseConnectionConfig::default();
        assert_eq!(config.backlog, 128);
        assert_eq!(config.max_connections_per_agent, 4);
        assert!(!config.require_auth);
    }

    #[test]
    fn test_registration_request_serialization() {
        let request = RegistrationRequest {
            protocol_version: 2,
            agent_id: "test-agent".to_string(),
            capabilities: UdsCapabilities {
                agent_id: "test-agent".to_string(),
                name: "Test Agent".to_string(),
                version: "1.0.0".to_string(),
                supported_events: vec![1, 2],
                features: Default::default(),
                limits: Default::default(),
            },
            auth_token: None,
            metadata: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: RegistrationRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.agent_id, "test-agent");
        assert_eq!(parsed.protocol_version, 2);
    }

    #[test]
    fn test_registration_response_serialization() {
        let response = RegistrationResponse {
            success: true,
            error: None,
            proxy_id: "zentinel".to_string(),
            proxy_version: "1.0.0".to_string(),
            connection_id: "conn-123".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: RegistrationResponse = serde_json::from_str(&json).unwrap();

        assert!(parsed.success);
        assert_eq!(parsed.connection_id, "conn-123");
    }
}
