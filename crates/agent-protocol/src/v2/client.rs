//! Agent client implementation for Protocol v2.
//!
//! The v2 client supports bidirectional streaming with connection multiplexing,
//! allowing multiple concurrent requests over a single connection.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tonic::transport::Channel;
use tracing::{debug, info, trace, warn};

use crate::grpc_v2::{self, agent_service_v2_client::AgentServiceV2Client, ProxyToAgent};
use crate::headers::iter_flat;
use crate::v2::pool::CHANNEL_BUFFER_SIZE;
use crate::v2::{AgentCapabilities, PROTOCOL_VERSION_2};
use crate::{AgentProtocolError, AgentResponse, Decision, EventType, HeaderOp};

/// Cancellation reason for in-flight requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    /// Client disconnected
    ClientDisconnect,
    /// Request timed out
    Timeout,
    /// Blocked by another agent
    BlockedByAgent,
    /// Upstream connection failed
    UpstreamError,
    /// Proxy is shutting down
    ProxyShutdown,
    /// Manual cancellation
    Manual,
}

impl CancelReason {
    fn to_grpc(self) -> i32 {
        match self {
            CancelReason::ClientDisconnect => 1,
            CancelReason::Timeout => 2,
            CancelReason::BlockedByAgent => 3,
            CancelReason::UpstreamError => 4,
            CancelReason::ProxyShutdown => 5,
            CancelReason::Manual => 6,
        }
    }
}

/// Flow control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowState {
    /// Normal operation
    #[default]
    Normal,
    /// Agent requested pause
    Paused,
    /// Draining (finishing in-flight, no new requests)
    Draining,
}

/// Callback for metrics reports from agents.
pub type MetricsCallback = Arc<dyn Fn(crate::v2::MetricsReport) + Send + Sync>;

/// Callback for config update requests from agents.
///
/// The callback receives the agent ID and the config update request.
/// It should return a response indicating whether the update was accepted.
pub type ConfigUpdateCallback = Arc<
    dyn Fn(String, crate::v2::ConfigUpdateRequest) -> crate::v2::ConfigUpdateResponse + Send + Sync,
>;

/// v2 agent client with connection multiplexing.
///
/// This client maintains a single bidirectional stream and multiplexes
/// multiple requests over it using correlation IDs.
///
/// # Features
///
/// - **Connection multiplexing**: Multiple concurrent requests over one connection
/// - **Cancellation support**: Cancel in-flight requests
/// - **Flow control**: Backpressure handling when agent is overloaded
/// - **Health tracking**: Monitor agent health status
/// - **Metrics collection**: Receive and forward agent metrics
pub struct AgentClientV2 {
    /// Agent identifier
    agent_id: String,
    /// gRPC channel (for reconnection)
    channel: Channel,
    /// Request timeout
    timeout: Duration,
    /// Negotiated capabilities
    capabilities: RwLock<Option<AgentCapabilities>>,
    /// Negotiated protocol version
    protocol_version: AtomicU64,
    /// Pending requests by correlation ID
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<AgentResponse>>>>,
    /// Sender for outbound messages
    outbound_tx: Mutex<Option<mpsc::Sender<ProxyToAgent>>>,
    /// Sequence counter for pings
    ping_sequence: AtomicU64,
    /// Connection state
    connected: RwLock<bool>,
    /// Flow control state
    flow_state: RwLock<FlowState>,
    /// Last known health state
    health_state: RwLock<i32>,
    /// In-flight request count
    in_flight: AtomicU64,
    /// Callback for metrics reports
    metrics_callback: Option<MetricsCallback>,
    /// Callback for config update requests
    config_update_callback: Option<ConfigUpdateCallback>,
}

impl AgentClientV2 {
    /// Create a new v2 client.
    pub async fn new(
        agent_id: impl Into<String>,
        endpoint: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let agent_id = agent_id.into();
        let endpoint = endpoint.into();

        debug!(agent_id = %agent_id, endpoint = %endpoint, "Creating v2 client");

        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Invalid endpoint: {}", e)))?
            .connect_timeout(timeout)
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!("Failed to connect: {}", e))
            })?;

        Ok(Self {
            agent_id,
            channel,
            timeout,
            capabilities: RwLock::new(None),
            protocol_version: AtomicU64::new(1), // Default to v1 until handshake
            pending: Arc::new(Mutex::new(HashMap::new())),
            outbound_tx: Mutex::new(None),
            ping_sequence: AtomicU64::new(0),
            connected: RwLock::new(false),
            flow_state: RwLock::new(FlowState::Normal),
            health_state: RwLock::new(1), // HEALTHY
            in_flight: AtomicU64::new(0),
            metrics_callback: None,
            config_update_callback: None,
        })
    }

    /// Set the metrics callback for receiving agent metrics reports.
    ///
    /// This callback is invoked whenever the agent sends a metrics report
    /// through the control stream. The callback should be fast and non-blocking.
    pub fn set_metrics_callback(&mut self, callback: MetricsCallback) {
        self.metrics_callback = Some(callback);
    }

    /// Set the config update callback for handling agent config requests.
    ///
    /// This callback is invoked whenever the agent sends a config update request
    /// through the control stream (e.g., requesting a reload, reporting errors).
    pub fn set_config_update_callback(&mut self, callback: ConfigUpdateCallback) {
        self.config_update_callback = Some(callback);
    }

    /// Connect and perform handshake.
    pub async fn connect(&self) -> Result<(), AgentProtocolError> {
        let mut client = AgentServiceV2Client::new(self.channel.clone());

        // Create bidirectional stream
        let (tx, rx) = mpsc::channel::<ProxyToAgent>(CHANNEL_BUFFER_SIZE);
        let rx_stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        let response_stream = client
            .process_stream(rx_stream)
            .await
            .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Stream failed: {}", e)))?;

        let mut inbound = response_stream.into_inner();

        // Send handshake
        let handshake = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::Handshake(
                grpc_v2::HandshakeRequest {
                    supported_versions: vec![PROTOCOL_VERSION_2, 1],
                    proxy_id: "zentinel-proxy".to_string(),
                    proxy_version: env!("CARGO_PKG_VERSION").to_string(),
                    config_json: "{}".to_string(),
                },
            )),
        };

        tx.send(handshake).await.map_err(|e| {
            AgentProtocolError::ConnectionFailed(format!("Failed to send handshake: {}", e))
        })?;

        // Wait for handshake response
        let handshake_resp = tokio::time::timeout(self.timeout, inbound.message())
            .await
            .map_err(|_| AgentProtocolError::Timeout(self.timeout))?
            .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Stream error: {}", e)))?
            .ok_or_else(|| {
                AgentProtocolError::ConnectionFailed("Empty handshake response".to_string())
            })?;

        // Process handshake response
        if let Some(grpc_v2::agent_to_proxy::Message::Handshake(resp)) = handshake_resp.message {
            if !resp.success {
                return Err(AgentProtocolError::ConnectionFailed(format!(
                    "Handshake failed: {}",
                    resp.error.unwrap_or_default()
                )));
            }

            self.protocol_version
                .store(resp.protocol_version as u64, Ordering::SeqCst);

            if let Some(caps) = resp.capabilities {
                let capabilities = convert_capabilities_from_grpc(caps);
                *self.capabilities.write().await = Some(capabilities);
            }

            info!(
                agent_id = %self.agent_id,
                protocol_version = resp.protocol_version,
                "v2 handshake successful"
            );
        } else {
            return Err(AgentProtocolError::ConnectionFailed(
                "Invalid handshake response".to_string(),
            ));
        }

        // Store outbound sender
        *self.outbound_tx.lock().await = Some(tx);
        *self.connected.write().await = true;

        // Spawn background task to handle incoming messages
        let pending = Arc::clone(&self.pending);
        let agent_id = self.agent_id.clone();
        let flow_state = Arc::new(RwLock::new(FlowState::Normal));
        let health_state = Arc::new(RwLock::new(1i32));
        let _in_flight = Arc::new(AtomicU64::new(0));

        // Share state with the spawned task
        let flow_state_clone = Arc::clone(&flow_state);
        let health_state_clone = Arc::clone(&health_state);
        let metrics_callback = self.metrics_callback.clone();
        let config_update_callback = self.config_update_callback.clone();

        tokio::spawn(async move {
            while let Ok(Some(msg)) = inbound.message().await {
                match msg.message {
                    Some(grpc_v2::agent_to_proxy::Message::Response(resp)) => {
                        let correlation_id = resp.correlation_id.clone();
                        if let Some(sender) = pending.lock().await.remove(&correlation_id) {
                            let response = convert_response_from_grpc(resp);
                            let _ = sender.send(response);
                        } else {
                            warn!(
                                agent_id = %agent_id,
                                correlation_id = %correlation_id,
                                "Received response for unknown correlation ID"
                            );
                        }
                    }
                    Some(grpc_v2::agent_to_proxy::Message::Health(health)) => {
                        trace!(
                            agent_id = %agent_id,
                            state = health.state,
                            "Received health status"
                        );
                        *health_state_clone.write().await = health.state;
                    }
                    Some(grpc_v2::agent_to_proxy::Message::Metrics(metrics)) => {
                        trace!(
                            agent_id = %agent_id,
                            counters = metrics.counters.len(),
                            gauges = metrics.gauges.len(),
                            histograms = metrics.histograms.len(),
                            "Received metrics report"
                        );
                        if let Some(ref callback) = metrics_callback {
                            let report = convert_metrics_from_grpc(metrics, &agent_id);
                            callback(report);
                        }
                    }
                    Some(grpc_v2::agent_to_proxy::Message::FlowControl(fc)) => {
                        // Handle flow control signals
                        let new_state = match fc.action {
                            1 => FlowState::Paused, // PAUSE
                            2 => FlowState::Normal, // RESUME
                            _ => FlowState::Normal,
                        };
                        debug!(
                            agent_id = %agent_id,
                            action = fc.action,
                            correlation_id = ?fc.correlation_id,
                            "Received flow control signal"
                        );
                        *flow_state_clone.write().await = new_state;
                    }
                    Some(grpc_v2::agent_to_proxy::Message::Pong(pong)) => {
                        trace!(
                            agent_id = %agent_id,
                            sequence = pong.sequence,
                            latency_ms = pong.timestamp_ms.saturating_sub(pong.ping_timestamp_ms),
                            "Received pong"
                        );
                    }
                    Some(grpc_v2::agent_to_proxy::Message::ConfigUpdate(update)) => {
                        debug!(
                            agent_id = %agent_id,
                            request_id = %update.request_id,
                            "Received config update request from agent"
                        );
                        if let Some(ref callback) = config_update_callback {
                            let request = convert_config_update_from_grpc(update);
                            let _response = callback(agent_id.clone(), request);
                            // Note: Response would be sent via control stream if we had one
                            // For now, the callback handles the request and logs/processes it
                        }
                    }
                    Some(grpc_v2::agent_to_proxy::Message::Log(log_msg)) => {
                        // Handle log messages from agent
                        match log_msg.level {
                            1 => {
                                trace!(agent_id = %agent_id, msg = %log_msg.message, "Agent debug log")
                            }
                            2 => {
                                debug!(agent_id = %agent_id, msg = %log_msg.message, "Agent info log")
                            }
                            3 => {
                                warn!(agent_id = %agent_id, msg = %log_msg.message, "Agent warning")
                            }
                            4 => warn!(agent_id = %agent_id, msg = %log_msg.message, "Agent error"),
                            _ => trace!(agent_id = %agent_id, msg = %log_msg.message, "Agent log"),
                        }
                    }
                    _ => {}
                }
            }

            debug!(agent_id = %agent_id, "Response handler ended");
        });

        Ok(())
    }

    /// Send a request headers event and wait for response.
    pub async fn send_request_headers(
        &self,
        correlation_id: &str,
        event: &crate::RequestHeadersEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::RequestHeaders(
                convert_request_headers_to_grpc(event),
            )),
        };

        self.send_and_wait(correlation_id, msg).await
    }

    /// Send a request body chunk event and wait for response.
    ///
    /// For streaming body inspection, chunks are sent sequentially with
    /// increasing `chunk_index`. The agent responds after processing each chunk.
    pub async fn send_request_body_chunk(
        &self,
        correlation_id: &str,
        event: &crate::RequestBodyChunkEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::RequestBodyChunk(
                convert_body_chunk_to_grpc(event),
            )),
        };

        self.send_and_wait(correlation_id, msg).await
    }

    /// Send a response headers event and wait for response.
    ///
    /// Called when upstream response headers are received, allowing the agent
    /// to inspect/modify response headers before they're sent to the client.
    pub async fn send_response_headers(
        &self,
        correlation_id: &str,
        event: &crate::ResponseHeadersEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::ResponseHeaders(
                convert_response_headers_to_grpc(event),
            )),
        };

        self.send_and_wait(correlation_id, msg).await
    }

    /// Send a response body chunk event and wait for response.
    ///
    /// For streaming response body inspection, chunks are sent sequentially.
    /// The agent can inspect and optionally modify response body data.
    pub async fn send_response_body_chunk(
        &self,
        correlation_id: &str,
        event: &crate::ResponseBodyChunkEvent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::ResponseBodyChunk(
                convert_response_body_chunk_to_grpc(event),
            )),
        };

        self.send_and_wait(correlation_id, msg).await
    }

    /// Send any event type and wait for response.
    pub async fn send_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> Result<AgentResponse, AgentProtocolError> {
        // For compatibility, extract correlation_id from event
        let correlation_id = extract_correlation_id(event);

        let msg = match event_type {
            EventType::RequestHeaders => {
                if let Ok(e) = serde_json::from_value::<crate::RequestHeadersEvent>(
                    serde_json::to_value(event).unwrap_or_default(),
                ) {
                    ProxyToAgent {
                        message: Some(grpc_v2::proxy_to_agent::Message::RequestHeaders(
                            convert_request_headers_to_grpc(&e),
                        )),
                    }
                } else {
                    return Err(AgentProtocolError::InvalidMessage(
                        "Failed to convert event".to_string(),
                    ));
                }
            }
            _ => {
                // Fall back to v1 for unsupported event types
                return Err(AgentProtocolError::InvalidMessage(format!(
                    "Event type {:?} not yet supported in v2 streaming mode",
                    event_type
                )));
            }
        };

        self.send_and_wait(&correlation_id, msg).await
    }

    /// Send a message and wait for response.
    async fn send_and_wait(
        &self,
        correlation_id: &str,
        msg: ProxyToAgent,
    ) -> Result<AgentResponse, AgentProtocolError> {
        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending request
        self.pending
            .lock()
            .await
            .insert(correlation_id.to_string(), tx);

        // Send message
        {
            let outbound = self.outbound_tx.lock().await;
            if let Some(sender) = outbound.as_ref() {
                sender.send(msg).await.map_err(|e| {
                    AgentProtocolError::ConnectionFailed(format!("Send failed: {}", e))
                })?;
            } else {
                return Err(AgentProtocolError::ConnectionFailed(
                    "Not connected".to_string(),
                ));
            }
        }

        // Wait for response with timeout
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.pending.lock().await.remove(correlation_id);
                Err(AgentProtocolError::ConnectionFailed(
                    "Response channel closed".to_string(),
                ))
            }
            Err(_) => {
                self.pending.lock().await.remove(correlation_id);
                Err(AgentProtocolError::Timeout(self.timeout))
            }
        }
    }

    /// Send a ping and measure latency.
    pub async fn ping(&self) -> Result<Duration, AgentProtocolError> {
        let sequence = self.ping_sequence.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = now_ms();

        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::Ping(grpc_v2::Ping {
                sequence,
                timestamp_ms,
            })),
        };

        let outbound = self.outbound_tx.lock().await;
        if let Some(sender) = outbound.as_ref() {
            sender
                .send(msg)
                .await
                .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Ping failed: {}", e)))?;
        }

        // Note: In a full implementation, we'd track pong responses
        // For now, just return a placeholder
        Ok(Duration::from_millis(0))
    }

    /// Get negotiated protocol version.
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version.load(Ordering::SeqCst) as u32
    }

    /// Get agent capabilities.
    pub async fn capabilities(&self) -> Option<AgentCapabilities> {
        self.capabilities.read().await.clone()
    }

    /// Check if client is connected.
    pub async fn is_connected(&self) -> bool {
        *self.connected.read().await
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<(), AgentProtocolError> {
        *self.outbound_tx.lock().await = None;
        *self.connected.write().await = false;
        Ok(())
    }

    /// Cancel an in-flight request.
    ///
    /// Sends a cancellation message to the agent and removes the request from
    /// the pending map. The agent should stop processing and clean up resources.
    pub async fn cancel_request(
        &self,
        correlation_id: &str,
        reason: CancelReason,
    ) -> Result<(), AgentProtocolError> {
        // Remove from pending (will cause the waiter to receive an error)
        self.pending.lock().await.remove(correlation_id);

        // Send cancel message to agent
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::Cancel(
                grpc_v2::CancelRequest {
                    correlation_id: correlation_id.to_string(),
                    reason: reason.to_grpc(),
                    timestamp_ms: now_ms(),
                    blocking_agent_id: None,
                    manual_reason: None,
                },
            )),
        };

        let outbound = self.outbound_tx.lock().await;
        if let Some(sender) = outbound.as_ref() {
            sender.send(msg).await.map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!("Cancel send failed: {}", e))
            })?;
        }

        debug!(
            agent_id = %self.agent_id,
            correlation_id = %correlation_id,
            reason = ?reason,
            "Cancelled request"
        );

        Ok(())
    }

    /// Cancel all in-flight requests.
    ///
    /// Used during shutdown or when the upstream connection fails.
    pub async fn cancel_all(&self, reason: CancelReason) -> Result<usize, AgentProtocolError> {
        let correlation_ids: Vec<String> = {
            let pending = self.pending.lock().await;
            pending.keys().cloned().collect()
        };

        let count = correlation_ids.len();
        for cid in correlation_ids {
            let _ = self.cancel_request(&cid, reason).await;
        }

        debug!(
            agent_id = %self.agent_id,
            count = count,
            reason = ?reason,
            "Cancelled all requests"
        );

        Ok(count)
    }

    /// Get current flow control state.
    pub async fn flow_state(&self) -> FlowState {
        *self.flow_state.read().await
    }

    /// Check if the agent is accepting new requests.
    ///
    /// Returns false if the agent has requested a pause or is draining.
    pub async fn can_accept_requests(&self) -> bool {
        matches!(*self.flow_state.read().await, FlowState::Normal)
    }

    /// Wait for flow control to allow new requests.
    ///
    /// If the agent has requested a pause, this will wait until it resumes
    /// or the timeout expires.
    pub async fn wait_for_flow_control(&self, timeout: Duration) -> Result<(), AgentProtocolError> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            if self.can_accept_requests().await {
                return Ok(());
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(AgentProtocolError::Timeout(timeout));
            }

            // Poll every 10ms
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Get current health state.
    ///
    /// Returns the numeric health state:
    /// - 1: Healthy
    /// - 2: Degraded
    /// - 3: Draining
    /// - 4: Unhealthy
    pub async fn health_state(&self) -> i32 {
        *self.health_state.read().await
    }

    /// Check if the agent is healthy.
    pub async fn is_healthy(&self) -> bool {
        *self.health_state.read().await == 1
    }

    /// Get the number of in-flight requests.
    pub fn in_flight_count(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }

    // =========================================================================
    // Control Stream Methods
    // =========================================================================

    /// Send a configuration update to the agent.
    pub async fn send_configure(
        &self,
        config: serde_json::Value,
        version: Option<String>,
    ) -> Result<(), AgentProtocolError> {
        let msg = ProxyToAgent {
            message: Some(grpc_v2::proxy_to_agent::Message::Configure(
                grpc_v2::ConfigureEvent {
                    config_json: serde_json::to_string(&config).unwrap_or_default(),
                    config_version: version,
                    is_initial: false,
                    timestamp_ms: now_ms(),
                },
            )),
        };

        let outbound = self.outbound_tx.lock().await;
        if let Some(sender) = outbound.as_ref() {
            sender.send(msg).await.map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!("Configure send failed: {}", e))
            })?;
        } else {
            return Err(AgentProtocolError::ConnectionFailed(
                "Not connected".to_string(),
            ));
        }

        debug!(agent_id = %self.agent_id, "Sent configuration update");
        Ok(())
    }

    /// Request the agent to shut down.
    pub async fn send_shutdown(
        &self,
        reason: ShutdownReason,
        grace_period_ms: u64,
    ) -> Result<(), AgentProtocolError> {
        info!(
            agent_id = %self.agent_id,
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Requesting agent shutdown"
        );

        // For shutdown, we should cancel all pending requests first
        let _ = self.cancel_all(CancelReason::ProxyShutdown).await;

        // Close the connection
        self.close().await
    }

    /// Request the agent to drain (stop accepting new requests).
    pub async fn send_drain(
        &self,
        duration_ms: u64,
        reason: DrainReason,
    ) -> Result<(), AgentProtocolError> {
        info!(
            agent_id = %self.agent_id,
            duration_ms = duration_ms,
            reason = ?reason,
            "Requesting agent drain"
        );

        // Set flow state to draining
        *self.flow_state.write().await = FlowState::Draining;

        Ok(())
    }

    /// Get agent identifier.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

/// Shutdown reason for agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Graceful,
    Immediate,
    ConfigReload,
    Upgrade,
}

/// Drain reason for agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainReason {
    ConfigReload,
    Maintenance,
    HealthCheckFailed,
    Manual,
}

// =============================================================================
// Conversion Helpers
// =============================================================================

fn convert_capabilities_from_grpc(caps: grpc_v2::AgentCapabilities) -> AgentCapabilities {
    use crate::v2::{AgentFeatures, AgentLimits, HealthConfig};

    let features = caps
        .features
        .map(|f| AgentFeatures {
            streaming_body: f.streaming_body,
            websocket: f.websocket,
            guardrails: f.guardrails,
            config_push: f.config_push,
            metrics_export: f.metrics_export,
            concurrent_requests: f.concurrent_requests,
            cancellation: f.cancellation,
            flow_control: f.flow_control,
            health_reporting: f.health_reporting,
        })
        .unwrap_or_default();

    let limits = caps
        .limits
        .map(|l| AgentLimits {
            max_body_size: l.max_body_size as usize,
            max_concurrency: l.max_concurrency,
            preferred_chunk_size: l.preferred_chunk_size as usize,
            max_memory: l.max_memory.map(|m| m as usize),
            max_processing_time_ms: l.max_processing_time_ms,
        })
        .unwrap_or_default();

    let health = caps
        .health_config
        .map(|h| HealthConfig {
            report_interval_ms: h.report_interval_ms,
            include_load_metrics: h.include_load_metrics,
            include_resource_metrics: h.include_resource_metrics,
        })
        .unwrap_or_default();

    AgentCapabilities {
        protocol_version: caps.protocol_version,
        agent_id: caps.agent_id,
        name: caps.name,
        version: caps.version,
        supported_events: caps
            .supported_events
            .into_iter()
            .filter_map(i32_to_event_type)
            .collect(),
        features,
        limits,
        health,
    }
}

fn i32_to_event_type(i: i32) -> Option<EventType> {
    match i {
        1 => Some(EventType::RequestHeaders),
        2 => Some(EventType::RequestBodyChunk),
        3 => Some(EventType::ResponseHeaders),
        4 => Some(EventType::ResponseBodyChunk),
        5 => Some(EventType::RequestComplete),
        6 => Some(EventType::WebSocketFrame),
        7 => Some(EventType::GuardrailInspect),
        8 => Some(EventType::Configure),
        _ => None,
    }
}

fn convert_request_headers_to_grpc(
    event: &crate::RequestHeadersEvent,
) -> grpc_v2::RequestHeadersEvent {
    let metadata = Some(grpc_v2::RequestMetadata {
        correlation_id: event.metadata.correlation_id.clone(),
        request_id: event.metadata.request_id.clone(),
        client_ip: event.metadata.client_ip.clone(),
        client_port: event.metadata.client_port as u32,
        server_name: event.metadata.server_name.clone(),
        protocol: event.metadata.protocol.clone(),
        tls_version: event.metadata.tls_version.clone(),
        route_id: event.metadata.route_id.clone(),
        upstream_id: event.metadata.upstream_id.clone(),
        timestamp_ms: now_ms(),
        traceparent: event.metadata.traceparent.clone(),
    });

    // Use iter_flat helper for cleaner iteration over flattened headers
    let headers: Vec<grpc_v2::Header> = iter_flat(&event.headers)
        .map(|(name, value)| grpc_v2::Header {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect();

    grpc_v2::RequestHeadersEvent {
        metadata,
        method: event.method.clone(),
        uri: event.uri.clone(),
        http_version: "HTTP/1.1".to_string(),
        headers,
    }
}

fn convert_body_chunk_to_grpc(event: &crate::RequestBodyChunkEvent) -> grpc_v2::BodyChunkEvent {
    // Convert through binary type to centralize the base64 decode logic
    let binary: crate::BinaryRequestBodyChunkEvent = event.into();
    convert_binary_body_chunk_to_grpc(&binary)
}

/// Convert binary body chunk directly to gRPC (no base64 decode needed).
///
/// This is the efficient path for binary transports (UDS binary mode, direct Bytes).
fn convert_binary_body_chunk_to_grpc(
    event: &crate::BinaryRequestBodyChunkEvent,
) -> grpc_v2::BodyChunkEvent {
    grpc_v2::BodyChunkEvent {
        correlation_id: event.correlation_id.clone(),
        chunk_index: event.chunk_index,
        data: event.data.to_vec(), // Bytes → Vec<u8> (single copy, no decode)
        is_last: event.is_last,
        total_size: event.total_size.map(|s| s as u64),
        bytes_transferred: event.bytes_received as u64,
        proxy_buffer_available: 0, // Will be set by flow control
        timestamp_ms: now_ms(),
    }
}

fn convert_response_headers_to_grpc(
    event: &crate::ResponseHeadersEvent,
) -> grpc_v2::ResponseHeadersEvent {
    // Use iter_flat helper for cleaner iteration over flattened headers
    let headers: Vec<grpc_v2::Header> = iter_flat(&event.headers)
        .map(|(name, value)| grpc_v2::Header {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect();

    grpc_v2::ResponseHeadersEvent {
        correlation_id: event.correlation_id.clone(),
        status_code: event.status as u32,
        headers,
    }
}

fn convert_response_body_chunk_to_grpc(
    event: &crate::ResponseBodyChunkEvent,
) -> grpc_v2::BodyChunkEvent {
    // Convert through binary type to centralize the base64 decode logic
    let binary: crate::BinaryResponseBodyChunkEvent = event.into();
    convert_binary_response_body_chunk_to_grpc(&binary)
}

/// Convert binary response body chunk directly to gRPC (no base64 decode needed).
///
/// This is the efficient path for binary transports (UDS binary mode, direct Bytes).
fn convert_binary_response_body_chunk_to_grpc(
    event: &crate::BinaryResponseBodyChunkEvent,
) -> grpc_v2::BodyChunkEvent {
    grpc_v2::BodyChunkEvent {
        correlation_id: event.correlation_id.clone(),
        chunk_index: event.chunk_index,
        data: event.data.to_vec(), // Bytes → Vec<u8> (single copy, no decode)
        is_last: event.is_last,
        total_size: event.total_size.map(|s| s as u64),
        bytes_transferred: event.bytes_sent as u64,
        proxy_buffer_available: 0,
        timestamp_ms: now_ms(),
    }
}

fn convert_response_from_grpc(resp: grpc_v2::AgentResponse) -> AgentResponse {
    let decision = match resp.decision {
        Some(grpc_v2::agent_response::Decision::Allow(_)) => Decision::Allow,
        Some(grpc_v2::agent_response::Decision::Block(b)) => Decision::Block {
            status: b.status as u16,
            body: b.body,
            headers: if b.headers.is_empty() {
                None
            } else {
                Some(b.headers.into_iter().map(|h| (h.name, h.value)).collect())
            },
        },
        Some(grpc_v2::agent_response::Decision::Redirect(r)) => Decision::Redirect {
            url: r.url,
            status: r.status as u16,
        },
        Some(grpc_v2::agent_response::Decision::Challenge(c)) => Decision::Challenge {
            challenge_type: c.challenge_type,
            params: c.params,
        },
        None => Decision::Allow,
    };

    let request_headers: Vec<HeaderOp> = resp
        .request_headers
        .into_iter()
        .filter_map(convert_header_op_from_grpc)
        .collect();

    let response_headers: Vec<HeaderOp> = resp
        .response_headers
        .into_iter()
        .filter_map(convert_header_op_from_grpc)
        .collect();

    let audit = resp
        .audit
        .map(|a| crate::AuditMetadata {
            tags: a.tags,
            rule_ids: a.rule_ids,
            confidence: a.confidence,
            reason_codes: a.reason_codes,
            custom: a
                .custom
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        })
        .unwrap_or_default();

    AgentResponse {
        version: PROTOCOL_VERSION_2,
        decision,
        request_headers,
        response_headers,
        routing_metadata: HashMap::new(),
        audit,
        needs_more: resp.needs_more,
        request_body_mutation: None,
        response_body_mutation: None,
        websocket_decision: None,
    }
}

fn convert_header_op_from_grpc(op: grpc_v2::HeaderOp) -> Option<HeaderOp> {
    match op.operation {
        Some(grpc_v2::header_op::Operation::Set(h)) => Some(HeaderOp::Set {
            name: h.name,
            value: h.value,
        }),
        Some(grpc_v2::header_op::Operation::Add(h)) => Some(HeaderOp::Add {
            name: h.name,
            value: h.value,
        }),
        Some(grpc_v2::header_op::Operation::Remove(name)) => Some(HeaderOp::Remove { name }),
        None => None,
    }
}

fn convert_metrics_from_grpc(
    report: grpc_v2::MetricsReport,
    agent_id: &str,
) -> crate::v2::MetricsReport {
    use crate::v2::metrics::{CounterMetric, GaugeMetric, HistogramBucket, HistogramMetric};

    let counters = report
        .counters
        .into_iter()
        .map(|c| CounterMetric {
            name: c.name,
            help: c.help.filter(|s| !s.is_empty()),
            labels: c.labels,
            value: c.value,
        })
        .collect();

    let gauges = report
        .gauges
        .into_iter()
        .map(|g| GaugeMetric {
            name: g.name,
            help: g.help.filter(|s| !s.is_empty()),
            labels: g.labels,
            value: g.value,
        })
        .collect();

    let histograms = report
        .histograms
        .into_iter()
        .map(|h| HistogramMetric {
            name: h.name,
            help: h.help.filter(|s| !s.is_empty()),
            labels: h.labels,
            sum: h.sum,
            count: h.count,
            buckets: h
                .buckets
                .into_iter()
                .map(|b| HistogramBucket {
                    le: b.le,
                    count: b.count,
                })
                .collect(),
        })
        .collect();

    crate::v2::MetricsReport {
        agent_id: agent_id.to_string(),
        timestamp_ms: report.timestamp_ms,
        interval_ms: report.interval_ms,
        counters,
        gauges,
        histograms,
    }
}

fn convert_config_update_from_grpc(
    update: grpc_v2::ConfigUpdateRequest,
) -> crate::v2::ConfigUpdateRequest {
    use crate::v2::control::{ConfigUpdateType, RuleDefinition};

    let update_type = match update.update_type {
        Some(grpc_v2::config_update_request::UpdateType::RequestReload(_)) => {
            ConfigUpdateType::RequestReload
        }
        Some(grpc_v2::config_update_request::UpdateType::RuleUpdate(ru)) => {
            ConfigUpdateType::RuleUpdate {
                rule_set: ru.rule_set,
                rules: ru
                    .rules
                    .into_iter()
                    .map(|r| RuleDefinition {
                        id: r.id,
                        priority: r.priority,
                        definition: serde_json::from_str(&r.definition_json).unwrap_or_default(),
                        enabled: r.enabled,
                        description: r.description,
                        tags: r.tags,
                    })
                    .collect(),
                remove_rules: ru.remove_rules,
            }
        }
        Some(grpc_v2::config_update_request::UpdateType::ListUpdate(lu)) => {
            ConfigUpdateType::ListUpdate {
                list_id: lu.list_id,
                add: lu.add,
                remove: lu.remove,
            }
        }
        Some(grpc_v2::config_update_request::UpdateType::RestartRequired(rr)) => {
            ConfigUpdateType::RestartRequired {
                reason: rr.reason,
                grace_period_ms: rr.grace_period_ms,
            }
        }
        Some(grpc_v2::config_update_request::UpdateType::ConfigError(ce)) => {
            ConfigUpdateType::ConfigError {
                error: ce.error,
                field: ce.field,
            }
        }
        None => ConfigUpdateType::RequestReload, // Default
    };

    crate::v2::ConfigUpdateRequest {
        update_type,
        request_id: update.request_id,
        timestamp_ms: update.timestamp_ms,
    }
}

fn extract_correlation_id<T: serde::Serialize>(event: &T) -> String {
    // Try to extract correlation_id from the serialized event
    if let Ok(value) = serde_json::to_value(event) {
        if let Some(metadata) = value.get("metadata") {
            if let Some(cid) = metadata.get("correlation_id").and_then(|v| v.as_str()) {
                return cid.to_string();
            }
        }
        if let Some(cid) = value.get("correlation_id").and_then(|v| v.as_str()) {
            return cid.to_string();
        }
    }
    uuid::Uuid::new_v4().to_string()
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
    fn test_event_type_conversion() {
        assert_eq!(i32_to_event_type(1), Some(EventType::RequestHeaders));
        assert_eq!(i32_to_event_type(2), Some(EventType::RequestBodyChunk));
        assert_eq!(i32_to_event_type(99), None);
    }

    #[test]
    fn test_extract_correlation_id() {
        #[derive(serde::Serialize)]
        struct TestEvent {
            correlation_id: String,
        }

        let event = TestEvent {
            correlation_id: "test-123".to_string(),
        };

        assert_eq!(extract_correlation_id(&event), "test-123");
    }
}
