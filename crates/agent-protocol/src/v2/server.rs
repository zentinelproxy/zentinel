//! Agent server implementation for Protocol v2.
//!
//! The v2 server supports bidirectional streaming with automatic fallback to v1
//! request/response mode for backward compatibility.

use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info, trace, warn};

use crate::grpc_v2::{
    self, agent_service_v2_server::AgentServiceV2, agent_service_v2_server::AgentServiceV2Server,
    AgentToProxy, ProxyToAgent,
};
use crate::v2::pool::CHANNEL_BUFFER_SIZE;
use crate::v2::{AgentCapabilities, HandshakeRequest, HandshakeResponse, HealthStatus};
use crate::{
    AgentResponse, Decision, EventType, HeaderOp, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, RequestMetadata, ResponseBodyChunkEvent, ResponseHeadersEvent,
    WebSocketFrameEvent,
};

/// Trait for implementing agent handlers in Protocol v2.
///
/// `AgentHandlerV2` defines the interface that agent implementations must provide
/// to handle various types of events from the proxy. This includes request/response
/// processing, WebSocket handling, health monitoring, and configuration management.
///
/// The trait provides sensible defaults for all methods, allowing agents to implement
/// only the events they need to handle. All methods are async to support I/O operations.
///
/// # Features
///
/// - **Capability reporting**: Declare what the agent can process
/// - **Health reporting**: Report current health status to the proxy
/// - **Flow control awareness**: Handle backpressure and flow control
/// - **Metrics export**: Provide metrics about agent performance
/// - **Configuration updates**: Handle dynamic configuration changes
///
/// # Event Lifecycle
///
/// 1. **Handshake**: Agent declares capabilities when connecting
/// 2. **Headers**: Process request/response headers first
/// 3. **Body chunks**: Handle streaming body data if needed
/// 4. **Completion**: Final processing when request/response is complete
/// 5. **WebSocket**: Handle WebSocket frames for upgraded connections
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use zentinel_agent_protocol::v2::{AgentHandlerV2, AgentCapabilities, AgentResponse};
/// use zentinel_agent_protocol::{EventType, RequestHeadersEvent};
///
/// pub struct MyWafAgent;
///
/// #[async_trait]
/// impl AgentHandlerV2 for MyWafAgent {
///     fn capabilities(&self) -> AgentCapabilities {
///         AgentCapabilities::new("my-waf", "My WAF Agent", "1.0.0")
///             .with_event(EventType::RequestHeaders)
///     }
///
///     async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
///         // Inspect headers for malicious patterns
///         if event.headers.contains_key("x-malicious") {
///             AgentResponse::block(403, Some("Blocked by WAF".to_string()))
///         } else {
///             AgentResponse::default_allow()
///         }
///     }
/// }
/// ```
///
/// # Errors
///
/// Agent methods should return `AgentResponse` with appropriate `Decision` variants.
/// Runtime errors should be logged internally rather than propagated, as the proxy
/// needs to maintain high availability.
#[async_trait]
pub trait AgentHandlerV2: Send + Sync {
    /// Get agent capabilities.
    fn capabilities(&self) -> AgentCapabilities;

    /// Handle handshake request.
    async fn on_handshake(&self, _request: HandshakeRequest) -> HandshakeResponse {
        // Default: accept handshake with our capabilities
        HandshakeResponse::success(self.capabilities())
    }

    /// Handle a request headers event.
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a request body chunk event.
    async fn on_request_body_chunk(&self, _event: RequestBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a response headers event.
    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a response body chunk event.
    async fn on_response_body_chunk(&self, _event: ResponseBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a request complete event.
    async fn on_request_complete(&self, _event: RequestCompleteEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    /// Handle a WebSocket frame event.
    async fn on_websocket_frame(&self, _event: WebSocketFrameEvent) -> AgentResponse {
        AgentResponse::websocket_allow()
    }

    /// Get current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy(self.capabilities().agent_id.clone())
    }

    /// Get current metrics report (if metrics export is enabled).
    fn metrics_report(&self) -> Option<crate::v2::MetricsReport> {
        None
    }

    /// Handle a configuration update from the proxy.
    async fn on_configure(&self, _config: serde_json::Value, _version: Option<String>) -> bool {
        // Default: accept configuration
        true
    }

    /// Handle a shutdown request.
    async fn on_shutdown(&self, _reason: ShutdownReason, _grace_period_ms: u64) {
        // Default: no-op, agent should gracefully shut down
    }

    /// Handle a drain request.
    async fn on_drain(&self, _duration_ms: u64, _reason: DrainReason) {
        // Default: no-op, agent should stop accepting new requests
    }

    /// Called when the stream is closed.
    async fn on_stream_closed(&self) {}
}

/// Shutdown reason from proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    Graceful,
    Immediate,
    ConfigReload,
    Upgrade,
}

/// Drain reason from proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainReason {
    ConfigReload,
    Maintenance,
    HealthCheckFailed,
    Manual,
}

/// gRPC-based agent server implementation for Protocol v2.
///
/// `GrpcAgentServerV2` provides a gRPC transport for agents that need to communicate
/// with the Zentinel proxy over the network. This is ideal for agents running in
/// separate processes, containers, or on different machines.
///
/// # Features
///
/// - **Network transport**: Communicates over TCP with HTTP/2 and TLS support
/// - **Language agnostic**: Works with any gRPC client implementation
/// - **Scalability**: Can handle multiple concurrent proxy connections
/// - **Monitoring**: Integrates with gRPC ecosystem tools for observability
///
/// # Example
///
/// ```rust
/// use zentinel_agent_protocol::v2::{GrpcAgentServerV2, AgentHandlerV2};
///
/// // Create server with your handler
/// let handler = Box::new(MyAgent::new());
/// let server = GrpcAgentServerV2::new("my-agent", handler);
///
/// // Serve on a specific address
/// let addr = "127.0.0.1:8080".parse()?;
/// server.run(addr).await?;
/// ```
///
/// # Transport Details
///
/// The gRPC transport uses the standard Agent Protocol v2 service definition:
/// - Bidirectional streaming for event processing
/// - Capability negotiation during handshake
/// - Health check integration
/// - Configuration update support
/// - Metrics collection
pub struct GrpcAgentServerV2 {
    id: String,
    handler: Arc<dyn AgentHandlerV2>,
}

impl GrpcAgentServerV2 {
    /// Create a new v2 gRPC agent server.
    pub fn new(id: impl Into<String>, handler: Box<dyn AgentHandlerV2>) -> Self {
        let id = id.into();
        debug!(agent_id = %id, "Creating gRPC agent server v2");
        Self {
            id,
            handler: Arc::from(handler),
        }
    }

    /// Get the tonic service for this agent.
    pub fn into_service(self) -> AgentServiceV2Server<GrpcAgentHandlerV2> {
        trace!(agent_id = %self.id, "Converting to tonic v2 service");
        AgentServiceV2Server::new(GrpcAgentHandlerV2 {
            id: self.id,
            handler: self.handler,
        })
    }

    /// Start the gRPC server on the given address.
    pub async fn run(self, addr: std::net::SocketAddr) -> Result<(), crate::AgentProtocolError> {
        info!(
            agent_id = %self.id,
            address = %addr,
            "gRPC agent server v2 listening"
        );

        tonic::transport::Server::builder()
            .add_service(self.into_service())
            .serve(addr)
            .await
            .map_err(|e| {
                error!(error = %e, "gRPC v2 server error");
                crate::AgentProtocolError::ConnectionFailed(format!("gRPC v2 server error: {}", e))
            })
    }
}

/// Internal handler that implements the gRPC AgentServiceV2 trait.
pub struct GrpcAgentHandlerV2 {
    id: String,
    handler: Arc<dyn AgentHandlerV2>,
}

type ProcessResponseStream = Pin<Box<dyn Stream<Item = Result<AgentToProxy, Status>> + Send>>;
type ControlResponseStream =
    Pin<Box<dyn Stream<Item = Result<grpc_v2::ProxyControl, Status>> + Send>>;

#[tonic::async_trait]
impl AgentServiceV2 for GrpcAgentHandlerV2 {
    type ProcessStreamStream = ProcessResponseStream;
    type ControlStreamStream = ControlResponseStream;

    /// Handle bidirectional stream for processing events.
    async fn process_stream(
        &self,
        request: Request<Streaming<ProxyToAgent>>,
    ) -> Result<Response<Self::ProcessStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
        let handler = Arc::clone(&self.handler);
        let agent_id = self.id.clone();

        debug!(agent_id = %agent_id, "Starting v2 process stream");

        tokio::spawn(async move {
            let mut handshake_done = false;

            while let Some(result) = inbound.next().await {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        error!(agent_id = %agent_id, error = %e, "Stream error");
                        break;
                    }
                };

                let response = match msg.message {
                    Some(grpc_v2::proxy_to_agent::Message::Handshake(req)) => {
                        trace!(agent_id = %agent_id, "Processing handshake");
                        let handshake_req = convert_handshake_request(req);
                        let resp = handler.on_handshake(handshake_req).await;
                        handshake_done = resp.success;
                        Some(AgentToProxy {
                            message: Some(grpc_v2::agent_to_proxy::Message::Handshake(
                                convert_handshake_response(resp),
                            )),
                        })
                    }
                    Some(grpc_v2::proxy_to_agent::Message::RequestHeaders(e)) => {
                        if !handshake_done {
                            warn!(agent_id = %agent_id, "Received event before handshake");
                            continue;
                        }
                        let event = convert_request_headers_from_grpc(e);
                        let correlation_id = event.metadata.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_request_headers(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::RequestBodyChunk(e)) => {
                        if !handshake_done {
                            continue;
                        }
                        let event = convert_body_chunk_to_request(e);
                        let correlation_id = event.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_request_body_chunk(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::ResponseHeaders(e)) => {
                        if !handshake_done {
                            continue;
                        }
                        let event = convert_response_headers_from_grpc(e);
                        let correlation_id = event.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_response_headers(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::ResponseBodyChunk(e)) => {
                        if !handshake_done {
                            continue;
                        }
                        let event = convert_body_chunk_to_response(e);
                        let correlation_id = event.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_response_body_chunk(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::RequestComplete(e)) => {
                        if !handshake_done {
                            continue;
                        }
                        let event = convert_request_complete_from_grpc(e);
                        let correlation_id = event.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_request_complete(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::WebsocketFrame(e)) => {
                        if !handshake_done {
                            continue;
                        }
                        let event = convert_websocket_frame_from_grpc(e);
                        let correlation_id = event.correlation_id.clone();
                        let start = Instant::now();
                        let resp = handler.on_websocket_frame(event).await;
                        let processing_time_ms = start.elapsed().as_millis() as u64;
                        Some(create_agent_response(
                            correlation_id,
                            resp,
                            processing_time_ms,
                        ))
                    }
                    Some(grpc_v2::proxy_to_agent::Message::Ping(ping)) => {
                        trace!(agent_id = %agent_id, sequence = ping.sequence, "Received ping");
                        Some(AgentToProxy {
                            message: Some(grpc_v2::agent_to_proxy::Message::Pong(grpc_v2::Pong {
                                sequence: ping.sequence,
                                ping_timestamp_ms: ping.timestamp_ms,
                                timestamp_ms: now_ms(),
                            })),
                        })
                    }
                    Some(grpc_v2::proxy_to_agent::Message::Cancel(cancel)) => {
                        debug!(
                            agent_id = %agent_id,
                            correlation_id = %cancel.correlation_id,
                            "Request cancelled"
                        );
                        None
                    }
                    Some(grpc_v2::proxy_to_agent::Message::Configure(_)) => {
                        // Configure is handled separately
                        None
                    }
                    Some(grpc_v2::proxy_to_agent::Message::Guardrail(_)) => {
                        // Guardrail inspection - allow by default
                        None
                    }
                    None => {
                        warn!(agent_id = %agent_id, "Empty message received");
                        None
                    }
                };

                if let Some(resp) = response {
                    if tx.send(Ok(resp)).await.is_err() {
                        debug!(agent_id = %agent_id, "Stream closed by receiver");
                        break;
                    }
                }
            }

            handler.on_stream_closed().await;
            debug!(agent_id = %agent_id, "Process stream ended");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::ProcessStreamStream
        ))
    }

    /// Handle control stream for health/metrics/config.
    ///
    /// The control stream is a bidirectional channel for:
    /// - Agent -> Proxy: Health status, metrics reports, config update requests, logs
    /// - Proxy -> Agent: Configuration updates, shutdown/drain requests
    async fn control_stream(
        &self,
        request: Request<Streaming<grpc_v2::AgentControl>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<grpc_v2::ProxyControl, Status>>(16);
        let handler = Arc::clone(&self.handler);
        let agent_id = self.id.clone();

        debug!(agent_id = %agent_id, "Starting v2 control stream");

        // Spawn task to handle incoming control messages from proxy
        let _handler_clone = Arc::clone(&handler);
        let tx_clone = tx.clone();
        let agent_id_clone = agent_id.clone();
        tokio::spawn(async move {
            while let Some(result) = inbound.next().await {
                let msg = match result {
                    Ok(m) => m,
                    Err(e) => {
                        error!(agent_id = %agent_id_clone, error = %e, "Control stream error");
                        break;
                    }
                };

                // Process incoming proxy control messages
                // Note: AgentControl is what the agent SENDS, but we're receiving from proxy
                // The proto shows ProxyControl for proxy->agent, so this handles agent->proxy
                match msg.message {
                    Some(grpc_v2::agent_control::Message::Health(health)) => {
                        trace!(
                            agent_id = %agent_id_clone,
                            state = health.state,
                            "Received health status from agent"
                        );
                        // This would be forwarded to the proxy's health tracking
                    }
                    Some(grpc_v2::agent_control::Message::Metrics(metrics)) => {
                        trace!(
                            agent_id = %agent_id_clone,
                            counters = metrics.counters.len(),
                            gauges = metrics.gauges.len(),
                            "Received metrics report from agent"
                        );
                        // This would be forwarded to the proxy's metrics collector
                    }
                    Some(grpc_v2::agent_control::Message::ConfigUpdate(update)) => {
                        debug!(
                            agent_id = %agent_id_clone,
                            request_id = %update.request_id,
                            "Received config update request from agent"
                        );
                        // Send acknowledgment
                        let response = grpc_v2::ProxyControl {
                            message: Some(grpc_v2::proxy_control::Message::ConfigResponse(
                                grpc_v2::ConfigUpdateResponse {
                                    request_id: update.request_id,
                                    accepted: true,
                                    error: None,
                                    timestamp_ms: now_ms(),
                                },
                            )),
                        };
                        if tx_clone.send(Ok(response)).await.is_err() {
                            break;
                        }
                    }
                    Some(grpc_v2::agent_control::Message::Log(log)) => {
                        // Forward log message to proxy's logging system
                        match log.level {
                            1 => {
                                trace!(agent_id = %agent_id_clone, msg = %log.message, "Agent log")
                            }
                            2 => {
                                debug!(agent_id = %agent_id_clone, msg = %log.message, "Agent log")
                            }
                            3 => warn!(agent_id = %agent_id_clone, msg = %log.message, "Agent log"),
                            4 => {
                                error!(agent_id = %agent_id_clone, msg = %log.message, "Agent log")
                            }
                            _ => info!(agent_id = %agent_id_clone, msg = %log.message, "Agent log"),
                        }
                    }
                    None => {
                        warn!(agent_id = %agent_id_clone, "Empty control message received");
                    }
                }
            }

            debug!(agent_id = %agent_id_clone, "Control stream inbound handler ended");
        });

        // Spawn task to periodically send health and metrics to proxy
        let capabilities = handler.capabilities();
        let health_interval_ms = capabilities.health.report_interval_ms;
        let metrics_enabled = capabilities.features.metrics_export;

        if health_interval_ms > 0 || metrics_enabled {
            let handler_for_health = Arc::clone(&handler);
            let tx_for_health = tx;
            let agent_id_for_health = agent_id.clone();

            tokio::spawn(async move {
                let health_interval = std::time::Duration::from_millis(health_interval_ms as u64);
                let mut interval = tokio::time::interval(health_interval);

                loop {
                    interval.tick().await;

                    // Collect health status from the handler
                    let health = handler_for_health.health_status();
                    trace!(
                        agent_id = %agent_id_for_health,
                        state = ?health.state,
                        message = ?health.message,
                        "Agent health status collected"
                    );

                    // Send a heartbeat through the control stream (ConfigureEvent
                    // with empty config serves as a keepalive ping to the agent)
                    let heartbeat = grpc_v2::ProxyControl {
                        message: Some(grpc_v2::proxy_control::Message::Configure(
                            grpc_v2::ConfigureEvent {
                                config_json: "{}".to_string(),
                                config_version: None,
                                is_initial: false,
                                timestamp_ms: now_ms(),
                            },
                        )),
                    };

                    if tx_for_health.send(Ok(heartbeat)).await.is_err() {
                        debug!(
                            agent_id = %agent_id_for_health,
                            "Control stream closed, stopping health reporter"
                        );
                        break;
                    }
                }
            });
        }

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::ControlStreamStream
        ))
    }

    /// Handle single event (v1 compatibility mode).
    async fn process_event(
        &self,
        request: Request<ProxyToAgent>,
    ) -> Result<Response<AgentToProxy>, Status> {
        let msg = request.into_inner();

        trace!(agent_id = %self.id, "Processing single event (v1 compat)");

        let response = match msg.message {
            Some(grpc_v2::proxy_to_agent::Message::Handshake(req)) => {
                let handshake_req = convert_handshake_request(req);
                let resp = self.handler.on_handshake(handshake_req).await;
                AgentToProxy {
                    message: Some(grpc_v2::agent_to_proxy::Message::Handshake(
                        convert_handshake_response(resp),
                    )),
                }
            }
            Some(grpc_v2::proxy_to_agent::Message::RequestHeaders(e)) => {
                let event = convert_request_headers_from_grpc(e);
                let correlation_id = event.metadata.correlation_id.clone();
                let start = Instant::now();
                let resp = self.handler.on_request_headers(event).await;
                let processing_time_ms = start.elapsed().as_millis() as u64;
                create_agent_response(correlation_id, resp, processing_time_ms)
            }
            Some(grpc_v2::proxy_to_agent::Message::Ping(ping)) => AgentToProxy {
                message: Some(grpc_v2::agent_to_proxy::Message::Pong(grpc_v2::Pong {
                    sequence: ping.sequence,
                    ping_timestamp_ms: ping.timestamp_ms,
                    timestamp_ms: now_ms(),
                })),
            },
            _ => {
                return Err(Status::invalid_argument("Unsupported event type"));
            }
        };

        Ok(Response::new(response))
    }
}

// =============================================================================
// Conversion Helpers
// =============================================================================

fn convert_handshake_request(req: grpc_v2::HandshakeRequest) -> HandshakeRequest {
    HandshakeRequest {
        supported_versions: req.supported_versions,
        proxy_id: req.proxy_id,
        proxy_version: req.proxy_version,
        config: serde_json::from_str(&req.config_json).unwrap_or(serde_json::Value::Null),
    }
}

fn convert_handshake_response(resp: HandshakeResponse) -> grpc_v2::HandshakeResponse {
    grpc_v2::HandshakeResponse {
        protocol_version: resp.protocol_version,
        capabilities: Some(convert_capabilities_to_grpc(&resp.capabilities)),
        success: resp.success,
        error: resp.error,
    }
}

fn convert_capabilities_to_grpc(caps: &AgentCapabilities) -> grpc_v2::AgentCapabilities {
    grpc_v2::AgentCapabilities {
        protocol_version: caps.protocol_version,
        agent_id: caps.agent_id.clone(),
        name: caps.name.clone(),
        version: caps.version.clone(),
        supported_events: caps
            .supported_events
            .iter()
            .map(|e| event_type_to_i32(*e))
            .collect(),
        features: Some(grpc_v2::AgentFeatures {
            streaming_body: caps.features.streaming_body,
            websocket: caps.features.websocket,
            guardrails: caps.features.guardrails,
            config_push: caps.features.config_push,
            metrics_export: caps.features.metrics_export,
            concurrent_requests: caps.features.concurrent_requests,
            cancellation: caps.features.cancellation,
            flow_control: caps.features.flow_control,
            health_reporting: caps.features.health_reporting,
        }),
        limits: Some(grpc_v2::AgentLimits {
            max_body_size: caps.limits.max_body_size as u64,
            max_concurrency: caps.limits.max_concurrency,
            preferred_chunk_size: caps.limits.preferred_chunk_size as u64,
            max_memory: caps.limits.max_memory.map(|m| m as u64),
            max_processing_time_ms: caps.limits.max_processing_time_ms,
        }),
        health_config: Some(grpc_v2::HealthConfig {
            report_interval_ms: caps.health.report_interval_ms,
            include_load_metrics: caps.health.include_load_metrics,
            include_resource_metrics: caps.health.include_resource_metrics,
        }),
    }
}

pub(crate) fn event_type_to_i32(event_type: EventType) -> i32 {
    match event_type {
        EventType::Configure => 8,
        EventType::RequestHeaders => 1,
        EventType::RequestBodyChunk => 2,
        EventType::ResponseHeaders => 3,
        EventType::ResponseBodyChunk => 4,
        EventType::RequestComplete => 5,
        EventType::WebSocketFrame => 6,
        EventType::GuardrailInspect => 7,
    }
}

fn convert_request_headers_from_grpc(e: grpc_v2::RequestHeadersEvent) -> RequestHeadersEvent {
    let metadata = match e.metadata {
        Some(m) => RequestMetadata {
            correlation_id: m.correlation_id,
            request_id: m.request_id,
            client_ip: m.client_ip,
            client_port: m.client_port as u16,
            server_name: m.server_name,
            protocol: m.protocol,
            tls_version: m.tls_version,
            tls_cipher: None,
            route_id: m.route_id,
            upstream_id: m.upstream_id,
            timestamp: format!("{}", m.timestamp_ms),
            traceparent: m.traceparent,
        },
        None => RequestMetadata {
            correlation_id: String::new(),
            request_id: String::new(),
            client_ip: String::new(),
            client_port: 0,
            server_name: None,
            protocol: String::new(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: String::new(),
            traceparent: None,
        },
    };

    let headers = e
        .headers
        .into_iter()
        .fold(std::collections::HashMap::new(), |mut map, h| {
            map.entry(h.name).or_insert_with(Vec::new).push(h.value);
            map
        });

    RequestHeadersEvent {
        metadata,
        method: e.method,
        uri: e.uri,
        headers,
    }
}

fn convert_body_chunk_to_request(e: grpc_v2::BodyChunkEvent) -> RequestBodyChunkEvent {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    RequestBodyChunkEvent {
        correlation_id: e.correlation_id,
        data: STANDARD.encode(&e.data),
        is_last: e.is_last,
        total_size: e.total_size.map(|s| s as usize),
        chunk_index: e.chunk_index,
        bytes_received: e.bytes_transferred as usize,
    }
}

fn convert_body_chunk_to_response(e: grpc_v2::BodyChunkEvent) -> ResponseBodyChunkEvent {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    ResponseBodyChunkEvent {
        correlation_id: e.correlation_id,
        data: STANDARD.encode(&e.data),
        is_last: e.is_last,
        total_size: e.total_size.map(|s| s as usize),
        chunk_index: e.chunk_index,
        bytes_sent: e.bytes_transferred as usize,
    }
}

fn convert_response_headers_from_grpc(e: grpc_v2::ResponseHeadersEvent) -> ResponseHeadersEvent {
    let headers = e
        .headers
        .into_iter()
        .fold(std::collections::HashMap::new(), |mut map, h| {
            map.entry(h.name).or_insert_with(Vec::new).push(h.value);
            map
        });

    ResponseHeadersEvent {
        correlation_id: e.correlation_id,
        status: e.status_code as u16,
        headers,
    }
}

fn convert_request_complete_from_grpc(e: grpc_v2::RequestCompleteEvent) -> RequestCompleteEvent {
    RequestCompleteEvent {
        correlation_id: e.correlation_id,
        status: e.status_code as u16,
        duration_ms: e.duration_ms,
        request_body_size: e.bytes_received as usize,
        response_body_size: e.bytes_sent as usize,
        upstream_attempts: 1,
        error: e.error,
    }
}

fn convert_websocket_frame_from_grpc(e: grpc_v2::WebSocketFrameEvent) -> WebSocketFrameEvent {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    WebSocketFrameEvent {
        correlation_id: e.correlation_id,
        opcode: format!("{}", e.frame_type),
        data: STANDARD.encode(&e.payload),
        client_to_server: e.client_to_server,
        frame_index: 0,
        fin: true,
        route_id: None,
        client_ip: String::new(),
    }
}

fn create_agent_response(
    correlation_id: String,
    resp: AgentResponse,
    processing_time_ms: u64,
) -> AgentToProxy {
    let decision = match resp.decision {
        Decision::Allow => Some(grpc_v2::agent_response::Decision::Allow(
            grpc_v2::AllowDecision {},
        )),
        Decision::Block {
            status,
            body,
            headers,
        } => Some(grpc_v2::agent_response::Decision::Block(
            grpc_v2::BlockDecision {
                status: status as u32,
                body,
                headers: headers
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| grpc_v2::Header { name: k, value: v })
                    .collect(),
            },
        )),
        Decision::Redirect { url, status } => Some(grpc_v2::agent_response::Decision::Redirect(
            grpc_v2::RedirectDecision {
                url,
                status: status as u32,
            },
        )),
        Decision::Challenge {
            challenge_type,
            params,
        } => Some(grpc_v2::agent_response::Decision::Challenge(
            grpc_v2::ChallengeDecision {
                challenge_type,
                params,
            },
        )),
    };

    let request_headers: Vec<grpc_v2::HeaderOp> = resp
        .request_headers
        .into_iter()
        .map(convert_header_op_to_grpc)
        .collect();

    let response_headers: Vec<grpc_v2::HeaderOp> = resp
        .response_headers
        .into_iter()
        .map(convert_header_op_to_grpc)
        .collect();

    let audit = Some(grpc_v2::AuditMetadata {
        tags: resp.audit.tags,
        rule_ids: resp.audit.rule_ids,
        confidence: resp.audit.confidence,
        reason_codes: resp.audit.reason_codes,
        custom: resp
            .audit
            .custom
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect(),
    });

    AgentToProxy {
        message: Some(grpc_v2::agent_to_proxy::Message::Response(
            grpc_v2::AgentResponse {
                correlation_id,
                decision,
                request_headers,
                response_headers,
                audit,
                processing_time_ms: Some(processing_time_ms),
                needs_more: resp.needs_more,
            },
        )),
    }
}

fn convert_header_op_to_grpc(op: HeaderOp) -> grpc_v2::HeaderOp {
    let operation = match op {
        HeaderOp::Set { name, value } => {
            Some(grpc_v2::header_op::Operation::Set(grpc_v2::Header {
                name,
                value,
            }))
        }
        HeaderOp::Add { name, value } => {
            Some(grpc_v2::header_op::Operation::Add(grpc_v2::Header {
                name,
                value,
            }))
        }
        HeaderOp::Remove { name } => Some(grpc_v2::header_op::Operation::Remove(name)),
    };
    grpc_v2::HeaderOp { operation }
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

    struct TestHandlerV2;

    #[async_trait]
    impl AgentHandlerV2 for TestHandlerV2 {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::new("test-v2", "Test Agent V2", "1.0.0")
        }
    }

    #[test]
    fn test_create_server() {
        let server = GrpcAgentServerV2::new("test", Box::new(TestHandlerV2));
        assert_eq!(server.id, "test");
    }
}
