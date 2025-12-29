//! Agent server for implementing external agents.
//!
//! Supports two transport mechanisms:
//! - Unix domain sockets (length-prefixed JSON)
//! - gRPC (Protocol Buffers over HTTP/2)

use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, error, info};

use crate::errors::AgentProtocolError;
use crate::grpc::{self, agent_processor_server::AgentProcessor, agent_processor_server::AgentProcessorServer};
use crate::protocol::{
    AgentRequest, AgentResponse, AuditMetadata, Decision, EventType, HeaderOp, RequestBodyChunkEvent,
    RequestCompleteEvent, RequestHeadersEvent, RequestMetadata, ResponseBodyChunkEvent, ResponseHeadersEvent,
    MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};

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
        debug!(
            "Echo agent: request headers for {}",
            event.metadata.correlation_id
        );

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
                return AgentResponse::block(403, Some("Forbidden path".to_string())).with_audit(
                    AuditMetadata {
                        tags: vec!["denylist".to_string(), "blocked_path".to_string()],
                        reason_codes: vec!["PATH_BLOCKED".to_string()],
                        ..Default::default()
                    },
                );
            }
        }

        // Check if IP is blocked
        if self.blocked_ips.contains(&event.metadata.client_ip) {
            return AgentResponse::block(403, Some("Forbidden IP".to_string())).with_audit(
                AuditMetadata {
                    tags: vec!["denylist".to_string(), "blocked_ip".to_string()],
                    reason_codes: vec!["IP_BLOCKED".to_string()],
                    ..Default::default()
                },
            );
        }

        AgentResponse::default_allow()
    }
}

// ============================================================================
// gRPC Server Implementation
// ============================================================================

/// gRPC agent server for implementing external agents
pub struct GrpcAgentServer {
    /// Agent ID
    id: String,
    /// Request handler
    handler: Arc<dyn AgentHandler>,
}

impl GrpcAgentServer {
    /// Create a new gRPC agent server
    pub fn new(id: impl Into<String>, handler: Box<dyn AgentHandler>) -> Self {
        Self {
            id: id.into(),
            handler: Arc::from(handler),
        }
    }

    /// Get the tonic service for this agent
    pub fn into_service(self) -> AgentProcessorServer<GrpcAgentHandler> {
        AgentProcessorServer::new(GrpcAgentHandler {
            id: self.id,
            handler: self.handler,
        })
    }

    /// Start the gRPC server on the given address
    pub async fn run(self, addr: SocketAddr) -> Result<(), AgentProtocolError> {
        info!("gRPC agent server '{}' listening on {}", self.id, addr);

        tonic::transport::Server::builder()
            .add_service(self.into_service())
            .serve(addr)
            .await
            .map_err(|e| AgentProtocolError::ConnectionFailed(format!("gRPC server error: {}", e)))
    }
}

/// Internal handler that implements the gRPC AgentProcessor trait
pub struct GrpcAgentHandler {
    id: String,
    handler: Arc<dyn AgentHandler>,
}

#[tonic::async_trait]
impl AgentProcessor for GrpcAgentHandler {
    async fn process_event(
        &self,
        request: Request<grpc::AgentRequest>,
    ) -> Result<Response<grpc::AgentResponse>, Status> {
        let grpc_request = request.into_inner();

        // Convert gRPC event to internal event and dispatch
        let response = match grpc_request.event {
            Some(grpc::agent_request::Event::RequestHeaders(e)) => {
                let event = Self::convert_request_headers_from_grpc(e);
                self.handler.on_request_headers(event).await
            }
            Some(grpc::agent_request::Event::RequestBodyChunk(e)) => {
                let event = Self::convert_request_body_chunk_from_grpc(e);
                self.handler.on_request_body_chunk(event).await
            }
            Some(grpc::agent_request::Event::ResponseHeaders(e)) => {
                let event = Self::convert_response_headers_from_grpc(e);
                self.handler.on_response_headers(event).await
            }
            Some(grpc::agent_request::Event::ResponseBodyChunk(e)) => {
                let event = Self::convert_response_body_chunk_from_grpc(e);
                self.handler.on_response_body_chunk(event).await
            }
            Some(grpc::agent_request::Event::RequestComplete(e)) => {
                let event = Self::convert_request_complete_from_grpc(e);
                self.handler.on_request_complete(event).await
            }
            None => {
                return Err(Status::invalid_argument("Missing event in request"));
            }
        };

        // Convert internal response to gRPC response
        let grpc_response = Self::convert_response_to_grpc(response);
        Ok(Response::new(grpc_response))
    }

    async fn process_event_stream(
        &self,
        request: Request<Streaming<grpc::AgentRequest>>,
    ) -> Result<Response<grpc::AgentResponse>, Status> {
        let mut stream = request.into_inner();

        // Process all events in the stream, returning the final response
        let mut final_response = AgentResponse::default_allow();

        while let Some(result) = stream.next().await {
            let grpc_request = result.map_err(|e| Status::internal(format!("Stream error: {}", e)))?;

            let response = match grpc_request.event {
                Some(grpc::agent_request::Event::RequestHeaders(e)) => {
                    let event = Self::convert_request_headers_from_grpc(e);
                    self.handler.on_request_headers(event).await
                }
                Some(grpc::agent_request::Event::RequestBodyChunk(e)) => {
                    let event = Self::convert_request_body_chunk_from_grpc(e);
                    self.handler.on_request_body_chunk(event).await
                }
                Some(grpc::agent_request::Event::ResponseHeaders(e)) => {
                    let event = Self::convert_response_headers_from_grpc(e);
                    self.handler.on_response_headers(event).await
                }
                Some(grpc::agent_request::Event::ResponseBodyChunk(e)) => {
                    let event = Self::convert_response_body_chunk_from_grpc(e);
                    self.handler.on_response_body_chunk(event).await
                }
                Some(grpc::agent_request::Event::RequestComplete(e)) => {
                    let event = Self::convert_request_complete_from_grpc(e);
                    self.handler.on_request_complete(event).await
                }
                None => continue,
            };

            // If any event results in a block/redirect, that becomes the final response
            if !matches!(response.decision, Decision::Allow) {
                final_response = response;
                break;
            }
            final_response = response;
        }

        let grpc_response = Self::convert_response_to_grpc(final_response);
        Ok(Response::new(grpc_response))
    }
}

impl GrpcAgentHandler {
    /// Convert gRPC RequestHeadersEvent to internal format
    fn convert_request_headers_from_grpc(e: grpc::RequestHeadersEvent) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: Self::convert_metadata_from_grpc(e.metadata),
            method: e.method,
            uri: e.uri,
            headers: e.headers.into_iter().map(|(k, v)| (k, v.values)).collect(),
        }
    }

    /// Convert gRPC RequestBodyChunkEvent to internal format
    fn convert_request_body_chunk_from_grpc(e: grpc::RequestBodyChunkEvent) -> RequestBodyChunkEvent {
        RequestBodyChunkEvent {
            correlation_id: e.correlation_id,
            data: String::from_utf8_lossy(&e.data).to_string(),
            is_last: e.is_last,
            total_size: e.total_size.map(|s| s as usize),
        }
    }

    /// Convert gRPC ResponseHeadersEvent to internal format
    fn convert_response_headers_from_grpc(e: grpc::ResponseHeadersEvent) -> ResponseHeadersEvent {
        ResponseHeadersEvent {
            correlation_id: e.correlation_id,
            status: e.status as u16,
            headers: e.headers.into_iter().map(|(k, v)| (k, v.values)).collect(),
        }
    }

    /// Convert gRPC ResponseBodyChunkEvent to internal format
    fn convert_response_body_chunk_from_grpc(e: grpc::ResponseBodyChunkEvent) -> ResponseBodyChunkEvent {
        ResponseBodyChunkEvent {
            correlation_id: e.correlation_id,
            data: String::from_utf8_lossy(&e.data).to_string(),
            is_last: e.is_last,
            total_size: e.total_size.map(|s| s as usize),
        }
    }

    /// Convert gRPC RequestCompleteEvent to internal format
    fn convert_request_complete_from_grpc(e: grpc::RequestCompleteEvent) -> RequestCompleteEvent {
        RequestCompleteEvent {
            correlation_id: e.correlation_id,
            status: e.status as u16,
            duration_ms: e.duration_ms,
            request_body_size: e.request_body_size as usize,
            response_body_size: e.response_body_size as usize,
            upstream_attempts: e.upstream_attempts,
            error: e.error,
        }
    }

    /// Convert gRPC metadata to internal format
    fn convert_metadata_from_grpc(metadata: Option<grpc::RequestMetadata>) -> RequestMetadata {
        match metadata {
            Some(m) => RequestMetadata {
                correlation_id: m.correlation_id,
                request_id: m.request_id,
                client_ip: m.client_ip,
                client_port: m.client_port as u16,
                server_name: m.server_name,
                protocol: m.protocol,
                tls_version: m.tls_version,
                tls_cipher: m.tls_cipher,
                route_id: m.route_id,
                upstream_id: m.upstream_id,
                timestamp: m.timestamp,
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
            },
        }
    }

    /// Convert internal response to gRPC format
    fn convert_response_to_grpc(response: AgentResponse) -> grpc::AgentResponse {
        let decision = match response.decision {
            Decision::Allow => Some(grpc::agent_response::Decision::Allow(grpc::AllowDecision {})),
            Decision::Block { status, body, headers } => {
                Some(grpc::agent_response::Decision::Block(grpc::BlockDecision {
                    status: status as u32,
                    body,
                    headers: headers.unwrap_or_default(),
                }))
            }
            Decision::Redirect { url, status } => {
                Some(grpc::agent_response::Decision::Redirect(grpc::RedirectDecision {
                    url,
                    status: status as u32,
                }))
            }
            Decision::Challenge { challenge_type, params } => {
                Some(grpc::agent_response::Decision::Challenge(grpc::ChallengeDecision {
                    challenge_type,
                    params,
                }))
            }
        };

        let request_headers: Vec<grpc::HeaderOp> = response.request_headers
            .into_iter()
            .map(Self::convert_header_op_to_grpc)
            .collect();

        let response_headers: Vec<grpc::HeaderOp> = response.response_headers
            .into_iter()
            .map(Self::convert_header_op_to_grpc)
            .collect();

        let audit = Some(grpc::AuditMetadata {
            tags: response.audit.tags,
            rule_ids: response.audit.rule_ids,
            confidence: response.audit.confidence,
            reason_codes: response.audit.reason_codes,
            custom: response.audit.custom.into_iter().map(|(k, v)| {
                (k, v.to_string())
            }).collect(),
        });

        grpc::AgentResponse {
            version: PROTOCOL_VERSION,
            decision,
            request_headers,
            response_headers,
            routing_metadata: response.routing_metadata,
            audit,
        }
    }

    /// Convert internal header operation to gRPC format
    fn convert_header_op_to_grpc(op: HeaderOp) -> grpc::HeaderOp {
        let operation = match op {
            HeaderOp::Set { name, value } => {
                Some(grpc::header_op::Operation::Set(grpc::SetHeader { name, value }))
            }
            HeaderOp::Add { name, value } => {
                Some(grpc::header_op::Operation::Add(grpc::AddHeader { name, value }))
            }
            HeaderOp::Remove { name } => {
                Some(grpc::header_op::Operation::Remove(grpc::RemoveHeader { name }))
            }
        };
        grpc::HeaderOp { operation }
    }
}
