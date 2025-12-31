//! Agent client for communicating with external agents.
//!
//! Supports two transport mechanisms:
//! - Unix domain sockets (length-prefixed JSON)
//! - gRPC (Protocol Buffers over HTTP/2)

use serde::Serialize;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tonic::transport::Channel;
use tracing::{debug, error, trace};

use crate::errors::AgentProtocolError;
use crate::grpc::{self, agent_processor_client::AgentProcessorClient};
use crate::protocol::{
    AgentRequest, AgentResponse, AuditMetadata, BodyMutation, Decision, EventType, HeaderOp,
    RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent, RequestMetadata,
    ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketDecision, WebSocketFrameEvent,
    MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};

/// Agent client for communicating with external agents
pub struct AgentClient {
    /// Agent ID
    id: String,
    /// Connection to agent
    connection: AgentConnection,
    /// Timeout for agent calls
    timeout: Duration,
    /// Maximum retries
    #[allow(dead_code)]
    max_retries: u32,
}

/// Agent connection type
enum AgentConnection {
    UnixSocket(UnixStream),
    Grpc(AgentProcessorClient<Channel>),
}

impl AgentClient {
    /// Create a new Unix socket agent client
    pub async fn unix_socket(
        id: impl Into<String>,
        path: impl AsRef<std::path::Path>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let path = path.as_ref();

        trace!(
            agent_id = %id,
            socket_path = %path.display(),
            timeout_ms = timeout.as_millis() as u64,
            "Connecting to agent via Unix socket"
        );

        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    socket_path = %path.display(),
                    error = %e,
                    "Failed to connect to agent via Unix socket"
                );
                AgentProtocolError::ConnectionFailed(e.to_string())
            })?;

        debug!(
            agent_id = %id,
            socket_path = %path.display(),
            "Connected to agent via Unix socket"
        );

        Ok(Self {
            id,
            connection: AgentConnection::UnixSocket(stream),
            timeout,
            max_retries: 3,
        })
    }

    /// Create a new gRPC agent client
    ///
    /// # Arguments
    /// * `id` - Agent identifier
    /// * `address` - gRPC server address (e.g., "http://localhost:50051")
    /// * `timeout` - Timeout for agent calls
    pub async fn grpc(
        id: impl Into<String>,
        address: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let address = address.into();

        trace!(
            agent_id = %id,
            address = %address,
            timeout_ms = timeout.as_millis() as u64,
            "Connecting to agent via gRPC"
        );

        let channel = Channel::from_shared(address.clone())
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    address = %address,
                    error = %e,
                    "Invalid gRPC URI"
                );
                AgentProtocolError::ConnectionFailed(format!("Invalid URI: {}", e))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    address = %address,
                    error = %e,
                    "Failed to connect to agent via gRPC"
                );
                AgentProtocolError::ConnectionFailed(format!("gRPC connect failed: {}", e))
            })?;

        let client = AgentProcessorClient::new(channel);

        debug!(
            agent_id = %id,
            address = %address,
            "Connected to agent via gRPC"
        );

        Ok(Self {
            id,
            connection: AgentConnection::Grpc(client),
            timeout,
            max_retries: 3,
        })
    }

    /// Get the agent ID
    #[allow(dead_code)]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Send an event to the agent and get a response
    pub async fn send_event(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        match &mut self.connection {
            AgentConnection::UnixSocket(_) => {
                self.send_event_unix_socket(event_type, payload).await
            }
            AgentConnection::Grpc(_) => {
                self.send_event_grpc(event_type, payload).await
            }
        }
    }

    /// Send event via Unix socket (length-prefixed JSON)
    async fn send_event_unix_socket(
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
            self.send_raw_unix(&request_bytes).await?;
            self.receive_raw_unix().await
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

    /// Send event via gRPC
    async fn send_event_grpc(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        // Build request first (doesn't need mutable borrow)
        let grpc_request = Self::build_grpc_request(event_type, payload)?;

        let AgentConnection::Grpc(client) = &mut self.connection else {
            unreachable!()
        };

        // Send with timeout
        let response = tokio::time::timeout(self.timeout, client.process_event(grpc_request))
            .await
            .map_err(|_| AgentProtocolError::Timeout(self.timeout))?
            .map_err(|e| AgentProtocolError::ConnectionFailed(format!("gRPC call failed: {}", e)))?;

        // Convert gRPC response to internal format
        Self::convert_grpc_response(response.into_inner())
    }

    /// Build a gRPC request from internal types
    fn build_grpc_request(
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<grpc::AgentRequest, AgentProtocolError> {
        let payload_json = serde_json::to_value(&payload)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        let grpc_event_type = match event_type {
            EventType::RequestHeaders => grpc::EventType::RequestHeaders,
            EventType::RequestBodyChunk => grpc::EventType::RequestBodyChunk,
            EventType::ResponseHeaders => grpc::EventType::ResponseHeaders,
            EventType::ResponseBodyChunk => grpc::EventType::ResponseBodyChunk,
            EventType::RequestComplete => grpc::EventType::RequestComplete,
            EventType::WebSocketFrame => grpc::EventType::WebsocketFrame,
        };

        let event = match event_type {
            EventType::RequestHeaders => {
                let event: RequestHeadersEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestHeaders(grpc::RequestHeadersEvent {
                    metadata: Some(Self::convert_metadata_to_grpc(&event.metadata)),
                    method: event.method,
                    uri: event.uri,
                    headers: event.headers.into_iter().map(|(k, v)| {
                        (k, grpc::HeaderValues { values: v })
                    }).collect(),
                })
            }
            EventType::RequestBodyChunk => {
                let event: RequestBodyChunkEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestBodyChunk(grpc::RequestBodyChunkEvent {
                    correlation_id: event.correlation_id,
                    data: event.data.into_bytes(),
                    is_last: event.is_last,
                    total_size: event.total_size.map(|s| s as u64),
                    chunk_index: event.chunk_index,
                    bytes_received: event.bytes_received as u64,
                })
            }
            EventType::ResponseHeaders => {
                let event: ResponseHeadersEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::ResponseHeaders(grpc::ResponseHeadersEvent {
                    correlation_id: event.correlation_id,
                    status: event.status as u32,
                    headers: event.headers.into_iter().map(|(k, v)| {
                        (k, grpc::HeaderValues { values: v })
                    }).collect(),
                })
            }
            EventType::ResponseBodyChunk => {
                let event: ResponseBodyChunkEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::ResponseBodyChunk(grpc::ResponseBodyChunkEvent {
                    correlation_id: event.correlation_id,
                    data: event.data.into_bytes(),
                    is_last: event.is_last,
                    total_size: event.total_size.map(|s| s as u64),
                    chunk_index: event.chunk_index,
                    bytes_sent: event.bytes_sent as u64,
                })
            }
            EventType::RequestComplete => {
                let event: RequestCompleteEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestComplete(grpc::RequestCompleteEvent {
                    correlation_id: event.correlation_id,
                    status: event.status as u32,
                    duration_ms: event.duration_ms,
                    request_body_size: event.request_body_size as u64,
                    response_body_size: event.response_body_size as u64,
                    upstream_attempts: event.upstream_attempts,
                    error: event.error,
                })
            }
            EventType::WebSocketFrame => {
                use base64::{Engine as _, engine::general_purpose::STANDARD};
                let event: WebSocketFrameEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::WebsocketFrame(grpc::WebSocketFrameEvent {
                    correlation_id: event.correlation_id,
                    opcode: event.opcode,
                    data: STANDARD.decode(&event.data).unwrap_or_default(),
                    client_to_server: event.client_to_server,
                    frame_index: event.frame_index,
                    fin: event.fin,
                    route_id: event.route_id,
                    client_ip: event.client_ip,
                })
            }
        };

        Ok(grpc::AgentRequest {
            version: PROTOCOL_VERSION,
            event_type: grpc_event_type as i32,
            event: Some(event),
        })
    }

    /// Convert internal metadata to gRPC format
    fn convert_metadata_to_grpc(metadata: &RequestMetadata) -> grpc::RequestMetadata {
        grpc::RequestMetadata {
            correlation_id: metadata.correlation_id.clone(),
            request_id: metadata.request_id.clone(),
            client_ip: metadata.client_ip.clone(),
            client_port: metadata.client_port as u32,
            server_name: metadata.server_name.clone(),
            protocol: metadata.protocol.clone(),
            tls_version: metadata.tls_version.clone(),
            tls_cipher: metadata.tls_cipher.clone(),
            route_id: metadata.route_id.clone(),
            upstream_id: metadata.upstream_id.clone(),
            timestamp: metadata.timestamp.clone(),
        }
    }

    /// Convert gRPC response to internal format
    fn convert_grpc_response(
        response: grpc::AgentResponse,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let decision = match response.decision {
            Some(grpc::agent_response::Decision::Allow(_)) => Decision::Allow,
            Some(grpc::agent_response::Decision::Block(b)) => Decision::Block {
                status: b.status as u16,
                body: b.body,
                headers: if b.headers.is_empty() { None } else { Some(b.headers) },
            },
            Some(grpc::agent_response::Decision::Redirect(r)) => Decision::Redirect {
                url: r.url,
                status: r.status as u16,
            },
            Some(grpc::agent_response::Decision::Challenge(c)) => Decision::Challenge {
                challenge_type: c.challenge_type,
                params: c.params,
            },
            None => Decision::Allow, // Default to allow if no decision
        };

        let request_headers: Vec<HeaderOp> = response.request_headers
            .into_iter()
            .filter_map(Self::convert_header_op_from_grpc)
            .collect();

        let response_headers: Vec<HeaderOp> = response.response_headers
            .into_iter()
            .filter_map(Self::convert_header_op_from_grpc)
            .collect();

        let audit = response.audit.map(|a| AuditMetadata {
            tags: a.tags,
            rule_ids: a.rule_ids,
            confidence: a.confidence,
            reason_codes: a.reason_codes,
            custom: a.custom.into_iter().map(|(k, v)| {
                (k, serde_json::Value::String(v))
            }).collect(),
        });

        // Convert body mutations
        let request_body_mutation = response.request_body_mutation.map(|m| BodyMutation {
            data: m.data.map(|d| String::from_utf8_lossy(&d).to_string()),
            chunk_index: m.chunk_index,
        });

        let response_body_mutation = response.response_body_mutation.map(|m| BodyMutation {
            data: m.data.map(|d| String::from_utf8_lossy(&d).to_string()),
            chunk_index: m.chunk_index,
        });

        // Convert WebSocket decision
        let websocket_decision = response.websocket_decision.map(|ws_decision| {
            match ws_decision {
                grpc::agent_response::WebsocketDecision::WebsocketAllow(_) => WebSocketDecision::Allow,
                grpc::agent_response::WebsocketDecision::WebsocketDrop(_) => WebSocketDecision::Drop,
                grpc::agent_response::WebsocketDecision::WebsocketClose(c) => WebSocketDecision::Close {
                    code: c.code as u16,
                    reason: c.reason,
                },
            }
        });

        Ok(AgentResponse {
            version: response.version,
            decision,
            request_headers,
            response_headers,
            routing_metadata: response.routing_metadata,
            audit: audit.unwrap_or_default(),
            needs_more: response.needs_more,
            request_body_mutation,
            response_body_mutation,
            websocket_decision,
        })
    }

    /// Convert gRPC header operation to internal format
    fn convert_header_op_from_grpc(op: grpc::HeaderOp) -> Option<HeaderOp> {
        match op.operation? {
            grpc::header_op::Operation::Set(s) => Some(HeaderOp::Set {
                name: s.name,
                value: s.value,
            }),
            grpc::header_op::Operation::Add(a) => Some(HeaderOp::Add {
                name: a.name,
                value: a.value,
            }),
            grpc::header_op::Operation::Remove(r) => Some(HeaderOp::Remove {
                name: r.name,
            }),
        }
    }

    /// Send raw bytes to agent (Unix socket only)
    async fn send_raw_unix(&mut self, data: &[u8]) -> Result<(), AgentProtocolError> {
        let AgentConnection::UnixSocket(stream) = &mut self.connection else {
            unreachable!()
        };
        // Write message length (4 bytes, big-endian)
        let len_bytes = (data.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        // Write message data
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Receive raw bytes from agent (Unix socket only)
    async fn receive_raw_unix(&mut self) -> Result<Vec<u8>, AgentProtocolError> {
        let AgentConnection::UnixSocket(stream) = &mut self.connection else {
            unreachable!()
        };
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

    /// Close the agent connection
    pub async fn close(self) -> Result<(), AgentProtocolError> {
        match self.connection {
            AgentConnection::UnixSocket(mut stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            AgentConnection::Grpc(_) => Ok(()), // gRPC channels close automatically
        }
    }
}
