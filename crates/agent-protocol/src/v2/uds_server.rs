//! Unix Domain Socket server for Agent Protocol v2.
//!
//! Provides a UDS-based v2 server that speaks the same binary wire format as
//! [`AgentClientV2Uds`](super::uds::AgentClientV2Uds). Agents implement
//! [`AgentHandlerV2`] and pass it to this server.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, trace, warn};

use crate::v2::server::AgentHandlerV2;
use crate::v2::uds::{
    read_message, write_message, MessageType, UdsCapabilities, UdsEncoding, UdsHandshakeRequest,
    UdsHandshakeResponse,
};
use crate::v2::HandshakeRequest;
use crate::{
    AgentProtocolError, AgentResponse, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketFrameEvent,
};

/// v2 agent server over Unix Domain Socket.
///
/// Listens on a Unix socket, accepts connections, and dispatches events to an
/// [`AgentHandlerV2`] implementation using the v2 binary wire format.
pub struct UdsAgentServerV2 {
    id: String,
    socket_path: PathBuf,
    handler: Arc<dyn AgentHandlerV2>,
}

impl UdsAgentServerV2 {
    /// Create a new UDS v2 agent server.
    pub fn new(
        id: impl Into<String>,
        socket_path: impl Into<PathBuf>,
        handler: Box<dyn AgentHandlerV2>,
    ) -> Self {
        let id = id.into();
        let socket_path = socket_path.into();

        debug!(
            agent_id = %id,
            socket_path = %socket_path.display(),
            "Creating UDS agent server v2"
        );

        Self {
            id,
            socket_path,
            handler: Arc::from(handler),
        }
    }

    /// Start the server.
    ///
    /// Removes any stale socket file, binds, and enters an accept loop that
    /// spawns a task per connection.
    pub async fn run(&self) -> Result<(), AgentProtocolError> {
        // Remove existing socket file if it exists
        if self.socket_path.exists() {
            trace!(
                agent_id = %self.id,
                socket_path = %self.socket_path.display(),
                "Removing existing socket file"
            );
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;

        info!(
            agent_id = %self.id,
            socket_path = %self.socket_path.display(),
            "UDS agent server v2 listening"
        );

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    trace!(agent_id = %self.id, "Accepted new connection");
                    let handler = Arc::clone(&self.handler);
                    let agent_id = self.id.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(handler, stream, agent_id.clone()).await {
                            if !matches!(e, AgentProtocolError::ConnectionClosed) {
                                error!(
                                    agent_id = %agent_id,
                                    error = %e,
                                    "Error handling UDS v2 connection"
                                );
                            }
                        }
                    });
                }
                Err(e) => {
                    error!(
                        agent_id = %self.id,
                        error = %e,
                        "Failed to accept connection"
                    );
                }
            }
        }
    }
}

/// Handle a single connection: handshake then event loop.
async fn handle_connection(
    handler: Arc<dyn AgentHandlerV2>,
    stream: UnixStream,
    agent_id: String,
) -> Result<(), AgentProtocolError> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    // ── Handshake (always JSON) ──────────────────────────────────────────

    let (msg_type, payload) = read_message(&mut reader).await?;
    if msg_type != MessageType::HandshakeRequest {
        return Err(AgentProtocolError::InvalidMessage(format!(
            "Expected HandshakeRequest, got {:?}",
            msg_type
        )));
    }

    let uds_req: UdsHandshakeRequest = serde_json::from_slice(&payload)
        .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;

    // Convert to domain-level HandshakeRequest
    let handshake_req = HandshakeRequest {
        supported_versions: uds_req.supported_versions,
        proxy_id: uds_req.proxy_id,
        proxy_version: uds_req.proxy_version,
        config: uds_req.config.unwrap_or(serde_json::Value::Null),
    };

    let handshake_resp = handler.on_handshake(handshake_req).await;
    let success = handshake_resp.success;

    // Negotiate encoding: pick the first proxy-preferred encoding we support
    let negotiated_encoding = negotiate_encoding(&uds_req.supported_encodings);

    // Build UDS-level response
    let uds_resp = UdsHandshakeResponse {
        protocol_version: handshake_resp.protocol_version,
        capabilities: UdsCapabilities::from(handshake_resp.capabilities),
        success,
        error: handshake_resp.error,
        encoding: negotiated_encoding,
    };

    let resp_bytes = serde_json::to_vec(&uds_resp)
        .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
    write_message(&mut writer, MessageType::HandshakeResponse, &resp_bytes).await?;

    if !success {
        debug!(agent_id = %agent_id, "Handshake rejected, closing connection");
        return Ok(());
    }

    info!(
        agent_id = %agent_id,
        encoding = ?negotiated_encoding,
        "UDS v2 handshake completed"
    );

    // ── Event loop (uses negotiated encoding) ────────────────────────────

    loop {
        let (msg_type, payload) = read_message(&mut reader).await?;

        match msg_type {
            MessageType::Ping => {
                trace!(agent_id = %agent_id, "Received ping, sending pong");
                // Echo the payload back as pong
                write_message(&mut writer, MessageType::Pong, &payload).await?;
            }
            MessageType::Cancel => {
                // Extract correlation_id for logging
                let cid = extract_correlation_id(&negotiated_encoding, &payload);
                debug!(
                    agent_id = %agent_id,
                    correlation_id = %cid,
                    "Request cancelled"
                );
            }
            MessageType::RequestHeaders => {
                let response =
                    handle_request_headers(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::RequestBodyChunk => {
                let response =
                    handle_request_body_chunk(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::ResponseHeaders => {
                let response =
                    handle_response_headers(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::ResponseBodyChunk => {
                let response =
                    handle_response_body_chunk(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::RequestComplete => {
                let response =
                    handle_request_complete(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::WebSocketFrame => {
                let response =
                    handle_websocket_frame(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            MessageType::Configure => {
                let response = handle_configure(&handler, &negotiated_encoding, &payload).await;
                write_response(&mut writer, &negotiated_encoding, response).await?;
            }
            _ => {
                warn!(
                    agent_id = %agent_id,
                    msg_type = ?msg_type,
                    "Received unhandled message type"
                );
            }
        }
    }
}

// ─── Encoding negotiation ────────────────────────────────────────────────────

/// Pick the first proxy-preferred encoding that we support. Falls back to JSON.
fn negotiate_encoding(proxy_encodings: &[UdsEncoding]) -> UdsEncoding {
    for enc in proxy_encodings {
        match enc {
            UdsEncoding::Json => return UdsEncoding::Json,
            UdsEncoding::MessagePack if cfg!(feature = "binary-uds") => {
                return UdsEncoding::MessagePack;
            }
            _ => continue,
        }
    }
    UdsEncoding::Json
}

// ─── Event handlers ──────────────────────────────────────────────────────────

async fn handle_request_headers(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: RequestHeadersEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize RequestHeaders");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };
    let cid = event.metadata.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_request_headers(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_request_body_chunk(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: RequestBodyChunkEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize RequestBodyChunk");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };
    let cid = event.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_request_body_chunk(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_response_headers(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: ResponseHeadersEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize ResponseHeaders");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };
    let cid = event.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_response_headers(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_response_body_chunk(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: ResponseBodyChunkEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize ResponseBodyChunk");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };
    let cid = event.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_response_body_chunk(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_request_complete(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: RequestCompleteEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize RequestComplete");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };
    let cid = event.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_request_complete(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_websocket_frame(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    let event: WebSocketFrameEvent = match encoding.deserialize(payload) {
        Ok(e) => e,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize WebSocketFrame");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::websocket_allow(), 0);
        }
    };
    let cid = event.correlation_id.clone();
    let start = Instant::now();
    let resp = handler.on_websocket_frame(event).await;
    (cid, resp, start.elapsed().as_millis() as u64)
}

async fn handle_configure(
    handler: &Arc<dyn AgentHandlerV2>,
    encoding: &UdsEncoding,
    payload: &[u8],
) -> (String, AgentResponse, u64) {
    // Configure payloads carry config + optional version
    #[derive(serde::Deserialize)]
    struct ConfigurePayload {
        #[serde(default)]
        correlation_id: String,
        #[serde(default)]
        config: serde_json::Value,
        #[serde(default)]
        config_version: Option<String>,
    }

    let parsed: ConfigurePayload = match encoding.deserialize(payload) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "Failed to deserialize Configure");
            let cid = extract_correlation_id(encoding, payload);
            return (cid, AgentResponse::default_allow(), 0);
        }
    };

    let cid = parsed.correlation_id;
    let start = Instant::now();
    let accepted = handler
        .on_configure(parsed.config, parsed.config_version)
        .await;
    let resp = if accepted {
        AgentResponse::default_allow()
    } else {
        AgentResponse::block(500, Some("Configuration rejected".to_string()))
    };
    (cid, resp, start.elapsed().as_millis() as u64)
}

// ─── Response serialization ──────────────────────────────────────────────────

/// Serialize and write an agent response, injecting the correlation ID into
/// `audit.custom` so the multiplexing client can route it.
async fn write_response<W: tokio::io::AsyncWriteExt + Unpin>(
    writer: &mut W,
    encoding: &UdsEncoding,
    (correlation_id, mut response, _processing_time_ms): (String, AgentResponse, u64),
) -> Result<(), AgentProtocolError> {
    // Inject correlation_id so the client can route the response
    response.audit.custom.insert(
        "correlation_id".to_string(),
        serde_json::Value::String(correlation_id),
    );

    let resp_bytes = encoding.serialize(&response)?;
    write_message(writer, MessageType::AgentResponse, &resp_bytes).await
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Best-effort extraction of `correlation_id` from a payload (for error paths).
fn extract_correlation_id(encoding: &UdsEncoding, payload: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct CidOnly {
        #[serde(default)]
        correlation_id: String,
        #[serde(default)]
        metadata: Option<MetaCid>,
    }
    #[derive(serde::Deserialize)]
    struct MetaCid {
        #[serde(default)]
        correlation_id: String,
    }

    if let Ok(parsed) = encoding.deserialize::<CidOnly>(payload) {
        if !parsed.correlation_id.is_empty() {
            return parsed.correlation_id;
        }
        if let Some(meta) = parsed.metadata {
            if !meta.correlation_id.is_empty() {
                return meta.correlation_id;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::AgentCapabilities;
    use crate::RequestMetadata;
    use async_trait::async_trait;

    struct TestHandler;

    #[async_trait]
    impl AgentHandlerV2 for TestHandler {
        fn capabilities(&self) -> AgentCapabilities {
            AgentCapabilities::new("test-uds-v2", "Test UDS V2 Agent", "1.0.0")
                .with_event(crate::EventType::RequestHeaders)
        }

        async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
            AgentResponse::default_allow().add_request_header(crate::HeaderOp::Set {
                name: "x-test-agent".to_string(),
                value: event.metadata.correlation_id.clone(),
            })
        }
    }

    #[test]
    fn test_negotiate_encoding_json() {
        let encodings = vec![UdsEncoding::Json];
        assert_eq!(negotiate_encoding(&encodings), UdsEncoding::Json);
    }

    #[test]
    fn test_negotiate_encoding_empty() {
        let encodings: Vec<UdsEncoding> = vec![];
        assert_eq!(negotiate_encoding(&encodings), UdsEncoding::Json);
    }

    #[test]
    fn test_create_server() {
        let server = UdsAgentServerV2::new("test", "/tmp/test-uds-v2.sock", Box::new(TestHandler));
        assert_eq!(server.id, "test");
    }

    #[tokio::test]
    async fn test_handshake_and_request_roundtrip() {
        use crate::v2::uds::AgentClientV2Uds;
        use std::time::Duration;

        let socket_path = format!("/tmp/test-uds-v2-{}.sock", std::process::id());
        let socket_path_clone = socket_path.clone();

        // Start server in background
        let server = UdsAgentServerV2::new("test-roundtrip", &socket_path, Box::new(TestHandler));

        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Give server time to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Connect client
        let client =
            AgentClientV2Uds::new("test-agent", &socket_path_clone, Duration::from_secs(5))
                .await
                .unwrap();
        client.connect().await.unwrap();

        assert!(client.is_connected().await);

        // Send a request headers event
        let event = RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-cid-1".to_string(),
                request_id: "req-1".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "0".to_string(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers: std::collections::HashMap::new(),
        };

        let response = client
            .send_request_headers("test-cid-1", &event)
            .await
            .unwrap();

        // Verify handler was called and response returned
        assert!(matches!(response.decision, crate::Decision::Allow));
        assert!(response.request_headers.iter().any(|h| matches!(
            h,
            crate::HeaderOp::Set { name, value }
                if name == "x-test-agent" && value == "test-cid-1"
        )));

        // Cleanup
        client.close().await.unwrap();
        server_handle.abort();
        let _ = std::fs::remove_file(&socket_path_clone);
    }
}
