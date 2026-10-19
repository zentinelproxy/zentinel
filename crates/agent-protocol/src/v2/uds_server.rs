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

/// Unix Domain Socket agent server implementation for Protocol v2.
///
/// `UdsAgentServerV2` provides a high-performance local transport for agents running
/// on the same machine as the Zentinel proxy. It uses Unix Domain Sockets for
/// inter-process communication with minimal overhead.
///
/// This transport is recommended for agents that need the lowest possible latency
/// and are co-located with the proxy process.
///
/// # Features
///
/// - **High performance**: Minimal overhead for local communication
/// - **Binary protocol**: Efficient binary encoding for reduced CPU usage
/// - **File system permissions**: Uses Unix socket permissions for access control
/// - **Socket cleanup**: Removes stale socket files on startup
///
/// # Example
///
/// ```rust,ignore
/// use zentinel_agent_protocol::v2::UdsAgentServerV2;
/// use std::path::Path;
///
/// // Create server with your handler
/// let handler = Box::new(MyAgent::new());
/// let server = UdsAgentServerV2::new(
///     "my-agent",
///     Path::new("/var/run/my-agent.sock"),
///     handler
/// );
///
/// // Start listening
/// server.run().await?;
/// ```
///
/// # Socket Management
///
/// The server automatically:
/// - Creates the socket file with appropriate permissions
/// - Removes stale socket files on startup
/// - Handles multiple concurrent proxy connections
///
/// # Errors
///
/// May return errors for:
/// - Permission issues creating/accessing the socket file
/// - Invalid socket paths or filesystem issues
/// - Handler implementation errors
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
///
/// Returns an empty string only when the payload holds no usable id at all.
/// That outcome is expensive: a response carrying an empty correlation id can
/// never be matched to the request waiting for it, so the client blocks until
/// its timeout expires. Every reasonable effort to find an id is worth making.
fn extract_correlation_id(encoding: &UdsEncoding, payload: &[u8]) -> String {
    if let Ok(parsed) = encoding.deserialize::<CidOnly>(payload) {
        return parsed.0;
    }
    String::new()
}

/// A payload reduced to just its correlation id, taken either from the top
/// level or from a nested `metadata` object.
///
/// The `Deserialize` implementation is written out by hand rather than derived
/// because this type runs *after* a derived implementation has already failed
/// on the same bytes. A derived one shares too many of its failure modes to be
/// a useful fallback — notably, it rejects a duplicate key outright, and a
/// payload with two `correlation_id` entries is precisely the sort this needs
/// to salvage an id from. Unrecognised fields are skipped without being
/// interpreted.
struct CidOnly(String);

impl<'de> serde::Deserialize<'de> for CidOnly {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{IgnoredAny, MapAccess, Visitor};

        struct CidVisitor;

        impl<'de> Visitor<'de> for CidVisitor {
            type Value = CidOnly;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an agent event payload")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<CidOnly, A::Error> {
                let mut direct: Option<String> = None;
                let mut nested: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        // First writer wins, so a duplicate key cannot
                        // overwrite an id already found with a later empty one.
                        "correlation_id" => {
                            let value: String = map.next_value()?;
                            if direct.is_none() && !value.is_empty() {
                                direct = Some(value);
                            }
                        }
                        // `metadata` is itself a map with a correlation id in
                        // it, so the same visitor handles it one level down.
                        "metadata" => {
                            let inner: CidOnly = map.next_value()?;
                            if nested.is_none() && !inner.0.is_empty() {
                                nested = Some(inner.0);
                            }
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(CidOnly(direct.or(nested).unwrap_or_default()))
            }

            // `metadata` is optional; absent or null is not an error here, it
            // just means there is no id to be had at that level.
            fn visit_unit<E>(self) -> Result<CidOnly, E> {
                Ok(CidOnly(String::new()))
            }

            fn visit_none<E>(self) -> Result<CidOnly, E> {
                Ok(CidOnly(String::new()))
            }

            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<CidOnly, D::Error> {
                deserializer.deserialize_any(CidVisitor)
            }
        }

        deserializer.deserialize_any(CidVisitor)
    }
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

    /// Every event type, driven through a real client and server over the
    /// negotiated encoding.
    ///
    /// The bug this guards against (#360) reached only one event type through
    /// its test: `RequestHeadersEvent` is the sole event that keeps its
    /// correlation id in a nested `metadata` object, and so the sole one that
    /// survived a client which emitted the key a second time at the top level.
    /// The other six carry the id directly, ended up with it twice under
    /// MessagePack, and were rejected by the server as a duplicate field —
    /// every call hanging until it timed out.
    ///
    /// Asserting `Ok` is not enough on its own: the server answers malformed
    /// payloads too, and a good enough correlation-id fallback would make a
    /// broken client look healthy. So the handler records what it was actually
    /// handed, and the test checks that every event arrived decoded.
    mod every_event_type {
        use super::*;
        use crate::v2::uds::AgentClientV2Uds;
        use std::sync::Mutex;
        use std::time::Duration;

        #[derive(Default)]
        struct RecordingHandler {
            seen: Arc<Mutex<Vec<String>>>,
        }

        impl RecordingHandler {
            fn record(&self, what: &str, cid: &str) {
                self.seen
                    .lock()
                    .expect("recording handler lock")
                    .push(format!("{what}:{cid}"));
            }
        }

        #[async_trait]
        impl AgentHandlerV2 for RecordingHandler {
            fn capabilities(&self) -> AgentCapabilities {
                AgentCapabilities::new("recording", "Recording Agent", "1.0.0")
                    .with_event(crate::EventType::RequestHeaders)
                    .with_event(crate::EventType::RequestBodyChunk)
                    .with_event(crate::EventType::ResponseHeaders)
                    .with_event(crate::EventType::ResponseBodyChunk)
                    .with_event(crate::EventType::RequestComplete)
                    .with_event(crate::EventType::WebSocketFrame)
            }

            async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
                self.record("request_headers", &event.metadata.correlation_id);
                AgentResponse::default_allow()
            }

            async fn on_request_body_chunk(
                &self,
                event: crate::RequestBodyChunkEvent,
            ) -> AgentResponse {
                self.record("request_body_chunk", &event.correlation_id);
                AgentResponse::default_allow()
            }

            async fn on_response_headers(
                &self,
                event: crate::ResponseHeadersEvent,
            ) -> AgentResponse {
                self.record("response_headers", &event.correlation_id);
                AgentResponse::default_allow()
            }

            async fn on_response_body_chunk(
                &self,
                event: crate::ResponseBodyChunkEvent,
            ) -> AgentResponse {
                self.record("response_body_chunk", &event.correlation_id);
                AgentResponse::default_allow()
            }

            async fn on_request_complete(
                &self,
                event: crate::RequestCompleteEvent,
            ) -> AgentResponse {
                self.record("request_complete", &event.correlation_id);
                AgentResponse::default_allow()
            }

            async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
                self.record("websocket_frame", &event.correlation_id);
                AgentResponse::websocket_allow()
            }

            // A configure payload is an envelope: the correlation id sits
            // beside the config rather than inside it, so what is recorded
            // here is the config itself — enough to show it arrived decoded.
            async fn on_configure(
                &self,
                config: serde_json::Value,
                _version: Option<String>,
            ) -> bool {
                let setting = config
                    .get("some-setting")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<missing>");
                self.record("configure", setting);
                true
            }
        }

        fn metadata(cid: &str) -> RequestMetadata {
            RequestMetadata {
                correlation_id: cid.to_string(),
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
            }
        }

        /// Sends one of every event and returns what the handler saw.
        async fn exercise_every_event(socket_suffix: &str) -> Vec<String> {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let handler = RecordingHandler {
                seen: Arc::clone(&seen),
            };

            let socket_path = format!(
                "/tmp/zentinel-every-event-{}-{}.sock",
                std::process::id(),
                socket_suffix
            );
            let _ = std::fs::remove_file(&socket_path);

            let server = UdsAgentServerV2::new("every-event", &socket_path, Box::new(handler));
            let server_handle = tokio::spawn(async move {
                let _ = server.run().await;
            });
            tokio::time::sleep(Duration::from_millis(50)).await;

            let client = AgentClientV2Uds::new("client", &socket_path, Duration::from_secs(5))
                .await
                .expect("client connects");
            client.connect().await.expect("handshake succeeds");

            // Each call blocks until the server's reply is matched back to it
            // by correlation id, so a mismatched id shows up as a timeout.
            client
                .send_request_headers(
                    "cid-headers",
                    &RequestHeadersEvent {
                        metadata: metadata("cid-headers"),
                        method: "GET".to_string(),
                        uri: "/test".to_string(),
                        headers: std::collections::HashMap::new(),
                    },
                )
                .await
                .expect("request headers");

            client
                .send_request_body_chunk(
                    "cid-req-body",
                    &crate::RequestBodyChunkEvent {
                        correlation_id: "cid-req-body".to_string(),
                        data: "aGk=".to_string(),
                        is_last: true,
                        total_size: Some(2),
                        chunk_index: 0,
                        bytes_received: 2,
                    },
                )
                .await
                .expect("request body chunk");

            client
                .send_response_headers(
                    "cid-resp-headers",
                    &crate::ResponseHeadersEvent {
                        correlation_id: "cid-resp-headers".to_string(),
                        status: 200,
                        headers: std::collections::HashMap::new(),
                    },
                )
                .await
                .expect("response headers");

            client
                .send_response_body_chunk(
                    "cid-resp-body",
                    &crate::ResponseBodyChunkEvent {
                        correlation_id: "cid-resp-body".to_string(),
                        data: "aGk=".to_string(),
                        is_last: true,
                        total_size: Some(2),
                        chunk_index: 0,
                        bytes_sent: 2,
                    },
                )
                .await
                .expect("response body chunk");

            client
                .send_request_complete(
                    "cid-complete",
                    &crate::RequestCompleteEvent {
                        correlation_id: "cid-complete".to_string(),
                        status: 200,
                        duration_ms: 1,
                        request_body_size: 2,
                        response_body_size: 2,
                        upstream_attempts: 1,
                        error: None,
                    },
                )
                .await
                .expect("request complete");

            client
                .send_websocket_frame(
                    "cid-ws",
                    &WebSocketFrameEvent {
                        correlation_id: "cid-ws".to_string(),
                        opcode: "text".to_string(),
                        data: "aGk=".to_string(),
                        client_to_server: true,
                        frame_index: 0,
                        fin: true,
                        route_id: None,
                        client_ip: "127.0.0.1".to_string(),
                    },
                )
                .await
                .expect("websocket frame");

            client
                .send_configure(
                    "cid-configure",
                    &serde_json::json!({ "config": { "some-setting": "value" } }),
                )
                .await
                .expect("configure");

            server_handle.abort();
            let _ = std::fs::remove_file(&socket_path);

            let recorded = seen.lock().expect("recording handler lock").clone();
            recorded
        }

        fn expected() -> Vec<String> {
            vec![
                "request_headers:cid-headers".to_string(),
                "request_body_chunk:cid-req-body".to_string(),
                "response_headers:cid-resp-headers".to_string(),
                "response_body_chunk:cid-resp-body".to_string(),
                "request_complete:cid-complete".to_string(),
                "websocket_frame:cid-ws".to_string(),
                "configure:value".to_string(),
            ]
        }

        #[tokio::test]
        async fn every_event_type_round_trips_over_json() {
            assert_eq!(exercise_every_event("json").await, expected());
        }

        /// The regression test for #360. Without the fix this hangs on the
        /// second event and fails on the first `expect` after it.
        #[cfg(feature = "binary-uds")]
        #[tokio::test]
        async fn every_event_type_round_trips_over_messagepack() {
            assert_eq!(exercise_every_event("msgpack").await, expected());
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

    fn test_request(correlation_id: &str) -> RequestHeadersEvent {
        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: correlation_id.to_string(),
                request_id: "req".to_string(),
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
            uri: "/".to_string(),
            headers: std::collections::HashMap::new(),
        }
    }

    /// Run an agent on its own runtime, so that stopping it closes every
    /// connection it accepted -- as an agent process exiting does. Aborting a
    /// server task is not enough: its per-connection tasks would keep running.
    fn start_agent_process(
        name: &'static str,
        socket_path: &str,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let _ = std::fs::remove_file(socket_path);
        let socket_path = socket_path.to_string();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                let server = UdsAgentServerV2::new(name, &socket_path, Box::new(TestHandler));
                tokio::select! {
                    _ = server.run() => {}
                    _ = stop_rx => {}
                }
            });
            // Dropping the runtime here ends the connection tasks too.
        });
        (stop_tx, thread)
    }

    async fn wait_for_socket(socket_path: &str) {
        for _ in 0..100 {
            if std::path::Path::new(socket_path).exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("agent never bound {socket_path}");
    }

    /// #528: when the agent went away, the client kept reporting itself
    /// connected, because only `close()` ever cleared the flag. The pool
    /// therefore never replaced the connection, and a restarted agent was not
    /// reconnected until the proxy restarted.
    #[tokio::test]
    async fn client_notices_when_its_agent_goes_away() {
        use crate::v2::uds::AgentClientV2Uds;
        use std::time::Duration;

        let socket_path = format!("/tmp/zt-gone-{}.sock", std::process::id());
        let (stop, agent) = start_agent_process("gone", &socket_path);
        wait_for_socket(&socket_path).await;

        let client = AgentClientV2Uds::new("gone", &socket_path, Duration::from_secs(5))
            .await
            .unwrap();
        client.connect().await.unwrap();
        assert!(client.is_connected().await);

        stop.send(()).unwrap();
        agent.join().unwrap();

        let mut connected = true;
        for _ in 0..200 {
            connected = client.is_connected().await;
            if !connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !connected,
            "client still reports connected after its agent exited"
        );

        // And a request fails promptly rather than waiting out the 5 s timeout.
        let started = std::time::Instant::now();
        let result = client
            .send_request_headers("after-exit", &test_request("after-exit"))
            .await;
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(1));

        let _ = std::fs::remove_file(&socket_path);
    }

    /// #528 end to end: the agent restarts on the same socket while the pool
    /// keeps running, and the pool must recover on its own. Multi-threaded, as
    /// in the proxy: connection selection may block briefly on a lock that
    /// maintenance holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_reconnects_an_agent_that_restarted() {
        use crate::v2::pool::{AgentPool, AgentPoolConfig};
        use std::sync::Arc;
        use std::time::Duration;

        let socket_path = format!("/tmp/zt-restart-{}.sock", std::process::id());
        let (stop, agent) = start_agent_process("restart", &socket_path);
        wait_for_socket(&socket_path).await;

        let pool = Arc::new(AgentPool::with_config(AgentPoolConfig {
            connections_per_agent: 1,
            health_check_interval: Duration::from_millis(50),
            reconnect_interval: Duration::from_millis(50),
            request_timeout: Duration::from_secs(1),
            ..Default::default()
        }));
        let maintenance = {
            let pool = Arc::clone(&pool);
            tokio::spawn(async move { pool.run_maintenance().await })
        };
        pool.add_agent("restart", format!("unix:{socket_path}"))
            .await
            .unwrap();
        pool.send_request_headers("restart", "before", &test_request("before"))
            .await
            .expect("agent answers before the restart");

        // The agent exits and comes back on the same socket.
        stop.send(()).unwrap();
        agent.join().unwrap();
        let (stop, agent) = start_agent_process("restart", &socket_path);
        wait_for_socket(&socket_path).await;

        // Send nothing while the agent is away. In the proxy that is what an
        // open circuit breaker does, and it is why this went unnoticed: with no
        // traffic, the pool's consecutive-error count never reached the point
        // that marks a connection unhealthy, and the connection itself kept
        // claiming to be connected. Maintenance alone has to repair it.
        tokio::time::sleep(Duration::from_millis(500)).await;

        pool.send_request_headers("restart", "after", &test_request("after"))
            .await
            .expect("first request after the restart reaches the new agent");

        maintenance.abort();
        stop.send(()).unwrap();
        agent.join().unwrap();
        let _ = std::fs::remove_file(&socket_path);
    }
}
