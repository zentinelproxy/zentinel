//! Agent protocol types and constants.
//!
//! This module defines the wire protocol types for communication between
//! the proxy dataplane and external processing agents.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Agent protocol version
pub const PROTOCOL_VERSION: u32 = 2;

/// Maximum message size for gRPC transport (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Agent event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Agent configuration (sent once when agent connects)
    Configure,
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
    /// WebSocket frame received (after upgrade)
    WebSocketFrame,
    /// Guardrail content inspection (prompt injection, PII detection)
    GuardrailInspect,
}

/// Agent response decision indicating how to handle a request or response.
///
/// This enum represents the decision an agent makes when processing a request or response.
/// It allows agents to allow, block, redirect, or challenge requests based on their processing logic.
///
/// # Variants
///
/// - **Allow**: Continue normal processing without modification
/// - **Block**: Reject the request/response with a custom error response
/// - **Redirect**: Send the client to a different URL
/// - **Challenge**: Request additional verification from the client
///
/// # Examples
///
/// ```rust
/// use std::collections::HashMap;
/// use zentinel_agent_protocol::Decision;
///
/// // Allow request to proceed normally
/// let allow = Decision::Allow;
///
/// // Block with 403 and custom body
/// let block = Decision::Block {
///     status: 403,
///     body: Some("Access denied".to_string()),
///     headers: None,
/// };
///
/// // Redirect to login page
/// let redirect = Decision::Redirect {
///     url: "https://example.com/login".to_string(),
///     status: 302,
/// };
///
/// // Challenge with CAPTCHA
/// let mut params = HashMap::new();
/// params.insert("type".to_string(), "recaptcha".to_string());
/// let challenge = Decision::Challenge {
///     challenge_type: "captcha".to_string(),
///     params,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Allow the request/response to continue without modification.
    ///
    /// This is the default decision that indicates normal processing should proceed.
    #[default]
    Allow,
    /// Block the request/response with a custom error response.
    ///
    /// The proxy will return the specified status code and optional body/headers
    /// instead of forwarding the request to the upstream or returning the original response.
    Block {
        /// HTTP status code to return (typically 4xx or 5xx)
        status: u16,
        /// Optional response body content
        body: Option<String>,
        /// Optional response headers to include
        headers: Option<HashMap<String, String>>,
    },
    /// Redirect the client to a different URL.
    ///
    /// The proxy will return a redirect response with the specified URL and status code.
    Redirect {
        /// Target URL for the redirect
        url: String,
        /// HTTP redirect status code (301, 302, 303, 307, or 308)
        status: u16,
    },
    /// Request additional verification from the client.
    ///
    /// This can be used to implement CAPTCHA, multi-factor authentication,
    /// or other challenge-response mechanisms.
    Challenge {
        /// Type of challenge (e.g., "captcha", "otp", "totp")
        challenge_type: String,
        /// Challenge-specific parameters and configuration
        params: HashMap<String, String>,
    },
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

// ============================================================================
// Body Mutation
// ============================================================================

/// Body mutation from agent
///
/// Allows agents to modify body content during streaming:
/// - `None` data: pass through original chunk unchanged
/// - `Some(empty)`: drop the chunk entirely
/// - `Some(data)`: replace chunk with modified content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyMutation {
    /// Modified body data (base64 encoded for JSON transport)
    ///
    /// - `None`: use original chunk unchanged
    /// - `Some("")`: drop this chunk
    /// - `Some(data)`: replace chunk with this data
    pub data: Option<String>,

    /// Chunk index this mutation applies to
    ///
    /// Must match the `chunk_index` from the body chunk event.
    #[serde(default)]
    pub chunk_index: u32,
}

impl BodyMutation {
    /// Create a pass-through mutation (no change)
    pub fn pass_through(chunk_index: u32) -> Self {
        Self {
            data: None,
            chunk_index,
        }
    }

    /// Create a mutation that drops the chunk
    pub fn drop_chunk(chunk_index: u32) -> Self {
        Self {
            data: Some(String::new()),
            chunk_index,
        }
    }

    /// Create a mutation that replaces the chunk
    pub fn replace(chunk_index: u32, data: String) -> Self {
        Self {
            data: Some(data),
            chunk_index,
        }
    }

    /// Check if this mutation passes through unchanged
    pub fn is_pass_through(&self) -> bool {
        self.data.is_none()
    }

    /// Check if this mutation drops the chunk
    pub fn is_drop(&self) -> bool {
        matches!(&self.data, Some(d) if d.is_empty())
    }
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
    /// W3C Trace Context traceparent header (for distributed tracing)
    ///
    /// Format: `{version}-{trace-id}-{parent-id}-{trace-flags}`
    /// Example: `00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01`
    ///
    /// Agents can use this to create child spans that link to the proxy's span.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
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
    /// Chunk index for ordering (0-based)
    ///
    /// Used to match mutations to chunks and ensure ordering.
    #[serde(default)]
    pub chunk_index: u32,
    /// Bytes received so far (cumulative)
    #[serde(default)]
    pub bytes_received: usize,
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
    /// Chunk index for ordering (0-based)
    #[serde(default)]
    pub chunk_index: u32,
    /// Bytes sent so far (cumulative)
    #[serde(default)]
    pub bytes_sent: usize,
}

// ============================================================================
// Binary Body Chunk Events (Zero-Copy)
// ============================================================================

/// Binary request body chunk event.
///
/// This type uses `Bytes` for zero-copy body streaming, avoiding the base64
/// encode/decode overhead of `RequestBodyChunkEvent`. Use this type for:
/// - Binary UDS transport (with `binary-uds` feature)
/// - gRPC transport (protobuf already uses bytes)
/// - Any transport that supports raw binary data
///
/// For JSON transport, use `RequestBodyChunkEvent` with base64-encoded data.
#[derive(Debug, Clone)]
pub struct BinaryRequestBodyChunkEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// Body chunk data (raw bytes, no encoding)
    pub data: Bytes,
    /// Is this the last chunk?
    pub is_last: bool,
    /// Total body size if known
    pub total_size: Option<usize>,
    /// Chunk index for ordering (0-based)
    pub chunk_index: u32,
    /// Bytes received so far (cumulative)
    pub bytes_received: usize,
}

/// Binary response body chunk event.
///
/// This type uses `Bytes` for zero-copy body streaming, avoiding the base64
/// encode/decode overhead of `ResponseBodyChunkEvent`. Use this type for:
/// - Binary UDS transport (with `binary-uds` feature)
/// - gRPC transport (protobuf already uses bytes)
/// - Any transport that supports raw binary data
///
/// For JSON transport, use `ResponseBodyChunkEvent` with base64-encoded data.
#[derive(Debug, Clone)]
pub struct BinaryResponseBodyChunkEvent {
    /// Correlation ID
    pub correlation_id: String,
    /// Body chunk data (raw bytes, no encoding)
    pub data: Bytes,
    /// Is this the last chunk?
    pub is_last: bool,
    /// Total body size if known
    pub total_size: Option<usize>,
    /// Chunk index for ordering (0-based)
    pub chunk_index: u32,
    /// Bytes sent so far (cumulative)
    pub bytes_sent: usize,
}

impl BinaryRequestBodyChunkEvent {
    /// Create a new binary request body chunk event.
    pub fn new(
        correlation_id: impl Into<String>,
        data: impl Into<Bytes>,
        chunk_index: u32,
        is_last: bool,
    ) -> Self {
        let data = data.into();
        Self {
            correlation_id: correlation_id.into(),
            bytes_received: data.len(),
            data,
            is_last,
            total_size: None,
            chunk_index,
        }
    }

    /// Set the total body size.
    pub fn with_total_size(mut self, size: usize) -> Self {
        self.total_size = Some(size);
        self
    }

    /// Set cumulative bytes received.
    pub fn with_bytes_received(mut self, bytes: usize) -> Self {
        self.bytes_received = bytes;
        self
    }
}

impl BinaryResponseBodyChunkEvent {
    /// Create a new binary response body chunk event.
    pub fn new(
        correlation_id: impl Into<String>,
        data: impl Into<Bytes>,
        chunk_index: u32,
        is_last: bool,
    ) -> Self {
        let data = data.into();
        Self {
            correlation_id: correlation_id.into(),
            bytes_sent: data.len(),
            data,
            is_last,
            total_size: None,
            chunk_index,
        }
    }

    /// Set the total body size.
    pub fn with_total_size(mut self, size: usize) -> Self {
        self.total_size = Some(size);
        self
    }

    /// Set cumulative bytes sent.
    pub fn with_bytes_sent(mut self, bytes: usize) -> Self {
        self.bytes_sent = bytes;
        self
    }
}

// ============================================================================
// Conversions between String (base64) and Binary body chunk types
// ============================================================================

impl From<BinaryRequestBodyChunkEvent> for RequestBodyChunkEvent {
    /// Convert binary body chunk to base64-encoded JSON-compatible type.
    fn from(event: BinaryRequestBodyChunkEvent) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        Self {
            correlation_id: event.correlation_id,
            data: STANDARD.encode(&event.data),
            is_last: event.is_last,
            total_size: event.total_size,
            chunk_index: event.chunk_index,
            bytes_received: event.bytes_received,
        }
    }
}

impl From<&RequestBodyChunkEvent> for BinaryRequestBodyChunkEvent {
    /// Convert base64-encoded body chunk to binary type.
    ///
    /// If base64 decoding fails, falls back to treating data as raw UTF-8 bytes.
    fn from(event: &RequestBodyChunkEvent) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let data = STANDARD
            .decode(&event.data)
            .map(Bytes::from)
            .unwrap_or_else(|_| Bytes::copy_from_slice(event.data.as_bytes()));
        Self {
            correlation_id: event.correlation_id.clone(),
            data,
            is_last: event.is_last,
            total_size: event.total_size,
            chunk_index: event.chunk_index,
            bytes_received: event.bytes_received,
        }
    }
}

impl From<BinaryResponseBodyChunkEvent> for ResponseBodyChunkEvent {
    /// Convert binary body chunk to base64-encoded JSON-compatible type.
    fn from(event: BinaryResponseBodyChunkEvent) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        Self {
            correlation_id: event.correlation_id,
            data: STANDARD.encode(&event.data),
            is_last: event.is_last,
            total_size: event.total_size,
            chunk_index: event.chunk_index,
            bytes_sent: event.bytes_sent,
        }
    }
}

impl From<&ResponseBodyChunkEvent> for BinaryResponseBodyChunkEvent {
    /// Convert base64-encoded body chunk to binary type.
    ///
    /// If base64 decoding fails, falls back to treating data as raw UTF-8 bytes.
    fn from(event: &ResponseBodyChunkEvent) -> Self {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let data = STANDARD
            .decode(&event.data)
            .map(Bytes::from)
            .unwrap_or_else(|_| Bytes::copy_from_slice(event.data.as_bytes()));
        Self {
            correlation_id: event.correlation_id.clone(),
            data,
            is_last: event.is_last,
            total_size: event.total_size,
            chunk_index: event.chunk_index,
            bytes_sent: event.bytes_sent,
        }
    }
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

// ============================================================================
// WebSocket Frame Events
// ============================================================================

/// WebSocket frame event
///
/// Sent to agents after a WebSocket upgrade when frame inspection is enabled.
/// Each frame is sent individually for inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketFrameEvent {
    /// Correlation ID (same as the original HTTP upgrade request)
    pub correlation_id: String,
    /// Frame opcode: "text", "binary", "ping", "pong", "close", "continuation"
    pub opcode: String,
    /// Frame payload (base64 encoded for JSON transport)
    pub data: String,
    /// Direction: true = client->server, false = server->client
    pub client_to_server: bool,
    /// Frame index for this connection (0-based, per direction)
    pub frame_index: u64,
    /// FIN bit - true if final frame of message (for fragmented messages)
    pub fin: bool,
    /// Route ID
    pub route_id: Option<String>,
    /// Client IP
    pub client_ip: String,
}

/// WebSocket opcode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketOpcode {
    /// Continuation frame (0x0)
    Continuation,
    /// Text frame (0x1)
    Text,
    /// Binary frame (0x2)
    Binary,
    /// Connection close (0x8)
    Close,
    /// Ping (0x9)
    Ping,
    /// Pong (0xA)
    Pong,
}

impl WebSocketOpcode {
    /// Convert opcode to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Continuation => "continuation",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Close => "close",
            Self::Ping => "ping",
            Self::Pong => "pong",
        }
    }

    /// Parse from byte value
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }

    /// Convert to byte value
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Text => 0x1,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }
}

/// WebSocket frame decision
///
/// Agents return this decision for WebSocket frame events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketDecision {
    /// Allow frame to pass through
    #[default]
    Allow,
    /// Drop this frame silently (don't forward)
    Drop,
    /// Close the WebSocket connection
    Close {
        /// Close code (RFC 6455 section 7.4.1)
        code: u16,
        /// Close reason
        reason: String,
    },
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

    // ========================================================================
    // Streaming-specific fields
    // ========================================================================
    /// Agent needs more data to make a final decision
    ///
    /// When `true`, the current `decision` is provisional and may change
    /// after processing more body chunks. The proxy should continue
    /// streaming body data to this agent.
    ///
    /// When `false` (default), the decision is final.
    #[serde(default)]
    pub needs_more: bool,

    /// Request body mutation (for streaming mode)
    ///
    /// If present, applies the mutation to the current request body chunk.
    /// Only valid for `RequestBodyChunk` events.
    #[serde(default)]
    pub request_body_mutation: Option<BodyMutation>,

    /// Response body mutation (for streaming mode)
    ///
    /// If present, applies the mutation to the current response body chunk.
    /// Only valid for `ResponseBodyChunk` events.
    #[serde(default)]
    pub response_body_mutation: Option<BodyMutation>,

    /// WebSocket frame decision
    ///
    /// Only valid for `WebSocketFrame` events. If not set, defaults to Allow.
    #[serde(default)]
    pub websocket_decision: Option<WebSocketDecision>,
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
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
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
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
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
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    /// Create a streaming response indicating more data is needed
    pub fn needs_more_data() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            decision: Decision::Allow,
            request_headers: vec![],
            response_headers: vec![],
            routing_metadata: HashMap::new(),
            audit: AuditMetadata::default(),
            needs_more: true,
            request_body_mutation: None,
            response_body_mutation: None,
            websocket_decision: None,
        }
    }

    /// Create a WebSocket allow response
    pub fn websocket_allow() -> Self {
        Self {
            websocket_decision: Some(WebSocketDecision::Allow),
            ..Self::default_allow()
        }
    }

    /// Create a WebSocket drop response (drop the frame, don't forward)
    pub fn websocket_drop() -> Self {
        Self {
            websocket_decision: Some(WebSocketDecision::Drop),
            ..Self::default_allow()
        }
    }

    /// Create a WebSocket close response (close the connection)
    pub fn websocket_close(code: u16, reason: String) -> Self {
        Self {
            websocket_decision: Some(WebSocketDecision::Close { code, reason }),
            ..Self::default_allow()
        }
    }

    /// Set WebSocket decision
    pub fn with_websocket_decision(mut self, decision: WebSocketDecision) -> Self {
        self.websocket_decision = Some(decision);
        self
    }

    /// Create a streaming response with body mutation
    pub fn with_request_body_mutation(mut self, mutation: BodyMutation) -> Self {
        self.request_body_mutation = Some(mutation);
        self
    }

    /// Create a streaming response with response body mutation
    pub fn with_response_body_mutation(mut self, mutation: BodyMutation) -> Self {
        self.response_body_mutation = Some(mutation);
        self
    }

    /// Set needs_more flag
    pub fn set_needs_more(mut self, needs_more: bool) -> Self {
        self.needs_more = needs_more;
        self
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

// ============================================================================
// Guardrail Inspection Types
// ============================================================================

/// Type of guardrail inspection to perform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailInspectionType {
    /// Prompt injection detection (analyze request content)
    PromptInjection,
    /// PII detection (analyze response content)
    PiiDetection,
}

/// Guardrail inspection event
///
/// Sent to guardrail agents for semantic content analysis.
/// Used for prompt injection detection on requests and PII detection on responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailInspectEvent {
    /// Correlation ID for request tracing
    pub correlation_id: String,
    /// Type of inspection to perform
    pub inspection_type: GuardrailInspectionType,
    /// Content to inspect (request body or response content)
    pub content: String,
    /// Model name if available (for context)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// PII categories to check (for PII detection)
    /// e.g., ["ssn", "credit_card", "email", "phone"]
    #[serde(default)]
    pub categories: Vec<String>,
    /// Route ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    /// Additional metadata for context
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Guardrail inspection response from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailResponse {
    /// Whether any issues were detected
    pub detected: bool,
    /// Confidence score (0.0 - 1.0)
    #[serde(default)]
    pub confidence: f64,
    /// List of detections found
    #[serde(default)]
    pub detections: Vec<GuardrailDetection>,
    /// Redacted content (for PII, if requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_content: Option<String>,
}

impl Default for GuardrailResponse {
    fn default() -> Self {
        Self {
            detected: false,
            confidence: 0.0,
            detections: Vec::new(),
            redacted_content: None,
        }
    }
}

impl GuardrailResponse {
    /// Create a response indicating nothing detected
    pub fn clean() -> Self {
        Self::default()
    }

    /// Create a response with a detection
    pub fn with_detection(detection: GuardrailDetection) -> Self {
        Self {
            detected: true,
            confidence: detection.confidence.unwrap_or(1.0),
            detections: vec![detection],
            redacted_content: None,
        }
    }

    /// Add a detection to the response
    pub fn add_detection(&mut self, detection: GuardrailDetection) {
        self.detected = true;
        if let Some(conf) = detection.confidence {
            self.confidence = self.confidence.max(conf);
        }
        self.detections.push(detection);
    }
}

/// A single guardrail detection (prompt injection attempt, PII instance, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailDetection {
    /// Category of detection (e.g., "prompt_injection", "ssn", "credit_card")
    pub category: String,
    /// Human-readable description of what was detected
    pub description: String,
    /// Severity level
    #[serde(default)]
    pub severity: DetectionSeverity,
    /// Confidence score for this detection (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// Location in content where detection occurred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span: Option<TextSpan>,
}

impl GuardrailDetection {
    /// Create a new detection
    pub fn new(category: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            description: description.into(),
            severity: DetectionSeverity::Medium,
            confidence: None,
            span: None,
        }
    }

    /// Set severity
    pub fn with_severity(mut self, severity: DetectionSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Set span
    pub fn with_span(mut self, start: usize, end: usize) -> Self {
        self.span = Some(TextSpan { start, end });
        self
    }
}

/// Text span indicating location in content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSpan {
    /// Start position (byte offset)
    pub start: usize,
    /// End position (byte offset, exclusive)
    pub end: usize,
}

/// Severity level for guardrail detections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DetectionSeverity {
    /// Low severity (informational)
    Low,
    /// Medium severity (default)
    #[default]
    Medium,
    /// High severity (should likely block)
    High,
    /// Critical severity (must block)
    Critical,
}
