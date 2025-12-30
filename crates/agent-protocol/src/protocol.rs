//! Agent protocol types and constants.
//!
//! This module defines the wire protocol types for communication between
//! the proxy dataplane and external processing agents.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Agent protocol version
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum message size (10MB)
pub const MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

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
        }
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
