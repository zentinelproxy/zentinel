# Protocol Specification

This document describes the wire protocol for communication between the Sentinel proxy dataplane and external processing agents.

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | `1` | Current protocol version |
| `MAX_MESSAGE_SIZE` | `10,485,760` (10 MB) | Maximum message size in bytes |

## Transport Mechanisms

### Unix Domain Sockets (Default)

The primary transport uses Unix Domain Sockets with length-prefixed JSON messages.

#### Message Format

```
┌──────────────────┬─────────────────────────────────┐
│ Length (4 bytes) │ JSON Payload (variable length)  │
│ Big-endian u32   │ UTF-8 encoded                   │
└──────────────────┴─────────────────────────────────┘
```

- **Length prefix**: 4-byte unsigned integer in big-endian byte order
- **Payload**: JSON-encoded message, max 10 MB
- **Encoding**: UTF-8

#### Example

```
00 00 00 1A  {"event_type":"Configure"...}
└─────┬────┘ └──────────────┬─────────────┘
  26 bytes        JSON payload
```

### gRPC Transport

For high-throughput scenarios, gRPC over HTTP/2 is supported.

#### Service Definition

```protobuf
service AgentProcessor {
    // Unary RPC for single request-response
    rpc ProcessEvent(AgentRequest) returns (AgentResponse);

    // Bidirectional streaming for body chunks
    rpc ProcessEventStream(stream AgentRequest) returns (stream AgentResponse);
}
```

#### Advantages

- Better performance for high-throughput scenarios
- Native TLS/mTLS support
- Language-agnostic (any gRPC-compatible language)
- Built-in flow control and backpressure

## Message Types

### AgentRequest

Sent from proxy to agent.

```rust
pub struct AgentRequest {
    pub protocol_version: u32,
    pub event_type: EventType,
    pub payload: Vec<u8>,  // JSON-encoded event data
}
```

### AgentResponse

Sent from agent to proxy.

```rust
pub struct AgentResponse {
    pub decision: Decision,
    pub request_headers: Vec<HeaderOp>,
    pub response_headers: Vec<HeaderOp>,
    pub request_body_mutation: Option<BodyMutation>,
    pub response_body_mutation: Option<BodyMutation>,
    pub audit: Option<AuditMetadata>,
    pub needs_more: bool,
    pub websocket_decision: Option<WebSocketDecision>,
    pub guardrail_response: Option<GuardrailResponse>,
}
```

## Event Types

### EventType Enum

```rust
pub enum EventType {
    Configure,           // Initial handshake
    RequestHeaders,      // HTTP request headers received
    RequestBodyChunk,    // Request body chunk (streaming)
    ResponseHeaders,     // HTTP response headers from upstream
    ResponseBodyChunk,   // Response body chunk (streaming)
    RequestComplete,     // Request processing complete
    WebSocketFrame,      // WebSocket frame received
    GuardrailInspect,    // Content inspection request
}
```

### Configure Event

Sent once when a connection is established. Used for capability negotiation.

```rust
pub struct ConfigureEvent {
    pub agent_name: String,
    pub supported_events: Vec<EventType>,
    pub max_body_size: Option<u64>,
    pub timeout_ms: Option<u64>,
}
```

### RequestHeaders Event

Sent when HTTP request headers are received.

```rust
pub struct RequestHeadersEvent {
    pub metadata: RequestMetadata,
    pub method: String,           // GET, POST, etc.
    pub uri: String,              // /path?query
    pub headers: HashMap<String, String>,
}
```

### RequestMetadata

Included with every request event.

```rust
pub struct RequestMetadata {
    pub correlation_id: String,    // Unique ID for this request lifecycle
    pub request_id: String,        // Unique request identifier
    pub client_ip: String,         // Client IP address
    pub client_port: u16,          // Client port
    pub server_name: Option<String>, // SNI or Host header
    pub protocol: String,          // HTTP/1.1, HTTP/2, etc.
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub route_id: Option<String>,  // Matched route identifier
    pub upstream_id: Option<String>,
    pub timestamp: String,         // RFC 3339 timestamp
    pub traceparent: Option<String>, // W3C Trace Context
}
```

### RequestBodyChunk Event

Sent for each chunk of the request body (streaming).

```rust
pub struct RequestBodyChunkEvent {
    pub metadata: RequestMetadata,
    pub chunk_index: u32,
    pub data: Vec<u8>,            // Raw body bytes
    pub is_last: bool,            // True if final chunk
}
```

### ResponseHeaders Event

Sent when response headers are received from upstream.

```rust
pub struct ResponseHeadersEvent {
    pub metadata: RequestMetadata,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
}
```

### ResponseBodyChunk Event

Sent for each chunk of the response body (streaming).

```rust
pub struct ResponseBodyChunkEvent {
    pub metadata: RequestMetadata,
    pub chunk_index: u32,
    pub data: Vec<u8>,
    pub is_last: bool,
}
```

### RequestComplete Event

Sent when request processing is complete.

```rust
pub struct RequestCompleteEvent {
    pub metadata: RequestMetadata,
    pub status_code: u16,
    pub duration_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
```

### WebSocketFrame Event

Sent when a WebSocket frame is received.

```rust
pub struct WebSocketFrameEvent {
    pub metadata: RequestMetadata,
    pub opcode: WebSocketOpcode,
    pub payload: Vec<u8>,
    pub is_masked: bool,
    pub is_final: bool,
}

pub enum WebSocketOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}
```

### GuardrailInspect Event

Sent to request content inspection for AI guardrails.

```rust
pub struct GuardrailInspectEvent {
    pub metadata: RequestMetadata,
    pub inspection_type: GuardrailInspectionType,
    pub content: String,
    pub context: Option<String>,
}

pub enum GuardrailInspectionType {
    PromptInjection,
    PiiDetection,
}
```

## Decision Types

### Decision Enum

```rust
pub enum Decision {
    Allow,
    Block {
        status: u16,
        body: Option<String>,
        headers: HashMap<String, String>,
    },
    Redirect {
        url: String,
        status: u16,  // 301, 302, 307, or 308
    },
    Challenge {
        challenge_type: String,
        params: HashMap<String, String>,
    },
}
```

### WebSocket Decision

```rust
pub enum WebSocketDecision {
    Allow,
    Drop,                           // Silently drop the frame
    Close { code: u16, reason: String },
}
```

## Header Operations

```rust
pub enum HeaderOp {
    Set { name: String, value: String },   // Set/overwrite header
    Add { name: String, value: String },   // Add header (allows duplicates)
    Remove { name: String },               // Remove header
}
```

## Body Mutations

```rust
pub struct BodyMutation {
    pub chunk_index: u32,
    pub action: BodyAction,
    pub data: Option<String>,
}

pub enum BodyAction {
    PassThrough,  // Forward chunk unchanged
    Drop,         // Drop this chunk
    Replace,      // Replace chunk with `data`
}
```

Helper constructors:

```rust
impl BodyMutation {
    pub fn pass_through(chunk_index: u32) -> Self;
    pub fn drop_chunk(chunk_index: u32) -> Self;
    pub fn replace(chunk_index: u32, data: String) -> Self;
}
```

## Audit Metadata

Structured data for logging and metrics.

```rust
pub struct AuditMetadata {
    pub tags: Vec<String>,
    pub rule_ids: Vec<String>,
    pub confidence: Option<f64>,
    pub reason_codes: Vec<String>,
    pub extra: HashMap<String, String>,
}
```

## Guardrail Response

Response for guardrail inspection requests.

```rust
pub struct GuardrailResponse {
    pub is_safe: bool,
    pub detections: Vec<GuardrailDetection>,
}

pub struct GuardrailDetection {
    pub detection_type: String,
    pub severity: DetectionSeverity,
    pub description: String,
    pub spans: Vec<TextSpan>,
}

pub enum DetectionSeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct TextSpan {
    pub start: u32,
    pub end: u32,
    pub text: String,
}
```

## Streaming Semantics

### Body Streaming Protocol

1. Proxy sends `RequestBodyChunk` events with `chunk_index` starting at 0
2. Each chunk has `is_last: false` except the final chunk
3. Agent responds with `BodyMutation` for each chunk
4. If agent needs to buffer, set `needs_more: true` in response
5. Agent must respond to all chunks before request completes

### Buffering Considerations

- Agents should respect `max_body_size` from configuration
- Unbounded buffering is not allowed
- If body exceeds limits, agent should make a decision on partial data

## Protocol Guarantees

1. **Ordering**: Events are delivered in order within a request lifecycle
2. **Correlation**: All events for a request share the same `correlation_id`
3. **Timeouts**: Proxy enforces per-event timeouts
4. **Isolation**: Agent crashes do not affect proxy stability
5. **Fail-safe**: Configurable fail-open or fail-closed on timeout
