# Protocol Specification v2

This document describes the v2 wire protocol for communication between the Zentinel proxy dataplane and external processing agents.

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PROTOCOL_VERSION` | `2` | Current protocol version |
| `MAX_MESSAGE_SIZE_GRPC` | `10,485,760` (10 MB) | Maximum message size for gRPC |
| `MAX_MESSAGE_SIZE_UDS` | `16,777,216` (16 MB) | Maximum message size for UDS binary |

## Transport Options

Protocol v2 supports three transport mechanisms:

| Transport | Use Case | Latency | Features |
|-----------|----------|---------|----------|
| **gRPC over HTTP/2** | Remote agents, cross-network | ~1.2ms | TLS, flow control, streaming |
| **Binary over UDS** | Co-located agents | ~0.4ms | Lowest latency, simple format |
| **Reverse Connections** | NAT traversal, dynamic scaling | Varies | Agent-initiated connections |

---

## gRPC Transport

### Service Definition

```protobuf
syntax = "proto3";

package zentinel.agent.v2;

service AgentProcessorV2 {
    // Bidirectional streaming for request/response lifecycle
    rpc ProcessStream(stream AgentMessage) returns (stream AgentMessage);

    // Health check
    rpc HealthCheck(HealthRequest) returns (HealthResponse);

    // Capability query
    rpc GetCapabilities(CapabilityRequest) returns (CapabilityResponse);
}

message AgentMessage {
    uint64 request_id = 1;
    oneof payload {
        RequestHeaders request_headers = 2;
        RequestBodyChunk request_body_chunk = 3;
        ResponseHeaders response_headers = 4;
        ResponseBodyChunk response_body_chunk = 5;
        AgentDecision decision = 6;
        CancelRequest cancel = 7;
    }
}
```

### Streaming Semantics

Unlike v1's request-response model, v2 uses bidirectional streaming:

```
Proxy                                    Agent
  │                                        │
  │ ──── RequestHeaders (id=1) ──────────► │
  │ ──── RequestBodyChunk (id=1) ────────► │
  │                                        │
  │ ◄──── Decision (id=1) ──────────────── │
  │                                        │
  │ ──── RequestHeaders (id=2) ──────────► │  (pipelined)
  │ ──── CancelRequest (id=1) ───────────► │  (cancellation)
  │                                        │
```

### Message Ordering

- Messages for a single `request_id` are ordered
- Messages for different `request_id`s may be interleaved
- `CancelRequest` terminates processing for a `request_id`

---

## Binary UDS Transport

### Wire Format

```
┌──────────────────┬──────────────────┬─────────────────────────────────┐
│ Length (4 bytes) │ Type (1 byte)    │ JSON Payload (variable length)  │
│ Big-endian u32   │ Message type ID  │ UTF-8 encoded                   │
└──────────────────┴──────────────────┴─────────────────────────────────┘
```

- **Length prefix**: 4-byte unsigned integer in big-endian byte order (includes type byte)
- **Type byte**: Message type identifier (see table below)
- **Payload**: JSON-encoded message body
- **Maximum size**: 16 MB total

### Message Types

| Type ID | Name | Direction | Description |
|---------|------|-----------|-------------|
| `0x01` | `HandshakeRequest` | Proxy → Agent | Initial capability negotiation |
| `0x02` | `HandshakeResponse` | Agent → Proxy | Capability confirmation |
| `0x10` | `RequestHeaders` | Proxy → Agent | HTTP request headers |
| `0x11` | `RequestBodyChunk` | Proxy → Agent | Request body chunk |
| `0x12` | `ResponseHeaders` | Proxy → Agent | HTTP response headers |
| `0x13` | `ResponseBodyChunk` | Proxy → Agent | Response body chunk |
| `0x20` | `Decision` | Agent → Proxy | Processing decision |
| `0x21` | `BodyMutation` | Agent → Proxy | Body chunk mutation |
| `0x30` | `CancelRequest` | Proxy → Agent | Cancel in-flight request |
| `0x31` | `CancelAll` | Proxy → Agent | Cancel all requests |
| `0xF0` | `Ping` | Either | Keep-alive ping |
| `0xF1` | `Pong` | Either | Keep-alive response |

### Example Frame

```
00 00 00 4A 10 {"request_id":1,"method":"GET","uri":"/api/users"...}
└────┬─────┘ └┘ └──────────────────────┬────────────────────────┘
   74 bytes  │         JSON payload (RequestHeaders)
             │
    Type: RequestHeaders (0x10)
```

### Handshake Protocol

Connection establishment requires a handshake:

```rust
pub struct UdsHandshakeRequest {
    pub protocol_version: u32,        // Must be 2
    pub client_name: String,          // Proxy identifier
    pub supported_features: Vec<String>,
}

pub struct UdsHandshakeResponse {
    pub protocol_version: u32,
    pub agent_name: String,
    pub capabilities: UdsCapabilities,
}

pub struct UdsCapabilities {
    pub handles_request_headers: bool,
    pub handles_request_body: bool,
    pub handles_response_headers: bool,
    pub handles_response_body: bool,
    pub supports_streaming: bool,
    pub supports_cancellation: bool,
    pub max_concurrent_requests: Option<u32>,
}
```

---

## Reverse Connections

Reverse connections allow agents to connect to the proxy instead of the proxy connecting to agents. This enables:

- Agents behind NAT/firewalls
- Dynamic agent scaling
- Load-based connection management

### Registration Protocol

When an agent connects via reverse connection:

```
Agent                                    Proxy
  │                                        │
  │ ──── Connect to listener socket ─────► │
  │                                        │
  │ ──── RegistrationRequest ────────────► │
  │                                        │
  │ ◄──── RegistrationResponse ─────────── │
  │                                        │
  │        (normal v2 protocol)            │
  │                                        │
```

### Registration Messages

```rust
pub struct RegistrationRequest {
    pub protocol_version: u32,       // Must be 2
    pub agent_id: String,            // Unique agent identifier
    pub capabilities: UdsCapabilities,
    pub auth_token: Option<String>,  // Optional authentication
    pub metadata: Option<Value>,     // Additional agent metadata
}

pub struct RegistrationResponse {
    pub accepted: bool,
    pub error: Option<String>,
    pub assigned_id: Option<String>, // Proxy-assigned connection ID
    pub config: Option<Value>,       // Optional pushed configuration
}
```

### Listener Configuration

```rust
pub struct ReverseConnectionConfig {
    pub handshake_timeout: Duration,      // Default: 10s
    pub max_connections_per_agent: usize, // Default: 4
    pub require_auth: bool,               // Default: false
    pub allowed_agents: Option<Vec<String>>,
}
```

---

## Message Types (Detailed)

### RequestHeaders

Sent when HTTP request headers are received.

```rust
pub struct RequestHeadersMessage {
    pub request_id: u64,              // Unique ID for this request
    pub metadata: RequestMetadata,
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub has_body: bool,               // Whether body chunks will follow
}
```

### RequestBodyChunk

Sent for each chunk of the request body.

```rust
pub struct RequestBodyChunkMessage {
    pub request_id: u64,
    pub chunk_index: u32,
    pub data: String,                 // Base64-encoded bytes
    pub is_last: bool,
}
```

### ResponseHeaders

Sent when response headers are received from upstream.

```rust
pub struct ResponseHeadersMessage {
    pub request_id: u64,
    pub status_code: u16,
    pub headers: Vec<(String, String)>,
    pub has_body: bool,
}
```

### ResponseBodyChunk

Sent for each chunk of the response body.

```rust
pub struct ResponseBodyChunkMessage {
    pub request_id: u64,
    pub chunk_index: u32,
    pub data: String,                 // Base64-encoded bytes
    pub is_last: bool,
}
```

### Decision

Agent's processing decision for a request.

```rust
pub struct DecisionMessage {
    pub request_id: u64,
    pub decision: Decision,
    pub request_headers: Vec<HeaderOp>,
    pub response_headers: Vec<HeaderOp>,
    pub audit: Option<AuditMetadata>,
}

pub enum Decision {
    Allow,
    Block { status: u16, body: Option<String>, headers: HashMap<String, String> },
    Redirect { url: String, status: u16 },
}
```

### CancelRequest

Cancels processing for a specific request.

```rust
pub struct CancelRequestMessage {
    pub request_id: u64,
    pub reason: Option<String>,
}
```

---

## Request Lifecycle

### Normal Flow

```
┌─────────┐    RequestHeaders     ┌─────────┐
│  Proxy  │ ───────────────────► │  Agent  │
│         │                       │         │
│         │    RequestBodyChunk   │         │
│         │ ───────────────────► │         │
│         │    (repeat)           │         │
│         │                       │         │
│         │    Decision           │         │
│         │ ◄─────────────────── │         │
│         │                       │         │
│         │    ResponseHeaders    │         │
│         │ ───────────────────► │         │
│         │                       │         │
│         │    Decision           │         │
│         │ ◄─────────────────── │         │
└─────────┘                       └─────────┘
```

### Cancellation Flow

```
┌─────────┐    RequestHeaders     ┌─────────┐
│  Proxy  │ ───────────────────► │  Agent  │
│         │                       │         │
│         │    CancelRequest      │         │
│         │ ───────────────────► │         │
│         │                       │         │
│         │    (agent cleans up)  │         │
└─────────┘                       └─────────┘
```

---

## Protocol Guarantees

### Ordering

1. Messages for a single `request_id` are delivered in order
2. Messages for different requests may be interleaved
3. `CancelRequest` is processed immediately, discarding pending messages

### Reliability

1. Each message must be acknowledged (Decision for requests)
2. Timeouts are enforced per-message and per-request
3. Connection failures trigger reconnection with backoff

### Concurrency

1. Multiple requests can be in-flight simultaneously
2. `max_concurrent_requests` in capabilities limits concurrency
3. Backpressure via flow control (gRPC) or queue bounds (UDS)

---

## Compatibility

### v1 to v2 Migration

| v1 Feature | v2 Equivalent |
|------------|---------------|
| Length-prefixed JSON | Binary UDS (type byte added) |
| Unary gRPC calls | Bidirectional streaming |
| Per-request connections | Multiplexed connections |
| N/A | Request cancellation |
| N/A | Reverse connections |

### Version Negotiation

- gRPC: Service name includes version (`AgentProcessorV2`)
- UDS: `protocol_version` field in handshake
- Reverse: `protocol_version` field in registration

Agents should reject connections with incompatible versions.

---

## Performance Considerations

### gRPC

- Use HTTP/2 connection pooling
- Enable flow control for backpressure
- Consider TLS session resumption

### UDS Binary

- Pre-allocate message buffers
- Use vectored I/O for large bodies
- Batch small messages when possible

### Reverse Connections

- Maintain connection pool per agent
- Implement health checking
- Use least-connections load balancing
