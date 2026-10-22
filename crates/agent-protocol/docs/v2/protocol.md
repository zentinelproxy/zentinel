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

The protocol uses bidirectional streaming:

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
| `0x14` | `RequestComplete` | Proxy → Agent | Request finished (logging) |
| `0x15` | `WebSocketFrame` | Proxy → Agent | WebSocket frame |
| `0x16` | `GuardrailInspect` | Proxy → Agent | Guardrail inspection |
| `0x17` | `Configure` | Proxy → Agent | The agent's configuration (see [Configuration delivery](#configuration-delivery)) |
| `0x20` | `AgentResponse` | Agent → Proxy | Decision for an event, routed by `correlation_id` |
| `0x30` | `HealthStatus` | Agent → Proxy | Health report |
| `0x31` | `MetricsReport` | Agent → Proxy | Metrics report |
| `0x32` | `ConfigUpdateRequest` | Agent → Proxy | Agent asks for a config change |
| `0x33` | `FlowControl` | Agent → Proxy | Pause / resume |
| `0x40` | `Cancel` | Proxy → Agent | Cancel an in-flight request |
| `0x41` | `Ping` | Either | Keep-alive ping |
| `0x42` | `Pong` | Either | Keep-alive response |

### Example Frame

```
00 00 00 4A 10 {"request_id":1,"method":"GET","uri":"/api/users"...}
└────┬─────┘ └┘ └──────────────────────┬────────────────────────┘
   74 bytes  │         JSON payload (RequestHeaders)
             │
    Type: RequestHeaders (0x10)
```

### Handshake Protocol

Connection establishment requires a handshake. Both messages are always JSON;
the encoding negotiated in it applies to every message after it.

```rust
pub struct UdsHandshakeRequest {
    pub supported_versions: Vec<u32>,         // [2]
    pub proxy_id: String,
    pub proxy_version: String,
    pub config: Option<serde_json::Value>,    // The agent's `config { }` block
    pub supported_encodings: Vec<UdsEncoding>, // Omitted when only JSON
}

pub struct UdsHandshakeResponse {
    pub protocol_version: u32,
    pub capabilities: UdsCapabilities,
    pub success: bool,
    pub error: Option<String>,
    pub encoding: UdsEncoding,                 // Defaults to JSON
}
```

## Configuration delivery

The `config { }` block of an agent in the proxy's KDL is delivered on **every
connection** the proxy makes to the agent: each pooled connection, and every
reconnect after the agent restarts. A connection carries no request before
its configuration has been delivered.

```kdl
agent "waf" type="custom" {
    unix-socket "/run/zentinel/waf.sock"
    config {
        paranoia-level 2
    }
}
```

The block is converted to JSON (`{"paranoia-level": 2}`) and sent twice per
connection:

1. **In the handshake** — `UdsHandshakeRequest.config` (UDS) or
   `HandshakeRequest.config_json` (gRPC, `"{}"` when there is none). It reaches
   `AgentHandlerV2::on_handshake`, whose default ignores it.
2. **As a Configure message** right after the handshake, which the SDK servers
   hand to `AgentHandlerV2::on_configure(config, version)`:
   - **UDS:** message `0x17` with payload
     `{"correlation_id": "...", "config": {...}, "config_version": null}`. The
     agent answers with an `AgentResponse` carrying that `correlation_id`
     (`UdsAgentServerV2` does this): `Allow` accepts, anything else rejects.
     The proxy waits for the longer of the agent's timeout and 5 s.
   - **gRPC:** `ProxyToAgent.configure` (`ConfigureEvent`, `is_initial: true`),
     followed by a `Ping`. The protocol has no reply to a configure event, so
     an agent that rejects it ends the stream (`GrpcAgentServerV2` does this);
     the `Pong` confirms it was handled.

A connection whose agent rejects its configuration, or does not answer in
time, is not used: it counts as a failed connection, the pool keeps retrying
it, and the agent's filters fail open or closed by their `failure-mode`.
Rejections are logged at ERROR. An agent without a `config { }` block is sent
no Configure message.

`on_configure` is therefore called once per connection, several times for
one agent process (once per pooled connection), and again after every
reconnect. It must be idempotent: applying the same configuration again
should not reset state such as rate-limit buckets.

The configuration is sent only when a connection is made; there is no
in-place reconfigure. A reload does not rebuild agents yet (#564), so a
changed `config { }` block takes effect after a restart of the proxy. Once
reloads rebuild changed agents, the new configuration arrives the same way,
on the new agent's connections.

Reverse connections (below) are registered by the agent and are sent no
configuration.

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
    Block { status: u16, body: Option<String>, headers: Option<HashMap<String, String>> },
    Redirect { url: String, status: u16 },
    Challenge { challenge_type: String, params: HashMap<String, String> },
}
```

#### How the proxy answers a decision in the request phases

In the request-headers and request-body phases (streamed or buffered),
every decision but `Allow` stops the request: it is never proxied, and the
proxy answers the client itself.

| Decision | Response |
|----------|----------|
| `Allow` | The request is proxied, with the agent's header changes. |
| `Block` | `status`, with the agent's `body` and `headers`. Without a body, the route's error page for the status, or the default refusal. |
| `Redirect` | `status` with `Location: <url>`. The status must be 301, 302, 303, 307 or 308; any other is answered as 302. A `url` that is not a valid header value is refused with 500. |
| `Challenge` | See below. |

The proxy cannot run a challenge itself, so a `Challenge` fails closed:
the client gets a response built from the challenge's `params` (names
matched case-insensitively), and the upstream is never contacted.

| Param | Effect |
|-------|--------|
| `www-authenticate` | An HTTP authentication challenge: `401 Unauthorized` with this value as the `WWW-Authenticate` header. Without it the status is `403 Forbidden` (CAPTCHA, JavaScript, proof-of-work and other challenges). |
| `body` | The response body, e.g. the challenge page. Without one, the route's error page for the status, or the default refusal. |
| `content-type` | The `Content-Type` of `body`; ignored without a `body`. |

Other params (`token`, `challenge_url`, ...) are not sent to the client;
an agent that wants the client to see them puts them into `body`. The proxy
logs the challenge type (and the param names, not their values) at INFO.

In the response phases, only `Block` is acted on so far; `Redirect` and
`Challenge` there are tracked in zentinelproxy/zentinel#588.

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
