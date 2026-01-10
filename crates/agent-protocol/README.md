# Sentinel Agent Protocol

A protocol crate for communication between the Sentinel proxy dataplane and external processing agents (WAF, auth, rate limiting, custom logic).

Inspired by [SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine) (Stream Processing Offload Engine) and [Envoy's ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter), designed for bounded, predictable behavior with strong failure isolation.

## Features

- **Dual Transport Support**: Unix Domain Sockets (default) and gRPC
- **Event-Driven Architecture**: 8 lifecycle event types for request/response processing
- **Flexible Decisions**: Allow, Block, Redirect, or Challenge requests
- **Header Mutations**: Add, set, or remove headers on requests and responses
- **Body Streaming**: Inspect and mutate request/response bodies chunk by chunk
- **WebSocket Support**: Inspect and filter WebSocket frames
- **Guardrail Inspection**: Built-in support for prompt injection and PII detection
- **Reference Implementations**: Echo and Denylist agents included

## Quick Start

### Implementing an Agent (Server)

```rust
use sentinel_agent_protocol::{
    AgentServer, AgentHandler, AgentResponse, Decision,
    RequestHeadersEvent, RequestMetadata,
};
use async_trait::async_trait;

struct MyAgent;

#[async_trait]
impl AgentHandler for MyAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Block requests to /admin
        if event.uri.starts_with("/admin") {
            return AgentResponse::block(403, "Forbidden");
        }
        AgentResponse::default_allow()
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = AgentServer::new(
        "my-agent",
        "/tmp/my-agent.sock",
        Box::new(MyAgent),
    );
    server.run().await?;
    Ok(())
}
```

### Connecting from the Proxy (Client)

```rust
use sentinel_agent_protocol::{AgentClient, EventType, RequestHeadersEvent};
use std::time::Duration;

// Unix socket transport
let mut client = AgentClient::unix_socket(
    "proxy",
    "/tmp/my-agent.sock",
    Duration::from_secs(5),
).await?;

// Or gRPC transport
let mut client = AgentClient::grpc(
    "proxy",
    "http://localhost:50051",
    Duration::from_secs(5),
).await?;

// Send an event
let response = client.send_event(EventType::RequestHeaders, &event).await?;
```

## Protocol Overview

| Property | Value |
|----------|-------|
| Protocol Version | 1 |
| Max Message Size | 10 MB |
| UDS Message Format | 4-byte big-endian length prefix + JSON payload |
| gRPC Format | Protocol Buffers over HTTP/2 |

## Event Types

The protocol supports 8 event types covering the full request/response lifecycle:

| Event | Description | Typical Use |
|-------|-------------|-------------|
| `Configure` | Initial handshake with agent capabilities | Feature negotiation |
| `RequestHeaders` | Request headers received | Auth, routing, early blocking |
| `RequestBodyChunk` | Request body chunk (streaming) | Body inspection, transformation |
| `ResponseHeaders` | Response headers from upstream | Header modification |
| `ResponseBodyChunk` | Response body chunk (streaming) | Response transformation |
| `RequestComplete` | Request fully processed | Logging, cleanup |
| `WebSocketFrame` | WebSocket frame received | Message filtering |
| `GuardrailInspect` | Content inspection request | Prompt injection, PII detection |

## Decision Types

Agents respond with one of four decisions:

| Decision | Description | Fields |
|----------|-------------|--------|
| `Allow` | Continue processing | - |
| `Block` | Reject the request | `status`, `body`, `headers` |
| `Redirect` | Redirect to another URL | `url`, `status` (301/302/307/308) |
| `Challenge` | Issue a challenge | `challenge_type`, `params` |

## Documentation

Detailed documentation is available in the [`docs/`](./docs/) directory:

- [Architecture & Flow Diagrams](./docs/architecture.md) - System architecture, request lifecycle, component interactions
- [Protocol Specification](./docs/protocol.md) - Wire format, message types, constraints
- [Agent Handler Interface](./docs/handler.md) - All hook methods and their semantics
- [Client & Server APIs](./docs/api.md) - Using AgentClient and AgentServer
- [Error Handling](./docs/errors.md) - Error types and recovery strategies
- [Examples](./docs/examples.md) - Common patterns and reference implementations

## Architecture

```
┌─────────────────┐         ┌─────────────────┐
│  Sentinel Proxy │         │  External Agent │
│   (Dataplane)   │         │   (WAF/Auth/    │
│                 │         │   Custom Logic) │
│  ┌───────────┐  │  UDS/   │  ┌───────────┐  │
│  │AgentClient│◄─┼─gRPC───►│  │AgentServer│  │
│  └───────────┘  │         │  └─────┬─────┘  │
│                 │         │        │        │
└─────────────────┘         │  ┌─────▼─────┐  │
                            │  │AgentHandler│ │
                            │  └───────────┘  │
                            └─────────────────┘
```

See [Architecture & Flow Diagrams](./docs/architecture.md) for detailed diagrams including:
- System architecture with multiple agents
- Request lifecycle flow (sequence diagram)
- Body streaming protocol
- Circuit breaker states
- Multi-agent pipeline

## Reference Implementations

Two reference agents are included for testing and as implementation examples:

### EchoAgent

Adds an `X-Agent-Processed: true` header to all requests. Useful for verifying agent connectivity.

```rust
use sentinel_agent_protocol::{AgentServer, EchoAgent};

let server = AgentServer::new("echo", "/tmp/echo.sock", Box::new(EchoAgent));
```

### DenylistAgent

Blocks requests matching configured paths or client IPs.

```rust
use sentinel_agent_protocol::{AgentServer, DenylistAgent};

let agent = DenylistAgent::new(
    vec!["/admin".to_string(), "/internal".to_string()],
    vec!["10.0.0.1".to_string()],
);
let server = AgentServer::new("denylist", "/tmp/denylist.sock", Box::new(agent));
```

## License

See the main Sentinel repository for license information.
