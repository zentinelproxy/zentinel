# Zentinel Agent Protocol

A protocol crate for communication between the Zentinel proxy dataplane and external processing agents (WAF, auth, rate limiting, custom logic).

Inspired by [SPOE](https://www.haproxy.com/blog/extending-haproxy-with-the-stream-processing-offload-engine) (Stream Processing Offload Engine) and [Envoy's ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter), designed for bounded, predictable behavior with strong failure isolation.

## Features

- **Dual Transport Support**: Unix Domain Sockets (default) and gRPC
- **Event-Driven Architecture**: 8 lifecycle event types for request/response processing
- **Connection Pooling**: Built-in `AgentPool` with 4 load balancing strategies
- **Flexible Decisions**: Allow, Block, Redirect, or Challenge requests
- **Header Mutations**: Add, set, or remove headers on requests and responses
- **Body Streaming**: Inspect and mutate request/response bodies chunk by chunk
- **WebSocket Support**: Inspect and filter WebSocket frames
- **Guardrail Inspection**: Built-in support for prompt injection and PII detection
- **Reverse Connections**: Agents can connect to the proxy (NAT traversal)
- **Request Cancellation**: Cancel in-flight requests

## Quick Start

### Implementing an Agent (Server)

```rust
use zentinel_agent_protocol::v2::{
    UdsAgentServerV2, AgentHandlerV2, AgentResponse, Decision,
    RequestHeadersEvent, RequestMetadata, AgentCapabilities,
};
use async_trait::async_trait;

struct MyAgent;

#[async_trait]
impl AgentHandlerV2 for MyAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            handles_request_headers: true,
            ..Default::default()
        }
    }

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
    let server = UdsAgentServerV2::new(
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
use zentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};
use std::time::Duration;

let config = AgentPoolConfig {
    connections_per_agent: 4,
    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
    request_timeout: Duration::from_secs(30),
    ..Default::default()
};

let pool = AgentPool::with_config(config);

// Add agents (transport auto-detected from endpoint)
pool.add_agent("waf", "localhost:50051").await?;       // gRPC
pool.add_agent("auth", "/var/run/auth.sock").await?;   // UDS

// Send requests through the pool
let response = pool.send_request_headers("waf", &headers).await?;
```

## Protocol Overview

| Property | Value |
|----------|-------|
| Protocol Version | 2 |
| Max Message Size | 16 MB (UDS) / 4 MB (gRPC) |
| UDS Message Format | 4-byte big-endian length prefix + 1-byte type prefix + JSON payload |
| gRPC Format | Protocol Buffers over HTTP/2 |

## Event Types

The protocol supports 8 event types covering the full request/response lifecycle:

| Event | Description | Typical Use |
|-------|-------------|-------------|
| `Configure` | The agent's `config { }` block, sent on every connection after the handshake | Agent configuration (see [protocol.md](docs/v2/protocol.md#configuration-delivery)) |
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
- [Protocol Specification](./docs/v2/protocol.md) - Wire format, message types, constraints
- [Client & Server APIs](./docs/v2/api.md) - Using AgentPool, AgentClientV2, and UdsAgentServerV2
- [Connection Pooling](./docs/v2/pooling.md) - Load balancing and connection management
- [Transport Options](./docs/v2/transports.md) - gRPC, UDS, and reverse connections

## Architecture

```
┌─────────────────┐         ┌──────────────────┐
│  Zentinel Proxy │         │  External Agent  │
│   (Dataplane)   │         │   (WAF/Auth/     │
│                 │         │   Custom Logic)  │
│  ┌───────────┐  │  UDS/   │  ┌────────────┐  │
│  │ AgentPool │◄─┼─gRPC───►│  │UdsAgentSrv │  │
│  └───────────┘  │         │  │     V2      │  │
│                 │         │  └──────┬──────┘  │
└─────────────────┘         │  ┌─────▼──────┐  │
                            │  │AgentHandler │  │
                            │  │     V2      │  │
                            │  └────────────┘  │
                            └──────────────────┘
```

See [Architecture & Flow Diagrams](./docs/architecture.md) for detailed diagrams including:
- System architecture with multiple agents
- Request lifecycle flow (sequence diagram)
- Body streaming protocol
- Circuit breaker states
- Multi-agent pipeline

## Reference Implementations

Two reference agents are available as standalone projects:

- **[echo agent](https://github.com/zentinelproxy/zentinel)** (`agents/echo/`) — Adds an `X-Agent-Processed: true` header to all requests. Useful for verifying agent connectivity.
- **[data-masking agent](https://github.com/zentinelproxy/zentinel)** (`agents/data-masking/`) — Masks sensitive data (SSNs, credit cards, emails) in response bodies. Example of body streaming and response transformation.

## Language SDKs

Official SDKs are available for building agents in your preferred language:

| Language | Repository | Installation |
|----------|------------|--------------|
| **Python** | [zentinel-agent-python-sdk](https://github.com/zentinelproxy/zentinel-agent-python-sdk) | `pip install zentinel-agent-sdk` |
| **TypeScript** | [zentinel-agent-typescript-sdk](https://github.com/zentinelproxy/zentinel-agent-typescript-sdk) | `npm install zentinel-agent-sdk` |
| **Go** | [zentinel-agent-go-sdk](https://github.com/zentinelproxy/zentinel-agent-go-sdk) | `go get github.com/zentinelproxy/zentinel-agent-go-sdk` |
| **Rust** | [zentinel-agent-rust-sdk](https://github.com/zentinelproxy/zentinel-agent-rust-sdk) | `zentinel-agent-sdk = "0.1"` |
| **Elixir** | [zentinel-agent-elixir-sdk](https://github.com/zentinelproxy/zentinel-agent-elixir-sdk) | `{:zentinel_agent_sdk, github: "zentinelproxy/zentinel-agent-elixir-sdk"}` |

All SDKs implement the same protocol and provide:
- Simple agent interface with lifecycle hooks
- Fluent decision builder API
- Request/response wrappers with convenience methods
- Typed configuration support
- CLI argument parsing

## License

See the main Zentinel repository for license information.
