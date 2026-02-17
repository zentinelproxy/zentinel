# Agent Protocol Documentation

This directory contains documentation for the Zentinel Agent Protocol, which defines how the proxy communicates with external processing agents.

## Protocol Versions

### [v2 (Current)](./v2/) - Agent Protocol 2.0

The v2 protocol is the recommended version for new deployments. It provides:

- **Multiple transports**: gRPC, Binary UDS, and Reverse Connections
- **Connection pooling**: Built-in `AgentPool` with load balancing
- **Request cancellation**: Cancel in-flight requests
- **Enhanced observability**: Metrics export in Prometheus format
- **Reverse connections**: Agents can connect to the proxy (NAT traversal)

| Document | Description |
|----------|-------------|
| [protocol.md](./v2/protocol.md) | Wire protocol specification |
| [api.md](./v2/api.md) | Client and server APIs |
| [pooling.md](./v2/pooling.md) | Connection pooling and load balancing |
| [transports.md](./v2/transports.md) | Transport options (gRPC, UDS, Reverse) |
| [reverse-connections.md](./v2/reverse-connections.md) | Reverse connection setup |
| [performance-roadmap.md](./performance-roadmap.md) | Performance bottlenecks and optimization plans |

### [v1 (Legacy)](./v1/) - Agent Protocol 1.0

The v1 protocol is still supported for backwards compatibility. Existing v1 agents will continue to work with the proxy.

| Document | Description |
|----------|-------------|
| [protocol.md](./v1/protocol.md) | Wire protocol specification |
| [api.md](./v1/api.md) | Client and server APIs |
| [examples.md](./v1/examples.md) | Example agent implementations |
| [errors.md](./v1/errors.md) | Error handling |
| [handler.md](./v1/handler.md) | Handler trait documentation |

## Architecture

See [architecture.md](./architecture.md) for system architecture diagrams covering both v1 and v2.

## Version Comparison

| Feature | v1 | v2 |
|---------|----|----|
| Transport | UDS (JSON), gRPC | UDS (binary), gRPC, Reverse |
| Connection pooling | No | Yes (4 strategies) |
| Bidirectional streaming | Limited | Full support |
| Metrics export | No | Prometheus format |
| Config push | No | Yes |
| Health tracking | Basic | Comprehensive (cached) |
| Flow control | No | Yes |
| Request cancellation | No | Yes |
| Max message size | 10 MB | 16 MB (UDS) |
| Lock-free agent lookup | N/A | Yes (DashMap) |
| Hot-path sync points | N/A | 2 per request |

## Migration Guide

To migrate from v1 to v2:

```rust
// Before (v1)
use zentinel_agent_protocol::AgentClient;

let client = AgentClient::unix_socket(
    "proxy",
    "/tmp/agent.sock",
    Duration::from_secs(5),
).await?;

let response = client.send_event(EventType::RequestHeaders, &event).await?;

// After (v2 with pooling)
use zentinel_agent_protocol::v2::AgentPool;

let pool = AgentPool::new();
pool.add_agent("agent", "/tmp/agent.sock").await?;

let response = pool.send_request_headers("agent", &headers).await?;
```

For detailed migration instructions, see the [RELEASE_NOTES_v0.3.0.md](../../../RELEASE_NOTES_v0.3.0.md).

## Quick Start

### v2 (Recommended)

```rust
use zentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};
use std::time::Duration;

// Create a connection pool
let config = AgentPoolConfig {
    connections_per_agent: 4,
    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
    request_timeout: Duration::from_secs(30),
    ..Default::default()
};

let pool = AgentPool::with_config(config);

// Add agents (transport auto-detected)
pool.add_agent("waf", "localhost:50051").await?;       // gRPC
pool.add_agent("auth", "/var/run/auth.sock").await?;   // UDS

// Send requests
let response = pool.send_request_headers("waf", &headers).await?;
```

### v1 (Legacy)

```rust
use zentinel_agent_protocol::AgentClient;
use std::time::Duration;

let client = AgentClient::unix_socket(
    "proxy-client",
    "/tmp/agent.sock",
    Duration::from_secs(5),
).await?;

let response = client.send_event(EventType::RequestHeaders, &event).await?;
```

## Related Documentation

- [Release Notes v0.3.0](../../../RELEASE_NOTES_v0.3.0.md) - Agent Protocol 2.0 announcement
- [Zentinel CLAUDE.md](../../../.claude/CLAUDE.md) - Overall project documentation
- [Performance Roadmap](./performance-roadmap.md) - Bottleneck analysis and optimization plans
