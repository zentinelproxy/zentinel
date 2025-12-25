# Sentinel Agent Ecosystem

Sentinel uses an external processing model where agents run as separate processes and communicate with the proxy over Unix domain sockets. This architecture provides isolation, independent versioning, and allows the community to create and share agents.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Sentinel Proxy                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Agent Client                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │    │
│  │  │   Echo      │  │  Rate Limit │  │    WAF      │      │    │
│  │  │   Client    │  │   Client    │  │   Client    │      │    │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘      │    │
│  └─────────┼────────────────┼────────────────┼─────────────┘    │
└────────────┼────────────────┼────────────────┼──────────────────┘
             │ UDS            │ UDS            │ UDS
             ▼                ▼                ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │  Echo Agent  │ │ RateLimit    │ │  WAF Agent   │
      │  (built-in)  │ │   Agent      │ │              │
      └──────────────┘ └──────────────┘ └──────────────┘
```

## Agent Types

### Built-in Agent

**Echo Agent** - A reference implementation included in the Sentinel monorepo for testing and learning.

- Location: `agents/echo/`
- Purpose: Testing, development, and as a template for new agents
- Events: `request_headers`, `response_headers`

### Community Agents

Additional agents are maintained as separate repositories:

| Agent | Description | Repository |
|-------|-------------|------------|
| Rate Limiter | Token bucket rate limiting | `github.com/raskell-io/sentinel-agent-ratelimit` |
| Denylist | IP/path/header blocking | `github.com/raskell-io/sentinel-agent-denylist` |
| WAF | ModSecurity/CRS integration | `github.com/raskell-io/sentinel-agent-waf` |

*Check [sentinel.raskell.io](https://sentinel.raskell.io) for the full registry.*

## Creating Your Own Agent

### Quick Start with cargo-generate

The fastest way to create a new agent:

```bash
# Install cargo-generate if you haven't already
cargo install cargo-generate

# Generate a new agent from the template
cargo generate --git https://github.com/raskell-io/sentinel --path agent-template

# Follow the prompts:
#   Project Name: my-awesome-agent
#   Description: My custom Sentinel agent
```

This creates a fully functional agent with:
- Proper project structure
- CI/CD workflows
- Registry manifest (`sentinel-agent.toml`)
- Example implementation
- Tests

### Manual Setup

If you prefer to set up manually, add these dependencies:

```toml
[dependencies]
sentinel-agent-protocol = "0.1"
sentinel-common = "0.1"
tokio = { version = "1.40", features = ["full"] }
tracing = "0.1"
```

Implement the `AgentHandler` trait:

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResult, Decision, Mutations,
    RequestHeadersEvent, ResponseHeadersEvent,
};

pub struct MyAgent;

#[async_trait::async_trait]
impl AgentHandler for MyAgent {
    async fn on_request_headers(
        &self,
        event: RequestHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        // Your logic here
        Ok((Decision::Allow, Mutations::default()))
    }

    async fn on_response_headers(
        &self,
        event: ResponseHeadersEvent,
    ) -> AgentResult<(Decision, Mutations)> {
        Ok((Decision::Allow, Mutations::default()))
    }
}
```

## Agent Protocol

### Events

Agents can subscribe to the following events:

| Event | Description | Use Cases |
|-------|-------------|-----------|
| `request_headers` | Request headers received | Auth, rate limiting, routing decisions |
| `request_body` | Request body chunks | WAF inspection, content validation |
| `response_headers` | Response headers from upstream | Header manipulation, caching decisions |
| `response_body` | Response body chunks | Content filtering, transformation |
| `request_complete` | Request fully processed | Logging, metrics |

### Decisions

Agents return one of these decisions:

| Decision | Description |
|----------|-------------|
| `Allow` | Continue processing the request |
| `Block` | Reject the request (returns 403 by default) |
| `Redirect` | Redirect to another URL |
| `Challenge` | Present a challenge (e.g., CAPTCHA) |

### Mutations

Agents can mutate requests/responses:

```rust
let mut mutations = Mutations::default();

// Add or replace headers
mutations.add_header("X-Custom-Header", "value");
mutations.replace_header("Content-Type", "application/json");

// Remove headers
mutations.remove_header("X-Unwanted-Header");

// Set routing metadata (for internal use)
mutations.set_metadata("route-override", "special-backend");
```

## Configuration

### Proxy Configuration

Configure agents in your Sentinel config (`config.kdl`):

```kdl
agents {
    agent "my-agent" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/my-agent.sock"
        }
        events ["request_headers"]
        timeout-ms 100
        failure-mode "open"  // or "closed"
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        agents ["my-agent"]
    }
}
```

### Agent Configuration

Agents typically accept configuration via:

1. **Command-line arguments**
2. **Environment variables**
3. **Configuration files** (YAML, TOML, etc.)

Example:

```bash
my-agent \
  --socket /var/run/sentinel/my-agent.sock \
  --config /etc/sentinel/my-agent.yaml \
  --log-level debug
```

## Registry Manifest

Every agent should include a `sentinel-agent.toml` manifest:

```toml
[agent]
name = "my-awesome-agent"
version = "0.1.0"
description = "Does awesome things with requests"
authors = ["Your Name <you@example.com>"]
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourname/my-awesome-agent"

[protocol]
version = "0.1"
events = ["request_headers", "response_headers"]

[compatibility]
sentinel-proxy = ">=0.1.0"
sentinel-agent-protocol = "0.1"

[registry]
homepage = "https://example.com/my-agent"
documentation = "https://docs.example.com/my-agent"
keywords = ["sentinel", "agent", "awesome"]
categories = ["custom"]
```

## Best Practices

### Performance

1. **Keep processing fast** - Agents add latency to every request
2. **Use async I/O** - Never block the event loop
3. **Pre-compile patterns** - Compile regexes and patterns at startup
4. **Limit body inspection** - Only inspect bodies when necessary

### Reliability

1. **Handle timeouts gracefully** - The proxy will timeout slow agents
2. **Fail safely** - Consider `failure-mode: "open"` for non-critical agents
3. **Log appropriately** - Use structured logging with trace IDs
4. **Monitor metrics** - Export Prometheus metrics for observability

### Security

1. **Validate all input** - Never trust data from the proxy
2. **Minimize dependencies** - Fewer deps = smaller attack surface
3. **Keep secrets secure** - Use environment variables, not config files
4. **Audit regularly** - Run `cargo audit` in CI

## Deploying Agents

### Docker

Build a container image for your agent:

```dockerfile
FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/my-agent /usr/local/bin/
USER nobody
ENTRYPOINT ["my-agent"]
```

### Systemd

Create a service file:

```ini
[Unit]
Description=My Sentinel Agent
After=network.target

[Service]
Type=simple
User=sentinel
ExecStart=/usr/local/bin/my-agent --socket /var/run/sentinel/my-agent.sock
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Kubernetes

Deploy as a sidecar or DaemonSet alongside Sentinel proxy.

## Testing

### Unit Tests

Test your handler logic in isolation:

```rust
#[tokio::test]
async fn test_blocks_bad_requests() {
    let agent = MyAgent::new();
    let event = RequestHeadersEvent {
        headers: vec![("x-bad-header".to_string(), "evil".to_string())],
        ..Default::default()
    };

    let (decision, _) = agent.on_request_headers(event).await.unwrap();
    assert_eq!(decision, Decision::Block);
}
```

### Integration Tests

Test with the actual protocol:

```bash
# Start your agent
./target/debug/my-agent --socket /tmp/test.sock &

# Send test requests via the proxy
curl -H "X-Test: true" http://localhost:8080/test
```

## Troubleshooting

### Agent not responding

1. Check socket permissions
2. Verify agent is running: `ps aux | grep my-agent`
3. Check logs: `journalctl -u my-agent`

### High latency

1. Profile agent code
2. Check for blocking I/O
3. Review timeout configuration

### Memory issues

1. Limit body buffering
2. Use streaming where possible
3. Profile with `cargo flamegraph`

## Resources

- [Agent Protocol Reference](./AGENT_PROTOCOL.md)
- [Agent Development Guide](./AGENT_DEVELOPMENT.md)
- [Example Agents](https://github.com/raskell-io?q=sentinel-agent)
- [Sentinel Discord](https://discord.gg/sentinel)
