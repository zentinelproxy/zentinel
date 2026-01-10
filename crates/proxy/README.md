# Sentinel Proxy

The core dataplane for Sentinel reverse proxy, built on [Cloudflare Pingora](https://github.com/cloudflare/pingora).

## Features

- **High-Performance Proxying**: Built on Pingora for production-grade performance
- **Flexible Routing**: Pattern matching, host-based, header-based, and priority routing
- **Load Balancing**: P2C, least-tokens, consistent hash, and adaptive algorithms
- **Health Checking**: Active (HTTP/TCP/gRPC) and passive health monitoring
- **Rate Limiting**: Local, Redis, and Memcached backends with token bucket algorithm
- **Circuit Breakers**: Scope-aware failure isolation
- **External Agents**: SPOE/ext_proc-inspired processing for WAF, auth, and custom logic
- **Inference Routing**: LLM/AI endpoint management with token-based limits and guardrails
- **TLS Termination**: SNI-based certificate selection, mTLS, OCSP stapling
- **WebSocket Support**: Frame-level inspection per RFC 6455
- **Static File Serving**: Range requests, compression, caching
- **HTTP Caching**: Response caching with stale-while-revalidate
- **Shadow Traffic**: Fire-and-forget request mirroring for canary testing
- **Service Discovery**: Static, DNS, Consul, and Kubernetes backends
- **Observability**: Prometheus metrics, structured logging, OpenTelemetry tracing
- **Hot Reload**: Zero-downtime configuration updates

## Quick Start

```rust
use sentinel_proxy::app::SentinelApp;
use sentinel_config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration
    let config = Config::from_file("sentinel.kdl")?;

    // Create and run the proxy
    let app = SentinelApp::new(config)?;
    app.run().await
}
```

## Architecture Overview

```
                           ┌─────────────────────────────────────────────────┐
                           │              Sentinel Proxy                      │
                           │                                                  │
  Client ──────────────────┼─▶ Listener ──▶ Route Matcher ──▶ Filters        │
  Request                  │        │              │              │           │
                           │        ▼              ▼              ▼           │
                           │   TLS/SNI      Rate Limit      Agent Calls       │
                           │                    │              │              │
                           │                    ▼              ▼              │
                           │              Upstream Pool ◀── Load Balancer    │
                           │                    │                             │
                           │                    ▼                             │
                           │              Health Check                        │
                           │                    │                             │
                           └────────────────────┼─────────────────────────────┘
                                                │
                                                ▼
                                           Backend Server
```

## Module Overview

| Module | Description |
|--------|-------------|
| `proxy` | Core proxy implementing Pingora's `ProxyHttp` trait |
| `routing` | Route matching with path, host, header, and method patterns |
| `upstream` | Load balancing and connection pooling |
| `health` | Active and passive health checking |
| `agents` | External processing integration |
| `inference` | LLM/AI routing with token-based limits |
| `rate_limit` | Request rate limiting |
| `distributed_rate_limit` | Redis-backed distributed rate limiting |
| `scoped_circuit_breaker` | Scope-aware circuit breakers |
| `cache` | HTTP response caching |
| `static_files` | Static file serving with compression |
| `websocket` | WebSocket frame handling |
| `shadow` | Traffic mirroring |
| `discovery` | Service discovery backends |
| `tls` | TLS termination and SNI |
| `logging` | Structured logging |
| `otel` | OpenTelemetry integration |

## Documentation

Detailed documentation is available in the [`docs/`](./docs/) directory:

- [Architecture](./docs/architecture.md) - System design and request flow
- [Modules](./docs/modules.md) - Detailed module documentation
- [Inference](./docs/inference.md) - LLM/AI routing features
- [Agents](./docs/agents.md) - External processing integration
- [Rate Limiting](./docs/rate-limiting.md) - Rate limiting and circuit breakers
- [Examples](./docs/examples.md) - Configuration patterns

## Feature Flags

```toml
[features]
default = []

# Redis-backed distributed rate limiting
distributed-rate-limit = ["redis", "deadpool-redis"]

# Memcached-backed distributed rate limiting
distributed-rate-limit-memcached = ["memcached-rs"]

# OpenTelemetry tracing export
opentelemetry = ["opentelemetry", "opentelemetry-otlp"]

# Kubernetes service discovery
kubernetes = ["kube", "k8s-openapi"]

# Token counting for inference routing
tiktoken = ["tiktoken-rs"]
```

## Performance Characteristics

- **Lock-free hot paths**: Uses `DashMap` and atomic operations
- **Connection pooling**: Per-upstream connection reuse
- **Zero-copy static files**: Memory-mapped files > 10MB
- **Bounded memory**: All queues and caches have size limits
- **Deterministic timeouts**: Every async operation has hard timeout

## Security Features

- **Fail-closed by default**: Security-first failure mode
- **Bounded decompression**: Zip bomb protection with ratio limits
- **Agent isolation**: Circuit breakers prevent cascade failures
- **Rate limiting**: Per-client and per-route request limits
- **GeoIP filtering**: Block or allow by country
- **TLS 1.2+ minimum**: No legacy TLS support

## Minimum Rust Version

Rust 1.92.0 or later (Edition 2021)

## License

See the repository root for license information.
