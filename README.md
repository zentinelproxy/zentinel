<div align="center">

<h1 align="center">
  <img src=".github/static/zentinel-mascot.png" alt="zentinel mascot" width="96" />
  <br>
  Zentinel
</h1>

<p align="center">
  <em>A security-first reverse proxy built to guard the free web.</em><br>
  <em>Sleepable ops at the edge.</em>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/">
    <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/cloudflare/pingora">
    <img alt="Pingora" src="https://img.shields.io/badge/Built%20on-Pingora-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="https://zentinelproxy.io/docs/">Documentation</a> •
  <a href="https://zentinelproxy.io/playground/">Playground</a> •
  <a href="https://zentinelproxy.io/benchmarks/">Benchmarks</a> •
  <a href="https://github.com/zentinelproxy/zentinel/discussions">Discussions</a> •
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

</div>

---

Zentinel is a high-performance reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It provides explicit limits, predictable behavior, and production-grade defaults for environments where operators need to sleep.

**Performance:** Lowest p99 latency in [benchmarks](https://zentinelproxy.io/benchmarks/) against Envoy, HAProxy, Nginx, and Caddy. 1M-request soak tests with 99.95% success rate and zero memory leaks. Pure Rust WAF engine processes clean traffic at 912K req/s — 30x faster than the C++ ModSecurity reference.

## Status

Production-ready core (proxy, routing, TLS, caching, load balancing). Agents are individually versioned — WAF, Auth, and AI Gateway are stable; others are beta or alpha. See [zentinelproxy.io/agents](https://zentinelproxy.io/agents/) for per-agent status.

## Quick Start

```bash
# Install
curl -fsSL https://get.zentinelproxy.io | sh

# Or via Cargo
cargo install zentinel-proxy

# Or via Docker
docker run -v $(pwd)/zentinel.kdl:/etc/zentinel/zentinel.kdl \
  ghcr.io/zentinelproxy/zentinel --config /etc/zentinel/zentinel.kdl
```

Save this as `zentinel.kdl` — it proxies `localhost:8080` to a backend on port `8081`:

```kdl
system {
    worker-threads 0  // auto-detect CPU cores
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

routes {
    route "default" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:8081"
    }
}
```

```bash
# Run
zentinel --config zentinel.kdl

# Validate config without starting
zentinel test --config zentinel.kdl
```

More examples: [`config/examples/`](config/examples/) covers API gateways, load balancing, WebSocket, caching, inference routing, and more. Or use the [config builder](https://zentinelproxy.io/customize/) to generate a config interactively.

## Features

| Feature | Description |
|---------|-------------|
| **Service Types** | Web, API, Static, Builtin, and Inference (LLM/AI) |
| **Load Balancing** | 14 algorithms: round-robin, weighted, least connections, Maglev, Peak EWMA, and more |
| **Security** | TLS/mTLS, rate limiting, GeoIP filtering, WAF, zip bomb protection |
| **Agent Protocol** | External agents for WAF, auth, and custom logic — crash-isolated, any language |
| **HTTP Caching** | Pingora-based response caching with stampede prevention and S3-FIFO + TinyLFU eviction |
| **WebSocket Proxying** | RFC 6455 compliant with frame inspection and traffic mirroring |
| **Observability** | Prometheus metrics, structured logging, OpenTelemetry tracing |
| **Hot Reload** | Zero-downtime config updates via SIGHUP with validation and atomic swap |

See the full feature breakdown at [zentinelproxy.io/features](https://zentinelproxy.io/features/).

### Use Cases

- **Reverse Proxy** — TLS termination, static file serving, compression, and security headers for web applications
- **API Gateway** — Versioned routing, JWT/API key auth, per-client rate limiting, and JSON error responses
- **Load Balancer** — Weighted traffic distribution, health checks, circuit breakers, and blue-green/canary deployments
- **Inference Gateway** — Token-based rate limiting, model routing with glob patterns (`gpt-4*`, `claude-*`), prompt injection detection, and PII filtering for OpenAI, Anthropic, and generic LLM providers
- **WebSocket Gateway** — Persistent connection proxying with frame inspection, message rate limiting, and session affinity
- **Security Gateway** — WAF, GeoIP filtering, mTLS, and composable agent pipelines for custom security logic

Example configs for each: [`config/examples/`](config/examples/)

## Why Zentinel

Modern proxies accumulate hidden behavior, unbounded complexity, and operational risk that surfaces under stress. Zentinel takes a different approach:

- **Bounded resources** — Memory limits, queue depths, deterministic timeouts. No surprise behavior.
- **Explicit failure modes** — Fail-open or fail-closed per route, never ambiguous.
- **External extensibility** — Security logic lives in agents, not the core. Small, stable dataplane.
- **Observable by default** — Every decision is logged and metered. Features ship only when bounded, observed, and tested.

The goal is infrastructure that is **correct, calm, and trustworthy**. See [`MANIFESTO.md`](MANIFESTO.md) for the full philosophy.

## Agents

Zentinel's security and extensibility lives in **agents** — external processes that hook into every request phase. Agents are crash-isolated from the proxy, independently deployable, and can be written in any language.

Agent SDKs: [Rust](https://github.com/zentinelproxy/zentinel-agent-rust-sdk) · [Go](https://github.com/zentinelproxy/zentinel-agent-go-sdk) · [Python](https://github.com/zentinelproxy/zentinel-agent-python-sdk) · [TypeScript](https://github.com/zentinelproxy/zentinel-agent-typescript-sdk) · [Elixir](https://github.com/zentinelproxy/zentinel-agent-elixir-sdk) · [Kotlin](https://github.com/zentinelproxy/zentinel-agent-kotlin-sdk) · [Haskell](https://github.com/zentinelproxy/zentinel-agent-haskell-sdk)

| Agent | Description |
|-------|-------------|
| [WAF](https://github.com/zentinelproxy/zentinel-agent-waf) | Pure Rust WAF — 200+ detection rules, ML-powered anomaly scoring, zero C dependencies |
| [AI Gateway](https://github.com/zentinelproxy/zentinel-agent-ai-gateway) | Prompt injection detection, jailbreak prevention, PII filtering for LLM APIs |
| [Policy](https://github.com/zentinelproxy/zentinel-agent-policy) | Multi-engine policy evaluation (Rego/OPA and Cedar) — written in Haskell |
| [Auth](https://github.com/zentinelproxy/zentinel-agent-auth) | JWT, OIDC, SAML, mTLS, API keys with Cedar-based fine-grained authorization |
| [Chaos](https://github.com/zentinelproxy/zentinel-agent-chaos) | Latency injection, error simulation, connection resets with safety guardrails |
| [Lua](https://github.com/zentinelproxy/zentinel-agent-lua) | Sandboxed Lua scripting with VM pooling, hot-reload, and resource limits |
| [ZentinelSec](https://github.com/zentinelproxy/zentinel-agent-zentinelsec) | Pure Rust ModSecurity — OWASP CRS-compatible SecLang parser, zero C dependencies |
| [WebSocket Inspector](https://github.com/zentinelproxy/zentinel-agent-websocket-inspector) | Content filtering, JSON/MessagePack validation, and rate limiting for WebSocket frames |
| [MQTT Gateway](https://github.com/zentinelproxy/zentinel-agent-mqtt-gateway) | IoT protocol security with topic ACLs, auth, and payload inspection |

Browse all 25+ agents at [zentinelproxy.io/agents](https://zentinelproxy.io/agents/).

<details>
<summary><strong>Crates</strong></summary>

Each crate has its own `docs/` directory with detailed documentation.

| Crate | Description |
|-------|-------------|
| [`zentinel-proxy`](crates/proxy/) | Core reverse proxy built on Pingora |
| [`zentinel-config`](crates/config/) | KDL configuration parsing and validation |
| [`zentinel-agent-protocol`](crates/agent-protocol/) | Agent protocol v1 (legacy) and v2 (current) |
| [`zentinel-common`](crates/common/) | Shared types, errors, and utilities |
| [`wasm-runtime`](crates/wasm-runtime/) | WASM agent runtime using Wasmtime |
| [`playground-wasm`](crates/playground-wasm/) | Browser bindings for the config playground |
| [`sim`](crates/sim/) | WASM-compatible configuration simulator |
| [`stack`](crates/stack/) | All-in-one process manager for proxy and agents |

</details>

## Control Plane

[**zentinel-control-plane**](https://github.com/zentinelproxy/zentinel-control-plane) — Fleet management for Zentinel proxies, built with Elixir/Phoenix. Centralized configuration, rolling deploys, and real-time observability across your Zentinel instances.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

**Using Claude Code?** See [`.claude/CLAUDE.md`](.claude/CLAUDE.md) for project context, architecture, and coding rules.

## Community

- 📖 [Documentation](https://zentinelproxy.io/docs) — Guides, reference, and examples
- 🎮 [Playground](https://zentinelproxy.io/playground/) — Try the routing engine in your browser (WASM)
- 📊 [Benchmarks](https://zentinelproxy.io/benchmarks/) — Performance, soak testing, and Envoy comparison
- 💬 [Discussions](https://github.com/zentinelproxy/zentinel/discussions) — Questions, ideas, show & tell
- 🐛 [Issues](https://github.com/zentinelproxy/zentinel/issues) — Bug reports and feature requests

## License

Apache 2.0 — See [LICENSE](LICENSE).
