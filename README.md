<div align="center">

<h1 align="center">
  <img src=".github/static/sentinel-mascot.png" alt="sentinel mascot" width="96" />
  <br>
  Sentinel
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
  <a href="https://sentinel.raskell.io/docs">Documentation</a> •
  <a href="https://sentinel.raskell.io/playground/">Playground</a> •
  <a href="https://sentinel.raskell.io/benchmarks/">Benchmarks</a> •
  <a href="https://github.com/raskell-io/sentinel/discussions">Discussions</a> •
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

</div>

---

Sentinel is a high-performance reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora). It provides explicit limits, predictable behavior, and production-grade defaults for environments where operators need to sleep.

## Quick Start

```bash
# Install
curl -fsSL https://getsentinel.raskell.io | sh

# Or via Cargo
cargo install sentinel-proxy
```

Save this as `sentinel.kdl` — it proxies `localhost:8080` to a backend on port `8081`:

```kdl
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
sentinel --config sentinel.kdl
```

More examples: [`config/examples/`](config/examples/) covers API gateways, load balancing, WebSocket, caching, inference routing, and more. Or use the [config builder](https://sentinel.raskell.io/customize/) to generate a config interactively.

## Features

| Feature | Description |
|---------|-------------|
| **KDL Configuration** | Human-readable config with hot reload |
| **Service Types** | Web, API, Static, Builtin, and Inference (LLM/AI) |
| **Load Balancing** | 14+ algorithms: round-robin, consistent hashing, Maglev, P2C, adaptive, and more |
| **ACME** | Automatic TLS certificates via Let's Encrypt with auto-renewal |
| **Agent Protocol** | External agents for WAF, auth, and custom logic with connection pooling |
| **Observability** | Prometheus metrics, structured logging, distributed tracing |

### Inference Gateway

First-class support for LLM/AI workloads: token-based rate limiting, usage budgets, model-based routing with glob patterns (`gpt-4*`, `claude-*`), and guardrails for prompt injection and PII detection. Supports OpenAI, Anthropic, and generic providers out of the box.

## Why Sentinel

Modern proxies accumulate hidden behavior, unbounded complexity, and operational risk that surfaces under stress.

Sentinel takes a different approach:

- **Bounded resources** — Memory limits, queue depths, deterministic timeouts
- **Explicit failure modes** — Fail-open or fail-closed, never ambiguous
- **External extensibility** — Security logic lives in agents, not the core
- **Observable by default** — Every decision is logged and metered

The goal is infrastructure that is **correct, calm, and trustworthy**.

## Design Principles

- **Sleepable operations** — No unbounded resources. No surprise behavior.
- **Security-first** — Every limit and decision is explicit in configuration.
- **Small, stable core** — Innovation lives outside the dataplane, behind contracts.
- **Production correctness** — Features ship only when bounded, observed, and tested.

See [`MANIFESTO.md`](MANIFESTO.md) for the full philosophy.

## Crates

Each crate has its own `docs/` directory with detailed documentation.

| Crate | Description |
|-------|-------------|
| [`sentinel-proxy`](crates/proxy/) | Core reverse proxy built on Pingora |
| [`sentinel-config`](crates/config/) | KDL configuration parsing and validation |
| [`sentinel-agent-protocol`](crates/agent-protocol/) | Agent protocol v1 (legacy) and v2 (current) |
| [`sentinel-common`](crates/common/) | Shared types, errors, and utilities |
| [`wasm-runtime`](crates/wasm-runtime/) | WASM agent runtime using Wasmtime |
| [`playground-wasm`](crates/playground-wasm/) | Browser bindings for the config playground |
| [`sim`](crates/sim/) | WASM-compatible configuration simulator |
| [`stack`](crates/stack/) | All-in-one process manager for proxy and agents |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

**Using Claude Code?** See [`.claude/CLAUDE.md`](.claude/CLAUDE.md) for project context, architecture, and coding rules.

## Community

- 📖 [Documentation](https://sentinel.raskell.io/docs) — Guides, reference, and examples
- 🎮 [Playground](https://sentinel.raskell.io/playground/) — Try the routing engine in your browser (WASM)
- 📊 [Benchmarks](https://sentinel.raskell.io/benchmarks/) — Performance, soak testing, and Envoy comparison
- 💬 [Discussions](https://github.com/raskell-io/sentinel/discussions) — Questions, ideas, show & tell
- 🐛 [Issues](https://github.com/raskell-io/sentinel/issues) — Bug reports and feature requests

## License

Apache 2.0 — See [LICENSE](LICENSE).
