# Sentinel

> **Security-first reverse proxy built to guard the free web.**

Sentinel is an open-source, high-performance reverse proxy built on Cloudflare's Pingora framework. It emphasizes **predictability**, **transparency**, and **operational simplicity**—infrastructure that lets operators sleep.

## Philosophy (North Star)

Every contribution must align with the [Manifesto](../MANIFESTO.md):

1. **Infrastructure should be calm** — No surprises. Clear limits, predictable timeouts, explainable failure modes.
2. **Security must be explicit** — No magic, no implied policy. Every decision visible and traceable.
3. **The edge is a boundary, not a battleground** — Step in only when necessary, proportionally.
4. **Complexity must be isolated** — Core dataplane stays small. Complex logic lives in external agents.
5. **The web is a commons** — No vendor lock-in, no hidden control planes. Code is readable, forkable, modifiable.
6. **Production correctness beats feature breadth** — Boring reliability over shiny features.

**Before adding anything, ask:**
- Does this introduce ambiguity?
- Can this fail loudly and safely?
- Will this make someone's on-call worse?

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Sentinel Proxy                               │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    Pingora Foundation                            ││
│  │  (async I/O, connection pooling, TLS, HTTP/1.1 & HTTP/2)        ││
│  └─────────────────────────────────────────────────────────────────┘│
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐│
│  │ Routing  │ │  Rate    │ │  Cache   │ │ Filters  │ │   Agent    ││
│  │  Engine  │ │ Limiting │ │  Layer   │ │  Chain   │ │  Manager   ││
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────┬──────┘│
└────────────────────────────────────────────────────────────┼────────┘
                                                             │
                    ┌────────────────────────────────────────┼────────┐
                    │              External Agents            │        │
                    │  ┌─────────┐ ┌─────────┐ ┌─────────┐  │        │
                    │  │   WAF   │ │  Auth   │ │  Rate   │  │◄───────┘
                    │  │  Agent  │ │  Agent  │ │  Limit  │  │
                    │  └─────────┘ └─────────┘ └─────────┘  │
                    └───────────────────────────────────────────────────┘
```

**Key design choice:** Agents are external processes, not compiled into the proxy. This provides crash isolation, independent deployment, and language flexibility.

---

## Crates

Each crate has its own `docs/` directory with detailed documentation. **When making changes to a crate, update its `docs/` accordingly.**

### Core Crates

#### `sentinel-proxy` (`crates/proxy/`)
Main binary and Pingora integration. Implements HTTP handling, routing, filtering, and upstream communication.
- **Key types:** `SentinelProxy`, `ProxyApp`
- **Docs:** `crates/proxy/docs/` — architecture, agents, rate-limiting, inference routing, modules

#### `sentinel-config` (`crates/config/`)
KDL configuration parsing, validation, and schema. Handles all configuration file processing.
- **Key types:** `Config`, `RouteConfig`, `UpstreamConfig`, `ListenerConfig`
- **Docs:** `crates/config/docs/` — KDL format, schema reference, validation rules, examples

#### `sentinel-agent-protocol` (`crates/agent-protocol/`)
Agent communication protocols (v1 legacy and v2 current). Handles UDS, gRPC, and reverse connections.
- **Key types:** `AgentPool`, `AgentClientV2`, `Decision`, `ReverseConnectionListener`
- **Docs:** `crates/agent-protocol/docs/` — v1/ and v2/ protocol specs, API reference, transport options

#### `sentinel-common` (`crates/common/`)
Shared types, utilities, and error handling used across all crates.
- **Key types:** `RequestId`, `Limits`, error types, identifiers
- **Docs:** `crates/common/docs/` — errors, identifiers, limits, observability, patterns

### Supporting Crates

| Crate | Path | Purpose |
|-------|------|---------|
| `playground-wasm` | `crates/playground-wasm/` | WASM module for web playground (config validation) |
| `wasm-runtime` | `crates/wasm-runtime/` | WASM agent runtime using Wasmtime |
| `sim` | `crates/sim/` | Simulation and testing utilities |
| `stack` | `crates/stack/` | Integration test harness |

### Crate Dependencies

```
sentinel-proxy
├── sentinel-config
├── sentinel-agent-protocol
├── sentinel-common
└── pingora (external)

sentinel-config
└── sentinel-common

sentinel-agent-protocol
└── sentinel-common
```

**Dependency rules:**
- `proxy` may depend on all internal crates
- `config` and `agent-protocol` depend only on `common`
- `common` has no internal dependencies

---

## Key Concepts

### Request Lifecycle

1. **Accept** — TCP connection established, TLS handshake (if HTTPS)
2. **Parse** — HTTP request parsed, headers extracted
3. **Route** — Priority-based matching, LRU cached
4. **Filter** — Pre-upstream filters, agent hooks
5. **Upstream** — Load-balanced backend selection, request forwarding
6. **Response** — Response filters, caching, compression
7. **Log** — Access logging, metrics emission

### Agent Protocol

Two versions supported:
- **v1 (Legacy)** — JSON over UDS, simple request/response
- **v2 (Current)** — Binary UDS, gRPC, connection pooling, streaming, cancellation

Agents handle: WAF, authentication, rate limiting, custom policy, request validation.

### Configuration (KDL)

Human-readable configuration language. Key blocks:
- `system` — Workers, limits, timeouts
- `listeners` — Network endpoints, TLS
- `routes` — Request matching, forwarding
- `upstreams` — Backend pools, health checks
- `agents` — External agent configuration

---

## Rules

| File | Purpose |
|------|---------|
| [rust-standards.md](rules/rust-standards.md) | Rust coding standards (APIs, error handling, async) |
| [project.md](rules/project.md) | Sentinel-specific context and architecture |
| [patterns.md](rules/patterns.md) | Code patterns (Pingora, agents, config) |
| [workflow.md](rules/workflow.md) | Commands, testing, releases |

---

## Quick Reference

### Common Commands

```bash
# Development
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# Run locally
cargo run --bin sentinel -- --config config/sentinel.kdl

# Run specific tests
cargo test -p sentinel-proxy test_name
cargo test -p sentinel-config --lib

# Benchmarks
cargo bench -p sentinel-proxy
```

### Key Files

| Path | Purpose |
|------|---------|
| `crates/proxy/src/lib.rs` | Main proxy implementation |
| `crates/config/src/lib.rs` | Configuration parsing entry |
| `crates/agent-protocol/src/v2/` | Agent protocol v2 implementation |
| `config/sentinel.kdl` | Default configuration |
| `tests/` | Integration tests |

### Documentation

**When making meaningful changes, documentation must be updated in multiple places:**

#### 1. Crate-level docs (this repo)
Each crate has a `docs/` directory for technical reference:
```
crates/proxy/docs/           # Architecture, routing, filtering
crates/config/docs/          # KDL format, schema, validation
crates/agent-protocol/docs/  # Protocol v1/, v2/, transports
crates/common/docs/          # Shared types, errors, patterns
```

**Update when:** Changing APIs, adding features, modifying behavior.

#### 2. Documentation site (separate repo)
**Repo:** `github.com/raskell-io/sentinel.raskell.io-docs`
**Live:** https://sentinel.raskell.io/docs

Contains user-facing documentation: getting started, configuration guides, examples, operations, deployment.

**Update when:**
- New user-visible features
- Configuration option changes
- New examples or use cases
- Breaking changes

**Structure:**
```
content/
├── getting-started/    # Installation, quick start
├── concepts/           # Architecture, routing, request lifecycle
├── configuration/      # All config options
├── agents/             # Agent protocol v1/, v2/
├── examples/           # Production-ready configs
├── operations/         # Security, monitoring, troubleshooting
├── deployment/         # Docker, K8s, systemd
└── reference/          # CLI, env vars, error codes
```

#### 3. Design documents (this repo)
- [AGENT_PROTOCOL_2.0.md](AGENT_PROTOCOL_2.0.md) — Agent protocol design and roadmap

#### External Links
- **Marketing site:** https://sentinel.raskell.io
- **Documentation:** https://sentinel.raskell.io/docs

---

## Contributing Checklist

Before submitting code:

**Code Quality:**
- [ ] Aligns with [Manifesto](../MANIFESTO.md) principles
- [ ] Has bounded resources (no unbounded growth)
- [ ] Fails loudly and safely
- [ ] Is observable (metrics, logs, traces)
- [ ] Has tests (unit + integration where applicable)
- [ ] Passes `cargo clippy -- -D warnings`
- [ ] Passes `cargo fmt --check`

**Documentation:**
- [ ] Crate `docs/` updated if API or behavior changed
- [ ] Docs site (`sentinel.raskell.io-docs`) updated if user-visible changes
- [ ] Code comments for non-obvious logic
- [ ] Public API has doc comments with `# Errors` section
