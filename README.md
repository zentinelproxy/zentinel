<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">A security-first reverse proxy built to guard the free web</h3>

<p align="center">A reverse proxy on Cloudflare Pingora with explicit limits, predictable failure modes and security logic in crash-isolated agents, for operators who want to sleep.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.99%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://zentinelproxy.io">Website</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://zentinelproxy.io/playground/">Playground</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

Zentinel is a reverse proxy built on [Cloudflare Pingora](https://github.com/cloudflare/pingora).
It ships bounded resources, deterministic timeouts and an explicit fail-open or
fail-closed choice per route, and keeps parsing-heavy or risky security logic
(WAF, auth, policy) out of the dataplane in external agents, so a buggy agent
cannot take the proxy down with it.

In the [benchmarks on zentinelproxy.io](https://zentinelproxy.io/benchmarks/)
Zentinel had the lowest p99 of five proxies (Zentinel, Envoy, HAProxy, Nginx,
Caddy) at 10,000 req/s, and a 1-hour, 1,000,000-request soak test finished with
a 99.95% success rate and no memory leak detected.

<p align="center">
  <img src=".github/static/demo.gif" alt="Zentinel demo: install, configure, run" width="720" />
</p>

The core (proxy, routing, TLS, caching, load balancing) is production-ready.
Agents are versioned separately; each one's status is on its
[registry page](https://registry.zentinelproxy.io/).

## Quick start

```bash
curl -fsSL https://get.zentinelproxy.io | sh
```

Save this as `zentinel.kdl`. It proxies `localhost:8080` to a backend on port `8081`:

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
zentinel test -c zentinel.kdl   # validate the config and exit
zentinel -c zentinel.kdl        # run
```

The `system` block is required. More examples in [`config/examples/`](config/examples/)
(API gateway, load balancing, WebSocket, caching, inference routing, ACME,
namespaces and more), or build a config interactively with the
[config builder](https://zentinelproxy.io/customize/).

## Install

```bash
# Install script (binary only)
curl -fsSL https://get.zentinelproxy.io | sh

# Install and start as a systemd service (Linux, root or sudo)
curl -fsSL https://get.zentinelproxy.io | sh -s -- --enable-service

# From crates.io (the crate is zentinel-proxy, the binary is zentinel).
# --locked builds with the tested dependency versions; without it a fresh
# resolve can pick tokio 1.54, which the current Pingora fork cannot run on (#624).
cargo install --locked zentinel-proxy

# Docker
docker run -p 8080:8080 -v $(pwd)/zentinel.kdl:/etc/zentinel/zentinel.kdl \
  ghcr.io/zentinelproxy/zentinel -c /etc/zentinel/zentinel.kdl
```

On systemd hosts the install script also writes `/etc/systemd/system/zentinel.service`,
a sysusers snippet and a starter config at `/etc/zentinel/zentinel.kdl`.
Enabling and starting the service is opt-in (`--enable-service`). See
[`crates/proxy/docs/deployment.md`](crates/proxy/docs/deployment.md).

## Configuration

Configuration is KDL. `zentinel test -c <file>` parses and validates it and
rejects unknown keys, so a typo fails loudly instead of being ignored.

**Proxying to an HTTPS backend?** Add a `tls` block to the upstream. Without it,
Zentinel connects with plaintext HTTP regardless of the port.

```kdl
upstreams {
    upstream "backend" {
        target "api.example.com:443"
        tls {
            sni "api.example.com"
        }
    }
}
```

Full reference: [docs.zentinelproxy.io](https://docs.zentinelproxy.io/).

## Features

| Feature | What it does |
|---|---|
| Service types | `web`, `api`, `static`, `builtin` and `inference` (LLM/AI) routes |
| Load balancing | 14 algorithms, including round-robin, weighted, least connections, consistent hash, Maglev, Peak EWMA and least-tokens-queued |
| Security | TLS and mTLS, per-SNI certificates, ACME, rate limiting, GeoIP filtering, decompression (zip bomb) limits |
| Agentic protocols | MCP and A2A awareness: per-method and per-tool allow/deny, resolved from the JSON-RPC body |
| Agents | External processors for WAF, auth and custom logic over agent protocol v2 (UDS or gRPC), crash-isolated, any language |
| HTTP caching | Pingora-based response caching with stampede prevention and memory, disk or hybrid backends |
| WebSocket | RFC 6455 proxying with per-frame agent inspection |
| Observability | Prometheus metrics and structured logging; OpenTelemetry tracing when built with `--features opentelemetry` (the released binaries are built without it) |
| Hot reload | SIGHUP reloads routes, upstreams and agents after validation, with an atomic swap; listener changes need a restart |

Full breakdown: [zentinelproxy.io/features](https://zentinelproxy.io/features/).

### Use cases

- **Reverse proxy**: TLS termination, static files, compression and security headers.
- **API gateway**: versioned routing, JWT or API-key auth (via agents), per-client rate limiting, JSON error responses.
- **Load balancer**: weighted distribution, health checks, circuit breakers, blue-green and canary rollouts.
- **Inference gateway**: token-based rate limiting, model routing with glob patterns (`gpt-4*`, `claude-*`), and prompt-injection and PII filtering through agents.
- **Agent gateway (MCP / A2A)**: per-method and per-tool allowlists enforced against the JSON-RPC body.
- **WebSocket gateway**: persistent connection proxying with frame inspection and message rate limiting.
- **Security gateway**: WAF, GeoIP filtering, mTLS and composable agent pipelines.

Example configs for each: [`config/examples/`](config/examples/).

## Agentic protocols

Zentinel understands MCP (Model Context Protocol) and A2A (Agent2Agent). A route
declares which methods and tools are permitted, and the proxy enforces that by
reading the JSON-RPC envelope:

```kdl
route "mcp" {
    matches { path-prefix "/mcp" }
    upstream "mcp-server"

    mcp {
        tools {
            allow "get_weather" "search_docs"
            deny "execute_sql"
        }
    }
}
```

**Policy is resolved from the body, never from the mirrored headers.** MCP's
Streamable HTTP transport copies the method and tool name into `Mcp-Method` and
`Mcp-Name` so intermediaries can route without parsing JSON. An allowlist built
on those headers allows everything:

```http
Mcp-Name: read_file                    <- what a header-based allowlist checks
{"method":"tools/call","params":{"name":"delete_everything"}}
                                ^ what the server actually executes
```

Zentinel reads the headers only to confirm they agree with the body, and
refuses a request that disagrees with itself. Requests claiming a protocol
revision older than `2026-07-28` are refused by default, because those
revisions never required the two to match; without that check, an attacker
opts out of validation by claiming an old version. A2A defines no mirrored
headers, so its policy reads the body directly.

This decides whether a call may be *made*. Whether its *contents* are safe
(prompt injection in an argument, PII in a payload) stays agent work.

Reference: [Agentic protocols](https://docs.zentinelproxy.io/configuration/agentic/).

## How it works

```
   ┌────────┐                                       ┌──────────┐
   │ Client │                                       │ Upstream │
   └────┬───┘                                       └─────▲────┘
        │                                                 │
        ▼                                                 │
   ╔═══════════ Zentinel (core, single binary) ══════════╤════╗
   ║                                                     │    ║
   ║  Listener ─▶ Routing ─▶ Filter chain ─▶ Forward ────┘    ║
   ║  TLS, H2     priority   rate-limit,     LB,              ║
   ║              + LRU      cache, hooks    retries          ║
   ║                              │                           ║
   ╚══════════════════════════════╪═══════════════════════════╝
                                  │ UDS / gRPC (agent protocol v2)
                                  ▼
          ╔═══════ External agents (separate processes) ═══════╗
          ║   WAF · Auth · Rate-limit · …                      ║
          ║   crash-isolated, any language                     ║
          ╚════════════════════════════════════════════════════╝
```

The response retraces the filter chain back to the client; access logs and
metrics are emitted at completion. The dataplane is a single binary. See
[`MANIFESTO.md`](MANIFESTO.md) for the reasoning and
[`crates/proxy/docs/architecture.md`](crates/proxy/docs/architecture.md) for the
per-phase details.

### Why Zentinel

- **Bounded resources**: memory limits, queue depths, deterministic timeouts.
- **Explicit failure modes**: fail-open or fail-closed per route, never ambiguous.
- **External extensibility**: security logic lives in agents, not the core, so the dataplane stays small.
- **Observable by default**: decisions are logged and metered; features ship only when bounded, observed and tested.

## Agents

Agents are external processes that hook into each request phase over agent
protocol v2. They are crash-isolated from the proxy, deployed independently,
and can be written in any language. Agents in the bundle install with
`zentinel bundle install <name>` (`zentinel bundle list` shows them).

SDKs: [Rust](https://github.com/zentinelproxy/zentinel-agent-rust-sdk) ·
[Go](https://github.com/zentinelproxy/zentinel-agent-go-sdk) ·
[Python](https://github.com/zentinelproxy/zentinel-agent-python-sdk) ·
[TypeScript](https://github.com/zentinelproxy/zentinel-agent-typescript-sdk) ·
[Elixir](https://github.com/zentinelproxy/zentinel-agent-elixir-sdk) ·
[Kotlin](https://github.com/zentinelproxy/zentinel-agent-kotlin-sdk) ·
[Haskell](https://github.com/zentinelproxy/zentinel-agent-haskell-sdk)

| Agent | What it does |
|---|---|
| [WAF](https://registry.zentinelproxy.io/waf/) | Pure Rust WAF: detection rules, anomaly scoring, API schema validation, bot protection |
| [ZentinelSec](https://registry.zentinelproxy.io/zentinelsec/) | Pure Rust ModSecurity-compatible WAF for SecLang rules and the OWASP CRS, no C dependencies |
| [AI Gateway](https://registry.zentinelproxy.io/ai-gateway/) | Pattern-based prompt-injection, jailbreak and PII detection for LLM APIs |
| [Auth](https://registry.zentinelproxy.io/auth/) | JWT, OIDC, API keys, Basic, SAML, mTLS, with Cedar-based authorization |
| [Policy](https://registry.zentinelproxy.io/policy/) | Rego/OPA and Cedar policy evaluation, written in Haskell (beta) |
| [Chaos](https://registry.zentinelproxy.io/chaos/) | Latency, error and timeout injection with targeting and safety controls |
| [Lua](https://registry.zentinelproxy.io/lua/) | Sandboxed Lua scripts for request and response processing |
| [WebSocket Inspector](https://registry.zentinelproxy.io/websocket-inspector/) | Content filtering, schema validation and attack detection for WebSocket frames |
| [MQTT Gateway](https://registry.zentinelproxy.io/mqtt-gateway/) | Topic ACLs, client auth and payload inspection for MQTT |

All agents: [registry.zentinelproxy.io](https://registry.zentinelproxy.io/).

<details>
<summary><strong>Crates in this repository</strong></summary>

Each crate has its own `docs/` directory where there is more to say.

| Crate | Path | What it does |
|---|---|---|
| `zentinel-proxy` | [`crates/proxy/`](crates/proxy/) | The reverse proxy (binary `zentinel`) |
| `zentinel-config` | [`crates/config/`](crates/config/) | KDL configuration parsing and validation |
| `zentinel-agent-protocol` | [`crates/agent-protocol/`](crates/agent-protocol/) | Agent protocol v2 and IPC |
| `zentinel-common` | [`crates/common/`](crates/common/) | Shared types, errors and utilities |
| `zentinel-gateway` | [`crates/gateway/`](crates/gateway/) | Kubernetes Gateway API controller (in progress, see [`conformance.md`](crates/gateway/docs/conformance.md)) |
| `zentinel-stack` | [`crates/stack/`](crates/stack/) | All-in-one launcher for the proxy and agents |
| `zentinel-wasm-runtime` | [`crates/wasm-runtime/`](crates/wasm-runtime/) | WASM agent runtime on Wasmtime |
| `zentinel-sim` | [`crates/sim/`](crates/sim/) | WASM-compatible configuration simulator |
| `zentinel-playground-wasm` | [`crates/playground-wasm/`](crates/playground-wasm/) | Browser bindings for the [playground](https://zentinelproxy.io/playground/) |
| `zentinel-config-inspect` | [`crates/config-inspect/`](crates/config-inspect/) | Static config topology analysis and visualization |

`sim`, `playground-wasm` and `config-inspect` are excluded from the workspace
and built separately.

</details>

## Development

The toolchain is pinned to Rust 1.99.1 in `rust-toolchain.toml`.

```bash
mise run build       # cargo build --workspace
mise run test-unit   # unit tests
mise run test        # all tests
mise run pre-push    # fmt-check, clippy -D warnings, docs (what CI requires)
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Using Claude Code? See
[`.claude/CLAUDE.md`](.claude/CLAUDE.md) for project context and coding rules.

## Related

- [Documentation](https://docs.zentinelproxy.io/): guides, reference and examples
- [Playground](https://zentinelproxy.io/playground/): try the routing engine in the browser (WASM)
- [Benchmarks](https://zentinelproxy.io/benchmarks/): latency, soak and chaos results
- [Agent registry](https://registry.zentinelproxy.io/): every agent and its status
- [zentinel-control-plane](https://github.com/zentinelproxy/zentinel-control-plane): fleet management for Zentinel proxies (Elixir/Phoenix)
- [Discussions](https://github.com/zentinelproxy/zentinel/discussions) and [issues](https://github.com/zentinelproxy/zentinel/issues)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
