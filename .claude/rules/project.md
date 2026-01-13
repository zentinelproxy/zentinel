# Sentinel Project Rules

These rules ensure contributions align with Sentinel's architecture and philosophy.

---

## Core Principles

### 1. Bounded by Design

Every resource must have explicit limits:

```rust
// GOOD: Explicit bounds
pub struct ConnectionPool {
    max_connections: usize,      // Hard limit
    idle_timeout: Duration,      // Connections reclaimed
    max_pending: usize,          // Queue depth limit
}

// BAD: Unbounded growth
pub struct ConnectionPool {
    connections: Vec<Connection>, // Can grow forever
}
```

**Checklist for new features:**
- [ ] Memory usage bounded?
- [ ] Queue depths limited?
- [ ] Timeouts on all blocking operations?
- [ ] Graceful behavior when limits reached?

### 2. Explicit Over Implicit

No hidden defaults or magic behavior:

```rust
// GOOD: Explicit configuration required
pub struct RouteConfig {
    pub timeout: Duration,           // Must be set
    pub failure_mode: FailureMode,   // Must choose
}

// BAD: Hidden defaults
pub struct RouteConfig {
    pub timeout: Option<Duration>,   // Falls back to... what?
}
```

**If behavior changes based on context, make it visible in config and logs.**

### 3. Fail Loudly and Safely

Errors must be:
- **Visible** — Logged, metriced, traceable
- **Contained** — Don't cascade to unrelated systems
- **Actionable** — Clear what went wrong and how to fix

```rust
// GOOD: Informative error
#[error("Route '{route_id}' upstream timeout after {elapsed:?} (limit: {timeout:?})")]
UpstreamTimeout {
    route_id: String,
    elapsed: Duration,
    timeout: Duration,
}

// BAD: Opaque error
#[error("Request failed")]
RequestFailed,
```

### 4. Observable by Default

Every significant operation should emit:
- **Metrics** — Counters, gauges, histograms
- **Logs** — Structured, with request context
- **Traces** — Span propagation for distributed tracing

```rust
// GOOD: Observable operation
tracing::info!(
    route_id = %route.id,
    upstream = %upstream.name,
    latency_ms = elapsed.as_millis(),
    status = %response.status,
    "Request completed"
);

metrics::counter!("sentinel_requests_total",
    "route" => route.id.clone(),
    "status" => status_class
).increment(1);
```

---

## Architecture Rules

### Agent Isolation

Agents are **external processes**. This is non-negotiable.

| Allowed | Not Allowed |
|---------|-------------|
| External process over UDS/gRPC | Compiled into proxy binary |
| WASM sandbox (Wasmtime) | Direct function calls to agent logic |
| Crash → agent restarts | Crash → proxy restarts |

**Why:** A buggy agent must never take down the proxy. The blast radius of complexity is contained by process boundaries.

### Crate Boundaries

Respect the separation of concerns:

| Crate | Owns | Does NOT Own |
|-------|------|--------------|
| `proxy` | HTTP handling, Pingora integration | Config parsing, agent protocol details |
| `config` | KDL parsing, validation | Runtime behavior, connection management |
| `agent-protocol` | Wire protocol, client/server | Business logic, decision making |
| `common` | Shared types, utilities | Feature-specific logic |

**Cross-crate rules:**
- `proxy` may depend on all other crates
- `config` and `agent-protocol` depend only on `common`
- `common` has no internal dependencies

### Configuration Ownership

All runtime behavior must be configurable via KDL:

```kdl
// Every limit, timeout, and policy exposed
system {
    max-connections 10000
    connection-timeout "30s"
}

routes {
    route "api" {
        timeout-ms 5000          // Not hidden in code
        failure-mode "open"      // Explicit choice
    }
}
```

**No hardcoded policy.** If it affects behavior, it belongs in config.

---

## Security Rules

### Input Validation

All external input validated at system boundaries:

```rust
// GOOD: Validate at entry point
pub fn parse_request(raw: &[u8]) -> Result<Request, ParseError> {
    if raw.len() > MAX_REQUEST_SIZE {
        return Err(ParseError::TooLarge { size: raw.len(), max: MAX_REQUEST_SIZE });
    }
    // ... parse
}

// BAD: Trust input
pub fn parse_request(raw: &[u8]) -> Request {
    // Assumes valid input
}
```

### No Secrets in Logs

Never log sensitive data:

```rust
// GOOD: Redact sensitive fields
tracing::info!(
    user_id = %auth.user_id,
    // token NOT logged
    "Authentication successful"
);

// BAD: Leaking secrets
tracing::debug!("Auth header: {}", request.headers.get("Authorization"));
```

### Timeout Everything

Every external operation needs a timeout:

```rust
// GOOD: Bounded wait
let response = tokio::time::timeout(
    config.upstream_timeout,
    client.send(request)
).await??;

// BAD: Unbounded wait
let response = client.send(request).await?;
```

---

## Performance Rules

### Hot Path Awareness

The request path is hot. Be careful with:

| Avoid | Prefer |
|-------|--------|
| Allocations per request | Pre-allocated buffers, pooling |
| Locks in hot path | Lock-free structures, sharding |
| String formatting | Pre-formatted, cached strings |
| Dynamic dispatch | Static dispatch, monomorphization |

```rust
// GOOD: Reuse buffer
let mut buf = self.buffer_pool.acquire();
buf.clear();
write_response(&mut buf, &response)?;

// BAD: Allocate per request
let buf = format!("{}", response);
```

### Measure Before Optimizing

Don't guess about performance:

```bash
# Profile before optimizing
cargo bench -p sentinel-proxy
cargo flamegraph --bin sentinel
```

---

## Testing Rules

### Test Boundaries

| Test Type | Location | Tests |
|-----------|----------|-------|
| Unit | `crates/*/src/**/*.rs` | Individual functions, modules |
| Integration | `tests/` | Full proxy with config |
| Chaos | `tests/chaos/` | Failure scenarios |

### Test Naming

```rust
#[test]
fn route_matching_prefers_exact_over_prefix() { }

#[test]
fn agent_timeout_triggers_circuit_breaker_after_threshold() { }

#[tokio::test]
async fn upstream_health_check_removes_unhealthy_backends() { }
```

### No Flaky Tests

Tests must be deterministic:

```rust
// GOOD: Controlled timing
tokio::time::pause();
tokio::time::advance(Duration::from_secs(30)).await;

// BAD: Real time dependencies
tokio::time::sleep(Duration::from_secs(1)).await;
assert!(elapsed < Duration::from_millis(100)); // Flaky!
```

---

## Documentation Rules

### Three Layers of Documentation

Sentinel has documentation at three levels. **All must be kept in sync.**

#### 1. Crate-level docs (`crates/*/docs/`)

Technical reference for each crate:

| Crate | Docs Path | Contents |
|-------|-----------|----------|
| `proxy` | `crates/proxy/docs/` | Architecture, routing, agents, rate-limiting |
| `config` | `crates/config/docs/` | KDL format, schema, validation, examples |
| `agent-protocol` | `crates/agent-protocol/docs/` | Protocol v1/, v2/, API, transports |
| `common` | `crates/common/docs/` | Errors, identifiers, limits, patterns |

**Update when:** API changes, new features, behavior modifications.

#### 2. Documentation site (`sentinel.raskell.io-docs`)

**Repo:** `github.com/raskell-io/sentinel.raskell.io-docs`

User-facing documentation including getting started, configuration guides, examples, and operations.

**Update when:**
- New user-visible features
- Configuration option changes
- New examples or use cases
- Breaking changes that affect users

#### 3. Code documentation

In-code doc comments for public APIs.

### Public API Documentation

Every public item needs documentation:

```rust
/// Processes an incoming request through the proxy pipeline.
///
/// # Errors
///
/// Returns [`ProxyError::UpstreamTimeout`] if the backend doesn't respond
/// within the configured timeout.
///
/// Returns [`ProxyError::NoHealthyUpstreams`] if all backends are unhealthy.
pub async fn process_request(&self, req: Request) -> Result<Response, ProxyError> {
```

### Config Documentation

New config options must be documented in **all three places**:

1. In-code doc comments on the config struct field
2. In `crates/config/docs/schema.md`
3. In docs site `content/configuration/` section

---

## Versioning Rules

### Semantic Versioning

- **MAJOR** — Breaking API changes
- **MINOR** — New features, backwards compatible
- **PATCH** — Bug fixes only

### Agent Protocol Versioning

- v1 and v2 coexist
- Version negotiated at handshake
- Breaking changes require new major version

### Config Compatibility

- New fields must have sensible defaults
- Removed fields should warn, not error
- Migration path documented for breaking changes
