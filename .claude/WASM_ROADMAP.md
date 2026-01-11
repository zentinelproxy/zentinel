# Sentinel WASM Roadmap

> Last updated: 2026-01-11 (Phase 2 complete)

This document outlines the current state and future direction for Sentinel's WebAssembly compilation, enabling browser-based configuration validation, simulation, and interactive playgrounds.

---

## Current State

### Production-Ready WASM Exports

The `sentinel-playground-wasm` crate provides these JavaScript bindings:

```javascript
// Validate a KDL configuration
validate(kdl: string) → {
  valid: boolean,
  errors: Error[],
  warnings: Warning[],
  effective_config: object  // Only if valid
}

// Simulate routing a request
simulate(kdl: string, request: string) → {
  matched_route: string | null,
  match_trace: MatchStep[],
  applied_policies: Policy[],
  upstream_selection: UpstreamTarget,
  agent_hooks: AgentHook[],
  warnings: Warning[]
}

// Get normalized config with defaults applied
get_normalized_config(kdl: string) → object

// Create a sample request for testing
create_sample_request(method: string, host: string, path: string) → SimulatedRequest

// Simulate multiple requests with state tracking (Phase 2)
simulate_stateful(config: string, requests: string) → {
  results: RequestResult[],
  state_transitions: StateTransition[],
  final_state: FinalState,
  summary: SimulationSummary
}
```

**Binary size:** ~800 KB uncompressed, ~250 KB gzipped
**Performance:** Full validate + simulate in ~20ms

### Crate Compatibility Matrix

| Crate | WASM Status | Size | Notes |
|-------|-------------|------|-------|
| `playground-wasm` | ✅ Production | ~280 lines | Full JS bindings |
| `sim` | ✅ Production | ~3,300 lines | Zero runtime deps, stateful simulation |
| `config` | ✅ Compatible | 2,500+ lines | Needs `--no-default-features` |
| `common` | ✅ Compatible | ~1,000 lines | Needs `--no-default-features` |
| `agent-protocol` | ⚠️ Partial | ~1,300 lines | Types OK, transport impossible |
| `proxy` | ❌ Impossible | — | Pingora + C FFI |
| `stack` | ❌ N/A | — | Subprocess launcher |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Browser / Node.js                         │
├─────────────────────────────────────────────────────────────┤
│                 sentinel-playground-wasm                     │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │  validate() │ │  simulate() │ │ get_normalized_...  │   │
│  └──────┬──────┘ └──────┬──────┘ └──────────┬──────────┘   │
├─────────┼───────────────┼───────────────────┼───────────────┤
│         │               │                   │                │
│         ▼               ▼                   ▼                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   sentinel-sim                       │    │
│  │  ┌───────────┐ ┌────────────┐ ┌───────────────┐    │    │
│  │  │  matcher  │ │  upstream  │ │     trace     │    │    │
│  │  │ (routing) │ │    (LB)    │ │  (decisions)  │    │    │
│  │  └───────────┘ └────────────┘ └───────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  sentinel-config                     │    │
│  │         (KDL parsing, validation, defaults)          │    │
│  └─────────────────────────────────────────────────────┘    │
│                            │                                 │
│                            ▼                                 │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  sentinel-common                     │    │
│  │            (types, enums, constants)                 │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘

                    ═══════════════════
                    WASM BOUNDARY ABOVE
                    ═══════════════════

┌─────────────────────────────────────────────────────────────┐
│              NOT POSSIBLE IN WASM (System I/O)              │
├─────────────────────────────────────────────────────────────┤
│  sentinel-proxy          │  Pingora + BoringSSL (C FFI)     │
│  sentinel-agent-protocol │  Unix sockets, gRPC, tokio       │
│  sentinel-stack          │  Subprocess management           │
└─────────────────────────────────────────────────────────────┘
```

---

## Dependency Analysis

### WASM-Safe Dependencies (Always Work)

```toml
# Pure Rust, no system calls
serde = "1.0"
serde_json = "1.0"
kdl = "6.5"
toml = "0.8"
regex = "1.12"
thiserror = "1.0"
parking_lot = "0.12"
arc-swap = "1.8"
wasm-bindgen = "0.2"
serde-wasm-bindgen = "0.6"
```

### Feature-Gated Dependencies (Disable for WASM)

**Config crate (`--no-default-features`):**
- `glob` - File globbing (needs filesystem)
- `notify` - File watching (needs inotify/FSEvents)
- `directories` - XDG paths (needs env vars)
- `envy` - Environment variable parsing
- `jsonschema` - Requires getrandom (no entropy in WASM)

**Common crate (`--no-default-features`):**
- `tokio` - Async runtime (no threads in WASM)
- `tracing-subscriber` - Logging to stdout
- `prometheus` - Metrics collection
- `sysinfo` - System statistics

### Blocker Dependencies (Never WASM-Compatible)

```toml
# Pingora ecosystem - All require BoringSSL C library
pingora = "*"
pingora-core = "*"
pingora-proxy = "*"
pingora-cache = "*"
pingora-load-balancing = "*"
pingora-limits = "*"
pingora-timeout = "*"
pingora-http = "*"

# System I/O
nix = "*"           # Unix syscalls
libc = "*"          # C library bindings
signal-hook = "*"   # Signal handling
notify = "*"        # Filesystem events

# Network I/O
tokio = "*"         # Async runtime (threads)
reqwest = "*"       # HTTP client (sockets)
tokio-tungstenite = "*"  # WebSocket (sockets)
```

---

## Roadmap

### Phase 1: Current (Complete)

**Status:** ✅ Production

- Full KDL config validation with rich error messages
- Route matching simulation with decision tracing
- All 14 load balancing algorithms (deterministic simulation)
- Policy preview (timeouts, body limits, rate limits, cache)
- Agent hook identification
- Config linting (undefined upstreams, duplicates)

### Phase 2: Stateful Policy Simulation

**Status:** ✅ Complete

Simulation of policy state across multiple requests:

```javascript
simulate_stateful(config: string, requests: string) → {
  results: RequestResult[],
  state_transitions: StateTransition[],
  final_state: FinalState,
  summary: SimulationSummary
}
```

**Implemented Features:**
- Token bucket rate limiter with refill over time
- Cache hit/miss/expiry tracking with TTL
- Load balancer position tracking (round-robin)
- Circuit breaker state machine (Closed/Open/HalfOpen)
- Per-request results with decision traces
- State transition logging
- Summary statistics (hit rates, rate limited count, etc.)

**Implementation:**

```
crates/sim/
├── lib.rs
├── matcher.rs
├── upstream.rs
├── trace.rs
├── types.rs
└── stateful.rs  ← ~1,050 lines
    ├── TokenBucket / RateLimitState
    ├── CacheState / CacheEntry
    ├── CircuitBreaker / CircuitBreakerState
    ├── LoadBalancerState
    └── simulate_sequence()
```

**Use cases:**
- "What happens after 100 requests hit this rate limit?"
- "How does the cache warm up over these 10 requests?"
- "When does the circuit breaker trip?"

### Phase 3: Agent Decision Simulation

**Status:** Planned
**Effort:** 1-2 weeks
**Value:** Medium-High

Create mock agent execution for the playground:

```javascript
// New export
simulate_with_agents(
  config: string,
  request: SimulatedRequest,
  agent_responses: Map<string, AgentDecision>
) → {
  final_decision: "allow" | "block" | "redirect",
  transformations: HeaderMutation[],
  agent_trace: AgentStep[],
  upstream_request: TransformedRequest
}
```

**Features:**
- Mock agent responses (user provides decisions)
- Header mutation simulation
- Agent chain execution order
- Failure mode simulation (what if agent times out?)

**Implementation:**

```
crates/
├── sim/
│   └── ... (existing)
└── agent-sim/  ← NEW CRATE (~400-600 lines)
    ├── Cargo.toml
    ├── lib.rs
    ├── mock.rs      # Mock agent implementations
    ├── chain.rs     # Agent chain execution
    └── transform.rs # Request/response mutations
```

**Use cases:**
- "If WAF blocks this request, what response does the client see?"
- "How do header mutations from auth agent affect downstream?"
- "What's the full request pipeline for this config?"

### Phase 4: Interactive Debugging

**Status:** Future
**Effort:** 2-3 weeks
**Value:** Medium

Enhanced debugging and visualization support:

```javascript
// Step-by-step execution
create_debugger(config: string) → Debugger

debugger.step() → DebugState
debugger.step_into(component: string) → DebugState
debugger.get_state() → FullState
debugger.set_breakpoint(condition: string) → void
```

**Features:**
- Step-by-step request processing visualization
- Breakpoints on conditions (e.g., "stop when rate limit hits 80%")
- State inspection at any point
- Time-travel debugging (step backward)

### Not Planned (Impossible or Low Value)

| Feature | Reason |
|---------|--------|
| Actual TLS handshake | Needs system time, CA bundles, crypto hardware |
| Real WAF engine | libmodsecurity is C, would add 10+ MB |
| Network requests | WASM sandbox has no socket access |
| File system access | WASM sandbox restriction |
| Environment variables | Must pass config as string |
| Real randomness | No entropy source (use deterministic hashing) |

---

## Design Principles

### 1. Deterministic Simulation

All WASM simulation is deterministic:
- Load balancing uses consistent hashing, not randomness
- Request IDs are derived from input, not generated
- Time-based features use provided timestamps

### 2. No Runtime Dependencies

The `sim` crate has zero default features:
```toml
[features]
default = []  # Nothing enabled by default
```

### 3. String-Based Input

All configuration comes as strings:
```rust
// Good - WASM compatible
pub fn validate(config_kdl: &str) -> ValidationResult

// Bad - requires filesystem
pub fn validate_file(path: &Path) -> ValidationResult
```

### 4. Bounded Memory

Simulation has hard limits:
- Max config size: 1 MB
- Max request body (simulated): 10 MB reference
- Max route count: 10,000
- Max upstream targets: 1,000

### 5. Rich Error Context

Errors include source locations and suggestions:
```json
{
  "valid": false,
  "errors": [{
    "message": "Unknown upstream 'backend'",
    "location": { "line": 42, "column": 9 },
    "suggestion": "Did you mean 'backends'?",
    "code": "E001"
  }]
}
```

---

## Building for WASM

### Prerequisites

```bash
# Install wasm-pack
cargo install wasm-pack

# Add WASM target
rustup target add wasm32-unknown-unknown
```

### Build Commands

```bash
# Development build (faster, larger)
cd crates/playground-wasm
wasm-pack build --target web --dev

# Production build (slower, optimized)
wasm-pack build --target web --release

# Output location
ls pkg/
# sentinel_playground_wasm_bg.wasm  (~800 KB)
# sentinel_playground_wasm.js       (~12 KB)
```

### Integration

```html
<script type="module">
  import init, { validate, simulate } from './pkg/sentinel_playground_wasm.js';

  await init();

  const result = validate(`
    system { worker-threads 0 }
    listeners { ... }
    routes { ... }
  `);

  console.log(result.valid ? 'Config OK' : result.errors);
</script>
```

---

## Testing

### Unit Tests (Rust)

```bash
cd crates/playground-wasm
cargo test
```

### WASM Integration Tests

```bash
wasm-pack test --headless --chrome
```

### Browser Manual Testing

```bash
# Serve the test page
cd crates/playground-wasm
python3 -m http.server 8000

# Open http://localhost:8000/test.html
```

---

## Performance Targets

| Operation | Target | Current |
|-----------|--------|---------|
| Config validation (small) | < 10ms | ~5ms |
| Config validation (large) | < 50ms | ~30ms |
| Route simulation | < 5ms | ~2ms |
| Stateful simulation (100 req) | < 100ms | TBD |
| WASM load time | < 200ms | ~150ms |
| Bundle size (gzipped) | < 300 KB | ~250 KB |

---

## Related Documentation

- [Sentinel Architecture](./CLAUDE.md) - Overall system design
- [Config Reference](../docs/configuration/) - KDL configuration guide
- [Playground](https://sentinel.raskell.io/playground/) - Live playground
