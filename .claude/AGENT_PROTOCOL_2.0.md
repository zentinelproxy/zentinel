# Agent Protocol 2.0 Design

**Status:** Draft
**Author:** Zentinel Core Team
**Last Updated:** 2026-01-12

> **⚠️ CRITICAL:** This document now includes performance bottlenecks identified in the v1 implementation that MUST be addressed in v2. See [Performance Critical Issues](#performance-critical-issues-v1-legacy).

---

## Executive Summary

Agent Protocol 2.0 evolves Zentinel's external processing model from request/response to bidirectional streaming, enabling richer agent interactions, better observability, and lower latency through WASM support.

### Architectural Decision: External Agents Only

**Zentinel does not compile agents into the proxy binary.** All agent logic runs externally (separate process or WASM sandbox). This is a deliberate architectural choice:

| Factor | In-Process | External Agent |
|--------|------------|----------------|
| Crash isolation | ❌ Takes down proxy | ✅ Proxy survives |
| Memory isolation | ❌ Shared heap | ✅ Separate process |
| Independent deploy | ❌ Rebuild proxy | ✅ Restart agent only |
| Language flexibility | ❌ Rust only | ✅ Any language |
| Blocking risk | ❌ Blocks event loop | ✅ Isolated |
| Latency | ~100ns | ~10-50μs (fixed impl) |

**The ~50μs overhead of well-implemented external agents is acceptable.** The current implementation adds 200-500μs due to bugs (single connection, async locks, sequential processing). Phase 0 fixes this.

After Phase 0, the latency breakdown will be:
```
External Agent (fixed):     ~40-50μs  ← acceptable
WASM Agent (sandboxed):     ~10-50μs  ← for latency-critical
In-process (hypothetical):  ~100ns    ← not worth the risk
```

**For operations requiring <10μs latency:** Use WASM agents (Phase 3). They run in-process but sandboxed, providing crash isolation without IPC overhead.

---

## Motivation

### Current Protocol v1 Limitations

| Area | Current State | Pain Point |
|------|---------------|------------|
| **Communication** | Request/response per event | Can't push updates, no backpressure |
| **Health** | Circuit breaker only | No graceful degradation signals |
| **Discovery** | Static socket config | No capability introspection |
| **Runtime** | External process only | High latency for simple checks |
| **Streaming** | Chunk-by-chunk with `needs_more` | Complex state management |
| **Versioning** | Single `version: u32` field | No feature negotiation |

### Goals

1. **Bidirectional streaming** — Agents can push config updates, metrics
2. **Health reporting** — Agents report readiness/degradation
3. **Capability negotiation** — Agents declare supported phases/features
4. **WASM agent runtime** — In-process sandboxed agents via Wasmtime

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Agent Protocol 2.0                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐         Bidirectional          ┌─────────────┐│
│  │   Zentinel  │◄──────── gRPC Stream ─────────►│    Agent    ││
│  │  Dataplane  │                                 │  (Process)  ││
│  └──────┬──────┘                                 └─────────────┘│
│         │                                                       │
│         │  In-Process (low latency)                             │
│         ▼                                                       │
│  ┌─────────────┐                                                │
│  │    WASM     │  Wasmtime sandbox                              │
│  │   Runtime   │  Component Model                               │
│  └─────────────┘                                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Transport Options

| Transport | Latency (v1) | Latency (v2 target) | Use Case |
|-----------|--------------|---------------------|----------|
| **WASM (in-process)** | N/A | ~10-50μs | Latency-critical, stateless checks |
| **Unix Socket** | ~100-500μs | ~30-50μs | Most agents (WAF, auth, logging) |
| **gRPC** | ~200-500μs | ~50-100μs | Remote agents, polyglot teams |

> **Note:** v1 latency includes implementation overhead. After Phase 0 fixes, UDS should match or approach WASM latency for most workloads.

### When to Use Each Transport

```
                  ┌─────────────────────────────────────────────────────┐
                  │              Decision Tree: Transport               │
                  └─────────────────────────────────────────────────────┘
                                         │
                    ┌────────────────────┴────────────────────┐
                    │    Does agent need <20μs latency?       │
                    └────────────────────┬────────────────────┘
                           │                        │
                          YES                       NO
                           │                        │
                           ▼                        ▼
                  ┌─────────────────┐    ┌─────────────────────┐
                  │    Use WASM     │    │ Does agent need     │
                  │   (Phase 3)     │    │ C libs or complex   │
                  │                 │    │ state?              │
                  │ Examples:       │    └──────────┬──────────┘
                  │ • Path prefix   │          │         │
                  │ • Header check  │         YES        NO
                  │ • Static rules  │          │         │
                  └─────────────────┘          ▼         ▼
                                      ┌───────────┐ ┌───────────┐
                                      │ Use UDS   │ │ Use UDS   │
                                      │ (default) │ │ or gRPC   │
                                      │           │ │           │
                                      │ Examples: │ │ Examples: │
                                      │ • WAF     │ │ • Logging │
                                      │ • ML bot  │ │ • Metrics │
                                      │ • Auth+IdP│ │ • Simple  │
                                      └───────────┘ │   checks  │
                                                    └───────────┘
```

### Why Not Compiled-In Agents?

The Zentinel architecture explicitly avoids compiling agent logic into the proxy:

1. **Isolation requirement**: "A broken agent must not crash the dataplane" (CLAUDE.md)
2. **C/C++ risk**: WAF engines like libmodsecurity have had CVEs; keep them out of the Rust dataplane
3. **Deployment independence**: Update WAF rules without rebuilding the proxy
4. **Unbounded computation**: Regex engines, ML inference can block; keep them isolated

The ~40-50μs overhead of a well-implemented external call is worth paying for these benefits. For the rare case where that's too slow, WASM provides a sandboxed in-process option.

---

## Performance Critical Issues (v1 Legacy)

The following issues in the v1 implementation **MUST** be resolved in v2 to prevent interference with Pingora's event loop under load.

### 🔴 P0: Event Loop Blockers

These issues can starve Pingora's event loop and must be fixed before v2 ships.

#### 1. Single Connection Per Agent (CRITICAL)

**Location:** `crates/proxy/src/agents/agent.rs:21, 476`

```rust
// CURRENT: All requests serialize through one connection
pub(super) client: Arc<RwLock<Option<AgentClient>>>,
let mut client_guard = self.client.write().await;  // Blocks all concurrent requests
```

**Impact:**
- All requests to an agent serialize through one TCP/UDS connection
- At 100 RPS with 50ms agent latency → 5 second queue buildup
- `AgentConnectionPool` exists but is unused (no `get()`/`return()` methods)

**Required Fix:** Implement actual connection pooling with lockless acquisition. Target: 8-32 connections per agent with round-robin or least-connections selection.

#### 2. Async Locks in Hot Path (CRITICAL)

**Location:** `crates/common/src/circuit_breaker.rs:104-150`

```rust
// CURRENT: Two RwLock reads per request just for circuit breaker
pub async fn is_closed(&self) -> bool {
    let state = *self.state.read().await;           // Lock 1
    let last_change = *self.last_state_change.read().await;  // Lock 2
```

**Impact:** Every request does two async lock acquisitions for a simple state check.

**Required Fix:** Replace with atomics:
```rust
// TARGET: Lock-free circuit breaker
state: AtomicU8,  // 0=Closed, 1=Open, 2=HalfOpen
failure_count: AtomicU32,
last_state_change: AtomicU64,  // Unix timestamp
```

#### 3. Sequential Agent Processing (HIGH)

**Location:** `crates/proxy/src/agents/manager.rs:457`

```rust
// CURRENT: Agents process one-by-one
for (agent_index, agent) in relevant_agents.iter().enumerate() {
```

**Impact:** If you have WAF + Auth + Logging agents, latency = WAF + Auth + Logging instead of max(WAF, Auth, Logging).

**Required Fix:** Process independent agents in parallel using `futures::join_all()` or `tokio::join!()`. Dependent agents (where one needs another's output) remain sequential.

### 🟠 P1: CPU Overhead in Event Loop

These issues add unnecessary CPU work on the event loop thread.

#### 4. Base64 Encoding All Body Data

**Location:** `crates/proxy/src/agents/manager.rs:172, 206-208`

```rust
// CURRENT: 33% bandwidth overhead on every chunk
data: STANDARD.encode(data),
```

**Impact:**
- 33% bandwidth overhead
- CPU cycles for encode/decode on every body chunk
- Compounds with large request/response bodies

**Required Fix:**
- For UDS: Pass raw bytes directly (binary framing)
- For gRPC: Use `bytes` type in protobuf (already binary)
- Keep base64 only for JSON-over-HTTP transport as fallback

#### 5. JSON Serialization on Unix Sockets

**Location:** `crates/agent-protocol/src/client.rs:604-610`

```rust
// CURRENT: JSON even on local sockets
let request_bytes = serde_json::to_vec(&request)  // Allocation per request
```

**Impact:** Serialization overhead that binary protocols avoid.

**Required Fix:** Add binary protocol option for UDS:
- Option A: Cap'n Proto (zero-copy)
- Option B: Raw binary framing with fixed-size headers
- Option C: MessagePack (simpler migration from JSON)

#### 6. HashMap Clone for Every Request

**Location:** `crates/proxy/src/agents/manager.rs:144-145`

```rust
// CURRENT: Full clone of headers
headers: headers.clone(),
```

**Impact:** Memory allocation on every request, GC-like pressure.

**Required Fix:**
- Use `Cow<'_, HashMap<...>>` for borrowed access
- Or pass headers by reference with lifetime bounds
- Clone only when agent actually needs ownership

### 🟡 P2: Memory and Lock Contention

#### 7. RwLock Per Agent in Loop

**Location:** `crates/proxy/src/agents/manager.rs:467-469`

```rust
// CURRENT: Lock acquired N times for N agents
let semaphores = self.agent_semaphores.read().await;
let agent_semaphore = semaphores.get(agent.id()).cloned();
drop(semaphores);
```

**Required Fix:** Cache semaphores once before the loop:
```rust
let semaphores = self.agent_semaphores.read().await;
let agent_sems: Vec<_> = relevant_agents.iter()
    .map(|a| semaphores.get(a.id()).cloned())
    .collect();
drop(semaphores);
// Then use agent_sems[i] in loop
```

#### 8. Unbounded Vec Allocation

**Location:** `crates/agent-protocol/src/client.rs:1069`

```rust
// CURRENT: New allocation per message (up to 10MB)
let mut buffer = vec![0u8; message_len];
```

**Required Fix:** Pool message buffers using slab allocator or `bytes::BytesMut` with reserved capacity.

#### 9. RwLock on Success Recording

**Location:** `crates/proxy/src/agents/agent.rs:562`

```rust
// CURRENT: Write lock just to update timestamp
*self.last_success.write().await = Some(Instant::now());
```

**Required Fix:** Use `AtomicU64` with `Instant::now().elapsed().as_nanos()` or similar atomic timestamp.

### Existing Strengths (Keep These)

The v1 implementation has solid foundations that should be preserved:

| Feature | Implementation | Notes |
|---------|----------------|-------|
| **Timeouts** | `pingora_timeout::timeout()` | Proper non-blocking timeouts ✓ |
| **Queue Isolation** | Per-agent semaphores | Prevents noisy neighbor (design good, impl needs atomics) |
| **Circuit Breakers** | Pattern exists | Correct pattern, needs atomic impl |
| **Streaming** | `needs_more` flag | Prevents unbounded buffering ✓ |
| **Failure Modes** | Fail-open/fail-closed | Configurable per route ✓ |

### Expected Impact After Fixes

| Fix | Latency Improvement | Throughput Improvement |
|-----|---------------------|------------------------|
| Connection pooling | 2-3x under load | 5-10x with concurrent requests |
| Atomic circuit breaker | 10-20% reduction | Eliminates lock contention |
| Parallel agents | N× (where N = agent count) | Linear scaling |
| Binary protocol (UDS) | 20-30% reduction | 15-20% improvement |
| Remove base64 | 10-15% for body-heavy | 33% bandwidth savings |

**Combined estimate:** 3-5x latency improvement, 10x+ throughput improvement under high concurrency.

### Post-Fix Performance Targets

After Phase 0, external agents should achieve these targets:

| Scenario | Current (v1) | Target (v2) | Notes |
|----------|--------------|-------------|-------|
| Single agent, header-only | ~200-300μs | ~40-50μs | Connection pooling + parallel |
| 3 agents, parallel | ~600-900μs | ~50-80μs | Parallel execution |
| WAF + body inspection | ~500μs-2ms | ~100-200μs | Binary protocol + streaming |

**Key insight:** At ~50μs per agent call, external agents add negligible latency compared to upstream RTT (typically 1-50ms). The architectural benefits (isolation, independent deployment, polyglot support) far outweigh this overhead.

For the rare use case requiring <20μs (e.g., per-request header injection on millions of RPS), use WASM agents (Phase 3).

---

## Protocol Specification

### 1. Capability Handshake

When an agent connects, it declares its capabilities:

```rust
/// Protocol version for v2
pub const PROTOCOL_VERSION_2: u32 = 2;

/// Agent capabilities declared during handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Protocol version supported (2 for v2)
    pub protocol_version: u32,

    /// Agent identifier
    pub agent_id: String,

    /// Agent display name
    pub name: String,

    /// Agent version
    pub version: String,

    /// Supported event phases
    pub supported_events: Vec<EventType>,

    /// Features this agent supports
    pub features: AgentFeatures,

    /// Resource limits the agent can handle
    pub limits: AgentLimits,

    /// Health check configuration
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentFeatures {
    /// Can handle streaming body inspection
    pub streaming_body: bool,

    /// Can handle WebSocket frames
    pub websocket: bool,

    /// Can handle guardrail inspection
    pub guardrails: bool,

    /// Supports bidirectional config updates
    pub config_push: bool,

    /// Supports metrics reporting
    pub metrics_export: bool,

    /// Can process multiple requests concurrently
    pub concurrent_requests: u32,

    /// Supports request cancellation
    pub cancellation: bool,

    /// Supports flow control / backpressure
    pub flow_control: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLimits {
    /// Max body size agent can inspect (bytes)
    pub max_body_size: usize,

    /// Max concurrent requests
    pub max_concurrency: u32,

    /// Preferred batch size for body chunks
    pub preferred_chunk_size: usize,

    /// Max memory the agent will use (bytes)
    pub max_memory: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// How often agent will send health updates (ms)
    pub report_interval_ms: u32,

    /// Include load metrics in health reports
    pub include_load_metrics: bool,

    /// Include resource metrics (CPU, memory)
    pub include_resource_metrics: bool,
}
```

### 2. Bidirectional Streaming

Replace request/response with bidirectional streams:

```protobuf
syntax = "proto3";

package zentinel.agent.v2;

service AgentService {
    // Main bidirectional stream for all traffic
    rpc ProcessStream(stream ProxyToAgent) returns (stream AgentToProxy);

    // Separate control plane stream (config, health, metrics)
    rpc ControlStream(stream AgentControl) returns (stream ProxyControl);
}

// Messages from proxy to agent
message ProxyToAgent {
    oneof message {
        HandshakeRequest handshake = 1;
        RequestHeadersEvent request_headers = 2;
        BodyChunkEvent body_chunk = 3;
        ResponseHeadersEvent response_headers = 4;
        ResponseBodyChunkEvent response_body_chunk = 5;
        WebSocketFrameEvent websocket_frame = 6;
        GuardrailInspectEvent guardrail = 7;
        RequestCompleteEvent request_complete = 8;
        CancelRequest cancel = 9;
        ConfigureEvent configure = 10;
    }
}

// Messages from agent to proxy
message AgentToProxy {
    oneof message {
        HandshakeResponse handshake = 1;
        AgentResponse response = 2;
        HealthStatus health = 3;
        MetricsReport metrics = 4;
        ConfigUpdateRequest config_update = 5;
        FlowControlSignal flow_control = 6;
    }
}

// Control plane messages (agent to proxy)
message AgentControl {
    oneof message {
        HealthStatus health = 1;
        MetricsReport metrics = 2;
        ConfigUpdateRequest config_update = 3;
        LogMessage log = 4;
    }
}

// Control plane messages (proxy to agent)
message ProxyControl {
    oneof message {
        ConfigureEvent configure = 1;
        ShutdownRequest shutdown = 2;
        DrainRequest drain = 3;
    }
}
```

### 3. Health Reporting

Agents proactively report health status:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current health state
    pub state: HealthState,

    /// Human-readable message
    pub message: Option<String>,

    /// Metrics for load shedding decisions
    pub load: Option<LoadMetrics>,

    /// Resource usage metrics
    pub resources: Option<ResourceMetrics>,

    /// When this status expires (Unix timestamp ms)
    pub valid_until_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Fully operational
    Healthy,

    /// Operational but degraded
    Degraded {
        /// Features currently unavailable
        disabled_features: Vec<String>,
        /// Suggested request timeout multiplier (e.g., 1.5 = 50% longer)
        timeout_multiplier: f32,
    },

    /// Not accepting new requests, finishing in-flight
    Draining {
        /// Estimated time until fully drained (ms)
        eta_ms: Option<u64>,
    },

    /// Completely unavailable
    Unhealthy {
        /// Reason for unhealthy state
        reason: String,
        /// Whether agent expects to recover
        recoverable: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadMetrics {
    /// Current in-flight requests
    pub in_flight: u32,

    /// Queue depth if applicable
    pub queue_depth: u32,

    /// Average processing latency (ms) over last interval
    pub avg_latency_ms: f32,

    /// P99 processing latency (ms) over last interval
    pub p99_latency_ms: f32,

    /// Requests processed in last interval
    pub requests_processed: u64,

    /// Requests rejected/dropped in last interval
    pub requests_rejected: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetrics {
    /// CPU usage percentage (0-100)
    pub cpu_percent: Option<f32>,

    /// Memory usage in bytes
    pub memory_bytes: Option<u64>,

    /// Memory limit in bytes
    pub memory_limit: Option<u64>,

    /// Number of active threads/goroutines
    pub active_threads: Option<u32>,

    /// File descriptors in use
    pub open_fds: Option<u32>,
}
```

### 4. Request Cancellation

Proxy can cancel in-flight requests:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelRequest {
    /// Correlation ID of request to cancel
    pub correlation_id: String,

    /// Reason for cancellation
    pub reason: CancelReason,

    /// Unix timestamp (ms) when cancel was issued
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// Client disconnected before response
    ClientDisconnect,

    /// Request timeout exceeded
    Timeout,

    /// Another agent blocked the request
    BlockedByAgent {
        agent_id: String,
    },

    /// Upstream connection failed
    UpstreamError,

    /// Proxy is shutting down
    ProxyShutdown,

    /// Manual cancellation (admin action)
    Manual {
        reason: String,
    },
}
```

### 5. Flow Control

Streaming with backpressure:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowControlSignal {
    /// Correlation ID this applies to (empty = global)
    pub correlation_id: Option<String>,

    /// Flow control action
    pub action: FlowAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAction {
    /// Pause sending data
    Pause,

    /// Resume sending data
    Resume,

    /// Update buffer capacity
    UpdateCapacity {
        /// Bytes agent is willing to buffer
        buffer_available: usize,
    },
}

/// Extended body chunk event with flow control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyChunkEventV2 {
    /// Correlation ID
    pub correlation_id: String,

    /// Chunk index for ordering (0-based)
    pub chunk_index: u32,

    /// Body chunk data (base64 encoded for JSON)
    pub data: String,

    /// Is this the last chunk?
    pub is_last: bool,

    /// Total body size if known
    pub total_size: Option<usize>,

    /// Bytes received/sent so far (cumulative)
    pub bytes_transferred: usize,

    /// Proxy's remaining buffer capacity
    pub proxy_buffer_available: usize,
}
```

### 6. Metrics Export

Agents push metrics to the proxy:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsReport {
    /// Agent identifier
    pub agent_id: String,

    /// Timestamp of report (Unix ms)
    pub timestamp_ms: u64,

    /// Reporting interval (ms)
    pub interval_ms: u64,

    /// Counter metrics (monotonically increasing)
    pub counters: Vec<CounterMetric>,

    /// Gauge metrics (point-in-time values)
    pub gauges: Vec<GaugeMetric>,

    /// Histogram metrics
    pub histograms: Vec<HistogramMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterMetric {
    /// Metric name (e.g., "requests_processed_total")
    pub name: String,

    /// Labels
    pub labels: HashMap<String, String>,

    /// Counter value
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GaugeMetric {
    /// Metric name (e.g., "queue_depth")
    pub name: String,

    /// Labels
    pub labels: HashMap<String, String>,

    /// Gauge value
    pub value: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramMetric {
    /// Metric name (e.g., "processing_duration_seconds")
    pub name: String,

    /// Labels
    pub labels: HashMap<String, String>,

    /// Sum of all observations
    pub sum: f64,

    /// Count of observations
    pub count: u64,

    /// Bucket boundaries and counts
    pub buckets: Vec<HistogramBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    /// Upper bound (exclusive)
    pub le: f64,

    /// Cumulative count
    pub count: u64,
}
```

### 7. Configuration Push

Agents can request or push config updates:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUpdateRequest {
    /// Type of update
    pub update_type: ConfigUpdateType,

    /// Request ID for tracking
    pub request_id: String,

    /// Timestamp
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigUpdateType {
    /// Request proxy to resend agent config
    RequestReload,

    /// Agent pushing rule updates (e.g., WAF rules)
    RuleUpdate {
        /// Rule set identifier
        rule_set: String,
        /// Rules to add/update
        rules: Vec<RuleDefinition>,
        /// Rules to remove (by ID)
        remove_rules: Vec<String>,
    },

    /// Agent pushing allowlist/denylist updates
    ListUpdate {
        /// List identifier
        list_id: String,
        /// Entries to add
        add: Vec<String>,
        /// Entries to remove
        remove: Vec<String>,
    },

    /// Agent signaling it needs to restart
    RestartRequired {
        /// Reason for restart
        reason: String,
        /// Grace period requested (ms)
        grace_period_ms: u64,
    },

    /// Agent reporting config validation error
    ConfigError {
        /// Error message
        error: String,
        /// Config field that caused error
        field: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDefinition {
    /// Rule ID
    pub id: String,

    /// Rule priority/order
    pub priority: i32,

    /// Rule definition (agent-specific format)
    pub definition: serde_json::Value,

    /// Whether rule is enabled
    pub enabled: bool,
}
```

---

## WASM Agent Interface

### When to Use WASM Agents

WASM agents are **not the default**—use them only when:

1. **Latency requirement <20μs**: External agents (post-Phase 0) add ~40-50μs; WASM adds ~10-50μs
2. **Operation is stateless and bounded**: No external calls, no unbounded loops
3. **Logic is stable**: Frequent changes defeat the purpose (just use external)

**Good WASM candidates:**
- Static allowlist/denylist checks
- Header presence/format validation
- Request ID injection
- Simple routing tag extraction

**Keep external for:**
- WAF (needs C libs, complex parsing)
- Auth with IdP calls
- ML inference
- Anything with unbounded computation

### Interface Definition

For in-process agents using WebAssembly Component Model:

```wit
// zentinel-agent.wit - WebAssembly Interface Type definition

package zentinel:agent@2.0.0;

/// Core types used throughout the agent interface
interface types {
    /// Request metadata passed to agents
    record request-metadata {
        correlation-id: string,
        request-id: string,
        client-ip: string,
        client-port: u16,
        server-name: option<string>,
        protocol: string,
        tls-version: option<string>,
        route-id: option<string>,
        upstream-id: option<string>,
        timestamp-ms: u64,
        traceparent: option<string>,
    }

    /// HTTP header
    record header {
        name: string,
        value: string,
    }

    /// Header modification operation
    variant header-op {
        set(header),
        add(header),
        remove(string),
    }

    /// Block parameters
    record block-params {
        status: u16,
        body: option<string>,
        headers: list<header>,
    }

    /// Redirect parameters
    record redirect-params {
        url: string,
        status: u16,
    }

    /// Agent decision
    variant decision {
        allow,
        block(block-params),
        redirect(redirect-params),
    }

    /// Audit metadata
    record audit-metadata {
        tags: list<string>,
        rule-ids: list<string>,
        confidence: option<f32>,
        reason-codes: list<string>,
    }

    /// Full agent response
    record agent-response {
        decision: decision,
        request-headers: list<header-op>,
        response-headers: list<header-op>,
        audit: audit-metadata,
    }
}

/// Agent handler interface
interface handler {
    use types.{request-metadata, agent-response, header};

    /// Called once when agent is loaded
    /// Returns error string if configuration is invalid
    configure: func(config: string) -> result<_, string>;

    /// Process request headers
    on-request-headers: func(
        metadata: request-metadata,
        method: string,
        uri: string,
        headers: list<header>
    ) -> agent-response;

    /// Process request body chunk (optional)
    on-request-body: func(
        correlation-id: string,
        data: list<u8>,
        chunk-index: u32,
        is-last: bool
    ) -> agent-response;

    /// Process response headers (optional)
    on-response-headers: func(
        correlation-id: string,
        status: u16,
        headers: list<header>
    ) -> agent-response;

    /// Process response body chunk (optional)
    on-response-body: func(
        correlation-id: string,
        data: list<u8>,
        chunk-index: u32,
        is-last: bool
    ) -> agent-response;
}

/// Agent lifecycle interface
interface lifecycle {
    /// Get agent capabilities
    get-capabilities: func() -> string;

    /// Health check
    health-check: func() -> string;

    /// Graceful shutdown
    shutdown: func();
}

/// The complete agent world
world agent {
    export handler;
    export lifecycle;
}
```

---

## Migration Path

### Timeline

| Phase | Timeline | Changes |
|-------|----------|---------|
| **v2-perf** | Q2 2025 | **NEW:** Performance foundation (connection pooling, atomic locks, parallel agents) |
| **v2-alpha** | Q3 2025 | Capability handshake, health reporting |
| **v2-beta** | Q4 2025 | Bidirectional streaming, binary protocol, cancellation, flow control |
| **v2-rc** | Q1 2026 | WASM runtime, metrics export, config push |
| **v2-stable** | Q2 2026 | Full release, v1 deprecated (not removed) |
| **v1-removal** | Q1 2027 | v1 support removed |

> **⚠️ Important:** v2-perf phase is a **hard prerequisite** for v2-beta. Do not ship bidirectional streaming without fixing the v1 performance bottlenecks, or they will be amplified under streaming load.

### Backward Compatibility

1. **Version detection**: Proxy detects protocol version during handshake
2. **Fallback mode**: v2 agents can operate in v1 mode if needed
3. **v1 agents**: Continue working with v2 proxy (no new features)
4. **Gradual adoption**: Features can be adopted incrementally

### Handshake Flow

```
Agent connects → Sends HandshakeRequest with capabilities
                 ↓
Proxy validates → Sends HandshakeResponse with accepted features
                 ↓
If v2 supported → Use bidirectional streaming
If v1 only     → Fall back to request/response
```

---

## Implementation Plan

> **Note:** Phase 0 is new and addresses critical v1 performance issues that block v2 adoption.

### Phase 0: Performance Foundation (v2-perf) ⚠️ BLOCKING

**Goal:** Fix v1 bottlenecks that will affect v2 performance. These changes are backward-compatible with v1 protocol.

**Timeline:** Must complete before Phase 2 (streaming).

#### 0.1 Lock-Free Circuit Breaker (P0)
- [ ] Replace `RwLock<CircuitState>` with `AtomicU8` for state
- [ ] Replace `RwLock<u32>` with `AtomicU32` for failure_count
- [ ] Replace `RwLock<Instant>` with `AtomicU64` for timestamps
- [ ] Benchmark: target <100ns for `is_closed()` check
- [ ] Update `crates/common/src/circuit_breaker.rs`

#### 0.2 Connection Pooling (P0)
- [ ] Implement `AgentConnectionPool::get()` and `return()` methods
- [ ] Use `crossbeam::deque::Worker` or similar for lockless pool
- [ ] Configurable pool size per agent (default: 8, max: 32)
- [ ] Health-aware connection selection (prefer healthy connections)
- [ ] Update `crates/proxy/src/agents/agent.rs`
- [ ] Benchmark: target 10K RPS with 50ms agent latency

#### 0.3 Parallel Agent Execution (P0)
- [ ] Identify independent vs dependent agent chains
- [ ] Use `futures::join_all()` for independent agents
- [ ] Preserve sequential execution for dependent agents
- [ ] Add `parallel: bool` flag to agent chain config
- [ ] Update `crates/proxy/src/agents/manager.rs`
- [ ] Benchmark: 3-agent chain should be ~1x agent latency, not 3x

#### 0.4 Atomic Timestamps and Counters (P2)
- [ ] Replace `last_success: RwLock<Option<Instant>>` with atomic
- [ ] Replace `last_failure` similarly
- [ ] Cache semaphores per-request, not per-agent-call
- [ ] Update `crates/proxy/src/agents/agent.rs`

**Exit Criteria:**
- [ ] Load test: 1000 RPS with 3 agents, p99 < 100ms (with 30ms agent latency)
- [ ] No async locks in hot path (verified by code review)
- [ ] Memory stable under 1-hour soak test

### Phase 1: Core Protocol (v2-alpha)

1. ✅ Define protobuf schema for v2 messages
2. ✅ Implement capability handshake types
3. ✅ Implement health reporting types
4. ✅ Update agent-protocol crate with v2 types
5. [ ] Add v2 server implementation with v1 fallback
6. [ ] Add v2 client with connection multiplexing

### Phase 2: Streaming & Binary Protocol (v2-beta)

**Prerequisite:** Phase 0 complete.

#### 2.1 Bidirectional Streaming
- [ ] Implement gRPC bidirectional ProcessStream
- [ ] Implement separate ControlStream for health/metrics
- [ ] Add cancellation support
- [ ] Add flow control / backpressure

#### 2.2 Binary Protocol for UDS (P1)
- [ ] Add binary framing option: `[4-byte len][1-byte type][payload]`
- [ ] Remove base64 encoding for body data over UDS
- [ ] Use `bytes::Bytes` instead of `Vec<u8>` for zero-copy
- [ ] Keep JSON as fallback for debugging/HTTP transport
- [ ] Update `crates/agent-protocol/src/client.rs`

#### 2.3 Zero-Copy Headers (P1)
- [ ] Replace `HashMap<String, String>` clone with `Cow` or reference
- [ ] Implement header iterator that doesn't allocate
- [ ] Update `crates/proxy/src/agents/manager.rs`

#### 2.4 Buffer Pooling (P2)
- [ ] Implement message buffer pool using `slab` or `bytes::BytesMut`
- [ ] Target: reuse buffers for messages < 64KB
- [ ] Allocate fresh only for large messages

### Phase 3: WASM Runtime (v2-rc)

1. Integrate Wasmtime runtime
2. Implement WIT bindings
3. Create WASM agent SDK
4. Build example WASM agents
5. Add resource limits (memory, CPU fuel)

### Phase 4: Observability (v2-stable)

1. Implement metrics export
2. Implement config push
3. Add unified metrics aggregation
4. Documentation and migration guides

### Phase Dependency Graph

```
Phase 0 (perf foundation)
    │
    ├──► Phase 1 (core protocol) ──► Phase 3 (WASM)
    │                                    │
    └──► Phase 2 (streaming) ───────────►│
                                         ▼
                                    Phase 4 (observability)
```

### Milestone Checkpoints

| Milestone | Criteria | Target |
|-----------|----------|--------|
| **v2-perf-ready** | Phase 0 complete, load tests pass | Before streaming work |
| **v2-alpha** | Phase 1 complete, capability handshake working | Q3 2025 |
| **v2-beta** | Phase 2 complete, binary protocol + streaming | Q4 2025 |
| **v2-rc** | Phase 3 complete, WASM agents functional | Q1 2026 |
| **v2-stable** | Phase 4 complete, full observability | Q2 2026 |

---

## Security Considerations

### WASM Sandboxing

- Memory limits enforced by Wasmtime
- No filesystem access by default
- No network access from WASM
- CPU time limits per invocation
- Capability-based permissions for optional features

### gRPC Security

- mTLS required for remote agents
- Agent authentication via certificates
- Rate limiting on control plane messages
- Audit logging for config updates

### Resource Limits

```rust
pub struct WasmAgentLimits {
    /// Max memory per agent instance (bytes)
    pub max_memory: usize,           // Default: 64MB

    /// Max execution time per call (ms)
    pub max_execution_time_ms: u64,  // Default: 100ms

    /// Max instances per agent type
    pub max_instances: u32,          // Default: 4

    /// Max fuel (instructions) per call
    pub max_fuel: u64,               // Default: 10_000_000
}
```

---

## Appendix: Metric Names

### Standard Agent Metrics

Agents SHOULD report these metrics with standard names:

| Metric | Type | Description |
|--------|------|-------------|
| `agent_requests_total` | Counter | Total requests processed |
| `agent_requests_blocked_total` | Counter | Requests blocked |
| `agent_requests_duration_seconds` | Histogram | Processing duration |
| `agent_errors_total` | Counter | Processing errors |
| `agent_in_flight_requests` | Gauge | Current in-flight |
| `agent_queue_depth` | Gauge | Request queue size |

### Labels

| Label | Description |
|-------|-------------|
| `agent_id` | Agent identifier |
| `route_id` | Route that invoked agent |
| `decision` | allow, block, redirect |
| `rule_id` | Matched rule (if applicable) |

---

## Risk Register

### Performance Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| **Event loop starvation under load** | Critical | High (if unfixed) | Phase 0 must complete before v2-beta |
| **Memory pressure from buffer allocation** | High | Medium | Buffer pooling in Phase 2.4 |
| **Agent timeout cascade** | High | Medium | Connection pooling isolates failures |
| **Streaming amplifies v1 bottlenecks** | Critical | Certain | Phase 0 is hard prerequisite for Phase 2 |

### Architectural Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| **Binary protocol complexity** | Medium | Medium | Keep JSON as fallback, phase in binary |
| **WASM sandbox escape** | Critical | Low | Use Wasmtime with strict limits, no WASI |
| **Backward compatibility breaks** | High | Medium | Version negotiation in handshake |
| **Agent overload cascading to dataplane** | High | Medium | Circuit breakers, per-agent semaphores |

### Operational Risks

| Risk | Severity | Likelihood | Mitigation |
|------|----------|------------|------------|
| **Complex debugging with binary protocol** | Medium | High | JSON mode for debugging, protocol logging |
| **Rolling upgrade failures** | High | Medium | Graceful degradation, v1 fallback |
| **Config drift between proxy and agents** | Medium | Medium | Config push with version tracking |

### Testing Requirements

Before each phase ships, the following tests must pass:

#### Phase 0 Exit Tests
```bash
# Connection pooling test
wrk -t4 -c100 -d60s --latency http://localhost:8080/agent-path
# Target: p99 < 100ms with 50ms agent latency

# Circuit breaker test (no async locks)
cargo bench --package zentinel-common -- circuit_breaker
# Target: is_closed() < 100ns

# Parallel agent test
./scripts/test-parallel-agents.sh
# Target: 3 agents @ 30ms each = total < 50ms (not 90ms)
```

#### Phase 2 Exit Tests
```bash
# Binary protocol benchmark
./scripts/bench-protocols.sh
# Target: Binary 2x faster than JSON

# Streaming load test
./scripts/streaming-load-test.sh
# Target: 10K concurrent streams, stable memory

# Memory soak test
./scripts/soak-test.sh --duration=1h
# Target: RSS growth < 10% over baseline
```

---

## Appendix: Quick Reference

### Priority Definitions

| Priority | Definition | SLA |
|----------|------------|-----|
| **P0** | Blocks production use, event loop at risk | Must fix in Phase 0 |
| **P1** | Significant performance impact | Must fix in Phase 2 |
| **P2** | Measurable impact, not critical | Fix when convenient |

### Files to Modify (Summary)

| File | Issues | Phase |
|------|--------|-------|
| `crates/common/src/circuit_breaker.rs` | #2 (async locks) | 0.1 |
| `crates/proxy/src/agents/agent.rs` | #1 (single conn), #9 (timestamp lock) | 0.2, 0.4 |
| `crates/proxy/src/agents/manager.rs` | #3 (sequential), #4 (base64), #6 (clone), #7 (loop lock) | 0.3, 2.2, 2.3 |
| `crates/agent-protocol/src/client.rs` | #5 (JSON), #8 (allocation) | 2.2, 2.4 |

### Recommended Dependencies

```toml
# For lock-free data structures
crossbeam = "0.8"

# For atomic timestamps
portable-atomic = "1.0"  # If targeting 32-bit

# For buffer pooling
bytes = "1.0"  # Already in use
slab = "0.4"   # Optional: for buffer reuse

# For binary protocol (choose one)
rmp-serde = "1.0"    # MessagePack - simpler
# OR
capnp = "0.19"       # Cap'n Proto - zero-copy
```

---

## References

- [Envoy External Processing](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
- [HAProxy SPOE](https://www.haproxy.org/download/2.0/doc/SPOE.txt)
- [WebAssembly Component Model](https://component-model.bytecodealliance.org/)
- [gRPC Bidirectional Streaming](https://grpc.io/docs/what-is-grpc/core-concepts/#bidirectional-streaming-rpc)
- [Crossbeam Deque](https://docs.rs/crossbeam-deque/latest/crossbeam_deque/) - Lock-free work-stealing deques
- [Tokio Best Practices](https://tokio.rs/tokio/tutorial/shared-state) - Avoiding async lock contention
