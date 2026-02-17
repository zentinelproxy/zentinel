# Agent Protocol v2 Performance Roadmap

> Performance bottlenecks identified during hot-path analysis for Pingora integration.
> Last updated: 2026-01-14

## Status Overview

| Priority | Issue | Status |
|----------|-------|--------|
| P0 | Lock contention in AgentPool | **Complete** |
| P0 | Per-request async health checks | **Complete** |
| P0 | RwLock in last_used tracking | **Complete** |
| P1 | JSON serialization in UDS hot path | **Complete** |
| P1 | Base64 body chunk encoding | **Complete** |
| P2 | Flow control not enforced | **Complete** |
| P2 | Buffer size mismatch (UDS vs gRPC) | **Complete** |
| P2 | Header allocation patterns | **Complete** |
| P3 | Metrics integration | **Complete** |
| P3 | Connection affinity | **Complete** |
| P3 | Zero-copy body streaming | **Complete** |

---

## Completed (P0)

### Lock Contention in AgentPool

**Commit:** `7e92035` (2025-01-14)

**Problem:** Global `RwLock<HashMap>` on agents map caused contention under high concurrency.

**Solution:**
- Replaced `RwLock<HashMap<String, Arc<AgentEntry>>>` with `DashMap`
- Agent lookup is now O(1) lock-free for reads
- Only writes (add/remove agent) take a shard lock

### Per-Request Async Health Checks

**Problem:** `select_connection()` called `is_healthy().await` for every connection, doing I/O in the hot path.

**Solution:**
- Added `healthy_cached: AtomicBool` to `PooledConnection`
- Background maintenance task updates cached health via `check_and_update_health()`
- Hot path uses `is_healthy_cached()` - atomic read, no I/O

### RwLock in last_used Tracking

**Problem:** `last_used: RwLock<Instant>` required write lock on every request.

**Solution:**
- Changed to `last_used_offset_ms: AtomicU64` storing milliseconds since `created_at`
- Added `touch()` method for atomic updates
- Added `last_used()` method to reconstruct `Instant` when needed

**Hot-path sync points reduced:** 4 → 2 per request

---

## Completed (P1)

### JSON Serialization in UDS Hot Path

**Date:** 2026-01-14

**Solution:** MessagePack encoding with negotiation
- Added `UdsEncoding` enum with `Json` and `MessagePack` variants
- Encoding negotiated during handshake via `supported_encodings` field
- `binary-uds` feature flag enables MessagePack support
- Helper methods `UdsEncoding::serialize()` and `deserialize()` abstract encoding

**Usage:**
```rust
// Enable in Cargo.toml
zentinel-agent-protocol = { version = "0.3", features = ["binary-uds"] }

// Encoding is negotiated automatically during connect()
```

### Base64 Body Chunk Encoding

**Date:** 2026-01-14

**Solution:** Binary body chunk types with `Bytes` data field
- Added `BinaryRequestBodyChunkEvent` and `BinaryResponseBodyChunkEvent`
- Conversion traits handle base64 decode from legacy types
- gRPC conversion routes through binary types to avoid double-conversion

**Types:**
```rust
pub struct BinaryRequestBodyChunkEvent {
    pub correlation_id: String,
    pub data: Bytes,  // Raw bytes, no encoding
    pub is_last: bool,
    pub total_size: Option<usize>,
    pub chunk_index: u32,
    pub bytes_received: usize,
}
```

---

## Completed (P2)

### Flow Control Enforcement

**Date:** 2026-01-14

**Solution:** Flow control now enforced in all send methods
- Added `FlowControlPaused { agent_id }` error variant
- Added `is_paused()` and `can_accept_requests()` methods to UDS and Reverse clients
- All `AgentPool::send_*` methods check flow control before sending
- Returns error immediately when agent has requested backpressure

**Implementation:**
```rust
// In AgentPool send methods:
if !conn.client.can_accept_requests().await {
    return Err(AgentProtocolError::FlowControlPaused {
        agent_id: agent_id.to_string(),
    });
}
```

### Buffer Size Alignment

**Date:** 2026-01-14

**Solution:** Unified buffer size across all transports
- Added `CHANNEL_BUFFER_SIZE = 64` constant in `pool.rs`
- Updated all channel creations: UDS, gRPC client, gRPC server, Reverse connections

| Transport | Before | After |
|-----------|--------|-------|
| gRPC client | 32 | 64 |
| gRPC server | 32 | 64 |
| UDS | 1024 | 64 |
| Reverse | 1024 | 64 |

### Header Allocation Patterns

**Date:** 2026-01-14

**Solution:** SmallVec-based header types and iteration helpers
- Added `smallvec` dependency with serde feature
- `HeaderValues = SmallVec<[String; 1]>` stores single header values inline
- `OptimizedHeaderMap = HashMap<String, HeaderValues>` for optimized storage
- `iter_flat()` provides zero-allocation iteration for gRPC conversion

**Types:**
```rust
use smallvec::SmallVec;

/// Single-value headers stored inline (no heap allocation)
pub type HeaderValues = SmallVec<[String; 1]>;

/// Optimized header map
pub type OptimizedHeaderMap = HashMap<String, HeaderValues>;

/// Zero-allocation iteration
pub fn iter_flat(headers: &HashMap<String, Vec<String>>) -> impl Iterator<Item = (&str, &str)>;
```

---

## Completed (P3)

### Metrics Integration

**Date:** 2026-01-14

**Solution:** Protocol-level metrics with atomic counters and histograms
- `ProtocolMetrics` struct with counters, gauges, and histograms
- Counters for requests, responses, timeouts, errors, flow control events
- Gauges for in-flight requests, buffer utilization, healthy/paused connections
- Histograms for serialization time and request duration (μs precision)
- Prometheus export format support

**Usage:**
```rust
// Access metrics from AgentPool
let metrics = pool.protocol_metrics();

// Get snapshot
let snapshot = metrics.snapshot();

// Export to Prometheus format
let prometheus_text = metrics.to_prometheus("agent_protocol");
```

### Connection Affinity

**Date:** 2026-01-14

**Solution:** Correlation ID to connection mapping for streaming consistency
- `correlation_affinity: DashMap<String, Arc<PooledConnection>>` in AgentPool
- `send_request_headers` stores connection for correlation_id
- `send_request_body_chunk` looks up affinity before falling back to selection
- Lock-free concurrent access via DashMap

**Usage:**
```rust
// Body chunks automatically routed to same connection as headers
pool.send_request_body_chunk("waf", "correlation-123", &chunk).await?;

// Cleanup after request completes
pool.clear_correlation_affinity("correlation-123");
```

### Zero-Copy Body Streaming

**Date:** 2026-01-14

**Solution:** Binary body chunk methods that avoid base64 encoding
- `send_request_body_chunk_binary()` takes `BinaryRequestBodyChunkEvent`
- `send_response_body_chunk_binary()` takes `BinaryResponseBodyChunkEvent`
- MessagePack path: raw bytes via `serde_bytes` (no base64)
- JSON path: base64 encoding for JSON compatibility

**Usage:**
```rust
use zentinel_agent_protocol::{BinaryRequestBodyChunkEvent, Bytes};

// Create binary body chunk
let chunk = BinaryRequestBodyChunkEvent::new(
    "correlation-123",
    Bytes::from_static(b"binary data"),
    0,  // chunk_index
    false,  // is_last
);

// Send via UDS (uses raw bytes with MessagePack encoding)
client.send_request_body_chunk_binary(&chunk).await?;
```

**Performance:**
- MessagePack serialization is ~33% more compact than JSON+base64 for binary data
- No CPU-intensive base64 encode/decode in hot path when using MessagePack

---

## Measurement Plan

### Benchmarks to Add

```rust
// benches/hot_path.rs

#[bench]
fn bench_select_connection(b: &mut Bencher) {
    // Measure connection selection latency
}

#[bench]
fn bench_send_request_headers_uds(b: &mut Bencher) {
    // Measure full UDS send path including serialization
}

#[bench]
fn bench_body_chunk_streaming(b: &mut Bencher) {
    // Measure body chunk throughput with various sizes
}
```

### Profiling Commands

```bash
# CPU profile under load
cargo flamegraph --bin zentinel -- --config config/zentinel.kdl

# Allocation tracking
DHAT_LOG=allocations cargo test -p zentinel-agent-protocol

# Latency histogram
wrk -t4 -c100 -d30s --latency http://localhost:8080/
```

---

## References

- [Original critique analysis](../.claude/agent-protocol-bottlenecks-roadmap.md)
- [Agent Protocol v2 Design](../../../AGENT_PROTOCOL_2.0.md)
- [Pingora Integration Patterns](../../proxy/docs/agents.md)
