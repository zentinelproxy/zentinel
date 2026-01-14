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
| P2 | Header allocation patterns | Planned |

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
sentinel-agent-protocol = { version = "0.3", features = ["binary-uds"] }

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

---

## Planned (P2) - High

### Header Allocation Patterns

**Location:** `src/protocol.rs:203`, `src/v2/client.rs:836-845`

**Problem:** Headers use allocation-heavy structures:
```rust
pub headers: HashMap<String, Vec<String>>,
```

Conversion to gRPC clones every header:
```rust
let headers: Vec<grpc_v2::Header> = event.headers.iter()
    .flat_map(|(name, values)| {
        values.iter().map(|v| grpc_v2::Header {
            name: name.clone(),   // Clone!
            value: v.clone(),     // Clone!
        })
    })
    .collect();
```

**Impact:** ~40+ allocations for typical 20-header request.

**Proposed Solution:**
```rust
use smallvec::SmallVec;
use std::borrow::Cow;

// Most headers have single value - inline it
pub headers: Vec<(Cow<'static, str>, SmallVec<[Cow<'_, str>; 1]>)>,
```

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
cargo flamegraph --bin sentinel -- --config config/sentinel.kdl

# Allocation tracking
DHAT_LOG=allocations cargo test -p sentinel-agent-protocol

# Latency histogram
wrk -t4 -c100 -d30s --latency http://localhost:8080/
```

---

## References

- [Original critique analysis](../.claude/agent-protocol-bottlenecks-roadmap.md)
- [Agent Protocol v2 Design](../../../AGENT_PROTOCOL_2.0.md)
- [Pingora Integration Patterns](../../proxy/docs/agents.md)
