# Connection Pooling

This document covers the AgentPool connection pooling system, including load balancing strategies, health tracking, and circuit breakers.

## Overview

The `AgentPool` maintains multiple connections per agent for:

- **Higher throughput**: Parallel request processing
- **Lower latency**: Reduced connection overhead
- **Better reliability**: Automatic failover between connections
- **Smart routing**: Load-balanced request distribution

```
┌─────────────────────────────────────────────────────────────┐
│                        AgentPool                            │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Agent: waf    │  │  Agent: auth    │                  │
│  │                 │  │                 │                  │
│  │  ┌───────────┐  │  │  ┌───────────┐  │                  │
│  │  │ Conn 1    │  │  │  │ Conn 1    │  │                  │
│  │  │ (gRPC)    │  │  │  │ (UDS)     │  │                  │
│  │  ├───────────┤  │  │  ├───────────┤  │                  │
│  │  │ Conn 2    │  │  │  │ Conn 2    │  │                  │
│  │  │ (gRPC)    │  │  │  │ (UDS)     │  │                  │
│  │  ├───────────┤  │  │  ├───────────┤  │                  │
│  │  │ Conn 3    │  │  │  │ Conn 3    │  │                  │
│  │  │ (gRPC)    │  │  │  │ (UDS)     │  │                  │
│  │  ├───────────┤  │  │  ├───────────┤  │                  │
│  │  │ Conn 4    │  │  │  │ Conn 4    │  │                  │
│  │  │ (gRPC)    │  │  │  │ (UDS)     │  │                  │
│  │  └───────────┘  │  │  └───────────┘  │                  │
│  │                 │  │                 │                  │
│  │  Health: OK     │  │  Health: OK     │                  │
│  │  In-flight: 12  │  │  In-flight: 8   │                  │
│  └─────────────────┘  └─────────────────┘                  │
│                                                             │
│  Load Balancer: LeastConnections                           │
│  Circuit Breaker: Enabled                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration

### Basic Setup

```rust
use sentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};
use std::time::Duration;

let config = AgentPoolConfig {
    connections_per_agent: 4,
    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
    request_timeout: Duration::from_secs(30),
    connect_timeout: Duration::from_secs(5),
    health_check_interval: Duration::from_secs(10),
    circuit_breaker_threshold: 5,
    circuit_breaker_reset_timeout: Duration::from_secs(30),
};

let pool = AgentPool::with_config(config);
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `connections_per_agent` | 4 | Number of connections maintained per agent |
| `load_balance_strategy` | LeastConnections | How requests are distributed |
| `request_timeout` | 30s | Timeout for individual requests |
| `connect_timeout` | 5s | Timeout for establishing connections |
| `health_check_interval` | 10s | Interval between health checks |
| `circuit_breaker_threshold` | 5 | Failures before opening circuit |
| `circuit_breaker_reset_timeout` | 30s | Time before circuit resets |

---

## Load Balancing Strategies

### RoundRobin

Distributes requests evenly across all connections in rotation.

```rust
let config = AgentPoolConfig {
    load_balance_strategy: LoadBalanceStrategy::RoundRobin,
    ..Default::default()
};
```

**Behavior**:
```
Request 1 → Connection 1
Request 2 → Connection 2
Request 3 → Connection 3
Request 4 → Connection 4
Request 5 → Connection 1  (wraps around)
```

**Best for**: Uniform request processing times, simple distribution.

### LeastConnections

Routes to the connection with the fewest in-flight requests.

```rust
let config = AgentPoolConfig {
    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
    ..Default::default()
};
```

**Behavior**:
```
Connection 1: 3 in-flight
Connection 2: 1 in-flight  ← Next request goes here
Connection 3: 4 in-flight
Connection 4: 2 in-flight
```

**Best for**: Variable request processing times, optimal latency.

### HealthBased

Prefers healthier connections based on recent error rates.

```rust
let config = AgentPoolConfig {
    load_balance_strategy: LoadBalanceStrategy::HealthBased,
    ..Default::default()
};
```

**Behavior**:
```
Connection 1: Health 100%, Weight 1.0
Connection 2: Health 95%,  Weight 0.95
Connection 3: Health 80%,  Weight 0.80  (recent errors)
Connection 4: Health 100%, Weight 1.0

Weighted random selection favors healthy connections
```

**Best for**: Unreliable networks, degraded agent instances.

### Random

Random selection for simple distribution.

```rust
let config = AgentPoolConfig {
    load_balance_strategy: LoadBalanceStrategy::Random,
    ..Default::default()
};
```

**Best for**: Testing, simple deployments.

---

## Health Tracking

### Connection Health

Each connection tracks:

- **Success rate**: Percentage of successful requests
- **Average latency**: Recent request latencies
- **Last error**: Most recent error and timestamp
- **State**: Healthy, Degraded, or Unhealthy

```rust
let health = pool.get_health("waf")?;

println!("Agent: {}", health.agent_name);
println!("Connections: {}", health.total_connections);
println!("Healthy: {}", health.healthy_connections);
println!("Success rate: {:.2}%", health.success_rate * 100.0);
println!("Avg latency: {:?}", health.average_latency);
```

### Health States

| State | Criteria | Behavior |
|-------|----------|----------|
| Healthy | Success rate > 95% | Normal routing |
| Degraded | Success rate 80-95% | Reduced weight in HealthBased |
| Unhealthy | Success rate < 80% | Minimal traffic, recovery checks |

### Automatic Recovery

Unhealthy connections are periodically tested:

```
┌──────────────────────────────────────────────────────────┐
│                    Health Check Loop                      │
│                                                          │
│   Every health_check_interval:                           │
│   ┌────────────────────────────────────────────────┐    │
│   │ For each connection:                            │    │
│   │   1. Send health check request                  │    │
│   │   2. Update health metrics                      │    │
│   │   3. Transition state if needed                 │    │
│   │   4. Trigger reconnect if unhealthy            │    │
│   └────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

---

## Circuit Breaker

### Overview

The circuit breaker prevents cascading failures by temporarily disabling unhealthy agents.

```
         ┌─────────┐
         │ Closed  │  Normal operation
         │ (Pass)  │
         └────┬────┘
              │ threshold failures
              ▼
         ┌─────────┐
         │  Open   │  Fail fast, no requests sent
         │ (Fail)  │
         └────┬────┘
              │ reset_timeout elapsed
              ▼
        ┌──────────┐
        │Half-Open │  Allow one test request
        │ (Test)   │
        └────┬─────┘
             │
    ┌────────┴────────┐
    │                 │
    ▼ success         ▼ failure
┌─────────┐      ┌─────────┐
│ Closed  │      │  Open   │
└─────────┘      └─────────┘
```

### Configuration

```rust
let config = AgentPoolConfig {
    circuit_breaker_threshold: 5,        // Open after 5 failures
    circuit_breaker_reset_timeout: Duration::from_secs(30),
    ..Default::default()
};
```

### States

| State | Behavior |
|-------|----------|
| **Closed** | Requests pass through normally |
| **Open** | Requests fail immediately with error |
| **Half-Open** | One request allowed to test recovery |

### Monitoring

```rust
let health = pool.get_health("waf")?;

match health.circuit_breaker_state {
    CircuitBreakerState::Closed => {
        // Normal operation
    }
    CircuitBreakerState::Open { opened_at } => {
        tracing::warn!("Circuit open since {:?}", opened_at);
    }
    CircuitBreakerState::HalfOpen => {
        tracing::info!("Circuit testing recovery");
    }
}
```

---

## Request Flow

### Successful Request

```
┌──────────┐     ┌───────────────┐     ┌──────────────┐     ┌───────┐
│  Caller  │     │  AgentPool    │     │ LoadBalancer │     │ Agent │
└────┬─────┘     └───────┬───────┘     └──────┬───────┘     └───┬───┘
     │                   │                    │                 │
     │ send_request()    │                    │                 │
     │──────────────────►│                    │                 │
     │                   │                    │                 │
     │                   │ select_connection()│                 │
     │                   │───────────────────►│                 │
     │                   │                    │                 │
     │                   │◄──────────────────│                 │
     │                   │   connection       │                 │
     │                   │                    │                 │
     │                   │ send_message()     │                 │
     │                   │────────────────────────────────────►│
     │                   │                    │                 │
     │                   │◄────────────────────────────────────│
     │                   │   response         │                 │
     │                   │                    │                 │
     │                   │ update_health()    │                 │
     │                   │───────────────────►│                 │
     │                   │                    │                 │
     │◄──────────────────│                    │                 │
     │   response        │                    │                 │
```

### Failed Request (Circuit Closed)

```
┌──────────┐     ┌───────────────┐     ┌────────────────┐
│  Caller  │     │  AgentPool    │     │ CircuitBreaker │
└────┬─────┘     └───────┬───────┘     └───────┬────────┘
     │                   │                     │
     │ send_request()    │                     │
     │──────────────────►│                     │
     │                   │                     │
     │                   │ check_state()       │
     │                   │────────────────────►│
     │                   │                     │
     │                   │◄────────────────────│
     │                   │   Open              │
     │                   │                     │
     │◄──────────────────│                     │
     │   Error::         │                     │
     │   CircuitOpen     │                     │
```

---

## Metrics

### Pool Metrics

```rust
let metrics = pool.metrics_collector();
let snapshot = metrics.snapshot();

// Per-agent metrics
for agent in &snapshot.agents {
    println!("Agent: {}", agent.name);
    println!("  Total requests: {}", agent.total_requests);
    println!("  Success rate: {:.2}%", agent.success_rate * 100.0);
    println!("  Avg latency: {:?}", agent.average_latency);
    println!("  Active connections: {}", agent.active_connections);
    println!("  In-flight requests: {}", agent.in_flight_requests);
}
```

### Prometheus Export

```rust
let prometheus_output = metrics.export_prometheus();
```

Output:
```prometheus
# HELP agent_requests_total Total number of requests to agents
# TYPE agent_requests_total counter
agent_requests_total{agent="waf",decision="allow"} 15234
agent_requests_total{agent="waf",decision="block"} 423
agent_requests_total{agent="auth",decision="allow"} 8921

# HELP agent_request_duration_seconds Request duration histogram
# TYPE agent_request_duration_seconds histogram
agent_request_duration_seconds_bucket{agent="waf",le="0.001"} 5234
agent_request_duration_seconds_bucket{agent="waf",le="0.005"} 12453
agent_request_duration_seconds_bucket{agent="waf",le="0.01"} 14876

# HELP agent_connections_active Current number of active connections
# TYPE agent_connections_active gauge
agent_connections_active{agent="waf"} 4
agent_connections_active{agent="auth"} 4

# HELP agent_circuit_breaker_state Circuit breaker state (0=closed, 1=open)
# TYPE agent_circuit_breaker_state gauge
agent_circuit_breaker_state{agent="waf"} 0
agent_circuit_breaker_state{agent="auth"} 0
```

---

## Best Practices

### 1. Size Your Pool Appropriately

```rust
// For high-throughput: more connections
let high_throughput = AgentPoolConfig {
    connections_per_agent: 8,
    ..Default::default()
};

// For low-latency: fewer connections, faster timeouts
let low_latency = AgentPoolConfig {
    connections_per_agent: 2,
    request_timeout: Duration::from_millis(100),
    ..Default::default()
};
```

### 2. Choose the Right Load Balancer

| Scenario | Recommended Strategy |
|----------|---------------------|
| Uniform workload | RoundRobin |
| Variable latency | LeastConnections |
| Unreliable agents | HealthBased |
| Testing | Random |

### 3. Tune Circuit Breaker

```rust
// Aggressive (fail fast)
let aggressive = AgentPoolConfig {
    circuit_breaker_threshold: 3,
    circuit_breaker_reset_timeout: Duration::from_secs(10),
    ..Default::default()
};

// Conservative (more tolerance)
let conservative = AgentPoolConfig {
    circuit_breaker_threshold: 10,
    circuit_breaker_reset_timeout: Duration::from_secs(60),
    ..Default::default()
};
```

### 4. Monitor and Alert

```rust
// Set up monitoring
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        let metrics = pool.metrics_collector().snapshot();

        for agent in &metrics.agents {
            if agent.success_rate < 0.95 {
                tracing::warn!(
                    agent = %agent.name,
                    success_rate = %agent.success_rate,
                    "Agent success rate degraded"
                );
            }
        }
    }
});
```

### 5. Graceful Shutdown

```rust
async fn shutdown(pool: &AgentPool) {
    // Cancel all in-flight requests
    for agent_name in pool.agent_names() {
        if let Err(e) = pool.cancel_all(&agent_name).await {
            tracing::error!("Failed to cancel requests for {}: {}", agent_name, e);
        }
    }

    // Wait for connections to drain
    tokio::time::sleep(Duration::from_secs(5)).await;
}
```

---

## Performance Optimizations

The `AgentPool` is optimized for high-throughput, low-latency operation in the Pingora hot path. Several key optimizations reduce lock contention and avoid async I/O during connection selection.

### Lock-Free Agent Lookup

Agent entries are stored in a `DashMap` rather than `RwLock<HashMap>`, enabling:

- **Lock-free reads**: Agent lookup is O(1) without acquiring any lock
- **Sharded writes**: Only agent add/remove operations take a shard lock
- **High concurrency**: Multiple requests can look up agents simultaneously

```rust
// Internal structure (simplified)
pub struct AgentPool {
    agents: DashMap<String, Arc<AgentEntry>>,
    // ...
}
```

### Cached Health State

Connection health is cached in an `AtomicBool` to avoid async I/O in the hot path:

```rust
// Hot path: atomic read, no I/O
let healthy = connection.is_healthy_cached();

// Background maintenance task updates the cache
connection.check_and_update_health().await;
```

This separates concerns:
- **Hot path**: Uses cached health (atomic read)
- **Background task**: Performs actual health checks and updates cache

### Synchronous Connection Selection

The `select_connection()` method is fully synchronous, avoiding async overhead:

```rust
// No .await in the selection path
fn select_connection(&self, agent_id: &str) -> Result<Arc<PooledConnection>, Error> {
    let entry = self.agents.get(agent_id)?;
    let connections = entry.connections.try_read()?;

    // Filter by cached health
    let healthy: Vec<_> = connections.iter()
        .filter(|c| c.is_healthy_cached())
        .collect();

    // Apply load balancing strategy
    self.load_balancer.select(&healthy)
}
```

### Atomic Timestamp Tracking

The `last_used` timestamp uses `AtomicU64` instead of `RwLock<Instant>`:

```rust
// Atomic update, no lock
connection.touch();

// Reconstruct Instant when needed (rare path)
let last_used = connection.last_used();
```

### Immediate Health Marking

Consecutive errors immediately mark connections as unhealthy without waiting for the next health check:

```rust
// After N consecutive errors, mark unhealthy immediately
if consecutive_errors >= UNHEALTHY_THRESHOLD {
    connection.mark_unhealthy();
}
```

### Performance Characteristics

| Operation | Latency | Sync Points |
|-----------|---------|-------------|
| Agent lookup | ~100ns | 0 (lock-free) |
| Connection selection | ~1μs | 1 (try_read) |
| Health check (cached) | ~10ns | 0 (atomic) |
| Timestamp update | ~10ns | 0 (atomic) |

**Total hot-path sync points per request:** 2 (down from 4 in earlier versions)

---

## Protocol Metrics

The `AgentPool` includes built-in protocol-level metrics for monitoring performance and health.

### Accessing Metrics

```rust
// Get metrics instance
let metrics = pool.protocol_metrics();

// Get point-in-time snapshot
let snapshot = metrics.snapshot();

// Export to Prometheus format
let prometheus_text = metrics.to_prometheus("agent_protocol");
```

### Available Metrics

| Type | Metric | Description |
|------|--------|-------------|
| Counter | `requests_total` | Total requests sent |
| Counter | `responses_total` | Total responses received |
| Counter | `timeouts_total` | Requests that timed out |
| Counter | `connection_errors_total` | Connection failures |
| Counter | `serialization_errors_total` | Serialization failures |
| Counter | `flow_control_pauses_total` | Agent pause signals |
| Counter | `flow_control_resumes_total` | Agent resume signals |
| Counter | `flow_control_rejections_total` | Requests rejected due to flow control |
| Gauge | `in_flight_requests` | Current in-flight requests |
| Gauge | `buffer_utilization_percent` | Channel buffer utilization |
| Gauge | `healthy_connections` | Number of healthy connections |
| Gauge | `paused_connections` | Number of paused connections |
| Histogram | `serialization_time_us` | Serialization latency (μs) |
| Histogram | `request_duration_us` | End-to-end request latency (μs) |

### Prometheus Export

```rust
let prometheus = pool.protocol_metrics().to_prometheus("agent_protocol");
```

Output:
```prometheus
# HELP agent_protocol_requests_total Total requests sent
# TYPE agent_protocol_requests_total counter
agent_protocol_requests_total 12345

# HELP agent_protocol_request_duration_us Request duration histogram
# TYPE agent_protocol_request_duration_us histogram
agent_protocol_request_duration_us_bucket{le="100"} 5234
agent_protocol_request_duration_us_bucket{le="500"} 10453
agent_protocol_request_duration_us_bucket{le="1000"} 11876
agent_protocol_request_duration_us_bucket{le="+Inf"} 12345
agent_protocol_request_duration_us_sum 4567890
agent_protocol_request_duration_us_count 12345
```

---

## Connection Affinity

For streaming requests, body chunks should be routed to the same connection as the initial headers. The pool tracks correlation_id to connection mappings.

### Automatic Affinity

When `send_request_headers` is called, the pool stores the selected connection for the correlation_id:

```rust
// Headers sent to connection A
let response = pool.send_request_headers("waf", &headers).await?;

// Body chunks automatically routed to connection A
pool.send_request_body_chunk("waf", &chunk1).await?;
pool.send_request_body_chunk("waf", &chunk2).await?;
```

### Manual Cleanup

After a request completes, clear the affinity mapping:

```rust
// Clear affinity for a specific correlation_id
pool.clear_correlation_affinity("correlation-123");

// Check current affinity count
let count = pool.correlation_affinity_count();
```

### Implementation Details

- Uses `DashMap<String, Arc<PooledConnection>>` for lock-free concurrent access
- `send_request_headers` stores affinity after selecting connection
- `send_request_body_chunk` checks affinity before falling back to normal selection
- No cleanup required for non-streaming requests (affinity expires naturally)

---

## Completed Optimizations

The following optimizations from the performance roadmap are now complete:

- **Binary serialization**: MessagePack encoding for UDS transport (`binary-uds` feature)
- **Zero-copy body streaming**: `send_request_body_chunk_binary()` and `send_response_body_chunk_binary()` methods
- **Buffer size alignment**: Unified `CHANNEL_BUFFER_SIZE = 64` across all transports
- **Header allocation**: SmallVec-based `HeaderValues` for inline single-value storage
- **Flow control enforcement**: All `send_*` methods check flow control state

See [performance-roadmap.md](../performance-roadmap.md) for full details.
