# Client & Server APIs (v2)

This document covers the v2 APIs for building agent integrations with connection pooling, multiple transports, and reverse connections.

## Quick Start

```rust
use sentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a connection pool
    let config = AgentPoolConfig {
        connections_per_agent: 4,
        load_balance_strategy: LoadBalanceStrategy::LeastConnections,
        request_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    let pool = AgentPool::with_config(config);

    // Add agents (transport auto-detected from endpoint)
    pool.add_agent("waf", "localhost:50051").await?;           // gRPC
    pool.add_agent("auth", "/var/run/auth.sock").await?;       // UDS

    // Send requests through the pool
    let response = pool.send_request_headers("waf", &headers).await?;

    Ok(())
}
```

---

## AgentPool

The `AgentPool` is the primary interface for v2 agent communication. It manages connections, load balancing, health tracking, and metrics.

### Creating a Pool

```rust
use sentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};

// Default configuration
let pool = AgentPool::new();

// Custom configuration
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

### Adding Agents

```rust
// gRPC agent (detected by host:port format)
pool.add_agent("waf", "localhost:50051").await?;
pool.add_agent("remote-waf", "waf.internal:50051").await?;

// UDS agent (detected by path format)
pool.add_agent("auth", "/var/run/sentinel/auth.sock").await?;

// Explicit transport selection
pool.add_grpc_agent("waf", "localhost:50051", tls_config).await?;
pool.add_uds_agent("auth", "/var/run/auth.sock").await?;
```

### Sending Requests

```rust
use sentinel_agent_protocol::v2::RequestHeaders;

let headers = RequestHeaders {
    request_id: 1,
    method: "POST".to_string(),
    uri: "/api/users".to_string(),
    headers: vec![
        ("content-type".to_string(), "application/json".to_string()),
    ],
    has_body: true,
    metadata: request_metadata,
};

// Send to specific agent
let response = pool.send_request_headers("waf", &headers).await?;

// Send body chunks
let chunk = RequestBodyChunk {
    request_id: 1,
    chunk_index: 0,
    data: base64::encode(&body_bytes),
    is_last: true,
};
let response = pool.send_request_body_chunk("waf", &chunk).await?;
```

### Cancelling Requests

```rust
// Cancel specific request
pool.cancel_request("waf", request_id).await?;

// Cancel all requests for an agent
pool.cancel_all("waf").await?;
```

### Removing Agents

```rust
pool.remove_agent("waf").await?;
```

### Pool Methods

| Method | Description |
|--------|-------------|
| `new()` | Create pool with default config |
| `with_config(config)` | Create pool with custom config |
| `add_agent(name, endpoint)` | Add agent with auto-detected transport |
| `add_grpc_agent(name, endpoint, tls)` | Add gRPC agent explicitly |
| `add_uds_agent(name, path)` | Add UDS agent explicitly |
| `add_reverse_connection(name, client, caps)` | Add reverse-connected agent |
| `remove_agent(name)` | Remove agent from pool |
| `send_request_headers(agent, headers)` | Send request headers |
| `send_request_body_chunk(agent, chunk)` | Send request body chunk |
| `send_response_headers(agent, headers)` | Send response headers |
| `send_response_body_chunk(agent, chunk)` | Send response body chunk |
| `cancel_request(agent, request_id)` | Cancel specific request |
| `cancel_all(agent)` | Cancel all requests |
| `get_health(agent)` | Get agent health status |
| `metrics_collector()` | Get metrics collector reference |

---

## AgentClientV2 (gRPC)

Low-level gRPC client for direct use without pooling.

### Creating a Client

```rust
use sentinel_agent_protocol::v2::AgentClientV2;

let client = AgentClientV2::connect(
    "waf-agent",
    "http://localhost:50051",
    Duration::from_secs(30),
).await?;

// With TLS
let client = AgentClientV2::connect_with_tls(
    "waf-agent",
    "https://waf.internal:50051",
    tls_config,
    Duration::from_secs(30),
).await?;
```

### Sending Messages

```rust
// Send request headers
let response = client.send_request_headers(&headers).await?;

// Send body chunk
let response = client.send_request_body_chunk(&chunk).await?;

// Cancel request
client.cancel_request(request_id).await?;
```

### Health Checking

```rust
let is_healthy = client.health_check().await?;
let capabilities = client.get_capabilities().await?;
```

---

## AgentClientV2Uds (Unix Domain Socket)

Low-level UDS client for direct use without pooling.

### Creating a Client

```rust
use sentinel_agent_protocol::v2::AgentClientV2Uds;

let client = AgentClientV2Uds::connect(
    "auth-agent",
    "/var/run/sentinel/auth.sock",
    Duration::from_secs(30),
).await?;
```

### Handshake

The UDS client performs automatic handshake on connection:

```rust
// Handshake is automatic, but you can query capabilities
let capabilities = client.capabilities();

println!("Agent: {}", capabilities.agent_name);
println!("Handles body: {}", capabilities.handles_request_body);
println!("Max concurrent: {:?}", capabilities.max_concurrent_requests);
```

### Sending Messages

```rust
// Send request headers
let response = client.send_request_headers(&headers).await?;

// Send body chunk
let response = client.send_request_body_chunk(&chunk).await?;

// Cancel request
client.cancel_request(request_id).await?;
client.cancel_all().await?;
```

---

## ReverseConnectionListener

Accepts inbound connections from agents.

### Creating a Listener

```rust
use sentinel_agent_protocol::v2::{ReverseConnectionListener, ReverseConnectionConfig};

let config = ReverseConnectionConfig {
    handshake_timeout: Duration::from_secs(10),
    max_connections_per_agent: 4,
    require_auth: false,
    allowed_agents: None,
};

let listener = ReverseConnectionListener::bind_uds(
    "/var/run/sentinel/agents.sock",
    config,
).await?;
```

### Accepting Connections

```rust
// Accept a single connection
let (client, registration) = listener.accept().await?;
println!("Agent connected: {}", registration.agent_id);

// Add to pool
pool.add_reverse_connection(
    &registration.agent_id,
    client,
    registration.capabilities,
).await?;
```

### Accept Loop

```rust
// Run accept loop in background
let pool_clone = pool.clone();
tokio::spawn(async move {
    loop {
        match listener.accept().await {
            Ok((client, registration)) => {
                let _ = pool_clone.add_reverse_connection(
                    &registration.agent_id,
                    client,
                    registration.capabilities,
                ).await;
            }
            Err(e) => {
                tracing::error!("Accept error: {}", e);
            }
        }
    }
});
```

---

## V2Transport

Unified transport abstraction for all v2 transport types.

```rust
use sentinel_agent_protocol::v2::V2Transport;

pub enum V2Transport {
    Grpc(AgentClientV2),
    Uds(AgentClientV2Uds),
    Reverse(ReverseConnectionClient),
}

impl V2Transport {
    pub async fn send_request_headers(&mut self, headers: &RequestHeaders) -> Result<Decision>;
    pub async fn send_request_body_chunk(&mut self, chunk: &RequestBodyChunk) -> Result<Decision>;
    pub async fn send_response_headers(&mut self, headers: &ResponseHeaders) -> Result<Decision>;
    pub async fn send_response_body_chunk(&mut self, chunk: &ResponseBodyChunk) -> Result<Decision>;
    pub async fn cancel_request(&mut self, request_id: u64) -> Result<()>;
    pub async fn cancel_all(&mut self) -> Result<()>;
    pub fn is_healthy(&self) -> bool;
}
```

---

## Configuration Types

### AgentPoolConfig

```rust
pub struct AgentPoolConfig {
    /// Number of connections to maintain per agent
    pub connections_per_agent: usize,  // Default: 4

    /// Load balancing strategy
    pub load_balance_strategy: LoadBalanceStrategy,  // Default: LeastConnections

    /// Timeout for individual requests
    pub request_timeout: Duration,  // Default: 30s

    /// Timeout for establishing connections
    pub connect_timeout: Duration,  // Default: 5s

    /// Interval between health checks
    pub health_check_interval: Duration,  // Default: 10s

    /// Failures before opening circuit breaker
    pub circuit_breaker_threshold: u32,  // Default: 5

    /// Time before circuit breaker resets
    pub circuit_breaker_reset_timeout: Duration,  // Default: 30s
}
```

### LoadBalanceStrategy

```rust
pub enum LoadBalanceStrategy {
    /// Distribute requests evenly across connections
    RoundRobin,

    /// Route to connection with fewest in-flight requests
    LeastConnections,

    /// Prefer healthier connections based on error rates
    HealthBased,

    /// Random selection
    Random,
}
```

### ReverseConnectionConfig

```rust
pub struct ReverseConnectionConfig {
    /// Timeout for registration handshake
    pub handshake_timeout: Duration,  // Default: 10s

    /// Maximum connections per agent ID
    pub max_connections_per_agent: usize,  // Default: 4

    /// Require authentication token
    pub require_auth: bool,  // Default: false

    /// Allowlist of agent IDs (None = allow all)
    pub allowed_agents: Option<Vec<String>>,
}
```

---

## Metrics

### MetricsCollector

```rust
let metrics = pool.metrics_collector();

// Get metrics snapshot
let snapshot = metrics.snapshot();
println!("Total requests: {}", snapshot.total_requests);
println!("Active connections: {}", snapshot.active_connections);

// Export in Prometheus format
let prometheus_output = metrics.export_prometheus();
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `agent_requests_total` | Counter | Total requests by agent and decision |
| `agent_request_duration_seconds` | Histogram | Request latency distribution |
| `agent_connections_active` | Gauge | Current active connections |
| `agent_errors_total` | Counter | Error counts by type |
| `agent_circuit_breaker_state` | Gauge | Circuit breaker state (0=closed, 1=open) |

---

## Error Handling

### V2-Specific Errors

```rust
pub enum AgentProtocolError {
    // ... existing errors ...

    /// Connection was closed unexpectedly (v2)
    #[error("Connection closed")]
    ConnectionClosed,
}
```

### Pool Error Handling

```rust
match pool.send_request_headers("waf", &headers).await {
    Ok(decision) => {
        // Handle decision
    }
    Err(AgentProtocolError::Timeout) => {
        // Request timed out - apply fallback policy
    }
    Err(AgentProtocolError::ConnectionClosed) => {
        // Connection lost - pool will reconnect automatically
    }
    Err(e) => {
        tracing::error!("Agent error: {}", e);
    }
}
```

---

## Migration from v1

### Before (v1)

```rust
use sentinel_agent_protocol::AgentClient;

let client = AgentClient::unix_socket(
    "proxy",
    "/tmp/agent.sock",
    Duration::from_secs(5),
).await?;

let response = client.send_event(EventType::RequestHeaders, &event).await?;
```

### After (v2 with pooling)

```rust
use sentinel_agent_protocol::v2::AgentPool;

let pool = AgentPool::new();
pool.add_agent("agent", "/tmp/agent.sock").await?;

let response = pool.send_request_headers("agent", &headers).await?;
```

---

## Best Practices

1. **Use AgentPool for production**: The pool handles connection management, health tracking, and load balancing automatically.

2. **Configure appropriate timeouts**: Set `request_timeout` based on your latency requirements.

3. **Enable circuit breakers**: Prevent cascading failures with appropriate thresholds.

4. **Monitor metrics**: Use the MetricsCollector to track agent health and performance.

5. **Use UDS for co-located agents**: UDS provides significantly lower latency than gRPC for local communication.

6. **Implement graceful shutdown**: Cancel pending requests before shutting down.

```rust
// Graceful shutdown
for agent_name in pool.agent_names() {
    pool.cancel_all(&agent_name).await?;
}
```
