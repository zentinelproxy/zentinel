# Observability

Prometheus metrics, structured logging, and tracing infrastructure.

## Initialization

### Tracing Setup

Initialize structured logging and tracing:

```rust
use zentinel_common::init_tracing;

fn main() {
    // Initialize with environment-based configuration
    init_tracing();

    tracing::info!("Zentinel starting");
}
```

**Environment Variables:**

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `ZENTINEL_LOG_FORMAT` | `json`, `pretty` | Text | Log output format |
| `RUST_LOG` | Log filter | `info` | Log level filter |

**Format Examples:**

```bash
# JSON format (production)
ZENTINEL_LOG_FORMAT=json ./zentinel

# Pretty format (development)
ZENTINEL_LOG_FORMAT=pretty ./zentinel

# Custom log levels
RUST_LOG=zentinel=debug,tower=warn ./zentinel
```

## RequestMetrics

Comprehensive Prometheus metrics collector.

### Setup

```rust
use zentinel_common::RequestMetrics;

// Create and register metrics
let metrics = RequestMetrics::new();

// Metrics are automatically registered with default registry
```

### Request Metrics

```rust
// Record completed request
metrics.record_request(
    "api-route",           // route
    "GET",                 // method
    200,                   // status
    Duration::from_ms(50), // duration
);

// Track active requests
metrics.inc_active_requests();
// ... process request ...
metrics.dec_active_requests();
```

**Prometheus Metrics:**

```
zentinel_request_duration_seconds{route="api", method="GET", quantile="0.99"}
zentinel_requests_total{route="api", method="GET", status="200"}
zentinel_active_requests
```

### Upstream Metrics

```rust
// Record upstream attempt
metrics.record_upstream_attempt("backend", "api-route");

// Record upstream failure
metrics.record_upstream_failure(
    "backend",     // upstream
    "api-route",   // route
    "timeout",     // reason
);
```

**Prometheus Metrics:**

```
zentinel_upstream_attempts_total{upstream="backend", route="api"}
zentinel_upstream_failures_total{upstream="backend", route="api", reason="timeout"}
```

### Circuit Breaker Metrics

```rust
// Update circuit breaker state
metrics.set_circuit_breaker_state(
    "backend",     // component
    "api-route",   // route
    true,          // is_open
);
```

**Prometheus Metrics:**

```
zentinel_circuit_breaker_state{component="backend", route="api"} 1
```

### Agent Metrics

```rust
// Record agent call latency
metrics.record_agent_latency(
    "waf-agent",           // agent
    "request-headers",     // event
    Duration::from_ms(5),  // duration
);

// Record agent timeout
metrics.record_agent_timeout("waf-agent", "request-body");

// Record blocked request
metrics.record_blocked_request("waf_rule_942100");
```

**Prometheus Metrics:**

```
zentinel_agent_latency_seconds{agent="waf-agent", event="request-headers", quantile="0.99"}
zentinel_agent_timeouts_total{agent="waf-agent", event="request-body"}
zentinel_blocked_requests_total{reason="waf_rule_942100"}
```

### Body Metrics

```rust
metrics.record_request_body_size("api-route", 1024);
metrics.record_response_body_size("api-route", 2048);
```

**Prometheus Metrics:**

```
zentinel_request_body_size_bytes{route="api"}
zentinel_response_body_size_bytes{route="api"}
```

### TLS Metrics

```rust
metrics.record_tls_handshake(
    "TLS1.3",              // version
    Duration::from_ms(10), // duration
);
```

**Prometheus Metrics:**

```
zentinel_tls_handshake_duration_seconds{version="TLS1.3", quantile="0.99"}
```

### Connection Pool Metrics

```rust
// Update pool state
metrics.update_connection_pool(
    "backend", // upstream
    50,        // total size
    10,        // idle count
);

// Record connection acquisition
metrics.record_connection_acquired("backend");
```

**Prometheus Metrics:**

```
zentinel_connection_pool_size{upstream="backend"}
zentinel_connection_pool_idle{upstream="backend"}
zentinel_connection_pool_acquired_total{upstream="backend"}
```

### System Metrics

```rust
// Update system metrics (CPU, memory)
metrics.update_system_metrics();
```

**Prometheus Metrics:**

```
zentinel_memory_usage_bytes
zentinel_cpu_usage_percent
zentinel_open_connections
```

### WebSocket Metrics

```rust
// Record WebSocket frame
metrics.record_websocket_frame(
    "ws-route",   // route
    "inbound",    // direction
    "text",       // opcode
    "allowed",    // decision
);

// Record frame size
metrics.record_websocket_frame_size(
    "ws-route",
    "inbound",
    "text",
    1024,
);

// Record connection
metrics.record_websocket_connection("ws-route");

// Record inspection time
metrics.record_websocket_inspection(
    "ws-route",
    Duration::from_micros(100),
);
```

**Prometheus Metrics:**

```
zentinel_websocket_frames_total{route, direction, opcode, decision}
zentinel_websocket_frame_size_bytes{route, direction, opcode}
zentinel_websocket_connections_total{route}
zentinel_websocket_inspection_duration_seconds{route}
```

### Decompression Metrics

```rust
metrics.record_decompression("gzip", "success");
metrics.record_decompression_ratio("gzip", 10.5);
```

**Prometheus Metrics:**

```
zentinel_decompression_total{encoding="gzip", result="success"}
zentinel_decompression_ratio{encoding="gzip"}
```

### Shadow/Mirror Metrics

```rust
metrics.record_shadow_request("api", "canary", "success");
metrics.record_shadow_error("api", "canary", "timeout");
metrics.record_shadow_latency("api", "canary", Duration::from_ms(100));
```

**Prometheus Metrics:**

```
zentinel_shadow_requests_total{route, upstream, result}
zentinel_shadow_errors_total{route, upstream, error_type}
zentinel_shadow_latency_seconds{route, upstream}
```

### PII Detection Metrics

```rust
metrics.record_pii_detected("api-route", "credit_card");
```

**Prometheus Metrics:**

```
zentinel_pii_detected_total{route="api", category="credit_card"}
```

## ScopedMetrics

Namespace and service-scoped metrics for multi-tenant deployments.

### Setup

```rust
use zentinel_common::{ScopedMetrics, Scope};

let metrics = ScopedMetrics::new();
```

### Recording with Scope

```rust
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Record request with scope labels
metrics.record_request(
    "checkout-route",
    "POST",
    200,
    Duration::from_ms(100),
    &scope,
);

// Record upstream attempt
metrics.record_upstream_attempt("payment-gateway", "checkout-route", &scope);

// Record rate limit hit
metrics.record_rate_limit_hit("checkout-route", "default", &scope);

// Update circuit breaker
metrics.set_circuit_breaker_state("payment-gateway", false, &scope);
```

**Prometheus Metrics:**

```
zentinel_scoped_requests_total{namespace="production", service="payments", route="checkout", method="POST", status="200"}
zentinel_scoped_request_duration_seconds{namespace="production", service="payments", route="checkout", method="POST"}
zentinel_scoped_upstream_attempts_total{namespace="production", service="payments", upstream="payment-gateway", route="checkout"}
zentinel_scoped_rate_limit_hits_total{namespace="production", service="payments", route="checkout", policy="default"}
zentinel_scoped_circuit_breaker_state{namespace="production", service="payments", upstream="payment-gateway"}
```

## Complete Metrics List

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `zentinel_request_duration_seconds` | Histogram | route, method | Request latency |
| `zentinel_requests_total` | Counter | route, method, status | Request count |
| `zentinel_active_requests` | Gauge | - | Current in-flight |
| `zentinel_upstream_attempts_total` | Counter | upstream, route | Upstream attempts |
| `zentinel_upstream_failures_total` | Counter | upstream, route, reason | Upstream failures |
| `zentinel_circuit_breaker_state` | Gauge | component, route | CB state (0/1) |
| `zentinel_agent_latency_seconds` | Histogram | agent, event | Agent call latency |
| `zentinel_agent_timeouts_total` | Counter | agent, event | Agent timeouts |
| `zentinel_blocked_requests_total` | Counter | reason | Blocked requests |
| `zentinel_request_body_size_bytes` | Histogram | route | Request body size |
| `zentinel_response_body_size_bytes` | Histogram | route | Response body size |
| `zentinel_tls_handshake_duration_seconds` | Histogram | version | TLS handshake time |
| `zentinel_connection_pool_size` | Gauge | upstream | Pool total size |
| `zentinel_connection_pool_idle` | Gauge | upstream | Pool idle connections |
| `zentinel_connection_pool_acquired_total` | Counter | upstream | Connections acquired |
| `zentinel_memory_usage_bytes` | Gauge | - | Memory usage |
| `zentinel_cpu_usage_percent` | Gauge | - | CPU usage |
| `zentinel_open_connections` | Gauge | - | Open connections |
| `zentinel_websocket_frames_total` | Counter | route, direction, opcode, decision | WS frames |
| `zentinel_websocket_connections_total` | Counter | route | WS connections |
| `zentinel_decompression_total` | Counter | encoding, result | Decompressions |
| `zentinel_decompression_ratio` | Histogram | encoding | Decompression ratio |
| `zentinel_shadow_requests_total` | Counter | route, upstream, result | Shadow requests |
| `zentinel_pii_detected_total` | Counter | route, category | PII detections |

## Structured Logging

Use tracing macros for structured logs:

```rust
use tracing::{info, warn, error, debug, instrument};

// Basic logging
info!("Server started on port {}", port);

// With fields
info!(
    route = %route_id,
    upstream = %upstream_id,
    latency_ms = duration.as_millis(),
    "Request completed"
);

// With span
#[instrument(skip(req), fields(route = %route_id))]
async fn handle_request(req: Request, route_id: &str) {
    debug!("Processing request");
    // ...
}
```

### Log Output (JSON)

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "target": "zentinel::proxy",
  "fields": {
    "route": "api-v1",
    "upstream": "backend",
    "latency_ms": 50,
    "message": "Request completed"
  },
  "span": {
    "route": "api-v1"
  }
}
```
