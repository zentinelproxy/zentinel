# Types Reference

Common type definitions used across Zentinel components.

## HTTP Types

### HttpMethod

HTTP request methods with custom method support.

```rust
use zentinel_common::HttpMethod;

let method = HttpMethod::GET;
let custom = HttpMethod::Custom("PURGE".to_string());

// From string
let method: HttpMethod = "POST".parse()?;

// To string
assert_eq!(method.to_string(), "POST");
```

**Variants:**
- `GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`
- `Custom(String)` - For non-standard methods

## TLS Types

### TlsVersion

Supported TLS protocol versions.

```rust
use zentinel_common::TlsVersion;

let version = TlsVersion::Tls13;

// Serializes to "TLS1.3"
let json = serde_json::to_string(&version)?;
```

**Variants:**
- `Tls12` - TLS 1.2 (minimum recommended)
- `Tls13` - TLS 1.3

## Trace ID Format

### TraceIdFormat

Format for generated trace IDs.

```rust
use zentinel_common::TraceIdFormat;

let format = TraceIdFormat::TinyFlake; // Default

// Case-insensitive parsing
let format = TraceIdFormat::from_str_loose("UUID")?;
```

**Variants:**
- `TinyFlake` (default) - 11-character Base58, time-prefixed, operator-friendly
- `Uuid` - Standard 36-character UUID v4

## Load Balancing

### LoadBalancingAlgorithm

Load balancing strategies for upstream pools.

```rust
use zentinel_common::LoadBalancingAlgorithm;

let algorithm = LoadBalancingAlgorithm::PowerOfTwoChoices;
```

**Variants:**

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `RoundRobin` | Sequential rotation | Simple distribution |
| `LeastConnections` | Fewest active connections | Varying request durations |
| `Random` | Random selection | Simple, stateless |
| `IpHash` | Hash of client IP | Session affinity |
| `Weighted` | Weight-based selection | Heterogeneous backends |
| `ConsistentHash` | Consistent hashing | Cache locality |
| `PowerOfTwoChoices` | P2C algorithm | Low latency (default) |
| `Adaptive` | Latency-weighted | Mixed workloads |
| `LeastTokensQueued` | Fewest queued tokens | LLM inference |

## Health Checks

### HealthCheckType

Health check probe configurations.

```rust
use zentinel_common::HealthCheckType;

// HTTP health check
let check = HealthCheckType::Http {
    path: "/health".to_string(),
    expected_status: 200,
    host: None,
};

// TCP health check
let check = HealthCheckType::Tcp;

// gRPC health check
let check = HealthCheckType::Grpc {
    service: Some("myservice".to_string()),
};

// LLM inference health check
let check = HealthCheckType::Inference {
    endpoint: "/v1/models".to_string(),
    expected_models: vec!["gpt-4".to_string()],
    readiness: None,
};
```

**Variants:**

| Type | Fields | Description |
|------|--------|-------------|
| `Http` | path, expected_status, host | HTTP GET with status check |
| `Tcp` | - | TCP connection attempt |
| `Grpc` | service | gRPC health protocol |
| `Inference` | endpoint, expected_models, readiness | LLM model availability |

## Retry Policy

### RetryPolicy

Retry configuration for failed requests.

```rust
use zentinel_common::RetryPolicy;

let policy = RetryPolicy {
    max_attempts: 3,
    timeout_ms: 30000,
    backoff_base_ms: 100,
    backoff_max_ms: 5000,
    retryable_status_codes: vec![502, 503, 504],
};

// Use defaults
let policy = RetryPolicy::default();
```

**Fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_attempts` | u32 | 3 | Maximum retry attempts |
| `timeout_ms` | u64 | 30000 | Total timeout for all attempts |
| `backoff_base_ms` | u64 | 100 | Initial backoff delay |
| `backoff_max_ms` | u64 | 5000 | Maximum backoff delay |
| `retryable_status_codes` | Vec<u16> | [502, 503, 504] | Status codes to retry |

## Circuit Breaker

### CircuitBreakerConfig

Circuit breaker threshold configuration.

```rust
use zentinel_common::CircuitBreakerConfig;

let config = CircuitBreakerConfig {
    failure_threshold: 5,
    success_threshold: 2,
    timeout_seconds: 30,
    half_open_max_requests: 1,
};
```

**Fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `failure_threshold` | u32 | 5 | Consecutive failures to open |
| `success_threshold` | u32 | 2 | Consecutive successes to close |
| `timeout_seconds` | u64 | 30 | Time in open state before half-open |
| `half_open_max_requests` | u32 | 1 | Requests allowed in half-open |

### CircuitBreakerState

Current state of a circuit breaker.

```rust
use zentinel_common::CircuitBreakerState;

match breaker.state() {
    CircuitBreakerState::Closed => { /* Normal operation */ }
    CircuitBreakerState::Open => { /* Fast-fail requests */ }
    CircuitBreakerState::HalfOpen => { /* Testing recovery */ }
}
```

## Priority

### Priority

Request priority levels for scheduling.

```rust
use zentinel_common::Priority;

let priority = Priority::High;

// Orderable
assert!(Priority::Critical > Priority::High);
assert!(Priority::High > Priority::Normal);
assert!(Priority::Normal > Priority::Low);

// Numeric value
assert_eq!(Priority::Critical.as_u8(), 3);
```

**Variants:**

| Priority | Value | Use Case |
|----------|-------|----------|
| `Low` | 0 | Background tasks |
| `Normal` | 1 | Default requests |
| `High` | 2 | Important requests |
| `Critical` | 3 | Must not be dropped |

## Byte Size

### ByteSize

Human-readable byte sizes with parsing and display.

```rust
use zentinel_common::ByteSize;

// Create from units
let size = ByteSize::from_mb(10);  // 10MB
let size = ByteSize::from_kb(512); // 512KB
let size = ByteSize::from_gb(1);   // 1GB

// Get raw bytes
let bytes = size.as_bytes();

// Parse from string
let size: ByteSize = "10MB".parse()?;
let size: ByteSize = "1.5GB".parse()?;
let size: ByteSize = "1024".parse()?; // Plain bytes

// Display
println!("{}", ByteSize::from_bytes(1536)); // "1.50KB"
println!("{}", ByteSize::from_mb(100));     // "100.00MB"
```

**Constants:**
- `ByteSize::KB` - 1024 bytes
- `ByteSize::MB` - 1024 KB
- `ByteSize::GB` - 1024 MB

## Client IP

### ClientIp

Client IP address with forwarded chain.

```rust
use zentinel_common::ClientIp;
use std::net::IpAddr;

let client = ClientIp {
    address: "192.168.1.100".parse()?,
    forwarded_for: Some(vec![
        "10.0.0.1".parse()?,
        "172.16.0.1".parse()?,
    ]),
};

// Get the actual client IP (first in chain or direct)
let real_ip = client.forwarded_for
    .as_ref()
    .and_then(|chain| chain.first())
    .unwrap_or(&client.address);
```

**Fields:**
- `address` - Direct connection IP
- `forwarded_for` - Optional X-Forwarded-For chain

## Time Window

### TimeWindow

Time window for rate limiting and metrics.

```rust
use zentinel_common::TimeWindow;
use std::time::Duration;

let window = TimeWindow {
    duration: Duration::from_secs(60),
    start: Instant::now(),
};

// Check if window has elapsed
if window.start.elapsed() > window.duration {
    // Window expired
}
```
