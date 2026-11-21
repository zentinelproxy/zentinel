# Limits & Rate Limiting

Resource bounds and rate limiting infrastructure for predictable behavior.

## Design Philosophy

Zentinel enforces hard limits everywhere to ensure "sleepable ops":

- **Bounded memory** - No unbounded allocations
- **Bounded queues** - All queues have maximum depth
- **Bounded time** - Every operation has a timeout
- **Bounded rate** - Configurable request rate limits

## Limits Configuration

### Limits Struct

Central configuration for all resource limits:

```rust
use zentinel_common::Limits;

// Production defaults (strict)
let limits = Limits::for_production();

// Testing defaults (permissive)
let limits = Limits::for_testing();

// Custom configuration
let limits = Limits {
    max_body_size_bytes: 10 * 1024 * 1024, // 10MB
    max_header_size_bytes: 8 * 1024,        // 8KB
    ..Limits::default()
};
```

### Limit Categories

#### Header Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_header_size_bytes` | 8KB | Maximum size of a single header |
| `max_header_count` | 100 | Maximum number of headers |
| `max_header_name_bytes` | 256 | Maximum header name length |
| `max_header_value_bytes` | 4KB | Maximum header value length |

#### Body Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_body_size_bytes` | 10MB | Maximum request/response body |
| `max_body_buffer_bytes` | 1MB | Maximum buffered body for inspection |
| `max_body_inspection_bytes` | 1MB | Maximum body sent to agents |

#### Decompression Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_decompression_ratio` | 100.0 | Maximum expansion ratio (zip bomb protection) |
| `max_decompressed_size_bytes` | 100MB | Maximum decompressed size |

#### Connection Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_connections_per_client` | unlimited (`None`) | Per-client connection limit. A client is counted by `client_key`: an IPv4 address, or an IPv6 address truncated to `Ipv6PrefixLen` bits (64 by default) |
| `max_connections_per_route` | 1000 | Per-route connection limit |
| `max_total_connections` | 10,000 | Total connection limit |
| `max_idle_connections_per_upstream` | 100 | Idle pool size per upstream |

#### Request Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_in_flight_requests` | 10,000 | Total concurrent requests |
| `max_in_flight_requests_per_worker` | 1,000 | Per-worker concurrent requests |
| `max_queued_requests` | 1,000 | Queued requests waiting |

#### Agent Limits

| Field | Default | Description |
|-------|---------|-------------|
| `max_agent_queue_depth` | 100 | Pending agent calls per agent |
| `max_agent_body_bytes` | 1MB | Body size sent to agent |
| `max_agent_response_bytes` | 10KB | Agent response size |

#### Rate Limits (Optional)

| Field | Default | Description |
|-------|---------|-------------|
| `max_requests_per_second_global` | None | Global rate limit |
| `max_requests_per_second_per_client` | None | Per-client rate limit |
| `max_requests_per_second_per_route` | None | Per-route rate limit |

### Validation

```rust
let limits = Limits::default();

// Validate limits are consistent
limits.validate()?;

// Check specific limits
limits.check_header_size(header_value.len())?;
limits.check_header_count(headers.len())?;
limits.check_body_size(body.len())?;
```

## RateLimiter

Token bucket rate limiter for single-instance deployments.

### Basic Usage

```rust
use zentinel_common::RateLimiter;

// 100 requests per second with bucket of 100
let limiter = RateLimiter::new(100, 100);

// Check if request is allowed (consumes 1 token)
if limiter.try_acquire(1) {
    // Process request
} else {
    // Rate limited
}
```

### Check Without Consuming

```rust
// Check if tokens available (doesn't consume)
if limiter.check(1) {
    // Tokens available
}

// Get available tokens
let available = limiter.available();
```

### Reset

```rust
// Reset to full capacity
limiter.reset();
```

### Implementation

The rate limiter uses a token bucket algorithm:

```
┌─────────────────────────────────────────────────────────┐
│                    Token Bucket                          │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   Capacity: 100 tokens                                   │
│   Refill: 100 tokens/second                             │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●● │   │
│   │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●●● │   │
│   │ ●●●●●●●●●●                                     │   │
│   └─────────────────────────────────────────────────┘   │
│                                                          │
│   Available: 80 tokens                                   │
│   Refill rate: 100/sec (time-based)                     │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

## MultiRateLimiter

Multi-level rate limiting (global, per-client, per-route).

### Setup

```rust
use zentinel_common::{MultiRateLimiter, Limits};

let limits = Limits {
    max_requests_per_second_global: Some(10000),
    max_requests_per_second_per_client: Some(100),
    max_requests_per_second_per_route: Some(1000),
    ..Default::default()
};

let limiter = MultiRateLimiter::new(&limits);
```

### Checking Requests

```rust
// Check all levels
match limiter.check_request(client_id, route_id) {
    Ok(()) => {
        // Request allowed
    }
    Err(ZentinelError::RateLimit { message, retry_after_secs }) => {
        // Rate limited
    }
}
```

### Cleanup

```rust
// Remove stale entries (run periodically)
let max_age = Duration::from_secs(300);
limiter.cleanup(max_age);

// Get entry counts
let (client_count, route_count) = limiter.entry_counts();
```

## ConnectionLimiter

Connection slot management with RAII guards.

### Setup

```rust
use zentinel_common::{ConnectionLimiter, Limits};

let limits = Limits::default();
let limiter = ConnectionLimiter::new(&limits);
```

### Acquiring Connections

```rust
// Try to acquire connection slot
match limiter.try_acquire(client_id, route_id) {
    Ok(guard) => {
        // Connection allowed
        // Guard automatically releases slot when dropped
        process_connection(connection, guard).await;
    }
    Err(ZentinelError::LimitExceeded { limit_type, .. }) => {
        // Connection rejected
        match limit_type {
            LimitType::ConnectionCount => { /* Total limit */ }
            _ => { /* Per-client or per-route limit */ }
        }
    }
}
```

### Statistics

```rust
let stats = limiter.stats();
println!("Total: {}", stats.total);
println!("Per-client: {}", stats.per_client_count);
println!("Per-route: {}", stats.per_route_count);
```

## Client Keys

Per-client limits count a client by a key, not by its raw address. The
addresses of one IPv6 prefix usually belong to the same subscriber or site, so
the prefix is counted as one client. Where unrelated hosts share one `/64` (a
LAN, a hosting provider's subnet), use a length of `128`, or raise the
per-client limits.

```rust
use zentinel_common::limits::{client_key, client_key_str, Ipv6PrefixLen};

let prefix = Ipv6PrefixLen::default(); // 64 bits; `Ipv6PrefixLen::new(128)` for none
let key = client_key("2001:db8:0:1::7".parse()?, prefix);
assert_eq!(key.to_string(), "2001:db8:0:1::");

// The same for a client address held as text. Text that is not an IP
// address (such as "unknown") is returned as it is.
assert_eq!(client_key_str("2001:db8:0:1::7", prefix), "2001:db8:0:1::");
```

| Address | Key |
|---------|-----|
| IPv4 | The address |
| IPv4-mapped IPv6 (`::ffff:a.b.c.d`) | The IPv4 address |
| Other IPv6 | The address with all bits after the first `prefix` set to zero |

A prefix length is a whole number from 1 to 128 (`Ipv6PrefixLen::new` rejects
the rest). In the proxy it is `system { client-ipv6-prefix-length }`.
`ConnectionLimiter::try_acquire` takes the key, and the permit it returns
gives the slot back under the key it was taken with.

## Integration Example

Complete request handling with limits:

```rust
use zentinel_common::{
    Limits, MultiRateLimiter, ConnectionLimiter,
    ZentinelError, LimitType,
};

struct RequestHandler {
    limits: Limits,
    rate_limiter: MultiRateLimiter,
    connection_limiter: ConnectionLimiter,
}

impl RequestHandler {
    async fn handle(&self, req: Request) -> Result<Response, ZentinelError> {
        let client_id = extract_client_id(&req);
        let route_id = match_route(&req);

        // Check rate limit
        self.rate_limiter.check_request(&client_id, &route_id)?;

        // Check connection limit
        let _guard = self.connection_limiter.try_acquire(&client_id, &route_id)?;

        // Check header limits
        self.limits.check_header_count(req.headers().len())?;
        for (name, value) in req.headers() {
            self.limits.check_header_size(value.len())?;
        }

        // Check body size
        if let Some(body) = req.body() {
            self.limits.check_body_size(body.len())?;
        }

        // Process request...
        Ok(response)
    }
}
```

## Metrics

Rate limiting metrics are exported automatically:

```
# Rate limit decisions
zentinel_rate_limit_allowed_total{level="global"} 10000
zentinel_rate_limit_allowed_total{level="client", client="1.2.3.4"} 100
zentinel_rate_limit_rejected_total{level="client", client="1.2.3.4"} 5

# Connection limits
zentinel_connections_total 500
zentinel_connections_per_client{client="1.2.3.4"} 10
zentinel_connection_rejections_total{reason="per_client"} 2
```
