# Rate Limiting & Circuit Breakers

Request rate limiting and failure isolation mechanisms.

## Rate Limiting Overview

Zentinel provides multiple rate limiting backends:

| Backend | Use Case | Consistency | Performance |
|---------|----------|-------------|-------------|
| Local | Single instance | Per-instance | Fastest |
| Redis | Multi-instance | Strong | Fast |
| Memcached | Multi-instance | Eventual | Fast |

## Local Rate Limiting

In-memory token bucket rate limiting using Pingora's `pingora-limits` crate.

### Configuration

```kdl
routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "backend"

        policies {
            rate-limit {
                requests-per-second 100
                burst 20
                key "client-ip"
                on-limit "reject"
                status-code 429
            }
        }
    }
}
```

### Rate Limit Keys

| Key Type | Description | Example |
|----------|-------------|---------|
| `client-ip` | Client IP address (default) | `192.168.1.100` |
| `header` | Specific header value | `X-API-Key: abc123` |
| `path` | Request path | `/api/v1/users` |
| `route` | Route ID | `api` |
| `composite` | Multiple keys combined | `ip:header:path` |

```kdl
policies {
    rate-limit {
        // Rate limit by API key
        key "header" "X-API-Key"
    }
}

policies {
    rate-limit {
        // Rate limit by client IP + path
        key "composite" ["client-ip", "path"]
    }
}
```

### Algorithm

Token bucket with 1-second sliding window:

```
┌────────────────────────────────────────────────────────┐
│                   Token Bucket                          │
├────────────────────────────────────────────────────────┤
│                                                         │
│   Capacity: 100 tokens (requests-per-second)           │
│   Burst: 20 tokens (additional capacity)               │
│                                                         │
│   ┌─────────────────────────────────┐                  │
│   │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●● │ ← Tokens          │
│   │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●● │                   │
│   │ ●●●●●●●●●●●●●●●●●●●●●●●●●●●●●● │                   │
│   │ ●●●●●●●●●●                     │ ← Available: 80   │
│   └─────────────────────────────────┘                  │
│                                                         │
│   Request arrives:                                      │
│   - If tokens available → Allow, consume 1 token       │
│   - If no tokens → Reject with 429                     │
│                                                         │
│   Refill rate: 100 tokens/second                       │
│                                                         │
└────────────────────────────────────────────────────────┘
```

### Response Headers

When rate limited:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 1
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705123456
Content-Type: application/json

{
  "error": "rate_limited",
  "message": "Too many requests",
  "retry_after": 1
}
```

## Distributed Rate Limiting (Redis)

Redis-backed sliding window rate limiting for multi-instance deployments.

### Prerequisites

Enable the feature:

```toml
[features]
distributed-rate-limit = ["redis", "deadpool-redis"]
```

### Configuration

```kdl
rate-limit-backend {
    type "redis"
    address "redis://localhost:6379"
    pool-size 10
    connection-timeout-ms 1000
}

routes {
    route "api" {
        policies {
            rate-limit {
                requests-per-second 100
                burst 20
                backend "distributed"
            }
        }
    }
}
```

### Algorithm

Sliding window log using Redis sorted sets:

```
┌────────────────────────────────────────────────────────┐
│              Redis Sliding Window                       │
├────────────────────────────────────────────────────────┤
│                                                         │
│   Key: "ratelimit:api:192.168.1.100"                   │
│   Type: Sorted Set                                      │
│                                                         │
│   ┌─────────────────────────────────────────────────┐  │
│   │  Timestamp (score)  │  Request ID (member)      │  │
│   ├─────────────────────┼───────────────────────────┤  │
│   │  1705123456.001     │  req_abc123               │  │
│   │  1705123456.015     │  req_def456               │  │
│   │  1705123456.032     │  req_ghi789               │  │
│   │  ...                │  ...                      │  │
│   └─────────────────────┴───────────────────────────┘  │
│                                                         │
│   On request:                                           │
│   1. ZREMRANGEBYSCORE - Remove entries > 1 sec old     │
│   2. ZCARD - Count remaining entries                   │
│   3. If count < limit → ZADD timestamp, return ALLOW   │
│   4. If count >= limit → return REJECT                 │
│                                                         │
│   All in single MULTI/EXEC transaction                 │
│                                                         │
└────────────────────────────────────────────────────────┘
```

### Fallback

On Redis error, falls back to local rate limiting:

```rust
match redis_limiter.check(key, max_rps).await {
    Ok(result) => result,
    Err(e) => {
        log::warn!("Redis rate limit failed, using local: {}", e);
        local_limiter.check(key, max_rps)
    }
}
```

## Distributed Rate Limiting (Memcached)

Memcached-backed fixed window rate limiting.

### Prerequisites

Enable the feature:

```toml
[features]
distributed-rate-limit-memcached = ["memcached-rs"]
```

### Configuration

```kdl
rate-limit-backend {
    type "memcached"
    addresses ["memcached1:11211", "memcached2:11211"]
    pool-size 10
}
```

### Algorithm

Fixed window counter:

```
┌────────────────────────────────────────────────────────┐
│              Memcached Fixed Window                     │
├────────────────────────────────────────────────────────┤
│                                                         │
│   Key: "ratelimit:api:192.168.1.100:1705123456"        │
│   Value: Counter (integer)                              │
│   TTL: 1 second                                         │
│                                                         │
│   On request:                                           │
│   1. INCR key                                           │
│   2. If key not exists → SET key 1 with TTL            │
│   3. If count <= limit → ALLOW                         │
│   4. If count > limit → REJECT                         │
│                                                         │
│   Window resets every second (key expires)             │
│                                                         │
└────────────────────────────────────────────────────────┘
```

## Scoped Rate Limiting

Hierarchical rate limits with inheritance.

### Scope Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│                    Scope Hierarchy                       │
├─────────────────────────────────────────────────────────┤
│                                                          │
│   Global (default: 10000 rps)                           │
│       │                                                  │
│       ├── Namespace: production (5000 rps)              │
│       │       │                                          │
│       │       ├── Service: api (1000 rps)               │
│       │       │       └── Route: /users (100 rps)       │
│       │       │                                          │
│       │       └── Service: web (2000 rps)               │
│       │                                                  │
│       └── Namespace: staging (1000 rps)                 │
│               │                                          │
│               └── Service: api (500 rps)                │
│                                                          │
│   Inheritance: Most specific limit applies              │
│   Fallback: Service → Namespace → Global                │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Configuration

```kdl
scopes {
    scope "production" {
        rate-limit {
            requests-per-second 5000
        }

        scope "api" {
            rate-limit {
                requests-per-second 1000
            }
        }

        scope "web" {
            rate-limit {
                requests-per-second 2000
            }
        }
    }

    scope "staging" {
        rate-limit {
            requests-per-second 1000
        }
    }
}
```

## Circuit Breakers

Failure isolation to prevent cascade failures.

### States

```
┌────────────────────────────────────────────────────────┐
│                 Circuit Breaker FSM                     │
├────────────────────────────────────────────────────────┤
│                                                         │
│      ┌──────────────────────────────────────────┐      │
│      │                                          │      │
│      ▼                                          │      │
│  ┌────────┐                              ┌────────┐   │
│  │ CLOSED │─── failures >= threshold ───▶│  OPEN  │   │
│  │        │                              │        │   │
│  │ Normal │                              │ Reject │   │
│  │ traffic│                              │  all   │   │
│  └────────┘                              └────────┘   │
│      ▲                                       │        │
│      │                                       │        │
│      │                              timeout  │        │
│      │                                       ▼        │
│      │                               ┌────────────┐   │
│      │                               │ HALF-OPEN  │   │
│      │                               │            │   │
│      │                               │   Test     │   │
│      │                               │  traffic   │   │
│      │                               └────────────┘   │
│      │                                       │        │
│      │                          ┌────────────┴───┐    │
│      │                          │                │    │
│      │                       success          failure │
│      │                      threshold           │     │
│      │                          │               │     │
│      └──────────────────────────┘               │     │
│                                                 │     │
│                          Back to OPEN ◀─────────┘     │
│                                                       │
└───────────────────────────────────────────────────────┘
```

### Configuration

```kdl
upstreams {
    upstream "backend" {
        target "10.0.0.1:8080"
        target "10.0.0.2:8080"

        circuit-breaker {
            // Consecutive failures to open circuit
            failure-threshold 5

            // Consecutive successes to close circuit
            success-threshold 2

            // Time in open state before half-open
            timeout-secs 30

            // What counts as failure
            failure-statuses [500, 502, 503, 504]
            failure-on-timeout true
        }
    }
}
```

### Per-Scope Circuit Breakers

Different circuit breaker settings per scope:

```kdl
scopes {
    scope "production" {
        circuit-breaker {
            failure-threshold 10
            timeout-secs 60
        }
    }

    scope "staging" {
        circuit-breaker {
            failure-threshold 3
            timeout-secs 10
        }
    }
}
```

### Response When Open

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 30
Content-Type: application/json

{
  "error": "circuit_open",
  "message": "Service temporarily unavailable",
  "upstream": "backend",
  "retry_after": 30
}
```

## Metrics

### Rate Limiting Metrics

```
# Request counts
zentinel_rate_limit_allowed_total{route="api", key="client-ip"} 100000
zentinel_rate_limit_limited_total{route="api", key="client-ip"} 500

# Current state
zentinel_rate_limit_current_requests{route="api"} 75

# Backend health (for distributed)
zentinel_rate_limit_backend_errors_total{backend="redis"} 5
zentinel_rate_limit_backend_latency_ms{backend="redis", quantile="0.99"} 2.5
```

### Circuit Breaker Metrics

```
# State (0=closed, 1=open, 2=half-open)
zentinel_circuit_breaker_state{upstream="backend", scope="production"} 0

# Transitions
zentinel_circuit_breaker_opens_total{upstream="backend"} 3
zentinel_circuit_breaker_closes_total{upstream="backend"} 2

# Current counts
zentinel_circuit_breaker_failures{upstream="backend"} 2
zentinel_circuit_breaker_successes{upstream="backend"} 5
```

## Best Practices

### 1. Layer Rate Limits

Apply rate limits at multiple levels:

```kdl
// Global rate limit
limits {
    max-requests-per-second 10000
}

// Per-namespace
scopes {
    scope "production" {
        rate-limit {
            requests-per-second 5000
        }
    }
}

// Per-route
routes {
    route "expensive-api" {
        policies {
            rate-limit {
                requests-per-second 100
            }
        }
    }
}
```

### 2. Use Appropriate Keys

Choose rate limit keys based on use case:

```kdl
// Public API - limit by client IP
route "public-api" {
    policies {
        rate-limit {
            key "client-ip"
        }
    }
}

// Authenticated API - limit by API key
route "authenticated-api" {
    policies {
        rate-limit {
            key "header" "Authorization"
        }
    }
}

// Premium tier - higher limits
route "premium-api" {
    policies {
        rate-limit {
            key "header" "X-API-Tier"
            // Different limits based on tier value
        }
    }
}
```

### 3. Set Reasonable Bursts

Allow some burst capacity for legitimate traffic spikes:

```kdl
policies {
    rate-limit {
        requests-per-second 100
        burst 20  // 20% burst capacity
    }
}
```

### 4. Configure Circuit Breakers Conservatively

Avoid false positives with appropriate thresholds:

```kdl
circuit-breaker {
    // Require multiple failures before opening
    failure-threshold 5

    // Give service time to recover
    timeout-secs 30

    // Require multiple successes before closing
    success-threshold 2

    // Only count real errors
    failure-statuses [502, 503, 504]
    // Don't count 500 (app errors) or 429 (rate limited)
}
```

### 5. Monitor and Alert

Set up alerts on rate limiting and circuit breaker events:

```yaml
# Example Prometheus alerting rules
groups:
  - name: rate_limiting
    rules:
      - alert: HighRateLimitRejections
        expr: rate(zentinel_rate_limit_limited_total[5m]) > 100
        for: 5m
        annotations:
          summary: "High rate limit rejections"

      - alert: CircuitBreakerOpen
        expr: zentinel_circuit_breaker_state == 1
        for: 1m
        annotations:
          summary: "Circuit breaker open"
```

## Comparison with Other Proxies

| Feature | Zentinel | Nginx | Envoy | HAProxy |
|---------|----------|-------|-------|---------|
| Local rate limit | Yes | Yes | Yes | Yes |
| Distributed (Redis) | Yes | No | Yes | No |
| Token bucket | Yes | Yes | Yes | Yes |
| Sliding window | Yes | No | Yes | No |
| Scoped limits | Yes | No | Partial | No |
| Circuit breaker | Yes | No | Yes | No |
| Per-agent isolation | Yes | N/A | No | N/A |
