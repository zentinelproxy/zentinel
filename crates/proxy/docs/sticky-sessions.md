# Sticky Sessions (Session Affinity)

Cookie-based session affinity for stateful applications.

## Overview

Sticky sessions route requests from the same client to the same backend server. This is essential for:

- Applications with server-side session state
- WebSocket connections with in-memory state
- Caching layers where client affinity improves hit rates
- Applications that haven't been designed for horizontal scaling

| Feature | Description |
|---------|-------------|
| Cookie-based | Uses HTTP cookies for affinity tracking |
| HMAC signed | Prevents cookie tampering |
| Fallback | Configurable algorithm when target unavailable |
| Health-aware | Automatic failover to healthy targets |

## Configuration

```kdl
upstreams {
    upstream "stateful-backend" {
        target "10.0.0.1:8080"
        target "10.0.0.2:8080"
        target "10.0.0.3:8080"

        load-balancing "sticky" {
            cookie-name "SERVERID"
            cookie-ttl "1h"
            cookie-path "/"
            cookie-secure true
            cookie-same-site "lax"
            fallback "round-robin"
        }
    }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cookie-name` | string | **required** | Name of the affinity cookie |
| `cookie-ttl` | duration | **required** | Cookie lifetime (e.g., "1h", "30m", "86400s") |
| `cookie-path` | string | "/" | Cookie path attribute |
| `cookie-secure` | bool | true | Set HttpOnly and Secure flags |
| `cookie-same-site` | string | "lax" | SameSite policy: "lax", "strict", or "none" |
| `fallback` | string | "round-robin" | Algorithm when no cookie or target unavailable |

### Duration Format

The `cookie-ttl` field supports human-readable durations:

```kdl
cookie-ttl "1h"      // 1 hour
cookie-ttl "30m"     // 30 minutes
cookie-ttl "1d"      // 1 day
cookie-ttl "3600s"   // 3600 seconds
cookie-ttl "3600"    // 3600 seconds (numeric)
```

### Fallback Algorithms

When no valid cookie exists or the target is unhealthy, the fallback algorithm is used:

```kdl
// Round-robin for even distribution (default)
fallback "round-robin"

// Random selection
fallback "random"

// Least connections
fallback "least-connections"

// Power of Two Choices (latency-aware)
fallback "p2c"

// Consistent hashing (by client IP)
fallback "ip-hash"
```

## How It Works

```
┌────────────────────────────────────────────────────────────┐
│                    Sticky Session Flow                      │
├────────────────────────────────────────────────────────────┤
│                                                             │
│   Client Request                                            │
│        │                                                    │
│        ▼                                                    │
│   ┌─────────────────┐                                       │
│   │ Check for       │                                       │
│   │ SERVERID cookie │                                       │
│   └────────┬────────┘                                       │
│            │                                                │
│       ┌────┴────┐                                           │
│       │ Cookie  │                                           │
│       │ exists? │                                           │
│       └────┬────┘                                           │
│            │                                                │
│     Yes    │    No                                          │
│    ┌───────┴───────┐                                        │
│    │               │                                        │
│    ▼               ▼                                        │
│ ┌─────────┐   ┌─────────────┐                               │
│ │ Verify  │   │  Fallback   │                               │
│ │  HMAC   │   │  Algorithm  │                               │
│ │signature│   │(round-robin)│                               │
│ └────┬────┘   └──────┬──────┘                               │
│      │               │                                      │
│   ┌──┴──┐            │                                      │
│   │Valid│            │                                      │
│   └──┬──┘            │                                      │
│      │               │                                      │
│  Yes │  No           │                                      │
│  ┌───┴───┐           │                                      │
│  │       │           │                                      │
│  ▼       └───────────┤                                      │
│ ┌───────────┐        │                                      │
│ │  Target   │        │                                      │
│ │  healthy? │        │                                      │
│ └─────┬─────┘        │                                      │
│       │              │                                      │
│   Yes │  No          │                                      │
│   ┌───┴───┐          │                                      │
│   │       └──────────┤                                      │
│   ▼                  │                                      │
│ ┌────────────┐       │                                      │
│ │ Route to   │       │                                      │
│ │ sticky     │       │                                      │
│ │ target     │       │                                      │
│ └────────────┘       │                                      │
│                      ▼                                      │
│              ┌────────────────┐                              │
│              │ Select target  │                              │
│              │ via fallback   │                              │
│              └───────┬────────┘                              │
│                      │                                       │
│                      ▼                                       │
│              ┌────────────────┐                              │
│              │ Set-Cookie in  │                              │
│              │ response       │                              │
│              └────────────────┘                              │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Cookie Format

The sticky session cookie uses a signed format to prevent tampering:

```
{target_index}.{hmac_signature}
```

### Example

```
SERVERID=2.a7f3b9c1d2e4f567
         │ └────────────────── HMAC-SHA256 signature (first 16 hex chars)
         └──────────────────── Target index (compact, doesn't expose IPs)
```

### Security Features

| Feature | Purpose |
|---------|---------|
| Index-based | Backend IPs not exposed in cookie |
| HMAC-SHA256 | Prevents cookie forgery/tampering |
| Auto-generated key | Unique 32-byte key per startup |
| HttpOnly | Prevents JavaScript access |
| Secure | HTTPS-only transmission |
| SameSite | CSRF protection |

## Response Headers

### First Request (No Cookie)

```http
HTTP/1.1 200 OK
Set-Cookie: SERVERID=0.a7f3b9c1d2e4f567; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax
Content-Type: application/json

{"message": "Hello from server 1"}
```

### Subsequent Requests (With Cookie)

```http
GET /api/user HTTP/1.1
Host: api.example.com
Cookie: SERVERID=0.a7f3b9c1d2e4f567
```

Response routed to same backend without setting new cookie.

### Failover (Target Unhealthy)

When the sticky target becomes unhealthy, a new cookie is issued:

```http
HTTP/1.1 200 OK
Set-Cookie: SERVERID=2.c8d9e0f1a2b3c4d5; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax
Content-Type: application/json

{"message": "Hello from server 3"}
```

## SameSite Policies

| Policy | Use Case |
|--------|----------|
| `lax` | Default. Cookie sent with top-level navigations and GET from third-party |
| `strict` | Cookie only sent in first-party context |
| `none` | Cookie sent in all contexts (requires Secure flag) |

### When to Use Each

```kdl
// Most applications (default)
cookie-same-site "lax"

// High-security applications
cookie-same-site "strict"

// Cross-origin APIs (CORS)
cookie-same-site "none"
```

## Metrics

```
# Sticky session hits (cookie valid, target healthy)
zentinel_sticky_session_hits_total{upstream="stateful-backend"} 95000

# Sticky session misses (no cookie or fallback used)
zentinel_sticky_session_misses_total{upstream="stateful-backend"} 5000

# Failovers due to unhealthy target
zentinel_sticky_session_failovers_total{upstream="stateful-backend"} 150

# Invalid cookie signatures (possible tampering attempts)
zentinel_sticky_session_invalid_signature_total{upstream="stateful-backend"} 23
```

## Best Practices

### 1. Choose Appropriate TTL

Balance session persistence with backend flexibility:

```kdl
// Short-lived sessions (API requests)
cookie-ttl "15m"

// Web application sessions
cookie-ttl "1h"

// Long-lived sessions (shopping cart)
cookie-ttl "7d"
```

### 2. Use with Health Checks

Always configure health checks to enable automatic failover:

```kdl
upstreams {
    upstream "stateful-backend" {
        target "10.0.0.1:8080"
        target "10.0.0.2:8080"

        health-check {
            path "/health"
            interval-secs 5
            timeout-secs 2
            unhealthy-threshold 3
            healthy-threshold 2
        }

        load-balancing "sticky" {
            cookie-name "SERVERID"
            cookie-ttl "1h"
            fallback "round-robin"
        }
    }
}
```

### 3. Consider Fallback Algorithm

Choose a fallback that matches your use case:

```kdl
// Stateless workloads: use round-robin
fallback "round-robin"

// Latency-sensitive: use P2C
fallback "p2c"

// Cache-heavy: use IP hash for some consistency
fallback "ip-hash"
```

### 4. Avoid Sticky Sessions When Possible

Sticky sessions have trade-offs:

| Consideration | Impact |
|---------------|--------|
| Uneven load | Popular sessions concentrate on one server |
| Failover | Session state lost on failover |
| Scaling | New servers don't receive existing sessions |
| Maintenance | Rolling updates harder |

**Prefer stateless design** where possible:
- Store session in Redis/Memcached
- Use JWT tokens with client-side state
- Use database-backed sessions

### 5. Monitor Sticky Session Health

Set up alerts for sticky session issues:

```yaml
# Example Prometheus alerting rules
groups:
  - name: sticky_sessions
    rules:
      - alert: HighStickyFailoverRate
        expr: rate(zentinel_sticky_session_failovers_total[5m]) > 10
        for: 5m
        annotations:
          summary: "High sticky session failover rate"

      - alert: StickySignatureTampering
        expr: rate(zentinel_sticky_session_invalid_signature_total[5m]) > 1
        for: 1m
        annotations:
          summary: "Possible cookie tampering detected"
```

## Comparison with Other Proxies

| Feature | Zentinel | Nginx | HAProxy | Envoy |
|---------|----------|-------|---------|-------|
| Cookie-based | Yes | Yes | Yes | Yes |
| HMAC signed | Yes | No | No | No |
| IP not exposed | Yes | No | No | No |
| Configurable fallback | Yes | Limited | Yes | Yes |
| SameSite support | Yes | Yes | Yes | Yes |
| Health-aware | Yes | Yes | Yes | Yes |

## Troubleshooting

### Cookie Not Being Set

1. Check that the upstream is configured with `load-balancing "sticky"`
2. Verify the response includes the `Set-Cookie` header
3. Check browser DevTools for cookie rejection reasons

### Requests Not Routing to Same Backend

1. Verify cookie is being sent with requests
2. Check for HMAC signature validation failures in logs
3. Ensure target is healthy (check health check status)

### Invalid Signature Warnings

```
WARN Invalid sticky cookie signature (possible tampering)
```

This can occur when:
- The proxy was restarted (new HMAC key generated)
- Cookie was modified by client
- Cookie from different Zentinel instance

**Resolution:** These are typically benign after restarts. The fallback algorithm assigns a new backend and sets a fresh cookie.

## Implementation Details

The sticky session balancer (`crates/proxy/src/upstream/sticky_session.rs`) wraps a fallback load balancer:

```rust
pub struct StickySessionBalancer {
    config: StickySessionRuntimeConfig,
    targets: Vec<UpstreamTarget>,
    fallback: Arc<dyn LoadBalancer>,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}
```

Key methods:
- `extract_affinity()` - Parses and validates sticky cookie
- `generate_cookie_value()` - Creates signed cookie value
- `select()` - Routes to sticky target or falls back
- `report_health()` - Updates health status and propagates to fallback
