# Proxy Architecture

This document describes the internal architecture of the Sentinel proxy dataplane.

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Sentinel Proxy                                  │
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Listeners  │    │   Routes    │    │  Upstreams  │    │   Agents    │  │
│  │             │    │             │    │             │    │             │  │
│  │  - HTTP     │───▶│  - Matcher  │───▶│  - Pools    │    │  - WAF      │  │
│  │  - HTTPS    │    │  - Priority │    │  - LB       │    │  - Auth     │  │
│  │  - H2       │    │  - Scoped   │    │  - Health   │    │  - Custom   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│         │                  │                  │                  │          │
│         ▼                  ▼                  ▼                  ▼          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         SentinelProxy                                  │  │
│  │                    (implements ProxyHttp)                              │  │
│  │                                                                        │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │  │
│  │  │  Rate    │  │ Circuit  │  │  Cache   │  │  GeoIP   │  │  Static  │ │  │
│  │  │  Limit   │  │ Breaker  │  │ Manager  │  │  Filter  │  │  Files   │ │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                        Observability Layer                             │  │
│  │                                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐            │  │
│  │  │   Metrics    │    │   Logging    │    │   Tracing    │            │  │
│  │  │ (Prometheus) │    │ (Structured) │    │ (OpenTelemetry)           │  │
│  │  └──────────────┘    └──────────────┘    └──────────────┘            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Request Lifecycle

The complete flow of a request through the proxy:

```
Client Request
      │
      ▼
┌─────────────────┐
│ 1. TLS Handshake│  SNI-based certificate selection
│    (if HTTPS)   │  mTLS client verification
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 2. Trace ID     │  Generate or extract from headers
│    Generation   │  X-Trace-Id, X-Correlation-Id, X-Request-Id
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 3. Route Match  │  Path, host, header, method matching
│                 │  Priority-based evaluation
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 4. Rate Limit   │  Token bucket per route/client
│    Check        │  Local or distributed (Redis/Memcached)
└────────┬────────┘
         │
    ┌────┴────┐
    │ Limited?│───Yes──▶ Return 429
    └────┬────┘
         │ No
         ▼
┌─────────────────┐
│ 5. GeoIP Filter │  Block/allow by country
│    (if enabled) │  MaxMind or IP2Location
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 6. Agent Call   │  on_request_headers
│    (Headers)    │  WAF, auth, custom logic
└────────┬────────┘
         │
    ┌────┴────┐
    │ Blocked?│───Yes──▶ Return block response
    └────┬────┘
         │ Allow
         ▼
┌─────────────────┐
│ 7. Body Read    │  Stream or buffer based on config
│    (if present) │  Decompression with limits
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 8. Agent Call   │  on_request_body (if configured)
│    (Body)       │  WAF body inspection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 9. Upstream     │  P2C, least-tokens, consistent hash
│    Selection    │  Health-aware selection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 10. Circuit     │  Check circuit breaker state
│     Breaker     │  Fast-fail if open
└────────┬────────┘
         │
    ┌────┴────┐
    │  Open?  │───Yes──▶ Return 503
    └────┬────┘
         │ Closed/Half-Open
         ▼
┌─────────────────┐
│ 11. Shadow      │  Fire-and-forget to canary
│     Request     │  Based on sampling rate
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 12. Upstream    │  With connection pooling
│     Request     │  Timeout enforcement
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 13. Agent Call  │  on_response_headers
│     (Response)  │  Header mutations
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 14. Cache Check │  Store if cacheable
│     (if enabled)│  Serve from cache on hit
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 15. Response    │  Compression, header rewrites
│     Processing  │  Agent body processing
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 16. Access Log  │  Structured JSON or combined format
│                 │  Trace ID, latency, status
└────────┬────────┘
         │
         ▼
   Client Response
```

## Component Interactions

### Configuration Hot Reload

```
┌──────────────────────────────────────────────────────────────────┐
│                        Hot Reload Flow                            │
└──────────────────────────────────────────────────────────────────┘

     ┌───────────┐         ┌───────────┐         ┌───────────┐
     │   File    │         │  Signal   │         │   API     │
     │  Change   │         │  (SIGHUP) │         │  Trigger  │
     └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
           │                     │                     │
           └──────────────┬──────┴─────────────────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ ConfigManager   │
                 │   .reload()     │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │   Parse New     │
                 │   Config File   │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │    Validate     │──── Fail ────▶ Rollback + Log
                 │   (Schema +     │
                 │   References)   │
                 └────────┬────────┘
                          │ Pass
                          ▼
                 ┌─────────────────┐
                 │  Atomic Swap    │
                 │                 │
                 │  - Routes       │
                 │  - Upstreams    │
                 │  - Rate Limits  │
                 │  - Agents       │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Graceful Drain  │
                 │ Old Connections │
                 └────────┬────────┘
                          │
                          ▼
                    Reload Complete
```

### Agent Processing Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│                     Agent Pipeline                                │
└──────────────────────────────────────────────────────────────────┘

                    Request
                       │
                       ▼
            ┌───────────────────┐
            │   AgentManager    │
            │                   │
            │  Route's agents:  │
            │  [waf, auth, log] │
            └─────────┬─────────┘
                      │
       ┌──────────────┼──────────────┐
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │   WAF   │   │  Auth   │   │  Log    │
  │  Agent  │   │  Agent  │   │  Agent  │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       │  Semaphore   │  Semaphore   │  Semaphore
       │  (isolated)  │  (isolated)  │  (isolated)
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │ Circuit │   │ Circuit │   │ Circuit │
  │ Breaker │   │ Breaker │   │ Breaker │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       ▼              ▼              ▼
  ┌─────────┐   ┌─────────┐   ┌─────────┐
  │  Pool   │   │  Pool   │   │  Pool   │
  │  (UDS)  │   │ (gRPC)  │   │  (UDS)  │
  └────┬────┘   └────┬────┘   └────┬────┘
       │              │              │
       └──────────────┼──────────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Merge Decisions   │
            │                   │
            │ - First BLOCK wins│
            │ - Merge mutations │
            │ - Collect tags    │
            └───────────────────┘
```

### Upstream Selection

```
┌──────────────────────────────────────────────────────────────────┐
│                   Load Balancing Flow                             │
└──────────────────────────────────────────────────────────────────┘

                    Request
                       │
                       ▼
            ┌───────────────────┐
            │   UpstreamPool    │
            │   "api-cluster"   │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │  Get Healthy      │
            │  Targets          │
            └─────────┬─────────┘
                      │
                      ▼
    ┌─────────────────────────────────────┐
    │         Load Balancer               │
    │                                     │
    │  ┌─────────┐  ┌─────────────────┐  │
    │  │   P2C   │  │ Least Tokens    │  │
    │  │ (default)│  │ (for inference) │  │
    │  └─────────┘  └─────────────────┘  │
    │                                     │
    │  ┌─────────────┐  ┌─────────────┐  │
    │  │ Consistent  │  │  Adaptive   │  │
    │  │    Hash     │  │ (latency)   │  │
    │  └─────────────┘  └─────────────┘  │
    └─────────────────┬───────────────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Selected Target   │
            │ 10.0.0.2:8080     │
            └─────────┬─────────┘
                      │
                      ▼
            ┌───────────────────┐
            │ Connection Pool   │
            │ (reuse or create) │
            └─────────┬─────────┘
                      │
                      ▼
               Send Request
```

## Rate Limiting Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                   Rate Limiting Layers                            │
└──────────────────────────────────────────────────────────────────┘

                         Request
                            │
                            ▼
                  ┌───────────────────┐
                  │ Extract Rate Key  │
                  │ (client-ip, header,│
                  │  route, etc.)     │
                  └─────────┬─────────┘
                            │
         ┌──────────────────┼──────────────────┐
         │                  │                  │
         ▼                  ▼                  ▼
   ┌───────────┐     ┌───────────┐     ┌───────────┐
   │   Local   │     │   Redis   │     │ Memcached │
   │   Rate    │     │   Rate    │     │   Rate    │
   │  Limiter  │     │  Limiter  │     │  Limiter  │
   └─────┬─────┘     └─────┬─────┘     └─────┬─────┘
         │                  │                  │
         │   In-memory      │  Sliding window  │  Fixed window
         │   token bucket   │  with sorted set │  with incr
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Allowed/Limited  │
                  └───────────────────┘


  For Inference Routes:

                         Request
                            │
                            ▼
                  ┌───────────────────┐
                  │   Count Tokens    │
                  │  (tiktoken/est.)  │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │ Token Rate Limit  │
                  │ (tokens/minute)   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │   Token Budget    │
                  │ (daily/monthly)   │
                  └─────────┬─────────┘
                            │
                            ▼
                  ┌───────────────────┐
                  │  Cost Tracking    │
                  │ ($ per request)   │
                  └───────────────────┘
```

## Circuit Breaker States

```
┌──────────────────────────────────────────────────────────────────┐
│                   Circuit Breaker FSM                             │
└──────────────────────────────────────────────────────────────────┘


         ┌──────────────────────────────────────────┐
         │                                          │
         │  ┌────────┐                              │
         │  │ CLOSED │◀──────────────────┐          │
         │  └───┬────┘                   │          │
         │      │                        │          │
         │      │ failure_count++        │          │
         │      │                        │          │
         │      ▼                        │          │
         │  ┌────────────────────┐       │          │
         │  │ failure_count >=   │──No───┘          │
         │  │ threshold?         │                  │
         │  └────────┬───────────┘                  │
         │           │ Yes                          │
         │           ▼                              │
         │     ┌──────────┐                         │
         │     │   OPEN   │                         │
         │     └────┬─────┘                         │
         │          │                               │
         │          │ (all requests fast-fail)      │
         │          │                               │
         │          │ after timeout_secs            │
         │          ▼                               │
         │   ┌────────────┐                         │
         │   │ HALF-OPEN  │                         │
         │   └──────┬─────┘                         │
         │          │                               │
         │    ┌─────┴─────┐                         │
         │    │           │                         │
         │    ▼           ▼                         │
         │  Success    Failure                      │
         │    │           │                         │
         │    │ success   │ failure                 │
         │    │ count++   │ → OPEN                  │
         │    │           │                         │
         │    ▼           │                         │
         │  count >=      │                         │
         │  threshold?    │                         │
         │    │           │                         │
         │    ▼           │                         │
         │  CLOSED ◀──────┘                         │
         │                                          │
         └──────────────────────────────────────────┘

  Configuration:
  - failure_threshold: 5 (consecutive failures to open)
  - success_threshold: 2 (consecutive successes to close)
  - timeout_secs: 30 (time in open state before half-open)
```

## Scoped Configuration

```
┌──────────────────────────────────────────────────────────────────┐
│                   Scope Hierarchy                                 │
└──────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │     Global      │
                    │                 │
                    │ - Default limits│
                    │ - Global routes │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
     ┌────────────┐   ┌────────────┐   ┌────────────┐
     │ Namespace A│   │ Namespace B│   │ Namespace C│
     │            │   │            │   │            │
     │ - Overrides│   │ - Overrides│   │ - Overrides│
     │ - NS routes│   │ - NS routes│   │ - NS routes│
     └──────┬─────┘   └──────┬─────┘   └──────┬─────┘
            │                │                │
     ┌──────┼──────┐         │         ┌──────┼──────┐
     │      │      │         │         │      │      │
     ▼      ▼      ▼         ▼         ▼      ▼      ▼
  ┌─────┐┌─────┐┌─────┐  ┌─────┐   ┌─────┐┌─────┐┌─────┐
  │Svc 1││Svc 2││Svc 3│  │Svc 4│   │Svc 5││Svc 6││Svc 7│
  └─────┘└─────┘└─────┘  └─────┘   └─────┘└─────┘└─────┘


  Visibility Rules:
  ┌─────────────────────────────────────────────────────────────┐
  │ Scope Level    │ Can See Routes From                        │
  ├─────────────────────────────────────────────────────────────┤
  │ Global         │ Global only                                │
  │ Namespace      │ Global + Own Namespace                     │
  │ Service        │ Global + Namespace + Own Service           │
  └─────────────────────────────────────────────────────────────┘

  Inheritance Chain (for config):
  Service config ─▶ Namespace config ─▶ Global config
         │                  │                │
         └──── overrides ───┴── overrides ───┘
```

## Memory Management

```
┌──────────────────────────────────────────────────────────────────┐
│                   Bounded Memory Design                           │
└──────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────┐
  │                     Memory Bounds                                │
  ├─────────────────────────────────────────────────────────────────┤
  │                                                                  │
  │  Request Body Buffer     │  max_body_size_bytes (config)        │
  │  Response Cache          │  max_size_bytes (100MB default)      │
  │  Static File Cache       │  max 1MB per file (mmap > 10MB)      │
  │  Route Match Cache       │  LRU with max_items                  │
  │  Agent Call Queue        │  Semaphore (100 concurrent default)  │
  │  Rate Limit State        │  Per-key with TTL expiration         │
  │  Connection Pool         │  max_connections per upstream        │
  │                                                                  │
  └─────────────────────────────────────────────────────────────────┘

  Decompression Protection:
  ┌─────────────────────────────────────────────────────────────────┐
  │  max_ratio: 100x       │  Prevents zip bombs                    │
  │  max_output: 10MB      │  Absolute size limit                   │
  │  incremental check     │  Stop early if ratio exceeded          │
  └─────────────────────────────────────────────────────────────────┘
```

## Design Principles

### 1. Lock-Free Hot Paths

```rust
// DashMap for concurrent access without global locks
let rate_limiters: DashMap<RouteId, RateLimiter> = DashMap::new();

// Atomic operations for counters
let request_count: AtomicU64 = AtomicU64::new(0);
```

### 2. Registry Pattern for Atomic Config Swap

```rust
// Old config continues serving in-flight requests
// New config takes effect for new requests atomically
let config: Arc<RwLock<Config>> = Arc::new(RwLock::new(config));

// Swap is atomic - no torn reads
*config.write() = new_config;
```

### 3. Queue Isolation (Noisy Neighbor Prevention)

```rust
// Each agent has its own semaphore
struct Agent {
    semaphore: Semaphore,  // Limits concurrent calls to THIS agent
    // ...
}

// Slow agent A doesn't affect agent B's queue
```

### 4. Fire-and-Forget for Non-Critical Paths

```rust
// Shadow requests don't block the response
tokio::spawn(async move {
    let _ = shadow_request(req).await;
    // Result ignored - fire and forget
});
```

### 5. Graceful Degradation

```rust
// Fallback to local rate limiting if Redis fails
match redis_check().await {
    Ok(result) => result,
    Err(_) => local_rate_limiter.check(),
}
```
