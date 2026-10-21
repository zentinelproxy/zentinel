# Module Reference

Comprehensive documentation for all modules in the Zentinel proxy crate.

## Core Modules

### `proxy`

The main proxy implementation using Pingora's `ProxyHttp` trait.

**Sub-modules:**
- `context` - Request context maintained throughout lifecycle
- `fallback` - Fallback handling when upstreams fail
- `handlers` - HTTP request handlers
- `http_trait` - `ProxyHttp` trait implementation
- `model_routing` - Model-based routing for inference

**Key Struct:** `ZentinelProxy`

```rust
pub struct ZentinelProxy {
    config_manager: Arc<ConfigManager>,
    route_matcher: Arc<RouteMatcher>,
    upstream_pool: Arc<UpstreamPool>,
    agent_manager: Arc<AgentManager>,
    rate_limit_manager: Arc<RateLimitManager>,
    cache_manager: Arc<CacheManager>,
    log_manager: Arc<LogManager>,
    // ...
}
```

### `app`

Application entry point and server lifecycle management.

**Key Struct:** `ZentinelApp`

```rust
impl ZentinelApp {
    pub fn new(config: Config) -> Result<Self, Error>;
    pub async fn run(self) -> Result<(), Error>;
    pub fn shutdown(&self);
}
```

### `routing`

Route matching with multiple match conditions.

**Match Types:**
- `Path` - Exact path match
- `PathPrefix` - Path prefix match
- `PathRegex` - Regex pattern match
- `Host` - Exact or wildcard host match
- `Header` - Header presence or value match
- `Method` - HTTP method match
- `QueryParam` - Query parameter match

**Key Struct:** `RouteMatcher`

```rust
impl RouteMatcher {
    pub fn match_request(&self, req: &Request) -> Option<&Route>;
    pub fn route_by_id(&self, id: &str) -> Option<&Route>;
    pub fn cache_stats(&self) -> CacheStats;
}
```

### Namespaces and services

There is no separate scoped matcher. `Config::lower_scopes` (config crate,
`scopes.rs`) moves every namespace and service resource to the top level under
its qualified id (`ns:name`, `ns:svc:name`) and resolves the references in it,
so scoped routes, upstreams, filters and agents are built like global ones.
`ZentinelProxy` keeps one `RouteMatcher` for the global listeners
(`Config::routes_served_on(&Scope::Global)`) and one per namespace- or
service-bound listener scope (`ListenerMatchers`). A route is served on the
listeners of the nearest scope, from its own outwards, that has a listener.

---

## Upstream Management

### `upstream`

Load balancing and upstream pool management.

**Sub-modules:**
- `p2c` - Power of Two Choices algorithm
- `least_tokens` - Token-aware load balancing
- `consistent_hash` - Consistent hashing for sticky sessions
- `adaptive` - Latency-weighted adaptive balancing
- `health` - Health checking integration
- `inference_health` - Inference-specific health checks

**Load Balancing Algorithms:**

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `P2cBalancer` | Power of Two Choices | General purpose (default) |
| `LeastTokensQueuedBalancer` | Least queued tokens | LLM inference endpoints |
| `ConsistentHashBalancer` | Consistent hashing | Session affinity |
| `AdaptiveBalancer` | Latency-weighted | Mixed workloads |

**Key Struct:** `UpstreamPool`

```rust
impl UpstreamPool {
    pub fn select(&self, ctx: &RequestContext) -> Result<TargetSelection, Error>;
    pub fn report_health(&self, target: &Target, healthy: bool);
    pub fn healthy_targets(&self) -> Vec<&Target>;
    pub fn report_result(&self, target: &Target, result: &RequestResult);
}
```

### `health`

Active and passive health checking.

**Check Types:**
- `Http` - GET request with expected status
- `Tcp` - TCP connection attempt
- `Grpc` - gRPC health check
- `Inference` - Query `/v1/models` endpoint
- `InferenceProbe` - Send minimal completion request
- `ModelStatus` - Provider-specific status endpoints
- `QueueDepth` - Monitor queue depth

**Key Structs:**

```rust
pub struct ActiveHealthChecker {
    pub fn check(&self, target: &Target) -> HealthStatus;
}

pub struct PassiveHealthChecker {
    pub fn record_success(&self, target: &Target);
    pub fn record_failure(&self, target: &Target);
    pub fn is_healthy(&self, target: &Target) -> bool;
}
```

**Configuration:**

```kdl
upstream "api" {
    health-check {
        type "http"
        path "/health"
        interval-secs 10
        timeout-secs 5
        healthy-threshold 2
        unhealthy-threshold 3
        expected-status 200
    }
}
```

---

## Rate Limiting

### `rate_limit`

Local token bucket rate limiting.

**Key Struct:** `RateLimitManager`

```rust
impl RateLimitManager {
    pub fn register_route(&self, route_id: &str, config: &RateLimitConfig);
    pub fn check(&self, route_id: &str, key: &str) -> RateLimitOutcome;
    pub fn cleanup(&self);  // Remove idle limiters
}

pub enum RateLimitOutcome {
    Allowed,
    Limited,
}
```

### `distributed_rate_limit`

Redis-backed distributed rate limiting using sliding window.

**Algorithm:**
1. Store timestamp in Redis sorted set
2. Remove timestamps older than window
3. Count remaining timestamps
4. Allow if count <= max_rps

**Key Struct:** `RedisRateLimiter`

```rust
impl RedisRateLimiter {
    pub async fn check(&self, key: &str, max_rps: u32) -> RateLimitOutcome;
}
```

**Requires Feature:** `distributed-rate-limit`

### `memcached_rate_limit`

Memcached-backed fixed window rate limiting.

**Key Struct:** `MemcachedRateLimiter`

**Requires Feature:** `distributed-rate-limit-memcached`

Rate limits of namespace and service routes and filters are ordinary
limiters keyed by the route's or filter's qualified id, so each scope's are
counted separately.

---

## Circuit Breakers

### `scoped_circuit_breaker`

Scope-aware circuit breakers for failure isolation.

**States:**
- `Closed` - Normal operation
- `Open` - Fast-fail after threshold
- `HalfOpen` - Testing if service recovered

**Key Struct:** `ScopedCircuitBreakerManager`

```rust
impl ScopedCircuitBreakerManager {
    pub fn set_scope_config(&self, scope: &Scope, config: &CircuitBreakerConfig);
    pub fn get_breaker(&self, scope: &Scope, upstream: &str) -> CircuitBreaker;
    pub fn record_success(&self, scope: &Scope, upstream: &str);
    pub fn record_failure(&self, scope: &Scope, upstream: &str);
}
```

**Configuration:**

```kdl
scope "namespace/service" {
    circuit-breaker {
        failure-threshold 5
        success-threshold 2
        timeout-secs 30
    }
}
```

---

## Caching

### `cache`

HTTP response caching using Pingora's cache infrastructure.

**Key Struct:** `CacheManager`

```rust
impl CacheManager {
    pub fn configure_cache(&self, config: &CacheConfig);
    pub fn is_cache_enabled(&self, route_id: &str) -> bool;
    pub fn is_path_cacheable(&self, route_id: &str, path: &str) -> bool;
    pub fn register_route(&self, route_id: &str, config: &RouteCacheConfig);
}
```

**Features:**
- Per-route cache configuration
- Cache-Control header parsing
- TTL calculation with defaults
- Stale-while-revalidate support
- Stale-if-error support
- Path and extension-based cache exclusions (`exclude-extensions`, `exclude-paths`)

### `memory_cache`

Fast in-memory caching with S3-FIFO + TinyLFU eviction.

**Key Struct:** `MemoryCacheManager`

```rust
impl MemoryCacheManager {
    pub fn get<K, V>(&self, key: &K) -> Option<V>;
    pub fn insert<K, V>(&self, key: K, value: V);
    pub fn stats(&self) -> CacheStats;
}
```

**Configuration:**

```rust
MemoryCacheConfig {
    max_items: 10_000,
    default_ttl: Duration::from_secs(60),
    enable_stats: true,
}
```

---

## Static Files

### `static_files`

Static file serving with compression and caching.

**Sub-modules:**
- `cache` - File caching with pre-computed compression
- `compression` - Content encoding negotiation
- `range` - HTTP Range request handling

**Key Struct:** `StaticFileServer`

```rust
impl StaticFileServer {
    pub async fn serve(&self, path: &Path, req: &Request) -> Response;
    pub fn clear_cache(&self);
    pub fn cache_stats(&self) -> CacheStats;
}
```

**Features:**
- Range requests (206 Partial Content)
- Zero-copy with mmap (files > 10MB)
- On-the-fly gzip/brotli compression
- In-memory cache (files < 1MB)
- Directory listing
- SPA fallback routing

**Configuration:**

```kdl
route "/static" {
    service-type "static"
    static-files {
        root "/var/www/static"
        index "index.html"
        fallback "index.html"
        cache-control "public, max-age=3600"
        compress #true
    }
}
```

---

## WebSocket

### `websocket`

WebSocket frame-level handling per RFC 6455.

**Sub-modules:**
- `codec` - Frame parsing/encoding
- `inspector` - Frame inspection logic
- `proxy` - WebSocket proxying

**Key Structs:**

```rust
pub struct WebSocketFrame {
    pub opcode: Opcode,
    pub fin: bool,
    pub payload: Bytes,
}

pub struct WebSocketHandler {
    pub async fn proxy(&self, client: &mut Stream, upstream: &mut Stream);
}

pub struct WebSocketInspector {
    pub fn inspect(&self, frame: &WebSocketFrame) -> InspectionResult;
}
```

**Configuration:**

```kdl
route "/ws" {
    upstream "websocket-backend"
    websocket #true
    websocket-inspection #false
}
```

---

## Traffic Management

### `shadow`

Fire-and-forget request mirroring for canary testing.

**Key Struct:** `ShadowManager`

```rust
impl ShadowManager {
    pub fn should_shadow(&self, route: &Route) -> bool;
    pub async fn shadow_request(&self, req: Request, config: &ShadowConfig);
}
```

**Configuration:**

```kdl
route "/api" {
    shadow {
        upstream "canary-pool"
        percentage 10.0
        sample-header "X-Shadow" "true"
        buffer-body #true
    }
}
```

### `discovery`

Service discovery backends.

**Discovery Methods:**
- `Static` - Fixed list of backends
- `Dns` - A/AAAA record resolution
- `DnsSrv` - SRV record resolution
- `Consul` - Consul service catalog
- `Kubernetes` - Kubernetes endpoints
- `File` - Watch config file

**Key Struct:** `DiscoveryManager`

```rust
impl DiscoveryManager {
    pub fn register(&self, upstream_id: &str, config: DiscoveryConfig) -> Result<(), Box<Error>>;
    pub fn get(&self, upstream_id: &str) -> Option<Arc<dyn ServiceDiscovery + Send + Sync>>;
    pub async fn discover(&self, upstream_id: &str)
        -> Option<Result<(BTreeSet<Backend>, HashMap<u64, bool>)>>;
    pub fn remove(&self, upstream_id: &str);
    pub fn count(&self) -> usize;
}
```

**How it reaches the request path**

An `UpstreamPool` holds its own discovery source rather than going through the
manager: `build_discovery` (the body `DiscoveryManager::register` also uses)
constructs it, and `UpstreamPool::new` resolves it before the pool serves any
traffic. Discovered targets are appended to the pool's statically configured
ones.

`upstream::discovery_refresh` then keeps them current. It is a single supervisor
task, started in `ZentinelProxy::new`, that reads the upstream registries on each
tick and refreshes any pool whose interval has elapsed:

```rust
// crates/proxy/src/upstream/mod.rs
impl UpstreamPool {
    pub fn discovery_refresh_interval(&self) -> Option<Duration>;
    pub async fn refreshed(&self) -> Option<UpstreamPool>;
}
```

`refreshed()` returns a replacement pool only when the target set actually
changed. The replacement shares the original's circuit breakers and statistics,
so breaker state survives the swap; breakers for targets that disappeared are
dropped so the map stays bounded as backends churn. The supervisor installs the
replacement with `Registry::insert` / `ScopedRegistry::replace_item`, which is
the same swap the `SIGHUP` reload path performs.

Reading the registries on each tick — rather than holding an `Arc<UpstreamPool>`
per task — is what keeps this correct across a config reload, which replaces
every pool wholesale.

**Configuration:**

```kdl
upstream "api" {
    discovery "kubernetes" {
        namespace "default"
        service "my-service"
        port-name "http"
        refresh-interval 10
    }
}
```

---

## Security

### `tls`

TLS termination and certificate management.

**Features:**
- SNI-based certificate selection
- Wildcard certificate matching
- mTLS client verification
- Certificate hot-reload
- OCSP stapling

**Key Structs:**

```rust
pub struct SniResolver {
    pub fn resolve(&self, server_name: &str) -> Option<&CertifiedKey>;
}

pub struct HotReloadableSniResolver {
    pub fn reload(&self) -> Result<(), Error>;
}
```

**Configuration:**

```kdl
listener "https" {
    tls {
        cert-file "/etc/certs/default.crt"
        key-file "/etc/certs/default.key"
        min-version "tls1.2"

        sni "api.example.com" "*.api.example.com" {
            cert-file "/etc/certs/api.crt"
            key-file "/etc/certs/api.key"
        }

        client-auth #true
        ca-file "/etc/certs/ca.crt"
        ocsp-stapling #true
    }
}
```

### `geo_filter`

GeoIP-based request filtering.

**Database Backends:**
- MaxMind (GeoLite2/GeoIP2)
- IP2Location

**Key Struct:** `GeoFilterManager`

```rust
impl GeoFilterManager {
    pub fn register_filter(&self, id: &str, config: &GeoFilterConfig);
    pub fn check(&self, filter_id: &str, ip: IpAddr) -> GeoFilterResult;
    pub fn clear_expired_caches(&self);
}

pub enum GeoFilterResult {
    Allowed,
    Blocked { country: String },
    Error,
}
```

**Configuration:**

```kdl
filter "geo-block" {
    type "geo"
    database-path "/var/lib/GeoLite2-Country.mmdb"
    database-type "maxmind"
    action "block"
    countries "CN" "RU" "KP"
    fail-mode "open"
    cache-ttl 3600
}
```

### `decompression`

Safe decompression with zip bomb protection.

**Supported Encodings:**
- gzip
- deflate
- brotli

**Key Function:**

```rust
pub fn decompress_body(
    body: &[u8],
    encoding: ContentEncoding,
    config: &DecompressionConfig,
) -> Result<Vec<u8>, DecompressionError>;
```

**Protection:**

```rust
DecompressionConfig {
    max_ratio: 100.0,    // Max expansion ratio
    max_output_bytes: 10 * 1024 * 1024,  // 10MB limit
}
```

---

## Observability

### `logging`

Structured logging for access, errors, and audit.

**Log Types:**
- Access logs - Request/response with trace ID
- Error logs - Errors and warnings
- Audit logs - Security events

**Log Formats:**
- `Json` - Structured JSON
- `Combined` - Apache/nginx combined format

Each log file is opened independently: an access or error log that cannot be
opened is reported and left off without affecting the others, while a
configured audit log that cannot be opened fails startup.

**Key Struct:** `LogManager`

```rust
impl LogManager {
    pub fn write_access_log(&self, entry: &AccessLogEntry);
    pub fn write_error_log(&self, entry: &ErrorLogEntry);
    pub fn write_audit_log(&self, entry: &AuditLogEntry);
}
```

### `otel`

OpenTelemetry integration for distributed tracing.

**Features:**
- W3C Trace Context propagation
- OTLP export (Jaeger, Tempo, etc.)
- Configurable sampling rates

**Headers:**
- `traceparent` - W3C trace context
- `tracestate` - Vendor-specific state

**Requires Feature:** `opentelemetry`

### `trace_id`

Trace ID generation and propagation.

**Formats:**
- `TinyFlake` - 11-character high-precision IDs (default)
- `UUID` - Standard UUID v4

**Header Priority:**
1. `X-Trace-Id`
2. `X-Correlation-Id`
3. `X-Request-Id`
4. Auto-generate if missing

---

## Error Handling

### `errors`

Error response generation.

**Key Struct:** `ErrorHandler`

```rust
impl ErrorHandler {
    pub fn generate_response(
        &self,
        status: StatusCode,
        service_type: ServiceType,
        accept: &str,
    ) -> Response;
}
```

**Response Formats:**
- JSON for API routes
- HTML for web routes
- Text for others

### `validation`

Request/response schema validation.

**Key Struct:** `SchemaValidator`

```rust
impl SchemaValidator {
    pub fn validate_request(&self, req: &Request, schema: &JsonSchema) -> ValidationResult;
    pub fn validate_response(&self, resp: &Response, schema: &JsonSchema) -> ValidationResult;
}
```

---

## Hot Reload

### `reload`

Configuration hot reload with graceful transition.

**Sub-modules:**
- `coordinator` - Graceful reload coordination
- `signals` - OS signal handling in foreground mode: SIGHUP reload, SIGUSR1 reopen log files, SIGTERM/SIGINT shutdown, SIGUSR2 ignored. With `daemon` the thread reading the signals does not survive the fork, so they are accepted and ignored (#573)
- `validators` - Configuration validators

**Key Struct:** `ConfigManager`

```rust
impl ConfigManager {
    pub async fn reload(&self) -> Result<(), ReloadError>;
    pub fn subscribe(&self) -> Receiver<ReloadEvent>;
    pub fn validate(&self, config: &Config) -> Result<(), ValidationError>;
}
```

**Reload Triggers:**
- `Manual` - API trigger
- `FileChange` - File modification
- `Signal` - SIGHUP received
- `Scheduled` - Periodic reload

---

## Process

### `daemon`

Daemon mode (`-d` or `system { daemon #true }`).

The proxy forks at the start of `run_server`, while the process has a single
thread, and Pingora is told not to fork again: threads that exist at a fork
are lost in the child, which is how the signal thread and the runtime used to
be missing from the daemon (#573). Before the fork the configuration is loaded
and validated, so a broken one fails in the foreground with a non-zero exit.

**Key Struct:** `DaemonPlan`

- `prepare` - decide on daemon mode and check the configuration
- `daemonize` - fork; umask `0o007`, old pid file moved to `<pid-file>.old`,
  pid file written and locked, stdout/stderr kept, current directory kept
- `drop_privileges` - switch to `system { user group }` just before
  `run_forever`, so listeners are bound after the switch (daemon mode only)

---

## Built-in Handlers

### `builtin_handlers`

Built-in endpoints for operations.

**Endpoints:**
- `/status` - Service status (version, uptime)
- `/health` - Health check
- `/metrics` - Prometheus metrics
- `/upstreams` - Upstream health status
- `/config` - Current configuration

**Key Struct:** `BuiltinHandlerState`

```rust
impl BuiltinHandlerState {
    pub fn uptime_string(&self) -> String;
}
```

---

## Utilities

### `http_helpers`

HTTP request/response utilities.

**Key Functions:**

```rust
pub fn extract_request_info(req: &Request) -> RequestInfo;
pub fn get_or_create_trace_id(headers: &HeaderMap) -> String;
pub fn write_response(resp: Response, downstream: &mut Session);
pub fn write_json_error(status: StatusCode, message: &str) -> Response;
```

### `grpc_health`

gRPC health check protocol implementation.

```rust
impl GrpcHealthService {
    pub fn check(&self, service: &str) -> HealthCheckResponse;
    pub fn watch(&self, service: &str) -> Stream<HealthCheckResponse>;
}
```
