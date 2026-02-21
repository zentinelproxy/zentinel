# Configuration Schema Reference

Complete reference for all Zentinel configuration options.

## Table of Contents

- [Server](#server)
- [Listeners](#listeners)
  - [ACME](#acmeconfig)
  - [DNS Provider](#dnsproviderconfig)
- [Routes](#routes)
- [Upstreams](#upstreams)
- [Filters](#filters)
- [Agents](#agents)
- [WAF](#waf)
- [Observability](#observability)
- [Limits](#limits)
- [Cache](#cache)

---

## Server

Global server configuration.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `worker-threads` | `u32` | `0` | Number of worker threads (0 = auto-detect CPU cores) |
| `max-connections` | `u32` | `10000` | Maximum total connections |
| `graceful-shutdown-timeout-secs` | `u64` | `30` | Graceful shutdown timeout in seconds |
| `daemon` | `bool` | `false` | Run as daemon |
| `pid-file` | `string` | - | Path to PID file |
| `user` | `string` | - | User to switch to after binding |
| `group` | `string` | - | Group to switch to after binding |
| `working-directory` | `string` | - | Working directory |
| `trace-id-format` | `string` | `"tinyflake"` | Trace ID format (`tinyflake` or `uuid`) |
| `auto-reload` | `bool` | `false` | Auto-reload config on file changes |

---

## Listeners

Port binding configuration.

### ListenerConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique listener identifier |
| `address` | `string` | **required** | Socket address (e.g., `0.0.0.0:8080`) |
| `protocol` | `string` | **required** | Protocol: `http`, `https`, `h2`, `h3` |
| `tls` | `TlsConfig` | - | TLS configuration (required for https) |
| `default-route` | `string` | - | Default route if no match |
| `request-timeout-secs` | `u64` | `60` | Request timeout |
| `keepalive-timeout-secs` | `u64` | `75` | Keep-alive timeout |
| `max-concurrent-streams` | `u32` | `100` | Max concurrent HTTP/2 streams |

### TlsConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `cert-file` | `string` | **required** | Certificate file path |
| `key-file` | `string` | **required** | Private key file path |
| `ca-file` | `string` | - | CA certificate for client verification |
| `min-version` | `string` | `"tls1.2"` | Minimum TLS version |
| `max-version` | `string` | - | Maximum TLS version |
| `cipher-suites` | `[string]` | `[]` | Cipher suites (empty = defaults) |
| `client-auth` | `bool` | `false` | Require client certificates (mTLS) |
| `ocsp-stapling` | `bool` | `true` | Enable OCSP stapling |
| `session-resumption` | `bool` | `true` | Enable session resumption |
| `additional-certs` | `[SniCertificate]` | `[]` | Additional certs for SNI |
| `acme` | `AcmeConfig` | - | ACME automatic certificate management |

### AcmeConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `email` | `string` | **required** | Contact email for Let's Encrypt account |
| `domains` | `[string]` | **required** | Domains to include in certificate |
| `staging` | `bool` | `false` | Use Let's Encrypt staging environment |
| `storage` | `string` | `/var/lib/zentinel/acme` | Certificate storage directory |
| `renew-before-days` | `u32` | `30` | Days before expiry to trigger renewal |
| `challenge-type` | `string` | `"http-01"` | Challenge type: `http-01` or `dns-01` |
| `dns-provider` | `DnsProviderConfig` | - | DNS provider (required for dns-01) |

### DnsProviderConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `type` | `string` | **required** | Provider: `hetzner`, `webhook` |
| `credentials-file` | `string` | - | Path to credentials file |
| `credentials-env` | `string` | - | Environment variable with credentials |
| `api-timeout-secs` | `u64` | `30` | API request timeout |
| `url` | `string` | - | Webhook URL (for webhook provider) |
| `auth-header` | `string` | - | Auth header name (for webhook provider) |
| `propagation` | `PropagationConfig` | `{}` | Propagation check settings |

### PropagationConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `initial-delay-secs` | `u64` | `10` | Wait before first propagation check |
| `check-interval-secs` | `u64` | `5` | Interval between checks |
| `timeout-secs` | `u64` | `120` | Max time to wait for propagation |
| `nameservers` | `[string]` | `[]` | DNS servers to query (empty = public DNS) |

### ListenerProtocol

| Value | Description |
|-------|-------------|
| `http` | HTTP/1.1 |
| `https` | HTTP/1.1 with TLS |
| `h2` | HTTP/2 |
| `h3` | HTTP/3 (QUIC) |

---

## Routes

Request routing configuration.

### RouteConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique route identifier |
| `priority` | `string` | `"normal"` | Priority: `low`, `normal`, `high`, `critical` |
| `matches` | `[MatchCondition]` | **required** | Match conditions |
| `upstream` | `string` | - | Target upstream ID |
| `service-type` | `string` | `"web"` | Service type |
| `policies` | `RoutePolicies` | `{}` | Route policies |
| `filters` | `[string]` | `[]` | Filter IDs to apply |
| `builtin-handler` | `string` | - | Built-in handler (for `builtin` service type) |
| `waf-enabled` | `bool` | `false` | Enable WAF for this route |
| `circuit-breaker` | `CircuitBreakerConfig` | - | Circuit breaker settings |
| `retry-policy` | `RetryPolicy` | - | Retry policy |
| `static-files` | `StaticFileConfig` | - | Static file config (for `static` type) |
| `api-schema` | `ApiSchemaConfig` | - | API schema validation |
| `inference` | `InferenceConfig` | - | Inference config (for `inference` type) |
| `error-pages` | `ErrorPageConfig` | - | Custom error pages |
| `websocket` | `bool` | `false` | Enable WebSocket upgrade |
| `websocket-inspection` | `bool` | `false` | Inspect WebSocket frames |
| `shadow` | `ShadowConfig` | - | Traffic mirroring config |
| `fallback` | `FallbackConfig` | - | Fallback routing config |

### MatchCondition

| Type | Example | Description |
|------|---------|-------------|
| `path-prefix` | `"/api"` | Match path prefix |
| `path` | `"/health"` | Match exact path |
| `path-regex` | `"^/users/\\d+$"` | Match path regex |
| `host` | `"api.example.com"` | Match Host header |
| `header` | `name="X-Api-Key"` | Match header presence/value |
| `method` | `["GET", "POST"]` | Match HTTP methods |
| `query-param` | `name="version"` | Match query parameter |

### ServiceType

| Value | Description |
|-------|-------------|
| `web` | Traditional web service (default) |
| `api` | REST API with JSON responses |
| `static` | Static file hosting |
| `builtin` | Built-in handler |
| `inference` | LLM/AI inference endpoint |

### BuiltinHandler

| Value | Description |
|-------|-------------|
| `status` | JSON status page |
| `health` | Health check endpoint |
| `metrics` | Prometheus metrics |
| `not-found` | 404 handler |
| `config` | Config dump (admin) |
| `upstreams` | Upstream health (admin) |
| `cache-purge` | Cache purge (admin) |
| `cache-stats` | Cache statistics (admin) |

### RoutePolicies

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `request-headers` | `HeaderModifications` | `{}` | Request header modifications |
| `response-headers` | `HeaderModifications` | `{}` | Response header modifications |
| `timeout-secs` | `u64` | - | Request timeout override |
| `max-body-size` | `string` | - | Body size limit (e.g., `"10MB"`) |
| `rate-limit` | `RateLimitPolicy` | - | Rate limit policy |
| `failure-mode` | `string` | `"closed"` | Failure mode: `open` or `closed` |
| `buffer-requests` | `bool` | `false` | Buffer request body |
| `buffer-responses` | `bool` | `false` | Buffer response body |
| `cache` | `RouteCacheConfig` | - | HTTP caching config |

### InferenceConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `provider` | `string` | `"generic"` | Provider: `generic`, `openai`, `anthropic` |
| `model-header` | `string` | - | Header containing model name |
| `rate-limit` | `TokenRateLimit` | - | Token-based rate limiting |
| `budget` | `TokenBudgetConfig` | - | Token budget tracking |
| `cost-attribution` | `CostAttributionConfig` | - | Per-model pricing |
| `routing` | `InferenceRouting` | - | Inference-aware routing |
| `model-routing` | `ModelRoutingConfig` | - | Model-based upstream routing |
| `guardrails` | `GuardrailsConfig` | - | Semantic guardrails |

### TokenRateLimit

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `tokens-per-minute` | `u64` | **required** | Max tokens per minute |
| `requests-per-minute` | `u64` | - | Max requests per minute |
| `burst-tokens` | `u64` | `10000` | Burst token allowance |
| `estimation-method` | `string` | `"chars"` | Token estimation: `chars`, `words`, `tiktoken` |

### GuardrailsConfig

| Property | Type | Description |
|----------|------|-------------|
| `prompt-injection` | `PromptInjectionConfig` | Prompt injection detection |
| `pii-detection` | `PiiDetectionConfig` | PII detection |

### FallbackConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `upstreams` | `[FallbackUpstream]` | `[]` | Ordered fallback upstreams |
| `triggers` | `FallbackTriggers` | `{}` | Conditions that trigger fallback |
| `max-attempts` | `u32` | `3` | Max fallback attempts |

---

## Upstreams

Backend server pool configuration.

### UpstreamConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique upstream identifier |
| `targets` | `[UpstreamTarget]` | **required** | Backend targets |
| `load-balancing` | `string` | `"round-robin"` | Load balancing algorithm |
| `health-check` | `HealthCheck` | - | Health check configuration |
| `connection-pool` | `ConnectionPoolConfig` | `{}` | Connection pool settings |
| `timeouts` | `UpstreamTimeouts` | `{}` | Timeout settings |
| `tls` | `UpstreamTlsConfig` | - | TLS configuration |
| `http-version` | `HttpVersionConfig` | `{}` | HTTP version settings |

### UpstreamTarget

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `address` | `string` | **required** | Target address (host:port) |
| `weight` | `u32` | `1` | Weight for load balancing |
| `max-requests` | `u32` | - | Max concurrent requests |
| `metadata` | `map` | `{}` | Target metadata |

### LoadBalancingAlgorithm

| Value | Description |
|-------|-------------|
| `round-robin` | Round-robin (default) |
| `weighted-round-robin` | Weighted round-robin |
| `random` | Random selection |
| `least-connections` | Least connections |
| `ip-hash` | Client IP hash |

### HealthCheck

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `type` | `string` | **required** | Check type: `tcp`, `http`, `https`, `grpc`, `inference` |
| `path` | `string` | - | HTTP path (for http/https) |
| `interval-secs` | `u64` | `10` | Check interval |
| `timeout-secs` | `u64` | `5` | Check timeout |
| `healthy-threshold` | `u32` | `2` | Successes to mark healthy |
| `unhealthy-threshold` | `u32` | `3` | Failures to mark unhealthy |

### ConnectionPoolConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-connections` | `u32` | `100` | Max connections per target |
| `max-idle` | `u32` | `20` | Max idle connections |
| `idle-timeout-secs` | `u64` | `60` | Idle connection timeout |
| `max-lifetime-secs` | `u64` | - | Max connection lifetime |

### UpstreamTimeouts

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `connect-secs` | `u64` | `10` | Connection timeout |
| `request-secs` | `u64` | `60` | Request timeout |
| `read-secs` | `u64` | `30` | Read timeout |
| `write-secs` | `u64` | `30` | Write timeout |

---

## Filters

Reusable filter definitions.

### FilterConfig

| Property | Type | Description |
|----------|------|-------------|
| `id` | `string` | Unique filter identifier |
| `type` | `string` | Filter type |
| *...* | *varies* | Type-specific properties |

### Filter Types

#### rate-limit

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-rps` | `u32` | **required** | Max requests per second |
| `burst` | `u32` | `10` | Burst size |
| `key` | `string` | `"client-ip"` | Rate limit key |
| `on-limit` | `string` | `"reject"` | Action: `reject`, `delay`, `log-only` |
| `status-code` | `u16` | `429` | Response status when limited |
| `backend` | `string` | `"local"` | Storage: `local`, `redis`, `memcached` |

#### headers

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `phase` | `string` | `"request"` | Phase: `request`, `response`, `both` |
| `set` | `map` | `{}` | Headers to set |
| `add` | `map` | `{}` | Headers to add |
| `remove` | `[string]` | `[]` | Headers to remove |

#### compress

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `algorithms` | `[string]` | `["gzip", "brotli"]` | Compression algorithms |
| `min-size` | `u32` | `1024` | Minimum size to compress |
| `content-types` | `[string]` | *text types* | MIME types to compress |
| `level` | `u8` | `6` | Compression level (1-9) |

#### cors

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `allowed-origins` | `[string]` | `["*"]` | Allowed origins |
| `allowed-methods` | `[string]` | *all methods* | Allowed methods |
| `allowed-headers` | `[string]` | `[]` | Allowed headers |
| `exposed-headers` | `[string]` | `[]` | Exposed headers |
| `allow-credentials` | `bool` | `false` | Allow credentials |
| `max-age-secs` | `u64` | `86400` | Preflight cache time |

#### geo

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `database-path` | `string` | **required** | Path to GeoIP database |
| `database-type` | `string` | - | Database type: `maxmind`, `ip2location` |
| `action` | `string` | `"block"` | Action: `block`, `allow`, `log-only` |
| `countries` | `[string]` | `[]` | ISO country codes |
| `on-failure` | `string` | `"open"` | Failure mode: `open`, `closed` |
| `status-code` | `u16` | `403` | Block status code |
| `cache-ttl-secs` | `u64` | `3600` | Lookup cache TTL |

#### agent

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `agent` | `string` | **required** | Agent ID reference |
| `phase` | `string` | `"request"` | Execution phase |
| `timeout-ms` | `u64` | - | Timeout override |
| `failure-mode` | `string` | - | Failure mode override |
| `inspect-body` | `bool` | `false` | Inspect request body |

---

## Agents

External processing agent configuration.

### AgentConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique agent identifier |
| `type` | `string` | **required** | Agent type: `waf`, `auth`, `rate-limit`, `custom` |
| `transport` | `AgentTransport` | **required** | Transport configuration |
| `events` | `[string]` | **required** | Events to handle |
| `timeout-ms` | `u64` | `1000` | Call timeout |
| `failure-mode` | `string` | `"closed"` | Failure mode |
| `circuit-breaker` | `CircuitBreakerConfig` | - | Circuit breaker |
| `max-request-body-bytes` | `u64` | - | Max request body to send |
| `max-response-body-bytes` | `u64` | - | Max response body to send |
| `request-body-mode` | `string` | `"buffer"` | Body mode: `buffer`, `stream`, `hybrid` |
| `max-concurrent-calls` | `u32` | `100` | Max concurrent calls |

### AgentTransport

```kdl
// Unix socket
transport {
    unix-socket "/var/run/agent.sock"
}

// gRPC
transport {
    grpc {
        address "localhost:50051"
        tls { ... }
    }
}

// HTTP
transport {
    http {
        url "http://localhost:8080/agent"
        tls { ... }
    }
}
```

### AgentEvent

| Value | Description |
|-------|-------------|
| `request-headers` | Request headers received |
| `request-body` | Request body chunks |
| `response-headers` | Response headers received |
| `response-body` | Response body chunks |
| `log` | Request complete (logging) |
| `websocket-frame` | WebSocket frame received |

---

## WAF

Web Application Firewall configuration.

### WafConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `engine` | `string` | **required** | Engine: `modsecurity`, `coraza`, `custom` |
| `mode` | `string` | `"prevention"` | Mode: `off`, `detection`, `prevention` |
| `audit-log` | `bool` | `true` | Enable audit logging |
| `ruleset` | `WafRuleset` | **required** | Ruleset configuration |
| `body-inspection` | `BodyInspectionPolicy` | `{}` | Body inspection policy |

### WafRuleset

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `crs-version` | `string` | **required** | CRS version (e.g., `"4.0"`) |
| `custom-rules-dir` | `string` | - | Custom rules directory |
| `paranoia-level` | `u8` | `1` | Paranoia level (1-4) |
| `anomaly-threshold` | `u32` | `5` | Anomaly score threshold |
| `exclusions` | `[RuleExclusion]` | `[]` | Rule exclusions |

### BodyInspectionPolicy

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `inspect-request-body` | `bool` | `true` | Inspect request bodies |
| `inspect-response-body` | `bool` | `false` | Inspect response bodies |
| `max-inspection-bytes` | `u64` | `1048576` | Max bytes to inspect |
| `content-types` | `[string]` | *form/json/xml* | Content types to inspect |
| `decompress` | `bool` | `false` | Decompress for inspection |
| `max-decompression-ratio` | `f32` | `100.0` | Max decompression ratio |

---

## Observability

Metrics, logging, and tracing configuration.

### ObservabilityConfig

| Property | Type | Description |
|----------|------|-------------|
| `metrics` | `MetricsConfig` | Metrics configuration |
| `logging` | `LoggingConfig` | Logging configuration |
| `tracing` | `TracingConfig` | Distributed tracing |

### MetricsConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable metrics |
| `address` | `string` | `"0.0.0.0:9090"` | Metrics endpoint address |
| `path` | `string` | `"/metrics"` | Metrics path |
| `high-cardinality` | `bool` | `false` | Include high-cardinality metrics |

### LoggingConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `level` | `string` | `"info"` | Log level |
| `format` | `string` | `"json"` | Format: `json`, `pretty` |
| `timestamps` | `bool` | `true` | Include timestamps |
| `file` | `string` | - | Log file path |
| `access-log` | `AccessLogConfig` | - | Access log config |
| `error-log` | `ErrorLogConfig` | - | Error log config |
| `audit-log` | `AuditLogConfig` | - | Audit log config |

### AccessLogConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable access logging |
| `file` | `string` | `/var/log/zentinel/access.log` | Log file path |
| `format` | `string` | `"json"` | Log format |
| `sample-rate` | `f64` | `1.0` | Sampling rate (0.0-1.0) |
| `include-trace-id` | `bool` | `true` | Include trace ID |

### TracingConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `backend` | `TracingBackend` | **required** | Tracing backend |
| `sampling-rate` | `f64` | `0.01` | Sampling rate |
| `service-name` | `string` | `"zentinel"` | Service name |

### TracingBackend

| Type | Properties |
|------|------------|
| `jaeger` | `endpoint` |
| `zipkin` | `endpoint` |
| `otlp` | `endpoint` |

---

## Limits

Global resource limits.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-header-size-bytes` | `u64` | `8192` | Max header size |
| `max-header-count` | `u32` | `100` | Max number of headers |
| `max-body-size-bytes` | `u64` | `1048576` | Max request body size |
| `max-connections-per-client` | `u32` | `100` | Max connections per client IP |

---

## Cache

HTTP response caching configuration.

### CacheStorageConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable caching |
| `backend` | `string` | `"memory"` | Backend: `memory`, `disk`, `hybrid` |
| `max-size-bytes` | `u64` | `104857600` | Max cache size (100MB) |
| `eviction-limit-bytes` | `u64` | - | Eviction trigger threshold |
| `lock-timeout-secs` | `u64` | `10` | Cache lock timeout |
| `disk-path` | `string` | - | Disk cache path |
| `disk-shards` | `u32` | `16` | Number of disk shards |
| `disk-max-size` | `u64` | - | Disk tier max size (hybrid only) |
