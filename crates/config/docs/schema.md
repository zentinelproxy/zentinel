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
| `graceful-shutdown-timeout-secs` | `u64` | `30` | On SIGTERM/SIGINT, how long to wait for open connections to close before exiting (seconds). The process exits earlier once none are left. A second SIGTERM/SIGINT while it waits ends the process at once |
| `daemon` | `bool` | `false` | Run as daemon, as with `-d`. The configuration is checked before the fork, so a broken one fails in the foreground |
| `pid-file` | `string` | `/tmp/pingora.pid` | Path to the PID file a daemon writes (an existing one is renamed to `<pid-file>.old`) |
| `user` | `string` | - | User a daemon switches to once the configuration, TLS keys and log files are loaded, before listeners are bound. Ignored in the foreground |
| `group` | `string` | primary group of `user` | Group a daemon switches to, at the same point as `user`. Ignored in the foreground |
| `working-directory` | `string` | - | Working directory |
| `trace-id-format` | `string` | `"tinyflake"` | Trace ID format (`tinyflake` or `uuid`) |
| `auto-reload` | `bool` | `false` | Auto-reload config on file changes |
| `route-cache-size` | `u32` | `1000` | Max entries in the route-match cache (per route set); must be > 0. Evictions counted in `zentinel_route_cache_evictions_total` |

> **Hot reload caveat:** routes, upstreams, filters, and agents are applied by
> hot reload (SIGHUP / auto-reload). Listener bindings and `system` settings
> are **not** — the proxy logs a warning if they changed and keeps the running
> values until restart.

---

## Listeners

Port binding configuration.

### ListenerConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `id` | `string` | **required** | Unique listener identifier |
| `address` | `string` | **required** | Socket address (e.g., `0.0.0.0:8080`) |
| `protocol` | `string` | **required** | Protocol: `http`, `https`, `h2`, `h3`, `h2c` |
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
| `cipher-suite` | `string` (repeatable) | `[]` | Cipher suite, one node per suite (empty = defaults) |
| `client-auth` | `bool` | `false` | Require client certificates (mTLS) |
| `ocsp-stapling` | `bool` | `true` | Staple OCSP responses fetched from each certificate's AIA responder; `cert-file` must include the issuer |
| `session-resumption` | `bool` | `true` | Enable session resumption |
| `sni` | `SniCertificate` (repeatable) | `[]` | Additional certs for SNI, one block per cert |
| `acme` | `AcmeConfig` | - | ACME automatic certificate management |

> **Note:** `min-version`, `max-version`, `cipher-suite`, `client-auth`, and
> per-SNI certificate serving are parsed but not yet applied to the listener
> (issue #303); the listener currently uses the built-in intermediate TLS
> profile and serves the primary certificate to all clients. Unknown nodes
> inside `tls` and `sni` blocks are rejected at parse time.

### AcmeConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `email` | `string` | **required** | Contact email for ACME account |
| `domains` | `[string]` | **required** | Domains to include in certificate |
| `server-url` | `string` | - | Custom ACME directory URL (e.g., ZeroSSL) |
| `staging` | `bool` | `false` | Use Let's Encrypt staging environment |
| `eab` | `ExternalAccountBinding` | - | EAB credentials (required by some CAs) |
| `storage` | `string` | `/var/lib/zentinel/acme` | Certificate storage directory |
| `renew-before-days` | `u32` | `30` | Days before expiry to trigger renewal |
| `challenge-type` | `string` | `"http-01"` | Challenge type: `http-01` or `dns-01` |
| `key-type` | `string` | `"ecdsa-p256"` | Key type: `ecdsa-p256`, `ecdsa-p384` |
| `dns-provider` | `DnsProviderConfig` | - | DNS provider (required for dns-01) |

### ExternalAccountBinding

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `kid` | `string` | **required** | Key ID provided by the ACME CA |
| `hmac-key` | `string` | **required** | HMAC key (base64url-encoded) from the CA |

### DnsProviderConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `type` | `string` | **required** | Provider: `cloudflare`, `hetzner`, `webhook` |
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
| `http` | HTTP/1.1, cleartext |
| `https` | TLS, HTTP/2 or HTTP/1.1 negotiated with ALPN. Needs a `tls` block |
| `h2` | The same as `https`. Needs a `tls` block |
| `h3` | HTTP/3 (QUIC). Not implemented: rejected by validation |
| `h2c` | HTTP/2 over cleartext TCP with prior knowledge. No `tls` block; a client that does not open with the HTTP/2 preface within 10 s is refused (`505` if it sent something else) |

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

### RetryPolicy

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-attempts` | `u32` | `1` | Upstream peer selection attempts (initial attempt + retries) |

> **Only `max-attempts` is implemented.** It bounds how many times the proxy
> will pick a peer from the upstream pool when selection fails; it does not
> re-send a request that reached an upstream. `timeout-ms`, `backoff-base-ms`,
> `backoff-max-ms` and `retryable-status-codes` appeared in older examples but
> were never implemented, and are now rejected at parse time rather than
> silently ignored. Tracked in issue #279.

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
| `cache` | `RouteCacheConfig` | - | HTTP caching config (see [Cache](#routecacheconfig)) |

### RouteCacheConfig

Per-route cache configuration, nested under `policies.cache`.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable caching for this route |
| `default-ttl-secs` | `u64` | `300` | Default TTL in seconds |
| `max-size-bytes` | `u64` | - | Max cached response size |
| `cacheable-methods` | `[string]` | `["GET", "HEAD"]` | HTTP methods to cache |
| `cacheable-status-codes` | `[u16]` | `[200, 203, 204, 206, 300, 301]` | Status codes to cache |
| `stale-while-revalidate-secs` | `u64` | - | Serve stale while refreshing |
| `stale-if-error-secs` | `u64` | - | Serve stale on upstream error |
| `vary-headers` | `[string]` | `[]` | Headers to vary cache key by |
| `ignore-query-params` | `[string]` | `[]` | Query params to exclude from cache key |
| `exclude-extensions` | `[string]` | `[]` | File extensions to exclude from caching (without dot, e.g., `"php"`, `"html"`) |
| `exclude-paths` | `[string]` | `[]` | Path patterns to exclude from caching (glob: `*`, `**`, `?`) |
| `respect-cache-control` | `bool` | `true` | Honor upstream Cache-Control headers |
| `ignore-no-cache` | `bool` | `false` | Cache even if upstream returns no-cache |

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

### TokenBudgetConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `period` | `string` | `"daily"` | Budget period: `hourly`, `daily`, `monthly`, or seconds |
| `limit` | `u64` | **required** | Total tokens allowed in the period |
| `alert-thresholds` | `[f64]` | `[0.80, 0.90, 0.95]` | Usage fractions that fire alerts |
| `enforce` | `bool` | `true` | Block requests when exhausted |
| `rollover` | `bool` | `false` | Carry unused tokens into the next period |
| `burst-allowance` | `f64` | - | Soft-limit burst fraction above the limit |
| `max-tenants` | `usize` | `10000` | Max distinct tenants tracked in memory; expired tenants are evicted at the cap (see `zentinel_inference_budget_tenants` / `zentinel_inference_budget_tenant_evictions_total` metrics) |

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
| `targets` | `[UpstreamTarget]` | **required** unless `discovery` is set | Backend targets |
| `discovery` | `UpstreamDiscovery` | - | Service discovery source for targets |
| `load-balancing` | `string` | `"round-robin"` | Load balancing algorithm |
| `health-check` | `HealthCheck` | - | Health check configuration |
| `connection-pool` | `ConnectionPoolConfig` | `{}` | Connection pool settings |
| `timeouts` | `UpstreamTimeouts` | `{}` | Timeout settings |
| `tls` | `UpstreamTlsConfig` | - | TLS configuration |
| `http-version` | `HttpVersionConfig` | `{}` | HTTP version settings |
| `h2c` | `bool` | `#false` | HTTP/2 over cleartext TCP with prior knowledge. Only without `tls`; never falls back to HTTP/1.1 |

### HttpVersionConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `min-version` | `1` or `2` | `1` | Lowest HTTP version to use with the upstream |
| `max-version` | `1` or `2` | `2` | Highest HTTP version to use with the upstream |
| `h2-ping-interval` | `int` (seconds) | `0` (off) | HTTP/2 PING interval on idle connections |
| `max-h2-streams` | `int` | `100` | Concurrent streams per HTTP/2 connection |

With `tls`, HTTP/2 is negotiated with ALPN within this range. Without `tls`
there is no negotiation: the upstream is spoken to over HTTP/1.1, unless
`h2c #true` is set, which uses HTTP/2 only. A plain upstream with
`min-version 2` and no `h2c` is a configuration error, as is `h2c` together
with `tls`, `max-version 1` or `min-version 1`.

### UpstreamDiscovery

Written as `discovery "<kind>" { ... }`. Targets resolved from the source are
added to any statically configured `targets`, and re-resolved on the interval
below. Settings are checked against the named kind: a setting belonging to a
different kind is a configuration error, not an ignored key.

| Kind | Settings | Refresh |
|------|----------|---------|
| `static` | `backends` (one or more `host:port`) | never |
| `dns` | `hostname`, `port`, `refresh-interval` (`30`) | `refresh-interval` |
| `dns-srv` | `service`, `refresh-interval` (`30`) | `refresh-interval` |
| `consul` | `address`, `service`, `datacenter`, `only-passing` (`#true`), `tag`, `refresh-interval` (`30`) | `refresh-interval` |
| `kubernetes` | `namespace`, `service`, `port-name`, `kubeconfig`, `refresh-interval` (`30`) | `refresh-interval` |
| `file` | `path`, `watch-interval` (`5`) | `watch-interval` |

Intervals are in seconds and must be greater than zero.

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
| `max-keys` | `usize` | `100000` | Max distinct keys tracked in memory; idle keys are evicted at the cap (see `zentinel_rate_limit_keys` / `zentinel_rate_limit_key_evictions_total` metrics) |

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
| `algorithms` | `[string]` | `["gzip"]` | `gzip`, `zstd`, in order of preference: the first one the client accepts (q > 0) is used. `br` (`brotli`) is accepted but skipped with a warning: Pingora's Brotli encoder does not finish its stream. `deflate` is rejected. Also accepted comma-separated in one string. Does not transcode a response the upstream already encoded in a coding the client accepts |
| `min-size` | `u32` | `1024` | Minimum size to compress |
| `content-types` | `[string]` | `text/html`, `text/css`, `application/json`, `application/javascript` | MIME type prefixes to compress |
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
| `timeout-ms` | `u64` | - | Timeout override for every call this filter's agent gets on the route (request and response headers and bodies); can only shorten the agent's `timeout-ms` |
| `failure-mode` | `string` | - | What a failed call to the agent means on routes using the filter: `open` continues, `closed` refuses (503; on a response body, the response is aborted). Unset uses the route's `policies { failure-mode }`. Applies to every request and response path and to WebSocket frames |
| `inspect-body` | `bool` | - | `#false` sends this agent no request body on routes using the filter; unset or `#true` leaves it to the agent's `events` |
| `max-body-bytes` | `u64` | - | Lowers the agent's `max-request-body-bytes` for routes using the filter; cannot raise it |

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
| `timeout-ms` | `u64` | `1000` | Call timeout (must be > 0) |
| `connect-timeout-ms` | `u64` | `5000` | Longest a new connection waits for the agent to accept it and answer the handshake (must be > 0). An agent that does not answer is not used and is reconnected in the background; its filters follow their `failure-mode` |
| `failure-mode` | `string` | - | **Deprecated, no effect** (#586). A failed call follows the agent filter's `failure-mode`, else the route's `policies { failure-mode }`, on every path including WebSocket frames. Reported by `zentinel test`; will be removed in a later release |
| `circuit-breaker` | `CircuitBreakerConfig` | - | Circuit breaker |
| `max-request-body-bytes` | `u64` | `1048576` (1 MiB) | Max request body inspected by this agent. Larger bodies follow the filter's `failure-mode`: `closed` blocks with 413, `open` skips this agent with a warning and metric |
| `max-response-body-bytes` | `u64` | `1048576` (1 MiB) | Max response body inspected by this agent (same failure-mode semantics) |
| `request-body-mode` | `string` | `"buffer"` | How the request body is sent: `buffer` (whole, up to `max-inspection-bytes`), `stream` (each chunk as it arrives), `hybrid` / `hybrid:<bytes>` (buffer up to the threshold, default 64 KiB, then stream). One body goes to all of a route's body agents in one mode; when they disagree, `buffer` wins over `hybrid` (largest threshold) over `stream` |
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
| `inspect-request-body` | `bool` | `true` | Send request bodies to the route's agents that subscribe to `request_body`. `#false` keeps them from every agent. Without a `waf` block, request bodies go to those agents too, with the defaults below except `content-types` (every content type is sent) |
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

File logs are opt-in: a log is opened only when its block is present (and not
`enabled #false`). Each file is independent. An access or error log that cannot
be opened is reported at startup, naming the log and its path, and stays off
while the other logs keep working. A configured audit log that cannot be opened
stops startup, so a deployment never runs without the audit trail it asked for.

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

Global resource limits. These are the single-file names; a directory config also
accepts the older `-bytes` spellings (`max-header-size-bytes`, `max-body-size-bytes`),
which a single-file config ignores.

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `max-header-size` | `u64` | `8192` | Max header size |
| `max-header-count` | `u32` | `100` | Max number of headers |
| `max-body-size` | `u64` | `10485760` | Max request body size |
| `max-connections-per-client` | `u32` | `100` | Max connections per client IP |

---

## Cache

HTTP response caching configuration.

### CacheStorageConfig

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable caching |
| `backend` | `string` | `"memory"` | Backend: `memory`, `disk`, `hybrid` |
| `max-size` | `u64` | `104857600` | Max cache size in bytes (100MB); `max-size-bytes` is accepted as well |
| `eviction-limit` | `u64` | - | Eviction trigger threshold in bytes |
| `lock-timeout` | `u64` | `10` | Cache lock timeout in seconds; `lock-timeout-secs` is accepted as well |
| `disk-path` | `string` | - | Disk cache path |
| `disk-shards` | `u32` | `16` | Number of disk shards |
| `disk-max-size` | `u64` | - | Disk tier max size (hybrid only) |
