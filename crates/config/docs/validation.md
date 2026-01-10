# Validation & Defaults

This document describes configuration validation rules and default values.

## Validation Process

Configuration validation occurs in multiple stages:

1. **Parse-time validation**: Syntax and type checking
2. **Schema validation**: Required fields, value constraints
3. **Semantic validation**: Cross-references, logical consistency
4. **Runtime validation**: File existence, network addresses

## Schema Version Compatibility

```kdl
schema-version "1.0"
```

| Config Version | Binary Support | Behavior |
|----------------|----------------|----------|
| < min supported | Not loadable | Error |
| = current | Full support | Exact match |
| > current | Loadable | Warning (may lack features) |

Current version: `1.0`
Minimum supported: `1.0`

## Validation Rules

### Server

| Property | Validation |
|----------|------------|
| `worker-threads` | `>= 0` (0 = auto-detect) |
| `max-connections` | `> 0` |
| `graceful-shutdown-timeout-secs` | `> 0` |
| `trace-id-format` | Must be `tinyflake` or `uuid` |

### Listeners

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `address` | Valid socket address (host:port) |
| `protocol` | Must be `http`, `https`, `h2`, or `h3` |
| `tls` | Required when protocol is `https` |
| `request-timeout-secs` | `> 0` |

**At least one listener is required.**

### Routes

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `matches` | At least one match condition |
| `upstream` | Must reference existing upstream (unless builtin/static) |
| `filters` | All filter IDs must exist |
| `builtin-handler` | Required when `service-type` is `builtin` |
| `static-files.root` | Required when `service-type` is `static` |

### Upstreams

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `targets` | At least one target required |
| `targets[].address` | Valid host:port format |
| `targets[].weight` | `> 0` |
| `health-check.interval-secs` | `> 0` |
| `health-check.timeout-secs` | `> 0`, `< interval-secs` |

### Filters

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `type` | Valid filter type |
| `rate-limit.max-rps` | `> 0` |
| `compress.algorithms` | At least one algorithm |
| `geo.database-path` | Non-empty |
| `geo.countries` | Valid ISO 3166-1 alpha-2 codes |
| `agent.agent` | Must reference existing agent |

### Agents

| Property | Validation |
|----------|------------|
| `id` | Non-empty, unique |
| `timeout-ms` | `> 0` |
| `transport.unix-socket` | Parent directory must exist |
| `transport.grpc.address` | Valid address format |
| `events` | At least one event |

### WAF

| Property | Validation |
|----------|------------|
| `engine` | Must be `modsecurity`, `coraza`, or `custom` |
| `mode` | Must be `off`, `detection`, or `prevention` |
| `ruleset.paranoia-level` | `1-4` |
| `body-inspection.max-decompression-ratio` | `> 0` |

### Observability

| Property | Validation |
|----------|------------|
| `metrics.address` | Valid socket address |
| `tracing.sampling-rate` | `0.0-1.0` |
| `logging.level` | Valid log level |

### Limits

| Property | Validation |
|----------|------------|
| `max-header-size-bytes` | `> 0` |
| `max-header-count` | `> 0` |
| `max-body-size-bytes` | `> 0` |

## Reference Integrity

The validator ensures all cross-references are valid:

```
Route → Upstream      ✓ Upstream must exist
Route → Filter        ✓ Filter must exist
Filter → Agent        ✓ Agent must exist
Listener → Route      ✓ Default route must exist
```

Invalid references produce clear error messages:

```
Configuration validation failed:
  Route 'api' references non-existent upstream 'backend'
```

## Default Values

### Server Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `worker-threads` | `0` | Auto-detect CPU cores for optimal performance |
| `max-connections` | `10000` | Reasonable for most deployments |
| `graceful-shutdown-timeout-secs` | `30` | Allow in-flight requests to complete |
| `daemon` | `false` | Prefer systemd/container orchestration |
| `trace-id-format` | `tinyflake` | Compact, operator-friendly IDs |
| `auto-reload` | `false` | Explicit reload preferred in production |

### Listener Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `request-timeout-secs` | `60` | Standard HTTP timeout |
| `keepalive-timeout-secs` | `75` | Slightly longer than typical client |
| `max-concurrent-streams` | `100` | Reasonable HTTP/2 limit |

### TLS Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `min-version` | `tls1.2` | Security baseline |
| `client-auth` | `false` | mTLS opt-in |
| `ocsp-stapling` | `true` | Better client experience |
| `session-resumption` | `true` | Performance optimization |

### Route Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `priority` | `normal` | Standard priority |
| `service-type` | `web` | Traditional web proxy |
| `failure-mode` | `closed` | Security-first (fail-closed) |
| `waf-enabled` | `false` | WAF opt-in |
| `websocket` | `false` | WebSocket opt-in |

### Upstream Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `load-balancing` | `round-robin` | Simple, fair distribution |
| `targets[].weight` | `1` | Equal weight by default |
| `connection-pool.max-connections` | `100` | Reasonable pool size |
| `connection-pool.max-idle` | `20` | Balance memory vs latency |
| `connection-pool.idle-timeout-secs` | `60` | Reclaim idle connections |
| `timeouts.connect-secs` | `10` | Reasonable connect timeout |
| `timeouts.request-secs` | `60` | Standard request timeout |
| `timeouts.read-secs` | `30` | Balance responsiveness |
| `timeouts.write-secs` | `30` | Balance responsiveness |

### Health Check Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `interval-secs` | `10` | Balance responsiveness vs overhead |
| `timeout-secs` | `5` | Quick failure detection |
| `healthy-threshold` | `2` | Require consistent health |
| `unhealthy-threshold` | `3` | Tolerate transient failures |

### Filter Defaults

#### rate-limit

| Property | Default | Rationale |
|----------|---------|-----------|
| `burst` | `10` | Allow small bursts |
| `key` | `client-ip` | Per-client limiting |
| `on-limit` | `reject` | Clear feedback to client |
| `status-code` | `429` | Standard rate limit status |
| `backend` | `local` | Simple single-instance |

#### compress

| Property | Default | Rationale |
|----------|---------|-----------|
| `algorithms` | `["gzip", "brotli"]` | Wide client support |
| `min-size` | `1024` | Don't compress tiny responses |
| `level` | `6` | Balance ratio vs CPU |

#### cors

| Property | Default | Rationale |
|----------|---------|-----------|
| `allowed-origins` | `["*"]` | Permissive default |
| `allow-credentials` | `false` | Security default |
| `max-age-secs` | `86400` | Cache preflight 24h |

#### geo

| Property | Default | Rationale |
|----------|---------|-----------|
| `action` | `block` | Blocklist mode |
| `on-failure` | `open` | Fail-open on lookup error |
| `status-code` | `403` | Standard forbidden |
| `cache-ttl-secs` | `3600` | Cache lookups 1h |

### Agent Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `timeout-ms` | `1000` | 1 second timeout |
| `failure-mode` | `closed` | Security-first |
| `request-body-mode` | `buffer` | Simpler agent implementation |
| `chunk-timeout-ms` | `5000` | Per-chunk timeout |
| `max-concurrent-calls` | `100` | Prevent agent overload |

### WAF Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `mode` | `prevention` | Active blocking |
| `audit-log` | `true` | Security visibility |
| `ruleset.paranoia-level` | `1` | Low false positives |
| `ruleset.anomaly-threshold` | `5` | Standard CRS threshold |
| `body-inspection.inspect-request-body` | `true` | Inspect requests |
| `body-inspection.inspect-response-body` | `false` | Response inspection opt-in |
| `body-inspection.max-inspection-bytes` | `1048576` | 1MB inspection limit |

### Observability Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `metrics.enabled` | `true` | Observability by default |
| `metrics.address` | `0.0.0.0:9090` | Standard metrics port |
| `metrics.path` | `/metrics` | Standard Prometheus path |
| `logging.level` | `info` | Balanced verbosity |
| `logging.format` | `json` | Structured logging |
| `tracing.sampling-rate` | `0.01` | 1% sampling |
| `access-log.sample-rate` | `1.0` | Log all requests |

### Limits Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `max-header-size-bytes` | `8192` | 8KB header limit |
| `max-header-count` | `100` | Reasonable header count |
| `max-body-size-bytes` | `1048576` | 1MB body limit |
| `max-connections-per-client` | `100` | Per-client limit |

### Cache Defaults

| Property | Default | Rationale |
|----------|---------|-----------|
| `enabled` | `true` | Caching when configured |
| `backend` | `memory` | Simple in-memory cache |
| `max-size-bytes` | `104857600` | 100MB cache |
| `lock-timeout-secs` | `10` | Prevent thundering herd |
| `disk-shards` | `16` | Concurrent disk access |

## Security Defaults

Sentinel follows a **security-first** design philosophy:

| Setting | Default | Security Impact |
|---------|---------|-----------------|
| `failure-mode` | `closed` | Block on failure (not fail-open) |
| `tls.min-version` | `tls1.2` | No legacy TLS |
| `waf-enabled` | `false` | WAF must be explicitly enabled |
| `agent.timeout-ms` | `1000` | Bounded agent calls |
| `limits.*` | Bounded | Prevent resource exhaustion |

## Validation Error Messages

Error messages include context for debugging:

```
Configuration validation failed:

  Route 'api' references non-existent upstream 'backend'

  Available upstreams: ["web-backend", "api-backend"]
```

```
Configuration validation failed:

  Filter 'auth' references non-existent agent 'auth-agent'

  Available agents: ["waf-agent"]
```

```
KDL configuration parse error:

  Expected closing brace

  --> at line 15, column 1
   14 | upstream "backend" {
   15 |     target "127.0.0.1:3000"
      | ^ expected '}'
   16 | }
```

## Dry-Run Validation

Validate configuration without starting the proxy:

```bash
sentinel --config sentinel.kdl --validate
```

Or programmatically:

```rust
let config = Config::from_file("sentinel.kdl")?;
config.validate()?;
println!("Configuration is valid");
```
