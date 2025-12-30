# Sentinel Short-Term Roadmap

**Last Updated:** 2024-12-30
**Current Version:** 0.1.8
**Production Readiness:** 70-75%

---

## Executive Summary

Sentinel is a well-architected reverse proxy built on Cloudflare's Pingora framework with excellent configuration discipline and "sleepable ops" design. However, several critical features remain incomplete for production deployment.

This roadmap outlines the path from current state to production-ready, prioritized by impact and dependencies.

---

## Current State Assessment

### What Works Well
- Core routing and upstream selection
- Load balancing (P2C, Consistent Hash, Round Robin)
- Active/passive health checking
- Rate limiting (local + Redis distributed)
- Hot configuration reload with validation
- Agent-based extension protocol (SPOE-inspired)
- Circuit breakers per upstream/agent
- Static file serving with compression
- Request body inspection for agents

### Critical Gaps
- ~~HTTPS/TLS is stubbed~~ → **DONE**: Basic TLS termination working
- ~~HTTP caching disabled by default~~ → **DONE**: Enabled for static routes
- ~~Metrics collected but not exposed~~ → **DONE**: /metrics endpoint available
- ~~No distributed rate limiting~~ → **DONE**: Redis backend with feature flag
- No WAF reference implementation
- No production load/soak testing

---

## Priority 1: Production Blockers

### 1.1 Complete HTTPS/TLS Implementation
**Status:** DONE - SNI and mTLS client auth implemented
**Impact:** CRITICAL - Cannot deploy to production without TLS
**Effort:** 1-2 weeks (remaining: cert hot-reload, OCSP)

**Tasks:**
- [x] Implement TLS listener in `main.rs` (uses Pingora's add_tls)
- [x] Load certificates from PEM files
- [x] Validate certificate files exist at startup
- [x] Support SNI for multiple certificates
- [x] Implement mTLS client certificate verification
- [ ] Add certificate hot-reload on SIGHUP
- [ ] Implement mTLS for upstream connections (client cert to backends)
- [ ] Add OCSP stapling support
- [ ] Test with OpenSSL s_client and curl

**Features Implemented:**
- SNI-based certificate selection with wildcard support
- mTLS client authentication (require client certs)
- KDL configuration for TLS with SNI blocks
- Certificate validation at startup

**KDL Configuration:**
```kdl
listener "https" {
    address "0.0.0.0:443"
    protocol "https"
    tls {
        cert-file "/etc/certs/default.crt"
        key-file "/etc/certs/default.key"
        ca-file "/etc/certs/ca.crt"  // For mTLS
        client-auth true

        sni {
            hostnames "example.com" "www.example.com"
            cert-file "/etc/certs/example.crt"
            key-file "/etc/certs/example.key"
        }
    }
}
```

**Files:**
- `crates/proxy/src/tls.rs` - SNI resolver and TLS configuration
- `crates/proxy/src/main.rs` - Listener setup
- `crates/config/src/server.rs` - TlsConfig, SniCertificate types
- `crates/config/src/kdl/server.rs` - KDL parsing for TLS

### 1.2 Enable HTTP Caching
**Status:** Core infrastructure implemented, enabled for static routes
**Impact:** HIGH - 30-50% origin load reduction
**Effort:** 1-2 weeks (remaining: cache config in KDL + PURGE API)

**Tasks:**
- [x] Enable pingora-cache storage backend (MemCache)
- [x] Wire `request_cache_filter()` to call `session.cache.enable()`
- [x] Implement proper `CacheMeta` creation in `response_cache_filter()`
- [x] Enable caching by default for static routes (1 hour TTL)
- [ ] Add cache storage configuration to KDL schema
- [ ] Implement cache invalidation API (PURGE method)
- [ ] Add cache statistics to metrics endpoint
- [ ] Test stale-while-revalidate and stale-if-error

**Files:**
- `crates/proxy/src/cache.rs` - Cache manager + static storage
- `crates/proxy/src/proxy/http_trait.rs` - Cache lifecycle methods
- `crates/config/src/routes.rs` - Per-route cache config

### 1.3 Expose Metrics Endpoint
**Status:** DONE - /metrics endpoint exposes Prometheus format
**Impact:** HIGH - Required for production monitoring
**Effort:** 2-3 days

**Tasks:**
- [x] Add `/metrics` builtin handler route
- [x] Expose Prometheus text format
- [x] Add `/_/health` and `/_/ready` endpoints
- [ ] Document available metrics
- [ ] Add Grafana dashboard template

**Files:**
- `crates/proxy/src/builtin_handlers.rs` - Add metrics handler
- `crates/proxy/src/app.rs` - Wire metrics registry

### 1.4 Production Testing Suite
**Status:** External repo exists (raskell-io/sentinel-bench)
**Impact:** HIGH - Cannot validate production behavior
**Effort:** 2-3 weeks (remaining: CI integration, performance investigation)

**Tasks:**
- [x] Load testing framework with oha/wrk/k6 (sentinel-bench repo)
- [x] Passthrough scenario benchmarks
- [x] Comparison against Envoy, HAProxy, Nginx
- [ ] **INVESTIGATE:** Sentinel ~5x slower than competition (10s p50 vs 1ms)
  - Possible causes: x86 emulation on ARM, logging overhead, connection pooling
- [ ] Soak tests for memory leaks (24-72h runs)
- [ ] Chaos tests (agent crashes, upstream failures, network partitions)
- [ ] Concurrent reload tests (requests in-flight during config change)
- [ ] TLS certificate rotation tests
- [ ] Add CI/CD gates for performance regressions

**Files:**
- `raskell-io/sentinel-bench` - External benchmarking repo
- `.github/workflows/` - CI integration (TODO)

---

## Priority 2: Security Hardening

### 2.1 WAF Agent Reference Implementation
**Status:** Protocol ready, no reference engine
**Impact:** HIGH - Security-first architecture incomplete
**Effort:** 3-4 weeks

**Tasks:**
- [ ] Create `sentinel-waf-agent` crate
- [ ] Integrate ModSecurity or compatible CRS engine
- [ ] Implement request header inspection
- [ ] Implement request body inspection (with size limits)
- [ ] Add OWASP CRS rule set support
- [ ] Create audit logging for WAF decisions
- [ ] Add rule exclusion/tuning workflow
- [ ] Document WAF deployment patterns

**Files:**
- `crates/waf-agent/` - New crate
- `examples/waf-config.kdl` - Example configuration

### 2.2 Request Body Inspection
**Status:** DONE - Core infrastructure implemented
**Impact:** MEDIUM - Required for WAF effectiveness
**Effort:** 1 week

**Tasks:**
- [x] Implement body streaming to agents in `request_body_filter()`
- [x] Enforce `max_body_bytes_inspected` limit (1MB default)
- [x] Add content-type allowlist for inspection
- [x] Buffer body chunks before sending to agents
- [x] Handle agent block decisions with proper error responses
- [x] Support fail-open/fail-closed modes per route
- [ ] Implement decompression with ratio limits
- [ ] Add body buffering metrics

**Files:**
- `crates/proxy/src/proxy/http_trait.rs` - Body filter implementation
- `crates/proxy/src/proxy/handlers.rs` - Body inspection setup
- `crates/proxy/src/proxy/context.rs` - Body inspection state
- `crates/config/src/waf.rs` - Body inspection config

---

## Priority 3: Scalability

### 3.1 Distributed Rate Limiting
**Status:** DONE - Redis backend implemented (requires feature flag)
**Impact:** HIGH - Multi-instance deployments enabled
**Effort:** 2-3 weeks (remaining: Memcached backend, documentation)

**Tasks:**
- [x] Add Redis backend for rate limit state
- [x] Implement sliding window algorithm with Redis (sorted sets)
- [ ] Add Memcached as alternative backend
- [x] Support rate limit synchronization across instances
- [x] Add fallback to local rate limiting if backend unavailable
- [ ] Document distributed deployment patterns

**Features:**
- Sliding window log algorithm using Redis sorted sets
- Automatic fallback to local rate limiting on Redis failure
- Configurable via KDL: `backend "redis"`, `redis-url`, `redis-prefix`, etc.
- Feature flag: `distributed-rate-limit`

**Files:**
- `crates/proxy/src/rate_limit.rs` - Distributed backend integration
- `crates/proxy/src/distributed_rate_limit.rs` - Redis rate limiter
- `crates/config/src/filters.rs` - Backend configuration

### 3.2 Service Discovery Integration
**Status:** DONE - Core implementations complete
**Impact:** MEDIUM - Cloud-native deployment
**Effort:** 2-3 weeks

**Tasks:**
- [x] Implement Static discovery (existing)
- [x] Implement DNS A/AAAA discovery (existing)
- [x] Implement Consul service discovery
- [x] Implement Kubernetes endpoint discovery (in-cluster)
- [x] Add DNS SRV record support (basic)
- [x] Add discovery refresh intervals
- [ ] Implement kubeconfig file parsing for K8s
- [ ] Add async HTTP client for HTTPS K8s API
- [ ] Document service mesh integration

**Features:**
- Static: Fixed list of backends
- DNS: Resolve A/AAAA records with configurable refresh
- Consul: HTTP API integration with health filtering
- Kubernetes: In-cluster endpoint discovery
- Caching with fallback on failure
- Configurable refresh intervals

**Files:**
- `crates/proxy/src/discovery.rs` - All discovery implementations
- `crates/proxy/src/lib.rs` - Exports ConsulDiscovery, KubernetesDiscovery

---

## Priority 4: Observability

### 4.1 OpenTelemetry Integration
**Status:** DONE - Core implementation complete
**Impact:** MEDIUM - Distributed tracing
**Effort:** 1-2 weeks

**Tasks:**
- [x] Add opentelemetry-otlp dependency (feature-gated)
- [x] Implement trace context propagation (W3C Trace Context)
- [x] Add span creation for request lifecycle phases
- [x] Export traces to Jaeger/Tempo/etc. via OTLP
- [x] Add trace sampling configuration
- [ ] Document tracing deployment

**Features:**
- W3C Trace Context header parsing (traceparent/tracestate)
- OTLP exporter to any OpenTelemetry-compatible backend
- Configurable sampling rates
- Feature flag: `opentelemetry`

**Files:**
- `crates/proxy/src/otel.rs` - OpenTelemetry integration
- `crates/config/src/observability.rs` - Tracing config

### 4.2 Enhanced Audit Logging
**Status:** Access logs only
**Impact:** MEDIUM - Security compliance
**Effort:** 1 week

**Tasks:**
- [ ] Add structured audit log format
- [ ] Log WAF decisions with rule IDs
- [ ] Log authentication events
- [ ] Log configuration changes
- [ ] Add log shipping configuration (syslog, Kafka)

**Files:**
- `crates/proxy/src/logging.rs` - Audit log implementation

---

## Priority 5: Configuration Enhancements

### 5.1 Per-Upstream Pool Configuration
**Status:** DONE - Fully configurable per upstream
**Impact:** MEDIUM - Performance tuning
**Effort:** 3-5 days

**Tasks:**
- [x] Add `connection-pool` block to upstream KDL config
- [x] Add per-upstream timeout overrides via `timeouts` block
- [x] Wire config values into Pingora peer options
- [x] Add `PoolConfigSnapshot` for metrics/debugging
- [x] Expose pool statistics via `UpstreamPool.stats()`

**KDL Configuration:**
```kdl
upstream "backend" {
    target "127.0.0.1:8080"
    connection-pool {
        max-connections 100
        max-idle 20
        idle-timeout 60
        max-lifetime 3600
    }
    timeouts {
        connect 10
        request 60
        read 30
        write 30
    }
}
```

**Files:**
- `crates/config/src/upstreams.rs` - Pool config
- `crates/config/src/kdl/upstreams.rs` - KDL parsing
- `crates/proxy/src/upstream/mod.rs` - Apply config

### 5.2 Configuration Schema Versioning
**Status:** No versioning
**Impact:** LOW - Breaking change protection
**Effort:** 1 week

**Tasks:**
- [ ] Add schema version field to config
- [ ] Implement version compatibility checks
- [ ] Add migration guide system
- [ ] Support config rollback on validation failure

---

## Milestone Timeline

| Milestone | Target | Deliverables |
|-----------|--------|--------------|
| **M1: Secure** | +2 weeks | HTTPS/TLS functional, metrics exposed |
| **M2: Cacheable** | +4 weeks | HTTP caching enabled, load tested |
| **M3: Protected** | +8 weeks | WAF agent reference, body inspection |
| **M4: Scalable** | +12 weeks | Distributed rate limiting, service discovery |
| **M5: Observable** | +14 weeks | OpenTelemetry, enhanced audit logging |

---

## Success Criteria

### For Production Deployment (M2)
- [ ] HTTPS/TLS working with certificate rotation
- [ ] HTTP caching reducing origin load by 30%+
- [ ] Metrics endpoint scraped by Prometheus
- [ ] Load test: 10K RPS with p99 < 10ms
- [ ] Soak test: 24h with no memory growth
- [ ] Zero-downtime config reload verified

### For Security-First Deployment (M3)
- [ ] WAF agent blocking OWASP Top 10 attacks
- [ ] Request body inspection for SQL injection/XSS
- [ ] Audit logs capturing all security decisions
- [ ] CRS regression tests passing

### For Enterprise Deployment (M5)
- [ ] Multi-instance deployment with shared rate limits
- [ ] Service discovery with health-aware routing
- [ ] Distributed tracing with Jaeger/Tempo
- [ ] Grafana dashboards for all key metrics

---

## Technical Debt to Address

| Item | Severity | Notes |
|------|----------|-------|
| Global agent semaphore | Medium | Add per-agent queue isolation |
| Hardcoded pool sizes | Medium | Expose in configuration |
| Async pool shutdown | Low | Bound spawned tasks |
| gRPC health checks | Medium | Implement full protocol |
| Adaptive LB not wired | Medium | Integrate into request path |

---

## Out of Scope (Phase 5+)

These features are valuable but not required for initial production:

- HTTP/3 / QUIC support
- WebSocket proxying
- GraphQL-aware routing
- Multi-tenant configuration
- Control plane API
- WASM extension modules

---

## Contributing

When implementing roadmap items:

1. Create feature branch from `main`
2. Include tests for new functionality
3. Update documentation
4. Add metrics/logging for observability
5. Update this roadmap when complete

All changes must pass:
- `cargo test` - Unit tests
- `cargo clippy` - Linting
- `cargo fmt --check` - Formatting
- Load test baseline (when available)
