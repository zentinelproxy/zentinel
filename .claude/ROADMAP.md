# Sentinel Short-Term Roadmap

**Last Updated:** 2024-12-30
**Current Version:** 0.1.8
**Production Readiness:** 30-40%

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
- Rate limiting (single-instance)
- Hot configuration reload with validation
- Agent-based extension protocol (SPOE-inspired)
- Circuit breakers per upstream/agent
- Static file serving with compression

### Critical Gaps
- HTTPS/TLS is stubbed (warns and proceeds without encryption)
- HTTP caching disabled by default
- No WAF reference implementation
- No distributed rate limiting
- Metrics collected but not exposed
- No production load/soak testing

---

## Priority 1: Production Blockers

### 1.1 Complete HTTPS/TLS Implementation
**Status:** Stubbed
**Impact:** CRITICAL - Cannot deploy to production without TLS
**Effort:** 1-2 weeks

**Tasks:**
- [ ] Implement TLS listener in `main.rs` (currently warns and skips)
- [ ] Load certificates from PEM files via rustls
- [ ] Support SNI for multiple certificates
- [ ] Add certificate hot-reload on SIGHUP
- [ ] Implement mTLS for upstream connections
- [ ] Add OCSP stapling support
- [ ] Test with OpenSSL s_client and curl

**Files:**
- `crates/proxy/src/main.rs` - Listener setup
- `crates/config/src/listeners.rs` - TLS configuration
- `crates/proxy/src/proxy/mod.rs` - TLS context

### 1.2 Enable HTTP Caching
**Status:** Infrastructure exists, disabled by default
**Impact:** HIGH - 30-50% origin load reduction
**Effort:** 1-2 weeks

**Tasks:**
- [ ] Enable pingora-cache storage backend (MemCache)
- [ ] Wire `request_cache_filter()` to call `session.cache.enable()`
- [ ] Implement proper `CacheMeta` creation in `response_cache_filter()`
- [ ] Add cache storage configuration to KDL schema
- [ ] Implement cache invalidation API (PURGE method)
- [ ] Add cache statistics to metrics endpoint
- [ ] Test stale-while-revalidate and stale-if-error

**Files:**
- `crates/proxy/src/cache.rs` - Cache manager
- `crates/proxy/src/proxy/http_trait.rs` - Cache lifecycle methods
- `crates/config/src/routes.rs` - Per-route cache config

### 1.3 Expose Metrics Endpoint
**Status:** Metrics collected, not exposed
**Impact:** HIGH - Required for production monitoring
**Effort:** 2-3 days

**Tasks:**
- [ ] Add `/metrics` builtin handler route
- [ ] Expose Prometheus text format
- [ ] Add `/_/health` and `/_/ready` endpoints
- [ ] Document available metrics
- [ ] Add Grafana dashboard template

**Files:**
- `crates/proxy/src/builtin_handlers.rs` - Add metrics handler
- `crates/proxy/src/app.rs` - Wire metrics registry

### 1.4 Production Testing Suite
**Status:** 91 unit tests only
**Impact:** HIGH - Cannot validate production behavior
**Effort:** 2-3 weeks

**Tasks:**
- [ ] Load tests with wrk/k6 (target: 10K RPS, p99 < 10ms)
- [ ] Soak tests for memory leaks (24-72h runs)
- [ ] Chaos tests (agent crashes, upstream failures, network partitions)
- [ ] Concurrent reload tests (requests in-flight during config change)
- [ ] TLS certificate rotation tests
- [ ] Add CI/CD gates for performance regressions

**Files:**
- `tests/load/` - New directory for load test configs
- `tests/chaos/` - Chaos test scenarios
- `.github/workflows/` - CI integration

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
**Status:** Infrastructure exists, not enforced
**Impact:** MEDIUM - Required for WAF effectiveness
**Effort:** 1 week

**Tasks:**
- [ ] Implement body streaming to agents in `request_body_filter()`
- [ ] Enforce `max_body_bytes_inspected` limit
- [ ] Add content-type allowlist for inspection
- [ ] Implement decompression with ratio limits
- [ ] Add body buffering metrics

**Files:**
- `crates/proxy/src/proxy/http_trait.rs` - Body filter
- `crates/config/src/routes.rs` - Body inspection config

---

## Priority 3: Scalability

### 3.1 Distributed Rate Limiting
**Status:** Single-instance only
**Impact:** HIGH - Multi-instance deployments broken
**Effort:** 2-3 weeks

**Tasks:**
- [ ] Add Redis backend for rate limit state
- [ ] Implement sliding window algorithm with Redis
- [ ] Add Memcached as alternative backend
- [ ] Support rate limit synchronization across instances
- [ ] Add fallback to local rate limiting if backend unavailable
- [ ] Document distributed deployment patterns

**Files:**
- `crates/proxy/src/rate_limit.rs` - Add distributed backend
- `crates/config/src/rate_limit.rs` - Backend configuration

### 3.2 Service Discovery Integration
**Status:** Planned (DiscoveryConfig exists)
**Impact:** MEDIUM - Cloud-native deployment
**Effort:** 2-3 weeks

**Tasks:**
- [ ] Implement Consul service discovery
- [ ] Implement Kubernetes endpoint discovery
- [ ] Add DNS SRV record support
- [ ] Support health-aware backend selection
- [ ] Add discovery refresh intervals
- [ ] Document service mesh integration

**Files:**
- `crates/proxy/src/discovery.rs` - Extend existing module
- `crates/config/src/upstreams.rs` - Discovery configuration

---

## Priority 4: Observability

### 4.1 OpenTelemetry Integration
**Status:** tracing crate used, no OTLP export
**Impact:** MEDIUM - Distributed tracing
**Effort:** 1-2 weeks

**Tasks:**
- [ ] Add opentelemetry-otlp dependency
- [ ] Implement trace context propagation (W3C Trace Context)
- [ ] Add span creation for request lifecycle phases
- [ ] Export traces to Jaeger/Tempo/etc.
- [ ] Add trace sampling configuration
- [ ] Document tracing deployment

**Files:**
- `crates/proxy/src/trace_id.rs` - Extend with OTLP
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
**Status:** Hardcoded to 256 connections
**Impact:** MEDIUM - Performance tuning
**Effort:** 3-5 days

**Tasks:**
- [ ] Add `pool-size` to upstream KDL config
- [ ] Add per-upstream timeout overrides
- [ ] Add connection retry configuration
- [ ] Expose pool statistics in metrics

**Files:**
- `crates/config/src/upstreams.rs` - Pool config
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
