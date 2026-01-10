# Sentinel Agents Roadmap

This document tracks ideas for future Sentinel agents. Agents extend Sentinel's capabilities through the [Agent Protocol](https://sentinel.raskell.io/docs/agent-protocol/).

## Current Agents

| Agent | Status | Description |
|-------|--------|-------------|
| [Auth](https://sentinel.raskell.io/agents/auth/) | Stable | JWT, API key, OAuth authentication with RBAC |
| [Denylist](https://sentinel.raskell.io/agents/denylist/) | Stable | IP, UA, header, path, query blocking |
| [WAF](https://sentinel.raskell.io/agents/waf/) | Beta | Lightweight Rust-native attack detection |
| [ModSecurity](https://sentinel.raskell.io/agents/modsec/) | Beta | Full OWASP CRS with 800+ rules |
| [AI Gateway](https://sentinel.raskell.io/agents/ai-gateway/) | Beta | LLM guardrails (input/output) |
| [WebSocket Inspector](https://sentinel.raskell.io/agents/websocket-inspector/) | Beta | WebSocket frame security |
| [Lua](https://sentinel.raskell.io/agents/lua/) | Beta | Lua scripting |
| [JavaScript](https://sentinel.raskell.io/agents/js/) | Beta | JavaScript scripting (QuickJS) |
| [WebAssembly](https://sentinel.raskell.io/agents/wasm/) | Beta | High-performance Wasm modules |

---

## Planned Agents

### Priority 1: High Value

#### Bot Management
**Status:** Proposed
**Complexity:** High
**Value:** High

Advanced bot detection beyond simple User-Agent blocking.

**Features:**
- [ ] Device fingerprinting (TLS, HTTP/2, headers)
- [ ] Behavioral analysis (request timing, patterns)
- [ ] IP reputation integration
- [ ] Browser integrity checks
- [ ] CAPTCHA/challenge integration
- [ ] Bot score headers for downstream decisions
- [ ] Allow known good bots (Googlebot, etc.)

**Use Cases:**
- Credential stuffing prevention
- Scraping protection
- Inventory hoarding prevention
- Account takeover protection

---

#### GraphQL Security
**Status:** Proposed
**Complexity:** Medium
**Value:** High

GraphQL-specific security controls.

**Features:**
- [ ] Query depth limiting
- [ ] Query complexity analysis (cost calculation)
- [ ] Field-level authorization
- [ ] Introspection control (disable in production)
- [ ] Batch query limits
- [ ] Alias limits
- [ ] Persisted queries / allowlist mode
- [ ] N+1 detection

**Use Cases:**
- Prevent resource exhaustion from deep/complex queries
- Field-level access control
- Production hardening

---

#### Request/Response Transform
**Status:** Proposed
**Complexity:** Medium
**Value:** High

General-purpose request and response transformation.

**Features:**
- [ ] URL rewriting (path, query params)
- [ ] Header injection/removal/modification
- [ ] Body transformation (JSON path manipulation)
- [ ] Request/response cloning
- [ ] Conditional transforms (based on headers, paths)
- [ ] Template-based responses

**Use Cases:**
- API migration (legacy URL support)
- Backend normalization
- Header standardization
- API versioning support

---

#### Circuit Breaker
**Status:** Proposed
**Complexity:** Medium
**Value:** High

Resilience patterns for upstream protection.

**Features:**
- [ ] Failure threshold configuration
- [ ] Half-open state with gradual recovery
- [ ] Per-upstream circuit breakers
- [ ] Fallback responses (static or from cache)
- [ ] Health check integration
- [ ] Metrics and alerting hooks
- [ ] Slow call detection

**Use Cases:**
- Microservices resilience
- Graceful degradation
- Cascade failure prevention

---

### Priority 2: Observability

#### OpenTelemetry
**Status:** Proposed
**Complexity:** Medium
**Value:** High

Distributed tracing integration.

**Features:**
- [ ] Trace context propagation (W3C, B3)
- [ ] Span creation for proxy processing
- [ ] Custom span attributes from headers/claims
- [ ] Sampling configuration
- [ ] OTLP export (gRPC, HTTP)
- [ ] Baggage propagation

**Use Cases:**
- End-to-end request tracing
- Performance analysis
- Debugging distributed systems

---

#### Audit Logger
**Status:** Proposed
**Complexity:** Low
**Value:** Medium

Structured compliance-focused audit logging.

**Features:**
- [ ] Configurable log fields
- [ ] Multiple output formats (JSON, CEF, LEEF)
- [ ] Log shipping (file, syslog, HTTP, Kafka)
- [ ] PII redaction in logs
- [ ] Request/response body logging (configurable)
- [ ] Compliance templates (SOC2, HIPAA, PCI)

**Use Cases:**
- Security audit trails
- Compliance requirements
- Incident investigation

---

### Priority 3: Compliance & Data

#### Data Masking
**Status:** Proposed
**Complexity:** High
**Value:** Medium

PII protection and data minimization.

**Features:**
- [ ] Field-level tokenization
- [ ] Format-preserving encryption
- [ ] Regex-based detection and masking
- [ ] Header value masking
- [ ] Request body field masking
- [ ] Response body field masking
- [ ] Reversible vs irreversible masking

**Use Cases:**
- GDPR compliance
- PCI DSS (card data protection)
- Secure logging
- Data minimization

---

#### CORS
**Status:** Proposed
**Complexity:** Low
**Value:** Medium

> Note: Evaluate if this should be built-in to Sentinel core instead.

Dynamic CORS policy management.

**Features:**
- [ ] Origin allowlist/denylist
- [ ] Regex origin matching
- [ ] Per-route CORS configuration
- [ ] Credentials support
- [ ] Preflight caching
- [ ] Custom headers exposure

**Use Cases:**
- SPA/mobile API security
- Third-party integrations
- Development environments

---

### Priority 4: Protocol-Specific

#### gRPC Inspector
**Status:** Proposed
**Complexity:** High
**Value:** Medium

gRPC/Protocol Buffers security.

**Features:**
- [ ] Method-level authorization
- [ ] Message size limits
- [ ] Metadata inspection
- [ ] Rate limiting per method
- [ ] Schema validation
- [ ] Reflection control

**Use Cases:**
- gRPC API security
- Service mesh integration
- Internal API governance

---

#### MQTT Gateway
**Status:** Proposed
**Complexity:** High
**Value:** Low-Medium

IoT protocol security.

**Features:**
- [ ] Topic-based ACLs
- [ ] Payload inspection
- [ ] Client authentication
- [ ] Message rate limiting
- [ ] QoS enforcement
- [ ] Retained message control

**Use Cases:**
- IoT device management
- MQTT broker protection
- Industrial IoT security

---

### Priority 5: Developer Experience

#### Mock Server
**Status:** Proposed
**Complexity:** Low
**Value:** Low

Request matching and stub responses.

**Features:**
- [ ] Request matching (path, headers, body)
- [ ] Static response stubs
- [ ] Dynamic responses (templates)
- [ ] Latency simulation
- [ ] Failure injection
- [ ] Record and replay mode

**Use Cases:**
- API development/testing
- Integration testing
- Demo environments

---

#### API Deprecation
**Status:** Proposed
**Complexity:** Low
**Value:** Low

API lifecycle management.

**Features:**
- [ ] Deprecation warning headers
- [ ] Sunset date headers
- [ ] Usage tracking for deprecated endpoints
- [ ] Automatic redirects to new versions
- [ ] Migration documentation links
- [ ] Gradual traffic shifting

**Use Cases:**
- API versioning strategy
- Breaking change management
- Client migration tracking

---

## Rejected / Deferred Ideas

| Idea | Reason |
|------|--------|
| Rate Limiter Agent | Now built-in to Sentinel core |
| Load Balancer Agent | Built-in to Sentinel core |
| Cache Agent | Better suited as built-in feature |
| Service Discovery Agent | Integration via config, not agent |

---

## Contributing

Want to work on one of these agents?

1. Open an issue to discuss the design
2. Check the [Agent SDK documentation](https://sentinel.raskell.io/docs/agent-sdk/)
3. Review existing agents for patterns
4. Submit a PR with implementation and docs

See [CONTRIBUTING.md](./CONTRIBUTING.md) for general contribution guidelines.
