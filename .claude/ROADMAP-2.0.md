# Sentinel Roadmap 2.0

## Thesis

The reverse proxy is evolving from "traffic plumbing" to **runtime governance layer**. The winners will be proxies that:

1. **Explain themselves** — Config simulation and decision tracing become features, not docs
2. **Keep policy out of core** — Sandboxed/out-of-process extensibility (agents, WASM) over monolithic plugins
3. **Route multiple traffic types** — Web, API, and inference traffic demand different primitives

Sentinel is positioned for this shift: agent architecture, simulatable KDL config, and a small stable core.

---

## Phase 1: Foundation (Q1–Q2 2025) ✓

*Establish production readiness and core differentiators*

| Feature | Status | Notes |
|---------|--------|-------|
| Config schema versioning | ✓ | Forward/backward compat checking |
| Hot reload with rollback | ✓ | Graceful draining on error |
| Agent protocol v1 | ✓ | Phases, timeouts, failure modes |
| WAF agent integration | ✓ | OWASP CRS-grade via Coraza |
| Playground (WASM simulation) | ✓ | Config validation + request tracing |
| Observability baseline | ✓ | Prometheus, structured logs, OTLP |
| TLS termination + SNI | ✓ | Certificate hot-reload |

---

## Phase 2: Legibility & Governance (Q3–Q4 2025)

*Make Sentinel the most explainable proxy in the market*

### 2.1 Decision Tracing (Explain Mode)

**Goal**: Every request can answer "why did this happen?"

- [ ] **Request trace API** — Structured log of every decision point (route match, policy eval, agent calls, upstream selection)
- [ ] **Dry-run mode** — Simulate request against config without forwarding
- [ ] **Diff mode** — Compare behavior between two configs for same request
- [ ] **Playground v2** — Visual decision tree, not just text trace

### 2.2 Policy-as-Code Integration

**Goal**: Policy decisions are auditable, versionable, testable

- [ ] **OPA/Rego agent** — First-class Open Policy Agent integration
- [ ] **Policy testing framework** — Unit tests for routing/authz decisions
- [ ] **Audit log enrichment** — Policy decision context in every log line
- [ ] **Git-driven config** — Webhook triggers for config reload on push

### 2.3 Agent Protocol v2

**Goal**: Tighten the contract, enable richer interactions

- [ ] **Bidirectional streaming** — Agents can push config updates
- [ ] **Health reporting** — Agents report readiness/degradation
- [ ] **Capability negotiation** — Agents declare supported phases/features
- [ ] **WASM agent runtime** — In-process sandboxed agents via Wasmtime

---

## Phase 3: Multi-Traffic Routing (Q1–Q2 2026)

*Beyond HTTP: inference, gRPC, and protocol brokering*

### 3.1 Inference-Aware Routing

**Goal**: First-class support for LLM/AI inference traffic patterns

- [ ] **Token budget rate limiting** — Rate limit by estimated/actual tokens, not just requests
- [ ] **Model-aware load balancing** — Route based on model availability, queue depth, latency
- [ ] **Inference health checks** — Probe model readiness, not just HTTP 200
- [ ] **Request/response inspection** — Semantic guardrails via agents (PII, prompt injection)
- [ ] **Cost attribution** — Per-route/per-tenant token accounting

### 3.2 Protocol Brokering

**Goal**: Graceful translation between client and upstream protocols

- [ ] **HTTP/3 downstream** — Full QUIC support for clients
- [ ] **HTTP/1↔2↔3 translation** — Automatic protocol negotiation
- [ ] **gRPC-Web bridging** — Browser clients to gRPC backends
- [ ] **Protocol observability** — Metrics on negotiation, fallback, version mismatch

### 3.3 Gateway API Alignment

**Goal**: Portable configuration concepts for K8s and non-K8s

- [ ] **GatewayClass/Gateway/HTTPRoute mapping** — KDL equivalents
- [ ] **Policy attachment model** — Inherit/override semantics like Gateway API
- [ ] **Reference implementation** — Sentinel as Gateway API backend (optional)

---

## Phase 4: Identity-First Security (Q3–Q4 2026)

*From "inspect traffic" to "verify identity"*

### 4.1 Workload Identity

**Goal**: SPIFFE/SPIRE as first-class identity source

- [ ] **SPIFFE ID verification** — mTLS with SVID validation
- [ ] **SPIRE integration** — Automatic workload registration
- [ ] **Identity-based routing** — Route decisions based on caller identity
- [ ] **Identity propagation** — Forward verified identity to upstreams

### 4.2 ECH-Ready Architecture

**Goal**: Function in a world where SNI inspection is unavailable

- [ ] **ECH termination** — Decrypt ECH when we hold the keys
- [ ] **Identity-first routing** — Route without relying on SNI visibility
- [ ] **Attestation hooks** — Integrate with remote attestation (TPM, SGX)

### 4.3 Zero-Trust Patterns

**Goal**: Built-in patterns for zero-trust architectures

- [ ] **Per-request authZ** — Every request evaluated, no implicit trust
- [ ] **Continuous verification** — Re-evaluate during long-lived connections
- [ ] **Least-privilege defaults** — Deny-by-default, explicit allow

---

## Phase 5: Enterprise Hardening (2027)

*Supply chain, compliance, and operational maturity*

### 5.1 Supply Chain Security

- [ ] **SLSA Level 3 builds** — Reproducible, attested build pipeline
- [ ] **SBOM generation** — CycloneDX/SPDX for every release
- [ ] **Signed releases** — Sigstore/cosign signatures
- [ ] **Vulnerability scanning** — Automated CVE tracking in deps

### 5.2 Compliance Features

- [ ] **Audit log export** — S3, Kafka, SIEM integrations
- [ ] **Data residency controls** — Route based on geo/jurisdiction
- [ ] **Retention policies** — Configurable log/cache retention
- [ ] **Compliance profiles** — Pre-built configs for SOC2, HIPAA, PCI patterns

### 5.3 Operational Excellence

- [ ] **Canary deployments** — Traffic shifting for config changes
- [ ] **Circuit breaker improvements** — Adaptive thresholds, ML-assisted
- [ ] **Chaos testing hooks** — Built-in fault injection
- [ ] **Fleet management** — Multi-instance coordination (via Hub)

---

## Phase 6: Ecosystem (2028)

*From proxy to platform*

### 6.1 Agent Marketplace

- [ ] **Agent registry** — Curated, verified agents
- [ ] **Agent SDK** — Multi-language SDKs (Rust, Go, Python, JS)
- [ ] **Agent testing framework** — Simulate agent behavior without Sentinel

### 6.2 Developer Experience

- [ ] **IDE plugins** — KDL language server, IntelliSense
- [ ] **Local dev mode** — Lightweight Sentinel for development
- [ ] **Mocking framework** — Mock upstreams for testing

### 6.3 Managed Offering (Optional)

- [ ] **Sentinel Cloud** — Hosted control plane
- [ ] **Global edge network** — Distributed Sentinel instances
- [ ] **Usage-based billing** — Pay per request/GB

---

## Non-Goals

Things Sentinel will **not** become:

1. **Full service mesh** — We're a gateway, not a sidecar runtime
2. **CDN** — Edge caching yes, global PoP network no
3. **API management platform** — No portal, no developer signup flows
4. **Everything in core** — Agents handle domain-specific logic

---

## Success Metrics

By end of 2028, Sentinel should:

| Metric | Target |
|--------|--------|
| Config simulation coverage | 100% of routing decisions explainable |
| Agent ecosystem | 20+ production-ready agents |
| Protocol support | HTTP/1, HTTP/2, HTTP/3, gRPC, WebSocket |
| Identity systems | SPIFFE, OIDC, mTLS, API keys |
| Compliance certifications | SOC2 Type II attestation |
| Community | 5k+ GitHub stars, 50+ contributors |

---

## Versioning

| Version | Target | Theme |
|---------|--------|-------|
| v0.2 | Q1 2025 | Production Ready (current) |
| v0.3 | Q3 2025 | Explain Mode |
| v0.4 | Q1 2026 | Inference Routing |
| v1.0 | Q3 2026 | Identity-First |
| v1.1 | 2027 | Enterprise |
| v2.0 | 2028 | Platform |

---

## How to Contribute

Priority areas where contributions are especially welcome:

1. **Agent implementations** — Auth, rate limiting, transformation, observability
2. **Protocol work** — HTTP/3, gRPC, WebSocket improvements
3. **Documentation** — Tutorials, examples, translations
4. **Testing** — Chaos tests, performance benchmarks, fuzzing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
