# Sentinel — Pingora-based Production Reverse Proxy Platform

**Tagline:** A security-first reverse proxy built on Pingora. Sleepable ops at the edge.

---

## 0) Purpose of this document
This file is a single source of truth for LLM agents and humans implementing a production-grade reverse proxy *application* built on top of Cloudflare Pingora (library). We are not reinventing Pingora; we are building the **product layer**: configuration, policy, extensibility, WAF integration, operability, and safe defaults.

This document prioritizes: **sleepable operations**, **security-first design**, **extensibility**, and **high performance**.

---

## 1) North Star
Build a reverse proxy platform that we can run in production without 03:00 wake-ups, while staying modern and extensible:

- **Rust dataplane app** (Pingora) with strong safety, performance, and predictable behavior.
- **External processing/agent boundary** (SPOE/ext_proc-style) for WAF and custom logic to isolate complexity and failure.
- **Config-first** (declarative, validated, safe defaults) with hot reload and graceful draining.
- **Observability by default** (metrics/logs/traces), with tight operational controls.

---

## 2) Principles (non-negotiables)
### 2.1 Sleepable Ops
- Bounded memory and bounded queues everywhere.
- Deterministic timeouts everywhere.
- Graceful reload, draining, and robust rollback.
- Clear failure modes (fail-open/fail-closed configurable per route/policy).

### 2.2 Security-first
- Hardened defaults (TLS, headers, timeouts, limits).
- Isolation for untrusted/parsing-heavy components (WAF engines, script runtimes).
- No “magic” behavior; all security posture is explicit in config.

### 2.3 Extensibility without destabilizing the core
- The dataplane stays minimal and robust.
- Complex logic belongs in **agents** (out-of-process), behind a stable contract.

### 2.4 Production correctness beats feature breadth
- Ship small, correct, testable increments.
- Add features only if they pass load, soak, and regression gates.

---

## 3) Target Outcomes
### 3.1 Must-have outcomes
- Reverse proxy for HTTP services with TLS termination, routing, upstream load balancing, timeouts, retries, and health checks.
- A clean extension model via external agents to implement:
  - WAF (CRS-grade behavior),
  - auth/PEP flows,
  - bot/rate-limit/policy logic,
  - custom business/security logic.

### 3.2 “Nice” outcomes (later)
- HTTP/3 / QUIC (only if needed).
- Service discovery integrations.
- Multi-tenant policy plane, centralized governance.
- Advanced traffic shaping, canary and progressive delivery.

---

## 4) Non-goals (explicit)
- Reimplementing Pingora internals or creating a generic proxy framework.
- Full parity with HAProxy/Envoy/Nginx on day 1.
- Embedding a scripting runtime into the dataplane as the primary extension mechanism.
- Complex control-plane features before dataplane reliability is proven.

---

## 5) High-level Architecture
### 5.1 Components
1) **Dataplane Proxy (Pingora-based)**
   - Handles connections, TLS, routing, upstream pools, retries, timeouts.
   - Provides lifecycle hook points for policy decisions and request/response mutations.

2) **External Processor / Agent Interface (stable contract)**
   - A local transport (Unix domain sockets first).
   - Request/response lifecycle events + bounded body streaming support.
   - Agent replies with decisions + optional mutations + audit metadata.

3) **Agents (separate processes)**
   - WAF agent (CRS-grade engine)
   - Auth/PEP agent
   - Policy/rate-limit agent
   - Custom logic agent(s)

4) **Configuration + Policy**
   - Declarative config file(s) with schema validation.
   - Hot reload with rollback if invalid.
   - Versioning and auditability.

### 5.2 Extension Philosophy
- **Dataplane is boring**: stable, bounded, predictable.
- **Agents are where innovation lives**: WAF engines, scripting, ML scoring, etc.
- A broken agent must not crash the dataplane.

---

## 6) External Agent Contract (SPOE/ext_proc-inspired)
### 6.1 Transport
- Primary: Unix Domain Socket (UDS)
- Secondary (optional): gRPC over localhost / internal network

### 6.2 Event model (minimum)
- `on_request_headers(headers, metadata)`
- `on_request_body_chunk(chunk, is_last)` (optional, bounded)
- `on_response_headers(headers, metadata)` (optional)
- `on_response_body_chunk(chunk, is_last)` (optional)
- `on_log(final_metadata)` (optional)

### 6.3 Agent response model
- Decision: `ALLOW | BLOCK | REDIRECT | CHALLENGE (optional)`
- Mutations:
  - add/replace/remove headers (request and/or response)
  - set routing metadata (optional, constrained)
- Audit:
  - tags, rule IDs, confidence, reason codes
  - structured fields for logging/metrics

### 6.4 Timeouts & failure policy (per route)
- Each call has:
  - timeout (hard),
  - fallback action: fail-open/fail-closed,
  - circuit breaker (disable agent temporarily if unhealthy).

### 6.5 Body inspection policy (critical)
- Body inspection is **opt-in** per route.
- Must enforce:
  - max body bytes inspected,
  - max buffered bytes,
  - content-type allowlist for inspection,
  - decompression limits,
  - streaming semantics (do not buffer unbounded).

---

## 7) WAF Strategy
### 7.1 Requirement: CRS-grade behavior
The platform must support OWASP CRS-grade WAF behavior.
Implementation detail (engine) must be pluggable.

### 7.2 Default implementation approach
- **Out-of-process WAF agent** first.
- Engine options:
  - libmodsecurity (via agent)
  - alternative CRS-compatible engines (as a backend option)

### 7.3 Why agent-first
- Keeps C/C++ risk out of the Rust dataplane.
- Allows independent upgrades/rollbacks of WAF rules and engine.
- Makes timeouts/circuit breakers effective.

### 7.4 WAF operational requirements
- Audit log support (structured).
- Rule set versioning.
- Test suite gate (CRS regression).
- Clear tuning workflow (exceptions, exclusions, rule tagging).

---

## 8) “Prod without 03:00” Operational Requirements
### 8.1 Limits (hard)
- Header size limits
- Header count limits
- Body size limits (global + per route)
- Decompression ratio/size limits
- Max in-flight requests per worker
- Queue bounds for agent calls
- Connection limits per client / per route (optional)

### 8.2 Timeouts (hard)
- Connect timeout
- TLS handshake timeout
- Request header timeout
- Request body timeout
- Upstream response header/body timeouts
- Agent call timeouts (all events)

### 8.3 Resilience
- Health checks for upstreams + ejection
- Retry policy with strict caps
- Circuit breakers for upstream and agents
- Graceful restart and connection draining
- Safe degraded modes

### 8.4 Observability (first-class)
- Metrics:
  - latency histograms per route
  - status codes
  - upstream health / retries
  - agent latencies, timeouts, circuit-breaker opens
- Logs:
  - structured JSON logs
  - correlation IDs
  - WAF decision fields
- Tracing:
  - request spans, optional OTEL export

---

## 9) Configuration & UX
### 9.1 Config format
- Human-editable, diff-friendly (KDL is a strong default).
- Strict schema validation + informative errors.
- No ambiguous defaults; security defaults are explicit and documented.

### 9.2 Hot reload semantics
- Validate new config fully before apply.
- Apply atomically.
- Roll back on error.
- Provide dry-run validation mode.

### 9.3 Policy model (example concepts)
- listeners (ports, TLS, protocols)
- routes (match rules)
- upstream pools (health checks, LB strategy)
- policies (timeouts, retries, body limits, header rewrites)
- agents (which processors apply, per phase)
- waf (enabled, body inspection rules, engine backend)

---

## 10) Testing & Quality Gates
### 10.1 Minimum gates for production rollout
- Unit tests for config parsing & validation.
- Integration tests for routing, TLS, upstream failover.
- Agent protocol tests (fuzzed inputs).
- Load tests (p95/p99, memory ceiling).
- Soak tests (hours/days, leak detection).
- Replay harness for captured traffic (sanitized).
- CRS regression gate for WAF-enabled routes.

### 10.2 Security validation
- Fuzz critical parsers and protocol boundaries.
- Dependency audits and SBOM.
- Strict input validation across agent boundary.

---

## 11) Roadmap
### Phase 0 — Bootstrap (1–2 weeks equivalent)
Deliverables:
- Repo structure, build system, CI
- Basic Pingora-based proxy skeleton:
  - TLS termination
  - single upstream routing
  - structured logs
  - basic metrics endpoint

Exit criteria:
- Stable binary builds + basic e2e test passing.

### Phase 1 — Minimal Production Proxy (V1)
Deliverables:
- Config schema + validation + hot reload
- Route matching + upstream pools + health checks
- Timeouts, retries, limits (hard bounds)
- Graceful restart + draining
- Observability baseline (metrics/logs)

Exit criteria:
- Load + soak tests pass for baseline traffic profile.
- On-call playbook exists.

### Phase 2 — External Processing (Agents) Foundation
Deliverables:
- UDS-based agent protocol + SDK/client
- Per-route policy to attach agents to phases
- Timeouts + failure policies + circuit breaker for agents
- Reference agent “echo” + “denylist” agent

Exit criteria:
- Fault injection: agent crash/timeout does not crash dataplane.
- Deterministic fallback behavior verified.

### Phase 3 — WAF Integration (CRS-grade)
Deliverables:
- WAF agent running CRS-grade rule set
- Per-route WAF enablement + body policy controls
- Audit logging + tuning workflow
- CRS regression gate in CI

Exit criteria:
- WAF-enabled routes pass CRS regression and performance targets.
- Clear rollback path for rule updates.

### Phase 4 — Productization (Internal GA)
Deliverables:
- Packaging (container/systemd/runit/etc. as needed)
- Upgrade strategy + versioned config
- Dashboards + runbooks
- Blue/green or canary deployment docs
- SLOs and alerting guidelines

Exit criteria:
- Serving meaningful production traffic with stable SLOs.
- Zero-downtime reload verified in prod.

### Phase 5 — Competitive Features (Selective)
Pick only what we need:
- ~~Advanced LB algorithms~~ → **DONE** (14 algorithms: Maglev, Peak EWMA, Locality-Aware, Weighted Least Conn, Deterministic Subset, etc.)
- mTLS to upstreams
- HTTP/3 (if justified)
- Rate limiting/bot mitigation agent
- Auth/PEP agent patterns

Exit criteria:
- Each feature has tests + limits + observability + rollback.

---

## 12) Decisions to lock early (avoid thrash)
- Config format + schema toolchain
- Agent protocol (message encoding, versioning)
- Default fail-open/closed posture per environment
- Which “first-party” agents ship in-tree vs separate repos
- Release cadence and compatibility guarantees

---

## 13) Risk Register (known hard problems)
- Request/response body streaming vs WAF inspection
- Preventing memory blow-ups under upload traffic
- Agent overload cascading into dataplane latency
- CRS false positives and tuning workflow
- Operational complexity creeping into the core

Mitigations:
- Hard limits + opt-in body inspection
- Agent circuit breakers and bulkheads
- Replay-based testing, progressive rollout

---

## 14) Work Instructions for LLM Agents
When implementing anything, follow these rules:
1) Never add features without:
   - explicit limits,
   - explicit timeouts,
   - explicit observability,
   - tests.
2) Prefer agent-based extension over embedding complex logic in dataplane.
3) Keep the dataplane “boring”: small surface area, stable behavior.
4) Document decisions and defaults in the config reference.
5) Any new config option must include:
   - safe default,
   - validation rules,
   - example usage,
   - migration notes if relevant.

---

## 15) Definition of Done (per milestone)
- Feature implemented + tested
- Limits and timeouts enforced
- Metrics/logs/traces updated
- Docs updated (config reference + runbook)
- Load/soak impact assessed
- Rollback plan documented

---

## 16) Immediate Next Steps (suggested task breakdown)
- Create `proxy/` dataplane crate and `agent/` protocol crate
- Implement config loader + schema validation + dry-run
- Implement agent client over UDS + request_headers event
- Implement reference agent: denylist + header mutation
- Add metrics: per-route latency, agent latency, timeouts, circuit breaks
- Build replay harness skeleton for future WAF regression
