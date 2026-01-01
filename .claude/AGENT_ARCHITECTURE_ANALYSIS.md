# Agent Architecture Analysis: Core vs External

**Last Updated:** 2026-01-01
**Analysis Scope:** All 10 Official Agents (Stable, Beta, Planned)

---

## Executive Summary

This document analyzes which Sentinel agents should be integral to the reverse proxy core versus remaining as independent external agents. The analysis is grounded in Sentinel's MANIFESTO principle: *"parsing-heavy, policy-rich, or operationally risky belongs outside the core."*

**Current State:** The following features are now **built into the core**:
- **Geo Filtering** — MaxMind and IP2Location database support
- **Response Caching** — Pingora cache with PURGE API
- **Telemetry** — Metrics, access logs, audit logs, OTLP tracing
- **Basic Rate Limiting** — Token bucket with global and per-route limits

**Recommendation:** The remaining agents are correctly isolated as external processes.

---

## Decision Framework

### Criteria for Core Integration

An agent should be considered for core integration if it meets **all** of the following:

1. **Latency-critical** — IPC overhead (100-500μs per Unix socket round-trip) is unacceptable
2. **Universal** — 95%+ of deployments will enable it
3. **Deterministic** — Simple, predictable logic with no complex failure modes
4. **Stable** — Algorithm/behavior changes infrequently
5. **Memory-safe** — Cannot cause unbounded memory growth

### Criteria for External Agent

An agent should remain external if it meets **any** of the following:

1. **Parsing-heavy** — Complex input parsing (HTML, SQL, regex rules)
2. **Policy-rich** — Behavior varies significantly across deployments
3. **Update-independent** — Rules/logic updates more frequently than proxy releases
4. **Failure-prone** — Has crash/hang/memory-leak potential
5. **Compute-heavy** — ML inference, cryptographic operations, external calls

---

## Agent-by-Agent Analysis

### Currently Stable (v0.1.0)

| Agent | Verdict | Rationale |
|-------|---------|-----------|
| **Auth** | External ✓ | Auth mechanisms vary wildly (JWT, OAuth, OIDC, API keys, custom). Token validation can involve external calls. Correctly isolated. |
| **Denylist** | External ✓ | Simple logic, but "real-time updates without restart" justifies external. Operational flexibility > marginal latency. |
| **Rate Limiter** | **Borderline** | See detailed analysis below. |

### Beta Phase (v0.1.0)

| Agent | Verdict | Rationale |
|-------|---------|-----------|
| **Lua Scripting** | External ✓ | Textbook case for isolation. VM sandboxing, script hot-reload, resource limits—exactly what agents are for. |
| **WAF** | External ✓ | Parsing-heavy (SQL, XSS patterns), rule sets change independently, CRS updates. The MANIFESTO explicitly calls this out. |

### Planned Releases

| Agent | Verdict | Rationale |
|-------|---------|-----------|
| **Adaptive Shield** | External ✓ | ML inference is compute-heavy and unpredictable. Must not block dataplane. |
| **AI Gateway** | External ✓ | Specialized for LLM traffic. Not universal. Involves external API calls. |
| **Geo Filter** | **Borderline** | See detailed analysis below. |
| **LLM Guardian** | External ✓ | AI-powered analysis. Same reasoning as Adaptive Shield. |
| **Request Hold** | External ✓ | Introduces async/blocking behavior (human approval). Proxy should never wait on humans. |
| **Response Cache** | **Core (partial)** | Basic caching infrastructure already exists in core. Complex invalidation policies can be agent-controlled. |
| **Telemetry** | **Core (partial)** | Basic metrics already in core (`/metrics`). Enrichment/analytics can be external. |
| **WebSocket Inspector** | External ✓ | Frame-level parsing is complex and protocol-specific. |

---

## Detailed Analysis: Borderline Cases

### Rate Limiter

**Current state:** External agent with Redis distributed support

**Analysis:**

| Aspect | Local Token Bucket | Distributed (Redis) |
|--------|-------------------|---------------------|
| Latency impact | ~50μs algorithm, ~200μs IPC overhead | ~1-5ms Redis RTT anyway |
| Complexity | Trivial | Connection pooling, failover |
| Universality | 99% of deployments | 30-40% of deployments |

**Recommendation:**
- **Basic local rate limiting → Core** (simple token bucket per route/IP)
- **Distributed rate limiting → External agent** (Redis coordination complexity)

NGINX, Envoy, Traefik, and HAProxy all have basic rate limiting built-in. The IPC overhead for checking every request is wasteful for such a simple algorithm.

**Implementation note:** Core could expose a `RateLimitDecision` hook that agents can override for complex cases.

---

### Geo Filter

**Current state:** Planned as external agent

**Analysis:**

| Aspect | Assessment |
|--------|------------|
| Algorithm complexity | Single hash/tree lookup (~50μs) |
| IPC overhead | ~200μs per request |
| Update frequency | MaxMind DB updates weekly/monthly |
| Memory footprint | ~50-100MB for GeoIP database |
| Universality | ~60% of deployments |

**Recommendation:** **Consider core integration** with periodic DB reload

A MaxMind lookup is faster than the IPC overhead to ask an agent. However, the database loading and update mechanism adds complexity.

**Compromise:** Core geo lookup with file-watch reload, external agent for complex geo policies (region-specific routing, compliance rules).

---

### Response Cache

**Current state:** Caching infrastructure exists in core

**Analysis:**

The dataplane already handles cache storage and retrieval. This is correct—cache lookups must be in the hot path.

**Recommendation:** Keep current architecture
- **Core:** Cache storage, TTL enforcement, cache key generation
- **External (optional):** Cache tag management, purge APIs, complex invalidation policies

---

### Telemetry

**Current state:** Basic metrics exposed via `/metrics` endpoint

**Analysis:**

Fire-and-forget telemetry should not block requests. Basic counters and histograms must be in-process.

**Recommendation:** Keep current architecture
- **Core:** Request/response metrics, latency histograms, error counts
- **External:** Traffic enrichment, analytics aggregation, custom dimensions

---

## Summary Matrix

| Agent | Current | Recommended | Change Needed |
|-------|---------|-------------|---------------|
| Auth | External | External | None |
| Denylist | External | External | None |
| Rate Limiter | External | **Hybrid** | Add basic local to core |
| Lua Scripting | External | External | None |
| WAF | External | External | None |
| Adaptive Shield | Planned External | External | None |
| AI Gateway | Planned External | External | None |
| Geo Filter | Planned External | **Consider Core** | Evaluate latency impact |
| LLM Guardian | Planned External | External | None |
| Request Hold | Planned External | External | None |
| Response Cache | Core + External | Core + External | None |
| Telemetry | Core + External | Core + External | None |
| WebSocket Inspector | Planned External | External | None |

---

## Architectural Principle Validation

The current design adheres well to the MANIFESTO:

> "A broken extension must never take the whole system down with it."

Only two potential changes are recommended:

1. **Basic rate limiting in core** — Algorithm is too simple and universal to justify IPC overhead
2. **Geo filtering in core** — Lookup is faster than agent round-trip

Both are deterministic, memory-bounded operations that cannot "break in interesting ways."

---

## Implementation Considerations

If moving basic rate limiting to core:

```kdl
// Example: Hybrid rate limiting config
rate-limit {
    // Core handles simple cases
    local {
        default-rps 100
        burst 20
    }

    // Agent handles complex cases
    agent "ratelimit" {
        enabled true
        // Invoked for: custom keys, distributed coordination, complex policies
        triggers ["custom-key", "distributed", "adaptive"]
    }
}
```

If moving geo filtering to core:

```kdl
geo {
    database "/var/lib/GeoIP/GeoLite2-Country.mmdb"
    reload-interval "24h"

    // Simple blocking in core
    deny-countries ["XX", "YY"]

    // Complex policies via agent
    agent "geo-policy" {
        enabled true
        triggers ["compliance", "routing"]
    }
}
```

---

## Conclusion

Sentinel's agent architecture is well-designed. The philosophy of isolating complexity is sound. The only refinements worth considering are:

1. **Basic rate limiting** — Strong candidate for core (universal, simple, latency-sensitive)
2. **Geo filtering** — Moderate candidate for core (simple lookup, but less universal)

All other agents are correctly positioned as external processes. The architecture successfully achieves the goal of keeping the dataplane "boring and predictable" while allowing innovation at the agent layer.
