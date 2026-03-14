# Why Bounded Resources

## The Decision

Every resource in Zentinel has an explicit upper bound: connections, request body size, header count, header size, agent concurrency, cache size, decompression ratios, connection pool depth. Nothing grows without limit. Nothing is "unlimited by default."

## Alternatives Considered

**Unbounded by default, limit when needed.** Most proxies start with no limits and let operators add them when problems arise. This is reactive: you discover the limit you needed after the outage. A single client opening 100,000 connections, a request with a 2 GB body, or a zip bomb expanding to fill all available memory—these are not edge cases, they are Tuesday.

**Dynamic auto-scaling.** Automatically grow buffers, pools, and queues based on demand. This works until it doesn't: auto-scaling under a DDoS attack means the proxy consumes all available memory trying to accommodate malicious traffic. The system that was supposed to protect your backend becomes the mechanism of its destruction.

**OS-level limits only.** Rely on `ulimit`, cgroups, and OOM killer for resource boundaries. These are blunt instruments: the OOM killer does not distinguish between a proxy handling legitimate traffic and one being abused. When the OS enforces the limit, recovery is a process restart, not a graceful rejection.

## Why Bounded

**Predictable memory usage.** An operator can look at the configuration and calculate the worst-case memory footprint:

| Resource | Default Limit | Purpose |
|----------|--------------|---------|
| Max body size | 1 MB | Prevents memory exhaustion from large uploads |
| Max header size | 8,192 bytes | Prevents header-based DoS |
| Max header count | 100 | Prevents header inflation attacks |
| Max connections per client | 100 | Prevents single-client monopolization |
| Agent concurrency | 100 per agent | Prevents agent overload |
| Cache size | 100 MB | Bounded memory for cached responses |
| Upstream connection pool | 100 per upstream | Prevents upstream connection exhaustion |
| Decompression ratio | 100x | Zip bomb protection |
| Decompression output | 10 MB | Absolute decompression ceiling |

These are not hidden safety nets. They are explicit configuration values, logged at startup, observable in metrics.

**Graceful degradation.** When a bound is reached, Zentinel rejects the specific request that would exceed it—with an appropriate HTTP status code and a log entry—rather than degrading the entire system. The 101st connection from a single client gets rejected; the other 100 continue normally. The request with a 2 MB body gets a 413; all other requests are unaffected.

**Noisy neighbor prevention.** Per-agent concurrency semaphores ensure that a slow agent cannot starve other agents. If the WAF agent is processing slowly, it uses its own semaphore budget. The authentication agent continues at full speed with its own independent semaphore. One misbehaving component cannot cascade into system-wide degradation.

**Zip bomb defense.** Decompression is double-bounded: by ratio (output/input must stay below the configured maximum, default 100x) and by absolute size (output must stay below the configured ceiling, default 10 MB). A 1 KB payload that decompresses to 1 GB is caught by the ratio check. A legitimate but large compressed payload is caught by the absolute limit. Both are configurable per deployment.

**Circuit breakers.** Each agent has a three-state circuit breaker (closed → open → half-open) with configurable thresholds. When an agent fails repeatedly, the circuit opens and requests are handled according to the configured failure mode (block or pass-through) without waiting for the agent to time out on every request. Recovery is automatic: after the timeout period, a probe request tests the agent, and on success, the circuit closes.

## Trade-offs

**Operators must size limits.** There is no "unlimited" escape hatch. An operator deploying Zentinel must decide: how large can a request body be? How many connections per client? How much memory for the cache? This requires understanding the workload. We provide documented defaults that work for common cases, but operators should review them.

**Legitimate traffic can be rejected.** A bound that is too tight will reject valid requests. A 1 MB body limit will reject a 2 MB file upload. This is by design: the operator must explicitly raise the limit for endpoints that need it, rather than having no limit and hoping for the best.

**Configuration surface.** Every bound is a configuration knob. More knobs means more to understand, more to review, more to get wrong. We mitigate this with sensible defaults and validation that warns about unusual values, but the complexity is real.

## When to Revisit

- If adaptive limiting (learning from traffic patterns to suggest bounds) proves reliable enough to supplement—not replace—explicit limits
- If a deployment pattern emerges where the defaults are consistently wrong, we should change the defaults rather than expecting every operator to override them
- If per-route or per-endpoint limits become necessary (currently most limits are global or per-agent), the configuration model may need to evolve

## Manifesto Alignment

> *"Infrastructure should be calm. [...] It should have clear limits, predictable timeouts, and failure modes you can explain to another human."* — Manifesto, principle 1

> *"A feature that cannot be bounded, observed, tested, and rolled back does not belong in the core."* — Manifesto, principle 6

Bounded resources are how Zentinel ensures that the proxy behaves predictably under any load condition. The operator sets the bounds. The proxy enforces them. The metrics show when they are reached. There are no surprises.
