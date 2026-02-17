# Zentinel Manifesto

Zentinel exists because critical web infrastructure should be **boring, inspectable, and shared**.

The web runs on systems that sit quietly at the edge, making decisions millions of times per second. When those systems fail, people wake up at 03:00. When they fail in opaque ways, people lose trust in the web itself.

Zentinel is an attempt to do this layer right.

Not bigger.
Not smarter.
Just **more honest**.

We build on proven foundations. Cloudflare's Pingora has handled trillions of requests. We inherit that battle-tested core and focus on what matters above it: configuration that humans can reason about, extension points that don't destabilize the system, and operational behavior you can trust with your sleep.

Zentinel aspires to be a **reference implementation**—not because we claim to be the best, but because we aim to demonstrate how this layer *should* be built: with explicit contracts, bounded resources, and a clear separation between what must be fast and what must be flexible.

---

## What We Believe

### 1. Infrastructure should be calm
A reverse proxy should not surprise you.

It should:
- have clear limits,
- predictable timeouts,
- and failure modes you can explain to another human.

If a system requires heroics to operate, it is already broken.

Zentinel is built so operators can sleep.

---

### 2. Security must be explicit
Security that relies on hidden behavior is not security.

Every limit, timeout, and decision in Zentinel is meant to be:
- visible in configuration,
- observable in metrics and logs,
- and explainable after the fact.

There is no “magic”.
There is no implied policy.

If Zentinel is protecting something, you should be able to point to **where and why**.

---

### 3. The edge is a boundary, not a battleground
Zentinel does not treat the network as a war zone.

It treats it as a **boundary**:
- where traffic enters,
- where limits matter,
- and where careful decisions prevent harm upstream.

Being a guardian means stepping in **only when necessary**, and doing so proportionally.

---

### 4. Complexity must be isolated
Complex systems fail in complex ways.

Zentinel keeps the core dataplane intentionally small and predictable.
Anything that is:
- parsing-heavy,
- policy-rich,
- or operationally risky

belongs **outside** the core, behind explicit contracts.

This is why Zentinel favors **external agents** over embedded logic.

The agent architecture is not a workaround or a plugin system bolted on as an afterthought. It is a fundamental design choice: the dataplane does one thing well (moving bytes with bounded resources), while agents handle everything else (WAF inspection, authentication, rate limiting, custom business logic).

A broken extension must never take the whole system down with it.
Agents can crash, restart, be upgraded, or be disabled—independently of the proxy.
The blast radius of complexity is contained by process boundaries, not just code boundaries.

---

### 5. The web is a commons
Zentinel is built for the free and open web.

That means:
- no hidden control planes,
- no vendor lock-in by design,
- no closed rule engines masquerading as “features”.

You should be able to:
- read the code,
- fork it,
- modify it,
- and run it independently.

Zentinel exists to keep this layer **shared**, not owned.

---

### 6. Production correctness beats feature breadth
Zentinel will always choose:
- correctness over cleverness,
- boring reliability over shiny features,
- and fewer knobs over unsafe defaults.

A feature that cannot be:
- bounded,
- observed,
- tested,
- and rolled back

does not belong in the core.

---

## Guarding Tomorrow's Web

The web is changing. New challenges are emerging that reverse proxies must address:

**Inference traffic is different.**
AI workloads don't fit the request-response model we've optimized for decades. Token streams, long-running connections, and cost-per-token economics require new primitives. Zentinel will treat inference as a first-class traffic type—with token-aware rate limiting, model routing, and semantic guardrails—without compromising the simplicity of HTTP routing.

**Identity is becoming workload-native.**
The future of security is not firewalls at the perimeter but cryptographic identity at every hop. Zentinel will embrace workload identity (SPIFFE, mTLS, continuous verification) so that every request can answer: *who is asking, and should they be allowed?*

**Explainability is mandatory.**
As edge decisions grow more complex—WAF rules, rate limits, routing policies, agent verdicts—operators need to understand *why* a request was blocked or allowed. Zentinel will make every decision traceable: not just what happened, but which rule, which agent, which configuration line.

**The attack surface is expanding.**
Prompt injection, model jailbreaking, PII leakage through AI APIs—these are new categories of harm that the edge must help prevent. Zentinel's agent architecture is designed precisely for this: specialized agents can inspect, classify, and guard against threats we haven't fully imagined yet, without requiring changes to the core.

We do not know exactly what the web will look like in ten years. But we know that the layer sitting at the boundary—accepting connections, making decisions, routing traffic—will still matter. Zentinel is built to evolve with that future, not to predict it.

---

## What Zentinel Is Not

Zentinel is not:
- a platform that needs a sales call,
- a framework that reinvents everything below it,
- a place to embed arbitrary logic because it “might be useful”.

It is not trying to win benchmarks at the cost of operability.
It is not trying to centralize power at the edge.

---

## A Note to Contributors

If you contribute to Zentinel, you are helping guard a shared layer of the web.

That comes with responsibility.

Before adding anything, ask:
- Does this introduce ambiguity?
- Can this fail loudly and safely?
- Will this make someone’s on-call worse?

If the answer is unclear, slow down.

Zentinel will still be here tomorrow.

---

## In Short

Zentinel stands for:
- explicit limits,
- predictable behavior,
- observable decisions,
- isolated complexity,
- and infrastructure people can trust.

We guard not just the web of today—the HTTP requests, the upstream pools, the TLS handshakes—but the web of tomorrow: the inference streams, the workload identities, the threats we haven't named yet.

We do this by staying small where it matters, extensible where it counts, and honest everywhere.

Guarding the free web does not require aggression.

It requires care.
