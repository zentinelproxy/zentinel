# Sentinel Manifesto

Sentinel exists because critical web infrastructure should be **boring, inspectable, and shared**.

The web runs on systems that sit quietly at the edge, making decisions millions of times per second. When those systems fail, people wake up at 03:00. When they fail in opaque ways, people lose trust in the web itself.

Sentinel is an attempt to do this layer right.

Not bigger.  
Not smarter.  
Just **more honest**.

---

## What We Believe

### 1. Infrastructure should be calm
A reverse proxy should not surprise you.

It should:
- have clear limits,
- predictable timeouts,
- and failure modes you can explain to another human.

If a system requires heroics to operate, it is already broken.

Sentinel is built so operators can sleep.

---

### 2. Security must be explicit
Security that relies on hidden behavior is not security.

Every limit, timeout, and decision in Sentinel is meant to be:
- visible in configuration,
- observable in metrics and logs,
- and explainable after the fact.

There is no “magic”.
There is no implied policy.

If Sentinel is protecting something, you should be able to point to **where and why**.

---

### 3. The edge is a boundary, not a battleground
Sentinel does not treat the network as a war zone.

It treats it as a **boundary**:
- where traffic enters,
- where limits matter,
- and where careful decisions prevent harm upstream.

Being a guardian means stepping in **only when necessary**, and doing so proportionally.

---

### 4. Complexity must be isolated
Complex systems fail in complex ways.

Sentinel keeps the core dataplane intentionally small and predictable.
Anything that is:
- parsing-heavy,
- policy-rich,
- or operationally risky

belongs **outside** the core, behind explicit contracts.

This is why Sentinel favors external agents over embedded logic.
A broken extension must never take the whole system down with it.

---

### 5. The web is a commons
Sentinel is built for the free and open web.

That means:
- no hidden control planes,
- no vendor lock-in by design,
- no closed rule engines masquerading as “features”.

You should be able to:
- read the code,
- fork it,
- modify it,
- and run it independently.

Sentinel exists to keep this layer **shared**, not owned.

---

### 6. Production correctness beats feature breadth
Sentinel will always choose:
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

## What Sentinel Is Not

Sentinel is not:
- a platform that needs a sales call,
- a framework that reinvents everything below it,
- a place to embed arbitrary logic because it “might be useful”.

It is not trying to win benchmarks at the cost of operability.
It is not trying to centralize power at the edge.

---

## A Note to Contributors

If you contribute to Sentinel, you are helping guard a shared layer of the web.

That comes with responsibility.

Before adding anything, ask:
- Does this introduce ambiguity?
- Can this fail loudly and safely?
- Will this make someone’s on-call worse?

If the answer is unclear, slow down.

Sentinel will still be here tomorrow.

---

## In Short

Sentinel stands for:
- explicit limits,
- predictable behavior,
- and infrastructure people can trust.

Guarding the free web does not require aggression.

It requires care.
