# Why Sentinel

Sentinel exists because operating a reverse proxy in production is harder than it should be.

Not because the underlying technology is weak — but because complexity, ambiguity, and hidden behavior accumulate over time.

This document explains the problem Sentinel is trying to solve.

---

## The problem is not performance

Modern proxies are fast.
Pingora, Envoy, HAProxy, and others prove this daily.

Performance is rarely the reason operators wake up at 03:00.

---

## The real problems

Operational incidents at the edge usually involve:
- unbounded queues or memory growth,
- timeouts that interact in unexpected ways,
- hidden retries or buffering,
- embedded logic that cannot be isolated or rolled back,
- security components that fail catastrophically under load.

These issues tend to appear only under stress — when debugging is hardest.

---

## Sentinel’s approach

Sentinel takes a deliberately conservative stance.

### Explicit boundaries
Every important behavior is meant to be:
- configured explicitly,
- validated upfront,
- and observable at runtime.

No defaults that quietly change behavior.
No hidden policy layers.

---

### Bounded by design
Sentinel enforces:
- hard limits on memory and queues,
- deterministic timeouts everywhere,
- controlled backpressure.

If something cannot be bounded, it does not belong in the core.

---

### Small, predictable core
The proxy dataplane is intentionally boring.

Anything that is:
- complex,
- policy-rich,
- or operationally risky

is pushed out into **external agents**, where it can be:
- upgraded independently,
- rate-limited,
- circuit-broken,
- or disabled without taking the proxy down.

---

### Security without theatrics
Sentinel treats security as a matter of:
- careful limits,
- transparent decisions,
- and proportional enforcement.

Not as a battleground.
Not as a black box.

---

## What Sentinel is optimizing for

Sentinel is optimized for:
- long-running production environments,
- human operators,
- and shared, open infrastructure.

It is not optimized for:
- feature checklists,
- maximal configurability,
- or embedding every possible use case into the core.

---

## In short

Sentinel exists to make the edge:
- calmer,
- more predictable,
- and easier to reason about.

That is what guarding the free web looks like in practice.
