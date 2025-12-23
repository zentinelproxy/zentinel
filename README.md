# Sentinel

**Sentinel is a security-first reverse proxy built to guard the free web.**

It is designed for explicit limits, predictable behavior, and production environments where operators are expected to sleep.

Sentinel is built on top of Cloudflare Pingora. It does not reinvent the proxy dataplane. Instead, it focuses on the product layer that matters in real operations: configuration, policy boundaries, extensibility, observability, and safe defaults.

The core philosophy is simple:

- the dataplane should be boring and predictable,
- security decisions should be explicit and observable,
- and complexity should be isolated rather than embedded.

Sentinel exists so critical web infrastructure remains **inspectable, forkable, and shared**.

---

## Why Sentinel exists

Modern reverse proxies are powerful, but often accumulate:
- hidden behavior,
- unbounded complexity,
- and operational risk that only appears under stress.

Sentinel takes a different approach.

It prioritizes:
- bounded memory and queues,
- deterministic timeouts everywhere,
- clear failure modes (fail-open / fail-closed),
- and extensibility via external agents rather than embedded logic.

The goal is not to compete on feature count.
The goal is to build infrastructure that is **correct, calm, and trustworthy**.

---

## Design principles

- **Sleepable operations**  
  No unbounded resources. No surprise behavior.

- **Security-first, not security-magic**  
  Every limit and decision is explicit in configuration.

- **Small, stable core**  
  Innovation lives outside the dataplane, behind contracts.

- **Production correctness over cleverness**  
  Features ship only when they can be bounded, observed, tested, and rolled back.

For a deeper explanation of these principles, see [`MANIFESTO.md`](MANIFESTO.md).
