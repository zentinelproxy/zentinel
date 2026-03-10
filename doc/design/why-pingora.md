# Why Pingora

## The Decision

Zentinel is built on [Pingora](https://github.com/cloudflare/pingora), Cloudflare's open-source HTTP proxy framework written in Rust.

We use Pingora as the core dataplane: connection handling, HTTP parsing, TLS termination, load balancing, and upstream connection pooling. Zentinel adds configuration, the agent architecture, observability, and operational semantics on top.

## Alternatives Considered

**Hyper (raw)**. Rust's de facto HTTP library. Gives you maximum control but requires building connection management, load balancing, graceful shutdown, hot restart, and TLS from scratch. Writing a production proxy on raw hyper means reimplementing what Pingora already provides—and getting it wrong in subtle ways under load.

**Envoy**. Battle-tested C++ proxy with a large ecosystem. But extending Envoy means writing C++ or using WASM filters, both of which add friction. Envoy's configuration surface is enormous (xDS, Lua, WASM, ext_proc), and the operational model assumes a control plane. Zentinel wants to be a single binary you can reason about.

**NGINX**. Proven, fast, widely deployed. But NGINX's module system is C-based, its configuration language is its own DSL with implicit inheritance rules, and its architecture (worker processes, shared memory zones) makes certain patterns—like per-request external callouts—awkward.

**Building from scratch**. Full control, no dependency risk. But HTTP proxy correctness is deceptively hard: connection reuse, keepalive management, upgrade handling, graceful shutdown with drain, hot restart without dropping connections. These are solved problems. Solving them again is a poor use of time.

## Why Pingora Fits

**Proven at scale.** Pingora handles trillions of requests at Cloudflare. The connection lifecycle, memory management, and failure handling have been tested under conditions we cannot reproduce in a lab.

**Rust-native.** Same language as Zentinel. No FFI boundary, no serialization overhead for the hot path. The `ProxyHttp` trait gives us typed hooks into the request lifecycle—request filter, upstream peer selection, response filter—without fighting a C API.

**Right abstraction level.** Pingora gives us the plumbing (connection pools, health checks, load balancing algorithms, TLS, HTTP/1 and HTTP/2) while letting us own the policy layer. We implement `ProxyHttp` and control what happens at each phase. It does not impose a configuration format, a control plane, or an extension model.

**Operational primitives.** Graceful shutdown, hot restart (upgrading the binary without dropping connections), and worker thread management come built in. These are hard to get right and critical for zero-downtime operation.

## Trade-offs

**External dependency.** We depend on a project maintained by Cloudflare. If Pingora's direction diverges from ours, we carry the cost. We mitigate this by maintaining a fork with security patches rebased, and by keeping our integration surface narrow (primarily the `ProxyHttp` trait).

**Abstraction leakage.** Pingora's APIs occasionally expose internal assumptions (session lifecycle, error types). We work around these where needed rather than fighting the framework.

**Upgrade friction.** Tracking upstream Pingora means periodic rebasing. Breaking changes in Pingora's trait signatures require updates across our proxy implementation.

## When to Revisit

- If Pingora is abandoned or development stalls significantly
- If our requirements diverge from HTTP proxying (e.g., raw TCP/UDP as a primary use case)
- If Pingora's abstraction becomes a bottleneck for features we need (unlikely given the trait-based design)

## Manifesto Alignment

> *"We build on proven foundations."* — Manifesto, introduction

> *"Production correctness beats feature breadth."* — Manifesto, principle 6

Building on Pingora means we inherit correctness for the hard parts (HTTP parsing, connection management, TLS) and spend our time on what makes Zentinel different: the agent architecture, KDL configuration, and explicit operational semantics.
