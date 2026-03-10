# Why External Agents

## The Decision

Zentinel processes complex request logic—WAF inspection, authentication, custom business rules—in external agent processes that communicate with the proxy over Unix domain sockets or gRPC. Agents are separate OS processes, not embedded plugins or in-process modules.

## Alternatives Considered

**Embedded plugins (shared libraries / dynamic loading).** Load `.so`/`.dylib` files at runtime. Fast (no IPC), but a bug in any plugin can corrupt proxy memory or crash the entire process. No language flexibility—plugins must be written in Rust or C. Upgrading a plugin requires restarting the proxy.

**WASM filters.** Sandboxed execution within the proxy process. Better isolation than shared libraries, but WASM has limited access to system resources (networking, filesystem), restricted language support (not all languages compile well to WASM), and the sandbox adds overhead for every call. Debugging WASM in production is painful.

**Lua scripting (NGINX/OpenResty model).** Flexible and fast for simple transformations. But Lua's type system is weak, error handling is ad hoc, and complex logic (WAF rule evaluation, ML model inference) does not belong in an embedded scripting language. Lua scripts share the proxy's address space—a runaway script blocks the event loop.

**HTTP callouts (ext_proc / ext_authz).** External services over HTTP. Good isolation, but HTTP adds serialization overhead, connection management complexity, and latency. Every request becomes at least one additional HTTP round-trip. The protocol is generic rather than purpose-built for proxy integration.

## Why External Processes

**Crash isolation.** If a WAF agent segfaults or panics, the proxy keeps serving traffic. The circuit breaker trips, the agent restarts, and recovery is automatic. A bug in request inspection must never take down the proxy.

**Language flexibility.** Agents can be written in any language: Rust, Go, Python, Java. The protocol is documented and SDK libraries are provided. Teams can extend Zentinel without learning Rust or understanding proxy internals.

**Independent deployment.** Agents have their own release cycle. You can upgrade a WAF agent without restarting the proxy. You can roll back an agent without touching the proxy binary. This matters in production where the proxy handles all traffic.

**Resource isolation.** Each agent has its own memory space, CPU allocation, and concurrency limits. A slow authentication agent cannot starve a fast header-transformation agent. Per-agent semaphores enforce concurrency bounds. Circuit breakers prevent cascading failures.

**Noisy neighbor prevention.** Per-agent concurrency semaphores ensure that one slow agent cannot consume all available processing capacity. If Agent A is slow, Agent B continues processing at full speed with its own independent semaphore.

## The Protocol

Agents communicate over a binary protocol with length-prefixed JSON messages:

- **Transport**: Unix domain sockets (primary), gRPC (remote agents), reverse connections (NAT traversal)
- **Message frame**: 4-byte big-endian length + 1-byte type prefix + JSON payload
- **Lifecycle events**: `RequestHeaders`, `RequestBody`, `ResponseHeaders`, `ResponseBody`, `RequestComplete`, `WebSocketFrame`, `GuardrailInspect`
- **Decisions**: `ALLOW` (continue), `BLOCK` (reject with status), `MODIFY` (transform headers/body)
- **Connection pooling**: Persistent connections with 4 load-balancing strategies (round-robin, least-connections, health-based, random)

The protocol is purpose-built for proxy integration. It exposes exactly the request lifecycle phases that matter, with no unnecessary abstraction.

## Trade-offs

**IPC overhead.** Every agent call crosses a process boundary. For the hot path (every request), this adds latency—typically sub-millisecond over UDS, but nonzero. We mitigate this with connection pooling, persistent connections, and batched communication where possible.

**Operational complexity.** External agents are additional processes to deploy, monitor, and manage. Each agent needs health checking, log collection, and lifecycle management. This is more complex than a single-binary approach.

**Protocol versioning.** The agent protocol is a contract. Breaking changes require coordinated updates across proxy and agents. We version the protocol and maintain backward compatibility where feasible.

## When to Revisit

- If WASM matures to support full system access, rich debugging, and broad language support, some lightweight agents could move in-process
- If the IPC overhead becomes measurable in latency-critical paths (sub-100μs budgets), a hybrid model with in-process fast-path and external slow-path could be considered
- If the operational burden of managing agent processes proves too high for small deployments, an embedded mode could be offered as an option

## Manifesto Alignment

> *"Complexity must be isolated. [...] The agent architecture is not a workaround or a plugin system bolted on as an afterthought. It is a fundamental design choice."* — Manifesto, principle 4

> *"A broken extension must never take the whole system down with it. Agents can crash, restart, be upgraded, or be disabled—independently of the proxy."* — Manifesto, principle 4

The external agent model is how Zentinel keeps the core small and the blast radius of complexity contained.
