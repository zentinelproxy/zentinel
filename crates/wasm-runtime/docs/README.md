# WASM Runtime Documentation

The `zentinel-wasm-runtime` crate provides a sandboxed WebAssembly runtime for executing agents in-process using the Wasmtime Component Model.

## Overview

WASM agents offer lower latency than external agents (~10-50μs vs ~40-50μs) while maintaining crash isolation through WebAssembly's sandboxing. They run in the same process as Zentinel but cannot access memory or resources outside their sandbox.

## When to Use WASM Agents

**Ideal for:**
- Latency-critical operations (<20μs requirement)
- Stateless, bounded computations
- Simple checks (allowlist/denylist, header validation, JWT verification)
- Request enrichment (adding headers, metadata)

**Keep using external agents for:**
- WAF (requires C libraries like libmodsecurity)
- Auth with external IdP calls (network I/O)
- ML inference (requires native libraries)
- Unbounded computation or large state

## Quick Start

```rust
use zentinel_wasm_runtime::{WasmAgentRuntime, WasmAgentConfig};

// Create runtime with default configuration
let config = WasmAgentConfig::default();
let runtime = WasmAgentRuntime::new(config)?;

// Compile a WASM agent component
runtime.compile_component_file("my-agent", "agents/my-agent.wasm")?;

// Load and instantiate the agent
let agent = runtime.load_agent("my-agent-1", "my-agent", r#"{"key": "value"}"#)?;

// Process requests
let response = agent.on_request_headers(&metadata, "GET", "/api/users", &headers)?;

match response.decision {
    Decision::Allow => { /* continue to upstream */ }
    Decision::Block { status, body, .. } => { /* return error response */ }
    Decision::Redirect { url, status } => { /* redirect client */ }
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Runtime design and component model |
| [Configuration](configuration.md) | Runtime and resource limit options |
| [WIT Interface](wit-interface.md) | WebAssembly Interface Types specification |
| [Building Agents](building-agents.md) | How to create WASM agents |

## Key Features

- **Component Model**: Uses Wasmtime's Component Model for type-safe bindings
- **WASI Preview 2**: Full WASI p2 support for stdin/stdout/stderr
- **Fuel Metering**: CPU limits via instruction counting
- **Memory Limits**: Configurable per-instance memory caps
- **Component Caching**: Compiled components are cached for reuse
- **Graceful Shutdown**: Proper lifecycle management for agents

## Performance

WASM agents execute synchronously in the request path with minimal overhead:

| Operation | Typical Latency |
|-----------|-----------------|
| Agent instantiation | ~1-5ms (one-time) |
| Request header processing | ~10-50μs |
| Body chunk processing | ~5-20μs per chunk |
| Health check | ~1-5μs |

## Limitations

- No network I/O from within WASM (by design)
- No filesystem access (except through WASI capabilities)
- Single-threaded execution per instance
- Fuel metering adds ~5% overhead
