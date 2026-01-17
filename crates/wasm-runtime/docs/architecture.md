# Architecture

This document describes the internal architecture of the WASM runtime.

## Component Model

The runtime uses Wasmtime's [Component Model](https://github.com/WebAssembly/component-model) rather than core WebAssembly modules. The Component Model provides:

- **Type-safe bindings**: Generated from WIT interface definitions
- **Rich types**: Records, variants, lists, options (not just i32/f64)
- **Composability**: Components can be linked together
- **WASI integration**: Standardized system interface

```
┌─────────────────────────────────────────────────────────────┐
│                    WasmAgentRuntime                          │
│                                                              │
│  ┌──────────────┐    ┌──────────────────────────────────┐   │
│  │   Wasmtime   │    │         Component Cache           │   │
│  │    Engine    │    │  ┌────────┐ ┌────────┐ ┌────────┐│   │
│  │              │    │  │ agent-1│ │ agent-2│ │ agent-3││   │
│  │  (shared)    │    │  │ .wasm  │ │ .wasm  │ │ .wasm  ││   │
│  └──────────────┘    │  └────────┘ └────────┘ └────────┘│   │
│                      └──────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Active Agent Instances                    │   │
│  │  ┌─────────────────┐  ┌─────────────────┐            │   │
│  │  │ WasmAgentInstance│  │ WasmAgentInstance│            │   │
│  │  │                 │  │                 │            │   │
│  │  │  Store<State>   │  │  Store<State>   │            │   │
│  │  │  Agent bindings │  │  Agent bindings │            │   │
│  │  │  WASI context   │  │  WASI context   │            │   │
│  │  └─────────────────┘  └─────────────────┘            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Module Structure

### `runtime.rs` - WasmAgentRuntime

The main runtime manager:

- Creates and owns the Wasmtime `Engine`
- Caches compiled `Component` objects
- Manages active `WasmAgentInstance` lifecycle
- Enforces instance limits
- Handles graceful shutdown

### `host.rs` - WasmAgentInstance

Individual agent instance:

- Owns a Wasmtime `Store` with agent state
- Holds the instantiated `Agent` bindings
- Implements WASI through `WasiView` trait
- Tracks fuel consumption per call
- Provides synchronous API for request processing

### `component.rs` - WIT Bindings

Generated bindings from the WIT interface:

- `bindgen!` macro generates Rust types from WIT
- Type conversion functions (WIT ↔ internal types)
- Re-exports handler and lifecycle interfaces

### `config.rs` - Configuration

Runtime and resource limit configuration:

- `WasmAgentConfig`: Runtime-level settings
- `WasmResourceLimits`: Per-instance resource caps

### `error.rs` - Error Types

Comprehensive error handling:

- Engine creation errors
- Compilation errors
- Instantiation errors
- Function call errors
- Resource limit errors

## Request Flow

```
1. Request arrives at Sentinel
           │
           ▼
2. Route matches, WASM agent configured
           │
           ▼
3. runtime.get_agent(agent_id)
           │
           ▼
4. agent.on_request_headers(metadata, method, uri, headers)
           │
           ▼
5. Convert types: RequestMetadata → WIT RequestMetadata
           │
           ▼
6. Set fuel limit, call WASM function
           │
           ▼
7. WASM agent executes (sandboxed)
           │
           ▼
8. Convert response: WIT AgentResponse → internal AgentResponse
           │
           ▼
9. Return Decision (Allow/Block/Redirect)
```

## Fuel Metering

Fuel metering prevents runaway computation:

```rust
// Before each call
store.set_fuel(limits.max_fuel)?;

// Execute WASM function
let response = handler.call_on_request_headers(&mut store, ...)?;

// Track consumption
let remaining = store.get_fuel().unwrap_or(0);
let consumed = limits.max_fuel.saturating_sub(remaining);
```

If fuel is exhausted during execution, Wasmtime traps and returns an error.

## WASI Integration

The runtime provides WASI Preview 2 capabilities:

```rust
impl WasiView for AgentState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}
```

Current capabilities:
- `inherit_stdout()`: Agent can write to stdout (for logging)
- `inherit_stderr()`: Agent can write to stderr (for errors)

Not provided (by design):
- Filesystem access
- Network access
- Environment variables
- Random number generation (deterministic execution)

## Thread Safety

- `WasmAgentRuntime` is `Send + Sync` (uses `RwLock` for caches)
- `WasmAgentInstance` uses `Mutex<Store>` for thread-safe calls
- Each call acquires the store lock, preventing concurrent execution
- Multiple instances can process requests concurrently

## Memory Management

- Components are compiled once and cached
- Instances are created on-demand with their own memory
- Instance memory is isolated (WASM linear memory)
- Memory limits enforced at instantiation time
- Instances are reference-counted (`Arc<WasmAgentInstance>`)
