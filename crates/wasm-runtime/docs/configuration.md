# Configuration

This document covers all configuration options for the WASM runtime.

## WasmAgentConfig

Runtime-level configuration for the WASM agent runtime.

```rust
use zentinel_wasm_runtime::{WasmAgentConfig, WasmResourceLimits};
use std::time::Duration;

let config = WasmAgentConfig {
    limits: WasmResourceLimits::default(),
    fuel_enabled: true,
    epoch_enabled: true,
    epoch_tick_interval: Duration::from_millis(1),
    cache_enabled: true,
    cache_dir: None,
    max_instances: 4,
};
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `limits` | `WasmResourceLimits` | default | Resource limits for instances |
| `fuel_enabled` | `bool` | `true` | Enable CPU fuel metering |
| `epoch_enabled` | `bool` | `true` | Enable epoch-based interruption |
| `epoch_tick_interval` | `Duration` | 1ms | Interval for epoch checks |
| `cache_enabled` | `bool` | `true` | Cache compiled components |
| `cache_dir` | `Option<String>` | `None` | Directory for persistent cache |
| `max_instances` | `u32` | 4 | Maximum concurrent agent instances |

### Presets

```rust
// Minimal configuration for testing
let config = WasmAgentConfig::minimal();

// High-performance configuration for production
let config = WasmAgentConfig::high_performance();

// Custom limits
let config = WasmAgentConfig::with_limits(WasmResourceLimits::strict());
```

---

## WasmResourceLimits

Per-instance resource limits to prevent resource exhaustion.

```rust
let limits = WasmResourceLimits {
    max_memory: 64 * 1024 * 1024,           // 64 MB
    max_execution_time: Duration::from_millis(100),
    max_fuel: 10_000_000,
    max_table_elements: 10_000,
    max_tables: 1,
    max_memories: 1,
    max_function_size: 1024 * 1024,         // 1 MB
};
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_memory` | `usize` | 64 MB | Maximum linear memory per instance |
| `max_execution_time` | `Duration` | 100ms | Maximum time per call |
| `max_fuel` | `u64` | 10,000,000 | Maximum fuel (instructions) per call |
| `max_table_elements` | `u32` | 10,000 | Maximum table elements |
| `max_tables` | `u32` | 1 | Maximum number of tables |
| `max_memories` | `u32` | 1 | Maximum number of memories |
| `max_function_size` | `usize` | 1 MB | Maximum size of a single function |

### Presets

```rust
// Default balanced limits
let limits = WasmResourceLimits::default();

// Strict limits for untrusted modules
let limits = WasmResourceLimits::strict();
// - 8 MB memory
// - 10ms execution time
// - 100,000 fuel
// - 100 table elements

// High-performance limits for trusted modules
let limits = WasmResourceLimits::high_performance();
// - 256 MB memory
// - 500ms execution time
// - 100,000,000 fuel
// - 100,000 table elements

// Minimal limits for testing
let limits = WasmResourceLimits::minimal();
// - 16 MB memory
// - 50ms execution time
// - 1,000,000 fuel
```

---

## Fuel Metering

Fuel metering limits CPU consumption by counting instructions. Each WASM instruction consumes one unit of fuel.

### How It Works

1. Before each call, fuel is set to `max_fuel`
2. During execution, fuel decrements with each instruction
3. If fuel reaches zero, execution traps with `ResourceLimit` error
4. After execution, consumed fuel is tracked for observability

### Tuning Fuel Limits

| Workload | Recommended Fuel | Notes |
|----------|------------------|-------|
| Simple header check | 100,000 | Allowlist/denylist lookup |
| JWT validation | 1,000,000 | Crypto operations |
| Complex policy | 10,000,000 | Multiple condition checks |
| Regex matching | 10,000,000+ | Can vary widely |

### Disabling Fuel Metering

Not recommended for production, but useful for testing:

```rust
let config = WasmAgentConfig {
    fuel_enabled: false,
    ..Default::default()
};
```

---

## Memory Configuration

WASM linear memory is bounded by `max_memory`:

```rust
// For simple agents processing small payloads
let limits = WasmResourceLimits {
    max_memory: 16 * 1024 * 1024,  // 16 MB
    ..Default::default()
};

// For agents that accumulate request bodies
let limits = WasmResourceLimits {
    max_memory: 128 * 1024 * 1024,  // 128 MB
    ..Default::default()
};
```

### Memory Usage Guidelines

| Agent Type | Recommended Memory |
|------------|-------------------|
| Header-only agent | 8-16 MB |
| Small body inspection | 32-64 MB |
| Full body buffering | 128-256 MB |

---

## Instance Limits

`max_instances` limits concurrent agent instances to prevent memory exhaustion:

```rust
let config = WasmAgentConfig {
    max_instances: 8,  // Allow up to 8 concurrent instances
    ..Default::default()
};
```

### Calculating Instance Limits

```
Total Memory = max_instances × max_memory_per_instance

Example:
  8 instances × 64 MB = 512 MB maximum WASM memory
```

---

## KDL Configuration

When configuring WASM agents via Zentinel's KDL config:

```kdl
agents {
    wasm-agent "header-validator" {
        component "/opt/zentinel/agents/header-validator.wasm"
        config {
            required-headers "Authorization" "X-Request-ID"
            max-header-size 8192
        }

        // Resource limits
        max-memory-mb 32
        max-fuel 5000000
        max-execution-ms 50
    }
}

routes {
    route "api" {
        matches { path-prefix "/api/" }
        upstream "backend"
        wasm-agents "header-validator"
    }
}
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ZENTINEL_WASM_CACHE_DIR` | Component cache directory | None (in-memory) |
| `ZENTINEL_WASM_MAX_INSTANCES` | Maximum agent instances | 4 |
| `ZENTINEL_WASM_FUEL_ENABLED` | Enable fuel metering | true |
