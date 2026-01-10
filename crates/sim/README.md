# Sentinel Sim

WASM-compatible simulation engine for Sentinel proxy configurations.

## Overview

The `sentinel-sim` crate enables in-browser configuration validation and route decision tracing without running the actual proxy. It powers the Sentinel playground and developer tools.

**Key Features:**

- **WASM Compatible** - Runs in browsers with no runtime dependencies
- **Deterministic** - Same input always produces same output
- **Stateless** - Each simulation is independent
- **Comprehensive Tracing** - Detailed explanation of routing decisions

## Quick Start

```rust
use sentinel_sim::{validate, simulate, SimulatedRequest};

// Validate a configuration
let kdl_config = r#"
schema-version "1.0"

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "backend"
    }
}
"#;

let result = validate(kdl_config);
if result.valid {
    println!("Configuration is valid!");

    // Simulate a request
    let request = SimulatedRequest::new("GET", "example.com", "/api/users");
    let decision = simulate(&result.effective_config.unwrap(), &request);

    if let Some(matched) = &decision.matched_route {
        println!("Matched route: {}", matched.route_id);
    }
}
```

## Use Cases

### 1. Configuration Validation

Validate KDL configurations before deployment:

```rust
let result = validate(kdl_config);

// Check for errors
for error in &result.errors {
    eprintln!("Error: {} at line {}", error.message, error.line);
}

// Check for warnings (non-fatal)
for warning in &result.warnings {
    println!("Warning: {}", warning.message);
}
```

### 2. Route Decision Debugging

Trace why requests match or don't match routes:

```rust
let decision = simulate(&config, &request);

// See the complete match trace
for step in &decision.match_trace {
    println!("Route '{}': {:?}", step.route_id, step.result);

    for detail in &step.condition_details {
        println!("  {} {} = {}",
            if detail.matched { "✓" } else { "✗" },
            detail.condition_type,
            detail.explanation.as_deref().unwrap_or("")
        );
    }
}
```

### 3. Upstream Selection Preview

See which backend would handle a request:

```rust
if let Some(upstream) = &decision.upstream_selection {
    println!("Upstream: {}", upstream.upstream_id);
    println!("Target: {}", upstream.selected_target);
    println!("Algorithm: {}", upstream.load_balancer);
    println!("Reason: {}", upstream.selection_reason);
}
```

### 4. Policy Analysis

View applied policies for matched routes:

```rust
if let Some(policies) = &decision.applied_policies {
    println!("Timeout: {:?}s", policies.timeout_secs);
    println!("Max body: {:?}", policies.max_body_size);
    println!("Failure mode: {}", policies.failure_mode);

    if let Some(rate_limit) = &policies.rate_limit {
        println!("Rate limit: {} rps", rate_limit.requests_per_second);
    }
}
```

## Module Reference

| Module | Description |
|--------|-------------|
| `lib.rs` | Main API: `validate()`, `simulate()`, `get_effective_config()` |
| `types.rs` | Request/response types and data structures |
| `matcher.rs` | Route matching algorithm with priority and specificity |
| `trace.rs` | Match tracing with detailed condition explanations |
| `upstream.rs` | Load balancer simulation |

## Documentation

Detailed documentation is available in the [`docs/`](./docs/) directory:

- [API Reference](./docs/api.md) - Public API documentation
- [Route Matching](./docs/matching.md) - How routes are matched
- [Load Balancing](./docs/load-balancing.md) - Upstream selection simulation

## WASM Usage

The crate is designed for WASM compilation:

```toml
[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
wasm-bindgen = "0.2"
```

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn validate_config(kdl: &str) -> JsValue {
    let result = sentinel_sim::validate(kdl);
    serde_wasm_bindgen::to_value(&result).unwrap()
}
```

## Design Principles

### Deterministic Simulation

All operations are deterministic. Load balancing uses request hashing instead of stateful counters:

```rust
// Same request always selects same target
let request = SimulatedRequest::new("GET", "example.com", "/api/users");
let decision1 = simulate(&config, &request);
let decision2 = simulate(&config, &request);
assert_eq!(
    decision1.upstream_selection,
    decision2.upstream_selection
);
```

### Comprehensive Tracing

Every route evaluation is traced with detailed explanations:

```
Route 'api-v2': NoMatch
  ✗ PathPrefix: Path '/users' does not start with '/api/v2'

Route 'api': Match
  ✓ PathPrefix: Path '/api/users' starts with '/api'
  ✓ Method: Method 'GET' is in allowed list [GET, POST]

Route 'fallback': Skipped (lower priority)
```

### Configuration Linting

Beyond syntax validation, the linter catches logical issues:

- Routes without upstreams (unless static/builtin)
- References to undefined upstreams
- Duplicate route IDs
- Shadow config without body buffering
- WebSocket inspection without WebSocket enabled

## Limitations

The simulation has inherent limitations compared to the real proxy:

| Feature | Simulation | Real Proxy |
|---------|------------|------------|
| Connection counts | Hash-based estimate | Actual count |
| Latency metrics | Not available | Real-time |
| Token queues | Not available | Actual queue depth |
| Random selection | Deterministic (hash) | True random |
| Request bodies | Not simulated | Full inspection |
| State | None | Persistent |

## Minimum Rust Version

Rust 1.92.0 or later (Edition 2021)
