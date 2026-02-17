# Zentinel Playground WASM

WebAssembly bindings for the Zentinel configuration playground.

## Overview

The `zentinel-playground-wasm` crate provides JavaScript-friendly bindings for the Zentinel configuration simulator. It enables in-browser configuration validation and route decision tracing without running the actual proxy.

**Key Features:**

- **Browser-Ready** - Compiles to WASM for browser environments
- **Zero Dependencies** - No server or runtime required
- **Full Simulation** - Validate configs and trace routing decisions
- **TypeScript-Friendly** - Returns structured JSON objects

## Installation

### Build from Source

```bash
# Install wasm-pack if needed
cargo install wasm-pack

# Build the WASM package
wasm-pack build --target web crates/playground-wasm
```

### Output

The build produces files in `pkg/`:

```
pkg/
├── zentinel_playground_wasm.js      # ES module loader
├── zentinel_playground_wasm_bg.wasm # WASM binary
├── zentinel_playground_wasm.d.ts    # TypeScript definitions
└── package.json                     # npm package manifest
```

## Quick Start

```javascript
import init, { validate, simulate, get_version } from './pkg/zentinel_playground_wasm.js';

async function main() {
    // Initialize the WASM module
    await init();

    console.log("Version:", get_version());

    // Validate a configuration
    const config = `
        server { }
        listeners {
            listener "http" {
                address "0.0.0.0:8080"
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
        upstreams {
            upstream "backend" {
                target "127.0.0.1:3000"
            }
        }
    `;

    const result = validate(config);

    if (result.valid) {
        console.log("Configuration is valid!");

        // Simulate a request
        const decision = simulate(config, JSON.stringify({
            method: "GET",
            host: "example.com",
            path: "/api/users",
            headers: {},
            query_params: {}
        }));

        console.log("Matched route:", decision.matched_route);
    } else {
        console.error("Validation errors:", result.errors);
    }
}

main();
```

## API Reference

### `get_version()`

Returns the version of the WASM module.

```javascript
const version = get_version();
// "0.2.3"
```

### `validate(config_kdl)`

Validates a KDL configuration string.

**Parameters:**
- `config_kdl` - KDL configuration as a string

**Returns:**

```typescript
interface ValidationResult {
    valid: boolean;
    errors: Array<{
        message: string;
        severity: string;
        line?: number;
        column?: number;
        hint?: string;
    }>;
    warnings: Array<{
        code: string;
        message: string;
    }>;
    effective_config?: object;  // Only present if valid
}
```

**Example:**

```javascript
const result = validate(`
    server { }
    listeners {
        listener "http" {
            address "0.0.0.0:8080"
        }
    }
`);

if (!result.valid) {
    for (const error of result.errors) {
        console.error(`Line ${error.line}: ${error.message}`);
        if (error.hint) {
            console.log(`  Hint: ${error.hint}`);
        }
    }
}
```

### `simulate(config_kdl, request_json)`

Simulates routing a request through the configuration.

**Parameters:**
- `config_kdl` - KDL configuration string
- `request_json` - JSON string representing the request

**Request Format:**

```typescript
interface SimulatedRequest {
    method: string;         // "GET", "POST", etc.
    host: string;           // "example.com"
    path: string;           // "/api/users"
    headers: Record<string, string>;
    query_params: Record<string, string>;
}
```

**Returns:**

```typescript
interface RouteDecision {
    matched_route?: {
        route_id: string;
        priority: string;
        service_type: string;
        upstream_id?: string;
    };
    match_trace: Array<{
        route_id: string;
        result: "Match" | "NoMatch" | "Skipped";
        reason: string;
        condition_details: Array<{
            condition_type: string;
            pattern: string;
            matched: boolean;
            explanation?: string;
        }>;
    }>;
    upstream_selection?: {
        upstream_id: string;
        selected_target: string;
        load_balancer: string;
        selection_reason: string;
    };
    applied_policies?: object;
    agent_hooks: Array<object>;
    warnings: Array<object>;
}
```

**Example:**

```javascript
const decision = simulate(config, JSON.stringify({
    method: "POST",
    host: "api.example.com",
    path: "/api/users",
    headers: {
        "content-type": "application/json",
        "authorization": "Bearer token123"
    },
    query_params: {}
}));

if (decision.matched_route) {
    console.log(`Route: ${decision.matched_route.route_id}`);
    console.log(`Upstream: ${decision.upstream_selection?.selected_target}`);
} else {
    console.log("No route matched");
    for (const step of decision.match_trace) {
        console.log(`  ${step.route_id}: ${step.reason}`);
    }
}
```

### `get_normalized_config(config_kdl)`

Returns the configuration with all defaults applied.

**Parameters:**
- `config_kdl` - KDL configuration string

**Returns:** JSON object with the normalized configuration, or error details if invalid.

**Example:**

```javascript
const normalized = get_normalized_config(config);
console.log(JSON.stringify(normalized, null, 2));
```

### `create_sample_request(method, host, path)`

Creates a sample request object for testing.

**Parameters:**
- `method` - HTTP method
- `host` - Request host
- `path` - Request path

**Returns:** JSON object suitable for `simulate()`.

**Example:**

```javascript
const request = create_sample_request("GET", "example.com", "/api/users");
// { method: "GET", host: "example.com", path: "/api/users", headers: {}, query_params: {} }
```

## HTML Integration

```html
<!DOCTYPE html>
<html>
<head>
    <title>Zentinel Playground</title>
</head>
<body>
    <textarea id="config"></textarea>
    <button onclick="validateConfig()">Validate</button>
    <pre id="output"></pre>

    <script type="module">
        import init, { validate, simulate } from './pkg/zentinel_playground_wasm.js';

        await init();

        window.validateConfig = function() {
            const config = document.getElementById('config').value;
            const result = validate(config);
            document.getElementById('output').textContent =
                JSON.stringify(result, null, 2);
        };
    </script>
</body>
</html>
```

## Build Options

### Development Build

```bash
wasm-pack build --target web --dev crates/playground-wasm
```

### Release Build (Optimized)

```bash
wasm-pack build --target web --release crates/playground-wasm
```

The release build uses:
- `opt-level = "s"` - Size optimization
- `lto = true` - Link-time optimization

### Target Options

| Target | Use Case |
|--------|----------|
| `web` | ES modules for browsers |
| `bundler` | For webpack/rollup bundlers |
| `nodejs` | Node.js environments |
| `no-modules` | No ES module support |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `console_error_panic_hook` | Yes | Better error messages in browser console |

## Error Handling

Both `validate()` and `simulate()` return structured error information:

```javascript
const decision = simulate(invalidConfig, requestJson);

if (decision.error) {
    console.error("Simulation failed:", decision.error);
    for (const detail of decision.details) {
        console.error("  -", detail);
    }
}
```

## Minimum Rust Version

Rust 1.92.0 or later (Edition 2021)
