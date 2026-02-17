# Building WASM Agents

This guide covers how to build WebAssembly agents for Zentinel.

## Prerequisites

- Rust 1.92+ with `wasm32-wasip2` target
- `wasm-tools` for component creation
- The Zentinel WIT interface file

```bash
# Add WASM target
rustup target add wasm32-wasip2

# Install wasm-tools
cargo install wasm-tools
```

## Project Setup

### 1. Create a New Crate

```bash
cargo new --lib my-zentinel-agent
cd my-zentinel-agent
```

### 2. Configure Cargo.toml

```toml
[package]
name = "my-zentinel-agent"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
# WIT bindings generator
wit-bindgen = "0.36"

# Optional: for JSON parsing
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[profile.release]
opt-level = "s"      # Optimize for size
lto = true           # Link-time optimization
strip = true         # Strip symbols
```

### 3. Add the WIT File

Copy `zentinel-agent.wit` to your project:

```bash
mkdir wit
cp /path/to/zentinel/crates/wasm-runtime/wit/zentinel-agent.wit wit/
```

### 4. Generate Bindings

In `src/lib.rs`:

```rust
wit_bindgen::generate!({
    path: "wit/zentinel-agent.wit",
    world: "agent",
});
```

## Implementing the Agent

### Basic Structure

```rust
wit_bindgen::generate!({
    path: "wit/zentinel-agent.wit",
    world: "agent",
});

use exports::zentinel::agent::{handler, lifecycle};
use zentinel::agent::types::*;

struct MyAgent;

impl handler::Guest for MyAgent {
    fn get_info() -> AgentInfo {
        AgentInfo {
            agent_id: "my-agent".to_string(),
            name: "My Custom Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec!["request_headers".to_string()],
            max_body_size: 0,
            supports_streaming: false,
        }
    }

    fn configure(config: String) -> Result<(), String> {
        // Parse and validate configuration
        Ok(())
    }

    fn on_request_headers(
        metadata: RequestMetadata,
        method: String,
        uri: String,
        headers: Vec<Header>,
    ) -> AgentResponse {
        // Your logic here
        allow_response()
    }

    fn on_request_body(
        correlation_id: String,
        data: Vec<u8>,
        chunk_index: u32,
        is_last: bool,
    ) -> AgentResponse {
        allow_response()
    }

    fn on_response_headers(
        correlation_id: String,
        status: u16,
        headers: Vec<Header>,
    ) -> AgentResponse {
        allow_response()
    }

    fn on_response_body(
        correlation_id: String,
        data: Vec<u8>,
        chunk_index: u32,
        is_last: bool,
    ) -> AgentResponse {
        allow_response()
    }
}

impl lifecycle::Guest for MyAgent {
    fn health_check() -> Result<String, String> {
        Ok("healthy".to_string())
    }

    fn shutdown() {}
}

// Export the component
export!(MyAgent);

// Helper function
fn allow_response() -> AgentResponse {
    AgentResponse {
        decision: Decision::Allow,
        request_headers: vec![],
        response_headers: vec![],
        audit: AuditMetadata {
            tags: vec![],
            rule_ids: vec![],
            confidence: None,
            reason_codes: vec![],
        },
        needs_more: false,
    }
}
```

## Building the Component

### 1. Build the WASM Module

```bash
cargo build --release --target wasm32-wasip2
```

### 2. Create Component (if needed)

If your toolchain doesn't produce a component directly:

```bash
wasm-tools component new \
    target/wasm32-wasip2/release/my_zentinel_agent.wasm \
    -o my-agent.wasm
```

### 3. Validate the Component

```bash
wasm-tools validate my-agent.wasm
wasm-tools component wit my-agent.wasm
```

## Example Agents

### IP Allowlist Agent

```rust
use std::collections::HashSet;
use std::sync::OnceLock;

static ALLOWED_IPS: OnceLock<HashSet<String>> = OnceLock::new();

impl handler::Guest for IpAllowlistAgent {
    fn configure(config: String) -> Result<(), String> {
        #[derive(serde::Deserialize)]
        struct Config {
            allowed_ips: Vec<String>,
        }

        let cfg: Config = serde_json::from_str(&config)
            .map_err(|e| e.to_string())?;

        ALLOWED_IPS.set(cfg.allowed_ips.into_iter().collect())
            .map_err(|_| "already configured")?;

        Ok(())
    }

    fn on_request_headers(
        metadata: RequestMetadata,
        _method: String,
        _uri: String,
        _headers: Vec<Header>,
    ) -> AgentResponse {
        let allowed = ALLOWED_IPS.get()
            .map(|ips| ips.contains(&metadata.client_ip))
            .unwrap_or(false);

        if allowed {
            allow_response()
        } else {
            AgentResponse {
                decision: Decision::Block(BlockParams {
                    status: 403,
                    body: Some("IP not allowed".to_string()),
                    headers: vec![],
                }),
                audit: AuditMetadata {
                    tags: vec!["security".to_string()],
                    rule_ids: vec!["IP-DENY".to_string()],
                    confidence: Some(1.0),
                    reason_codes: vec!["IP_NOT_ALLOWED".to_string()],
                },
                ..Default::default()
            }
        }
    }
}
```

### Header Validation Agent

```rust
impl handler::Guest for HeaderValidatorAgent {
    fn on_request_headers(
        _metadata: RequestMetadata,
        _method: String,
        _uri: String,
        headers: Vec<Header>,
    ) -> AgentResponse {
        // Check for required headers
        let has_request_id = headers.iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-request-id"));

        if !has_request_id {
            // Add missing header
            return AgentResponse {
                decision: Decision::Allow,
                request_headers: vec![
                    HeaderOp::Set(Header {
                        name: "X-Request-ID".to_string(),
                        value: generate_request_id(),
                    }),
                ],
                ..Default::default()
            };
        }

        allow_response()
    }
}
```

## Testing Locally

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowed_ip() {
        // Configure
        let config = r#"{"allowed_ips": ["192.168.1.1"]}"#;
        IpAllowlistAgent::configure(config.to_string()).unwrap();

        // Test
        let metadata = RequestMetadata {
            client_ip: "192.168.1.1".to_string(),
            ..Default::default()
        };

        let response = IpAllowlistAgent::on_request_headers(
            metadata, "GET".to_string(), "/".to_string(), vec![]
        );

        assert!(matches!(response.decision, Decision::Allow));
    }
}
```

### Integration Testing

Use Zentinel's test harness:

```rust
use zentinel_wasm_runtime::{WasmAgentRuntime, WasmAgentConfig};

#[test]
fn test_agent_integration() {
    let runtime = WasmAgentRuntime::new(WasmAgentConfig::minimal()).unwrap();

    let wasm_bytes = include_bytes!("../target/wasm32-wasip2/release/my_agent.wasm");
    let agent = runtime.load_agent_from_bytes(
        "test-agent",
        wasm_bytes,
        r#"{"allowed_ips": ["127.0.0.1"]}"#,
    ).unwrap();

    let metadata = RequestMetadata { /* ... */ };
    let response = agent.on_request_headers(&metadata, "GET", "/", &headers).unwrap();

    assert!(matches!(response.decision, Decision::Allow));
}
```

## Deployment

### 1. Package the Component

```bash
# Optimize size
wasm-opt -Os my-agent.wasm -o my-agent.opt.wasm

# Final size check
ls -lh my-agent.opt.wasm
```

### 2. Deploy to Zentinel

```kdl
agents {
    wasm-agent "my-agent" {
        component "/opt/zentinel/agents/my-agent.opt.wasm"
        config {
            allowed-ips "192.168.0.0/16" "10.0.0.0/8"
        }
    }
}
```

## Best Practices

### Performance

1. **Minimize allocations** - Reuse buffers where possible
2. **Avoid complex regex** - Use simple string matching when possible
3. **Keep state small** - Large state increases memory footprint
4. **Use early returns** - Exit quickly for allowed requests

### Security

1. **Validate all input** - Don't trust header values
2. **Bound iterations** - Limit loops to prevent fuel exhaustion
3. **Handle errors gracefully** - Don't panic on invalid input
4. **Log decisions** - Use audit metadata for traceability

### Size Optimization

```toml
[profile.release]
opt-level = "z"      # Optimize for size
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## Troubleshooting

### Component Validation Errors

```bash
# Check component structure
wasm-tools component wit my-agent.wasm

# Verify exports match WIT
wasm-tools print my-agent.wasm | grep -i export
```

### Runtime Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `FunctionNotFound` | Missing export | Implement all required functions |
| `ResourceLimit` | Fuel exhausted | Optimize code or increase limits |
| `Configuration` | Invalid config JSON | Validate JSON structure |
| `Instantiation` | Component incompatible | Rebuild with correct WIT version |
