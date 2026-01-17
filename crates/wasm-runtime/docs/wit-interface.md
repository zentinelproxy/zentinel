# WIT Interface Specification

This document describes the WebAssembly Interface Types (WIT) specification that WASM agents must implement.

## Overview

Sentinel WASM agents implement the `sentinel:agent@2.0.0` world, which exports two interfaces:

- **handler**: Request/response processing functions
- **lifecycle**: Health check and shutdown

## World Definition

```wit
package sentinel:agent@2.0.0;

world agent {
    export handler;
    export lifecycle;
}
```

---

## Handler Interface

The `handler` interface contains all request processing functions.

### get-info

Returns agent capabilities and metadata. Called once when the agent is loaded.

```wit
get-info: func() -> agent-info;

record agent-info {
    agent-id: string,
    name: string,
    version: string,
    supported-events: list<string>,
    max-body-size: u64,
    supports-streaming: bool,
}
```

**Supported events:**
- `request_headers` - Inspect/modify request headers
- `request_body` - Inspect request body chunks
- `response_headers` - Inspect/modify response headers
- `response_body` - Inspect response body chunks

### configure

Initialize the agent with JSON configuration. Called once after `get-info`.

```wit
configure: func(config: string) -> result<_, string>;
```

- `config`: JSON string with agent-specific configuration
- Returns: `Ok(())` on success, `Err(message)` on failure

### on-request-headers

Process incoming request headers. Called for every request.

```wit
on-request-headers: func(
    metadata: request-metadata,
    method: string,
    uri: string,
    headers: list<header>
) -> agent-response;
```

**Arguments:**
- `metadata`: Request context (correlation ID, client IP, etc.)
- `method`: HTTP method (GET, POST, etc.)
- `uri`: Request URI path and query string
- `headers`: List of request headers

**Returns:** `agent-response` with decision and modifications

### on-request-body

Process request body chunks. Only called if agent declared streaming support.

```wit
on-request-body: func(
    correlation-id: string,
    data: list<u8>,
    chunk-index: u32,
    is-last: bool
) -> agent-response;
```

**Arguments:**
- `correlation-id`: Links to the original request
- `data`: Raw body bytes
- `chunk-index`: Chunk sequence number (0-based)
- `is-last`: True if this is the final chunk

### on-response-headers

Process response headers from upstream.

```wit
on-response-headers: func(
    correlation-id: string,
    status: u16,
    headers: list<header>
) -> agent-response;
```

### on-response-body

Process response body chunks.

```wit
on-response-body: func(
    correlation-id: string,
    data: list<u8>,
    chunk-index: u32,
    is-last: bool
) -> agent-response;
```

---

## Lifecycle Interface

### health-check

Health check called periodically by the runtime.

```wit
health-check: func() -> result<string, string>;
```

- Returns: `Ok("healthy")` or `Err(error_message)`

### shutdown

Graceful shutdown notification. Called when the agent is being unloaded.

```wit
shutdown: func();
```

---

## Type Definitions

### request-metadata

Context about the incoming request:

```wit
record request-metadata {
    correlation-id: string,      // Unique request tracking ID
    request-id: string,          // Internal request identifier
    client-ip: string,           // Client IP address
    client-port: u16,            // Client port number
    server-name: option<string>, // SNI or Host header
    protocol: string,            // HTTP/1.1, HTTP/2, etc.
    tls-version: option<string>, // TLSv1.2, TLSv1.3, etc.
    route-id: option<string>,    // Matched route ID
    upstream-id: option<string>, // Selected upstream ID
    timestamp-ms: u64,           // Unix timestamp in milliseconds
    traceparent: option<string>, // W3C Trace Context header
}
```

### header

Simple name-value pair:

```wit
record header {
    name: string,
    value: string,
}
```

### decision

The agent's decision for the request:

```wit
variant decision {
    allow,                       // Continue to upstream
    block(block-params),         // Return error response
    redirect(redirect-params),   // Redirect client
}

record block-params {
    status: u16,                 // HTTP status code (e.g., 403)
    body: option<string>,        // Response body
    headers: list<header>,       // Response headers
}

record redirect-params {
    url: string,                 // Redirect URL
    status: u16,                 // 301, 302, 307, or 308
}
```

### header-op

Header modification operations:

```wit
variant header-op {
    set(header),    // Replace header value
    add(header),    // Append header value
    remove(string), // Remove header by name
}
```

### agent-response

Complete response from the agent:

```wit
record agent-response {
    decision: decision,
    request-headers: list<header-op>,   // Request header modifications
    response-headers: list<header-op>,  // Response header modifications
    audit: audit-metadata,
    needs-more: bool,                   // For streaming: need more data
}

record audit-metadata {
    tags: list<string>,          // Searchable tags
    rule-ids: list<string>,      // Matched rule IDs
    confidence: option<f32>,     // Confidence score (0.0-1.0)
    reason-codes: list<string>,  // Machine-readable reason codes
}
```

---

## Example Implementation (Rust)

```rust
use sentinel_agent_wit::exports::sentinel::agent::{handler, lifecycle};
use sentinel_agent_wit::sentinel::agent::types::*;

struct MyAgent {
    config: MyConfig,
}

impl handler::Guest for MyAgent {
    fn get_info() -> AgentInfo {
        AgentInfo {
            agent_id: "my-agent".to_string(),
            name: "My Custom Agent".to_string(),
            version: "1.0.0".to_string(),
            supported_events: vec!["request_headers".to_string()],
            max_body_size: 0,
            supports_streaming: false,
        }
    }

    fn configure(config: String) -> Result<(), String> {
        // Parse JSON config
        let config: MyConfig = serde_json::from_str(&config)
            .map_err(|e| e.to_string())?;
        // Store config...
        Ok(())
    }

    fn on_request_headers(
        metadata: RequestMetadata,
        method: String,
        uri: String,
        headers: Vec<Header>,
    ) -> AgentResponse {
        // Check authorization
        let has_auth = headers.iter()
            .any(|h| h.name.eq_ignore_ascii_case("authorization"));

        if !has_auth {
            return AgentResponse {
                decision: Decision::Block(BlockParams {
                    status: 401,
                    body: Some("Unauthorized".to_string()),
                    headers: vec![],
                }),
                request_headers: vec![],
                response_headers: vec![],
                audit: AuditMetadata {
                    tags: vec!["auth".to_string()],
                    rule_ids: vec!["AUTH-001".to_string()],
                    confidence: Some(1.0),
                    reason_codes: vec!["MISSING_AUTH".to_string()],
                },
                needs_more: false,
            };
        }

        AgentResponse {
            decision: Decision::Allow,
            request_headers: vec![
                HeaderOp::Set(Header {
                    name: "X-Validated".to_string(),
                    value: "true".to_string(),
                }),
            ],
            response_headers: vec![],
            audit: AuditMetadata::default(),
            needs_more: false,
        }
    }

    // ... other handler methods
}

impl lifecycle::Guest for MyAgent {
    fn health_check() -> Result<String, String> {
        Ok("healthy".to_string())
    }

    fn shutdown() {
        // Cleanup resources
    }
}
```

---

## WIT File Location

The WIT file is located at:
```
crates/wasm-runtime/wit/sentinel-agent.wit
```

This file is used by `wasmtime::component::bindgen!` to generate Rust bindings.
