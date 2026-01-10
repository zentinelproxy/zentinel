# Client & Server APIs

This document covers the `AgentClient` and `AgentServer` APIs for building agent integrations.

## AgentClient

The `AgentClient` is used by the proxy dataplane to communicate with external agents.

### Creating a Client

#### Unix Domain Socket

```rust
use sentinel_agent_protocol::AgentClient;
use std::time::Duration;

let client = AgentClient::unix_socket(
    "proxy-client",           // Client name (for logging)
    "/tmp/agent.sock",        // Socket path
    Duration::from_secs(5),   // Timeout per request
).await?;
```

#### gRPC

```rust
use sentinel_agent_protocol::AgentClient;
use std::time::Duration;

let client = AgentClient::grpc(
    "proxy-client",               // Client name
    "http://localhost:50051",     // gRPC endpoint
    Duration::from_secs(5),       // Timeout per request
).await?;
```

### Sending Events

```rust
use sentinel_agent_protocol::{EventType, RequestHeadersEvent, RequestMetadata};
use std::collections::HashMap;

// Build the event
let event = RequestHeadersEvent {
    metadata: RequestMetadata {
        correlation_id: "corr-123".to_string(),
        request_id: "req-456".to_string(),
        client_ip: "192.168.1.1".to_string(),
        client_port: 54321,
        server_name: Some("api.example.com".to_string()),
        protocol: "HTTP/2".to_string(),
        tls_version: Some("TLSv1.3".to_string()),
        tls_cipher: Some("TLS_AES_256_GCM_SHA384".to_string()),
        route_id: Some("api-route".to_string()),
        upstream_id: Some("api-backend".to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
        traceparent: None,
    },
    method: "POST".to_string(),
    uri: "/api/users".to_string(),
    headers: HashMap::from([
        ("content-type".to_string(), "application/json".to_string()),
        ("authorization".to_string(), "Bearer token123".to_string()),
    ]),
};

// Send and get response
let response = client.send_event(EventType::RequestHeaders, &event).await?;

// Handle the decision
match response.decision {
    Decision::Allow => {
        // Apply header mutations and continue
    }
    Decision::Block { status, body, .. } => {
        // Return error response to client
    }
    Decision::Redirect { url, status } => {
        // Redirect the client
    }
    Decision::Challenge { challenge_type, params } => {
        // Issue challenge
    }
}
```

### Closing the Connection

```rust
client.close().await?;
```

### Client Methods

| Method | Description |
|--------|-------------|
| `unix_socket(name, path, timeout)` | Create client with Unix socket transport |
| `grpc(name, endpoint, timeout)` | Create client with gRPC transport |
| `send_event(event_type, payload)` | Send event and wait for response |
| `close()` | Close the connection gracefully |

## AgentServer

The `AgentServer` runs an agent handler and accepts connections from the proxy.

### Creating a Server (Unix Socket)

```rust
use sentinel_agent_protocol::{AgentServer, AgentHandler, AgentResponse, RequestHeadersEvent};
use async_trait::async_trait;

struct MyAgent;

#[async_trait]
impl AgentHandler for MyAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Your logic here
        AgentResponse::default_allow()
    }
}

let server = AgentServer::new(
    "my-agent",              // Agent name
    "/tmp/my-agent.sock",    // Socket path
    Box::new(MyAgent),       // Handler implementation
);

// Run the server (blocks until shutdown)
server.run().await?;
```

### Creating a gRPC Server

```rust
use sentinel_agent_protocol::{GrpcAgentServer, AgentHandler};

struct MyAgent;
// ... implement AgentHandler ...

let server = GrpcAgentServer::new(
    "my-agent",
    "[::1]:50051",           // gRPC listen address
    Box::new(MyAgent),
);

server.run().await?;
```

### Server Methods

| Method | Description |
|--------|-------------|
| `new(name, path/addr, handler)` | Create a new server |
| `run()` | Start accepting connections (blocking) |

## AgentResponse Builders

The `AgentResponse` struct provides convenient builder methods:

### Creating Responses

```rust
use sentinel_agent_protocol::{AgentResponse, Decision, HeaderOp, BodyMutation};

// Allow with no modifications
let response = AgentResponse::default_allow();

// Block with status code and message
let response = AgentResponse::block(403, "Access denied");

// Redirect
let response = AgentResponse::redirect("https://login.example.com", 302);

// Allow with header modifications
let mut response = AgentResponse::default_allow();
response.request_headers.push(HeaderOp::Set {
    name: "X-Request-ID".to_string(),
    value: "abc123".to_string(),
});

// Allow with body mutation
let response = AgentResponse::default_allow()
    .with_request_body_mutation(BodyMutation::pass_through(0));

// Request more data (for streaming)
let response = AgentResponse::needs_more_data();
```

### Response Builder Methods

| Method | Description |
|--------|-------------|
| `default_allow()` | Create an Allow response with no modifications |
| `block(status, body)` | Create a Block response |
| `redirect(url, status)` | Create a Redirect response |
| `needs_more_data()` | Create response requesting more body chunks |
| `with_request_body_mutation(mutation)` | Add request body mutation |
| `with_response_body_mutation(mutation)` | Add response body mutation |
| `set_needs_more(bool)` | Set the needs_more flag |

## Header Operations

```rust
use sentinel_agent_protocol::HeaderOp;

// Set or overwrite a header
let op = HeaderOp::Set {
    name: "X-Custom-Header".to_string(),
    value: "custom-value".to_string(),
};

// Add a header (allows duplicates)
let op = HeaderOp::Add {
    name: "Set-Cookie".to_string(),
    value: "session=abc123".to_string(),
};

// Remove a header
let op = HeaderOp::Remove {
    name: "X-Unwanted".to_string(),
};
```

## Body Mutations

```rust
use sentinel_agent_protocol::BodyMutation;

// Pass chunk through unchanged
let mutation = BodyMutation::pass_through(chunk_index);

// Drop the chunk entirely
let mutation = BodyMutation::drop_chunk(chunk_index);

// Replace chunk content
let mutation = BodyMutation::replace(chunk_index, "new content".to_string());

// Check mutation type
assert!(mutation.is_pass_through());
assert!(mutation.is_drop());
```

## Audit Metadata

Add structured audit data for logging and metrics:

```rust
use sentinel_agent_protocol::AuditMetadata;
use std::collections::HashMap;

let audit = AuditMetadata {
    tags: vec!["waf".to_string(), "sqli".to_string()],
    rule_ids: vec!["942100".to_string()],
    confidence: Some(0.95),
    reason_codes: vec!["SQL_INJECTION_DETECTED".to_string()],
    extra: HashMap::from([
        ("matched_pattern".to_string(), "SELECT.*FROM".to_string()),
    ]),
};

let mut response = AgentResponse::block(403, "Blocked by WAF");
response.audit = Some(audit);
```

## Connection Lifecycle

### Unix Socket

```
Proxy                                 Agent
  │                                     │
  │  ─────── Connect to socket ───────► │
  │                                     │
  │  ◄────── Accept connection ──────── │
  │                                     │
  │  ─────── Configure event ─────────► │
  │  ◄────── Configure response ─────── │
  │                                     │
  │  ─────── RequestHeaders ──────────► │
  │  ◄────── Decision + mutations ───── │
  │                                     │
  │  ─────── RequestBodyChunk ────────► │
  │  ◄────── Body mutation ──────────── │
  │                                     │
  │            ... more events ...      │
  │                                     │
  │  ─────── RequestComplete ─────────► │
  │  ◄────── Ack ────────────────────── │
  │                                     │
  │  ─────── Close ───────────────────► │
  │                                     │
```

### gRPC

Similar flow but uses HTTP/2 with Protocol Buffers encoding. Supports both unary RPC (`ProcessEvent`) and bidirectional streaming (`ProcessEventStream`).

## Concurrency

### Client

The `AgentClient` is designed for single-threaded use per connection. For concurrent requests, create multiple clients or use connection pooling:

```rust
use tokio::sync::Semaphore;
use std::sync::Arc;

struct AgentPool {
    clients: Vec<Arc<tokio::sync::Mutex<AgentClient>>>,
    semaphore: Semaphore,
}
```

### Server

The `AgentServer` handles multiple concurrent connections. Each connection is processed independently:

```rust
// Handler must be Send + Sync for concurrent access
let handler: Box<dyn AgentHandler> = Box::new(MyAgent);
let server = AgentServer::new("agent", "/tmp/agent.sock", handler);
```

## Timeout Handling

Timeouts are enforced at the client level:

```rust
let client = AgentClient::unix_socket(
    "proxy",
    "/tmp/agent.sock",
    Duration::from_millis(100),  // 100ms timeout
).await?;

// This will return Err(AgentProtocolError::Timeout) if agent doesn't respond in 100ms
let result = client.send_event(EventType::RequestHeaders, &event).await;
```

Configure appropriate timeouts based on your latency requirements:
- WAF inspection: 10-50ms typical
- Auth lookups: 50-200ms typical
- External API calls: 500-2000ms typical
