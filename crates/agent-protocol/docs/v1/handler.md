# Agent Handler Interface

The `AgentHandler` trait defines the interface for implementing external processing agents. This document covers all hook methods and their semantics.

## The AgentHandler Trait

```rust
#[async_trait]
pub trait AgentHandler: Send + Sync {
    async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse;
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse;
    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse;
    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse;
    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse;
    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse;
    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse;
    async fn on_guardrail_inspect(&self, event: GuardrailInspectEvent) -> AgentResponse;
}
```

All methods have default implementations that return `AgentResponse::default_allow()`. Override only the methods you need.

## Hook Methods

### on_configure

```rust
async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse
```

**When called**: Once when a connection is established between proxy and agent.

**Purpose**: Capability negotiation and configuration exchange.

**Event fields**:
- `agent_name`: Name of the connecting agent
- `supported_events`: List of event types the agent wants to receive
- `max_body_size`: Maximum body size the agent can handle
- `timeout_ms`: Suggested timeout for agent responses

**Typical uses**:
- Register agent capabilities
- Initialize per-connection state
- Validate configuration

**Example**:
```rust
async fn on_configure(&self, event: ConfigureEvent) -> AgentResponse {
    tracing::info!("Agent {} connected", event.agent_name);
    AgentResponse::default_allow()
}
```

### on_request_headers

```rust
async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse
```

**When called**: When HTTP request headers have been fully received.

**Purpose**: Early request inspection, authentication, routing decisions.

**Event fields**:
- `metadata`: Request metadata (client IP, route ID, timestamps, etc.)
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `uri`: Request URI including path and query string
- `headers`: HTTP request headers as key-value pairs

**Typical uses**:
- Authentication and authorization
- IP-based blocking
- Path-based access control
- Request header validation
- Adding tracing headers

**Example**:
```rust
async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
    // Block requests without auth header
    if !event.headers.contains_key("authorization") {
        return AgentResponse::block(401, "Unauthorized");
    }

    // Add processing header
    let mut response = AgentResponse::default_allow();
    response.request_headers.push(HeaderOp::Set {
        name: "X-Authenticated".to_string(),
        value: "true".to_string(),
    });
    response
}
```

### on_request_body_chunk

```rust
async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse
```

**When called**: For each chunk of the request body as it streams through.

**Purpose**: Body inspection, transformation, or blocking based on content.

**Event fields**:
- `metadata`: Request metadata
- `chunk_index`: Zero-based index of this chunk
- `data`: Raw body bytes
- `is_last`: `true` if this is the final chunk

**Response considerations**:
- Use `needs_more: true` to buffer chunks before making a decision
- Use `BodyMutation` to modify, drop, or pass through chunks

**Typical uses**:
- WAF body inspection (SQL injection, XSS, etc.)
- Content type validation
- Body size enforcement
- Sensitive data redaction

**Example**:
```rust
async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
    // Check for SQL injection patterns
    let body_str = String::from_utf8_lossy(&event.data);
    if body_str.contains("DROP TABLE") {
        return AgentResponse::block(400, "Invalid request");
    }

    // Pass through unchanged
    AgentResponse::default_allow()
        .with_request_body_mutation(BodyMutation::pass_through(event.chunk_index))
}
```

### on_response_headers

```rust
async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse
```

**When called**: When response headers are received from the upstream.

**Purpose**: Response header inspection and modification.

**Event fields**:
- `metadata`: Request metadata
- `status_code`: HTTP status code from upstream
- `headers`: Response headers

**Typical uses**:
- Security header injection (CSP, HSTS, X-Frame-Options)
- Header sanitization
- Response caching decisions
- Upstream error handling

**Example**:
```rust
async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
    let mut response = AgentResponse::default_allow();

    // Add security headers
    response.response_headers.push(HeaderOp::Set {
        name: "X-Content-Type-Options".to_string(),
        value: "nosniff".to_string(),
    });
    response.response_headers.push(HeaderOp::Set {
        name: "X-Frame-Options".to_string(),
        value: "DENY".to_string(),
    });

    response
}
```

### on_response_body_chunk

```rust
async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse
```

**When called**: For each chunk of the response body.

**Purpose**: Response body inspection and transformation.

**Event fields**:
- `metadata`: Request metadata
- `chunk_index`: Zero-based index of this chunk
- `data`: Raw body bytes
- `is_last`: `true` if this is the final chunk

**Typical uses**:
- Data loss prevention (DLP)
- Response body transformation
- Content filtering
- Sensitive data masking

**Example**:
```rust
async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
    let mut body = String::from_utf8_lossy(&event.data).to_string();

    // Mask credit card numbers (simplified example)
    body = body.replace(r"\d{16}", "****-****-****-****");

    AgentResponse::default_allow()
        .with_response_body_mutation(BodyMutation::replace(event.chunk_index, body))
}
```

### on_request_complete

```rust
async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse
```

**When called**: After the request has been fully processed.

**Purpose**: Logging, metrics, cleanup.

**Event fields**:
- `metadata`: Request metadata
- `status_code`: Final response status code
- `duration_ms`: Total request processing time
- `bytes_sent`: Total bytes sent to client
- `bytes_received`: Total bytes received from client

**Typical uses**:
- Access logging
- Metrics collection
- State cleanup
- Alerting on anomalies

**Example**:
```rust
async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
    tracing::info!(
        correlation_id = %event.metadata.correlation_id,
        status = event.status_code,
        duration_ms = event.duration_ms,
        "Request completed"
    );
    AgentResponse::default_allow()
}
```

### on_websocket_frame

```rust
async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse
```

**When called**: When a WebSocket frame is received (after upgrade).

**Purpose**: WebSocket message filtering and inspection.

**Event fields**:
- `metadata`: Request metadata
- `opcode`: Frame type (Text, Binary, Close, Ping, Pong, Continuation)
- `payload`: Frame payload bytes
- `is_masked`: Whether the frame is masked
- `is_final`: Whether this is the final fragment

**Response considerations**:
- Use `websocket_decision` field to allow, drop, or close the connection

**Typical uses**:
- Message content filtering
- Rate limiting messages
- Connection termination on policy violation

**Example**:
```rust
async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
    if event.opcode == WebSocketOpcode::Text {
        let text = String::from_utf8_lossy(&event.payload);
        if text.contains("forbidden") {
            let mut response = AgentResponse::default_allow();
            response.websocket_decision = Some(WebSocketDecision::Close {
                code: 1008,  // Policy violation
                reason: "Forbidden content".to_string(),
            });
            return response;
        }
    }
    AgentResponse::default_allow()
}
```

### on_guardrail_inspect

```rust
async fn on_guardrail_inspect(&self, event: GuardrailInspectEvent) -> AgentResponse
```

**When called**: When content needs to be inspected for AI guardrail policies.

**Purpose**: Prompt injection detection, PII detection, content safety.

**Event fields**:
- `metadata`: Request metadata
- `inspection_type`: Type of inspection (PromptInjection, PiiDetection)
- `content`: The content to inspect
- `context`: Optional additional context

**Response considerations**:
- Set `guardrail_response` with detection results

**Typical uses**:
- Prompt injection detection for LLM APIs
- PII detection and redaction
- Content moderation

**Example**:
```rust
async fn on_guardrail_inspect(&self, event: GuardrailInspectEvent) -> AgentResponse {
    let mut detections = Vec::new();

    if event.inspection_type == GuardrailInspectionType::PromptInjection {
        // Simple pattern-based detection (use ML models in production)
        if event.content.to_lowercase().contains("ignore previous instructions") {
            detections.push(GuardrailDetection {
                detection_type: "prompt_injection".to_string(),
                severity: DetectionSeverity::High,
                description: "Potential prompt injection attempt".to_string(),
                spans: vec![],
            });
        }
    }

    let mut response = AgentResponse::default_allow();
    response.guardrail_response = Some(GuardrailResponse {
        is_safe: detections.is_empty(),
        detections,
    });
    response
}
```

## Default Implementations

All methods have sensible defaults:

```rust
async fn on_configure(&self, _: ConfigureEvent) -> AgentResponse {
    AgentResponse::default_allow()
}

async fn on_request_headers(&self, _: RequestHeadersEvent) -> AgentResponse {
    AgentResponse::default_allow()
}

// ... and so on for all methods
```

Override only the methods relevant to your use case.

## Thread Safety

The `AgentHandler` trait requires `Send + Sync`:

- `Send`: The handler can be transferred across thread boundaries
- `Sync`: The handler can be shared between threads

Use interior mutability patterns (e.g., `Arc<Mutex<_>>`) if you need mutable state:

```rust
struct StatefulAgent {
    request_count: Arc<AtomicU64>,
}

#[async_trait]
impl AgentHandler for StatefulAgent {
    async fn on_request_headers(&self, _: RequestHeadersEvent) -> AgentResponse {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        AgentResponse::default_allow()
    }
}
```

## Best Practices

1. **Keep handlers fast**: The proxy waits for agent responses. Long-running operations add latency.

2. **Handle errors gracefully**: Return `AgentResponse::default_allow()` if uncertain rather than panicking.

3. **Log with correlation IDs**: Always include `metadata.correlation_id` in logs for tracing.

4. **Respect timeouts**: Agent operations should complete well within configured timeouts.

5. **Be stateless when possible**: Prefer stateless handlers for easier scaling.

6. **Use structured audit data**: Populate `AuditMetadata` for observability.
