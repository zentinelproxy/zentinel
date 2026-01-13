# Examples

This document provides practical examples and common patterns for implementing agents.

## Reference Implementations

### EchoAgent

A minimal agent that adds a header to all requests. Useful for testing connectivity.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, HeaderOp, RequestHeadersEvent,
};
use async_trait::async_trait;

pub struct EchoAgent;

#[async_trait]
impl AgentHandler for EchoAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        let mut response = AgentResponse::default_allow();
        response.request_headers.push(HeaderOp::Set {
            name: "X-Agent-Processed".to_string(),
            value: "true".to_string(),
        });
        response
    }
}
```

### DenylistAgent

Blocks requests matching configured paths or client IPs.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, RequestHeadersEvent,
};
use async_trait::async_trait;

pub struct DenylistAgent {
    blocked_paths: Vec<String>,
    blocked_ips: Vec<String>,
}

impl DenylistAgent {
    pub fn new(blocked_paths: Vec<String>, blocked_ips: Vec<String>) -> Self {
        Self { blocked_paths, blocked_ips }
    }
}

#[async_trait]
impl AgentHandler for DenylistAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Check blocked paths
        for path in &self.blocked_paths {
            if event.uri.starts_with(path) {
                let mut response = AgentResponse::block(403, "Forbidden");
                response.audit = Some(AuditMetadata {
                    tags: vec!["denylist".to_string()],
                    rule_ids: vec!["PATH_BLOCKED".to_string()],
                    confidence: Some(1.0),
                    reason_codes: vec![format!("path_match:{}", path)],
                    extra: Default::default(),
                });
                return response;
            }
        }

        // Check blocked IPs
        if self.blocked_ips.contains(&event.metadata.client_ip) {
            let mut response = AgentResponse::block(403, "Forbidden");
            response.audit = Some(AuditMetadata {
                tags: vec!["denylist".to_string()],
                rule_ids: vec!["IP_BLOCKED".to_string()],
                confidence: Some(1.0),
                reason_codes: vec![format!("ip_match:{}", event.metadata.client_ip)],
                extra: Default::default(),
            });
            return response;
        }

        AgentResponse::default_allow()
    }
}
```

## Common Patterns

### Authentication Agent

Validates JWT tokens and adds user identity headers.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, HeaderOp, RequestHeadersEvent,
};
use async_trait::async_trait;

pub struct AuthAgent {
    jwt_secret: String,
}

#[async_trait]
impl AgentHandler for AuthAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Extract Authorization header
        let auth_header = match event.headers.get("authorization") {
            Some(h) => h,
            None => return AgentResponse::block(401, "Missing Authorization header"),
        };

        // Parse Bearer token
        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return AgentResponse::block(401, "Invalid Authorization format"),
        };

        // Validate JWT (simplified - use a proper JWT library)
        match self.validate_jwt(token) {
            Ok(claims) => {
                let mut response = AgentResponse::default_allow();
                // Add user identity headers for upstream
                response.request_headers.push(HeaderOp::Set {
                    name: "X-User-ID".to_string(),
                    value: claims.sub,
                });
                response.request_headers.push(HeaderOp::Set {
                    name: "X-User-Roles".to_string(),
                    value: claims.roles.join(","),
                });
                // Remove the Authorization header (optional)
                response.request_headers.push(HeaderOp::Remove {
                    name: "Authorization".to_string(),
                });
                response
            }
            Err(e) => AgentResponse::block(401, &format!("Invalid token: {}", e)),
        }
    }
}

impl AuthAgent {
    fn validate_jwt(&self, _token: &str) -> Result<Claims, String> {
        // JWT validation logic here
        todo!()
    }
}

struct Claims {
    sub: String,
    roles: Vec<String>,
}
```

### Rate Limiting Agent

Simple in-memory rate limiter using token bucket.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, HeaderOp, RequestHeadersEvent,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimitAgent {
    limits: Mutex<HashMap<String, TokenBucket>>,
    requests_per_second: u32,
    burst_size: u32,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimitAgent {
    pub fn new(requests_per_second: u32, burst_size: u32) -> Self {
        Self {
            limits: Mutex::new(HashMap::new()),
            requests_per_second,
            burst_size,
        }
    }

    fn check_rate_limit(&self, client_ip: &str) -> bool {
        let mut limits = self.limits.lock().unwrap();
        let now = Instant::now();

        let bucket = limits.entry(client_ip.to_string()).or_insert(TokenBucket {
            tokens: self.burst_size as f64,
            last_update: now,
        });

        // Refill tokens based on elapsed time
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.requests_per_second as f64)
            .min(self.burst_size as f64);
        bucket.last_update = now;

        // Try to consume a token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[async_trait]
impl AgentHandler for RateLimitAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if self.check_rate_limit(&event.metadata.client_ip) {
            AgentResponse::default_allow()
        } else {
            let mut response = AgentResponse::block(429, "Too Many Requests");
            response.response_headers.push(HeaderOp::Set {
                name: "Retry-After".to_string(),
                value: "1".to_string(),
            });
            response
        }
    }
}
```

### Body Inspection Agent

Inspects request bodies for sensitive patterns.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AuditMetadata, BodyMutation,
    RequestBodyChunkEvent, RequestHeadersEvent,
};
use async_trait::async_trait;
use std::sync::Mutex;
use std::collections::HashMap;

pub struct BodyInspectionAgent {
    // Buffer body chunks per request for analysis
    buffers: Mutex<HashMap<String, Vec<u8>>>,
    max_buffer_size: usize,
}

impl BodyInspectionAgent {
    pub fn new(max_buffer_size: usize) -> Self {
        Self {
            buffers: Mutex::new(HashMap::new()),
            max_buffer_size,
        }
    }

    fn check_patterns(&self, body: &[u8]) -> Option<String> {
        let body_str = String::from_utf8_lossy(body);

        // Check for SQL injection patterns
        let sql_patterns = ["DROP TABLE", "DELETE FROM", "'; --", "1=1"];
        for pattern in sql_patterns {
            if body_str.to_uppercase().contains(pattern) {
                return Some(format!("SQL injection pattern: {}", pattern));
            }
        }

        // Check for XSS patterns
        let xss_patterns = ["<script>", "javascript:", "onerror="];
        for pattern in xss_patterns {
            if body_str.to_lowercase().contains(pattern) {
                return Some(format!("XSS pattern: {}", pattern));
            }
        }

        None
    }
}

#[async_trait]
impl AgentHandler for BodyInspectionAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Initialize buffer for this request
        let mut buffers = self.buffers.lock().unwrap();
        buffers.insert(event.metadata.correlation_id.clone(), Vec::new());
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        let correlation_id = &event.metadata.correlation_id;

        // Accumulate body chunks
        {
            let mut buffers = self.buffers.lock().unwrap();
            if let Some(buffer) = buffers.get_mut(correlation_id) {
                if buffer.len() + event.data.len() <= self.max_buffer_size {
                    buffer.extend_from_slice(&event.data);
                }
            }
        }

        // On last chunk, perform full inspection
        if event.is_last {
            let buffers = self.buffers.lock().unwrap();
            if let Some(buffer) = buffers.get(correlation_id) {
                if let Some(reason) = self.check_patterns(buffer) {
                    let mut response = AgentResponse::block(400, "Request blocked");
                    response.audit = Some(AuditMetadata {
                        tags: vec!["body_inspection".to_string()],
                        rule_ids: vec!["BODY_PATTERN_MATCH".to_string()],
                        confidence: Some(0.9),
                        reason_codes: vec![reason],
                        extra: Default::default(),
                    });
                    return response;
                }
            }
        }

        // Pass through the chunk
        AgentResponse::default_allow()
            .with_request_body_mutation(BodyMutation::pass_through(event.chunk_index))
    }
}
```

### Security Headers Agent

Adds security headers to all responses.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, HeaderOp, ResponseHeadersEvent,
};
use async_trait::async_trait;

pub struct SecurityHeadersAgent {
    hsts_max_age: u64,
    frame_options: String,
    content_type_options: String,
    xss_protection: String,
}

impl Default for SecurityHeadersAgent {
    fn default() -> Self {
        Self {
            hsts_max_age: 31536000, // 1 year
            frame_options: "DENY".to_string(),
            content_type_options: "nosniff".to_string(),
            xss_protection: "1; mode=block".to_string(),
        }
    }
}

#[async_trait]
impl AgentHandler for SecurityHeadersAgent {
    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        let mut response = AgentResponse::default_allow();

        response.response_headers.push(HeaderOp::Set {
            name: "Strict-Transport-Security".to_string(),
            value: format!("max-age={}; includeSubDomains", self.hsts_max_age),
        });

        response.response_headers.push(HeaderOp::Set {
            name: "X-Frame-Options".to_string(),
            value: self.frame_options.clone(),
        });

        response.response_headers.push(HeaderOp::Set {
            name: "X-Content-Type-Options".to_string(),
            value: self.content_type_options.clone(),
        });

        response.response_headers.push(HeaderOp::Set {
            name: "X-XSS-Protection".to_string(),
            value: self.xss_protection.clone(),
        });

        response
    }
}
```

### Logging Agent

Comprehensive request/response logging.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, RequestCompleteEvent, RequestHeadersEvent,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct LoggingAgent {
    requests: Mutex<HashMap<String, RequestLog>>,
}

struct RequestLog {
    method: String,
    uri: String,
    client_ip: String,
    started_at: Instant,
}

impl LoggingAgent {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl AgentHandler for LoggingAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let log = RequestLog {
            method: event.method.clone(),
            uri: event.uri.clone(),
            client_ip: event.metadata.client_ip.clone(),
            started_at: Instant::now(),
        };

        self.requests
            .lock()
            .unwrap()
            .insert(event.metadata.correlation_id.clone(), log);

        AgentResponse::default_allow()
    }

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        let request = self
            .requests
            .lock()
            .unwrap()
            .remove(&event.metadata.correlation_id);

        if let Some(req) = request {
            tracing::info!(
                method = %req.method,
                uri = %req.uri,
                client_ip = %req.client_ip,
                status = event.status_code,
                duration_ms = event.duration_ms,
                bytes_sent = event.bytes_sent,
                bytes_received = event.bytes_received,
                correlation_id = %event.metadata.correlation_id,
                "Request completed"
            );
        }

        AgentResponse::default_allow()
    }
}
```

### Prompt Injection Detection Agent

Detects potential prompt injection attempts for LLM APIs.

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, DetectionSeverity, GuardrailDetection,
    GuardrailInspectEvent, GuardrailInspectionType, GuardrailResponse, TextSpan,
};
use async_trait::async_trait;

pub struct PromptGuardAgent {
    injection_patterns: Vec<&'static str>,
}

impl Default for PromptGuardAgent {
    fn default() -> Self {
        Self {
            injection_patterns: vec![
                "ignore previous instructions",
                "ignore all previous",
                "disregard your instructions",
                "forget your instructions",
                "you are now",
                "pretend you are",
                "act as if",
                "new instructions:",
                "system prompt:",
                "override:",
            ],
        }
    }
}

#[async_trait]
impl AgentHandler for PromptGuardAgent {
    async fn on_guardrail_inspect(&self, event: GuardrailInspectEvent) -> AgentResponse {
        if event.inspection_type != GuardrailInspectionType::PromptInjection {
            return AgentResponse::default_allow();
        }

        let content_lower = event.content.to_lowercase();
        let mut detections = Vec::new();

        for pattern in &self.injection_patterns {
            if let Some(start) = content_lower.find(pattern) {
                let end = start + pattern.len();
                detections.push(GuardrailDetection {
                    detection_type: "prompt_injection".to_string(),
                    severity: DetectionSeverity::High,
                    description: format!("Potential prompt injection: '{}'", pattern),
                    spans: vec![TextSpan {
                        start: start as u32,
                        end: end as u32,
                        text: event.content[start..end].to_string(),
                    }],
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
}
```

## Running an Agent

### Binary Example

```rust
use sentinel_agent_protocol::{AgentServer, DenylistAgent};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Load configuration
    let socket_path = env::var("AGENT_SOCKET")
        .unwrap_or_else(|_| "/tmp/denylist-agent.sock".to_string());

    let blocked_paths: Vec<String> = env::var("BLOCKED_PATHS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    let blocked_ips: Vec<String> = env::var("BLOCKED_IPS")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    // Create agent
    let agent = DenylistAgent::new(blocked_paths, blocked_ips);

    // Start server
    tracing::info!("Starting denylist agent on {}", socket_path);
    let server = AgentServer::new("denylist", &socket_path, Box::new(agent));
    server.run().await?;

    Ok(())
}
```

### Composing Multiple Agents

Chain multiple agent behaviors in a single handler:

```rust
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, HeaderOp, RequestHeadersEvent,
};
use async_trait::async_trait;

pub struct ComposedAgent {
    auth: AuthAgent,
    rate_limit: RateLimitAgent,
    security_headers: SecurityHeadersAgent,
}

#[async_trait]
impl AgentHandler for ComposedAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // First: Rate limiting
        let rate_response = self.rate_limit.on_request_headers(event.clone()).await;
        if !matches!(rate_response.decision, Decision::Allow) {
            return rate_response;
        }

        // Second: Authentication
        let auth_response = self.auth.on_request_headers(event).await;
        if !matches!(auth_response.decision, Decision::Allow) {
            return auth_response;
        }

        // Merge header modifications
        let mut response = AgentResponse::default_allow();
        response.request_headers.extend(rate_response.request_headers);
        response.request_headers.extend(auth_response.request_headers);
        response
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        self.security_headers.on_response_headers(event).await
    }
}
```

## Language SDK Examples

For language-specific examples with idiomatic APIs, see the official SDKs:

| Language | Examples |
|----------|----------|
| **Python** | [examples/](https://github.com/raskell-io/sentinel-agent-python-sdk/tree/main/examples) - Simple agent, configurable agent, body inspection |
| **TypeScript** | [examples/](https://github.com/raskell-io/sentinel-agent-typescript-sdk/tree/main/examples) - Simple agent, configurable agent |
| **Go** | [examples/](https://github.com/raskell-io/sentinel-agent-go-sdk/tree/main/examples) - Simple agent, configurable agent, body inspection |
| **Rust** | [examples/](https://github.com/raskell-io/sentinel-agent-rust-sdk/tree/main/examples) - Simple agent, configurable agent, body inspection |
| **Elixir** | [examples/](https://github.com/raskell-io/sentinel-agent-elixir-sdk/tree/main/examples) - Simple agent, configurable agent, body inspection |

Each SDK provides comprehensive documentation at `docs/examples.md` with patterns for:
- IP-based access control
- JWT authentication
- Rate limiting
- Header modification
- Content-type validation
- Request logging
- Redirect handling
- Security checks
