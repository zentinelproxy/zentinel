# Sentinel Agent Development Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Agent Protocol](#agent-protocol)
3. [Creating Your First Agent](#creating-your-first-agent)
4. [Agent Lifecycle](#agent-lifecycle)
5. [Decision Types](#decision-types)
6. [Header Mutations](#header-mutations)
7. [Best Practices](#best-practices)
8. [Testing Agents](#testing-agents)
9. [Deployment](#deployment)
10. [Advanced Topics](#advanced-topics)
11. [Troubleshooting](#troubleshooting)
12. [Reference Examples](#reference-examples)

---

## Introduction

Sentinel agents are external processes that extend the proxy's functionality without modifying the core dataplane. They communicate via a well-defined protocol inspired by HAProxy's SPOE (Stream Processing Offload Engine) and Envoy's ext_proc.

### Why Write an Agent?

- **Isolation**: Complex logic runs outside the proxy
- **Language Freedom**: Write agents in any language
- **Independent Deployment**: Update agents without proxy restarts
- **Failure Isolation**: Agent crashes don't affect the proxy
- **Resource Control**: Separate CPU/memory limits

### Common Use Cases

- **Security**: WAF, bot detection, threat intelligence
- **Authentication**: OAuth, JWT validation, SSO
- **Authorization**: Policy enforcement, RBAC
- **Rate Limiting**: Advanced algorithms, distributed state
- **Data Processing**: Request/response transformation
- **Observability**: Custom logging, analytics

---

## Agent Protocol

### Protocol Overview

Agents communicate with Sentinel using a JSON-based protocol over Unix domain sockets (gRPC support planned).

#### Message Flow
```
Proxy → Agent: AgentRequest
    {
        "version": 1,
        "event_type": "request_headers",
        "payload": { ... }
    }

Agent → Proxy: AgentResponse
    {
        "version": 1,
        "decision": "allow|block|redirect|challenge",
        "request_headers": [...],
        "response_headers": [...],
        "audit": { ... }
    }
```

### Event Types

| Event | When Triggered | Payload |
|-------|---------------|---------|
| `request_headers` | Request headers received | Method, URI, headers, metadata |
| `request_body_chunk` | Request body chunk received | Data (base64), is_last, size |
| `response_headers` | Response headers received | Status, headers |
| `response_body_chunk` | Response body chunk received | Data (base64), is_last, size |
| `request_complete` | Request/response complete | Status, duration, sizes, error |

### Protocol Features

- **Versioning**: Forward compatibility
- **Timeouts**: Enforced by proxy
- **Size Limits**: 10MB max message
- **Correlation**: Request tracking via correlation_id
- **Metadata**: Rich context for decisions

---

## Creating Your First Agent

### Rust Implementation

Using the `sentinel-agent-protocol` crate:

```rust
use async_trait::async_trait;
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer,
    RequestHeadersEvent, HeaderOp, AuditMetadata,
};

struct MyAgent {
    // Your agent state
}

#[async_trait]
impl AgentHandler for MyAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        // Your logic here
        println!("Processing request: {} {}", event.method, event.uri);
        
        // Check something
        if event.uri.starts_with("/blocked") {
            return AgentResponse::block(403, Some("Forbidden".to_string()));
        }
        
        // Allow with header modification
        AgentResponse::default_allow()
            .add_request_header(HeaderOp::Set {
                name: "X-Agent-Processed".to_string(),
                value: "true".to_string(),
            })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let agent = Box::new(MyAgent {});
    let server = AgentServer::new("my-agent", "/tmp/my-agent.sock", agent);
    server.run().await?;
    Ok(())
}
```

### Python Implementation

For other languages, implement the protocol directly:

```python
import json
import socket
import struct
import base64
from typing import Dict, Any

class AgentServer:
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        
    def run(self):
        # Create Unix socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.socket_path)
        sock.listen(1)
        
        while True:
            conn, _ = sock.accept()
            self.handle_connection(conn)
            
    def handle_connection(self, conn):
        while True:
            # Read message length (4 bytes, big-endian)
            length_bytes = conn.recv(4)
            if not length_bytes:
                break
                
            message_len = struct.unpack('>I', length_bytes)[0]
            
            # Read message
            message = conn.recv(message_len)
            request = json.loads(message)
            
            # Process request
            response = self.process_request(request)
            
            # Send response
            response_bytes = json.dumps(response).encode()
            conn.send(struct.pack('>I', len(response_bytes)))
            conn.send(response_bytes)
            
    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        event_type = request['event_type']
        
        if event_type == 'request_headers':
            return self.on_request_headers(request['payload'])
            
        # Default allow
        return {
            'version': 1,
            'decision': 'allow',
            'request_headers': [],
            'response_headers': [],
            'routing_metadata': {},
            'audit': {}
        }
        
    def on_request_headers(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # Your logic here
        if event['uri'].startswith('/blocked'):
            return {
                'version': 1,
                'decision': {
                    'block': {
                        'status': 403,
                        'body': 'Forbidden',
                        'headers': None
                    }
                },
                'request_headers': [],
                'response_headers': [],
                'routing_metadata': {},
                'audit': {
                    'tags': ['blocked'],
                    'reason_codes': ['FORBIDDEN_PATH']
                }
            }
            
        return {
            'version': 1,
            'decision': 'allow',
            'request_headers': [
                {'set': {'name': 'X-Python-Agent', 'value': 'processed'}}
            ],
            'response_headers': [],
            'routing_metadata': {},
            'audit': {}
        }
```

---

## Agent Lifecycle

### Initialization
1. Agent starts and creates Unix socket
2. Waits for connections from proxy
3. Proxy connects when route needs agent

### Request Processing
1. Proxy sends event to agent
2. Agent processes within timeout
3. Agent returns decision
4. Proxy applies decision

### Shutdown
1. Proxy sends shutdown signal (optional)
2. Agent cleans up resources
3. Socket closed

### Connection Management
- Proxy maintains persistent connections
- Automatic reconnection on failure
- Connection pooling for efficiency

---

## Decision Types

### Allow
```json
{
    "decision": "allow"
}
```
Request continues normally.

### Block
```json
{
    "decision": {
        "block": {
            "status": 403,
            "body": "Access Denied",
            "headers": {
                "Content-Type": "text/plain"
            }
        }
    }
}
```
Request terminated with response.

### Redirect
```json
{
    "decision": {
        "redirect": {
            "url": "https://example.com/login",
            "status": 302
        }
    }
}
```
Client redirected.

### Challenge
```json
{
    "decision": {
        "challenge": {
            "challenge_type": "captcha",
            "params": {
                "site_key": "...",
                "difficulty": "medium"
            }
        }
    }
}
```
Challenge presented to client.

---

## Header Mutations

### Set Header
Replace or add header:
```json
{
    "request_headers": [
        {"set": {"name": "X-User-Id", "value": "12345"}}
    ]
}
```

### Add Header
Append to existing headers:
```json
{
    "request_headers": [
        {"add": {"name": "X-Role", "value": "admin"}}
    ]
}
```

### Remove Header
Delete header:
```json
{
    "request_headers": [
        {"remove": {"name": "Cookie"}}
    ]
}
```

---

## Best Practices

### Performance
1. **Minimize Latency**:
   - Cache decisions when possible
   - Use connection pooling
   - Optimize hot paths
   - Profile performance

2. **Bounded Resources**:
   - Limit memory usage
   - Set max connections
   - Use timeouts
   - Implement backpressure

### Reliability
1. **Error Handling**:
   - Always return valid responses
   - Log errors appropriately
   - Fail gracefully
   - Implement health checks

2. **Timeout Handling**:
   - Respect proxy timeouts
   - Return fast decisions
   - Offload heavy work

### Security
1. **Input Validation**:
   - Validate all inputs
   - Sanitize outputs
   - Prevent injection attacks
   - Limit resource consumption

2. **Audit Trail**:
   - Log decisions
   - Include correlation IDs
   - Track rule matches
   - Record metrics

### Code Organization
```
my-agent/
├── src/
│   ├── main.rs           # Entry point
│   ├── handler.rs        # Request handlers
│   ├── rules/            # Business logic
│   │   ├── auth.rs
│   │   └── rate_limit.rs
│   ├── cache.rs          # Caching layer
│   └── metrics.rs        # Metrics collection
├── config/
│   └── default.yaml      # Configuration
├── tests/
│   └── integration.rs    # Tests
└── Cargo.toml
```

---

## Testing Agents

### Unit Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_block_forbidden_path() {
        let agent = MyAgent::new();
        let event = RequestHeadersEvent {
            method: "GET".to_string(),
            uri: "/blocked/path".to_string(),
            // ...
        };
        
        let response = agent.on_request_headers(event).await;
        match response.decision {
            Decision::Block { status, .. } => {
                assert_eq!(status, 403);
            }
            _ => panic!("Expected block decision"),
        }
    }
}
```

### Integration Testing
```bash
#!/bin/bash
# Start agent
./my-agent --socket /tmp/test.sock &
AGENT_PID=$!

# Test with curl through proxy
curl -i http://localhost:8080/test

# Check response
# ...

# Cleanup
kill $AGENT_PID
```

### Load Testing
```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_decision(c: &mut Criterion) {
    c.bench_function("auth decision", |b| {
        b.iter(|| {
            // Benchmark decision logic
        });
    });
}
```

---

## Deployment

### Systemd Service
```ini
[Unit]
Description=My Sentinel Agent
After=network.target sentinel.service

[Service]
Type=simple
ExecStart=/usr/local/bin/my-agent --socket /var/run/sentinel/my-agent.sock
User=sentinel
Group=sentinel
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
MemoryMax=256M
LimitNOFILE=8192

[Install]
WantedBy=sentinel.service
```

### Configuration
```yaml
# /etc/sentinel/agents/my-agent.yaml
rules:
  - name: "block-admin"
    condition:
      path_prefix: "/admin"
    action: "block"
    unless:
      header: "X-Admin-Token"
      
cache:
  ttl_seconds: 60
  max_entries: 10000
  
logging:
  level: "info"
  format: "json"
```

### Monitoring
```rust
// Expose metrics
use prometheus::{Counter, Histogram, register_counter, register_histogram};

lazy_static! {
    static ref REQUESTS_TOTAL: Counter = register_counter!(
        "my_agent_requests_total",
        "Total requests processed"
    ).unwrap();
    
    static ref DECISION_DURATION: Histogram = register_histogram!(
        "my_agent_decision_duration_seconds",
        "Decision latency"
    ).unwrap();
}
```

---

## Advanced Topics

### State Management
```rust
use dashmap::DashMap;
use std::sync::Arc;

struct StatefulAgent {
    // Thread-safe state
    sessions: Arc<DashMap<String, SessionData>>,
}
```

### Async Processing
```rust
async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
    // Spawn background task
    let correlation_id = event.metadata.correlation_id.clone();
    tokio::spawn(async move {
        // Async work (logging, metrics, etc.)
    });
    
    // Return decision immediately
    AgentResponse::default_allow()
}
```

### Caching Decisions
```rust
use moka::future::Cache;

struct CachedAgent {
    cache: Cache<String, Decision>,
}

impl CachedAgent {
    async fn get_decision(&self, key: String) -> Decision {
        self.cache
            .get_or_insert_with(key, async {
                // Compute decision
                Decision::Allow
            })
            .await
    }
}
```

### Circuit Breaking
```rust
use circuit_breaker::{CircuitBreaker, Config};

struct ResilientAgent {
    breaker: CircuitBreaker,
}

impl ResilientAgent {
    async fn call_external_service(&self) -> Result<Response> {
        self.breaker.call(async {
            // External call
        }).await
    }
}
```

---

## Troubleshooting

### Agent Not Responding
1. Check socket exists: `ls -la /var/run/sentinel/`
2. Check agent running: `ps aux | grep my-agent`
3. Check logs: `journalctl -u my-agent -f`
4. Test socket: `socat - UNIX-CONNECT:/var/run/sentinel/my-agent.sock`

### High Latency
1. Profile agent: `cargo flamegraph`
2. Check cache hit rate
3. Review external calls
4. Enable debug logging

### Memory Issues
1. Check limits: `systemctl show my-agent | grep Memory`
2. Profile memory: `valgrind --tool=massif`
3. Review data structures
4. Implement cleanup

### Protocol Errors
1. Verify protocol version
2. Check message size
3. Validate JSON schema
4. Review error logs

---

## Reference Examples

### Echo Agent
See: `agents/echo/` for a minimal reference implementation demonstrating the agent protocol.

---

## Resources

- [Agents Overview](./AGENTS.md)
- [Example Agents](../agents/echo/)
- [Integration Tests](../tests/test_agents.sh)
- [Agent Protocol Crate](../crates/agent-protocol/)

---

**Remember**: Agents should be simple, fast, and reliable. Complex logic belongs in agents, not in the proxy core.