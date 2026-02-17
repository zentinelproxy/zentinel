# Zentinel Code Patterns

Specific patterns for working with Zentinel's codebase.

---

## Pingora Patterns

Zentinel builds on Cloudflare's Pingora framework. Follow these patterns when working with Pingora types.

### ProxyHttp Trait

The core proxy logic implements `pingora_proxy::ProxyHttp`:

```rust
use pingora_proxy::{ProxyHttp, Session};
use pingora_error::Result;

impl ProxyHttp for ZentinelProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool> {
        // Return true to short-circuit (response already sent)
        // Return false to continue to upstream
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Select and return upstream
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        // Modify response headers
        Ok(())
    }
}
```

### Session Headers

Use Pingora's header manipulation methods:

```rust
// Reading headers
let host = session.req_header().headers.get("host");
let method = session.req_header().method.as_str();
let path = session.req_header().uri.path();

// Modifying request headers (in request_filter)
session.req_header_mut().insert_header("X-Request-Id", &request_id)?;
session.req_header_mut().remove_header("X-Internal-Header");

// Modifying response headers (in response_filter)
response.insert_header("X-Served-By", "zentinel")?;
```

### HTTP Peer Selection

```rust
use pingora_core::upstreams::peer::HttpPeer;
use std::sync::Arc;

fn select_peer(upstream: &Upstream) -> Box<HttpPeer> {
    let mut peer = HttpPeer::new(
        upstream.address.clone(),
        upstream.tls,
        upstream.sni.clone(),
    );
    peer.options.connection_timeout = Some(upstream.connect_timeout);
    peer.options.read_timeout = Some(upstream.read_timeout);
    Box::new(peer)
}
```

---

## Agent Protocol Patterns

### v2 Pool Usage

Always use the pool for agent communication:

```rust
use zentinel_agent_protocol::v2::{AgentPool, AgentPoolConfig, LoadBalanceStrategy};

// Create pool (typically at startup)
let config = AgentPoolConfig {
    connections_per_agent: 4,
    load_balance_strategy: LoadBalanceStrategy::LeastConnections,
    request_timeout: Duration::from_secs(30),
    ..Default::default()
};
let pool = AgentPool::with_config(config);

// Add agents from config
for agent in config.agents.iter() {
    pool.add_agent(&agent.name, &agent.endpoint).await?;
}

// Send requests through pool
let decision = pool.send_request_headers("waf", &headers).await?;
```

### Decision Handling

Handle all decision variants:

```rust
use zentinel_agent_protocol::v2::Decision;

match decision {
    Decision::Allow => {
        // Continue to upstream
    }
    Decision::Block { status, body, headers } => {
        // Return error response to client
        send_error_response(session, status, body, headers).await?;
        return Ok(true); // Short-circuit
    }
    Decision::Redirect { location, status } => {
        send_redirect(session, location, status).await?;
        return Ok(true);
    }
    Decision::Modify { headers_to_add, headers_to_remove } => {
        // Apply modifications, continue
        apply_header_modifications(session, headers_to_add, headers_to_remove)?;
    }
}
```

### Agent Timeouts and Fallback

Always handle agent failures:

```rust
use zentinel_agent_protocol::v2::AgentProtocolError;

match pool.send_request_headers("auth", &headers).await {
    Ok(decision) => handle_decision(decision),
    Err(AgentProtocolError::Timeout) => {
        // Apply failure policy
        match config.failure_mode {
            FailureMode::Open => Decision::Allow,
            FailureMode::Closed => Decision::Block {
                status: 503,
                body: Some("Service unavailable".into()),
                headers: vec![],
            },
        }
    }
    Err(e) => {
        tracing::error!(error = %e, agent = "auth", "Agent communication failed");
        // Apply failure policy
    }
}
```

---

## Configuration Patterns

### KDL Parsing

Use the config crate's parsing utilities:

```rust
use zentinel_config::{Config, ConfigError};

// Parse from file
let config = Config::from_file("zentinel.kdl")?;

// Parse from string (useful in tests)
let config = Config::from_str(r#"
    listeners {
        listener "http" address="0.0.0.0:8080"
    }
"#)?;

// Validate after parsing
config.validate()?;
```

### Config Validation

Add validation for new config fields:

```rust
impl RouteConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Bounds checking
        if self.timeout_ms == 0 {
            return Err(ConfigError::InvalidValue {
                field: "timeout_ms".into(),
                message: "must be greater than 0".into(),
            });
        }

        // Cross-field validation
        if self.retry_count > 0 && self.retry_timeout.is_none() {
            return Err(ConfigError::InvalidValue {
                field: "retry_timeout".into(),
                message: "required when retry_count > 0".into(),
            });
        }

        Ok(())
    }
}
```

### Environment Variable Substitution

Support env vars in config values:

```rust
// In KDL config
// api-key "${API_KEY}"
// port "${PORT:-8080}"  // With default

// Parsing handles substitution automatically
let config = Config::from_file_with_env("zentinel.kdl")?;
```

---

## Error Handling Patterns

### Error Types

Use thiserror for library errors:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("Route not found for path: {path}")]
    RouteNotFound { path: String },

    #[error("Upstream timeout after {elapsed:?} (limit: {timeout:?})")]
    UpstreamTimeout {
        elapsed: Duration,
        timeout: Duration,
    },

    #[error("All upstreams unhealthy for route: {route_id}")]
    NoHealthyUpstreams { route_id: String },

    #[error("Agent '{agent}' failed: {source}")]
    AgentError {
        agent: String,
        #[source]
        source: AgentProtocolError,
    },

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

### Error Context

Add context when propagating errors:

```rust
use anyhow::Context;

// In application code
let config = Config::from_file(&path)
    .with_context(|| format!("Failed to load config from {}", path.display()))?;

let upstream = select_upstream(&route)
    .with_context(|| format!("No upstream available for route '{}'", route.id))?;
```

---

## Metrics Patterns

### Counter Metrics

```rust
use metrics::{counter, gauge, histogram};

// Request counters
counter!("zentinel_requests_total",
    "route" => route_id.clone(),
    "method" => method.to_string(),
    "status" => status_class(&response.status),
).increment(1);

// Error counters
counter!("zentinel_errors_total",
    "type" => error_type,
    "route" => route_id.clone(),
).increment(1);
```

### Histogram Metrics

```rust
// Latency histograms
histogram!("zentinel_request_duration_seconds",
    "route" => route_id.clone(),
).record(elapsed.as_secs_f64());

// Size histograms
histogram!("zentinel_request_size_bytes",
    "route" => route_id.clone(),
).record(request_size as f64);
```

### Gauge Metrics

```rust
// Connection gauges
gauge!("zentinel_connections_active").set(active_count as f64);

// Pool gauges
gauge!("zentinel_upstream_pool_size",
    "upstream" => upstream_name.clone(),
).set(pool_size as f64);
```

---

## Testing Patterns

### Unit Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RouteConfig {
        RouteConfig {
            id: "test-route".into(),
            path_prefix: "/api".into(),
            upstream: "backend".into(),
            timeout: Duration::from_secs(30),
            // Explicit fields, no ..Default::default()
        }
    }

    #[test]
    fn matches_exact_path() {
        let route = test_config();
        assert!(route.matches("/api/users"));
        assert!(!route.matches("/other"));
    }
}
```

### Async Test with Timeout

```rust
#[tokio::test]
async fn upstream_request_respects_timeout() {
    tokio::time::pause();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let proxy = TestProxy::new();

    let handle = tokio::spawn(async move {
        proxy.send_request("/slow").await
    });

    // Advance past timeout
    tokio::time::advance(Duration::from_secs(31)).await;

    let result = handle.await.unwrap();
    assert!(matches!(result, Err(ProxyError::UpstreamTimeout { .. })));
}
```

### Integration Test with Config

```rust
#[tokio::test]
async fn full_proxy_request() {
    let config = Config::from_str(r#"
        listeners {
            listener "test" address="127.0.0.1:0"
        }
        upstreams {
            upstream "backend" {
                target "127.0.0.1:9000"
            }
        }
        routes {
            route "api" {
                matches { path-prefix "/api" }
                upstream "backend"
            }
        }
    "#).unwrap();

    let proxy = ZentinelProxy::from_config(config).await.unwrap();
    let addr = proxy.local_addr();

    let client = reqwest::Client::new();
    let response = client.get(format!("http://{}/api/test", addr))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
}
```

---

## Tracing Patterns

### Structured Logging

```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(session), fields(request_id = %ctx.request_id))]
async fn handle_request(
    session: &mut Session,
    ctx: &mut RequestContext,
) -> Result<(), ProxyError> {
    info!(
        method = %session.req_header().method,
        path = %session.req_header().uri.path(),
        "Processing request"
    );

    // ... processing ...

    info!(
        status = %response.status,
        latency_ms = %elapsed.as_millis(),
        "Request completed"
    );

    Ok(())
}
```

### Span Propagation

```rust
use tracing::Span;

// Create child span for upstream request
let upstream_span = tracing::info_span!(
    "upstream_request",
    upstream = %upstream.name,
    address = %upstream.address,
);

let response = upstream_span.in_scope(|| {
    client.send(request)
}).await?;
```
