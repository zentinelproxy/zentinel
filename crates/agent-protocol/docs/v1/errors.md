# Error Handling

This document describes error types, recovery strategies, and best practices for handling failures in the agent protocol.

## Error Types

The `AgentProtocolError` enum defines all possible errors:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AgentProtocolError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Timeout waiting for agent response")]
    Timeout,

    #[error("Message too large: {size} bytes (max: {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol version mismatch: got {got}, expected {expected}")]
    VersionMismatch { got: u32, expected: u32 },

    #[error("Agent error: {0}")]
    Agent(String),
}
```

## Error Descriptions

### Connection

Occurs when the client cannot establish or maintain a connection to the agent.

**Causes**:
- Socket file doesn't exist
- Agent not running
- Permission denied
- Network unreachable (gRPC)

**Recovery**:
- Retry with exponential backoff
- Check agent health status
- Verify socket path permissions

```rust
match client.send_event(EventType::RequestHeaders, &event).await {
    Err(AgentProtocolError::Connection(msg)) => {
        tracing::error!("Agent connection failed: {}", msg);
        // Fall back to fail-open or fail-closed based on config
    }
    // ...
}
```

### Timeout

Occurs when the agent doesn't respond within the configured timeout.

**Causes**:
- Agent is overloaded
- Agent is blocked on I/O
- Agent has crashed
- Network congestion (gRPC)

**Recovery**:
- Apply fail-open or fail-closed policy
- Trigger circuit breaker
- Alert on repeated timeouts

```rust
match client.send_event(EventType::RequestHeaders, &event).await {
    Err(AgentProtocolError::Timeout) => {
        metrics::counter!("agent.timeout").increment(1);
        // Apply configured fallback policy
        if config.fail_open {
            return Ok(AgentResponse::default_allow());
        } else {
            return Ok(AgentResponse::block(503, "Service temporarily unavailable"));
        }
    }
    // ...
}
```

### MessageTooLarge

Occurs when a message exceeds `MAX_MESSAGE_SIZE` (10 MB).

**Causes**:
- Large request/response body
- Misconfigured body inspection limits

**Recovery**:
- Truncate body before sending
- Skip body inspection for large payloads
- Increase limits if justified

```rust
match client.send_event(EventType::RequestBodyChunk, &chunk_event).await {
    Err(AgentProtocolError::MessageTooLarge { size, max }) => {
        tracing::warn!("Body chunk too large ({} > {}), skipping inspection", size, max);
        // Skip body inspection and pass through
    }
    // ...
}
```

### Serialization / Deserialization

Occurs when JSON encoding/decoding fails.

**Causes**:
- Invalid UTF-8 in headers/body
- Unexpected data types
- Protocol bugs

**Recovery**:
- Log the error for debugging
- Return safe default response
- Report to error tracking system

```rust
match client.send_event(EventType::RequestHeaders, &event).await {
    Err(AgentProtocolError::Serialization(msg)) => {
        tracing::error!("Failed to serialize event: {}", msg);
        // This shouldn't happen with valid data - investigate
        return Ok(AgentResponse::default_allow());
    }
    Err(AgentProtocolError::Deserialization(msg)) => {
        tracing::error!("Failed to deserialize response: {}", msg);
        // Agent returned invalid data
        return Ok(AgentResponse::default_allow());
    }
    // ...
}
```

### Io

Wraps standard I/O errors from socket operations.

**Causes**:
- Connection reset
- Broken pipe
- Buffer overflow

**Recovery**:
- Reconnect to agent
- Apply fallback policy

### VersionMismatch

Occurs when protocol versions don't match.

**Causes**:
- Agent running different protocol version
- Upgrade/rollback mismatch

**Recovery**:
- Upgrade agent to matching version
- Use version-compatible communication

```rust
match client.send_event(EventType::Configure, &config).await {
    Err(AgentProtocolError::VersionMismatch { got, expected }) => {
        tracing::error!(
            "Agent protocol version mismatch: got {}, expected {}",
            got, expected
        );
        // Cannot communicate - disable this agent
    }
    // ...
}
```

### Agent

Generic error returned by the agent itself.

**Causes**:
- Agent-specific logic errors
- Configuration issues
- Backend failures

**Recovery**:
- Log and apply fallback
- Check agent logs for details

## Error Handling Patterns

### Fail-Open vs Fail-Closed

Configure per-route behavior for agent failures:

```rust
struct FailurePolicy {
    fail_open: bool,           // Allow traffic on failure
    timeout_ms: u64,
    max_retries: u32,
}

async fn handle_with_policy(
    client: &mut AgentClient,
    event: &RequestHeadersEvent,
    policy: &FailurePolicy,
) -> Result<AgentResponse, AgentProtocolError> {
    match client.send_event(EventType::RequestHeaders, event).await {
        Ok(response) => Ok(response),
        Err(e) => {
            tracing::warn!("Agent error: {}, fail_open={}", e, policy.fail_open);
            if policy.fail_open {
                Ok(AgentResponse::default_allow())
            } else {
                Ok(AgentResponse::block(503, "Service unavailable"))
            }
        }
    }
}
```

### Circuit Breaker

Temporarily disable failing agents:

```rust
use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use std::time::{Duration, Instant};

struct CircuitBreaker {
    failures: AtomicU32,
    open: AtomicBool,
    opened_at: std::sync::Mutex<Option<Instant>>,
    threshold: u32,
    reset_timeout: Duration,
}

impl CircuitBreaker {
    fn record_failure(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.threshold {
            self.open.store(true, Ordering::Release);
            *self.opened_at.lock().unwrap() = Some(Instant::now());
        }
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.open.store(false, Ordering::Release);
    }

    fn is_open(&self) -> bool {
        if !self.open.load(Ordering::Acquire) {
            return false;
        }
        // Check if reset timeout has passed
        if let Some(opened_at) = *self.opened_at.lock().unwrap() {
            if opened_at.elapsed() > self.reset_timeout {
                // Half-open: allow one request through
                return false;
            }
        }
        true
    }
}
```

### Retry with Backoff

```rust
use tokio::time::{sleep, Duration};

async fn send_with_retry(
    client: &mut AgentClient,
    event_type: EventType,
    event: &impl serde::Serialize,
    max_retries: u32,
) -> Result<AgentResponse, AgentProtocolError> {
    let mut retries = 0;
    let mut delay = Duration::from_millis(10);

    loop {
        match client.send_event(event_type, event).await {
            Ok(response) => return Ok(response),
            Err(e) if retries < max_retries && is_retryable(&e) => {
                retries += 1;
                tracing::debug!("Retry {} after error: {}", retries, e);
                sleep(delay).await;
                delay = std::cmp::min(delay * 2, Duration::from_secs(1));
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_retryable(error: &AgentProtocolError) -> bool {
    matches!(
        error,
        AgentProtocolError::Timeout | AgentProtocolError::Connection(_)
    )
}
```

## Observability

### Metrics

Track error rates for operational visibility:

```rust
// Recommended metrics
metrics::counter!("agent.requests.total", "agent" => agent_name).increment(1);
metrics::counter!("agent.errors.timeout", "agent" => agent_name).increment(1);
metrics::counter!("agent.errors.connection", "agent" => agent_name).increment(1);
metrics::counter!("agent.circuit_breaker.open", "agent" => agent_name).increment(1);
metrics::histogram!("agent.latency_ms", "agent" => agent_name).record(latency_ms);
```

### Logging

Include correlation IDs in all error logs:

```rust
tracing::error!(
    correlation_id = %event.metadata.correlation_id,
    agent = agent_name,
    error = %e,
    "Agent request failed"
);
```

### Alerting

Set up alerts for:
- Error rate > threshold (e.g., 5%)
- P99 latency > SLA
- Circuit breaker opens
- Repeated version mismatches

## Best Practices

1. **Always handle all error variants**: Don't use `unwrap()` on agent results.

2. **Configure appropriate timeouts**: Too short causes spurious failures; too long affects latency.

3. **Use circuit breakers**: Prevent cascading failures when agents are unhealthy.

4. **Log with context**: Include correlation IDs, agent names, and error details.

5. **Monitor error rates**: Set up dashboards and alerts for agent health.

6. **Test failure modes**: Simulate agent crashes, timeouts, and invalid responses.

7. **Document fallback behavior**: Make fail-open/fail-closed decisions explicit in config.
