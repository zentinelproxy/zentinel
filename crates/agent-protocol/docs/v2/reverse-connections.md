# Reverse Connections

This document provides detailed coverage of the reverse connection feature in Agent Protocol v2, which allows agents to connect to the proxy instead of the proxy connecting to agents.

## Overview

Traditional agent deployment requires the proxy to initiate connections to agents:

```
┌─────────┐                    ┌─────────┐
│  Proxy  │ ──── Connect ────► │  Agent  │
└─────────┘                    └─────────┘
```

This model has limitations:
- Agents behind NAT cannot be reached
- Firewall rules must allow inbound connections to agents
- Static agent discovery required
- Scaling requires configuration changes

**Reverse connections** flip this model:

```
┌─────────┐                    ┌─────────┐
│  Proxy  │ ◄──── Connect ──── │  Agent  │
│         │                    │  (NAT)  │
│ Listener│                    │         │
└─────────┘                    └─────────┘
```

Benefits:
- **NAT Traversal**: Agents behind NAT/firewalls can connect out
- **Dynamic Scaling**: Agents register on startup, no config changes
- **Zero-Config Discovery**: Agents announce their capabilities
- **Load-Based Pooling**: Agents can open multiple connections

---

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Proxy                                        │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                 ReverseConnectionListener                     │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │ UDS Socket  │  │ TCP Socket  │  │ TLS Socket  │          │   │
│  │  │ (local)     │  │ (remote)    │  │ (secure)    │          │   │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘          │   │
│  │         │                │                │                   │   │
│  │         └────────────────┼────────────────┘                   │   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │                   ┌─────────────┐                            │   │
│  │                   │   Accept    │                            │   │
│  │                   │   Handler   │                            │   │
│  │                   └──────┬──────┘                            │   │
│  │                          │                                    │   │
│  │                          ▼                                    │   │
│  │                   ┌─────────────┐                            │   │
│  │                   │ Registration│                            │   │
│  │                   │  Validator  │                            │   │
│  │                   └──────┬──────┘                            │   │
│  │                          │                                    │   │
│  └──────────────────────────┼────────────────────────────────────┘   │
│                             │                                        │
│                             ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      AgentPool                                │   │
│  │                                                               │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │   │
│  │  │  waf-1      │  │  waf-2      │  │  auth-1     │          │   │
│  │  │  (reverse)  │  │  (reverse)  │  │  (reverse)  │          │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘          │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Registration Flow

```
Agent                                                     Proxy
  │                                                         │
  │ 1. TCP/UDS Connect                                      │
  │ ───────────────────────────────────────────────────────►│
  │                                                         │
  │ 2. RegistrationRequest                                  │
  │    {                                                    │
  │      protocol_version: 2,                               │
  │      agent_id: "waf-worker-3",                          │
  │      capabilities: {                                    │
  │        handles_request_headers: true,                   │
  │        handles_request_body: true,                      │
  │        supports_cancellation: true,                     │
  │        max_concurrent_requests: 100                     │
  │      },                                                 │
  │      auth_token: "secret-token",                        │
  │      metadata: { "version": "1.2.0", "region": "us-west" }
  │    }                                                    │
  │ ───────────────────────────────────────────────────────►│
  │                                                         │
  │                                          3. Validate    │
  │                                             - Auth      │
  │                                             - Allowlist │
  │                                             - Limits    │
  │                                                         │
  │ 4. RegistrationResponse                                 │
  │    {                                                    │
  │      accepted: true,                                    │
  │      assigned_id: "waf-worker-3-conn-7",                │
  │      config: { "rules_version": "3.4.0" }               │
  │    }                                                    │
  │ ◄───────────────────────────────────────────────────────│
  │                                                         │
  │ 5. Add to AgentPool                                     │
  │                                                         │
  │ 6. Normal v2 protocol                                   │
  │ ◄──────────────────────────────────────────────────────►│
  │                                                         │
```

---

## Listener Configuration

### Basic Setup

```rust
use sentinel_agent_protocol::v2::{
    ReverseConnectionListener,
    ReverseConnectionConfig,
};
use std::time::Duration;

let config = ReverseConnectionConfig {
    handshake_timeout: Duration::from_secs(10),
    max_connections_per_agent: 4,
    require_auth: false,
    allowed_agents: None,
};

// UDS listener for local agents
let listener = ReverseConnectionListener::bind_uds(
    "/var/run/sentinel/agents.sock",
    config.clone(),
).await?;

// TCP listener for remote agents
let listener = ReverseConnectionListener::bind_tcp(
    "0.0.0.0:9090",
    config,
).await?;
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `handshake_timeout` | 10s | Time allowed for registration handshake |
| `max_connections_per_agent` | 4 | Max connections from same agent_id |
| `require_auth` | false | Require auth_token in registration |
| `allowed_agents` | None | Allowlist of agent IDs (supports wildcards) |

### Security Configuration

```rust
let config = ReverseConnectionConfig {
    // Require authentication
    require_auth: true,

    // Only allow specific agents
    allowed_agents: Some(vec![
        "waf-*".to_string(),           // Wildcard: any waf-prefixed agent
        "auth-primary".to_string(),    // Exact match
        "auth-secondary".to_string(),
    ]),

    // Shorter timeout for faster failure detection
    handshake_timeout: Duration::from_secs(5),

    ..Default::default()
};
```

---

## Accepting Connections

### Simple Accept Loop

```rust
let pool = AgentPool::new();
let listener = ReverseConnectionListener::bind_uds(
    "/var/run/sentinel/agents.sock",
    ReverseConnectionConfig::default(),
).await?;

// Accept loop
loop {
    match listener.accept().await {
        Ok((client, registration)) => {
            tracing::info!(
                agent_id = %registration.agent_id,
                capabilities = ?registration.capabilities,
                "Agent connected"
            );

            // Add to pool
            if let Err(e) = pool.add_reverse_connection(
                &registration.agent_id,
                client,
                registration.capabilities,
            ).await {
                tracing::error!("Failed to add agent: {}", e);
            }
        }
        Err(e) => {
            tracing::error!("Accept error: {}", e);
        }
    }
}
```

### Production Accept Loop

```rust
use tokio::select;
use tokio::sync::broadcast;

async fn run_accept_loop(
    listener: ReverseConnectionListener,
    pool: AgentPool,
    mut shutdown: broadcast::Receiver<()>,
) {
    loop {
        select! {
            result = listener.accept() => {
                match result {
                    Ok((client, registration)) => {
                        handle_new_connection(&pool, client, registration).await;
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                        // Brief pause before retrying on error
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("Shutting down accept loop");
                break;
            }
        }
    }
}

async fn handle_new_connection(
    pool: &AgentPool,
    client: ReverseConnectionClient,
    registration: RegistrationRequest,
) {
    let agent_id = registration.agent_id.clone();

    // Check connection limits
    if let Some(health) = pool.get_health(&agent_id).ok() {
        if health.total_connections >= 4 {
            tracing::warn!(
                agent_id = %agent_id,
                "Agent at connection limit, rejecting"
            );
            return;
        }
    }

    // Add to pool
    match pool.add_reverse_connection(
        &agent_id,
        client,
        registration.capabilities,
    ).await {
        Ok(()) => {
            tracing::info!(agent_id = %agent_id, "Agent added to pool");
        }
        Err(e) => {
            tracing::error!(
                agent_id = %agent_id,
                error = %e,
                "Failed to add agent"
            );
        }
    }
}
```

---

## Agent-Side Implementation

### Connecting to Proxy

```rust
use tokio::net::UnixStream;
use sentinel_agent_protocol::v2::reverse::{
    RegistrationRequest,
    RegistrationResponse,
    write_registration_request,
    read_registration_response,
};

async fn connect_to_proxy(
    socket_path: &str,
    agent_id: &str,
    auth_token: Option<String>,
) -> Result<UnixStream, Box<dyn std::error::Error>> {
    // Connect to proxy listener
    let mut stream = UnixStream::connect(socket_path).await?;

    // Build registration request
    let request = RegistrationRequest {
        protocol_version: 2,
        agent_id: agent_id.to_string(),
        capabilities: UdsCapabilities {
            handles_request_headers: true,
            handles_request_body: true,
            handles_response_headers: true,
            handles_response_body: false,
            supports_streaming: true,
            supports_cancellation: true,
            max_concurrent_requests: Some(100),
        },
        auth_token,
        metadata: Some(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": hostname::get()?.to_string_lossy(),
        })),
    };

    // Send registration
    write_registration_request(&mut stream, &request).await?;

    // Read response
    let response = read_registration_response(&mut stream).await?;

    if !response.accepted {
        return Err(format!(
            "Registration rejected: {}",
            response.error.unwrap_or_default()
        ).into());
    }

    tracing::info!(
        assigned_id = ?response.assigned_id,
        "Registered with proxy"
    );

    // Apply any pushed configuration
    if let Some(config) = response.config {
        apply_config(&config)?;
    }

    Ok(stream)
}
```

### Connection Pool on Agent Side

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;

struct AgentConnectionManager {
    socket_path: String,
    agent_id: String,
    auth_token: Option<String>,
    target_connections: usize,
    connections: Arc<Semaphore>,
}

impl AgentConnectionManager {
    pub fn new(
        socket_path: &str,
        agent_id: &str,
        auth_token: Option<String>,
        target_connections: usize,
    ) -> Self {
        Self {
            socket_path: socket_path.to_string(),
            agent_id: agent_id.to_string(),
            auth_token,
            target_connections,
            connections: Arc::new(Semaphore::new(0)),
        }
    }

    pub async fn run(&self) {
        loop {
            // Maintain target number of connections
            while self.connections.available_permits() < self.target_connections {
                match self.establish_connection().await {
                    Ok(stream) => {
                        self.connections.add_permits(1);
                        let connections = self.connections.clone();

                        tokio::spawn(async move {
                            handle_connection(stream).await;
                            // Connection closed, release permit
                            connections.acquire().await.unwrap().forget();
                        });
                    }
                    Err(e) => {
                        tracing::error!("Connection failed: {}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn establish_connection(&self) -> Result<UnixStream, Box<dyn std::error::Error>> {
        connect_to_proxy(
            &self.socket_path,
            &self.agent_id,
            self.auth_token.clone(),
        ).await
    }
}
```

### Handling Requests

```rust
async fn handle_connection(mut stream: UnixStream) {
    loop {
        match read_message(&mut stream).await {
            Ok(message) => {
                let response = process_message(message).await;
                if let Err(e) = write_message(&mut stream, &response).await {
                    tracing::error!("Write error: {}", e);
                    break;
                }
            }
            Err(AgentProtocolError::ConnectionClosed) => {
                tracing::info!("Connection closed by proxy");
                break;
            }
            Err(e) => {
                tracing::error!("Read error: {}", e);
                break;
            }
        }
    }
}

async fn process_message(message: InboundMessage) -> OutboundMessage {
    match message {
        InboundMessage::RequestHeaders(headers) => {
            // Process headers
            let decision = inspect_headers(&headers);
            OutboundMessage::Decision(decision)
        }
        InboundMessage::RequestBodyChunk(chunk) => {
            // Process body chunk
            let mutation = inspect_body(&chunk);
            OutboundMessage::BodyMutation(mutation)
        }
        InboundMessage::CancelRequest { request_id } => {
            // Clean up any buffered state for this request
            cleanup_request(request_id);
            OutboundMessage::Ack
        }
        InboundMessage::Ping => OutboundMessage::Pong,
        _ => OutboundMessage::Ack,
    }
}
```

---

## Error Handling

### Registration Errors

```rust
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("Protocol version mismatch: got {got}, expected 2")]
    VersionMismatch { got: u32 },

    #[error("Authentication failed")]
    AuthFailed,

    #[error("Agent not in allowlist: {agent_id}")]
    NotAllowed { agent_id: String },

    #[error("Connection limit exceeded for agent: {agent_id}")]
    ConnectionLimitExceeded { agent_id: String },

    #[error("Handshake timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
```

### Handling Disconnects

```rust
// Proxy side: AgentPool handles disconnects automatically
pool.add_reverse_connection(agent_id, client, caps).await?;
// When connection drops, pool removes it and metrics update

// Agent side: reconnect loop
loop {
    match connect_and_handle().await {
        Ok(()) => {
            tracing::info!("Connection closed normally");
        }
        Err(e) => {
            tracing::error!("Connection error: {}", e);
        }
    }

    // Exponential backoff
    let delay = Duration::from_secs(backoff.next());
    tokio::time::sleep(delay).await;
}
```

---

## Monitoring

### Metrics

```rust
let metrics = pool.metrics_collector();
let snapshot = metrics.snapshot();

for agent in &snapshot.agents {
    // Count reverse connections
    let reverse_count = agent.connections
        .iter()
        .filter(|c| c.transport_type == "reverse")
        .count();

    println!(
        "Agent {}: {} reverse connections",
        agent.name,
        reverse_count
    );
}
```

### Health Checking

Reverse connections support the same health tracking as other transports:

```rust
let health = pool.get_health("waf-agent")?;

println!("Total connections: {}", health.total_connections);
println!("Reverse connections: {}", health.reverse_connections);
println!("Success rate: {:.2}%", health.success_rate * 100.0);
```

### Logging

```rust
// Enable detailed logging for reverse connections
RUST_LOG="sentinel_agent_protocol::v2::reverse=debug"

// Example output:
// DEBUG reverse: Accepted connection from /var/run/sentinel/agents.sock
// DEBUG reverse: Registration request from agent_id="waf-worker-1"
// DEBUG reverse: Validating auth token
// DEBUG reverse: Agent registered successfully assigned_id="waf-worker-1-conn-3"
// DEBUG reverse: Connection added to pool agent="waf-worker-1"
```

---

## Best Practices

### 1. Use Multiple Connections Per Agent

```rust
// Agent side: maintain 4 connections
let manager = AgentConnectionManager::new(
    "/var/run/sentinel/agents.sock",
    "waf-worker-1",
    Some("auth-token".to_string()),
    4,  // target connections
);
```

### 2. Implement Graceful Reconnection

```rust
struct ReconnectBackoff {
    current: Duration,
    max: Duration,
    multiplier: f64,
}

impl ReconnectBackoff {
    fn next(&mut self) -> Duration {
        let result = self.current;
        self.current = std::cmp::min(
            Duration::from_secs_f64(self.current.as_secs_f64() * self.multiplier),
            self.max,
        );
        result
    }

    fn reset(&mut self) {
        self.current = Duration::from_secs(1);
    }
}
```

### 3. Include Useful Metadata

```rust
let request = RegistrationRequest {
    // ...
    metadata: Some(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "hostname": hostname::get()?.to_string_lossy(),
        "pid": std::process::id(),
        "started_at": chrono::Utc::now().to_rfc3339(),
        "features": ["waf", "rate-limiting"],
    })),
};
```

### 4. Handle Configuration Pushes

```rust
if let Some(config) = response.config {
    // Hot-reload configuration
    if let Some(rules_version) = config.get("rules_version") {
        reload_rules(rules_version.as_str().unwrap())?;
    }

    if let Some(log_level) = config.get("log_level") {
        set_log_level(log_level.as_str().unwrap())?;
    }
}
```

### 5. Monitor Connection Health

```rust
// Agent side: track connection health
let mut consecutive_errors = 0;

loop {
    match handle_next_request(&mut stream).await {
        Ok(()) => {
            consecutive_errors = 0;
        }
        Err(e) => {
            consecutive_errors += 1;
            if consecutive_errors > 5 {
                tracing::warn!("Too many errors, reconnecting");
                break;
            }
        }
    }
}
```
