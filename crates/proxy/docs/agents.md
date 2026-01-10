# Agent Integration

External processing integration for WAF, auth, and custom logic.

## Overview

Agents are external processes that can inspect and mutate requests/responses at various lifecycle phases. This SPOE/ext_proc-inspired design keeps complex processing logic out of the core proxy while maintaining low latency.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Sentinel Proxy                                │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                     AgentManager                                │ │
│  │                                                                 │ │
│  │   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐      │ │
│  │   │  WAF    │   │  Auth   │   │ Custom  │   │   Log   │      │ │
│  │   │ Agent   │   │ Agent   │   │ Agent   │   │ Agent   │      │ │
│  │   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘      │ │
│  │        │             │             │             │            │ │
│  │   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐      │ │
│  │   │Semaphore│   │Semaphore│   │Semaphore│   │Semaphore│      │ │
│  │   │  (100)  │   │  (100)  │   │  (100)  │   │  (100)  │      │ │
│  │   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘      │ │
│  │        │             │             │             │            │ │
│  │   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐      │ │
│  │   │ Circuit │   │ Circuit │   │ Circuit │   │ Circuit │      │ │
│  │   │ Breaker │   │ Breaker │   │ Breaker │   │ Breaker │      │ │
│  │   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘      │ │
│  │        │             │             │             │            │ │
│  │   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐   ┌────┴────┐      │ │
│  │   │  Conn   │   │  Conn   │   │  Conn   │   │  Conn   │      │ │
│  │   │  Pool   │   │  Pool   │   │  Pool   │   │  Pool   │      │ │
│  │   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘      │ │
│  │        │             │             │             │            │ │
│  └────────┼─────────────┼─────────────┼─────────────┼────────────┘ │
│           │             │             │             │              │
└───────────┼─────────────┼─────────────┼─────────────┼──────────────┘
            │             │             │             │
            ▼             ▼             ▼             ▼
      ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
      │   WAF    │  │   Auth   │  │  Custom  │  │   Log    │
      │ Process  │  │ Process  │  │ Process  │  │ Process  │
      │  (UDS)   │  │ (gRPC)   │  │  (UDS)   │  │  (UDS)   │
      └──────────┘  └──────────┘  └──────────┘  └──────────┘
```

## Configuration

### Agent Definition

```kdl
agents {
    // Unix Domain Socket transport
    agent "waf-agent" {
        type "waf"
        transport {
            unix-socket "/var/run/waf-agent.sock"
        }
        events ["request-headers", "request-body"]
        timeout-ms 50
        failure-mode "open"
        max-request-body-bytes 1048576

        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }
    }

    // gRPC transport
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "localhost:50051"
                tls {
                    insecure-skip-verify false
                    ca-cert "/etc/ssl/certs/ca.crt"
                }
            }
        }
        events ["request-headers"]
        timeout-ms 100
        failure-mode "closed"

        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }
    }
}
```

### Attaching Agents to Routes

```kdl
routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "backend"
        filters ["auth", "waf"]  // Agent filters
    }
}

filters {
    filter "auth" {
        type "agent"
        agent "auth-agent"
        phase "request"
        failure-mode "closed"
    }

    filter "waf" {
        type "agent"
        agent "waf-agent"
        phase "request"
        failure-mode "open"
    }
}
```

## Event Model

### Event Types

| Event | Phase | Description |
|-------|-------|-------------|
| `request-headers` | Request | Called after headers parsed, before body |
| `request-body` | Request | Called with request body (buffered or streamed) |
| `request-body-chunk` | Request | Called per chunk for streaming bodies |
| `response-headers` | Response | Called after upstream response headers |
| `response-body` | Response | Called with response body |
| `response-body-chunk` | Response | Called per chunk for streaming responses |
| `log` | Logging | Called at request completion for logging |
| `configure` | Startup | Called at startup/reload for agent config |

### Event Flow

```
        Request Phase                    Response Phase
             │                                 │
             ▼                                 ▼
    ┌─────────────────┐              ┌─────────────────┐
    │ request-headers │              │ response-headers│
    └────────┬────────┘              └────────┬────────┘
             │                                 │
             ▼                                 ▼
    ┌─────────────────┐              ┌─────────────────┐
    │  request-body   │              │  response-body  │
    │ (or body-chunk) │              │ (or body-chunk) │
    └────────┬────────┘              └────────┬────────┘
             │                                 │
             └──────────┬──────────────────────┘
                        │
                        ▼
                 ┌────────────┐
                 │    log     │
                 └────────────┘
```

## Decision Model

### Decision Types

```rust
pub enum AgentDecision {
    // Allow request to continue
    Allow {
        mutations: Option<Mutations>,
        tags: Vec<String>,
    },

    // Block the request
    Block {
        status_code: u16,
        body: Option<String>,
        headers: HashMap<String, String>,
        reason: String,
        rule_id: Option<String>,
    },

    // Redirect the client
    Redirect {
        location: String,
        status_code: u16,  // 301, 302, 307, 308
    },

    // Challenge the client (e.g., CAPTCHA)
    Challenge {
        challenge_type: String,
        challenge_url: String,
    },
}
```

### Mutations

```rust
pub struct Mutations {
    // Request header modifications
    pub request_headers: HeaderMutations,

    // Response header modifications
    pub response_headers: HeaderMutations,

    // Request body replacement (if buffered)
    pub request_body: Option<Bytes>,

    // Response body replacement (if buffered)
    pub response_body: Option<Bytes>,

    // Routing metadata
    pub routing: Option<RoutingMutations>,
}

pub struct HeaderMutations {
    pub set: HashMap<String, String>,
    pub append: HashMap<String, Vec<String>>,
    pub remove: Vec<String>,
}

pub struct RoutingMutations {
    pub upstream_override: Option<String>,
    pub route_override: Option<String>,
    pub tags: Vec<String>,
}
```

## Failure Handling

### Failure Modes

| Mode | Behavior |
|------|----------|
| `open` | Allow request if agent fails (fail-open) |
| `closed` | Block request if agent fails (fail-closed) |

### Circuit Breaker

Each agent has an independent circuit breaker:

```
┌────────────────────────────────────────────────────────┐
│                  Circuit Breaker                        │
├────────────────────────────────────────────────────────┤
│                                                         │
│   CLOSED ──── failures >= threshold ───▶ OPEN          │
│      ▲                                     │            │
│      │                                     │            │
│      │                           timeout   │            │
│      │                                     ▼            │
│      │                               HALF-OPEN         │
│      │                                     │            │
│      └─────── success >= threshold ────────┘            │
│                                                         │
│   Config:                                               │
│   - failure_threshold: 5                                │
│   - success_threshold: 2                                │
│   - timeout_secs: 30                                    │
│                                                         │
└────────────────────────────────────────────────────────┘
```

### Timeout Handling

```kdl
agent "waf-agent" {
    // Hard timeout for all agent calls
    timeout-ms 50

    // Per-event timeouts (optional, overrides global)
    event-timeouts {
        request-headers 30
        request-body 100
        response-headers 30
    }
}
```

## Queue Isolation

Each agent has its own concurrency semaphore to prevent "noisy neighbor" problems:

```
┌─────────────────────────────────────────────────────────┐
│                Queue Isolation                           │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Request 1 ──▶ [WAF Semaphore: 99/100] ──▶ WAF Agent   │
│  Request 2 ──▶ [Auth Semaphore: 98/100] ──▶ Auth Agent │
│  Request 3 ──▶ [WAF Semaphore: 98/100] ──▶ WAF Agent   │
│                                                          │
│  If WAF agent is slow:                                   │
│  - WAF semaphore fills up                                │
│  - Auth agent unaffected (own semaphore)                │
│  - Request 4 to WAF waits or times out                  │
│  - Request 5 to Auth proceeds normally                  │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

Configuration:

```kdl
agent "waf-agent" {
    max-concurrent-calls 100  // Semaphore size
}
```

## Body Handling

### Body Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `buffer` | Buffer entire body before calling agent | WAF inspection |
| `stream` | Stream body chunks to agent | Large uploads |
| `skip` | Don't send body to agent | Header-only checks |

### Configuration

```kdl
agent "waf-agent" {
    events ["request-headers", "request-body"]

    body-handling {
        mode "buffer"
        max-bytes 1048576  // 1MB limit
        content-types [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data"
        ]
    }
}
```

### Streaming Body Handling

For large bodies, use chunk-based processing:

```kdl
agent "content-filter" {
    events ["request-headers", "request-body-chunk"]

    body-handling {
        mode "stream"
        chunk-size 65536  // 64KB chunks
        chunk-timeout-ms 5000
    }
}
```

## Connection Pooling

Each agent maintains a connection pool for efficient reuse:

```rust
pub struct AgentConnectionPool {
    connections: Vec<Connection>,
    max_connections: usize,
    idle_timeout: Duration,
}

impl AgentConnectionPool {
    pub async fn get(&self) -> Result<PooledConnection, Error>;
    pub fn return_connection(&self, conn: Connection);
}
```

Configuration:

```kdl
agent "waf-agent" {
    connection-pool {
        max-connections 10
        idle-timeout-secs 60
    }
}
```

## Metrics

Agent metrics are exported for monitoring:

```
# Call latency
sentinel_agent_latency_ms{agent="waf-agent", event="request-headers", quantile="0.99"} 12.5

# Call counts
sentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="success"} 10000
sentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="timeout"} 5
sentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="error"} 2

# Circuit breaker state
sentinel_agent_circuit_breaker_state{agent="waf-agent"} 0  # 0=closed, 1=open, 2=half-open
sentinel_agent_circuit_breaker_opens_total{agent="waf-agent"} 3

# Queue depth
sentinel_agent_queue_depth{agent="waf-agent"} 5
sentinel_agent_queue_rejections_total{agent="waf-agent"} 0

# Decision counts
sentinel_agent_decisions_total{agent="waf-agent", decision="allow"} 9990
sentinel_agent_decisions_total{agent="waf-agent", decision="block"} 10
```

## Multi-Agent Pipeline

When multiple agents are attached to a route, they form a pipeline:

```
Request
    │
    ▼
┌─────────────┐
│   Agent 1   │──── BLOCK ────▶ Return block response
│   (Auth)    │
└──────┬──────┘
       │ ALLOW
       ▼
┌─────────────┐
│   Agent 2   │──── BLOCK ────▶ Return block response
│   (WAF)     │
└──────┬──────┘
       │ ALLOW
       ▼
┌─────────────┐
│   Agent 3   │──── BLOCK ────▶ Return block response
│  (Custom)   │
└──────┬──────┘
       │ ALLOW
       ▼
   Continue to upstream
```

### Decision Merging

- **First BLOCK wins** - Pipeline stops at first blocking decision
- **Mutations merge** - Header mutations from all agents are combined
- **Tags accumulate** - All agent tags are collected

```rust
pub fn merge_decisions(decisions: Vec<AgentDecision>) -> AgentDecision {
    let mut merged_mutations = Mutations::default();
    let mut merged_tags = Vec::new();

    for decision in decisions {
        match decision {
            AgentDecision::Block { .. } => return decision,
            AgentDecision::Redirect { .. } => return decision,
            AgentDecision::Challenge { .. } => return decision,
            AgentDecision::Allow { mutations, tags } => {
                if let Some(m) = mutations {
                    merged_mutations.merge(m);
                }
                merged_tags.extend(tags);
            }
        }
    }

    AgentDecision::Allow {
        mutations: Some(merged_mutations),
        tags: merged_tags,
    }
}
```

## Example: WAF Agent Integration

Complete configuration for WAF agent:

```kdl
agents {
    agent "waf-agent" {
        type "waf"
        transport {
            unix-socket "/var/run/waf-agent.sock"
        }
        events ["request-headers", "request-body"]
        timeout-ms 50
        failure-mode "open"

        body-handling {
            mode "buffer"
            max-bytes 1048576
            content-types [
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/xml",
                "application/xml"
            ]
        }

        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }

        connection-pool {
            max-connections 10
            idle-timeout-secs 60
        }

        max-concurrent-calls 100
    }
}

filters {
    filter "waf" {
        type "agent"
        agent "waf-agent"
        phase "request"
        failure-mode "open"
    }
}

routes {
    route "protected-api" {
        matches {
            path-prefix "/api"
        }
        upstream "backend"
        filters ["waf"]
        waf-enabled true
    }
}
```

## Example: Auth Agent Integration

Complete configuration for authentication agent:

```kdl
agents {
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "localhost:50051"
                tls {
                    ca-cert "/etc/ssl/certs/ca.crt"
                }
            }
        }
        events ["request-headers"]
        timeout-ms 100
        failure-mode "closed"  // Block if auth fails

        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }
    }
}

filters {
    filter "auth" {
        type "agent"
        agent "auth-agent"
        phase "request"
        failure-mode "closed"
    }
}

routes {
    route "authenticated-api" {
        matches {
            path-prefix "/api/v1"
        }
        upstream "backend"
        filters ["auth"]
    }

    route "public-api" {
        matches {
            path-prefix "/public"
        }
        upstream "backend"
        // No auth filter
    }
}
```

## Building Custom Agents

See the [`agent-protocol`](../../agent-protocol/README.md) crate for:

- Protocol specification
- Handler trait implementation
- Client and server libraries
- Example agents
