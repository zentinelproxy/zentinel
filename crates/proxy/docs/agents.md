# Agent Integration

External processing integration for WAF, auth, and custom logic.

## Overview

Agents are external processes that can inspect and mutate requests/responses at various lifecycle phases. This SPOE/ext_proc-inspired design keeps complex processing logic out of the core proxy while maintaining low latency.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Zentinel Proxy                                │
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
        events "request-headers" "request-body"
        timeout-ms 50
        max-request-body-bytes 1048576

        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }
    }
    // Body inspection limits: bodies larger than max-request-body-bytes /
    // max-response-body-bytes (default 1 MiB each) follow the filter's
    // failure-mode — "closed" blocks the request with 413, "open" skips
    // this agent's inspection with a warning and a body_size_skips metric.
    // Agents whose limit accommodates the body still inspect it.

    // gRPC transport
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "localhost:50051"
                tls {
                    insecure-skip-verify #false
                    ca-cert "/etc/ssl/certs/ca.crt"
                }
            }
        }
        events "request-headers"
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
        filters "auth" "waf"  // Agent filters
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
| `configure` | Connection | The agent's `config { }` block, delivered on every connection (each pooled connection and every reconnect) before any request; a rejected configuration makes the connection unusable |

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

### Decisions in each phase

Every decision type has the same meaning in every phase; only `Allow` lets
the request, or the upstream's response, through.

| Decision | Request headers / body | Response headers | Response body |
|----------|------------------------|------------------|---------------|
| `Allow` | Proxied | Upstream response sent | Body sent |
| `Block` | Agent's status, body, headers | Replaces the upstream response | Aborts the response¹ |
| `Redirect` | Agent's 301/302/303/307/308 (else 302) with `Location` | Replaces the upstream response | Aborts the response¹ |
| `Challenge` | 403, or 401 with the `www-authenticate` parameter | Replaces the upstream response | Aborts the response¹ |

¹ Once the status line has gone out it cannot be replaced: the body is
withheld and the connection closed without ending it, so the client sees an
incomplete response. If the header has not gone out yet (a body that arrived
with it), the decision's response replaces the upstream's instead. Response
`Redirect` and `Challenge` were ignored before #588.

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

### Decisions in the Response Phase

An agent subscribed to `response-headers` or `response-body` can block the
response as well as change it.

| Decided on | What the client gets |
|------------|----------------------|
| Response headers | The block response **in place of** the upstream's: the agent's status, its body (as `text/plain`) and its headers, or, without a body, the route's error page for the status (`Blocked by agent` where the route has none). No byte of the upstream's response is sent. |
| Response body | The upstream's status and headers have normally gone out already, so the response is **aborted**: the connection is closed without ending the body. The body is withheld until the agent has decided, so the client receives none of it, and the chunked framing the proxy uses for such responses lets it see the body is incomplete (HTTP/1.0 clients get a close-delimited body and cannot). A body that arrived together with its headers is decided on before anything is sent; it is answered with the block response, as on response headers. |

The response body is buffered for the agents up to the largest of their
`max-response-body-bytes`. A body over it is decided on at that point by the
filter's `failure-mode`: `closed` refuses it with 413 (aborting the response
if its status is out), `open` sends it on uninspected, whole.

Both are logged at WARN with the agent, its filter and (for the body) how
many body bytes had been sent, counted as blocked requests
(`agent_response_blocked`, `agent_response_body_blocked`) and written to
the audit log as an agent decision with `phase` `response_headers` or
`response_body`. Neither is counted against the upstream.

## Failure Handling

### Failure Modes

| Mode | Behavior |
|------|----------|
| `open` | Allow request if agent fails (fail-open) |
| `closed` | Block request if agent fails (fail-closed) |

A failed call -- the agent is not loaded, unreachable, behind an open
circuit breaker, too slow, or the body is over its inspection limit --
follows the **filter's** `failure-mode`, else the route's `policies
{ failure-mode }` (closed by default). This holds on every path: request
headers and body, response headers and body. On the request side a
fail-closed failure answers 503 (504 for a timeout, 413 for a body over the
limit); on response headers the upstream response is replaced by that
refusal; on the response body the response is aborted as above. WebSocket
frames follow the same rule: only the route's agents see them, and a
fail-closed failure closes the connection with 1011 (#586).

The agent's own `failure-mode` (`agents { agent "x" { failure-mode ... } }`)
is **deprecated and has no effect**. `zentinel test` and the startup log
report it, naming the filters (and their routes) where the value belongs.
It will be removed in a later release.

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
    events "request-headers" "request-body"

    body-handling {
        mode "buffer"
        max-bytes 1048576  // 1MB limit
        content-types "application/json" "application/x-www-form-urlencoded" "multipart/form-data"
    }
}
```

### Streaming Body Handling

For large bodies, use chunk-based processing:

```kdl
agent "content-filter" {
    events "request-headers" "request-body-chunk"

    body-handling {
        mode "stream"
        chunk-size 65536  // 64KB chunks
        chunk-timeout-ms 5000
    }
}
```

## Connection Pooling

Each agent uses the v2 protocol's built-in connection pool (four connections
per agent, round-robin, health-checked). The pool is managed internally by the
agent and handles reconnection automatically: a connection that fails is
retried in the background, with a backoff that grows to two minutes.

A new connection waits at most `connect-timeout-ms` (default 5000) for the
agent to accept it and answer the handshake:

```kdl
agent "waf-agent" type="waf" {
    unix-socket "/var/run/zentinel/waf.sock"
    timeout-ms 100
    connect-timeout-ms 2000
}
```

An agent that does not answer in time is not used until it does: its filters
follow their `failure-mode` (`open` forwards the request uninspected,
`closed` answers 503), and the pool keeps reconnecting. Startup does not wait
for it: all agents connect at once, and the proxy starts serving after at
most the longest `connect-timeout-ms` plus 5 s for the agents to acknowledge
their configuration. An agent still connecting then is connected in the
background.

The other pool settings (connections per agent, load balancing, reconnect
interval, health-check interval) are not configurable from KDL; a `pool { }`
block in an agent is reported as an unknown key.

## Metrics

Agent metrics are exported for monitoring:

```
# Call latency
zentinel_agent_latency_ms{agent="waf-agent", event="request-headers", quantile="0.99"} 12.5

# Call counts
zentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="success"} 10000
zentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="timeout"} 5
zentinel_agent_calls_total{agent="waf-agent", event="request-headers", result="error"} 2

# Circuit breaker state
zentinel_agent_circuit_breaker_state{agent="waf-agent"} 0  # 0=closed, 1=open, 2=half-open
zentinel_agent_circuit_breaker_opens_total{agent="waf-agent"} 3

# Queue depth
zentinel_agent_queue_depth{agent="waf-agent"} 5
zentinel_agent_queue_rejections_total{agent="waf-agent"} 0

# Decision counts
zentinel_agent_decisions_total{agent="waf-agent", decision="allow"} 9990
zentinel_agent_decisions_total{agent="waf-agent", decision="block"} 10
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
- **Attribution survives merging** - `AgentDecision.decided_by` records which
  agent produced the deciding (non-allow) action, including synthetic blocks
  from fail-closed timeouts, circuit breakers, and body-size limits. Block
  logs carry it as `agent_id`, and audit log entries get an `agent:<id>` tag,
  so every block can answer *which agent decided, and why*.

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
        events "request-headers" "request-body"
        timeout-ms 50

        body-handling {
            mode "buffer"
            max-bytes 1048576
            content-types "application/json" "application/x-www-form-urlencoded" "multipart/form-data" "text/xml" "application/xml"
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
        filters "waf"
        waf-enabled #true
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
        events "request-headers"
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
        filters "auth"
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
