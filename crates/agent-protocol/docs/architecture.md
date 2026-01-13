# Architecture & Flow Diagrams

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Sentinel Proxy                                  │
│                             (Rust Dataplane)                                │
│                                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Listener   │───►│   Router    │───►│  Upstream   │───►│  Response   │  │
│  │  (TLS/H2)   │    │  (Matching) │    │   Pool      │    │  Pipeline   │  │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    └─────────────┘  │
│                            │                                                │
│                            ▼                                                │
│                    ┌───────────────┐                                        │
│                    │  AgentPool    │  ◄── v2: Connection pooling            │
│                    │  (v1 or v2)   │      with load balancing               │
│                    └───────┬───────┘                                        │
│                            │                                                │
└────────────────────────────┼────────────────────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
     ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
     │  WAF Agent  │ │ Auth Agent  │ │Rate Limiter │
     │             │ │             │ │   Agent     │
     │ ┌─────────┐ │ │ ┌─────────┐ │ │ ┌─────────┐ │
     │ │ Server  │ │ │ │ Server  │ │ │ │ Server  │ │
     │ └────┬────┘ │ │ └────┬────┘ │ │ └────┬────┘ │
     │      │      │ │      │      │ │      │      │
     │ ┌────▼────┐ │ │ ┌────▼────┐ │ │ ┌────▼────┐ │
     │ │ Handler │ │ │ │ Handler │ │ │ │ Handler │ │
     │ └─────────┘ │ │ └─────────┘ │ │ └─────────┘ │
     │             │ │             │ │             │
     │  ModSec/CRS │ │  JWT/OAuth  │ │Token Bucket │
     └─────────────┘ └─────────────┘ └─────────────┘
           │                │               │
           └────────────────┴───────────────┘
                           │
                    Unix Domain Sockets
                    gRPC, or Reverse Connections

```

---

## Protocol Version Comparison

| Feature | v1 | v2 |
|---------|----|----|
| Transport | UDS (JSON), gRPC | UDS (binary), gRPC, Reverse |
| Connection pooling | No | Yes (4 strategies) |
| Bidirectional streaming | Limited | Full support |
| Metrics export | No | Prometheus format |
| Config push | No | Yes |
| Health tracking | Basic | Comprehensive |
| Flow control | No | Yes |
| Cancellation | No | Yes |

---

## v2 Transport Architecture

### Transport Options

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           V2Transport Enum                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐ │
│   │   V2Transport::     │  │   V2Transport::     │  │   V2Transport::     │ │
│   │   Grpc              │  │   Uds               │  │   Reverse           │ │
│   │                     │  │                     │  │                     │ │
│   │   AgentClientV2     │  │   AgentClientV2Uds  │  │ ReverseConnection   │ │
│   │                     │  │                     │  │      Client         │ │
│   │   - HTTP/2          │  │   - Unix socket     │  │                     │ │
│   │   - TLS support     │  │   - Binary protocol │  │   - Agent-initiated │ │
│   │   - Protobuf        │  │   - JSON payload    │  │   - NAT traversal   │ │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘ │
│             │                        │                        │             │
│             └────────────────────────┼────────────────────────┘             │
│                                      │                                      │
│                                      ▼                                      │
│                          ┌─────────────────────┐                            │
│                          │   Unified Interface │                            │
│                          │                     │                            │
│                          │  send_request_*()   │                            │
│                          │  send_response_*()  │                            │
│                          │  cancel_request()   │                            │
│                          │  capabilities()     │                            │
│                          └─────────────────────┘                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Unix Domain Socket (v2 Binary Protocol)

```
┌──────────────────────────────────────────────────────────────┐
│                     v2 UDS Message Frame                      │
├──────────────┬────────────┬──────────────────────────────────┤
│ Length (4B)  │ Type (1B)  │         JSON Payload             │
│ Big-endian   │ MessageType│         (UTF-8)                  │
│ uint32       │ enum       │         Max 16MB                 │
└──────────────┴────────────┴──────────────────────────────────┘

Message Types:
┌────────────────────────────────────────────────────────────┐
│ 0x01 HandshakeRequest    │ 0x02 HandshakeResponse          │
│ 0x10 RequestHeaders      │ 0x11 RequestBodyChunk           │
│ 0x12 ResponseHeaders     │ 0x13 ResponseBodyChunk          │
│ 0x14 RequestComplete     │ 0x15 WebSocketFrame             │
│ 0x16 GuardrailInspect    │ 0x17 Configure                  │
│ 0x20 AgentResponse       │ 0x30 HealthStatus               │
│ 0x31 MetricsReport       │ 0x32 ConfigUpdateRequest        │
│ 0x33 FlowControl         │ 0x40 Cancel                     │
│ 0x41 Ping                │ 0x42 Pong                       │
└────────────────────────────────────────────────────────────┘
```

### gRPC Transport (v2)

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP/2 Connection                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Bidirectional Streaming RPC:                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ ProcessEventStream                                       │   │
│   │                                                          │   │
│   │ Proxy ──► StreamMessage ──► StreamMessage ──► ...       │   │
│   │       ◄── StreamMessage ◄── StreamMessage ◄── ...       │   │
│   │                                                          │   │
│   │ StreamMessage contains:                                  │   │
│   │ - correlation_id (request tracking)                      │   │
│   │ - message_type (event or response)                       │   │
│   │ - payload (event data or response)                       │   │
│   │ - timestamp_ms                                           │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Control Messages (Agent → Proxy):                             │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ - HealthStatus (periodic health updates)                 │   │
│   │ - MetricsReport (agent metrics for aggregation)          │   │
│   │ - FlowControl (pause/resume/adjust)                      │   │
│   │ - ConfigUpdateRequest (request config from proxy)        │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Reverse Connections

```
┌─────────────────────────────────────────────────────────────────┐
│                      Reverse Connection Flow                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Agent                          Proxy                           │
│     │                              │                             │
│     │─── TCP/UDS Connect ─────────►│                             │
│     │                              │                             │
│     │─── RegistrationRequest ────►│                             │
│     │    - protocol_version        │                             │
│     │    - agent_id                │                             │
│     │    - capabilities            │                             │
│     │    - auth_token (optional)   │                             │
│     │                              │                             │
│     │◄── RegistrationResponse ────│                             │
│     │    - success/error           │                             │
│     │    - connection_id           │                             │
│     │                              │                             │
│     │                              │ (Connection added to pool)  │
│     │                              │                             │
│     │◄── RequestHeaders ──────────│                             │
│     │─── AgentResponse ──────────►│                             │
│     │          ...                 │                             │
│     ▼                              ▼                             │
│                                                                  │
│   Benefits:                                                      │
│   - Agents behind NAT/firewalls                                 │
│   - Dynamic agent scaling                                        │
│   - Simpler agent deployment (no exposed ports)                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Connection Pool Architecture (v2)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AgentPool                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         Agent Entries                                │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│   │  │  AgentEntry  │  │  AgentEntry  │  │  AgentEntry  │               │   │
│   │  │  "waf"       │  │  "auth"      │  │  "rate"      │               │   │
│   │  │              │  │              │  │              │               │   │
│   │  │ Connections: │  │ Connections: │  │ Connections: │               │   │
│   │  │ ┌──┐┌──┐┌──┐ │  │ ┌──┐┌──┐    │  │ ┌──┐         │               │   │
│   │  │ │C1││C2││C3│ │  │ │C1││C2│    │  │ │C1│         │               │   │
│   │  │ └──┘└──┘└──┘ │  │ └──┘└──┘    │  │ └──┘         │               │   │
│   │  │              │  │              │  │              │               │   │
│   │  │ Capabilities │  │ Capabilities │  │ Capabilities │               │   │
│   │  │ RoundRobin   │  │ LeastConn    │  │ HealthBased │               │   │
│   │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                       Load Balancing                                 │   │
│   │                                                                      │   │
│   │   RoundRobin ──► Even distribution across connections               │   │
│   │   LeastConn  ──► Route to connection with fewest in-flight          │   │
│   │   HealthBased──► Prefer connections with lower error rates          │   │
│   │   Random     ──► Random selection                                   │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                       Observability                                  │   │
│   │                                                                      │   │
│   │   MetricsCollector ──► Aggregates metrics from all agents           │   │
│   │   ConfigPusher     ──► Distributes config updates to agents         │   │
│   │   HealthTracker    ──► Monitors connection health                   │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Request Lifecycle Flow

### Complete HTTP Request Flow (v2)

```
 Client                Proxy                    Agent                 Upstream
   │                     │                        │                      │
   │──── TCP Connect ───►│                        │                      │
   │◄─── TLS Handshake ──│                        │                      │
   │                     │                        │                      │
   │──── HTTP Request ──►│                        │                      │
   │     Headers         │                        │                      │
   │                     │                        │                      │
   │                     │── RequestHeaders ─────►│                      │
   │                     │◄─ Decision + Mutations─│                      │
   │                     │                        │                      │
   │                     │   [If Block/Redirect]  │                      │
   │◄── Error Response ──│◄──────────────────────┘                      │
   │                     │                        │                      │
   │                     │   [If Allow]           │                      │
   │──── Request Body ──►│                        │                      │
   │     (streaming)     │── RequestBodyChunk ───►│                      │
   │                     │◄─ BodyMutation ────────│                      │
   │                     │         ...            │                      │
   │                     │── RequestBodyChunk ───►│  (is_last=true)      │
   │                     │◄─ BodyMutation ────────│                      │
   │                     │                        │                      │
   │                     │─────── Forward Request ──────────────────────►│
   │                     │                        │                      │
   │                     │◄────── Response Headers ──────────────────────│
   │                     │                        │                      │
   │                     │── ResponseHeaders ────►│                      │
   │                     │◄─ Header Mutations ────│                      │
   │                     │                        │                      │
   │◄── Response Headers─│                        │                      │
   │                     │                        │                      │
   │                     │◄────── Response Body ─────────────────────────│
   │                     │        (streaming)     │                      │
   │                     │── ResponseBodyChunk ──►│                      │
   │                     │◄─ BodyMutation ────────│                      │
   │◄── Response Body ───│         ...            │                      │
   │                     │                        │                      │
   │                     │── RequestComplete ────►│                      │
   │                     │◄─ Ack ─────────────────│                      │
   │                     │                        │                      │
   ▼                     ▼                        ▼                      ▼
```

### v2 Cancellation Flow

```
  Proxy                                          Agent
    │                                              │
    │──────── RequestHeaders ─────────────────────►│
    │                                              │
    │         [Client disconnects]                 │
    │                                              │
    │──────── Cancel ─────────────────────────────►│
    │         correlation_id: "req-123"            │
    │         reason: ClientDisconnect             │
    │                                              │
    │                                    Agent stops│
    │                                    processing │
    │                                              │
```

---

## Event Types & Lifecycle

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Request Lifecycle                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐                                                           │
│  │  Configure   │  ◄─── Once per connection (capability negotiation)        │
│  └──────────────┘                                                           │
│                                                                             │
│  ┌──────────────┐                                                           │
│  │  Request     │  ◄─── Headers received (auth, routing, early block)       │
│  │  Headers     │                                                           │
│  └──────────────┘                                                           │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────┐                                                           │
│  │  Request     │  ◄─── Body chunks (WAF inspection, transformation)        │
│  │  BodyChunk   │       Repeats for each chunk                              │
│  │  [0..N]      │       is_last=true on final chunk                         │
│  └──────────────┘                                                           │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────┐                                                           │
│  │  Response    │  ◄─── Upstream headers (add security headers)             │
│  │  Headers     │                                                           │
│  └──────────────┘                                                           │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────┐                                                           │
│  │  Response    │  ◄─── Body chunks (DLP, content filtering)                │
│  │  BodyChunk   │       Repeats for each chunk                              │
│  │  [0..N]      │                                                           │
│  └──────────────┘                                                           │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────┐                                                           │
│  │  Request     │  ◄─── Final event (logging, metrics, cleanup)             │
│  │  Complete    │                                                           │
│  └──────────────┘                                                           │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Special Event Types                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐                                                           │
│  │  WebSocket   │  ◄─── After upgrade, per-frame inspection                 │
│  │  Frame       │       Bidirectional (client↔server frames)                │
│  └──────────────┘                                                           │
│                                                                             │
│  ┌──────────────┐                                                           │
│  │  Guardrail   │  ◄─── AI safety inspection                                │
│  │  Inspect     │       Prompt injection, PII detection                     │
│  └──────────────┘                                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Failure Handling

### Circuit Breaker States

```
                    ┌───────────────────┐
                    │                   │
           Reset    │      CLOSED       │◄────────────────┐
           Timeout  │   (Normal Flow)   │                 │
              │     │                   │                 │
              │     └─────────┬─────────┘                 │
              │               │                           │
              │               │ Failure                   │
              │               │ Threshold                 │
              │               │ Reached                   │
              │               ▼                           │
              │     ┌───────────────────┐                 │
              │     │                   │                 │
              │     │       OPEN        │                 │
              └────►│  (Fail Fast)      │                 │
                    │                   │                 │ Success
                    └─────────┬─────────┘                 │
                              │                           │
                              │ Timeout                   │
                              │ Elapsed                   │
                              ▼                           │
                    ┌───────────────────┐                 │
                    │                   │                 │
                    │    HALF-OPEN      │─────────────────┘
                    │  (Test Request)   │
                    │                   │────────┐
                    └───────────────────┘        │
                                                 │ Failure
                                                 │
                                                 ▼
                                        Back to OPEN
```

### v2 Health Tracking

```
┌─────────────────────────────────────────────────────────────────┐
│                      Connection Health                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Health Score = f(error_rate, latency, consecutive_errors)     │
│                                                                  │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│   │  Healthy    │  │  Degraded   │  │  Unhealthy  │             │
│   │  Score > 80 │  │  40 < S ≤80 │  │  Score ≤ 40 │             │
│   │             │  │             │  │             │             │
│   │  Full       │  │  Reduced    │  │  No new     │             │
│   │  traffic    │  │  traffic    │  │  requests   │             │
│   └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                  │
│   Agent Reports:                                                 │
│   - HealthStatus messages (periodic)                            │
│   - State: Healthy | Degraded | Unhealthy | Draining            │
│   - Current load, memory usage                                   │
│   - Version info                                                 │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Component Interactions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           sentinel-agent-protocol                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                            v1 (Legacy)                               │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│   │  │ AgentClient  │  │ AgentServer  │  │ AgentHandler │               │   │
│   │  │ (UDS/gRPC)   │  │              │  │ (trait)      │               │   │
│   │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                            v2 (New)                                  │   │
│   │                                                                      │   │
│   │   Clients:                                                          │   │
│   │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │   │
│   │   │ AgentClientV2  │  │AgentClientV2Uds│  │ ReverseConn    │        │   │
│   │   │ (gRPC)         │  │ (Binary UDS)   │  │ Client         │        │   │
│   │   └────────────────┘  └────────────────┘  └────────────────┘        │   │
│   │                                                                      │   │
│   │   Pooling:                                                          │   │
│   │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │   │
│   │   │ AgentPool      │  │ V2Transport    │  │ LoadBalance    │        │   │
│   │   │                │  │ (enum)         │  │ Strategy       │        │   │
│   │   └────────────────┘  └────────────────┘  └────────────────┘        │   │
│   │                                                                      │   │
│   │   Observability:                                                    │   │
│   │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │   │
│   │   │MetricsCollector│  │ ConfigPusher   │  │ HealthTracker  │        │   │
│   │   └────────────────┘  └────────────────┘  └────────────────┘        │   │
│   │                                                                      │   │
│   │   Server:                                                           │   │
│   │   ┌────────────────┐  ┌────────────────┐                            │   │
│   │   │GrpcAgentServer │  │AgentHandlerV2  │                            │   │
│   │   │     V2         │  │ (trait)        │                            │   │
│   │   └────────────────┘  └────────────────┘                            │   │
│   │                                                                      │   │
│   │   Reverse:                                                          │   │
│   │   ┌────────────────┐  ┌────────────────┐                            │   │
│   │   │ ReverseConn    │  │ Registration   │                            │   │
│   │   │ Listener       │  │ Request/Resp   │                            │   │
│   │   └────────────────┘  └────────────────┘                            │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                           errors.rs                                  │   │
│   │  AgentProtocolError: ConnectionFailed | ConnectionClosed |          │   │
│   │                       Timeout | MessageTooLarge | InvalidMessage |   │   │
│   │                       VersionMismatch | Serialization | Io          │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
