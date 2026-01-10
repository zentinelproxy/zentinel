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
│                    │ Agent Client  │                                        │
│                    │    Pool       │                                        │
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
                        or gRPC
```

## Transport Architecture

### Unix Domain Socket Transport

```
┌──────────────────────────────────────────────────────────────┐
│                     Message Frame                             │
├──────────────┬───────────────────────────────────────────────┤
│ Length (4B)  │              JSON Payload                      │
│ Big-endian   │              (UTF-8)                           │
│ uint32       │              Max 10MB                          │
└──────────────┴───────────────────────────────────────────────┘

Example:
┌────────────────┬─────────────────────────────────────────────┐
│ 00 00 00 2F   │ {"event_type":"RequestHeaders","payload":..} │
│ (47 bytes)    │                                              │
└────────────────┴─────────────────────────────────────────────┘
```

### gRPC Transport

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP/2 Connection                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Stream 1: ProcessEvent (Unary)                                │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ Request:  AgentRequest (protobuf)                        │   │
│   │ Response: AgentResponse (protobuf)                       │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
│   Stream 2: ProcessEventStream (Bidirectional)                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │ Client ──► AgentRequest ──► AgentRequest ──► ...        │   │
│   │ Server ◄── AgentResponse ◄── AgentResponse ◄── ...      │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Request Lifecycle Flow

### Complete HTTP Request Flow

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

### Decision Flow

```
                    ┌─────────────────┐
                    │ Receive Event   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Agent Handler   │
                    │ Processes Event │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Return Decision │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
            ▼                ▼                ▼
     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
     │   ALLOW     │  │   BLOCK     │  │  REDIRECT   │
     └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
            │                │                │
            ▼                ▼                ▼
     ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
     │ Apply Header│  │Return Error │  │ Send 3xx    │
     │ Mutations   │  │  Response   │  │ Response    │
     │ Continue    │  │ status/body │  │ Location:   │
     │ Processing  │  │             │  │ <url>       │
     └─────────────┘  └─────────────┘  └─────────────┘
```

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

## Body Streaming Flow

```
                Proxy                              Agent
                  │                                  │
                  │   RequestBodyChunk               │
                  │   chunk_index: 0                 │
                  │   is_last: false                 │
                  │   data: [first 64KB]             │
                  │─────────────────────────────────►│
                  │                                  │
                  │   Response                       │
                  │   needs_more: true               │  ◄── Agent buffering
                  │◄─────────────────────────────────│
                  │                                  │
                  │   RequestBodyChunk               │
                  │   chunk_index: 1                 │
                  │   is_last: false                 │
                  │   data: [next 64KB]              │
                  │─────────────────────────────────►│
                  │                                  │
                  │   Response                       │
                  │   needs_more: true               │
                  │◄─────────────────────────────────│
                  │                                  │
                  │   RequestBodyChunk               │
                  │   chunk_index: 2                 │
                  │   is_last: true    ◄────────────────── Final chunk
                  │   data: [last bytes]             │
                  │─────────────────────────────────►│
                  │                                  │
                  │   Response                       │
                  │   decision: Allow                │  ◄── Final decision
                  │   body_mutation: [0,1,2]         │      after full inspection
                  │◄─────────────────────────────────│
                  │                                  │
```

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

### Timeout Handling

```
  Proxy                                          Agent
    │                                              │
    │──────── Send Event ─────────────────────────►│
    │                                              │
    │         ┌─────────────────────┐              │
    │         │  Start Timeout      │              │
    │         │  Timer (e.g. 50ms)  │              │
    │         └─────────────────────┘              │
    │                                              │
    │                    ...                       │  Processing
    │                                              │
    │         ┌─────────────────────┐              │
    │         │  Timeout Fires!     │              │
    │         └──────────┬──────────┘              │
    │                    │                         │
    │                    ▼                         │
    │         ┌─────────────────────┐              │
    │         │  Apply Fallback     │              │
    │         │  Policy             │              │
    │         └──────────┬──────────┘              │
    │                    │                         │
    │         ┌──────────┴──────────┐              │
    │         │                     │              │
    │         ▼                     ▼              │
    │  ┌─────────────┐      ┌─────────────┐       │
    │  │ Fail-Open   │      │ Fail-Closed │       │
    │  │ Allow       │      │ Block 503   │       │
    │  └─────────────┘      └─────────────┘       │
    │                                              │
```

## Multi-Agent Pipeline

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              Request Pipeline                               │
└────────────────────────────────────────────────────────────────────────────┘

  Incoming        ┌─────────┐    ┌─────────┐    ┌─────────┐    To
  Request    ────►│  Rate   │───►│  Auth   │───►│  WAF    │───► Upstream
                  │  Limit  │    │  Agent  │    │  Agent  │
                  └────┬────┘    └────┬────┘    └────┬────┘
                       │              │              │
                       ▼              ▼              ▼
                  ┌─────────┐    ┌─────────┐    ┌─────────┐
                  │ Allow?  │    │ Allow?  │    │ Allow?  │
                  │ 429 Too │    │ 401/403 │    │ 403     │
                  │ Many    │    │ Unauth  │    │ Blocked │
                  └─────────┘    └─────────┘    └─────────┘

  Short-circuit on any Block/Redirect decision
  Headers accumulate through pipeline
```

## Component Interactions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           sentinel-agent-protocol                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                            protocol.rs                               │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│   │  │  EventType   │  │  Decision    │  │  HeaderOp    │               │   │
│   │  │  (8 types)   │  │  (4 types)   │  │  (3 ops)     │               │   │
│   │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│   │  │BodyMutation  │  │ WebSocket    │  │ Guardrail    │               │   │
│   │  │ (3 actions)  │  │ Decision     │  │ Types        │               │   │
│   │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                    ┌───────────────┴───────────────┐                       │
│                    │                               │                        │
│                    ▼                               ▼                        │
│   ┌─────────────────────────────┐   ┌─────────────────────────────┐        │
│   │         client.rs           │   │         server.rs           │        │
│   │  ┌───────────────────────┐  │   │  ┌───────────────────────┐  │        │
│   │  │    AgentClient        │  │   │  │    AgentServer        │  │        │
│   │  │  ├─ unix_socket()     │  │   │  │  ├─ new()             │  │        │
│   │  │  ├─ grpc()            │  │   │  │  └─ run()             │  │        │
│   │  │  ├─ send_event()      │  │   │  └───────────────────────┘  │        │
│   │  │  └─ close()           │  │   │  ┌───────────────────────┐  │        │
│   │  └───────────────────────┘  │   │  │    AgentHandler       │  │        │
│   └─────────────────────────────┘   │  │  (trait, 8 methods)   │  │        │
│                                     │  └───────────────────────┘  │        │
│                                     │  ┌───────────────────────┐  │        │
│                                     │  │  Reference Impls      │  │        │
│                                     │  │  ├─ EchoAgent         │  │        │
│                                     │  │  └─ DenylistAgent     │  │        │
│                                     │  └───────────────────────┘  │        │
│                                     └─────────────────────────────┘        │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                           errors.rs                                  │   │
│   │  AgentProtocolError: Connection | Timeout | MessageTooLarge |       │   │
│   │                       Serialization | Deserialization | Io |         │   │
│   │                       VersionMismatch | Agent                        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```
