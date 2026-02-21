# Config Inspect — Design & Implementation Plan

> **Status:** In progress
> **Created:** 2026-02-21
> **Crate:** `crates/config-inspect`

## Motivation

Zentinel's KDL configuration can be complex — listeners, routes with priority-based matching, filter chains referencing agents, upstream pools with load balancing. Users currently have to mentally map the config to understand proxy behavior. We need a tool that statically analyzes a config and produces a visual topology + heuristic warnings, so users can **see** what happens rather than guess.

## What It Does

Given a `zentinel.kdl` config, produce:

1. **Topology graph** — the full listener → route → filter chain → upstream structure
2. **Heuristic warnings** — shadowed routes, orphaned resources, missing health checks, security concerns
3. **Multiple output formats** — Mermaid (docs/GitHub), DOT (Graphviz), JSON (web renderers), text (terminal)

This is **config-centric** (show the whole topology), complementing the existing **request-centric** `crates/sim` (trace a specific request).

## Architecture

```
crates/config-inspect/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Public API: inspect(config) -> Topology
│   ├── graph.rs            # Build topology graph from parsed Config
│   ├── heuristics.rs       # Static analysis warnings
│   ├── render/
│   │   ├── mod.rs          # Renderer trait
│   │   ├── mermaid.rs      # Mermaid flowchart output
│   │   ├── dot.rs          # Graphviz DOT output
│   │   ├── json.rs         # JSON graph for web renderers
│   │   └── text.rs         # Terminal-friendly text output
│   └── shadow.rs           # Route shadow/overlap detection
└── src/bin/
    └── zentinel-inspect.rs # CLI binary
```

### Crate Positioning

- Depends on `zentinel-config` (no-default-features, WASM-compatible)
- Depends on `zentinel-common` (shared types)
- No runtime dependencies (no tokio, no network)
- Can be compiled to WASM for website integration
- Lives in workspace `exclude` list (like `sim` and `playground-wasm`)

## Data Model

### TopologyGraph (core output type)

```rust
pub struct Topology {
    pub listeners: Vec<ListenerNode>,
    pub routes: Vec<RouteNode>,
    pub filters: Vec<FilterNode>,
    pub agents: Vec<AgentNode>,
    pub upstreams: Vec<UpstreamNode>,
    pub edges: Vec<Edge>,
    pub warnings: Vec<Warning>,
}
```

### Node Types

```rust
pub struct ListenerNode {
    pub id: String,
    pub address: String,
    pub protocol: String,
    pub tls: bool,
}

pub struct RouteNode {
    pub id: String,
    pub priority: String,        // "high", "normal", "low"
    pub match_summary: String,   // "POST,PUT /api/v2/* (host: api.example.com)"
    pub service_type: String,
    pub has_circuit_breaker: bool,
    pub has_retry: bool,
}

pub struct FilterNode {
    pub id: String,
    pub filter_type: String,     // "rate-limit", "headers", "agent", etc.
    pub failure_mode: Option<String>,
}

pub struct AgentNode {
    pub id: String,
    pub agent_type: String,
    pub transport: String,       // "grpc://localhost:50051" or "uds:///tmp/agent.sock"
    pub events: Vec<String>,
    pub failure_mode: String,
    pub timeout_ms: u64,
}

pub struct UpstreamNode {
    pub id: String,
    pub targets: Vec<String>,    // ["10.0.1.10:8080 (w=1)", "10.0.1.11:8080 (w=2)"]
    pub load_balancing: String,
    pub has_health_check: bool,
}
```

### Edges

```rust
pub struct Edge {
    pub from: NodeRef,
    pub to: NodeRef,
    pub label: Option<String>,   // e.g. filter order "1", "2", "3"
}

pub enum NodeRef {
    Listener(String),
    Route(String),
    Filter(String),
    Agent(String),
    Upstream(String),
}
```

### Warnings (Heuristics)

```rust
pub struct Warning {
    pub severity: Severity,      // Error, Warn, Info
    pub code: &'static str,      // "SHADOW_ROUTE", "ORPHAN_UPSTREAM", etc.
    pub message: String,
    pub context: Vec<String>,    // Relevant node IDs
}
```

## Heuristics (v1)

| Code | Severity | Description |
|------|----------|-------------|
| `SHADOW_ROUTE` | Warn | Route is unreachable because a higher-priority route matches a superset of its conditions |
| `ORPHAN_UPSTREAM` | Warn | Upstream defined but not referenced by any route |
| `ORPHAN_AGENT` | Warn | Agent defined but not referenced by any filter |
| `ORPHAN_FILTER` | Warn | Filter defined but not referenced by any route |
| `NO_HEALTH_CHECK` | Info | Upstream with multiple targets has no health check |
| `FAIL_OPEN_SECURITY` | Warn | Security agent (auth, waf) configured with failure_mode=open |
| `NO_TIMEOUT` | Info | Agent with no explicit timeout (using default) |
| `SINGLE_TARGET` | Info | Upstream with only one target (no redundancy) |
| `CATCH_ALL_NOT_LAST` | Warn | A catch-all route (no match conditions) has non-lowest priority |

## CLI UX

```bash
# Full topology as Mermaid
zentinel-inspect config.kdl --format mermaid

# Heuristics only (CI/CD lint)
zentinel-inspect config.kdl --lint

# JSON graph (for web renderers)
zentinel-inspect config.kdl --format json

# DOT for Graphviz
zentinel-inspect config.kdl --format dot | dot -Tpng -o topology.png

# Text summary (default)
zentinel-inspect config.kdl
```

## Implementation Order

1. **Crate scaffolding** — Cargo.toml, lib.rs, module structure
2. **Graph builder** — Walk Config, produce TopologyGraph
3. **Mermaid renderer** — Most useful output format first
4. **Heuristics engine** — Shadow detection, orphan detection, security warnings
5. **CLI binary** — Wire it all together
6. **JSON renderer** — For future web integration
7. **Text renderer** — Terminal-friendly summary
8. **DOT renderer** — Graphviz output

## Future (post-v1)

- WASM target for website playground "Topology" tab
- Interactive web visualizer with D3.js
- Request trace overlay (highlight path through topology)
- Config diff (compare two configs and show what changed)
- `zentinel inspect --watch` for live config reload
