# Sentinel Documentation

## User Guides

| Document | Description |
|----------|-------------|
| [Agents](AGENTS.md) | Agent ecosystem overview and community agents |
| [Agent Development](AGENT_DEVELOPMENT.md) | Building custom agents |
| [Service Types](SERVICE_TYPES.md) | API, web, and static file handling |
| [Distributed Deployment](DISTRIBUTED_DEPLOYMENT.md) | Multi-node and HA deployment |

## Operations

| Document | Description |
|----------|-------------|
| [Runbook](RUNBOOK.md) | Operational procedures and troubleshooting |
| [Metrics](METRICS.md) | Prometheus metrics reference |
| [Tracing](TRACING.md) | Distributed tracing with OpenTelemetry |
| [SLOs](slo.md) | Service level objectives |

## Development

| Document | Description |
|----------|-------------|
| [Integration Status](INTEGRATION_STATUS.md) | Feature implementation status |
| [Mise Tasks](MISE_TASKS.md) | Development task runner commands |

## Crate Documentation

Detailed API and implementation documentation lives in each crate:

| Crate | Description |
|-------|-------------|
| [`sentinel-proxy`](../crates/proxy/) | Core reverse proxy built on Pingora |
| [`sentinel-config`](../crates/config/) | KDL configuration parsing and validation |
| [`sentinel-common`](../crates/common/) | Shared types, errors, and utilities |
| [`sentinel-agent-protocol`](../crates/agent-protocol/) | External agent communication protocol |
| [`sentinel-sim`](../crates/sim/) | WASM-compatible configuration simulator |
| [`sentinel-stack`](../crates/stack/) | All-in-one process manager |
| [`sentinel-playground-wasm`](../crates/playground-wasm/) | Browser bindings for the playground |

## Philosophy

- [Why Sentinel](why-sentinel.md) - Design philosophy and goals
- [Manifesto](../MANIFESTO.md) - Core principles
