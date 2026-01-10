# Configuration Examples

Example configurations demonstrating Sentinel features and patterns.

## Getting Started

| Example | Description |
|---------|-------------|
| [basic.kdl](basic.kdl) | Minimal configuration for getting started |

## API Features

| Example | Description |
|---------|-------------|
| [api-schema-validation.kdl](api-schema-validation.kdl) | JSON Schema and OpenAPI validation for API routes |

## AI/Inference

| Example | Description |
|---------|-------------|
| [inference-routing.kdl](inference-routing.kdl) | LLM/AI endpoint routing with token-based rate limiting |
| [ai-guardrails.kdl](ai-guardrails.kdl) | Prompt injection detection and PII protection |

### Inference Features Covered

- **Token Rate Limiting** - Per-minute token limits with burst
- **Token Budgets** - Cumulative tracking per period (daily/monthly)
- **Cost Attribution** - Per-model pricing for billing
- **Model Routing** - Route requests based on model name
- **Provider Support** - OpenAI, Anthropic, and generic providers
- **Fallback Routing** - Cross-provider failover with model mapping
- **Guardrails** - Prompt injection detection, PII detection/redaction

## Traffic Management

| Example | Description |
|---------|-------------|
| [shadow-traffic.kdl](shadow-traffic.kdl) | Traffic mirroring for canary deployments and A/B testing |
| [distributed-rate-limit.kdl](distributed-rate-limit.kdl) | Redis and Memcached rate limiting backends |
| [http-caching.kdl](http-caching.kdl) | Response caching with memory, disk, and hybrid storage |

### Shadow Traffic Features

- Percentage-based sampling (1%, 10%, 50%, 100%)
- Header-based sampling triggers
- Request body buffering for POST/PUT
- Fire-and-forget with configurable timeout
- Gradual rollout patterns

### Rate Limiting Features

- **Local** - In-memory, single instance
- **Redis** - Distributed with connection pooling
- **Memcached** - Distributed with TTL control
- Fallback to local on backend failure
- Delay action (instead of hard reject)
- Tiered limits by user type

### Caching Features

- Memory, disk, and hybrid backends
- Per-route TTL configuration
- Vary by headers
- Stale-while-revalidate
- Stale-if-error
- Cache-Control header respect
- Built-in purge and stats endpoints

## Organization

| Example | Description |
|---------|-------------|
| [namespaces.kdl](namespaces.kdl) | Hierarchical resource organization for multi-tenant setups |

### Namespace Features

- Namespace-scoped resources (routes, upstreams, agents, filters)
- Services within namespaces
- Resource exports for sharing across namespaces
- Hierarchical scope resolution (service → namespace → global)
- Per-namespace and per-service limits

## Usage

Copy an example as a starting point:

```bash
cp config/examples/basic.kdl my-config.kdl
sentinel --config my-config.kdl
```

Validate without starting:

```bash
sentinel --config my-config.kdl --dry-run
```

## Related Documentation

- [Main Configuration Reference](../sentinel.kdl) - Full configuration with all options
- [Multi-File Example](../example-multi-file/) - Splitting config across files
- [Config Crate Docs](../../crates/config/) - Parser and schema details

## Configuration Blocks

All examples use these standard blocks:

| Block | Purpose |
|-------|---------|
| `server` | Worker threads, connections, shutdown |
| `listeners` | Listen addresses, TLS, protocols |
| `upstreams` | Backend pools, load balancing, health checks |
| `routes` | Request matching, policies, filters |
| `filters` | Named filter configurations |
| `agents` | External processing agents |
| `observability` | Metrics, logging, tracing |
| `limits` | Header, body, connection limits |
| `cache` | Global cache storage settings |
| `namespaces` | Resource organization |
