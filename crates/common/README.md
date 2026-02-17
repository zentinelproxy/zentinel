# Zentinel Common

Shared types, utilities, and infrastructure for all Zentinel components.

## Overview

The `zentinel-common` crate provides the foundational building blocks used across the Zentinel platform:

- **Type-safe identifiers** - Compile-time safety for IDs and scopes
- **Error handling** - Comprehensive error types with HTTP mapping
- **Resource limits** - Hard bounds for predictable behavior
- **Observability** - Prometheus metrics and structured logging
- **Circuit breakers** - Failure isolation patterns
- **Registries** - Thread-safe component storage with hot reload
- **Budget tracking** - Token budgets and cost attribution for inference

## Modules

| Module | Description |
|--------|-------------|
| `ids` | Type-safe identifiers (RouteId, UpstreamId, AgentId) and hierarchical scoping |
| `types` | Common types (HttpMethod, TlsVersion, LoadBalancingAlgorithm, etc.) |
| `errors` | Error types with HTTP status mapping and client-safe messages |
| `limits` | Resource limits and rate limiting infrastructure |
| `observability` | Prometheus metrics and tracing initialization |
| `circuit_breaker` | Circuit breaker state machine |
| `registry` | Generic thread-safe component registry |
| `scoped_registry` | Scope-aware hierarchical registry |
| `scoped_metrics` | Namespace/service-scoped metrics |
| `budget` | Token budgets and cost attribution for inference |
| `inference` | Inference health check configurations |

## Quick Start

```rust
use zentinel_common::{
    // Identifiers
    RouteId, UpstreamId, Scope, QualifiedId, CorrelationId,

    // Types
    HttpMethod, LoadBalancingAlgorithm, CircuitBreakerConfig,

    // Errors
    ZentinelError, ZentinelResult,

    // Limits
    Limits, RateLimiter,

    // Observability
    RequestMetrics, init_tracing,

    // Patterns
    CircuitBreaker, Registry, ScopedRegistry,
};

// Initialize tracing
init_tracing();

// Create metrics collector
let metrics = RequestMetrics::new();

// Use type-safe identifiers
let route_id = RouteId::new("api-v1");
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Resolve names through scope chain
let qualified = QualifiedId::new("backend", scope.clone());
println!("Canonical: {}", qualified.canonical()); // "production:payments:backend"
```

## Documentation

Detailed documentation is available in the [`docs/`](./docs/) directory:

- [Identifiers & Scoping](./docs/identifiers.md) - Type-safe IDs and hierarchical scopes
- [Types Reference](./docs/types.md) - Common type definitions
- [Error Handling](./docs/errors.md) - Error types and HTTP mapping
- [Limits & Rate Limiting](./docs/limits.md) - Resource bounds
- [Observability](./docs/observability.md) - Metrics and logging
- [Patterns](./docs/patterns.md) - Circuit breakers and registries

## Hierarchical Scoping

Zentinel supports hierarchical configuration with scope-based resolution:

```
Global
  └── Namespace (e.g., "production")
        └── Service (e.g., "payments")
```

Names resolve through the scope chain (most specific wins):

```rust
use zentinel_common::{Scope, ScopedRegistry};

let registry: ScopedRegistry<Config> = ScopedRegistry::new();

// Insert at different scopes
registry.insert(QualifiedId::global("timeout"), global_config);
registry.insert(QualifiedId::namespaced("production", "timeout"), prod_config);
registry.insert(QualifiedId::in_service("production", "payments", "timeout"), payments_config);

// Resolve from service scope
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Finds "production:payments:timeout" first
let config = registry.resolve("timeout", &scope);
```

## Error Handling

All errors map to appropriate HTTP status codes:

```rust
use zentinel_common::{ZentinelError, ZentinelResult};

fn process_request() -> ZentinelResult<Response> {
    // Errors automatically map to HTTP status
    Err(ZentinelError::RateLimit {
        message: "Too many requests".to_string(),
        retry_after_secs: Some(60),
    })
}

// In handler
match result {
    Ok(response) => response,
    Err(e) => {
        let status = e.to_http_status();  // 429
        let message = e.client_message(); // Safe for client
        // ...
    }
}
```

## Resource Limits

Hard bounds prevent resource exhaustion:

```rust
use zentinel_common::Limits;

// Production defaults
let limits = Limits::for_production();

// Check before processing
if body.len() > limits.max_body_size_bytes {
    return Err(ZentinelError::LimitExceeded {
        limit_type: LimitType::BodySize,
        message: "Request body too large".to_string(),
        current_value: body.len() as u64,
        limit: limits.max_body_size_bytes as u64,
    });
}
```

## Observability

Prometheus metrics with automatic registration:

```rust
use zentinel_common::RequestMetrics;

let metrics = RequestMetrics::new();

// Record request
metrics.record_request("api", "GET", 200, Duration::from_millis(50));

// Track active requests
metrics.inc_active_requests();
// ... process ...
metrics.dec_active_requests();

// Circuit breaker state
metrics.set_circuit_breaker_state("upstream", "api", true);
```

## Circuit Breakers

Failure isolation with automatic recovery:

```rust
use zentinel_common::{CircuitBreaker, CircuitBreakerConfig};

let config = CircuitBreakerConfig {
    failure_threshold: 5,
    success_threshold: 2,
    timeout_seconds: 30,
    half_open_max_requests: 1,
};

let breaker = CircuitBreaker::new(config);

// Check before calling
if !breaker.is_closed() {
    return Err(ZentinelError::CircuitBreakerOpen { ... });
}

// Record result
match upstream_call().await {
    Ok(response) => {
        breaker.record_success();
        Ok(response)
    }
    Err(e) => {
        breaker.record_failure();
        Err(e)
    }
}
```

## Token Budgets

For inference routes with usage limits:

```rust
use zentinel_common::{TokenBudgetConfig, BudgetPeriod, BudgetCheckResult};

let config = TokenBudgetConfig {
    period: BudgetPeriod::Daily,
    limit: 1_000_000,
    enforce: true,
    alert_thresholds: vec![0.80, 0.90, 0.95],
    ..Default::default()
};

// Check budget before processing
match budget_tracker.check(estimated_tokens) {
    BudgetCheckResult::Allowed { remaining } => {
        // Process request
    }
    BudgetCheckResult::Exhausted { retry_after_secs } => {
        return Err(ZentinelError::LimitExceeded { ... });
    }
    BudgetCheckResult::Soft { remaining, over_by } => {
        // Allowed via burst allowance
    }
}
```

## Design Principles

1. **Type Safety** - Distinct ID types prevent accidental confusion
2. **Fail-Safe Defaults** - Secure, bounded defaults everywhere
3. **Observability First** - Metrics for every significant operation
4. **Lock-Free Hot Paths** - Atomic operations where possible
5. **Graceful Degradation** - Clear failure modes with fallbacks

## Usage by Other Crates

| Crate | Uses |
|-------|------|
| `config` | Types, Limits, Error handling, ID types |
| `proxy` | All modules - core runtime infrastructure |
| `agent-protocol` | Error types, ID types |

## Minimum Rust Version

Rust 1.92.0 or later (Edition 2021)
