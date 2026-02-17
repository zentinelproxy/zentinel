# Identifiers & Scoping

Type-safe identifiers and hierarchical scoping for Zentinel configuration.

## Overview

Zentinel uses distinct types for different identifiers to prevent accidental confusion at compile time. The scoping system enables hierarchical configuration with inheritance.

## Identifier Types

### RouteId

Unique identifier for a route in the proxy configuration.

```rust
use zentinel_common::RouteId;

let route = RouteId::new("api-v1");
println!("{}", route.as_str()); // "api-v1"
```

### UpstreamId

Unique identifier for an upstream pool.

```rust
use zentinel_common::UpstreamId;

let upstream = UpstreamId::new("backend-cluster");
```

### AgentId

Unique identifier for an external processing agent.

```rust
use zentinel_common::AgentId;

let agent = AgentId::new("waf-agent");
```

### CorrelationId

Request correlation ID for end-to-end tracing (UUID-based).

```rust
use zentinel_common::CorrelationId;

// Generate new
let id = CorrelationId::new();

// From existing string
let id = CorrelationId::from_string("abc-123-def".to_string());

// Use in headers
response.headers.insert("X-Correlation-Id", id.as_str());
```

### RequestId

Internal request tracking ID for metrics and debugging.

```rust
use zentinel_common::RequestId;

let id = RequestId::new();
tracing::info!(request_id = %id.as_str(), "Processing request");
```

## Scope Hierarchy

Zentinel supports three levels of scope:

```
┌─────────────────────────────────────────────────────────┐
│                        Global                            │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │              Namespace: production               │   │
│   │                                                  │   │
│   │   ┌────────────────┐   ┌────────────────┐      │   │
│   │   │ Service: api   │   │ Service: web   │      │   │
│   │   └────────────────┘   └────────────────┘      │   │
│   │                                                  │   │
│   └──────────────────────────────────────────────────┘   │
│                                                          │
│   ┌─────────────────────────────────────────────────┐   │
│   │               Namespace: staging                 │   │
│   │                                                  │   │
│   │   ┌────────────────┐                            │   │
│   │   │ Service: api   │                            │   │
│   │   └────────────────┘                            │   │
│   │                                                  │   │
│   └──────────────────────────────────────────────────┘   │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Scope Enum

```rust
use zentinel_common::Scope;

// Global scope (visible everywhere)
let global = Scope::Global;

// Namespace scope
let namespace = Scope::Namespace("production".to_string());

// Service scope (within a namespace)
let service = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};
```

### Scope Methods

```rust
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Check scope type
assert!(!scope.is_global());
assert!(!scope.is_namespace());
assert!(scope.is_service());

// Extract components
assert_eq!(scope.namespace(), Some("production"));
assert_eq!(scope.service(), Some("payments"));

// Get parent scope
let parent = scope.parent(); // Scope::Namespace("production")
let grandparent = parent.parent(); // Scope::Global

// Get full chain (most specific to least)
let chain = scope.chain(); // [Service, Namespace, Global]
```

## QualifiedId

Combines a local name with a scope for fully-qualified identification.

### Creation

```rust
use zentinel_common::{QualifiedId, Scope};

// Global scope
let global = QualifiedId::global("timeout-policy");

// Namespace scope
let namespaced = QualifiedId::namespaced("production", "timeout-policy");

// Service scope
let service = QualifiedId::in_service("production", "payments", "timeout-policy");

// From scope and name
let scope = Scope::Namespace("staging".to_string());
let qualified = QualifiedId::new("backend", scope);
```

### Canonical Format

Each QualifiedId has a canonical string representation:

```rust
// Global: "name"
let global = QualifiedId::global("backend");
assert_eq!(global.canonical(), "backend");

// Namespace: "ns:name"
let ns = QualifiedId::namespaced("production", "backend");
assert_eq!(ns.canonical(), "production:backend");

// Service: "ns:svc:name"
let svc = QualifiedId::in_service("production", "api", "backend");
assert_eq!(svc.canonical(), "production:api:backend");
```

### Parsing

```rust
// Parse canonical format
let id = QualifiedId::parse("production:api:backend")?;
assert_eq!(id.name(), "backend");
assert!(id.scope().is_service());

// Check if qualified
let global = QualifiedId::global("name");
assert!(!global.is_qualified());

let namespaced = QualifiedId::namespaced("ns", "name");
assert!(namespaced.is_qualified());
```

## Scope Resolution

The scoped registry resolves names through the scope chain:

```
Resolution Order (most specific first):
1. Service scope: ns:svc:name
2. Namespace scope: ns:name
3. Exported names
4. Global scope: name
```

### Example

```rust
use zentinel_common::{Scope, ScopedRegistry, QualifiedId};

let registry: ScopedRegistry<Config> = ScopedRegistry::new();

// Insert at different scopes
registry.insert(
    QualifiedId::global("timeout"),
    Config { timeout_ms: 30000 }
);
registry.insert(
    QualifiedId::namespaced("production", "timeout"),
    Config { timeout_ms: 10000 }
);
registry.insert(
    QualifiedId::in_service("production", "payments", "timeout"),
    Config { timeout_ms: 5000 }
);

// Resolve from service scope
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Finds service-specific config (5000ms)
let config = registry.resolve("timeout", &scope);

// Resolve from different service (no service-specific config)
let other_scope = Scope::Service {
    namespace: "production".to_string(),
    service: "inventory".to_string(),
};

// Falls back to namespace config (10000ms)
let config = registry.resolve("timeout", &other_scope);

// Resolve from staging namespace
let staging = Scope::Namespace("staging".to_string());

// Falls back to global config (30000ms)
let config = registry.resolve("timeout", &staging);
```

## Visibility Rules

| Scope Level | Can See |
|-------------|---------|
| Global | Global only |
| Namespace | Global + own namespace |
| Service | Global + namespace + own service |

### Exported Names

Names can be marked as exported to make them visible globally:

```rust
// Insert with export
registry.insert_exported(
    QualifiedId::namespaced("production", "shared-policy"),
    policy
);

// Or mark existing as exported
registry.mark_exported("shared-policy");

// Now visible from any scope
let staging = Scope::Namespace("staging".to_string());
let policy = registry.resolve("shared-policy", &staging); // Found!
```

## Use Cases

### Multi-Tenant Configuration

```kdl
// Global defaults
routes {
    route "health" {
        // Visible to all namespaces
    }
}

// Production namespace
namespace "production" {
    routes {
        route "api" {
            // Only visible in production
        }
    }

    service "payments" {
        routes {
            route "checkout" {
                // Only visible in payments service
            }
        }
    }
}
```

### Scoped Rate Limits

```rust
// Global limit
limits.set(Scope::Global, RateLimit::new(10000));

// Stricter for staging
limits.set(
    Scope::Namespace("staging".to_string()),
    RateLimit::new(1000)
);

// Even stricter for specific service
limits.set(
    Scope::Service {
        namespace: "staging".to_string(),
        service: "load-test".to_string(),
    },
    RateLimit::new(100)
);
```

### Scoped Metrics

```rust
use zentinel_common::ScopedMetrics;

let metrics = ScopedMetrics::new();

// Record with scope for proper labeling
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "api".to_string(),
};

metrics.record_request("route-id", "GET", 200, duration, &scope);
// Prometheus labels: {namespace="production", service="api", ...}
```
