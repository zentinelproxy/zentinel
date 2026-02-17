# Patterns

Circuit breakers, registries, and budget tracking patterns.

## Circuit Breaker

Failure isolation pattern to prevent cascade failures.

### State Machine

```
┌─────────────────────────────────────────────────────────┐
│                  Circuit Breaker FSM                     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│      ┌────────┐                              ┌────────┐ │
│      │ CLOSED │─── failures >= threshold ───▶│  OPEN  │ │
│      │        │                              │        │ │
│      │ Normal │                              │ Reject │ │
│      │ traffic│                              │  all   │ │
│      └────────┘                              └────────┘ │
│          ▲                                       │      │
│          │                              timeout  │      │
│          │                                       ▼      │
│          │                               ┌────────────┐ │
│          │                               │ HALF-OPEN  │ │
│          │                               │   Test     │ │
│          └─── success >= threshold ──────│  traffic   │ │
│                                          └────────────┘ │
│                                                 │       │
│                                   failure ──────┘       │
│                                   (back to OPEN)        │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

### Basic Usage

```rust
use zentinel_common::{CircuitBreaker, CircuitBreakerConfig};

// Configure thresholds
let config = CircuitBreakerConfig {
    failure_threshold: 5,      // Open after 5 failures
    success_threshold: 2,      // Close after 2 successes
    timeout_seconds: 30,       // Wait 30s before half-open
    half_open_max_requests: 1, // Allow 1 request in half-open
};

let breaker = CircuitBreaker::new(config);
```

### Request Flow

```rust
async fn call_upstream(breaker: &CircuitBreaker) -> Result<Response, Error> {
    // Check if circuit is closed (requests allowed)
    if !breaker.is_closed() {
        return Err(Error::CircuitOpen);
    }

    // Make the call
    match upstream_request().await {
        Ok(response) => {
            breaker.record_success();
            Ok(response)
        }
        Err(e) => {
            breaker.record_failure();
            Err(e)
        }
    }
}
```

### State Inspection

```rust
use zentinel_common::CircuitBreakerState;

// Get current state
match breaker.state() {
    CircuitBreakerState::Closed => println!("Normal operation"),
    CircuitBreakerState::Open => println!("Circuit open, rejecting"),
    CircuitBreakerState::HalfOpen => println!("Testing recovery"),
}

// Get counters
let failures = breaker.consecutive_failures();
let successes = breaker.consecutive_successes();

// Manual reset
breaker.reset();
```

### Named Circuit Breakers

```rust
// Create with name for logging
let breaker = CircuitBreaker::with_name(config, "payment-gateway");
```

## Registry

Generic thread-safe component storage.

### Basic Usage

```rust
use zentinel_common::Registry;

// Create registry
let routes: Registry<Route> = Registry::new();

// Or with initial capacity
let routes: Registry<Route> = Registry::with_capacity(100);
```

### Operations

```rust
// Insert item
routes.insert("api-v1".to_string(), Arc::new(route)).await;

// Get item
if let Some(route) = routes.get("api-v1").await {
    // Use route
}

// Check existence
if routes.contains("api-v1").await {
    // Route exists
}

// Remove item
let removed = routes.remove("api-v1").await;

// Get all keys
let keys = routes.keys().await;

// Get count
let count = routes.len().await;
```

### Atomic Replacement (Hot Reload)

```rust
// Build new configuration
let mut new_routes = HashMap::new();
new_routes.insert("api-v1".to_string(), Arc::new(new_route));
new_routes.insert("api-v2".to_string(), Arc::new(new_route_v2));

// Atomic swap - returns old routes
let old_routes = routes.replace(new_routes).await;

// Old routes continue serving in-flight requests
// New routes used for new requests
```

### Snapshot

```rust
// Get a point-in-time snapshot
let snapshot = routes.snapshot().await;

// Iterate over snapshot
for (id, route) in &snapshot {
    println!("{}: {:?}", id, route);
}
```

### Custom Operations

```rust
// Execute with read lock
routes.with_read(|map| {
    // Read-only access to internal map
    map.len()
}).await;

// Execute with write lock
routes.with_write(|map| {
    // Mutable access to internal map
    map.retain(|k, _| k.starts_with("api-"));
}).await;
```

## ScopedRegistry

Hierarchical registry with scope-based resolution.

### Setup

```rust
use zentinel_common::{ScopedRegistry, QualifiedId, Scope};

let registry: ScopedRegistry<Policy> = ScopedRegistry::new();
```

### Inserting Items

```rust
// Insert at global scope
registry.insert(
    QualifiedId::global("default-timeout"),
    Arc::new(Policy::timeout(30000)),
).await;

// Insert at namespace scope
registry.insert(
    QualifiedId::namespaced("production", "timeout"),
    Arc::new(Policy::timeout(10000)),
).await;

// Insert at service scope
registry.insert(
    QualifiedId::in_service("production", "payments", "timeout"),
    Arc::new(Policy::timeout(5000)),
).await;

// Insert and export (visible from all scopes)
registry.insert_exported(
    QualifiedId::namespaced("production", "shared-auth"),
    Arc::new(Policy::auth()),
).await;
```

### Resolution

```rust
// Resolve from service scope
let scope = Scope::Service {
    namespace: "production".to_string(),
    service: "payments".to_string(),
};

// Finds "production:payments:timeout" (5000ms)
let policy = registry.resolve("timeout", &scope).await;

// Resolution chain:
// 1. production:payments:timeout (found!)
// 2. production:timeout
// 3. Exported names
// 4. timeout (global)
```

### Direct Lookup

```rust
// By canonical ID
let policy = registry.get_by_canonical("production:payments:timeout").await;

// By QualifiedId
let qid = QualifiedId::in_service("production", "payments", "timeout");
let policy = registry.get(&qid).await;
```

## Token Budgets

Usage limits for inference endpoints.

### Configuration

```rust
use zentinel_common::{TokenBudgetConfig, BudgetPeriod};

let config = TokenBudgetConfig {
    period: BudgetPeriod::Daily,
    limit: 1_000_000,                      // 1M tokens/day
    alert_thresholds: vec![0.80, 0.90, 0.95],
    enforce: true,                         // Block when exhausted
    rollover: false,                       // No rollover
    burst_allowance: Some(0.10),          // 10% burst allowed
};
```

### Budget Periods

```rust
use zentinel_common::BudgetPeriod;

// Predefined periods
let hourly = BudgetPeriod::Hourly;   // Resets every hour
let daily = BudgetPeriod::Daily;     // Resets at midnight UTC
let monthly = BudgetPeriod::Monthly; // Resets on 1st

// Custom period
let custom = BudgetPeriod::Custom { seconds: 3600 * 4 }; // 4 hours

// Get duration
let duration = daily.as_duration(); // 86400 seconds
```

### Checking Budget

```rust
use zentinel_common::BudgetCheckResult;

match tracker.check(estimated_tokens) {
    BudgetCheckResult::Allowed { remaining } => {
        println!("Allowed, {} tokens remaining", remaining);
    }
    BudgetCheckResult::Exhausted { retry_after_secs } => {
        println!("Budget exhausted, retry after {}s", retry_after_secs);
    }
    BudgetCheckResult::Soft { remaining, over_by } => {
        println!("Allowed via burst, {} over limit", over_by);
    }
}

// Check if allowed
if result.is_allowed() {
    // Process request
}
```

### Budget Status

```rust
use zentinel_common::TenantBudgetStatus;

let status = tracker.status();
println!("Used: {} / {}", status.tokens_used, status.tokens_limit);
println!("Remaining: {}", status.tokens_remaining);
println!("Usage: {:.1}%", status.usage_percent * 100.0);
println!("Exhausted: {}", status.exhausted);
println!("Period: {} to {}", status.period_start, status.period_end);
```

### Alerts

```rust
use zentinel_common::BudgetAlert;

// Alerts triggered when thresholds crossed
fn handle_alert(alert: BudgetAlert) {
    println!(
        "Budget alert for {}: {:.0}% used ({}/{})",
        alert.tenant,
        alert.usage_percent() * 100.0,
        alert.tokens_used,
        alert.tokens_limit,
    );
}
```

## Cost Attribution

Track costs for inference requests.

### Configuration

```rust
use zentinel_common::{CostAttributionConfig, ModelPricing};

let config = CostAttributionConfig {
    enabled: true,
    pricing: vec![
        ModelPricing {
            model_pattern: "gpt-4*".to_string(),
            input_cost_per_million: 30.0,
            output_cost_per_million: 60.0,
            currency: None, // Use default
        },
        ModelPricing {
            model_pattern: "gpt-3.5-turbo*".to_string(),
            input_cost_per_million: 0.5,
            output_cost_per_million: 1.5,
            currency: None,
        },
    ],
    default_input_cost: 1.0,
    default_output_cost: 2.0,
    currency: "USD".to_string(),
};
```

### Pattern Matching

```rust
let pricing = ModelPricing {
    model_pattern: "gpt-4*".to_string(),
    input_cost_per_million: 30.0,
    output_cost_per_million: 60.0,
    currency: None,
};

// Pattern matching
assert!(pricing.matches("gpt-4"));
assert!(pricing.matches("gpt-4-turbo"));
assert!(pricing.matches("gpt-4-0125-preview"));
assert!(!pricing.matches("gpt-3.5-turbo"));
```

### Cost Calculation

```rust
use zentinel_common::CostResult;

// Calculate cost
let cost = pricing.calculate_cost(1000, 500);
// Input: 1000 tokens * $30/M = $0.03
// Output: 500 tokens * $60/M = $0.03
// Total: $0.06

let result = CostResult::new(
    "gpt-4".to_string(),
    1000,  // input tokens
    500,   // output tokens
    0.03,  // input cost
    0.03,  // output cost
    "USD".to_string(),
);

println!("Total: ${:.4} {}", result.total_cost, result.currency);
```

## Inference Health Checks

Advanced health checks for LLM backends.

### Inference Probe

Send minimal completion request:

```rust
use zentinel_common::InferenceProbeConfig;

let config = InferenceProbeConfig {
    endpoint: "/v1/completions".to_string(),
    model: "gpt-3.5-turbo".to_string(),
    prompt: ".".to_string(),
    max_tokens: 1,
    timeout_secs: 30,
    max_latency_ms: Some(5000), // Mark unhealthy if > 5s
};
```

### Model Status

Query provider status endpoints:

```rust
use zentinel_common::ModelStatusConfig;

let config = ModelStatusConfig {
    endpoint_pattern: "/v1/models/{model}/status".to_string(),
    models: vec!["gpt-4".to_string(), "gpt-3.5-turbo".to_string()],
    expected_status: "ready".to_string(),
    status_field: "status".to_string(),
    timeout_secs: 30,
};
```

### Queue Depth

Monitor backend queue depth:

```rust
use zentinel_common::QueueDepthConfig;

let config = QueueDepthConfig {
    header: Some("X-Queue-Depth".to_string()),
    body_field: None,
    endpoint: None,
    degraded_threshold: 100,   // Mark degraded if > 100
    unhealthy_threshold: 500,  // Mark unhealthy if > 500
    timeout_secs: 30,
};
```

### Warmth Detection

Detect cold models:

```rust
use zentinel_common::{WarmthDetectionConfig, ColdModelAction};

let config = WarmthDetectionConfig {
    sample_size: 10,
    cold_threshold_multiplier: 2.0,  // 2x baseline = cold
    idle_cold_timeout_secs: 300,     // Cold after 5min idle
    cold_action: ColdModelAction::MarkDegraded,
};
```

**Cold Model Actions:**
- `LogOnly` - Just log (default)
- `MarkDegraded` - Lower weight in LB
- `MarkUnhealthy` - Exclude until warmed
