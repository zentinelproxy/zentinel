# Load Balancing Simulation

How upstream selection is simulated.

## Overview

The simulation engine models how load balancers would select backend targets. Since the simulation is stateless, it uses deterministic hashing to produce consistent results.

## Deterministic Selection

All load balancing algorithms use request hashing for determinism:

```rust
// Same request always selects same target
let request = SimulatedRequest::new("GET", "example.com", "/api/users");

let decision1 = simulate(&config, &request);
let decision2 = simulate(&config, &request);

assert_eq!(
    decision1.upstream_selection.unwrap().selected_target,
    decision2.upstream_selection.unwrap().selected_target
);
```

This enables predictable UI behavior in the playground.

## Algorithms

### Round Robin

Distributes requests evenly across targets.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    target "10.0.0.3:8080"
    load-balancing "round-robin"
}
```

**Simulation:** Uses `hash(request) % target_count`

**Selection Reason:**
```
Round robin selection: position 1 of 3 targets
```

### Random

Selects targets randomly.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    load-balancing "random"
}
```

**Simulation:** Same as round robin (deterministic hash)

**Selection Reason:**
```
Random selection (deterministic in simulation)
```

### Weighted

Distributes requests according to target weights.

```kdl
upstream "backend" {
    target "10.0.0.1:8080" weight=5
    target "10.0.0.2:8080" weight=3
    target "10.0.0.3:8080" weight=2
    load-balancing "weighted"
}
```

**Simulation:** Uses weighted bucket selection

```
Total weight = 5 + 3 + 2 = 10

Buckets:
  [0-4]  → 10.0.0.1:8080 (50% probability)
  [5-7]  → 10.0.0.2:8080 (30% probability)
  [8-9]  → 10.0.0.3:8080 (20% probability)

Selection = hash(request) % total_weight
```

**Selection Reason:**
```
Weighted selection: target has weight 5 of 10 total (50.0% probability)
```

### Least Connections

Selects target with fewest active connections.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    load-balancing "least-connections"
}
```

**Simulation:** Simulated as round robin (cannot know real connection counts)

**Selection Reason:**
```
Least connections (simulated as round robin - real connection counts unavailable)
```

### Consistent Hash

Uses consistent hashing for session affinity.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    target "10.0.0.3:8080"
    load-balancing "consistent-hash"
}
```

**Simulation:** Hashes client IP (from `X-Forwarded-For`) or request path

```rust
// Same client always goes to same target
let request1 = SimulatedRequest::new("GET", "example.com", "/api/users")
    .with_header("X-Forwarded-For", "192.168.1.100");

let request2 = SimulatedRequest::new("GET", "example.com", "/api/posts")
    .with_header("X-Forwarded-For", "192.168.1.100");

// Both select same target (same client IP)
```

**Selection Reason:**
```
Consistent hash based on client IP '192.168.1.100'
```

### IP Hash

Hashes client IP for session affinity.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    load-balancing "ip-hash"
}
```

**Simulation:** Uses `X-Forwarded-For` or `X-Real-IP` header

**Selection Reason:**
```
IP hash based on client '192.168.1.100'
```

### Power of Two Choices (P2C)

Picks two random targets, selects the better one.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    target "10.0.0.3:8080"
    target "10.0.0.4:8080"
    load-balancing "power-of-two-choices"
}
```

**Simulation:** Picks two targets based on hash, selects lower index

**Selection Reason:**
```
Power of two choices: selected from candidates [10.0.0.1:8080, 10.0.0.3:8080]
```

### Adaptive

Adapts based on real-time latency metrics.

```kdl
upstream "backend" {
    target "10.0.0.1:8080"
    target "10.0.0.2:8080"
    load-balancing "adaptive"
}
```

**Simulation:** Simulated (real version uses runtime metrics)

**Selection Reason:**
```
Adaptive selection (simulated - real latency metrics unavailable)
```

### Least Tokens Queued

Selects target with fewest queued tokens (for LLM inference).

```kdl
upstream "inference" {
    target "gpu-1.local:8080"
    target "gpu-2.local:8080"
    load-balancing "least-tokens-queued"
}
```

**Simulation:** Simulated (real version uses token queue depths)

**Selection Reason:**
```
Least tokens queued (simulated - real queue depths unavailable)
```

## Upstream Selection Result

The simulation returns complete selection details:

```rust
pub struct UpstreamSelection {
    pub upstream_id: String,       // "backend"
    pub selected_target: String,   // "10.0.0.1:8080"
    pub load_balancer: String,     // "weighted"
    pub selection_reason: String,  // Human-readable explanation
    pub health_status: String,     // "healthy" (simulated)
}
```

## Example Usage

```rust
let config = validate(kdl_config).effective_config.unwrap();
let request = SimulatedRequest::new("GET", "example.com", "/api/users");
let decision = simulate(&config, &request);

if let Some(upstream) = &decision.upstream_selection {
    println!("Upstream: {}", upstream.upstream_id);
    println!("Target: {}", upstream.selected_target);
    println!("Algorithm: {}", upstream.load_balancer);
    println!("Reason: {}", upstream.selection_reason);
    println!("Health: {}", upstream.health_status);
}
```

**Output:**

```
Upstream: backend
Target: 10.0.0.2:8080
Algorithm: weighted
Reason: Weighted selection: target has weight 3 of 10 total (30.0% probability)
Health: healthy
```

## Limitations

| Feature | Simulation | Real Proxy |
|---------|------------|------------|
| Connection counts | Not available | Real-time tracking |
| Latency metrics | Not available | Real-time measurement |
| Token queues | Not available | Actual queue depth |
| Health status | Always "healthy" | Active/passive checks |
| Random selection | Deterministic | True random |

## Hash Function

The simulation uses xxHash3 for fast, deterministic hashing:

```rust
use xxhash_rust::xxh3::xxh3_64;

fn hash_request(request: &SimulatedRequest) -> u64 {
    let key = format!("{}:{}:{}", request.method, request.host, request.path);
    xxh3_64(key.as_bytes())
}
```

This ensures:
- Consistent results across runs
- Fast computation (suitable for WASM)
- Good distribution for load balancing
