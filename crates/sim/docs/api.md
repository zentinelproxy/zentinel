# API Reference

Public API for the Sentinel simulation engine.

## Functions

### validate

Validates a KDL configuration string.

```rust
pub fn validate(kdl_config: &str) -> ValidationResult
```

**Parameters:**
- `kdl_config` - KDL configuration as a string

**Returns:** `ValidationResult` with validation status, errors, warnings, and parsed config

**Example:**

```rust
let result = validate(r#"
schema-version "1.0"

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}
"#);

if result.valid {
    println!("Config is valid");
} else {
    for error in &result.errors {
        eprintln!("Line {}: {}", error.line, error.message);
    }
}
```

### simulate

Simulates routing a request through the configuration.

```rust
pub fn simulate(config: &Config, request: &SimulatedRequest) -> RouteDecision
```

**Parameters:**
- `config` - Parsed configuration (from `ValidationResult.effective_config`)
- `request` - Simulated HTTP request

**Returns:** `RouteDecision` with matched route, trace, policies, and upstream selection

**Example:**

```rust
let request = SimulatedRequest::new("GET", "api.example.com", "/users");
let decision = simulate(&config, &request);

match &decision.matched_route {
    Some(route) => println!("Matched: {}", route.route_id),
    None => println!("No route matched"),
}
```

### get_effective_config

Returns the normalized configuration with all defaults applied.

```rust
pub fn get_effective_config(config: &Config) -> serde_json::Value
```

**Parameters:**
- `config` - Parsed configuration

**Returns:** JSON representation of the configuration with defaults

## Types

### SimulatedRequest

Represents an HTTP request for simulation.

```rust
pub struct SimulatedRequest {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}
```

**Constructors:**

```rust
// Basic request
let request = SimulatedRequest::new("GET", "example.com", "/api/users");

// With headers
let request = SimulatedRequest::new("POST", "example.com", "/api/users")
    .with_header("Content-Type", "application/json")
    .with_header("Authorization", "Bearer token123");

// With query parameters
let request = SimulatedRequest::new("GET", "example.com", "/search")
    .with_query_param("q", "test")
    .with_query_param("page", "1");

// With multiple headers at once
let headers = HashMap::from([
    ("Accept".to_string(), "application/json".to_string()),
    ("X-Custom".to_string(), "value".to_string()),
]);
let request = SimulatedRequest::new("GET", "example.com", "/api")
    .with_headers(headers);
```

**Methods:**

| Method | Description |
|--------|-------------|
| `new(method, host, path)` | Create new request |
| `with_header(name, value)` | Add a header |
| `with_headers(map)` | Add multiple headers |
| `with_query_param(name, value)` | Add query parameter |
| `path_without_query()` | Get path without query string |
| `cache_key()` | Generate cache key for request |

### ValidationResult

Result of configuration validation.

```rust
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<Warning>,
    pub effective_config: Option<Config>,
}
```

**Fields:**

| Field | Description |
|-------|-------------|
| `valid` | Whether configuration is valid |
| `errors` | Parse or validation errors (fatal) |
| `warnings` | Non-fatal warnings about potential issues |
| `effective_config` | Parsed config if valid, None otherwise |

### ValidationError

A configuration error.

```rust
pub struct ValidationError {
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub context: Option<String>,
}
```

### Warning

A non-fatal configuration warning.

```rust
pub struct Warning {
    pub code: String,
    pub message: String,
    pub route_id: Option<String>,
    pub suggestion: Option<String>,
}
```

**Warning Codes:**

| Code | Description |
|------|-------------|
| `W001` | Route has no upstream (and not static/builtin) |
| `W002` | Route references undefined upstream |
| `W003` | Duplicate route ID |
| `W004` | Shadow config without body buffering |
| `W005` | WebSocket inspection without WebSocket enabled |

### RouteDecision

Complete result of route simulation.

```rust
pub struct RouteDecision {
    pub matched_route: Option<MatchedRoute>,
    pub match_trace: Vec<MatchStep>,
    pub applied_policies: Option<AppliedPolicies>,
    pub upstream_selection: Option<UpstreamSelection>,
    pub agent_hooks: Vec<AgentHook>,
    pub warnings: Vec<Warning>,
}
```

### MatchedRoute

Information about a matched route.

```rust
pub struct MatchedRoute {
    pub route_id: String,
    pub priority: String,
    pub service_type: String,
    pub upstream_id: Option<String>,
}
```

### MatchStep

One step in the route matching trace.

```rust
pub struct MatchStep {
    pub route_id: String,
    pub result: MatchStepResult,
    pub reason: String,
    pub conditions_checked: usize,
    pub conditions_passed: usize,
    pub condition_details: Vec<ConditionDetail>,
}

pub enum MatchStepResult {
    Match,
    NoMatch,
    Skipped,
}
```

### ConditionDetail

Detail about a single match condition.

```rust
pub struct ConditionDetail {
    pub condition_type: String,
    pub pattern: String,
    pub matched: bool,
    pub actual_value: Option<String>,
    pub explanation: Option<String>,
}
```

**Condition Types:**

| Type | Description |
|------|-------------|
| `PathPrefix` | Path prefix match |
| `Path` | Exact path match |
| `PathRegex` | Regex path match |
| `Host` | Host match (exact or wildcard) |
| `Method` | HTTP method match |
| `Header` | Header presence or value match |
| `QueryParam` | Query parameter match |

### AppliedPolicies

Policies that would apply to matched route.

```rust
pub struct AppliedPolicies {
    pub timeout_secs: Option<u64>,
    pub max_body_size: Option<String>,
    pub failure_mode: String,
    pub rate_limit: Option<RateLimitInfo>,
    pub cache: Option<CacheInfo>,
    pub buffer_requests: bool,
    pub buffer_responses: bool,
}
```

### RateLimitInfo

Rate limiting configuration.

```rust
pub struct RateLimitInfo {
    pub requests_per_second: u32,
    pub burst: u32,
    pub key: String,
}
```

### CacheInfo

Caching configuration.

```rust
pub struct CacheInfo {
    pub enabled: bool,
    pub ttl_secs: Option<u64>,
    pub vary_headers: Vec<String>,
}
```

### UpstreamSelection

Simulated upstream selection.

```rust
pub struct UpstreamSelection {
    pub upstream_id: String,
    pub selected_target: String,
    pub load_balancer: String,
    pub selection_reason: String,
    pub health_status: String,
}
```

### AgentHook

Agent that would be invoked for the route.

```rust
pub struct AgentHook {
    pub agent_id: String,
    pub hook: String,
    pub timeout_ms: u64,
    pub failure_mode: String,
    pub body_inspection: Option<BodyInspectionInfo>,
}
```

**Hook Types:**

| Hook | Description |
|------|-------------|
| `on_request_headers` | Called after request headers received |
| `on_request_body` | Called with request body |
| `on_response_headers` | Called after response headers |
| `on_response_body` | Called with response body |

### BodyInspectionInfo

Body inspection configuration for agent.

```rust
pub struct BodyInspectionInfo {
    pub max_bytes: usize,
    pub content_types: Vec<String>,
}
```
