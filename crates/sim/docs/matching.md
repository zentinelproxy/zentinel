# Route Matching

How routes are matched in the simulation engine.

## Overview

The route matcher evaluates routes in order of priority and specificity, returning the first route where all conditions match.

```
Request arrives
      │
      ▼
Sort routes by priority (desc) → specificity (desc)
      │
      ▼
For each route:
      │
      ├── Evaluate all conditions
      │         │
      │    ┌────┴────┐
      │    │All pass?│
      │    └────┬────┘
      │         │
      │    Yes  │  No
      │    ↓    │  ↓
      │  MATCH  │  Continue to next route
      │         │
      ▼         ▼
Return matched route (or default/none)
```

## Match Conditions

### Path Prefix

Matches if request path starts with the specified prefix.

```kdl
route "api" {
    matches {
        path-prefix "/api"
    }
}
```

| Request Path | Matches |
|--------------|---------|
| `/api` | Yes |
| `/api/users` | Yes |
| `/api/users/123` | Yes |
| `/apis` | No |
| `/other` | No |

### Exact Path

Matches only if request path exactly equals the specified path.

```kdl
route "health" {
    matches {
        path "/health"
    }
}
```

| Request Path | Matches |
|--------------|---------|
| `/health` | Yes |
| `/health/` | No |
| `/health/check` | No |

### Path Regex

Matches if request path matches the regular expression.

```kdl
route "api-versioned" {
    matches {
        path-regex "^/api/v[0-9]+/"
    }
}
```

| Request Path | Matches |
|--------------|---------|
| `/api/v1/users` | Yes |
| `/api/v2/posts` | Yes |
| `/api/v10/items` | Yes |
| `/api/users` | No |
| `/api/vX/users` | No |

### Host

Matches based on the request host.

**Exact match:**

```kdl
route "api" {
    matches {
        host "api.example.com"
    }
}
```

**Wildcard match:**

```kdl
route "subdomains" {
    matches {
        host "*.example.com"
    }
}
```

| Host | Pattern | Matches |
|------|---------|---------|
| `api.example.com` | `api.example.com` | Yes |
| `www.example.com` | `api.example.com` | No |
| `api.example.com` | `*.example.com` | Yes |
| `sub.api.example.com` | `*.example.com` | Yes |
| `example.com` | `*.example.com` | No |

**Regex match:**

```kdl
route "regional" {
    matches {
        host "[a-z]{2}.api.example.com"
    }
}
```

### HTTP Method

Matches if request method is in the allowed list.

```kdl
route "api-write" {
    matches {
        path-prefix "/api"
        method "POST" "PUT" "DELETE"
    }
}
```

| Method | Allowed Methods | Matches |
|--------|-----------------|---------|
| `POST` | `POST, PUT, DELETE` | Yes |
| `GET` | `POST, PUT, DELETE` | No |
| `PUT` | `POST, PUT, DELETE` | Yes |

### Header

Matches based on header presence or value.

**Presence check:**

```kdl
route "authenticated" {
    matches {
        header "Authorization"
    }
}
```

**Value check:**

```kdl
route "json-api" {
    matches {
        header "Content-Type" "application/json"
    }
}
```

| Header | Pattern | Matches |
|--------|---------|---------|
| `Authorization: Bearer x` | `Authorization` (presence) | Yes |
| (no Authorization header) | `Authorization` (presence) | No |
| `Content-Type: application/json` | `Content-Type: application/json` | Yes |
| `Content-Type: text/html` | `Content-Type: application/json` | No |

### Query Parameter

Matches based on query parameter presence or value.

**Presence check:**

```kdl
route "search" {
    matches {
        query-param "q"
    }
}
```

**Value check:**

```kdl
route "api-v2" {
    matches {
        query-param "version" "2"
    }
}
```

## Priority

Routes are evaluated in priority order (highest first).

```kdl
routes {
    route "critical" {
        priority "critical"  // Evaluated first
        matches { path "/health" }
    }

    route "high" {
        priority "high"      // Evaluated second
        matches { path-prefix "/admin" }
    }

    route "normal" {
        priority "normal"    // Evaluated third (default)
        matches { path-prefix "/api" }
    }

    route "low" {
        priority "low"       // Evaluated last
        matches { path-prefix "/" }
    }
}
```

**Priority Levels:**

| Priority | Order |
|----------|-------|
| Critical | 1st (highest) |
| High | 2nd |
| Normal | 3rd (default) |
| Low | 4th (lowest) |

## Specificity

Within the same priority level, routes are ordered by specificity score. More specific routes are evaluated first.

**Specificity Scores:**

| Condition Type | Score |
|----------------|-------|
| Exact Path | 1000 |
| Path Regex | 500 |
| Path Prefix | 100 |
| Host | 50 |
| Header (with value) | 30 |
| Query Param (with value) | 25 |
| Header (presence only) | 20 |
| Query Param (presence only) | 15 |
| Method | 10 |

**Example:**

```kdl
routes {
    // Specificity: 1000 (exact path)
    route "exact" {
        matches { path "/api/users" }
    }

    // Specificity: 130 (prefix 100 + header 30)
    route "json-api" {
        matches {
            path-prefix "/api"
            header "Content-Type" "application/json"
        }
    }

    // Specificity: 100 (prefix only)
    route "api" {
        matches { path-prefix "/api" }
    }
}
```

For a request to `/api/users` with `Content-Type: application/json`:
1. `exact` matches (specificity 1000)
2. `json-api` would match but is skipped (lower specificity)
3. `api` would match but is skipped (lower specificity)

## Match Tracing

The simulator provides detailed tracing of match decisions.

```rust
let decision = simulate(&config, &request);

for step in &decision.match_trace {
    match step.result {
        MatchStepResult::Match => {
            println!("✓ Route '{}' matched", step.route_id);
        }
        MatchStepResult::NoMatch => {
            println!("✗ Route '{}': {}", step.route_id, step.reason);
        }
        MatchStepResult::Skipped => {
            println!("- Route '{}' skipped (lower priority)", step.route_id);
        }
    }

    // Show condition details
    for detail in &step.condition_details {
        let icon = if detail.matched { "✓" } else { "✗" };
        println!("  {} {}: {}",
            icon,
            detail.condition_type,
            detail.explanation.as_deref().unwrap_or("")
        );
    }
}
```

**Example Output:**

```
✗ Route 'admin': PathPrefix condition failed
  ✗ PathPrefix: Path '/api/users' does not start with '/admin'

✓ Route 'api' matched
  ✓ PathPrefix: Path '/api/users' starts with '/api'
  ✓ Method: Method 'GET' is in allowed list [GET, POST, PUT]

- Route 'fallback' skipped (lower priority)
```

## Default Route

If no routes match, the default route (if configured) is used.

```kdl
listeners {
    listener "http" {
        address "0.0.0.0:8080"
        default-route "fallback"
    }
}

routes {
    route "fallback" {
        matches { path-prefix "/" }
        service-type "builtin"
        builtin-handler "not-found"
    }
}
```

## Multiple Conditions

When a route has multiple conditions, ALL must match.

```kdl
route "admin-api" {
    matches {
        path-prefix "/admin"           // AND
        host "admin.example.com"       // AND
        method "GET" "POST"            // AND
        header "Authorization"         // ALL must match
    }
}
```

| Request | Matches |
|---------|---------|
| `GET /admin/users` on `admin.example.com` with `Authorization` header | Yes |
| `GET /admin/users` on `api.example.com` with `Authorization` header | No (wrong host) |
| `DELETE /admin/users` on `admin.example.com` with `Authorization` header | No (wrong method) |
| `GET /admin/users` on `admin.example.com` without `Authorization` header | No (missing header) |
