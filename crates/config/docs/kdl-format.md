# KDL Configuration Format

Zentinel uses [KDL](https://kdl.dev/) as its primary configuration format. KDL is a document language designed for human readability while being easy to parse.

## Why KDL?

- **Human-friendly**: Clean syntax, easy to read and write
- **Diff-friendly**: Minimal syntax noise for version control
- **Type-safe**: Supports strings, numbers, booleans, and null
- **Comments**: Both line (`//`) and block (`/* */`) comments
- **No ambiguity**: Clear structure without YAML's gotchas

## Basic Syntax

### Nodes

Nodes are the basic building blocks:

```kdl
// Simple node with a value
server-name "zentinel"

// Node with multiple arguments
target "127.0.0.1" 3000

// Node with properties (named arguments)
listener address="0.0.0.0:8080" protocol="http"

// Node with children (block)
server {
    worker-threads 4
    graceful-shutdown-timeout-secs 30
}
```

### Values

```kdl
// Strings (quoted)
name "my-service"

// Numbers
port 8080
timeout 30.5
weight 1

// Booleans
enabled #true
disabled #false

// Null
optional-field #null
```

### Comments

```kdl
// Line comment

/*
 * Block comment
 * spanning multiple lines
 */

server {
    worker-threads 4  // Inline comment
}
```

## Zentinel Configuration Structure

### Top-Level Nodes

```kdl
// Schema version (required for compatibility)
schema-version "1.0"

// Server configuration
server {
    // ...
}

// Listener definitions
listeners {
    listener "name" {
        // ...
    }
}

// Route definitions
routes {
    route "name" {
        // ...
    }
}

// Upstream pool definitions
upstreams {
    upstream "name" {
        // ...
    }
}

// Filter definitions
filters {
    filter "name" {
        // ...
    }
}

// Agent definitions
agents {
    agent "name" {
        // ...
    }
}

// WAF configuration
waf {
    // ...
}

// Observability settings
observability {
    // ...
}

// Global limits
limits {
    // ...
}

// Cache configuration
cache {
    // ...
}
```

## Configuration Examples

### Server Block

```kdl
server {
    worker-threads 0          // 0 = auto-detect CPU cores
    graceful-shutdown-timeout-secs 30
    daemon #false
    pid-file "/var/run/zentinel.pid"
    user "zentinel"
    group "zentinel"
    trace-id-format "tinyflake"  // or "uuid"
    auto-reload #true
}
```

### Listeners Block

```kdl
listeners {
    // HTTP listener
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
        request-timeout-secs 60
        keepalive-timeout-secs 75
        default-route "catch-all"
    }

    // HTTPS listener with TLS
    listener "https" {
        address "0.0.0.0:8443"
        protocol "https"
        request-timeout-secs 60

        tls {
            cert-file "/etc/ssl/certs/server.crt"
            key-file "/etc/ssl/private/server.key"
            min-version "tls1.2"
            client-auth #false
            ocsp-stapling #true

            // SNI certificate for an additional domain.
            // NOTE: parsed and used for ACME issuance, but per-SNI
            // certificate *serving* is not wired in yet (issue #303).
            sni {
                hostnames "api.example.com"
                cert-file "/etc/ssl/certs/api.crt"
                key-file "/etc/ssl/private/api.key"
            }
        }
    }

    // HTTP/2 over cleartext (h2c) with prior knowledge, for trusted internal
    // hops: no TLS, and clients that do not open with the HTTP/2 preface get
    // a 505. (`h2` is the same as `https`: HTTP/2 negotiated over TLS.)
    listener "internal-h2c" {
        address "10.0.0.1:8080"
        protocol "h2c"
    }

    // Internal listener that serves a *separate* route set: requests here are
    // matched only against the "ops" namespace's routes, never the global ones.
    listener "admin" {
        address "127.0.0.1:9000"
        protocol "http"
        namespace "ops"
    }
}
```

#### Protocol and `tls`

A listener serves TLS when its `protocol` is `https` (or `h2`), and then it needs a
`tls` block. `protocol` is `http` when it is not written, and `http` and `h2c`
serve cleartext, so a `tls` block on them would never be used. That is a load
error rather than a listener that quietly serves plain HTTP:

```
Listener 'web': has a 'tls' block, but protocol "http" (the protocol when none is
written) serves plain HTTP/1.1, so the block would not be used. Add protocol
"https" to serve TLS, or remove the 'tls' block.
```

```kdl
listener "web" {
    address "0.0.0.0:443"
    protocol "https"   // required for the tls block below
    tls {
        cert-file "/etc/ssl/certs/server.crt"
        key-file "/etc/ssl/private/server.key"
    }
}
```

#### Per-listener route sets

A listener without `namespace` serves the global top-level `routes`, together
with the routes of every namespace and service that has no listener of its own.
Set `namespace` on a listener to make it serve **only** that namespace's routes
(and those of its services without a listener) in isolation, with no fallback
to the global set — useful for exposing an admin/metrics surface on a separate,
internal port. A namespace with a listener of its own is not served on the
other listeners.

```kdl
listeners {
    // Serves the global routes (default)
    listener "public" {
        address "0.0.0.0:8080"
    }
    // Serves only the "ops" namespace's routes
    listener "admin" {
        address "127.0.0.1:9000"
        namespace "ops"
    }
}

namespace "ops" {
    routes {
        route "metrics" {
            matches { path "/metrics" }
            service-type "builtin"
            builtin-handler "metrics"
        }
    }
}
```

A request on `127.0.0.1:9000` matches only `ops` routes; a request on `:8080`
matches the global `routes` (and those of namespaces without a listener), never
the `ops` ones. The referenced namespace must exist or configuration validation
fails.

A listener declared inside a namespace (`namespace "x" { listeners { ... } }`)
or a service (`service "y" { listener { ... } }`) works the same way: it is
bound like a top-level listener, under the id `x:listener` / `x:y:listener`,
and serves only its scope's routes. One that cannot be bound -- an address
another listener already binds -- is reported by `zentinel test` and
`zentinel lint` as ignored, and its scope's routes are then served nowhere
rather than on the global listeners.

The routes served on one listener are matched together, by priority and then
specificity, as if they were one `routes` block. Inside a namespace or service,
a route's `upstream`, `filters` and agent references resolve in the scope
first, then the namespace, then other namespaces' exports, then the top level;
`ns:name` and `ns:svc:name` name a resource directly. Scoped routes appear in
logs and metrics under their qualified id (`api:main`, `api:users:list`).

### Routes Block

```kdl
routes {
    // Basic route — integer priority (higher = evaluated first)
    route "api" {
        priority 100
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
    }

    // Route with multiple match conditions. Named string aliases are also
    // accepted: "critical" (1000), "high" (100), "normal" (50), "low" (10).
    route "admin" {
        priority "high"
        matches {
            path-prefix "/admin"
            host "admin.example.com"
            method "GET" "POST"
        }
        upstream "admin-backend"
    }

    // Static file serving
    route "static" {
        matches {
            path-prefix "/static"
        }
        service-type "static"
        static-files {
            root "/var/www/static"
            index "index.html"
            cache-control "public, max-age=3600"
            compress #true
        }
    }

    // Built-in handler — gap-based numeric priority allows fine-grained
    // ordering between the named tiers (e.g. 500 sits between HIGH and CRITICAL)
    route "health" {
        priority 1000
        matches {
            path "/health"
        }
        service-type "builtin"
        builtin-handler "health"
    }

    // Inference route (LLM)
    route "llm" {
        matches {
            path-prefix "/v1/chat"
        }
        service-type "inference"
        upstream "openai-backend"
        inference {
            provider "openai"
            rate-limit {
                tokens-per-minute 100000
                burst-tokens 10000
            }
        }
    }

    // Route with policies
    route "api-protected" {
        matches {
            path-prefix "/api/v2"
        }
        upstream "api-backend"
        policies {
            timeout-secs 30
            max-body-size "10MB"
            failure-mode "closed"
            request-headers {
                set {
                    "X-Forwarded-Proto" "https"
                }
                remove "X-Debug"
            }
        }
        filters "auth" "rate-limit"
    }
}
```

### Upstreams Block

```kdl
upstreams {
    // Simple upstream
    upstream "backend" {
        target "127.0.0.1:3000"
    }

    // Multiple targets with load balancing
    upstream "api-cluster" {
        target "10.0.0.1:8080" weight=3
        target "10.0.0.2:8080" weight=2
        target "10.0.0.3:8080" weight=1

        load-balancing "weighted-round-robin"

        health-check {
            type "http"
            path "/health"
            interval-secs 10
            timeout-secs 5
            healthy-threshold 2
            unhealthy-threshold 3
        }

        connection-pool {
            idle-timeout-secs 60
        }

        timeouts {
            connect-secs 10
            request-secs 60
            read-secs 30
            write-secs 30
        }
    }

    // Upstream with TLS
    upstream "secure-backend" {
        target "api.internal:443"

        tls {
            sni "api.internal"
            insecure-skip-verify #false
        }

        http-version {
            min-version 2
            max-version 2
        }
    }

    // HTTP/2 over cleartext (h2c) with prior knowledge: no TLS, no
    // negotiation, no fallback to HTTP/1.1
    upstream "internal-h2" {
        target "10.0.0.5:8080"
        h2c #true
    }
}
```

#### Target syntax

Targets accept several equivalent forms — use whichever reads best. The
shorthand (`target "host:port"`) is recommended:

```kdl
upstream "backend" {
    // Shorthand: address as the first argument (recommended)
    target "127.0.0.1:8081"
    target "127.0.0.1:8082" weight=2

    // Block form: address (and weight) as child nodes
    target { address "127.0.0.1:8083"; weight 3 }

    // Property form
    target address="127.0.0.1:8084" weight=4

    // Optional `targets { ... }` wrapper around any of the above
    targets {
        target "127.0.0.1:8085"
    }
}

// Single-target shorthand on the upstream itself
upstream "single" {
    address "127.0.0.1:8086"
}
```

All forms are accepted identically whether the config is a single file or
split across multiple files.

### Filters Block

```kdl
filters {
    // Rate limiting filter
    filter "rate-limit" {
        type "rate-limit"
        max-rps 100
        burst 20
        key "client-ip"
        on-limit "reject"
        status-code 429
    }

    // Headers filter
    filter "security-headers" {
        type "headers"
        phase "response"
        set {
            "X-Frame-Options" "DENY"
            "X-Content-Type-Options" "nosniff"
            "Strict-Transport-Security" "max-age=31536000"
        }
    }

    // Compression filter
    filter "compress" {
        type "compress"
        algorithms "gzip" "zstd"
        min-size 1024
        level 6
    }

    // CORS filter
    filter "cors" {
        type "cors"
        allowed-origins "https://example.com"
        allowed-methods "GET" "POST" "PUT" "DELETE"
        allow-credentials #true
        max-age-secs 86400
    }

    // GeoIP filter
    filter "geo-block" {
        type "geo"
        database-path "/etc/zentinel/GeoLite2-Country.mmdb"
        action "block"
        countries "RU" "CN" "KP"
        on-failure "open"
    }

    // Agent filter
    filter "auth" {
        type "agent"
        agent "auth-agent"
        timeout-ms 100
        failure-mode "closed"
    }
}
```

### Agents Block

```kdl
agents {
    // Unix socket agent
    agent "waf-agent" {
        type "waf"
        transport {
            unix-socket "/var/run/waf-agent.sock"
        }
        events "request-headers" "request-body"
        timeout-ms 50
        max-request-body-bytes 1048576
    }

    // gRPC agent over TLS. Every TLS option is applied or the configuration is
    // rejected: an https:// address proves the agent's certificate against
    // ca-cert, and client-cert/client-key add mTLS.
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "https://localhost:50051"
                tls {
                    ca-cert "/etc/ssl/certs/ca.crt"
                }
            }
        }
        events "request-headers"
        timeout-ms 100
        circuit-breaker {
            failure-threshold 5
            recovery-timeout-secs 30
        }
    }
}
```

### WAF Block

```kdl
waf {
    engine "coraza"
    mode "prevention"  // or "detection", "off"
    audit-log #true

    ruleset {
        crs-version "4.0"
        paranoia-level 1
        anomaly-threshold 5
        custom-rules-dir "/etc/zentinel/waf-rules"

        exclusions {
            exclusion {
                rule-ids "920170" "920180"
                scope "path" "/api/upload"
            }
        }
    }

    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
        content-types "application/json" "application/x-www-form-urlencoded" "multipart/form-data"
        decompress #false
        max-decompression-ratio 100.0
    }
}
```

`body-inspection { content-types }` is an allowlist of media types, matched
without regard to ASCII case (RFC 9110 section 8.3.1): `APPLICATION/JSON` matches
`application/json`, and leading whitespace and parameters (`; charset=utf-8`) on
the request's value are ignored. An entry matches as a prefix. A request that
carries several `Content-Type` headers is inspected when **any** of them matches.
A request with no `Content-Type` is inspected only when the list has an empty
entry (`content-types "" "application/json"`); an empty list inspects every body.

### Observability Block

```kdl
observability {
    metrics {
        enabled #true
        address "0.0.0.0:9090"
        path "/metrics"
        high-cardinality #false
    }

    logging {
        timestamps #true

        access-log {
            enabled #true
            file "/var/log/zentinel/access.log"
            format "json"
            sample-rate 1.0
            include-trace-id #true
        }

        error-log {
            enabled #true
            file "/var/log/zentinel/error.log"
            level "warn"
        }

        audit-log {
            enabled #true
            file "/var/log/zentinel/audit.log"
            log-blocked #true
            log-waf-events #true
        }
    }

    tracing {
        backend {
            otlp {
                endpoint "http://jaeger:4317"
            }
        }
        sampling-rate 0.01
        service-name "zentinel"
    }
}
```

### Limits Block

```kdl
limits {
    max-header-size 8192
    max-header-count 100
    max-body-size 10485760  // 10MB
    max-connections-per-client 100
}
```

### Cache Block

```kdl
cache {
    enabled #true
    backend "memory"  // or "disk", "hybrid"
    max-size-bytes 104857600  // 100MB
    lock-timeout-secs 10

    // For disk backend
    disk-path "/var/cache/zentinel"
    disk-shards 16
}
```

#### Per-Route Cache Configuration

Cache is configured per route by a `cache` block written in the route itself,
beside `policies`. A `cache` block inside `policies` is not read (see
[Accepted but not applied](schema.md#accepted-but-not-applied)).

```kdl
route "api" {
    matches {
        path-prefix "/api"
    }
    upstream "api-backend"
    // Request headers are not part of the cache key: cache only a route whose
    // response does not vary by a request header
    cache {
        enabled #true
        default-ttl-secs 300
        stale-while-revalidate-secs 60

        // Exclude specific file extensions from caching
        exclude-extensions "php" "html" "asp"

        // Exclude paths using glob patterns (*, **, ?)
        exclude-paths "/wp-admin/**" "/login" "/api/auth/**"
    }
}
```

The `exclude-extensions` and `exclude-paths` options are useful when a broad route pattern (e.g., `path-prefix "/"`) should cache most content but skip certain dynamic paths or file types.

## Property Naming

KDL properties use `kebab-case`:

```kdl
// Correct
worker-threads 4
request-timeout-secs 60
websocket-inspection #true

// Incorrect (will not parse correctly)
workerThreads 4
request_timeout_secs 60
websocketInspection #true
```

## Lists and Arrays

Arrays are specified with brackets:

```kdl
// Array of strings
methods "GET" "POST" "PUT"

// Array in a match condition
matches {
    method "GET" "POST"
    path-prefix "/api"
}

// Array of numbers
ports 8080 8081 8082
```

## Value Types

A setting takes a value of one type: a string in quotes, an integer, a number,
or `#true` / `#false`. A value of another type is a load error, at startup and on
reload, instead of being read as if the setting were absent. The error names the
setting, what it takes, the type that was written, and where it is. It does not
repeat the value:

```
Wrong value type for 'max-connections-per-client' in limits: expected an integer
(without quotes), found a string.
```

```kdl
limits {
    // Integer: no quotes
    max-connections-per-client 100

    // Error: a string where an integer is expected
    // max-connections-per-client "100"
}

tls {
    // String: in quotes
    min-version "1.3"

    // Error: a number where a string is expected
    // min-version 1.3

    // Boolean: #true or #false, no quotes
    client-auth #true
}
```

The same holds for each value of a list (`domains`, `cacheable-methods`,
`filters`, `allow` and `deny`, ...), for a property such as `weight=2`, and for the
value of a header in `set`, `add` and `rename`. A setting that is written with no
value at all is an error too, and so is one written as `name=value` where it takes
an argument (`failure-mode mode="closed"`, which has to be `failure-mode "closed"`),
and an entry written as `name=value` in a list. Omit the node to get the default.
`#null` is the one way to write "no value": the setting keeps its default.
`tls-insecure` alone, with no value, means `#true`.

A few settings take more than one type, and each of the forms below is accepted:

| Setting | Accepted values |
|---------|-----------------|
| `policies { max-body-size }` | an integer number of bytes, or a size string such as `"10MB"` |
| `shadow { percentage }` | a number, or a numeric string such as `"50"` |
| `load-balancing "sticky" { cookie-ttl }` | an integer number of seconds, or a duration string such as `"1h"`, `"30m"` or `"3600"` |
| `health-check { type "http" { expected-status } }` | an integer status code, or a string such as `"204"` |
| `waf { body-inspection { max-decompression-ratio } }` | an integer or a number with a fraction |
| `priority` on a route | an integer, or one of `"low"`, `"normal"`, `"high"`, `"critical"`; any other value is reported by `zentinel lint` and the route has normal priority |

To fix a configuration that now fails, write the value with the type the error
names: add the quotes around a string, or remove them from an integer or a
boolean.

## One Node, One Value

A block reads each of its settings once, so a node that is written twice in the
same block is a load error rather than a choice between the two. The error names
the node and where it is:

```
Duplicate node 'filters' in routes > route "api": it is written 2 times, but only
one of them would take effect. Combine them into a single 'filters' node, or
remove the extra ones.
```

```kdl
route "api" {
    // One node lists every filter
    filters "auth" "rate-limit"

    // Error: 'filters' is written twice in this route
    // filters "auth"
    // filters "rate-limit"
}
```

The same holds for a block (`matches`, `policies`, `timeouts`, `tls`, ...), for a
header named twice inside `set`, `add` or `rename` (header names are compared
without regard to case, so `X-A` and `x-a` are the same header), and for a
`route`, `listener`, `upstream`, `filter` or `agent` whose id is already taken.

To fix a configuration that now fails, merge the copies into one node, or remove
the one that was not in effect. Which copy was in effect depended on the block:
the first for most settings, the last for blocks that are read by walking their
children (an agent's settings, `logging`, a namespace's blocks) and for ids and
header names. Check the behavior you rely on before choosing which to keep.

Inside a `namespace` or a `service`, `limits`, `listeners`, `upstreams`, `routes`,
`agents` and `filters` are each one block, so a second `routes` block there is an
error too. At the top level, `routes` blocks add up.

Nodes that make a list by repeating are the exception, and each repetition adds
to the list: `route`, `listener`, `upstream`, `filter` and `agent` (each with its
own id), `target`, the conditions inside `matches`, an agent's `events`, a
listener's `trusted-proxies`, and the `routes`, `upstreams`, `listeners`,
`filters` and `agents` blocks at the top level.

The top-level `system`, `limits`, `observability`, `rate-limits`, `cache` and
`waf` blocks may also be written again, in another file or in an environment
override; the later one replaces the earlier one.

## Multi-Line Strings

For long values, use a multi-line raw string. The `#` prefix means the contents
are taken literally, so embedded quotes need no escaping, and the indentation of
the closing delimiter is stripped from every line:

```kdl
custom-error-page #"""
    <!DOCTYPE html>
    <html>
    <body>
    <h1>Error</h1>
    </body>
    </html>
    """#
```

## Including Other Files

While KDL itself doesn't have includes, Zentinel's multi-file loader supports directory-based configuration:

```
config/
├── main.kdl
├── routes/
│   └── *.kdl
└── upstreams/
    └── *.kdl
```
