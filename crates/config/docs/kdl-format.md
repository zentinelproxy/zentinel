# KDL Configuration Format

Sentinel uses [KDL](https://kdl.dev/) as its primary configuration format. KDL is a document language designed for human readability while being easy to parse.

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
server-name "sentinel"

// Node with multiple arguments
target "127.0.0.1" 3000

// Node with properties (named arguments)
listener address="0.0.0.0:8080" protocol="http"

// Node with children (block)
server {
    worker-threads 4
    max-connections 10000
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
enabled true
disabled false

// Null
optional-field null
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

## Sentinel Configuration Structure

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
    max-connections 10000
    graceful-shutdown-timeout-secs 30
    daemon false
    pid-file "/var/run/sentinel.pid"
    user "sentinel"
    group "sentinel"
    trace-id-format "tinyflake"  // or "uuid"
    auto-reload true
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
            client-auth false
            ocsp-stapling true

            // SNI support for multiple domains
            additional-certs {
                cert hostnames=["api.example.com"] {
                    cert-file "/etc/ssl/certs/api.crt"
                    key-file "/etc/ssl/private/api.key"
                }
            }
        }
    }

    // HTTP/2 listener
    listener "h2" {
        address "0.0.0.0:8443"
        protocol "h2"
        max-concurrent-streams 100
    }
}
```

### Routes Block

```kdl
routes {
    // Basic route
    route "api" {
        priority "normal"
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
    }

    // Route with multiple match conditions
    route "admin" {
        priority "high"
        matches {
            path-prefix "/admin"
            host "admin.example.com"
            method ["GET" "POST"]
        }
        upstream "admin-backend"
        waf-enabled true
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
            compress true
        }
    }

    // Built-in handler
    route "health" {
        priority "high"
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
                remove ["X-Debug"]
            }
        }
        filters ["auth" "rate-limit"]
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
            max-connections 100
            max-idle 20
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
            insecure-skip-verify false
            ca-cert "/etc/ssl/certs/internal-ca.crt"
        }

        http-version {
            min-version 2
            max-version 2
        }
    }
}
```

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
        algorithms ["gzip" "brotli"]
        min-size 1024
        level 6
    }

    // CORS filter
    filter "cors" {
        type "cors"
        allowed-origins ["https://example.com"]
        allowed-methods ["GET" "POST" "PUT" "DELETE"]
        allow-credentials true
        max-age-secs 86400
    }

    // GeoIP filter
    filter "geo-block" {
        type "geo"
        database-path "/etc/sentinel/GeoLite2-Country.mmdb"
        action "block"
        countries ["RU" "CN" "KP"]
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
        events ["request-headers" "request-body"]
        timeout-ms 50
        failure-mode "open"
        max-request-body-bytes 1048576
    }

    // gRPC agent
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "localhost:50051"
                tls {
                    insecure-skip-verify false
                    ca-cert "/etc/ssl/certs/ca.crt"
                }
            }
        }
        events ["request-headers"]
        timeout-ms 100
        failure-mode "closed"
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
    audit-log true

    ruleset {
        crs-version "4.0"
        paranoia-level 1
        anomaly-threshold 5
        custom-rules-dir "/etc/sentinel/waf-rules"

        exclusions {
            exclusion {
                rule-ids ["920170" "920180"]
                scope "path" "/api/upload"
            }
        }
    }

    body-inspection {
        inspect-request-body true
        inspect-response-body false
        max-inspection-bytes 1048576
        content-types [
            "application/json"
            "application/x-www-form-urlencoded"
            "multipart/form-data"
        ]
        decompress false
        max-decompression-ratio 100.0
    }
}
```

### Observability Block

```kdl
observability {
    metrics {
        enabled true
        address "0.0.0.0:9090"
        path "/metrics"
        high-cardinality false
    }

    logging {
        level "info"
        format "json"
        timestamps true

        access-log {
            enabled true
            file "/var/log/sentinel/access.log"
            format "json"
            sample-rate 1.0
            include-trace-id true
        }

        error-log {
            enabled true
            file "/var/log/sentinel/error.log"
            level "warn"
        }

        audit-log {
            enabled true
            file "/var/log/sentinel/audit.log"
            log-blocked true
            log-waf-events true
        }
    }

    tracing {
        backend {
            otlp {
                endpoint "http://jaeger:4317"
            }
        }
        sampling-rate 0.01
        service-name "sentinel"
    }
}
```

### Limits Block

```kdl
limits {
    max-header-size-bytes 8192
    max-header-count 100
    max-body-size-bytes 10485760  // 10MB
    max-connections-per-client 100
}
```

### Cache Block

```kdl
cache {
    enabled true
    backend "memory"  // or "disk", "hybrid"
    max-size-bytes 104857600  // 100MB
    lock-timeout-secs 10

    // For disk backend
    disk-path "/var/cache/sentinel"
    disk-shards 16
}
```

## Property Naming

KDL properties use `kebab-case`:

```kdl
// Correct
max-connections 1000
request-timeout-secs 60
waf-enabled true

// Incorrect (will not parse correctly)
maxConnections 1000
request_timeout_secs 60
wafEnabled true
```

## Lists and Arrays

Arrays are specified with brackets:

```kdl
// Array of strings
methods ["GET" "POST" "PUT"]

// Array in a match condition
matches {
    method ["GET" "POST"]
    path-prefix "/api"
}

// Array of numbers
ports [8080 8081 8082]
```

## Multi-Line Strings

For long values, use raw strings:

```kdl
custom-error-page r#"
<!DOCTYPE html>
<html>
<body>
<h1>Error</h1>
</body>
</html>
"#
```

## Including Other Files

While KDL itself doesn't have includes, Sentinel's multi-file loader supports directory-based configuration:

```
config/
├── main.kdl
├── routes/
│   └── *.kdl
└── upstreams/
    └── *.kdl
```
