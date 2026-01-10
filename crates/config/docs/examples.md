# Configuration Examples

Common configuration patterns for Sentinel deployments.

## Basic Reverse Proxy

Simple HTTP reverse proxy to a single backend:

```kdl
schema-version "1.0"

server {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "all" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
    }
}
```

## HTTPS with TLS Termination

```kdl
schema-version "1.0"

server {
    worker-threads 0
}

listeners {
    // Redirect HTTP to HTTPS
    listener "http" {
        address "0.0.0.0:80"
        protocol "http"
        default-route "redirect-https"
    }

    listener "https" {
        address "0.0.0.0:443"
        protocol "https"
        tls {
            cert-file "/etc/ssl/certs/server.crt"
            key-file "/etc/ssl/private/server.key"
            min-version "tls1.2"
        }
        default-route "app"
    }
}

upstreams {
    upstream "app-backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "redirect-https" {
        matches {
            path-prefix "/"
        }
        service-type "builtin"
        policies {
            response-headers {
                set {
                    "Location" "https://${host}${uri}"
                }
            }
        }
    }

    route "app" {
        matches {
            path-prefix "/"
        }
        upstream "app-backend"
        policies {
            response-headers {
                set {
                    "Strict-Transport-Security" "max-age=31536000; includeSubDomains"
                }
            }
        }
    }
}
```

## Load Balanced Backend

Multiple backend servers with health checks:

```kdl
schema-version "1.0"

upstreams {
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
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "api-cluster"
        retry-policy {
            max-retries 2
            retry-on ["5xx" "connection-error"]
        }
    }
}
```

## API Gateway with Rate Limiting

```kdl
schema-version "1.0"

filters {
    filter "api-rate-limit" {
        type "rate-limit"
        max-rps 100
        burst 20
        key "header" "X-API-Key"
        on-limit "reject"
        status-code 429
    }

    filter "security-headers" {
        type "headers"
        phase "response"
        set {
            "X-Content-Type-Options" "nosniff"
            "X-Frame-Options" "DENY"
            "X-XSS-Protection" "1; mode=block"
        }
    }
}

upstreams {
    upstream "api-backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
            header name="X-API-Key"
        }
        upstream "api-backend"
        service-type "api"
        filters ["api-rate-limit" "security-headers"]
    }

    route "api-unauthorized" {
        matches {
            path-prefix "/api"
        }
        service-type "builtin"
        builtin-handler "not-found"
    }
}
```

## Static File Server with SPA Support

```kdl
schema-version "1.0"

routes {
    // API routes first (higher priority)
    route "api" {
        priority "high"
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
    }

    // Static files with SPA fallback
    route "static" {
        matches {
            path-prefix "/"
        }
        service-type "static"
        static-files {
            root "/var/www/app"
            index "index.html"
            fallback "index.html"  // SPA fallback
            cache-control "public, max-age=3600"
            compress true
            mime-types {
                ".wasm" "application/wasm"
            }
        }
    }
}

filters {
    filter "compress" {
        type "compress"
        algorithms ["brotli" "gzip"]
        min-size 1024
        content-types [
            "text/html"
            "text/css"
            "application/javascript"
            "application/json"
        ]
    }
}
```

## Multi-Domain with SNI

```kdl
schema-version "1.0"

listeners {
    listener "https" {
        address "0.0.0.0:443"
        protocol "https"
        tls {
            // Default certificate
            cert-file "/etc/ssl/certs/default.crt"
            key-file "/etc/ssl/private/default.key"

            // Additional certificates for SNI
            additional-certs {
                cert hostnames=["api.example.com" "*.api.example.com"] {
                    cert-file "/etc/ssl/certs/api.crt"
                    key-file "/etc/ssl/private/api.key"
                }
                cert hostnames=["admin.example.com"] {
                    cert-file "/etc/ssl/certs/admin.crt"
                    key-file "/etc/ssl/private/admin.key"
                }
            }
        }
    }
}

routes {
    route "api" {
        matches {
            host "api.example.com"
        }
        upstream "api-backend"
    }

    route "admin" {
        matches {
            host "admin.example.com"
        }
        upstream "admin-backend"
        waf-enabled true
    }

    route "main" {
        matches {
            host "www.example.com"
        }
        upstream "web-backend"
    }
}
```

## WAF-Protected Application

```kdl
schema-version "1.0"

waf {
    engine "coraza"
    mode "prevention"
    audit-log true

    ruleset {
        crs-version "4.0"
        paranoia-level 1
        anomaly-threshold 5

        exclusions {
            // Exclude file upload endpoint from body inspection
            exclusion {
                rule-ids ["920170" "920180"]
                scope "path" "/api/upload"
            }

            // Exclude webhook endpoint
            exclusion {
                rule-ids ["920170"]
                scope "path" "/webhooks"
            }
        }
    }

    body-inspection {
        inspect-request-body true
        max-inspection-bytes 1048576
        content-types [
            "application/json"
            "application/x-www-form-urlencoded"
            "multipart/form-data"
        ]
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
        waf-enabled true
    }
}
```

## External Authentication Agent

```kdl
schema-version "1.0"

agents {
    agent "auth-agent" {
        type "auth"
        transport {
            grpc {
                address "localhost:50051"
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

filters {
    filter "auth" {
        type "agent"
        agent "auth-agent"
        phase "request"
        failure-mode "closed"
    }
}

routes {
    route "protected-api" {
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
        filters ["auth"]
    }

    route "public" {
        matches {
            path-prefix "/public"
        }
        upstream "api-backend"
    }
}
```

## LLM Inference Gateway

```kdl
schema-version "1.0"

upstreams {
    upstream "openai" {
        target "api.openai.com:443"
        tls {
            sni "api.openai.com"
        }
    }

    upstream "anthropic" {
        target "api.anthropic.com:443"
        tls {
            sni "api.anthropic.com"
        }
    }
}

routes {
    route "openai-proxy" {
        matches {
            path-prefix "/v1/chat/completions"
            header name="X-Provider" value="openai"
        }
        upstream "openai"
        service-type "inference"
        inference {
            provider "openai"
            rate-limit {
                tokens-per-minute 100000
                requests-per-minute 100
                burst-tokens 10000
            }
            budget {
                daily-limit 1000000
                monthly-limit 10000000
            }
        }
    }

    route "anthropic-proxy" {
        matches {
            path-prefix "/v1/messages"
            header name="X-Provider" value="anthropic"
        }
        upstream "anthropic"
        service-type "inference"
        inference {
            provider "anthropic"
            rate-limit {
                tokens-per-minute 50000
                burst-tokens 5000
            }
            guardrails {
                prompt-injection {
                    enabled true
                    agent "guardrail-agent"
                    action "block"
                }
            }
        }
    }
}

// Model-based routing with fallback
routes {
    route "llm-router" {
        matches {
            path-prefix "/v1/chat"
        }
        upstream "openai"
        service-type "inference"
        inference {
            provider "openai"
            model-routing {
                model "gpt-4*" upstream="openai"
                model "claude-*" upstream="anthropic" provider="anthropic"
                default-upstream "openai"
            }
            fallback {
                upstreams {
                    upstream "anthropic" provider="anthropic" {
                        model-mapping {
                            "gpt-4" "claude-3-opus"
                            "gpt-3.5-turbo" "claude-3-sonnet"
                        }
                    }
                }
                triggers {
                    on-health-failure true
                    on-budget-exhausted true
                    on-error-codes [429 503]
                }
            }
        }
    }
}
```

## GeoIP Filtering

```kdl
schema-version "1.0"

filters {
    // Block specific countries
    filter "geo-block" {
        type "geo"
        database-path "/etc/sentinel/GeoLite2-Country.mmdb"
        action "block"
        countries ["RU" "CN" "KP" "IR"]
        on-failure "open"
        status-code 403
        block-message "Access denied from your region"
    }

    // Allow only specific countries
    filter "geo-allow" {
        type "geo"
        database-path "/etc/sentinel/GeoLite2-Country.mmdb"
        action "allow"
        countries ["US" "CA" "GB" "AU"]
        on-failure "closed"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
        filters ["geo-block"]
    }

    route "admin" {
        matches {
            path-prefix "/admin"
        }
        upstream "admin-backend"
        filters ["geo-allow"]  // Only US, CA, GB, AU
    }
}
```

## HTTP Caching

```kdl
schema-version "1.0"

cache {
    enabled true
    backend "memory"
    max-size-bytes 104857600  // 100MB
    lock-timeout-secs 10
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "api-backend"
        policies {
            cache {
                enabled true
                default-ttl-secs 300  // 5 minutes
                max-size-bytes 1048576  // 1MB per response
                cacheable-methods ["GET" "HEAD"]
                cacheable-status-codes [200 203 204 206 300 301]
                stale-while-revalidate-secs 60
                stale-if-error-secs 300
                vary-headers ["Accept" "Accept-Encoding"]
                ignore-query-params ["utm_source" "utm_campaign"]
            }
        }
    }

    route "static" {
        matches {
            path-prefix "/static"
        }
        service-type "static"
        static-files {
            root "/var/www/static"
            cache-control "public, max-age=31536000, immutable"
        }
    }
}
```

## WebSocket Support

```kdl
schema-version "1.0"

upstreams {
    upstream "websocket-backend" {
        target "127.0.0.1:8000"
        timeouts {
            read-secs 3600   // Long timeout for WS
            write-secs 3600
        }
    }
}

routes {
    route "websocket" {
        matches {
            path-prefix "/ws"
        }
        upstream "websocket-backend"
        websocket true
        websocket-inspection false  // Enable for content filtering
    }
}

// With frame inspection
agents {
    agent "ws-filter" {
        type "custom"
        transport {
            unix-socket "/var/run/ws-filter.sock"
        }
        events ["websocket-frame"]
        timeout-ms 10
    }
}

routes {
    route "chat" {
        matches {
            path-prefix "/chat"
        }
        upstream "chat-backend"
        websocket true
        websocket-inspection true
        filters ["ws-filter"]
    }
}
```

## Traffic Mirroring (Shadow)

```kdl
schema-version "1.0"

upstreams {
    upstream "production" {
        target "10.0.0.1:8080"
    }

    upstream "canary" {
        target "10.0.0.2:8080"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "production"
        shadow {
            upstream "canary"
            percentage 10.0  // Mirror 10% of traffic
            timeout-ms 5000
            buffer-body true
            max-body-bytes 1048576
        }
    }
}
```

## Observability Configuration

```kdl
schema-version "1.0"

observability {
    metrics {
        enabled true
        address "0.0.0.0:9090"
        path "/metrics"
    }

    logging {
        level "info"
        format "json"

        access-log {
            enabled true
            file "/var/log/sentinel/access.log"
            format "json"
            sample-rate 1.0
            include-trace-id true
            fields {
                timestamp true
                trace-id true
                method true
                path true
                status true
                latency-ms true
                client-ip true
                user-agent true
            }
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
            log-agent-decisions true
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

## Production Deployment

Complete production configuration:

```kdl
schema-version "1.0"

server {
    worker-threads 0
    max-connections 50000
    graceful-shutdown-timeout-secs 60
    trace-id-format "uuid"
    auto-reload false
}

listeners {
    listener "http" {
        address "0.0.0.0:80"
        protocol "http"
        default-route "redirect-https"
    }

    listener "https" {
        address "0.0.0.0:443"
        protocol "https"
        request-timeout-secs 60
        keepalive-timeout-secs 75
        max-concurrent-streams 200
        tls {
            cert-file "/etc/ssl/certs/server.crt"
            key-file "/etc/ssl/private/server.key"
            min-version "tls1.2"
            ocsp-stapling true
            session-resumption true
        }
    }

    listener "admin" {
        address "127.0.0.1:9091"
        protocol "http"
        default-route "health"
    }
}

limits {
    max-header-size-bytes 16384
    max-header-count 100
    max-body-size-bytes 10485760
    max-connections-per-client 100
}

// ... routes, upstreams, filters, etc.
```
