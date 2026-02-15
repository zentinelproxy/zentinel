# Configuration Examples

Common configuration patterns for the Sentinel proxy.

## Basic HTTP Proxy

Simple reverse proxy to a single backend:

```kdl
schema-version "1.0"

server {
    worker-threads 0  // Auto-detect CPU cores
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

TLS termination with HTTP to HTTPS redirect:

```kdl
schema-version "1.0"

listeners {
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
    }
}

upstreams {
    upstream "backend" {
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
                    "Location" "https://example.com/"
                }
            }
        }
    }

    route "app" {
        matches {
            path-prefix "/"
        }
        upstream "backend"
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
            retry-on ["5xx", "connection-error"]
        }
    }
}
```

## API Gateway with Rate Limiting

Rate-limited API with security headers:

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
        filters ["api-rate-limit", "security-headers"]
    }

    route "api-unauthorized" {
        matches {
            path-prefix "/api"
        }
        service-type "builtin"
        builtin-handler "unauthorized"
    }
}
```

## Static File Server with SPA

Static files with single-page application fallback:

```kdl
schema-version "1.0"

upstreams {
    upstream "api-backend" {
        target "127.0.0.1:3000"
    }
}

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
            fallback "index.html"
            cache-control "public, max-age=3600"
            compress true
        }
    }
}
```

## Multi-Domain with SNI

Multiple domains on single listener with SNI:

```kdl
schema-version "1.0"

listeners {
    listener "https" {
        address "0.0.0.0:443"
        protocol "https"
        tls {
            cert-file "/etc/ssl/certs/default.crt"
            key-file "/etc/ssl/private/default.key"

            additional-certs {
                cert hostnames=["api.example.com", "*.api.example.com"] {
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

upstreams {
    upstream "api-backend" {
        target "10.0.0.1:8080"
    }
    upstream "admin-backend" {
        target "10.0.0.2:8080"
    }
    upstream "web-backend" {
        target "10.0.0.3:8080"
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

Web Application Firewall with CRS rules:

```kdl
schema-version "1.0"

agents {
    agent "waf-agent" {
        type "waf"
        transport {
            unix-socket "/var/run/waf-agent.sock"
        }
        events ["request-headers", "request-body"]
        timeout-ms 50
        failure-mode "open"

        body-handling {
            mode "buffer"
            max-bytes 1048576
            content-types [
                "application/json"
                "application/x-www-form-urlencoded"
                "multipart/form-data"
            ]
        }
    }
}

filters {
    filter "waf" {
        type "agent"
        agent "waf-agent"
        phase "request"
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
        }
        upstream "api-backend"
        filters ["waf"]
        waf-enabled true
    }
}

observability {
    logging {
        audit-log {
            enabled true
            file "/var/log/sentinel/audit.log"
            log-blocked true
            log-waf-events true
        }
    }
}
```

## External Authentication

Authentication via external agent:

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

upstreams {
    upstream "api-backend" {
        target "127.0.0.1:3000"
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

LLM proxy with token-based rate limiting:

```kdl
schema-version "1.0"

upstreams {
    upstream "openai" {
        target "api.openai.com:443"
        tls {
            sni "api.openai.com"
        }
        health-check {
            type "inference"
            models-endpoint "/v1/models"
            interval-secs 30
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
    route "chat" {
        matches {
            path-prefix "/v1/chat/completions"
        }
        upstream "openai"
        service-type "inference"

        inference {
            provider "openai"

            rate-limit {
                tokens-per-minute 100000
                burst-tokens 10000
                requests-per-minute 100
            }

            budget {
                daily-limit 1000000
                monthly-limit 10000000
                enforce true
            }

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
                    on-error-codes [429, 503]
                }
            }
        }
    }
}
```

## GeoIP Filtering

Block or allow by geographic region:

```kdl
schema-version "1.0"

filters {
    filter "geo-block" {
        type "geo"
        database-path "/etc/sentinel/GeoLite2-Country.mmdb"
        action "block"
        countries ["RU", "CN", "KP", "IR"]
        on-failure "open"
        status-code 403
    }

    filter "geo-allow" {
        type "geo"
        database-path "/etc/sentinel/GeoLite2-Country.mmdb"
        action "allow"
        countries ["US", "CA", "GB", "AU"]
        on-failure "closed"
    }
}

upstreams {
    upstream "api-backend" {
        target "127.0.0.1:3000"
    }
    upstream "admin-backend" {
        target "127.0.0.1:3001"
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
        filters ["geo-allow"]
    }
}
```

## WebSocket Proxy

WebSocket support with long timeouts:

```kdl
schema-version "1.0"

upstreams {
    upstream "websocket-backend" {
        target "127.0.0.1:8000"
        timeouts {
            read-secs 3600
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
    }
}
```

## Traffic Mirroring

Shadow traffic to canary for testing:

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
            percentage 10.0
            timeout-ms 5000
            buffer-body true
        }
    }
}
```

## HTTP Caching

Response caching with stale-while-revalidate:

```kdl
schema-version "1.0"

cache {
    enabled true
    backend "memory"
    max-size-bytes 104857600
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
        }
        upstream "api-backend"
        policies {
            cache {
                enabled true
                default-ttl-secs 300
                cacheable-methods ["GET", "HEAD"]
                cacheable-status-codes [200, 203, 204, 206, 300, 301]
                stale-while-revalidate-secs 60
                stale-if-error-secs 300
                vary-headers ["Accept", "Accept-Encoding"]
            }
        }
    }
}
```

## Full Observability

Complete observability setup:

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

## Production Deployment

Complete production configuration:

```kdl
schema-version "1.0"

server {
    worker-threads 0
    max-connections 50000
    graceful-shutdown-timeout-secs 60
    trace-id-format "tinyflake"
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
        tls {
            cert-file "/etc/ssl/certs/server.crt"
            key-file "/etc/ssl/private/server.key"
            min-version "tls1.2"
            ocsp-stapling true
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

// ... routes, upstreams, agents, etc.
```

## Kubernetes Service Discovery

Dynamic backends from Kubernetes:

```kdl
schema-version "1.0"

upstreams {
    upstream "api" {
        discovery "kubernetes" {
            namespace "production"
            service "api-service"
            port-name "http"
            refresh-interval 10
        }

        health-check {
            type "http"
            path "/health"
            interval-secs 10
        }
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api"
        }
        upstream "api"
    }
}
```

Requires feature: `kubernetes`
