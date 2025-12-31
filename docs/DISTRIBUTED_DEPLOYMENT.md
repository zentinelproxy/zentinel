# Distributed Deployment Patterns

This guide covers deploying Sentinel in multi-instance configurations for high availability, horizontal scaling, and global distribution.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Basic Multi-Instance Setup](#basic-multi-instance-setup)
- [Distributed Rate Limiting](#distributed-rate-limiting)
- [Service Discovery Integration](#service-discovery-integration)
- [Session Affinity](#session-affinity)
- [Configuration Management](#configuration-management)
- [Health Checks and Load Balancing](#health-checks-and-load-balancing)
- [Observability at Scale](#observability-at-scale)
- [Deployment Topologies](#deployment-topologies)

---

## Architecture Overview

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (L4/L7/DNS)    │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
        ▼                    ▼                    ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│  Sentinel #1  │   │  Sentinel #2  │   │  Sentinel #3  │
│  (Zone A)     │   │  (Zone B)     │   │  (Zone C)     │
└───────┬───────┘   └───────┬───────┘   └───────┬───────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │
                    ┌───────┴───────┐
                    │               │
                    ▼               ▼
            ┌─────────────┐ ┌─────────────┐
            │   Redis     │ │  Backends   │
            │  (shared)   │ │  (upstreams)│
            └─────────────┘ └─────────────┘
```

### Key Principles

1. **Stateless proxy instances** - Each Sentinel instance is stateless; state is externalized to Redis
2. **Shared configuration** - All instances load the same configuration
3. **Distributed coordination** - Rate limits and session state synchronized via Redis
4. **Independent failure** - Each instance can fail without affecting others

---

## Basic Multi-Instance Setup

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sentinel
  labels:
    app: sentinel
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sentinel
  template:
    metadata:
      labels:
        app: sentinel
    spec:
      containers:
      - name: sentinel
        image: sentinel:latest
        ports:
        - containerPort: 8080
          name: http
        - containerPort: 9090
          name: metrics
        resources:
          requests:
            memory: "128Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /metrics
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /metrics
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: config
          mountPath: /etc/sentinel
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: sentinel-config
---
apiVersion: v1
kind: Service
metadata:
  name: sentinel
spec:
  selector:
    app: sentinel
  ports:
  - name: http
    port: 80
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
  type: ClusterIP
```

### Docker Compose (Development)

```yaml
version: '3.8'

services:
  sentinel-1:
    image: sentinel:latest
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./config:/etc/sentinel:ro
    environment:
      - SENTINEL_INSTANCE_ID=sentinel-1
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  sentinel-2:
    image: sentinel:latest
    ports:
      - "8081:8080"
      - "9091:9090"
    volumes:
      - ./config:/etc/sentinel:ro
    environment:
      - SENTINEL_INSTANCE_ID=sentinel-2
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  sentinel-3:
    image: sentinel:latest
    ports:
      - "8082:8080"
      - "9092:9090"
    volumes:
      - ./config:/etc/sentinel:ro
    environment:
      - SENTINEL_INSTANCE_ID=sentinel-3
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  haproxy:
    image: haproxy:2.8
    ports:
      - "80:80"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - sentinel-1
      - sentinel-2
      - sentinel-3
```

---

## Distributed Rate Limiting

When running multiple Sentinel instances, rate limits must be synchronized to prevent clients from exceeding limits by spreading requests across instances.

### Redis Backend Configuration

```kdl
filters {
    filter "api-rate-limit" {
        type "rate-limit"
        max-rps 100
        burst 200
        key "client-ip"
        on-limit "reject"

        // Distributed backend configuration
        backend "redis"
        redis-url "redis://redis-cluster:6379"
        redis-prefix "sentinel:ratelimit:"
        redis-timeout-ms 50

        // Fallback behavior if Redis is unavailable
        fallback-to-local true
    }
}
```

### Redis Cluster Setup

For high availability, use Redis Cluster or Redis Sentinel:

```kdl
filters {
    filter "global-rate-limit" {
        type "rate-limit"
        max-rps 1000
        burst 2000
        key "client-ip"

        backend "redis"
        // Redis Cluster endpoints
        redis-url "redis://redis-node-1:6379,redis-node-2:6379,redis-node-3:6379"
        redis-prefix "sentinel:rl:"
        redis-timeout-ms 100

        // Connection pool settings
        redis-pool-size 10
        redis-pool-timeout-ms 1000
    }
}
```

### Rate Limit Keys

Choose appropriate keys for distributed rate limiting:

| Key Type | Use Case | Example |
|----------|----------|---------|
| `client-ip` | Per-IP limiting | Default, works for most cases |
| `header:X-API-Key` | Per-API-key limiting | API gateway scenarios |
| `header:Authorization` | Per-user limiting | Authenticated APIs |
| `path` | Per-endpoint limiting | Protect specific routes |
| `client-ip,path` | Combined | IP + endpoint limiting |

### Sliding Window Algorithm

Sentinel uses a sliding window log algorithm with Redis sorted sets:

```
Key: sentinel:ratelimit:{filter_id}:{key_value}
Score: Unix timestamp (milliseconds)
Member: Unique request ID

Window slides continuously, providing accurate rate limiting
without the boundary issues of fixed windows.
```

### Fallback Behavior

When Redis is unavailable:

```kdl
filter "api-rate-limit" {
    type "rate-limit"
    backend "redis"
    redis-url "redis://redis:6379"

    // If Redis fails, fall back to local (per-instance) limiting
    fallback-to-local true

    // Or fail open (allow all requests)
    // fallback-to-local false
    // on-redis-failure "open"
}
```

---

## Service Discovery Integration

### Kubernetes (In-Cluster)

```kdl
upstreams {
    upstream "api-backend" {
        discovery "kubernetes" {
            namespace "default"
            service "api-service"
            port "http"
            refresh-interval-secs 30
        }

        load-balancing "least_connections"

        health-check {
            type "http" {
                path "/health"
                expected-status 200
            }
            interval-secs 10
        }
    }
}
```

### Consul

```kdl
upstreams {
    upstream "payment-service" {
        discovery "consul" {
            address "consul.service.consul:8500"
            service "payment-api"
            datacenter "dc1"
            tag "production"
            refresh-interval-secs 15

            // Only include healthy services
            healthy-only true
        }

        load-balancing "round_robin"
    }
}
```

### DNS-Based Discovery

```kdl
upstreams {
    upstream "backend-pool" {
        discovery "dns" {
            hostname "backend.internal.example.com"
            port 8080
            refresh-interval-secs 60

            // Resolve A/AAAA records
            record-type "A"
        }

        load-balancing "round_robin"
    }
}
```

---

## Session Affinity

For stateful backends or WebSocket connections, use consistent hashing:

### IP-Based Affinity

```kdl
upstreams {
    upstream "stateful-backend" {
        target "10.0.1.1:8080" weight=1
        target "10.0.1.2:8080" weight=1
        target "10.0.1.3:8080" weight=1

        // Consistent hashing based on client IP
        load-balancing "ip_hash"
    }
}
```

### Header-Based Affinity

```kdl
upstreams {
    upstream "session-backend" {
        target "10.0.1.1:8080" weight=1
        target "10.0.1.2:8080" weight=1

        // Hash based on session cookie or header
        load-balancing "consistent_hash" {
            key "cookie:session_id"
            // Or: key "header:X-Session-ID"
        }
    }
}
```

---

## Configuration Management

### Shared Configuration via ConfigMap (Kubernetes)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sentinel-config
data:
  sentinel.kdl: |
    server {
        worker-threads 0
        max-connections 10000
    }

    listeners {
        listener "http" {
            address "0.0.0.0:8080"
            protocol "http"
        }
    }

    // ... rest of configuration
```

### Configuration Hot Reload

All Sentinel instances support hot reload via SIGHUP:

```bash
# Reload configuration on all instances
kubectl exec -it deployment/sentinel -- kill -HUP 1

# Or using a rolling restart
kubectl rollout restart deployment/sentinel
```

### Configuration Versioning

Track configuration versions for debugging:

```kdl
// Add version comment at top of config
// Version: 2025-01-01-v3

server {
    // Configuration version tracked in metrics
    // sentinel_build_info{config_version="2025-01-01-v3"}
}
```

---

## Health Checks and Load Balancing

### External Load Balancer Configuration

#### HAProxy

```haproxy
frontend sentinel_front
    bind *:80
    default_backend sentinel_back

backend sentinel_back
    balance roundrobin
    option httpchk GET /metrics
    http-check expect status 200

    server sentinel1 sentinel-1:8080 check inter 5s fall 3 rise 2
    server sentinel2 sentinel-2:8080 check inter 5s fall 3 rise 2
    server sentinel3 sentinel-3:8080 check inter 5s fall 3 rise 2
```

#### NGINX

```nginx
upstream sentinel {
    least_conn;

    server sentinel-1:8080 max_fails=3 fail_timeout=30s;
    server sentinel-2:8080 max_fails=3 fail_timeout=30s;
    server sentinel-3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;

    location / {
        proxy_pass http://sentinel;
        proxy_next_upstream error timeout http_502 http_503;
    }

    location /health {
        proxy_pass http://sentinel/metrics;
    }
}
```

#### AWS ALB

```yaml
# Terraform example
resource "aws_lb_target_group" "sentinel" {
  name     = "sentinel"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/metrics"
    port                = "9090"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 10
    matcher             = "200"
  }
}
```

---

## Observability at Scale

### Prometheus Federation

For large deployments, use Prometheus federation:

```yaml
# prometheus.yml on central Prometheus
scrape_configs:
  - job_name: 'sentinel-federation'
    honor_labels: true
    metrics_path: '/federate'
    params:
      'match[]':
        - '{job="sentinel"}'
    static_configs:
      - targets:
        - 'prometheus-zone-a:9090'
        - 'prometheus-zone-b:9090'
        - 'prometheus-zone-c:9090'
```

### Per-Instance Labels

Add instance identification to metrics:

```yaml
# Kubernetes pod annotations
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "9090"
    prometheus.io/path: "/metrics"
```

### Distributed Tracing

Enable trace propagation across instances:

```kdl
observability {
    tracing {
        backend "otlp" {
            endpoint "http://jaeger-collector:4317"
        }
        sampling-rate 0.01
        service-name "sentinel"

        // Propagate trace context
        propagation "w3c"  // W3C Trace Context
    }
}
```

### Centralized Logging

Ship logs to a central aggregator:

```kdl
observability {
    logging {
        level "info"
        format "json"

        // Include instance identifier in logs
        // Logs will include: {"instance_id": "sentinel-1", ...}
    }
}
```

---

## Deployment Topologies

### Single Region, Multi-AZ

```
┌─────────────────────────────────────────────────────────────┐
│                         Region                               │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐        │
│  │    AZ-A     │   │    AZ-B     │   │    AZ-C     │        │
│  │ ┌─────────┐ │   │ ┌─────────┐ │   │ ┌─────────┐ │        │
│  │ │Sentinel │ │   │ │Sentinel │ │   │ │Sentinel │ │        │
│  │ │  (x2)   │ │   │ │  (x2)   │ │   │ │  (x2)   │ │        │
│  │ └─────────┘ │   │ └─────────┘ │   │ └─────────┘ │        │
│  └─────────────┘   └─────────────┘   └─────────────┘        │
│                           │                                  │
│                    ┌──────┴──────┐                          │
│                    │ Redis (HA)  │                          │
│                    └─────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

**Benefits:**
- High availability within region
- Low latency between instances
- Shared Redis for rate limiting

### Multi-Region (Active-Active)

```
┌─────────────────┐              ┌─────────────────┐
│   US-EAST       │              │   EU-WEST       │
│ ┌─────────────┐ │              │ ┌─────────────┐ │
│ │  Sentinel   │ │              │ │  Sentinel   │ │
│ │   Cluster   │ │              │ │   Cluster   │ │
│ └─────────────┘ │              │ └─────────────┘ │
│        │        │              │        │        │
│ ┌─────────────┐ │              │ ┌─────────────┐ │
│ │ Redis (local)│◄──────────────►│ Redis (local)│ │
│ └─────────────┘ │  Replication │ └─────────────┘ │
└─────────────────┘              └─────────────────┘
        │                                │
        └────────────┬───────────────────┘
                     │
              ┌──────┴──────┐
              │  Global LB  │
              │  (GeoDNS)   │
              └─────────────┘
```

**Considerations:**
- Use geo-aware DNS (Route 53, Cloudflare, etc.)
- Local Redis per region with cross-region replication
- Accept eventual consistency for rate limits
- Configure region-aware rate limit keys

### Edge Deployment (CDN Pattern)

```
                    ┌─────────────────┐
                    │   Origin        │
                    │   Servers       │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────┴───────┐   ┌───────┴───────┐   ┌───────┴───────┐
│  Edge PoP 1   │   │  Edge PoP 2   │   │  Edge PoP 3   │
│ ┌───────────┐ │   │ ┌───────────┐ │   │ ┌───────────┐ │
│ │ Sentinel  │ │   │ │ Sentinel  │ │   │ │ Sentinel  │ │
│ │ + Cache   │ │   │ │ + Cache   │ │   │ │ + Cache   │ │
│ └───────────┘ │   │ └───────────┘ │   │ └───────────┘ │
└───────────────┘   └───────────────┘   └───────────────┘
```

**Use cases:**
- Static content caching at edge
- Geographic request routing
- DDoS protection at edge
- Local rate limiting (acceptable for edge)

---

## Best Practices

### 1. Instance Sizing

| Traffic Level | Instances | CPU | Memory |
|--------------|-----------|-----|--------|
| < 1K RPS | 2 | 0.5 core | 256 MB |
| 1K-10K RPS | 3-5 | 1 core | 512 MB |
| 10K-50K RPS | 5-10 | 2 cores | 1 GB |
| > 50K RPS | 10+ | 4 cores | 2 GB |

### 2. Redis Sizing for Rate Limiting

```
Memory per rate limit entry: ~100 bytes
Entries per window: RPS × window_seconds

Example: 10K unique IPs, 60s window, 100 RPS limit
Memory: 10,000 × 100 bytes = 1 MB
```

### 3. Graceful Shutdown

Ensure zero-downtime deployments:

```kdl
server {
    graceful-shutdown-timeout-secs 30
}
```

```yaml
# Kubernetes
spec:
  terminationGracePeriodSeconds: 45
  containers:
  - name: sentinel
    lifecycle:
      preStop:
        exec:
          command: ["sleep", "10"]  # Allow LB to drain
```

### 4. Resource Limits

Always set resource limits in production:

```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "500m"
  limits:
    memory: "1Gi"
    cpu: "2000m"
```

---

## Troubleshooting

### Rate Limits Not Synchronized

1. Check Redis connectivity from all instances
2. Verify `redis-url` is correct and reachable
3. Check Redis memory usage
4. Verify Redis cluster health

```bash
# Test Redis from Sentinel pod
kubectl exec -it sentinel-xxx -- redis-cli -h redis ping
```

### Uneven Load Distribution

1. Check load balancer health check configuration
2. Verify all instances are healthy
3. Check for connection pooling issues at LB

### Configuration Drift

1. Use ConfigMaps/Secrets for configuration
2. Implement configuration validation pre-deploy
3. Monitor `sentinel_build_info` for version consistency

---

## See Also

- [Metrics Reference](./METRICS.md)
- [Configuration Reference](../config/sentinel.kdl)
- [Rate Limiting Configuration](../config/sentinel.kdl) - `filters` block
- [Service Discovery](../crates/proxy/src/discovery.rs)
