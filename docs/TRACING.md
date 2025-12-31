# Sentinel Distributed Tracing

Sentinel supports distributed tracing via OpenTelemetry, enabling end-to-end visibility across your microservices architecture.

## Quick Start

```kdl
observability {
    tracing {
        backend "otlp" {
            endpoint "http://localhost:4317"
        }
        sampling-rate 0.1
        service-name "sentinel-proxy"
    }
}
```

```bash
# Build with OpenTelemetry support
cargo build --release --features opentelemetry

# Run with tracing enabled
./target/release/sentinel --config config/sentinel.kdl
```

---

## Configuration

### Tracing Block

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | block | - | Backend configuration (see below) |
| `sampling-rate` | float | `0.01` | Fraction of requests to trace (0.0-1.0) |
| `service-name` | string | `"sentinel"` | Service name in traces |

### Backend Options

All backends use OTLP (OpenTelemetry Protocol) for export:

```kdl
// Jaeger
backend "jaeger" {
    endpoint "http://jaeger:4317"
}

// Tempo (Grafana)
backend "otlp" {
    endpoint "http://tempo:4317"
}

// Zipkin (via OTLP collector)
backend "zipkin" {
    endpoint "http://zipkin:9411"
}

// Generic OTLP collector
backend "otlp" {
    endpoint "http://otel-collector:4317"
}
```

### Sampling Strategies

```kdl
// Always sample (development)
sampling-rate 1.0

// Sample 10% of requests (staging)
sampling-rate 0.1

// Sample 1% of requests (production)
sampling-rate 0.01

// Never sample (disabled)
sampling-rate 0.0
```

---

## W3C Trace Context

Sentinel implements the [W3C Trace Context](https://www.w3.org/TR/trace-context/) specification for distributed trace propagation.

### Traceparent Header

Sentinel parses and propagates the `traceparent` header:

```
traceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
             |  |                                |                |
             |  |                                |                +-- Flags (01=sampled)
             |  |                                +-- Parent Span ID (16 hex)
             |  +-- Trace ID (32 hex)
             +-- Version (always 00)
```

### Tracestate Header

The optional `tracestate` header is preserved for vendor-specific data:

```
tracestate: congo=t61rcWkgMzE,rojo=00f067aa0ba902b7
```

### Header Propagation

When Sentinel receives a request:

1. **With `traceparent`**: Parses trace context, creates child span, propagates to upstream
2. **Without `traceparent`**: Generates new trace ID, creates root span

Headers propagated to upstreams:
- `traceparent` - Updated with new span ID
- `tracestate` - Preserved from incoming request
- `X-Trace-Id` - Sentinel's internal trace ID (TinyFlake format)

---

## Trace ID Formats

Sentinel uses two trace ID formats:

### TinyFlake (Default)

Compact 11-character IDs optimized for logging:

```
k7BxR3nVp2Ym
```

- 3-character timestamp prefix
- 8-character random suffix
- Base58 encoded (no ambiguous characters)
- Easy to select in terminals (no dashes)

### UUID

Standard 36-character UUIDs:

```
550e8400-e29b-41d4-a716-446655440000
```

Configure in `server` block:

```kdl
server {
    trace-id-format "tinyflake"  // or "uuid"
}
```

---

## Request Lifecycle Spans

Sentinel creates spans for key request phases:

```
[Server Span: GET /api/users]
├── [Upstream Connection]
├── [Agent: auth-agent]
├── [Agent: rate-limit]
├── [Upstream Request]
│   └── [Response Headers]
└── [Response Body]
```

### Span Attributes

| Attribute | Description |
|-----------|-------------|
| `http.method` | HTTP method (GET, POST, etc.) |
| `http.target` | Request path |
| `http.status_code` | Response status code |
| `http.route` | Matched route ID |
| `upstream.id` | Target upstream pool |
| `upstream.target` | Selected backend address |
| `service.name` | Configured service name |

---

## Integration Examples

### Jaeger

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:1.50
    ports:
      - "4317:4317"   # OTLP gRPC
      - "16686:16686" # UI
    environment:
      COLLECTOR_OTLP_ENABLED: true
```

```kdl
# sentinel.kdl
observability {
    tracing {
        backend "jaeger" {
            endpoint "http://jaeger:4317"
        }
        sampling-rate 1.0
        service-name "sentinel"
    }
}
```

Access UI at http://localhost:16686

### Grafana Tempo

```yaml
# docker-compose.yml
services:
  tempo:
    image: grafana/tempo:2.3.0
    command: ["-config.file=/etc/tempo.yaml"]
    ports:
      - "4317:4317"   # OTLP gRPC
      - "3200:3200"   # Tempo API
    volumes:
      - ./tempo.yaml:/etc/tempo.yaml

  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      GF_FEATURE_TOGGLES_ENABLE: traceqlEditor
```

```yaml
# tempo.yaml
server:
  http_listen_port: 3200

distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          endpoint: 0.0.0.0:4317

storage:
  trace:
    backend: local
    local:
      path: /var/tempo/traces
```

```kdl
# sentinel.kdl
observability {
    tracing {
        backend "otlp" {
            endpoint "http://tempo:4317"
        }
        sampling-rate 0.1
        service-name "sentinel"
    }
}
```

### OpenTelemetry Collector

For complex pipelines, use the OTel Collector:

```yaml
# otel-collector.yaml
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:
    timeout: 1s
    send_batch_size: 1024

exporters:
  jaeger:
    endpoint: jaeger:14250
  prometheus:
    endpoint: 0.0.0.0:8889

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger]
```

```kdl
# sentinel.kdl
observability {
    tracing {
        backend "otlp" {
            endpoint "http://otel-collector:4317"
        }
    }
}
```

---

## Correlating Traces with Logs

Sentinel includes trace IDs in all structured logs:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "message": "Request completed",
  "trace_id": "k7BxR3nVp2Ym",
  "correlation_id": "k7BxR3nVp2Ym",
  "method": "GET",
  "path": "/api/users",
  "status": 200,
  "duration_ms": 45
}
```

### Grafana Loki Integration

Link traces and logs in Grafana:

```yaml
# grafana datasources
datasources:
  - name: Tempo
    type: tempo
    url: http://tempo:3200
    jsonData:
      tracesToLogs:
        datasourceUid: loki
        tags: ['trace_id']

  - name: Loki
    type: loki
    url: http://loki:3100
    jsonData:
      derivedFields:
        - datasourceUid: tempo
          matcherRegex: "trace_id=(\\w+)"
          name: TraceID
          url: '$${__value.raw}'
```

---

## Performance Considerations

### Sampling Impact

| Sampling Rate | Overhead | Use Case |
|---------------|----------|----------|
| 0.0 | None | Disabled |
| 0.01 (1%) | Minimal | High-traffic production |
| 0.1 (10%) | Low | Standard production |
| 0.5 (50%) | Moderate | Staging/debugging |
| 1.0 (100%) | Higher | Development/testing |

### Best Practices

1. **Start with low sampling** in production (1-10%)
2. **Increase temporarily** when debugging issues
3. **Use head-based sampling** (Sentinel's default) for consistent traces
4. **Configure collector-side sampling** for additional control

### Resource Usage

With tracing enabled at 10% sampling:
- Memory: +2-5MB for span buffering
- CPU: +1-2% for span creation/export
- Network: ~1KB per sampled request to collector

---

## Troubleshooting

### Traces Not Appearing

1. **Check feature flag**: Build with `--features opentelemetry`
2. **Verify endpoint**: Ensure collector is reachable
3. **Check sampling rate**: Increase for testing
4. **Review collector logs**: Look for connection errors

### Connection Errors

```bash
# Test OTLP endpoint
grpcurl -plaintext localhost:4317 list

# Check collector health
curl http://localhost:13133/health
```

### Missing Spans

- Verify upstream services propagate `traceparent`
- Check agent timeouts aren't causing span drops
- Ensure batch exporter has time to flush on shutdown

---

## Feature Flag

OpenTelemetry support is optional to minimize binary size:

```toml
# Cargo.toml
[features]
default = []
opentelemetry = [
    "dep:opentelemetry",
    "dep:opentelemetry_sdk",
    "dep:opentelemetry-otlp",
    "dep:opentelemetry-semantic-conventions"
]
```

Build without tracing:
```bash
cargo build --release  # No OTel, smaller binary
```

Build with tracing:
```bash
cargo build --release --features opentelemetry
```

---

## See Also

- [Metrics Reference](METRICS.md) - Prometheus metrics
- [Distributed Deployment](DISTRIBUTED_DEPLOYMENT.md) - Multi-instance setup
- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
