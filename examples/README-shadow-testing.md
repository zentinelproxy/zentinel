# Traffic Mirroring / Shadow Testing Example

This directory contains a complete example configuration for testing Sentinel's traffic mirroring (shadow) feature, which enables safe canary deployments by duplicating traffic to shadow upstreams without affecting the primary response.

## Files

- **`shadow-test.kdl`** - Sentinel configuration demonstrating various shadow/mirroring patterns
- **`shadow-test-compose.yml`** - Docker Compose file for test upstreams
- **`nginx-production.conf`** - Production upstream configuration
- **`nginx-canary.conf`** - Canary upstream configuration (v2.0)
- **`nginx-staging.conf`** - Staging upstream configuration
- **`test-shadow.sh`** - Automated test script for all shadow scenarios

## What is Traffic Mirroring?

Traffic mirroring (also called shadow traffic or dark traffic) allows you to duplicate live requests to a secondary upstream (shadow target) for testing purposes, while the client receives the response from the primary upstream. This enables:

- **Safe canary deployments** - Test new versions with real traffic without impacting users
- **Performance testing** - Validate new infrastructure under production load
- **Debug/replay** - Capture and test specific request patterns
- **Data collection** - Gather metrics from shadow deployments

### Key Characteristics

- **Fire-and-forget** - Shadow requests are non-blocking, sent asynchronously
- **No client impact** - Shadow failures don't affect the primary response
- **Sampling** - Control what percentage of traffic is mirrored
- **Header-based filtering** - Mirror only requests with specific headers

## Shadow Configuration Options

```kdl
route "my-route" {
    upstream "production"  // Primary upstream

    shadow {
        upstream "canary"            // Shadow target upstream ID
        percentage 100.0             // 0.0-100.0 sampling rate (default: 100.0)
        sample-header "X-Debug" "1"  // Only mirror if header matches (optional)
        timeout-ms 5000              // Shadow request timeout (default: 5000)
        buffer-body #false           // Whether to buffer request bodies (default: false)
        max-body-bytes 1048576       // Max body size to shadow (default: 1MB)
    }
}
```

### Configuration Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upstream` | string | *required* | Shadow target upstream ID (must exist in upstreams block) |
| `percentage` | float | 100.0 | Percentage of requests to mirror (0.0-100.0) |
| `sample-header` | tuple | none | Only mirror if request header matches `(name, value)` |
| `timeout-ms` | int | 5000 | Shadow request timeout in milliseconds |
| `buffer-body` | bool | false | Whether to buffer request bodies for POST/PUT/PATCH |
| `max-body-bytes` | int | 1048576 | Maximum body size to shadow (1MB default) |

## Example Scenarios

### 1. Full Shadow (100% Mirrored)

```kdl
route "api-full-shadow" {
    matches {
        path-prefix "/api/v1"
    }
    upstream "production"

    shadow {
        upstream "canary"
        percentage 100.0  // Mirror all requests
    }
}
```

**Use case**: Initial canary deployment testing - mirror all traffic to validate stability.

### 2. Partial Shadow (10% Sampling)

```kdl
route "api-partial-shadow" {
    matches {
        path-prefix "/api/v2"
    }
    upstream "production"

    shadow {
        upstream "canary"
        percentage 10.0  // Mirror 10% of requests
    }
}
```

**Use case**: Gradual rollout - reduce shadow load while still getting representative traffic.

### 3. Header-Based Shadow (Debug/Testing)

```kdl
route "api-debug-shadow" {
    matches {
        path-prefix "/api/v3"
    }
    upstream "production"

    shadow {
        upstream "canary"
        percentage 100.0
        sample-header "X-Debug-Shadow" "true"  // Only if header present
    }
}
```

**Use case**: Developer testing - only mirror requests with debug header for targeted testing.

### 4. Staging Shadow (Internal Testing)

```kdl
route "internal-api" {
    matches {
        path-prefix "/internal"
    }
    upstream "production"

    shadow {
        upstream "staging"
        percentage 100.0
        sample-header "X-Internal-Test" "enabled"
    }
}
```

**Use case**: Internal QA - mirror authenticated internal requests to staging for validation.

## Body Buffering

By default, shadow requests **do not** include request bodies to avoid buffering overhead. For POST/PUT/PATCH requests that need body inspection in the shadow:

```kdl
shadow {
    upstream "canary"
    buffer-body #true        // Enable body buffering
    max-body-bytes 1048576   // Limit to 1MB
}
```

**Important**: Buffering request bodies has memory and latency implications. Use `max-body-bytes` to enforce strict limits.

### When to Buffer Bodies

- ✅ **Buffer**: Small payloads (<1MB), testing form submissions, API validation
- ❌ **Don't buffer**: Large uploads, streaming data, file uploads, high-throughput APIs

## Metrics

Sentinel exposes Prometheus metrics for shadow traffic monitoring:

```prometheus
# Total shadow requests sent (labels: route, upstream, result)
shadow_requests_total{route="api-full-shadow",upstream="canary",result="success"} 1234

# Shadow request errors (labels: route, upstream, error_type)
shadow_errors_total{route="api-full-shadow",upstream="canary",error_type="timeout"} 5

# Shadow request latency histogram (labels: route, upstream)
shadow_latency_seconds_bucket{route="api-full-shadow",upstream="canary",le="0.1"} 980
shadow_latency_seconds_bucket{route="api-full-shadow",upstream="canary",le="0.5"} 1200
```

### Key Metrics to Monitor

- **`shadow_requests_total{result="success"}`** - Successful shadow requests
- **`shadow_requests_total{result="error"}`** - Failed shadow requests (doesn't affect client)
- **`shadow_errors_total{error_type="timeout"}`** - Shadow timeouts
- **`shadow_latency_seconds`** - Shadow request latency distribution

## Running the Example

### Prerequisites

- Docker and Docker Compose installed
- Sentinel compiled: `cargo build --release`

### Start the Test Environment

```bash
# 1. Start upstream containers (production, canary, staging)
cd examples
docker compose -f shadow-test-compose.yml up -d

# 2. Verify upstreams are healthy
curl http://localhost:9001/health  # production
curl http://localhost:9002/health  # canary
curl http://localhost:9003/health  # staging

# 3. Start Sentinel with shadow configuration
../target/release/sentinel -c shadow-test.kdl

# 4. In another terminal, run the test script
./test-shadow.sh
```

### Manual Testing

```bash
# Test full shadow (100% to canary)
curl http://localhost:8080/api/v1/users
# Response from production, mirrored to canary

# Test partial shadow (10% to canary - run multiple times)
for i in {1..20}; do
  curl http://localhost:8080/api/v2/test
done

# Test header-based shadow (with header)
curl -H "X-Debug-Shadow: true" http://localhost:8080/api/v3/test
# Mirrored to canary

# Test header-based shadow (without header)
curl http://localhost:8080/api/v3/test
# NOT mirrored

# Check metrics
curl http://localhost:9090/metrics | grep shadow_
```

## Observing Shadow Traffic

### 1. Check upstream responses

```bash
# Production (primary response)
curl http://localhost:9001/api/test
# {"message":"Response from PRODUCTION upstream",...}

# Canary (shadow target)
curl http://localhost:9002/api/test
# {"message":"Response from CANARY upstream","version":"v2.0",...}
```

### 2. Monitor Sentinel logs

```bash
tail -f /var/log/sentinel/access.log
# Look for shadow request entries
```

### 3. Check Prometheus metrics

```bash
curl http://localhost:9090/metrics | grep shadow
```

## Cleanup

```bash
# Stop Sentinel
pkill sentinel

# Stop upstream containers
docker compose -f shadow-test-compose.yml down
```

## Best Practices

### 1. Start with Low Sampling

Begin with 1-5% sampling and gradually increase:

```kdl
shadow {
    upstream "canary"
    percentage 1.0  // Start small
}
```

### 2. Use Timeouts

Always configure shadow timeouts to prevent resource exhaustion:

```kdl
shadow {
    upstream "canary"
    timeout-ms 3000  // Shorter than primary timeout
}
```

### 3. Monitor Shadow Health

Set up alerts for shadow error rates:

```promql
rate(shadow_errors_total[5m]) / rate(shadow_requests_total[5m]) > 0.1
```

### 4. Body Buffering Limits

Enforce strict body size limits when buffering:

```kdl
shadow {
    upstream "canary"
    buffer-body #true
    max-body-bytes 524288  // 512KB limit
}
```

### 5. Header-Based Targeting

Use headers for targeted testing without impacting all traffic:

```kdl
shadow {
    upstream "canary"
    sample-header "X-Canary-User" "beta"  // Only beta users
}
```

## Troubleshooting

### Shadow requests not being sent

1. **Check configuration** - Validate shadow block syntax: `sentinel test -c config.kdl`
2. **Check sampling** - Is percentage > 0? Are header conditions met?
3. **Check metrics** - Look for `shadow_requests_total` counter
4. **Check logs** - Enable debug logging to see shadow decisions

### High shadow error rate

1. **Check shadow upstream health** - Is the canary/staging backend healthy?
2. **Check timeouts** - Are `timeout-ms` values appropriate?
3. **Check network** - Can Sentinel reach the shadow upstream?
4. **Check metrics** - What error types are occurring? (`shadow_errors_total{error_type}`)

### Memory issues with body buffering

1. **Reduce `max-body-bytes`** - Lower the buffer limit
2. **Disable body buffering** - Set `buffer-body #false` for large payloads
3. **Reduce sampling** - Lower `percentage` to reduce buffering load
4. **Add rate limiting** - Limit upstream request rate

## Security Considerations

### Data Sensitivity

Shadow traffic contains **real user data**. Ensure shadow upstreams:

- Have equivalent security controls (TLS, auth, encryption)
- Comply with data residency and privacy requirements
- Use the same data handling policies as production
- Audit shadow traffic access

### Authentication

Shadow requests include original authentication headers. Ensure:

- Shadow upstreams validate credentials
- Tokens/sessions are valid in shadow environment
- API keys are rate-limited separately

### Compliance

For regulated environments (PCI, HIPAA, GDPR):

- **Do not** mirror sensitive data to less-secure environments
- Use `sample-header` to exclude sensitive requests
- Consider data masking/scrubbing before shadowing
- Document shadow data flows in compliance audits

## Architecture Notes

### Fire-and-Forget Model

Shadow requests are sent using `tokio::spawn()`:

```rust
tokio::spawn(async move {
    shadow_manager.shadow_request(headers, body, ctx).await;
});
```

This ensures:
- **Zero latency impact** on primary request
- **No blocking** if shadow target is slow/down
- **Independent failure** domain (shadow errors don't affect client)

### Upstream Pool Isolation

Shadow upstreams use separate connection pools from primary upstreams, preventing:
- Shadow traffic from consuming primary connections
- Shadow failures from affecting primary health checks
- Resource contention between primary and shadow

### Request Cloning

Headers are cloned before sending to shadow to preserve original request state. Body buffering is opt-in to avoid unnecessary memory allocation.

## Related Documentation

- [Route Configuration](../docs/configuration/routes.md)
- [Upstream Pools](../docs/configuration/upstreams.md)
- [Health Checks](../docs/configuration/health-checks.md)
- [Observability & Metrics](../docs/observability.md)

## Feedback

For questions or issues with traffic mirroring:
- GitHub Issues: [sentinel/issues](https://github.com/raskell-io/sentinel/issues)
- Documentation: [sentinel.raskell.io](https://sentinel.raskell.io)
