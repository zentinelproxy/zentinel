# Zentinel Testing Guide

This directory contains the integration test suite for Zentinel reverse proxy. The tests validate both the engineering (source code) and configuration correctness in a simulated production-like environment.

## Quick Start

```bash
# Run all tests (builds images, starts environment, runs tests)
cd tests
make test

# Or run the integration test script directly
./integration_test.sh

# Quick smoke tests only
make test-quick
```

## Test Environment Overview

The test environment consists of:

| Component | Port | Description |
|-----------|------|-------------|
| Zentinel Proxy | 8080 (HTTP), 8443 (HTTPS) | Main reverse proxy |
| Metrics | 9090 | Proxy health and Prometheus metrics |
| Backend | 8081 | httpbin test service |
| Rate Limit Agent | 9092 (metrics) | Token-bucket rate limiting |
| WAF Agent | 9094 (metrics) | ModSecurity-based WAF |
| Echo Agent | - | Header manipulation test agent |
| Prometheus | 9091 | Metrics collection |
| Grafana | 3000 | Visualization (admin/zentinel) |
| Jaeger | 16686 | Distributed tracing UI |

## Available Make Targets

### Environment Management

```bash
make up            # Start the test environment
make down          # Stop the test environment
make build         # Build Docker images
make logs          # Show all container logs
make logs-proxy    # Show only proxy logs
make logs-agents   # Show agent logs (ratelimit, waf, echo)
make clean         # Remove all containers and volumes
make health        # Check health of all services
```

### Test Suites

```bash
make test          # Run all integration tests
make test-quick    # Quick smoke tests only
make test-echo     # Test echo agent scenarios
make test-ratelimit # Test rate limit agent scenarios
make test-waf      # Test WAF security scenarios
make test-security # Full security test suite
make test-performance # Performance/load tests
make test-local    # Test against local binaries (no Docker)
```

## Test Scenarios

### 1. Echo Agent Tests (`scenarios/test_echo_agent.sh`)

Tests the echo agent's header manipulation functionality:
- Basic request passthrough
- Custom header addition
- Correlation ID tracking
- HTTP method handling
- Unicode header support
- Concurrent request handling

### 2. Rate Limit Agent Tests (`scenarios/test_ratelimit_agent.sh`)

Tests rate limiting functionality:
- Rate limit header presence
- Rate limiting enforcement
- Rate limit window reset
- Per-client isolation
- Retry-After header
- Burst allowance
- Circuit breaker behavior

### 3. WAF Agent Tests (`scenarios/test_waf_agent.sh`)

Tests OWASP CRS-style security protections:

**SQL Injection:**
- Classic injection (OR 1=1)
- UNION-based attacks
- Stacked queries
- Blind SQL injection
- POST body injection

**XSS (Cross-Site Scripting):**
- Script tag injection
- Event handler attacks
- SVG-based XSS
- JavaScript protocol

**Path Traversal:**
- Basic traversal (../)
- URL-encoded traversal
- Double-encoded attacks
- Windows-style paths

**Command Injection:**
- Semicolon injection
- Pipe injection
- Command substitution
- Backtick injection

**Scanner Detection:**
- SQLMap user agent
- Nikto user agent

### 4. Inline OpenAPI Validation Tests (`test_inline_openapi.sh`)

Tests API schema validation with inline OpenAPI specifications:

**Valid Request Tests:**
- All required fields present (email, password, username)
- Optional fields (age)

**Schema Violation Tests:**
- Missing required fields
- Invalid email format
- Password too short (< 8 chars)
- Username too short (< 3 chars)
- Username invalid pattern (special characters)
- Age below minimum (< 13)
- Age above maximum (> 120)
- Additional properties (strict mode)

**Run the test:**
```bash
cd tests

# Start mock backend
python3 fixtures/mock-backend.py &

# Start Zentinel with inline OpenAPI config
../target/release/zentinel -c test-inline-openapi.kdl &

# Run validation tests
./test_inline_openapi.sh
```

## Integration Test Script

The main integration test script (`integration_test.sh`) provides comprehensive testing:

```bash
./integration_test.sh              # Run all tests
./integration_test.sh --quick      # Quick smoke tests
./integration_test.sh --no-build   # Skip Docker build
./integration_test.sh --keep       # Keep containers after tests
./integration_test.sh --verbose    # Verbose output
./integration_test.sh --help       # Show help
```

### Test Categories

1. **Basic Proxy Tests** - Request/response handling
2. **Health Endpoint Tests** - Proxy health and metrics
3. **Configuration Tests** - Config loading and route matching
4. **Echo Agent Tests** - Header manipulation
5. **Rate Limit Tests** - Rate limiting enforcement
6. **WAF Tests** - Security protections
7. **Multi-Agent Tests** - Agent pipeline
8. **Failure Handling Tests** - Fail-open/closed behavior
9. **Observability Tests** - Prometheus, Grafana, Jaeger
10. **Performance Tests** - Throughput and concurrency

## Running Tests Manually

### Start the Environment

```bash
cd /path/to/zentinel
docker compose -f docker-compose.yml up -d

# Wait for services
sleep 30

# Verify health
curl http://localhost:9090/health
```

### Run Individual Tests

```bash
# Test basic proxy
curl http://localhost:8080/get

# Test echo agent
curl -i http://localhost:8080/echo/test

# Test rate limiting
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/limited/test
done

# Test WAF - SQL injection (should return 403)
curl http://localhost:8080/protected/?id="' OR '1'='1"

# Test WAF - XSS (should return 403)
curl -X POST http://localhost:8080/protected/ \
  -d "input=<script>alert('XSS')</script>"

# Test WAF bypass header
curl http://localhost:8080/protected/?id="' OR '1'='1" \
  -H "X-WAF-Bypass: test-secret-key"
```

### Check Metrics

```bash
# Proxy metrics
curl http://localhost:9090/metrics | grep zentinel_

# Rate limit agent metrics
curl http://localhost:9092/metrics

# WAF agent metrics
curl http://localhost:9094/metrics
```

### View Observability Tools

- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (admin/zentinel)
- **Jaeger**: http://localhost:16686

## Test Configuration

### Proxy Config (`config/docker/proxy.kdl`)

The test proxy configuration includes:
- Multiple routes with different agent configurations
- `/api/*` - Echo + rate limit agents
- `/protected/*` - WAF agent
- `/limited/*` - Rate limit agent only
- `/echo/*` - Echo agent only
- `/multi/*` - All agents chained

### Rate Limit Config (`config/docker/ratelimit.yaml`)

- Default: 10 req/s, burst 20
- API routes: 50 req/s, burst 100
- Auth endpoints: 5 req/s, burst 10

### WAF Config (`config/docker/waf.yaml`)

- SQL injection detection
- XSS prevention
- Path traversal blocking
- Command injection detection
- Scanner detection
- Bypass header: `X-WAF-Bypass: test-secret-key`

## Troubleshooting

### Containers Won't Start

```bash
# Check for port conflicts
lsof -i :8080
lsof -i :9090

# View container logs
docker compose logs

# Rebuild images
docker compose build --no-cache
```

### Tests Failing

```bash
# Check proxy health
curl -v http://localhost:9090/health

# Check agent connectivity
docker compose exec proxy ls -la /var/run/zentinel/

# View agent logs
docker compose logs ratelimit
docker compose logs waf
```

### Rate Limiting Not Working

The rate limit agent may not be connected. Check:
1. Agent socket exists: `/var/run/zentinel/ratelimit.sock`
2. Agent is running: `docker compose ps ratelimit`
3. Agent logs: `docker compose logs ratelimit`

### WAF Not Blocking

The WAF agent may be in detection-only mode or not connected:
1. Check WAF config: `config/docker/waf.yaml`
2. Verify `detection_only: false`
3. Check agent logs: `docker compose logs waf`

## Extending Tests

### Adding New Test Scenarios

1. Create a new script in `tests/scenarios/`
2. Follow the existing pattern for logging and assertions
3. Add a Make target in `tests/Makefile`

### Adding New Agents

1. Add agent to `docker-compose.yml`
2. Configure in `config/docker/proxy.kdl`
3. Create agent config in `config/docker/`
4. Write tests in `tests/scenarios/`

## CI/CD Integration

For CI pipelines:

```bash
# Build and test in one command
./tests/integration_test.sh

# Exit code 0 = all tests passed
# Exit code 1 = some tests failed
```

Or with Make:

```bash
cd tests
make test
echo "Exit code: $?"
```
