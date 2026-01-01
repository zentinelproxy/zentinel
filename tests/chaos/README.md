# Sentinel Chaos Tests

Chaos testing framework for validating Sentinel's resilience under failure conditions.

## Overview

These tests inject various failure scenarios to verify:

- **Agent Failures**: Crash handling, timeout behavior, circuit breaker state transitions
- **Upstream Failures**: Backend crashes, 5xx errors, failover behavior
- **Resilience Modes**: Fail-open vs fail-closed behavior, health check recovery
- **Memory Stability**: No memory leaks during failure/recovery cycles

## Quick Start

```bash
# Run quick validation (4 scenarios)
make quick

# Run all scenarios
make test

# Run specific scenario
make test-agent-crash
```

## Prerequisites

- Docker and Docker Compose
- bash 4.0+
- curl
- Python 3.8+ (for analysis)

## Test Scenarios

### Agent Failure Tests

| Scenario | Description |
|----------|-------------|
| `agent-crash` | Kill agent, verify fail-open/closed behavior and circuit breaker |
| `agent-timeout` | Freeze agent, verify timeout enforcement |
| `circuit-breaker` | Test CB state transitions: CLOSED → OPEN → HALF-OPEN → CLOSED |

### Upstream Failure Tests

| Scenario | Description |
|----------|-------------|
| `backend-crash` | Kill primary backend, verify failover to secondary |
| `backend-5xx` | Test 5xx error handling and retry behavior |
| `all-backends-down` | Kill all backends, verify graceful degradation |

### Resilience Tests

| Scenario | Description |
|----------|-------------|
| `fail-open` | Verify traffic continues when agent fails (fail-open mode) |
| `fail-closed` | Verify traffic blocked when agent fails (fail-closed mode) |
| `health-recovery` | Test health check detection and recovery |
| `memory-stability` | Run 20 chaos cycles, verify no memory leaks |

## Usage

### Running Tests

```bash
# Run all tests
./run-chaos-test.sh --all

# Run quick subset
./run-chaos-test.sh --quick

# Run specific scenarios
./run-chaos-test.sh --scenario agent-crash --scenario backend-crash

# Keep environment running after tests (for debugging)
./run-chaos-test.sh --quick --keep

# Skip Docker build (use existing images)
./run-chaos-test.sh --quick --skip-build

# Verbose output
./run-chaos-test.sh --quick --verbose
```

### Makefile Targets

```bash
make help               # Show all available targets
make test               # Run all scenarios
make quick              # Run quick subset

# Individual scenarios
make test-agent-crash
make test-agent-timeout
make test-circuit-breaker
make test-backend-crash
make test-backend-5xx
make test-all-backends-down
make test-fail-open
make test-fail-closed
make test-health-recovery
make test-memory-stability

# Environment management
make up                 # Start test environment
make down               # Stop test environment
make logs               # View container logs
make ps                 # Show running containers
```

### Analyzing Results

```bash
# Analyze latest results
python analyze-chaos-results.py results/<timestamp>/

# JSON output for CI
python analyze-chaos-results.py results/<timestamp>/ --json
```

## Test Configuration

### chaos-config.kdl

The chaos test configuration defines:

- **Routes with different failure modes**:
  - `/failopen/*` - Uses `failure-mode "open"`
  - `/protected/*` - Uses `failure-mode "closed"`
  - `/circuit/*` - Circuit breaker testing
  - `/failover/*` - Multi-backend failover

- **Agent configuration**:
  - Echo agent with 1000ms timeout
  - Circuit breaker: 5 failure threshold, 10s timeout

- **Upstream pools**:
  - Primary backend (single server)
  - Failover pool (primary + secondary)

### Circuit Breaker Settings

```
failure-threshold: 5      # Opens after 5 consecutive failures
success-threshold: 2      # Closes after 2 successes in half-open
timeout-seconds: 10       # Time before transitioning to half-open
half-open-max-requests: 2 # Requests allowed in half-open state
```

## Results Directory Structure

```
results/<timestamp>/
├── summary.json           # Overall test summary
├── chaos-events.log       # Timeline of chaos injections
├── logs/
│   ├── test_agent_crash.log
│   ├── test_backend_crash.log
│   ├── proxy.log          # Container logs
│   └── ...
├── metrics/
│   └── final.txt          # Final Prometheus metrics snapshot
└── memory-test-results.yaml  # Memory stability results
```

## Writing New Scenarios

### Scenario Template

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

test_baseline() {
    log_info "=== Baseline: Normal operation ==="
    assert_status "${PROXY_URL}/status/200" "200" "Route works"
}

test_chaos_scenario() {
    log_info "=== Test: Chaos scenario ==="

    # Inject chaos
    inject_agent_crash "echo"
    sleep 2

    # Verify behavior
    local status=$(http_status "${PROXY_URL}/status/200")
    # ... assertions ...

    # Restore
    restore_agent "echo"
}

main() {
    log_info "Starting My Chaos Test"

    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy"
        return 1
    }

    test_baseline
    test_chaos_scenario

    print_summary
    return $(get_exit_code)
}

main "$@"
```

### Available Chaos Injectors

```bash
# Agent chaos
inject_agent_crash <name>          # Kill agent container
inject_agent_freeze <name> [secs]  # Pause agent (simulates hang)
inject_agent_unfreeze <name>       # Unpause agent
inject_agent_restart <name>        # Crash + restart
restore_agent <name>               # Restart stopped agent

# Backend chaos
inject_backend_crash <name>        # Kill backend container
inject_backend_freeze <name> [s]   # Pause backend
inject_backend_unfreeze <name>     # Unpause backend
inject_all_backends_crash          # Kill all backends
restore_backend <name>             # Restart backend
restore_all_backends               # Restart all backends

# Generic
kill_service <name>                # Kill any service
restore_service <name>             # Restart any service
restart_service <name>             # Docker restart

# Network (requires NET_ADMIN)
inject_network_latency <container> <ms>
inject_packet_loss <container> <percent>
```

### Available Assertions

```bash
assert_eq <actual> <expected> <message>
assert_gte <actual> <expected> <message>
assert_lt <actual> <expected> <message>
assert_status <url> <expected_status> <message>
assert_true <result> <message>
```

### Available Utilities

```bash
# HTTP
http_status <url>                  # Get HTTP status code
http_get <url>                     # Get response body
count_successes <url> <count>      # Count 200 responses
count_status <url> <count> <code>  # Count specific status

# Metrics
get_metric <name> [labels]         # Get Prometheus metric value
get_metrics_matching <pattern>     # Get all matching metrics
metric_exists <name>               # Check if metric exists

# Services
wait_for_service <url> <name> [timeout]
wait_for_unhealthy <url> [timeout]
wait_for_recovery <url> [timeout]
service_is_up <url>
```

## Metrics Validated

| Metric | Expected Behavior |
|--------|-------------------|
| `sentinel_agent_circuit_breaker_state` | Transitions 0→1→2→0 |
| `sentinel_agent_failures_total` | Increments on failures |
| `sentinel_agent_timeouts_total` | Increments on timeouts |
| `sentinel_agent_bypasses_total` | Increments on fail-open bypass |
| `sentinel_upstream_healthy_backends` | Decreases on crash |
| `sentinel_upstream_retries_total` | Increments on retries |
| Memory (RSS) | Stable after failure cycles |

## CI Integration

```yaml
# Example GitHub Actions
chaos-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Run chaos tests
      run: |
        cd tests/chaos
        ./run-chaos-test.sh --quick
    - name: Upload results
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: chaos-results
        path: tests/chaos/results/
```

## Troubleshooting

### Tests failing to start

```bash
# Check if Docker is running
docker info

# Check if ports are available
lsof -i :8080
lsof -i :9090

# View container status
make ps

# View logs
make logs
```

### Debugging a failed scenario

```bash
# Run with --keep to preserve environment
./run-chaos-test.sh --scenario agent-crash --keep

# Check container logs
docker logs chaos-proxy-1
docker logs chaos-echo-1

# Check metrics
curl http://localhost:9090/metrics | grep sentinel_agent

# Manual chaos injection
docker compose -p chaos -f docker-compose.chaos.yml kill echo
docker compose -p chaos -f docker-compose.chaos.yml start echo
```

### Memory test showing high growth

1. Check baseline memory is stable before test
2. Increase `CHAOS_CYCLES` for longer test
3. Check for actual leaks vs. expected growth
4. Review memory test results YAML for details
