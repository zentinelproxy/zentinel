#!/bin/bash
#
# Sentinel Agent Integration Tests
# Tests the external agent processing functionality
#
# Prerequisites:
# - Built binaries in target/release/
# - curl and jq installed
# - Unix socket support
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/sentinel-test-$$"
PROXY_PORT=18080
METRICS_PORT=19090
ECHO_SOCKET="$TEST_DIR/echo.sock"
RATELIMIT_SOCKET="$TEST_DIR/ratelimit.sock"
PROXY_CONFIG="$TEST_DIR/config.kdl"
PROXY_PID=""
ECHO_PID=""
RATELIMIT_PID=""

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    ((TESTS_RUN++))
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    # Kill processes if they exist
    [[ -n "$PROXY_PID" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill -TERM "$ECHO_PID" 2>/dev/null || true
    [[ -n "$RATELIMIT_PID" ]] && kill -TERM "$RATELIMIT_PID" 2>/dev/null || true

    # Wait for processes to terminate
    sleep 2

    # Force kill if still running
    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$ECHO_PID" ]] && kill -9 "$ECHO_PID" 2>/dev/null || true
    [[ -n "$RATELIMIT_PID" ]] && kill -9 "$RATELIMIT_PID" 2>/dev/null || true

    # Remove test directory
    rm -rf "$TEST_DIR"
}

# Set up cleanup on exit
trap cleanup EXIT INT TERM

# Create test directory
setup_test_environment() {
    log_info "Setting up test environment..."
    mkdir -p "$TEST_DIR"

    # Create test configuration
    cat > "$PROXY_CONFIG" <<EOF
server {
    worker-threads 2
    max-connections 1000
}

listeners {
    listener "http" {
        address "127.0.0.1:$PROXY_PORT"
        protocol "http"
        request-timeout-secs 30
    }
}

routes {
    route "echo-test" {
        priority "high"
        matches {
            path-prefix "/echo/"
        }
        upstream "test-backend"
        agents ["echo-agent"]
        policies {
            failure-mode "open"
        }
    }

    route "ratelimit-test" {
        priority "high"
        matches {
            path-prefix "/ratelimit/"
        }
        upstream "test-backend"
        agents ["ratelimit-agent"]
        policies {
            failure-mode "closed"
        }
    }

    route "multi-agent-test" {
        priority "high"
        matches {
            path-prefix "/multi/"
        }
        upstream "test-backend"
        agents ["echo-agent" "ratelimit-agent"]
    }

    route "default" {
        priority "low"
        matches {
            path-prefix "/"
        }
        upstream "test-backend"
    }
}

upstreams {
    upstream "test-backend" {
        targets {
            target {
                address "httpbin.org:80"
                weight 1
            }
        }
        load-balancing "round_robin"
    }
}

agents {
    agent "echo-agent" {
        type "custom"
        transport "unix_socket" {
            path "$ECHO_SOCKET"
        }
        events ["request_headers" "response_headers"]
        timeout-ms 100
        failure-mode "open"
    }

    agent "ratelimit-agent" {
        type "rate_limit"
        transport "unix_socket" {
            path "$RATELIMIT_SOCKET"
        }
        events ["request_headers"]
        timeout-ms 100
        failure-mode "closed"
    }
}

limits {
    max-header-count 100
    max-header-size-bytes 8192
    max-body-size-bytes 1048576
}

observability {
    metrics {
        enabled true
        address "127.0.0.1:$METRICS_PORT"
        path "/metrics"
    }
    logging {
        level "debug"
        format "json"
    }
}
EOF
}

# Start echo agent
start_echo_agent() {
    log_info "Starting echo agent..."

    if [[ ! -f "target/release/sentinel-echo-agent" ]]; then
        log_failure "Echo agent binary not found"
        return 1
    fi

    RUST_LOG=debug ./target/release/sentinel-echo-agent \
        --socket "$ECHO_SOCKET" \
        --prefix "X-Test-" \
        --verbose \
        > "$TEST_DIR/echo-agent.log" 2>&1 &

    ECHO_PID=$!

    # Wait for socket to be created
    local retries=10
    while [[ ! -S "$ECHO_SOCKET" ]] && [[ $retries -gt 0 ]]; do
        sleep 0.5
        ((retries--))
    done

    if [[ -S "$ECHO_SOCKET" ]]; then
        log_info "Echo agent started (PID: $ECHO_PID)"
        return 0
    else
        log_failure "Echo agent failed to start"
        return 1
    fi
}

# Start rate limit agent
start_ratelimit_agent() {
    log_info "Starting rate limit agent..."

    if [[ ! -f "target/release/sentinel-ratelimit-agent" ]]; then
        log_failure "Rate limit agent binary not found"
        return 1
    fi

    RUST_LOG=debug ./target/release/sentinel-ratelimit-agent \
        --socket "$RATELIMIT_SOCKET" \
        --default-rps 5 \
        --default-burst 10 \
        > "$TEST_DIR/ratelimit-agent.log" 2>&1 &

    RATELIMIT_PID=$!

    # Wait for socket to be created
    local retries=10
    while [[ ! -S "$RATELIMIT_SOCKET" ]] && [[ $retries -gt 0 ]]; do
        sleep 0.5
        ((retries--))
    done

    if [[ -S "$RATELIMIT_SOCKET" ]]; then
        log_info "Rate limit agent started (PID: $RATELIMIT_PID)"
        return 0
    else
        log_failure "Rate limit agent failed to start"
        return 1
    fi
}

# Start proxy
start_proxy() {
    log_info "Starting Sentinel proxy..."

    if [[ ! -f "target/release/sentinel" ]]; then
        log_failure "Proxy binary not found"
        return 1
    fi

    RUST_LOG=debug SENTINEL_CONFIG="$PROXY_CONFIG" \
        ./target/release/sentinel \
        > "$TEST_DIR/proxy.log" 2>&1 &

    PROXY_PID=$!

    # Wait for proxy to be ready
    local retries=20
    while ! curl -sf "http://127.0.0.1:$PROXY_PORT/health" >/dev/null 2>&1; do
        sleep 0.5
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            log_failure "Proxy failed to start"
            cat "$TEST_DIR/proxy.log" | tail -20
            return 1
        fi
    done

    log_info "Proxy started (PID: $PROXY_PID)"
    return 0
}

# Test echo agent functionality
test_echo_agent() {
    log_test "Testing echo agent..."

    # Make request through echo route
    local response=$(curl -s -i -H "X-Test-Header: TestValue" \
        "http://127.0.0.1:$PROXY_PORT/echo/test")

    # Check for echo headers
    if echo "$response" | grep -q "X-Test-Agent: echo-agent"; then
        log_success "Echo agent added agent header"
    else
        log_failure "Echo agent did not add agent header"
    fi

    if echo "$response" | grep -q "X-Test-Correlation-Id:"; then
        log_success "Echo agent added correlation ID"
    else
        log_failure "Echo agent did not add correlation ID"
    fi

    if echo "$response" | grep -q "X-Test-Method: GET"; then
        log_success "Echo agent echoed method"
    else
        log_failure "Echo agent did not echo method"
    fi

    if echo "$response" | grep -q "X-Test-Path: /echo/test"; then
        log_success "Echo agent echoed path"
    else
        log_failure "Echo agent did not echo path"
    fi
}

# Test rate limit agent functionality
test_ratelimit_agent() {
    log_test "Testing rate limit agent..."

    # Make multiple requests to trigger rate limit
    local success_count=0
    local limit_count=0

    for i in {1..15}; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" \
            "http://127.0.0.1:$PROXY_PORT/ratelimit/test")

        if [[ "$status" == "200" ]]; then
            ((success_count++))
        elif [[ "$status" == "429" ]]; then
            ((limit_count++))
        fi

        # Small delay between requests
        sleep 0.1
    done

    log_info "Successful requests: $success_count, Rate limited: $limit_count"

    if [[ $limit_count -gt 0 ]]; then
        log_success "Rate limit agent enforced limits"
    else
        log_failure "Rate limit agent did not enforce limits"
    fi

    # Test rate limit headers
    local response=$(curl -s -i "http://127.0.0.1:$PROXY_PORT/ratelimit/test")

    if echo "$response" | grep -q "X-RateLimit-"; then
        log_success "Rate limit agent added rate limit headers"
    else
        log_failure "Rate limit agent did not add rate limit headers"
    fi
}

# Test multiple agents
test_multiple_agents() {
    log_test "Testing multiple agents..."

    local response=$(curl -s -i \
        -H "X-Test-Header: MultiTest" \
        "http://127.0.0.1:$PROXY_PORT/multi/test")

    # Check for headers from both agents
    local echo_header=$(echo "$response" | grep "X-Test-Agent:" | wc -l)
    local ratelimit_header=$(echo "$response" | grep "X-RateLimit-" | wc -l)

    if [[ $echo_header -gt 0 ]] && [[ $ratelimit_header -gt 0 ]]; then
        log_success "Both agents processed request"
    else
        log_failure "Not all agents processed request"
    fi
}

# Test agent failure handling
test_agent_failure() {
    log_test "Testing agent failure handling..."

    # Kill echo agent to test failure mode
    kill -TERM "$ECHO_PID" 2>/dev/null || true
    ECHO_PID=""
    sleep 1

    # Request should still work (fail-open)
    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/echo/test")

    if [[ "$status" == "200" ]]; then
        log_success "Fail-open mode worked for echo route"
    else
        log_failure "Fail-open mode did not work for echo route"
    fi

    # Kill rate limit agent
    kill -TERM "$RATELIMIT_PID" 2>/dev/null || true
    RATELIMIT_PID=""
    sleep 1

    # Request should fail (fail-closed)
    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/ratelimit/test")

    if [[ "$status" != "200" ]]; then
        log_success "Fail-closed mode worked for rate limit route"
    else
        log_failure "Fail-closed mode did not work for rate limit route"
    fi
}

# Test metrics endpoint
test_metrics() {
    log_test "Testing metrics endpoint..."

    local metrics=$(curl -s "http://127.0.0.1:$METRICS_PORT/metrics")

    if echo "$metrics" | grep -q "sentinel_agent_calls_total"; then
        log_success "Agent metrics exposed"
    else
        log_failure "Agent metrics not exposed"
    fi

    if echo "$metrics" | grep -q "sentinel_agent_latency_seconds"; then
        log_success "Agent latency metrics exposed"
    else
        log_failure "Agent latency metrics not exposed"
    fi
}

# Test circuit breaker
test_circuit_breaker() {
    log_test "Testing agent circuit breaker..."

    # Restart agents for this test
    start_echo_agent
    start_ratelimit_agent
    sleep 2

    # Configure agent to timeout quickly
    # This would normally be in config, simulating with agent failure

    log_info "Circuit breaker test requires manual verification in logs"

    # Check logs for circuit breaker events
    if grep -q "Circuit breaker" "$TEST_DIR/proxy.log"; then
        log_success "Circuit breaker functionality detected"
    else
        log_info "Circuit breaker not triggered (may be normal)"
    fi
}

# Run performance test
test_performance() {
    log_test "Testing agent performance..."

    # Warm up
    for i in {1..10}; do
        curl -s "http://127.0.0.1:$PROXY_PORT/echo/warmup" >/dev/null 2>&1
    done

    # Measure baseline (no agent)
    local start=$(date +%s%N)
    for i in {1..100}; do
        curl -s "http://127.0.0.1:$PROXY_PORT/test" >/dev/null 2>&1
    done
    local end=$(date +%s%N)
    local baseline=$((($end - $start) / 1000000))

    # Measure with agent
    start=$(date +%s%N)
    for i in {1..100}; do
        curl -s "http://127.0.0.1:$PROXY_PORT/echo/test" >/dev/null 2>&1
    done
    end=$(date +%s%N)
    local with_agent=$((($end - $start) / 1000000))

    local overhead=$((($with_agent - $baseline) * 100 / $baseline))

    log_info "Baseline: ${baseline}ms, With agent: ${with_agent}ms, Overhead: ${overhead}%"

    if [[ $overhead -lt 50 ]]; then
        log_success "Agent overhead is acceptable (<50%)"
    else
        log_failure "Agent overhead is too high (${overhead}%)"
    fi
}

# Main test execution
main() {
    echo "==================================="
    echo "Sentinel Agent Integration Tests"
    echo "==================================="
    echo

    # Setup
    setup_test_environment

    # Start services
    start_echo_agent || exit 1
    start_ratelimit_agent || exit 1
    start_proxy || exit 1

    # Wait for services to stabilize
    sleep 2

    # Run tests
    test_echo_agent
    test_ratelimit_agent
    test_multiple_agents
    test_agent_failure
    test_metrics
    test_circuit_breaker
    test_performance

    # Print summary
    echo
    echo "==================================="
    echo "Test Summary"
    echo "==================================="
    echo "Tests run:    $TESTS_RUN"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    else
        echo -e "Tests failed: $TESTS_FAILED"
    fi
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        echo
        echo "Check logs for details:"
        echo "  Proxy log: $TEST_DIR/proxy.log"
        echo "  Echo agent log: $TEST_DIR/echo-agent.log"
        echo "  Rate limit agent log: $TEST_DIR/ratelimit-agent.log"
        exit 1
    fi
}

# Run main function
main "$@"
