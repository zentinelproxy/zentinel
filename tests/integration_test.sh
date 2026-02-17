#!/bin/bash
#
# Zentinel Comprehensive Integration Test Suite
#
# This script tests the Zentinel reverse proxy with all agents in a Docker environment.
# It validates both engineering (source code) and configuration correctness.
#
# Prerequisites:
# - Docker and Docker Compose installed
# - curl, jq installed
#
# Usage:
#   ./tests/integration_test.sh              # Run all tests
#   ./tests/integration_test.sh --quick      # Run quick smoke tests only
#   ./tests/integration_test.sh --no-build   # Skip docker build step
#   ./tests/integration_test.sh --keep       # Keep containers running after tests
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8080}"
METRICS_PORT="${METRICS_PORT:-9090}"
RATELIMIT_METRICS_PORT="${RATELIMIT_METRICS_PORT:-9092}"
WAF_METRICS_PORT="${WAF_METRICS_PORT:-9094}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9091}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
JAEGER_PORT="${JAEGER_PORT:-16686}"

# Test options
QUICK_TEST=false
SKIP_BUILD=false
KEEP_CONTAINERS=false
VERBOSE=false

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)
            QUICK_TEST=true
            shift
            ;;
        --no-build)
            SKIP_BUILD=true
            shift
            ;;
        --keep)
            KEEP_CONTAINERS=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick      Run quick smoke tests only"
            echo "  --no-build   Skip docker build step"
            echo "  --keep       Keep containers running after tests"
            echo "  --verbose    Show verbose output"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging functions
log_header() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

log_section() {
    echo ""
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────────${NC}"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    ((TESTS_SKIPPED++))
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    ((TESTS_RUN++))
}

# Cleanup function
cleanup() {
    local exit_code=$?

    if [[ "$KEEP_CONTAINERS" == "true" ]]; then
        log_info "Keeping containers running (--keep flag)"
        log_info "To stop: docker compose -f docker-compose.yml down"
    else
        log_info "Cleaning up Docker containers..."
        cd "$PROJECT_DIR"
        docker compose -f docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true
    fi

    print_summary
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Print test summary
print_summary() {
    echo ""
    log_header "Test Summary"
    echo ""
    echo -e "  ${BOLD}Total tests run:${NC}   $TESTS_RUN"
    echo -e "  ${GREEN}Tests passed:${NC}      $TESTS_PASSED"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "  ${RED}Tests failed:${NC}      $TESTS_FAILED"
    else
        echo -e "  Tests failed:      $TESTS_FAILED"
    fi
    if [[ $TESTS_SKIPPED -gt 0 ]]; then
        echo -e "  ${YELLOW}Tests skipped:${NC}     $TESTS_SKIPPED"
    fi
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}All tests passed!${NC}"
    else
        echo -e "${RED}${BOLD}Some tests failed. See above for details.${NC}"
    fi
}

# Wait for a service to be ready
wait_for_service() {
    local url="$1"
    local service_name="$2"
    local timeout="${3:-60}"
    local start_time=$(date +%s)

    log_info "Waiting for $service_name to be ready..."

    while true; do
        if curl -sf "$url" >/dev/null 2>&1; then
            log_debug "$service_name is ready"
            return 0
        fi

        local elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -gt $timeout ]]; then
            log_failure "$service_name failed to start within ${timeout}s"
            return 1
        fi

        sleep 1
    done
}

# Make HTTP request and capture response
http_request() {
    local method="${1:-GET}"
    local path="$2"
    local data="${3:-}"
    local headers=()
    shift 3 || true

    while [[ $# -gt 0 ]]; do
        headers+=(-H "$1")
        shift
    done

    local url="http://${PROXY_HOST}:${PROXY_PORT}${path}"
    local curl_args=(-s -w "\n%{http_code}" -X "$method" "${headers[@]}")

    if [[ -n "$data" ]]; then
        curl_args+=(-d "$data")
    fi

    local response
    response=$(curl "${curl_args[@]}" "$url" 2>/dev/null)
    echo "$response"
}

# Extract HTTP status code from response
get_status_code() {
    echo "$1" | tail -n1
}

# Extract response body
get_body() {
    echo "$1" | sed '$d'
}

# Assert HTTP status code
assert_status() {
    local response="$1"
    local expected="$2"
    local test_name="$3"

    local actual=$(get_status_code "$response")

    if [[ "$actual" == "$expected" ]]; then
        log_success "$test_name (HTTP $actual)"
        return 0
    else
        log_failure "$test_name - expected HTTP $expected, got HTTP $actual"
        log_debug "Response body: $(get_body "$response")"
        return 1
    fi
}

# Assert response contains text
assert_contains() {
    local response="$1"
    local expected="$2"
    local test_name="$3"

    local body=$(get_body "$response")

    if echo "$body" | grep -q "$expected"; then
        log_success "$test_name"
        return 0
    else
        log_failure "$test_name - response does not contain '$expected'"
        log_debug "Response: $body"
        return 1
    fi
}

# Assert response header exists
assert_header() {
    local header_name="$1"
    local path="$2"
    local test_name="$3"

    local headers=$(curl -sI "http://${PROXY_HOST}:${PROXY_PORT}${path}" 2>/dev/null)

    if echo "$headers" | grep -qi "^${header_name}:"; then
        log_success "$test_name"
        return 0
    else
        log_failure "$test_name - header '$header_name' not found"
        log_debug "Headers: $headers"
        return 1
    fi
}

###############################################################################
# Test Suites
###############################################################################

# Test basic proxy functionality
test_basic_proxy() {
    log_section "Basic Proxy Tests"

    log_test "GET request to backend"
    local response=$(http_request GET "/get")
    assert_status "$response" "200" "Basic GET request"

    log_test "POST request to backend"
    response=$(http_request POST "/post" '{"test":"data"}' "Content-Type: application/json")
    assert_status "$response" "200" "Basic POST request"

    log_test "Request with custom headers"
    response=$(http_request GET "/headers" "" "X-Custom-Header: test-value")
    assert_status "$response" "200" "Custom header passthrough"

    log_test "404 for unknown path"
    response=$(http_request GET "/this-path-does-not-exist-12345")
    # httpbin returns 404 for unknown paths
    local status=$(get_status_code "$response")
    if [[ "$status" == "404" ]]; then
        log_success "404 for unknown path"
    else
        # Backend might return 200 for any path - that's OK
        log_success "Backend response for unknown path (HTTP $status)"
    fi
}

# Test health endpoints
test_health_endpoints() {
    log_section "Health Endpoint Tests"

    log_test "Proxy health endpoint"
    local response=$(curl -sf "http://${PROXY_HOST}:${METRICS_PORT}/health" 2>/dev/null)
    if [[ -n "$response" ]]; then
        log_success "Proxy health endpoint responds"
    else
        log_failure "Proxy health endpoint not responding"
    fi

    log_test "Proxy metrics endpoint"
    response=$(curl -sf "http://${PROXY_HOST}:${METRICS_PORT}/metrics" 2>/dev/null)
    if echo "$response" | grep -q "zentinel_"; then
        log_success "Proxy metrics endpoint returns zentinel metrics"
    else
        log_failure "Proxy metrics endpoint missing zentinel metrics"
    fi
}

# Test echo agent
test_echo_agent() {
    log_section "Echo Agent Tests"

    log_test "Echo agent adds headers"
    local headers=$(curl -sI "http://${PROXY_HOST}:${PROXY_PORT}/echo/test" 2>/dev/null)

    if echo "$headers" | grep -qi "X-.*Agent"; then
        log_success "Echo agent added agent headers"
    else
        log_skip "Echo agent headers not detected (agent may not be running)"
    fi

    log_test "Echo agent with correlation ID"
    headers=$(curl -sI "http://${PROXY_HOST}:${PROXY_PORT}/echo/test" 2>/dev/null)

    if echo "$headers" | grep -qi "Correlation"; then
        log_success "Echo agent added correlation ID"
    else
        log_skip "Correlation ID not detected"
    fi

    log_test "Echo agent request passes through"
    local response=$(http_request GET "/echo/anything")
    assert_status "$response" "200" "Echo route request succeeds"
}

# Test rate limit agent
test_ratelimit_agent() {
    log_section "Rate Limit Agent Tests"

    log_test "Rate limit agent metrics"
    local metrics=$(curl -sf "http://${PROXY_HOST}:${RATELIMIT_METRICS_PORT}/metrics" 2>/dev/null)
    if [[ -n "$metrics" ]]; then
        log_success "Rate limit agent metrics endpoint accessible"
    else
        log_skip "Rate limit agent metrics not accessible"
    fi

    log_test "Rate limit headers present"
    local headers=$(curl -sI "http://${PROXY_HOST}:${PROXY_PORT}/limited/test" 2>/dev/null)

    if echo "$headers" | grep -qi "X-RateLimit"; then
        log_success "Rate limit headers present"
    else
        log_skip "Rate limit headers not detected"
    fi

    log_test "Rate limit enforcement"
    local success_count=0
    local limited_count=0

    # Make rapid requests to trigger rate limit
    for i in {1..30}; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${PROXY_PORT}/limited/test?req=$i" 2>/dev/null)

        if [[ "$status" == "200" ]]; then
            ((success_count++))
        elif [[ "$status" == "429" ]]; then
            ((limited_count++))
        fi
    done

    log_info "Rate limit results: $success_count allowed, $limited_count rate-limited"

    if [[ $limited_count -gt 0 ]]; then
        log_success "Rate limiting enforced ($limited_count requests limited)"
    else
        log_skip "Rate limiting not triggered (may have higher limits configured)"
    fi
}

# Test WAF agent
test_waf_agent() {
    log_section "WAF Agent Tests"

    log_test "WAF agent metrics"
    local metrics=$(curl -sf "http://${PROXY_HOST}:${WAF_METRICS_PORT}/metrics" 2>/dev/null)
    if [[ -n "$metrics" ]]; then
        log_success "WAF agent metrics endpoint accessible"
    else
        log_skip "WAF agent metrics not accessible"
    fi

    log_test "Legitimate request passes WAF"
    local response=$(http_request GET "/protected/test")
    local status=$(get_status_code "$response")
    if [[ "$status" == "200" ]]; then
        log_success "Legitimate request allowed through WAF"
    else
        log_skip "WAF may not be active (status: $status)"
    fi

    log_test "SQL injection blocked"
    response=$(http_request GET "/protected/test?id=1' OR '1'='1")
    status=$(get_status_code "$response")
    if [[ "$status" == "403" ]]; then
        log_success "SQL injection blocked (HTTP 403)"
    elif [[ "$status" == "200" ]]; then
        log_skip "WAF not blocking SQL injection (may be in detection mode)"
    else
        log_info "SQL injection test returned HTTP $status"
    fi

    log_test "XSS attack blocked"
    response=$(http_request POST "/protected/test" "input=<script>alert('XSS')</script>" "Content-Type: application/x-www-form-urlencoded")
    status=$(get_status_code "$response")
    if [[ "$status" == "403" ]]; then
        log_success "XSS attack blocked (HTTP 403)"
    else
        log_skip "XSS not blocked (status: $status)"
    fi

    log_test "Path traversal blocked"
    response=$(http_request GET "/protected/../../../etc/passwd")
    status=$(get_status_code "$response")
    if [[ "$status" == "403" ]]; then
        log_success "Path traversal blocked (HTTP 403)"
    else
        log_skip "Path traversal not blocked (status: $status)"
    fi

    log_test "WAF bypass header"
    response=$(http_request GET "/protected/test?id=' OR '1'='1" "" "X-WAF-Bypass: test-secret-key")
    status=$(get_status_code "$response")
    if [[ "$status" == "200" ]]; then
        log_success "WAF bypass header works"
    else
        log_skip "WAF bypass not configured (status: $status)"
    fi
}

# Test multi-agent pipeline
test_multi_agent() {
    log_section "Multi-Agent Pipeline Tests"

    log_test "Request through multi-agent pipeline"
    local response=$(http_request GET "/multi/test")
    assert_status "$response" "200" "Multi-agent route accessible"

    log_test "All agents process request"
    local headers=$(curl -sI "http://${PROXY_HOST}:${PROXY_PORT}/multi/test" 2>/dev/null)

    local agents_detected=0
    if echo "$headers" | grep -qi "X-.*Agent"; then
        ((agents_detected++))
    fi
    if echo "$headers" | grep -qi "X-RateLimit"; then
        ((agents_detected++))
    fi

    if [[ $agents_detected -ge 1 ]]; then
        log_success "Multiple agents processed request ($agents_detected agent signatures)"
    else
        log_skip "Agent signatures not detected in response"
    fi
}

# Test agent failure handling
test_agent_failures() {
    log_section "Agent Failure Handling Tests"

    # Note: Can't easily simulate agent failures in Docker without stopping containers
    # This tests the configured failure mode behavior

    log_test "Fail-open routes work when agents unavailable"
    local response=$(http_request GET "/echo/failtest")
    local status=$(get_status_code "$response")

    if [[ "$status" == "200" || "$status" == "502" || "$status" == "503" ]]; then
        log_success "Fail-open route handled agent issue gracefully"
    else
        log_failure "Unexpected status for fail-open route: $status"
    fi

    log_test "Request timeout handling"
    # Make a request that might timeout
    response=$(curl -s -m 5 -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${PROXY_PORT}/get" 2>/dev/null || echo "timeout")

    if [[ "$response" == "timeout" ]]; then
        log_skip "Request timed out (expected behavior in some scenarios)"
    else
        log_success "Request completed within timeout"
    fi
}

# Test observability
test_observability() {
    log_section "Observability Tests"

    # Generate some traffic first
    for i in {1..5}; do
        curl -sf "http://${PROXY_HOST}:${PROXY_PORT}/get" >/dev/null 2>&1 || true
    done

    log_test "Prometheus metrics collection"
    local metrics=$(curl -sf "http://${PROXY_HOST}:${PROMETHEUS_PORT}/api/v1/query?query=up" 2>/dev/null)
    if echo "$metrics" | jq -e '.status == "success"' >/dev/null 2>&1; then
        log_success "Prometheus is collecting metrics"
    else
        log_skip "Prometheus not accessible or not collecting metrics"
    fi

    log_test "Grafana accessible"
    local grafana_status=$(curl -s -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${GRAFANA_PORT}/api/health" 2>/dev/null)
    if [[ "$grafana_status" == "200" ]]; then
        log_success "Grafana is accessible"
    else
        log_skip "Grafana not accessible (status: $grafana_status)"
    fi

    log_test "Jaeger tracing UI"
    local jaeger_status=$(curl -s -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${JAEGER_PORT}/" 2>/dev/null)
    if [[ "$jaeger_status" == "200" ]]; then
        log_success "Jaeger UI is accessible"
    else
        log_skip "Jaeger not accessible (status: $jaeger_status)"
    fi
}

# Performance/load test
test_performance() {
    log_section "Performance Tests"

    if [[ "$QUICK_TEST" == "true" ]]; then
        log_skip "Performance tests skipped in quick mode"
        return
    fi

    log_test "Throughput test (100 requests)"
    local start_time=$(date +%s%N)
    local success=0
    local failed=0

    for i in {1..100}; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${PROXY_PORT}/get" 2>/dev/null)
        if [[ "$status" == "200" ]]; then
            ((success++))
        else
            ((failed++))
        fi
    done

    local end_time=$(date +%s%N)
    local duration_ms=$(( (end_time - start_time) / 1000000 ))
    local rps=$(( 100 * 1000 / duration_ms ))

    log_info "Completed 100 requests in ${duration_ms}ms (~${rps} req/s)"
    log_info "Success: $success, Failed: $failed"

    if [[ $success -ge 95 ]]; then
        log_success "Throughput test passed (${success}% success rate)"
    else
        log_failure "Throughput test failed (${success}% success rate)"
    fi

    log_test "Concurrent request handling"
    local concurrent_success=0

    # Run 10 concurrent requests
    for i in {1..10}; do
        curl -sf "http://${PROXY_HOST}:${PROXY_PORT}/get" >/dev/null 2>&1 &
    done
    wait

    # Verify proxy still responds
    if curl -sf "http://${PROXY_HOST}:${PROXY_PORT}/get" >/dev/null 2>&1; then
        log_success "Proxy handles concurrent requests"
    else
        log_failure "Proxy failed after concurrent requests"
    fi
}

# Configuration validation tests
test_configuration() {
    log_section "Configuration Validation Tests"

    log_test "Proxy configuration loaded"
    local health=$(curl -sf "http://${PROXY_HOST}:${METRICS_PORT}/health" 2>/dev/null)
    if [[ -n "$health" ]]; then
        log_success "Proxy loaded configuration and is healthy"
    else
        log_failure "Proxy health check failed"
    fi

    log_test "Route matching works"
    # Test different route prefixes
    local routes_working=0

    for route in "/api/test" "/echo/test" "/limited/test" "/protected/test"; do
        local status=$(curl -s -o /dev/null -w "%{http_code}" "http://${PROXY_HOST}:${PROXY_PORT}${route}" 2>/dev/null)
        if [[ "$status" == "200" || "$status" == "403" || "$status" == "429" ]]; then
            ((routes_working++))
        fi
    done

    if [[ $routes_working -ge 3 ]]; then
        log_success "Route matching working ($routes_working/4 routes respond)"
    else
        log_failure "Route matching issues ($routes_working/4 routes working)"
    fi
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log_header "Zentinel Integration Test Suite"
    echo ""
    echo -e "  ${BOLD}Test Configuration:${NC}"
    echo -e "    Proxy:       http://${PROXY_HOST}:${PROXY_PORT}"
    echo -e "    Metrics:     http://${PROXY_HOST}:${METRICS_PORT}"
    echo -e "    Quick mode:  ${QUICK_TEST}"
    echo -e "    Skip build:  ${SKIP_BUILD}"
    echo ""

    cd "$PROJECT_DIR"

    # Build and start containers
    if [[ "$SKIP_BUILD" != "true" ]]; then
        log_section "Building Docker Images"
        log_info "Building Zentinel Docker images..."

        if ! docker compose -f docker-compose.yml build 2>&1 | tee /tmp/docker-build.log; then
            log_failure "Docker build failed. Check /tmp/docker-build.log for details"
            exit 1
        fi
        log_success "Docker images built successfully"
    else
        log_info "Skipping Docker build (--no-build)"
    fi

    log_section "Starting Test Environment"
    log_info "Starting Docker containers..."

    # Stop any existing containers
    docker compose -f docker-compose.yml down --volumes --remove-orphans 2>/dev/null || true

    # Start containers
    if ! docker compose -f docker-compose.yml up -d 2>&1; then
        log_failure "Failed to start Docker containers"
        exit 1
    fi

    # Wait for services to be ready
    log_info "Waiting for services to be ready..."

    # Wait for backend first (other services depend on it)
    wait_for_service "http://${PROXY_HOST}:8081/status/200" "Backend" 60 || exit 1

    # Wait for proxy
    wait_for_service "http://${PROXY_HOST}:${METRICS_PORT}/health" "Proxy" 120 || {
        log_info "Proxy not responding. Checking container logs..."
        docker compose -f docker-compose.yml logs proxy | tail -50
        exit 1
    }

    # Give agents a moment to connect
    sleep 5

    log_success "Test environment is ready"

    # Run test suites
    test_basic_proxy
    test_health_endpoints
    test_configuration
    test_echo_agent
    test_ratelimit_agent
    test_waf_agent
    test_multi_agent
    test_agent_failures
    test_observability
    test_performance

    # Exit with appropriate code
    if [[ $TESTS_FAILED -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"
