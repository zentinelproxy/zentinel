#!/usr/bin/env bash
#
# Sentinel Chaos Tests - Common Utilities
#
# Shared functions for chaos test scenarios.
# Source this file at the start of each test script.
#

# Prevent double-sourcing
[[ -n "${_CHAOS_COMMON_SOURCED:-}" ]] && return 0
_CHAOS_COMMON_SOURCED=1

# ============================================================================
# Colors
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# Test Counters
# ============================================================================

declare -g TESTS_RUN=0
declare -g TESTS_PASSED=0
declare -g TESTS_FAILED=0
declare -g TESTS_SKIPPED=0

# ============================================================================
# Configuration
# ============================================================================

# Default endpoints (can be overridden)
PROXY_URL="${PROXY_URL:-http://localhost:8080}"
METRICS_URL="${METRICS_URL:-http://localhost:9090/metrics}"
HEALTH_URL="${HEALTH_URL:-http://localhost:9090/health}"

# Default timeouts
SERVICE_TIMEOUT="${SERVICE_TIMEOUT:-60}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-10}"

# Output directory (set by run-chaos-test.sh)
OUTPUT_DIR="${OUTPUT_DIR:-./results/$(date '+%Y%m%d_%H%M%S')}"

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%H:%M:%S') $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
    ((TESTS_SKIPPED++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_chaos() {
    echo -e "${CYAN}[CHAOS]${NC} $(date '+%H:%M:%S') $*"
}

log_restore() {
    echo -e "${GREEN}[RESTORE]${NC} $(date '+%H:%M:%S') $*"
}

# ============================================================================
# Service Utilities
# ============================================================================

# Wait for a service to become available
# Usage: wait_for_service <url> <name> [timeout_seconds]
wait_for_service() {
    local url="$1"
    local name="$2"
    local timeout="${3:-$SERVICE_TIMEOUT}"
    local start_time=$(date +%s)

    log_info "Waiting for $name at $url..."

    while true; do
        if curl -sf "$url" >/dev/null 2>&1; then
            log_info "$name is ready"
            return 0
        fi

        local elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -gt $timeout ]]; then
            log_warn "$name not ready after ${timeout}s"
            return 1
        fi

        sleep 1
    done
}

# Check if a service is responding
# Usage: service_is_up <url>
service_is_up() {
    local url="$1"
    curl -sf "$url" >/dev/null 2>&1
}

# ============================================================================
# HTTP Request Utilities
# ============================================================================

# Make a request and return the HTTP status code
# Usage: http_status <url> [method]
http_status() {
    local url="$1"
    local method="${2:-GET}"
    curl -sf -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null || echo "000"
}

# Make a request and return the response body
# Usage: http_get <url>
http_get() {
    local url="$1"
    curl -sf "$url" 2>/dev/null || echo ""
}

# Make multiple requests and count successes
# Usage: count_successes <url> <count>
count_successes() {
    local url="$1"
    local count="$2"
    local successes=0

    for ((i=1; i<=count; i++)); do
        local status=$(http_status "$url")
        [[ "$status" == "200" ]] && ((successes++))
    done

    echo "$successes"
}

# Make multiple requests and count specific status codes
# Usage: count_status <url> <count> <expected_status>
count_status() {
    local url="$1"
    local count="$2"
    local expected="$3"
    local matches=0

    for ((i=1; i<=count; i++)); do
        local status=$(http_status "$url")
        [[ "$status" == "$expected" ]] && ((matches++))
    done

    echo "$matches"
}

# ============================================================================
# Metrics Utilities
# ============================================================================

# Get a metric value from Prometheus endpoint
# Usage: get_metric <metric_name> [labels]
# Example: get_metric "sentinel_agent_failures_total" "agent=\"echo\""
get_metric() {
    local metric="$1"
    local labels="${2:-}"
    local endpoint="${METRICS_URL}"

    local pattern="$metric"
    [[ -n "$labels" ]] && pattern="${metric}{${labels}}"

    curl -sf "$endpoint" 2>/dev/null | grep "^${pattern}" | head -1 | awk '{print $2}'
}

# Get all metrics matching a pattern
# Usage: get_metrics_matching <pattern>
get_metrics_matching() {
    local pattern="$1"
    curl -sf "$METRICS_URL" 2>/dev/null | grep "$pattern"
}

# Check if a metric exists
# Usage: metric_exists <metric_name>
metric_exists() {
    local metric="$1"
    curl -sf "$METRICS_URL" 2>/dev/null | grep -q "^${metric}"
}

# ============================================================================
# Assertion Functions
# ============================================================================

# Assert that two values are equal
# Usage: assert_eq <actual> <expected> <message>
assert_eq() {
    local actual="$1"
    local expected="$2"
    local message="$3"

    if [[ "$actual" == "$expected" ]]; then
        log_pass "$message"
        return 0
    else
        log_fail "$message (expected: $expected, got: $actual)"
        return 1
    fi
}

# Assert that a value is greater than or equal to expected
# Usage: assert_gte <actual> <expected> <message>
assert_gte() {
    local actual="$1"
    local expected="$2"
    local message="$3"

    if [[ "$actual" -ge "$expected" ]]; then
        log_pass "$message"
        return 0
    else
        log_fail "$message (expected >= $expected, got: $actual)"
        return 1
    fi
}

# Assert that a value is less than expected
# Usage: assert_lt <actual> <expected> <message>
assert_lt() {
    local actual="$1"
    local expected="$2"
    local message="$3"

    if [[ "$actual" -lt "$expected" ]]; then
        log_pass "$message"
        return 0
    else
        log_fail "$message (expected < $expected, got: $actual)"
        return 1
    fi
}

# Assert HTTP status code
# Usage: assert_status <url> <expected_status> <message>
assert_status() {
    local url="$1"
    local expected="$2"
    local message="$3"

    local actual=$(http_status "$url")
    assert_eq "$actual" "$expected" "$message"
}

# Assert that a condition is true
# Usage: assert_true <condition_result> <message>
assert_true() {
    local result="$1"
    local message="$2"

    if [[ "$result" == "0" || "$result" == "true" || "$result" == "1" ]]; then
        log_pass "$message"
        return 0
    else
        log_fail "$message"
        return 1
    fi
}

# ============================================================================
# Chaos Event Logging
# ============================================================================

# Log a chaos event to the events file
# Usage: log_chaos_event <event_type> <target> [details]
log_chaos_event() {
    local event_type="$1"
    local target="$2"
    local details="${3:-}"

    local timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    echo "$timestamp $event_type $target $details" >> "${OUTPUT_DIR}/chaos-events.log"
}

# ============================================================================
# Summary and Reporting
# ============================================================================

# Print test summary
print_summary() {
    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo -e "Total:   ${TESTS_RUN}"
    echo -e "Passed:  ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Failed:  ${RED}${TESTS_FAILED}${NC}"
    echo -e "Skipped: ${YELLOW}${TESTS_SKIPPED}${NC}"
    echo "=========================================="

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
    else
        echo -e "${RED}SOME TESTS FAILED${NC}"
    fi
    echo ""
}

# Get exit code based on test results
get_exit_code() {
    [[ $TESTS_FAILED -eq 0 ]] && echo 0 || echo 1
}

# ============================================================================
# Docker Utilities
# ============================================================================

# Get container memory usage
# Usage: get_container_memory <container_name>
get_container_memory() {
    local container="$1"
    docker stats "$container" --no-stream --format '{{.MemUsage}}' 2>/dev/null | awk -F'/' '{print $1}'
}

# Check if a container is running
# Usage: container_is_running <container_name>
container_is_running() {
    local container="$1"
    docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q 'true'
}

# Get container status
# Usage: get_container_status <container_name>
get_container_status() {
    local container="$1"
    docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null
}

# ============================================================================
# Initialization
# ============================================================================

# Ensure output directory exists
mkdir -p "${OUTPUT_DIR}" 2>/dev/null || true

# Initialize chaos events log
touch "${OUTPUT_DIR}/chaos-events.log" 2>/dev/null || true
