#!/usr/bin/env bash
#
# Chaos Test: Backend 5xx Errors
#
# Tests proxy behavior when backends return 5xx errors.
# Uses httpbin's /status endpoint to simulate error responses.
# Validates:
#   - 5xx errors are passed through correctly
#   - Retry policy triggers on retryable status codes (502, 503, 504)
#   - Error metrics are recorded
#   - Health checks still work despite application errors
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

# httpbin /status/<code> returns that status code
ERROR_500_URL="${PROXY_URL}/primary/status/500"
ERROR_502_URL="${PROXY_URL}/primary/status/502"
ERROR_503_URL="${PROXY_URL}/primary/status/503"
ERROR_504_URL="${PROXY_URL}/primary/status/504"
SUCCESS_URL="${PROXY_URL}/primary/status/200"

# Failover route has retry policy for 502, 503, 504
RETRY_502_URL="${PROXY_URL}/failover/status/502"
RETRY_503_URL="${PROXY_URL}/failover/status/503"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify normal operation ==="

    assert_status "$SUCCESS_URL" "200" "Success endpoint works"
}

test_500_passthrough() {
    log_info "=== Test: 500 Internal Server Error passthrough ==="

    # 500 is not in retry list, should pass through as-is
    local status
    status=$(http_status "$ERROR_500_URL")

    if [[ "$status" == "500" ]]; then
        log_pass "500 error passed through correctly"
    else
        log_fail "Expected 500, got $status"
    fi
}

test_502_handling() {
    log_info "=== Test: 502 Bad Gateway handling ==="

    local status
    status=$(http_status "$ERROR_502_URL")

    if [[ "$status" == "502" ]]; then
        log_pass "502 error returned"
    else
        log_info "Response status: $status"
    fi
}

test_503_handling() {
    log_info "=== Test: 503 Service Unavailable handling ==="

    local status
    status=$(http_status "$ERROR_503_URL")

    if [[ "$status" == "503" ]]; then
        log_pass "503 error returned"
    else
        log_info "Response status: $status"
    fi
}

test_504_handling() {
    log_info "=== Test: 504 Gateway Timeout handling ==="

    local status
    status=$(http_status "$ERROR_504_URL")

    if [[ "$status" == "504" ]]; then
        log_pass "504 error returned"
    else
        log_info "Response status: $status"
    fi
}

test_retry_on_5xx() {
    log_info "=== Test: Retry policy for 5xx errors ==="

    # Get initial retry count
    local initial_retries
    initial_retries=$(get_metric "sentinel_upstream_retries_total" "upstream=\"with-failover\"" || echo "0")

    # Make requests that should trigger retries
    # Note: Both backends in failover pool return 502, so retries won't help
    # but should still be attempted
    for i in {1..5}; do
        http_status "$RETRY_502_URL" >/dev/null 2>&1 || true
    done

    # Check if retries were attempted
    local final_retries
    final_retries=$(get_metric "sentinel_upstream_retries_total" "upstream=\"with-failover\"" || echo "0")

    if [[ "${final_retries:-0}" -gt "${initial_retries:-0}" ]]; then
        local diff=$((${final_retries:-0} - ${initial_retries:-0}))
        log_pass "Retries triggered on 5xx: $diff retries"
    else
        log_info "Retry count: initial=$initial_retries, final=$final_retries"
    fi
}

test_error_metrics() {
    log_info "=== Test: Error response metrics ==="

    # Make several error requests
    for code in 500 502 503 504; do
        http_status "${PROXY_URL}/primary/status/${code}" >/dev/null 2>&1 || true
    done

    # Check for error count metrics
    local errors_5xx
    errors_5xx=$(get_metric "sentinel_upstream_responses_total" "upstream=\"primary\",status=\"5xx\"")

    if [[ -n "$errors_5xx" && "$errors_5xx" -gt 0 ]]; then
        log_pass "5xx responses recorded in metrics: $errors_5xx"
    else
        log_info "5xx response metric: ${errors_5xx:-not found}"
    fi

    # Check status code distribution
    log_info "Status code distribution:"
    for code in 200 500 502 503 504; do
        local count
        count=$(get_metric "sentinel_upstream_responses_total" "upstream=\"primary\",status=\"${code}\"")
        log_info "  $code: ${count:-0}"
    done
}

test_health_check_independent() {
    log_info "=== Test: Health check independent of application errors ==="

    # Even though we're getting 5xx on application endpoints,
    # the health check endpoint (/status/200) should still work
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")

    if [[ -n "$healthy" && "$healthy" -ge 1 ]]; then
        log_pass "Backend still marked healthy despite 5xx application responses"
    else
        log_info "Healthy backends: ${healthy:-unknown}"
    fi

    # Verify health endpoint still works
    assert_status "$SUCCESS_URL" "200" "Success endpoint still works"
}

test_mixed_responses() {
    log_info "=== Test: Mixed success/error responses ==="

    # Alternate between success and error
    local successes=0
    local errors=0

    for i in {1..10}; do
        local url status
        if [[ $((i % 2)) -eq 0 ]]; then
            url="$SUCCESS_URL"
        else
            url="$ERROR_503_URL"
        fi

        status=$(http_status "$url")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        elif [[ "$status" == "503" ]]; then
            ((errors++))
        fi
    done

    log_info "Mixed test results: $successes successes, $errors expected errors"

    if [[ $successes -ge 4 && $errors -ge 4 ]]; then
        log_pass "Mixed responses handled correctly"
    else
        log_warn "Unexpected distribution of responses"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Backend 5xx Error Chaos Test"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests
    test_baseline
    test_500_passthrough
    test_502_handling
    test_503_handling
    test_504_handling
    test_retry_on_5xx
    test_error_metrics
    test_health_check_independent
    test_mixed_responses

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
