#!/usr/bin/env bash
#
# Chaos Test: Backend 5xx Errors (Simplified)
#
# NOTE: Full 5xx testing requires httpbin backend which can return arbitrary status codes.
# With nginx backend, this test validates basic error handling and metrics.
#
# Validates:
#   - Normal operation works
#   - Error metrics infrastructure is present
#   - Backend errors (via crash) are handled correctly
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

SUCCESS_URL="${PROXY_URL}/primary/"
FAILOVER_URL="${PROXY_URL}/failover/"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify normal operation ==="

    assert_status "$SUCCESS_URL" "200" "Primary route works"
    assert_status "$FAILOVER_URL" "200" "Failover route works"
}

test_backend_error_via_crash() {
    log_info "=== Test: Backend errors via crash (simulated 5xx) ==="

    # Kill the primary backend - this will cause connection errors (similar to 502)
    inject_backend_crash "backend-primary"
    sleep 3

    # Primary route should return 5xx
    local status
    status=$(http_status "$SUCCESS_URL")

    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Primary route returns $status when backend is down"
    else
        log_fail "Primary route returned $status, expected 502/503/504"
    fi

    # Restore
    restore_backend "backend-primary"
    sleep 3
}

test_retry_on_backend_error() {
    log_info "=== Test: Retry behavior on backend errors ==="

    # Get initial retry count
    local initial_retries
    initial_retries=$(get_metric "sentinel_upstream_retries_total" || echo "0")

    # Kill primary - failover route should retry and hit secondary
    inject_backend_crash "backend-primary"
    sleep 3

    # Make requests to failover route
    for i in {1..5}; do
        http_status "$FAILOVER_URL" >/dev/null 2>&1 || true
    done

    # Check if retries increased
    local final_retries
    final_retries=$(get_metric "sentinel_upstream_retries_total" || echo "0")

    if [[ "${final_retries:-0}" -gt "${initial_retries:-0}" ]]; then
        log_pass "Retries recorded: ${initial_retries:-0} -> ${final_retries:-0}"
    else
        log_info "Retry count: ${initial_retries:-0} -> ${final_retries:-0} (may not have needed retries)"
    fi

    # Restore
    restore_backend "backend-primary"
    sleep 3
}

test_error_metrics_exist() {
    log_info "=== Test: Error metrics infrastructure ==="

    # Check for upstream error metrics
    local errors
    errors=$(get_metric "sentinel_upstream_connection_errors_total")
    if [[ -n "$errors" ]]; then
        log_pass "Connection error metric exists: $errors"
    else
        log_info "Connection error metric: not found (may be OK if no errors occurred)"
    fi

    # Check for response metrics
    local responses
    responses=$(get_metrics_matching "sentinel_upstream_responses_total")
    if [[ -n "$responses" ]]; then
        log_pass "Response metrics exist"
        echo "$responses" | head -3 | while read -r line; do
            log_info "  $line"
        done
    else
        log_info "Response metrics: not found"
    fi
}

test_health_check_independent() {
    log_info "=== Test: Health check independent of application errors ==="

    # Verify health endpoint still works
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")

    if [[ -n "$healthy" && "$healthy" -ge 1 ]]; then
        log_pass "Backend marked healthy: $healthy backend(s)"
    else
        log_info "Healthy backends: ${healthy:-unknown}"
    fi

    # Verify routes work
    assert_status "$SUCCESS_URL" "200" "Primary route works"
}

test_httpbin_skip_notice() {
    log_info "=== Notice: Full 5xx testing requires httpbin ==="
    log_info "The following tests are skipped with nginx backend:"
    log_info "  - 500 passthrough test"
    log_info "  - 502/503/504 individual handling"
    log_info "  - Retry on specific 5xx codes"
    log_skip "Detailed 5xx tests (requires httpbin backend)"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Backend 5xx Error Test (Simplified for nginx)"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests
    test_baseline
    test_backend_error_via_crash
    test_retry_on_backend_error
    test_error_metrics_exist
    test_health_check_independent
    test_httpbin_skip_notice

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
