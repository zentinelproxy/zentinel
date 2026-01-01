#!/usr/bin/env bash
#
# Chaos Test: All Backends Down
#
# Tests proxy behavior when all backend servers are unavailable.
# Validates:
#   - Appropriate 502/503 responses returned
#   - Proxy remains stable and responsive
#   - Health endpoint still works
#   - Metrics endpoint still works
#   - Recovery when backends return
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

PRIMARY_URL="${PROXY_URL}/primary/"
FAILOVER_URL="${PROXY_URL}/failover/"
HEALTH_CHECK_INTERVAL=5

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify all backends healthy ==="

    assert_status "$PRIMARY_URL" "200" "Primary route works"
    assert_status "$FAILOVER_URL" "200" "Failover route works"
}

test_kill_all_backends() {
    log_info "=== Chaos: Kill all backend servers ==="

    # Kill all backends
    inject_all_backends_crash

    # Wait for health checks to detect failures
    log_info "Waiting for health checks to detect failures..."
    sleep $((HEALTH_CHECK_INTERVAL * 3))

    # Check healthy count is zero
    local healthy_primary healthy_failover
    healthy_primary=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
    healthy_failover=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"with-failover\"")

    log_info "Healthy backends - primary: ${healthy_primary:-unknown}, failover: ${healthy_failover:-unknown}"
}

test_graceful_degradation() {
    log_info "=== Test: Graceful degradation with no backends ==="

    # All routes should return error responses (502/503)
    local status
    status=$(http_status "$PRIMARY_URL")
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Primary route returns $status with no backends"
    else
        log_fail "Primary route returned $status, expected 502/503/504"
    fi

    status=$(http_status "$FAILOVER_URL")
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Failover route returns $status with no backends"
    else
        log_fail "Failover route returned $status, expected 502/503/504"
    fi
}

test_proxy_remains_healthy() {
    log_info "=== Test: Proxy health endpoint still responds ==="

    # Health endpoint should still work (it's handled by the proxy, not backends)
    local status
    status=$(http_status "$HEALTH_URL")

    if [[ "$status" == "200" ]]; then
        log_pass "Proxy health endpoint responds with 200"
    else
        # Some proxies report degraded health when backends are down
        log_info "Proxy health endpoint returned $status"
        if [[ "$status" == "503" ]]; then
            log_pass "Proxy reports degraded health (expected behavior)"
        else
            log_fail "Unexpected health status: $status"
        fi
    fi
}

test_metrics_still_available() {
    log_info "=== Test: Metrics endpoint still available ==="

    local status
    status=$(http_status "$METRICS_URL")

    if [[ "$status" == "200" ]]; then
        log_pass "Metrics endpoint responds with 200"

        # Verify we can still fetch metrics
        local metric_count
        metric_count=$(curl -sf "$METRICS_URL" 2>/dev/null | wc -l | tr -d ' ')
        log_info "Metrics response has $metric_count lines"
    else
        log_fail "Metrics endpoint returned $status"
    fi
}

test_proxy_stability_under_load() {
    log_info "=== Test: Proxy stability under load with no backends ==="

    # Send many requests quickly - proxy should remain stable
    local start_time requests errors
    start_time=$(date +%s)
    requests=0
    errors=0

    for i in {1..50}; do
        local status
        status=$(http_status "$PRIMARY_URL")
        ((requests++))
        # We expect 502/503/504, anything else is unexpected
        if [[ "$status" != "502" && "$status" != "503" && "$status" != "504" && "$status" != "000" ]]; then
            ((errors++))
            log_warn "Unexpected response: $status"
        fi
    done

    local elapsed=$(($(date +%s) - start_time))
    log_info "Sent $requests requests in ${elapsed}s"

    if [[ $errors -eq 0 ]]; then
        log_pass "Proxy handled all requests gracefully ($requests requests)"
    else
        log_warn "Had $errors unexpected responses out of $requests"
    fi

    # Verify proxy is still responding
    assert_status "$HEALTH_URL" "200" "Proxy still healthy after load" ||
    assert_status "$HEALTH_URL" "503" "Proxy reports degraded after load"
}

test_recovery_when_backends_return() {
    log_info "=== Test: Recovery when backends restart ==="

    # Restore all backends
    restore_all_backends

    # Wait for health checks to detect recovery
    log_info "Waiting for health checks to detect recovery..."
    sleep $((HEALTH_CHECK_INTERVAL * 4))

    # Routes should work again
    local successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$PRIMARY_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
        sleep 0.5
    done

    if [[ $successes -ge 3 ]]; then
        log_pass "Primary route recovered ($successes/5 success)"
    else
        log_fail "Primary route not recovered ($successes/5 success)"
    fi

    successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$FAILOVER_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
        sleep 0.5
    done

    if [[ $successes -ge 3 ]]; then
        log_pass "Failover route recovered ($successes/5 success)"
    else
        log_fail "Failover route not recovered ($successes/5 success)"
    fi

    # Check healthy count restored
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
    if [[ -n "$healthy" && "$healthy" -ge 1 ]]; then
        log_pass "Primary upstream healthy: $healthy backend(s)"
    else
        log_info "Primary upstream healthy backends: ${healthy:-unknown}"
    fi
}

test_error_metrics_accumulated() {
    log_info "=== Test: Error metrics accumulated correctly ==="

    # Check for connection errors
    local errors
    errors=$(get_metric "sentinel_upstream_connection_errors_total" "upstream=\"primary\"")
    if [[ -n "$errors" && "$errors" -gt 0 ]]; then
        log_pass "Connection errors recorded: $errors"
    else
        log_info "Connection errors: ${errors:-not found}"
    fi

    # Check for health check failures
    local failures
    failures=$(get_metric "sentinel_upstream_health_check_failures_total" "upstream=\"primary\"")
    if [[ -n "$failures" && "$failures" -gt 0 ]]; then
        log_pass "Health check failures recorded: $failures"
    else
        log_info "Health check failures: ${failures:-not found}"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting All Backends Down Chaos Test"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests in sequence
    test_baseline
    test_kill_all_backends
    test_graceful_degradation
    test_proxy_remains_healthy
    test_metrics_still_available
    test_proxy_stability_under_load
    test_recovery_when_backends_return
    test_error_metrics_accumulated

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
