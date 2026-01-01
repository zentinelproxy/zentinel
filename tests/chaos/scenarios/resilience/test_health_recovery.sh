#!/usr/bin/env bash
#
# Chaos Test: Health Check Recovery
#
# Tests that the proxy correctly detects when services recover
# after failures.
# Validates:
#   - Health check detects backend recovery
#   - Traffic resumes after recovery detection
#   - Health metrics update correctly
#   - Recovery is stable (no flapping)
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

PRIMARY_URL="${PROXY_URL}/primary/status/200"
FAILOVER_URL="${PROXY_URL}/failover/status/200"
HEALTH_CHECK_INTERVAL=5  # From chaos-config.kdl
HEALTHY_THRESHOLD=2      # Probes needed to mark healthy

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: All services healthy ==="

    assert_status "$HEALTH_URL" "200" "Proxy health endpoint responds"
    assert_status "$PRIMARY_URL" "200" "Primary route works"

    # Verify healthy backends count
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
    log_info "Initial healthy backends (primary): ${healthy:-unknown}"
}

test_backend_failure_detection() {
    log_info "=== Test: Health check detects backend failure ==="

    # Kill primary backend
    inject_backend_crash "backend-primary"

    # Wait for health check to detect failure
    local wait_time=$((HEALTH_CHECK_INTERVAL * 3))
    log_info "Waiting ${wait_time}s for health check to detect failure..."
    sleep $wait_time

    # Verify backend marked unhealthy
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")

    if [[ -n "$healthy" && "$healthy" == "0" ]]; then
        log_pass "Health check detected failure (0 healthy backends)"
    else
        log_info "Healthy backends: ${healthy:-unknown}"
    fi

    # Traffic should fail
    local status
    status=$(http_status "$PRIMARY_URL")
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Primary route fails as expected ($status)"
    else
        log_fail "Primary route returned $status"
    fi
}

test_backend_recovery_detection() {
    log_info "=== Test: Health check detects backend recovery ==="

    # Restore the backend
    restore_backend "backend-primary"

    # Wait for health check to detect recovery
    # Need HEALTHY_THRESHOLD successful probes at HEALTH_CHECK_INTERVAL each
    local wait_time=$((HEALTH_CHECK_INTERVAL * (HEALTHY_THRESHOLD + 2)))
    log_info "Waiting ${wait_time}s for health check to detect recovery..."
    sleep $wait_time

    # Verify backend marked healthy again
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")

    if [[ -n "$healthy" && "$healthy" -ge 1 ]]; then
        log_pass "Health check detected recovery ($healthy healthy backend(s))"
    else
        log_warn "Healthy backends: ${healthy:-unknown}"
    fi

    # Traffic should work again
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
        log_pass "Traffic resumed after recovery ($successes/5 success)"
    else
        log_fail "Traffic not resumed ($successes/5 success)"
    fi
}

test_rapid_failure_recovery_cycle() {
    log_info "=== Test: Rapid failure/recovery cycle ==="

    # Perform multiple failure/recovery cycles
    for cycle in 1 2 3; do
        log_info "Cycle $cycle: Injecting failure..."
        inject_backend_crash "backend-primary"
        sleep $((HEALTH_CHECK_INTERVAL * 2))

        # Verify failure detected
        local healthy
        healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
        log_info "  Healthy after failure: ${healthy:-unknown}"

        log_info "Cycle $cycle: Restoring..."
        restore_backend "backend-primary"
        sleep $((HEALTH_CHECK_INTERVAL * 3))

        # Verify recovery detected
        healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
        log_info "  Healthy after restore: ${healthy:-unknown}"

        # Check traffic works
        local status
        status=$(http_status "$PRIMARY_URL")
        if [[ "$status" == "200" ]]; then
            log_info "  Cycle $cycle: Traffic OK"
        else
            log_warn "  Cycle $cycle: Traffic returned $status"
        fi
    done

    log_pass "Completed 3 failure/recovery cycles"
}

test_stable_after_recovery() {
    log_info "=== Test: System stable after recovery ==="

    # Ensure backend is up
    restore_backend "backend-primary" 2>/dev/null || true
    sleep $((HEALTH_CHECK_INTERVAL * 3))

    # Send sustained traffic and verify stability
    local successes=0
    local failures=0
    local total=50

    log_info "Sending $total requests to verify stability..."
    for i in $(seq 1 $total); do
        local status
        status=$(http_status "$PRIMARY_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        else
            ((failures++))
            if [[ $failures -le 3 ]]; then
                log_warn "Request $i failed with $status"
            fi
        fi
    done

    local success_rate=$((successes * 100 / total))
    log_info "Stability test: $successes/$total success (${success_rate}%)"

    if [[ $successes -ge $((total - 2)) ]]; then
        log_pass "System stable after recovery ($successes/$total success)"
    else
        log_fail "System unstable after recovery ($successes/$total success)"
    fi
}

test_health_check_metrics() {
    log_info "=== Test: Health check metrics recorded ==="

    # Check health check success/failure counts
    local successes failures
    successes=$(get_metric "sentinel_upstream_health_check_successes_total" "upstream=\"primary\"")
    failures=$(get_metric "sentinel_upstream_health_check_failures_total" "upstream=\"primary\"")

    log_info "Health check metrics:"
    log_info "  Successes: ${successes:-not found}"
    log_info "  Failures: ${failures:-not found}"

    if [[ -n "$successes" && "$successes" -gt 0 ]]; then
        log_pass "Health check successes recorded"
    else
        log_info "No health check success metric found"
    fi

    if [[ -n "$failures" && "$failures" -gt 0 ]]; then
        log_pass "Health check failures recorded"
    else
        log_info "No health check failure metric found"
    fi

    # Check for state transition events
    local transitions
    transitions=$(get_metrics_matching "sentinel_upstream_health_state_transitions")
    if [[ -n "$transitions" ]]; then
        log_info "Health state transitions:"
        echo "$transitions" | head -5 | while read -r line; do
            log_info "  $line"
        done
    fi
}

test_failover_pool_recovery() {
    log_info "=== Test: Failover pool recovery ==="

    # Kill primary, verify failover works
    inject_backend_crash "backend-primary"
    sleep $((HEALTH_CHECK_INTERVAL * 2))

    local status
    status=$(http_status "$FAILOVER_URL")
    if [[ "$status" == "200" ]]; then
        log_pass "Failover route works with primary down"
    else
        log_warn "Failover route returned $status"
    fi

    # Kill secondary too
    inject_backend_crash "backend-secondary"
    sleep $((HEALTH_CHECK_INTERVAL * 2))

    # Should fail now
    status=$(http_status "$FAILOVER_URL")
    if [[ "$status" != "200" ]]; then
        log_pass "Failover route fails with all backends down ($status)"
    else
        log_fail "Failover route unexpectedly succeeded"
    fi

    # Restore both
    restore_all_backends
    sleep $((HEALTH_CHECK_INTERVAL * 3))

    # Should work again
    status=$(http_status "$FAILOVER_URL")
    if [[ "$status" == "200" ]]; then
        log_pass "Failover route recovered after restoring backends"
    else
        log_fail "Failover route not recovered ($status)"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Health Check Recovery Test"
    log_info "Proxy URL: $PROXY_URL"
    log_info "Health check interval: ${HEALTH_CHECK_INTERVAL}s"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests
    test_baseline
    test_backend_failure_detection
    test_backend_recovery_detection
    test_rapid_failure_recovery_cycle
    test_stable_after_recovery
    test_health_check_metrics
    test_failover_pool_recovery

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
