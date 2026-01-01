#!/usr/bin/env bash
#
# Chaos Test: Backend Crash
#
# Tests proxy behavior when the primary backend crashes.
# Validates:
#   - Health check detects failure
#   - Traffic fails over to secondary backend (if configured)
#   - Recovery after backend restart
#   - Health metrics update correctly
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
HEALTH_CHECK_INTERVAL=5  # From chaos-config.kdl

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify both backends healthy ==="

    assert_status "$PRIMARY_URL" "200" "Primary backend route works"
    assert_status "$FAILOVER_URL" "200" "Failover route works"

    # Check healthy backends metric
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
    log_info "Healthy backends (primary): ${healthy:-unknown}"

    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"with-failover\"")
    log_info "Healthy backends (failover pool): ${healthy:-unknown}"
}

test_primary_backend_crash() {
    log_info "=== Test: Primary backend crash ==="

    # Kill the primary backend
    inject_backend_crash "backend-primary"

    # Wait for health check to detect failure
    log_info "Waiting for health check to detect failure (${HEALTH_CHECK_INTERVAL}s interval)..."
    sleep $((HEALTH_CHECK_INTERVAL * 3))

    # Primary-only route should fail
    local status
    status=$(http_status "$PRIMARY_URL")
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Primary route returns $status with backend down"
    else
        log_fail "Primary route returned $status, expected 502/503/504"
    fi
}

test_failover_works() {
    log_info "=== Test: Failover to secondary backend ==="

    # Failover route should still work (routes to secondary)
    local successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$FAILOVER_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
        sleep 0.5
    done

    if [[ $successes -ge 3 ]]; then
        log_pass "Failover route works with primary down ($successes/5 success)"
    else
        log_fail "Failover not working ($successes/5 success)"
    fi
}

test_health_metrics_update() {
    log_info "=== Test: Health check metrics update ==="

    # Check that healthy count decreased
    local healthy
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"primary\"")
    if [[ -n "$healthy" && "$healthy" == "0" ]]; then
        log_pass "Primary upstream shows 0 healthy backends"
    else
        log_info "Primary upstream healthy backends: ${healthy:-unknown}"
    fi

    # Failover pool should show 1 healthy (secondary only)
    healthy=$(get_metric "sentinel_upstream_healthy_backends" "upstream=\"with-failover\"")
    if [[ -n "$healthy" && "$healthy" -ge 1 ]]; then
        log_pass "Failover pool still has $healthy healthy backend(s)"
    else
        log_info "Failover pool healthy backends: ${healthy:-unknown}"
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

test_recovery_after_restart() {
    log_info "=== Test: Recovery after backend restart ==="

    # Restore the primary backend
    restore_backend "backend-primary"

    # Wait for the backend container to be healthy first
    log_info "Waiting for backend container to be healthy..."
    local container_ready=0
    for i in {1..15}; do
        local container_status
        container_status=$(docker inspect --format='{{.State.Health.Status}}' chaos-backend-primary 2>/dev/null || echo "unknown")
        if [[ "$container_status" == "healthy" ]]; then
            container_ready=1
            log_info "Backend container is healthy"
            break
        fi
        log_info "  Container status: $container_status (attempt $i/15)"
        sleep 2
    done

    if [[ $container_ready -eq 0 ]]; then
        log_warn "Backend container did not become healthy in time"
    fi

    # Wait for proxy health check to detect recovery
    # healthy-threshold is 2, interval is 5s, so need at least 10s + buffer
    log_info "Waiting for proxy health check to detect recovery..."
    sleep $((HEALTH_CHECK_INTERVAL * 3))

    # Poll until route works or timeout
    local successes=0
    local attempts=0
    local max_attempts=10
    while [[ $attempts -lt $max_attempts ]]; do
        local status
        status=$(http_status "$PRIMARY_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
            if [[ $successes -ge 3 ]]; then
                break
            fi
        fi
        ((attempts++))
        sleep 1
    done

    if [[ $successes -ge 3 ]]; then
        log_pass "Primary route recovered ($successes/$attempts success)"
    else
        log_fail "Primary route not recovered ($successes/$attempts success)"
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

test_request_retries() {
    log_info "=== Test: Request retries during failure ==="

    # Kill primary again briefly
    inject_backend_crash "backend-primary"
    sleep 2

    # Failover route has retry policy - check if retries work
    local retry_count
    retry_count=$(get_metric "sentinel_upstream_retries_total" "upstream=\"with-failover\"")
    log_info "Initial retry count: ${retry_count:-0}"

    # Make requests that would need retries
    for i in {1..10}; do
        http_status "$FAILOVER_URL" >/dev/null 2>&1 || true
    done

    # Check retry count increased
    local new_retry_count
    new_retry_count=$(get_metric "sentinel_upstream_retries_total" "upstream=\"with-failover\"")
    log_info "Final retry count: ${new_retry_count:-0}"

    if [[ -n "$new_retry_count" && "${new_retry_count:-0}" -gt "${retry_count:-0}" ]]; then
        log_pass "Request retries recorded"
    else
        log_info "Retry metrics may not have changed (or weren't needed)"
    fi

    # Restore for cleanup
    restore_backend "backend-primary"
    sleep 2
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Backend Crash Chaos Test"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests in sequence
    test_baseline
    test_primary_backend_crash
    test_failover_works
    test_health_metrics_update
    test_recovery_after_restart
    test_request_retries

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
