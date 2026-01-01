#!/usr/bin/env bash
#
# Chaos Test: Agent Crash
#
# Tests proxy behavior when the echo agent crashes.
# Validates:
#   - Fail-open routes continue to work
#   - Fail-closed routes block traffic
#   - Circuit breaker opens after threshold failures
#   - Recovery after agent restart
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

FAILOPEN_URL="${PROXY_URL}/failopen/status/200"
PROTECTED_URL="${PROXY_URL}/protected/status/200"
CIRCUIT_URL="${PROXY_URL}/circuit/status/200"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify normal operation ==="

    # Both routes should work when agent is healthy
    assert_status "$FAILOPEN_URL" "200" "Fail-open route works before chaos"
    assert_status "$PROTECTED_URL" "200" "Protected route works before chaos"
}

test_failopen_during_crash() {
    log_info "=== Test: Fail-open route during agent crash ==="

    # Kill the agent
    inject_agent_crash "echo"

    # Wait for the agent to be unavailable
    sleep 2

    # Fail-open route should still work (bypasses failed agent)
    local status
    status=$(http_status "$FAILOPEN_URL")
    if [[ "$status" == "200" ]]; then
        log_pass "Fail-open route returns 200 with agent down"
    else
        log_fail "Fail-open route returned $status, expected 200"
    fi
}

test_protected_during_crash() {
    log_info "=== Test: Protected (fail-closed) route during agent crash ==="

    # Agent should still be down from previous test
    # Protected route should block (503 or similar)
    local status
    status=$(http_status "$PROTECTED_URL")

    # Accept 502, 503, or 504 as valid "blocked" responses
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Protected route blocked with $status when agent down"
    else
        log_fail "Protected route returned $status, expected 502/503/504"
    fi
}

test_circuit_breaker_opens() {
    log_info "=== Test: Circuit breaker opens after threshold failures ==="

    # Agent should still be down
    # Make requests to trigger circuit breaker (threshold is 5)
    local failures=0
    for i in {1..7}; do
        local status
        status=$(http_status "$CIRCUIT_URL")
        if [[ "$status" != "200" ]]; then
            ((failures++))
        fi
    done

    # Check if circuit breaker opened (should see consistent failures)
    if [[ $failures -ge 5 ]]; then
        log_pass "Circuit breaker opened after $failures failures"
    else
        log_fail "Expected at least 5 failures, got $failures"
    fi

    # Check metrics for circuit breaker state
    local cb_state
    cb_state=$(get_metric "sentinel_agent_circuit_breaker_state" "agent=\"echo\"")
    if [[ -n "$cb_state" && "$cb_state" != "0" ]]; then
        log_pass "Circuit breaker metric shows non-closed state: $cb_state"
    else
        log_info "Circuit breaker metric: ${cb_state:-not found}"
    fi
}

test_recovery_after_restart() {
    log_info "=== Test: Recovery after agent restart ==="

    # Restore the agent
    restore_agent "echo"

    # Wait for agent to become healthy
    sleep 3

    # Wait for circuit breaker timeout (configured at 10s)
    log_info "Waiting for circuit breaker half-open timeout..."
    sleep 12

    # Both routes should work again
    local successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$PROTECTED_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
        sleep 0.5
    done

    if [[ $successes -ge 3 ]]; then
        log_pass "Protected route recovered after agent restart ($successes/5 success)"
    else
        log_fail "Protected route not recovered ($successes/5 success)"
    fi

    assert_status "$FAILOPEN_URL" "200" "Fail-open route works after recovery"
}

test_metrics_recorded() {
    log_info "=== Test: Verify failure metrics were recorded ==="

    # Check agent failure counter
    local failures
    failures=$(get_metric "sentinel_agent_failures_total" "agent=\"echo\"")
    if [[ -n "$failures" && "$failures" -gt 0 ]]; then
        log_pass "Agent failures recorded in metrics: $failures"
    else
        log_info "Agent failure metric: ${failures:-not found}"
    fi

    # Check agent timeout counter (may not be present if no timeouts)
    local timeouts
    timeouts=$(get_metric "sentinel_agent_timeouts_total" "agent=\"echo\"")
    log_info "Agent timeouts recorded: ${timeouts:-0}"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Agent Crash Chaos Test"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests in sequence
    test_baseline
    test_failopen_during_crash
    test_protected_during_crash
    test_circuit_breaker_opens
    test_recovery_after_restart
    test_metrics_recorded

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
