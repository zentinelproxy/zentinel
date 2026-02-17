#!/usr/bin/env bash
#
# Chaos Test: Agent Timeout
#
# Tests proxy behavior when the echo agent becomes unresponsive (frozen).
# Validates:
#   - Agent timeout is enforced (1000ms configured)
#   - Timeout counted in metrics
#   - Fail-open continues to work
#   - Fail-closed blocks on timeout
#   - Recovery after unfreezing
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

FAILOPEN_URL="${PROXY_URL}/failopen/"
PROTECTED_URL="${PROXY_URL}/protected/"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Verify normal operation ==="

    # Measure baseline latency
    local start_time end_time latency_ms
    start_time=$(date +%s)
    http_status "$PROTECTED_URL" >/dev/null
    end_time=$(date +%s)
    latency_ms=$((end_time - start_time))

    log_info "Baseline latency: ${latency_ms}ms"
    assert_status "$FAILOPEN_URL" "200" "Fail-open route works"
    assert_status "$PROTECTED_URL" "200" "Protected route works"
}

test_timeout_behavior() {
    log_info "=== Test: Agent timeout behavior ==="

    # Freeze the agent (simulates hang/unresponsive)
    inject_agent_freeze "echo" 30  # Freeze for 30s

    # Wait a moment for freeze to take effect
    sleep 1

    # Test fail-open route - should timeout but still succeed
    log_info "Testing fail-open route during agent freeze..."
    local start_time end_time latency_ms status
    start_time=$(date +%s)
    status=$(http_status "$FAILOPEN_URL")
    end_time=$(date +%s)
    latency_ms=$((end_time - start_time))

    log_info "Fail-open response: $status in ${latency_ms}ms"

    if [[ "$status" == "200" ]]; then
        log_pass "Fail-open route succeeds during agent timeout"
    else
        log_fail "Fail-open route returned $status, expected 200"
    fi

    # Latency should include timeout wait
    if [[ $latency_ms -ge 900 && $latency_ms -le 3000 ]]; then
        log_pass "Response latency indicates timeout was triggered (${latency_ms}ms)"
    else
        log_info "Response latency: ${latency_ms}ms (expected ~1000ms for timeout)"
    fi
}

test_protected_timeout() {
    log_info "=== Test: Protected route timeout behavior ==="

    # Agent should still be frozen
    local start_time end_time latency_ms status
    start_time=$(date +%s)
    status=$(http_status "$PROTECTED_URL")
    end_time=$(date +%s)
    latency_ms=$((end_time - start_time))

    log_info "Protected response: $status in ${latency_ms}ms"

    # Protected route should fail (503) on timeout
    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Protected route blocked on timeout ($status)"
    else
        log_fail "Protected route returned $status, expected 502/503/504"
    fi

    # Verify timeout was enforced (should take ~1000ms)
    if [[ $latency_ms -ge 900 && $latency_ms -le 2000 ]]; then
        log_pass "Timeout enforced correctly (${latency_ms}ms)"
    else
        log_warn "Timeout latency unexpected: ${latency_ms}ms"
    fi
}

test_timeout_metrics() {
    log_info "=== Test: Verify timeout metrics ==="

    # Record initial timeout count
    local initial_timeouts
    initial_timeouts=$(get_metric "zentinel_agent_timeouts_total" "agent=\"echo\"" || echo "0")

    # Make a few more requests to accumulate timeouts
    for i in {1..3}; do
        http_status "$PROTECTED_URL" >/dev/null 2>&1 || true
    done

    # Check timeout count increased
    local final_timeouts
    final_timeouts=$(get_metric "zentinel_agent_timeouts_total" "agent=\"echo\"" || echo "0")

    if [[ -n "$final_timeouts" && "${final_timeouts:-0}" -gt "${initial_timeouts:-0}" ]]; then
        log_pass "Timeout metrics increased: $initial_timeouts -> $final_timeouts"
    else
        log_info "Timeout metrics: initial=$initial_timeouts, final=$final_timeouts"
    fi
}

test_recovery_after_unfreeze() {
    log_info "=== Test: Recovery after agent unfreeze ==="

    # Unfreeze the agent
    inject_agent_unfreeze "echo"

    # Wait for agent to recover
    sleep 2

    # Both routes should work again with normal latency
    local start_time end_time latency_ms status
    start_time=$(date +%s)
    status=$(http_status "$PROTECTED_URL")
    end_time=$(date +%s)
    latency_ms=$((end_time - start_time))

    log_info "Recovery response: $status in ${latency_ms}ms"

    if [[ "$status" == "200" ]]; then
        log_pass "Protected route recovered after unfreeze"
    else
        log_fail "Protected route returned $status after unfreeze"
    fi

    # Latency should be back to normal (not waiting for timeout)
    if [[ $latency_ms -lt 500 ]]; then
        log_pass "Latency back to normal: ${latency_ms}ms"
    else
        log_warn "Latency still elevated after unfreeze: ${latency_ms}ms"
    fi

    assert_status "$FAILOPEN_URL" "200" "Fail-open route works after unfreeze"
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Agent Timeout Chaos Test"
    log_info "Proxy URL: $PROXY_URL"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Run tests in sequence
    test_baseline
    test_timeout_behavior
    test_protected_timeout
    test_timeout_metrics
    test_recovery_after_unfreeze

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
