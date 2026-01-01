#!/usr/bin/env bash
#
# Chaos Test: Fail-Closed Mode Validation
#
# Tests that routes configured with failure-mode "closed" block
# traffic when the agent fails.
#
# Fail-closed is appropriate for:
#   - Security-critical agents (WAF, authentication)
#   - Authorization/access control
#   - Any processing where bypassing is a security risk
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

PROTECTED_URL="${PROXY_URL}/protected/status/200"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Protected route with healthy agent ==="

    # With healthy agent, requests should succeed
    assert_status "$PROTECTED_URL" "200" "Protected route works with healthy agent"

    # Multiple requests should all succeed
    local successes
    successes=$(count_successes "$PROTECTED_URL" 10)
    assert_eq "$successes" "10" "All 10 requests succeed with healthy agent"
}

test_failclosed_agent_crash() {
    log_info "=== Test: Fail-closed behavior during agent crash ==="

    # Kill the agent
    inject_agent_crash "echo"
    sleep 2

    # Requests should be BLOCKED (fail-closed)
    local status
    status=$(http_status "$PROTECTED_URL")

    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Fail-closed route blocks with agent crashed ($status)"
    else
        log_fail "Fail-closed route returned $status, expected 502/503/504"
    fi

    # Confirm consistent blocking behavior
    local blocks=0
    for i in {1..10}; do
        status=$(http_status "$PROTECTED_URL")
        if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
            ((blocks++))
        fi
    done

    if [[ $blocks -ge 8 ]]; then
        log_pass "Fail-closed consistently blocks traffic ($blocks/10 blocked)"
    else
        log_fail "Fail-closed not blocking consistently ($blocks/10 blocked)"
    fi
}

test_failclosed_agent_timeout() {
    log_info "=== Test: Fail-closed behavior during agent timeout ==="

    # Restore then freeze the agent
    restore_agent "echo" 2>/dev/null || true
    sleep 1
    inject_agent_freeze "echo" 30

    # Wait for freeze to take effect
    sleep 2

    # Measure latency - should timeout then block
    local start_time end_time latency_ms status
    start_time=$(date +%s%3N)
    status=$(http_status "$PROTECTED_URL")
    end_time=$(date +%s%3N)
    latency_ms=$((end_time - start_time))

    log_info "Response: $status in ${latency_ms}ms"

    if [[ "$status" == "502" || "$status" == "503" || "$status" == "504" ]]; then
        log_pass "Fail-closed route blocks during agent timeout ($status)"
    else
        log_fail "Fail-closed route returned $status, expected 502/503/504"
    fi

    # Verify timeout is enforced (should be ~1000ms)
    if [[ $latency_ms -ge 800 && $latency_ms -le 3000 ]]; then
        log_pass "Agent timeout enforced (${latency_ms}ms)"
    else
        log_info "Response latency: ${latency_ms}ms"
    fi

    # Cleanup: unfreeze
    inject_agent_unfreeze "echo"
}

test_failclosed_no_bypass() {
    log_info "=== Test: No traffic bypasses fail-closed route ==="

    # Ensure agent is down
    inject_agent_crash "echo"
    sleep 1

    # Send many requests - none should succeed
    local successes=0
    local total=50
    for i in $(seq 1 $total); do
        local status
        status=$(http_status "$PROTECTED_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
            log_warn "Request $i unexpectedly succeeded!"
        fi
    done

    if [[ $successes -eq 0 ]]; then
        log_pass "Zero requests bypassed fail-closed protection (0/$total)"
    else
        log_fail "Some requests bypassed protection ($successes/$total succeeded)"
    fi
}

test_failclosed_recovery() {
    log_info "=== Test: Fail-closed route after agent recovery ==="

    # Restore the agent
    restore_agent "echo"

    # Wait for circuit breaker recovery (if tripped)
    sleep 12  # CB timeout is 10s

    # Route should work again
    local successes=0
    for i in {1..10}; do
        local status
        status=$(http_status "$PROTECTED_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
        sleep 0.3
    done

    if [[ $successes -ge 7 ]]; then
        log_pass "Protected route recovered after agent restart ($successes/10)"
    else
        log_fail "Protected route not recovered ($successes/10 success)"
    fi
}

test_failclosed_error_responses() {
    log_info "=== Test: Error response codes for fail-closed ==="

    # Kill agent and check error codes
    inject_agent_crash "echo"
    sleep 1

    # Count different error codes
    local count_502=0 count_503=0 count_504=0 count_other=0

    for i in {1..20}; do
        local status
        status=$(http_status "$PROTECTED_URL")
        case "$status" in
            502) ((count_502++)) ;;
            503) ((count_503++)) ;;
            504) ((count_504++)) ;;
            *) ((count_other++)) ;;
        esac
    done

    log_info "Error code distribution:"
    log_info "  502 Bad Gateway: $count_502"
    log_info "  503 Service Unavailable: $count_503"
    log_info "  504 Gateway Timeout: $count_504"
    log_info "  Other: $count_other"

    if [[ $count_other -eq 0 ]]; then
        log_pass "All responses are appropriate 5xx error codes"
    else
        log_warn "Some unexpected response codes: $count_other"
    fi

    # Restore for cleanup
    restore_agent "echo"
}

test_failclosed_metrics() {
    log_info "=== Test: Fail-closed events recorded in metrics ==="

    # Check for blocked requests metric
    local blocked
    blocked=$(get_metric "sentinel_agent_blocks_total" "agent=\"echo\",mode=\"closed\"")

    if [[ -n "$blocked" && "$blocked" -gt 0 ]]; then
        log_pass "Fail-closed blocks recorded: $blocked"
    else
        log_info "Fail-closed block metric: ${blocked:-not found}"
    fi

    # Check agent failure events
    local failures
    failures=$(get_metric "sentinel_agent_failures_total" "agent=\"echo\"")

    if [[ -n "$failures" && "$failures" -gt 0 ]]; then
        log_pass "Agent failures recorded: $failures"
    else
        log_info "Agent failure metric: ${failures:-not found}"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Fail-Closed Mode Validation Test"
    log_info "Proxy URL: $PROXY_URL"
    log_info ""
    log_info "Fail-closed mode blocks requests when the agent fails."
    log_info "This is critical for security-sensitive processing."

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Ensure agent is healthy at start
    restore_agent "echo" 2>/dev/null || true
    sleep 2

    # Run tests
    test_baseline
    test_failclosed_agent_crash
    test_failclosed_agent_timeout
    test_failclosed_no_bypass
    test_failclosed_recovery
    test_failclosed_error_responses
    test_failclosed_metrics

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
