#!/usr/bin/env bash
#
# Chaos Test: Fail-Open Mode Validation
#
# Tests that routes configured with failure-mode "open" continue to
# allow traffic when the agent fails.
#
# Fail-open is appropriate for:
#   - Non-critical enhancement agents (logging, metrics enrichment)
#   - Rate limiting (prefer availability over enforcement)
#   - Optional processing that shouldn't block requests
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

FAILOPEN_URL="${PROXY_URL}/failopen/"

# ============================================================================
# Test Cases
# ============================================================================

test_baseline() {
    log_info "=== Baseline: Fail-open route with healthy agent ==="

    # With healthy agent, requests should succeed
    assert_status "$FAILOPEN_URL" "200" "Fail-open route works with healthy agent"

    # Multiple requests should all succeed
    local successes
    successes=$(count_successes "$FAILOPEN_URL" 10)
    assert_eq "$successes" "10" "All 10 requests succeed with healthy agent"
}

test_failopen_agent_crash() {
    log_info "=== Test: Fail-open behavior during agent crash ==="

    # Kill the agent
    inject_agent_crash "echo"
    sleep 2

    # Requests should STILL succeed (fail-open bypasses agent)
    local status
    status=$(http_status "$FAILOPEN_URL")

    if [[ "$status" == "200" ]]; then
        log_pass "Fail-open route succeeds with agent crashed"
    else
        log_fail "Fail-open route returned $status, expected 200"
    fi

    # Run multiple requests to confirm consistent behavior
    local successes
    successes=$(count_successes "$FAILOPEN_URL" 10)

    if [[ $successes -ge 8 ]]; then
        log_pass "Fail-open maintains availability ($successes/10 success)"
    else
        log_fail "Fail-open not working correctly ($successes/10 success)"
    fi
}

test_failopen_agent_timeout() {
    log_info "=== Test: Fail-open behavior during agent timeout ==="

    # First restore then freeze the agent
    restore_agent "echo" 2>/dev/null || true
    sleep 1
    inject_agent_freeze "echo" 30

    # Wait for freeze to take effect
    sleep 2

    # Measure latency - should be around agent timeout (1000ms) then bypass
    local start_time end_time latency_ms status
    # Use seconds for portability (macOS doesn't support %3N)
    start_time=$(date +%s)
    status=$(http_status "$FAILOPEN_URL")
    end_time=$(date +%s)
    latency_ms=$(( (end_time - start_time) * 1000 ))

    log_info "Response: $status in ${latency_ms}ms"

    if [[ "$status" == "200" ]]; then
        log_pass "Fail-open route succeeds during agent timeout"
    else
        log_fail "Fail-open route returned $status, expected 200"
    fi

    # Cleanup: unfreeze
    inject_agent_unfreeze "echo"
}

test_failopen_throughput() {
    log_info "=== Test: Throughput maintained in fail-open mode ==="

    # Ensure agent is down
    inject_agent_crash "echo"
    sleep 1

    # Measure throughput
    local start_time end_time elapsed rps
    start_time=$(date +%s)

    local successes=0
    local total=100
    for i in $(seq 1 $total); do
        local status
        status=$(http_status "$FAILOPEN_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
    done

    end_time=$(date +%s)
    elapsed=$((end_time - start_time))
    if [[ $elapsed -eq 0 ]]; then
        elapsed=1
    fi
    rps=$((successes / elapsed))

    log_info "Throughput: $successes requests in ${elapsed}s (~${rps} RPS)"

    if [[ $successes -ge 90 ]]; then
        log_pass "High availability maintained ($successes/$total success)"
    else
        log_fail "Availability degraded ($successes/$total success)"
    fi
}

test_failopen_recovery() {
    log_info "=== Test: Fail-open route after agent recovery ==="

    # Restore the agent
    restore_agent "echo"
    sleep 3

    # Route should continue working (was already working, just with agent again)
    local successes
    successes=$(count_successes "$FAILOPEN_URL" 10)

    if [[ $successes -eq 10 ]]; then
        log_pass "Fail-open route continues working after recovery ($successes/10)"
    else
        log_fail "Some requests failed after recovery ($successes/10)"
    fi
}

test_failopen_metrics() {
    log_info "=== Test: Fail-open events recorded in metrics ==="

    # Check for fail-open bypass events
    local bypasses
    bypasses=$(get_metric "sentinel_agent_bypasses_total" "agent=\"echo\",mode=\"open\"")

    if [[ -n "$bypasses" && "$bypasses" -gt 0 ]]; then
        log_pass "Fail-open bypasses recorded: $bypasses"
    else
        log_info "Fail-open bypass metric: ${bypasses:-not found}"
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
    log_info "Starting Fail-Open Mode Validation Test"
    log_info "Proxy URL: $PROXY_URL"
    log_info ""
    log_info "Fail-open mode allows requests to proceed even when the agent fails."
    log_info "This is appropriate for non-critical processing that shouldn't block traffic."

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Ensure agent is ready - may need time after proxy restart
    restore_agent "echo" 2>/dev/null || true
    sleep 2

    # Run tests
    test_baseline
    test_failopen_agent_crash
    test_failopen_agent_timeout
    test_failopen_throughput
    test_failopen_recovery
    test_failopen_metrics

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
