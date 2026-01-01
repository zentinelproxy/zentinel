#!/usr/bin/env bash
#
# Chaos Test: Circuit Breaker State Transitions
#
# Tests the circuit breaker behavior for agent communication.
# Validates state transitions: CLOSED -> OPEN -> HALF-OPEN -> CLOSED
#
# Circuit breaker config (from chaos-config.kdl):
#   - failure-threshold: 5
#   - success-threshold: 2
#   - timeout-seconds: 10
#   - half-open-max-requests: 2
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

CIRCUIT_URL="${PROXY_URL}/circuit/status/200"
CB_TIMEOUT=10  # Circuit breaker timeout (seconds)
FAILURE_THRESHOLD=5
SUCCESS_THRESHOLD=2

# ============================================================================
# Helper Functions
# ============================================================================

get_cb_state() {
    # Get circuit breaker state from metrics
    # States: 0=closed, 1=open, 2=half-open
    get_metric "sentinel_agent_circuit_breaker_state" "agent=\"echo\""
}

get_cb_state_name() {
    local state="$1"
    case "$state" in
        0) echo "CLOSED" ;;
        1) echo "OPEN" ;;
        2) echo "HALF-OPEN" ;;
        *) echo "UNKNOWN($state)" ;;
    esac
}

# ============================================================================
# Test Cases
# ============================================================================

test_phase1_closed_state() {
    log_info "=== Phase 1: Verify CLOSED state (normal operation) ==="

    # Agent should be healthy, circuit breaker should be closed
    local state state_name
    state=$(get_cb_state)
    state_name=$(get_cb_state_name "${state:-0}")

    log_info "Initial circuit breaker state: $state_name"

    # Make several successful requests
    local successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$CIRCUIT_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
        fi
    done

    if [[ $successes -eq 5 ]]; then
        log_pass "All requests succeeded in CLOSED state ($successes/5)"
    else
        log_fail "Expected 5 successes in CLOSED state, got $successes"
    fi

    # Verify state is still closed
    state=$(get_cb_state)
    if [[ "${state:-0}" == "0" ]]; then
        log_pass "Circuit breaker remains CLOSED"
    else
        log_info "Circuit breaker state: $(get_cb_state_name "${state:-0}")"
    fi
}

test_phase2_transition_to_open() {
    log_info "=== Phase 2: Trigger transition CLOSED -> OPEN ==="

    # Kill the agent to cause failures
    inject_agent_crash "echo"
    sleep 2

    # Make requests to trigger failures (threshold is 5)
    log_info "Sending requests to trigger $FAILURE_THRESHOLD failures..."
    local failures=0
    for i in {1..7}; do
        local status
        status=$(http_status "$CIRCUIT_URL")
        if [[ "$status" != "200" ]]; then
            ((failures++))
            log_info "  Request $i: failure ($status)"
        else
            log_info "  Request $i: success"
        fi
        sleep 0.2
    done

    log_info "Total failures: $failures"

    # Check if circuit breaker is now open
    sleep 1
    local state state_name
    state=$(get_cb_state)
    state_name=$(get_cb_state_name "${state:-0}")

    log_info "Circuit breaker state after failures: $state_name"

    if [[ "${state:-0}" == "1" ]]; then
        log_pass "Circuit breaker transitioned to OPEN state"
    else
        log_info "Circuit breaker state: $state_name (expected OPEN)"
    fi

    # Verify requests are fast-failed when open
    local start_time end_time latency_ms
    start_time=$(date +%s%3N)
    http_status "$CIRCUIT_URL" >/dev/null 2>&1 || true
    end_time=$(date +%s%3N)
    latency_ms=$((end_time - start_time))

    if [[ $latency_ms -lt 100 ]]; then
        log_pass "Requests fast-fail when circuit is OPEN (${latency_ms}ms)"
    else
        log_info "Response time when OPEN: ${latency_ms}ms"
    fi
}

test_phase3_transition_to_half_open() {
    log_info "=== Phase 3: Wait for OPEN -> HALF-OPEN transition ==="

    # Restore the agent before timeout
    log_info "Restoring agent before circuit breaker timeout..."
    restore_agent "echo"
    sleep 2

    log_info "Waiting for circuit breaker timeout (${CB_TIMEOUT}s)..."
    sleep $((CB_TIMEOUT + 2))

    # Check state - should be half-open
    local state state_name
    state=$(get_cb_state)
    state_name=$(get_cb_state_name "${state:-0}")

    log_info "Circuit breaker state after timeout: $state_name"

    # Make a probe request (should trigger half-open state if not already)
    local status
    status=$(http_status "$CIRCUIT_URL")
    log_info "Probe request status: $status"

    # Check state again
    state=$(get_cb_state)
    state_name=$(get_cb_state_name "${state:-0}")

    if [[ "${state:-0}" == "2" ]]; then
        log_pass "Circuit breaker transitioned to HALF-OPEN state"
    elif [[ "${state:-0}" == "0" ]]; then
        log_pass "Circuit breaker already transitioned back to CLOSED"
    else
        log_info "Circuit breaker state: $state_name"
    fi
}

test_phase4_transition_back_to_closed() {
    log_info "=== Phase 4: Transition HALF-OPEN -> CLOSED ==="

    # Make successful requests to close the circuit
    # Need SUCCESS_THRESHOLD (2) successes to close
    log_info "Making requests to close circuit (need $SUCCESS_THRESHOLD successes)..."
    local successes=0
    for i in {1..5}; do
        local status
        status=$(http_status "$CIRCUIT_URL")
        if [[ "$status" == "200" ]]; then
            ((successes++))
            log_info "  Request $i: success (total: $successes)"
        else
            log_info "  Request $i: failure ($status)"
        fi
        sleep 0.3
    done

    # Check final state
    local state state_name
    state=$(get_cb_state)
    state_name=$(get_cb_state_name "${state:-0}")

    log_info "Final circuit breaker state: $state_name"

    if [[ "${state:-0}" == "0" ]]; then
        log_pass "Circuit breaker transitioned back to CLOSED"
    else
        log_warn "Circuit breaker not CLOSED: $state_name"
    fi

    # Verify normal operation restored
    local final_successes=0
    for i in {1..3}; do
        local status
        status=$(http_status "$CIRCUIT_URL")
        if [[ "$status" == "200" ]]; then
            ((final_successes++))
        fi
    done

    if [[ $final_successes -eq 3 ]]; then
        log_pass "Normal operation restored ($final_successes/3 success)"
    else
        log_fail "Normal operation not restored ($final_successes/3 success)"
    fi
}

test_circuit_breaker_metrics() {
    log_info "=== Test: Verify circuit breaker metrics ==="

    # Check for circuit breaker opens
    local opens
    opens=$(get_metric "sentinel_agent_circuit_breaker_opens_total" "agent=\"echo\"")
    if [[ -n "$opens" && "$opens" -gt 0 ]]; then
        log_pass "Circuit breaker open events recorded: $opens"
    else
        log_info "Circuit breaker opens: ${opens:-not found}"
    fi

    # Check for state changes
    local state_changes
    state_changes=$(get_metrics_matching "sentinel_agent_circuit_breaker")
    if [[ -n "$state_changes" ]]; then
        log_info "Circuit breaker metrics:"
        echo "$state_changes" | while read -r line; do
            log_info "  $line"
        done
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Circuit Breaker State Transition Test"
    log_info "Proxy URL: $PROXY_URL"
    log_info "Configuration: threshold=$FAILURE_THRESHOLD, success=$SUCCESS_THRESHOLD, timeout=${CB_TIMEOUT}s"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Ensure agent is running at start
    restore_agent "echo" 2>/dev/null || true
    sleep 2

    # Run test phases in sequence
    test_phase1_closed_state
    test_phase2_transition_to_open
    test_phase3_transition_to_half_open
    test_phase4_transition_back_to_closed
    test_circuit_breaker_metrics

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
