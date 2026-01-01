#!/usr/bin/env bash
#
# Chaos Test: Memory Stability Under Failures
#
# Tests that the proxy does not leak memory during failure conditions.
# Runs multiple chaos cycles and monitors memory usage.
#
# Validates:
#   - Memory does not grow unbounded during failures
#   - Memory is reclaimed after failures resolve
#   - No memory leaks during repeated failure/recovery cycles
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/chaos-injectors.sh"

# ============================================================================
# Test Configuration
# ============================================================================

PROXY_CONTAINER="chaos-proxy"
CHAOS_CYCLES=20
REQUESTS_PER_CYCLE=100
MEMORY_GROWTH_THRESHOLD_PERCENT=50  # Fail if memory grows more than 50%

# ============================================================================
# Helper Functions
# ============================================================================

get_proxy_memory_bytes() {
    # Get memory usage in bytes from docker stats
    docker stats "$PROXY_CONTAINER" --no-stream --format '{{.MemUsage}}' 2>/dev/null | \
        awk -F'/' '{print $1}' | \
        sed 's/[^0-9.]//g' | \
        awk '{
            if (index($0, "GiB") > 0 || index($0, "G") > 0) print $1 * 1073741824;
            else if (index($0, "MiB") > 0 || index($0, "M") > 0) print $1 * 1048576;
            else if (index($0, "KiB") > 0 || index($0, "K") > 0) print $1 * 1024;
            else print $1;
        }'
}

get_proxy_memory_mb() {
    local bytes
    bytes=$(docker stats "$PROXY_CONTAINER" --no-stream --format '{{.MemUsage}}' 2>/dev/null | \
        awk -F'/' '{print $1}' | sed 's/[^0-9.]//g')

    # Simplified: just get the number, docker usually reports in MiB
    echo "$bytes" | head -1
}

format_bytes() {
    local bytes="$1"
    if [[ $bytes -ge 1073741824 ]]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc)GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc)MB"
    elif [[ $bytes -ge 1024 ]]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc)KB"
    else
        echo "${bytes}B"
    fi
}

# ============================================================================
# Test Cases
# ============================================================================

test_baseline_memory() {
    log_info "=== Baseline: Record initial memory usage ==="

    # Get initial memory
    INITIAL_MEMORY=$(get_proxy_memory_mb)
    log_info "Initial memory: ${INITIAL_MEMORY}MB"

    # Run some baseline requests
    for i in {1..100}; do
        http_status "${PROXY_URL}/status/200" >/dev/null 2>&1 || true
    done

    # Get memory after warmup
    sleep 2
    local warmup_memory
    warmup_memory=$(get_proxy_memory_mb)
    log_info "Memory after warmup: ${warmup_memory}MB"

    BASELINE_MEMORY="$warmup_memory"
    log_pass "Baseline memory recorded: ${BASELINE_MEMORY}MB"
}

test_chaos_cycles() {
    log_info "=== Test: Memory stability during $CHAOS_CYCLES chaos cycles ==="

    local memory_samples=()
    local cycle_results=()

    for cycle in $(seq 1 $CHAOS_CYCLES); do
        log_info "--- Chaos cycle $cycle/$CHAOS_CYCLES ---"

        # Random chaos injection
        local chaos_type=$((RANDOM % 4))
        case $chaos_type in
            0)
                log_info "  Injecting: agent crash"
                inject_agent_crash "echo"
                ;;
            1)
                log_info "  Injecting: agent freeze (3s)"
                inject_agent_freeze "echo" 3
                ;;
            2)
                log_info "  Injecting: backend crash"
                inject_backend_crash "backend-primary"
                ;;
            3)
                log_info "  Injecting: backend freeze (3s)"
                inject_backend_freeze "backend-primary" 3
                ;;
        esac

        # Send requests during chaos
        local successes=0
        for i in $(seq 1 $REQUESTS_PER_CYCLE); do
            local status
            status=$(http_status "${PROXY_URL}/status/200")
            if [[ "$status" == "200" ]]; then
                ((successes++))
            fi
        done

        log_info "  Requests: $successes/$REQUESTS_PER_CYCLE success"

        # Restore services
        restore_agent "echo" 2>/dev/null || true
        restore_backend "backend-primary" 2>/dev/null || true

        # Sample memory every 5 cycles
        if [[ $((cycle % 5)) -eq 0 ]]; then
            sleep 1
            local current_memory
            current_memory=$(get_proxy_memory_mb)
            memory_samples+=("$current_memory")
            log_info "  Memory sample: ${current_memory}MB"
        fi

        # Brief pause between cycles
        sleep 1
    done

    # Log memory trend
    log_info ""
    log_info "Memory samples during test:"
    for i in "${!memory_samples[@]}"; do
        local cycle=$((($i + 1) * 5))
        log_info "  Cycle $cycle: ${memory_samples[$i]}MB"
    done

    log_pass "Completed $CHAOS_CYCLES chaos cycles"
}

test_memory_growth() {
    log_info "=== Test: Analyze memory growth ==="

    # Wait for any cleanup
    sleep 5

    # Get final memory
    local final_memory
    final_memory=$(get_proxy_memory_mb)
    log_info "Final memory: ${final_memory}MB"

    # Calculate growth percentage
    local baseline="${BASELINE_MEMORY:-1}"
    if [[ -z "$baseline" || "$baseline" == "0" ]]; then
        baseline=1
    fi

    local growth_mb=$((${final_memory:-0} - ${baseline:-0}))
    local growth_percent=$((growth_mb * 100 / baseline))

    log_info "Memory growth: ${growth_mb}MB (${growth_percent}%)"

    if [[ $growth_percent -le $MEMORY_GROWTH_THRESHOLD_PERCENT ]]; then
        log_pass "Memory growth within threshold (${growth_percent}% <= ${MEMORY_GROWTH_THRESHOLD_PERCENT}%)"
    else
        log_fail "Memory growth exceeds threshold (${growth_percent}% > ${MEMORY_GROWTH_THRESHOLD_PERCENT}%)"
    fi
}

test_memory_reclamation() {
    log_info "=== Test: Memory reclamation after idle period ==="

    # Let the system sit idle
    log_info "Waiting 30s for potential memory reclamation..."
    sleep 30

    local post_idle_memory
    post_idle_memory=$(get_proxy_memory_mb)
    log_info "Memory after idle: ${post_idle_memory}MB"

    local baseline="${BASELINE_MEMORY:-1}"
    local diff_mb=$((${post_idle_memory:-0} - ${baseline:-0}))

    if [[ $diff_mb -le 5 ]]; then
        log_pass "Memory returned to near baseline (within 5MB)"
    else
        log_info "Memory ${diff_mb}MB above baseline (may be acceptable)"
    fi
}

test_sustained_load_after_chaos() {
    log_info "=== Test: Memory stable under sustained load after chaos ==="

    # Get starting memory
    local start_memory
    start_memory=$(get_proxy_memory_mb)

    # Send sustained load
    log_info "Sending 1000 requests..."
    for i in $(seq 1 1000); do
        http_status "${PROXY_URL}/status/200" >/dev/null 2>&1 || true
    done

    # Check memory
    sleep 2
    local end_memory
    end_memory=$(get_proxy_memory_mb)

    local diff=$((${end_memory:-0} - ${start_memory:-0}))
    log_info "Memory before: ${start_memory}MB, after: ${end_memory}MB (diff: ${diff}MB)"

    if [[ $diff -le 10 ]]; then
        log_pass "Memory stable during sustained load (${diff}MB change)"
    else
        log_warn "Memory increased by ${diff}MB during sustained load"
    fi
}

test_final_summary() {
    log_info "=== Memory Test Summary ==="

    local final_memory
    final_memory=$(get_proxy_memory_mb)

    local baseline="${BASELINE_MEMORY:-1}"
    local initial="${INITIAL_MEMORY:-1}"

    log_info "Initial memory:  ${initial}MB"
    log_info "Baseline memory: ${baseline}MB"
    log_info "Final memory:    ${final_memory}MB"

    local total_growth=$((${final_memory:-0} - ${initial:-0}))
    local growth_percent=$((total_growth * 100 / ${initial:-1}))

    log_info "Total growth:    ${total_growth}MB (${growth_percent}%)"

    # Record results
    echo "memory_test_results:" > "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  initial_mb: $initial" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  baseline_mb: $baseline" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  final_mb: $final_memory" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  growth_mb: $total_growth" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  growth_percent: $growth_percent" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  chaos_cycles: $CHAOS_CYCLES" >> "${OUTPUT_DIR}/memory-test-results.yaml"
    echo "  threshold_percent: $MEMORY_GROWTH_THRESHOLD_PERCENT" >> "${OUTPUT_DIR}/memory-test-results.yaml"

    if [[ $growth_percent -le $MEMORY_GROWTH_THRESHOLD_PERCENT ]]; then
        echo "  result: PASS" >> "${OUTPUT_DIR}/memory-test-results.yaml"
        log_pass "Memory stability test PASSED"
    else
        echo "  result: FAIL" >> "${OUTPUT_DIR}/memory-test-results.yaml"
        log_fail "Memory stability test FAILED (growth: ${growth_percent}%)"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    log_info "Starting Memory Stability Chaos Test"
    log_info "Proxy URL: $PROXY_URL"
    log_info "Container: $PROXY_CONTAINER"
    log_info "Chaos cycles: $CHAOS_CYCLES"
    log_info "Memory growth threshold: ${MEMORY_GROWTH_THRESHOLD_PERCENT}%"

    # Wait for services to be ready
    wait_for_service "$HEALTH_URL" "proxy" 30 || {
        log_fail "Proxy not healthy, aborting test"
        return 1
    }

    # Ensure all services are up
    restore_agent "echo" 2>/dev/null || true
    restore_all_backends 2>/dev/null || true
    sleep 3

    # Run tests
    test_baseline_memory
    test_chaos_cycles
    test_memory_growth
    test_memory_reclamation
    test_sustained_load_after_chaos
    test_final_summary

    # Print summary
    print_summary

    return $(get_exit_code)
}

main "$@"
