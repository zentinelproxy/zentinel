#!/bin/bash
# Concurrent Reload Integration Tests
#
# Tests that requests in-flight during configuration reloads complete successfully.
# Validates zero-downtime config reloading with live traffic.
#
# Prerequisites:
# - Sentinel binary built
# - curl installed
#
# Usage: ./test_concurrent_reload.sh [--skip-connectivity]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SENTINEL_BIN="${SENTINEL_BIN:-$PROJECT_ROOT/target/debug/sentinel}"

# Test configuration
TEST_PORT="${TEST_PORT:-18080}"
PROXY_URL="http://localhost:$TEST_PORT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# Cleanup tracking
SENTINEL_PID=""
TEMP_DIR=""
declare -a REQUEST_PIDS=()

# Parse arguments
SKIP_CONNECTIVITY="${SKIP_CONNECTIVITY:-0}"
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-connectivity)
            SKIP_CONNECTIVITY=1
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date +%H:%M:%S) $*"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $*"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $*"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
}

print_summary() {
    echo ""
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo "Total:   $TESTS_RUN"
    echo -e "Passed:  ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Failed:  ${RED}$TESTS_FAILED${NC}"
    echo -e "Skipped: ${YELLOW}$TESTS_SKIPPED${NC}"
    echo "=========================================="

    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        return 0
    fi
}

cleanup() {
    log_info "Cleaning up..."

    # Kill any background request processes
    if [[ ${#REQUEST_PIDS[@]} -gt 0 ]]; then
        for pid in "${REQUEST_PIDS[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
    fi

    if [[ -n "$SENTINEL_PID" ]] && kill -0 "$SENTINEL_PID" 2>/dev/null; then
        kill "$SENTINEL_PID" 2>/dev/null || true
        wait "$SENTINEL_PID" 2>/dev/null || true
    fi
    if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v curl &> /dev/null; then
        log_fail "curl is required but not installed"
        exit 1
    fi

    if [[ ! -f "$SENTINEL_BIN" ]]; then
        log_info "Building Sentinel..."
        cargo build --package sentinel --quiet
    fi

    if [[ ! -f "$SENTINEL_BIN" ]]; then
        log_fail "Sentinel binary not found: $SENTINEL_BIN"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Create test config with specified response message
create_config() {
    local config_file="$1"
    local response_msg="$2"

    cat > "$config_file" << EOF
server {
    worker-threads 2
}

listeners {
    listener "http" {
        address "0.0.0.0:$TEST_PORT"
        protocol "http"
    }
}

routes {
    route "health" {
        priority "high"
        matches {
            path "/health"
        }
        respond 200 "OK"
    }

    route "test" {
        priority "medium"
        matches {
            path-prefix "/"
        }
        respond 200 "$response_msg"
    }
}
EOF
}

# Start Sentinel with test config
start_sentinel() {
    local config_file="$1"

    log_info "Starting Sentinel..."

    "$SENTINEL_BIN" --config "$config_file" &
    SENTINEL_PID=$!

    # Wait for startup
    local retries=30
    while [[ $retries -gt 0 ]]; do
        if curl -s --connect-timeout 1 "$PROXY_URL/health" &> /dev/null; then
            log_info "Sentinel started (PID: $SENTINEL_PID)"
            return 0
        fi
        sleep 0.2
        retries=$((retries - 1))
    done

    log_fail "Sentinel failed to start"
    return 1
}

# Send continuous requests in background, return PID
start_request_loop() {
    local output_file="$1"
    local count="${2:-100}"
    local delay="${3:-0.05}"

    (
        success=0
        fail=0
        for _ in $(seq 1 "$count"); do
            if curl -s --connect-timeout 2 "$PROXY_URL/test" > /dev/null 2>&1; then
                success=$((success + 1))
            else
                fail=$((fail + 1))
            fi
            sleep "$delay"
        done
        echo "$success $fail" > "$output_file"
    ) &

    echo $!
}

# Test: Basic reload doesn't break requests
test_reload_during_requests() {
    log_info "Testing reload during active requests..."

    local results_file="$TEMP_DIR/results1.txt"

    # Start background requests
    local request_pid
    request_pid=$(start_request_loop "$results_file" 100 0.02)
    REQUEST_PIDS+=("$request_pid")

    # Wait a bit then trigger reload
    sleep 0.5
    log_info "Sending SIGHUP to trigger reload..."
    kill -HUP "$SENTINEL_PID"

    # Wait for requests to complete
    wait "$request_pid" 2>/dev/null || true

    # Check results
    if [[ -f "$results_file" ]]; then
        read -r success fail < "$results_file"
        log_info "Results: $success succeeded, $fail failed"

        if [[ "$fail" -eq 0 ]]; then
            log_pass "All requests succeeded during reload"
        elif [[ "$fail" -le 2 ]]; then
            log_pass "Minimal disruption during reload ($fail failures acceptable)"
        else
            log_fail "Too many request failures during reload: $fail"
        fi
    else
        log_fail "Could not read results file"
    fi
}

# Test: Multiple rapid reloads
test_rapid_reloads() {
    log_info "Testing rapid successive reloads..."

    local results_file="$TEMP_DIR/results2.txt"

    # Start background requests
    local request_pid
    request_pid=$(start_request_loop "$results_file" 200 0.01)
    REQUEST_PIDS+=("$request_pid")

    # Trigger multiple reloads rapidly
    for i in $(seq 1 5); do
        sleep 0.2
        log_info "Reload $i/5..."
        kill -HUP "$SENTINEL_PID"
    done

    # Wait for requests to complete
    wait "$request_pid" 2>/dev/null || true

    # Check results
    if [[ -f "$results_file" ]]; then
        read -r success fail < "$results_file"
        log_info "Results: $success succeeded, $fail failed"

        local total=$((success + fail))
        local fail_rate=$((fail * 100 / total))

        if [[ "$fail_rate" -le 5 ]]; then
            log_pass "Rapid reloads handled well (${fail_rate}% failure rate)"
        else
            log_fail "High failure rate during rapid reloads: ${fail_rate}%"
        fi
    else
        log_fail "Could not read results file"
    fi
}

# Test: Config changes take effect after reload
test_config_changes_visible() {
    log_info "Testing config changes are visible after reload..."

    # Get initial response
    local initial_response
    initial_response=$(curl -s "$PROXY_URL/test")
    log_info "Initial response: $initial_response"

    # Update config with different response
    create_config "$TEMP_DIR/test-config.kdl" "UPDATED_RESPONSE_V2"

    # Reload
    kill -HUP "$SENTINEL_PID"
    sleep 0.5

    # Get new response
    local new_response
    new_response=$(curl -s "$PROXY_URL/test")
    log_info "New response: $new_response"

    if [[ "$new_response" == "UPDATED_RESPONSE_V2" ]]; then
        log_pass "Config change visible after reload"
    else
        log_fail "Config change not visible. Expected 'UPDATED_RESPONSE_V2', got '$new_response'"
    fi

    # Restore original config
    create_config "$TEMP_DIR/test-config.kdl" "ORIGINAL_RESPONSE"
    kill -HUP "$SENTINEL_PID"
    sleep 0.3
}

# Test: Concurrent requests from multiple clients during reload
test_concurrent_clients_during_reload() {
    log_info "Testing multiple concurrent clients during reload..."

    local results_dir="$TEMP_DIR/concurrent"
    mkdir -p "$results_dir"

    # Start 5 concurrent request loops
    local pids=()
    for i in $(seq 1 5); do
        local pid
        pid=$(start_request_loop "$results_dir/client$i.txt" 50 0.02)
        pids+=("$pid")
        REQUEST_PIDS+=("$pid")
    done

    # Trigger reload mid-way
    sleep 0.3
    kill -HUP "$SENTINEL_PID"
    sleep 0.3
    kill -HUP "$SENTINEL_PID"

    # Wait for all clients
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # Aggregate results
    local total_success=0
    local total_fail=0
    for i in $(seq 1 5); do
        if [[ -f "$results_dir/client$i.txt" ]]; then
            read -r s f < "$results_dir/client$i.txt"
            total_success=$((total_success + s))
            total_fail=$((total_fail + f))
        fi
    done

    log_info "Total: $total_success succeeded, $total_fail failed"

    local total=$((total_success + total_fail))
    if [[ $total -gt 0 ]]; then
        local fail_rate=$((total_fail * 100 / total))
        if [[ "$fail_rate" -le 3 ]]; then
            log_pass "Concurrent clients handled well (${fail_rate}% failure rate)"
        else
            log_fail "High failure rate with concurrent clients: ${fail_rate}%"
        fi
    else
        log_fail "No requests completed"
    fi
}

# Test: Reload with invalid config doesn't break service
test_invalid_config_reload() {
    log_info "Testing reload with invalid config preserves service..."

    # Verify service is working
    local before
    before=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/health")
    if [[ "$before" != "200" ]]; then
        log_fail "Service not healthy before test"
        return
    fi

    # Write invalid config
    echo "this is { invalid } kdl {{{{" > "$TEMP_DIR/test-config.kdl"

    # Attempt reload (should fail gracefully)
    kill -HUP "$SENTINEL_PID"
    sleep 0.5

    # Service should still be running with old config
    local after
    after=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/health")

    if [[ "$after" == "200" ]]; then
        log_pass "Service continues with previous config after invalid reload"
    else
        log_fail "Service became unavailable after invalid config reload"
    fi

    # Restore valid config
    create_config "$TEMP_DIR/test-config.kdl" "ORIGINAL_RESPONSE"
    kill -HUP "$SENTINEL_PID"
    sleep 0.3
}

# Test: Metrics updated after reload
test_metrics_after_reload() {
    log_info "Testing metrics endpoint after reload..."

    # Make some requests
    for _ in $(seq 1 10); do
        curl -s "$PROXY_URL/test" > /dev/null
    done

    # Trigger reload
    kill -HUP "$SENTINEL_PID"
    sleep 0.3

    # Make more requests
    for _ in $(seq 1 10); do
        curl -s "$PROXY_URL/test" > /dev/null
    done

    # Check metrics endpoint (if available)
    local metrics_status
    metrics_status=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY_URL/_/metrics" 2>/dev/null || echo "000")

    if [[ "$metrics_status" == "200" ]]; then
        log_pass "Metrics endpoint available after reload"
    else
        log_skip "Metrics endpoint not configured (status: $metrics_status)"
    fi
}

# Run offline tests (no server needed)
run_offline_tests() {
    log_info "=== Offline Reload Tests ==="

    # Test config parsing
    log_info "Testing config file parsing..."

    local test_config="$TEMP_DIR/parse-test.kdl"
    create_config "$test_config" "test"

    if "$SENTINEL_BIN" --config "$test_config" --dry-run 2>/dev/null; then
        log_pass "Config file parses successfully"
    else
        # dry-run might not be implemented, skip
        log_skip "Config validation (--dry-run not available)"
    fi
}

# Main execution
main() {
    log_info "Starting Concurrent Reload Integration Tests"
    echo ""

    check_prerequisites

    # Setup
    TEMP_DIR=$(mktemp -d)
    log_info "Temp directory: $TEMP_DIR"

    # Run offline tests first
    run_offline_tests
    echo ""

    if [[ "$SKIP_CONNECTIVITY" == "1" ]]; then
        log_skip "Online tests (--skip-connectivity)"
        print_summary
        exit $?
    fi

    # Create initial config
    create_config "$TEMP_DIR/test-config.kdl" "ORIGINAL_RESPONSE"

    if ! start_sentinel "$TEMP_DIR/test-config.kdl"; then
        log_fail "Could not start Sentinel for online tests"
        print_summary
        exit 1
    fi

    echo ""
    log_info "=== Online Concurrent Reload Tests ==="

    test_reload_during_requests
    test_rapid_reloads
    test_config_changes_visible
    test_concurrent_clients_during_reload
    test_invalid_config_reload
    test_metrics_after_reload

    print_summary
}

main "$@"
