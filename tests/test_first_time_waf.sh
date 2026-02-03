#!/bin/bash
#
# First-Time User Smoke Test: WAF Agent
#
# Validates that a first-time user can build Sentinel + the WAF agent,
# wire them together, and see the agent working. Catches broken builds,
# protocol mismatches, config errors, and missing features.
#
# Prerequisites:
# - Rust toolchain (cargo)
# - Python 3
# - curl
# - Unix socket support
#
# Usage:
#   ./tests/test_first_time_waf.sh
#   SENTINEL_BIN=./target/release/sentinel WAF_BIN=./sentinel-waf-agent ./tests/test_first_time_waf.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="/tmp/sentinel-first-time-waf-$$"
WAF_SOCKET="$TEST_DIR/waf.sock"
PROXY_CONFIG="$TEST_DIR/config.kdl"
PROXY_PID=""
WAF_PID=""
BACKEND_PID=""
PROXY_PORT=""
BACKEND_PORT=""
METRICS_PORT=""

# Paths (overridable via env)
SENTINEL_BIN="${SENTINEL_BIN:-}"
WAF_BIN="${WAF_BIN:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WAF_REPO="${WAF_REPO:-$REPO_ROOT/../sentinel-agent-waf}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Clean headers to avoid WAF false positives on broad rules:
# - Rule 933100 matches any parentheses (LDAP injection)
# - Rule 934104 matches */* in Accept header (XPath node extraction)
CLEAN_HEADERS=(-H "User-Agent: SentinelTest" -H "Accept: text/html")

# Overall timeout (60s)
SCRIPT_START=$(date +%s)
SCRIPT_TIMEOUT=60

check_timeout() {
    local now=$(date +%s)
    local elapsed=$((now - SCRIPT_START))
    if [[ $elapsed -ge $SCRIPT_TIMEOUT ]]; then
        echo -e "${RED}[TIMEOUT]${NC} Script exceeded ${SCRIPT_TIMEOUT}s timeout"
        exit 1
    fi
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++)) || true
}

log_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++)) || true
}

log_test() {
    echo -e "${YELLOW}[TEST]${NC} $1"
    ((TESTS_RUN++)) || true
}

# Find a random available port
find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    [[ -n "$PROXY_PID" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "$WAF_PID" ]] && kill -TERM "$WAF_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -TERM "$BACKEND_PID" 2>/dev/null || true

    sleep 1

    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$WAF_PID" ]] && kill -9 "$WAF_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -9 "$BACKEND_PID" 2>/dev/null || true

    rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

# Build binaries if needed
build_binaries() {
    if [[ -z "$SENTINEL_BIN" ]]; then
        if [[ -f "$REPO_ROOT/target/release/sentinel" ]]; then
            SENTINEL_BIN="$REPO_ROOT/target/release/sentinel"
            log_info "Using existing Sentinel binary: $SENTINEL_BIN"
        else
            log_info "Building Sentinel proxy (release)..."
            (cd "$REPO_ROOT" && cargo build --release --bin sentinel)
            SENTINEL_BIN="$REPO_ROOT/target/release/sentinel"
        fi
    fi

    if [[ ! -f "$SENTINEL_BIN" ]]; then
        echo -e "${RED}[ERROR]${NC} Sentinel binary not found at $SENTINEL_BIN"
        exit 1
    fi

    if [[ -z "$WAF_BIN" ]]; then
        if [[ -f "$WAF_REPO/target/release/sentinel-waf-agent" ]]; then
            WAF_BIN="$WAF_REPO/target/release/sentinel-waf-agent"
            log_info "Using existing WAF agent binary: $WAF_BIN"
        elif [[ -d "$WAF_REPO" ]]; then
            log_info "Building WAF agent from $WAF_REPO (release)..."
            (cd "$WAF_REPO" && cargo build --release)
            WAF_BIN="$WAF_REPO/target/release/sentinel-waf-agent"
        else
            echo -e "${RED}[ERROR]${NC} WAF agent repo not found at $WAF_REPO"
            echo "Clone it as a sibling: git clone <url> ../sentinel-agent-waf"
            exit 1
        fi
    fi

    if [[ ! -f "$WAF_BIN" ]]; then
        echo -e "${RED}[ERROR]${NC} WAF agent binary not found at $WAF_BIN"
        exit 1
    fi
}

# Start a minimal Python HTTP backend
start_backend() {
    log_info "Starting Python HTTP backend..."

    BACKEND_PORT=$(find_free_port)
    mkdir -p "$TEST_DIR/www"
    echo "<html><body>Hello from backend</body></html>" > "$TEST_DIR/www/index.html"

    python3 -m http.server "$BACKEND_PORT" --directory "$TEST_DIR/www" \
        > "$TEST_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!

    # Wait for backend to be ready
    local retries=10
    while ! curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null 2>&1; do
        sleep 0.5
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            echo -e "${RED}[ERROR]${NC} Backend failed to start"
            return 1
        fi
    done

    log_info "Backend started on port $BACKEND_PORT (PID: $BACKEND_PID)"
}

# Generate config
generate_config() {
    PROXY_PORT=$(find_free_port)
    METRICS_PORT=$(find_free_port)

    log_info "Generating config (proxy=$PROXY_PORT, metrics=$METRICS_PORT, backend=$BACKEND_PORT)"

    cat > "$PROXY_CONFIG" <<EOF
system {
    worker-threads 2
    max-connections 1000
    graceful-shutdown-timeout-secs 5
}

listeners {
    listener "http" {
        address "127.0.0.1:$PROXY_PORT"
        protocol "http"
        request-timeout-secs 30
    }
}

filters {
    filter "waf-filter" {
        type "agent"
        agent "waf-agent"
        timeout-ms 200
        failure-mode "open"
    }
}

routes {
    route "default" {
        priority "low"
        matches {
            path-prefix "/"
        }
        upstream "test-backend"
        filters "waf-filter"
    }
}

upstreams {
    upstream "test-backend" {
        target "127.0.0.1:$BACKEND_PORT" weight=1
        load-balancing "round_robin"
    }
}

agents {
    agent "waf-agent" type="waf" {
        unix-socket "$WAF_SOCKET"
        events "request_headers"
        timeout-ms 200
        failure-mode "open"
        config {
            paranoia-level 1
            sqli #true
            xss #true
            path-traversal #true
            command-injection #true
            block-mode #true
        }
    }
}

limits {
    max-header-count 100
    max-header-size-bytes 8192
    max-body-size-bytes 1048576
}

observability {
    metrics {
        enabled #true
        address "127.0.0.1:$METRICS_PORT"
        path "/metrics"
    }
    logging {
        level "debug"
        format "json"
    }
}
EOF
}

# Start WAF agent
start_waf_agent() {
    log_info "Starting WAF agent..."

    RUST_LOG=debug "$WAF_BIN" \
        --socket "$WAF_SOCKET" \
        --paranoia-level 1 \
        --sqli \
        --xss \
        --path-traversal \
        --block-mode \
        --verbose \
        > "$TEST_DIR/waf-agent.log" 2>&1 &
    WAF_PID=$!

    local retries=10
    while [[ ! -S "$WAF_SOCKET" ]] && [[ $retries -gt 0 ]]; do
        sleep 0.5
        ((retries--))
    done

    if [[ -S "$WAF_SOCKET" ]]; then
        log_info "WAF agent started (PID: $WAF_PID)"
        return 0
    else
        echo -e "${RED}[ERROR]${NC} WAF agent failed to start"
        cat "$TEST_DIR/waf-agent.log" | tail -20
        return 1
    fi
}

# Start proxy
start_proxy() {
    log_info "Starting Sentinel proxy..."

    RUST_LOG=debug SENTINEL_CONFIG="$PROXY_CONFIG" \
        "$SENTINEL_BIN" \
        > "$TEST_DIR/proxy.log" 2>&1 &
    PROXY_PID=$!

    local retries=20
    while ! curl -sf "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; do
        sleep 0.5
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            echo -e "${RED}[ERROR]${NC} Proxy failed to start"
            cat "$TEST_DIR/proxy.log" | tail -30
            return 1
        fi
    done

    log_info "Proxy started (PID: $PROXY_PID)"
}

# ========================================================================
# Test cases
# ========================================================================

test_legitimate_request() {
    log_test "Legitimate request passes through"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/" || true)

    if [[ "$status" == "200" ]]; then
        log_success "Legitimate GET / returned 200"
    else
        log_failure "Legitimate GET / returned $status (expected 200)"
    fi
}

test_waf_blocks_with_body() {
    log_test "WAF block response returns 403 with body"

    local response
    response=$(curl -s --max-time 5 -g \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/?id=1'OR'1'='1" || true)

    if echo "$response" | grep -qi "Forbidden"; then
        log_success "WAF block response includes 'Forbidden' body"
    else
        log_failure "WAF block response missing expected body"
    fi
}

test_sqli_blocked() {
    log_test "SQL injection blocked"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -g \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/?id=1'OR'1'='1" || true)

    if [[ "$status" == "403" ]]; then
        log_success "SQL injection blocked with 403"
    else
        log_failure "SQL injection returned $status (expected 403)"
    fi
}

test_xss_blocked() {
    log_test "XSS blocked"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${CLEAN_HEADERS[@]}" -H "X-Input: <script>alert(1)</script>" \
        "http://127.0.0.1:$PROXY_PORT/" || true)

    if [[ "$status" == "403" ]]; then
        log_success "XSS blocked with 403"
    else
        log_failure "XSS returned $status (expected 403)"
    fi
}

test_path_traversal_blocked() {
    log_test "Path traversal blocked"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 --path-as-is \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/../../etc/passwd" || true)

    if [[ "$status" == "403" ]]; then
        log_success "Path traversal blocked with 403"
    else
        log_failure "Path traversal returned $status (expected 403)"
    fi
}

test_clean_request_allowed() {
    log_test "Clean request with query params passes through"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/?search=hello+world" || true)

    if [[ "$status" == "200" ]]; then
        log_success "Clean request with query params returned 200"
    else
        log_failure "Clean request with query params returned $status (expected 200)"
    fi
}

test_agent_crash_fail_open() {
    log_test "Agent crash — fail-open"

    # Kill WAF agent
    kill -TERM "$WAF_PID" 2>/dev/null || true
    local saved_pid="$WAF_PID"
    WAF_PID=""
    sleep 1

    # Legitimate request should still pass (fail-open)
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/" || true)

    if [[ "$status" == "200" ]]; then
        log_success "Request passed through with dead agent (fail-open)"
    else
        log_failure "Request returned $status with dead agent (expected 200)"
    fi
}

test_agent_recovery() {
    log_test "Agent recovers after restart"

    # Restart WAF agent
    start_waf_agent || {
        log_failure "WAF agent failed to restart"
        return
    }

    # Give proxy time to reconnect
    sleep 2

    # SQL injection should be blocked again
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -g \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/?id=1'OR'1'='1" || true)

    if [[ "$status" == "403" ]]; then
        log_success "WAF blocks attacks after recovery"
    else
        log_failure "WAF did not block after recovery (got $status, expected 403)"
    fi
}

# ========================================================================
# Main
# ========================================================================

main() {
    echo "==========================================="
    echo "First-Time User Smoke Test: WAF Agent"
    echo "==========================================="
    echo

    # Setup
    mkdir -p "$TEST_DIR"
    build_binaries
    start_backend
    generate_config
    start_waf_agent || exit 1
    start_proxy || exit 1

    # Stabilize
    sleep 2

    # Run tests
    check_timeout; test_legitimate_request
    check_timeout; test_waf_blocks_with_body
    check_timeout; test_sqli_blocked
    check_timeout; test_xss_blocked
    check_timeout; test_path_traversal_blocked
    check_timeout; test_clean_request_allowed
    check_timeout; test_agent_crash_fail_open
    check_timeout; test_agent_recovery

    # Summary
    echo
    echo "==========================================="
    echo "Test Summary"
    echo "==========================================="
    echo "Tests run:    $TESTS_RUN"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    else
        echo "Tests failed: $TESTS_FAILED"
    fi
    echo

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        echo
        echo "Check logs for details:"
        echo "  Proxy log:     $TEST_DIR/proxy.log"
        echo "  WAF agent log: $TEST_DIR/waf-agent.log"
        echo "  Backend log:   $TEST_DIR/backend.log"
        exit 1
    fi
}

main "$@"
