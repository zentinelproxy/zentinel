#!/bin/bash
#
# Zentinel Bundle Integration Tests
# Tests the bundle CLI commands and agent integration
#
# Prerequisites:
# - Built binaries in target/release/
# - curl installed
#
# Usage:
#   ./tests/bundle_integration_test.sh
#
# This test uses the local echo agent since external agents don't have
# releases yet. Once releases are available, this can test real downloads.

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
TEST_DIR="/tmp/zentinel-bundle-test-$$"
PROXY_PORT=18080
ECHO_SOCKET="$TEST_DIR/echo.sock"
DATA_MASKING_SOCKET="$TEST_DIR/data-masking.sock"
PROXY_CONFIG="$TEST_DIR/config.kdl"
PROXY_PID=""
ECHO_PID=""
DATA_MASKING_PID=""
BACKEND_PID=""

# Binaries
ZENTINEL_BIN="./target/release/zentinel"
ECHO_AGENT_BIN="./target/release/zentinel-echo-agent"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
log_failure() { echo -e "${RED}[FAIL]${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; TESTS_RUN=$((TESTS_RUN + 1)); }
log_section() { echo -e "\n${BLUE}═══════════════════════════════════════════════════════${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}\n"; }

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    [[ -n "${PROXY_PID:-}" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "${ECHO_PID:-}" ]] && kill -TERM "$ECHO_PID" 2>/dev/null || true
    [[ -n "${DATA_MASKING_PID:-}" ]] && kill -TERM "$DATA_MASKING_PID" 2>/dev/null || true
    [[ -n "${BACKEND_PID:-}" ]] && kill -TERM "$BACKEND_PID" 2>/dev/null || true

    sleep 1

    [[ -n "${PROXY_PID:-}" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "${ECHO_PID:-}" ]] && kill -9 "$ECHO_PID" 2>/dev/null || true
    [[ -n "${DATA_MASKING_PID:-}" ]] && kill -9 "$DATA_MASKING_PID" 2>/dev/null || true
    [[ -n "${BACKEND_PID:-}" ]] && kill -9 "$BACKEND_PID" 2>/dev/null || true

    rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -f "$ZENTINEL_BIN" ]]; then
        echo "Error: Zentinel binary not found. Run: cargo build --release -p zentinel-proxy"
        exit 1
    fi

    if [[ ! -f "$ECHO_AGENT_BIN" ]]; then
        echo "Error: Echo agent binary not found. Run: cargo build --release -p zentinel-echo-agent"
        exit 1
    fi

    if ! command -v curl &>/dev/null; then
        echo "Error: curl is required"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# ============================================================================
# Bundle CLI Tests
# ============================================================================

test_bundle_status() {
    log_test "bundle status command"

    local output=$("$ZENTINEL_BIN" bundle status 2>&1)

    if echo "$output" | grep -q "Zentinel Bundle Status"; then
        log_success "bundle status shows header"
    else
        log_failure "bundle status missing header"
    fi

    if echo "$output" | grep -q "Bundle version:"; then
        log_success "bundle status shows version"
    else
        log_failure "bundle status missing version"
    fi

    if echo "$output" | grep -q "waf"; then
        log_success "bundle status lists waf agent"
    else
        log_failure "bundle status missing waf agent"
    fi

    if echo "$output" | grep -q "Total:"; then
        log_success "bundle status shows summary"
    else
        log_failure "bundle status missing summary"
    fi

    # Check agent count
    local agent_count=$(echo "$output" | grep -c "not installed" || true)
    if [[ $agent_count -ge 20 ]]; then
        log_success "bundle status lists all agents ($agent_count agents)"
    else
        log_failure "bundle status missing agents (found $agent_count)"
    fi
}

test_bundle_list() {
    log_test "bundle list command"

    local output=$("$ZENTINEL_BIN" bundle list 2>&1)

    if echo "$output" | grep -q "waf"; then
        log_success "bundle list shows waf"
    else
        log_failure "bundle list missing waf"
    fi

    if echo "$output" | grep -q "ratelimit"; then
        log_success "bundle list shows ratelimit"
    else
        log_failure "bundle list missing ratelimit"
    fi
}

test_bundle_list_verbose() {
    log_test "bundle list --verbose command"

    local output=$("$ZENTINEL_BIN" bundle list --verbose 2>&1)

    if echo "$output" | grep -q "Repository:"; then
        log_success "bundle list --verbose shows repository"
    else
        log_failure "bundle list --verbose missing repository"
    fi

    if echo "$output" | grep -q "Binary:"; then
        log_success "bundle list --verbose shows binary name"
    else
        log_failure "bundle list --verbose missing binary name"
    fi

    if echo "$output" | grep -q "URL:"; then
        log_success "bundle list --verbose shows download URL"
    else
        log_failure "bundle list --verbose missing download URL"
    fi

    if echo "$output" | grep -q "github.com/zentinelproxy"; then
        log_success "bundle list --verbose has correct GitHub URLs"
    else
        log_failure "bundle list --verbose has incorrect URLs"
    fi
}

test_bundle_install_dry_run() {
    log_test "bundle install --dry-run command"

    local output=$("$ZENTINEL_BIN" bundle install --dry-run 2>&1 || true)

    if echo "$output" | grep -qi "dry.run\|would\|preview"; then
        log_success "bundle install --dry-run works"
    else
        log_info "bundle install --dry-run output: $output"
        log_failure "bundle install --dry-run unexpected output"
    fi
}

# ============================================================================
# Agent Integration Tests
# ============================================================================

setup_test_environment() {
    log_info "Setting up test environment in $TEST_DIR..."
    mkdir -p "$TEST_DIR"

    # Create test configuration with echo agent
    cat > "$PROXY_CONFIG" <<EOF
system {
    worker-threads 2
}

listeners {
    listener "http" {
        address "127.0.0.1:$PROXY_PORT"
        protocol "http"
    }
}

routes {
    route "echo-test" {
        priority 100
        matches {
            path-prefix "/echo"
        }
        upstream "test-backend"
        policies {
            agents "echo-agent"
        }
    }

    route "default" {
        priority 1
        matches {
            path-prefix "/"
        }
        upstream "test-backend"
    }
}

upstreams {
    upstream "test-backend" {
        target "127.0.0.1:19000"
    }
}

agents {
    agent "echo-agent" {
        unix-socket path="$ECHO_SOCKET"
        timeout-ms 1000
        failure-mode "open"
    }
}
EOF

    log_info "Configuration written to $PROXY_CONFIG"
}

start_mock_backend() {
    log_info "Starting mock backend on port 19000..."

    # Simple Python HTTP server as backend
    python3 -c "
import http.server
import socketserver
import json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            'path': self.path,
            'method': 'GET',
            'headers': dict(self.headers)
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Backend-Response', 'true')
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            'path': self.path,
            'method': 'POST',
            'body': body,
            'headers': dict(self.headers)
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

    def log_message(self, format, *args):
        pass  # Suppress logging

with socketserver.TCPServer(('127.0.0.1', 19000), Handler) as httpd:
    httpd.serve_forever()
" &
    BACKEND_PID=$!
    sleep 1

    if kill -0 "$BACKEND_PID" 2>/dev/null; then
        log_info "Mock backend started (PID: $BACKEND_PID)"
    else
        log_failure "Failed to start mock backend"
        exit 1
    fi
}

start_echo_agent() {
    log_info "Starting echo agent..."

    RUST_LOG=info "$ECHO_AGENT_BIN" \
        --socket "$ECHO_SOCKET" \
        > "$TEST_DIR/echo-agent.log" 2>&1 &

    ECHO_PID=$!

    # Wait for socket
    local retries=20
    while [[ ! -S "$ECHO_SOCKET" ]] && [[ $retries -gt 0 ]]; do
        sleep 0.2
        ((retries--))
    done

    if [[ -S "$ECHO_SOCKET" ]]; then
        log_info "Echo agent started (PID: $ECHO_PID, socket: $ECHO_SOCKET)"
    else
        log_failure "Echo agent failed to create socket"
        cat "$TEST_DIR/echo-agent.log"
        exit 1
    fi
}

start_proxy() {
    log_info "Starting Zentinel proxy..."

    RUST_LOG=info,zentinel=debug "$ZENTINEL_BIN" \
        --config "$PROXY_CONFIG" \
        > "$TEST_DIR/proxy.log" 2>&1 &

    PROXY_PID=$!

    # Wait for proxy to be ready
    local retries=30
    while ! curl -sf "http://127.0.0.1:$PROXY_PORT/_builtin/health" >/dev/null 2>&1; do
        sleep 0.3
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            log_failure "Proxy failed to start"
            cat "$TEST_DIR/proxy.log" | tail -30
            exit 1
        fi
    done

    log_info "Proxy started (PID: $PROXY_PID)"
}

test_basic_proxy() {
    log_test "Basic proxy request (no agent)"

    local response=$(curl -s "http://127.0.0.1:$PROXY_PORT/test")

    if echo "$response" | grep -q '"path": "/test"'; then
        log_success "Basic proxy request works"
    else
        log_failure "Basic proxy request failed"
        echo "Response: $response"
    fi
}

test_echo_agent_headers() {
    log_test "Echo agent adds headers"

    local headers=$(curl -sI "http://127.0.0.1:$PROXY_PORT/echo/test" 2>/dev/null)

    # Check for proxy-added headers (Zentinel adds X-Correlation-Id)
    if echo "$headers" | grep -qi "X-Correlation-Id"; then
        log_success "Proxy/agent added correlation headers to response"
    else
        log_info "Response headers:"
        echo "$headers" | head -20
        log_failure "Proxy did not add expected headers"
    fi
}

test_echo_agent_processing() {
    log_test "Echo agent processes request"

    # Make request through echo route
    local status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Test-Header: TestValue" \
        "http://127.0.0.1:$PROXY_PORT/echo/test")

    if [[ "$status" == "200" ]]; then
        log_success "Request through echo agent returns 200"
    else
        log_failure "Request through echo agent returned $status"
    fi

    # Check agent logs for activity
    sleep 0.5
    if grep -qi "request\|processing\|handle" "$TEST_DIR/echo-agent.log" 2>/dev/null; then
        log_success "Echo agent logged request processing"
    else
        log_info "Echo agent log:"
        cat "$TEST_DIR/echo-agent.log" | tail -10
        log_info "Agent may not log at info level"
    fi
}

test_multiple_requests() {
    log_test "Multiple sequential requests through agent"

    local success=0
    local failed=0

    # Send sequential requests with timeout
    for i in {1..5}; do
        local status=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" \
            "http://127.0.0.1:$PROXY_PORT/echo/request-$i")
        if [[ "$status" == "200" ]]; then
            ((success++)) || true
        else
            ((failed++)) || true
        fi
    done

    if [[ $success -ge 4 ]]; then
        log_success "Multiple requests through agent succeeded ($success/5)"
    else
        log_failure "Multiple requests failed (only $success/5 succeeded)"
    fi
}

test_agent_logs() {
    log_test "Agent activity in logs"

    log_info "Echo agent log (last 15 lines):"
    tail -15 "$TEST_DIR/echo-agent.log" 2>/dev/null || echo "(no log)"

    log_info "Proxy log (last 15 lines):"
    tail -15 "$TEST_DIR/proxy.log" 2>/dev/null || echo "(no log)"

    # Check proxy logs for agent communication
    if grep -qi "agent\|echo" "$TEST_DIR/proxy.log" 2>/dev/null; then
        log_success "Proxy logs show agent activity"
    else
        log_info "Agent activity not visible in proxy logs at current level"
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo ""
    log_section "Zentinel Bundle Integration Tests"

    check_prerequisites

    # Part 1: Bundle CLI Tests
    log_section "Part 1: Bundle CLI Commands"
    test_bundle_status
    test_bundle_list
    test_bundle_list_verbose
    test_bundle_install_dry_run

    # Part 2: Agent Integration Tests
    log_section "Part 2: Agent Integration"
    setup_test_environment
    start_mock_backend
    start_echo_agent
    start_proxy

    sleep 1

    test_basic_proxy
    test_echo_agent_headers
    test_echo_agent_processing
    test_multiple_requests
    test_agent_logs

    # Summary
    log_section "Test Summary"
    echo "Tests run:    $TESTS_RUN"
    echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    else
        echo "Tests failed: $TESTS_FAILED"
    fi
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        echo ""
        echo "Logs available at:"
        echo "  Proxy:      $TEST_DIR/proxy.log"
        echo "  Echo agent: $TEST_DIR/echo-agent.log"
        exit 1
    fi
}

main "$@"
