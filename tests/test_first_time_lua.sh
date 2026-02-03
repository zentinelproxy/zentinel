#!/bin/bash
#
# First-Time User Smoke Test: Lua Agent
#
# Validates that a first-time user can build Sentinel + the Lua agent,
# wire them together with a custom Lua script, and see the agent working.
# Uses an echo backend to verify header injection via request headers.
#
# Prerequisites:
# - Rust toolchain (cargo)
# - Python 3
# - curl
# - Unix socket support
#
# Usage:
#   ./tests/test_first_time_lua.sh
#   SENTINEL_BIN=./target/release/sentinel LUA_BIN=./sentinel-lua-agent ./tests/test_first_time_lua.sh
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_DIR="/tmp/sentinel-first-time-lua-$$"
LUA_SOCKET="$TEST_DIR/lua.sock"
PROXY_CONFIG="$TEST_DIR/config.kdl"
LUA_SCRIPT="$TEST_DIR/agent.lua"
PROXY_PID=""
LUA_PID=""
BACKEND_PID=""
PROXY_PORT=""
BACKEND_PORT=""
METRICS_PORT=""
LUA_GRPC_PORT=""

# Paths (overridable via env)
SENTINEL_BIN="${SENTINEL_BIN:-}"
LUA_BIN="${LUA_BIN:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LUA_REPO="${LUA_REPO:-$REPO_ROOT/../sentinel-agent-lua}"

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

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
    [[ -n "$LUA_PID" ]] && kill -TERM "$LUA_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -TERM "$BACKEND_PID" 2>/dev/null || true

    sleep 1

    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$LUA_PID" ]] && kill -9 "$LUA_PID" 2>/dev/null || true
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

    if [[ -z "$LUA_BIN" ]]; then
        if [[ -f "$LUA_REPO/target/release/sentinel-lua-agent" ]]; then
            LUA_BIN="$LUA_REPO/target/release/sentinel-lua-agent"
            log_info "Using existing Lua agent binary: $LUA_BIN"
        elif [[ -d "$LUA_REPO" ]]; then
            log_info "Building Lua agent from $LUA_REPO (release)..."
            (cd "$LUA_REPO" && cargo build --release)
            LUA_BIN="$LUA_REPO/target/release/sentinel-lua-agent"
        else
            echo -e "${RED}[ERROR]${NC} Lua agent repo not found at $LUA_REPO"
            echo "Clone it as a sibling: git clone <url> ../sentinel-agent-lua"
            exit 1
        fi
    fi

    if [[ ! -f "$LUA_BIN" ]]; then
        echo -e "${RED}[ERROR]${NC} Lua agent binary not found at $LUA_BIN"
        exit 1
    fi
}

# Start a Python echo backend that reflects request headers in the response body
start_backend() {
    log_info "Starting Python echo backend..."

    BACKEND_PORT=$(find_free_port)

    cat > "$TEST_DIR/echo_server.py" <<'PYEOF'
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        lines = [f"{k}: {v}" for k, v in self.headers.items()]
        self.wfile.write("\n".join(lines).encode())

    def log_message(self, fmt, *args):
        pass  # suppress log noise

HTTPServer(("127.0.0.1", int(sys.argv[1])), EchoHandler).serve_forever()
PYEOF

    python3 "$TEST_DIR/echo_server.py" "$BACKEND_PORT" \
        > "$TEST_DIR/backend.log" 2>&1 &
    BACKEND_PID=$!

    local retries=10
    while ! curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null 2>&1; do
        sleep 0.5
        ((retries--))
        if [[ $retries -eq 0 ]]; then
            echo -e "${RED}[ERROR]${NC} Backend failed to start"
            return 1
        fi
    done

    log_info "Echo backend started on port $BACKEND_PORT (PID: $BACKEND_PID)"
}

# Create Lua script
create_lua_script() {
    log_info "Creating Lua agent script..."

    cat > "$LUA_SCRIPT" <<'LUAEOF'
-- Sentinel Lua Agent: first-time user test script
-- Adds a custom request header to every allowed request, blocks requests with ?block=true

function on_request_headers()
    -- Check if we should block
    local uri = request.uri or ""
    if string.find(uri, "block=true") then
        return {
            decision = "block",
            status = 403,
            body = "Blocked by Lua agent"
        }
    end

    -- Allow with custom request header (injected into upstream request)
    return {
        decision = "allow",
        add_request_headers = {
            ["X-Processed-By"] = "lua-agent"
        }
    }
end
LUAEOF
}

# Generate config
generate_config() {
    PROXY_PORT=$(find_free_port)
    METRICS_PORT=$(find_free_port)
    LUA_GRPC_PORT=$(find_free_port)

    log_info "Generating config (proxy=$PROXY_PORT, metrics=$METRICS_PORT, backend=$BACKEND_PORT, lua-grpc=$LUA_GRPC_PORT)"

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
    filter "lua-filter" {
        type "agent"
        agent "lua-agent"
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
        filters "lua-filter"
    }
}

upstreams {
    upstream "test-backend" {
        target "127.0.0.1:$BACKEND_PORT" weight=1
        load-balancing "round_robin"
    }
}

agents {
    agent "lua-agent" {
        type "custom"
        grpc "http://127.0.0.1:$LUA_GRPC_PORT"
        protocol-version "v2"
        events "request_headers"
        timeout-ms 200
        failure-mode "open"
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

# Start Lua agent
start_lua_agent() {
    log_info "Starting Lua agent..."

    RUST_LOG=debug "$LUA_BIN" \
        --socket "$LUA_SOCKET" \
        --grpc-address "127.0.0.1:$LUA_GRPC_PORT" \
        --script "$LUA_SCRIPT" \
        --fail-open \
        --verbose \
        > "$TEST_DIR/lua-agent.log" 2>&1 &
    LUA_PID=$!

    # Wait for gRPC port to be ready
    local retries=20
    while ! curl -sf "http://127.0.0.1:$LUA_GRPC_PORT/" >/dev/null 2>&1 && [[ $retries -gt 0 ]]; do
        sleep 0.5
        ((retries--))
    done

    # Give a moment for gRPC server to fully initialize
    sleep 1

    if kill -0 "$LUA_PID" 2>/dev/null; then
        log_info "Lua agent started (PID: $LUA_PID, gRPC: $LUA_GRPC_PORT)"
        return 0
    else
        echo -e "${RED}[ERROR]${NC} Lua agent failed to start"
        cat "$TEST_DIR/lua-agent.log" | tail -20
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
    while ! curl -sf "http://127.0.0.1:$PROXY_PORT/" >/dev/null 2>&1; do
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

test_request_passes() {
    log_test "Request passes through"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://127.0.0.1:$PROXY_PORT/" || true)

    if [[ "$status" == "200" ]]; then
        log_success "GET / returned 200"
    else
        log_failure "GET / returned $status (expected 200)"
    fi
}

test_lua_adds_header() {
    log_test "Lua agent injects request header"

    # The echo backend reflects request headers in the response body,
    # so we can verify the Lua agent injected X-Processed-By
    local body
    body=$(curl -s --max-time 5 "http://127.0.0.1:$PROXY_PORT/" || true)

    if echo "$body" | grep -qi "x-processed-by: lua-agent"; then
        log_success "Lua agent injected X-Processed-By request header"
    else
        log_failure "Lua agent did not inject X-Processed-By header (body: $body)"
    fi
}

test_lua_blocks_request() {
    log_test "Lua agent blocks request"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://127.0.0.1:$PROXY_PORT/?block=true" || true)

    if [[ "$status" == "403" ]]; then
        log_success "Lua agent blocked request with 403"
    else
        log_failure "Lua agent returned $status (expected 403)"
    fi
}

test_agent_crash_fail_open() {
    log_test "Agent crash — fail-open"

    # Kill Lua agent
    kill -TERM "$LUA_PID" 2>/dev/null || true
    LUA_PID=""
    sleep 1

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://127.0.0.1:$PROXY_PORT/" || true)

    if [[ "$status" == "200" ]]; then
        log_success "Request passed through with dead agent (fail-open)"
    else
        log_failure "Request returned $status with dead agent (expected 200)"
    fi
}

# ========================================================================
# Main
# ========================================================================

main() {
    echo "==========================================="
    echo "First-Time User Smoke Test: Lua Agent"
    echo "==========================================="
    echo

    # Setup
    mkdir -p "$TEST_DIR"
    build_binaries
    start_backend
    create_lua_script
    generate_config
    start_lua_agent || exit 1
    start_proxy || exit 1

    # Stabilize
    sleep 2

    # Run tests
    check_timeout; test_request_passes
    check_timeout; test_lua_adds_header
    check_timeout; test_lua_blocks_request
    check_timeout; test_agent_crash_fail_open

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
        echo "  Lua agent log: $TEST_DIR/lua-agent.log"
        echo "  Backend log:   $TEST_DIR/backend.log"
        exit 1
    fi
}

main "$@"
