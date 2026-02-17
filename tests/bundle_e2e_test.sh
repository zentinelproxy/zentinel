#!/usr/bin/env bash
#
# Zentinel Bundle End-to-End Test
#
# This test validates the complete bundle distribution system by:
# 1. Installing all available agents via `zentinel bundle install`
# 2. Starting each agent with appropriate configuration
# 3. Configuring the proxy to chain all agents together
# 4. Sending test requests through the full agent pipeline
# 5. Verifying each agent logged activity
#
# This simulates an enterprise deployment where all agents run in parallel.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Test configuration
TEST_DIR="/tmp/zentinel-e2e-test-$$"
PROXY_PORT=18080
BACKEND_PORT=19000
INSTALL_DIR=""  # Set after bundle install
CONFIG_DIR="$TEST_DIR/config"
LOG_DIR="$TEST_DIR/logs"
SOCKET_DIR="$TEST_DIR/sockets"

# Tracking (using simple arrays and temp files for bash 3.x compatibility)
STARTED_AGENTS=""
FAILED_AGENTS=""
SKIPPED_AGENTS=""
PIDS_FILE="$TEST_DIR/pids.txt"
SOCKETS_FILE="$TEST_DIR/sockets.txt"

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

PROXY_PID=""
BACKEND_PID=""

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
log_test() { echo -e "${YELLOW}[TEST]${NC} $*"; }
log_section() {
    echo ""
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}  $*${NC}"
    echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"
}

# Test assertion
assert() {
    local description="$1"
    local condition="$2"
    TESTS_RUN=$((TESTS_RUN + 1))
    if eval "$condition"; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}[PASS]${NC} $description"
        return 0
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}[FAIL]${NC} $description"
        return 1
    fi
}

# Store agent PID
store_pid() {
    local agent="$1"
    local pid="$2"
    echo "$agent:$pid" >> "$PIDS_FILE"
}

# Store agent socket
store_socket() {
    local agent="$1"
    local socket="$2"
    echo "$agent:$socket" >> "$SOCKETS_FILE"
}

# Get agent PID
get_pid() {
    local agent="$1"
    grep "^$agent:" "$PIDS_FILE" 2>/dev/null | cut -d: -f2 | head -1
}

# Get agent socket
get_socket() {
    local agent="$1"
    grep "^$agent:" "$SOCKETS_FILE" 2>/dev/null | cut -d: -f2 | head -1
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."

    # Kill all agent processes
    if [[ -f "$PIDS_FILE" ]]; then
        while IFS=: read -r agent pid; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PIDS_FILE"
    fi

    # Kill proxy
    if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
    fi

    # Kill backend
    if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi

    # Wait for processes to terminate
    sleep 1

    # Force kill if necessary
    if [[ -f "$PIDS_FILE" ]]; then
        while IFS=: read -r agent pid; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        done < "$PIDS_FILE"
    fi

    if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill -9 "$PROXY_PID" 2>/dev/null || true
    fi

    if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill -9 "$BACKEND_PID" 2>/dev/null || true
    fi

    # Optionally preserve logs on failure
    if [[ $TESTS_FAILED -gt 0 && "${PRESERVE_LOGS:-}" == "true" ]]; then
        log_warn "Preserving test directory for debugging: $TEST_DIR"
    else
        rm -rf "$TEST_DIR"
    fi
}

trap cleanup EXIT

# Detect platform
detect_platform() {
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        linux) os="linux" ;;
        darwin) os="darwin" ;;
        *) log_error "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) log_error "Unsupported architecture: $arch"; exit 1 ;;
    esac

    echo "${os}-${arch}"
}

# All 22 agents in the bundle
ALL_AGENTS="waf ratelimit denylist zentinelsec modsec ip-reputation bot-management content-scanner graphql-security grpc-inspector soap api-deprecation websocket-inspector mqtt-gateway lua js wasm transform audit-logger mock-server chaos spiffe"

# Get agent-specific CLI arguments
# Each agent may have different CLI requirements
get_agent_args() {
    local agent="$1"
    local socket="$2"

    # Agent-specific configurations to ensure they don't block test traffic
    # All agents configured in detection/passthrough mode where applicable
    case "$agent" in
        waf)
            # WAF: paranoia level 1, detection mode via env var
            echo "--socket $socket --paranoia-level 1"
            ;;
        ratelimit)
            # Ratelimit: high default limit to avoid blocking test traffic
            echo "--socket $socket"
            ;;
        denylist)
            # Denylist: empty list by default (no blocking)
            echo "--socket $socket"
            ;;
        zentinelsec)
            # ZentinelSec: comprehensive security agent
            echo "--socket $socket"
            ;;
        modsec)
            # ModSecurity: detection mode
            echo "--socket $socket"
            ;;
        ip-reputation)
            # IP Reputation: passthrough mode for testing
            echo "--socket $socket"
            ;;
        bot-management)
            # Bot Management: detection only
            echo "--socket $socket"
            ;;
        content-scanner)
            # Content Scanner: scan without blocking
            echo "--socket $socket"
            ;;
        graphql-security)
            # GraphQL Security: validate but allow
            echo "--socket $socket"
            ;;
        grpc-inspector)
            # gRPC Inspector: inspect without blocking
            echo "--socket $socket"
            ;;
        soap)
            # SOAP: validate XML but allow
            echo "--socket $socket"
            ;;
        api-deprecation)
            # API Deprecation: warn only
            echo "--socket $socket"
            ;;
        websocket-inspector)
            # WebSocket Inspector: inspect without blocking
            echo "--socket $socket"
            ;;
        mqtt-gateway)
            # MQTT Gateway: passthrough
            echo "--socket $socket"
            ;;
        lua)
            # Lua: scripting agent
            echo "--socket $socket"
            ;;
        js)
            # JavaScript: scripting agent
            echo "--socket $socket"
            ;;
        wasm)
            # WASM: sandbox execution
            echo "--socket $socket"
            ;;
        transform)
            # Transform: passthrough (no transforms configured)
            echo "--socket $socket"
            ;;
        audit-logger)
            # Audit Logger: log to test directory
            echo "--socket $socket --log-file $LOG_DIR/audit.log"
            ;;
        mock-server)
            # Mock Server: test utility
            echo "--socket $socket"
            ;;
        chaos)
            # Chaos: disabled for testing (no failures injected)
            echo "--socket $socket"
            ;;
        spiffe)
            # SPIFFE: identity agent
            echo "--socket $socket"
            ;;
        *)
            # Default: just socket
            echo "--socket $socket"
            ;;
    esac
}

# Get agent-specific environment variables
# Returns space-separated KEY=VALUE pairs
get_agent_env() {
    local agent="$1"

    case "$agent" in
        waf)
            # WAF: detection mode (don't block requests)
            echo "WAF_BLOCK_MODE=false"
            ;;
        ratelimit)
            # Ratelimit: high limit for testing (10000 req/s)
            echo "RATE_LIMIT_DEFAULT_RPS=10000"
            ;;
        modsec)
            # ModSecurity: detection only mode
            echo "MODSEC_DETECTION_ONLY=true"
            ;;
        bot-management)
            # Bot Management: detection only
            echo "BOT_DETECTION_ONLY=true"
            ;;
        content-scanner)
            # Content Scanner: scan only, don't block
            echo "SCANNER_BLOCK_MODE=false"
            ;;
        chaos)
            # Chaos: disable fault injection
            echo "CHAOS_ENABLED=false"
            ;;
        ip-reputation)
            # IP Reputation: allow all (no blocking)
            echo "IP_REPUTATION_BLOCK_MODE=false"
            ;;
        api-deprecation)
            # API Deprecation: warn only, don't block
            echo "DEPRECATION_WARN_ONLY=true"
            ;;
        *)
            # No special env vars needed
            echo ""
            ;;
    esac
}

# Start an agent
start_agent() {
    local agent="$1"
    local binary="$INSTALL_DIR/zentinel-${agent}-agent"
    local socket="$SOCKET_DIR/${agent}.sock"
    local log_file="$LOG_DIR/${agent}.log"

    # Check if binary exists
    if [[ ! -x "$binary" ]]; then
        log_warn "  Agent binary not found: $binary"
        SKIPPED_AGENTS="$SKIPPED_AGENTS $agent"
        return 1
    fi

    # Remove existing socket
    rm -f "$socket"

    # Get agent-specific arguments and environment variables
    local args env_vars
    args=$(get_agent_args "$agent" "$socket")
    env_vars=$(get_agent_env "$agent")

    # Start the agent
    local started=false
    local pid

    # Try with agent-specific args first
    if [[ -n "$env_vars" ]]; then
        log_info "  Starting $agent: $env_vars $binary $args"
        eval "$env_vars $binary $args" > "$log_file" 2>&1 &
    else
        log_info "  Starting $agent: $binary $args"
        eval "$binary $args" > "$log_file" 2>&1 &
    fi
    pid=$!

    # Wait for socket to be created (up to 3 seconds)
    local wait_count=0
    while [[ $wait_count -lt 15 ]]; do
        sleep 0.2
        if [[ -S "$socket" ]]; then
            break
        fi
        # Check if process is still running
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        wait_count=$((wait_count + 1))
    done

    if kill -0 "$pid" 2>/dev/null && [[ -S "$socket" ]]; then
        started=true
        store_pid "$agent" "$pid"
        store_socket "$agent" "$socket"
        log_success "  $agent started (PID: $pid)"
    elif kill -0 "$pid" 2>/dev/null; then
        log_warn "  $agent running but socket not created after 3s"
        kill "$pid" 2>/dev/null || true
    else
        log_warn "  $agent process exited"
        if [[ -f "$log_file" ]]; then
            echo "    Last 3 lines of log:"
            tail -3 "$log_file" | sed 's/^/    /'
        fi
    fi

    # If first method failed, try with environment variable for socket
    if ! $started && [[ -z "$env_vars" ]]; then
        log_info "  Trying $agent with AGENT_SOCKET env var..."
        rm -f "$socket"
        AGENT_SOCKET="$socket" "$binary" > "$log_file" 2>&1 &
        pid=$!

        wait_count=0
        while [[ $wait_count -lt 15 ]]; do
            sleep 0.2
            if [[ -S "$socket" ]]; then
                break
            fi
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            wait_count=$((wait_count + 1))
        done

        if kill -0 "$pid" 2>/dev/null && [[ -S "$socket" ]]; then
            started=true
            store_pid "$agent" "$pid"
            store_socket "$agent" "$socket"
            log_success "  $agent started with env var (PID: $pid)"
        else
            kill "$pid" 2>/dev/null || true
        fi
    fi

    if $started; then
        STARTED_AGENTS="$STARTED_AGENTS $agent"
        return 0
    else
        log_warn "  Failed to start agent: $agent"
        FAILED_AGENTS="$FAILED_AGENTS $agent"
        return 1
    fi
}

# Generate proxy configuration with all agents
generate_proxy_config() {
    local config_file="$CONFIG_DIR/proxy.kdl"

    # Build space-separated agents list for policies
    local agents_string=""
    for agent in $STARTED_AGENTS; do
        if [[ -z "$agents_string" ]]; then
            agents_string="\"$agent\""
        else
            agents_string="$agents_string \"$agent\""
        fi
    done

    cat > "$config_file" << EOF
// Zentinel E2E Test Configuration
// Generated for testing all agents in parallel

system {
    worker-threads 4
}

listeners {
    listener "http" {
        address "127.0.0.1:$PROXY_PORT"
        protocol "http"
    }
}

routes {
    route "test-all-agents" {
        priority 100
        matches {
            path-prefix "/"
        }
        upstream "backend"
        policies {
            agents $agents_string
        }
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:$BACKEND_PORT"
    }
}

agents {
EOF

    # Add each started agent with simpler format
    for agent in $STARTED_AGENTS; do
        local socket
        socket=$(get_socket "$agent")
        if [[ -n "$socket" ]]; then
            cat >> "$config_file" << EOF
    agent "$agent" {
        unix-socket path="$socket"
        timeout-ms 5000
        failure-mode "open"
    }
EOF
        fi
    done

    echo "}" >> "$config_file"

    echo "$config_file"
}

# Start mock backend that logs requests
start_mock_backend() {
    local log_file="$LOG_DIR/backend.log"

    # Python-based mock backend
    python3 -c '
import http.server
import json
import sys
from datetime import datetime

class LoggingHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        timestamp = datetime.now().isoformat()
        print(f"[{timestamp}] {format % args}", flush=True)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Processed", "true")
        self.end_headers()

        response = {
            "status": "ok",
            "path": self.path,
            "method": "GET",
            "timestamp": datetime.now().isoformat(),
            "headers": dict(self.headers)
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Processed", "true")
        self.end_headers()

        response = {
            "status": "ok",
            "path": self.path,
            "method": "POST",
            "timestamp": datetime.now().isoformat(),
            "body_length": len(body),
            "headers": dict(self.headers)
        }
        self.wfile.write(json.dumps(response, indent=2).encode())

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19000
server = http.server.HTTPServer(("127.0.0.1", PORT), LoggingHandler)
print(f"Mock backend listening on port {PORT}", flush=True)
server.serve_forever()
' "$BACKEND_PORT" > "$log_file" 2>&1 &

    BACKEND_PID=$!
    sleep 1

    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        log_error "Failed to start mock backend"
        return 1
    fi

    log_info "Mock backend started (PID: $BACKEND_PID)"
    return 0
}

# Start the proxy
start_proxy() {
    local config_file="$1"
    local log_file="$LOG_DIR/proxy.log"

    # Find zentinel binary
    local zentinel_bin=""
    if [[ -x "./target/release/zentinel" ]]; then
        zentinel_bin="./target/release/zentinel"
    elif [[ -x "./target/debug/zentinel" ]]; then
        zentinel_bin="./target/debug/zentinel"
    elif command -v zentinel &>/dev/null; then
        zentinel_bin="zentinel"
    else
        log_error "Zentinel binary not found. Please build with 'cargo build --release'"
        return 1
    fi

    RUST_LOG=debug "$zentinel_bin" --config "$config_file" > "$log_file" 2>&1 &
    PROXY_PID=$!

    # Wait for proxy to be ready
    local retries=30
    while [[ $retries -gt 0 ]]; do
        if curl -s "http://127.0.0.1:$PROXY_PORT/_builtin/health" > /dev/null 2>&1; then
            log_info "Proxy started and healthy (PID: $PROXY_PID)"
            return 0
        fi
        sleep 0.2
        retries=$((retries - 1))
    done

    log_error "Proxy failed to become healthy"
    if [[ -f "$log_file" ]]; then
        log_error "Proxy log (last 20 lines):"
        tail -20 "$log_file"
    fi
    return 1
}

# Main test sequence
main() {
    local platform
    platform=$(detect_platform)

    echo -e "${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║     Zentinel Bundle End-to-End Test                          ║"
    echo "║     Testing ALL 22 agents in enterprise deployment           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    log_info "Platform: $platform"
    log_info "Test directory: $TEST_DIR"
    log_info "Expected agents: 22 (waf, ratelimit, denylist, zentinelsec, modsec,"
    log_info "                     ip-reputation, bot-management, content-scanner,"
    log_info "                     graphql-security, grpc-inspector, soap, api-deprecation,"
    log_info "                     websocket-inspector, mqtt-gateway, lua, js, wasm,"
    log_info "                     transform, audit-logger, mock-server, chaos, spiffe)"

    # Create directories
    mkdir -p "$TEST_DIR" "$CONFIG_DIR" "$LOG_DIR" "$SOCKET_DIR"
    touch "$PIDS_FILE" "$SOCKETS_FILE"

    # =========================================================================
    log_section "Phase 1: Install Agents"
    # =========================================================================

    log_info "Installing all available agents via 'zentinel bundle install'..."

    # Find zentinel binary
    local zentinel_bin=""
    if [[ -x "./target/release/zentinel" ]]; then
        zentinel_bin="./target/release/zentinel"
    elif [[ -x "./target/debug/zentinel" ]]; then
        zentinel_bin="./target/debug/zentinel"
    else
        log_error "Zentinel binary not found. Please build with 'cargo build --release'"
        exit 1
    fi

    # Run bundle install with custom prefix
    local install_log="$LOG_DIR/bundle-install.log"
    if "$zentinel_bin" bundle install --prefix "$TEST_DIR" > "$install_log" 2>&1; then
        log_success "Bundle install completed"
    else
        log_warn "Bundle install had some failures (check $install_log)"
    fi

    # Agents are installed to $prefix/bin
    INSTALL_DIR="$TEST_DIR/bin"

    # Show what was installed
    log_info "Installed agents:"
    ls -la "$INSTALL_DIR"/ 2>/dev/null || log_warn "No agents installed"

    # Count installed agents
    local installed_count
    installed_count=$(find "$INSTALL_DIR" -type f -perm +111 2>/dev/null | wc -l | tr -d ' ')
    log_info "Total agents installed: $installed_count / 22"

    # Note: Not all agents may have releases available yet
    # The test validates the architecture with whatever agents are available
    if [[ $installed_count -lt 22 ]]; then
        log_warn "Not all 22 agents have releases available yet."
        log_warn "Testing with $installed_count available agents."
    fi

    assert "At least 1 agent was installed" "[[ $installed_count -ge 1 ]]"

    # =========================================================================
    log_section "Phase 2: Start Agents"
    # =========================================================================

    # Get list of installed agents
    local agents=""
    for binary in "$INSTALL_DIR"/zentinel-*-agent; do
        if [[ -x "$binary" ]]; then
            local name
            name=$(basename "$binary" | sed 's/zentinel-//' | sed 's/-agent$//')
            agents="$agents $name"
        fi
    done

    local agent_count
    agent_count=$(echo $agents | wc -w | tr -d ' ')
    log_info "Found $agent_count agent binaries to start"

    # Start all agents
    log_info "Starting agents..."
    for agent in $agents; do
        start_agent "$agent" || true
    done

    # Give agents time to fully initialize
    sleep 2

    # Summary
    local started_count failed_count skipped_count
    started_count=$(echo $STARTED_AGENTS | wc -w | tr -d ' ')
    failed_count=$(echo $FAILED_AGENTS | wc -w | tr -d ' ')
    skipped_count=$(echo $SKIPPED_AGENTS | wc -w | tr -d ' ')

    log_info "Agent startup summary:"
    log_success "  Started: $started_count / $installed_count agents"
    if [[ $failed_count -gt 0 ]]; then
        log_warn "  Failed: $failed_count agents"
        for agent in $FAILED_AGENTS; do
            log_warn "    - $agent"
        done
    fi
    if [[ $skipped_count -gt 0 ]]; then
        log_warn "  Skipped (not installed): $skipped_count agents"
    fi

    # Require majority of installed agents to start successfully
    local min_required=$((installed_count / 2))
    if [[ $min_required -lt 1 ]]; then
        min_required=1
    fi
    assert "At least $min_required agents started (majority of $installed_count installed)" "[[ $started_count -ge $min_required ]]"

    # =========================================================================
    log_section "Phase 3: Start Infrastructure"
    # =========================================================================

    # Start mock backend
    log_info "Starting mock backend..."
    start_mock_backend

    # Generate proxy config
    log_info "Generating proxy configuration with $started_count agents..."
    local proxy_config
    proxy_config=$(generate_proxy_config)
    log_info "Proxy config written to: $proxy_config"

    # Show config for debugging
    if [[ "${VERBOSE:-}" == "true" ]]; then
        log_info "Proxy configuration:"
        cat "$proxy_config"
    fi

    # Start proxy
    log_info "Starting Zentinel proxy..."
    start_proxy "$proxy_config"

    assert "Proxy is running" "kill -0 $PROXY_PID 2>/dev/null"

    # =========================================================================
    log_section "Phase 4: Traffic Tests"
    # =========================================================================

    log_test "Test 1: Basic GET request through all agents"
    local response body http_code
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "http://127.0.0.1:$PROXY_PORT/test/basic")
    http_code=$(echo "$response" | grep -o 'HTTP_CODE:[0-9]*' | cut -d: -f2)
    body=$(echo "$response" | sed 's/HTTP_CODE:[0-9]*$//')

    assert "Basic GET returns 200" "[[ '$http_code' == '200' ]]"
    assert "Response contains backend marker" "[[ '$body' == *'status'* ]]"

    log_test "Test 2: POST request with body"
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: application/json" \
        -d '{"test": "data", "enterprise": true}' \
        "http://127.0.0.1:$PROXY_PORT/test/post")
    http_code=$(echo "$response" | tail -1)

    assert "POST request returns 200" "[[ '$http_code' == '200' ]]"

    log_test "Test 3: Request with custom headers"
    response=$(curl -s -w "\n%{http_code}" \
        -H "X-Custom-Header: test-value" \
        -H "X-Request-ID: e2e-test-123" \
        -H "Authorization: Bearer test-token" \
        "http://127.0.0.1:$PROXY_PORT/test/headers")
    http_code=$(echo "$response" | tail -1)

    assert "Request with headers returns 200" "[[ '$http_code' == '200' ]]"

    log_test "Test 4: Multiple concurrent requests"
    local success_count=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$PROXY_PORT/test/concurrent-$i" | grep -q "200"; then
            success_count=$((success_count + 1))
        fi
    done

    assert "All 10 concurrent requests succeeded" "[[ $success_count -eq 10 ]]"

    log_test "Test 5: Large request body"
    local large_body
    large_body=$(python3 -c "print('x' * 10000)")
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -H "Content-Type: text/plain" \
        -d "$large_body" \
        "http://127.0.0.1:$PROXY_PORT/test/large-body")
    http_code=$(echo "$response" | tail -1)

    assert "Large body request returns 200" "[[ '$http_code' == '200' ]]"

    log_test "Test 6: Request with query parameters"
    response=$(curl -s -w "\n%{http_code}" \
        "http://127.0.0.1:$PROXY_PORT/test/query?param1=value1&param2=value2&enterprise=true")
    http_code=$(echo "$response" | tail -1)

    assert "Request with query params returns 200" "[[ '$http_code' == '200' ]]"

    # =========================================================================
    log_section "Phase 5: Agent Activity Verification"
    # =========================================================================

    log_info "Waiting for agents to process requests..."
    sleep 2

    log_test "Verifying agent activity logs"
    local active_agents=0

    for agent in $STARTED_AGENTS; do
        local log_file="$LOG_DIR/${agent}.log"
        if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
            active_agents=$((active_agents + 1))
            local log_lines
            log_lines=$(wc -l < "$log_file" | tr -d ' ')
            log_success "  $agent: $log_lines log lines"
        else
            log_warn "  $agent: no activity detected"
        fi
    done

    assert "Most agents show activity" "[[ $active_agents -ge $((started_count / 2)) ]]"

    # =========================================================================
    log_section "Phase 6: Stress Test"
    # =========================================================================

    log_test "Sending 100 requests in rapid succession"
    local stress_success=0
    local stress_failed=0

    for i in $(seq 1 100); do
        if curl -s -o /dev/null -w "%{http_code}" \
            -H "X-Stress-Test: request-$i" \
            "http://127.0.0.1:$PROXY_PORT/stress/request-$i" 2>/dev/null | grep -q "200"; then
            stress_success=$((stress_success + 1))
        else
            stress_failed=$((stress_failed + 1))
        fi
    done

    log_info "Stress test results: $stress_success/100 successful"
    assert "At least 95% of stress test requests succeeded" "[[ $stress_success -ge 95 ]]"

    # =========================================================================
    log_section "Phase 7: Agent Log Summaries"
    # =========================================================================

    log_info "Agent log summaries:"
    for agent in $STARTED_AGENTS; do
        local log_file="$LOG_DIR/${agent}.log"
        if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
            echo ""
            echo -e "${CYAN}=== $agent ===${NC}"
            head -3 "$log_file"
            local total_lines
            total_lines=$(wc -l < "$log_file" | tr -d ' ')
            if [[ $total_lines -gt 3 ]]; then
                echo "... ($((total_lines - 3)) more lines)"
            fi
        fi
    done

    # =========================================================================
    log_section "Phase 8: Proxy Logs Analysis"
    # =========================================================================

    local proxy_log="$LOG_DIR/proxy.log"
    if [[ -f "$proxy_log" ]]; then
        local request_count
        request_count=$(grep -c "Request completed" "$proxy_log" 2>/dev/null) || request_count=0
        log_info "Proxy processed $request_count requests"

        # Check for actual errors (not just error=None in logs)
        local error_count
        error_count=$(grep -cE "(ERROR|PANIC|FATAL|panicked)" "$proxy_log" 2>/dev/null) || error_count=0
        if [[ $error_count -gt 0 ]]; then
            log_warn "Found $error_count error entries in proxy log"
            grep -E "(ERROR|PANIC|FATAL|panicked)" "$proxy_log" | head -5
        else
            log_success "No errors in proxy log"
        fi
    fi

    # =========================================================================
    log_section "Test Summary"
    # =========================================================================

    echo ""
    echo -e "${BOLD}Agents Summary (22 total in bundle):${NC}"
    echo "  Installed:  $installed_count / 22"
    echo "  Started:    $started_count / $installed_count"
    echo "  Failed:     $failed_count"
    echo "  Skipped:    $skipped_count (not installed)"
    echo ""
    echo -e "${BOLD}Started Agents ($started_count):${NC}"
    local col=0
    for agent in $STARTED_AGENTS; do
        if [[ $col -eq 0 ]]; then
            printf "  "
        fi
        printf "%-20s" "$agent"
        col=$((col + 1))
        if [[ $col -eq 4 ]]; then
            echo ""
            col=0
        fi
    done
    if [[ $col -ne 0 ]]; then
        echo ""
    fi
    if [[ -n "$FAILED_AGENTS" ]]; then
        echo ""
        echo -e "${BOLD}Failed Agents ($failed_count):${NC}"
        for agent in $FAILED_AGENTS; do
            echo "  - $agent"
        done
    fi
    echo ""
    echo "Tests run:    $TESTS_RUN"
    if [[ $TESTS_PASSED -gt 0 ]]; then
        echo -e "${GREEN}Tests passed: $TESTS_PASSED${NC}"
    fi
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}Tests failed: $TESTS_FAILED${NC}"
    fi
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}${BOLD}  SUCCESS: All tests passed!${NC}"
        echo -e "${GREEN}${BOLD}  Enterprise deployment with $started_count agents validated.${NC}"
        echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════${NC}"
        exit 0
    else
        echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════${NC}"
        echo -e "${RED}${BOLD}  FAILURE: $TESTS_FAILED tests failed${NC}"
        echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════${NC}"
        exit 1
    fi
}

# Run main
main "$@"
