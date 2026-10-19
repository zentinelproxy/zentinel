#!/bin/bash
#
# Mega Agent Smoke Test: All 26 Agents
#
# Validates that ALL 26 agents can build, start, connect to Zentinel,
# and handle basic HTTP traffic without errors. Catches build breakage,
# protocol mismatches, config errors, and startup crashes across the
# entire agent ecosystem in a single run.
#
# Every agent must pass — missing binaries, build failures, and startup
# failures are all test failures.
#
# Prerequisites:
# - Rust toolchain (cargo) with wasm32-unknown-unknown target
# - Haskell toolchain (cabal) for policy agent
# - Python 3
# - curl, nc, gh (GitHub CLI)
# - All 26 agent repos as siblings at $REPO_ROOT/..
#
# Usage:
#   ./tests/test_mega_agent.sh
#   ZENTINEL_BIN=./target/release/zentinel ./tests/test_mega_agent.sh
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

TEST_DIR="/tmp/zentinel-mega-agent-$$"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_ROOT="$REPO_ROOT/.."
ZENTINEL_BIN="${ZENTINEL_BIN:-}"

CONFIGS="$TEST_DIR/configs"
SCRIPTS="$TEST_DIR/scripts"
WASM="$TEST_DIR/wasm"
RULES="$TEST_DIR/rules"
POLICIES="$TEST_DIR/policies"
SOCKETS="$TEST_DIR/sockets"
LOGS="$TEST_DIR/logs"
BINDIR="$TEST_DIR/bin"
STATE="$TEST_DIR/state"

PROXY_PORT=""
BACKEND_PORT=""
METRICS_PORT=""
PROXY_PID=""
BACKEND_PID=""

SCRIPT_START=$(date +%s)
SCRIPT_TIMEOUT=${SCRIPT_TIMEOUT:-600}

# Test counters
TOTAL_AGENTS=26
BUILDS_OK=0
BUILDS_FAILED=0
STARTS_OK=0
STARTS_FAILED=0
REQUESTS_OK=0
REQUESTS_FAILED=0
LOGS_CLEAN=0
LOGS_DIRTY=0

CLEAN_HEADERS=(-H "User-Agent: ZentinelTest" -H "Accept: text/html")

# Platform detection for release downloads
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  PLATFORM="linux-x86_64" ;;
    aarch64) PLATFORM="linux-aarch64" ;;
    arm64)   PLATFORM="darwin-aarch64" ;;
    *)       PLATFORM="" ;;
esac

# ============================================================================
# Agent Registry (bash 3.2 compatible — no associative arrays)
# ============================================================================

AGENT_NAMES=(
    ai-gateway
    api-deprecation
    audit-logger
    auth
    bot-management
    chaos
    content-scanner
    denylist
    graphql-security
    grpc-inspector
    image-optimization
    ip-reputation
    js
    lua
    mock-server
    modsec
    mqtt-gateway
    policy
    ratelimit
    soap
    spiffe
    transform
    waf
    wasm
    websocket-inspector
    zentinelsec
)

agent_binary() {
    case "$1" in
        ai-gateway)            echo "zentinel-ai-gateway-agent" ;;
        api-deprecation)       echo "zentinel-api-deprecation-agent" ;;
        audit-logger)          echo "zentinel-audit-logger-agent" ;;
        auth)                  echo "zentinel-auth-agent" ;;
        bot-management)        echo "zentinel-bot-management-agent" ;;
        chaos)                 echo "zentinel-chaos-agent" ;;
        content-scanner)       echo "zentinel-content-scanner-agent" ;;
        denylist)              echo "zentinel-denylist-agent" ;;
        graphql-security)      echo "zentinel-graphql-security-agent" ;;
        grpc-inspector)        echo "zentinel-grpc-inspector-agent" ;;
        image-optimization)    echo "zentinel-image-optimization-agent" ;;
        ip-reputation)         echo "zentinel-ip-reputation-agent" ;;
        js)                    echo "zentinel-js-agent" ;;
        lua)                   echo "zentinel-lua-agent" ;;
        mock-server)           echo "zentinel-mock-server-agent" ;;
        modsec)                echo "zentinel-modsec-agent" ;;
        mqtt-gateway)          echo "zentinel-mqtt-gateway-agent" ;;
        policy)                echo "zentinel-policy-agent" ;;
        ratelimit)             echo "zentinel-ratelimit-agent" ;;
        soap)                  echo "zentinel-soap-agent" ;;
        spiffe)                echo "zentinel-spiffe-agent" ;;
        transform)             echo "zentinel-transform-agent" ;;
        waf)                   echo "zentinel-waf-agent" ;;
        wasm)                  echo "zentinel-wasm-agent" ;;
        websocket-inspector)   echo "zentinel-websocket-inspector-agent" ;;
        zentinelsec)           echo "zentinel-zentinelsec-agent" ;;
    esac
}

agent_transport() {
    case "$1" in
        content-scanner|grpc-inspector|js|soap|transform|wasm|zentinelsec) echo "grpc" ;;
        *) echo "uds" ;;
    esac
}

agent_events() {
    case "$1" in
        ai-gateway)          echo "request_headers request_body" ;;
        api-deprecation)     echo "request_headers response_headers" ;;
        audit-logger)        echo "request_headers request_body response_headers response_body" ;;
        auth)                echo "request_headers" ;;
        bot-management)      echo "request_headers" ;;
        chaos)               echo "request_headers response_headers response_body" ;;
        content-scanner)     echo "request_body" ;;
        denylist)            echo "request_headers" ;;
        graphql-security)    echo "request_headers request_body" ;;
        grpc-inspector)      echo "request_headers request_body" ;;
        image-optimization)  echo "request_headers response_headers response_body request_complete" ;;
        ip-reputation)       echo "request_headers" ;;
        js)                  echo "request_headers response_headers" ;;
        lua)                 echo "request_headers response_headers" ;;
        mock-server)         echo "request_headers request_body" ;;
        modsec)              echo "request_headers request_body response_headers response_body" ;;
        mqtt-gateway)        echo "request_body response_body" ;;
        policy)              echo "request_headers" ;;
        ratelimit)           echo "request_headers" ;;
        soap)                echo "request_headers request_body" ;;
        spiffe)              echo "request_headers" ;;
        transform)           echo "request_headers request_body response_headers response_body" ;;
        waf)                 echo "request_headers" ;;
        wasm)                echo "request_headers response_headers" ;;
        websocket-inspector) echo "request_headers response_headers request_body response_body" ;;
        zentinelsec)         echo "request_headers request_body response_headers response_body" ;;
    esac
}

# State helpers (file-based, bash 3.2 safe)
set_state()   { echo "$3" > "$STATE/$1.$2"; }
get_state()   { cat "$STATE/$1.$2" 2>/dev/null || echo "${3:-N/A}"; }
set_pid()     { echo "$2" > "$STATE/$1.pid"; }
get_pid()     { cat "$STATE/$1.pid" 2>/dev/null || echo ""; }
set_port()    { echo "$2" > "$STATE/$1.port"; }
get_port()    { cat "$STATE/$1.port" 2>/dev/null || echo ""; }

# ============================================================================
# Utility functions
# ============================================================================

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_failure() { echo -e "${RED}[FAIL]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }

log_phase() {
    echo ""
    echo -e "${CYAN}=======================================${NC}"
    echo -e "${CYAN} $1${NC}"
    echo -e "${CYAN}=======================================${NC}"
    echo ""
}

find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

check_timeout() {
    local now
    now=$(date +%s)
    local elapsed=$((now - SCRIPT_START))
    if [[ $elapsed -ge $SCRIPT_TIMEOUT ]]; then
        echo -e "${RED}[TIMEOUT]${NC} Script exceeded ${SCRIPT_TIMEOUT}s timeout"
        exit 1
    fi
}

# ============================================================================
# Cleanup
# ============================================================================

cleanup() {
    log_info "Cleaning up..."

    for name in "${AGENT_NAMES[@]}"; do
        local pid
        pid=$(get_pid "$name")
        [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null || true
    done
    [[ -n "$PROXY_PID" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -TERM "$BACKEND_PID" 2>/dev/null || true

    sleep 1

    for name in "${AGENT_NAMES[@]}"; do
        local pid
        pid=$(get_pid "$name")
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    [[ -n "$PROXY_PID" ]] && kill -9 "$PROXY_PID" 2>/dev/null || true
    [[ -n "$BACKEND_PID" ]] && kill -9 "$BACKEND_PID" 2>/dev/null || true

    rm -rf "$TEST_DIR"
}

trap cleanup EXIT INT TERM

# ============================================================================
# Phase 1: Build all agents
# ============================================================================

build_zentinel() {
    if [[ -z "$ZENTINEL_BIN" ]]; then
        if [[ -f "$REPO_ROOT/target/release/zentinel" ]]; then
            ZENTINEL_BIN="$REPO_ROOT/target/release/zentinel"
            log_info "Using existing Zentinel binary: $ZENTINEL_BIN"
        else
            log_info "Building Zentinel proxy (release)..."
            (cd "$REPO_ROOT" && cargo build --release --bin zentinel)
            ZENTINEL_BIN="$REPO_ROOT/target/release/zentinel"
        fi
    fi

    if [[ ! -f "$ZENTINEL_BIN" ]]; then
        log_failure "Zentinel binary not found at $ZENTINEL_BIN"
        exit 1
    fi
}

build_wasm_module() {
    local wasm_example="$AGENT_ROOT/zentinel-agent-wasm/examples/wasm-module"

    if [[ ! -d "$wasm_example" ]]; then
        log_failure "  wasm module: example dir not found"
        return 1
    fi

    if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
        log_info "  wasm module: installing wasm32-unknown-unknown target..."
        rustup target add wasm32-unknown-unknown
    fi

    local wasm_output="$wasm_example/target/wasm32-unknown-unknown/release/example_wasm_module.wasm"
    if [[ ! -f "$wasm_output" ]]; then
        log_info "  wasm module: building..."
        if ! (cd "$wasm_example" && cargo build --target wasm32-unknown-unknown --release 2>"$LOGS/wasm-module-build.log"); then
            log_failure "  wasm module: build failed"
            tail -5 "$LOGS/wasm-module-build.log" 2>/dev/null || true
            return 1
        fi
    fi

    cp "$wasm_output" "$WASM/passthrough.wasm"
    log_info "  wasm module: ready"
}

download_agent() {
    local name="$1"
    local binary
    binary=$(agent_binary "$name")
    local repo_slug="zentinelproxy/zentinel-agent-$name"

    [[ -z "$PLATFORM" ]] && return 1

    local tag
    tag=$(gh release list --repo "$repo_slug" --limit 1 --json tagName --jq '.[0].tagName' 2>/dev/null) || return 1
    [[ -z "$tag" ]] && return 1

    local version="${tag#v}"
    local asset="${binary}-${version}-${PLATFORM}.tar.gz"

    log_info "  $name: downloading $asset..."
    if gh release download "$tag" --repo "$repo_slug" --pattern "$asset" --dir "$BINDIR" --clobber 2>/dev/null; then
        (cd "$BINDIR" && tar xzf "$asset" && rm -f "$asset")
        if [[ -f "$BINDIR/$binary" ]]; then
            chmod +x "$BINDIR/$binary"
            return 0
        fi
    fi
    return 1
}

build_agent() {
    local name="$1"
    local binary
    binary=$(agent_binary "$name")
    local repo="$AGENT_ROOT/zentinel-agent-$name"

    # 1) Already built locally? Prefer local builds — they have the latest
    #    protocol changes. Downloaded release binaries may be stale.
    if [[ "$name" == "policy" ]]; then
        local policy_bin
        policy_bin=$(cd "$repo" 2>/dev/null && cabal list-bin "$binary" 2>/dev/null || true)
        if [[ -n "$policy_bin" && -f "$policy_bin" ]]; then
            log_info "  $name: using existing cabal binary"
            set_state "$name" build "OK"
            BUILDS_OK=$((BUILDS_OK + 1))
            return 0
        fi
    elif [[ -f "$repo/target/release/$binary" ]]; then
        log_info "  $name: using existing binary"
        set_state "$name" build "OK"
        BUILDS_OK=$((BUILDS_OK + 1))
        return 0
    fi

    # 2) Build from source if repo exists
    if [[ -d "$repo" ]]; then
        if [[ "$name" == "policy" ]]; then
            log_info "  $name: building with cabal..."
            if (cd "$repo" && cabal build 2>"$LOGS/$name-build.log"); then
                set_state "$name" build "OK"
                BUILDS_OK=$((BUILDS_OK + 1))
            else
                log_failure "  $name: cabal build failed"
                tail -5 "$LOGS/$name-build.log" 2>/dev/null || true
                set_state "$name" build "FAIL"
                BUILDS_FAILED=$((BUILDS_FAILED + 1))
                return 1
            fi
            return 0
        fi

        log_info "  $name: building from source..."
        if (cd "$repo" && cargo build --release 2>"$LOGS/$name-build.log"); then
            set_state "$name" build "OK"
            BUILDS_OK=$((BUILDS_OK + 1))
            return 0
        else
            log_failure "  $name: cargo build failed"
            tail -5 "$LOGS/$name-build.log" 2>/dev/null || true
            set_state "$name" build "FAIL"
            BUILDS_FAILED=$((BUILDS_FAILED + 1))
            return 1
        fi
    fi

    # 3) No local repo — try downloading from GitHub release
    if download_agent "$name"; then
        log_success "  $name: downloaded from release"
        set_state "$name" build "OK"
        BUILDS_OK=$((BUILDS_OK + 1))
        return 0
    fi

    log_failure "  $name: no local repo and no release available"
    set_state "$name" build "FAIL"
    BUILDS_FAILED=$((BUILDS_FAILED + 1))
    return 1
}

build_all() {
    log_phase "Phase 1: Build all agents"

    build_zentinel
    build_wasm_module || true

    for name in "${AGENT_NAMES[@]}"; do
        check_timeout
        build_agent "$name" || true
    done

    log_info "Build results: $BUILDS_OK OK, $BUILDS_FAILED failed"
}

# ============================================================================
# Phase 2: Generate configs and stub files
# ============================================================================

generate_stubs() {
    log_phase "Phase 2: Generate configs and stub files"

    mkdir -p "$CONFIGS" "$SCRIPTS/lua" "$WASM" "$RULES" "$POLICIES" "$SOCKETS" "$LOGS" "$BINDIR" "$STATE"

    # --- YAML config stubs ---

    cat > "$CONFIGS/api-deprecation.yaml" <<'YAML'
endpoints: []
YAML

    cat > "$CONFIGS/audit-logger.yaml" <<YAML
output:
  type: file
  path: "$TEST_DIR/audit.log"
YAML

    cat > "$CONFIGS/chaos.yaml" <<'YAML'
faults: []
YAML

    cat > "$CONFIGS/content-scanner.yaml" <<'YAML'
rules: []
YAML

    cat > "$CONFIGS/graphql-security.yaml" <<'YAML'
max_depth: 10
max_aliases: 5
YAML

    cat > "$CONFIGS/grpc-inspector.yaml" <<'YAML'
settings:
  fail_action: allow
  debug_headers: false
  log_blocked: true
  log_allowed: false
YAML

    cat > "$CONFIGS/image-optimization.json" <<JSON
{
  "formats": ["webp"],
  "quality": {"webp": 80},
  "max_input_size_bytes": 10485760,
  "max_pixel_count": 25000000,
  "eligible_content_types": ["image/jpeg", "image/png"],
  "passthrough_patterns": [],
  "cache": {
    "enabled": false
  }
}
JSON

    cat > "$CONFIGS/ip-reputation.yaml" <<'YAML'
providers: []
YAML

    cat > "$CONFIGS/mock-server.yaml" <<'YAML'
stubs: []
YAML

    cat > "$CONFIGS/soap.yaml" <<'YAML'
services: []
YAML

    cat > "$CONFIGS/transform.yaml" <<'YAML'
rules: []
YAML

    # --- Script stubs ---

    cat > "$SCRIPTS/passthrough.js" <<'JS'
function on_request_headers(headers) { return { action: "continue" }; }
function on_response_headers(headers) { return { action: "continue" }; }
JS

    cat > "$SCRIPTS/lua/passthrough.lua" <<'LUA'
function on_request_headers(headers)
  return { action = "continue" }
end
function on_response_headers(headers)
  return { action = "continue" }
end
LUA

    # --- ModSecurity rules ---

    cat > "$RULES/minimal.conf" <<'CONF'
SecRuleEngine On
CONF

    # --- Cedar policy ---

    cat > "$POLICIES/policy.cedar" <<'CEDAR'
permit(principal, action, resource);
CEDAR

    # --- Backend content ---

    mkdir -p "$TEST_DIR/www"
    echo "<html><body>Hello from backend</body></html>" > "$TEST_DIR/www/index.html"

    log_info "Stub files generated"
}

# ============================================================================
# Phase 3: Start backend + all agents
# ============================================================================

start_backend() {
    BACKEND_PORT=$(find_free_port)
    python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(b'<html><body>OK</body></html>')
    do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1',$BACKEND_PORT),H).serve_forever()
" > "$LOGS/backend.log" 2>&1 &
    BACKEND_PID=$!

    local retries=10
    while ! curl -sf "http://127.0.0.1:$BACKEND_PORT/" >/dev/null 2>&1; do
        sleep 0.5
        retries=$((retries - 1))
        if [[ $retries -eq 0 ]]; then
            log_failure "Backend failed to start"
            return 1
        fi
    done
    log_info "Backend started on port $BACKEND_PORT (PID: $BACKEND_PID)"
}

get_agent_bin_path() {
    local name="$1"
    local binary
    binary=$(agent_binary "$name")
    local repo="$AGENT_ROOT/zentinel-agent-$name"

    # Prefer local builds over downloaded binaries
    if [[ "$name" == "policy" ]]; then
        (cd "$repo" 2>/dev/null && cabal list-bin "$binary" 2>/dev/null) || echo ""
    elif [[ -f "$repo/target/release/$binary" ]]; then
        echo "$repo/target/release/$binary"
    elif [[ -f "$BINDIR/$binary" ]]; then
        echo "$BINDIR/$binary"
    else
        echo "$repo/target/release/$binary"
    fi
}

build_agent_args() {
    local name="$1"
    local transport
    transport=$(agent_transport "$name")
    local socket_path="$SOCKETS/$name.sock"

    # Transport args
    if [[ "$transport" == "uds" ]]; then
        case "$name" in
            api-deprecation|audit-logger|bot-management|chaos|denylist|\
            graphql-security|grpc-inspector|image-optimization|ip-reputation|\
            mock-server|mqtt-gateway|policy|ratelimit|soap)
                echo "-s $socket_path"
                ;;
            *)
                echo "--socket $socket_path"
                ;;
        esac
    else
        local port
        port=$(find_free_port)
        set_port "$name" "$port"
        echo "--grpc-address 127.0.0.1:$port"
    fi

    # Agent-specific extra args
    case "$name" in
        ai-gateway)       echo "--fail-open" ;;
        api-deprecation)  echo "-c $CONFIGS/api-deprecation.yaml" ;;
        audit-logger)     echo "-c $CONFIGS/audit-logger.yaml" ;;
        auth)             echo "--jwt-secret test-secret --fail-open" ;;
        chaos)            echo "-c $CONFIGS/chaos.yaml" ;;
        content-scanner)  echo "--config $CONFIGS/content-scanner.yaml" ;;
        graphql-security) echo "--config $CONFIGS/graphql-security.yaml" ;;
        grpc-inspector)   echo "-c $CONFIGS/grpc-inspector.yaml" ;;
        image-optimization) echo "-c $CONFIGS/image-optimization.json" ;;
        ip-reputation)    echo "-c $CONFIGS/ip-reputation.yaml" ;;
        js)               echo "--script $SCRIPTS/passthrough.js --fail-open" ;;
        lua)              echo "--script $SCRIPTS/lua/passthrough.lua" ;;
        mock-server)      echo "-c $CONFIGS/mock-server.yaml" ;;
        modsec)           echo "--rules $RULES/minimal.conf" ;;
        policy)           echo "--engine cedar --policy-dir $POLICIES" ;;
        ratelimit)        echo "--default-rps 100 --default-burst 200" ;;
        soap)             echo "--config $CONFIGS/soap.yaml" ;;
        transform)        echo "--config $CONFIGS/transform.yaml" ;;
        waf)              echo "--paranoia-level 1" ;;
        wasm)             echo "--module $WASM/passthrough.wasm --fail-open" ;;
    esac
}

start_agent() {
    local name="$1"

    if [[ "$(get_state "$name" build)" != "OK" ]]; then
        set_state "$name" start "SKIP"
        STARTS_FAILED=$((STARTS_FAILED + 1))
        return 1
    fi

    local bin_path
    bin_path=$(get_agent_bin_path "$name")

    if [[ -z "$bin_path" || ! -f "$bin_path" ]]; then
        log_failure "  $name: binary not found"
        set_state "$name" start "FAIL"
        STARTS_FAILED=$((STARTS_FAILED + 1))
        return 1
    fi

    local log_file="$LOGS/$name.log"
    local transport
    transport=$(agent_transport "$name")

    # Build args (this also sets port for grpc agents)
    local args_str
    args_str=$(build_agent_args "$name")

    # Start agent process
    # shellcheck disable=SC2086
    RUST_LOG=info "$bin_path" $args_str > "$log_file" 2>&1 &
    local agent_pid=$!
    set_pid "$name" "$agent_pid"

    # Wait for agent to be ready
    local retries=20
    if [[ "$transport" == "uds" ]]; then
        local socket_path="$SOCKETS/$name.sock"
        while [[ ! -S "$socket_path" ]] && [[ $retries -gt 0 ]]; do
            if ! kill -0 "$agent_pid" 2>/dev/null; then
                log_failure "  $name: process died during startup"
                tail -20 "$log_file"
                set_state "$name" start "FAIL"
                STARTS_FAILED=$((STARTS_FAILED + 1))
                return 1
            fi
            sleep 0.5
            retries=$((retries - 1))
        done

        if [[ -S "$socket_path" ]]; then
            log_success "  $name: started (UDS, PID $agent_pid)"
            set_state "$name" start "OK"
            STARTS_OK=$((STARTS_OK + 1))
        else
            log_failure "  $name: socket not created after 10s"
            tail -20 "$log_file"
            set_state "$name" start "FAIL"
            STARTS_FAILED=$((STARTS_FAILED + 1))
            return 1
        fi
    else
        local port
        port=$(get_port "$name")
        while ! nc -z 127.0.0.1 "$port" 2>/dev/null && [[ $retries -gt 0 ]]; do
            if ! kill -0 "$agent_pid" 2>/dev/null; then
                log_failure "  $name: process died during startup"
                tail -20 "$log_file"
                set_state "$name" start "FAIL"
                STARTS_FAILED=$((STARTS_FAILED + 1))
                return 1
            fi
            sleep 0.5
            retries=$((retries - 1))
        done

        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            log_success "  $name: started (gRPC :$port, PID $agent_pid)"
            set_state "$name" start "OK"
            STARTS_OK=$((STARTS_OK + 1))
        else
            log_failure "  $name: port $port not listening after 10s"
            tail -20 "$log_file"
            set_state "$name" start "FAIL"
            STARTS_FAILED=$((STARTS_FAILED + 1))
            return 1
        fi
    fi
}

start_all_agents() {
    log_phase "Phase 3: Start backend + all agents"

    start_backend || exit 1

    for name in "${AGENT_NAMES[@]}"; do
        check_timeout
        start_agent "$name" || true
    done

    log_info "Start results: $STARTS_OK OK, $STARTS_FAILED failed"
}

# ============================================================================
# Phase 4: Generate KDL config and start Zentinel
# ============================================================================

generate_kdl_config() {
    PROXY_PORT=$(find_free_port)
    METRICS_PORT=$(find_free_port)

    local config_file="$TEST_DIR/config.kdl"

    cat > "$config_file" <<EOF
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

EOF

    # Agents block
    echo "agents {" >> "$config_file"
    for name in "${AGENT_NAMES[@]}"; do
        [[ "$(get_state "$name" start)" != "OK" ]] && continue

        local transport events
        transport=$(agent_transport "$name")
        events=$(agent_events "$name")

        echo "    agent \"$name-agent\" type=\"custom\" {" >> "$config_file"

        if [[ "$transport" == "uds" ]]; then
            echo "        unix-socket \"$SOCKETS/$name.sock\"" >> "$config_file"
        else
            local port
            port=$(get_port "$name")
            echo "        grpc \"http://127.0.0.1:$port\"" >> "$config_file"
        fi

        printf "        events" >> "$config_file"
        for event in $events; do
            printf " \"%s\"" "$event" >> "$config_file"
        done
        echo "" >> "$config_file"

        echo "        timeout-ms 500" >> "$config_file"
        echo "        failure-mode \"open\"" >> "$config_file"
        echo "    }" >> "$config_file"
    done
    echo "}" >> "$config_file"
    echo "" >> "$config_file"

    # Filters block — each agent gets a filter that wires it to routes
    echo "filters {" >> "$config_file"
    for name in "${AGENT_NAMES[@]}"; do
        [[ "$(get_state "$name" start)" != "OK" ]] && continue

        cat >> "$config_file" <<EOF
    filter "$name-filter" {
        type "agent"
        agent "$name-agent"
        timeout-ms 500
        failure-mode "open"
    }
EOF
    done
    echo "}" >> "$config_file"
    echo "" >> "$config_file"

    # Routes block
    echo "routes {" >> "$config_file"

    cat >> "$config_file" <<'EOF'
    route "control" {
        priority "high"
        matches {
            path-prefix "/control/"
        }
        upstream "test-backend"
    }
EOF

    for name in "${AGENT_NAMES[@]}"; do
        [[ "$(get_state "$name" start)" != "OK" ]] && continue

        cat >> "$config_file" <<EOF
    route "test-$name" {
        priority "high"
        matches {
            path-prefix "/test-$name/"
        }
        upstream "test-backend"
        filters "$name-filter"
    }
EOF
    done

    cat >> "$config_file" <<'EOF'
    route "default" {
        priority "low"
        matches {
            path-prefix "/"
        }
        upstream "test-backend"
    }
}
EOF

    cat >> "$config_file" <<EOF

upstreams {
    upstream "test-backend" {
        target "127.0.0.1:$BACKEND_PORT" weight=1
        load-balancing "round_robin"
    }
}

limits {
    max-header-count 100
    max-header-size 8192
    max-body-size 1048576
}

observability {
    metrics {
        enabled #true
        address "127.0.0.1:$METRICS_PORT"
        path "/metrics"
    }
    logging {
        level "info"
        format "json"
    }
}
EOF

    log_info "KDL config generated at $config_file"
}

start_zentinel() {
    log_phase "Phase 4: Generate KDL config and start Zentinel"

    generate_kdl_config

    log_info "Starting Zentinel proxy (port $PROXY_PORT)..."

    RUST_LOG=info ZENTINEL_CONFIG="$TEST_DIR/config.kdl" \
        "$ZENTINEL_BIN" > "$LOGS/proxy.log" 2>&1 &
    PROXY_PID=$!

    local retries=20
    while ! curl -s -o /dev/null -w "%{http_code}" "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/" 2>/dev/null | grep -qv "000"; do
        sleep 0.5
        retries=$((retries - 1))
        if [[ $retries -eq 0 ]]; then
            log_failure "Zentinel failed to start"
            tail -30 "$LOGS/proxy.log"
            exit 1
        fi
    done

    log_info "Zentinel started on port $PROXY_PORT (PID: $PROXY_PID)"
}

# ============================================================================
# Phase 5: Send requests and validate
# ============================================================================

send_requests() {
    log_phase "Phase 5: Send requests and validate"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/control/" || echo "000")

    if [[ "$status" == "200" ]]; then
        log_success "  control: $status"
    else
        log_failure "  control: $status (expected 200)"
    fi

    for name in "${AGENT_NAMES[@]}"; do
        if [[ "$(get_state "$name" start)" != "OK" ]]; then
            set_state "$name" request "SKIP"
            REQUESTS_FAILED=$((REQUESTS_FAILED + 1))
            continue
        fi

        check_timeout

        status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
            "${CLEAN_HEADERS[@]}" "http://127.0.0.1:$PROXY_PORT/test-$name/" || echo "000")

        if [[ "$status" == "200" ]]; then
            log_success "  $name: $status"
            set_state "$name" request "OK"
            REQUESTS_OK=$((REQUESTS_OK + 1))
        else
            log_failure "  $name: $status (expected 200)"
            set_state "$name" request "FAIL($status)"
            REQUESTS_FAILED=$((REQUESTS_FAILED + 1))
        fi
    done

    log_info "Request results: $REQUESTS_OK OK, $REQUESTS_FAILED failed"
}

# ============================================================================
# Phase 6: Scan logs for errors
# ============================================================================

scan_logs() {
    log_phase "Phase 6: Scan logs for errors"

    local error_pattern='ERROR|FATAL|panic|SIGSEGV|thread.*panicked'
    local any_dirty=false

    for name in "${AGENT_NAMES[@]}"; do
        local log_file="$LOGS/$name.log"
        if [[ ! -f "$log_file" ]]; then
            set_state "$name" log "N/A"
            continue
        fi

        local matches
        matches=$(grep -cE "$error_pattern" "$log_file" 2>/dev/null) || true

        if [[ "$matches" -gt 0 ]]; then
            log_failure "  $name: $matches error(s) in log"
            grep -E "$error_pattern" "$log_file" | head -5
            set_state "$name" log "DIRTY"
            LOGS_DIRTY=$((LOGS_DIRTY + 1))
            any_dirty=true
        else
            set_state "$name" log "CLEAN"
            LOGS_CLEAN=$((LOGS_CLEAN + 1))
        fi
    done

    if [[ -f "$LOGS/proxy.log" ]]; then
        local matches
        matches=$(grep -cE "$error_pattern" "$LOGS/proxy.log" 2>/dev/null) || true
        if [[ "$matches" -gt 0 ]]; then
            log_failure "  proxy: $matches error(s) in log"
            grep -E "$error_pattern" "$LOGS/proxy.log" | head -5
            any_dirty=true
        else
            log_success "  proxy: clean"
        fi
    fi

    if [[ "$any_dirty" == "false" ]]; then
        log_info "All logs clean"
    fi
}

# ============================================================================
# Phase 7: Summary
# ============================================================================

print_summary() {
    log_phase "Phase 7: Summary"

    printf "\n%-25s %-8s %-8s %-12s %-8s\n" \
        "Agent" "Build" "Start" "Request" "Logs"
    printf "%-25s %-8s %-8s %-12s %-8s\n" \
        "-------------------------" "--------" "--------" "------------" "--------"

    local all_pass=true

    for name in "${AGENT_NAMES[@]}"; do
        local build start request logs
        build=$(get_state "$name" build)
        start=$(get_state "$name" start)
        request=$(get_state "$name" request)
        logs=$(get_state "$name" log)

        local bc sc rc lc
        [[ "$build" == "OK" ]]   && bc="$GREEN" || bc="$RED"
        [[ "$start" == "OK" ]]   && sc="$GREEN" || sc="$RED"
        [[ "$request" == "OK" ]] && rc="$GREEN" || rc="$RED"
        if [[ "$logs" == "CLEAN" ]]; then
            lc="$GREEN"
        elif [[ "$logs" == "N/A" ]]; then
            lc="$YELLOW"
        else
            lc="$RED"
        fi

        printf "%-25s ${bc}%-8s${NC} ${sc}%-8s${NC} ${rc}%-12s${NC} ${lc}%-8s${NC}\n" \
            "$name" "$build" "$start" "$request" "$logs"

        if [[ "$build" != "OK" || "$start" != "OK" || "$request" != "OK" || "$logs" == "DIRTY" ]]; then
            all_pass=false
        fi
    done

    echo
    echo "==========================================="
    echo "Totals"
    echo "==========================================="
    echo "Agents:   $TOTAL_AGENTS"
    echo "Built:    $BUILDS_OK OK, $BUILDS_FAILED failed"
    echo "Started:  $STARTS_OK OK, $STARTS_FAILED failed"
    echo "Requests: $REQUESTS_OK OK, $REQUESTS_FAILED failed"
    echo "Logs:     $LOGS_CLEAN clean, $LOGS_DIRTY dirty"
    echo

    if [[ "$all_pass" == "true" ]]; then
        echo -e "${GREEN}All $TOTAL_AGENTS agents passed!${NC}"
        return 0
    else
        echo -e "${RED}Some agents failed!${NC}"
        echo
        echo "Logs directory: $LOGS"
        echo "Config file:    $TEST_DIR/config.kdl"
        return 1
    fi
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo "==========================================="
    echo "Mega Agent Smoke Test (all $TOTAL_AGENTS agents)"
    echo "==========================================="

    mkdir -p "$TEST_DIR" "$LOGS" "$STATE"

    generate_stubs
    build_all

    if [[ $BUILDS_FAILED -gt 0 ]]; then
        log_warn "$BUILDS_FAILED agent(s) failed to build — continuing with remaining agents"
    fi

    start_all_agents

    if [[ $STARTS_OK -eq 0 ]]; then
        log_failure "No agents started successfully — aborting"
        exit 1
    fi

    start_zentinel

    sleep 2

    send_requests
    scan_logs

    if print_summary; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
