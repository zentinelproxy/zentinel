#!/bin/bash
#
# WAF Agent Config Block End-to-End Test
# Tests that config blocks in KDL are sent to agents via Configure event
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WAF_AGENT_DIR="${WAF_AGENT_DIR:-$PROJECT_ROOT/../sentinel-agent-waf}"

PROXY_HOST="127.0.0.1"
PROXY_PORT="18080"
SOCKET_PATH="/tmp/sentinel-waf-e2e-test.sock"
BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}"
CONFIG_FILE="$PROJECT_ROOT/tests/fixtures/waf-config-block-test.kdl"

# PIDs for cleanup
WAF_PID=""
PROXY_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

cleanup() {
    info "Cleaning up..."
    [[ -n "$WAF_PID" ]] && kill "$WAF_PID" 2>/dev/null || true
    [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null || true
    rm -f "$SOCKET_PATH"
    wait 2>/dev/null || true
}

trap cleanup EXIT

echo "═══════════════════════════════════════════════════════"
echo "  WAF Config Block End-to-End Test"
echo "═══════════════════════════════════════════════════════"
echo ""

# Check prerequisites
if [[ ! -f "$PROJECT_ROOT/target/release/sentinel" ]]; then
    echo "Building sentinel proxy..."
    (cd "$PROJECT_ROOT" && cargo build --release -p sentinel-proxy)
fi

if [[ ! -f "$WAF_AGENT_DIR/target/release/sentinel-waf-agent" ]]; then
    echo "Building WAF agent..."
    (cd "$WAF_AGENT_DIR" && cargo build --release)
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    fail "Config file not found: $CONFIG_FILE"
    exit 1
fi

# Clean up any stale socket
rm -f "$SOCKET_PATH"

# Start WAF agent (no CLI config - will receive via Configure event)
info "Starting WAF agent (listening on $SOCKET_PATH)..."
RUST_LOG=info "$WAF_AGENT_DIR/target/release/sentinel-waf-agent" \
    --socket "$SOCKET_PATH" \
    2>&1 | sed 's/^/  [WAF] /' &
WAF_PID=$!

# Wait for socket to be created
for i in {1..30}; do
    if [[ -S "$SOCKET_PATH" ]]; then
        break
    fi
    sleep 0.1
done

if [[ ! -S "$SOCKET_PATH" ]]; then
    fail "WAF agent socket not created"
    exit 1
fi
pass "WAF agent started"

# Start proxy
info "Starting Sentinel proxy..."
RUST_LOG=info "$PROJECT_ROOT/target/release/sentinel" \
    --config "$CONFIG_FILE" \
    2>&1 | sed 's/^/  [PROXY] /' &
PROXY_PID=$!

# Wait for proxy to be ready
for i in {1..50}; do
    if curl -sf "http://${PROXY_HOST}:${PROXY_PORT}/" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

if ! curl -sf "http://${PROXY_HOST}:${PROXY_PORT}/" >/dev/null 2>&1; then
    fail "Proxy not responding"
    exit 1
fi
pass "Proxy started and responding"

echo ""
info "═══ Testing Config Block Applied ═══"
echo ""

# Test 1: Paranoia level 2 should detect SQL comments
# Config has paranoia-level 2, so SQL comments should be blocked
info "Test 1: SQL comment detection (paranoia level 2)"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?q=admin--" 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "SQL comment blocked (paranoia level 2 active)"
else
    fail "SQL comment not blocked (expected 403, got $status)"
fi

# Test 2: Classic SQLi should be blocked
info "Test 2: Classic SQL injection"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=' OR '1'='1" 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "SQL injection blocked"
else
    fail "SQL injection not blocked (expected 403, got $status)"
fi

# Test 3: XSS should be blocked
info "Test 3: XSS attack"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?x=<script>alert(1)</script>" 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "XSS blocked"
else
    fail "XSS not blocked (expected 403, got $status)"
fi

# Test 4: Path traversal should be blocked
info "Test 4: Path traversal"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/../../../etc/passwd" 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "Path traversal blocked"
else
    fail "Path traversal not blocked (expected 403, got $status)"
fi

# Test 5: Excluded paths should bypass WAF
# Config has exclude-paths "/health" "/metrics"
info "Test 5: Excluded path /health bypasses WAF"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health?id=' OR '1'='1" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "Excluded path bypasses WAF"
else
    # May get 404 if route doesn't exist, but shouldn't be 403
    if [[ "$status" != "403" ]]; then
        pass "Excluded path not blocked by WAF (status $status)"
    else
        fail "Excluded path was blocked (expected non-403, got $status)"
    fi
fi

# Test 6: Scanner detection (protocol rules)
info "Test 6: Scanner detection (sqlmap user agent)"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/" \
    -H "User-Agent: sqlmap/1.0" 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "Scanner user agent blocked"
else
    fail "Scanner not blocked (expected 403, got $status)"
fi

# Test 7: Legitimate request should pass
info "Test 7: Legitimate request allowed"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/api/users?page=1" 2>/dev/null || echo "000")
if [[ "$status" == "200" ]]; then
    pass "Legitimate request allowed"
else
    fail "Legitimate request blocked (expected 200, got $status)"
fi

# Test 8: Body inspection (SQLi in POST body)
info "Test 8: SQLi in POST body"
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/api" \
    -H "Content-Type: application/json" \
    -d '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}' 2>/dev/null || echo "000")
if [[ "$status" == "403" ]]; then
    pass "SQLi in body blocked"
else
    fail "SQLi in body not blocked (expected 403, got $status)"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Config Block Test Results"
echo "═══════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}Tests passed:${NC} $PASSED"
echo -e "  ${RED}Tests failed:${NC} $FAILED"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo -e "${GREEN}All tests passed! Config block is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Check the output above.${NC}"
    exit 1
fi
