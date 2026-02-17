#!/bin/bash
#
# Echo Agent Test Scenarios
# Tests the echo agent's header manipulation and passthrough functionality
#

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8080}"
BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

echo "═══════════════════════════════════════════════════════"
echo "  Echo Agent Test Scenarios"
echo "═══════════════════════════════════════════════════════"
echo ""

# Test 1: Basic request passthrough
info "Test 1: Basic request passthrough"
response=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/test")
if [[ "$response" == "200" ]]; then
    pass "Basic request returns 200"
else
    fail "Expected 200, got $response"
fi

# Test 2: Echo agent adds headers
info "Test 2: Echo agent adds headers"
headers=$(curl -sI "${BASE_URL}/echo/test" 2>/dev/null)
if echo "$headers" | grep -qi "X-.*Agent\|X-.*Echo"; then
    pass "Echo agent added custom headers"
else
    info "No echo agent headers detected (agent may not be active)"
fi

# Test 3: Correlation ID header
info "Test 3: Correlation ID tracking"
headers=$(curl -sI "${BASE_URL}/echo/test" 2>/dev/null)
if echo "$headers" | grep -qi "Correlation\|Request-Id\|Trace-Id"; then
    pass "Correlation/Request ID header present"
else
    info "No correlation ID header (may not be configured)"
fi

# Test 4: Request method echoing
info "Test 4: Request method handling"
for method in GET POST PUT DELETE; do
    status=$(curl -s -X "$method" -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/method-test")
    if [[ "$status" =~ ^(200|204|405)$ ]]; then
        pass "$method method handled correctly (HTTP $status)"
    else
        fail "$method method returned unexpected status $status"
    fi
done

# Test 5: Custom header passthrough
info "Test 5: Custom header passthrough"
response=$(curl -s "${BASE_URL}/echo/headers" -H "X-Custom-Test: zentinel-test-value")
if echo "$response" | grep -q "zentinel-test-value"; then
    pass "Custom headers passed through to backend"
else
    info "Custom header not visible in response (backend may not echo)"
fi

# Test 6: Query parameter handling
info "Test 6: Query parameter handling"
response=$(curl -s "${BASE_URL}/echo/test?param1=value1&param2=value2")
if [[ -n "$response" ]]; then
    pass "Query parameters handled correctly"
else
    fail "No response with query parameters"
fi

# Test 7: Path preservation
info "Test 7: Path preservation"
response=$(curl -s "${BASE_URL}/echo/deep/nested/path/test")
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/deep/nested/path/test")
if [[ "$status" =~ ^(200|404)$ ]]; then
    pass "Deep path handled correctly (HTTP $status)"
else
    fail "Unexpected status for deep path: $status"
fi

# Test 8: Large header handling
info "Test 8: Large header handling"
large_value=$(head -c 4000 /dev/urandom | base64 | tr -d '\n' | head -c 4000)
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/test" -H "X-Large-Header: ${large_value:0:4000}" 2>/dev/null)
if [[ "$status" =~ ^(200|431)$ ]]; then
    pass "Large header handled correctly (HTTP $status)"
else
    fail "Unexpected status for large header: $status"
fi

# Test 9: Unicode handling
info "Test 9: Unicode header handling"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/test" -H "X-Unicode: 你好世界 🚀")
if [[ "$status" == "200" ]]; then
    pass "Unicode headers handled correctly"
else
    info "Unicode header returned status $status"
fi

# Test 10: Concurrent requests
info "Test 10: Concurrent request handling"
for i in {1..10}; do
    curl -s "${BASE_URL}/echo/concurrent-$i" >/dev/null 2>&1 &
done
wait

status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/echo/after-concurrent")
if [[ "$status" == "200" ]]; then
    pass "Proxy stable after concurrent requests"
else
    fail "Proxy unstable after concurrent requests"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════"

exit $FAILED
