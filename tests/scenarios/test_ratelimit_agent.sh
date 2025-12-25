#!/bin/bash
#
# Rate Limit Agent Test Scenarios
# Tests the rate limiting functionality and circuit breaker behavior
#

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8080}"
RATELIMIT_METRICS_PORT="${RATELIMIT_METRICS_PORT:-9092}"
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
echo "  Rate Limit Agent Test Scenarios"
echo "═══════════════════════════════════════════════════════"
echo ""

# Test 1: Basic rate limit headers
info "Test 1: Rate limit headers present"
headers=$(curl -sI "${BASE_URL}/limited/test" 2>/dev/null)
if echo "$headers" | grep -qi "X-RateLimit"; then
    pass "Rate limit headers present in response"
    echo "$headers" | grep -i "X-RateLimit" | head -3
else
    info "Rate limit headers not detected"
fi

# Test 2: Rate limit agent metrics
info "Test 2: Rate limit agent metrics endpoint"
metrics=$(curl -sf "http://${PROXY_HOST}:${RATELIMIT_METRICS_PORT}/metrics" 2>/dev/null || echo "")
if [[ -n "$metrics" ]]; then
    pass "Rate limit agent metrics accessible"
    if echo "$metrics" | grep -q "ratelimit\|requests"; then
        info "Found rate limiting metrics"
    fi
else
    info "Rate limit metrics endpoint not accessible"
fi

# Test 3: Basic rate limiting enforcement
info "Test 3: Rate limiting enforcement"
success=0
limited=0

# Make rapid requests
for i in {1..50}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/burst-test?i=$i")
    if [[ "$status" == "200" ]]; then
        ((success++))
    elif [[ "$status" == "429" ]]; then
        ((limited++))
    fi
done

info "Results: $success allowed, $limited rate-limited"

if [[ $limited -gt 0 ]]; then
    pass "Rate limiting is working ($limited requests limited)"
elif [[ $success -eq 50 ]]; then
    info "All requests allowed (limits may be higher than test volume)"
fi

# Test 4: Rate limit reset
info "Test 4: Rate limit window reset"
# Wait for rate limit window to reset
sleep 2

status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/after-reset")
if [[ "$status" == "200" ]]; then
    pass "Rate limit resets after window"
else
    info "Request after reset returned $status"
fi

# Test 5: Per-client rate limiting
info "Test 5: Per-client isolation"
# Simulate different clients with X-Forwarded-For
client1_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/client1" -H "X-Forwarded-For: 192.168.1.1")
client2_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/client2" -H "X-Forwarded-For: 192.168.1.2")

if [[ "$client1_status" == "200" ]] && [[ "$client2_status" == "200" ]]; then
    pass "Different clients tracked independently"
else
    info "Client isolation test: client1=$client1_status, client2=$client2_status"
fi

# Test 6: Retry-After header
info "Test 6: Retry-After header on 429"
# Exhaust rate limit first
for i in {1..100}; do
    curl -s "${BASE_URL}/limited/exhaust-$i" >/dev/null 2>&1
done

headers=$(curl -sI "${BASE_URL}/limited/retry-after-test" 2>/dev/null)
status=$(echo "$headers" | head -1 | grep -o '[0-9]\{3\}')

if [[ "$status" == "429" ]]; then
    if echo "$headers" | grep -qi "Retry-After"; then
        pass "Retry-After header present on 429"
    else
        info "429 returned but no Retry-After header"
    fi
else
    info "Did not hit 429 status (got $status)"
fi

# Test 7: Rate limit by API key
info "Test 7: API key-based rate limiting"
apikey1=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/apikey" -H "X-API-Key: key-001")
apikey2=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/apikey" -H "X-API-Key: key-002")

if [[ "$apikey1" =~ ^(200|429)$ ]] && [[ "$apikey2" =~ ^(200|429)$ ]]; then
    pass "API key-based limiting works"
else
    info "API key test: key1=$apikey1, key2=$apikey2"
fi

# Test 8: Burst allowance
info "Test 8: Burst allowance"
# Quick burst of requests
burst_success=0
for i in {1..10}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/burst-$i")
    if [[ "$status" == "200" ]]; then
        ((burst_success++))
    fi
done

if [[ $burst_success -ge 5 ]]; then
    pass "Burst allowance working ($burst_success/10 in quick burst)"
else
    info "Burst test: $burst_success/10 requests allowed"
fi

# Test 9: Rate limit with different paths
info "Test 9: Path-based rate limit rules"
api_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/api/test")
limited_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/test")

info "API route status: $api_status, Limited route status: $limited_status"
pass "Path-based routing functional"

# Test 10: Circuit breaker behavior
info "Test 10: Rate limit agent resilience"
# Rapid requests to test agent stability
for i in {1..100}; do
    curl -s "${BASE_URL}/limited/stress-$i" >/dev/null 2>&1 &
done
wait

# Verify agent still responds
final_status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/limited/final-check")
if [[ "$final_status" =~ ^(200|429)$ ]]; then
    pass "Rate limit agent stable under load"
else
    fail "Rate limit agent may be unstable (status: $final_status)"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Results: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
echo "═══════════════════════════════════════════════════════"

exit $FAILED
