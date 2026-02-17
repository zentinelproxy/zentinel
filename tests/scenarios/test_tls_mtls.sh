#!/bin/bash
# mTLS Integration Tests
#
# Tests mutual TLS (client certificate authentication)
# using a running Zentinel instance with mTLS configured.
#
# Prerequisites:
# - Zentinel running with mTLS enabled (client_auth: true)
# - Test certificates from tests/fixtures/tls/
# - curl with client certificate support
#
# Usage: ./test_tls_mtls.sh [--proxy-url URL] [--mtls-url URL]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures/tls"

# Default configuration
PROXY_URL="${PROXY_URL:-https://localhost:8443}"
MTLS_URL="${MTLS_URL:-https://localhost:8444}"  # mTLS listener
CA_CERT="$FIXTURES_DIR/ca.crt"
CLIENT_CERT="$FIXTURES_DIR/client.crt"
CLIENT_KEY="$FIXTURES_DIR/client.key"
UNTRUSTED_CERT="$FIXTURES_DIR/untrusted.crt"
UNTRUSTED_KEY="$FIXTURES_DIR/untrusted.key"

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

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --proxy-url)
            PROXY_URL="$2"
            shift 2
            ;;
        --mtls-url)
            MTLS_URL="$2"
            shift 2
            ;;
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

# Check if prerequisites are available
check_prerequisites() {
    log_info "Checking prerequisites..."

    if ! command -v curl &> /dev/null; then
        log_fail "curl is required but not installed"
        exit 1
    fi

    if ! command -v openssl &> /dev/null; then
        log_fail "openssl is required but not installed"
        exit 1
    fi

    local missing=0
    for file in "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY"; do
        if [[ ! -f "$file" ]]; then
            log_fail "Required file not found: $file"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        log_info "Run tests/fixtures/tls/generate-certs.sh first"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Check proxy connectivity
check_connectivity() {
    if [[ "${SKIP_CONNECTIVITY:-0}" == "1" ]]; then
        log_skip "Connectivity check (--skip-connectivity)"
        return 1
    fi

    log_info "Checking mTLS endpoint at $MTLS_URL..."

    # Try to connect with client cert (allowing connection errors since mTLS might reject)
    if curl -sk --connect-timeout 5 \
        --cacert "$CA_CERT" \
        --cert "$CLIENT_CERT" \
        --key "$CLIENT_KEY" \
        "$MTLS_URL/health" &> /dev/null; then
        log_info "mTLS endpoint is reachable with client certificate"
        return 0
    else
        log_skip "mTLS endpoint not reachable at $MTLS_URL - skipping integration tests"
        return 1
    fi
}

# Test: mTLS connection with valid client certificate
test_mtls_with_valid_cert() {
    log_info "Testing mTLS with valid client certificate..."

    local response
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        --cacert "$CA_CERT" \
        --cert "$CLIENT_CERT" \
        --key "$CLIENT_KEY" \
        --connect-timeout 5 \
        "$MTLS_URL/health" 2>&1 || echo "error")

    if [[ "$status" == "200" ]]; then
        log_pass "mTLS connection succeeded with valid client certificate"
    elif [[ "$status" =~ ^[0-9]+$ ]]; then
        log_fail "mTLS returned unexpected status: $status"
    else
        log_fail "mTLS connection failed: $status"
    fi
}

# Test: mTLS connection fails without client certificate
test_mtls_fails_without_cert() {
    log_info "Testing mTLS fails without client certificate..."

    local response
    response=$(curl -s \
        --cacert "$CA_CERT" \
        --connect-timeout 5 \
        "$MTLS_URL/health" 2>&1 || true)

    # Connection should be rejected (SSL error or 4xx)
    if echo "$response" | grep -qiE "ssl|certificate|alert|handshake|4[0-9][0-9]"; then
        log_pass "mTLS correctly rejected request without client certificate"
    elif curl -s -o /dev/null -w "%{http_code}" \
        --cacert "$CA_CERT" \
        "$MTLS_URL/health" 2>/dev/null | grep -q "^4"; then
        log_pass "mTLS rejected request without client certificate (4xx)"
    else
        log_fail "mTLS should require client certificate but didn't: $response"
    fi
}

# Test: mTLS connection fails with untrusted certificate
test_mtls_fails_with_untrusted_cert() {
    log_info "Testing mTLS fails with untrusted client certificate..."

    if [[ ! -f "$UNTRUSTED_CERT" ]] || [[ ! -f "$UNTRUSTED_KEY" ]]; then
        log_skip "Untrusted certificate not available"
        return
    fi

    local response
    response=$(curl -s \
        --cacert "$CA_CERT" \
        --cert "$UNTRUSTED_CERT" \
        --key "$UNTRUSTED_KEY" \
        --connect-timeout 5 \
        "$MTLS_URL/health" 2>&1 || true)

    # Connection should be rejected (SSL error)
    if echo "$response" | grep -qiE "ssl|certificate|alert|handshake|unknown ca|verify"; then
        log_pass "mTLS correctly rejected untrusted client certificate"
    else
        # Check HTTP status
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" \
            --cacert "$CA_CERT" \
            --cert "$UNTRUSTED_CERT" \
            --key "$UNTRUSTED_KEY" \
            --connect-timeout 5 \
            "$MTLS_URL/health" 2>/dev/null || echo "error")

        if [[ "$status" =~ ^4 ]]; then
            log_pass "mTLS rejected untrusted certificate (HTTP $status)"
        else
            log_fail "mTLS should reject untrusted certificate: $response (status: $status)"
        fi
    fi
}

# Test: Client certificate DN extraction
test_client_dn_extraction() {
    log_info "Testing client certificate DN is accessible..."

    # This test checks if the proxy can extract client DN info
    # Implementation depends on how the proxy exposes this info
    # (headers, logs, etc.)

    local response
    response=$(curl -s \
        --cacert "$CA_CERT" \
        --cert "$CLIENT_CERT" \
        --key "$CLIENT_KEY" \
        -H "Accept: application/json" \
        "$MTLS_URL/debug/client-info" 2>&1 || true)

    if echo "$response" | grep -qi "test-client\|CN="; then
        log_pass "Client certificate DN is accessible"
    else
        log_skip "Client DN endpoint not available or not configured"
    fi
}

# Offline tests for certificate validation
run_offline_tests() {
    log_info "=== Offline Certificate Validation Tests ==="

    # Verify client certificate is signed by CA
    log_info "Verifying client certificate chain..."
    if openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" &>/dev/null; then
        log_pass "Client certificate is signed by CA"
    else
        log_fail "Client certificate is NOT signed by CA"
    fi

    # Verify client certificate has correct key usage
    log_info "Verifying client certificate key usage..."
    local key_usage
    key_usage=$(openssl x509 -in "$CLIENT_CERT" -noout -text 2>/dev/null | grep -A1 "Extended Key Usage" || true)

    if echo "$key_usage" | grep -qi "client"; then
        log_pass "Client certificate has clientAuth key usage"
    else
        log_skip "Client certificate key usage not verified (may still work)"
    fi

    # Verify client cert and key match
    log_info "Verifying client certificate and key match..."
    local cert_modulus key_modulus
    cert_modulus=$(openssl x509 -in "$CLIENT_CERT" -noout -modulus 2>/dev/null | md5)
    key_modulus=$(openssl rsa -in "$CLIENT_KEY" -noout -modulus 2>/dev/null | md5)

    if [[ "$cert_modulus" == "$key_modulus" ]]; then
        log_pass "Client certificate and key match"
    else
        log_fail "Client certificate and key do NOT match"
    fi

    # Verify untrusted cert is NOT signed by our CA
    if [[ -f "$UNTRUSTED_CERT" ]]; then
        log_info "Verifying untrusted certificate is not CA-signed..."
        if openssl verify -CAfile "$CA_CERT" "$UNTRUSTED_CERT" &>/dev/null; then
            log_fail "Untrusted certificate SHOULD NOT be verified by CA"
        else
            log_pass "Untrusted certificate correctly not verified by CA"
        fi
    fi

    # Check certificate expiration
    log_info "Checking certificate expiration..."
    if openssl x509 -in "$CLIENT_CERT" -noout -checkend 86400 2>/dev/null; then
        log_pass "Client certificate is valid for at least 24 hours"
    else
        log_fail "Client certificate expires within 24 hours"
    fi
}

# Main execution
main() {
    log_info "Starting mTLS Integration Tests"
    log_info "mTLS URL: $MTLS_URL"
    log_info "CA Certificate: $CA_CERT"
    log_info "Client Certificate: $CLIENT_CERT"
    echo ""

    check_prerequisites

    # Always run offline tests
    run_offline_tests
    echo ""

    if ! check_connectivity; then
        log_info ""
        log_info "mTLS endpoint not available - skipping online tests"
        print_summary
        exit $?
    fi

    echo ""
    log_info "=== mTLS Connection Tests ==="

    test_mtls_with_valid_cert
    test_mtls_fails_without_cert
    test_mtls_fails_with_untrusted_cert
    test_client_dn_extraction

    print_summary
}

main "$@"
