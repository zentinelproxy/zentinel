#!/bin/bash
# TLS SNI Integration Tests
#
# Tests Server Name Indication (SNI) certificate selection
# using a running Zentinel instance with HTTPS configured.
#
# Prerequisites:
# - Zentinel running with TLS configured
# - Test certificates from tests/fixtures/tls/
# - curl with SNI support
#
# Usage: ./test_tls_sni.sh [--proxy-url URL]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures/tls"

# Default configuration
PROXY_URL="${PROXY_URL:-https://localhost:8443}"
CA_CERT="$FIXTURES_DIR/ca.crt"

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

    if [[ ! -f "$CA_CERT" ]]; then
        log_fail "CA certificate not found: $CA_CERT"
        log_info "Run tests/fixtures/tls/generate-certs.sh first"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Check proxy connectivity
check_connectivity() {
    if [[ "${SKIP_CONNECTIVITY:-0}" == "1" ]]; then
        log_skip "Connectivity check (--skip-connectivity)"
        return 1  # Return 1 to skip online tests
    fi

    log_info "Checking proxy connectivity at $PROXY_URL..."

    # Try to connect (allowing self-signed cert for now)
    if curl -sk --connect-timeout 5 "$PROXY_URL/health" &> /dev/null; then
        log_info "Proxy is reachable"
        return 0
    else
        log_skip "Proxy not reachable at $PROXY_URL - skipping integration tests"
        return 1
    fi
}

# Test: Verify TLS connection with CA certificate
test_tls_with_ca_cert() {
    log_info "Testing TLS connection with CA certificate..."

    local response
    if response=$(curl -s --cacert "$CA_CERT" \
        --connect-timeout 5 \
        "$PROXY_URL/health" 2>&1); then
        log_pass "TLS connection succeeded with CA certificate"
    else
        log_fail "TLS connection failed: $response"
    fi
}

# Test: Verify TLS connection fails without CA cert (strict mode)
test_tls_fails_without_ca() {
    log_info "Testing TLS connection fails without CA cert (strict)..."

    # This should fail because we're using a self-signed cert
    if curl -s --connect-timeout 5 "$PROXY_URL/health" 2>&1 | grep -qi "certificate"; then
        log_pass "TLS correctly requires certificate verification"
    else
        log_skip "Cannot verify strict TLS (may have system CA installed)"
    fi
}

# Test: SNI selects correct certificate
test_sni_certificate_selection() {
    local hostname="$1"
    local expected_cn="$2"

    log_info "Testing SNI certificate selection for $hostname..."

    # Use openssl s_client to check the certificate
    local cert_info
    cert_info=$(echo | openssl s_client \
        -connect "${PROXY_URL#https://}" \
        -servername "$hostname" \
        -CAfile "$CA_CERT" \
        2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)

    if [[ -z "$cert_info" ]]; then
        log_fail "Could not retrieve certificate for SNI: $hostname"
        return
    fi

    if echo "$cert_info" | grep -qi "$expected_cn"; then
        log_pass "SNI '$hostname' returned correct certificate (CN=$expected_cn)"
    else
        log_fail "SNI '$hostname' returned wrong certificate. Expected CN containing '$expected_cn', got: $cert_info"
    fi
}

# Test: Wildcard certificate matching
test_wildcard_certificate() {
    local subdomain="$1"
    local expected_pattern="$2"

    log_info "Testing wildcard certificate for $subdomain..."

    local cert_info
    cert_info=$(echo | openssl s_client \
        -connect "${PROXY_URL#https://}" \
        -servername "$subdomain" \
        -CAfile "$CA_CERT" \
        2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)

    if [[ -z "$cert_info" ]]; then
        log_fail "Could not retrieve certificate for: $subdomain"
        return
    fi

    if echo "$cert_info" | grep -qi "$expected_pattern"; then
        log_pass "Wildcard certificate matched for '$subdomain'"
    else
        log_fail "Wildcard certificate not matched for '$subdomain'. Got: $cert_info"
    fi
}

# Test: Certificate chain verification
test_certificate_chain() {
    log_info "Testing certificate chain verification..."

    local verify_result
    verify_result=$(echo | openssl s_client \
        -connect "${PROXY_URL#https://}" \
        -CAfile "$CA_CERT" \
        2>&1 | grep -i "verify" | head -1 || true)

    if echo "$verify_result" | grep -qi "ok"; then
        log_pass "Certificate chain verified successfully"
    else
        log_fail "Certificate chain verification failed: $verify_result"
    fi
}

# Test: TLS protocol version
test_tls_version() {
    local min_version="${1:-TLSv1.2}"

    log_info "Testing TLS protocol version (minimum: $min_version)..."

    # Test that TLS 1.2+ is supported
    local protocol
    protocol=$(echo | openssl s_client \
        -connect "${PROXY_URL#https://}" \
        -tls1_2 \
        -CAfile "$CA_CERT" \
        2>/dev/null | grep -i "protocol" | head -1 || true)

    if echo "$protocol" | grep -qi "TLSv1.[23]"; then
        log_pass "TLS version is acceptable: $protocol"
    else
        log_fail "TLS version check failed: $protocol"
    fi
}

# Test: ALPN negotiation (HTTP/2)
test_alpn_negotiation() {
    log_info "Testing ALPN negotiation for HTTP/2..."

    local alpn_result
    alpn_result=$(echo | openssl s_client \
        -connect "${PROXY_URL#https://}" \
        -alpn h2,http/1.1 \
        -CAfile "$CA_CERT" \
        2>/dev/null | grep -i "ALPN" || true)

    if echo "$alpn_result" | grep -qi "h2\|http"; then
        log_pass "ALPN negotiation successful: $alpn_result"
    else
        log_skip "ALPN negotiation not available or no protocol selected"
    fi
}

# Main execution
main() {
    log_info "Starting TLS SNI Integration Tests"
    log_info "Proxy URL: $PROXY_URL"
    log_info "CA Certificate: $CA_CERT"
    echo ""

    check_prerequisites

    if ! check_connectivity; then
        log_info ""
        log_info "Proxy not available - running offline certificate tests only"
        echo ""

        # Run offline tests
        log_info "=== Offline Certificate Tests ==="

        # Verify certificates are valid
        log_info "Verifying test certificates..."

        for cert in "$FIXTURES_DIR"/server-*.crt; do
            if [[ -f "$cert" ]]; then
                if openssl x509 -in "$cert" -noout -checkend 0 2>/dev/null; then
                    log_pass "Certificate valid: $(basename "$cert")"
                else
                    log_fail "Certificate invalid or expired: $(basename "$cert")"
                fi
            fi
        done

        # Verify CA can verify server certs
        for cert in "$FIXTURES_DIR"/server-*.crt; do
            if [[ -f "$cert" ]]; then
                if openssl verify -CAfile "$CA_CERT" "$cert" &>/dev/null; then
                    log_pass "CA verified: $(basename "$cert")"
                else
                    log_fail "CA cannot verify: $(basename "$cert")"
                fi
            fi
        done

        # Verify client cert for mTLS
        if openssl verify -CAfile "$CA_CERT" "$FIXTURES_DIR/client.crt" &>/dev/null; then
            log_pass "Client certificate verified by CA"
        else
            log_fail "Client certificate not verified by CA"
        fi

        print_summary
        exit $?
    fi

    echo ""
    log_info "=== TLS Connection Tests ==="

    test_tls_with_ca_cert
    test_tls_fails_without_ca
    test_certificate_chain
    test_tls_version "TLSv1.2"
    test_alpn_negotiation

    echo ""
    log_info "=== SNI Certificate Selection Tests ==="

    # These tests assume specific SNI configuration in the proxy
    # Adjust hostnames based on actual config
    test_sni_certificate_selection "example.com" "example.com"
    test_sni_certificate_selection "api.example.com" "api.example.com"
    test_sni_certificate_selection "secure.example.com" "secure.example.com"

    echo ""
    log_info "=== Wildcard Certificate Tests ==="

    test_wildcard_certificate "foo.example.com" "example.com"
    test_wildcard_certificate "bar.example.com" "example.com"
    test_wildcard_certificate "sub.api.example.com" "example.com"

    print_summary
}

main "$@"
