#!/bin/bash
# TLS Certificate Rotation Tests
#
# Tests hot-reload of TLS certificates via SIGHUP signal.
# Verifies that Zentinel picks up new certificates without restart.
#
# Prerequisites:
# - Zentinel binary built
# - Test certificates from tests/fixtures/tls/
# - curl and openssl installed
#
# Usage: ./test_tls_cert_rotation.sh [--skip-connectivity]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures/tls"
ZENTINEL_BIN="${ZENTINEL_BIN:-$PROJECT_ROOT/target/debug/zentinel}"

# Test configuration
TEST_PORT="${TEST_PORT:-18443}"
PROXY_URL="https://localhost:$TEST_PORT"
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

# Cleanup tracking
ZENTINEL_PID=""
TEMP_DIR=""

# Parse arguments
SKIP_CONNECTIVITY="${SKIP_CONNECTIVITY:-0}"
while [[ $# -gt 0 ]]; do
    case $1 in
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

cleanup() {
    log_info "Cleaning up..."
    if [[ -n "$ZENTINEL_PID" ]] && kill -0 "$ZENTINEL_PID" 2>/dev/null; then
        kill "$ZENTINEL_PID" 2>/dev/null || true
        wait "$ZENTINEL_PID" 2>/dev/null || true
    fi
    if [[ -n "$TEMP_DIR" ]] && [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

trap cleanup EXIT

# Check prerequisites
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

    if [[ ! -f "$ZENTINEL_BIN" ]]; then
        log_info "Building Zentinel..."
        cargo build --package zentinel --quiet
    fi

    if [[ ! -f "$ZENTINEL_BIN" ]]; then
        log_fail "Zentinel binary not found: $ZENTINEL_BIN"
        exit 1
    fi

    if [[ ! -f "$CA_CERT" ]]; then
        log_fail "CA certificate not found: $CA_CERT"
        log_info "Run tests/fixtures/tls/generate-certs.sh first"
        exit 1
    fi

    log_info "Prerequisites OK"
}

# Setup test environment with temporary cert files
setup_temp_certs() {
    log_info "Setting up temporary certificate directory..."

    TEMP_DIR=$(mktemp -d)
    TEMP_CERT="$TEMP_DIR/server.crt"
    TEMP_KEY="$TEMP_DIR/server.key"

    # Start with default certificate
    cp "$FIXTURES_DIR/server-default.crt" "$TEMP_CERT"
    cp "$FIXTURES_DIR/server-default.key" "$TEMP_KEY"

    log_info "Temp directory: $TEMP_DIR"
}

# Create test config using temp certs
create_test_config() {
    local config_file="$TEMP_DIR/test-config.kdl"

    cat > "$config_file" << EOF
// Test configuration for certificate rotation
listeners {
    https "0.0.0.0:$TEST_PORT" {
        cert-file "$TEMP_CERT"
        key-file "$TEMP_KEY"
    }
}

routes {
    route "health" {
        match { path "/health" }
        respond 200 "OK"
    }

    route "test" {
        match { path "/*" }
        respond 200 "Test endpoint"
    }
}
EOF

    echo "$config_file"
}

# Start Zentinel with test config
start_zentinel() {
    local config_file="$1"

    log_info "Starting Zentinel..."

    "$ZENTINEL_BIN" --config "$config_file" &
    ZENTINEL_PID=$!

    # Wait for startup
    local retries=20
    while [[ $retries -gt 0 ]]; do
        if curl -sk --connect-timeout 1 "$PROXY_URL/health" &> /dev/null; then
            log_info "Zentinel started (PID: $ZENTINEL_PID)"
            return 0
        fi
        sleep 0.5
        retries=$((retries - 1))
    done

    log_fail "Zentinel failed to start"
    return 1
}

# Get certificate CN from server
get_server_cert_cn() {
    echo | openssl s_client \
        -connect "localhost:$TEST_PORT" \
        -CAfile "$CA_CERT" \
        2>/dev/null | \
    openssl x509 -noout -subject 2>/dev/null | \
    sed -n 's/.*CN *= *\([^,]*\).*/\1/p' || echo ""
}

# Get certificate serial from server
get_server_cert_serial() {
    echo | openssl s_client \
        -connect "localhost:$TEST_PORT" \
        -CAfile "$CA_CERT" \
        2>/dev/null | \
    openssl x509 -noout -serial 2>/dev/null | \
    cut -d= -f2 || echo ""
}

# Test: Verify initial certificate is served
test_initial_certificate() {
    log_info "Testing initial certificate..."

    local cn
    cn=$(get_server_cert_cn)

    if [[ "$cn" == *"default"* ]] || [[ "$cn" == *"localhost"* ]]; then
        log_pass "Initial certificate served correctly (CN: $cn)"
    else
        log_fail "Expected default certificate, got CN: $cn"
    fi
}

# Test: Certificate rotation via SIGHUP
test_cert_rotation_via_sighup() {
    log_info "Testing certificate rotation via SIGHUP..."

    # Get initial certificate serial
    local initial_serial
    initial_serial=$(get_server_cert_serial)
    log_info "Initial certificate serial: $initial_serial"

    # Swap in API certificate
    log_info "Swapping certificate files..."
    cp "$FIXTURES_DIR/server-api.crt" "$TEMP_CERT"
    cp "$FIXTURES_DIR/server-api.key" "$TEMP_KEY"

    # Send SIGHUP to trigger reload
    log_info "Sending SIGHUP to Zentinel (PID: $ZENTINEL_PID)..."
    kill -HUP "$ZENTINEL_PID"

    # Wait for reload to complete
    sleep 1

    # Get new certificate serial
    local new_serial
    new_serial=$(get_server_cert_serial)
    log_info "New certificate serial: $new_serial"

    # Verify certificate changed
    if [[ "$initial_serial" != "$new_serial" ]]; then
        log_pass "Certificate rotated successfully via SIGHUP"
    else
        log_fail "Certificate did not change after SIGHUP"
    fi

    # Verify new cert CN
    local cn
    cn=$(get_server_cert_cn)
    if [[ "$cn" == *"api"* ]]; then
        log_pass "New certificate has correct CN (api)"
    else
        log_fail "Expected api certificate CN, got: $cn"
    fi
}

# Test: Multiple rotations work correctly
test_multiple_rotations() {
    log_info "Testing multiple certificate rotations..."

    local rotation_count=3
    local certs=("server-default" "server-api" "server-secure")
    local last_serial=""

    for i in $(seq 0 $((rotation_count - 1))); do
        local cert_base="${certs[$i]}"

        log_info "Rotation $((i + 1)): switching to $cert_base"
        cp "$FIXTURES_DIR/${cert_base}.crt" "$TEMP_CERT"
        cp "$FIXTURES_DIR/${cert_base}.key" "$TEMP_KEY"

        kill -HUP "$ZENTINEL_PID"
        sleep 1

        local current_serial
        current_serial=$(get_server_cert_serial)

        if [[ -n "$last_serial" ]] && [[ "$current_serial" == "$last_serial" ]]; then
            log_fail "Rotation $((i + 1)): Certificate did not change"
            return
        fi

        last_serial="$current_serial"
    done

    log_pass "Multiple certificate rotations completed successfully"
}

# Test: Connections remain stable during rotation
test_connection_stability() {
    log_info "Testing connection stability during rotation..."

    local success_count=0
    local fail_count=0

    # Make requests while triggering rotations
    for i in $(seq 1 10); do
        # Every 3rd iteration, trigger a rotation
        if (( i % 3 == 0 )); then
            cp "$FIXTURES_DIR/server-default.crt" "$TEMP_CERT"
            cp "$FIXTURES_DIR/server-default.key" "$TEMP_KEY"
            kill -HUP "$ZENTINEL_PID"
        fi

        if curl -sk --connect-timeout 2 "$PROXY_URL/health" &> /dev/null; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi

        sleep 0.2
    done

    log_info "Requests: $success_count succeeded, $fail_count failed"

    if [[ $fail_count -eq 0 ]]; then
        log_pass "All requests succeeded during certificate rotation"
    elif [[ $fail_count -le 1 ]]; then
        log_pass "Connection stability acceptable ($fail_count brief disruption)"
    else
        log_fail "Too many connection failures during rotation: $fail_count"
    fi
}

# Offline tests (certificate validation without running server)
run_offline_tests() {
    log_info "=== Offline Certificate Rotation Tests ==="

    # Verify all test certificates exist
    log_info "Verifying test certificates exist..."
    local cert_count=0
    for cert in "$FIXTURES_DIR"/server-*.crt; do
        if [[ -f "$cert" ]]; then
            cert_count=$((cert_count + 1))
            local key="${cert%.crt}.key"
            if [[ -f "$key" ]]; then
                # Verify cert/key match
                local cert_mod key_mod
                cert_mod=$(openssl x509 -in "$cert" -noout -modulus 2>/dev/null | md5)
                key_mod=$(openssl rsa -in "$key" -noout -modulus 2>/dev/null | md5)
                if [[ "$cert_mod" == "$key_mod" ]]; then
                    log_pass "Certificate and key match: $(basename "$cert")"
                else
                    log_fail "Certificate and key mismatch: $(basename "$cert")"
                fi
            else
                log_fail "Missing key for: $(basename "$cert")"
            fi
        fi
    done

    if [[ $cert_count -ge 3 ]]; then
        log_pass "Found $cert_count server certificates for rotation testing"
    else
        log_fail "Need at least 3 server certificates, found: $cert_count"
    fi

    # Verify all certs are signed by CA
    log_info "Verifying CA chain..."
    for cert in "$FIXTURES_DIR"/server-*.crt; do
        if [[ -f "$cert" ]]; then
            if openssl verify -CAfile "$CA_CERT" "$cert" &>/dev/null; then
                log_pass "CA verified: $(basename "$cert")"
            else
                log_fail "CA cannot verify: $(basename "$cert")"
            fi
        fi
    done

    # Verify certificates have different serials
    log_info "Verifying certificates have unique serials..."
    local serials=""
    local has_duplicate=0
    for cert in "$FIXTURES_DIR"/server-*.crt; do
        if [[ -f "$cert" ]]; then
            local serial
            serial=$(openssl x509 -in "$cert" -noout -serial 2>/dev/null | cut -d= -f2)
            if [[ "$serials" == *"$serial"* ]]; then
                log_fail "Duplicate serial found: $serial"
                has_duplicate=1
            else
                serials="$serials $serial"
            fi
        fi
    done
    if [[ $has_duplicate -eq 0 ]]; then
        log_pass "All certificates have unique serials"
    fi
}

# Main execution
main() {
    log_info "Starting TLS Certificate Rotation Tests"
    echo ""

    check_prerequisites

    # Always run offline tests
    run_offline_tests
    echo ""

    if [[ "$SKIP_CONNECTIVITY" == "1" ]]; then
        log_skip "Online tests (--skip-connectivity)"
        print_summary
        exit $?
    fi

    # Setup and run online tests
    setup_temp_certs
    local config_file
    config_file=$(create_test_config)

    if ! start_zentinel "$config_file"; then
        log_fail "Could not start Zentinel for online tests"
        print_summary
        exit 1
    fi

    echo ""
    log_info "=== Online Certificate Rotation Tests ==="

    test_initial_certificate
    test_cert_rotation_via_sighup
    test_multiple_rotations
    test_connection_stability

    print_summary
}

main "$@"
