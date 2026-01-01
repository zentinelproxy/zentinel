#!/bin/bash
# Generate test certificates for TLS testing
# These are self-signed certificates for testing purposes only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Certificate validity (days)
VALIDITY=3650

echo "=== Generating Test CA ==="
# Generate CA private key
openssl genrsa -out ca.key 2048

# Generate CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days $VALIDITY \
    -out ca.crt \
    -subj "/C=US/ST=Test/L=Test/O=Sentinel Test CA/CN=Sentinel Test Root CA"

echo "=== Generating Server Certificates ==="

# Function to generate a server certificate
generate_server_cert() {
    local name=$1
    local cn=$2
    local sans=$3

    echo "Generating certificate for $name ($cn)"

    # Generate private key
    openssl genrsa -out "${name}.key" 2048

    # Generate CSR
    openssl req -new -key "${name}.key" \
        -out "${name}.csr" \
        -subj "/C=US/ST=Test/L=Test/O=Sentinel Test/CN=${cn}"

    # Create extensions file for SAN
    cat > "${name}.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = ${sans}
EOF

    # Sign with CA
    openssl x509 -req -in "${name}.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${name}.crt" -days $VALIDITY -sha256 \
        -extfile "${name}.ext"

    # Clean up intermediate files
    rm -f "${name}.csr" "${name}.ext"

    # Create combined PEM (cert + key)
    cat "${name}.crt" "${name}.key" > "${name}.pem"
}

# Default server certificate (example.com)
generate_server_cert "server-default" "example.com" "DNS:example.com,DNS:localhost,IP:127.0.0.1"

# API server certificate for SNI testing
generate_server_cert "server-api" "api.example.com" "DNS:api.example.com,DNS:localhost,IP:127.0.0.1"

# Secure server certificate for SNI testing
generate_server_cert "server-secure" "secure.example.com" "DNS:secure.example.com,DNS:localhost,IP:127.0.0.1"

# Wildcard certificate for fallback testing
generate_server_cert "server-wildcard" "*.example.com" "DNS:*.example.com,DNS:example.com,DNS:localhost,IP:127.0.0.1"

echo "=== Generating Client Certificate for mTLS ==="

# Generate client private key
openssl genrsa -out client.key 2048

# Generate client CSR
openssl req -new -key client.key \
    -out client.csr \
    -subj "/C=US/ST=Test/L=Test/O=Sentinel Test Client/CN=test-client"

# Create extensions file for client cert
cat > client.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign with CA
openssl x509 -req -in client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days $VALIDITY -sha256 \
    -extfile client.ext

# Clean up intermediate files
rm -f client.csr client.ext

# Create combined PEM
cat client.crt client.key > client.pem

echo "=== Generating Invalid/Expired Certificate for Testing ==="

# Generate expired certificate (expired yesterday)
openssl genrsa -out expired.key 2048
openssl req -new -key expired.key -out expired.csr \
    -subj "/C=US/ST=Test/L=Test/O=Sentinel Test/CN=expired.example.com"

# Create cert that expired yesterday
openssl x509 -req -in expired.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out expired.crt -days -1 -sha256 \
    -set_serial 999 2>/dev/null || {
    # Some openssl versions don't support negative days, use faketime if available
    echo "Note: Could not create expired cert with negative days, creating short-lived cert instead"
    openssl x509 -req -in expired.csr \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out expired.crt -days 1 -sha256
}

rm -f expired.csr

# Generate self-signed certificate (not signed by our CA) for rejection testing
openssl genrsa -out untrusted.key 2048
openssl req -x509 -new -nodes -key untrusted.key -sha256 -days $VALIDITY \
    -out untrusted.crt \
    -subj "/C=US/ST=Test/L=Test/O=Unknown CA/CN=untrusted.example.com"

# Clean up serial file
rm -f ca.srl

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Generated files:"
echo "  CA:"
echo "    ca.crt              - CA certificate (add to trust store)"
echo "    ca.key              - CA private key"
echo ""
echo "  Server certificates (for SNI testing):"
echo "    server-default.*    - Default cert for example.com"
echo "    server-api.*        - Cert for api.example.com"
echo "    server-secure.*     - Cert for secure.example.com"
echo "    server-wildcard.*   - Wildcard cert for *.example.com"
echo ""
echo "  Client certificate (for mTLS):"
echo "    client.crt/key/pem  - Client certificate"
echo ""
echo "  Test certificates:"
echo "    expired.*           - Expired certificate"
echo "    untrusted.*         - Self-signed (not trusted by CA)"
echo ""
