#!/bin/bash
# test_waf.sh - Integration tests for WAF agent with CRS

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
PROXY_PORT=${PROXY_PORT:-8080}
PROXY_HOST=${PROXY_HOST:-localhost}
BACKEND_PORT=${BACKEND_PORT:-8081}
WAF_CONFIG=${WAF_CONFIG:-/tmp/sentinel-test-waf.yaml}
WAF_SOCKET=${WAF_SOCKET:-/tmp/sentinel-test-waf.sock}
WAF_METRICS_PORT=${WAF_METRICS_PORT:-9094}
AUDIT_LOG_DIR=${AUDIT_LOG_DIR:-/tmp/sentinel-waf-audit}
TEST_DURATION=${TEST_DURATION:-10}

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}Cleaning up...${NC}"

    # Kill processes
    if [[ -n "${PROXY_PID:-}" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
    fi

    if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi

    if [[ -n "${WAF_PID:-}" ]] && kill -0 "$WAF_PID" 2>/dev/null; then
        kill "$WAF_PID" 2>/dev/null || true
    fi

    # Clean up files
    rm -f "$WAF_CONFIG" "$WAF_SOCKET"
    rm -rf "$AUDIT_LOG_DIR"

    # Print summary
    echo -e "\n${BLUE}===========================================${NC}"
    echo -e "${BLUE}Test Summary:${NC}"
    echo -e "  Tests Run:    $TESTS_RUN"
    echo -e "  Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "  Tests Failed: ${RED}$TESTS_FAILED${NC}"

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "\n${GREEN}✅ All WAF tests passed!${NC}"
        exit 0
    else
        echo -e "\n${RED}❌ Some WAF tests failed${NC}"
        exit 1
    fi
}

trap cleanup EXIT INT TERM

# Helper functions
run_test() {
    local test_name="$1"
    local test_func="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${YELLOW}Running: $test_name${NC}"

    if $test_func; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        echo -e "${GREEN}✓ $test_name passed${NC}"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        echo -e "${RED}✗ $test_name failed${NC}"
    fi
}

wait_for_port() {
    local port=$1
    local timeout=${2:-30}
    local start=$(date +%s)

    while ! nc -z localhost "$port" 2>/dev/null; do
        if [[ $(($(date +%s) - start)) -gt $timeout ]]; then
            echo -e "${RED}Timeout waiting for port $port${NC}"
            return 1
        fi
        sleep 0.1
    done

    return 0
}

wait_for_socket() {
    local socket=$1
    local timeout=${2:-30}
    local start=$(date +%s)

    while [[ ! -S "$socket" ]]; do
        if [[ $(($(date +%s) - start)) -gt $timeout ]]; then
            echo -e "${RED}Timeout waiting for socket $socket${NC}"
            return 1
        fi
        sleep 0.1
    done

    return 0
}

# Create WAF configuration
create_waf_config() {
    mkdir -p "$AUDIT_LOG_DIR"

    cat > "$WAF_CONFIG" << EOF
engine:
  enabled: true
  detection_only: false
  paranoia_level: 1
  anomaly_threshold: 5

rules:
  load_crs: false  # Load simplified test rules instead of full CRS
  custom_rules:
    # Block SQL injection patterns
    - |
      SecRule ARGS|REQUEST_BODY "@detectSQLi" \\
        "id:100001,\\
        phase:2,\\
        block,\\
        msg:'SQL Injection Attack Detected',\\
        severity:'CRITICAL',\\
        tag:'attack-sqli'"

    # Block XSS patterns
    - |
      SecRule ARGS|REQUEST_BODY "@rx <script.*?>.*?</script>" \\
        "id:100002,\\
        phase:2,\\
        block,\\
        msg:'XSS Attack Detected',\\
        severity:'CRITICAL',\\
        tag:'attack-xss'"

    # Block path traversal
    - |
      SecRule REQUEST_URI "@contains ../" \\
        "id:100003,\\
        phase:1,\\
        block,\\
        msg:'Path Traversal Attack Detected',\\
        severity:'CRITICAL',\\
        tag:'attack-lfi'"

    # Block command injection
    - |
      SecRule ARGS|REQUEST_BODY "@rx (;|\\||&&|\\$\\(|\\`)" \\
        "id:100004,\\
        phase:2,\\
        block,\\
        msg:'Command Injection Attack Detected',\\
        severity:'CRITICAL',\\
        tag:'attack-rce'"

    # Block bad user agents
    - |
      SecRule REQUEST_HEADERS:User-Agent "@rx (scanner|nikto|sqlmap|havij)" \\
        "id:100005,\\
        phase:1,\\
        block,\\
        msg:'Malicious User Agent Detected',\\
        severity:'WARNING',\\
        tag:'scanner'"

body_inspection:
  max_request_body_size: 1048576
  request_body_buffer_limit: 131072
  inspect_request_content_types:
    - "application/x-www-form-urlencoded"
    - "application/json"
    - "text/plain"

audit:
  enabled: true
  log_dir: $AUDIT_LOG_DIR
  log_relevant: true
  format: json

exclusions:
  - name: "health-check"
    enabled: true
    bypass_waf: true
    conditions:
      - type: path
        pattern: "/health"
        regex: false

  - name: "test-bypass"
    enabled: true
    bypass_waf: true
    conditions:
      - type: header
        name: "X-WAF-Bypass"
        value: "test-secret"
        regex: false

listener:
  socket_path: $WAF_SOCKET
  socket_permissions: 0666
  max_connections: 100

metrics:
  enabled: true
  port: $WAF_METRICS_PORT
  bind_address: "127.0.0.1"
EOF
}

# Create proxy configuration with WAF
create_proxy_config() {
    cat > /tmp/sentinel-test-config.kdl << EOF
listener "http" {
    address "0.0.0.0:$PROXY_PORT"
    protocol "http"
}

upstream "backend" {
    endpoint "127.0.0.1:$BACKEND_PORT"
    health-check {
        path "/health"
        interval 5
        timeout 2
    }
}

agent "waf-agent" {
    type "waf"
    transport "unix_socket" {
        path "$WAF_SOCKET"
    }
    events ["request_headers"]
    timeout-ms 100
    failure-mode "open"
}

route "default" {
    matches { all true }
    upstream "backend"
    agents ["waf-agent"]
}

metrics {
    enabled true
    port 9091
    path "/metrics"
}
EOF
}

# Start test backend server
start_backend() {
    echo -e "${BLUE}Starting test backend on port $BACKEND_PORT...${NC}"

    # Simple HTTP server that echoes requests
    python3 -c "
import http.server
import json
import socketserver

class TestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                'method': 'GET',
                'path': self.path,
                'headers': dict(self.headers)
            }
            self.wfile.write(json.dumps(response).encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        response = {
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'body': body
        }
        self.wfile.write(json.dumps(response).encode())

    def log_message(self, format, *args):
        pass  # Suppress logs

with socketserver.TCPServer(('', $BACKEND_PORT), TestHandler) as httpd:
    httpd.serve_forever()
" &
    BACKEND_PID=$!

    wait_for_port $BACKEND_PORT || return 1
    echo -e "${GREEN}Backend started (PID: $BACKEND_PID)${NC}"
}

# Start WAF agent
start_waf() {
    echo -e "${BLUE}Building WAF agent...${NC}"

    # Build in standalone mode for testing
    if ! cargo build --release -p sentinel-waf-agent --features standalone 2>/dev/null; then
        echo -e "${YELLOW}Warning: Failed to build WAF agent, using mock${NC}"
        # Create a mock WAF agent for testing
        cat > /tmp/mock-waf-agent.py << 'MOCK_EOF'
import socket
import os
import json
import struct

socket_path = os.environ.get('WAF_SOCKET', '/tmp/sentinel-test-waf.sock')

if os.path.exists(socket_path):
    os.unlink(socket_path)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(socket_path)
server.listen(1)
os.chmod(socket_path, 0o666)

print(f"Mock WAF agent listening on {socket_path}")

while True:
    try:
        conn, _ = server.accept()
        while True:
            # Read message length
            length_data = conn.recv(4)
            if not length_data:
                break

            msg_len = struct.unpack('>I', length_data)[0]

            # Read message
            data = conn.recv(msg_len)
            request = json.loads(data)

            # Simple blocking logic
            block = False
            if 'request_headers' in request:
                headers = request['request_headers'].get('headers', {})
                path = request['request_headers'].get('path', '')
                body = request['request_headers'].get('body', '')

                # Block SQL injection
                if 'union' in path.lower() or 'select' in body.lower():
                    block = True

                # Block XSS
                if '<script>' in path or '<script>' in body:
                    block = True

                # Block path traversal
                if '../' in path:
                    block = True

                # Check bypass header
                if headers.get('X-WAF-Bypass') == 'test-secret':
                    block = False

            # Send response
            response = {
                'decision': 'block' if block else 'allow',
                'headers_to_add': {'X-WAF-Processed': 'true'},
                'headers_to_remove': [],
                'metadata': {'waf_mock': 'true'}
            }

            response_data = json.dumps(response).encode()
            conn.send(struct.pack('>I', len(response_data)) + response_data)

    except Exception as e:
        pass
    finally:
        conn.close()
MOCK_EOF

        python3 /tmp/mock-waf-agent.py &
        WAF_PID=$!
    else
        echo -e "${BLUE}Starting WAF agent...${NC}"

        WAF_CONFIG=$WAF_CONFIG target/release/sentinel-waf-agent &
        WAF_PID=$!
    fi

    wait_for_socket $WAF_SOCKET || return 1
    echo -e "${GREEN}WAF agent started (PID: $WAF_PID)${NC}"
}

# Start proxy
start_proxy() {
    echo -e "${BLUE}Starting Sentinel proxy...${NC}"

    target/release/sentinel -c /tmp/sentinel-test-config.kdl &
    PROXY_PID=$!

    wait_for_port $PROXY_PORT || return 1
    echo -e "${GREEN}Proxy started (PID: $PROXY_PID)${NC}"
}

# Test functions
test_waf_blocks_sql_injection() {
    echo "Testing SQL injection blocking..."

    # Test various SQL injection patterns
    local patterns=(
        "?id=1' OR '1'='1"
        "?id=1 UNION SELECT * FROM users"
        "?id=1; DROP TABLE users"
    )

    for pattern in "${patterns[@]}"; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" "http://$PROXY_HOST:$PROXY_PORT/test${pattern}" 2>/dev/null)

        if [[ "$response" == "403" ]]; then
            echo "  ✓ Blocked: $pattern"
        else
            echo "  ✗ Failed to block: $pattern (got $response)"
            return 1
        fi
    done

    return 0
}

test_waf_blocks_xss() {
    echo "Testing XSS blocking..."

    # Test XSS patterns
    local patterns=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
    )

    for pattern in "${patterns[@]}"; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "http://$PROXY_HOST:$PROXY_PORT/test" \
            -d "input=$pattern" 2>/dev/null)

        if [[ "$response" == "403" ]]; then
            echo "  ✓ Blocked: $pattern"
        else
            echo "  ✗ Failed to block: $pattern (got $response)"
            return 1
        fi
    done

    return 0
}

test_waf_blocks_path_traversal() {
    echo "Testing path traversal blocking..."

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://$PROXY_HOST:$PROXY_PORT/../../../etc/passwd" 2>/dev/null)

    if [[ "$response" == "403" ]]; then
        echo "  ✓ Blocked path traversal attempt"
        return 0
    else
        echo "  ✗ Failed to block path traversal (got $response)"
        return 1
    fi
}

test_waf_blocks_command_injection() {
    echo "Testing command injection blocking..."

    local patterns=("; ls -la" "| cat /etc/passwd" "&& rm -rf /")

    for pattern in "${patterns[@]}"; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST "http://$PROXY_HOST:$PROXY_PORT/exec" \
            -d "cmd=$pattern" 2>/dev/null)

        if [[ "$response" == "403" ]]; then
            echo "  ✓ Blocked: $pattern"
        else
            echo "  ✗ Failed to block: $pattern (got $response)"
            return 1
        fi
    done

    return 0
}

test_waf_blocks_bad_user_agents() {
    echo "Testing bad user agent blocking..."

    local agents=("sqlmap/1.0" "nikto/2.1" "scanner/1.0")

    for agent in "${agents[@]}"; do
        local response
        response=$(curl -s -o /dev/null -w "%{http_code}" \
            -H "User-Agent: $agent" \
            "http://$PROXY_HOST:$PROXY_PORT/test" 2>/dev/null)

        if [[ "$response" == "403" ]]; then
            echo "  ✓ Blocked: $agent"
        else
            echo "  ✗ Failed to block: $agent (got $response)"
            return 1
        fi
    done

    return 0
}

test_waf_allows_legitimate_requests() {
    echo "Testing legitimate requests..."

    # Normal GET request
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://$PROXY_HOST:$PROXY_PORT/api/users?page=1" 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo "  ✓ Allowed normal GET request"
    else
        echo "  ✗ Blocked legitimate GET request (got $response)"
        return 1
    fi

    # Normal POST request
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$PROXY_HOST:$PROXY_PORT/api/login" \
        -H "Content-Type: application/json" \
        -d '{"username":"user","password":"pass"}' 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo "  ✓ Allowed normal POST request"
    else
        echo "  ✗ Blocked legitimate POST request (got $response)"
        return 1
    fi

    return 0
}

test_waf_exclusions() {
    echo "Testing WAF exclusions..."

    # Test health check exclusion
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://$PROXY_HOST:$PROXY_PORT/health?test=' OR '1'='1" 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo "  ✓ Health check excluded from WAF"
    else
        echo "  ✗ Health check was blocked (got $response)"
        return 1
    fi

    # Test bypass header
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-WAF-Bypass: test-secret" \
        "http://$PROXY_HOST:$PROXY_PORT/test?id=' OR '1'='1" 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo "  ✓ Bypass header works"
    else
        echo "  ✗ Bypass header failed (got $response)"
        return 1
    fi

    return 0
}

test_waf_audit_logging() {
    echo "Testing audit logging..."

    # Trigger a block
    curl -s -o /dev/null "http://$PROXY_HOST:$PROXY_PORT/test?id=' OR '1'='1" 2>/dev/null

    sleep 1  # Give time for log to be written

    if [[ -d "$AUDIT_LOG_DIR" ]] && ls "$AUDIT_LOG_DIR"/*.json >/dev/null 2>&1; then
        echo "  ✓ Audit logs created"

        # Check log content
        if grep -q "blocked" "$AUDIT_LOG_DIR"/*.json 2>/dev/null; then
            echo "  ✓ Block event logged"
            return 0
        else
            echo "  ✗ Block event not found in logs"
            return 1
        fi
    else
        echo "  ✗ No audit logs found"
        return 1
    fi
}

test_waf_metrics() {
    echo "Testing WAF metrics..."

    # Make some requests to generate metrics
    curl -s "http://$PROXY_HOST:$PROXY_PORT/test" >/dev/null 2>&1
    curl -s "http://$PROXY_HOST:$PROXY_PORT/test?id=' OR '1'='1" >/dev/null 2>&1

    # Check metrics endpoint
    local metrics
    metrics=$(curl -s "http://localhost:$WAF_METRICS_PORT/metrics" 2>/dev/null)

    if [[ -n "$metrics" ]]; then
        echo "  ✓ Metrics endpoint accessible"

        # Check for specific metrics
        if echo "$metrics" | grep -q "waf_requests_total"; then
            echo "  ✓ Request metrics present"
        else
            echo "  ✗ Request metrics missing"
            return 1
        fi

        if echo "$metrics" | grep -q "waf_requests_blocked_total"; then
            echo "  ✓ Block metrics present"
        else
            echo "  ✗ Block metrics missing"
            return 1
        fi

        return 0
    else
        echo "  ✗ Metrics endpoint not accessible"
        return 1
    fi
}

test_waf_performance() {
    echo "Testing WAF performance under load..."

    local total_requests=1000
    local concurrent=10

    # Use Apache Bench if available
    if command -v ab >/dev/null 2>&1; then
        echo "  Running $total_requests requests with concurrency $concurrent..."

        local output
        output=$(ab -n $total_requests -c $concurrent -q \
            "http://$PROXY_HOST:$PROXY_PORT/api/test" 2>&1)

        local requests_per_sec
        requests_per_sec=$(echo "$output" | grep "Requests per second" | awk '{print $4}')

        if (( $(echo "$requests_per_sec > 100" | bc -l) )); then
            echo "  ✓ Performance acceptable: ${requests_per_sec} req/s"
            return 0
        else
            echo "  ✗ Performance too low: ${requests_per_sec} req/s"
            return 1
        fi
    else
        echo "  ⚠ Apache Bench not available, using curl loop..."

        local start_time
        start_time=$(date +%s)

        for ((i=1; i<=100; i++)); do
            curl -s "http://$PROXY_HOST:$PROXY_PORT/api/test" >/dev/null 2>&1 &
        done
        wait

        local end_time
        end_time=$(date +%s)
        local duration=$((end_time - start_time))

        if [[ $duration -lt 10 ]]; then
            echo "  ✓ 100 requests completed in ${duration}s"
            return 0
        else
            echo "  ✗ Performance test took too long: ${duration}s"
            return 1
        fi
    fi
}

test_waf_body_inspection() {
    echo "Testing body inspection..."

    # Test small body with attack pattern
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$PROXY_HOST:$PROXY_PORT/api/data" \
        -H "Content-Type: application/json" \
        -d '{"query":"SELECT * FROM users WHERE id=1 OR 1=1"}' 2>/dev/null)

    if [[ "$response" == "403" ]]; then
        echo "  ✓ Blocked SQL in JSON body"
    else
        echo "  ✗ Failed to block SQL in JSON body (got $response)"
        return 1
    fi

    # Test form data
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$PROXY_HOST:$PROXY_PORT/form" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "comment=<script>alert('XSS')</script>" 2>/dev/null)

    if [[ "$response" == "403" ]]; then
        echo "  ✓ Blocked XSS in form data"
    else
        echo "  ✗ Failed to block XSS in form data (got $response)"
        return 1
    fi

    # Test body size limit
    local large_body
    large_body=$(python3 -c "print('A' * 2000000)")  # 2MB

    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "http://$PROXY_HOST:$PROXY_PORT/upload" \
        -H "Content-Type: text/plain" \
        -d "$large_body" 2>/dev/null)

    # Should still process but truncate inspection
    if [[ "$response" == "200" || "$response" == "413" ]]; then
        echo "  ✓ Handled large body correctly"
        return 0
    else
        echo "  ✗ Unexpected response for large body (got $response)"
        return 1
    fi
}

test_waf_fail_open() {
    echo "Testing fail-open behavior..."

    # Kill WAF agent
    if [[ -n "${WAF_PID:-}" ]]; then
        kill "$WAF_PID" 2>/dev/null || true
        sleep 2
    fi

    # Request should still go through (fail-open)
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "http://$PROXY_HOST:$PROXY_PORT/test" 2>/dev/null)

    if [[ "$response" == "200" ]]; then
        echo "  ✓ Requests succeed when WAF is down (fail-open)"

        # Restart WAF for other tests
        start_waf
        return 0
    else
        echo "  ✗ Requests blocked when WAF is down (got $response)"
        return 1
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}Sentinel WAF Integration Tests${NC}"
    echo -e "${BLUE}===========================================${NC}"

    # Build the project
    echo -e "\n${BLUE}Building Sentinel...${NC}"
    if ! cargo build --release 2>/dev/null; then
        echo -e "${RED}Failed to build project${NC}"
        exit 1
    fi

    # Create configurations
    create_waf_config
    create_proxy_config

    # Start services
    start_backend
    start_waf
    start_proxy

    # Allow services to stabilize
    sleep 2

    # Run tests
    run_test "SQL Injection Blocking" test_waf_blocks_sql_injection
    run_test "XSS Blocking" test_waf_blocks_xss
    run_test "Path Traversal Blocking" test_waf_blocks_path_traversal
    run_test "Command Injection Blocking" test_waf_blocks_command_injection
    run_test "Bad User Agent Blocking" test_waf_blocks_bad_user_agents
    run_test "Legitimate Request Handling" test_waf_allows_legitimate_requests
    run_test "WAF Exclusions" test_waf_exclusions
    run_test "Audit Logging" test_waf_audit_logging
    run_test "WAF Metrics" test_waf_metrics
    run_test "Body Inspection" test_waf_body_inspection
    run_test "Fail-Open Behavior" test_waf_fail_open
    run_test "Performance Under Load" test_waf_performance
}

# Run main function
main
