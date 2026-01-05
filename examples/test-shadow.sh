#!/bin/bash
# Traffic Mirroring / Shadow Testing Script
# This script tests all shadow configurations defined in shadow-test.kdl

set -e

echo "=== Shadow / Traffic Mirroring Test Suite ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Start upstreams
echo "Starting upstream containers..."
cd "$(dirname "$0")"
docker compose -f shadow-test-compose.yml up -d
sleep 3

# Verify upstreams are healthy
echo -e "${YELLOW}Verifying upstreams...${NC}"
curl -sf http://localhost:9001/health | jq . || { echo "Production upstream not healthy"; exit 1; }
curl -sf http://localhost:9002/health | jq . || { echo "Canary upstream not healthy"; exit 1; }
curl -sf http://localhost:9003/health | jq . || { echo "Staging upstream not healthy"; exit 1; }
echo -e "${GREEN}✓ All upstreams healthy${NC}"
echo ""

# Start Sentinel
echo "Starting Sentinel proxy..."
SENTINEL_BIN="../target/release/sentinel"
if [ ! -f "$SENTINEL_BIN" ]; then
    echo "Error: Sentinel binary not found at $SENTINEL_BIN"
    echo "Please run: cargo build --release"
    exit 1
fi

$SENTINEL_BIN -c shadow-test.kdl > /tmp/sentinel-shadow-test.log 2>&1 &
SENTINEL_PID=$!
echo "Sentinel started (PID: $SENTINEL_PID)"
sleep 4

# Cleanup on exit
trap "kill $SENTINEL_PID 2>/dev/null || true; docker compose -f shadow-test-compose.yml down" EXIT

# Verify Sentinel is running
curl -sf http://localhost:8080/health > /dev/null || { echo "Sentinel not responding"; exit 1; }
echo -e "${GREEN}✓ Sentinel is running${NC}"
echo ""

# Test 1: Full shadow (100% mirrored to canary)
echo -e "${YELLOW}Test 1: Full shadow (100% mirrored to canary)${NC}"
echo "Request to /api/v1/test should go to production AND mirror to canary"
curl -s http://localhost:8080/api/v1/test | jq .
echo ""

# Test 2: Partial shadow (10% mirrored)
echo -e "${YELLOW}Test 2: Partial shadow (10% mirrored to canary)${NC}"
echo "Sending 20 requests to /api/v2/test (expect ~2 mirrored to canary at 10% rate)"
for i in $(seq 1 20); do
    curl -s http://localhost:8080/api/v2/test > /dev/null
done
echo "Sent 20 requests"
echo ""

# Test 3: Header-based shadow (with header)
echo -e "${YELLOW}Test 3: Header-based shadow (WITH X-Debug-Shadow header)${NC}"
echo "Request should be mirrored to canary because header is present"
curl -s -H "X-Debug-Shadow: true" http://localhost:8080/api/v3/test | jq .
echo ""

# Test 4: Header-based shadow (without header)
echo -e "${YELLOW}Test 4: Header-based shadow (WITHOUT X-Debug-Shadow header)${NC}"
echo "Request should NOT be mirrored to canary (no header)"
curl -s http://localhost:8080/api/v3/test | jq .
echo ""

# Test 5: Internal API with staging shadow
echo -e "${YELLOW}Test 5: Internal API (WITH X-Internal-Test header)${NC}"
echo "Request should be mirrored to staging"
curl -s -H "X-Internal-Test: enabled" http://localhost:8080/internal/test | jq .
echo ""

# Check metrics
echo -e "${YELLOW}Shadow Metrics:${NC}"
if curl -sf http://localhost:9090/metrics | grep -E "shadow_"; then
    echo ""
else
    echo "No shadow metrics found (may need to wait for shadow requests to complete)"
fi
echo ""

# Check logs for shadow activity
echo -e "${YELLOW}Shadow Activity in Logs:${NC}"
grep -i shadow /tmp/sentinel-shadow-test.log | tail -10 || echo "No shadow logs yet"
echo ""

echo -e "${GREEN}=== Test Complete ===${NC}"
echo "Check /tmp/sentinel-shadow-test.log for detailed logs"
echo "Metrics available at http://localhost:9090/metrics"
