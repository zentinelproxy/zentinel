#!/usr/bin/env bash
#
# Gateway API Conformance Test Runner
#
# Sets up a kind cluster, deploys the gateway controller + proxy,
# and runs the official Gateway API conformance test suite.
#
# Prerequisites:
#   - kind (https://kind.sigs.k8s.io/)
#   - kubectl
#   - helm
#   - docker
#   - go 1.22+
#
# Usage:
#   ./scripts/conformance-test.sh                  # full run
#   ./scripts/conformance-test.sh --skip-build     # reuse existing images
#   ./scripts/conformance-test.sh --keep-cluster   # don't delete cluster after

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CLUSTER_NAME="zentinel-conformance"
GATEWAY_IMAGE="zentinel-gateway:conformance"
PROXY_IMAGE="zentinel:conformance"
GATEWAY_API_VERSION="v1.4.1"
NAMESPACE="zentinel-system"

SKIP_BUILD=false
KEEP_CLUSTER=false
GENERATE_REPORT=false

for arg in "$@"; do
    case "$arg" in
        --skip-build)    SKIP_BUILD=true ;;
        --keep-cluster)  KEEP_CLUSTER=true ;;
        --report)        GENERATE_REPORT=true ;;
        --help|-h)
            echo "Usage: $0 [--skip-build] [--keep-cluster] [--report]"
            exit 0
            ;;
    esac
done

cleanup() {
    if [ "$KEEP_CLUSTER" = false ]; then
        echo "==> Cleaning up kind cluster..."
        kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    else
        echo "==> Keeping cluster '$CLUSTER_NAME' (use 'kind delete cluster --name $CLUSTER_NAME' to remove)"
    fi
}
trap cleanup EXIT

echo "==> Gateway API Conformance Test Suite"
echo "    Cluster:     $CLUSTER_NAME"
echo "    Gateway API: $GATEWAY_API_VERSION"
echo ""

# Step 1: Build Docker images
if [ "$SKIP_BUILD" = false ]; then
    echo "==> Building gateway controller image..."
    docker build -t "$GATEWAY_IMAGE" --target gateway "$ROOT_DIR"

    echo "==> Building proxy image..."
    docker build -t "$PROXY_IMAGE" --target proxy "$ROOT_DIR"
else
    echo "==> Skipping image build (--skip-build)"
fi

# Step 2: Create kind cluster
echo "==> Creating kind cluster..."
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

cat <<EOF | kind create cluster --name "$CLUSTER_NAME" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 8080
        protocol: TCP
      - containerPort: 30443
        hostPort: 8443
        protocol: TCP
EOF

echo "==> Loading images into kind..."
kind load docker-image "$GATEWAY_IMAGE" --name "$CLUSTER_NAME"
kind load docker-image "$PROXY_IMAGE" --name "$CLUSTER_NAME"

# Step 3: Install Gateway API CRDs
echo "==> Installing Gateway API CRDs ($GATEWAY_API_VERSION)..."
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/standard-install.yaml"

# Step 4: Deploy zentinel-gateway
echo "==> Deploying zentinel-gateway controller + proxy..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

helm upgrade --install zentinel-gateway "$ROOT_DIR/deploy/helm/zentinel-gateway" \
    --namespace "$NAMESPACE" \
    --set image.repository=zentinel-gateway \
    --set image.tag=conformance \
    --set image.pullPolicy=Never \
    --set proxy.image.repository=zentinel \
    --set proxy.image.tag=conformance \
    --set proxy.image.pullPolicy=Never \
    --set proxy.httpPort=8080 \
    --set proxy.httpsPort=8443 \
    --wait \
    --timeout 120s

echo "==> Waiting for controller to be ready..."
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=zentinel-gateway \
    -n "$NAMESPACE" \
    --timeout=60s

echo "==> Verifying GatewayClass..."
kubectl get gatewayclass zentinel -o yaml

# Step 5: Run conformance tests
echo "==> Running Gateway API conformance tests..."
cd "$ROOT_DIR/conformance"

CONFORMANCE_ARGS=(
    -run TestConformance
    -gateway-class=zentinel
    -v
    -count=1
)

if [ "$GENERATE_REPORT" = true ]; then
    REPORT_FILE="$ROOT_DIR/conformance/reports/standard-v0.6.1-default-report.yaml"
    CONFORMANCE_ARGS+=(-report-output="$REPORT_FILE")
    echo "    Report will be written to: $REPORT_FILE"
fi

go test ./... "${CONFORMANCE_ARGS[@]}" -timeout=90m 2>&1 | tee "$ROOT_DIR/conformance/test-output.log"
TEST_EXIT=${PIPESTATUS[0]}

if [ $TEST_EXIT -eq 0 ]; then
    echo ""
    echo "==> Conformance tests PASSED"
else
    echo ""
    echo "==> Conformance tests FAILED (exit code: $TEST_EXIT)"
    echo "    See conformance/test-output.log for details"
fi

exit $TEST_EXIT
