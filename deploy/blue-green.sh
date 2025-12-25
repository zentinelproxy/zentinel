#!/bin/bash

# Sentinel Blue-Green Deployment Script
# This script performs safe blue-green deployments with health checks and automatic rollback

set -euo pipefail

# Configuration
NAMESPACE="${NAMESPACE:-sentinel}"
SERVICE_NAME="${SERVICE_NAME:-sentinel}"
BLUE_DEPLOYMENT="${BLUE_DEPLOYMENT:-sentinel-blue}"
GREEN_DEPLOYMENT="${GREEN_DEPLOYMENT:-sentinel-green}"
IMAGE="${IMAGE:-sentinel/proxy:latest}"
HEALTH_CHECK_RETRIES="${HEALTH_CHECK_RETRIES:-30}"
HEALTH_CHECK_INTERVAL="${HEALTH_CHECK_INTERVAL:-10}"
TRAFFIC_SWITCH_PERCENTAGE="${TRAFFIC_SWITCH_PERCENTAGE:-10}"
TRAFFIC_SWITCH_INTERVAL="${TRAFFIC_SWITCH_INTERVAL:-30}"
SMOKE_TEST_DURATION="${SMOKE_TEST_DURATION:-60}"
ROLLBACK_ON_ERROR="${ROLLBACK_ON_ERROR:-true}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

log_success() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}▶ $1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}\n"
}

# Error handling
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Deployment failed with exit code $exit_code"
        if [[ "$ROLLBACK_ON_ERROR" == "true" ]]; then
            log_warning "Initiating automatic rollback..."
            rollback
        fi
    fi
}

trap cleanup EXIT

# Utility functions
check_prerequisites() {
    log_step "Checking Prerequisites"

    # Check required tools
    local required_tools=("kubectl" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is not installed"
            exit 1
        fi
    done

    # Check kubectl connection
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        exit 1
    fi

    log_success "All prerequisites met"
}

get_active_deployment() {
    local selector
    selector=$(kubectl get service "$SERVICE_NAME" -n "$NAMESPACE" -o json | jq -r '.spec.selector.deployment')

    if [[ "$selector" == "blue" ]]; then
        echo "$BLUE_DEPLOYMENT"
    elif [[ "$selector" == "green" ]]; then
        echo "$GREEN_DEPLOYMENT"
    else
        log_warning "No active deployment found, defaulting to blue"
        echo "$BLUE_DEPLOYMENT"
    fi
}

get_inactive_deployment() {
    local active
    active=$(get_active_deployment)

    if [[ "$active" == "$BLUE_DEPLOYMENT" ]]; then
        echo "$GREEN_DEPLOYMENT"
    else
        echo "$BLUE_DEPLOYMENT"
    fi
}

get_deployment_color() {
    local deployment=$1
    if [[ "$deployment" == "$BLUE_DEPLOYMENT" ]]; then
        echo "blue"
    else
        echo "green"
    fi
}

deploy_new_version() {
    local target_deployment=$1
    local target_color
    target_color=$(get_deployment_color "$target_deployment")

    log_step "Deploying New Version to $target_color Environment"

    # Create or update deployment
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $target_deployment
  namespace: $NAMESPACE
  labels:
    app: sentinel
    deployment: $target_color
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sentinel
      deployment: $target_color
  template:
    metadata:
      labels:
        app: sentinel
        deployment: $target_color
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: proxy
        image: $IMAGE
        imagePullPolicy: Always
        ports:
        - name: http
          containerPort: 8080
        - name: https
          containerPort: 8443
        - name: metrics
          containerPort: 9090
        env:
        - name: DEPLOYMENT_COLOR
          value: $target_color
        - name: RUST_LOG
          value: info,sentinel=debug
        livenessProbe:
          httpGet:
            path: /health
            port: metrics
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: metrics
          initialDelaySeconds: 10
          periodSeconds: 5
          failureThreshold: 3
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
EOF

    # Wait for rollout to complete
    log_info "Waiting for deployment to roll out..."
    if ! kubectl rollout status deployment/"$target_deployment" -n "$NAMESPACE" --timeout=300s; then
        log_error "Deployment rollout failed"
        return 1
    fi

    log_success "Deployment $target_deployment rolled out successfully"
}

health_check() {
    local deployment=$1
    local retries=$HEALTH_CHECK_RETRIES
    local interval=$HEALTH_CHECK_INTERVAL

    log_info "Running health checks for $deployment"

    # Get pod IPs
    local pod_ips
    pod_ips=$(kubectl get pods -n "$NAMESPACE" -l deployment="$(get_deployment_color "$deployment")" \
        -o jsonpath='{.items[*].status.podIP}')

    if [[ -z "$pod_ips" ]]; then
        log_error "No pods found for deployment $deployment"
        return 1
    fi

    # Check each pod
    for ip in $pod_ips; do
        local attempt=0
        local success=false

        while [[ $attempt -lt $retries ]]; do
            attempt=$((attempt + 1))
            log_info "Health check attempt $attempt/$retries for pod $ip"

            # Create a temporary pod for health checking
            if kubectl run health-check-$$ \
                --image=curlimages/curl:latest \
                --rm \
                --restart=Never \
                -n "$NAMESPACE" \
                -- curl -sf "http://$ip:9090/health" &> /dev/null; then
                log_success "Pod $ip is healthy"
                success=true
                break
            else
                log_warning "Pod $ip health check failed, retrying in ${interval}s..."
                sleep "$interval"
            fi
        done

        if [[ "$success" != "true" ]]; then
            log_error "Pod $ip failed health checks after $retries attempts"
            return 1
        fi
    done

    log_success "All pods in $deployment are healthy"
    return 0
}

smoke_test() {
    local deployment=$1
    local color
    color=$(get_deployment_color "$deployment")

    log_step "Running Smoke Tests on $color Environment"

    # Create test service pointing to new deployment
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: sentinel-test
  namespace: $NAMESPACE
spec:
  selector:
    app: sentinel
    deployment: $color
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
EOF

    # Wait for service to be ready
    sleep 5

    # Port-forward for testing
    kubectl port-forward -n "$NAMESPACE" service/sentinel-proxy-test 18080:8080 &
    local port_forward_pid=$!
    sleep 5

    # Run smoke tests
    local test_passed=true

    # Test 1: Basic connectivity
    log_info "Test 1: Basic connectivity"
    if curl -sf http://localhost:18080/health > /dev/null; then
        log_success "Basic connectivity test passed"
    else
        log_error "Basic connectivity test failed"
        test_passed=false
    fi

    # Test 2: Response time
    log_info "Test 2: Response time check"
    local response_time
    response_time=$(curl -sf -w "%{time_total}" -o /dev/null http://localhost:18080/health)
    if (( $(echo "$response_time < 1" | bc -l) )); then
        log_success "Response time acceptable: ${response_time}s"
    else
        log_error "Response time too high: ${response_time}s"
        test_passed=false
    fi

    # Test 3: Metrics endpoint
    log_info "Test 3: Metrics endpoint"
    if curl -sf http://localhost:18080/../metrics | grep -q "sentinel_requests_total"; then
        log_success "Metrics endpoint working"
    else
        log_error "Metrics endpoint not working"
        test_passed=false
    fi

    # Cleanup
    kill $port_forward_pid 2>/dev/null || true
    kubectl delete service sentinel-test -n "$NAMESPACE" 2>/dev/null || true

    if [[ "$test_passed" == "true" ]]; then
        log_success "All smoke tests passed"
        return 0
    else
        log_error "Some smoke tests failed"
        return 1
    fi
}

switch_traffic() {
    local target_deployment=$1
    local target_color
    target_color=$(get_deployment_color "$target_deployment")

    log_step "Switching Traffic to $target_color Environment"

    # Progressive traffic switch
    if [[ "$TRAFFIC_SWITCH_PERCENTAGE" -gt 0 ]]; then
        log_info "Starting progressive traffic switch (${TRAFFIC_SWITCH_PERCENTAGE}% increments)"

        for percentage in $(seq "$TRAFFIC_SWITCH_PERCENTAGE" "$TRAFFIC_SWITCH_PERCENTAGE" 100); do
            log_info "Switching $percentage% of traffic to $target_color"

            # Update service with weighted routing (requires service mesh or ingress controller support)
            kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" --type merge -p \
                "{\"spec\":{\"selector\":{\"deployment\":\"$target_color\"}}}"

            # Monitor for errors
            sleep "$TRAFFIC_SWITCH_INTERVAL"

            # Check error rate
            local error_rate
            error_rate=$(kubectl exec -n "$NAMESPACE" deployment/"$target_deployment" -- \
                curl -s http://localhost:9090/metrics | \
                grep 'sentinel_requests_total{status="5' | \
                awk '{sum+=$2} END {print sum}' || echo "0")

            if [[ "$error_rate" -gt 100 ]]; then
                log_error "High error rate detected: $error_rate errors"
                return 1
            fi

            log_success "$percentage% of traffic switched successfully"
        done
    else
        # Immediate switch
        log_info "Performing immediate traffic switch"
        kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" --type merge -p \
            "{\"spec\":{\"selector\":{\"deployment\":\"$target_color\"}}}"
    fi

    log_success "Traffic fully switched to $target_color environment"
}

monitor_deployment() {
    local duration=$1

    log_step "Monitoring New Deployment for ${duration}s"

    local end_time=$(($(date +%s) + duration))
    local error_count=0
    local check_interval=10

    while [[ $(date +%s) -lt $end_time ]]; do
        # Check error rate
        local current_errors
        current_errors=$(kubectl exec -n "$NAMESPACE" deployment/"$(get_active_deployment)" -- \
            curl -s http://localhost:9090/metrics 2>/dev/null | \
            grep 'sentinel_requests_total{status="5' | \
            awk '{sum+=$2} END {print sum}' || echo "0")

        if [[ "$current_errors" -gt "$error_count" ]]; then
            local new_errors=$((current_errors - error_count))
            log_warning "Detected $new_errors new errors"
            error_count=$current_errors

            if [[ $new_errors -gt 50 ]]; then
                log_error "Error spike detected, consider rollback"
                return 1
            fi
        fi

        log_info "Monitoring... $((end_time - $(date +%s)))s remaining"
        sleep $check_interval
    done

    log_success "Monitoring completed, deployment is stable"
}

cleanup_old_deployment() {
    local old_deployment=$1

    log_step "Cleaning Up Old Deployment"

    log_info "Scaling down $old_deployment"
    kubectl scale deployment/"$old_deployment" -n "$NAMESPACE" --replicas=0

    # Optionally delete the old deployment after a delay
    # kubectl delete deployment/"$old_deployment" -n "$NAMESPACE"

    log_success "Old deployment cleaned up"
}

rollback() {
    log_step "Rolling Back Deployment"

    local current_active
    current_active=$(get_active_deployment)
    local previous_active
    previous_active=$(get_inactive_deployment)

    log_info "Rolling back from $current_active to $previous_active"

    # Switch traffic back
    kubectl patch service "$SERVICE_NAME" -n "$NAMESPACE" --type merge -p \
        "{\"spec\":{\"selector\":{\"deployment\":\"$(get_deployment_color "$previous_active")\"}}}"

    # Scale up previous deployment if needed
    kubectl scale deployment/"$previous_active" -n "$NAMESPACE" --replicas=3

    log_success "Rollback completed"
}

# Main deployment flow
main() {
    log_step "Starting Blue-Green Deployment"
    log_info "Namespace: $NAMESPACE"
    log_info "Service: $SERVICE_NAME"
    log_info "Image: $IMAGE"

    # Check prerequisites
    check_prerequisites

    # Determine active and target deployments
    local active_deployment
    active_deployment=$(get_active_deployment)
    local target_deployment
    target_deployment=$(get_inactive_deployment)

    log_info "Active deployment: $active_deployment"
    log_info "Target deployment: $target_deployment"

    # Deploy new version
    if ! deploy_new_version "$target_deployment"; then
        log_error "Failed to deploy new version"
        exit 1
    fi

    # Health checks
    if ! health_check "$target_deployment"; then
        log_error "Health checks failed"
        exit 1
    fi

    # Smoke tests
    if ! smoke_test "$target_deployment"; then
        log_error "Smoke tests failed"
        exit 1
    fi

    # Switch traffic
    if ! switch_traffic "$target_deployment"; then
        log_error "Traffic switch failed"
        exit 1
    fi

    # Monitor deployment
    if ! monitor_deployment "$SMOKE_TEST_DURATION"; then
        log_error "Monitoring detected issues"
        exit 1
    fi

    # Cleanup old deployment
    cleanup_old_deployment "$active_deployment"

    log_success "Blue-Green deployment completed successfully!"
    log_info "New active deployment: $target_deployment"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --image)
            IMAGE="$2"
            shift 2
            ;;
        --no-rollback)
            ROLLBACK_ON_ERROR="false"
            shift
            ;;
        --rollback)
            rollback
            exit 0
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --namespace NAMESPACE    Kubernetes namespace (default: sentinel)"
            echo "  --image IMAGE           Docker image to deploy"
            echo "  --no-rollback          Disable automatic rollback on error"
            echo "  --rollback             Perform rollback to previous deployment"
            echo "  --help                 Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main deployment
main
