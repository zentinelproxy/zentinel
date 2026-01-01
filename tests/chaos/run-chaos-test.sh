#!/usr/bin/env bash
#
# Sentinel Chaos Test Runner
#
# Main orchestrator for running chaos tests against Sentinel.
#
# Usage:
#   ./run-chaos-test.sh [options]
#
# Options:
#   --scenario NAME    Run specific scenario (agent-crash, backend-crash, etc.)
#   --all              Run all scenarios
#   --quick            Run quick subset (agent-crash, backend-crash, fail-open, fail-closed)
#   --skip-build       Skip Docker image build
#   --skip-cleanup     Don't tear down environment after tests
#   --keep             Alias for --skip-cleanup
#   --verbose          Enable verbose output
#   -h, --help         Show this help message
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================================
# Configuration
# ============================================================================

COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.chaos.yml"
PROJECT_NAME="chaos"
BUILD_CONTEXT="${SCRIPT_DIR}/../.."

# Output directory
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
OUTPUT_DIR="${SCRIPT_DIR}/results/${TIMESTAMP}"

# Test scenarios
AGENT_SCENARIOS=(
    "agent-failures/test_agent_crash.sh"
    "agent-failures/test_agent_timeout.sh"
    "agent-failures/test_circuit_breaker.sh"
)

UPSTREAM_SCENARIOS=(
    "upstream-failures/test_backend_crash.sh"
    "upstream-failures/test_backend_5xx.sh"
    "upstream-failures/test_all_backends_down.sh"
)

RESILIENCE_SCENARIOS=(
    "resilience/test_fail_open.sh"
    "resilience/test_fail_closed.sh"
    "resilience/test_health_recovery.sh"
    "resilience/test_memory_stability.sh"
)

QUICK_SCENARIOS=(
    "agent-failures/test_agent_crash.sh"
    "upstream-failures/test_backend_crash.sh"
    "resilience/test_fail_open.sh"
    "resilience/test_fail_closed.sh"
)

ALL_SCENARIOS=("${AGENT_SCENARIOS[@]}" "${UPSTREAM_SCENARIOS[@]}" "${RESILIENCE_SCENARIOS[@]}")

# Options
SKIP_BUILD=false
SKIP_CLEANUP=false
VERBOSE=false
SCENARIOS_TO_RUN=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ============================================================================
# Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

show_help() {
    cat << EOF
Sentinel Chaos Test Runner

Usage:
  ./run-chaos-test.sh [options]

Options:
  --scenario NAME    Run specific scenario. Available scenarios:
                       Agent failures:
                         agent-crash, agent-timeout, circuit-breaker
                       Upstream failures:
                         backend-crash, backend-5xx, all-backends-down
                       Resilience:
                         fail-open, fail-closed, health-recovery, memory-stability

  --all              Run all scenarios
  --quick            Run quick subset (agent-crash, backend-crash, fail-open, fail-closed)
  --skip-build       Skip Docker image build
  --skip-cleanup     Don't tear down environment after tests
  --keep             Alias for --skip-cleanup
  --verbose          Enable verbose output
  -h, --help         Show this help message

Examples:
  # Run quick validation
  ./run-chaos-test.sh --quick

  # Run all tests
  ./run-chaos-test.sh --all

  # Run specific scenario
  ./run-chaos-test.sh --scenario agent-crash

  # Run multiple scenarios
  ./run-chaos-test.sh --scenario agent-crash --scenario backend-crash

  # Keep environment running for debugging
  ./run-chaos-test.sh --quick --keep
EOF
}

get_scenario_path() {
    local name="$1"
    case "$name" in
        agent-crash)        echo "agent-failures/test_agent_crash.sh" ;;
        agent-timeout)      echo "agent-failures/test_agent_timeout.sh" ;;
        circuit-breaker)    echo "agent-failures/test_circuit_breaker.sh" ;;
        backend-crash)      echo "upstream-failures/test_backend_crash.sh" ;;
        backend-5xx)        echo "upstream-failures/test_backend_5xx.sh" ;;
        all-backends-down)  echo "upstream-failures/test_all_backends_down.sh" ;;
        fail-open)          echo "resilience/test_fail_open.sh" ;;
        fail-closed)        echo "resilience/test_fail_closed.sh" ;;
        health-recovery)    echo "resilience/test_health_recovery.sh" ;;
        memory-stability)   echo "resilience/test_memory_stability.sh" ;;
        *)
            log_error "Unknown scenario: $name"
            return 1
            ;;
    esac
}

compose_cmd() {
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

build_images() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Skipping Docker build (--skip-build)"
        return 0
    fi

    log_info "Building Docker images..."
    cd "$BUILD_CONTEXT"

    if [[ "$VERBOSE" == "true" ]]; then
        compose_cmd build
    else
        compose_cmd build --quiet
    fi

    log_success "Docker images built"
}

start_environment() {
    log_info "Starting chaos test environment..."

    compose_cmd up -d

    log_info "Waiting for services to be ready..."
    sleep 5

    # Wait for proxy health
    local retries=30
    while [[ $retries -gt 0 ]]; do
        if curl -sf "http://localhost:9090/health" >/dev/null 2>&1; then
            log_success "Proxy is healthy"
            break
        fi
        ((retries--))
        sleep 2
    done

    if [[ $retries -eq 0 ]]; then
        log_error "Proxy failed to become healthy"
        compose_cmd logs proxy
        return 1
    fi

    # Log running containers
    log_info "Running containers:"
    compose_cmd ps
}

stop_environment() {
    if [[ "$SKIP_CLEANUP" == "true" ]]; then
        log_info "Skipping cleanup (--skip-cleanup)"
        log_info "To stop manually: docker compose -p $PROJECT_NAME -f $COMPOSE_FILE down"
        return 0
    fi

    log_info "Stopping chaos test environment..."
    compose_cmd down --volumes --remove-orphans
    log_success "Environment stopped"
}

run_scenario() {
    local scenario_path="$1"
    local scenario_name
    scenario_name=$(basename "$scenario_path" .sh)

    log_info "=========================================="
    log_info "Running scenario: $scenario_name"
    log_info "=========================================="

    local scenario_log="${OUTPUT_DIR}/logs/${scenario_name}.log"
    mkdir -p "$(dirname "$scenario_log")"

    # Export environment for the test
    export OUTPUT_DIR
    export PROXY_URL="http://localhost:8080"
    export METRICS_URL="http://localhost:9090/metrics"
    export HEALTH_URL="http://localhost:9090/health"
    export CHAOS_COMPOSE_FILE="$COMPOSE_FILE"
    export CHAOS_PROJECT="$PROJECT_NAME"

    local exit_code=0
    if [[ "$VERBOSE" == "true" ]]; then
        "${SCRIPT_DIR}/scenarios/${scenario_path}" 2>&1 | tee "$scenario_log" || exit_code=$?
    else
        "${SCRIPT_DIR}/scenarios/${scenario_path}" > "$scenario_log" 2>&1 || exit_code=$?
        # Show summary
        tail -20 "$scenario_log"
    fi

    if [[ $exit_code -eq 0 ]]; then
        log_success "Scenario $scenario_name PASSED"
    else
        log_error "Scenario $scenario_name FAILED (exit code: $exit_code)"
    fi

    return $exit_code
}

collect_artifacts() {
    log_info "Collecting test artifacts..."

    mkdir -p "${OUTPUT_DIR}/logs"
    mkdir -p "${OUTPUT_DIR}/metrics"

    # Collect container logs
    for container in proxy echo backend-primary backend-secondary; do
        docker logs "${PROJECT_NAME}-${container}-1" > "${OUTPUT_DIR}/logs/${container}.log" 2>&1 || true
    done

    # Collect final metrics
    curl -sf "http://localhost:9090/metrics" > "${OUTPUT_DIR}/metrics/final.txt" 2>/dev/null || true

    log_info "Artifacts saved to: ${OUTPUT_DIR}"
}

generate_summary() {
    local total_passed=$1
    local total_failed=$2
    local total_run=$3

    log_info "Generating summary..."

    cat > "${OUTPUT_DIR}/summary.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "total": $total_run,
    "passed": $total_passed,
    "failed": $total_failed
  },
  "scenarios": [
EOF

    local first=true
    for scenario in "${SCENARIOS_TO_RUN[@]}"; do
        local name
        name=$(basename "$scenario" .sh)
        local log_file="${OUTPUT_DIR}/logs/${name}.log"
        local status="unknown"

        if [[ -f "$log_file" ]]; then
            if grep -q "ALL TESTS PASSED" "$log_file"; then
                status="passed"
            elif grep -q "SOME TESTS FAILED" "$log_file"; then
                status="failed"
            fi
        fi

        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "${OUTPUT_DIR}/summary.json"
        fi
        echo -n "    {\"name\": \"$name\", \"status\": \"$status\"}" >> "${OUTPUT_DIR}/summary.json"
    done

    cat >> "${OUTPUT_DIR}/summary.json" << EOF

  ]
}
EOF

    # Print final summary
    echo ""
    echo "=========================================="
    echo "CHAOS TEST SUMMARY"
    echo "=========================================="
    echo "Total scenarios: $total_run"
    echo -e "Passed: ${GREEN}$total_passed${NC}"
    echo -e "Failed: ${RED}$total_failed${NC}"
    echo "Results: ${OUTPUT_DIR}"
    echo "=========================================="

    if [[ $total_failed -eq 0 ]]; then
        echo -e "${GREEN}ALL SCENARIOS PASSED${NC}"
    else
        echo -e "${RED}SOME SCENARIOS FAILED${NC}"
    fi
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scenario)
                local path
                path=$(get_scenario_path "$2") || exit 1
                SCENARIOS_TO_RUN+=("$path")
                shift 2
                ;;
            --all)
                SCENARIOS_TO_RUN=("${ALL_SCENARIOS[@]}")
                shift
                ;;
            --quick)
                SCENARIOS_TO_RUN=("${QUICK_SCENARIOS[@]}")
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --skip-cleanup|--keep)
                SKIP_CLEANUP=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Default to quick if no scenarios specified
    if [[ ${#SCENARIOS_TO_RUN[@]} -eq 0 ]]; then
        log_info "No scenarios specified, running --quick"
        SCENARIOS_TO_RUN=("${QUICK_SCENARIOS[@]}")
    fi

    log_info "Sentinel Chaos Test Runner"
    log_info "Scenarios to run: ${#SCENARIOS_TO_RUN[@]}"
    log_info "Output directory: ${OUTPUT_DIR}"

    # Create output directory
    mkdir -p "$OUTPUT_DIR"

    # Setup trap for cleanup
    trap 'stop_environment; exit' INT TERM

    # Build and start environment
    build_images
    start_environment

    # Run scenarios
    local passed=0
    local failed=0

    for scenario in "${SCENARIOS_TO_RUN[@]}"; do
        if run_scenario "$scenario"; then
            ((passed++))
        else
            ((failed++))
        fi

        # Brief pause between scenarios to let things settle
        sleep 3

        # Restore all services between scenarios
        docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" start echo backend-primary backend-secondary 2>/dev/null || true
        sleep 2
    done

    # Collect artifacts
    collect_artifacts

    # Stop environment
    stop_environment

    # Generate summary
    generate_summary $passed $failed ${#SCENARIOS_TO_RUN[@]}

    # Exit with appropriate code
    if [[ $failed -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
