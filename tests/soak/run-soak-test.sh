#!/usr/bin/env bash
#
# Sentinel Soak Test Runner
#
# Runs extended load tests (24-72 hours) to detect memory leaks and
# stability issues in production-like conditions.
#
# Usage:
#   ./run-soak-test.sh [OPTIONS]
#
# Options:
#   --duration HOURS    Test duration in hours (default: 24)
#   --rps RPS           Requests per second (default: 100)
#   --connections N     Concurrent connections (default: 10)
#   --output DIR        Output directory for results (default: ./results)
#   --config FILE       Sentinel config file (default: ./soak-config.kdl)
#   --skip-build        Skip building Sentinel
#   --docker            Run in Docker instead of native
#   --help              Show this help message
#

set -euo pipefail

# Default configuration
DURATION_HOURS=24
DURATION_MINUTES=0  # Alternative: specify in minutes
RPS=100
CONNECTIONS=10
OUTPUT_DIR="./results"
CONFIG_FILE="./soak-config.kdl"
SKIP_BUILD=false
USE_DOCKER=false
SENTINEL_PORT=8080
METRICS_PORT=9090
BACKEND_PORT=8081

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION_HOURS="$2"
            shift 2
            ;;
        --minutes)
            DURATION_MINUTES="$2"
            DURATION_HOURS=0
            shift 2
            ;;
        --rps)
            RPS="$2"
            shift 2
            ;;
        --connections)
            CONNECTIONS="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --docker)
            USE_DOCKER=true
            shift
            ;;
        --help)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Calculate duration in seconds
if [[ "$DURATION_MINUTES" -gt 0 ]]; then
    DURATION_SECS=$((DURATION_MINUTES * 60))
    DURATION_DISPLAY="${DURATION_MINUTES} minutes"
else
    DURATION_SECS=$((DURATION_HOURS * 3600))
    DURATION_DISPLAY="${DURATION_HOURS} hours"
fi

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $*"
}

# Check dependencies
check_dependencies() {
    log_info "Checking dependencies..."

    local missing=()

    # Required tools
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")

    # Load testing tool (prefer oha, fall back to wrk or hey)
    if command -v oha >/dev/null 2>&1; then
        LOAD_TOOL="oha"
    elif command -v wrk >/dev/null 2>&1; then
        LOAD_TOOL="wrk"
    elif command -v hey >/dev/null 2>&1; then
        LOAD_TOOL="hey"
    else
        missing+=("oha or wrk or hey (load testing tool)")
    fi

    # Python for analysis (optional)
    if ! command -v python3 >/dev/null 2>&1; then
        log_warn "python3 not found - analysis script will not work"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  brew install curl jq"
        echo "  cargo install oha  # or: brew install wrk"
        exit 1
    fi

    log_success "Using load tool: $LOAD_TOOL"
}

# Setup output directory
setup_output() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')

    # Convert to absolute path
    if [[ "$OUTPUT_DIR" != /* ]]; then
        OUTPUT_DIR="${SCRIPT_DIR}/${OUTPUT_DIR}"
    fi
    OUTPUT_DIR="${OUTPUT_DIR}/${timestamp}"

    # Create all subdirectories first
    mkdir -p "$OUTPUT_DIR/memory"
    mkdir -p "$OUTPUT_DIR/metrics"
    mkdir -p "$OUTPUT_DIR/logs"

    log_info "Results will be saved to: $OUTPUT_DIR"
}

# Build Sentinel
build_sentinel() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "Skipping build (--skip-build)"
        return
    fi

    log_info "Building Sentinel (release mode)..."
    cd "$PROJECT_ROOT"
    cargo build --release --bin sentinel 2>&1 | tee "$OUTPUT_DIR/logs/build.log"
    log_success "Build complete"
}

# Start simple HTTP backend
start_backend() {
    log_info "Starting test backend on port $BACKEND_PORT..."

    # Use Python's built-in HTTP server or a simple echo server
    if command -v python3 >/dev/null 2>&1; then
        # Create a simple response file
        mkdir -p /tmp/soak-backend
        echo '{"status":"ok","message":"soak test backend"}' > /tmp/soak-backend/health
        echo '{"data":"test response for soak testing"}' > /tmp/soak-backend/api

        cd /tmp/soak-backend
        python3 -m http.server "$BACKEND_PORT" > "$OUTPUT_DIR/logs/backend.log" 2>&1 &
        BACKEND_PID=$!
        cd - > /dev/null
    else
        log_error "python3 required for backend"
        exit 1
    fi

    sleep 2

    if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
        log_error "Backend failed to start"
        exit 1
    fi

    log_success "Backend started (PID: $BACKEND_PID)"
}

# Start Sentinel proxy
start_sentinel() {
    log_info "Starting Sentinel proxy..."

    local config_path
    if [[ -f "$CONFIG_FILE" ]]; then
        config_path="$CONFIG_FILE"
    elif [[ -f "${SCRIPT_DIR}/${CONFIG_FILE}" ]]; then
        config_path="${SCRIPT_DIR}/${CONFIG_FILE}"
    else
        log_error "Config file not found: $CONFIG_FILE"
        exit 1
    fi

    if [[ "$USE_DOCKER" == "true" ]]; then
        # Docker mode
        docker run -d --name sentinel-soak \
            -p "$SENTINEL_PORT:8080" \
            -p "$METRICS_PORT:9090" \
            -v "$config_path:/etc/sentinel/config.kdl:ro" \
            sentinel:latest \
            --config /etc/sentinel/config.kdl \
            > "$OUTPUT_DIR/logs/sentinel.log" 2>&1
        SENTINEL_PID="docker"
    else
        # Native mode
        "$PROJECT_ROOT/target/release/sentinel" \
            --config "$config_path" \
            > "$OUTPUT_DIR/logs/sentinel.log" 2>&1 &
        SENTINEL_PID=$!
    fi

    # Wait for startup
    log_info "Waiting for Sentinel to start..."
    local retries=30
    while [[ $retries -gt 0 ]]; do
        # Try metrics endpoint first, then main proxy port
        if curl -sf "http://localhost:$METRICS_PORT/metrics" >/dev/null 2>&1; then
            log_success "Sentinel started (PID: $SENTINEL_PID)"
            return 0
        fi
        if curl -sf "http://localhost:$SENTINEL_PORT/" -o /dev/null 2>&1; then
            log_success "Sentinel started (PID: $SENTINEL_PID)"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    log_error "Sentinel failed to start within 30 seconds"
    cat "$OUTPUT_DIR/logs/sentinel.log"
    exit 1
}

# Get memory usage of Sentinel process
get_memory_usage() {
    if [[ "$USE_DOCKER" == "true" ]]; then
        docker stats sentinel-soak --no-stream --format '{{.MemUsage}}' 2>/dev/null | awk '{print $1}'
    else
        # macOS uses different ps format than Linux
        if [[ "$(uname)" == "Darwin" ]]; then
            ps -o rss= -p "$SENTINEL_PID" 2>/dev/null | awk '{print $1 * 1024}'
        else
            ps -o rss= -p "$SENTINEL_PID" 2>/dev/null | awk '{print $1 * 1024}'
        fi
    fi
}

# Memory monitoring loop
monitor_memory() {
    local interval=60  # Sample every 60 seconds
    local memory_log="$OUTPUT_DIR/memory/memory.csv"

    echo "timestamp,memory_bytes,memory_mb" > "$memory_log"

    log_info "Starting memory monitoring (interval: ${interval}s)..."

    while true; do
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        local mem_bytes=$(get_memory_usage)

        if [[ -n "$mem_bytes" && "$mem_bytes" =~ ^[0-9]+$ ]]; then
            local mem_mb=$((mem_bytes / 1024 / 1024))
            echo "$timestamp,$mem_bytes,$mem_mb" >> "$memory_log"
        fi

        sleep "$interval"
    done
}

# Collect metrics snapshot
collect_metrics() {
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    curl -sf "http://localhost:$METRICS_PORT/metrics" > "$OUTPUT_DIR/metrics/metrics_${timestamp}.txt" 2>/dev/null || true
}

# Run load test
run_load_test() {
    log_info "Starting load test..."
    log_info "  Duration: ${DURATION_DISPLAY} (${DURATION_SECS} seconds)"
    log_info "  Target RPS: $RPS"
    log_info "  Connections: $CONNECTIONS"

    local url="http://localhost:$SENTINEL_PORT/api"
    local load_log="$OUTPUT_DIR/logs/load.log"

    case "$LOAD_TOOL" in
        oha)
            # oha: Modern HTTP benchmarking tool
            oha -c "$CONNECTIONS" \
                -q "$RPS" \
                -z "${DURATION_SECS}s" \
                --latency-correction \
                --disable-keepalive \
                --json \
                "$url" > "$OUTPUT_DIR/load_results.json" 2>"$load_log" &
            ;;
        wrk)
            # wrk: Well-known benchmarking tool
            wrk -c "$CONNECTIONS" \
                -d "${DURATION_SECS}s" \
                -t 4 \
                --latency \
                "$url" > "$OUTPUT_DIR/load_results.txt" 2>"$load_log" &
            ;;
        hey)
            # hey: Simple HTTP load generator
            hey -c "$CONNECTIONS" \
                -q "$RPS" \
                -z "${DURATION_SECS}s" \
                "$url" > "$OUTPUT_DIR/load_results.txt" 2>"$load_log" &
            ;;
    esac

    LOAD_PID=$!
    log_success "Load test started (PID: $LOAD_PID)"
}

# Progress monitoring
show_progress() {
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION_SECS))

    while true; do
        local now=$(date +%s)
        local elapsed=$((now - start_time))
        local remaining=$((end_time - now))

        if [[ $remaining -le 0 ]]; then
            break
        fi

        local pct=$((elapsed * 100 / DURATION_SECS))
        local mem=$(get_memory_usage)
        local mem_mb=""
        if [[ -n "$mem" && "$mem" =~ ^[0-9]+$ ]]; then
            mem_mb="$((mem / 1024 / 1024))MB"
        fi

        # Collect metrics snapshot every 5 minutes
        if [[ $((elapsed % 300)) -eq 0 ]]; then
            collect_metrics
        fi

        printf "\r${BLUE}[PROGRESS]${NC} %3d%% | Elapsed: %02d:%02d:%02d | Remaining: %02d:%02d:%02d | Memory: %s    " \
            "$pct" \
            $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60)) \
            $((remaining / 3600)) $(((remaining % 3600) / 60)) $((remaining % 60)) \
            "$mem_mb"

        sleep 10
    done

    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Stop memory monitor
    if [[ -n "${MONITOR_PID:-}" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
    fi

    # Stop load test
    if [[ -n "${LOAD_PID:-}" ]]; then
        kill "$LOAD_PID" 2>/dev/null || true
        wait "$LOAD_PID" 2>/dev/null || true
    fi

    # Stop Sentinel
    if [[ "${SENTINEL_PID:-}" == "docker" ]]; then
        docker stop sentinel-soak 2>/dev/null || true
        docker rm sentinel-soak 2>/dev/null || true
    elif [[ -n "${SENTINEL_PID:-}" ]]; then
        kill "$SENTINEL_PID" 2>/dev/null || true
    fi

    # Stop backend
    if [[ -n "${BACKEND_PID:-}" ]]; then
        kill "$BACKEND_PID" 2>/dev/null || true
    fi

    log_success "Cleanup complete"
}

# Analyze results
analyze_results() {
    log_info "Analyzing results..."

    local memory_log="$OUTPUT_DIR/memory/memory.csv"

    if [[ ! -f "$memory_log" ]]; then
        log_warn "No memory data to analyze"
        return
    fi

    # Calculate memory statistics
    local mem_values=$(tail -n +2 "$memory_log" | cut -d',' -f3)
    local count=$(echo "$mem_values" | wc -l | tr -d ' ')
    local first=$(echo "$mem_values" | head -1)
    local last=$(echo "$mem_values" | tail -1)
    local min=$(echo "$mem_values" | sort -n | head -1)
    local max=$(echo "$mem_values" | sort -n | tail -1)
    local sum=$(echo "$mem_values" | paste -sd+ | bc)
    local avg=$((sum / count))

    # Calculate growth
    local growth=$((last - first))
    local growth_pct=0
    if [[ $first -gt 0 ]]; then
        growth_pct=$((growth * 100 / first))
    fi

    # Write summary
    cat > "$OUTPUT_DIR/summary.txt" << EOF
Sentinel Soak Test Summary
==========================
Date: $(date)
Duration: ${DURATION_HOURS} hours
Target RPS: ${RPS}
Connections: ${CONNECTIONS}

Memory Analysis
---------------
Samples: ${count}
Initial: ${first} MB
Final: ${last} MB
Min: ${min} MB
Max: ${max} MB
Average: ${avg} MB
Growth: ${growth} MB (${growth_pct}%)

Leak Detection
--------------
EOF

    # Determine if there's a leak
    # Rule of thumb: >20% growth over 24h is suspicious
    if [[ $growth_pct -gt 20 ]]; then
        echo "STATUS: POTENTIAL LEAK DETECTED" >> "$OUTPUT_DIR/summary.txt"
        echo "Memory grew by ${growth_pct}% which exceeds the 20% threshold." >> "$OUTPUT_DIR/summary.txt"
        log_error "POTENTIAL MEMORY LEAK: ${growth_pct}% growth"
    elif [[ $growth_pct -gt 10 ]]; then
        echo "STATUS: WARNING - Elevated memory growth" >> "$OUTPUT_DIR/summary.txt"
        echo "Memory grew by ${growth_pct}% which is slightly elevated." >> "$OUTPUT_DIR/summary.txt"
        log_warn "Elevated memory growth: ${growth_pct}%"
    else
        echo "STATUS: OK - No significant memory growth" >> "$OUTPUT_DIR/summary.txt"
        echo "Memory grew by ${growth_pct}% which is within acceptable limits." >> "$OUTPUT_DIR/summary.txt"
        log_success "No significant memory leak detected: ${growth_pct}% growth"
    fi

    echo "" >> "$OUTPUT_DIR/summary.txt"
    echo "Files" >> "$OUTPUT_DIR/summary.txt"
    echo "-----" >> "$OUTPUT_DIR/summary.txt"
    echo "Memory data: memory/memory.csv" >> "$OUTPUT_DIR/summary.txt"
    echo "Load results: load_results.*" >> "$OUTPUT_DIR/summary.txt"
    echo "Metrics snapshots: metrics/" >> "$OUTPUT_DIR/summary.txt"
    echo "Logs: logs/" >> "$OUTPUT_DIR/summary.txt"

    cat "$OUTPUT_DIR/summary.txt"
}

# Main
main() {
    echo ""
    echo "==========================================="
    echo "     Sentinel Soak Test"
    echo "==========================================="
    echo ""

    trap cleanup EXIT

    check_dependencies
    setup_output
    build_sentinel
    start_backend
    start_sentinel

    # Start memory monitoring in background
    monitor_memory &
    MONITOR_PID=$!

    # Collect initial metrics
    collect_metrics

    # Run load test
    run_load_test

    # Show progress
    show_progress

    # Wait for load test to complete
    wait "$LOAD_PID" 2>/dev/null || true

    # Collect final metrics
    collect_metrics

    # Stop memory monitor
    kill "$MONITOR_PID" 2>/dev/null || true

    # Analyze results
    analyze_results

    log_success "Soak test complete! Results saved to: $OUTPUT_DIR"
}

main "$@"
