#!/usr/bin/env bash
#
# Zentinel Chaos Tests - Chaos Injectors
#
# Functions to inject various failure conditions for chaos testing.
# Source this file after common.sh in test scripts.
#

# Prevent double-sourcing
[[ -n "${_CHAOS_INJECTORS_SOURCED:-}" ]] && return 0
_CHAOS_INJECTORS_SOURCED=1

# ============================================================================
# Configuration
# ============================================================================

# Docker Compose file location
CHAOS_COMPOSE_FILE="${CHAOS_COMPOSE_FILE:-docker-compose.chaos.yml}"
CHAOS_PROJECT="${CHAOS_PROJECT:-chaos}"

# Compose command helper
compose_cmd() {
    docker compose -p "$CHAOS_PROJECT" -f "$CHAOS_COMPOSE_FILE" "$@"
}

# ============================================================================
# Agent Chaos Injectors
# ============================================================================

# Kill an agent container (simulates crash)
# Usage: inject_agent_crash <agent_name>
inject_agent_crash() {
    local agent_name="$1"

    log_chaos "Killing agent '$agent_name'"
    compose_cmd kill "$agent_name" 2>/dev/null || true
    log_chaos_event "AGENT_CRASH" "$agent_name"
}

# Pause an agent container (simulates hang/timeout)
# Usage: inject_agent_freeze <agent_name> [duration_secs]
inject_agent_freeze() {
    local agent_name="$1"
    local duration="${2:-30}"

    log_chaos "Freezing agent '$agent_name' for ${duration}s"
    compose_cmd pause "$agent_name" 2>/dev/null || true
    log_chaos_event "AGENT_FREEZE" "$agent_name" "duration=${duration}s"

    # If duration provided, schedule unfreeze
    if [[ "$duration" -gt 0 ]]; then
        (
            sleep "$duration"
            compose_cmd unpause "$agent_name" 2>/dev/null || true
            log_chaos_event "AGENT_UNFREEZE" "$agent_name"
        ) &
    fi
}

# Unfreeze a paused agent
# Usage: inject_agent_unfreeze <agent_name>
inject_agent_unfreeze() {
    local agent_name="$1"

    log_restore "Unfreezing agent '$agent_name'"
    compose_cmd unpause "$agent_name" 2>/dev/null || true
    log_chaos_event "AGENT_UNFREEZE" "$agent_name"
}

# Restart an agent (crash + recovery)
# Usage: inject_agent_restart <agent_name> [delay_secs]
inject_agent_restart() {
    local agent_name="$1"
    local delay="${2:-5}"

    inject_agent_crash "$agent_name"
    sleep "$delay"
    restore_agent "$agent_name"
}

# Stop an agent gracefully
# Usage: inject_agent_stop <agent_name>
inject_agent_stop() {
    local agent_name="$1"

    log_chaos "Stopping agent '$agent_name'"
    compose_cmd stop "$agent_name" 2>/dev/null || true
    log_chaos_event "AGENT_STOP" "$agent_name"
}

# Restore a crashed/stopped agent
# Usage: restore_agent <agent_name>
restore_agent() {
    local agent_name="$1"

    log_restore "Starting agent '$agent_name'"
    compose_cmd start "$agent_name" 2>/dev/null || true
    log_chaos_event "AGENT_RESTORE" "$agent_name"
}

# ============================================================================
# Backend/Upstream Chaos Injectors
# ============================================================================

# Kill a backend container
# Usage: inject_backend_crash <backend_name>
inject_backend_crash() {
    local backend_name="${1:-backend-primary}"

    log_chaos "Killing backend '$backend_name'"
    compose_cmd kill "$backend_name" 2>/dev/null || true
    log_chaos_event "BACKEND_CRASH" "$backend_name"
}

# Stop a backend gracefully
# Usage: inject_backend_stop <backend_name>
inject_backend_stop() {
    local backend_name="${1:-backend-primary}"

    log_chaos "Stopping backend '$backend_name'"
    compose_cmd stop "$backend_name" 2>/dev/null || true
    log_chaos_event "BACKEND_STOP" "$backend_name"
}

# Pause a backend (simulates slow responses)
# Usage: inject_backend_freeze <backend_name> [duration_secs]
inject_backend_freeze() {
    local backend_name="${1:-backend-primary}"
    local duration="${2:-30}"

    log_chaos "Freezing backend '$backend_name' for ${duration}s"
    compose_cmd pause "$backend_name" 2>/dev/null || true
    log_chaos_event "BACKEND_FREEZE" "$backend_name" "duration=${duration}s"

    if [[ "$duration" -gt 0 ]]; then
        (
            sleep "$duration"
            compose_cmd unpause "$backend_name" 2>/dev/null || true
            log_chaos_event "BACKEND_UNFREEZE" "$backend_name"
        ) &
    fi
}

# Unfreeze a paused backend
# Usage: inject_backend_unfreeze <backend_name>
inject_backend_unfreeze() {
    local backend_name="${1:-backend-primary}"

    log_restore "Unfreezing backend '$backend_name'"
    compose_cmd unpause "$backend_name" 2>/dev/null || true
    log_chaos_event "BACKEND_UNFREEZE" "$backend_name"
}

# Restart a backend (crash + recovery)
# Usage: inject_backend_restart <backend_name> [delay_secs]
inject_backend_restart() {
    local backend_name="${1:-backend-primary}"
    local delay="${2:-5}"

    inject_backend_crash "$backend_name"
    sleep "$delay"
    restore_backend "$backend_name"
}

# Restore a crashed/stopped backend
# Usage: restore_backend <backend_name>
restore_backend() {
    local backend_name="${1:-backend-primary}"

    log_restore "Starting backend '$backend_name'"
    compose_cmd start "$backend_name" 2>/dev/null || true
    log_chaos_event "BACKEND_RESTORE" "$backend_name"
}

# Kill all backends
# Usage: inject_all_backends_crash
inject_all_backends_crash() {
    log_chaos "Killing all backends"
    inject_backend_crash "backend-primary"
    inject_backend_crash "backend-secondary"
    log_chaos_event "ALL_BACKENDS_CRASH" "all"
}

# Restore all backends
# Usage: restore_all_backends
restore_all_backends() {
    log_restore "Starting all backends"
    restore_backend "backend-primary"
    restore_backend "backend-secondary"
    log_chaos_event "ALL_BACKENDS_RESTORE" "all"
}

# ============================================================================
# Network Chaos Injectors (Optional - requires NET_ADMIN)
# ============================================================================

# Add network latency to a container
# Usage: inject_network_latency <container_name> <delay_ms>
inject_network_latency() {
    local container="$1"
    local delay_ms="${2:-500}"

    log_chaos "Adding ${delay_ms}ms latency to '$container'"

    # Try to add latency using tc
    docker exec "$container" tc qdisc add dev eth0 root netem delay "${delay_ms}ms" 2>/dev/null || {
        log_warn "Failed to inject network latency (tc not available or no NET_ADMIN)"
        return 1
    }

    log_chaos_event "NETWORK_LATENCY" "$container" "delay=${delay_ms}ms"
}

# Remove network latency from a container
# Usage: remove_network_latency <container_name>
remove_network_latency() {
    local container="$1"

    log_restore "Removing network latency from '$container'"
    docker exec "$container" tc qdisc del dev eth0 root 2>/dev/null || true
    log_chaos_event "NETWORK_LATENCY_REMOVE" "$container"
}

# Add packet loss to a container
# Usage: inject_packet_loss <container_name> <loss_percent>
inject_packet_loss() {
    local container="$1"
    local loss_percent="${2:-10}"

    log_chaos "Adding ${loss_percent}% packet loss to '$container'"

    docker exec "$container" tc qdisc add dev eth0 root netem loss "${loss_percent}%" 2>/dev/null || {
        log_warn "Failed to inject packet loss (tc not available or no NET_ADMIN)"
        return 1
    }

    log_chaos_event "PACKET_LOSS" "$container" "loss=${loss_percent}%"
}

# ============================================================================
# Generic Service Helpers
# ============================================================================

# Restore any service by name
# Usage: restore_service <service_name>
restore_service() {
    local service="$1"

    log_restore "Restoring service '$service'"
    compose_cmd start "$service" 2>/dev/null || true
    log_chaos_event "SERVICE_RESTORE" "$service"
}

# Kill any service by name
# Usage: kill_service <service_name>
kill_service() {
    local service="$1"

    log_chaos "Killing service '$service'"
    compose_cmd kill "$service" 2>/dev/null || true
    log_chaos_event "SERVICE_KILL" "$service"
}

# Restart any service
# Usage: restart_service <service_name>
restart_service() {
    local service="$1"

    log_info "Restarting service '$service'"
    compose_cmd restart "$service" 2>/dev/null || true
    log_chaos_event "SERVICE_RESTART" "$service"
}

# ============================================================================
# Chaos Utilities
# ============================================================================

# Wait for a service to become unhealthy/unavailable
# Usage: wait_for_unhealthy <url> [timeout_secs]
wait_for_unhealthy() {
    local url="$1"
    local timeout="${2:-30}"
    local start_time=$(date +%s)

    log_info "Waiting for $url to become unavailable..."

    while curl -sf "$url" >/dev/null 2>&1; do
        local elapsed=$(($(date +%s) - start_time))
        if [[ $elapsed -gt $timeout ]]; then
            log_warn "Service still responding after ${timeout}s"
            return 1
        fi
        sleep 0.5
    done

    log_info "Service is now unavailable"
    return 0
}

# Wait for a service to recover
# Usage: wait_for_recovery <url> [timeout_secs]
wait_for_recovery() {
    local url="$1"
    local timeout="${2:-60}"

    wait_for_service "$url" "recovery" "$timeout"
}

# Random chaos injection (for stress testing)
# Usage: inject_random_chaos
inject_random_chaos() {
    local chaos_types=("agent_crash" "backend_crash" "agent_freeze" "backend_freeze")
    local random_index=$((RANDOM % ${#chaos_types[@]}))
    local chaos_type="${chaos_types[$random_index]}"

    log_chaos "Random chaos: $chaos_type"

    case "$chaos_type" in
        agent_crash)
            inject_agent_crash "echo"
            ;;
        backend_crash)
            inject_backend_crash "backend-primary"
            ;;
        agent_freeze)
            inject_agent_freeze "echo" 5
            ;;
        backend_freeze)
            inject_backend_freeze "backend-primary" 5
            ;;
    esac
}
