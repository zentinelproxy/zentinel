#!/bin/bash
#
# Sentinel Deployment Script
# Deploy Sentinel proxy and agents to production
#
# Usage: ./deploy.sh [options]
#
# Options:
#   install       Install Sentinel and agents
#   upgrade       Upgrade existing installation
#   uninstall     Remove Sentinel and agents
#   start         Start all services
#   stop          Stop all services
#   restart       Restart all services
#   status        Show service status
#   config        Deploy configuration
#   backup        Backup current installation
#   rollback      Rollback to previous version
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_PREFIX="/usr/local"
CONFIG_DIR="/etc/sentinel"
DATA_DIR="/var/lib/sentinel"
LOG_DIR="/var/log/sentinel"
RUN_DIR="/var/run/sentinel"
BACKUP_DIR="/var/backups/sentinel"
SERVICE_USER="sentinel"
SERVICE_GROUP="sentinel"

# Binary names
PROXY_BIN="sentinel"
ECHO_AGENT_BIN="sentinel-echo-agent"
RATELIMIT_AGENT_BIN="sentinel-ratelimit-agent"
DENYLIST_AGENT_BIN="sentinel-denylist-agent"
WAF_AGENT_BIN="sentinel-waf-agent"

# Service names
PROXY_SERVICE="sentinel.service"
ECHO_SERVICE="sentinel-echo-agent.service"
RATELIMIT_SERVICE="sentinel-ratelimit-agent.service"
DENYLIST_SERVICE="sentinel-denylist-agent.service"
WAF_SERVICE="sentinel-waf-agent.service"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Create system user and group
create_user() {
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log_info "Creating user: $SERVICE_USER"
        useradd --system \
                --user-group \
                --home-dir "$DATA_DIR" \
                --shell /usr/sbin/nologin \
                --comment "Sentinel Proxy Service Account" \
                "$SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

# Create required directories
create_directories() {
    log_info "Creating directories..."

    # Create directories with appropriate permissions
    mkdir -p "$CONFIG_DIR"/{agents,certs}
    mkdir -p "$DATA_DIR"/{cache,state}
    mkdir -p "$LOG_DIR"
    mkdir -p "$RUN_DIR"
    mkdir -p "$BACKUP_DIR"

    # Set ownership and permissions
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$LOG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$RUN_DIR"

    chmod 755 "$CONFIG_DIR"
    chmod 700 "$DATA_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$RUN_DIR"
}

# Build binaries
build_binaries() {
    log_info "Building Sentinel binaries..."

    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        log_error "Rust/Cargo not found. Please install Rust first."
        exit 1
    fi

    # Build in release mode
    cargo build --release --workspace

    if [ $? -eq 0 ]; then
        log_info "Build completed successfully"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Install binaries
install_binaries() {
    log_info "Installing binaries to $INSTALL_PREFIX/bin..."

    # Install proxy
    if [ -f "target/release/$PROXY_BIN" ]; then
        install -m 755 -o root -g root \
            "target/release/$PROXY_BIN" \
            "$INSTALL_PREFIX/bin/$PROXY_BIN"
        log_info "Installed $PROXY_BIN"
    else
        log_error "$PROXY_BIN not found"
        exit 1
    fi

    # Install agents
    for agent in "$ECHO_AGENT_BIN" "$RATELIMIT_AGENT_BIN"; do
        if [ -f "target/release/$agent" ]; then
            install -m 755 -o root -g root \
                "target/release/$agent" \
                "$INSTALL_PREFIX/bin/$agent"
            log_info "Installed $agent"
        else
            log_warn "$agent not found (optional)"
        fi
    done
}

# Install systemd services
install_services() {
    log_info "Installing systemd services..."

    # Install service files
    for service in deploy/*.service; do
        if [ -f "$service" ]; then
            cp "$service" /etc/systemd/system/
            log_info "Installed $(basename $service)"
        fi
    done

    # Reload systemd
    systemctl daemon-reload

    # Enable main service
    systemctl enable "$PROXY_SERVICE"
    log_info "Enabled $PROXY_SERVICE"
}

# Deploy configuration
deploy_config() {
    log_info "Deploying configuration..."

    # Deploy main config
    if [ -f "config/sentinel.kdl" ]; then
        cp "config/sentinel.kdl" "$CONFIG_DIR/config.kdl"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/config.kdl"
        chmod 644 "$CONFIG_DIR/config.kdl"
        log_info "Deployed main configuration"
    else
        log_warn "No configuration file found, using defaults"
    fi

    # Deploy agent configs if they exist
    if [ -d "config/agents" ]; then
        cp -r config/agents/* "$CONFIG_DIR/agents/"
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/agents"
        chmod -R 644 "$CONFIG_DIR/agents"/*
    fi

    # Create environment files
    cat > "$CONFIG_DIR/env" <<EOF
# Sentinel Proxy Environment Variables
RUST_LOG=info
SENTINEL_CONFIG=$CONFIG_DIR/config.kdl
SENTINEL_WORKERS=0
EOF

    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR/env"
    chmod 600 "$CONFIG_DIR/env"
}

# Backup current installation
backup_installation() {
    local backup_name="sentinel-backup-$(date +%Y%m%d-%H%M%S)"
    local backup_path="$BACKUP_DIR/$backup_name"

    log_info "Creating backup: $backup_name"

    mkdir -p "$backup_path"

    # Backup binaries
    if [ -f "$INSTALL_PREFIX/bin/$PROXY_BIN" ]; then
        cp "$INSTALL_PREFIX/bin/$PROXY_BIN" "$backup_path/"
    fi

    # Backup configuration
    if [ -d "$CONFIG_DIR" ]; then
        cp -r "$CONFIG_DIR" "$backup_path/"
    fi

    # Create backup info
    cat > "$backup_path/backup.info" <<EOF
Backup Date: $(date)
Version: $(${INSTALL_PREFIX}/bin/${PROXY_BIN} --version 2>/dev/null || echo "unknown")
User: $(whoami)
EOF

    # Compress backup
    tar -czf "$backup_path.tar.gz" -C "$BACKUP_DIR" "$backup_name"
    rm -rf "$backup_path"

    log_info "Backup created: $backup_path.tar.gz"
}

# Start services
start_services() {
    log_info "Starting Sentinel services..."

    # Start main proxy
    systemctl start "$PROXY_SERVICE"

    # Start agents if their services exist
    for service in "$ECHO_SERVICE" "$RATELIMIT_SERVICE"; do
        if systemctl list-unit-files | grep -q "$service"; then
            systemctl start "$service" || log_warn "Failed to start $service"
        fi
    done

    log_info "Services started"
}

# Stop services
stop_services() {
    log_info "Stopping Sentinel services..."

    # Stop agents first
    for service in "$ECHO_SERVICE" "$RATELIMIT_SERVICE" "$DENYLIST_SERVICE"; do
        if systemctl is-active --quiet "$service"; then
            systemctl stop "$service"
        fi
    done

    # Stop main proxy
    systemctl stop "$PROXY_SERVICE" || true

    log_info "Services stopped"
}

# Restart services
restart_services() {
    log_info "Restarting Sentinel services..."
    stop_services
    sleep 2
    start_services
}

# Show service status
show_status() {
    echo "=== Sentinel Service Status ==="
    echo

    # Check main proxy
    echo "Proxy Service ($PROXY_SERVICE):"
    systemctl status "$PROXY_SERVICE" --no-pager | head -n 10
    echo

    # Check agents
    for service in "$ECHO_SERVICE" "$RATELIMIT_SERVICE" "$DENYLIST_SERVICE"; do
        if systemctl list-unit-files | grep -q "$service"; then
            echo "Agent Service ($service):"
            systemctl status "$service" --no-pager | head -n 10 || true
            echo
        fi
    done

    # Check processes
    echo "=== Running Processes ==="
    ps aux | grep -E "($PROXY_BIN|$ECHO_AGENT_BIN|$RATELIMIT_AGENT_BIN)" | grep -v grep || echo "No processes found"

    # Check ports
    echo
    echo "=== Listening Ports ==="
    ss -tlnp | grep -E "(8080|8443|9090)" || echo "No ports found"

    # Check sockets
    echo
    echo "=== Unix Sockets ==="
    ls -la "$RUN_DIR"/*.sock 2>/dev/null || echo "No sockets found"
}

# Validate configuration
validate_config() {
    log_info "Validating configuration..."

    if [ -f "$INSTALL_PREFIX/bin/$PROXY_BIN" ]; then
        "$INSTALL_PREFIX/bin/$PROXY_BIN" \
            --validate \
            --config "$CONFIG_DIR/config.kdl" || {
            log_error "Configuration validation failed"
            exit 1
        }
        log_info "Configuration is valid"
    else
        log_warn "Proxy binary not found, skipping validation"
    fi
}

# Install Sentinel
install() {
    log_info "Installing Sentinel..."

    check_root
    create_user
    create_directories
    build_binaries
    backup_installation 2>/dev/null || true
    install_binaries
    install_services
    deploy_config
    validate_config

    log_info "Installation completed successfully!"
    log_info "Start services with: systemctl start $PROXY_SERVICE"
}

# Upgrade Sentinel
upgrade() {
    log_info "Upgrading Sentinel..."

    check_root
    backup_installation
    stop_services
    build_binaries
    install_binaries
    deploy_config
    validate_config
    start_services

    log_info "Upgrade completed successfully!"
}

# Uninstall Sentinel
uninstall() {
    log_warn "Uninstalling Sentinel..."

    check_root

    # Stop and disable services
    stop_services
    systemctl disable "$PROXY_SERVICE" 2>/dev/null || true

    # Remove service files
    rm -f /etc/systemd/system/sentinel*.service
    systemctl daemon-reload

    # Remove binaries
    rm -f "$INSTALL_PREFIX/bin/$PROXY_BIN"
    rm -f "$INSTALL_PREFIX/bin/$ECHO_AGENT_BIN"
    rm -f "$INSTALL_PREFIX/bin/$RATELIMIT_AGENT_BIN"
    rm -f "$INSTALL_PREFIX/bin/$DENYLIST_AGENT_BIN"
    rm -f "$INSTALL_PREFIX/bin/$WAF_AGENT_BIN"

    # Optional: Remove data (commented by default for safety)
    # rm -rf "$CONFIG_DIR"
    # rm -rf "$DATA_DIR"
    # rm -rf "$LOG_DIR"
    # rm -rf "$RUN_DIR"

    # Optional: Remove user
    # userdel "$SERVICE_USER"

    log_info "Uninstall completed (config and data preserved)"
}

# Rollback to previous version
rollback() {
    log_info "Rolling back to previous version..."

    check_root

    # Find latest backup
    local latest_backup=$(ls -t "$BACKUP_DIR"/sentinel-backup-*.tar.gz 2>/dev/null | head -1)

    if [ -z "$latest_backup" ]; then
        log_error "No backup found to rollback to"
        exit 1
    fi

    log_info "Rolling back to: $(basename $latest_backup)"

    # Stop services
    stop_services

    # Extract backup
    local temp_dir=$(mktemp -d)
    tar -xzf "$latest_backup" -C "$temp_dir"

    # Restore binaries
    local backup_dir="$temp_dir/$(basename $latest_backup .tar.gz)"
    if [ -f "$backup_dir/$PROXY_BIN" ]; then
        cp "$backup_dir/$PROXY_BIN" "$INSTALL_PREFIX/bin/"
        chmod 755 "$INSTALL_PREFIX/bin/$PROXY_BIN"
    fi

    # Restore configuration
    if [ -d "$backup_dir/sentinel" ]; then
        cp -r "$backup_dir/sentinel"/* "$CONFIG_DIR/"
        chown -R "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_DIR"
    fi

    # Clean up
    rm -rf "$temp_dir"

    # Start services
    start_services

    log_info "Rollback completed"
}

# Main script
main() {
    case "${1:-}" in
        install)
            install
            ;;
        upgrade)
            upgrade
            ;;
        uninstall)
            uninstall
            ;;
        start)
            check_root
            start_services
            ;;
        stop)
            check_root
            stop_services
            ;;
        restart)
            check_root
            restart_services
            ;;
        status)
            show_status
            ;;
        config)
            check_root
            deploy_config
            validate_config
            ;;
        backup)
            check_root
            backup_installation
            ;;
        rollback)
            rollback
            ;;
        *)
            echo "Usage: $0 {install|upgrade|uninstall|start|stop|restart|status|config|backup|rollback}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
