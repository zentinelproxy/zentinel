#!/bin/sh
# Zentinel Install Script
# Usage: curl -fsSL https://get.zentinelproxy.io | sh
#
# Detects your OS and architecture, downloads the appropriate pre-built
# binary, and installs it to /usr/local/bin (or ~/.local/bin if
# /usr/local/bin is not writable).
#
# On systemd hosts (when running as root or via sudo) it also installs:
#   - /etc/systemd/system/zentinel.service
#   - /usr/lib/sysusers.d/zentinel.conf
#   - /etc/zentinel/zentinel.kdl  (starter config; preserved if present)
#
# Service enable and start are opt-in. Pass --enable-service to enable
# and start zentinel.service after install. Pass --skip-service to skip
# all systemd setup.
#
# After installation, use `zentinel bundle install` to install bundled
# agents (WAF, rate limiter, denylist).
# See https://zentinelproxy.io/docs/deployment/bundle/
#
# Options:
#   --help              Show help message
#   --enable-service    Enable and start zentinel.service after install
#   --skip-service      Skip systemd unit, sysusers, and starter config
#   --binary-only       Alias for --skip-service

set -e

# Configuration
REPO="zentinelproxy/zentinel"
BINARY_NAME="zentinel"
INSTALL_DIR="/usr/local/bin"
FALLBACK_DIR="$HOME/.local/bin"

# Systemd / config layout
SYSTEMD_UNIT_PATH="/etc/systemd/system/zentinel.service"
SYSUSERS_PATH="/usr/lib/sysusers.d/zentinel.conf"
CONFIG_DIR="/etc/zentinel"
CONFIG_FILE="${CONFIG_DIR}/zentinel.kdl"

# Flags
ENABLE_SERVICE=0
SKIP_SERVICE=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
info() {
    printf "${BLUE}info${NC}: %s\n" "$1"
}

success() {
    printf "${GREEN}success${NC}: %s\n" "$1"
}

warn() {
    printf "${YELLOW}warning${NC}: %s\n" "$1"
}

error() {
    printf "${RED}error${NC}: %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) error "Windows is not yet supported. Please use WSL or Docker." ;;
        *)          error "Unsupported operating system: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Check for required commands
check_dependencies() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required command not found: $cmd"
        fi
    done
}

# Get the latest release version that has downloadable binaries.
# Uses /releases (not /releases/latest) because the "latest" release may lack
# binary assets if it was tagged manually without going through CI.
# Checks for both zentinel-* and sentinel-* asset names (pre-rename releases).
get_latest_version() {
    local tmp_releases="${tmp_dir:-.}/.releases.json"
    curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=10" \
        -o "$tmp_releases"

    if command -v jq >/dev/null 2>&1; then
        jq -r '
            [.[] | select(.draft == false and .prerelease == false and
                (.assets | map(.name) | any(test("^(zentinel|sentinel)-.*\\.tar\\.gz$"))))]
            | .[0].tag_name // empty
        ' "$tmp_releases"
    else
        # Fallback: line-oriented parsing of GitHub's JSON response.
        # Releases are returned newest-first; find the first with binary assets.
        awk '
            /"tag_name":/ {
                gsub(/.*"tag_name": *"/, "")
                gsub(/".*/, "")
                tag = $0
            }
            /"prerelease": *true/ { tag = "" }
            /"name":.*(zentinel|sentinel)-.*tar\.gz"/ {
                if (tag) { print tag; exit }
            }
        ' "$tmp_releases"
    fi
    rm -f "$tmp_releases"
}

# Download and verify the binary
download_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local tmp_dir="$4"

    # Build artifact name — try zentinel-* first, fall back to sentinel-* (pre-rename releases)
    local artifact="zentinel-${version}-${os}-${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${artifact}"

    if ! curl -fsSL --head "$url" >/dev/null 2>&1; then
        artifact="sentinel-${version}-${os}-${arch}.tar.gz"
        url="https://github.com/${REPO}/releases/download/${version}/${artifact}"
    fi
    local checksum_url="${url}.sha256"

    info "Downloading ${artifact}..."

    # Download the tarball
    if ! curl -fsSL -o "${tmp_dir}/${artifact}" "$url"; then
        error "Failed to download ${artifact}. Check if the release exists for your platform."
    fi

    # Download and verify checksum
    info "Verifying checksum..."
    if curl -fsSL -o "${tmp_dir}/${artifact}.sha256" "$checksum_url" 2>/dev/null; then
        cd "$tmp_dir"
        if command -v sha256sum >/dev/null 2>&1; then
            if ! sha256sum -c "${artifact}.sha256" >/dev/null 2>&1; then
                error "Checksum verification failed!"
            fi
        elif command -v shasum >/dev/null 2>&1; then
            expected=$(cat "${artifact}.sha256" | awk '{print $1}')
            actual=$(shasum -a 256 "${artifact}" | awk '{print $1}')
            if [ "$expected" != "$actual" ]; then
                error "Checksum verification failed!"
            fi
        else
            warn "No checksum tool available (sha256sum or shasum)"
            warn "Skipping verification - binary integrity cannot be confirmed"
            warn "Consider installing coreutils for checksum verification"
        fi
        cd - >/dev/null
    else
        warn "Checksum file not available, skipping verification"
    fi

    # Extract the tarball
    info "Extracting..."
    tar -xzf "${tmp_dir}/${artifact}" -C "$tmp_dir"
}

# Install the binary
install_binary() {
    local tmp_dir="$1"
    local install_dir="$2"

    # Find the binary in the extracted files (check zentinel first, then sentinel for pre-rename releases)
    local binary_path=""
    for name in "$BINARY_NAME" "sentinel"; do
        if [ -f "${tmp_dir}/${name}" ]; then
            binary_path="${tmp_dir}/${name}"
            break
        elif [ -f "${tmp_dir}/bin/${name}" ]; then
            binary_path="${tmp_dir}/bin/${name}"
            break
        fi
    done

    if [ -z "$binary_path" ] || [ ! -f "$binary_path" ]; then
        error "Could not find ${BINARY_NAME} binary in the downloaded archive"
    fi

    # Check if we can write to the install directory
    if [ ! -d "$install_dir" ]; then
        if ! mkdir -p "$install_dir" 2>/dev/null; then
            if [ "$install_dir" = "$INSTALL_DIR" ]; then
                install_dir="$FALLBACK_DIR"
                mkdir -p "$install_dir" 2>/dev/null || true
            fi
        fi
    fi

    # Try to install
    if ! cp "$binary_path" "${install_dir}/${BINARY_NAME}" 2>/dev/null; then
        if [ "$install_dir" = "$INSTALL_DIR" ]; then
            # Try with sudo, fall back to ~/.local/bin if that fails
            if command -v sudo >/dev/null 2>&1; then
                echo ""
                info "Installing to ${install_dir} requires administrator privileges."
                info "You may be prompted for your password."
                echo ""
                if ! sudo cp "$binary_path" "${install_dir}/${BINARY_NAME}" 2>/dev/null; then
                    install_dir="$FALLBACK_DIR"
                    mkdir -p "$install_dir"
                    info "sudo failed, installing to ${install_dir} instead..."
                    cp "$binary_path" "${install_dir}/${BINARY_NAME}"
                    chmod +x "${install_dir}/${BINARY_NAME}"
                else
                    sudo chmod +x "${install_dir}/${BINARY_NAME}"
                fi
            else
                install_dir="$FALLBACK_DIR"
                mkdir -p "$install_dir"
                info "Installing to ${install_dir}/${BINARY_NAME}..."
                cp "$binary_path" "${install_dir}/${BINARY_NAME}"
                chmod +x "${install_dir}/${BINARY_NAME}"
            fi
        else
            error "Failed to install to ${install_dir}"
        fi
    else
        info "Installing to ${install_dir}/${BINARY_NAME}..."
        chmod +x "${install_dir}/${BINARY_NAME}"
    fi

    # Return the install directory via a file to avoid stdout pollution
    echo "$install_dir" > "${tmp_dir}/.install_dir"
}

# Check if directory is in PATH
check_path() {
    local dir="$1"
    case ":$PATH:" in
        *":$dir:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Run a command as root, using sudo if available and not already root.
# Returns non-zero if elevation is impossible.
as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        return 1
    fi
}

# Fetch a file from the repo at $version (or main as fallback) into $1.
# $1 = destination path
# $2 = repo-relative source path
fetch_repo_file() {
    local dest="$1"
    local src="$2"
    local version="$3"

    local tag_url="https://raw.githubusercontent.com/${REPO}/${version}/${src}"
    local main_url="https://raw.githubusercontent.com/${REPO}/main/${src}"

    if curl -fsSL "$tag_url" -o "$dest" 2>/dev/null; then
        return 0
    fi
    if curl -fsSL "$main_url" -o "$dest" 2>/dev/null; then
        warn "Using ${src} from main branch (release tag ${version} did not include it)"
        return 0
    fi
    return 1
}

# Set up the systemd unit, sysusers snippet, and starter config.
# Skips with a clear message when systemd is unavailable, the user is not
# root and cannot escalate, or --skip-service was passed.
setup_systemd() {
    local version="$1"
    local tmp_dir="$2"

    if [ "$SKIP_SERVICE" = 1 ]; then
        info "Skipping systemd setup (--skip-service)"
        return 0
    fi

    if [ "$(uname -s)" != "Linux" ]; then
        return 0
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        info "systemd not detected; skipping service setup"
        return 0
    fi

    # We need to be able to write to /etc, /usr/lib, and run systemctl.
    if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
        warn "Cannot configure systemd unit (not root and sudo unavailable)"
        warn "Re-run as root or with sudo to install the zentinel.service unit"
        return 0
    fi

    info "Configuring systemd unit and starter config..."

    # Stage files in tmp dir, then copy under sudo in a single batch.
    local stage_unit="${tmp_dir}/zentinel.service"
    local stage_sysusers="${tmp_dir}/zentinel.sysusers.conf"
    local stage_starter="${tmp_dir}/zentinel.starter.kdl"

    if ! fetch_repo_file "$stage_unit" "deploy/zentinel.service" "$version"; then
        warn "Failed to fetch deploy/zentinel.service; skipping systemd setup"
        return 0
    fi
    if ! fetch_repo_file "$stage_sysusers" "deploy/sysusers.d/zentinel.conf" "$version"; then
        warn "Failed to fetch deploy/sysusers.d/zentinel.conf; skipping systemd setup"
        return 0
    fi
    if ! fetch_repo_file "$stage_starter" "deploy/zentinel.starter.kdl" "$version"; then
        warn "Failed to fetch deploy/zentinel.starter.kdl; skipping systemd setup"
        return 0
    fi

    if [ "$(id -u)" -ne 0 ]; then
        info "systemd setup requires administrator privileges; you may be prompted."
    fi

    # Drop the sysusers snippet, then apply via systemd-sysusers when
    # available. Verify the user exists afterwards and fall back to useradd
    # if needed.
    as_root install -D -m 0644 "$stage_sysusers" "$SYSUSERS_PATH" \
        || error "Failed to install ${SYSUSERS_PATH}"

    if as_root sh -c 'command -v systemd-sysusers >/dev/null 2>&1'; then
        as_root systemd-sysusers || warn "systemd-sysusers exited non-zero; will verify user separately"
    fi

    if ! getent passwd zentinel >/dev/null 2>&1; then
        info "Creating zentinel system user via useradd..."
        as_root useradd --system --shell /usr/sbin/nologin \
            --home-dir /var/lib/zentinel --comment "Zentinel reverse proxy" \
            zentinel || warn "Failed to create zentinel user; service will not start"
    fi

    # Install the unit file.
    as_root install -D -m 0644 "$stage_unit" "$SYSTEMD_UNIT_PATH" \
        || error "Failed to install ${SYSTEMD_UNIT_PATH}"

    # Install the starter config (preserve any existing edits).
    as_root install -d -m 0755 "$CONFIG_DIR"
    if [ -e "$CONFIG_FILE" ]; then
        info "Preserving existing ${CONFIG_FILE}"
    else
        as_root install -m 0644 "$stage_starter" "$CONFIG_FILE" \
            || error "Failed to install ${CONFIG_FILE}"
    fi

    # Reload systemd to pick up the new unit.
    as_root systemctl daemon-reload \
        || warn "systemctl daemon-reload failed; you may need to reload manually"

    if [ "$ENABLE_SERVICE" = 1 ]; then
        info "Enabling and starting zentinel.service..."
        if as_root systemctl enable --now zentinel.service; then
            success "zentinel.service is active"
        else
            warn "Failed to enable/start zentinel.service. Check: journalctl -u zentinel"
        fi
    fi
}

# Print next-step hints once the install is complete.
print_next_steps() {
    local final_dir="$1"
    local version="$2"

    echo ""
    if [ -e "$SYSTEMD_UNIT_PATH" ]; then
        if [ "$ENABLE_SERVICE" = 1 ]; then
            printf "${GREEN}zentinel.service${NC} is enabled and running.\n"
            printf "  Logs:    ${BLUE}journalctl -u zentinel -f${NC}\n"
            printf "  Status:  ${BLUE}systemctl status zentinel${NC}\n"
            printf "  Config:  ${BLUE}%s${NC}\n" "$CONFIG_FILE"
        else
            printf "${YELLOW}Next steps${NC} (service is installed but not started):\n"
            printf "  1. Edit config:   ${BLUE}sudoedit %s${NC}\n" "$CONFIG_FILE"
            printf "  2. Validate:      ${BLUE}zentinel test --config %s${NC}\n" "$CONFIG_FILE"
            printf "  3. Enable+start:  ${BLUE}sudo systemctl enable --now zentinel${NC}\n"
            printf "  4. Tail logs:     ${BLUE}journalctl -u zentinel -f${NC}\n"
        fi
    else
        printf "${YELLOW}Next steps${NC}:\n"
        printf "  1. Run the proxy:    ${BLUE}zentinel${NC}            # uses embedded default config\n"
        printf "  2. With your config: ${BLUE}zentinel --config zentinel.kdl${NC}\n"
        printf "  3. Validate config:  ${BLUE}zentinel test --config zentinel.kdl${NC}\n"
    fi
    echo ""
    printf "Documentation: ${BLUE}https://docs.zentinelproxy.io${NC}\n"
    printf "GitHub:        ${BLUE}https://github.com/${REPO}${NC}\n"
    echo ""
    printf "${YELLOW}Tip:${NC} To install bundled agents (WAF, rate limiter, denylist):\n"
    printf "     ${GREEN}sudo zentinel bundle install${NC}\n"
    echo ""
}

# Show help message
show_help() {
    cat << EOF
Zentinel Install Script

Usage: curl -fsSL https://get.zentinelproxy.io | sh
       curl -fsSL https://get.zentinelproxy.io | sh -s -- [options]

Options:
    --help              Show this help message
    --enable-service    Enable and start zentinel.service after install
                        (also accepts ZENTINEL_ENABLE_SERVICE=1)
    --skip-service      Skip systemd unit, sysusers, and starter config
    --binary-only       Alias for --skip-service

Default behavior on systemd hosts:
    Installs the systemd unit, sysusers snippet, and starter config at
    /etc/zentinel/zentinel.kdl, but does not enable or start the service.
    Pass --enable-service for Caddy/Nginx-style auto-start.

After installing Zentinel, you can install bundled agents using:

    sudo zentinel bundle install

This downloads and installs:
    - WAF agent (ModSecurity-based firewall)
    - Rate limit agent (token bucket limiting)
    - Denylist agent (IP/path blocking)

See the bundle command documentation:
    https://zentinelproxy.io/docs/deployment/bundle/

For more information: https://docs.zentinelproxy.io
EOF
}

# Parse command line arguments
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                show_help
                exit 0
                ;;
            --enable-service)
                ENABLE_SERVICE=1
                ;;
            --skip-service|--binary-only)
                SKIP_SERVICE=1
                ;;
            *)
                warn "Unknown option: $1"
                ;;
        esac
        shift
    done

    # Environment variable opt-in
    case "${ZENTINEL_ENABLE_SERVICE:-}" in
        1|true|yes) ENABLE_SERVICE=1 ;;
    esac
}

# Main installation
main() {
    parse_args "$@"
    echo ""

    printf "${BLUE}┌─────────────────────────────────────┐${NC}\n"
    printf "${BLUE}│${NC}     ${GREEN}Zentinel${NC} Installer              ${BLUE}│${NC}\n"
    printf "${BLUE}│${NC}     Security-first reverse proxy    ${BLUE}│${NC}\n"
    printf "${BLUE}└─────────────────────────────────────┘${NC}\n"
    echo ""

    # Check dependencies
    check_dependencies

    # Detect platform
    local os=$(detect_os)
    local arch=$(detect_arch)
    info "Detected platform: ${os}-${arch}"

    # Create temporary directory
    local tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    # Download and install
    info "Fetching latest release..."
    local version=$(get_latest_version)
    if [ -z "$version" ]; then
        error "Could not determine latest version"
    fi
    info "Latest version: ${version}"

    # Download and extract
    download_binary "$version" "$os" "$arch" "$tmp_dir"

    # Install
    install_binary "$tmp_dir" "$INSTALL_DIR"
    local final_dir=$(cat "${tmp_dir}/.install_dir")

    # Success!
    echo ""
    success "Zentinel ${version} installed to ${final_dir}/${BINARY_NAME}"
    echo ""

    # Check if in PATH
    if ! check_path "$final_dir"; then
        warn "${final_dir} is not in your PATH"
        echo ""
        echo "Add it to your PATH by running:"
        echo ""
        if [ -f "$HOME/.zshrc" ]; then
            printf "  ${YELLOW}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc${NC}\n" "$final_dir"
        elif [ -f "$HOME/.bashrc" ]; then
            printf "  ${YELLOW}echo 'export PATH=\"%s:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}\n" "$final_dir"
        else
            printf "  ${YELLOW}export PATH=\"%s:\$PATH\"${NC}\n" "$final_dir"
        fi
        echo ""
    fi

    # Verify installation
    if command -v zentinel >/dev/null 2>&1; then
        info "Verifying installation..."
        zentinel --version 2>/dev/null || true
    fi

    # Optional systemd setup (Linux + systemd only)
    setup_systemd "$version" "$tmp_dir"

    print_next_steps "$final_dir" "$version"
}

# Run main
main "$@"
