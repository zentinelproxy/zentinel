#!/bin/sh
# Sentinel Install Script
# Usage: curl -fsSL https://raw.githubusercontent.com/raskell-io/sentinel/main/install.sh | sh
#
# This script detects your OS and architecture, downloads the appropriate
# pre-built binary, and installs it to /usr/local/bin (or ~/.local/bin if
# /usr/local/bin is not writable).

set -e

# Configuration
REPO="raskell-io/sentinel"
BINARY_NAME="sentinel"
INSTALL_DIR="/usr/local/bin"
FALLBACK_DIR="$HOME/.local/bin"

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

# Get the latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
        grep '"tag_name"' |
        sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and verify the binary
download_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local tmp_dir="$4"

    # Build artifact name
    local artifact="sentinel-${version}-${os}-${arch}.tar.gz"
    local url="https://github.com/${REPO}/releases/download/${version}/${artifact}"
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
            warn "No checksum tool available, skipping verification"
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

    # Find the binary in the extracted files
    local binary_path=""
    if [ -f "${tmp_dir}/${BINARY_NAME}" ]; then
        binary_path="${tmp_dir}/${BINARY_NAME}"
    elif [ -f "${tmp_dir}/bin/${BINARY_NAME}" ]; then
        binary_path="${tmp_dir}/bin/${BINARY_NAME}"
    else
        # Search for it
        binary_path=$(find "$tmp_dir" -name "$BINARY_NAME" -type f | head -n 1)
    fi

    if [ -z "$binary_path" ] || [ ! -f "$binary_path" ]; then
        error "Could not find ${BINARY_NAME} binary in the downloaded archive"
    fi

    # Check if we can write to the install directory
    if [ ! -d "$install_dir" ]; then
        info "Creating directory ${install_dir}..."
        if ! mkdir -p "$install_dir" 2>/dev/null; then
            if [ "$install_dir" = "$INSTALL_DIR" ]; then
                warn "Cannot create ${INSTALL_DIR}, falling back to ${FALLBACK_DIR}"
                install_dir="$FALLBACK_DIR"
                mkdir -p "$install_dir"
            else
                error "Cannot create ${install_dir}"
            fi
        fi
    fi

    # Try to install
    info "Installing to ${install_dir}/${BINARY_NAME}..."
    if ! cp "$binary_path" "${install_dir}/${BINARY_NAME}" 2>/dev/null; then
        if [ "$install_dir" = "$INSTALL_DIR" ]; then
            # Try with sudo
            info "Requesting elevated permissions..."
            if command -v sudo >/dev/null 2>&1; then
                sudo cp "$binary_path" "${install_dir}/${BINARY_NAME}"
                sudo chmod +x "${install_dir}/${BINARY_NAME}"
            else
                warn "Cannot write to ${INSTALL_DIR}, falling back to ${FALLBACK_DIR}"
                install_dir="$FALLBACK_DIR"
                mkdir -p "$install_dir"
                cp "$binary_path" "${install_dir}/${BINARY_NAME}"
                chmod +x "${install_dir}/${BINARY_NAME}"
            fi
        else
            error "Failed to install to ${install_dir}"
        fi
    else
        chmod +x "${install_dir}/${BINARY_NAME}"
    fi

    echo "$install_dir"
}

# Check if directory is in PATH
check_path() {
    local dir="$1"
    case ":$PATH:" in
        *":$dir:"*) return 0 ;;
        *) return 1 ;;
    esac
}

# Main installation
main() {
    echo ""
    printf "${BLUE}┌─────────────────────────────────────┐${NC}\n"
    printf "${BLUE}│${NC}     ${GREEN}Sentinel${NC} Installer             ${BLUE}│${NC}\n"
    printf "${BLUE}│${NC}     Security-first reverse proxy   ${BLUE}│${NC}\n"
    printf "${BLUE}└─────────────────────────────────────┘${NC}\n"
    echo ""

    # Check dependencies
    check_dependencies

    # Detect platform
    local os=$(detect_os)
    local arch=$(detect_arch)
    info "Detected platform: ${os}-${arch}"

    # Check for unsupported combinations
    if [ "$os" = "linux" ] && [ "$arch" = "arm64" ]; then
        error "Linux ARM64 binaries are not yet available. Please build from source or use Docker."
    fi

    # Get latest version
    info "Fetching latest release..."
    local version=$(get_latest_version)
    if [ -z "$version" ]; then
        error "Could not determine latest version"
    fi
    info "Latest version: ${version}"

    # Create temporary directory
    local tmp_dir=$(mktemp -d)
    trap "rm -rf '$tmp_dir'" EXIT

    # Download and extract
    download_binary "$version" "$os" "$arch" "$tmp_dir"

    # Install
    local final_dir=$(install_binary "$tmp_dir" "$INSTALL_DIR")

    # Success!
    echo ""
    success "Sentinel ${version} installed successfully!"
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
    if command -v sentinel >/dev/null 2>&1; then
        info "Verifying installation..."
        sentinel --version 2>/dev/null || true
    else
        echo "Run 'sentinel --help' to get started"
    fi

    echo ""
    printf "Documentation: ${BLUE}https://sentinel.raskell.io${NC}\n"
    printf "GitHub: ${BLUE}https://github.com/${REPO}${NC}\n"
    echo ""
}

# Run main
main "$@"
