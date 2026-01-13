# syntax=docker/dockerfile:1.4

# Sentinel Optimized Container Image
#
# Targets:
#   - proxy (default): Distroless production image (~20-25MB)
#   - proxy-debug: Alpine with shell for debugging (~35-40MB)
#   - proxy-prebuilt: For CI with pre-built binaries
#   - echo-agent: Echo agent image
#
# Build examples:
#   docker build -t sentinel:latest .
#   docker build --target proxy-debug -t sentinel:debug .

# Build arguments
ARG RUST_VERSION=1.85
ARG DEBIAN_VARIANT=slim-bookworm

################################################################################
# Build stage - compiles the Rust binary with optimizations
################################################################################
FROM rust:${RUST_VERSION}-${DEBIAN_VARIANT} AS builder

# Install build dependencies (only what's needed for compilation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        cmake \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifest files first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/proxy/Cargo.toml crates/proxy/Cargo.toml
COPY crates/agent-protocol/Cargo.toml crates/agent-protocol/Cargo.toml
COPY crates/config/Cargo.toml crates/config/Cargo.toml
COPY crates/common/Cargo.toml crates/common/Cargo.toml
COPY crates/stack/Cargo.toml crates/stack/Cargo.toml
COPY agents/echo/Cargo.toml agents/echo/Cargo.toml

# Create dummy source files for dependency compilation
# This allows Docker to cache the dependency build layer
RUN mkdir -p crates/proxy/src && \
    echo "fn main() {}" > crates/proxy/src/main.rs && \
    echo "" > crates/proxy/src/lib.rs && \
    mkdir -p crates/agent-protocol/src && echo "" > crates/agent-protocol/src/lib.rs && \
    mkdir -p crates/config/src && echo "" > crates/config/src/lib.rs && \
    mkdir -p crates/common/src && echo "" > crates/common/src/lib.rs && \
    mkdir -p crates/stack/src && echo "fn main() {}" > crates/stack/src/main.rs && \
    mkdir -p agents/echo/src && echo "fn main() {}" > agents/echo/src/main.rs

# Build dependencies only (this layer is cached)
RUN cargo build --release --package sentinel-proxy

# Remove dummy source files
RUN rm -rf crates/*/src agents/*/src

# Copy actual source code
COPY crates/ crates/
COPY agents/ agents/

# Touch source files to ensure rebuild
RUN find . -name "main.rs" -exec touch {} \; && \
    find . -name "lib.rs" -exec touch {} \;

# Build release binaries with full optimizations
# Binary is already stripped via Cargo.toml profile.release.strip = true
RUN cargo build --release --package sentinel-proxy --package sentinel-echo-agent

################################################################################
# Production image: Distroless (smallest, most secure)
#
# Uses gcr.io/distroless/cc-debian12 which includes:
# - glibc runtime (required for dynamically-linked Rust binaries)
# - libgcc
# - CA certificates
# - tzdata
# - NO shell, NO package manager (minimal attack surface)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS proxy

# Copy the binary
COPY --from=builder /app/target/release/sentinel /sentinel

# Copy default configuration
COPY config/docker/default.kdl /etc/sentinel/config.kdl

# Labels for container metadata
LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Security-first reverse proxy built on Pingora" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel"

# Environment variables
# - RUST_LOG: Logging configuration
# - MALLOC_CONF: jemalloc tuning for container environments
#   - background_thread: Offload memory purging from request threads
#   - dirty_decay_ms: Return dirty pages to OS within 5s (container memory awareness)
#   - muzzy_decay_ms: Same for muzzy pages
ENV RUST_LOG=info,sentinel_proxy=info \
    MALLOC_CONF="background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000"

# Expose ports:
# - 8080: HTTP listener
# - 8443: HTTPS listener
# - 9090: Metrics/observability
EXPOSE 8080 8443 9090

# Run as non-root user (distroless:nonroot runs as uid 65532)
USER nonroot:nonroot

# Health check notes:
# Distroless has no shell, so HEALTHCHECK with curl/wget isn't possible.
# Use one of these approaches:
# 1. Kubernetes: Configure livenessProbe/readinessProbe with httpGet to /_builtin/health
# 2. Docker Compose: Use `test: ["CMD", "/sentinel", "test", "-c", "/etc/sentinel/config.kdl"]`
# 3. External monitoring: Poll http://container:8080/_builtin/health

# Sentinel handles SIGTERM/SIGHUP natively via signal_hook - no tini needed
ENTRYPOINT ["/sentinel"]
CMD ["-c", "/etc/sentinel/config.kdl"]

################################################################################
# Debug image: Alpine with shell for troubleshooting
################################################################################
FROM alpine:3.23 AS proxy-debug

# Install minimal runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    && adduser -D -u 65532 -g 65532 sentinel

# Copy the binary
COPY --from=builder /app/target/release/sentinel /usr/local/bin/sentinel

# Copy default configuration
COPY config/docker/default.kdl /etc/sentinel/config.kdl

# Create directories with correct ownership
RUN mkdir -p /var/lib/sentinel /var/log/sentinel && \
    chown -R sentinel:sentinel /etc/sentinel /var/lib/sentinel /var/log/sentinel

# Environment variables
ENV RUST_LOG=info,sentinel_proxy=info \
    MALLOC_CONF="background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000"

EXPOSE 8080 8443 9090

USER sentinel

# Alpine has curl, so we can use HTTP health checks
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:8080/_builtin/health || exit 1

ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["-c", "/etc/sentinel/config.kdl"]

################################################################################
# Pre-built binary stage (for CI multi-arch builds)
# Usage: docker build --build-arg BINARY_PATH=./sentinel --target proxy-prebuilt .
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS proxy-prebuilt

# Copy pre-built binary from build context
COPY sentinel /sentinel

# Copy default configuration
COPY config/docker/default.kdl /etc/sentinel/config.kdl

LABEL org.opencontainers.image.title="Sentinel" \
      org.opencontainers.image.description="Security-first reverse proxy built on Pingora"

ENV RUST_LOG=info,sentinel_proxy=info \
    MALLOC_CONF="background_thread:true,dirty_decay_ms:5000,muzzy_decay_ms:5000"

EXPOSE 8080 8443 9090

USER nonroot:nonroot

ENTRYPOINT ["/sentinel"]
CMD ["-c", "/etc/sentinel/config.kdl"]

################################################################################
# Echo agent image (for testing agent functionality)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS echo-agent

COPY --from=builder /app/target/release/sentinel-echo-agent /sentinel-echo-agent

ENV RUST_LOG=info,sentinel_echo_agent=debug \
    SOCKET_PATH=/var/run/sentinel/echo.sock

USER nonroot:nonroot

CMD ["/sentinel-echo-agent"]

################################################################################
# Echo agent pre-built stage (for CI multi-arch builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS echo-agent-prebuilt

COPY sentinel-echo-agent /sentinel-echo-agent

LABEL org.opencontainers.image.title="Sentinel Echo Agent" \
      org.opencontainers.image.description="Echo agent for Sentinel proxy testing"

ENV RUST_LOG=info,sentinel_echo_agent=debug \
    SOCKET_PATH=/var/run/sentinel/echo.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-echo-agent"]
