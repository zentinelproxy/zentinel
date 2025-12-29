# syntax=docker/dockerfile:1.4

# Build arguments
ARG RUST_VERSION=1.85
ARG DEBIAN_VARIANT=slim-bookworm

################################################################################
# Create a stage for building the application
FROM rust:${RUST_VERSION}-${DEBIAN_VARIANT} AS builder

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
        pkg-config \
        libssl-dev \
        protobuf-compiler \
        cmake \
        build-essential \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifest files first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/proxy/Cargo.toml crates/proxy/Cargo.toml
COPY crates/agent-protocol/Cargo.toml crates/agent-protocol/Cargo.toml
COPY crates/config/Cargo.toml crates/config/Cargo.toml
COPY crates/common/Cargo.toml crates/common/Cargo.toml
COPY crates/stack/Cargo.toml crates/stack/Cargo.toml
COPY agents/echo/Cargo.toml agents/echo/Cargo.toml

# Create dummy source files for dependency compilation
# sentinel-proxy has both lib.rs and main.rs (binary + library)
RUN mkdir -p crates/proxy/src && \
    echo "fn main() {}" > crates/proxy/src/main.rs && \
    echo "" > crates/proxy/src/lib.rs && \
    mkdir -p crates/agent-protocol/src && echo "" > crates/agent-protocol/src/lib.rs && \
    mkdir -p crates/config/src && echo "" > crates/config/src/lib.rs && \
    mkdir -p crates/common/src && echo "" > crates/common/src/lib.rs && \
    mkdir -p crates/stack/src && echo "fn main() {}" > crates/stack/src/main.rs && \
    mkdir -p agents/echo/src && echo "fn main() {}" > agents/echo/src/main.rs

# Build dependencies for proxy only (this layer will be cached)
RUN cargo build --release --package sentinel-proxy

# Remove dummy source files
RUN rm -rf crates/*/src agents/*/src

# Copy actual source code
COPY crates/ crates/
COPY agents/ agents/

# Touch the main files to ensure they're newer than the deps
RUN find . -name "main.rs" -exec touch {} \; && \
    find . -name "lib.rs" -exec touch {} \;

# Build release binary with optimizations (proxy only)
RUN cargo build --release --package sentinel-proxy && \
    strip /app/target/release/sentinel

################################################################################
# Create runtime stage for the proxy
FROM debian:bookworm-slim AS runtime-base

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y \
        libssl3 \
        ca-certificates \
        curl \
        jq \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r sentinel -g 1000 && \
    useradd -r -g sentinel -u 1000 -m -s /bin/bash sentinel

# Create required directories
RUN mkdir -p \
    /etc/sentinel \
    /var/lib/sentinel \
    /var/log/sentinel \
    /var/run/sentinel \
    /usr/local/share/sentinel \
    && chown -R sentinel:sentinel \
    /etc/sentinel \
    /var/lib/sentinel \
    /var/log/sentinel \
    /var/run/sentinel \
    /usr/local/share/sentinel

################################################################################
# Proxy runtime stage
FROM runtime-base AS proxy

# Copy proxy binary
COPY --from=builder /app/target/release/sentinel /usr/local/bin/

# Copy default configuration
COPY config/examples/basic.kdl /etc/sentinel/config.kdl.example

# Set up health check script
RUN echo '#!/bin/sh\ncurl -f http://localhost:9090/health || exit 1' > /usr/local/bin/healthcheck && \
    chmod +x /usr/local/bin/healthcheck

# Switch to non-root user
USER sentinel

# Environment variables
ENV RUST_LOG=info,sentinel_proxy=info \
    SENTINEL_CONFIG=/etc/sentinel/config.kdl \
    SENTINEL_DATA_DIR=/var/lib/sentinel \
    SENTINEL_LOG_DIR=/var/log/sentinel

# Expose ports
EXPOSE 8080 8443 9090

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/healthcheck"]

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["sentinel", "-c", "/etc/sentinel/config.kdl"]

################################################################################
# NOTE: Additional agents (echo, ratelimit, waf, etc.) are available as
# separate repositories. See https://github.com/raskell-io for community agents.
