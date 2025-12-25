# syntax=docker/dockerfile:1.4

# Build arguments
ARG RUST_VERSION=1.75
ARG DEBIAN_VERSION=bookworm-slim

################################################################################
# Create a stage for building the application
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

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
COPY agents/echo/Cargo.toml agents/echo/Cargo.toml
COPY agents/ratelimit/Cargo.toml agents/ratelimit/Cargo.toml
COPY agents/denylist/Cargo.toml agents/denylist/Cargo.toml
COPY agents/waf/Cargo.toml agents/waf/Cargo.toml

# Create dummy source files for dependency compilation
RUN mkdir -p crates/proxy/src && echo "fn main() {}" > crates/proxy/src/main.rs && \
    mkdir -p crates/agent-protocol/src && echo "" > crates/agent-protocol/src/lib.rs && \
    mkdir -p crates/config/src && echo "" > crates/config/src/lib.rs && \
    mkdir -p crates/common/src && echo "" > crates/common/src/lib.rs && \
    mkdir -p agents/echo/src && echo "fn main() {}" > agents/echo/src/main.rs && \
    mkdir -p agents/ratelimit/src && echo "fn main() {}" > agents/ratelimit/src/main.rs && \
    mkdir -p agents/denylist/src && echo "fn main() {}" > agents/denylist/src/main.rs && \
    mkdir -p agents/waf/src && echo "fn main() {}" > agents/waf/src/main.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --workspace

# Remove dummy source files
RUN rm -rf crates/*/src agents/*/src

# Copy actual source code
COPY crates/ crates/
COPY agents/ agents/
COPY src/ src/

# Touch the main files to ensure they're newer than the deps
RUN find . -name "main.rs" -exec touch {} \; && \
    find . -name "lib.rs" -exec touch {} \;

# Build release binaries with optimizations
RUN cargo build --release --workspace && \
    strip /app/target/release/sentinel && \
    strip /app/target/release/sentinel-echo-agent && \
    strip /app/target/release/sentinel-ratelimit-agent && \
    strip /app/target/release/sentinel-denylist-agent && \
    strip /app/target/release/sentinel-waf-agent || true

################################################################################
# Create runtime stage for the proxy
FROM debian:${DEBIAN_VERSION} AS runtime-base

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
# Rate limit agent runtime stage
FROM runtime-base AS ratelimit-agent

# Copy agent binary
COPY --from=builder /app/target/release/sentinel-ratelimit-agent /usr/local/bin/

# Copy default configuration
COPY config/agents/ratelimit.yaml /etc/sentinel/ratelimit.yaml.example

# Switch to non-root user
USER sentinel

# Environment variables
ENV RUST_LOG=info,sentinel_ratelimit_agent=info \
    RATELIMIT_CONFIG=/etc/sentinel/ratelimit.yaml

# Expose metrics port
EXPOSE 9092

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["sentinel-ratelimit-agent"]

################################################################################
# WAF agent runtime stage
FROM runtime-base AS waf-agent

# Install ModSecurity runtime dependencies
RUN apt-get update && \
    apt-get install -y \
        libpcre3 \
        libxml2 \
        libyajl2 \
        libcurl4 \
        libmaxminddb0 \
        liblua5.3-0 \
    && rm -rf /var/lib/apt/lists/*

# Install ModSecurity library (using standalone mode for now)
# In production, you would copy from a ModSecurity build stage
RUN echo "ModSecurity would be installed here in production" > /tmp/modsecurity.note

# Copy agent binary
COPY --from=builder /app/target/release/sentinel-waf-agent /usr/local/bin/

# Copy default configuration
COPY config/waf/waf.yaml /etc/sentinel/waf.yaml.example

# Create audit log directory
RUN mkdir -p /var/log/sentinel-waf && \
    chown -R sentinel:sentinel /var/log/sentinel-waf

# Switch to non-root user
USER sentinel

# Environment variables
ENV RUST_LOG=info,sentinel_waf_agent=info \
    WAF_CONFIG=/etc/sentinel/waf.yaml

# Expose metrics port
EXPOSE 9094

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["sentinel-waf-agent"]

################################################################################
# Echo agent runtime stage (for testing)
FROM runtime-base AS echo-agent

# Copy agent binary
COPY --from=builder /app/target/release/sentinel-echo-agent /usr/local/bin/

# Switch to non-root user
USER sentinel

# Environment variables
ENV RUST_LOG=info,sentinel_echo_agent=debug

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["sentinel-echo-agent", "--socket", "/var/run/sentinel/echo.sock"]

################################################################################
# All-in-one development stage
FROM runtime-base AS all-in-one

# Install ModSecurity runtime dependencies
RUN apt-get update && \
    apt-get install -y \
        libpcre3 \
        libxml2 \
        libyajl2 \
        libcurl4 \
        libmaxminddb0 \
        liblua5.3-0 \
        supervisor \
    && rm -rf /var/lib/apt/lists/*

# Copy all binaries
COPY --from=builder /app/target/release/sentinel /usr/local/bin/
COPY --from=builder /app/target/release/sentinel-echo-agent /usr/local/bin/
COPY --from=builder /app/target/release/sentinel-ratelimit-agent /usr/local/bin/
COPY --from=builder /app/target/release/sentinel-denylist-agent /usr/local/bin/
COPY --from=builder /app/target/release/sentinel-waf-agent /usr/local/bin/

# Copy configuration examples
COPY config/ /etc/sentinel/config-examples/

# Create supervisord configuration
RUN <<SUPERVISOR_EOF cat > /etc/supervisor/conf.d/sentinel.conf
[supervisord]
nodaemon=true
user=sentinel
logfile=/var/log/sentinel/supervisord.log

[program:proxy]
command=/usr/local/bin/sentinel -c /etc/sentinel/config.kdl
user=sentinel
autostart=true
autorestart=true
stdout_logfile=/var/log/sentinel/proxy.log
stderr_logfile=/var/log/sentinel/proxy-error.log

[program:ratelimit]
command=/usr/local/bin/sentinel-ratelimit-agent
user=sentinel
autostart=false
autorestart=true
stdout_logfile=/var/log/sentinel/ratelimit.log
stderr_logfile=/var/log/sentinel/ratelimit-error.log

[program:waf]
command=/usr/local/bin/sentinel-waf-agent
user=sentinel
autostart=false
autorestart=true
stdout_logfile=/var/log/sentinel/waf.log
stderr_logfile=/var/log/sentinel/waf-error.log

[program:echo]
command=/usr/local/bin/sentinel-echo-agent --socket /var/run/sentinel/echo.sock
user=sentinel
autostart=false
autorestart=true
stdout_logfile=/var/log/sentinel/echo.log
stderr_logfile=/var/log/sentinel/echo-error.log
SUPERVISOR_EOF

# Create startup script
RUN <<STARTUP_EOF cat > /usr/local/bin/start-sentinel && chmod +x /usr/local/bin/start-sentinel
#!/bin/bash
set -e

echo "Starting Sentinel all-in-one container..."

# Copy example configs if not present
if [ ! -f /etc/sentinel/config.kdl ]; then
    echo "No config found, copying example..."
    cp /etc/sentinel/config-examples/examples/basic.kdl /etc/sentinel/config.kdl
fi

# Start supervisord
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/sentinel.conf
STARTUP_EOF

# Switch to non-root user
USER sentinel

# Environment variables
ENV RUST_LOG=info \
    SENTINEL_CONFIG=/etc/sentinel/config.kdl

# Expose all ports
EXPOSE 8080 8443 9090 9091 9092 9093 9094

# Health check
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:9090/health || exit 1

# Use tini for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["/usr/local/bin/start-sentinel"]
