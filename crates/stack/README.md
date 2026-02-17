# Zentinel Stack

All-in-one launcher for Zentinel proxy and agents.

## Overview

The `zentinel-stack` binary spawns and manages the Zentinel proxy along with configured external agents as child processes. It's designed for development and simple production deployments where you need to coordinate multiple processes as a single unit.

## Features

- **Process Management** - Spawn and monitor proxy and agents
- **Restart Policies** - Automatic restart on failure with configurable limits
- **Graceful Shutdown** - Orderly termination with SIGTERM/SIGINT handling
- **Configuration Validation** - Dry-run mode to validate before starting
- **Structured Logging** - JSON-formatted logs for monitoring

## Installation

```bash
cargo install zentinel-stack
```

Or build from source:

```bash
cargo build --release -p zentinel-stack
```

## Quick Start

```bash
# Start proxy and all configured agents
zentinel-stack --config zentinel.kdl

# Validate configuration without starting
zentinel-stack --config zentinel.kdl --dry-run

# Start only the proxy (agents managed externally)
zentinel-stack --config zentinel.kdl --proxy-only

# Start only agents (proxy managed externally)
zentinel-stack --config zentinel.kdl --agents-only
```

## Command-Line Options

```
zentinel-stack [OPTIONS]

Options:
  -c, --config <PATH>           Path to configuration file [default: zentinel.kdl]
  -l, --log-level <LEVEL>       Log level: trace, debug, info, warn, error [default: info]
      --proxy-only              Start only the proxy (agents managed externally)
      --agents-only             Start only agents (proxy managed externally)
      --dry-run                 Validate configuration and exit
      --shutdown-timeout <SEC>  Graceful shutdown timeout [default: 30]
      --startup-timeout <SEC>   Agent startup timeout [default: 10]
  -h, --help                    Print help
  -V, --version                 Print version
```

## Configuration

Agents are configured in the KDL configuration file:

```kdl
agents {
    agent "waf-agent" {
        command "/usr/local/bin/waf-agent" "--config" "/etc/zentinel/waf.toml"
        restart-policy "always"
        restart-delay-ms 1000
        max-restarts 5
        env {
            RUST_LOG "info"
            WAF_RULES_PATH "/etc/zentinel/rules"
        }
    }

    agent "auth-agent" {
        command "/usr/local/bin/auth-agent"
        restart-policy "on-failure"
        restart-delay-ms 2000
        max-restarts 3
        env {
            AUTH_BACKEND "https://auth.internal:8443"
            API_KEY "${HOME}/.config/zentinel/api-key"
        }
    }
}
```

### Agent Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `command` | strings | (required) | Command and arguments to execute |
| `restart-policy` | string | `"always"` | Restart behavior: `always`, `on-failure`, `never` |
| `restart-delay-ms` | integer | `1000` | Delay between restart attempts (ms) |
| `max-restarts` | integer | `0` | Maximum restarts (0 = unlimited) |
| `env` | block | `{}` | Environment variables for the agent |

### Restart Policies

| Policy | Description |
|--------|-------------|
| `always` | Always restart the agent when it exits |
| `on-failure` | Only restart if exit code is non-zero |
| `never` | Do not restart the agent |

### Environment Variable Expansion

Agent environment variables support `${VAR}` expansion:

```kdl
agent "my-agent" {
    command "/usr/local/bin/agent"
    env {
        HOME_DIR "${HOME}"
        CONFIG_PATH "${XDG_CONFIG_HOME}/zentinel"
        API_KEY "${ZENTINEL_API_KEY}"
    }
}
```

## Process Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                        Startup Phase                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Parse CLI arguments                                         │
│   2. Initialize logging (JSON format)                            │
│   3. Parse and validate configuration                            │
│   4. Register signal handlers (SIGTERM, SIGINT)                  │
│   5. Start all configured agents                                 │
│   6. Wait for startup timeout                                    │
│   7. Start Zentinel proxy                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Monitoring Loop                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   Every 500ms:                                                   │
│     - Check proxy status (exit triggers shutdown)               │
│     - Check each agent status                                    │
│     - Restart agents per policy if needed                        │
│     - Check shutdown flag                                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Graceful Shutdown                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   1. Stop proxy (SIGTERM, 5s grace, then SIGKILL)               │
│   2. Stop all agents (SIGTERM, 5s grace, then SIGKILL)          │
│   3. Exit cleanly                                                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGTERM` | Initiates graceful shutdown |
| `SIGINT` | Initiates graceful shutdown (Ctrl+C) |

## Logging

Logs are JSON-structured for easy parsing:

```json
{"timestamp":"2024-01-15T10:30:00Z","level":"INFO","message":"Starting agent","agent":"waf-agent"}
{"timestamp":"2024-01-15T10:30:01Z","level":"INFO","message":"Agent started","agent":"waf-agent","pid":12345}
{"timestamp":"2024-01-15T10:30:02Z","level":"INFO","message":"Starting proxy"}
{"timestamp":"2024-01-15T10:30:03Z","level":"INFO","message":"Proxy started","pid":12346}
```

Set log level via CLI or environment:

```bash
# Via CLI
zentinel-stack --log-level debug

# Via environment
RUST_LOG=debug zentinel-stack
```

## Use Cases

### Development Environment

Start the entire stack with a single command:

```bash
zentinel-stack --config dev.kdl
```

### Simple Production

For standalone servers without complex orchestration:

```bash
zentinel-stack --config /etc/zentinel/zentinel.kdl \
    --shutdown-timeout 60 \
    --log-level info
```

### Testing

Validate configuration before deployment:

```bash
zentinel-stack --config zentinel.kdl --dry-run
```

### Separate Management

Run proxy and agents independently:

```bash
# Terminal 1: Run agents
zentinel-stack --config zentinel.kdl --agents-only

# Terminal 2: Run proxy
zentinel-stack --config zentinel.kdl --proxy-only
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        zentinel-stack                            │
│                     (Process Manager)                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │   Proxy     │    │ WAF Agent   │    │ Auth Agent  │        │
│   │  Process    │    │  Process    │    │  Process    │        │
│   └─────────────┘    └─────────────┘    └─────────────┘        │
│         │                  │                  │                 │
│         └──────────────────┼──────────────────┘                 │
│                            │                                     │
│                    Unix Domain Sockets                           │
│                   (agent-protocol)                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Comparison with Other Approaches

| Approach | Use Case | Complexity |
|----------|----------|------------|
| `zentinel-stack` | Development, simple deployments | Low |
| systemd | Production Linux servers | Medium |
| Docker Compose | Containerized deployments | Medium |
| Kubernetes | Large-scale production | High |

## Minimum Rust Version

Rust 1.92.0 or later (Edition 2021)
