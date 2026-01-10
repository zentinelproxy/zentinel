# Sentinel mise Tasks Reference

This document provides a comprehensive reference for all available `mise` tasks in the Sentinel project. Tasks are organized by category for easy navigation.

## Prerequisites

Install mise if you haven't already:
```bash
curl https://mise.run | sh
```

## Task Categories

- [Build Tasks](#build-tasks)
- [Test Tasks](#test-tasks)
- [Code Quality](#code-quality)
- [Development](#development)
- [Agent Tasks](#agent-tasks)
- [Documentation](#documentation)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Performance](#performance)
- [Utilities](#utilities)

---

## Build Tasks

### `mise run build`
Build debug binaries for all workspace members.
```bash
mise run build
```

### `mise run release`
Build optimized release binaries with debug symbols stripped.
```bash
mise run release
```

### `mise run install`
Build release binaries and install them to `/usr/local/bin/` (requires sudo).
```bash
mise run install
```

---

## Test Tasks

### `mise run test`
Run all tests across the workspace with output capture disabled.
```bash
mise run test
```

### `mise run test-unit`
Run only unit tests (lib tests).
```bash
mise run test-unit
```

### `mise run test-integration`
Run integration tests including agent tests.
```bash
mise run test-integration
```

### `mise run test-coverage`
Generate HTML test coverage report using tarpaulin.
```bash
mise run test-coverage
# Report available at: target/coverage/tarpaulin-report.html
```

### `mise run bench`
Run all benchmarks.
```bash
mise run bench
```

---

## Code Quality

### `mise run fmt`
Format all code using rustfmt.
```bash
mise run fmt
```

### `mise run fmt-check`
Check code formatting without making changes.
```bash
mise run fmt-check
```

### `mise run lint`
Run clippy linter with all warnings as errors.
```bash
mise run lint
```

### `mise run audit`
Run security audit on dependencies.
```bash
mise run audit
```

### `mise run check`
Run format, lint, and tests in sequence.
```bash
mise run check
```

### `mise run unused-deps`
Check for unused dependencies using cargo-machete.
```bash
mise run unused-deps
```

---

## Development

### `mise run run`
Run the proxy with debug build and debug logging.
```bash
mise run run
# Uses RUST_LOG=debug by default
```

### `mise run run-release`
Run the proxy with release build.
```bash
mise run run-release
```

### `mise run dev`
Run development environment with proxy and echo agent.
```bash
mise run dev
# Starts:
# - Echo agent on /tmp/sentinel-echo.sock
# - Proxy with debug logging
```

### `mise run watch`
Watch for file changes and auto-rebuild/test.
```bash
mise run watch
```

---

## Agent Tasks

### `mise run agent-echo`
Run the echo agent standalone.
```bash
mise run agent-echo
# Socket: /tmp/echo.sock
```

### `mise run agent-test`
Run agent integration test suite.
```bash
mise run agent-test
```

---

## Documentation

### `mise run docs`
Generate and open documentation in browser.
```bash
mise run docs
```

### `mise run docs-serve`
Generate docs and serve them locally on port 8000.
```bash
mise run docs-serve
# Access at: http://localhost:8000
```

---

## Deployment

### `mise run deploy`
Full deployment to production (build, test, install).
```bash
mise run deploy
```

### `mise run upgrade`
Upgrade existing installation.
```bash
mise run upgrade
```

### `mise run rollback`
Rollback to previous version from backup.
```bash
mise run rollback
```

### `mise run systemd-install`
Install systemd service files.
```bash
mise run systemd-install
```

### `mise run systemd-start`
Start all Sentinel services.
```bash
mise run systemd-start
```

### `mise run systemd-stop`
Stop all Sentinel services.
```bash
mise run systemd-stop
```

### `mise run systemd-status`
Show status of all services.
```bash
mise run systemd-status
```

---

## Configuration

### `mise run config-validate`
Validate the current configuration file.
```bash
mise run config-validate
```

### `mise run config-reload`
Hot reload configuration (send SIGHUP to proxy).
```bash
mise run config-reload
```

### `mise run config-example`
Generate example configuration file.
```bash
mise run config-example
# Creates: config/example.kdl
```

---

## Performance

### `mise run profile`
Run proxy with perf profiling.
```bash
mise run profile
```

### `mise run flamegraph`
Generate flamegraph for performance analysis.
```bash
mise run flamegraph
# Output: flamegraph.svg
```

### `mise run load-test`
Run load tests using k6.
```bash
mise run load-test
```

---

## Utilities

### `mise run clean`
Clean build artifacts and temporary files.
```bash
mise run clean
```

### `mise run clean-all`
Deep clean including installed binaries (requires sudo).
```bash
mise run clean-all
```

### `mise run version`
Show version information.
```bash
mise run version
```

### `mise run stats`
Show project statistics (LOC, dependencies, binary sizes).
```bash
mise run stats
```

### `mise run setup`
Set up development environment with all required tools.
```bash
mise run setup
```

### `mise run ci`
Run all CI checks locally.
```bash
mise run ci
# Runs: fmt-check, lint, test, audit
```

### `mise run all`
Build everything and run all tests.
```bash
mise run all
```

---

## Task Aliases

Short aliases for common tasks:

| Alias | Full Command |
|-------|-------------|
| `mise run b` | `mise run build` |
| `mise run r` | `mise run run` |
| `mise run t` | `mise run test` |
| `mise run c` | `mise run check` |

---

## Environment Variables

Tasks respect these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Log level (trace, debug, info, warn, error) |
| `SENTINEL_CONFIG` | `config/sentinel.kdl` | Configuration file path |
| `SENTINEL_WORKERS` | `0` | Worker threads (0 = CPU count) |
| `RUST_BACKTRACE` | `1` | Show backtraces on panic |

Example usage:
```bash
RUST_LOG=trace mise run run
SENTINEL_CONFIG=/etc/sentinel/prod.kdl mise run run-release
```

---

## Task Dependencies

Some tasks automatically run dependencies:

- `install` → runs `release` first
- `check` → runs `fmt`, `lint`, `test`
- `deploy` → runs `release`, `test`
- `all` → runs `fmt`, `lint`, `build`, `test`, `audit`
- `ci` → runs `fmt-check`, `lint`, `test`, `audit`

---

## Common Workflows

### Development Cycle
```bash
# Initial setup
mise run setup

# Development loop
mise run watch        # In terminal 1
mise run dev          # In terminal 2

# Before commit
mise run check
```

### Testing Changes
```bash
# Quick test
mise run test-unit

# Full test
mise run test

# With coverage
mise run test-coverage
```

### Production Deployment
```bash
# Build and test
mise run release
mise run test

# Deploy
mise run deploy

# Verify
mise run systemd-status
```

### Debugging
```bash
# Verbose logging
RUST_LOG=trace mise run run

# With profiling
mise run profile

# Generate flamegraph
mise run flamegraph
```

---

## Tips and Tricks

1. **List all tasks**: Run `mise tasks` to see all available tasks
2. **Task help**: Run `mise run <task> --help` for task-specific help
3. **Parallel execution**: Some tasks can be run in parallel in different terminals
4. **Custom config**: Override config with `SENTINEL_CONFIG` environment variable
5. **Debug output**: Use `RUST_LOG=debug` or `trace` for verbose output

---

## Troubleshooting

### Task not found
```bash
# Ensure you're in the project root
cd /path/to/sentinel

# Verify mise.toml exists
ls mise.toml
```

### Permission errors
```bash
# Some tasks require sudo (install, systemd-*, clean-all)
sudo mise run install
```

### Build failures
```bash
# Clean and rebuild
mise run clean
mise run build
```

### Missing tools
```bash
# Install all required tools
mise run setup
```

---

## Creating Custom Tasks

Add custom tasks to `mise.toml`:

```toml
[tasks.my-task]
description = "My custom task"
run = "echo 'Hello from custom task'"
depends = ["build"]  # Optional dependencies
```

Then run with:
```bash
mise run my-task
```

---

For more information, see the [Quick Start Guide](../QUICKSTART.md) or run `mise tasks` to explore available commands.