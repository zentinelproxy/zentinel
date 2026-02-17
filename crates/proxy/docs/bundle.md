# Bundle Command

The `zentinel bundle` command manages the installation of bundled agents - a curated set of agents that are tested to work together with a specific version of Zentinel.

## Overview

Instead of manually downloading and configuring each agent, the bundle command:

1. Reads a version lock file that pins compatible agent versions
2. Downloads agents from their respective GitHub releases
3. Installs binaries to the appropriate locations
4. Optionally generates configuration and systemd service files

## Quick Start

```bash
# Install Zentinel first
curl -fsSL https://getzentinelproxy.io | sh

# Install all bundled agents
sudo zentinel bundle install

# Check what's installed
zentinel bundle status

# Start everything
sudo systemctl start zentinel.target
```

## Commands

### `zentinel bundle install`

Downloads and installs bundled agents.

```bash
# Install all agents
zentinel bundle install

# Install a specific agent
zentinel bundle install waf

# Preview without installing
zentinel bundle install --dry-run

# Force reinstall
zentinel bundle install --force

# Include systemd services
zentinel bundle install --systemd

# Custom installation prefix
zentinel bundle install --prefix /opt/zentinel
```

**Options:**

| Option | Description |
|--------|-------------|
| `--dry-run, -n` | Preview what would be installed |
| `--force, -f` | Reinstall even if already up to date |
| `--systemd` | Also install systemd service files |
| `--prefix PATH` | Custom installation prefix |
| `--skip-verify` | Skip SHA256 checksum verification |

### `zentinel bundle status`

Shows the installation status of all bundled agents.

```bash
zentinel bundle status
```

Example output:

```
Zentinel Bundle Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Bundle version: 26.01_1
Install path:   /usr/local/bin

Agent           Installed    Expected     Status
─────────────────────────────────────────────────
denylist        0.2.0        0.2.0        ✓ up to date
ratelimit       0.2.0        0.2.0        ✓ up to date
waf             -            0.2.0        ✗ not installed

Total: 3 | Up to date: 2 | Outdated: 0 | Not installed: 1
```

### `zentinel bundle list`

Lists available agents in the bundle.

```bash
zentinel bundle list
zentinel bundle list --verbose  # Show download URLs
```

### `zentinel bundle uninstall`

Removes installed agents.

```bash
# Uninstall all agents
zentinel bundle uninstall

# Uninstall a specific agent
zentinel bundle uninstall waf

# Preview
zentinel bundle uninstall --dry-run
```

### `zentinel bundle update`

Checks for available updates.

```bash
# Check for updates
zentinel bundle update

# Show and apply updates
zentinel bundle update --apply
```

## Bundled Agents

The bundle includes agents that cover ~80% of production use cases:

| Agent | Purpose |
|-------|---------|
| **waf** | ModSecurity-based Web Application Firewall |
| **ratelimit** | Token bucket rate limiting |
| **denylist** | IP and path blocking |

## Installation Paths

**System-wide (requires root):**
- Binaries: `/usr/local/bin/zentinel-{agent}-agent`
- Configs: `/etc/zentinel/agents/{agent}.yaml`
- Systemd: `/etc/systemd/system/zentinel-{agent}.service`

**User-local:**
- Binaries: `~/.local/bin/zentinel-{agent}-agent`
- Configs: `~/.config/zentinel/agents/{agent}.yaml`
- Systemd: `~/.config/systemd/user/zentinel-{agent}.service`

The command automatically detects whether to use system-wide or user-local paths based on permissions.

## Version Lock File

Agent versions are coordinated via `bundle-versions.lock`:

```toml
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"
ratelimit = "0.2.0"
denylist = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
ratelimit = "zentinelproxy/zentinel-agent-ratelimit"
denylist = "zentinelproxy/zentinel-agent-denylist"
```

The lock file is embedded in the Zentinel binary at build time, ensuring reproducible installations.

## Configuration

After installation, configure agents in your `zentinel.kdl`:

```kdl
agents {
    agent "waf" {
        endpoint "unix:///var/run/zentinel/waf.sock"
        timeout-ms 100
        failure-mode "open"
    }

    agent "ratelimit" {
        endpoint "unix:///var/run/zentinel/ratelimit.sock"
        timeout-ms 50
        failure-mode "open"
    }

    agent "denylist" {
        endpoint "unix:///var/run/zentinel/denylist.sock"
        timeout-ms 20
        failure-mode "open"
    }
}
```

Then reference them in routes:

```kdl
routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        policies {
            agents "denylist" "ratelimit" "waf"
        }
    }
}
```

## Systemd Integration

With `--systemd`, the command installs service files and a target:

```bash
# Install with systemd
sudo zentinel bundle install --systemd

# Reload systemd
sudo systemctl daemon-reload

# Enable and start all services
sudo systemctl enable zentinel.target
sudo systemctl start zentinel.target

# Check status
sudo systemctl status zentinel.target
```

The `zentinel.target` starts the proxy and all agent services together.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    zentinel bundle                       │
│                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐ │
│  │   lock.rs   │───▶│  fetch.rs   │───▶│ install.rs  │ │
│  │ Parse lock  │    │  Download   │    │ Place files │ │
│  │   file      │    │  from GH    │    │ Set perms   │ │
│  └─────────────┘    └─────────────┘    └─────────────┘ │
│         │                  │                  │         │
│         ▼                  ▼                  ▼         │
│  bundle-versions     GitHub Releases    /usr/local/bin  │
│      .lock           (per agent)        /etc/zentinel   │
└─────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Permission denied

Run with `sudo` for system-wide installation:

```bash
sudo zentinel bundle install
```

Or use user-local paths:

```bash
zentinel bundle install --prefix ~/.local
```

### Download failed

Check network connectivity and verify the agent release exists:

```bash
zentinel bundle list --verbose  # Shows download URLs
```

### Agent won't start

Check logs:

```bash
journalctl -u zentinel-waf -f
```

Verify socket permissions:

```bash
ls -la /var/run/zentinel/
```

### Version mismatch

Force reinstall:

```bash
sudo zentinel bundle install --force
```

## See Also

- [Agent Protocol](agents.md) - How agents communicate with the proxy
- [Configuration Reference](../../../config/docs/agents.md) - Agent configuration options
- [Deployment Guide](https://zentinelproxy.io/docs/deployment/zentinel-stack) - Full stack deployment
