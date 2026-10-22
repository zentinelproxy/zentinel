# Bundle Command

The `zentinel bundle` command manages the installation of bundled agents - a curated set of agents that are tested to work together with a specific version of Zentinel.

## Overview

Instead of manually downloading and configuring each agent, the bundle command:

1. Reads a version lock file that pins compatible agent versions
2. Downloads agents from their respective GitHub releases
3. Installs binaries to the appropriate locations
4. Writes `agents.kdl`, the proxy's `agents { }` block for the installed
   agents, and prints the command each agent is started with (or, with
   `--systemd`, writes a unit per agent running exactly that command)

## Quick Start

```bash
# Install Zentinel first
curl -fsSL https://get.zentinelproxy.io | sh

# Install all bundled agents
sudo zentinel bundle install

# Check what's installed
zentinel bundle status

# Wire the agents into the proxy: add the printed line to zentinel.kdl
#   include "/etc/zentinel/agents/agents.kdl"
# then start the agents
sudo systemctl daemon-reload
sudo systemctl enable --now zentinel-waf.service
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

# Also write a systemd unit per agent
zentinel bundle install --systemd

# Custom installation prefix
zentinel bundle install --prefix /opt/zentinel
```

**Options:**

| Option | Description |
|--------|-------------|
| `--dry-run, -n` | Preview what would be installed |
| `--force, -f` | Reinstall even if already up to date |
| `--systemd` | Also write a systemd unit per agent |
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
modsec          0.4.0        0.4.0        ✓ up to date
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

`zentinel bundle list --verbose` shows every agent in the bundle with its
version, download URL, transport and any file it needs.

The `ratelimit` agent is no longer bundled: rate limiting is built into
Zentinel (`policies { rate-limit { ... } }` on a route, see
[rate-limiting.md](rate-limiting.md)). `zentinel bundle install ratelimit`
says so; `zentinel bundle uninstall ratelimit` removes a copy installed
earlier.

## Installation Paths

| | System-wide (root) | User-local | `--prefix P` |
|---|---|---|---|
| Binaries | `/usr/local/bin` | `~/.local/bin` | `P/bin` |
| `agents.kdl`, agent files | `/etc/zentinel/agents` | `~/.config/zentinel/agents` | `P/etc/zentinel/agents` |
| Agent sockets | `/run/zentinel-agents` (`/var/run/...` on macOS) | `~/.local/state/zentinel/run` | `P/run/zentinel` |
| systemd units | `/etc/systemd/system` | `~/.config/systemd/user` | `P/lib/systemd/system` |

The command uses the system-wide paths only when it can create every one of
them (in practice: as root), and the user-local ones otherwise.

The socket directory is created by the install: `0700` for user and prefix
installs (the agents and the proxy run as the installing user), `0750` for a
system-wide one, whose units run the agents as `zentinel`, the proxy's user in
`deploy/zentinel.service`. It is deliberately not `/run/zentinel`: that is the
proxy unit's `RuntimeDirectory=`, which systemd deletes whenever the proxy
stops. A socket path must stay under 104 bytes; the install warns if a long
`--prefix` makes it longer.

## How agents are started

Every agent takes the same command line (agent protocol v2):

| Transport | Started with | `agents.kdl` |
|---|---|---|
| Unix socket (default) | `--socket <socket dir>/<name>.sock` | `unix-socket "<same path>"` |
| gRPC (agents whose release serves only gRPC) | `--grpc-address 127.0.0.1:<port>` | `grpc address="http://127.0.0.1:<port>"` |

Both come from one place, so the command, the unit and the KDL cannot
disagree. For example, a user-local install of `waf` and `zentinelsec`:

```text
~/.local/bin/zentinel-waf-agent --socket ~/.local/state/zentinel/run/waf.sock
~/.local/bin/zentinel-zentinelsec-agent --grpc-address 127.0.0.1:50151
```

Which agents use gRPC, and on which port, is per-agent metadata in the lock
file (`[transports]`, `[grpc_ports]`). In the current bundle: zentinelsec
(50151), content-scanner (50152), js (50153), wasm (50154) and transform
(50155).

Some releases do not start without a file of their own (`[required_files]`):
content-scanner, ip-reputation, grpc-inspector and chaos need `--config
<agent>.yaml`, lua and js a `--script`, wasm a `--module`. The install passes
the flag with a path in the config directory (e.g. `--script
~/.config/zentinel/agents/lua.lua`) and tells you to create the file; it does
not invent one, because the format is the agent's (see each agent's README;
`zentinel-content-scanner-agent --example-config` prints a starting point).
A generated systemd unit has `ConditionPathExists=` on that file, so it is
skipped rather than restarted in a loop until the file exists.

Earlier versions wrote a `<agent>.yaml` per agent with a `socket:` block and
started agents with `--config` pointing at it. No agent reads those files;
the install points out any it finds, and they can be deleted.

## Version Lock File

Agent versions are coordinated via `bundle-versions.lock`:

```toml
[bundle]
version = "26.10_01"
platforms = ["linux-x86_64", "linux-aarch64", "darwin-aarch64"]

[agents]
waf = "0.4.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"

[platforms]
# per-agent override of [bundle] platforms, when an agent differs

[transports]
zentinelsec = "grpc"       # default "uds"

[grpc_ports]
zentinelsec = 50151        # required for every "grpc" agent, unique

[required_files]
lua = { flag = "--script", file = "lua.lua" }
```

All three per-agent tables are optional, so older lock files still parse.
Both the binary and `scripts/check-bundle-lock.py` reject an inconsistent
entry (an unknown transport, a gRPC agent without a port, a duplicate port).
They describe the release pinned in `[agents]`: when an agent bump adds
`--socket` or makes `--config` optional, remove its entry.

Asset URLs start with `https://github.com`; set `ZENTINEL_BUNDLE_DOWNLOAD_URL`
to a mirror with the same `<owner>/<repo>/releases/download/...` layout to
install from somewhere else (an air-gapped network, a test server).

The lock file is embedded in the Zentinel binary at build time, ensuring
reproducible installations. It is the single source of truth:
`crates/proxy/bundle-versions.lock` is a byte-identical copy (what
`cargo publish` packages), and api.zentinelproxy.io serves `/v1/bundle/`
(read by `bundle update`) from a vendored copy in its `data/` directory.

An agent belongs in the lock only once its release exists for every platform
listed for it. `python3 scripts/check-bundle-lock.py` requests each asset URL
and fails otherwise; CI runs it on every change. To bump an agent: cut its
release, then update both copies here, then the API's copy.

## Configuration

The install writes `agents.kdl` to the config directory, covering every
bundled agent whose binary is installed (so installing agents one at a time
still leaves one complete block), and prints the line to add to
`zentinel.kdl`:

```kdl
include "/etc/zentinel/agents/agents.kdl"
```

For a system-wide install of waf and zentinelsec it contains:

```kdl
agents {
    // waf 0.4.0, started as:
    //   /usr/local/bin/zentinel-waf-agent --socket /run/zentinel-agents/waf.sock
    agent "waf" {
        unix-socket "/run/zentinel-agents/waf.sock"
        failure-mode "open"
    }

    // zentinelsec 0.4.0, started as:
    //   /usr/local/bin/zentinel-zentinelsec-agent --grpc-address 127.0.0.1:50151
    agent "zentinelsec" {
        grpc address="http://127.0.0.1:50151"
        failure-mode "open"
    }
}
```

The file is regenerated on every install; to customise it (timeouts,
`events`, `failure-mode "closed"`), copy it. `events` defaults to request
headers: add `"request_body"` and the response events for agents that inspect
bodies. Agents only see traffic that a route sends through them:

```kdl
filters {
    filter "waf" {
        type "agent"
        agent "waf"
    }
}

routes {
    route "api" {
        matches { path-prefix "/api" }
        upstream "backend"
        filters "waf"
    }
}
```

## Systemd Integration

With `--systemd` the install writes `zentinel-<agent>.service` per agent,
running the command above. As root these are system units (`User=zentinel`,
sandboxed, `RuntimeDirectory=zentinel-agents` with
`RuntimeDirectoryPreserve=yes` so one agent stopping does not delete the
others' sockets, ordered `Before=zentinel.service`):

```bash
sudo zentinel bundle install --systemd
sudo systemctl daemon-reload
sudo systemctl enable --now zentinel-waf.service zentinel-zentinelsec.service
```

Otherwise they are user units (no `User=`, which a user manager cannot switch
to, and no `ProtectHome=`, which would hide `~/.local/bin`):

```bash
zentinel bundle install --systemd
systemctl --user daemon-reload
systemctl --user enable --now zentinel-waf.service
```

There is no launchd support; on macOS start the agents with the printed
commands.

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

Or install without root: the user-local paths are chosen automatically, or
pick a directory with `--prefix`:

```bash
zentinel bundle install --prefix ~/zentinel
```

### Download failed

Check network connectivity and verify the agent release exists:

```bash
zentinel bundle list --verbose  # Shows download URLs
```

### Agent won't start

Check logs:

```bash
journalctl -u zentinel-waf -f          # system unit
journalctl --user -u zentinel-waf -f   # user unit
```

Check that the agent listens where `agents.kdl` says (`zentinel bundle list
--verbose` shows each agent's transport and required file):

```bash
ls -la /run/zentinel-agents/
```

An agent with a required file does not start until that file exists.

### Version mismatch

Force reinstall:

```bash
sudo zentinel bundle install --force
```

## See Also

- [Agent Protocol](agents.md) - How agents communicate with the proxy
- [Configuration Reference](../../../config/docs/agents.md) - Agent configuration options
- [Deployment Guide](https://docs.zentinelproxy.io/deployment/zentinel-stack/) - Full stack deployment
