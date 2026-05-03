# Deployment

This document covers running Zentinel as a long-lived systemd service on Linux. For Docker, Kubernetes, and other targets, see the user-facing docs at https://docs.zentinelproxy.io/deployment.

## Install via the official script

```bash
# Binary only (default)
curl -fsSL https://get.zentinelproxy.io | sh

# Binary + systemd unit + sysusers + starter config (no auto-start)
curl -fsSL https://get.zentinelproxy.io | sh
sudo systemctl enable --now zentinel

# Caddy-style: install everything and start the service
curl -fsSL https://get.zentinelproxy.io | sh -s -- --enable-service
```

The script:

1. Downloads the latest released binary for your platform and installs it to `/usr/local/bin/zentinel` (falling back to `~/.local/bin` when `/usr/local/bin` is not writable).
2. On Linux with systemd, when run as root or via sudo:
   - Installs `/etc/systemd/system/zentinel.service`.
   - Installs `/usr/lib/sysusers.d/zentinel.conf` and creates the `zentinel` system user (via `systemd-sysusers`, falling back to `useradd`).
   - Drops a starter config at `/etc/zentinel/zentinel.kdl`. An existing file is preserved.
   - Runs `systemctl daemon-reload`.
   - With `--enable-service` (or `ZENTINEL_ENABLE_SERVICE=1`), runs `systemctl enable --now zentinel.service`.
3. On macOS, in containers, or when systemd is unavailable, only the binary is installed.

Pass `--skip-service` (or `--binary-only`) to install only the binary even on systemd hosts.

## File layout

| Path | Purpose | Mode | Owner |
|------|---------|------|-------|
| `/usr/local/bin/zentinel` | Binary | 0755 | root |
| `/etc/systemd/system/zentinel.service` | Unit file | 0644 | root |
| `/usr/lib/sysusers.d/zentinel.conf` | System user declaration | 0644 | root |
| `/etc/zentinel/zentinel.kdl` | Configuration | 0644 | root |
| `/etc/zentinel/env` (optional) | Environment overrides loaded by the unit | 0600 | root |
| `/var/lib/zentinel/` | Runtime state (managed by `StateDirectory=`) | 0700 | zentinel |
| `/var/log/zentinel/` | Log files (managed by `LogsDirectory=`) | 0755 | zentinel |
| `/run/zentinel/` | PID file and sockets (managed by `RuntimeDirectory=`) | 0755 | zentinel |

The `/var/lib`, `/var/log`, and `/run` directories are created and chowned by systemd on each service start; you do not need to provision them manually.

## Service lifecycle

```bash
# Enable and start at boot
sudo systemctl enable --now zentinel

# Reload config without dropping connections (SIGHUP)
sudo systemctl reload zentinel

# Restart (drops connections)
sudo systemctl restart zentinel

# Stop and disable
sudo systemctl disable --now zentinel

# Inspect status
systemctl status zentinel
journalctl -u zentinel -f
```

## Binding privileged ports (80, 443)

The shipped unit grants `AmbientCapabilities=CAP_NET_BIND_SERVICE` and bounds the capability set to the same. To bind 80 or 443, edit the listener address in `/etc/zentinel/zentinel.kdl`:

```kdl
listeners {
    listener "default-http" {
        address "0.0.0.0:80"
        protocol "http"
    }
}
```

No further setup is required. The proxy still runs as the unprivileged `zentinel` user.

## Sandboxing

The unit applies the following hardening directives. Edit the unit if your environment requires changes; do not relax these defaults without reason.

- `User=zentinel`, `Group=zentinel`, `UMask=0077`
- `NoNewPrivileges=true`
- `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`
- `Protect{Kernel,Tunables,Modules,Logs,Clock,Hostname,ControlGroups}=true`
- `RestrictNamespaces=true`, `RestrictRealtime=true`, `RestrictSUIDSGID=true`, `LockPersonality=true`, `RemoveIPC=true`
- `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
- `SystemCallFilter=@system-service`, `SystemCallErrorNumber=EPERM`, `SystemCallArchitectures=native`
- `LimitNOFILE=65535`, `LimitNPROC=4096`, `MemoryMax=2G`, `MemoryHigh=1500M`, `TasksMax=4096`
- `OOMScoreAdjust=-500`

If you add new outbound integrations (e.g., a Unix domain socket to an agent at `/run/agents/foo.sock`), `ProtectSystem=strict` blocks writes outside `RuntimeDirectory=`, `StateDirectory=`, and `LogsDirectory=`. Use `ReadWritePaths=` rather than relaxing `ProtectSystem`.

## Environment overrides

The unit honors `/etc/zentinel/env` when present (loaded with `EnvironmentFile=-/etc/zentinel/env`, where the leading `-` makes it optional). Use it to adjust log levels or feature flags without editing the unit:

```sh
# /etc/zentinel/env
RUST_LOG=zentinel=debug,pingora=info
```

Restart the service after editing.

## Validating the config

```bash
# Without starting
sudo zentinel test --config /etc/zentinel/zentinel.kdl

# With network and agent connectivity probes
sudo zentinel validate --config /etc/zentinel/zentinel.kdl
```

The starter config dropped by the installer passes both checks out of the box.

## Uninstalling

```bash
sudo systemctl disable --now zentinel
sudo rm -f /etc/systemd/system/zentinel.service
sudo rm -f /usr/lib/sysusers.d/zentinel.conf
sudo systemctl daemon-reload
sudo userdel zentinel 2>/dev/null || true
sudo rm -rf /etc/zentinel /var/lib/zentinel /var/log/zentinel
sudo rm -f /usr/local/bin/zentinel
```

## See also

- [`deploy/zentinel.service`](../../../deploy/zentinel.service) — the unit shipped by the installer
- [`deploy/sysusers.d/zentinel.conf`](../../../deploy/sysusers.d/zentinel.conf) — system user declaration
- [`deploy/zentinel.starter.kdl`](../../../deploy/zentinel.starter.kdl) — starter config dropped at `/etc/zentinel/zentinel.kdl`
- [`install.sh`](../../../install.sh) — installer script (also served at https://get.zentinelproxy.io)
