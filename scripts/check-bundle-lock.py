#!/usr/bin/env python3
"""Check bundle-versions.lock against the releases it points at.

    python3 scripts/check-bundle-lock.py [--offline] [LOCK ...]

`bundle-versions.lock` is the single source of truth for `zentinel bundle`:
the binary embeds it, and api.zentinelproxy.io serves /v1/bundle/ from a
vendored copy of it. This script fails when:

  * the lock copies given (default: the repository root and crates/proxy/,
    which is what `cargo publish` packages) are not byte-identical;
  * an agent has no repository, or a platform name is not one the proxy
    can ask for (linux|darwin)-(x86_64|aarch64);
  * the per-agent setup tables `bundle install` acts on are inconsistent:
    [transports] values other than "uds"/"grpc", a "grpc" agent without a
    unique [grpc_ports] entry, or a [required_files] entry that is not
    { flag = "--...", file = "<plain name>" } (crates/proxy/src/bundle/lock.rs
    refuses the same lock at runtime);
  * (unless --offline) any agent/platform asset is not downloadable. A
    missing .sha256 next to it is reported as a warning: the installer then
    skips verification, and older agent releases ship none. URLs are built exactly as crates/proxy/src/bundle/lock.rs
    builds them:

      https://github.com/<repo>/releases/download/v<ver>/<bin>-<ver>-<os>-<arch>.tar.gz

An agent is only in the lock if its release really exists for every
platform listed for it. To add an agent or bump a version, release first,
then update the lock; CI on the lock PR fails until the assets are public.
Requires Python 3.11+ (tomllib). No third-party modules.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCKS = [ROOT / "bundle-versions.lock", ROOT / "crates/proxy/bundle-versions.lock"]
KNOWN_PLATFORMS = {"linux-x86_64", "linux-aarch64", "darwin-x86_64", "darwin-aarch64"}


def asset_urls(lock: dict) -> tuple[list[tuple[str, str, str]], list[str]]:
    """Return ([(agent, platform, url)], [errors])."""
    errors: list[str] = []
    out: list[tuple[str, str, str]] = []
    default_platforms = lock.get("bundle", {}).get("platforms")
    if not default_platforms:
        errors.append("[bundle] platforms is missing or empty")
        default_platforms = []
    overrides = lock.get("platforms", {})
    repos = lock.get("repositories", {})
    names = lock.get("binary_names", {})

    for extra in sorted(set(repos) - set(lock.get("agents", {}))):
        errors.append(f"[repositories] {extra} has no entry in [agents]")
    for extra in sorted(set(overrides) - set(lock.get("agents", {}))):
        errors.append(f"[platforms] {extra} has no entry in [agents]")

    for agent, version in sorted(lock.get("agents", {}).items()):
        repo = repos.get(agent)
        if not repo:
            errors.append(f"{agent}: no [repositories] entry")
            continue
        binary = names.get(agent, f"zentinel-{agent}-agent")
        platforms = overrides.get(agent, default_platforms)
        if not platforms:
            errors.append(f"{agent}: no platforms")
        for platform in platforms:
            if platform not in KNOWN_PLATFORMS:
                errors.append(f"{agent}: unknown platform {platform!r}")
                continue
            url = (
                f"https://github.com/{repo}/releases/download/v{version}/"
                f"{binary}-{version}-{platform}.tar.gz"
            )
            out.append((agent, platform, url))
    return out, errors


def setup_errors(lock: dict) -> list[str]:
    """Check [transports], [grpc_ports] and [required_files]."""
    errors: list[str] = []
    agents = lock.get("agents", {})
    transports = lock.get("transports", {})
    ports = lock.get("grpc_ports", {})
    required = lock.get("required_files", {})
    for table, entries in (("transports", transports), ("grpc_ports", ports), ("required_files", required)):
        for extra in sorted(set(entries) - set(agents)):
            errors.append(f"[{table}] {extra} has no entry in [agents]")
    seen: dict[int, str] = {}
    for agent, transport in sorted(transports.items()):
        if transport not in ("uds", "grpc"):
            errors.append(f"[transports] {agent} = {transport!r}: expected \"uds\" or \"grpc\"")
        elif transport == "grpc":
            port = ports.get(agent)
            if not isinstance(port, int) or not 0 < port < 65536:
                errors.append(f"{agent}: \"grpc\" transport needs a [grpc_ports] port, got {port!r}")
            elif port in seen:
                errors.append(f"[grpc_ports] {agent} and {seen[port]} both use port {port}")
            else:
                seen[port] = agent
    for agent in sorted(ports):
        if transports.get(agent) != "grpc":
            errors.append(f"[grpc_ports] {agent} is not a \"grpc\" agent in [transports]")
    for agent, req in sorted(required.items()):
        if not isinstance(req, dict) or set(req) != {"flag", "file"}:
            errors.append(f"[required_files] {agent}: expected {{ flag = ..., file = ... }}")
            continue
        if not str(req["flag"]).startswith("--"):
            errors.append(f"[required_files] {agent}: flag {req['flag']!r} must start with --")
        f = str(req["file"])
        if not f or "/" in f or f.startswith("."):
            errors.append(f"[required_files] {agent}: file {f!r} must be a plain file name")
    return errors


def reachable(url: str) -> str | None:
    """None if the URL answers 200 after redirects, else a reason."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "zentinel-bundle-check"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return None if resp.status == 200 else f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return f"HTTP {e.code}"
            reason = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError) as e:
            reason = str(e)
    return reason


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("locks", nargs="*", type=Path, help="lock files (default: root + crates/proxy)")
    ap.add_argument("--offline", action="store_true", help="skip the HTTP checks")
    args = ap.parse_args()
    locks = args.locks or DEFAULT_LOCKS

    errors: list[str] = []
    contents = [p.read_bytes() for p in locks]
    for path, data in zip(locks[1:], contents[1:]):
        if data != contents[0]:
            errors.append(
                f"{path} differs from {locks[0]}; the binary embeds one and crates.io ships the other"
            )

    lock = tomllib.loads(contents[0].decode())
    assets, lock_errors = asset_urls(lock)
    errors += lock_errors
    errors += setup_errors(lock)
    print(f"bundle {lock['bundle']['version']}: {len(lock['agents'])} agents, {len(assets)} assets")

    if not args.offline:
        checks = [(a, p, u) for a, p, u in assets] + [(a, p, u + ".sha256") for a, p, u in assets]
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda c: (c, reachable(c[2])), checks))
        missing_sums = 0
        for (agent, platform, url), reason in results:
            if not reason:
                continue
            if url.endswith(".sha256"):
                # The installer skips verification (with a warning) when the
                # checksum file is absent; older agent releases ship none.
                missing_sums += 1
                print(f"warning: {agent} {platform}: no checksum ({reason}) {url}")
            else:
                errors.append(f"{agent} {platform}: {reason} {url}")
        print(f"checked {len(checks)} URLs ({missing_sums} assets without a .sha256)")

    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} problem(s)", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
