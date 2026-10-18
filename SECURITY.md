# Security Policy

Zentinel is infrastructure that sits at the edge of the web. Security is foundational to its design.

## Supported Versions

Zentinel releases use CalVer (`YY.MM_PATCH`); the crates are published on the
0.6.x line on crates.io. The [Release Overview](CHANGELOG.md#release-overview)
in the changelog maps each release to its crate version.

| Version                                  | Supported          |
|------------------------------------------|--------------------|
| Latest release (crate 0.6.x)             | :white_check_mark: |
| Any earlier release                      | :x:                |

Only the latest release receives security fixes, which ship as a new release.
There are no long-term-support branches; if you run an older release, upgrade
to the latest one.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately via GitHub:

**[@raffaelschneider](https://github.com/raffaelschneider)**

You can use [GitHub's private vulnerability reporting](https://github.com/zentinelproxy/zentinel/security/advisories/new) if enabled, or contact directly via GitHub.

Please include:

1. **Description** — What is the vulnerability?
2. **Impact** — What can an attacker do with this?
3. **Reproduction** — Steps to reproduce the issue
4. **Affected versions** — Which versions are affected?
5. **Suggested fix** — If you have one

### What to Expect

- **Acknowledgment** — Within 48 hours
- **Initial assessment** — Within 7 days
- **Resolution timeline** — Depends on severity, but we aim for:
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: Next release

### Disclosure Policy

- We follow coordinated disclosure
- We will credit reporters (unless you prefer anonymity)
- We will publish a security advisory once a fix is available

## Security Design Principles

Zentinel's security is built on the principles in our [Manifesto](MANIFESTO.md):

1. **Explicit over implicit** — No hidden defaults or magic behavior
2. **Bounded resources** — Memory limits, queue depths, timeouts
3. **Isolated complexity** — Security logic in external agents, not the core
4. **Observable decisions** — Every security decision is logged and metered

## Security Features

- Memory-safe implementation (100% Rust)
- No unsafe code in core proxy
- TLS with modern cipher suites
- Rate limiting (local and distributed)
- External agent isolation (crash boundaries)
- Request validation and sanitization

## Known Limitations

- WASM agents run in-process (sandboxed via Wasmtime)
- UDS agent traffic is not encrypted (use gRPC+TLS for sensitive environments)

## Security Updates

Security updates are announced via:

- [GitHub Security Advisories](https://github.com/zentinelproxy/zentinel/security/advisories)
- [GitHub Releases](https://github.com/zentinelproxy/zentinel/releases)
