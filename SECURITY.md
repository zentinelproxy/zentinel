# Security Policy

Zentinel is infrastructure that sits at the edge of the web. Security is foundational to its design.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

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
- Agent protocol v1 does not encrypt UDS traffic (use v2 with gRPC+TLS for sensitive environments)

## Security Updates

Security updates are announced via:

- [GitHub Security Advisories](https://github.com/zentinelproxy/zentinel/security/advisories)
- [GitHub Releases](https://github.com/zentinelproxy/zentinel/releases)
