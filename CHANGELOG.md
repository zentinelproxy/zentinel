# Changelog

All notable changes to Sentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

---

## [0.4.0] - 2026-01-21

### Added
- **DNS-01 ACME challenge support** for wildcard certificate issuance
  - Modular DNS provider system with `DnsProvider` trait
  - Hetzner DNS provider implementation
  - Generic webhook provider for custom DNS integrations
  - DNS propagation checking with configurable nameservers
  - Secure credential loading from files or environment variables
- New configuration options for DNS-01 challenges:
  - `challenge-type` option in ACME config (`http-01` or `dns-01`)
  - `dns-provider` block with provider-specific settings
  - `propagation` block for DNS propagation check tuning
- Integration tests for DNS providers using wiremock

### Changed
- ACME scheduler now supports both HTTP-01 and DNS-01 renewal flows
- ACME client extended with `create_order_dns01()` method

---

## [0.3.1] - 2026-01-12

### Added
- Agent Protocol v2 with connection pooling and load balancing
- Reverse connection support for NAT traversal
- gRPC transport with bidirectional streaming
- Request cancellation support
- Prometheus metrics export for agent pools

### Changed
- Improved agent health tracking with circuit breakers
- Better error messages for configuration validation

### Fixed
- Connection leak in agent pool under high load
- Race condition in route matching cache

---

## [0.3.0] - 2026-01-10

### Added
- Initial Agent Protocol v2 implementation
- Binary UDS transport for lower latency
- Connection pooling with multiple strategies (RoundRobin, LeastConnections, HealthBased)
- WASM agent runtime using Wasmtime

### Changed
- Agent protocol documentation reorganized into v1/ and v2/

---

## [0.2.x] and Earlier

See [GitHub Releases](https://github.com/raskell-io/sentinel/releases) for historical changes.

---

[Unreleased]: https://github.com/raskell-io/sentinel/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/raskell-io/sentinel/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/raskell-io/sentinel/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/raskell-io/sentinel/releases/tag/v0.3.0
