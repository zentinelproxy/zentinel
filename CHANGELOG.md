# Changelog

All notable changes to Zentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Zentinel uses [CalVer](https://calver.org/) (`YY.MM_PATCH`) for releases and
[SemVer](https://semver.org/) for crate versions on crates.io. CalVer is the
primary, operator-facing version. See [Versioning](https://zentinelproxy.io/docs/appendix/versioning/)
for details.

## Release Overview

| CalVer | Crate Version | Date | Highlights |
|--------|---------------|------|------------|
| [26.02_7](#26027---2026-02-16) | 0.5.0 | 2026-02-16 | Wire 18 config features into runtime, filter & config coverage tests |
| [26.02_4](#26024---2026-02-04) | 0.4.10 | 2026-02-04 | Maintenance: CI, dependency audit, Pingora fork security fix |
| [26.02_3](#26023---2026-02-03) | 0.4.9 | 2026-02-03 | First-time user smoke tests, protocol-version config, docs refresh |
| [26.02_1](#26021---2026-02-02) | 0.4.7 | 2026-02-02 | Pingora 0.7 upgrade, drop fork, major dependency sweep |
| [26.02_0](#26020---2026-01-29) | 0.4.5 | 2026-01-29 | Supply chain security: SBOM, cosign signing, SLSA provenance |
| [26.01_11](#260111---2026-01-29) | 0.4.5 | 2026-01-29 | Per-request allocation reduction in hot path |
| [26.01_10](#260110---2026-01-27) | 0.4.3 | 2026-01-27 | Security fixes, dependency updates |
| [26.01_9](#26019---2026-01-21) | 0.4.2 | 2026-01-21 | Sticky load balancing, install script UX |
| [26.01_8](#26018---2026-01-21) | 0.4.1 | 2026-01-21 | Dependency updates (prost, tonic, tungstenite, sysinfo) |
| [26.01_7](#26017---2026-01-21) | 0.4.0 | 2026-01-21 | DNS-01 ACME challenge support |
| [26.01_6](#26016---2026-01-14) | 0.3.1 | 2026-01-14 | Agent Protocol v2 connection pooling |
| [26.01_5](#26015---2026-01-13) | 0.3.1 | 2026-01-13 | Agent Protocol v2 connection pooling |
| [26.01_4](#26014---2026-01-11) | 0.3.0 | 2026-01-11 | Agent Protocol v2, WASM runtime |
| [26.01_3](#26013---2026-01-05) | 0.2.3 | 2026-01-05 | Bug fixes |
| [26.01_0](#26010---2026-01-01) | 0.2.0 | 2026-01-01 | First CalVer release |
| [25.12](#2512) | 0.1.x | 2025-12 | Initial public releases |
| [24.12](#2412) | 0.1.0 | 2024-12 | Initial development |

---

## [26.02_7] - 2026-02-16

**Crate version:** 0.5.0

### Added
- **Runtime wiring for 18 config features** — Closed an entire class of silent-failure bugs where config options were parsed but not applied at runtime:
  - **5 filter types:** Headers (set/add/remove per phase), CORS (preflight 204 + response headers + origin validation), Compress (via Pingora's built-in module), Timeout (per-filter connect/upstream overrides), Log (request/response with configurable level)
  - **Route policies:** `response_headers` set/add/remove, per-route `timeout_secs` on upstream peers, per-route `cache` config (default TTL, enabled flag)
  - **Server/listener config:** `graceful_shutdown_timeout_secs`, `pid_file`, `user`, `group`, `working_directory`, per-listener `request_timeout` and `keepalive_timeout`
  - **Agent protocol:** guardrail agent calls (V1 + V2), V2 config delivery, V2 health reporting, gRPC `insecure_skip_verify` with custom rustls verifier
  - **OpenTelemetry:** span status, error recording, upstream attributes, span lifecycle
  - **TLS hardening:** `resolve_protocol_versions()`, `resolve_cipher_suites()`, full `ServerConfig` build (staged as warnings pending Pingora fork support)
  - **Observability:** `MetricsConfig.enabled`/`path`, `AccessLogFields` filtering, `LoggingConfig` level/format/file with `RUST_LOG` precedence
- **Config validation safety net** (`validate_implementation_status()`) — Hard errors for security-critical stubs (WAF mode enabled without engine), warnings for convenience features not yet fully wired.
- **20 filter wiring unit tests** — Verify each filter type actually modifies requests/responses: headers set/add/remove, CORS origin validation and response headers, compress content-type/size/encoding checks, timeout overrides, log emission smoke tests.
- **Config field coverage test** (`config_field_coverage_exhaustive_construction`) — Constructs all config structs with explicit field initialization; fails to compile when new fields are added without wiring.
- **Validation warnings snapshot test** — Locks down the exact set of unwired feature warnings; fails when warnings are added or removed without updating the expected list.

### Changed
- **Dependency updates:**
  - jsonschema 0.41.0 → 0.42.0
  - toml 0.9.11 → 1.0.1
  - 18 minor dependency updates across the workspace

### Fixed
- **CI release publish** — Made publish job idempotent to handle partial failures.
- **Config validation** — Added `weighted-round-robin` alias, fixed invalid variable substitution in docs.

---

## [26.02_4] - 2026-02-04

**Crate version:** 0.4.10

### Fixed
- **16 rustdoc warnings** — Fixed bare URLs, unclosed HTML tags, unresolved type references, and private module links across 10 files.
- **Clippy warnings** — Resolved warnings and migrated to updated dependency APIs.
- **`_build.yml` header comment** — Fixed misleading "Called by" reference.

### Changed
- **Pingora switched to fork** — All Pingora dependencies now point to `raskell-io/pingora` fork (rev `5847d5e`) which disables the prometheus protobuf default feature, removing the RUSTSEC-2024-0437 vulnerability.
- **Dependency updates:**
  - `cargo update` — 61 packages updated to latest compatible versions
  - reqwest 0.12 → 0.13 (feature renames: `rustls-tls` → `rustls`, `query` now opt-in)
  - jsonschema 0.40 → 0.41 (performance improvements)
  - bytes 1.9 → 1.11.1 (integer overflow fix)

### Added
- **CI workflow** (`.github/workflows/ci.yml`) — Formatting, clippy, tests, and docs checks on PRs and pushes to main.
- **Weekly audit workflow** (`.github/workflows/audit.yml`) — Runs `cargo audit` weekly, creates/updates GitHub issues on vulnerabilities.
- **Cargo audit ignore list** (`.cargo/audit.toml`) — Documented ignores for upstream-only advisories (daemonize, derivative, fxhash, rustls-pemfile).
- **Branch protection** — Required status checks (Formatting, Clippy, Tests, Documentation) on main.

---

## [26.02_3] - 2026-02-03

**Crate version:** 0.4.9

### Added
- **First-time user smoke tests** — Self-contained integration tests (`test_first_time_waf.sh`, `test_first_time_lua.sh`) that validate building Zentinel + an agent from source, wiring them together, and verifying end-to-end behavior. WAF test covers 8 scenarios (SQLi, XSS, path traversal, fail-open, recovery); Lua test covers 4 (header injection, blocking, fail-open).
- **`protocol-version` KDL config** — Agent blocks now accept `protocol-version "v2"` to explicitly select Protocol v2 for gRPC agents, instead of always defaulting to v1.
- **Makefile targets** — `test-first-time`, `test-first-time-waf`, `test-first-time-lua` for running smoke tests.

### Fixed
- **Example configs** — All configs in `config/examples/` now pass `zentinel test` validation.
- **Install script** — Removed stale linux-arm64 block, fixed sudo fallback.

### Changed
- **README** — Replaced Inference Gateway section with Use Cases overview; updated feature table with caching, WebSocket, hot reload details; linked to full features page.

---

## [26.02_1] - 2026-02-02

**Crate version:** 0.4.7

### Changed
- **Pingora 0.6 → 0.7** — Upgraded to upstream Pingora 0.7.0, removing the `raskell-io/pingora` security fork and all 16 `[patch.crates-io]` overrides. Zentinel now builds against upstream Pingora with zero patches.
  - `ForcedInvalidationKind` renamed to `ForcedFreshness` in cache layer
  - `range_header_filter` now accepts `max_multipart_ranges` parameter (defaults to 200)
- **Major dependency updates:**
  - thiserror 1.x → 2.0
  - redis 0.27 → 1.0 (distributed rate limiting)
  - criterion 0.6 → 0.8 (benchmarking)
  - instant-acme 0.7 → 0.8 (ACME client rewritten for new builder/stream API)
  - jsonschema 0.18 → 0.40 (validation module rewritten for new API: `JSONSchema` → `Validator`, `compile` → `draft7::new`)
  - quick-xml 0.37 → 0.39 (data masking agent: `unescape()` → `decode()`)
  - async-memcached 0.5 → 0.6
  - tiktoken-rs 0.6 → 0.9
  - sysinfo 0.37 → 0.38

### Security
- **Resolved all three security issues** previously requiring a Pingora fork:
  - [RUSTSEC-2026-0002](https://rustsec.org/advisories/RUSTSEC-2026-0002.html): `lru` crate vulnerability (fixed in upstream Pingora 0.7)
  - `atty` unmaintained dependency removed (fixed in upstream Pingora 0.7)
  - `protobuf` uncontrolled recursion bounded (fixed in upstream Pingora 0.7)

### Removed
- `[patch.crates-io]` section with 16 git overrides pointing to `raskell-io/pingora` fork

---

## [26.02_0] - 2026-01-29

**Crate version:** 0.4.5

### Added
- **Supply chain security for release pipeline**
  - SBOM generation in CycloneDX 1.5 and SPDX 2.3 formats via `cargo-sbom`
  - Binary signing with Sigstore cosign (keyless, GitHub Actions OIDC)
  - Container image signing with cosign and SBOM attestation via syft
  - SLSA v1.0 provenance via `slsa-github-generator` (Build Level 3)
  - Sigstore bundles (`.bundle`), SBOMs (`.cdx.json`, `.spdx.json`), and SLSA provenance (`.intoto.jsonl`) attached to every GitHub release
  - Supply chain verification commands in release notes

---

## [26.01_11] - 2026-01-29

**Crate version:** 0.4.5

### Changed
- **Performance:** Reduce per-request allocations in hot path
- **Performance:** Avoid cloning header modification maps per request
- **Performance:** Optimize agent header map construction

---

## [26.01_10] - 2026-01-27

**Crate version:** 0.4.3

### Fixed
- Prevent single connection failure from permanently marking upstream target unhealthy
- Update code for rand 0.9 and hickory-resolver 0.25 API changes
- Use pingora fork to resolve remaining security vulnerabilities

### Security
- Resolve dependabot security alerts

### Changed
- **Dependency updates:**
  - opentelemetry_sdk 0.27 → 0.31
  - opentelemetry-otlp 0.27 → 0.31
  - hickory-resolver 0.24 → 0.25
  - rand 0.8 → 0.9
  - wasmtime 40.0 → 41.0
  - notify 6.1 → 8.2
  - validator 0.18 → 0.20
  - nix 0.29 → 0.31
  - webpki-roots 0.26 → 1.0

---

## [26.01_9] - 2026-01-21

**Crate version:** 0.4.2

### Added
- Sticky load balancing algorithm support in simulation framework

### Changed
- Improved install script user experience

---

## [26.01_8] - 2026-01-21

**Crate version:** 0.4.1

### Changed
- **Dependency updates** with breaking change fixes:
  - prost 0.13 → 0.14 (with tonic ecosystem upgrade to 0.14)
  - tonic 0.12 → 0.14 (TLS features renamed: `tls` → `tls-ring`, `tls-roots` → `tls-native-roots`)
  - tungstenite 0.24 → 0.28 (`Message::Text` now uses `Utf8Bytes`)
  - sysinfo 0.31 → 0.37 (`RefreshKind::new()` → `RefreshKind::nothing()`)
  - toml 0.8 → 0.9
  - brotli 7.0 → 8.0
  - directories 5.0 → 6.0
  - signal-hook 0.3 → 0.4
  - jsonschema 0.17 → 0.18
  - ip2location 0.5 → 0.6
  - tokio-tungstenite 0.24 → 0.28
- GitHub Actions updates: checkout v6, github-script v8, docker/build-push-action v6

### Fixed
- WebSocket test compatibility with tungstenite 0.28 API changes
- System metrics collection with sysinfo 0.37 API changes

---

## [26.01_7] - 2026-01-21

**Crate version:** 0.4.0

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

## [26.01_6] - 2026-01-14

**Crate version:** 0.3.1

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

## [26.01_5] - 2026-01-13

**Crate version:** 0.3.1

Same as 26.01_6.

---

## [26.01_4] - 2026-01-11

**Crate version:** 0.3.0

### Added
- Initial Agent Protocol v2 implementation
- Binary UDS transport for lower latency
- Connection pooling with multiple strategies (RoundRobin, LeastConnections, HealthBased)
- WASM agent runtime using Wasmtime

### Changed
- Agent protocol documentation reorganized into v1/ and v2/

---

## [26.01_3] - 2026-01-05

**Crate version:** 0.2.3

See [GitHub Release](https://github.com/zentinelproxy/zentinel/releases/tag/26.01_3).

---

## [26.01_0] - 2026-01-01

**Crate version:** 0.2.0

First release using CalVer tagging.

See [GitHub Release](https://github.com/zentinelproxy/zentinel/releases/tag/26.01_0).

---

## 25.12

**Crate versions:** 0.1.0 – 0.1.8
**Releases:** 25.12_0 through 25.12_19

Initial public release series. Core proxy, routing, upstreams, agent system, observability, and KDL configuration.

See [GitHub Releases](https://github.com/zentinelproxy/zentinel/releases?q=25.12) for individual release notes.

---

## 24.12

**Crate version:** 0.1.0
**Releases:** 24.12_0 through 24.12_2

Initial development releases.

See [GitHub Releases](https://github.com/zentinelproxy/zentinel/releases?q=24.12) for individual release notes.

---

[26.02_1]: https://github.com/zentinelproxy/zentinel/compare/26.02_0...26.02_1
[26.02_0]: https://github.com/zentinelproxy/zentinel/compare/26.01_11...26.02_0
[26.01_11]: https://github.com/zentinelproxy/zentinel/compare/26.01_10...26.01_11
[26.01_10]: https://github.com/zentinelproxy/zentinel/compare/26.01_9...26.01_10
[26.01_9]: https://github.com/zentinelproxy/zentinel/compare/26.01_8...26.01_9
[26.01_8]: https://github.com/zentinelproxy/zentinel/compare/26.01_7...26.01_8
[26.01_7]: https://github.com/zentinelproxy/zentinel/compare/26.01_6...26.01_7
[26.01_6]: https://github.com/zentinelproxy/zentinel/compare/26.01_5...26.01_6
[26.01_5]: https://github.com/zentinelproxy/zentinel/compare/26.01_4...26.01_5
[26.01_4]: https://github.com/zentinelproxy/zentinel/compare/26.01_3...26.01_4
[26.01_3]: https://github.com/zentinelproxy/zentinel/compare/26.01_0...26.01_3
[26.01_0]: https://github.com/zentinelproxy/zentinel/releases/tag/26.01_0
