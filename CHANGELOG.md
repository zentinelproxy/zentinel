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
| [26.04_7](#26047---2026-04-28) | 0.6.10 | 2026-04-28 | Security: rand fix in `zentinel-sim` |
| [26.04_6](#26046---2026-04-25) | 0.6.9 | 2026-04-25 | Security: openssl & rand fixes, ACME schema docs, CI update |
| [26.04_5](#26045---2026-04-20) | 0.6.8 | 2026-04-20 | Configurable ACME certificate key type (ECDSA P-256/P-384) |
| [26.04_4](#26044---2026-04-19) | 0.6.7 | 2026-04-19 | Cloudflare DNS-01, custom ACME servers, EAB, SAN renewal fix |
| [26.04_3](#26043---2026-04-16) | 0.6.6 | 2026-04-16 | Security: rand unsoundness fix, dependency updates |
| [26.04_2](#26042---2026-04-10) | 0.6.5 | 2026-04-10 | Security: wasmtime 43.0.1 (critical sandbox escape fix) |
| [26.04_1](#26041---2026-04-09) | 0.6.4 | 2026-04-09 | Numeric route priorities, host extraction fix, Docker glibc fix, conformance CI restored |
| [26.03_4](#26034---2026-03-18) | 0.6.2 | 2026-03-18 | Configurable Cache-Status header name |
| [26.02_18](#260218---2026-02-26) | 0.5.10 | 2026-02-26 | Remove v1 agent protocol |
| [26.02_16](#260216---2026-02-24) | 0.5.7 | 2026-02-24 | Fix KDL parser missing agent event aliases |
| [26.02_14](#260214---2026-02-24) | 0.5.5 | 2026-02-24 | Bundle command with agent registry, API-first bundle fetch |
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

## [26.04_7] - 2026-04-28

**Crate version:** 0.6.10

### Security
- **Bump `rand` 0.9.2 → 0.9.4 in `zentinel-sim`** — closes Dependabot alert for [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc) (rand unsoundness with custom logger using `rand::rng()`). Also re-syncs `zentinel-sim`'s stale path-dep version pins to the workspace so its lockfile is regenerable. (#214)

---

## [26.04_6] - 2026-04-25

**Crate version:** 0.6.9

### Security
- **Bump `openssl` 0.10.77 → 0.10.78** — fixes 4 high-severity vulnerabilities: buffer overflows in `Deriver::derive`, `MdCtxRef::digest_final`, AES key wrap bounds, and unchecked PSK/cookie callback lengths leaking memory to peers. (#205)
- **Bump `rand` 0.8.5 → 0.8.6** — fixes unsoundness with custom logger using `rand::rng()`. (#205)

### Changed
- **CI: bump `actions/upload-pages-artifact` from 4 to 5.** (#201)

### Docs
- **ACME configuration schema** — document `server-url`, `eab`, `key-type`, and `cloudflare` options in config schema reference. (#202)

---

## [26.04_5] - 2026-04-20

**Crate version:** 0.6.8

### Added
- **Configurable ACME certificate key type** via `key-type` config option. Supports `ecdsa-p256` (default) and `ecdsa-p384` for higher security strength. Invalid values produce a clear config parse error. (#199)

---

## [26.04_4] - 2026-04-19

**Crate version:** 0.6.7

### Added
- **Cloudflare DNS-01 provider** for ACME challenges, enabling wildcard certificate issuance via Cloudflare DNS API v4. Includes zone ID caching and full test coverage. (#197)
- **Custom ACME directory URLs** via `server-url` config option, supporting non-Let's Encrypt CAs like ZeroSSL and Step-ca. (#197)
- **External Account Binding (EAB)** support for ACME account creation, required by providers like ZeroSSL. Configured via `eab { kid "..." hmac-key "..." }` block. (#197)

### Fixed
- **SAN certificate renewal loop** where the renewal scheduler iterated all domains in a multi-domain certificate, triggering redundant renewals. Now only checks the primary domain. (#197)

### Security
- **Bump `github.com/moby/spdystream`** 0.5.0 to 0.5.1 in conformance tests, fixing a high-severity DOS on CRI vulnerability. (#196)

---

## [26.04_3] - 2026-04-16

**Crate version:** 0.6.6

### Security
- **Bump rand to fix unsoundness advisory** — Updates pingora fork to bump `rand` 0.8→0.9 across all pingora crates, and bumps direct `rand` 0.10.0→0.10.1 and transitive `rand` 0.9.2→0.9.4. Resolves Dependabot alerts #43, #44, #45 (RUSTSEC unsoundness with custom loggers). (#192)
- **Bump aes 0.8→0.9** — Migrates to cipher 0.5 (`BlockEncrypt`→`BlockCipherEncrypt`). (#193)

### Dependencies
- Bump `jsonschema` 0.45→0.46 (#193)
- Bump `tiktoken-rs` 0.9→0.11 (#193)
- Bump `actions/github-script` 8→9 (#186)
- Bump `softprops/action-gh-release` 2→3 (#185)
- Bump Rust toolchain to 1.94.1, MSRV to 1.94.1

---

## [26.04_2] - 2026-04-10

**Crate version:** 0.6.5

### Security
- **Bump wasmtime 43.0.0 → 43.0.1** — Resolves 10 Dependabot advisories including CVE-2026-34971 (critical: sandbox escape on aarch64 via miscompiled guest heap access in Cranelift), 6 medium-severity issues (OOB memory access, host panics/crashes), and 3 low-severity issues (data leakage, use-after-free). (#183)

---

## [26.04_1] - 2026-04-09

**Crate version:** 0.6.4

### Added
- **Numeric route priorities** — The `priority` directive now accepts integer weights (`priority 100`) in addition to the existing named string aliases (`priority "high"`). This matches the syntax documented across zentinelproxy.io since 25.12. Named constants: `LOW=10`, `NORMAL=50`, `HIGH=100`, `CRITICAL=1000`. Any `i32` is valid, enabling fine-grained gap-based ordering like `priority 75` (between `NORMAL` and `HIGH`). The `"critical"` string alias now works (was previously silently dropped to `Normal`). (#180)

### Fixed
- **Route matcher host extraction** — Route matching now uses `uri.host()` before falling back to the `Host` header, fixing `404 No matching route found` errors for HTTP/2 traffic and HTTP/1.1 requests with relative URIs (e.g., Matrix federation). Port stripping is handled by `HostMatcher::matches` per Gateway API semantics. (#178, fixes #173)
- **Docker image GLIBC crash** — The published `ghcr.io/zentinelproxy/zentinel:latest` image crashed on startup with `GLIBC_2.39 not found` because CI built on `ubuntu-latest` (24.04, glibc 2.39) but packaged into `distroless/cc-debian12` (bookworm, glibc 2.36). Pinned Linux build runners to `ubuntu-22.04` (glibc 2.35). Added a Docker smoke test (`docker run --rm <image> --version`) in the validation pipeline to catch future regressions before publishing. (#179, fixes #172)
- **Gateway controller startup crash** — The controller's initial `rebuild_reference_grants` call raced the Kubernetes API server's initialization, consistently receiving HTTP 429 "storage is (re)initializing" and crashing the pod. Made the initial rebuild non-fatal (log and continue); the watcher repopulates the index once the API is ready. (#182)

### Changed
- **Gateway API conformance CI restored** — The conformance workflow had been red on every PR since 2026-03-15 (when it was introduced). Six fixes across #181 and #182 restored it to a reliable 23-minute end-to-end run: kind cluster config file path, helm image name/tag split, Go 1.25, CRDs v1.4.1 with server-side apply, non-fatal controller startup, `-controller-name` flag removal, and timeout adjustments. Baseline established: 42/235 tests passing (all controller/status tests; data-plane routing is incomplete). (#181, #182)
- **Priority type refactored** — `Priority` changed from a 4-variant enum (`Low/Normal/High/Critical`) to a transparent `i32` newtype with named constants. Serialization is now integer (`"priority": 50`) instead of string (`"priority": "normal"`). The gateway KDL writer emits integer weights (was incorrectly collapsing `Critical` onto `"high"`). (#180)

### Dependencies
- Bump sha2 0.10→0.11, hmac 0.12→0.13 (digest 0.11 migration) (#175)
- Bump tokio 1.50→1.51, hyper 1.8→1.9, arc-swap 1.9.0→1.9.1, toml 1.1.0→1.1.2, insta 1.47.1→1.47.2, libc, and others (#177)
- Bump rcgen to 0.14.7 (#174)
- Bump wasmtime and wasmtime-wasi to 43.0.0 (#176)
- Bump tokio-tungstenite 0.28→0.29 (#169)
- Bump rust-minor group with 3 updates (#165)

### Chores
- Update Pingora fork URL from raskell-io to zentinelproxy (#163)
- Bump actions/deploy-pages from 4 to 5 (#164)

---

## [26.03_4] - 2026-03-18

**Crate version:** 0.6.2

### Added
- **Configurable `Cache-Status` header name** — New `status-header-name` option in the global cache config block allows operators to customize the RFC 9211 cache identifier. Defaults to `"zentinel"` for backwards compatibility.

---

## [26.02_18] - 2026-02-26

**Crate version:** 0.5.10

### Removed
- **V1 agent protocol** — All 25 external agents have migrated to v2. Removed the v1 `Agent` implementation, `AgentConnectionPool`, `UnifiedAgent` dispatch enum, and `AgentProtocolVersion` config enum (~1,600 lines deleted). All agents now use the v2 binary protocol with bidirectional streaming, connection pooling, and health reporting.

### Changed
- **`protocol-version` KDL field** — Now a deprecated no-op that emits a warning. Existing configs continue to work without modification.

---

## [26.02_16] - 2026-02-24

**Crate version:** 0.5.7

### Fixed
- **KDL config parser: missing agent event aliases** — `request_complete` and `request-complete` are now accepted as aliases for the `log` event, matching the documentation. Previously, using `request_complete` in an agent's `events` block caused a "Unknown agent event" error at startup.
- **KDL config parser: missing event types** — Added parsing support for `websocket_frame` / `websocket-frame` and `guardrail` agent events, which were defined in the `AgentEvent` enum but not wired into the KDL parser.

---

## [26.02_14] - 2026-02-24

**Crate version:** 0.5.5

### Added
- **`zentinel bundle` command** — Install, manage, and update curated agent bundles without a package manager or registry service. Subcommands: `install`, `status`, `list`, `uninstall`, `update`.
- **Static JSON API** (`api.zentinelproxy.io`) — Zola-generated metadata API serving agent versions, download URLs, and bundle manifests at `/v1/agents/` and `/v1/bundle/`.
- **API-first bundle fetch** — `bundle update` and `bundle install` now query the static API as the primary source, with TOML lock file fallback for air-gapped environments.
- **`bundle-versions.lock`** — TOML lock file embedded in the binary at compile time, pinning 22 agent versions with repository mappings and optional SHA256 checksums.
- **Bundle install features** — Platform auto-detection (linux/darwin × amd64/arm64), `--dry-run`, `--force`, `--prefix`, `--skip-verify`, `--systemd` (generates per-agent service units).
- **Three-tier fetch fallback** — `ZENTINEL_API_URL` env var → `api.zentinelproxy.io` → raw GitHub lock file, supporting self-hosted and air-gapped deployments.
- **65 bundle unit tests** — Lock file parsing, install paths, binary extraction, status checking, config generation, systemd service templates, API response conversion.

### Changed
- **Moved API to Zola site on Cloudflare Pages** — Agent registry metadata is now statically generated and served via CDN.
- **Dependency updates:**
  - Minor dependency updates across the workspace

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

[26.02_14]: https://github.com/zentinelproxy/zentinel/compare/26.02_13...26.02_14
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
