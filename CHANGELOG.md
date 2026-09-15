# Changelog

All notable changes to Zentinel are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Zentinel uses [CalVer](https://calver.org/) (`YY.MM_PATCH`) for releases and
[SemVer](https://semver.org/) for crate versions on crates.io. CalVer is the
primary, operator-facing version. See [Versioning](https://zentinelproxy.io/docs/appendix/versioning/)
for details.

## Release Overview

> **Crate Version** is the version actually **published to crates.io** for that
> release — the version you can depend on. It is *not* the version present in
> `Cargo.toml` at the tagged commit: the Release workflow reads that value and
> publishes it **plus one**. Rows from 26.04_1 onward were reconciled against
> crates.io on 2026-08-08; rows before 26.04_1 have not been verified.

| CalVer | Crate Version | Date | Highlights |
|--------|---------------|------|------------|
| [26.09_6](#26096---2026-09-15) | 0.6.43 | 2026-09-15 | **Pingora 0.9.0**: request-target and authority hardening, hop-by-hop request headers stripped before the upstream, no HTTP/1 upstream reuse after an incomplete response; gRPC-Go advisory in the conformance suite; dependency maintenance |
| [26.09_5](#26095---2026-09-04) | 0.6.42 | 2026-09-04 | **`zentinel bundle install` failed for every non-root user**, so no agent could be installed by following the documented instructions |
| [26.09_4](#26094---2026-09-03) | 0.6.41 | 2026-09-03 | **An agent the proxy could not reach at startup was lost until the proxy restarted**, silently — including any agent that restarts; multiplexed MCP tool calls are now proxied rather than originated, so they use the connection pool and retry policy |
| [26.09_3](#26093---2026-09-03) | 0.6.40 | 2026-09-03 | **Agents in the container images could not create their sockets**, so agent routes silently failed open; one route can now also front several MCP servers as a single endpoint, merging their listings and routing calls by tool |
| [26.09_2](#26092---2026-09-02) | 0.6.39 | 2026-09-02 | **Health checks never probed anything** — every `health-check` block in every configuration was inert, so failover was an appearance rather than a fact; MCP gateway: per-tool metrics, per-tool rate limiting, tool-list filtering, and an MCP-native health check |
| [26.09_1](#26091---2026-09-01) | 0.6.38 | 2026-09-01 | Dependency updates only; the XML parser in the data-masking agent was ported to quick-xml 0.42 |
| [26.08_14](#260814---2026-08-29) | 0.6.37 | 2026-08-29 | `zentinel` with no configuration starts instead of retrying port 9090 forever; `logging { timestamps }` is read |
| [26.08_13](#260813---2026-08-29) | 0.6.36 | 2026-08-29 | `dns-srv` discovery reads SRV records: the port and weight come from the record, where it previously resolved the bare domain on port 80 |
| [26.08_12](#260812---2026-08-29) | 0.6.35 | 2026-08-29 | `Cache-Status` no longer erases what an upstream cache reported, so a Zentinel placed in front of another cache shows the whole path rather than only its own member |
| [26.08_11](#260811---2026-08-29) | 0.6.34 | 2026-08-29 | Upstream `discovery` blocks now reach the proxy: targets are resolved from DNS, Consul, Kubernetes or a file before serving and refreshed in the background, where previously the block parsed into nothing and the upstream routed nowhere |
| [26.08_10](#260810---2026-08-28) | 0.6.33 | 2026-08-28 | `tracing { enabled #false }` now actually disables tracing, having previously been read by nothing; the access log's `include-trace-id` is honoured |
| [26.08_9](#26089---2026-08-28) | 0.6.32 | 2026-08-28 | Configuration checking now covers the observability blocks, completing #365; three settings the documentation describes and no parser reads are removed from the shipped configs |
| [26.08_8](#26088---2026-08-28) | 0.6.31 | 2026-08-28 | Configuration checking reaches the remaining blocks and the browser playground, which was running a different set of checks entirely; agent `type` is read as a child node as well as a property |
| [26.08_7](#26087---2026-08-27) | 0.6.30 | 2026-08-27 | `zentinel lint` now reports settings that parse but are read by nothing: run-together lines, and keys written into the wrong one of two same-named blocks |
| [26.08_6](#26086---2026-08-27) | 0.6.29 | 2026-08-27 | Listener `namespace` isolation and per-listener timeouts now work on wildcard binds — both were silently ignored on `0.0.0.0` listeners; certificate reloads report what changed instead of only counts |
| [26.08_5](#26085---2026-08-24) | 0.6.28 | 2026-08-24 | MCP and A2A policy is now enforced — it was parsed and ignored in 26.08_4; `cargo install zentinel-proxy` works again; unknown-key checking extended to `route` and `system`; **breaking**: dead buffering fields removed |
| [26.08_4](#26084---2026-08-23) | 0.6.27 | 2026-08-23 | Native MCP and A2A support; settings that were parsed and discarded now take effect (upstream timeouts, route policies, `failure-mode`); agent and mTLS authentication hardening |
| [26.08_3](#26083---2026-08-22) | 0.6.26 | 2026-08-22 | Per-SNI certificates, mTLS and TLS hardening settings now reach the listener (#303) |
| [26.08_2](#26082---2026-08-22) | 0.6.25 | 2026-08-22 | ACME DNS-01 idempotency, breaking TLS config schema |
| [26.08_1](#26081---2026-08-08) | 0.6.24 | 2026-08-08 | Security: rustls 0.23.43 (ticket-age and binder arithmetic hardening); dependency maintenance: pem 4.0, base64 0.23, jsonschema 0.49, validator 0.21, async-memcached 0.7, http 1.5, redis 1.5 |
| [26.07_4](#26074---2026-07-30) | 0.6.23 | 2026-07-30 | Dependency maintenance: wasmtime 47, quinn-proto 0.11.16, maxminddb 0.30, rust-minor batch (17 updates), actions/setup-go 7 |
| [26.07_3](#26073---2026-07-18) | 0.6.22 | 2026-07-18 | Security: serde_with 3.21 (GHSA-7gcf-g7xr-8hxj); dependency maintenance: tokio-tungstenite 0.30, jsonschema 0.48, rust-minor batches (13 updates) |
| [26.07_2](#26072---2026-07-06) | 0.6.21 | 2026-07-06 | Dependency maintenance: quick-xml 0.41, rust-minor batch (4 updates), cmov 0.5.4, conformance golang.org/x/net 0.55 |
| [26.07_1](#26071---2026-07-01) | 0.6.20 | 2026-07-01 | Dependency maintenance: maxminddb 0.29, wasmtime 46, rust-minor batch (12 updates), actions/cache 6 |
| [26.06_3](#26063---2026-06-23) | 0.6.18 | 2026-06-23 | Multi-file KDL block merging, upstream circuit-breaker recovery fix, counter underflow guard, dependency maintenance |
| [26.06_2](#26062---2026-06-16) | 0.6.17 | 2026-06-16 | Manifesto hardening (agent body limits, bounded limiter/pool state, pool maintenance), route-level retry-policy parsing, Pingora 0.8.1 security bump, dependency maintenance |
| [26.06_1](#26061---2026-06-07) | 0.6.16 | 2026-06-07 | Standalone Prometheus metrics server, per-listener route sets, quickstart fixes, dep maintenance (tikv-jemallocator 0.7, openssl 0.10.80, rust-minor batches) |
| [26.05_5](#26055---2026-05-25) | — (no crate published) | 2026-05-25 | Tagged release; crates.io publish collided with an already-published version. Changes are documented under 26.06_1. |
| [26.05_4](#26054---2026-05-12) | 0.6.15 | 2026-05-12 | Dependency maintenance: OpenTelemetry 0.32, sysinfo 0.39, Rust toolchain 1.95 |
| [26.05_3](#26053---2026-05-05) | — (not released) | 2026-05-05 | Embedded and bundled KDL configs use `system` block; ACME hickory-resolver 0.26 fix |
| [26.05_2](#26052---2026-05-03) | 0.6.13 | 2026-05-03 | Install script provisions systemd unit, system user, and starter config |
| [26.05_1](#26051---2026-05-01) | 0.6.12 | 2026-05-01 | Per-SNI ACME certificates for multi-tenant TLS, dependency updates |
| [26.04_7](#26047---2026-04-28) | 0.6.11 | 2026-04-28 | Security: rand fix in `zentinel-sim` |
| [26.04_6](#26046---2026-04-25) | 0.6.10 | 2026-04-25 | Security: openssl & rand fixes, ACME schema docs, CI update |
| [26.04_5](#26045---2026-04-20) | 0.6.9 | 2026-04-20 | Configurable ACME certificate key type (ECDSA P-256/P-384) |
| [26.04_4](#26044---2026-04-19) | 0.6.8 | 2026-04-19 | Cloudflare DNS-01, custom ACME servers, EAB, SAN renewal fix |
| [26.04_3](#26043---2026-04-16) | 0.6.7 | 2026-04-16 | Security: rand unsoundness fix, dependency updates |
| [26.04_2](#26042---2026-04-10) | 0.6.6 | 2026-04-10 | Security: wasmtime 43.0.1 (critical sandbox escape fix) |
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

## [Unreleased]

_Nothing yet._

---

## [26.09_6] - 2026-09-15

**Crate version:** 0.6.43

> **Pingora 0.9.0.** The proxy engine under Zentinel moves from 0.8.1 to 0.9.0.
> No configuration changes are needed, but one forwarding behaviour changes:
> hop-by-hop request headers no longer reach the upstream. See *Changed*.

### Security
- **Bump Pingora 0.8.1 → 0.9.0**
  ([cloudflare/pingora release](https://github.com/cloudflare/pingora/releases/tag/0.9.0)).
  The fork was rebased in
  [zentinelproxy/pingora#10](https://github.com/zentinelproxy/pingora/pull/10)
  and republished as `zentinel-pingora-* 0.9.0`; both fork patches
  (`TlsSettings::with_server_config`, `should_retry_response`) carry over
  unchanged in behaviour. What 0.9.0 brings that matters here:
  - **HTTP request-target hardening.** Path and authority validation share one
    parser; ambiguous request authorities are rejected on ingress and egress,
    CR/LF bytes in an HTTP/2 `:path` are rejected, and non-origin-form request
    targets are preserved without mangling the URI.
  - **Hop-by-hop request headers are stripped before the upstream sees them**
    (`Connection`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`,
    `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`,
    `HTTP2-Settings`), along with any header the client nominates in
    `Connection`. A request that nominates `Host`, a forwarding header or a
    pseudo-header-shaped name is rejected rather than forwarded with the
    protection removed.
  - **HTTP/1 upstream connections are never reused after an incomplete response
    or a failed write**, which previously could leave a reused connection out of
    step with the next request.
  - Obsolete line folding in upstream response headers is normalized before the
    response is forwarded.
  - Default HTTP/2 server limits are bounded rather than unbounded (memory
    exhaustion).
  - The unmaintained `daemonize` crate is replaced by `daemonix`; `nix` 0.31,
    `lru` 0.18, `h2` ≥ 0.4.16.

  (#482)
- **`google.golang.org/grpc` 1.83.2 in the conformance suite**
  ([GHSA-2v4p-qf9q-27wj](https://github.com/advisories/GHSA-2v4p-qf9q-27wj),
  xDS server crash on missing `:authority`/`Host`). Closes Dependabot alert #64.
  The conformance harness is the only Go code in the repository; the proxy is
  unaffected. (#480)

### Changed
- **Forwarding behaviour: WebSocket upgrades still work, other HTTP/1 upgrades
  are no longer forwarded.** Pingora 0.9.0 forwards a normalized `Upgrade:
  websocket` handshake and drops every other `Upgrade` (for example `h2c`),
  as part of the hop-by-hop stripping above. `Proxy-Authorization` is likewise
  not passed on. Nothing in Zentinel's configuration turns the legacy
  pass-through back on; if you depended on it, open an issue.
- **Cache storage moved to the 0.9.0 `Storage` API.** The disk and hybrid
  caches take a `PurgeTarget` and report a `PurgeOutcome` instead of a bool;
  `CacheKey` no longer has a namespace argument. Zentinel always passed an
  empty namespace, so cache keys and on-disk hashes are unchanged and no cache
  goes cold. (#482)
- **Dependency maintenance:** `brotli` 9.0 (#479), `jsonschema` 0.53 (#478),
  and the rust-minor group of 13 — `rustls` 0.23.44, `hyper` 1.11.1,
  `aws-lc-rs` 1.18.1, `reqwest` 0.13.5, `hickory-resolver` 0.26.3,
  `tokio-rustls` 0.26.5, `smallvec` 1.16, `redis` 1.7, `uuid` 1.26.1,
  `flate2` 1.1.10, `toml` 1.1.6, `rcgen` 0.14.10, `aes` 0.9.3 (#481).

---

## [26.09_5] - 2026-09-04

**Crate version:** 0.6.42

> **If you install agents with `zentinel bundle install`, upgrade.** It could not
> succeed for a non-root user on a standard Unix system.

### Fixed
- **`zentinel bundle install <agent>` failed for every non-root user**, which is
  the documented first step for installing any agent:

  ```
  Install path:   /usr/local/bin
  Mode:           system-wide (requires root)
  Error: Failed to create installation directories
  Caused by: Permission denied: /etc/zentinel/agents
  ```

  The writability check asked the wrong question. It used
  `Permissions::readonly()`, which on Unix is `mode & 0o222 == 0` — *"can anyone
  write here?"*, not *"can I?"*. `/usr/local/bin` is `root:wheel drwxr-xr-x` on a
  standard install, so the owner's write bit made it look writable to every user
  on the machine. The installer therefore chose a system-wide install for
  everyone and then failed creating `/etc/zentinel/agents`, and the user-local
  fallback beneath it was unreachable.

  It now uses `access(2)`, and checks every directory the install creates rather
  than only the binary one — a check narrower than the operation it guards is a
  check that passes and then fails.

  A user-local install places the binary in `~/.local/bin` and its configuration
  in `~/.config/zentinel/agents/`. Use `--prefix` to choose somewhere else, or
  run as root for the system-wide install.

  Reported by [@alanorth](https://github.com/alanorth) at
  [registry.zentinelproxy.io#3](https://github.com/zentinelproxy/registry.zentinelproxy.io/issues/3),
  who also spotted that the registry pages named a path — `~/.zentinel/agents/` —
  that the installer has never used. All 23 agent pages have been corrected.

---

## [26.09_4] - 2026-09-03

**Crate version:** 0.6.41

> **If you run agents, upgrade.** An agent that restarts was lost until the
> proxy restarted, and with `failure-mode "open"` nothing reported it.

### Fixed
- **An agent the proxy could not reach at startup was lost for the life of the
  process.** With `failure-mode "open"` — the default in the shipped examples —
  this was silent: requests were forwarded unprocessed, the agent process looked
  healthy, and nothing anywhere reported it.

  Three ordinary situations produced it: an agent slower to start than the
  proxy, **an agent that restarts** (a crash, an upgrade, a rolling deploy), and
  a socket on a volume that is not ready yet.

  Four things had to change, each of which alone kept the agent dead:

  - Registration **refused** an unreachable agent instead of recording it. The
    pool reconnects the agents it holds, so one never added had nothing to
    reconnect it. It is now registered and marked unhealthy.
  - Pool maintenance was started **after** registration and behind it, so a
    failed registration also took down the loop meant to recover it.
  - Reconnection **gave up permanently** after three attempts — roughly fifteen
    seconds — which covers most restarts. Attempts now bound the retry
    *interval*, capped at two minutes, rather than stopping the retrying.
  - Reconnection never learned the agent's capabilities, which the first three
    hid; without it a recovered agent would answer calls while the proxy
    believed it supported nothing, and configuration push would never reach it.

  No configuration change is needed. If you added start-ordering to work around
  this, it is no longer required — though ordering agents before the proxy is
  still sensible.

### Changed
- **Multiplexed MCP tool calls are proxied rather than originated.** A route
  fronting several MCP servers answered every request itself, so tool calls used
  neither the connection pool, nor the route's retry policy, nor the upstream's
  TLS settings. A tool call goes to exactly one upstream, so it now takes the
  normal proxy path and gets all three.

  Listings still cannot be: merging several answers into one is composition, not
  proxying. Nor can the single `initialize` handshake per upstream, which
  happens before the client's own request. So the first call to an upstream
  costs one extra round trip and every call after it is proxied.

---

## [26.09_3] - 2026-09-03

**Crate version:** 0.6.40

### Added
- **A route can front several MCP servers and present them as one endpoint.**
  `tools/list` is answered by asking every upstream and merging the results,
  with each tool carrying its upstream's prefix; a call is routed to the server
  its prefix names, with the prefix stripped before the upstream sees it.

  ```kdl
  mcp {
      upstreams {
          upstream "docs" prefix="docs"
          upstream "warehouse" prefix="warehouse" path="/mcp"
      }
      session-key "…64 hex chars…"
  }
  ```

  Three things worth knowing before configuring it:

  - **Prefixes are declared, never derived.** A tool's name is what a model
    reasons about, so it must not change because an unrelated upstream was added
    or an existing one renamed. Duplicate prefixes, and prefixes containing `.`,
    are refused at load.

  - **`session-key` is required with two or more upstreams, and must be
    configured rather than generated.** A client session spans several upstream
    sessions, and that mapping travels in an encrypted `Mcp-Session-Id` rather
    than in the proxy. A key generated at startup would rotate on every reload
    and drop every live session, and two Zentinel instances could not read each
    other's tokens — which would force session affinity onto the load balancer.
    Generate one with `openssl rand -hex 32`.

  - **Policy applies to the name the client sees.** Write
    `deny "warehouse.execute_sql"`, not `deny "execute_sql"`. Denied tools are
    both hidden from the merged listing and refused when called.

  Upstream sessions are opened lazily, the first time a call routes to that
  upstream.

  **When an upstream is down**, its tools are omitted from the merged listing
  rather than the listing failing — one unreachable server costs its own tools
  and no others — and a call routed to it fails fast with
  `upstream is not reachable` rather than hanging. Measured with one of two
  upstreams stopped: the listing came back in 58 ms, the call was refused in
  17 ms.

  Configuring an MCP health check on the upstreams improves this further, since
  an upstream already known to be unhealthy is skipped rather than tried. That
  matters most for a server that accepts connections but never answers, where
  there is no refused connection to fail fast on.

  There is no *failover* in the sense of retrying the call elsewhere: a tool
  lives on one upstream, so there is nowhere else to send it. Telling a
  connected client that the tool list changed, via
  `notifications/tools/list_changed`, needs the server-to-client SSE channel
  that Streamable HTTP defines and Zentinel does not implement yet.

  These routes originate rather than forward — merging a listing is composition,
  not proxying — so their upstream calls use neither the connection pool nor the
  route's retry policy. They do go through the upstream's own load balancing,
  service discovery and health checking.

  **Resources are not served on a multiplexing route**, and `resources/*` is
  refused there with a reason. They are identified by URI, and a URI cannot
  carry an upstream prefix — `docs.file:///a.txt` is not a URI — so a merged
  listing would show the same URI from two servers with no way to tell them
  apart and no way to read either. Tools and prompts, which have bare names,
  merge and route normally. A route with a single upstream is unaffected and
  serves resources as before.

### Fixed
- **JSON-RPC response ids preserve their type.** A request with `"id": 42` was
  answered with `"id": "42"`, because ids are normalised to strings internally
  for policy and audit. The specification requires the response id to equal the
  request id including its type, and a strict client is entitled to reject the
  mismatch.

- **Agents could not create their sockets in the container images.**
  `/var/run/zentinel` — where agents place their listening sockets and where the
  proxy looks for them — was not created in any image. Mounted there, a Docker
  named volume is created **root-owned**, and the agent images run as
  `nonroot`, so the bind failed. The proxy then had nothing to connect to and
  every agent route silently failed open.

  **If you run the published images with agents over a shared socket volume,
  this affected you**, and the symptom was agents appearing to do nothing rather
  than any error.

  The images now create the directory, but that alone is not a reliable fix and
  should not be relied on: both the Debian and distroless bases have `/var/run`
  as a symlink to `/run`, so a directory placed at `/var/run/zentinel` is not
  necessarily where Docker looks when initialising a volume mounted there, and
  whichever container starts first decides whose layout is used. **If you write
  your own Compose file, prepare the volume explicitly**, as the one shipped in
  this repository now does:

  ```yaml
  socket-init:
    image: busybox
    user: "0:0"
    command: ["sh", "-c", "mkdir -p /sockets && chmod 1777 /sockets"]
    volumes:
      - agent-sockets:/sockets
  ```

  and have the agents wait on it with
  `condition: service_completed_successfully`. `1777` because the proxy and the
  agents may run as different users, sticky so one agent cannot remove
  another's socket.

- **Start agents before the proxy.** The proxy registers each agent once, at
  startup, and a registration that fails is not retried — the agent is then
  absent for the life of the process, and every call to it answers
  `Agent <id> not found` while the agent sits there listening. With
  `failure-mode "open"` that is silent: traffic flows unprocessed.

  The shipped Compose file now orders them. If you run your own, do the same.
  The underlying behaviour is tracked in
  [#465](https://github.com/zentinelproxy/zentinel/issues/465) — it also means
  an agent that *restarts* is lost until the proxy restarts.

- **The echo agent's integration tests can now fail, and can now pass.** One
  asserted a request-only header against the response and could never pass,
  skipping every run behind a message that blamed the environment; the other
  matched a header the proxy adds regardless and passed with the agent stopped.
  Between them they verified nothing, which is why the bug above survived: the
  suite covering it could not report it. The suite now also captures the agent's
  own container logs when the assertion fails.

---

## [26.09_2] - 2026-09-02

**Crate version:** 0.6.39

> **If you configure `health-check` on any upstream, upgrade.** On 0.6.38 and
> earlier it never sent a single probe.

### Fixed
- **Health checks never probed anything.** `ActiveHealthChecker` built its
  backend set from the configured targets and never called `update()`.
  `Backends::run_health_check` iterates only the set `update()` populates, so
  every cycle checked zero backends — for every check type: `http`, `tcp`,
  `grpc` and `inference` alike.

  It failed silently in both directions, which is what let it go unnoticed. No
  probe was sent, so a backend that was down was never detected; and no backend
  was ever marked unhealthy, so nothing was taken out of rotation. There was no
  error anywhere. The runner spawned, logged `Starting health check runner`,
  and ticked on schedule, while the configuration and `zentinel lint` both
  reported health checking as configured.

  Measured against a real backend at `interval-secs 2`: **0 probes in twelve
  seconds before, 29 after**.

  Anyone relying on health-checked failover has not had it. There is no
  configuration change needed — existing `health-check` blocks begin working on
  upgrade, which means backends that have been quietly failing may now be
  marked unhealthy and removed from rotation for the first time.

- **The Docker image builds again**, against Rust 1.95; the version had drifted
  behind what the workspace requires.
- **The integration suite runs**, having never been executed by CI since it was
  written. Fixing that surfaced four further faults in it: it terminated itself
  on its first passing assertion, probed `/health` on the metrics port instead
  of the proxy port, lacked routes for the paths it asserted on, and could not
  reach the echo agent.
- **The post-release version bump lands** instead of leaving an orphan branch
  and a `Cargo.lock` a release behind.

### Added
- **MCP calls are counted per tool.** `zentinel_mcp_calls_total`, labelled by
  route, JSON-RPC method, target and decision. The method and target are
  resolved from the request **body**, never from the mirrored `Mcp-Method` and
  `Mcp-Name` headers — a client can set those to name a cheap tool while the
  body calls an expensive one. Labels are bounded by what the route's own
  configuration names, so a client cannot mint series by calling random tools.

- **Rate limiting per MCP tool**, via the `mcp-tool` and
  `client-ip-and-mcp-tool` rate-limit keys. An MCP endpoint otherwise shares
  one limit across every tool it exposes, so a client hammering an expensive
  tool exhausts the quota for the cheap ones. These are the first keys resolved
  from the request body rather than from headers, and so apply once the body
  has arrived.

- **Tools a route forbids are hidden from `tools/list`.** Refusing a call to a
  forbidden tool left the upstream still advertising it, so a client discovered
  tools it would only ever be refused. `tools/list`, `resources/list` and
  `prompts/list` responses are now filtered to exactly what the route permits,
  using the same identity rule and predicate as the enforcer.

  This matters beyond tidiness: tool descriptions are spent from the model's
  context window, and a tool list is an inventory that routinely discloses
  which internal systems exist and what they can be made to do. Set
  `filter-tool-list #false` on a route to keep the previous behaviour.

- **An MCP-native health check**, `health-check { type "mcp" }`. A TCP check
  proves a socket is open and an HTTP check proves something answered 200;
  neither says the server still speaks MCP, and many MCP servers expose no
  `/health` at all. The probe sends `initialize`, and given `expected-tools`
  also asks `tools/list` and requires those tools to be present — so a server
  that is up but has lost the backend behind its tools is taken out of rotation
  rather than left to fail real calls.

---

## [26.09_1] - 2026-09-01

**Crate version:** 0.6.38

Dependency updates only. Nothing in this release changes how Zentinel routes,
inspects or blocks traffic; there is no reason to hurry the upgrade, and no
configuration change is needed.

### Changed
- **`quick-xml` 0.41 → 0.42**, which decodes as it reads. The XML parser in the
  data-masking agent was ported to match: element names and attribute keys now
  arrive as `&str` rather than `&[u8]`, attribute values as `Cow<'_, str>`, and
  `BytesText` derefs to `str` instead of offering a fallible `decode()`.
  Attribute values remain unnormalised, as before, so masking sees exactly the
  text it saw on 0.41.
- **`jsonschema` 0.50 → 0.52** in the config and proxy crates.
- **`uuid` 1.24.1 → 1.26.0** and **`maxminddb` 0.30.0 → 0.30.3**.

---

## [26.08_14] - 2026-08-29

**Crate version:** 0.6.37

> **If you run Zentinel with no configuration file, upgrade.** On 0.6.36 and
> earlier it never finished starting.

### Fixed
- **The default configuration no longer fights itself for port 9090.** Running
  `zentinel` with no arguments started the standalone metrics server on
  `0.0.0.0:9090` and then tried to bind an admin listener to the same address.
  The metrics server won, and Pingora retried the listener once a second
  forever:

  ```
  WARN pingora_core::listeners::l4: 0.0.0.0:9090 is in use, will try again
  ```

  The standalone server was redundant there: the default configuration already
  serves `/metrics` from the admin listener through the builtin `metrics` route,
  at the same address. It is now explicitly disabled in the shipped
  configurations, so the endpoint is unchanged and the conflict is gone. The
  starter configuration written to disk had the same collision. (#432, #435)

- **A listener that collides with the metrics server is now a configuration
  error.** The metrics server binds its own socket outside Pingora's listeners,
  so the duplicate-listener-address check could not see it and nothing failed at
  bind time — the loser simply retried. Loading now fails with a message naming
  both sides. Addresses are compared as parsed sockets, since `0.0.0.0:9090` and
  `127.0.0.1:9090` cannot both be bound. (#435)

- **`logging { timestamps }` is read.** Two things were wrong: the KDL parser
  never read the key, so `timestamps #false` reached the configuration as
  `true`, and nothing consumed the value afterwards. Turning timestamps off is
  for environments whose log transport stamps arrival time itself — systemd
  journal, Docker, most shippers — where a second timestamp per line is noise.
  (#415, #433)

  The log subscriber now starts after the configuration is read, since the
  setting has to be known to build it. The diagnostics emitted while finding
  that configuration are buffered and replayed once logging is up, so nothing is
  lost by the reordering.

### Changed
- Every KDL example in the crates' own `docs/` now parses. 175 lines across nine
  files used bare `true`/`false`, bracketed arrays and KDL v1 raw strings, none
  of which are valid KDL, so those examples could not be copied. Two documented
  settings that never existed were corrected against the parser. (#434)

---

## [26.08_13] - 2026-08-29

**Crate version:** 0.6.36

> **If any upstream of yours uses `discovery "dns-srv"`, the backends it selects
> will change after this upgrade.** It was resolving the wrong host on the wrong
> port; it now resolves what the SRV record actually names. Check that the
> targets it picks are the ones you expect before rolling this out widely.

### Fixed
- **`dns-srv` discovery reads SRV records.** It never did. The service name had
  its underscore labels stripped — `_http._tcp.api.example.com` became
  `api.example.com` — and that was resolved as A/AAAA on port 80, discarding the
  port and weight the record exists to carry. A warning was logged and the
  limitation was documented, but any upstream configured this way was pointed at
  the wrong host and port. (#429)

  Resolution now follows [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782):

  - only the lowest-numbered priority receives traffic, since higher numbers are
    standby targets and mixing them in would put live traffic on backups;
  - the record's weight becomes the backend weight, with `0` treated as `1`
    because it means "no preference" rather than "never select";
  - a `.` target means the service is explicitly unavailable and yields no
    backends rather than being resolved as a hostname.

  Each SRV target is then resolved to its A/AAAA addresses, both families
  included. A target that fails to resolve is skipped with a warning rather than
  discarding the rest of the set.

---

## [26.08_12] - 2026-08-29

**Crate version:** 0.6.35

### Fixed
- **`Cache-Status` preserves an upstream cache's member.** The header was written
  with `insert_header`, which replaces every existing value under that name.
  RFC 9211 makes `Cache-Status` a List carrying one member per cache on the path,
  ordered origin-closest first, and says a cache "SHOULD preserve the existing
  field value, to allow debugging of the entire chain of caches handling the
  request".

  So a Zentinel placed in front of another cache erased whatever that cache
  reported, leaving no way to tell which tier served a response. A response that
  should read

  ```
  Cache-Status: origin-shield; hit, edge; fwd=miss
  ```

  arrived as `edge; fwd=miss` alone. This affected any deployment with a cache
  upstream of Zentinel, not only Zentinel-to-Zentinel. (#397, #426)

  Give each tier its own `status-header-name`: two nodes both defaulting to
  `zentinel` produce members that are preserved but indistinguishable.

---

## [26.08_11] - 2026-08-29

**Crate version:** 0.6.34

> **If you have an upstream with a `discovery` block, it has been routing to
> nothing and will start routing to real backends after this upgrade.** That is
> the block finally doing what it says, but it is a change in behaviour: an
> upstream that reliably returned errors begins forwarding traffic. Configurations
> that added a static `target` alongside `discovery` to work around this will now
> serve *both* the pinned target and the discovered set.

### Added
- **Upstream service discovery is wired to the request path.** `discovery`
  blocks are documented across ten pages and backed by working DNS, DNS SRV,
  Consul, Kubernetes, file and static implementations, but nothing connected the
  two: the configuration type had no `discovery` field, so the block parsed into
  nothing and the upstream was left with no targets. Targets are now resolved
  before the pool serves traffic and re-resolved on the interval the source
  declares. (#419, #423)

  Discovered targets are *added* to statically configured ones, so a fixed
  backend can be pinned alongside a discovered set; an address that appears in
  both is listed once. Circuit breaker state and pool statistics survive a
  refresh, so a failing backend stays ejected rather than looking healthy again
  every interval, and breakers for backends that disappear are dropped.

  A source that cannot be reached leaves the upstream serving the targets it
  already has and retries on the next interval; one that fails during startup
  leaves it with only its static targets. Neither stops the proxy from starting,
  so an unreachable registry cannot take unrelated upstreams down with it. A
  source that answers with *no* backends is honoured and logged at `WARN`.

  Two metrics are exported: `zentinel_upstream_discovery_refreshes_total` and
  `zentinel_upstream_discovery_targets`.

- **`static` and `dns-srv` discovery are documented.** Both were implemented and
  undocumented. `dns-srv` still reduces the service name to a hostname and
  resolves it as A/AAAA on port 80 rather than reading SRV records, ignoring the
  port and weight the record carries; it is documented with that limitation
  rather than presented as working.

### Fixed
- **Sticky-session affinity survives a pool rebuild.** The key signing affinity
  cookies is generated randomly per load balancer, so rebuilding one rotated it
  and invalidated every cookie already issued. Configuration reload did this
  once; with discovery refresh it would have happened every time a backend
  appeared or disappeared, resetting all sessions on a churning backend set.
  (#423)

- **Discovery settings are checked against the backend they name.** A `hostname`
  inside a `discovery "consul"` block, an unknown discovery type, a missing
  required setting, or a zero refresh interval are now errors rather than keys
  that parse and are ignored. (#423)

---

## [26.08_10] - 2026-08-28

**Crate version:** 0.6.33

> **If any configuration of yours sets `tracing { enabled #false }`, tracing has
> been running regardless, and stops after this upgrade.** That is the setting
> doing what it says, but it is a change in behaviour: spans stop reaching the
> collector, and anything downstream that expected them — dashboards, sampling
> alerts, a trace-based SLO — goes quiet. Check before upgrading if you are not
> sure which of your configurations set it.

### Fixed
- **`tracing { enabled }` is read.** Tracing was switched on by the *presence*
  of the `tracing` block, and `enabled` was read by nothing, so a configuration
  asking for it to be off got it anyway with no indication. An operator
  disabling tracing to cut overhead, or to stop shipping spans to a collector
  they no longer trust, did not get what they asked for. The setting defaults to
  true, so a `tracing` block without it behaves exactly as before, and the skip
  is now logged rather than silent. (#415, #420)
- **`access-log { include-trace-id }` is read.** The access log writer already
  consults a trace-id field flag, and the field list has no configuration syntax
  of its own, so this setting was the only way to reach it — and nothing read
  it, leaving the choice permanently at its default. (#415, #420)

  `logging { timestamps }` remains unread and is still reported by
  `zentinel lint`. Honouring it means starting the log subscriber after the
  configuration is read, and it currently starts first so that configuration
  discovery is logged at all; that trade is #415's remaining question.

---

## [26.08_9] - 2026-08-28

**Crate version:** 0.6.32

> Configuration checking only — nothing about how the proxy handles traffic
> changes. As before: a setting that starts being reported was already being
> ignored, and no config that loaded before will fail to load.

### Added
- **Observability blocks are checked**, completing the block list from #365:
  `observability`, `logging`, `access-log`, `error-log`, `audit-log`, `metrics`,
  `tracing`, and a tracing `backend`. The access log takes `format` where the
  error log takes `level` — two blocks that look alike and accept different
  settings — so each is checked against its own list. Forty-three blocks are now
  covered in total. (#365, #416)

### Fixed
- **Three settings that no parser reads are removed from the shipped configs.**
  `timestamps` in `logging`, `include-trace-id` in `access-log`, and `enabled` in
  `tracing` appeared across seven configurations, `config/zentinel.kdl` included.
  Every occurrence was `#true`, so nothing changes behaviourally — they were
  already doing nothing. All three are also described in the documentation, and
  whether they should be implemented or de-documented is tracked in #415. (#416)

  Worth calling out if you use it: **tracing is switched on by the presence of
  the `tracing` block**, not by `enabled`. A configuration reading
  `tracing { enabled #false }` gets tracing regardless. `zentinel lint` now
  reports that setting rather than passing over it.

---

## [26.08_8] - 2026-08-28

**Crate version:** 0.6.31

> Configuration checking only — nothing about how the proxy handles traffic
> changes. As in 26.08_7: if `zentinel lint` starts warning about a config you
> have been running, the setting was already being ignored. The warning is new,
> the behaviour is not, and no config that loaded before will fail to load.

### Added
- **Checking extended to the remaining configuration blocks**, and now covering
  thirty-five in total: `health-check` and its per-type settings, the inference
  `readiness` block and its four sub-blocks, `agent` and its transport blocks,
  an agent transport's `tls`, the global `rate-limits` block, and rate-limit
  filters. (#365, #409, #410, #411)
- **Settings are checked against the block they are actually in.** Several block
  names mean more than one thing — `cache` at the top level configures storage
  and inside a route configures policy; `tls` means one thing on a listener,
  another on an upstream and a third on an agent transport; `type "http"` and
  `type "grpc"` accept different health-check settings. Each is now checked
  against its own list rather than a merged one, and a setting placed in the
  wrong one is told where it belongs rather than offered a spelling suggestion.
  (#365, #405, #409, #411)
- **The configuration playground runs the same checks as the CLI.** It reported
  only topology warnings, so a configuration could look clean in the browser
  while `zentinel lint` reported settings the proxy ignores. The checks needed
  nothing but the configuration text, but sat behind a feature flag that pulls
  in the async runtime and X.509 parsing and cannot build for WebAssembly; the
  flag now gates only the checks that genuinely need it. (#365, #411)

### Fixed
- **An agent's `type` written as a child node was ignored.** The documented form
  is a property (`agent "waf" type="waf"`), and four shipped configurations —
  including the default `zentinel.kdl` — used a `type "waf"` child node instead,
  which silently produced an agent type of `Custom(<id>)` rather than the type
  named. Both forms are now read, the same way `unix-socket`, `grpc` and `http`
  already accept either a child node or a bare argument. The agent type is
  reported in logs and by the config endpoint and affects no routing or security
  decision, so nothing changes beyond those two reporting it correctly. (#411)

---

## [26.08_7] - 2026-08-27

**Crate version:** 0.6.30

> Configuration checking only — no change to how the proxy handles traffic.
> `zentinel lint` reports more of the configuration that parses cleanly and then
> does nothing. If it now warns about a config you have been running, the setting
> in question was already being ignored; the warning is new, the behaviour is not.

### Added
- **Settings swallowed by a run-together line are reported.** KDL separates nodes
  by newline or `;`. Written on one line with neither,
  `listener "public" { address "0.0.0.0:8080" namespace "iso" }` is a single
  `address` node with three arguments — `namespace` never reaches a parser, and
  the config loads, validates and starts without it. That is how a listener's
  namespace isolation came to be silently absent in #396, and both `zentinel test`
  and `zentinel lint` reported success. The check reports an argument after the
  first whose value names a key of the same block, so a node legitimately taking a
  list (`hostnames "a.com" "b.com"`) is not affected. (#365, #404)
- **Keys in the wrong one of two same-named blocks are reported, with where they
  belong.** Block names are not unique: the top-level `cache` block configures the
  storage backend (`backend`, `disk-path`), while a route's `cache` block
  configures that route's policy (`default-ttl-secs`), and they share one key
  between them. Checking them against a merged list accepted either half
  anywhere, which is why #90 — storage settings in a route's cache block, cache
  directory silently empty — produced no warning. The same applies to `tls`,
  which means one thing on a listener and another on an upstream. Misplaced keys
  are now named as misplaced rather than offered a spelling suggestion:
  `'disk-path' is a setting of the top-level 'cache' block, not of a 'route'
  block's 'cache' block`. (#90, #365, #405)
- **Unknown-key checking extended to eleven more blocks:** `listener`, `cache`
  (both), `sni`, `sni-certs`, `acme`, `eab`, `upstream`, an upstream's `tls`, and
  `target`. (#365, #404, #405, #406)

### Fixed
- **`verify` in the inference-routing example did nothing.** Two upstream `tls`
  blocks in `config/examples/inference-routing.kdl` set `verify #true`. No parser
  reads it — certificate verification is controlled by `insecure-skip-verify` and
  is on by default — so the example got the behaviour it intended by accident
  while stating it in a key that has never existed. Found by the new checks on
  their first run against the shipped configs. (#406)

### Changed
- The release process documentation in `.claude/rules/workflow.md` stated the
  CHANGELOG's crate version rule backwards, describing it as the tagged
  `Cargo.toml` version rather than the version actually published. Corrected, and
  the two versions are now named rather than both written `X.Y.Z`. (#403)

---

## [26.08_6] - 2026-08-27

**Crate version:** 0.6.29

> **If you set `namespace` on a listener bound to `0.0.0.0` or `[::]`, it was
> doing nothing.** The listener served the *global* route set instead of its
> namespace's, with no warning, log line, or validation error. `namespace` is an
> isolation control, so this failed in the permissive direction: routes an
> operator believed were scoped away were reachable. Concrete binds such as
> `127.0.0.1:9000` were unaffected, which is why this survived — the documented
> admin-listener example is loopback-bound.
>
> **Check any wildcard-bound listener that carries a `namespace` before
> upgrading:** it begins enforcing isolation for the first time, so routes that
> have been served from the global set will stop being reachable there. The same
> listeners' `request-timeout-secs` and `keepalive-timeout-secs` also begin
> taking effect, having run on defaults until now.

### Fixed
- **Listener `namespace` is enforced on wildcard binds.** Namespace route
  matchers were keyed by the *configured* bind address and looked up by the
  accepted connection's local address, which Pingora takes from `getsockname()`.
  A connection accepted on `0.0.0.0:443` reports the concrete interface it
  landed on — `203.0.113.5:443` — and never `0.0.0.0:443`, so the lookup could
  not hit and the request fell through to the global matcher. Both call sites
  now resolve on parsed socket addresses: exact binds by equality, wildcard
  binds by port with the address families that bind can actually accept, and
  IPv4-mapped addresses canonicalised so a dual-stack listener resolves both
  families alike. Concrete binds take precedence over wildcard binds on the same
  port. (#396, #398)
- **Per-listener `request-timeout-secs` and `keepalive-timeout-secs` apply on
  wildcard binds.** The same comparison, in `request_filter`, meant a config
  setting either on a `0.0.0.0` listener validated cleanly and ran on the
  defaults. (#396, #398)

### Added
- **Certificate reloads report what changed.** A reload logged counts and a bare
  success line, which cannot answer whether anything actually changed: a renewal
  covers the same hostnames as the certificate it replaces, so every count stays
  identical. Reloads now log `added`, `removed` and `replaced` hostnames at
  `info`, where `replaced` names a hostname whose certificate changed and
  carries the SHA-256 fingerprints on both sides — the same digest
  `openssl x509 -fingerprint -sha256` prints, so it can be matched against a
  file on disk. A rescan that changed nothing says so explicitly. The default
  certificate participates as `<default>`, since a silent rotation of it was
  equally invisible. Completes the diff from the #117 checklist, which shipped
  without it. (#399, #400)

---

## [26.08_5] - 2026-08-24

**Crate version:** 0.6.28

> **If you configured `mcp` or `a2a` in 26.08_4, it did nothing.** The blocks
> parsed, validated, and rejected unknown keys — and no request was ever checked
> against them. A route declaring `tools { allow "get_weather" }` permitted every
> tool there is. That is fixed here, which means these routes begin enforcing
> policy for the first time: **check your allow and deny lists say what you
> intend before upgrading.**
>
> Also breaking: `buffer-requests` and `buffer-responses` are removed. Neither
> ever had any effect, so no behaviour changes, but a config setting them will
> now be reported by `zentinel lint` as a key nothing reads.

### Fixed
- **MCP and A2A route policy is enforced.** `RouteConfig::mcp` and
  `RouteConfig::a2a` were read by nothing: the module had no call site anywhere
  in the request path. Policy now runs in `request_body_filter`, resolved from
  the JSON-RPC envelope, with the body accumulated across chunks and judged once
  at end of stream — never on a partial envelope, and before anything reaches an
  upstream. Denials return 403 with an operator-readable reason; allowed
  requests record the method and tool resolved *from the body*, so metrics
  describe what the upstream will execute rather than what a header claimed.
  Accumulation stops at 1 MiB, past which `on-uninspectable-body` decides rather
  than a truncated prefix being judged as the whole request. (#392)
- **`cargo install zentinel-proxy` works again.** `cargo publish` strips git
  sources, so the published crate resolved `pingora-core` from crates.io —
  upstream, without `TlsSettings::with_server_config` — and failed to compile
  after roughly ten minutes. Broken in 0.6.26 and 0.6.27. The fork's five
  affected crates are now published as `zentinel-pingora`,
  `zentinel-pingora-core`, `-proxy`, `-cache` and `-load-balancing`, and are
  depended on by version. No git or path dependencies remain. (#357, #391)
- **`workers` in two shipped configs was read by nothing** — the parser reads
  `worker-threads`, so both ran on the default worker count while the file said
  4 and 1. (#386)
- **`circuit-breaker` inside `route` blocks did nothing.** Circuit breakers are
  configured per upstream and per agent; `RouteConfig` has no such field. Eight
  occurrences across five shipped configs, including `config/zentinel.kdl`, are
  removed. The simulator and `zentinel-inspect` made the same assumption and are
  corrected to report breakers against upstreams. (#386, #387, #390)
- **`crates/sim` compiles again**, and `zentinel-inspect` and
  `playground-wasm` resolve their dependencies. All three were broken and
  invisible, because crates in the workspace `exclude` list are built by no CI
  job. (#387, #389, #390)

### Added
- **Unknown-key checking covers `route`, `system` and `server`.** A misspelled
  key inside those blocks was accepted and discarded; `zentinel lint` now names
  it and suggests the intended spelling. (#365, #386)
- **CI builds the excluded crates.** A new `Excluded Crates` job covers all four
  crates outside the workspace, including formatting, which the workspace-wide
  `cargo fmt --all` cannot reach. (#387, #389, #390)

### Changed
- **BREAKING — `buffer-requests` and `buffer-responses` removed** from
  `RoutePolicies`. No KDL key set them and nothing in the proxy read them, so
  they could never be anything but `false`. Thirteen sites across five shipped
  configs and a test fixture set them anyway; `ai-guardrails.kdl` annotated them
  "Required for request inspection", which was not true. No behaviour changes.
  (#366, #388)
- Dependency maintenance: wasmtime group 47 → 48, `jsonschema` 0.50, rust-minor
  batch. (#381, #382, #383)

---

## [26.08_4] - 2026-08-23

**Crate version:** 0.6.27

> **Read this before deploying.** A number of settings in this release were
> previously parsed and then discarded, and now take effect. Nothing about your
> configuration files changes — but configurations you have been running will
> start behaving the way they read, which for some deployments is a change in
> behaviour even though nothing was edited.
>
> Affected: every `upstream.timeouts` setting, `connection-pool.idle-timeout-secs`
> and `max-lifetime-secs`, route `policies` (including `failure-mode`,
> `timeout-secs` and `rate-limit`), the distributed rate-limit fallback and TTL
> settings, and WAF rule exclusions. Separately, `retry-policy.max-attempts`
> changes meaning, host matching becomes case-insensitive, and two
> configurations that previously started with a warning now refuse to start:
> `client-auth` without a `ca-file`, and a listener with `protocol "h3"`.
>
> Each is detailed below with what it did before.

### Added
- **Native MCP and A2A awareness.** Routes can carry an `mcp` or `a2a` block
  and the proxy inspects the JSON-RPC envelope: per-method and per-tool
  allow/deny lists, resolved against the request body.

  The reason this is in the proxy rather than an agent is MCP's Streamable HTTP
  transport, which mirrors `method` and the tool name into `Mcp-Method` and
  `Mcp-Name` headers so intermediaries can route without parsing bodies. Taken
  at face value that is a bypass: send `Mcp-Name: read_file` with a body calling
  `delete_everything` and any allowlist keyed on the header waves it through.
  Zentinel resolves policy from the body and treats a header that disagrees as
  hostile. `Mcp-Param-*` headers, which mirror individual tool arguments, are
  checked the same way.

  Requests claiming a protocol revision older than `2026-07-28` are refused by
  default, because those revisions never required headers to match the body — so
  without that check an attacker opts out of validation by claiming an old
  version. Configurable via `require-validated-version`.

  A2A carries no mirrored headers, so its policy resolves from the body
  directly. Unknown methods are forwarded by default so the proxy does not block
  agent upgrades.

  Verified against the MCP draft revision `2026-07-28` and A2A v1.0. (#377)
- **`zentinel lint` reports config keys that no parser reads.** A misspelled key
  in a nested KDL block was accepted and discarded — no error, no warning, no
  effect — so `failure_mode` with an underscore, or `ratelimit` without a
  hyphen, silently disabled a policy while the config file said otherwise. The
  lint now names the key, says it is being ignored, and suggests the intended
  spelling. It checks blocks whose key set is fixed (`connection-pool`,
  `timeouts`, `policies`); blocks that legitimately hold arbitrary keys, like a
  JSON schema's properties, are left alone. A test asserts every shipped config
  passes, so an under-listed key set fails the build rather than warning
  operators about valid configuration. (#365)
- **Certificate folders.** An `sni-certs` block points at a directory, and every
  certificate/key pair found there is registered with the hostnames from its own
  CN and SANs — no config edit to add or remove one. `reload-mode` selects `off`
  (SIGHUP only), `interval`, or `watch`; a watcher that cannot be established
  falls back to the interval and logs why rather than leaving the folder
  silently unwatched. Overlapping hostnames are an error by default, since which
  certificate wins would otherwise depend on directory order;
  `allow-sni-overlaps` accepts them and resolves by sorted path. New metrics:
  `zentinel_tls_certificates_loaded`, `zentinel_tls_reload_total{result}`,
  `zentinel_tls_folder_entries_skipped_total{reason}`. (#117)
- **`retry-policy` gains `retryable-status-codes`, `backoff`, `max-backoff`,
  `per-attempt-timeout` and `retry-non-idempotent`.** Nothing is retried on a
  status code unless configured, and `POST` is not replayed without opting in —
  the proxy cannot tell whether an origin already performed a side effect. When
  the budget runs out the client receives the upstream's own response, not a
  gateway error. (#279)
- **`zentinel lint` checks resource bounds.** Warns about a `max-connections` of
  0, an unreachable `max-idle`, an agent with `max-concurrent-calls` 0, a route
  that buffers bodies with no `max-body-size`, and limits generous enough to be
  indistinguishable from unbounded. (#128)

### Changed
- **BREAKING (behaviour) — `retry-policy.max-attempts` now bounds request
  retries.** It previously bounded upstream *peer-selection* attempts: retrying
  the choice of backend from the pool, which fails only when no pool member is
  healthy. A route configured for request resilience was getting extra tries at
  an operation that rarely fails. Peer selection now has its own small fixed
  count. Re-check any route relying on the old meaning. (#279)
- **CI runs tests with `--all-features`.** Optional features were compiled by
  the clippy job and executed by no job at all, which is how two `binary-uds`
  faults (#359, #360) reached main. The documentation job passes it too, so docs
  on feature-gated items are rendered rather than skipped. (#360)
- **Host matching is case-insensitive**, per RFC 3986 §3.2.2. This previously
  failed in both directions: a request for `EXAMPLE.COM` missed a route for
  `example.com`, and a route written `host "Example.com"` matched nothing at
  all — silently, permanently. Routes with mixed-case hosts that appeared to do
  nothing will now start matching. (#113)

### Fixed
- **`client-auth` without `ca-file` is now rejected instead of silently serving
  ordinary TLS.** Client certificates cannot be verified without a CA to verify
  them against, and the proxy logged a warning and carried on with client
  authentication disabled. An operator could configure mutual TLS, pass
  `zentinel test` and `zentinel validate`, start the proxy, and be accepting
  unauthenticated clients — with one startup warning as the only signal. For
  internal traffic where mTLS is often the only authentication, that is the
  whole control. **A config with `client-auth` and no `ca-file` will now fail
  to start**; it was never getting mutual TLS, so the failure reveals a
  misconfiguration rather than creating one.
- **`ReverseConnectionConfig::require_auth` now authenticates.** It checked that
  a registering agent sent *a* token, never that the token was correct, so any
  non-empty string authenticated. Tokens are now compared in constant time
  against a configured `auth_tokens` set, and a listener configured to require
  authentication with no tokens to check against refuses to bind rather than
  accepting everyone. The reverse-connection socket is also created `0600`;
  previously it took whatever the umask gave, commonly leaving it
  world-connectable. Not reachable from any Zentinel configuration — nothing
  instantiates this listener — but `zentinel-agent-protocol` is published, so
  anyone building on it inherited the flaw. (#374)
- **The WebSocket example enables WebSocket.** It wrote `websocket { enabled
  #true … }` as a block, while a route reads `websocket` as a scalar boolean —
  so every route in the example demonstrating WebSocket proxying parsed to
  `websocket = false` and proxied none. The example now uses `websocket #true`
  and `websocket-inspection #true`, and the keepalive, message-size and
  per-IP-connection settings it carried are kept as comments, since none of
  them exist in the schema. Its header no longer advertises them. (#369)
- **`zentinel lint` no longer claims a check it cannot perform.** The
  "buffers bodies but sets no max-body-size" rule could never fire —
  `buffer-requests` and `buffer-responses` have no KDL key and are read by
  nothing, so they are always false for any config a person can write. The
  rule is removed rather than left reporting coverage that does not exist; a
  test now guards that those fields are still unreachable, so it fails if
  #366 wires them up. (#366)
- **Distributed rate-limit fallback and TTL are read.** The backend parser
  looked for `redis-fallback`, `memcached-fallback` and `memcached-ttl` while
  every config writes `redis-fallback-local`, `memcached-fallback-local` and
  `memcached-ttl-secs`. The defaults matched what the examples asked for, so
  the mismatch was invisible until a value differed — and the value that
  mattered was `#false`. An operator disabling local fallback (so a Redis
  outage does not silently degrade one global limit into one limit per proxy
  instance) was ignored, and got local fallback anyway. (#365)
- **WAF rule exclusions are read.** Exclusions were looked for as direct
  children of `ruleset`, but configs group them in an `exclusions { }` block,
  so every exclusion was discarded — including all of `config/zentinel.kdl`'s.
  Rules an operator had excluded because they false-positive on their
  application kept firing, with the exclusion plainly visible in the file. The
  two-argument scope form (`scope "path" "/api/v1/upload"`), which the shipped
  config uses, is now accepted alongside `scope "path=/api/v1/upload"`. (#365)
- **Route `policies` are read.** Six of the nine fields on `RoutePolicies` were
  never populated: the parser set header rewriting and caching and left the rest
  behind a `..Default::default()`. `timeout-secs`, `max-body-size`,
  `failure-mode` and `rate-limit` are now parsed.

  **`failure-mode` is the one to check before upgrading.** The proxy reads it to
  decide whether to block a request when an agent fails, and it was pinned to
  `closed` regardless of configuration. A route written `failure-mode "open"`
  ran fail-closed, so an agent crash blocked that route's traffic rather than
  letting it through. Those routes will now fail open, as their config asked.
  Routes that say nothing are unaffected — the default is still `closed`, and a
  route only becomes fail-open by naming it. An unrecognised value is now an
  error rather than a silent fall back to `closed`.

  Per-route `timeout-secs` and `rate-limit` also take effect for the first time,
  so routes carrying them will start enforcing limits they previously declared
  but did not apply. `buffer-requests` and `buffer-responses` are deliberately
  still not parsed — nothing reads them (#366). (#368)
- **Upstream timeouts are read.** `timeouts` accepted `connect`, `request`,
  `read` and `write`, while every shipped config and the documentation write
  `connect-secs`, `request-secs`, `read-secs` and `write-secs`. Every timeout in
  every shipped config was therefore discarded in favour of its default. The
  worst case was an upstream asking for `request-secs 300` — the inference
  examples do — and being cut off at the 60s default, a fifth of what it asked
  for; `connect-secs 2` likewise waited 10s. **Timeouts will now take the values
  your config specifies**, which for existing deployments means both shorter
  connect timeouts and longer request timeouts than they have been running with.
  The unsuffixed names remain accepted as aliases. (#365)
- **`connection-pool.idle-timeout-secs` and `max-lifetime-secs` are read.** The
  parser looked for `idle-timeout` and `max-lifetime` — names that appear in no
  config anywhere, including this repo's own. The documented `-secs` spellings,
  used by `config/zentinel.kdl` and four shipped examples, were discarded. The
  visible effect was that `max-lifetime-secs 300` produced *no* lifetime cap, so
  pooled connections were never retired by age; `idle-timeout-secs` appeared to
  work only because 60 is also the default. **Deployments using the shipped
  config or those examples will now cap connection lifetime at 300s where they
  previously had none.** The bare names remain accepted as aliases. Found via
  #365. (#365)
- **Route cache poisoning across query parameters.** The cache key was built
  from method, host, path and headers, and `path` carries no query string — so
  `/api?version=v2` and `/api?version=v1` shared an entry and the second request
  was routed to the first's upstream. A route selected by query parameter could
  be reached by any request to the same path once an entry was primed. (#355)
- **A trailing dot no longer bypasses a host route.** `admin.example.com.` names
  the same host as `admin.example.com` but did not match it, so a restrictive
  host route could be stepped around by appending a dot and falling through to a
  permissive catch-all. (#113)
- **IPv6 hosts are no longer mangled when stripping a port.** The port was
  removed with `split(':').next()`, which reduces `[::1]:8080` to `[`. (#113)
- **`binary-uds` no longer hangs every agent call.** The UDS server reads only
  the correlation id out of an event payload; `rmp_serde::to_vec` encodes structs
  positionally, so that partial read failed and the server answered with an empty
  correlation id. The proxy, which matches responses by correlation id, waited
  out its timeout on every request. Structs are now encoded as maps. (#359)
- **`binary-uds` no longer hangs six of the seven agent event types.** The
  client added `correlation_id` beside each event with `#[serde(flatten)]`, but
  every event except `RequestHeadersEvent` already carries one — so the key went
  out twice. JSON hid it, because that path mutates a `serde_json::Value` and the
  second insert overwrites the first; a MessagePack map keeps both entries and
  the server rejected the payload as a duplicate field. The server's fallback for
  recovering a correlation id from an undecodable payload was derived too, and
  failed on the same duplicate, so the reply carried an empty id and the caller
  waited out its timeout. Request bodies, response headers, response bodies,
  request completion, WebSocket frames and guardrail inspection were all affected;
  `RequestHeadersEvent` escaped only because it nests its id under `metadata`.
  (#360)

## [26.08_3] - 2026-08-22

**Crate version:** 0.6.26

> Closes the gap 26.08_2 warned about. If you configured SNI certificates,
> `client-auth`, `min-version`/`max-version`, `cipher-suite` or
> `session-resumption` and saw the startup warnings, those settings now take
> effect. **Re-check that your configuration says what you intend before
> upgrading** — a listener that previously ignored `client-auth true` will now
> require and verify client certificates.

### Fixed
- **Per-SNI certificates are served.** A client is now sent the certificate
  matching the SNI hostname it requested, with wildcard matching and fallback to
  the default certificate. Previously every client received the primary
  certificate regardless of the name requested. (#303)
- **`client-auth` (mTLS) is enforced.** The listener requests and verifies client
  certificates against `ca-file`. Previously it did neither, so a listener
  configured for mTLS accepted unauthenticated connections. (#303)
- **`min-version`, `max-version`, `cipher-suite` and `session-resumption` are
  applied.** The listener previously used Pingora's built-in intermediate profile
  (TLS 1.2+, default cipher suites) and ignored all four. (#303)
- **Certificates reload on SIGHUP.** The resolver installed in the TLS
  configuration is now the same object the certificate reloader refreshes, so a
  renewed certificate is picked up without a restart. ACME renewals previously
  reached disk but not the listener. (#303)

### Changed
- The startup warnings added in 26.08_2 for unapplied TLS settings are removed:
  there is nothing left for them to warn about. (#303)

### Internal
- The pinned Pingora fork gains `TlsSettings::with_server_config`, which accepts a
  caller-built `rustls::ServerConfig`. `TlsSettings::build()` previously
  constructed its own and finished with `with_single_cert`, so no per-SNI
  resolver, client-certificate verifier, or version/cipher selection could reach
  the listener. (zentinelproxy/pingora#6)
- `crates/proxy/tests/tls_handshake_test.rs` runs real TLS handshakes over
  loopback and asserts on what the client observed. The existing SNI tests all
  call the resolver directly, so none of them could have caught #303 — the defect
  was that the resolver was never reached. (#350)

## [26.08_2] - 2026-08-22

**Crate version:** 0.6.25

> **Contains a breaking configuration change** (listener TLS schema, below).
> Released as a SemVer patch rather than a minor bump, so pinning `0.6` will
> pick it up: check your listener `tls` blocks before upgrading. Configs using
> `additional-certs` or `cipher-suites` will fail to load.

### Changed
- **BREAKING — listener TLS config schema.** SNI certificates now use repeated
  `sni { ... }` blocks instead of `additional-certs { cert ... }`, and cipher suites
  use repeated `cipher-suite "NAME"` nodes instead of a `cipher-suites { ... }` list.
  Unknown nodes inside `tls` and `sni` blocks are now **rejected at parse time**
  (previously silently ignored) with descriptive errors and legacy-syntax hints, so
  a config can no longer imply TLS behavior the proxy never applies. (#311)
- Route match conditions with a missing or non-string value are now a hard error
  rather than being silently skipped. A route that drops a match condition matches
  more traffic than its author intended. (#344)
- `shadow` percentages are validated instead of silently coerced. (#344)

### Added
- Loud startup warnings when TLS hardening settings — per-SNI certificate serving,
  client-auth/mTLS, min/max TLS version, cipher suites, and session resumption — are
  configured but not yet applied by the listener (issue #303); the listener uses
  Pingora's built-in intermediate profile and serves the primary certificate to all
  clients until #303 lands. Unenforced mTLS emits a `SECURITY:` warning. (#311)
- Actionable errors for route match conditions: the route, the condition and a
  concrete example are named, and unknown condition names get a "did you mean"
  suggestion from an edit-distance match. (#344)
- `crates/config/tests/shipped_examples.rs` loads and validates every shipped
  example plus the multi-file tree, so the examples cannot drift again. (#345)

### Fixed
- **ACME DNS-01 is now idempotent.** `create_txt_record` behaves as an *ensure*
  operation across Cloudflare, Hetzner and webhook providers, so a stale
  `_acme-challenge` TXT from a failed run no longer breaks issuance on restart.
  Duplicate detection requires both the status code and the provider's message,
  and only exact value matches are reused — the previous heuristic could select an
  unrelated record and delete it during cleanup. (#343)
- **DNS-01 propagation is visible.** Empty `propagation.nameservers` now falls back
  to public resolvers instead of failing every lookup silently at `TRACE`. (#343)
- **Transient ACME failures no longer abort startup.** Account, order and
  finalization errors retry with bounded backoff, and retryability is decided by
  matching error variants rather than message substrings, so a propagation timeout
  is no longer misclassified as transient. (#346)
- **Keep-ready deferral is scoped to renewals.** A transient failure during *first*
  issuance now fails fast rather than leaving the HTTPS listener silently absent —
  a skipped listener could never be re-added, since hot-reload only swaps
  certificates on live listeners. (#346)
- All 22 shipped example configs load and validate again; nine did not. Fixes
  property-style `address=`, `server` in place of `target`, bare booleans, and
  `retry-policy` keys that were never implemented. `config/example-multi-file/`
  is rebuilt as a working demonstration of the `include` mechanism. (#345)

### Security
- Bump `wasmtime-wasi` 47.0.2 → 47.0.3, carrying upstream fixes including
  GHSA-hgjw-h833-99q9 (stores mixing type indices between engines). (#338)

### Migration

Update listener `tls` blocks to the new schema:

```kdl
// before                                  // after
additional-certs {                         sni {
    cert hostnames=["a.com"] {                 hostnames "a.com"
        cert-file "a.crt"                      cert-file "a.crt"
        key-file  "a.key"                      key-file  "a.key"
    }                                      }
}

cipher-suites {                            cipher-suite "TLS_AES_128_GCM_SHA256"
    - "TLS_AES_128_GCM_SHA256"             cipher-suite "TLS_AES_256_GCM_SHA384"
    - "TLS_AES_256_GCM_SHA384"
}
```

`retry-policy` accepts only `max-attempts`; `timeout-ms`, `backoff-base-ms`,
`backoff-max-ms` and `retryable-status-codes` are rejected at parse time and
must be removed. The behaviour they describe is tracked in #279.

---

## [26.08_1] - 2026-08-08

**Crate version:** 0.6.24

Dependency-only release. No proxy behavior, configuration schema, or agent
protocol changes.

### Security
- Bump `rustls` 0.23.42 → 0.23.43, part of the rust-minor group. Upstream
  hardens session-ticket age arithmetic and the PSK binder suffix calculation
  (`checked_sub` in `Rfc5077Ticketer::decrypt`), and tightens QUIC cipher-suite
  and TLS-version checks. No CVE assigned and no Zentinel-specific exposure
  identified; taken as defense in depth for the TLS listener path. (#326)

### Changed
- Bump the rust-minor group (4 updates): `rustls` 0.23.42 → 0.23.43,
  `http` 1.4.2 → 1.5.0, `redis` 1.4.1 → 1.5.0, and
  `toml` 1.1.3+spec-1.1.0 → 1.1.4+spec-1.1.0. (#326)
- Bump `pem` 3.0.6 → 4.0.0. (#327)
- Bump `jsonschema` 0.48.1 → 0.49.5. (#328)
- Bump `base64` 0.22.1 → 0.23.1. (#329)
- Bump `validator` 0.20.0 → 0.21.0. (#330)
- Bump `async-memcached` 0.6.0 → 0.7.0. (#332)

### Documentation
- Correct the documented release process to match the Release workflow's
  actual tag+1 versioning behavior. (#325)

---

## [26.07_4] - 2026-07-30

**Crate version:** 0.6.23

### Changed
- Bump the `wasmtime` group (`wasmtime`, `wasmtime-wasi`) 46.0 → 47.0. (#319)
- Bump `quinn-proto` 0.11.14 → 0.11.16. (#321)
- Bump `maxminddb` 0.29 → 0.30. (#317)
- Bump the rust-minor group (17 updates), including `tokio` 1.53.1, `hyper` 1.11.0,
  `serde` 1.0.229, `libc` 0.2.189, and `clap` 4.6.4. (#322)
- CI: bump `actions/setup-go` 6 → 7. (#315)
- CI: bump `google.golang.org/grpc` in `/conformance`. (#318)

---

## [26.07_3] - 2026-07-18

**Crate version:** 0.6.22

### Security
- Bump `serde_with` 3.18.0 → 3.21.0 — fixes GHSA-7gcf-g7xr-8hxj, a serialization
  panic (DoS) in `KeyValueMap`. Zentinel's exposure was low (transitive via
  `ip2location`, no `KeyValueMap` usage), resolved regardless. (#307)

### Changed
- Bump `tokio-tungstenite` 0.29.0 → 0.30.0. (#306)
- Bump `jsonschema` 0.46.10 → 0.48.1. (#305)
- Bump the rust-minor group (`bytes` 1.12.1, `uuid`, `regex`, `sysinfo` 0.39.6). (#309)
- Bump the rust-minor group (`tokio` 1.53, `rustls` 0.23.42, `uuid` 1.24,
  `regex` 1.13.1, `http-body-util`, `toml`, `clap`, `redis` 1.4.1,
  `xxhash-rust`). (#310)

---

## [26.07_2] - 2026-07-06

**Crate version:** 0.6.21

### Changed
- Bump `quick-xml` 0.40 → 0.41. (#300)
- Bump the rust-minor group (`html-escape`, `jsonschema`, `rand`, `xxhash-rust`). (#299)
- Bump `cmov` 0.5.3 → 0.5.4. (#298)
- CI: bump `golang.org/x/net` 0.52 → 0.55 in `/conformance`. (#297)

---

## [26.07_1] - 2026-07-01

**Crate version:** 0.6.20

### Changed
- Bump `maxminddb` 0.28 → 0.29. (#293)
- Bump the `wasmtime` group (`wasmtime`, `wasmtime-wasi`) 45.0 → 46.0. (#292)
- Bump the rust-minor group (12 updates). (#291)
- CI: bump `actions/cache` 5 → 6. (#290)

---

## [26.06_3] - 2026-06-23

**Crate version:** 0.6.18

### Added
- **Merge duplicate top-level blocks across included KDL files.** `listeners`,
  `routes`, `upstreams`, `filters`, and `agents` blocks now merge across
  `include`d files instead of the last file silently winning; duplicate IDs are
  rejected at parse time. Singleton blocks (`system`/`server`/`waf`) keep
  last-wins semantics but now warn on duplicates. (#277)

### Fixed
- **Upstream circuit breaker now recovers from the open state.** A breaker that
  tripped open could remain open instead of transitioning to half-open and
  recovering once the backend healed. (#282)
- Guard active request/connection counters against underflow. (#278)

### Changed
- Bump `tiktoken-rs` 0.11 → 0.12. (#269)
- Bump the rust-minor group (4 updates). (#284)
- CI: bump `actions/checkout` 6 → 7. (#283)

---

## [26.06_2] - 2026-06-16

**Crate version:** 0.6.17

### Added
- **Enforce agent request/response body limits and bound per-key limiter state.** Agent body inspection now enforces the configured `max-request-body-bytes` / `max-response-body-bytes`, and per-key rate-limiter state is bounded so it can no longer grow without limit — closing latent unbounded-growth paths and bringing runtime behavior in line with the Manifesto's "bounded by design" principle. (#273)
- **Route-level `retry-policy` parsing.** The `retry-policy` block inside a `route` is now parsed instead of being silently dropped by the KDL parser. `max-attempts` is honored (it bounds upstream peer-selection attempts); `timeout-ms`, `backoff-base-ms`, `backoff-max-ms`, and `retryable-status-codes` are parsed but not yet applied at runtime (each logs "parsed, but not implemented"). Resolves the docs↔parser mismatch in #262; the remaining retry behavior is tracked in #279. (#267)

### Fixed
- **Bound hidden unbounded state and run pool maintenance.** Fixes several latent bugs surfaced during the hardening audit: the agent-pool maintenance loop was never spawned, per-request correlation affinity could leak, and `max_series` was not enforced. Runtime behavior now matches the documented bounds. (#274)

### Security
- **Bump Pingora 0.8.0 → 0.8.1** ([cloudflare/pingora release](https://github.com/cloudflare/pingora/releases/tag/0.8.1)). Brings in two security-relevant changes: bounded default HTTP/2 server limits to mitigate memory exhaustion, and the upstream dev-dep bumps that resolve `RUSTSEC-2026-0098` / `RUSTSEC-2026-0099` (`rustls-webpki`). Fork rev bumped to `b8d0c00` via [zentinelproxy/pingora#4](https://github.com/zentinelproxy/pingora/pull/4). (#270)

### Changed
- **Bump rust-minor group (9 updates).** (#276)
- **Bump `alpine` Docker base 3.23 → 3.24.** (#275)

---

## [26.06_1] - 2026-06-07

**Crate version:** 0.6.16

### Added
- **Standalone Prometheus metrics server.** When `observability.metrics.enabled` is set, the proxy binds a dedicated HTTP listener on `observability.metrics.address` (default `0.0.0.0:9090`) and serves the Prometheus exposition format at `observability.metrics.path` (default `/metrics`), logging a `Metrics server listening` line at startup. Previously `address` was parsed but never consumed, so nothing bound the port — a silent failure that violated the "fail loudly" principle. (#256)
- **Per-listener route sets.** A listener may now serve a distinct set of routes via a `namespace "<id>"` field. Requests arriving on that listener are matched **only** against the named namespace's routes — no fallback to the global set — so you can expose, e.g., an internal admin/metrics surface on a separate port. Listeners without a `namespace` field serve the global `routes` exactly as before. Modeled on Envoy's listener→route-configuration binding; the referenced namespace must exist or validation fails. (#258)

### Fixed
- **Default Docker image starts cleanly as a non-root user.** The distroless `proxy` and `proxy-prebuilt` images now ship `/var/log/zentinel` and `/var/lib/zentinel` owned by uid/gid 65532, and the bundled container config logs to stdout/stderr rather than a file. Previously the default config failed to initialize file logging under `/var/log/zentinel` (not writable by the non-root user), and a `tmpfs` mount did not resolve it. (#255)
- **Upstream `target` syntax is now identical across single-file and multi-file configs.** The two KDL parsers previously accepted *disjoint* target syntaxes — the single-file parser only took the `target "host:port"` shorthand while the multi-file parser only took the `targets { target { address … } }` block form — so a config copied between layouts (or from the docs) could fail with "requires at least one target". A single shared parser now accepts the shorthand, block form, property form, the `targets { … }` wrapper, and the top-level `address` shorthand in both. This was the root cause behind #254. (#254)

### Changed
- **Bump `tikv-jemallocator` 0.6.1 → 0.7.0.** (#265)
- **Bump rust-minor group (10 updates).** (#264)
- **Bump `busybox` Docker base 1.37 → 1.38.** (#263)
- **Bump `openssl` 0.10.79 → 0.10.80.** (#252)
- **Bump rust-minor group (5 updates).** (#251)
- **Bump `wasmtime` group.** (#250)
- **Bump `quick-xml` 0.39.4 → 0.40.1.** (#249)

### Chores
- Delete defunct `docs.yml` mdbook workflow. (#253)

---

## [26.05_5] - 2026-05-25

**Crate version:** — no crate was published for this release.

Tagged and released on GitHub (binaries and signatures were produced), but the
crates.io publish produced nothing: the tag sat at workspace version `0.6.14`,
the same version 26.05_4 was tagged at, so the Release workflow's `tag + 1`
computation resolved to `0.6.15` — already published by 26.05_4.

The five dependency/CI changes it carried (#249, #250, #251, #252, #253) are
documented under [26.06_1](#26061---2026-06-07), the next release that actually
published a crate.

---

## [26.05_4] - 2026-05-12

**Crate version:** 0.6.15

### Changed
- **Bump `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` 0.31 → 0.32** as a coordinated stack. Bumping individually leaves the workspace with two versions of `opentelemetry` in the dependency graph, breaking trait resolution at the proxy boundary. (#244, supersedes #238 #239 #241)
- **Bump `opentelemetry-semantic-conventions` 0.31 → 0.32.** (#240)
- **Bump `sysinfo` 0.38.4 → 0.39.1.** Requires `rustc >= 1.95`, paired with the toolchain bump below. (#246, supersedes #242)
- **Bump Rust toolchain 1.94.1 → 1.95.0** in `rust-toolchain.toml` and the workspace `rust-version`. Fixes three new `collapsible_match` lints surfaced by Clippy 1.95 in `crates/config/src/filters.rs` and `crates/proxy/src/proxy/filters.rs`. (#246)
- **Bump `openssl` 0.10.78 → 0.10.79.** (#236)
- **Bump rust-minor group.** Two batches of patch/minor bumps from the `rust-minor` Dependabot group. (#237, #245)

---

## [26.05_3] - 2026-05-05

**Crate version:** — this release was never tagged; its changes first shipped in 26.05_4 (`0.6.15`).

### Fixed
- **Embedded `DEFAULT_CONFIG_KDL` no longer emits a deprecation warning on first run.** The fallback configuration baked into the binary still declared a `server { ... }` block, which the parser accepts but warns against. Switched to `system { ... }` so fresh Docker containers and binaries with no external config file start cleanly. Resolves #231. (#232)
- **ACME DNS propagation checker** adapted to the `hickory-resolver` 0.26 API, restoring DNS-01 challenge verification after the upstream major bump. (#229)

### Changed
- **Bump `hickory-resolver` 0.25.2 → 0.26.1.** (#228)
- **Bundled KDL configurations use `system` block.** Sweeps the deprecated `server { ... }` keyword in `deploy/zentinel.starter.kdl` (the installer drop-in at `/etc/zentinel/zentinel.kdl`), the eight `config/examples/*.kdl` files, and `config/example-multi-file/README.md` so users copying or following these examples no longer hit the deprecation warning. Pure keyword rename — fields inside the block are unchanged and the parser still accepts both. Resolves #233. (#234)

### Docs
- **README request-flow diagram** added between the Status and Quick Start sections to illustrate how a request traverses the proxy. (#230)

---

## [26.05_2] - 2026-05-03

**Crate version:** 0.6.13

### Added
- **Systemd service bootstrap in the install script.** `curl -fsSL https://get.zentinelproxy.io | sh` now installs `/etc/systemd/system/zentinel.service`, a sysusers snippet at `/usr/lib/sysusers.d/zentinel.conf`, and a starter config at `/etc/zentinel/zentinel.kdl` on Linux hosts running systemd. Service enable and start are opt-in via `--enable-service` (or `ZENTINEL_ENABLE_SERVICE=1`). Resolves discussion #218. (#224)
- **`deploy/zentinel.starter.kdl`** — annotated starter configuration dropped at `/etc/zentinel/zentinel.kdl`. An existing file is preserved on re-install. (#224)
- **`deploy/sysusers.d/zentinel.conf`** — declarative system user, applied via `systemd-sysusers` with a `useradd` fallback. (#224)
- **`crates/proxy/docs/deployment.md`** — systemd deployment reference (file layout, lifecycle, capabilities, sandboxing). (#224)

### Changed
- **`deploy/zentinel.service`** now passes `--config /etc/zentinel/zentinel.kdl` explicitly and grants `AmbientCapabilities=CAP_NET_BIND_SERVICE` so listeners can bind ports below 1024 without root. (#224)
- **Canonical config path renamed `config.kdl` → `zentinel.kdl`.** Aligns the unit file, Dockerfile, `docker-compose.yml`, and `deploy/deploy.sh` with the path already documented in the README. Helm chart still uses `config.kdl` internally; tracked as a follow-up. (#224)

---

## [26.05_1] - 2026-05-01

**Crate version:** 0.6.12

### Added
- **Per-SNI ACME certificates for multi-tenant TLS.** SNI blocks can now carry their own `acme` configuration, enabling independent certificate lifecycles per tenant on the same listener. Each ACME block gets its own `RenewalScheduler` and `AcmeClient` ("Option B" architecture), so a stuck issuance on one domain (e.g. waiting on DNS propagation) does not block renewals for others. Includes global domain-uniqueness validation across all ACME blocks (case-insensitive, preventing physical storage path collisions) and implicit hostname derivation from `acme.domains` when explicit `hostnames` are omitted. (#213)
- **Cold-start observability for ACME-managed SNI.** When an ACME-managed SNI certificate is missing at startup (the cold-start case), Zentinel logs a structured warning carrying `listener_id`, `sni_index`, and `primary_domain`, and increments a new `tls_metrics::record_sni_cert_skip` counter so operators can detect tenants stuck in shadowed state. The certificate is loaded later via hot-reload once issued. (#213)

### Changed
- **Bump `maxminddb` 0.27.3 → 0.28.1.** (#209)
- **Bump `jsonschema` 0.46.2 → 0.46.3.** Fixes memory not reclaimed when a `Validator` for a schema with recursive `$ref` is dropped. (#219)
- **Bump `reqwest` 0.13.2 → 0.13.3.** Fixes rustls CRL PEM parsing, hickory-dns fallback when `/etc/resolv.conf` is unreadable, HTTP/3 `STOP_SENDING` handling, IPv6 connection establishment. (#219)
- **Bump `rustls` 0.23.39 → 0.23.40.** (#219)

---

## [26.04_7] - 2026-04-28

**Crate version:** 0.6.11

### Security
- **Bump `rand` 0.9.2 → 0.9.4 in `zentinel-sim`** — closes Dependabot alert for [GHSA-cq8v-f236-94qc](https://github.com/advisories/GHSA-cq8v-f236-94qc) (rand unsoundness with custom logger using `rand::rng()`). Also re-syncs `zentinel-sim`'s stale path-dep version pins to the workspace so its lockfile is regenerable. (#214)

---

## [26.04_6] - 2026-04-25

**Crate version:** 0.6.10

### Security
- **Bump `openssl` 0.10.77 → 0.10.78** — fixes 4 high-severity vulnerabilities: buffer overflows in `Deriver::derive`, `MdCtxRef::digest_final`, AES key wrap bounds, and unchecked PSK/cookie callback lengths leaking memory to peers. (#205)
- **Bump `rand` 0.8.5 → 0.8.6** — fixes unsoundness with custom logger using `rand::rng()`. (#205)

### Changed
- **CI: bump `actions/upload-pages-artifact` from 4 to 5.** (#201)

### Docs
- **ACME configuration schema** — document `server-url`, `eab`, `key-type`, and `cloudflare` options in config schema reference. (#202)

---

## [26.04_5] - 2026-04-20

**Crate version:** 0.6.9

### Added
- **Configurable ACME certificate key type** via `key-type` config option. Supports `ecdsa-p256` (default) and `ecdsa-p384` for higher security strength. Invalid values produce a clear config parse error. (#199)

---

## [26.04_4] - 2026-04-19

**Crate version:** 0.6.8

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

**Crate version:** 0.6.7

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

**Crate version:** 0.6.6

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
