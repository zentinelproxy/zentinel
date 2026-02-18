# Sentinel → Zentinel Migration Roadmap

> **Domain:** zentinelproxy.io
> **Brand:** Zentinel — Zen + Sentinel, the sleepable ops proxy at the edge
> **GitHub Org:** [github.com/zentinelproxy](https://github.com/zentinelproxy)
> **Old Org:** github.com/raskell-io (repos transferred out, redirects active)
> **Local workspace:** `/Users/zara/Development/github.com/zentinelproxy/`
> **Created:** 2026-02-17
> **Last updated:** 2026-02-18
> **Status:** Sites deployed on Cloudflare Pages — old-crate deprecation and branding remaining

---

## Executive Summary

Migrated 41 repositories and 2 websites from the "Sentinel" brand under `raskell-io` org to
"Zentinel" under the new `zentinelproxy` GitHub org at `zentinelproxy.io`. All code has been
renamed, builds verified, dependencies fixed, and core crate names claimed on crates.io.

### Inventory

| Category | Count | Old (raskell-io) | New (zentinelproxy) |
|----------|-------|------------------|---------------------|
| Core proxy | 1 | `sentinel` | `zentinel` |
| Control planes | 2 | `sentinel-control-plane`, `sentinel-hub` | `zentinel-control-plane`, `zentinel-hub` |
| Infrastructure | 3 | `sentinel-helm`, `sentinel-bench`, `sentinel-modsec` | `zentinel-helm`, `zentinel-bench`, `zentinel-modsec` |
| Tooling | 1 | `sentinel-convert` | `zentinel-convert` |
| Websites | 2 | `sentinel.raskell.io`, `sentinel.raskell.io-docs` | `zentinelproxy.io`, `zentinelproxy.io-docs` |
| Agent SDKs | 7 | `sentinel-agent-{go,rust,ts,py,ex,kt,hs}-sdk` | `zentinel-agent-*-sdk` |
| Specialty agents | 25 | `sentinel-agent-{waf,ratelimit,...}` | `zentinel-agent-*` |
| **Total** | **41** | | |

---

## Completed Work

### Phase 1: GitHub Org & Repo Transfer ✅

- [x] New GitHub org created: `github.com/zentinelproxy`
- [x] All 41 repos **transferred** from `raskell-io` → `zentinelproxy` with new names via GitHub transfer API
- [x] GitHub auto-redirects active (old `raskell-io/sentinel*` URLs → new org)
- [x] Fresh clones in `/Users/zara/Development/github.com/zentinelproxy/`
- [x] All git remotes point to `git@github.com-raffael:zentinelproxy/<name>.git`
- [x] Renamed `zentinel-agent-sentinelsec` → `zentinel-agent-zentinelsec` on GitHub
- [x] Made `zentinel-modsec` repo public

### Phase 2: Code Rename ✅

- [x] Automated rename script (`rename-sentinel.sh`) processed 1,785 files
- [x] All `sentinel` → `zentinel` references replaced (lowercase, uppercase, PascalCase)
- [x] All `sentinel.raskell.io` → `zentinelproxy.io` URLs replaced
- [x] All `raskell-io/sentinel*` → `zentinelproxy/zentinel*` GitHub refs replaced
- [x] Haskell module directories renamed (`src/Sentinel/` → `src/Zentinel/`)
- [x] JSON files and `site.webmanifest` fixed (initially skipped by binary detection)
- [x] Zero `sentinel` references remaining in code (verified via grep)
- [x] Intentionally kept `raskell-io` references: Pingora fork, tanuki theme, test fixtures

### Phase 3: Dependency Fixes ✅

Renamed crates don't exist on crates.io under the old names. All bare crates.io deps
were switched to git deps pointing at the correct repos:

- [x] `zentinel-agent-protocol` — 23 agent repos: `"0.3"` → git dep to `zentinelproxy/zentinel.git` v0.5
- [x] `zentinel-common` — 8 agent repos: `"0.3"` → git dep to `zentinelproxy/zentinel.git` v0.5
- [x] `zentinel-modsec` — zentinel-agent-zentinelsec: `"0.1"` → git dep to `zentinelproxy/zentinel-modsec.git`
- [x] `zentinel-agent-sdk-macros` — zentinel-agent-rust-sdk: added `path = "zentinel-agent-sdk-macros"`
- [x] `zentinel-agent-sdk` — zentinel-agent-graphql-security: version `"0.1"` → `"0.2"`
- [x] `zentinel-agent-bot-management` — removed `branch = "main"` from git dep, added `package`
- [x] Fixed docs site links: `zentinel-agent-sdk` → `zentinel-agent-rust-sdk`

### Phase 4: Build Verification ✅

All Rust repos pass `cargo check`:

| Repo | Status |
|------|--------|
| zentinel (main proxy) | ✅ check + tests |
| zentinel-convert | ✅ |
| zentinel-modsec | ✅ |
| zentinel-agent-rust-sdk | ✅ |
| zentinel-agent-waf | ✅ |
| zentinel-agent-auth | ✅ |
| zentinel-agent-denylist | ✅ |
| zentinel-agent-ratelimit | ✅ |
| zentinel-agent-ai-gateway | ✅ |
| zentinel-agent-js | ✅ |
| zentinel-agent-zentinelsec | ✅ |
| zentinel-agent-modsec | ✅ |
| zentinel-agent-api-deprecation | ✅ |
| zentinel-agent-audit-logger | ✅ |
| zentinel-agent-bot-management | ✅ |
| zentinel-agent-chaos | ✅ |
| zentinel-agent-content-scanner | ✅ |
| zentinel-agent-graphql-security | ✅ |
| zentinel-agent-grpc-inspector | ✅ |
| zentinel-agent-ip-reputation | ✅ |
| zentinel-agent-lua | ✅ |
| zentinel-agent-mock-server | ✅ |
| zentinel-agent-mqtt-gateway | ✅ |
| zentinel-agent-soap | ✅ |
| zentinel-agent-spiffe | ✅ |
| zentinel-agent-transform | ✅ |
| zentinel-agent-wasm | ✅ |
| zentinel-agent-websocket-inspector | ✅ |

Other languages:

| Repo | Status |
|------|--------|
| zentinel-hub (Go) | ✅ |
| zentinel-agent-go-sdk (Go) | ✅ |
| zentinel-control-plane (Elixir) | ✅ |
| zentinel-agent-elixir-sdk (Elixir) | ✅ |
| zentinel-agent-typescript-sdk (TypeScript) | ✅ |
| zentinel-agent-python-sdk (Python) | ✅ syntax check |
| zentinelproxy.io (Zola) | ✅ builds (broken links are DNS-only) |
| zentinelproxy.io-docs (Zola) | ✅ builds (broken links are DNS-only) |
| zentinel-bench | N/A — scripts/configs only |
| zentinel-helm | N/A — chart templates only |

Toolchain not available (ARM macOS):

| Repo | Issue |
|------|-------|
| zentinel-agent-haskell-sdk | cabal not available for aarch64-darwin |
| zentinel-agent-kotlin-sdk | Gradle wrapper missing class |
| zentinel-agent-policy (Haskell) | Same cabal issue |

### Phase 5: Commit & Push ✅

- [x] All 41 repos committed with rename message and pushed
- [x] All dependency fix commits pushed
- [x] All lockfile updates committed and pushed
- [x] Zero uncommitted changes remaining across all repos

### Phase 6: GitHub Metadata ✅

- [x] All 40 repo **descriptions** updated: "Sentinel" → "Zentinel" (zero sentinel refs remaining)
- [x] All 40 repo **topics** updated: `sentinel` → `zentinel`, `sentinel-agent` → `zentinel-agent`
- [x] All 30 repo **homepage URLs** updated: `sentinel.raskell.io` → `zentinelproxy.io`

### Phase 7: GHA Workflow Audit ✅

- [x] All workflow files verified clean — no sentinel/raskell-io references
- [x] Docker image names use `${{ github.repository }}` — resolves dynamically to `zentinelproxy/*`
- [x] Main proxy release workflow publishes to crates.io in correct order
- [x] WAF and Auth agents push Docker images to ghcr.io with correct names

### Phase 8: crates.io Name Claims ✅

Published core crates to claim the names:

| Crate | Version | Status |
|-------|---------|--------|
| `zentinel-common` | 0.5.0 | ✅ Published |
| `zentinel-config` | 0.5.0 | ✅ Published |
| `zentinel-agent-protocol` | 0.5.0 | ✅ Published |
| `zentinel-proxy` | 0.5.0 | ✅ Published |
| `zentinel-modsec` | 0.1.0 | ✅ Published |
| `zentinel-agent-sdk-macros` | 0.1.0 | ✅ Published |
| `zentinel-agent-sdk` | 0.2.0 | ✅ Published |

Individual agent crates will be published automatically by their release workflows when version tags are pushed.

### Phase 9: DNS & Cloudflare Pages Deployment ✅

- [x] Domain `zentinelproxy.io` added to Cloudflare (zone active, nameservers configured)
- [x] Cloudflare Pages projects created via dashboard with GitHub integration:
  - `zentinelproxy-io` → `zentinelproxy/zentinelproxy.io` (auto-deploys on push)
  - `zentinelproxy-io-docs` → `zentinelproxy/zentinelproxy.io-docs` (auto-deploys on push)
- [x] Custom domains configured and active:
  - `zentinelproxy.io` → main site
  - `www.zentinelproxy.io` → main site
  - `docs.zentinelproxy.io` → docs site
- [x] SSL certificates provisioned automatically by Cloudflare
- [x] Removed stale `themes/tanuki` submodule from main site repo (was causing clone failures)
- [x] Sites verified live: all three domains returning HTTP 200
- [x] Set up old-domain redirect: `sentinel.raskell.io` → `zentinelproxy.io` (301) via Cloudflare Redirect Rule

---

## Remaining Work

### Phase 10: Branding Assets

- [ ] Create new logo/mascot for Zentinel (or adapt current sentinel-mascot)
- [ ] Generate favicon set
- [ ] Prepare Open Graph images with new branding
- [ ] Rename image assets in website repo (sentinel-mascot → zentinel-mascot, etc.)

### Phase 11: WASM Binary Recompilation ✅

- [x] Rebuilt `zentinel_convert_wasm` from zentinel-convert repo (`wasm-pack build --target web --release`)
- [x] Rebuilt `zentinel_playground_wasm` from main proxy repo (bumped sim/playground-wasm versions 0.4.3 → 0.5.0)
- [x] Deployed updated WASM binaries to zentinelproxy.io website (`static/wasm/`)

### Phase 12: Package Registry Publishing (non-Rust)

- [ ] npm: Publish `zentinel-agent-sdk` (TypeScript SDK)
- [ ] PyPI: Publish `zentinel-agent-sdk` (Python SDK)
- [ ] Hex.pm: Publish `zentinel_agent_sdk` (Elixir SDK)
- [ ] Helm: Publish `zentinel` chart

### Phase 13: Old Package Deprecation ✅

- [x] crates.io: Published deprecation releases for all 7 old `sentinel-*` crates with pointers to `zentinel-*` replacements:
  - `sentinel-common` v0.4.15, `sentinel-config` v0.4.15, `sentinel-agent-protocol` v0.4.15, `sentinel-proxy` v0.4.15
  - `sentinel-modsec` v0.1.1, `sentinel-agent-sdk-macros` v0.1.1, `sentinel-agent-sdk` v0.1.1
- [x] npm: No old `sentinel-agent-sdk` package exists — nothing to deprecate
- [x] PyPI: No old `sentinel-agent-sdk` package exists — nothing to deprecate
- [x] Hex.pm: No old `sentinel_agent_sdk` package exists — nothing to deprecate
- [ ] Docker: Check `ghcr.io/raskell-io/sentinel` images (requires `read:packages` scope)

### Phase 14: GitHub Org Housekeeping ✅

- [x] Updated zentinelproxy org description and blog URL
- [x] Pinned key repos: zentinel, zentinel-control-plane, zentinel-agent-rust-sdk, zentinelproxy.io, zentinelproxy.io-docs, zentinel-helm
- [x] No old sentinel repos remain on raskell-io — all 32 remaining repos are other projects
- [x] Set up `get.zentinelproxy.io` install script redirect (302 → raw GitHub)
- [x] Updated `getsentinel.raskell.io` to chain through `get.zentinelproxy.io`
- [x] Updated all `getzentinelproxy.io` references to `get.zentinelproxy.io` across 3 repos (16 files)

### Phase 15: End-to-End Verification & Install Script Fixes ✅

- [x] Comprehensive end-to-end testing of all user-facing paths
- [x] Fixed install script: added fallback for pre-rename `sentinel-*` asset names in releases
- [x] Fixed install script: added fallback for `sentinel` binary name inside tarballs
- [x] Verified all paths work:
  - `zentinelproxy.io` ✅, `www.zentinelproxy.io` ✅, `docs.zentinelproxy.io` ✅
  - `sentinel.raskell.io` → 301 → `zentinelproxy.io` ✅ (with path preservation)
  - `get.zentinelproxy.io` → install script ✅
  - `getsentinel.raskell.io` → chains through new URL ✅
  - GitHub redirects (raskell-io → zentinelproxy) ✅
  - crates.io: new zentinel crates published, old sentinel crates deprecated ✅

### Phase 16: Announcement & Launch ✅

- [x] Published blog post: [zentinelproxy.io/blog/sentinel-is-now-zentinel/](https://zentinelproxy.io/blog/sentinel-is-now-zentinel/)
- [x] GitHub Discussion: [zentinelproxy/zentinel#86](https://github.com/zentinelproxy/zentinel/discussions/86)
- [ ] Update social media profiles/links (manual task)

### Phase 17: Long-Term Maintenance

- [ ] Keep `sentinel.raskell.io` redirect active: minimum 12 months
- [ ] GitHub redirects: permanent (handled automatically by GitHub)
- [ ] Monitor old URLs for traffic
- [ ] Switch agent Cargo.toml git deps back to crates.io version deps after first tagged releases

---

## Risk Register

| Risk | Impact | Mitigation | Status |
|------|--------|------------|--------|
| Broken cross-repo path dependencies | Build failures | Switched to git deps, verified all builds | ✅ Resolved |
| Stale sentinel refs in user configs | User confusion | Document migration guide for users | Pending |
| SEO loss from domain change | Traffic loss | 301 redirects, keep old domain 12+ months | Pending |
| crates.io name conflicts | Can't publish | Checked and claimed all zentinel-* names | ✅ Resolved |
| npm/PyPI name conflicts | Can't publish | Check availability before publishing | Pending |
| WASM recompilation needed | Website features broken | Rebuild after full rename | Pending |
| GitHub org permissions | Can't push | SSH key works, all pushes successful | ✅ Resolved |
| Old raskell-io references in code | Broken links | Grep sweep found and fixed all refs | ✅ Resolved |
| crates.io rate limiting | Delayed publishing | Published with delays between crates | ✅ Resolved |
| Haskell/Kotlin toolchains unavailable | Can't verify builds | ARM macOS limitation, CI will verify | Known |
