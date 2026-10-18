# Zentinel Workflow

Commands, processes, and common tasks for working with Zentinel.

---

## Development Environment

### Prerequisites

- Rust 1.96.0+ (see `rust-toolchain.toml`)
- mise (task runner)
- Docker (for integration tests)

### Setup

```bash
# Install mise tasks
mise install

# Build all crates
cargo build --workspace

# Verify setup
cargo test --workspace
```

---

## Common Commands

### Building

```bash
# Debug build (fast compilation)
cargo build --workspace

# Release build (optimized)
cargo build --workspace --release

# Build specific crate
cargo build -p zentinel-proxy
cargo build -p zentinel-config
cargo build -p zentinel-agent-protocol
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p zentinel-proxy
cargo test -p zentinel-config
cargo test -p zentinel-agent-protocol

# Run specific test
cargo test -p zentinel-proxy route_matching

# Run tests with output
cargo test --workspace -- --nocapture

# Run ignored (slow) tests
cargo test --workspace -- --ignored
```

### Linting

```bash
# Format code
cargo fmt --all

# Check formatting (CI)
cargo fmt --all --check

# Run clippy (must pass with no warnings)
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Run clippy with fixes
cargo clippy --workspace --all-targets --fix --allow-dirty
```

### Documentation

```bash
# Generate docs
cargo doc --workspace --no-deps

# Open docs in browser
cargo doc --workspace --no-deps --open

# Check doc links
cargo doc --workspace --no-deps 2>&1 | grep -i warning
```

---

## Running Zentinel

### Local Development

```bash
# Run with default config
cargo run --bin zentinel -- --config config/zentinel.kdl

# Run with debug logging
RUST_LOG=debug cargo run --bin zentinel -- --config config/zentinel.kdl

# Run with specific log levels
RUST_LOG=zentinel=debug,pingora=info cargo run --bin zentinel

# Run release build
cargo run --release --bin zentinel -- --config config/zentinel.kdl
```

### Docker

```bash
# Build image
docker build -t zentinel:dev .

# Run container
docker run -p 8080:8080 -v $(pwd)/config:/etc/zentinel zentinel:dev

# Docker Compose (with upstreams)
docker-compose up
```

---

## Testing Workflows

### Unit Tests

Run frequently during development:

```bash
cargo test -p zentinel-config --lib
cargo test -p zentinel-agent-protocol --lib
```

### Integration Tests

Run before committing:

```bash
# Start test dependencies
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
cargo test --test '*'

# Cleanup
docker-compose -f docker-compose.test.yml down
```

### Benchmarks

Run for performance-sensitive changes:

```bash
# Run all benchmarks
cargo bench -p zentinel-proxy

# Run specific benchmark
cargo bench -p zentinel-proxy routing

# Compare against baseline
cargo bench -p zentinel-proxy -- --save-baseline main
cargo bench -p zentinel-proxy -- --baseline main
```

---

## Git Workflow

### Branch Naming

```
feature/add-grpc-health-checks
fix/route-matching-priority
docs/update-agent-protocol
refactor/simplify-config-parsing
```

### Commit Messages

Follow conventional commits:

```
feat(proxy): add request timeout configuration

Add per-route timeout configuration with validation.
Defaults to 30s if not specified.

Closes #123
```

```
fix(agent): handle connection reset during streaming

The agent client now properly handles ECONNRESET errors
during body streaming, triggering circuit breaker as expected.

Fixes #456
```

```
docs(config): document rate limiting options

Add comprehensive documentation for token bucket and
sliding window rate limiting configuration.
```

### Before Pushing

Always run `mise run pre-push` before pushing to avoid wasting GHA minutes on lint failures:

```bash
mise run pre-push
```

This runs `fmt-check` + `lint` (clippy) + `docs-check` — the fast CI jobs that catch formatting and linting issues without the slow test/audit steps.

---

## Release Process

Zentinel uses [CalVer](https://calver.org/) (`YY.MM_PATCH`) as the operator-facing version
and [SemVer](https://semver.org/) for crate versions on crates.io. The Release workflow
(`.github/workflows/release.yml`) is triggered by **CalVer tags** matching
`[0-9][0-9].[0-9][0-9]_[0-9]*` (e.g. `26.04_7`). It builds platform binaries, signs them,
publishes the four published crates to crates.io, and creates the GitHub Release.

### Cutting a release

> **The workflow publishes `tag_version + 1`, not the tagged version.** It reads the
> current `Cargo.toml` version, increments the patch, and publishes *that*. Between
> releases `main` already sits at the **last published** crate version, so **do not bump
> `Cargo.toml` when preparing a release** — bumping it makes the workflow publish `+2`
> and silently skips a version on crates.io (this is why `0.6.19` was skipped on 26.07_1).

Two different crate versions are in play at every release, and confusing them is the
single most common mistake here. Naming them, because `X.Y.Z` alone is ambiguous:

| Term | Value | Where it appears |
|---|---|---|
| **`CURRENT`** | the version in `Cargo.toml` at the commit you tag | nowhere user-facing; it is only an input |
| **`PUBLISHED`** | `CURRENT` + 1 — what the workflow actually publishes | crates.io, the CHANGELOG entry, the GitHub Release notes, the docs-site changelog |

Everything a reader ever sees says **`PUBLISHED`**. `CURRENT` is plumbing.

1. **Prepare PR (CHANGELOG only):** open a branch (e.g.
   `chore/prepare-release-YY.MM_PATCH`) against `main` that edits **only `CHANGELOG.md`**:
   - Add the overview-table row and the dated `## [YY.MM_PATCH] - DATE` section.
   - The section's `**Crate version:**` is **`PUBLISHED`** — the `Cargo.toml` version
     **plus one**, i.e. what this release will put on crates.io. Leave `Cargo.toml` and
     `Cargo.lock` untouched.

     `CHANGELOG.md`'s own "Release Overview" preamble is the authority on this and says
     so outright: *"**Crate Version** is the version actually **published to crates.io**
     [...] It is not the version present in `Cargo.toml` at the tagged commit."* Check it
     against the previous entry if in doubt — e.g. 26.08_5 was tagged with `Cargo.toml`
     at `0.6.27`, and its CHANGELOG entry, its GitHub Release and crates.io all read
     `0.6.28`.
   - Commit message: `chore: prepare release YY.MM_PATCH`.
2. **Merge** to `main` once CI is green. The base-branch policy blocks the merge while
   **any** check is still pending — even non-required ones (Unit Tests) — so `gh pr merge`
   fails until every check finishes.
3. **Tag** the merge commit with the **CalVer** form (annotated). SemVer-form tags do not
   trigger the workflow.
   ```bash
   git fetch origin main
   # The semver in the message is CURRENT -- the version in Cargo.toml right now,
   # one below what this tag will publish. It is a note to yourself about the input,
   # not the release's version; see the caveat under step 4.
   git tag -a YY.MM_PATCH origin/main -m "Release YY.MM_PATCH (semver CURRENT)"
   git push origin YY.MM_PATCH
   ```
4. **Verify** the run: `gh run list --workflow Release --limit 1`. It builds 4 platform
   targets, signs with cosign, publishes the four published crates as **`PUBLISHED`**, and
   creates the GitHub Release. The Release notes, the CHANGELOG entry and crates.io all
   agree on `PUBLISHED` — there is no by-design discrepancy between them. All builds run
   **before** any publish, so a build failure publishes nothing.

   > The **annotated tag message** is the one place carrying `CURRENT`, and the two
   > conventions have actually been mixed. `26.08_4` and `26.08_5` *both* read
   > `(semver 0.6.27)` and mean opposite things by it:
   >
   > | Tag | `Cargo.toml` at tag | Message says | Published | Message meant |
   > |---|---|---|---|---|
   > | `26.08_4` | `0.6.26` | `0.6.27` | `0.6.27` | `PUBLISHED` |
   > | `26.08_5` | `0.6.27` | `0.6.27` | `0.6.28` | `CURRENT` |
   >
   > (`26.08_3` carries no semver at all.) So treat a tag message as an informal note and
   > **never as evidence of what a release shipped** — read crates.io, the Release notes,
   > or the CHANGELOG for that. All three agree; the tag message may not.
5. **Post-release bump (manual, every release):** the workflow force-pushes a
   `chore/bump-<published>` branch but its `gh pr create` reliably fails, leaving an
   **orphan branch that only edits `Cargo.toml`**. Open the PR yourself, add a
   `cargo update --workspace` commit so `Cargo.lock` reflects the new version, and merge.
   This moves `main` up to the just-published version.

> **Don't skip step 3.** If you merge the prepare PR without tagging, no release is cut
> (this happened to `26.04_6`, PR #207, tagged retroactively).
>
> **Flaky linux-arm64 build?** The `zigbuild` toolchain-setup step occasionally fails with
> a rustup `clippy-preview` / `cargo-clippy` conflict (runner-state, not our code). Nothing
> publishes on a build failure — just `gh run rerun <run-id> --failed`, which re-runs the
> failed build plus the gated publish/release jobs while the 3 good builds carry over.

### Crates.io publishing

**Only four crates are published.** The workflow's `CRATES=(...)` array is the single
source of truth, and it lists exactly these, in dependency order:

```bash
cargo publish -p zentinel-common
cargo publish -p zentinel-config
cargo publish -p zentinel-agent-protocol
cargo publish -p zentinel-proxy
```

The Release workflow runs this automatically once the tag is pushed. Manual publishing is
only needed when re-publishing or recovering from a partial failure.

> **Do not add crates to this list to "fix" a release.** `zentinel-wasm-runtime`,
> `zentinel-gateway` and `zentinel-stack` are workspace members that have **never** been
> published — they return HTTP 404 on crates.io, and that is the expected steady state, not
> a broken publish. None of them set `publish = false`, so the manifests give no hint;
> running `cargo publish` on one would **create a new crate under that name**, which cannot
> be undone (crates.io permits yanking, never deletion or renaming).
>
> When verifying a release, query the crates.io API for the four above only.

Crates excluded from the workspace entirely (`crates/sim`, `crates/playground-wasm`,
`crates/config-inspect`) are likewise not published.

---

## Debugging

### Logging

```bash
# Maximum verbosity
RUST_LOG=trace cargo run --bin zentinel

# Specific modules
RUST_LOG=zentinel::routing=debug,zentinel::agents=trace cargo run --bin zentinel

# Filter by span
RUST_LOG=zentinel[request_id]=debug cargo run --bin zentinel
```

### Profiling

```bash
# CPU profiling with flamegraph
cargo flamegraph --bin zentinel -- --config config/zentinel.kdl

# Memory profiling with heaptrack
heaptrack cargo run --release --bin zentinel

# Perf stat
perf stat cargo run --release --bin zentinel
```

### Debugging Tests

```bash
# Run single test with backtrace
RUST_BACKTRACE=1 cargo test -p zentinel-proxy specific_test -- --nocapture

# Run under debugger
rust-lldb target/debug/deps/zentinel_proxy-xxx specific_test
```

---

## Configuration Testing

### Validate Config

```bash
# Check config syntax and schema (parse + validate, don't start)
cargo run --bin zentinel -- test --config config/zentinel.kdl

# Validate with connectivity checks (network, agents, certificates)
cargo run --bin zentinel -- validate --config config/zentinel.kdl

# Lint for best practices
cargo run --bin zentinel -- lint --config config/zentinel.kdl
```

> There are no `--check`/`--dry-run` flags; use the `test`/`validate`/`lint`
> subcommands (or the `-t/--test` flag, equivalent to `test`).

### Config Examples

Test against example configs:

```bash
for config in config/examples/*.kdl; do
    echo "Testing $config"
    cargo run --bin zentinel -- test --config "$config"
done
```

---

## Mise Tasks

Common tasks are defined in `mise.toml`:

```bash
# List available tasks
mise tasks

# Run specific task
mise run build
mise run test
mise run lint
mise run docs
```

---

## Troubleshooting

### Build Errors

```bash
# Clean and rebuild
cargo clean && cargo build --workspace

# Update dependencies
cargo update

# Check for outdated deps
cargo outdated
```

### Test Failures

```bash
# Run with verbose output
cargo test --workspace -- --nocapture

# Run single test isolated
cargo test -p zentinel-proxy test_name -- --test-threads=1

# Check for port conflicts
lsof -i :8080
```

### Performance Issues

```bash
# Build with optimizations for profiling
cargo build --release --features profiling

# Check for debug assertions in release
cargo build --release 2>&1 | grep debug_assertions
```

---

## CI/CD

### GitHub Actions

Workflows in `.github/workflows/`:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push, PR | Build, test, lint |
| `release.yml` | Tag push | Build binaries, publish |
| `docs.yml` | Push to main | Deploy documentation |

### Local CI Simulation

```bash
# Quick check (fmt + clippy + docs — matches fast CI jobs)
mise run pre-push

# Full CI (fmt + clippy + tests + audit — matches all CI jobs)
mise run ci
```
