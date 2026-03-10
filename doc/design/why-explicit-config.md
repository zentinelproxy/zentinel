# Why Explicit Configuration

## The Decision

Zentinel requires all operational parameters—limits, timeouts, failure modes, TLS settings—to be explicitly stated in configuration. There are no hidden defaults that silently shape behavior. Every default value is documented, logged on startup, and observable in metrics.

The proxy's failure mode defaults to `closed`: if something is ambiguous or misconfigured, Zentinel rejects rather than guesses.

## Alternatives Considered

**Convention over configuration.** Many frameworks minimize configuration by assuming sensible defaults. Ruby on Rails popularized this: if you follow the convention, things "just work." For a web framework, this reduces boilerplate. For a reverse proxy handling production traffic, invisible conventions become invisible failure modes. An operator debugging a 3 AM outage should not have to know that the default timeout was 30 seconds because the documentation said so three versions ago.

**Auto-detection / smart defaults.** Automatically detect the number of CPU cores, available memory, and network interfaces, then configure accordingly. This sounds helpful but creates non-reproducible behavior: the same configuration file produces different behavior on different machines. When you move from a 4-core dev box to a 64-core production server, the proxy silently changes its concurrency model.

**Fail-open by default.** Many proxies default to permissive behavior: if a WAF agent is unreachable, pass the request through. This prioritizes availability over security. It means that the moment your security infrastructure fails, you have no security—precisely when you need it most.

## Why Explicit

**Debuggability.** When every parameter is stated in configuration, an operator can look at the config file and know exactly what the proxy will do. No need to check documentation for default values, no need to wonder whether a parameter was auto-detected or explicitly set. The configuration file is the source of truth.

**Reproducibility.** The same configuration file produces the same behavior on any machine. If `worker-threads=4` is in the config, there are 4 worker threads—on a laptop and on a 128-core server. The only exception is `worker-threads=0`, which explicitly means "auto-detect," and this choice is logged on startup.

**Fail-closed security.** Zentinel defaults to rejecting ambiguous or broken states:

| Scenario | Default Behavior |
|----------|-----------------|
| Agent unreachable | Block request (fail closed) |
| TLS cert missing | Refuse to start |
| Unknown config key | Validation error |
| Cross-reference to nonexistent upstream | Validation error |

An operator can override any of these to fail-open, but they must do so explicitly. The configuration records that decision for auditing.

**Startup validation.** Zentinel validates configuration at startup with four phases:

1. **Parse-time**: Syntax correctness (valid KDL)
2. **Schema**: Required fields present, types correct
3. **Semantic**: Cross-references valid (routes reference existing upstreams, filters reference existing agents)
4. **Runtime**: External resources exist (TLS cert files, agent socket paths)

A misconfigured proxy fails loudly at startup, not silently at 3 AM when a particular code path is first exercised.

**Audit trail.** Explicit configuration means you can diff two config versions and see exactly what changed. No implicit state to track, no auto-detected values that shifted between deployments. Code review of config changes is meaningful because the config contains the full picture.

## Trade-offs

**More configuration to write.** Operators must specify values that other proxies would assume. This is intentional friction: it forces the operator to make conscious decisions about timeouts, limits, and failure modes. But it does increase the initial setup effort.

**Steeper onboarding.** A new user cannot start with an empty config file and have everything work. They must understand what the proxy needs: at minimum, a listener, a route, and an upstream. We mitigate this with example configurations and clear validation error messages that tell you what's missing.

**Verbose for simple cases.** A proxy that serves a single backend on port 80 requires more configuration in Zentinel than in proxies that assume defaults. This is an acceptable cost: simple cases should still be explicit, because simple deployments eventually become complex deployments, and the configuration should grow predictably rather than revealing hidden assumptions.

## When to Revisit

- If the configuration burden becomes a significant barrier to adoption, we could offer a `zentinel init` command that generates an explicit config with documented defaults—but never hide those defaults from the running config
- If a particular default proves universally correct (never needs changing across deployments), it could be promoted to a documented, logged implicit default—but this bar should be very high

## Manifesto Alignment

> *"Security must be explicit. [...] There is no 'magic'. There is no implied policy. If Zentinel is protecting something, you should be able to point to where and why."* — Manifesto, principle 2

> *"Infrastructure should be calm. [...] It should have clear limits, predictable timeouts, and failure modes you can explain to another human."* — Manifesto, principle 1

Explicit configuration is how Zentinel delivers on both promises: every limit is visible, every failure mode is a conscious choice, and the configuration file tells the full story.
