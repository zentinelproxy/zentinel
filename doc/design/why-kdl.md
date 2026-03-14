# Why KDL

## The Decision

Zentinel uses [KDL](https://kdl.dev/) (KDL Document Language) as its configuration format. All proxy configuration—listeners, routes, upstreams, agents, filters, TLS, limits—is expressed in KDL files.

## Alternatives Considered

**YAML.** The most common configuration format for infrastructure tools. But YAML has well-documented pitfalls: implicit type coercion (`yes` becomes `true`, `3.10` becomes `3.1`), significant whitespace that breaks on copy-paste, the Norway problem (`NO` becomes `false`), and multiple ways to express the same thing (block vs flow style). These ambiguities cause real production incidents.

**TOML.** Explicit and well-typed. Good for flat or shallow configuration. But TOML becomes unwieldy for deeply nested structures—Zentinel's config has routes containing filters containing parameters, agents with circuit breaker settings, and upstreams with health check configurations. Deeply nested TOML requires verbose `[section.subsection.sub-subsection]` headers that obscure the structure.

**JSON.** Unambiguous parsing, universal support. But JSON has no comments, no trailing commas, and no multiline strings. A configuration format that does not support comments is hostile to operators who need to document why a setting exists or temporarily disable a block.

**HCL (HashiCorp Configuration Language).** Purpose-built for infrastructure. Good block syntax. But HCL is tightly associated with the HashiCorp ecosystem, has complex interpolation semantics, and its specification has changed between versions (HCL1 vs HCL2) in breaking ways.

**Custom DSL.** Maximum expressiveness for our domain. But a custom language means custom tooling (syntax highlighting, linting, formatting), a learning curve for every new user, and maintenance burden for the parser. The configuration language should be a solved problem, not a project unto itself.

## Why KDL Fits

**Node-based structure.** KDL's fundamental unit is a node with optional arguments, properties, and children. This maps naturally to proxy configuration:

```kdl
route "api" {
  match path="/api/*" methods=["GET" "POST"]
  upstream "api-backend"
  filter "rate-limit" requests-per-second=100
}
```

The hierarchy is visually clear. Nesting is explicit via braces, not indentation.

**No type coercion surprises.** Strings are strings, numbers are numbers, booleans are `true` or `false`. `"yes"` is always the string `"yes"`, never silently converted to a boolean. `3.10` stays `3.10`.

**Comments are first-class.** Line comments (`//`) and block comments (`/* */`) are part of the language. Operators can document why a rate limit is set to a specific value, or comment out an agent block for debugging.

**Diff-friendly.** Each node is typically one line. Adding a route, changing a limit, or adding a filter produces clean, reviewable diffs. No ambiguity about whether a change affected surrounding blocks.

**Consistent syntax.** There is one way to express a configuration block. No choice between block style and flow style, no alternative quoting mechanisms, no optional colons. This consistency means configuration looks the same regardless of who wrote it.

## Trade-offs

**Smaller ecosystem.** KDL is newer than YAML, TOML, or JSON. Fewer editors have syntax highlighting out of the box. Fewer developers have seen it before. There is a learning curve, though the syntax is simple enough that most people read it correctly on first encounter.

**Fewer libraries.** KDL parsing libraries exist for major languages (Rust, JavaScript, Go, Python), but the ecosystem is smaller than YAML or JSON. If we need KDL support in an unusual language for an agent SDK, we may need to contribute to or write a parser.

**Unfamiliarity.** Operators evaluating Zentinel may see KDL as a barrier. "Why not just use YAML like everything else?" is a reasonable question. The answer is that YAML's ambiguities cause real incidents, and the cost of learning KDL is lower than the cost of debugging YAML type coercion in production.

## When to Revisit

- If KDL development stalls and the specification does not reach stability
- If a future configuration format emerges that solves the same problems with broader adoption
- If the KDL Rust parser becomes unmaintained (currently well-maintained via the `kdl` crate)

## Manifesto Alignment

> *"Security must be explicit. [...] Every limit, timeout, and decision in Zentinel is meant to be: visible in configuration, observable in metrics and logs, and explainable after the fact."* — Manifesto, principle 2

> *"There is no 'magic'. There is no implied policy."* — Manifesto, principle 2

KDL supports this principle by being an unambiguous format. What you read in the configuration file is what the proxy does. No implicit type conversions, no hidden inheritance, no surprising defaults.
