<div align="center">

<h1 align="center">
  <img src=".github/static/sentinel-mascot.png" alt="sentinel mascot" width="96" />
  <br>
  Sentinel
</h1>

<p align="center">
  <em>A security-first reverse proxy built to guard the free web.</em><br>
  <em>Sleepable ops at the edge.</em>
</p>

<p align="center">
  <a href="https://www.rust-lang.org/">
    <img alt="Rust" src="https://img.shields.io/badge/Rust-stable-000000?logo=rust&logoColor=white&style=for-the-badge">
  </a>
  <a href="https://github.com/cloudflare/pingora">
    <img alt="Pingora" src="https://img.shields.io/badge/Built%20on-Pingora-f5a97f?style=for-the-badge">
  </a>
  <a href="LICENSE">
    <img alt="License" src="https://img.shields.io/badge/License-Apache--2.0-c6a0f6?style=for-the-badge">
  </a>
</p>

<p align="center">
  <a href="MANIFESTO.md">Manifesto</a> •
  <a href="docs/why-sentinel.md">Why Sentinel</a> •
  <a href="https://sentinel.raskell.io/docs">Documentation</a> •
  <a href="https://github.com/raskell-io/sentinel/discussions">Discussions</a> •
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<hr />

</div>

It is designed for explicit limits, predictable behavior, and production environments where operators are expected to sleep.

Sentinel is built on top of Cloudflare Pingora. It does not reinvent the proxy dataplane. Instead, it focuses on the product layer that matters in real operations: configuration, policy boundaries, extensibility, observability, and safe defaults.

The core philosophy is simple:

- the dataplane should be boring and predictable,
- security decisions should be explicit and observable,
- and complexity should be isolated rather than embedded.

Sentinel exists so critical web infrastructure remains **inspectable, forkable, and shared**.

---

## Why Sentinel exists

Modern reverse proxies are powerful, but often accumulate:
- hidden behavior,
- unbounded complexity,
- and operational risk that only appears under stress.

Sentinel takes a different approach.

It prioritizes:
- bounded memory and queues,
- deterministic timeouts everywhere,
- clear failure modes (fail-open / fail-closed),
- and extensibility via external agents rather than embedded logic.

The goal is not to compete on feature count.
The goal is to build infrastructure that is **correct, calm, and trustworthy**.

---

## Design principles

- **Sleepable operations**  
  No unbounded resources. No surprise behavior.

- **Security-first, not security-magic**  
  Every limit and decision is explicit in configuration.

- **Small, stable core**  
  Innovation lives outside the dataplane, behind contracts.

- **Production correctness over cleverness**  
  Features ship only when they can be bounded, observed, tested, and rolled back.

For a deeper explanation of these principles, see [`MANIFESTO.md`](MANIFESTO.md).

---

## Community

- 💬 [Discussions](https://github.com/raskell-io/sentinel/discussions) — Questions, ideas, show & tell
- 🐛 [Issues](https://github.com/raskell-io/sentinel/issues) — Bug reports and feature requests
- 📖 [Documentation](https://sentinel.raskell.io/docs) — Guides, reference, and examples

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) to get started.
