# Contributing to Sentinel

Thank you for considering contributing to Sentinel.

Sentinel is infrastructure that sits at the edge of the web. Changes here affect availability, security, and sleep schedules. Because of that, the bar for changes is intentionally high.

This document explains how to contribute in a way that aligns with Sentinel’s goals.

---

## Guiding principles

Before writing code, please read [`MANIFESTO.md`](MANIFESTO.md).

In short:
- Sentinel values predictability over flexibility,
- explicit behavior over implicit magic,
- and calm operation over feature breadth.

---

## AI-assisted development

We believe that software in the future will be increasingly maintained with AI assistance. Sentinel embraces this transformation.

This is not a contradiction to our goal of building boring, stable infrastructure. It is an enabler. AI assistance allows us to:

- **Maintain quality** — Consistent application of coding standards and architectural rules
- **Adapt quickly** — Respond to security issues, dependency updates, and ecosystem changes
- **Stay relevant** — Participate in the fundamental transformation society is undergoing in the post-AI age
- **Lower barriers** — Make contributing accessible to those who work differently

To support AI-assisted contribution, we maintain structured context in [`.claude/CLAUDE.md`](.claude/CLAUDE.md). This includes:
- Project architecture and crate purposes
- Coding standards and patterns
- The Manifesto principles that guide all decisions

Whether you contribute with AI assistance or without, the standards remain the same. Code must be correct, bounded, observable, and aligned with the Manifesto.

The tools change. The principles do not.

---

## What belongs in Sentinel

Changes that are generally welcome:
- Improvements to correctness, safety, and clarity
- Better limits, timeouts, and validation
- Observability (metrics, logs, traces)
- Configuration ergonomics and error messages
- Tests, fuzzing, and regression coverage
- Documentation and examples

Changes that require strong justification:
- New extension points
- New configuration knobs
- New protocol surface area
- Anything that increases memory or latency risk

---

## What does *not* belong in the core

Sentinel intentionally keeps the dataplane small.

The following generally do **not** belong in the core proxy:
- complex policy engines,
- scripting runtimes,
- parsing-heavy or unsafe dependencies,
- business-specific logic.

These belong in **external agents**, behind explicit and bounded contracts.

---

## Expectations for contributions

Any non-trivial change should include:
- clear limits and timeouts,
- observability (metrics and/or logs),
- tests that demonstrate correctness,
- and documentation updates if behavior is visible.

If a change cannot fail safely, it should not be merged.

---

## How to propose changes

If you are unsure whether something fits:
- open an issue,
- describe the problem you are trying to solve,
- explain why it belongs in the core.

Discussion is preferred over premature implementation.

Sentinel will still be here tomorrow.

---

## Code of conduct

Be respectful, precise, and patient.

This project values careful thinking over fast opinions.
