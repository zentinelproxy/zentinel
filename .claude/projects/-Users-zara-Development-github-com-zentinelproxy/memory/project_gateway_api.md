---
name: Gateway API Controller
description: New zentinel-gateway crate implementing Kubernetes Gateway API controller to position Zentinel as NGINX Ingress replacement
type: project
---

Zentinel is building a Kubernetes Gateway API controller (`crates/gateway/`) to capture the NGINX Ingress retirement migration wave (retired March 2026).

**Why:** NGINX Ingress Controller maintenance halted March 2026. Kubernetes community recommends Gateway API as the migration path. Zentinel's security-first design (agent isolation vs NGINX's dangerous snippets) is a compelling alternative.

**How to apply:** When working on the gateway crate, reference the todo at `.claude/gateway-api-todo.md` for remaining work. The crate uses `gateway-api` 0.19 (kube 2.x, k8s-openapi 0.26). Phases 1-3 are complete (controller runtime, config translation). Phase 4 (proxy integration) is next.

Key dependencies: `kube = "2.0"`, `k8s-openapi = "0.26"`, `gateway-api = "0.19"`.
Controller name: `zentinelproxy.io/gateway-controller`.
