# Gateway API Controller — Implementation Plan

> Goal: Build a Kubernetes Gateway API controller that positions Zentinel as a
> first-class NGINX Ingress replacement. The controller watches Gateway API CRDs
> and translates them into Zentinel's internal config, managing proxy instances
> as the data plane.

## Phase 1: New Crate & Core Types

- [x] Create `crates/gateway/` crate with dependencies (`kube`, `k8s-openapi`, `gateway-api`)
- [x] Add to workspace `Cargo.toml`
- [x] Define Gateway API resource types (Gateway, HTTPRoute, GRPCRoute, TLSRoute, ReferenceGrant)
- [x] Map Gateway API concepts → Zentinel config types (HTTPRoute → RouteConfig, Service backend → UpstreamConfig)

## Phase 2: Kubernetes Controller Runtime

- [x] Implement controller using `kube::runtime::Controller`
- [x] Watch Gateway resources — reconcile into listener configs
- [x] Watch HTTPRoute resources — reconcile into route + upstream configs
- [ ] Watch GRPCRoute resources (stretch)
- [ ] Watch TLSRoute resources (stretch)
- [x] Watch ReferenceGrant for cross-namespace references
- [x] Implement GatewayClass controller to claim ownership (`zentinel` class)
- [x] Status updates — set conditions on Gateway/HTTPRoute (Accepted, Programmed, etc.)

## Phase 3: Config Translation Layer

- [x] Translate HTTPRoute matches (path, header, method, query) → Zentinel route matches
- [x] Translate HTTPRoute filters (RequestHeaderModifier, ResponseHeaderModifier, RequestRedirect, URLRewrite, RequestMirror) → Zentinel filters
- [x] Translate HTTPRoute backend refs → Zentinel upstreams with Kubernetes discovery
- [x] Handle HTTPRoute weights for traffic splitting
- [x] Translate Gateway listeners → Zentinel listener configs (ports, TLS, hostnames)

## Phase 4: Integration with Zentinel Proxy

- [x] Wire translated config into proxy's hot-reload mechanism — added `ConfigManager::apply_config()` + `config_store()` + `ReloadTrigger::GatewayApi`
- [x] Integrate with existing Kubernetes service discovery — backends use K8s DNS (`svc.cluster.local`); Endpoints API integration deferred
- [x] TLS certificate handling — `SecretCertificateManager` watches TLS Secrets, writes certs to disk, populates `TlsConfig` with SNI support
- [x] Health check integration — default HTTP health checks (GET / expect 200) on all K8s upstreams

## Phase 5: Operational Readiness

- [x] Leader election — Kubernetes Lease-based (`coordination.k8s.io/v1`) with configurable duration/renew/retry intervals
- [x] Prometheus metrics — reconciliation count/duration/errors, config rebuild stats, active resource gauges, leader status, TLS errors
- [x] Helm chart — `deploy/helm/zentinel-gateway/` with Deployment, RBAC, ServiceAccount, GatewayClass, metrics Service
- [x] Gateway API conformance test scaffolding — integration tests + Go conformance suite instructions in `docs/conformance.md`
- [x] Migration guide — `docs/migration-from-nginx-ingress.md` mapping NGINX annotations → Gateway API + Zentinel

## Phase 6: Stretch Goals

- [x] GRPCRoute support — reconciler + translator with service/method → path matching, gRPC health checks, HTTP/2 forced
- [ ] TLSRoute / TCPRoute support
- [ ] BackendTLSPolicy support
- [ ] Custom Zentinel policy CRDs (rate limiting, agent attachment, WAF)
- [ ] Ingress resource compatibility shim (for easier migration)
