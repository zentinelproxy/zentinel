# Migrating from NGINX Ingress to Zentinel

> NGINX Ingress Controller maintenance halted in March 2026.
> This guide maps common NGINX Ingress patterns to Zentinel Gateway API equivalents.

## Why Migrate?

- **No more security patches** — NGINX Ingress is unmaintained
- **Snippets are a security risk** — arbitrary NGINX config injection was a [known vulnerability](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/)
- **Gateway API is the future** — official Kubernetes successor to Ingress
- **Zentinel is faster** — 912K req/s WAF, lowest p99 latency vs NGINX/Envoy/HAProxy
- **Agent isolation** — custom logic runs in crash-isolated processes, not config snippets

## Quick Start

```bash
# 1. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml

# 2. Install Zentinel Gateway controller
helm install zentinel-gateway deploy/helm/zentinel-gateway/ \
  --namespace zentinel-system --create-namespace

# 3. Create a Gateway (replaces your Ingress controller deployment)
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: main
  namespace: default
spec:
  gatewayClassName: zentinel
  listeners:
    - name: http
      port: 80
      protocol: HTTP
    - name: https
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: my-tls-secret
EOF

# 4. Create HTTPRoutes (replaces your Ingress resources)
kubectl apply -f - <<EOF
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-app
  namespace: default
spec:
  parentRefs:
    - name: main
  hostnames:
    - "app.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: api-service
          port: 8080
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: web-service
          port: 80
EOF
```

## Annotation Mapping

### Routing

| NGINX Ingress | Zentinel Gateway API |
|---------------|---------------------|
| `spec.rules[].host` | `HTTPRoute.spec.hostnames[]` |
| `spec.rules[].http.paths[].path` | `HTTPRoute.spec.rules[].matches[].path.value` |
| `spec.rules[].http.paths[].pathType: Prefix` | `matches[].path.type: PathPrefix` |
| `spec.rules[].http.paths[].pathType: Exact` | `matches[].path.type: Exact` |
| `spec.rules[].http.paths[].pathType: ImplementationSpecific` | `matches[].path.type: RegularExpression` |
| `spec.rules[].http.paths[].backend` | `HTTPRoute.spec.rules[].backendRefs[]` |

### TLS

| NGINX Ingress | Zentinel Gateway API |
|---------------|---------------------|
| `spec.tls[].secretName` | `Gateway.spec.listeners[].tls.certificateRefs[].name` |
| `spec.tls[].hosts[]` | `Gateway.spec.listeners[].hostname` |
| `nginx.ingress.kubernetes.io/ssl-redirect: "true"` | Use RequestRedirect filter (or separate HTTP→HTTPS listener) |
| `nginx.ingress.kubernetes.io/force-ssl-redirect` | Same as above |

### Backend Configuration

| NGINX Ingress Annotation | Zentinel Gateway API |
|--------------------------|---------------------|
| `nginx.ingress.kubernetes.io/upstream-hash-by` | Traffic splitting via `backendRefs[].weight` |
| `nginx.ingress.kubernetes.io/load-balance` | Zentinel supports 14 algorithms via KDL config |
| `nginx.ingress.kubernetes.io/proxy-connect-timeout` | Zentinel upstream timeouts (auto-configured) |
| `nginx.ingress.kubernetes.io/proxy-read-timeout` | Zentinel upstream timeouts (auto-configured) |

### Header Manipulation

| NGINX Ingress Annotation | Zentinel Gateway API |
|--------------------------|---------------------|
| `nginx.ingress.kubernetes.io/configuration-snippet` (headers) | `HTTPRoute.spec.rules[].filters[].requestHeaderModifier` |
| `nginx.ingress.kubernetes.io/proxy-set-headers` | `requestHeaderModifier.set` |
| `nginx.ingress.kubernetes.io/custom-http-errors` | Zentinel error pages via KDL config |

### Rate Limiting

| NGINX Ingress Annotation | Zentinel Equivalent |
|--------------------------|---------------------|
| `nginx.ingress.kubernetes.io/limit-rps` | Zentinel rate limiting via KDL config or agent |
| `nginx.ingress.kubernetes.io/limit-connections` | Zentinel connection limits in system config |

### Security — The Key Difference

| NGINX Ingress | Zentinel |
|---------------|----------|
| `nginx.ingress.kubernetes.io/server-snippet` | **Removed by design** — no arbitrary config injection |
| `nginx.ingress.kubernetes.io/configuration-snippet` | Use Gateway API filters or Zentinel agents |
| Custom Lua scripts | Zentinel agents (any language, crash-isolated) |
| ModSecurity WAF | Built-in Rust WAF (30x faster, 912K req/s) |

## Traffic Splitting (Canary Deployments)

NGINX Ingress canary annotations → Gateway API weighted backends:

```yaml
# NGINX Ingress (before)
# Primary Ingress + Canary Ingress with:
#   nginx.ingress.kubernetes.io/canary: "true"
#   nginx.ingress.kubernetes.io/canary-weight: "20"

# Gateway API (after) — single HTTPRoute with weights
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-app
spec:
  parentRefs:
    - name: main
  rules:
    - backendRefs:
        - name: app-stable
          port: 8080
          weight: 80
        - name: app-canary
          port: 8080
          weight: 20
```

## Cross-Namespace Routing

NGINX Ingress `ExternalName` services → Gateway API `ReferenceGrant`:

```yaml
# Allow HTTPRoutes in "web" namespace to reference Services in "backend"
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-web-to-backend
  namespace: backend
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: web
  to:
    - group: ""
      kind: Service
```

## Step-by-Step Migration

1. **Install Gateway API CRDs** and Zentinel controller (see Quick Start)
2. **Create a Gateway** with the same ports/TLS as your NGINX Ingress
3. **Convert each Ingress to HTTPRoute** using the mapping table above
4. **Test** with a subset of traffic (use DNS-based cutover or weighted routes)
5. **Remove NGINX Ingress** resources and controller once verified
6. **Explore Zentinel extras** — WAF agents, inference routing, WebSocket inspection

## Getting Help

- [Zentinel Documentation](https://zentinelproxy.io/docs)
- [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)
- [GitHub Issues](https://github.com/zentinelproxy/zentinel/issues)
