# Gateway API Conformance Testing

Zentinel's Gateway API controller aims to pass the official [Gateway API conformance test suite](https://gateway-api.sigs.k8s.io/guides/implementers/#conformance).

## Quick Start

### Prerequisites

- A Kubernetes cluster (kind, k3s, or cloud)
- Gateway API CRDs installed
- zentinel-gateway controller deployed

### Install Gateway API CRDs

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
```

### Deploy the Controller

```bash
helm install zentinel-gateway deploy/helm/zentinel-gateway/ \
  --namespace zentinel-system \
  --create-namespace
```

### Run Built-in Integration Tests

These Rust-based tests verify core functionality against a live cluster:

```bash
cargo test -p zentinel-gateway --test conformance -- --ignored --nocapture
```

### Run Official Go Conformance Suite

The official conformance suite is a Go test binary. To run it against Zentinel:

```bash
# Clone the gateway-api repo
git clone https://github.com/kubernetes-sigs/gateway-api.git
cd gateway-api

# Run conformance tests
go test ./conformance -run TestConformance \
  -gateway-class=zentinel \
  -controller-name=zentinelproxy.io/gateway-controller \
  -supported-features=HTTPRoute,ReferenceGrant \
  -v
```

## Supported Conformance Profiles

| Profile | Status |
|---------|--------|
| **Gateway** (Core) | In progress |
| **HTTPRoute** (Core) | In progress |
| **Mesh** | Not planned |

## Supported Features

### Core (Required)

| Feature | Status |
|---------|--------|
| GatewayClass acceptance | Implemented |
| Gateway listener management | Implemented |
| HTTPRoute path matching (Exact, PathPrefix) | Implemented |
| HTTPRoute header matching | Implemented |
| HTTPRoute method matching | Implemented |
| HTTPRoute query param matching | Implemented |
| Backend weight-based traffic splitting | Implemented |
| RequestHeaderModifier filter | Implemented |
| ResponseHeaderModifier filter | Implemented |
| Cross-namespace references with ReferenceGrant | Implemented |
| Status condition updates | Implemented |

### Extended

| Feature | Status |
|---------|--------|
| RegularExpression path matching | Implemented |
| RequestRedirect filter | Planned |
| URLRewrite filter | Planned |
| RequestMirror filter | Planned |
| GRPCRoute | Planned |
| TLSRoute | Planned |

## Reporting Conformance

Once all core tests pass, conformance can be reported upstream:

```bash
# Generate conformance report
go test ./conformance -run TestConformance \
  -gateway-class=zentinel \
  -controller-name=zentinelproxy.io/gateway-controller \
  -conformance-report=zentinel-conformance-report.yaml
```

Submit the report to the [Gateway API implementations list](https://gateway-api.sigs.k8s.io/implementations/).
