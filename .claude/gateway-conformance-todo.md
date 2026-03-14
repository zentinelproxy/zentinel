# Gateway API Conformance — Road to Official Listing

> Goal: Pass the official Gateway API conformance test suite and get Zentinel
> listed on the [Gateway API implementations page](https://gateway-api.sigs.k8s.io/implementations/).

## Current blocker

The conformance tests send real HTTP requests through the proxy and verify
responses. Right now the gateway controller translates K8s resources into
`Config` objects but **no proxy data plane actually serves traffic from that
config**. The controller is a control plane without a connected data plane.

## Phase 1: Wire the data plane (prerequisite)

**Architecture decision**: two-container pattern, not embedded. Pingora cannot
add/remove listeners at runtime (`run_forever()` is blocking, all listeners
must be configured before startup). Embedding the full `ZentinelProxy` in the
gateway binary would also create massive coupling.

Instead: the controller writes translated config as a KDL file to a shared
volume. A Zentinel proxy sidecar reads the file with `auto-reload: true` and
picks up changes via file watching.

- [x] Add `ConfigWriter` that serializes `Config` to KDL format
- [x] Write bootstrap config on startup (listeners on 8080/8443, auto-reload enabled)
- [x] After each `ConfigTranslator::rebuild()`, write updated KDL to shared volume
- [x] Atomic write pattern (write to .tmp, rename) to prevent partial reads
- [x] `CONFIG_OUTPUT_PATH` env var to enable file output
- [x] Update Helm chart: two-container pod (controller + proxy sidecar)
- [x] Add shared `config-dir` volume between controller and proxy
- [x] Add LoadBalancer Service for proxy traffic (ports 80/443)
- [ ] Verify: create a Gateway + HTTPRoute, send an HTTP request, get a response

## Phase 2: kind-based test harness

- [x] Create `scripts/conformance-test.sh` that automates the full flow
- [x] Create a kind cluster with port mappings for the proxy's listeners
- [x] Install Gateway API CRDs (standard + experimental)
- [x] Build the `zentinel-gateway` Docker image locally
- [x] Load the image into kind (`kind load docker-image`)
- [x] Deploy via Helm chart with local images
- [x] Wait for controller + proxy to be ready
- [x] Go conformance test wrapper (`conformance/conformance_test.go`)
- [x] `go.mod` with gateway-api v1.2.1 dependency
- [x] `--report` flag for generating conformance report YAML
- [x] `--keep-cluster` flag for debugging failures

## Phase 3: Fix conformance failures

There will be edge cases. Common areas where implementations fail:

- [ ] Status condition timing (tests expect conditions within a timeout)
- [ ] Exact path matching semantics (trailing slash behavior)
- [ ] Header matching case sensitivity
- [ ] ReferenceGrant cross-namespace edge cases
- [ ] Gateway listener isolation (routes should only attach to matching listeners)
- [ ] Weight-based traffic splitting accuracy
- [ ] Redirect filter: correct Location header construction (scheme, host, port, path)
- [ ] URLRewrite filter: path prefix replacement edge cases

## Phase 4: Generate and submit conformance report

- [ ] Run with `-conformance-report=zentinel-conformance-report.yaml`
- [ ] Verify report contains required metadata (contact, version, gatewayAPIVersion, channel)
- [ ] Name report: `standard-v0.6.1-default-report.yaml`
- [ ] Submit PR to `kubernetes-sigs/gateway-api` repo under `conformance/reports/v1.2.1/zentinelproxy-zentinel/`
- [ ] Include README.md with implementation details
- [ ] Get listed on https://gateway-api.sigs.k8s.io/implementations/

## Phase 5: CI integration

- [x] GitHub Actions workflow (`.github/workflows/conformance.yml`)
- [x] Triggers on PRs touching `crates/gateway/`, `conformance/`, `deploy/helm/zentinel-gateway/`
- [x] Uses `helm/kind-action` for cluster creation
- [x] Builds images, loads into kind, deploys via Helm
- [x] Runs Go conformance suite with 20m timeout
- [x] Collects controller + proxy logs on failure
