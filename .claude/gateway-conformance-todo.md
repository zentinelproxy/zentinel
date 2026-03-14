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

- [ ] Create `scripts/conformance-test.sh` that automates the full flow
- [ ] Create a kind cluster with port mappings for the proxy's listeners
- [ ] Install Gateway API CRDs (`kubectl apply -f standard-install.yaml`)
- [ ] Build the `zentinel-gateway` Docker image locally
- [ ] Load the image into kind (`kind load docker-image`)
- [ ] Deploy via Helm chart
- [ ] Wait for controller + proxy to be ready
- [ ] Run the Go conformance suite: `go test ./conformance -run TestConformance -gateway-class=zentinel -controller-name=zentinelproxy.io/gateway-controller -supported-features=HTTPRoute,ReferenceGrant -v`
- [ ] Capture output and report

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

- [ ] Add a GitHub Actions workflow (`conformance.yml`) that runs on PRs touching `crates/gateway/`
- [ ] Use kind-action to create a cluster in CI
- [ ] Run conformance tests as a CI check
- [ ] Fail the build if conformance regresses
