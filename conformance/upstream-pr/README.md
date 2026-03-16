# Zentinel

## Table of Contents

| API channel | Implementation version | Mode | Report |
|-------------|------------------------|---------|--------|
| standard | [v0.6.1](https://github.com/zentinelproxy/zentinel/releases/tag/v0.6.1) | default | [link](./standard-v0.6.1-default-report.yaml) |

## Reproduce

1. Clone the Zentinel repository

   ```bash
   git clone https://github.com/zentinelproxy/zentinel.git && cd zentinel
   ```

2. Check out the desired version

   ```bash
   git checkout v0.6.1
   ```

3. Run the conformance test script (requires kind, kubectl, helm, go, docker)

   ```bash
   ./scripts/conformance-test.sh --report
   ```

4. Check the produced report

   ```bash
   cat conformance/reports/standard-v0.6.1-default-report.yaml
   ```
