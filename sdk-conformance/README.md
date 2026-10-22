# Agent SDK conformance harness

One test that every agent SDK runs to prove that agents built with it work with
Zentinel. It starts a real `zentinel` binary in front of a fixture echo
upstream, puts the SDK's agent on the filter chain, and checks over plain HTTP
what reaches the upstream and the client. Nothing is mocked, so a check passes
only if the agent and the proxy really agree on agent protocol v2.

It came out of zentinel#600: the Go, Python and TypeScript SDKs all had green
unit tests while none of them could complete a handshake with the proxy.

## What it checks

| Check | Passes when |
|---|---|
| `handshake` | A request on the agent's route reaches the upstream (the filter is fail-closed, so a failed handshake is a 503). |
| `configure` | The upstream receives `X-Conformance-Config: nested-config-ok`, a value from a nested block of the agent's `config { }`, delivered by the Configure message the proxy sends after the handshake (zentinel#603). The proxy uses a connection only once the agent has acknowledged that message. |
| `request_header` | The upstream receives `X-Hello: from-agent`. |
| `response_header` | The client receives `X-Conformance-Response: from-agent`, set in the response-headers event. |
| `block` | `GET /block/...` gets `403` with body `blocked-by-agent`, and the upstream never sees it. |
| `body` | A POSTed body containing `block-this-body` gets `403` with body `body-seen:<the whole body>`; a body without it reaches the upstream unchanged. |
| `reconnect` | After the agent is killed (requests then fail closed) and started again, requests are served again, configured, within 45 s. |

Each check runs once per transport: the Unix socket (`--agent-cmd`) and,
when given, gRPC (`--grpc-agent-cmd`).

The `hello` profile runs only `handshake`, `request_header` and `reconnect`.
It is for the quick-start agent in each SDK's README, which adds `X-Hello` and
allows everything.

## The conformance agent

The `full` profile expects an agent that does exactly this:

- **Configure:** keep the config it is given. `config.nested.value` is the
  string the harness looks for. Accept the configuration (reply allow / pong).
- **Request headers:**
  - If the path starts with `/block`, block with status `403` and body
    `blocked-by-agent`.
  - Otherwise allow, and set the request headers `X-Hello: from-agent` and
    `X-Conformance-Config: <config.nested.value>` (`unconfigured` if no
    configuration has arrived).
- **Request body:** collect the chunks of a request. On the last chunk, if the
  body contains `block-this-body`, block with `403` and body
  `body-seen:<the whole body>`; otherwise allow.
- **Response headers:** allow, and set the response header
  `X-Conformance-Response: from-agent`.

The agent subscribes to the `request_headers`, `request_body` and
`response_headers` events. The harness writes the proxy config (see
`kdl_config` in `run.py`):

```kdl
agent "sdk-under-test" type="custom" {
    unix-socket "..."            // or: grpc "http://127.0.0.1:PORT"
    events "request_headers" "request_body" "response_headers"
    timeout-ms 2000
    failure-mode "closed"
    config {
        greeting "hello-from-the-proxy"
        nested {
            value "nested-config-ok"
            depth 2
        }
    }
}
```

`reference-agent/` is this agent written against the protocol crate itself.
It passes on both transports and is the thing to compare with when an SDK
fails:

```bash
cargo build --manifest-path sdk-conformance/reference-agent/Cargo.toml
python3 sdk-conformance/run.py --zentinel-bin target/debug/zentinel \
  --agent-cmd 'sdk-conformance/reference-agent/target/debug/zentinel-conformance-reference-agent --socket {socket}' \
  --grpc-agent-cmd 'sdk-conformance/reference-agent/target/debug/zentinel-conformance-reference-agent --grpc {grpc}'
```

## Running it

Python 3.9 or newer, standard library only:

```bash
python3 run.py \
  --zentinel-version 26.10_8 \
  --agent-cmd 'go run ./examples/conformance --socket {socket}' \
  --grpc-agent-cmd 'go run ./examples/conformance --grpc {grpc}'
```

- `{socket}` and `{grpc}` in the commands become the Unix socket path and the
  `host:port` the agent must listen on. They are also exported as
  `ZENTINEL_AGENT_SOCKET` and `ZENTINEL_AGENT_GRPC_ADDRESS`.
- The commands run through the shell, in their own process group; the harness
  kills the group to restart the agent, so wrappers like `go run` or `npx` are
  fine.
- The zentinel binary is one of `--zentinel-bin PATH` (or `ZENTINEL_BIN`),
  `--zentinel-version TAG` (a release, downloaded and checked against its
  `.sha256`), or `--zentinel-url URL` (a release-style tarball).
- `--profile hello` for the README agent.
- `--json-out FILE` writes the results; the exit code is non-zero if any check
  failed. On failure the last lines of the agent and proxy logs are printed and
  the work directory (configs, sockets, logs) is kept.

**Zentinel version.** The `configure` check needs zentinel#603, which delivers
the agent's `config { }` block over the Configure message. No release includes
it yet: 26.10_7 (0.6.50) fails `configure`. Until one does, build zentinel from
`main` (`cargo build -p zentinel-proxy`) and pass `--zentinel-bin`, or use the
action's `zentinel-ref` input below.

## In an SDK's CI

The directory is a composite GitHub Action:

```yaml
  conformance:
    name: Conformance (agent protocol v2)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... install the SDK's toolchain and build the agents ...
      - uses: zentinelproxy/zentinel/sdk-conformance@sdk/conformance-harness
        with:
          # Switch to `zentinel-version: <first release with #603>` once it
          # ships; building from source is the fallback until then.
          zentinel-ref: main
          agent-command: ./bin/conformance-agent --socket {socket}
          grpc-agent-command: ./bin/conformance-agent --grpc {grpc}
      - uses: zentinelproxy/zentinel/sdk-conformance@sdk/conformance-harness
        with:
          zentinel-ref: main
          profile: hello
          agent-command: ./bin/hello-agent --socket {socket}
```

Inputs: `agent-command`, `grpc-agent-command`, `profile`, `zentinel-version`,
`zentinel-url`, `zentinel-ref`, `working-directory`. Building from
`zentinel-ref` checks the repository out into `.zentinel-src` and caches the
build with `Swatinem/rust-cache`; a cold build takes several minutes.

Build the agent before the harness starts it, rather than through `go run` or
similar: the harness waits up to 120 s (`--agent-start-timeout`) for the agent
to listen, and it starts the agent twice.

## Known proxy limitations it works around

- Response headers set in the request-headers phase do not reach the client
  (zentinel#596), so the response header is set in the response-headers event.
- Request bodies reach agents only with `waf { body-inspection {
  inspect-request-body #true } }`, and only buffered (zentinel#602); the
  harness config sets that.
- An agent that accepts a connection but never answers the handshake hangs
  proxy startup (zentinel#599); the harness reports that as a `handshake`
  failure after 30 s.
