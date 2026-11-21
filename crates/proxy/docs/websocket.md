# WebSocket Inspection

How Zentinel passes WebSocket connections through, and what it does with the
frames of a route that inspects them.

## Overview

A route with `websocket #true` accepts WebSocket upgrades and tunnels the
connection to the upstream. The proxy does not read the frames.

A route that also sets `websocket-inspection #true` has the proxy decode the
frames of each connection, in both directions, and send them to the agents on
the route's filter chain that subscribe to `websocket_frame` events. An agent
can allow a frame, drop it, or close the connection.

```kdl
agents {
    agent "ws-filter" type="custom" {
        unix-socket "/var/run/ws-filter.sock"
        events "websocket_frame"
        timeout-ms 100
    }
}

filters {
    filter "ws-filter" {
        type "agent"
        agent "ws-filter"
        failure-mode "closed"
    }
}

routes {
    route "chat" {
        matches { path-prefix "/chat" }
        upstream "chat-backend"
        websocket #true
        websocket-inspection #true
        websocket-max-frame-size "4MB"   // default 1MB
        filters "ws-filter"
    }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `websocket` | `false` | Accept WebSocket upgrades on the route |
| `websocket-inspection` | `false` | Decode the route's frames and send them to its agents |
| `websocket-max-frame-size` | `1MB` | Largest frame payload that is decoded. A byte count or a size such as `"4MB"`, from 1 byte to 16MB |

A route without `websocket-inspection` is not affected by anything on this
page: its upgrade request is passed on as it came, and its frames are not
read. `zentinel lint` warns about a route that sets `websocket-max-frame-size`
without `websocket-inspection`, since the limit is not used there.

## Extensions

The proxy decodes frames itself and implements no WebSocket extension. An
extension that was negotiated would change what a frame looks like. For
example, `permessage-deflate` sets the RSV1 bit on a compressed frame and
compresses its payload, and the proxy could neither decode the frame as
specified nor show an agent the data inside.

So on a route with `websocket-inspection #true`, the proxy removes the
`Sec-WebSocket-Extensions` header from the upgrade request before it goes to
the upstream, whatever extensions it offered and however many header lines it
came in. The upstream has nothing to accept, and the connection runs without
extensions. Compression is not used on the route.

Removing every extension, and not only `permessage-deflate`, keeps this rule
independent of how the header is written, and of extensions that use RSV bits
other than RSV1.

This applies to every route with `websocket-inspection #true`, whether or not
an agent subscribes to frame events.

## Frames that cannot be decoded

A frame cannot be decoded when:

| Cause | Close status | Reason text |
|-------|--------------|-------------|
| The payload is larger than `websocket-max-frame-size` | 1009 (message too big) | `frame too large` |
| An RSV bit is set | 1002 (protocol error) | `unsupported RSV bits` |

The limit is checked when the frame header has been read, before the payload
arrives. No agent is shown such a frame.

The bytes of a frame that cannot be decoded are **not forwarded**, in either
direction, and neither is anything that follows: with the frame unread, the
position of the next one in the stream is not known. Frames that arrived in
the same read before it, and that the agents allowed, are forwarded first. The
proxy then closes the connection:

- **A frame from the client.** The client is sent a close frame with the
  status above, and the connection to the upstream is closed. The upstream
  receives none of the frame. If frames before it were forwarded, the
  connection to the upstream is closed when the client answers the close
  frame, or sends more data.
- **A frame from the upstream.** The client is sent a close frame with the
  status above after any frames that came before it, and nothing more from
  the upstream is forwarded. The connection ends when the client answers the
  close frame, or when the upstream sends more data, whichever comes first. If
  neither happens, the connection stays open until a timeout of the route
  ends it.

A client that is still writing a frame larger than the limit when the proxy
closes the connection may see the connection reset before it has read the
close frame.

Each time this happens the proxy logs a warning,
`WebSocket frame could not be decoded, closing the connection`, with the
`correlation_id`, the `direction` (`c2s` or `s2c`), the close `code` and the
decode `error`, and counts it in `zentinel_blocked_requests_total` with the
reason `websocket_frame_undecodable`.

### Relation to `failure-mode`

The `failure-mode` of an agent filter says what a failed call to the agent
means: `open` lets the frame through, `closed` closes the connection.

A frame that cannot be decoded is never sent to an agent, so there is no call
to fail, and `failure-mode` does not apply. The connection closes under either
setting. Raise `websocket-max-frame-size` if the route carries larger frames
legitimately.

### Frames too large for an agent

`websocket-max-frame-size` bounds what the proxy decodes. What an agent can be
sent is bounded by its transport: one message over a Unix socket is at most
16MiB, and gRPC's default is 4MiB. A frame is sent to the agent base64-encoded,
which makes it about 1.33 times as large, so a frame of about 12MiB over a Unix
socket, or about 3MiB over gRPC, is already too large.

A frame that is within `websocket-max-frame-size` and too large for the agent's
transport is a failed call to the agent, and follows the agent filter's
`failure-mode`: `open` forwards the frame without the agent having seen it,
`closed` closes the connection. After such a failed call the agent can be
unavailable for a short time (a few hundred milliseconds in testing), so a
request to it that arrives then fails as well. Keep `websocket-max-frame-size`
below what the agents' transport carries if every frame must be seen.

### Memory

A frame is held whole until it can be decoded, so a connection can hold one
frame of up to `websocket-max-frame-size` bytes in each direction. A frame at
the limit is also alive as a decoded copy of its payload, as base64, and as
the message to the agent. As a rough budget, plan for

    connections x 2 directions x websocket-max-frame-size x 5

bytes in the worst case, and choose the limit with the number of concurrent
connections on the route in mind.

## Decisions of agents

| Agent decision | Effect |
|----------------|--------|
| Allow | The frame is forwarded |
| Drop | The frame is not forwarded; the connection stays open |
| Close | The connection is closed |
| Failed call, `failure-mode "open"` | The frame is forwarded |
| Failed call, `failure-mode "closed"` | The connection is closed |

See [Agents](agents.md) for how a filter's `failure-mode` and timeout are
chosen.

## Frames from the upstream and the runtime

Frames from the upstream are inspected from a filter that cannot be async, so
it waits for the agent on a thread of the proxy's tokio runtime. That is only
possible on a multi-thread runtime. Where the runtime is not multi-threaded,
the frames from the upstream are forwarded without inspection, and the warning
`WebSocket frame inspection skipped (server->client)` is logged each time.
