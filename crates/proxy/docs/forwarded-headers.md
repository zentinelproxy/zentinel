# Forwarded Headers

How Zentinel treats the headers that say where a request came from: the client
address, the scheme and port it used, and the URL and host it was first sent
to. The code is in `crates/proxy/src/proxy/forwarded.rs`.

## What Zentinel writes

For every request, once, before routing, rate limiting and agents see it,
Zentinel sets three headers on the request:

| Header | Value |
|--------|-------|
| `X-Forwarded-For` | The address of the TCP peer (appended to the incoming chain for a trusted peer) |
| `X-Forwarded-Proto` | `https` if the connection to Zentinel is TLS, otherwise `http` |
| `X-Forwarded-Host` | The request's own host, with its port when the `Host` header has one |

Agents receive the request headers after this step, and the upstream request is
a copy of the same request, so both see the same values. The route's
`policies { request-headers { ... } }` and header filters run afterwards, when
the upstream request is built, and can still `set` or `remove` any of them.

## Trusted and untrusted peers

A peer is trusted when its address is inside the listener's `trusted-proxies`
(a load balancer or CDN in front of Zentinel). Every other peer is untrusted,
which is the default when `trusted-proxies` is not set.

```kdl
listener "public" {
    address "0.0.0.0:8080"
    protocol "http"
    trusted-proxies "10.0.0.0/8"
}
```

**Untrusted peer.** None of the forwarding headers the client sent is passed
on:

- `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` are rebuilt
  from the connection, as in the table above.
- Every header in the list below is removed, on every line it appears.

Header names are compared whole, ignoring letter case, and `-` and `_` count as
the same character, because some servers read `X_Real_IP` as `X-Real-IP`. A
copy of `X-Forwarded-For`, `X-Forwarded-Proto` or `X-Forwarded-Host` spelled
that way is removed too, so it cannot sit next to the one Zentinel writes.

**Trusted peer.** The incoming chain is believed, and what the peer sent is
checked before it is passed on:

| Header | From a trusted peer |
|--------|---------------------|
| `X-Forwarded-For` | The peer is appended, and the chain that is passed on starts at the client IP Zentinel chose (see below). Everything to the left of the client, whether an address or not (`unknown`, a host name), is left out, because no trusted hop vouched for it. The client and the trusted hops to its right stay as written, in their order. An upstream that reads the chain from the right with the same trusted networks reaches the same client. |
| `X-Forwarded-Proto` | Kept as sent when every element is `http` or `https` (any letter case). Otherwise replaced by the scheme of the listener, as in the table above. |
| `X-Forwarded-Host` | Kept as sent when every element reads as a host with an optional port: a name of letters, digits, `-`, `.` and `_`, an IPv4 address, or an IPv6 address in brackets. Otherwise (an element that is empty or contains a space, a control character, `/` or `@`) replaced by the request's own host, or removed when the request has none. |
| `X-Real-IP` | Rewritten to the client IP Zentinel chose. Not added when the peer did not send one. |
| `Forwarded` and the other headers in the list below | Passed on as sent. Zentinel does not read or write them, so it does not check them either; an upstream that reads `Forwarded` gets what the trusted peer put there, including, in its `for=` elements, the addresses that were left out of `X-Forwarded-For`. |

For `X-Forwarded-Proto` and `X-Forwarded-Host`, all lines of the header are
read as one comma-separated list, the way a proxy that adds its own value to
the one it received writes it (`https, http`). The value stays as sent when
every element is accepted; one element that is not accepted replaces all of
it, so no element that was not checked reaches the upstream.

A copy of `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` or
`X-Real-IP` spelled with `_` instead of `-` (`X_Real_IP`) is removed, because
some servers read it as the hyphenated name; otherwise a value that was not
checked would reach the upstream next to the one that was. The other headers
in the list below are passed on in any spelling.

If Zentinel sits behind a load balancer or CDN, list that peer in
`trusted-proxies`; otherwise the upstream sees the load balancer's address and
none of the forwarding headers it set. The headers are removed before the route
is chosen, so a route's `matches { header ... }` condition and a rate limit
keyed on a header (`key "header:..."`) also read the request without them: if
the peer in front of Zentinel is not listed, those headers count as absent, and
a header-keyed rate limit uses the shared key `unknown`.

The chain that is passed on starts at the first address, counting from the
right end of the chain, that is not listed (or at the last listed hop before an
element that is not an address). To keep a proxy that sits between
the client and the listed peer, and the addresses before it, in
`X-Forwarded-For`, list that proxy as well. A listed proxy is trusted in every
respect, so this also has effects beyond the chain:

- The client IP Zentinel chooses (the `client-ip` rate-limit key, geo filters,
  access logs, `ip-hash` and the agents' `client_ip`) becomes the address to
  the left of that proxy.
- A listed proxy that connects to Zentinel directly is exempt from
  `max-connections-per-client`, which counts the TCP peer only (see
  `crates/proxy/src/connection_limit.rs`).
- The forwarding headers of a request that reaches Zentinel directly from that
  proxy are believed as well.

## Headers removed from untrusted peers

| Group | Headers |
|-------|---------|
| Client address | `Forwarded`, `X-Real-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`, `Fastly-Client-IP`, `Client-IP`, `X-Originating-IP`, `X-Envoy-External-Address`, `X-Azure-ClientIP`, `X-Appengine-User-IP` |
| Scheme and port | `X-Forwarded-Port`, `X-Forwarded-Ssl`, `X-Forwarded-Scheme`, `X-Forwarded-Protocol`, `X-Scheme`, `X-Url-Scheme`, `Front-End-Https`, `CF-Visitor` |
| Original URL, host and prefix | `X-Forwarded-Prefix`, `X-Forwarded-Server`, `X-Forwarded-Uri`, `X-Forwarded-Path`, `X-Original-URL`, `X-Original-URI`, `X-Original-Host`, `X-Rewrite-URL` |

Zentinel writes none of these. They are removed rather than rebuilt so that
Zentinel does not invent headers a backend never asked for; a backend that
reads one falls back to `X-Forwarded-For`, `X-Forwarded-Proto` and
`X-Forwarded-Host`, or to the connection.

`X-Forwarded-Port` and `X-Forwarded-Ssl` are not rebuilt in particular because
the port Zentinel listens on is often not the port the client used (a published
container port, a NAT). `X-Forwarded-Host` carries the client's own port when
the `Host` header has one, and `X-Forwarded-Proto` carries the scheme.

## Other headers

Only the headers above are removed. For any other header that a backend reads
as client information, add a request-header policy on the route:

```kdl
route "api" {
    matches {
        path-prefix "/api"
    }
    upstream "backend"
    policies {
        request-headers {
            remove "X-Client-Region"
        }
    }
}
```

A `set` in the same block can also write one of the headers in the list with a
fixed value, since policies run after the removal. Policies change the upstream
request only; agents are shown the request before policies run.

## Client IP inside Zentinel

The client IP used for the `client-ip` rate-limit key, geo filters, the
`client_ip` that agents receive, access logs and `ip-hash` follows the same
trust rule: the peer's address when it is untrusted, otherwise the right-most
address in `X-Forwarded-For` that is not itself in `trusted-proxies`. None of
the headers in the list above is read for it.
