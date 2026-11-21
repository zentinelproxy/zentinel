//! `X-Forwarded-For`, `-Proto` and `-Host`, and the client IP Zentinel uses.
//!
//! The proxy used to send none of these (#515), so every backend saw Zentinel
//! as the client. They are written here, once per request in
//! `early_request_filter`, onto the downstream request itself. Everything
//! after that reads the same values: agents (which receive the request
//! headers), the upstream request (a copy of the downstream one), and the
//! `request-headers` route policies and header filters, which run later in
//! `upstream_request_filter` and can therefore still override or remove them.
//!
//! # Trust
//!
//! A client can send any `X-Forwarded-*` it likes. Passing that on would let it
//! choose the IP address that backends log and rate-limit by, and that agents
//! doing IP reputation see. So by default none of the forwarding headers a
//! client sends survives:
//!
//! * `X-Forwarded-For` is **replaced** by the TCP peer's address;
//! * `X-Forwarded-Proto` is replaced by what the listener observed (`https`
//!   when the connection is TLS, else `http`);
//! * `X-Forwarded-Host` is replaced by the request's own host.
//!
//! Header names are compared whole, ignoring case and treating `-` and `_` as
//! the same character, because some servers read `X_Real_IP` as `X-Real-IP`.
//! A copy of one of the three headers above spelled that way is removed too.
//!
//! * Every header in [`REMOVED_FROM_UNTRUSTED_PEERS`] is **removed**:
//!   `Forwarded` (RFC 7239), `X-Real-IP`, the other client-address headers
//!   (`True-Client-IP`, `CF-Connecting-IP`, ...), the other scheme and port
//!   headers (`X-Forwarded-Port`, `X-Forwarded-Ssl`, ...) and the original-URL
//!   and host headers (`X-Original-URL`, `X-Forwarded-Prefix`, ...). Zentinel
//!   produces none of them, so a value from the client would be the only one
//!   a backend sees. Removing them, rather than writing values of our own,
//!   keeps Zentinel from inventing headers a backend never asked for: the
//!   backend falls back to `X-Forwarded-For`, `-Proto` and `-Host`, or to the
//!   connection, all of which are ours. `X-Forwarded-Port` in particular is
//!   not rebuilt: the port Zentinel listens on is often not the port the
//!   client used (a published container port, a NAT), whereas
//!   `X-Forwarded-Host` carries the client's own port when the `Host` header
//!   has one. A `request-headers`
//!   policy can still `set` any of them, and can `remove` headers that are
//!   not in the list.
//!
//! Only when the TCP peer is inside the listener's `trusted-proxies` (a load
//! balancer or CDN in front of Zentinel) is the incoming chain believed: the
//! peer is appended to `X-Forwarded-For`, an incoming `X-Forwarded-Proto`
//! or `-Host` is kept (and set as above when absent), and every header in
//! [`REMOVED_FROM_UNTRUSTED_PEERS`] is passed on unchanged.
//!
//! The client IP Zentinel itself uses (rate-limit key `client-ip`, geo
//! filters, agents' `client_ip`, access logs, `ip-hash`) follows the same
//! rule: the peer when it is untrusted, otherwise the right-most address in
//! the chain that is not itself a trusted proxy. Walking from the right and
//! stopping at the first untrusted hop matters: everything to its left was
//! written by a party nobody vouched for.

use std::net::{IpAddr, SocketAddr};

use pingora::http::RequestHeader;
use zentinel_config::IpCidr;

use super::listener_addr::canonical_ip;

pub(crate) const X_FORWARDED_FOR: &str = "X-Forwarded-For";
pub(crate) const X_FORWARDED_PROTO: &str = "X-Forwarded-Proto";
pub(crate) const X_FORWARDED_HOST: &str = "X-Forwarded-Host";
/// Headers removed from a request whose peer is not in `trusted-proxies`; see
/// the module docs. They say where a request came from, which scheme and port
/// it used, or which URL and host it was first sent to. The three that
/// Zentinel writes itself are not listed: they are rebuilt, not removed.
///
/// Names are matched whole, ignoring case and treating `-` and `_` as the same
/// character (see [`same_header_name`]), and every line of a repeated header
/// goes. The list is documented in `crates/proxy/docs/forwarded-headers.md`;
/// keep the two in step.
pub(crate) const REMOVED_FROM_UNTRUSTED_PEERS: &[&str] = &[
    // Client address.
    "Forwarded",
    "X-Real-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "Client-IP",
    "X-Originating-IP",
    "X-Envoy-External-Address",
    "X-Azure-ClientIP",
    "X-Appengine-User-IP",
    // Scheme and port.
    "X-Forwarded-Port",
    "X-Forwarded-Ssl",
    "X-Forwarded-Scheme",
    "X-Forwarded-Protocol",
    "X-Scheme",
    "X-Url-Scheme",
    "Front-End-Https",
    "CF-Visitor",
    // Original URL, host and prefix.
    "X-Forwarded-Prefix",
    "X-Forwarded-Server",
    "X-Forwarded-Uri",
    "X-Forwarded-Path",
    "X-Original-URL",
    "X-Original-URI",
    "X-Original-Host",
    "X-Rewrite-URL",
];

/// The three headers Zentinel writes for an untrusted peer. A copy of one
/// that differs only in case or in `-` versus `_` is removed along with the
/// list above, so it cannot sit next to Zentinel's own.
const REBUILT_FOR_UNTRUSTED_PEERS: [&str; 3] =
    [X_FORWARDED_FOR, X_FORWARDED_PROTO, X_FORWARDED_HOST];

/// One byte of a header name, folded for comparison: case is ignored, and `_`
/// counts as `-`, because some servers read the two as the same character
/// (`X_Real_IP` is `X-Real-IP` to them).
fn fold_name_byte(byte: u8) -> u8 {
    if byte == b'_' {
        b'-'
    } else {
        byte.to_ascii_lowercase()
    }
}

/// Whether `name` is `listed` once case and `-` versus `_` are ignored.
fn same_header_name(listed: &str, name: &str) -> bool {
    listed.len() == name.len()
        && listed
            .bytes()
            .zip(name.bytes())
            .all(|(a, b)| fold_name_byte(a) == fold_name_byte(b))
}

/// Whether a header of an untrusted peer's request is dropped before the
/// three rebuilt headers are written.
fn dropped_for_untrusted_peer(name: &str) -> bool {
    REMOVED_FROM_UNTRUSTED_PEERS
        .iter()
        .chain(REBUILT_FOR_UNTRUSTED_PEERS.iter())
        .any(|listed| same_header_name(listed, name))
}

fn is_trusted(ip: IpAddr, trusted: &[IpCidr]) -> bool {
    trusted.iter().any(|cidr| cidr.contains(ip))
}

/// One `X-Forwarded-For` element as an address.
///
/// Proxies in the wild write `192.0.2.1`, `192.0.2.1:4711`, `2001:db8::1` and
/// `[2001:db8::1]:4711`; all four are accepted. Anything else (`unknown`,
/// obfuscated identifiers, garbage) is `None`.
fn parse_element(element: &str) -> Option<IpAddr> {
    let element = element.trim();
    if let Ok(ip) = element.parse::<IpAddr>() {
        return Some(canonical_ip(ip));
    }
    if let Ok(addr) = element.parse::<SocketAddr>() {
        return Some(canonical_ip(addr.ip()));
    }
    element
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .and_then(|inner| inner.parse::<IpAddr>().ok())
        .map(canonical_ip)
}

/// The client address of a chain whose last element is a trusted peer.
///
/// Walks from the right, skipping trusted proxies; the first address that is
/// not trusted is the client. An element that is not an address stops the
/// walk, and the last trusted hop before it is used instead: a trusted proxy
/// vouched for what is to its right, not for whatever it received.
fn client_from_chain(chain: &[&str], peer: IpAddr, trusted: &[IpCidr]) -> IpAddr {
    let mut client = peer;
    for element in chain.iter().rev() {
        match parse_element(element) {
            Some(ip) => {
                client = ip;
                if !is_trusted(ip, trusted) {
                    break;
                }
            }
            None => break,
        }
    }
    client
}

/// The request's own host, port included, as `X-Forwarded-Host` carries it.
fn request_host(req: &RequestHeader) -> Option<String> {
    if let Some(authority) = req.uri.authority() {
        return Some(authority.as_str().to_string());
    }
    req.headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .filter(|h| !h.is_empty())
        .map(str::to_string)
}

/// Write the `X-Forwarded-*` headers for a request from `peer` and return the
/// client IP Zentinel should use for it. See the module docs for the rule.
pub(crate) fn apply_forwarded_headers(
    req: &mut RequestHeader,
    peer: IpAddr,
    tls: bool,
    trusted: &[IpCidr],
) -> IpAddr {
    let peer = canonical_ip(peer);
    let scheme = if tls { "https" } else { "http" };

    if !is_trusted(peer, trusted) {
        let host = request_host(req);
        // Every header name is looked at, so the cost here grows with the
        // number of headers; it is paid for untrusted peers only.
        let dropped: Vec<_> = req
            .headers
            .keys()
            .filter(|name| dropped_for_untrusted_peer(name.as_str()))
            .cloned()
            .collect();
        for name in &dropped {
            req.remove_header(name);
        }
        req.insert_header(X_FORWARDED_FOR, peer.to_string()).ok();
        req.insert_header(X_FORWARDED_PROTO, scheme).ok();
        if let Some(host) = host {
            req.insert_header(X_FORWARDED_HOST, host).ok();
        }
        return peer;
    }

    // Trusted peer: extend its chain. Repeated header lines are one list
    // (RFC 9110 5.3), so they are joined before splitting.
    let incoming: Vec<String> = req
        .headers
        .get_all(X_FORWARDED_FOR)
        .iter()
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .collect();
    let elements: Vec<&str> = incoming
        .iter()
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    let client = client_from_chain(&elements, peer, trusted);

    let peer_str = peer.to_string();
    let mut chain = elements.join(", ");
    if !chain.is_empty() {
        chain.push_str(", ");
    }
    chain.push_str(&peer_str);
    req.insert_header(X_FORWARDED_FOR, chain).ok();

    if req.headers.get(X_FORWARDED_PROTO).is_none() {
        req.insert_header(X_FORWARDED_PROTO, scheme).ok();
    }
    if req.headers.get(X_FORWARDED_HOST).is_none() {
        if let Some(host) = request_host(req) {
            req.insert_header(X_FORWARDED_HOST, host).ok();
        }
    }
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/path", None).unwrap();
        for (name, value) in headers {
            req.append_header(name.to_string(), *value).unwrap();
        }
        req
    }

    fn get(req: &RequestHeader, name: &str) -> Option<String> {
        let values: Vec<_> = req
            .headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        (!values.is_empty()).then(|| values.join(" | "))
    }

    fn cidrs(list: &[&str]) -> Vec<IpCidr> {
        list.iter().map(|c| c.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn plain_request_gets_all_three_headers() {
        let mut r = req(&[("Host", "example.com:8080")]);
        let client = apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(client, ip("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(
            get(&r, "x-forwarded-host").as_deref(),
            Some("example.com:8080")
        );
    }

    /// The returned client IP is the rate-limit key: two clients must be two
    /// keys, and it carries no port.
    #[test]
    fn distinct_untrusted_clients_are_distinct_client_ips() {
        let a = apply_forwarded_headers(&mut req(&[]), ip("127.0.0.1"), false, &[]);
        let b = apply_forwarded_headers(&mut req(&[]), ip("::1"), false, &[]);
        assert_ne!(a, b);
        assert_eq!(a.to_string(), "127.0.0.1");
    }

    #[test]
    fn tls_listener_reports_https() {
        let mut r = req(&[("Host", "example.com")]);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), true, &[]);
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("https"));
    }

    /// The security property: without trusted proxies a client cannot choose
    /// the address backends and agents see, nor the scheme or host.
    #[test]
    fn untrusted_peer_cannot_spoof_any_forwarded_header() {
        let mut r = req(&[
            ("Host", "example.com"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-Forwarded-For", "5.6.7.8, 9.9.9.9"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "evil.example"),
        ]);
        let client = apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(client, ip("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(get(&r, "x-forwarded-host").as_deref(), Some("example.com"));
    }

    /// The other two client-address headers in common use. Zentinel writes
    /// neither, so from an untrusted peer they are dropped, not passed on.
    #[test]
    fn untrusted_peer_cannot_pass_forwarded_or_x_real_ip() {
        let mut r = req(&[
            ("Forwarded", "for=6.6.6.6;proto=https"),
            ("X-Real-IP", "6.6.6.6"),
        ]);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(get(&r, "forwarded"), None);
        assert_eq!(get(&r, "x-real-ip"), None);
    }

    /// Headers that say where a request came from, which scheme and port it
    /// used, or which URL and host it was first sent to. Listed by hand, and
    /// not from `REMOVED_FROM_UNTRUSTED_PEERS`, so a name dropped from that
    /// list fails here.
    const FORWARDING_HEADERS: &[&str] = &[
        "Forwarded",
        "X-Real-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Fastly-Client-IP",
        "Client-IP",
        "X-Originating-IP",
        "X-Envoy-External-Address",
        "X-Azure-ClientIP",
        "X-Appengine-User-IP",
        "X-Forwarded-Port",
        "X-Forwarded-Ssl",
        "X-Forwarded-Scheme",
        "X-Forwarded-Protocol",
        "X-Scheme",
        "X-Url-Scheme",
        "Front-End-Https",
        "CF-Visitor",
        "X-Forwarded-Prefix",
        "X-Forwarded-Server",
        "X-Forwarded-Uri",
        "X-Forwarded-Path",
        "X-Original-URL",
        "X-Original-URI",
        "X-Original-Host",
        "X-Rewrite-URL",
    ];

    /// A request from a peer outside `trusted-proxies` reaches the upstream
    /// without any of the headers above, whatever the client put in them.
    #[test]
    fn untrusted_peer_loses_client_supplied_forwarding_headers() {
        let mut headers = vec![("Host", "a.example")];
        headers.extend(
            FORWARDING_HEADERS
                .iter()
                .map(|name| (*name, "198.51.100.7")),
        );
        let mut r = req(&headers);
        let client = apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(client, ip("203.0.113.9"));
        for name in FORWARDING_HEADERS {
            assert_eq!(get(&r, name), None, "{name} was passed on");
        }
        // The three headers Zentinel writes are still its own.
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(get(&r, "x-forwarded-host").as_deref(), Some("a.example"));
    }

    /// Names are case-insensitive (HTTP/2 sends them lowercase) and a header
    /// sent on several lines is removed whole.
    #[test]
    fn untrusted_peer_forwarding_headers_go_in_any_case_and_on_every_line() {
        let mut r = req(&[
            ("true-client-ip", "198.51.100.7"),
            ("TRUE-CLIENT-IP", "198.51.100.8"),
            ("x-original-url", "/a"),
            ("X-Forwarded-Port", "8443"),
            ("x-forwarded-port", "9443"),
        ]);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(get(&r, "true-client-ip"), None);
        assert_eq!(get(&r, "x-original-url"), None);
        assert_eq!(get(&r, "x-forwarded-port"), None);
    }

    /// Only the headers in the list go; everything else is the client's to
    /// send.
    #[test]
    fn untrusted_peer_other_headers_are_untouched() {
        let mut r = req(&[
            ("Host", "a.example"),
            ("Accept", "text/html"),
            ("Cookie", "k=v"),
            ("X-Request-Id", "req-1"),
            ("X-Custom", "kept"),
            ("Via", "1.1 a.example"),
            ("X-Real-IP-Extra", "kept"),
            ("X-Forwarded-Foo", "kept"),
            ("Real-IP", "kept"),
        ]);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(get(&r, "accept").as_deref(), Some("text/html"));
        assert_eq!(get(&r, "cookie").as_deref(), Some("k=v"));
        assert_eq!(get(&r, "x-request-id").as_deref(), Some("req-1"));
        assert_eq!(get(&r, "x-custom").as_deref(), Some("kept"));
        assert_eq!(get(&r, "via").as_deref(), Some("1.1 a.example"));
        // Whole names are compared, not prefixes or suffixes.
        assert_eq!(get(&r, "x-real-ip-extra").as_deref(), Some("kept"));
        assert_eq!(get(&r, "x-forwarded-foo").as_deref(), Some("kept"));
        assert_eq!(get(&r, "real-ip").as_deref(), Some("kept"));
    }

    /// Some servers read `-` and `_` in a header name as the same character
    /// (`X_Real_IP` is `X-Real-IP` to them), so a name written with
    /// underscores is removed like the hyphenated one.
    #[test]
    fn untrusted_peer_forwarding_headers_go_with_underscores_in_the_name() {
        let mut headers = vec![("Host", "a.example")];
        let underscored: Vec<String> = FORWARDING_HEADERS
            .iter()
            .map(|name| name.replace('-', "_"))
            .collect();
        headers.extend(
            underscored
                .iter()
                .map(|name| (name.as_str(), "198.51.100.7")),
        );
        let mut r = req(&headers);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        for name in &underscored {
            assert_eq!(get(&r, name), None, "{name} was passed on");
        }
        for name in FORWARDING_HEADERS {
            assert_eq!(get(&r, name), None, "{name} was passed on");
        }
    }

    /// The same holds for the three headers Zentinel writes itself: a copy
    /// spelled with underscores would otherwise sit next to ours.
    #[test]
    fn untrusted_peer_underscore_forms_of_rebuilt_headers_are_replaced() {
        let mut r = req(&[
            ("Host", "a.example"),
            ("X_Forwarded_For", "198.51.100.7"),
            ("x_forwarded_proto", "https"),
            ("X_FORWARDED_HOST", "b.example"),
        ]);
        apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &[]);
        assert_eq!(get(&r, "x_forwarded_for"), None);
        assert_eq!(get(&r, "x_forwarded_proto"), None);
        assert_eq!(get(&r, "x_forwarded_host"), None);
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("http"));
        assert_eq!(get(&r, "x-forwarded-host").as_deref(), Some("a.example"));
    }

    /// For a peer in `trusted-proxies` nothing is renamed or removed, however
    /// the name is spelled.
    #[test]
    fn trusted_peer_keeps_headers_whatever_their_spelling() {
        let mut r = req(&[
            ("X_Real_IP", "198.51.100.7"),
            ("true_client_ip", "198.51.100.8"),
        ]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(get(&r, "x_real_ip").as_deref(), Some("198.51.100.7"));
        assert_eq!(get(&r, "true_client_ip").as_deref(), Some("198.51.100.8"));
    }

    /// The documented list and the one in the code are the same.
    #[test]
    fn docs_list_every_removed_header() {
        let docs = include_str!("../../docs/forwarded-headers.md");
        for name in REMOVED_FROM_UNTRUSTED_PEERS {
            assert!(
                docs.contains(&format!("`{name}`")),
                "{name} is not documented"
            );
        }
        for name in FORWARDING_HEADERS {
            assert!(
                REMOVED_FROM_UNTRUSTED_PEERS
                    .iter()
                    .any(|listed| listed.eq_ignore_ascii_case(name)),
                "{name} is not in REMOVED_FROM_UNTRUSTED_PEERS"
            );
        }
    }

    /// A peer in `trusted-proxies` vouches for what it sends, so the same
    /// headers reach the upstream unchanged.
    #[test]
    fn trusted_peer_keeps_other_forwarding_headers() {
        let mut headers = vec![("Host", "internal:8080")];
        headers.extend(
            FORWARDING_HEADERS
                .iter()
                .map(|name| (*name, "198.51.100.7")),
        );
        let mut r = req(&headers);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        for name in FORWARDING_HEADERS {
            assert_eq!(
                get(&r, name).as_deref(),
                Some("198.51.100.7"),
                "{name} was changed"
            );
        }
    }

    #[test]
    fn trusted_peer_keeps_forwarded_and_x_real_ip() {
        let mut r = req(&[
            ("Forwarded", "for=198.51.100.7;proto=https"),
            ("X-Real-IP", "198.51.100.7"),
        ]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(
            get(&r, "forwarded").as_deref(),
            Some("for=198.51.100.7;proto=https")
        );
        assert_eq!(get(&r, "x-real-ip").as_deref(), Some("198.51.100.7"));
    }

    /// Trusting someone else is not trusting this peer.
    #[test]
    fn peer_outside_trusted_networks_is_untrusted() {
        let mut r = req(&[("X-Forwarded-For", "1.2.3.4")]);
        let client =
            apply_forwarded_headers(&mut r, ip("203.0.113.9"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("203.0.113.9"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn trusted_peer_chain_is_extended_and_its_proto_and_host_kept() {
        let mut r = req(&[
            ("Host", "internal:8080"),
            ("X-Forwarded-For", "198.51.100.7"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Host", "www.example.com"),
        ]);
        let client =
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("198.51.100.7"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 10.0.0.2")
        );
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(
            get(&r, "x-forwarded-host").as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn trusted_peer_without_incoming_headers_gets_ours() {
        let mut r = req(&[("Host", "example.com")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), true, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("10.0.0.2"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("10.0.0.2"));
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(get(&r, "x-forwarded-host").as_deref(), Some("example.com"));
    }

    /// A client behind a trusted load balancer can still prepend addresses;
    /// the client IP is the right-most untrusted hop, never the left-most.
    #[test]
    fn client_ip_is_rightmost_untrusted_hop() {
        let trusted = cidrs(&["10.0.0.0/8", "192.168.0.0/16"]);
        let mut r = req(&[("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 192.168.1.1")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("198.51.100.7"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("6.6.6.6, 198.51.100.7, 192.168.1.1, 10.0.0.2")
        );
    }

    #[test]
    fn garbage_in_the_chain_stops_at_the_last_trusted_hop() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7, unknown, 10.1.1.1")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("10.1.1.1"));
    }

    #[test]
    fn elements_with_ports_and_brackets_parse() {
        assert_eq!(parse_element("192.0.2.1:4711"), Some(ip("192.0.2.1")));
        assert_eq!(parse_element("[2001:db8::1]:4711"), Some(ip("2001:db8::1")));
        assert_eq!(parse_element("[2001:db8::1]"), Some(ip("2001:db8::1")));
        assert_eq!(parse_element(" 2001:db8::1 "), Some(ip("2001:db8::1")));
        assert_eq!(parse_element("unknown"), None);
    }

    /// A dual-stack `[::]` listener reports IPv4 peers as `::ffff:a.b.c.d`;
    /// they must match IPv4 trusted networks and be reported in IPv4 form.
    #[test]
    fn ipv4_mapped_peer_is_canonicalised() {
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7")]);
        let client = apply_forwarded_headers(
            &mut r,
            ip("::ffff:10.0.0.2"),
            false,
            &cidrs(&["10.0.0.0/8"]),
        );
        assert_eq!(client, ip("198.51.100.7"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 10.0.0.2")
        );
    }

    #[test]
    fn cidr_matching() {
        let c: IpCidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains(ip("10.255.0.1")));
        assert!(!c.contains(ip("11.0.0.1")));
        assert!(!c.contains(ip("::ffff:10.0.0.1")));
        let all: IpCidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains(ip("203.0.113.1")));
        let host: IpCidr = "2001:db8::1".parse().unwrap();
        assert!(host.contains(ip("2001:db8::1")));
        assert!(!host.contains(ip("2001:db8::2")));
        let v6: IpCidr = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!("10.0.0.0/33".parse::<IpCidr>().is_err());
        assert!("not-an-ip".parse::<IpCidr>().is_err());
    }
}
