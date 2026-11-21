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
//! balancer or CDN in front of Zentinel) is the incoming chain believed, and
//! even then what it sent is checked before it is passed on:
//!
//! * the peer is appended to `X-Forwarded-For`, and the chain that is passed
//!   on starts at the client IP chosen below: the elements to the left of it,
//!   whether addresses or not, are left out, and the others keep their order
//!   and spelling;
//! * an incoming `X-Forwarded-Proto` is kept when every element of it is
//!   `http` or `https`, and replaced by the listener's scheme otherwise (as
//!   when it is absent);
//! * an incoming `X-Forwarded-Host` is kept when every element of it reads
//!   as a host with an optional port, and replaced by the request's own host
//!   otherwise (or removed, when the request has none);
//! * an incoming `X-Real-IP` is rewritten to the client IP chosen below; one
//!   the peer did not send is not added;
//! * for `-Proto` and `-Host`, all lines are read as one list, so a trusted
//!   proxy that adds its own value (`https, http`) keeps a valid value valid;
//!   one element that is not accepted replaces the whole value;
//! * a copy of one of these four headers spelled with `_` (`X_Real_IP`) is
//!   removed, so a value that was not checked does not follow the one that
//!   was;
//! * `Forwarded` and every other header in [`REMOVED_FROM_UNTRUSTED_PEERS`]
//!   are passed on as sent. Zentinel neither reads nor writes them.
//!
//! The client IP Zentinel itself uses (rate-limit key `client-ip`, geo
//! filters, agents' `client_ip`, access logs, `ip-hash`) follows the same
//! rule: the peer when it is untrusted, otherwise the right-most address in
//! the chain that is not itself a trusted proxy. Walking from the right and
//! stopping at the first untrusted hop matters: everything to its left was
//! written by a party nobody vouched for.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use pingora::http::RequestHeader;
use zentinel_config::IpCidr;

use super::listener_addr::canonical_ip;

pub(crate) const X_FORWARDED_FOR: &str = "X-Forwarded-For";
pub(crate) const X_FORWARDED_PROTO: &str = "X-Forwarded-Proto";
pub(crate) const X_FORWARDED_HOST: &str = "X-Forwarded-Host";
const X_REAL_IP: &str = "X-Real-IP";
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

/// The four headers Zentinel checks and writes for a trusted peer. A copy
/// spelled with `_` (see [`same_header_name`]) is removed, so that the value
/// that was checked is not followed by one that was not.
const CHECKED_FOR_TRUSTED_PEERS: [&str; 4] = [
    X_FORWARDED_FOR,
    X_FORWARDED_PROTO,
    X_FORWARDED_HOST,
    X_REAL_IP,
];

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

/// Whether `name` (as a `HeaderMap` key, so in lowercase) is a copy of one of
/// the headers in [`CHECKED_FOR_TRUSTED_PEERS`] that is spelled with `_`.
fn is_other_spelling_of_checked_header(name: &str) -> bool {
    name.contains('_')
        && CHECKED_FOR_TRUSTED_PEERS
            .iter()
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

/// The client address of a chain whose last element is a trusted peer, and the
/// index of the element it came from (the chain's length when it is the peer).
///
/// Walks from the right, skipping trusted proxies; the first address that is
/// not trusted is the client. An element that is not an address stops the
/// walk, and the last trusted hop before it is used instead: a trusted proxy
/// vouched for what is to its right, not for whatever it received. Every
/// element from that index on is an address, and all but the first are
/// trusted proxies.
fn client_from_chain(chain: &[&str], peer: IpAddr, trusted: &[IpCidr]) -> (IpAddr, usize) {
    let mut client = peer;
    let mut start = chain.len();
    for (index, element) in chain.iter().enumerate().rev() {
        match parse_element(element) {
            Some(ip) => {
                client = ip;
                start = index;
                if !is_trusted(ip, trusted) {
                    break;
                }
            }
            None => break,
        }
    }
    (client, start)
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

/// Whether `value` is a scheme the upstream is told about: `http` or `https`.
fn is_scheme(value: &str) -> bool {
    value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https")
}

fn is_port(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) && value.parse::<u16>().is_ok()
}

/// Whether `value` reads as a host with an optional port, the form of a `Host`
/// header: a name made of letters, digits, `-`, `.` and `_`, an IPv4 address,
/// or an IPv6 address in brackets. Spaces, control characters, `/`, `@` and
/// non-ASCII bytes are not part of a host.
fn is_host(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('[') {
        return rest.split_once(']').is_some_and(|(inner, after)| {
            inner.parse::<Ipv6Addr>().is_ok()
                && (after.is_empty() || after.strip_prefix(':').is_some_and(is_port))
        });
    }
    let (name, port) = match value.rsplit_once(':') {
        Some((name, port)) => (name, Some(port)),
        None => (value, None),
    };
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && port.is_none_or(is_port)
}

/// What a trusted peer sent in a header that holds a scheme or a host.
enum Incoming {
    Absent,
    /// Every element is accepted by the check.
    Valid,
    /// At least one element is rejected by the check or is not readable as
    /// text.
    Invalid,
}

/// Reads every line of the header `name` as one list (RFC 9110 5.3), the way
/// a proxy in front of Zentinel that adds its own value writes it, and checks
/// each element. A list is kept only when all of its elements are accepted,
/// so that no element the check did not see reaches the upstream.
fn incoming_value(req: &RequestHeader, name: &str, is_valid: fn(&str) -> bool) -> Incoming {
    let mut lines = req.headers.get_all(name).iter().peekable();
    if lines.peek().is_none() {
        return Incoming::Absent;
    }
    let valid = lines.all(|line| {
        line.to_str().is_ok_and(|line| {
            line.split(',')
                .all(|element| is_valid(element.trim_ascii()))
        })
    });
    if valid {
        Incoming::Valid
    } else {
        Incoming::Invalid
    }
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
    let other_spellings: Vec<_> = req
        .headers
        .keys()
        .filter(|name| is_other_spelling_of_checked_header(name.as_str()))
        .cloned()
        .collect();
    if !other_spellings.is_empty() {
        tracing::debug!(
            peer = %peer,
            removed = other_spellings.len(),
            "Removed copies of X-Forwarded-For, -Proto, -Host or X-Real-IP spelled with an underscore"
        );
    }
    for name in &other_spellings {
        req.remove_header(name);
    }
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
    // The chain that is passed on starts at the client chosen from the chain
    // as received. What is to its left, elements that are not addresses
    // included, no trusted hop vouched for, and is not passed on; an upstream
    // that reads the chain from the right with the same trusted networks
    // reaches the same client.
    let (client, start) = client_from_chain(&elements, peer, trusted);
    if start > 0 {
        tracing::debug!(
            peer = %peer,
            dropped = start,
            "Dropped X-Forwarded-For elements left of the client address"
        );
    }

    let mut chain = elements[start..].join(", ");
    if !chain.is_empty() {
        chain.push_str(", ");
    }
    chain.push_str(&peer.to_string());
    req.insert_header(X_FORWARDED_FOR, chain).ok();

    // A value that is not a scheme or a host is replaced by the listener's
    // scheme or the request's own host, as when the header is absent.
    match incoming_value(req, X_FORWARDED_PROTO, is_scheme) {
        Incoming::Valid => {}
        incoming => {
            if matches!(incoming, Incoming::Invalid) {
                tracing::debug!(peer = %peer, "Replaced an X-Forwarded-Proto that is not http or https");
            }
            req.insert_header(X_FORWARDED_PROTO, scheme).ok();
        }
    }
    match incoming_value(req, X_FORWARDED_HOST, is_host) {
        Incoming::Valid => {}
        incoming => {
            if matches!(incoming, Incoming::Invalid) {
                tracing::debug!(peer = %peer, "Replaced an X-Forwarded-Host that is not a host");
            }
            match request_host(req) {
                Some(host) => {
                    req.insert_header(X_FORWARDED_HOST, host).ok();
                }
                None => {
                    req.remove_header(X_FORWARDED_HOST);
                }
            }
        }
    }

    // `X-Real-IP` says what Zentinel decided, not what the peer sent. It is
    // not added when the peer sent none: the only headers Zentinel adds of its
    // own are the three above.
    if req.headers.contains_key(X_REAL_IP) {
        let client_str = client.to_string();
        let mut lines = req.headers.get_all(X_REAL_IP).iter();
        let unchanged = matches!(
            (lines.next(), lines.next()),
            (Some(line), None) if line.as_bytes() == client_str.as_bytes()
        );
        if !unchanged {
            tracing::debug!(peer = %peer, "Rewrote an X-Real-IP that is not the client address");
        }
        req.insert_header(X_REAL_IP, client_str).ok();
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

    /// For a peer in `trusted-proxies` the headers that are passed on as sent
    /// stay, however the name is spelled.
    #[test]
    fn trusted_peer_keeps_other_headers_whatever_their_spelling() {
        let mut r = req(&[
            ("true_client_ip", "198.51.100.8"),
            ("X_Forwarded_Port", "8443"),
            ("X_Original_URL", "/a"),
        ]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(get(&r, "true_client_ip").as_deref(), Some("198.51.100.8"));
        assert_eq!(get(&r, "x_forwarded_port").as_deref(), Some("8443"));
        assert_eq!(get(&r, "x_original_url").as_deref(), Some("/a"));
    }

    /// The four headers Zentinel checks and rewrites are written once, with
    /// the checked value. A copy spelled with underscores (`X_Real_IP` is
    /// `X-Real-IP` to some servers) is removed, so it cannot sit next to it
    /// with a value nobody checked.
    #[test]
    fn trusted_peer_underscore_spellings_of_checked_headers_are_removed() {
        let mut r = req(&[
            ("Host", "a.example"),
            ("X-Forwarded-For", "198.51.100.7"),
            ("X_Forwarded_For", "192.0.2.99"),
            ("X-Forwarded-Proto", "https"),
            ("x_forwarded_proto", "ftp"),
            ("X-Forwarded-Host", "www.example.com"),
            ("X_FORWARDED_HOST", "b.example/path"),
            ("X-Real-IP", "192.0.2.98"),
            ("X_Real_IP", "192.0.2.99"),
        ]);
        let client =
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("198.51.100.7"));
        for name in [
            "x_forwarded_for",
            "x_forwarded_proto",
            "x_forwarded_host",
            "x_real_ip",
        ] {
            assert_eq!(get(&r, name), None, "{name} was passed on");
        }
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 10.0.0.2")
        );
        assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some("https"));
        assert_eq!(
            get(&r, "x-forwarded-host").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(get(&r, "x-real-ip").as_deref(), Some("198.51.100.7"));
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

    /// A peer in `trusted-proxies` is believed about the other forwarding
    /// headers, so they reach the upstream unchanged. `X-Real-IP` is the
    /// exception: it is rewritten, and has its own test below.
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
        for name in FORWARDING_HEADERS
            .iter()
            .filter(|name| !name.eq_ignore_ascii_case("X-Real-IP"))
        {
            assert_eq!(
                get(&r, name).as_deref(),
                Some("198.51.100.7"),
                "{name} was changed"
            );
        }
    }

    /// `Forwarded` is neither read nor written by Zentinel, so it is passed on
    /// as the trusted peer sent it.
    #[test]
    fn trusted_peer_keeps_forwarded() {
        let mut r = req(&[("Forwarded", "for=198.51.100.7;proto=https")]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(
            get(&r, "forwarded").as_deref(),
            Some("for=198.51.100.7;proto=https")
        );
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
    /// the client IP is the right-most untrusted hop, never the left-most, and
    /// what the client prepended is not passed on.
    #[test]
    fn client_ip_is_rightmost_untrusted_hop() {
        let trusted = cidrs(&["10.0.0.0/8", "192.168.0.0/16"]);
        let mut r = req(&[("X-Forwarded-For", "6.6.6.6, 198.51.100.7, 192.168.1.1")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("198.51.100.7"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("198.51.100.7, 192.168.1.1, 10.0.0.2")
        );
    }

    /// The client IP is chosen from the chain as received: an element that is
    /// not an address ends the walk.
    #[test]
    fn garbage_in_the_chain_stops_at_the_last_trusted_hop() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7, unknown, 10.1.1.1")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("10.1.1.1"));
    }

    /// The chain that is passed on starts at the client IP Zentinel chose. What
    /// is to its left, elements that are not addresses included, was not
    /// vouched for by any trusted hop. What is to its right is kept as
    /// written, ports and brackets included.
    #[test]
    fn trusted_peer_chain_starts_at_the_chosen_client() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[(
            "X-Forwarded-For",
            "unknown, a.example, 198.51.100.7, _hidden, 192.0.2.1:4711, \
             [2001:db8::1]:4711, 10.1.1.1",
        )]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("2001:db8::1"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("[2001:db8::1]:4711, 10.1.1.1, 10.0.0.2")
        );
    }

    /// An element that is not an address ends the walk, as it always did, and
    /// the chain that is passed on starts at the last trusted hop before it:
    /// the client IP is unchanged, and the elements to its left are gone.
    #[test]
    fn chain_written_starts_where_the_walk_for_the_client_ended() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7, unknown, 10.1.1.1")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("10.1.1.1"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("10.1.1.1, 10.0.0.2")
        );
    }

    /// When every hop is trusted the client is the left-most one, and the whole
    /// chain is passed on.
    #[test]
    fn chain_of_trusted_hops_is_kept_whole() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[("X-Forwarded-For", "10.1.1.1, 10.1.1.2")]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("10.1.1.1"));
        assert_eq!(
            get(&r, "x-forwarded-for").as_deref(),
            Some("10.1.1.1, 10.1.1.2, 10.0.0.2")
        );
    }

    /// An element that is not an address next to the peer leaves the peer as
    /// the client, and nothing else in the chain.
    #[test]
    fn chain_ending_in_a_non_address_becomes_the_peer() {
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7, unknown")]);
        let client =
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("10.0.0.2"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("10.0.0.2"));
    }

    /// Whatever the incoming chain, on one line or several, with empty
    /// elements or without, an upstream that reads the chain that is passed on
    /// from the right, with the same trusted networks, reaches the client IP
    /// Zentinel chose.
    #[test]
    fn chain_written_leads_to_the_chosen_client() {
        let trusted = cidrs(&["10.0.0.0/8", "192.168.0.0/16", "2001:db8:10::/48"]);
        let chains: &[&[&str]] = &[
            &[],
            &[""],
            &["198.51.100.7"],
            &["6.6.6.6, 198.51.100.7, 192.168.1.1"],
            &["198.51.100.7, unknown, 10.1.1.1"],
            &["198.51.100.7, unknown"],
            &["unknown, 198.51.100.7, 10.1.1.1, 192.168.1.1"],
            &["10.1.1.1, 10.1.1.2"],
            &["198.51.100.7, [2001:db8::1]:4711, 10.1.1.1"],
            &["a.example, 10.1.1.1, _x, 10.1.1.2"],
            // Several lines are one list.
            &["6.6.6.6", "198.51.100.7, 10.1.1.1", "192.168.1.1"],
            &["198.51.100.7, unknown", "10.1.1.1"],
            &["198.51.100.7", "unknown"],
            // Empty elements.
            &["198.51.100.7,,10.1.1.1"],
            &["6.6.6.6, ,198.51.100.7,, 192.168.1.1,"],
            &["a.example,,10.1.1.1"],
            // Trusted IPv6 hops, bare and with a port.
            &["198.51.100.7, 2001:db8:10::1"],
            &["6.6.6.6, 198.51.100.7, 2001:db8:10::1, 10.1.1.1"],
            &["198.51.100.7, [2001:db8:10::2]:4711, 10.1.1.1"],
            &["2001:db8:10::1, 2001:db8:10::2"],
            &["2001:db8::1, 2001:db8:10::1"],
        ];
        for lines in chains {
            let headers: Vec<(&str, &str)> = lines
                .iter()
                .map(|line| ("X-Forwarded-For", *line))
                .collect();
            let mut r = req(&headers);
            let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
            let written = get(&r, "x-forwarded-for").unwrap();
            let mut again = req(&[("X-Forwarded-For", written.as_str())]);
            assert_eq!(
                apply_forwarded_headers(&mut again, ip("10.0.0.2"), false, &trusted),
                client,
                "chain {lines:?} became {written:?}"
            );
            // Nothing that is not an address, and nothing empty, is passed on.
            for element in written.split(", ") {
                assert!(
                    parse_element(element).is_some(),
                    "chain {lines:?} became {written:?}"
                );
            }
        }
    }

    /// A chain with nothing readable in it leaves the peer alone, on one line
    /// or several.
    #[test]
    fn trusted_peer_chain_without_addresses_becomes_the_peer() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[
            ("X-Forwarded-For", "unknown, _hidden"),
            ("X-Forwarded-For", "a.example"),
        ]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("10.0.0.2"));
        assert_eq!(get(&r, "x-forwarded-for").as_deref(), Some("10.0.0.2"));
    }

    /// `X-Forwarded-Proto` lines as the request carries them, with a `Host`.
    fn proto_request(lines: &[&str]) -> RequestHeader {
        let mut headers = vec![("Host", "a.example")];
        headers.extend(lines.iter().map(|line| ("X-Forwarded-Proto", *line)));
        req(&headers)
    }

    /// `X-Forwarded-Host` lines as the request carries them, with a `Host`.
    fn host_request(lines: &[&str]) -> RequestHeader {
        let mut headers = vec![("Host", "internal:8080")];
        headers.extend(lines.iter().map(|line| ("X-Forwarded-Host", *line)));
        req(&headers)
    }

    /// Only `http` and `https` are schemes the upstream is told about; any
    /// other value is replaced by the scheme of the listener.
    #[test]
    fn trusted_peer_proto_that_is_not_http_or_https_is_replaced() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        for (tls, expected) in [(false, "http"), (true, "https")] {
            for value in ["ftp", "gopher", "", " ", "https://a.example"] {
                let mut r = proto_request(&[value]);
                apply_forwarded_headers(&mut r, ip("10.0.0.2"), tls, &trusted);
                assert_eq!(
                    get(&r, "x-forwarded-proto").as_deref(),
                    Some(expected),
                    "tls {tls}, value {value:?}"
                );
            }
        }
    }

    /// A list of values, on one line or several, is read as one: one element
    /// that is not a scheme replaces all of it, so no element the check did
    /// not see reaches the upstream.
    #[test]
    fn trusted_peer_proto_list_with_an_element_that_is_not_a_scheme_is_replaced() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let lists: &[&[&str]] = &[
            &["https, gopher"],
            &["gopher, https"],
            &["https,"],
            &["https,,http"],
            &["https", "gopher"],
            &["gopher", "https"],
            &["https, http", "ftp"],
        ];
        for (tls, expected) in [(false, "http"), (true, "https")] {
            for lines in lists {
                let mut r = proto_request(lines);
                apply_forwarded_headers(&mut r, ip("10.0.0.2"), tls, &trusted);
                assert_eq!(
                    get(&r, "x-forwarded-proto").as_deref(),
                    Some(expected),
                    "tls {tls}, lines {lines:?}"
                );
            }
        }
    }

    /// A trusted proxy that adds its own value to the one it received writes a
    /// list (`https, http`): when every element is a scheme, all of it stays.
    #[test]
    fn trusted_peer_proto_list_of_schemes_is_kept() {
        let lists: &[&[&str]] = &[
            &["https, http"],
            &["http,https"],
            &["HTTPS ,  http"],
            &["https", "http"],
            &["https, https", "http"],
        ];
        for lines in lists {
            let mut r = proto_request(lines);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
            assert_eq!(
                get(&r, "x-forwarded-proto"),
                Some(lines.join(" | ")),
                "lines {lines:?}"
            );
        }
    }

    #[test]
    fn trusted_peer_proto_http_and_https_are_kept_in_any_case() {
        for value in ["http", "https", "HTTPS", "Http"] {
            let mut r = proto_request(&[value]);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), true, &cidrs(&["10.0.0.0/8"]));
            assert_eq!(get(&r, "x-forwarded-proto").as_deref(), Some(value));
        }
    }

    /// A value that is not a host, with or without a port, is replaced by the
    /// request's own host.
    #[test]
    fn trusted_peer_host_that_is_not_a_host_is_replaced() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        for value in [
            "",
            " ",
            "a b.example",
            "a.example\tb",
            "a.example/path",
            "a.example?q=1",
            "a.example#f",
            "user@a.example",
            "a.example:",
            "a.example:http",
            "a.example:99999",
            "a.example:80:80",
            "caf\u{e9}.example",
            "[2001:db8::1",
            "[a.example]",
            "[2001:db8::1]x",
            "2001:db8::1",
        ] {
            let mut r = host_request(&[value]);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
            assert_eq!(
                get(&r, "x-forwarded-host").as_deref(),
                Some("internal:8080"),
                "value {value:?}"
            );
        }
    }

    /// A list of values, on one line or several, is read as one: one element
    /// that is not a host replaces all of it.
    #[test]
    fn trusted_peer_host_list_with_an_element_that_is_not_a_host_is_replaced() {
        let lists: &[&[&str]] = &[
            &["a.example, b.example/path"],
            &["a.example/path, b.example"],
            &["a.example,"],
            &["a.example,,b.example"],
            &["a.example", "b.example/path"],
            &["a.example/path", "b.example"],
        ];
        for lines in lists {
            let mut r = host_request(lines);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
            assert_eq!(
                get(&r, "x-forwarded-host").as_deref(),
                Some("internal:8080"),
                "lines {lines:?}"
            );
        }
    }

    /// With no host of its own to put there, the request keeps no
    /// `X-Forwarded-Host` rather than one that is not a host.
    #[test]
    fn trusted_peer_host_that_is_not_a_host_is_removed_without_a_request_host() {
        let mut r = req(&[("X-Forwarded-Host", "a.example/path")]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(get(&r, "x-forwarded-host"), None);
    }

    /// A list of hosts, on one line or several, stays when every element is a
    /// host.
    #[test]
    fn trusted_peer_host_list_of_hosts_is_kept() {
        let lists: &[&[&str]] = &[
            &["a.example, b.example:8443"],
            &["a.example,b.example"],
            &["a.example", "b.example"],
            &["www.example.com, [2001:db8::1]:8443", "203.0.113.5"],
        ];
        for lines in lists {
            let mut r = host_request(lines);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
            assert_eq!(
                get(&r, "x-forwarded-host"),
                Some(lines.join(" | ")),
                "lines {lines:?}"
            );
        }
    }

    #[test]
    fn trusted_peer_host_that_is_a_host_is_kept() {
        for value in [
            "a.example",
            "a.example:8443",
            "A.Example",
            "a-b.example.",
            "internal_svc:80",
            "203.0.113.5",
            "203.0.113.5:80",
            "[2001:db8::1]",
            "[2001:db8::1]:8443",
            "localhost",
        ] {
            let mut r = host_request(&[value]);
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
            assert_eq!(
                get(&r, "x-forwarded-host").as_deref(),
                Some(value),
                "value {value:?}"
            );
        }
    }

    /// `X-Real-IP` is Zentinel's client IP, not what the peer sent.
    #[test]
    fn trusted_peer_x_real_ip_is_the_client_ip() {
        let trusted = cidrs(&["10.0.0.0/8"]);
        let mut r = req(&[
            ("X-Forwarded-For", "198.51.100.7, 10.1.1.1"),
            ("X-Real-IP", "192.0.2.99"),
        ]);
        let client = apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &trusted);
        assert_eq!(client, ip("198.51.100.7"));
        assert_eq!(get(&r, "x-real-ip").as_deref(), Some("198.51.100.7"));
    }

    /// With no chain the client is the peer, and a value sent on several
    /// lines, or one that is not an address, goes the same way.
    #[test]
    fn trusted_peer_x_real_ip_without_a_chain_is_the_peer() {
        let mut r = req(&[("X-Real-IP", "192.0.2.99"), ("X-Real-IP", "not-an-address")]);
        let client =
            apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(client, ip("10.0.0.2"));
        assert_eq!(get(&r, "x-real-ip").as_deref(), Some("10.0.0.2"));
    }

    /// A trusted peer that sends no `X-Real-IP` is not given one.
    #[test]
    fn trusted_peer_without_x_real_ip_is_not_given_one() {
        let mut r = req(&[("X-Forwarded-For", "198.51.100.7")]);
        apply_forwarded_headers(&mut r, ip("10.0.0.2"), false, &cidrs(&["10.0.0.0/8"]));
        assert_eq!(get(&r, "x-real-ip"), None);
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
