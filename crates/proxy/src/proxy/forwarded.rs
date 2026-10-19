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
//! doing IP reputation see. So by default nothing a client sends survives:
//!
//! * `X-Forwarded-For` is **replaced** by the TCP peer's address;
//! * `X-Forwarded-Proto` is replaced by what the listener observed (`https`
//!   when the connection is TLS, else `http`);
//! * `X-Forwarded-Host` is replaced by the request's own host.
//!
//! Only when the TCP peer is inside the listener's `trusted-proxies` (a load
//! balancer or CDN in front of Zentinel) is the incoming chain believed: the
//! peer is appended to `X-Forwarded-For`, and an incoming `X-Forwarded-Proto`
//! or `-Host` is kept (and set as above when absent).
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
        req.insert_header(X_FORWARDED_FOR, peer.to_string()).ok();
        req.insert_header(X_FORWARDED_PROTO, scheme).ok();
        match request_host(req) {
            Some(host) => {
                req.insert_header(X_FORWARDED_HOST, host).ok();
            }
            None => {
                req.remove_header(X_FORWARDED_HOST);
            }
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
