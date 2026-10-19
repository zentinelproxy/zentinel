//! Matching an accepted connection back to the listener that configured it.
//!
//! Listeners are configured by bind address (`0.0.0.0:443`, `127.0.0.1:9000`).
//! At request time all we have is the accepted connection's local address, which
//! Pingora reports from `getsockname()`. Those two are *not* interchangeable: a
//! connection accepted on a wildcard bind reports the concrete interface it
//! landed on (`203.0.113.5:443`), never `0.0.0.0:443`. Comparing the configured
//! string against the local address therefore silently never matches for
//! wildcard binds, which is how per-listener settings came to be ignored on
//! exactly the listeners that face the internet.
//!
//! Everything here works on parsed [`SocketAddr`]s rather than strings.
//! `ListenerConfig::address` is validated as a `SocketAddr` at load time
//! (`validate_socket_addr`), so parsing is total for any config that passed
//! validation.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use zentinel_config::ListenerConfig;

use crate::routing::RouteMatcher;

/// Collapse an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to its IPv4 form.
///
/// A dual-stack `[::]` bind reports IPv4 peers in mapped form, so without this
/// the same connection compares unequal depending on which family the socket
/// was opened with.
pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The client IP Zentinel records for a connection from `peer`: the bare,
/// canonical address. No port, which would make every connection a different
/// client for rate limiting and hashing.
pub(crate) fn client_ip_string(peer: SocketAddr) -> String {
    canonical_ip(peer.ip()).to_string()
}

/// [`canonical_ip`] applied to a whole socket address.
fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(addr.ip()), addr.port())
}

/// Whether a connection with local address `local` arrived on a listener bound
/// to `configured`.
///
/// Exact addresses compare by equality. A wildcard bind matches any local
/// address on the same port, restricted to the families that bind can actually
/// accept: `0.0.0.0` is an `AF_INET` socket and only ever sees IPv4, while
/// `[::]` is dual-stack on every platform we support and sees both.
pub(crate) fn listener_addr_matches(configured: SocketAddr, local: SocketAddr) -> bool {
    if configured.port() != local.port() {
        return false;
    }

    let cfg_ip = canonical_ip(configured.ip());
    let local_ip = canonical_ip(local.ip());

    if cfg_ip == local_ip {
        return true;
    }

    match cfg_ip {
        IpAddr::V6(v6) if v6.is_unspecified() => true,
        IpAddr::V4(v4) if v4.is_unspecified() => local_ip.is_ipv4(),
        _ => false,
    }
}

/// The listener a connection with local address `local` arrived on.
///
/// Concrete binds take precedence over wildcard binds on the same port, so a
/// config that pairs `127.0.0.1:8080` with `0.0.0.0:8080` resolves loopback
/// traffic to the specific listener. Listeners whose address does not parse are
/// skipped rather than panicking; validation rejects those at load time, so this
/// only guards a config that bypassed it.
pub(crate) fn listener_for_addr(
    listeners: &[ListenerConfig],
    local: SocketAddr,
) -> Option<&ListenerConfig> {
    let mut wildcard = None;

    for listener in listeners {
        let Ok(configured) = listener.address.parse::<SocketAddr>() else {
            continue;
        };
        if !listener_addr_matches(configured, local) {
            continue;
        }
        if configured.ip().is_unspecified() {
            wildcard.get_or_insert(listener);
        } else {
            return Some(listener);
        }
    }

    wildcard
}

/// Namespace route matchers indexed by the listener they belong to.
///
/// Split by bind kind so the common case stays a hash lookup: concrete binds
/// resolve in `exact`, and only a miss falls through to the wildcard scan, which
/// is bounded by the number of wildcard-bound namespaced listeners (typically
/// one or two).
#[derive(Default)]
pub(crate) struct ListenerMatchers {
    /// Concrete binds, keyed by canonicalized address.
    exact: HashMap<SocketAddr, Arc<RouteMatcher>>,
    /// Wildcard binds, in config order. No `getsockname()` result ever equals
    /// one of these, so they can only be resolved by [`listener_addr_matches`].
    wildcard: Vec<(SocketAddr, Arc<RouteMatcher>)>,
}

impl ListenerMatchers {
    /// Register `matcher` for the listener bound to `address`.
    ///
    /// Returns `false` if `address` does not parse, in which case nothing is
    /// registered.
    pub(crate) fn insert(&mut self, address: &str, matcher: Arc<RouteMatcher>) -> bool {
        let Ok(addr) = address.parse::<SocketAddr>() else {
            return false;
        };
        if addr.ip().is_unspecified() {
            self.wildcard.push((addr, matcher));
        } else {
            self.exact.insert(canonical_addr(addr), matcher);
        }
        true
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.exact.len() + self.wildcard.len()
    }

    /// Matcher for a connection whose local address is `local`, if its listener
    /// is bound to a namespace route set.
    ///
    /// Concrete binds win over wildcard binds on the same port.
    pub(crate) fn get(&self, local: SocketAddr) -> Option<&Arc<RouteMatcher>> {
        if let Some(matcher) = self.exact.get(&canonical_addr(local)) {
            return Some(matcher);
        }
        self.wildcard
            .iter()
            .find(|(configured, _)| listener_addr_matches(*configured, local))
            .map(|(_, matcher)| matcher)
    }

    /// Whether a listener bound to `address` is registered. Test/introspection
    /// helper: this compares the *configured* address, not a local address.
    #[cfg(test)]
    pub(crate) fn contains_configured(&self, address: &str) -> bool {
        let Ok(addr) = address.parse::<SocketAddr>() else {
            return false;
        };
        if addr.ip().is_unspecified() {
            self.wildcard.iter().any(|(cfg, _)| *cfg == addr)
        } else {
            self.exact.contains_key(&canonical_addr(addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two connections from one client are one rate-limit key; two clients
    /// are two. The key used to be "" for everyone (#518 verification).
    #[test]
    fn client_ip_is_the_bare_canonical_peer_address() {
        assert_eq!(client_ip_string(addr("192.0.2.1:50000")), "192.0.2.1");
        assert_eq!(
            client_ip_string(addr("192.0.2.1:50000")),
            client_ip_string(addr("192.0.2.1:50001"))
        );
        assert_ne!(
            client_ip_string(addr("127.0.0.1:50000")),
            client_ip_string(addr("[::1]:50000"))
        );
        assert_eq!(client_ip_string(addr("[::ffff:192.0.2.1]:1")), "192.0.2.1");
        assert_eq!(client_ip_string(addr("[2001:db8::1]:443")), "2001:db8::1");
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("test address parses")
    }

    #[test]
    fn concrete_bind_matches_only_itself() {
        assert!(listener_addr_matches(
            addr("127.0.0.1:9000"),
            addr("127.0.0.1:9000")
        ));
        assert!(!listener_addr_matches(
            addr("127.0.0.1:9000"),
            addr("203.0.113.5:9000")
        ));
    }

    #[test]
    fn port_must_always_agree() {
        assert!(!listener_addr_matches(
            addr("0.0.0.0:443"),
            addr("203.0.113.5:8443")
        ));
        assert!(!listener_addr_matches(addr("[::]:443"), addr("[::1]:8443")));
    }

    /// The regression: a `0.0.0.0` bind is reported by `getsockname()` as the
    /// concrete interface the connection landed on.
    #[test]
    fn ipv4_wildcard_matches_any_ipv4_local_addr() {
        for local in ["203.0.113.5:443", "127.0.0.1:443", "10.0.0.7:443"] {
            assert!(
                listener_addr_matches(addr("0.0.0.0:443"), addr(local)),
                "0.0.0.0:443 should match {local}"
            );
        }
    }

    #[test]
    fn ipv4_wildcard_does_not_match_ipv6_local_addr() {
        assert!(!listener_addr_matches(
            addr("0.0.0.0:443"),
            addr("[2001:db8::1]:443")
        ));
    }

    #[test]
    fn ipv6_wildcard_is_dual_stack() {
        assert!(listener_addr_matches(
            addr("[::]:443"),
            addr("[2001:db8::1]:443")
        ));
        // Dual-stack sockets report IPv4 peers in mapped form...
        assert!(listener_addr_matches(
            addr("[::]:443"),
            addr("[::ffff:203.0.113.5]:443")
        ));
        // ...and plain IPv4 must resolve identically.
        assert!(listener_addr_matches(
            addr("[::]:443"),
            addr("203.0.113.5:443")
        ));
    }

    #[test]
    fn ipv4_mapped_local_addr_resolves_to_concrete_ipv4_bind() {
        assert!(listener_addr_matches(
            addr("203.0.113.5:443"),
            addr("[::ffff:203.0.113.5]:443")
        ));
    }

    #[test]
    fn concrete_listener_wins_over_wildcard_on_same_port() {
        let listeners = vec![
            listener("public", "0.0.0.0:8080"),
            listener("admin", "127.0.0.1:8080"),
        ];
        assert_eq!(
            listener_for_addr(&listeners, addr("127.0.0.1:8080")).map(|l| l.id.as_str()),
            Some("admin")
        );
        assert_eq!(
            listener_for_addr(&listeners, addr("203.0.113.5:8080")).map(|l| l.id.as_str()),
            Some("public")
        );
    }

    #[test]
    fn no_listener_on_that_port_resolves_to_none() {
        let listeners = vec![listener("public", "0.0.0.0:8080")];
        assert!(listener_for_addr(&listeners, addr("203.0.113.5:9999")).is_none());
    }

    /// Validation rejects these at load time; the guard exists so a config that
    /// reached us another way degrades to "no match" instead of panicking.
    #[test]
    fn unparseable_address_is_skipped_not_panicked() {
        let mut broken = listener("broken", "127.0.0.1:8080");
        broken.address = "not-an-address".to_string();
        assert!(listener_for_addr(&[broken], addr("127.0.0.1:8080")).is_none());
    }

    fn listener(id: &str, address: &str) -> ListenerConfig {
        let kdl = format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "{id}" {{ address "{address}" }}
            }}
            routes {{
                route "r" {{
                    matches {{ path "/" }}
                    service-type "builtin"
                    builtin-handler "health"
                }}
            }}
            "#
        );
        zentinel_config::Config::from_kdl(&kdl)
            .expect("config parses")
            .listeners
            .remove(0)
    }
}
