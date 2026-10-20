//! Resolution of `host:port` upstream targets on the request path.
//!
//! A target that is a socket address (`10.0.0.1:8080`, `[::1]:80`) never comes
//! here: the pool parses it and connects to it as before. A hostname target
//! used to be resolved with the blocking `ToSocketAddrs` on every request,
//! inside the async request path, which stalled a worker thread for the
//! duration of each DNS lookup; and only the first address it resolved to was
//! ever dialled, so `localhost` (`::1` first) failed every request to a
//! backend that only listens on IPv4.
//!
//! [`TargetResolver`] fixes both:
//!
//! - **Resolution** goes through `tokio::net::lookup_host` (the system
//!   resolver on the blocking pool, never a worker thread) and is cached per
//!   target. An answer younger than [`REFRESH_AFTER`] is used as is; an older
//!   one is still used while a background task refreshes it, so a request
//!   only ever waits for DNS when a name has no usable answer at all (first
//!   use, or no successful lookup for [`EXPIRE_AFTER`]).
//! - **Address choice**: an address that refused or timed out a connection is
//!   held back for [`CONNECT_FAILURE_HOLD`], and the next address of the name
//!   is used instead. [`TargetResolver::connect_failed`] tells the caller
//!   whether such an address exists, which `fail_to_connect` uses to retry
//!   the request on it, so the request that found the dead address does not
//!   fail either.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tracing::{debug, warn};

/// How old an answer may get before it is refreshed in the background.
pub(crate) const REFRESH_AFTER: Duration = Duration::from_secs(5);

/// How long an answer is still used while refreshes keep failing. After this
/// a request waits for a fresh lookup and fails if that fails.
pub(crate) const EXPIRE_AFTER: Duration = Duration::from_secs(60);

/// How long an address that failed to connect is passed over in favour of
/// the other addresses of its name.
pub(crate) const CONNECT_FAILURE_HOLD: Duration = Duration::from_secs(30);

/// Upper bound on one lookup.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve `host:port` through the system resolver without blocking the
/// calling thread. Duplicate addresses are dropped, order is kept, and an
/// empty answer is an error.
pub(crate) async fn lookup(address: &str, timeout: Duration) -> io::Result<Vec<SocketAddr>> {
    match tokio::time::timeout(timeout, tokio::net::lookup_host(address)).await {
        Ok(Ok(addrs)) => {
            let mut unique: Vec<SocketAddr> = Vec::new();
            for addr in addrs {
                if !unique.contains(&addr) {
                    unique.push(addr);
                }
            }
            if unique.is_empty() {
                Err(io::Error::other("no addresses"))
            } else {
                Ok(unique)
            }
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "resolution timed out",
        )),
    }
}

struct Entry {
    addrs: Arc<[SocketAddr]>,
    resolved_at: Instant,
    refreshing: bool,
}

/// Per-pool cache of hostname resolutions and of addresses that recently
/// failed to connect. Shared by the pools a discovery refresh replaces.
#[derive(Default)]
pub struct TargetResolver {
    hosts: Mutex<HashMap<String, Entry>>,
    /// Address -> until when it is passed over.
    failed: Mutex<HashMap<SocketAddr, Instant>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl TargetResolver {
    /// The addresses `target` (`host:port`) resolves to, in resolver order.
    pub async fn resolve(self: &Arc<Self>, target: &str) -> io::Result<Arc<[SocketAddr]>> {
        {
            let mut hosts = locked(&self.hosts);
            if let Some(entry) = hosts.get_mut(target) {
                let age = entry.resolved_at.elapsed();
                if age < REFRESH_AFTER {
                    return Ok(entry.addrs.clone());
                }
                if age < EXPIRE_AFTER {
                    if !entry.refreshing {
                        entry.refreshing = true;
                        let resolver = Arc::clone(self);
                        let target = target.to_string();
                        tokio::spawn(async move { resolver.refresh(&target).await });
                    }
                    return Ok(entry.addrs.clone());
                }
            }
        }

        // Nothing usable: this request has to wait for the answer.
        let addrs: Arc<[SocketAddr]> = lookup(target, LOOKUP_TIMEOUT).await?.into();
        self.store(target, addrs.clone());
        Ok(addrs)
    }

    async fn refresh(&self, target: &str) {
        match lookup(target, LOOKUP_TIMEOUT).await {
            Ok(addrs) => self.store(target, addrs.into()),
            Err(e) => {
                warn!(
                    target = %target,
                    error = %e,
                    "Re-resolving upstream target failed; using the previous answer"
                );
                if let Some(entry) = locked(&self.hosts).get_mut(target) {
                    entry.refreshing = false;
                }
            }
        }
    }

    pub(crate) fn store(&self, target: &str, addrs: Arc<[SocketAddr]>) {
        locked(&self.hosts).insert(
            target.to_string(),
            Entry {
                addrs,
                resolved_at: Instant::now(),
                refreshing: false,
            },
        );
    }

    /// Which of `addrs` to connect to.
    ///
    /// The first address that is neither held unhealthy by the active health
    /// check (`unhealthy`) nor recently failed to connect; failing that, the
    /// first one the health check does not hold unhealthy; failing that, the
    /// first. `None` only for an empty slice.
    pub fn choose(
        &self,
        addrs: &[SocketAddr],
        unhealthy: impl Fn(&SocketAddr) -> bool,
    ) -> Option<SocketAddr> {
        let now = Instant::now();
        let failed = locked(&self.failed);
        let held = |addr: &SocketAddr| failed.get(addr).is_some_and(|until| *until > now);
        addrs
            .iter()
            .find(|addr| !unhealthy(addr) && !held(addr))
            .or_else(|| addrs.iter().find(|addr| !unhealthy(addr)))
            .or_else(|| addrs.first())
            .copied()
    }

    /// Record that connecting to `addr` failed.
    ///
    /// Only addresses a hostname target resolved to are tracked: an IP
    /// literal target has no other address to fall back to. Returns whether
    /// a name `addr` belongs to has another address that is not held back,
    /// i.e. whether retrying the request would try somewhere new.
    pub fn connect_failed(&self, addr: SocketAddr) -> bool {
        let hosts = locked(&self.hosts);
        let mut names = hosts
            .values()
            .filter(|entry| entry.addrs.contains(&addr))
            .peekable();
        if names.peek().is_none() {
            return false;
        }

        let now = Instant::now();
        let mut failed = locked(&self.failed);
        failed.retain(|_, until| *until > now);
        failed.insert(addr, now + CONNECT_FAILURE_HOLD);
        let alternative =
            names.any(|entry| entry.addrs.iter().any(|other| !failed.contains_key(other)));
        debug!(
            address = %addr,
            hold_secs = CONNECT_FAILURE_HOLD.as_secs(),
            alternative,
            "Upstream address failed to connect; passing it over"
        );
        alternative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn resolves_without_blocking_and_caches() {
        let resolver = Arc::new(TargetResolver::default());
        let first = resolver.resolve("localhost:19530").await.expect("resolves");
        assert!(first
            .iter()
            .all(|a| a.port() == 19530 && a.ip().is_loopback()));
        let second = resolver.resolve("localhost:19530").await.expect("cached");
        assert!(
            Arc::ptr_eq(&first, &second),
            "second call did not hit the cache"
        );
    }

    #[tokio::test]
    async fn an_unresolvable_name_is_an_error() {
        let resolver = Arc::new(TargetResolver::default());
        assert!(resolver.resolve("does-not-exist.invalid:80").await.is_err());
    }

    /// The current-thread runtime is the one `block_in_place` panics on; the
    /// resolver, including its background refresh, must work there.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_answer_is_used_while_refreshing() {
        let resolver = Arc::new(TargetResolver::default());
        let stale: Arc<[SocketAddr]> = vec![addr("192.0.2.1:19531")].into();
        resolver.hosts.lock().unwrap().insert(
            "localhost:19531".to_string(),
            Entry {
                addrs: stale.clone(),
                resolved_at: Instant::now() - REFRESH_AFTER - Duration::from_millis(1),
                refreshing: false,
            },
        );
        let got = resolver
            .resolve("localhost:19531")
            .await
            .expect("stale answer");
        assert!(
            Arc::ptr_eq(&got, &stale),
            "a stale answer must not wait for DNS"
        );

        // The refresh runs in the background and replaces it.
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let fresh = resolver.resolve("localhost:19531").await.unwrap();
            if fresh.iter().all(|a| a.ip().is_loopback()) {
                return;
            }
        }
        panic!("the background refresh never replaced the stale answer");
    }

    #[tokio::test]
    async fn an_expired_answer_is_resolved_again() {
        let resolver = Arc::new(TargetResolver::default());
        resolver.hosts.lock().unwrap().insert(
            "localhost:19532".to_string(),
            Entry {
                addrs: vec![addr("192.0.2.1:19532")].into(),
                resolved_at: Instant::now() - EXPIRE_AFTER,
                refreshing: false,
            },
        );
        let got = resolver.resolve("localhost:19532").await.unwrap();
        assert!(got.iter().all(|a| a.ip().is_loopback()));
    }

    #[test]
    fn choose_skips_failed_then_unhealthy_addresses() {
        let resolver = TargetResolver::default();
        let v6 = addr("[::1]:19533");
        let v4 = addr("127.0.0.1:19533");
        resolver.store("localhost:19533", vec![v6, v4].into());

        assert_eq!(resolver.choose(&[v6, v4], |_| false), Some(v6));

        // ::1 refuses: retrying makes sense, and it is passed over.
        assert!(resolver.connect_failed(v6));
        assert_eq!(resolver.choose(&[v6, v4], |_| false), Some(v4));

        // Both failed: nothing new to retry on, fall back to the first.
        assert!(!resolver.connect_failed(v4));
        assert_eq!(resolver.choose(&[v6, v4], |_| false), Some(v6));

        // The health check still has the last word over passive marks.
        assert_eq!(resolver.choose(&[v6, v4], |a| *a == v6), Some(v4));
        assert_eq!(resolver.choose(&[], |_| false), None);
    }

    #[test]
    fn a_failure_hold_expires() {
        let resolver = TargetResolver::default();
        let v6 = addr("[::1]:19534");
        let v4 = addr("127.0.0.1:19534");
        resolver.store("localhost:19534", vec![v6, v4].into());
        resolver
            .failed
            .lock()
            .unwrap()
            .insert(v6, Instant::now() - Duration::from_millis(1));
        assert_eq!(resolver.choose(&[v6, v4], |_| false), Some(v6));
    }

    #[test]
    fn ip_literal_targets_are_not_tracked() {
        let resolver = TargetResolver::default();
        assert!(!resolver.connect_failed(addr("127.0.0.1:19535")));
        assert!(resolver.failed.lock().unwrap().is_empty());
    }
}
