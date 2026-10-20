//! The shared result of active health checking for one upstream.
//!
//! An [`ActiveHealthView`] sits between the health checker and the upstream
//! pools that serve the same upstream:
//!
//! - The checker writes probe results into it after every cycle.
//! - Every pool for that upstream reads it before selecting a target and
//!   pushes changes into its load balancer, which is what takes an unhealthy
//!   target out of rotation for every algorithm.
//! - Pools publish their current target set into it, so the checker probes
//!   the targets the pool actually routes to -- including ones that came from
//!   service discovery -- rather than only the statically configured ones.
//!
//! Views are keyed by upstream id and outlive both sides: a reload rebuilds
//! pools and may restart the checker, a discovery refresh rebuilds pools, and
//! global upstreams are served from two registries. All of them share the one
//! view, so a new pool starts from what the checker already knows instead of
//! treating every target as healthy until the next probe.

use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use pingora_load_balancing::{discovery::ServiceDiscovery, Backend};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Probe results and the probed target set for one upstream.
#[derive(Debug, Default)]
pub struct ActiveHealthView {
    /// Address -> healthy, for every address the checker has reported on.
    /// An address absent from the map is healthy.
    health: RwLock<HashMap<String, bool>>,
    /// The targets the pools route to (`host:port`), as last published.
    targets: RwLock<Option<Vec<String>>>,
    /// Bumped whenever `health` changes, so a pool can tell cheaply whether
    /// it has anything to apply.
    generation: AtomicU64,
}

impl ActiveHealthView {
    /// A view with no results: every target healthy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Changes whenever any recorded health status changes.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Whether the checker currently considers `address` unhealthy.
    pub fn is_unhealthy(&self, address: &str) -> bool {
        self.health.read().get(address) == Some(&false)
    }

    /// Every recorded status.
    pub fn snapshot(&self) -> Vec<(String, bool)> {
        self.health
            .read()
            .iter()
            .map(|(a, h)| (a.clone(), *h))
            .collect()
    }

    /// Record the result of a probe cycle.
    pub fn record<I>(&self, statuses: I)
    where
        I: IntoIterator<Item = (String, bool)>,
    {
        let mut health = self.health.write();
        let mut changed = false;
        for (address, healthy) in statuses {
            if health.insert(address, healthy) != Some(healthy) {
                changed = true;
            }
        }
        if changed {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Forget all results: every target healthy again.
    ///
    /// Recorded addresses are flipped to healthy rather than removed, so a
    /// pool that applies the change re-admits a target it had taken out.
    pub fn reset(&self) {
        let mut health = self.health.write();
        let mut changed = false;
        for healthy in health.values_mut() {
            if !*healthy {
                *healthy = true;
                changed = true;
            }
        }
        if changed {
            self.generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Publish the targets the pools route to.
    pub fn publish_targets(&self, targets: Vec<String>) {
        *self.targets.write() = Some(targets);
    }

    /// The targets last published by a pool, if any pool has published.
    pub fn targets(&self) -> Option<Vec<String>> {
        self.targets.read().clone()
    }
}

/// What the last probe cycle resolved a hostname target to.
#[derive(Debug, Default)]
pub(crate) struct HostResolution {
    /// The addresses the name resolved to, all of which were probed. Empty
    /// while resolution is failing.
    pub(crate) addrs: Vec<std::net::SocketAddr>,
    /// Consecutive cycles in which the name did not resolve.
    pub(crate) failures: u32,
}

/// Hostname target (`host:port`) -> its current resolution.
pub(crate) type HostResolutions = Arc<Mutex<HashMap<String, HostResolution>>>;

/// Health check discovery that probes what the pools route to.
///
/// Falls back to the configured targets until a pool has published its set.
///
/// Pingora's `Backend` needs a socket address, so a hostname target
/// (`backend.internal:80`) used to be dropped here -- never probed, never in
/// the view, and so always treated as healthy. Hostnames are now resolved and
/// every address they resolve to is probed; [`ViewDiscovery::host_statuses`]
/// folds those results back into one status per hostname target, which is
/// the key the pools look up.
///
/// Resolution happens in `discover`, which the checker calls at the start of
/// every probe cycle. Re-resolving per cycle follows DNS changes (a service
/// moving, a record with several addresses rotating) with the same staleness
/// as the health results themselves; the request path keeps its own answer
/// for at most a few seconds before refreshing it (see
/// `upstream::resolve`), so the two disagree only briefly after a change.
/// The cost is one lookup per hostname per interval, through the system
/// resolver and its cache.
pub(crate) struct ViewDiscovery {
    pub(crate) view: Arc<ActiveHealthView>,
    /// Configured target addresses (`host:port`), probed until a pool
    /// publishes its own set.
    pub(crate) configured: Vec<String>,
    pub(crate) weights: HashMap<String, usize>,
    /// Shared with the checker, which reads it after each cycle.
    pub(crate) resolutions: HostResolutions,
    /// Bounds each lookup, so a hanging resolver delays a cycle by at most
    /// this much rather than stalling probing altogether.
    pub(crate) resolve_timeout: Duration,
}

impl ViewDiscovery {
    /// Resolve `address` if it is `host:port` rather than a socket address.
    /// `None` means it is a socket address already.
    async fn resolve(&self, address: &str) -> Option<std::io::Result<Vec<std::net::SocketAddr>>> {
        if address.parse::<std::net::SocketAddr>().is_ok() {
            return None;
        }
        Some(crate::upstream::resolve::lookup(address, self.resolve_timeout).await)
    }

    /// One status per hostname target, from the probe results of the
    /// addresses it resolved to.
    ///
    /// A hostname is healthy while **any** of its addresses is: taking the
    /// whole name out because one of several replicas behind it is down would
    /// throw away the healthy ones, and the request path connects to a
    /// healthy address when there is one (see `UpstreamPool::create_peer`).
    ///
    /// A name that does not resolve has nothing to probe. The request path
    /// cannot connect to it either, so once it has failed to resolve for
    /// `unhealthy_threshold` consecutive cycles it is reported unhealthy;
    /// before that its last status stands, so one lost DNS answer does not
    /// take a target out.
    pub(crate) fn host_statuses(
        resolutions: &Mutex<HashMap<String, HostResolution>>,
        probed: &HashMap<String, bool>,
        unhealthy_threshold: u32,
    ) -> Vec<(String, bool)> {
        resolutions
            .lock()
            .iter()
            .filter_map(|(host, resolution)| {
                if resolution.addrs.is_empty() {
                    (resolution.failures >= unhealthy_threshold.max(1))
                        .then(|| (host.clone(), false))
                } else {
                    let healthy = resolution
                        .addrs
                        .iter()
                        .any(|a| probed.get(&a.to_string()).copied().unwrap_or(true));
                    Some((host.clone(), healthy))
                }
            })
            .collect()
    }
}

#[async_trait]
impl ServiceDiscovery for ViewDiscovery {
    async fn discover(&self) -> pingora_core::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let targets = self
            .view
            .targets()
            .unwrap_or_else(|| self.configured.clone());

        let mut backends = BTreeSet::new();
        let mut resolved: HashMap<String, std::io::Result<Vec<std::net::SocketAddr>>> =
            HashMap::new();
        for address in &targets {
            let weight = self.weights.get(address).copied().unwrap_or(1);
            match self.resolve(address).await {
                None => {
                    if let Ok(backend) = Backend::new_with_weight(address, weight) {
                        backends.insert(backend);
                    }
                }
                Some(Ok(addrs)) => {
                    for addr in &addrs {
                        if let Ok(backend) = Backend::new_with_weight(&addr.to_string(), weight) {
                            backends.insert(backend);
                        }
                    }
                    resolved.insert(address.clone(), Ok(addrs));
                }
                Some(Err(e)) => {
                    resolved.insert(address.clone(), Err(e));
                }
            }
        }

        // Rebuilt from the current targets, so a hostname that is no longer
        // routed to stops being reported.
        let mut resolutions = self.resolutions.lock();
        let mut next = HashMap::with_capacity(resolved.len());
        for (host, result) in resolved {
            let previous = resolutions.remove(&host).unwrap_or_default();
            let entry = match result {
                Ok(addrs) => HostResolution { addrs, failures: 0 },
                Err(e) => {
                    warn!(
                        target = %host,
                        error = %e,
                        "Failed to resolve health check target"
                    );
                    HostResolution {
                        addrs: Vec::new(),
                        failures: previous.failures.saturating_add(1),
                    }
                }
            };
            next.insert(host, entry);
        }
        *resolutions = next;

        Ok((backends, HashMap::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_moves_only_on_change() {
        let view = ActiveHealthView::new();
        let g0 = view.generation();
        view.record([("10.0.0.1:80".to_string(), true)]);
        let g1 = view.generation();
        assert_ne!(g0, g1);
        view.record([("10.0.0.1:80".to_string(), true)]);
        assert_eq!(view.generation(), g1);
        view.record([("10.0.0.1:80".to_string(), false)]);
        assert!(view.is_unhealthy("10.0.0.1:80"));
        assert!(view.generation() > g1);
    }

    #[test]
    fn reset_readmits_unhealthy_targets() {
        let view = ActiveHealthView::new();
        view.record([("10.0.0.1:80".to_string(), false)]);
        view.reset();
        assert!(!view.is_unhealthy("10.0.0.1:80"));
        assert_eq!(view.snapshot(), vec![("10.0.0.1:80".to_string(), true)]);
    }
}
