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
use parking_lot::RwLock;
use pingora_load_balancing::{discovery::ServiceDiscovery, Backend};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

/// Health check discovery that probes what the pools route to.
///
/// Falls back to the configured targets until a pool has published its set.
pub(crate) struct ViewDiscovery {
    pub(crate) view: Arc<ActiveHealthView>,
    pub(crate) configured: BTreeSet<Backend>,
    pub(crate) weights: HashMap<String, usize>,
}

#[async_trait]
impl ServiceDiscovery for ViewDiscovery {
    async fn discover(&self) -> pingora_core::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let Some(targets) = self.view.targets() else {
            return Ok((self.configured.clone(), HashMap::new()));
        };
        let backends = targets
            .iter()
            .filter_map(|address| {
                let weight = self.weights.get(address).copied().unwrap_or(1);
                Backend::new_with_weight(address, weight).ok()
            })
            .collect();
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
