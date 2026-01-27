//! Deterministic Subsetting load balancer
//!
//! For very large clusters (1000+ backends), maintaining connections to all
//! backends is expensive. Deterministic subsetting limits each proxy instance
//! to a subset of backends while ensuring:
//!
//! 1. Each backend gets roughly equal traffic across all proxies
//! 2. The subset is stable (same proxy always uses same subset)
//! 3. Subset membership is deterministic (based on proxy ID)
//!
//! The algorithm uses consistent hashing to assign backends to subsets,
//! ensuring minimal disruption when backends are added or removed.
//!
//! Reference: https://sre.google/sre-book/load-balancing-datacenter/

use async_trait::async_trait;
use rand::seq::IndexedRandom;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};
use xxhash_rust::xxh3::xxh3_64;

use sentinel_common::errors::{SentinelError, SentinelResult};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};

/// Configuration for Deterministic Subsetting
#[derive(Debug, Clone)]
pub struct SubsetConfig {
    /// Number of backends in each subset (default: 10)
    /// Smaller subsets reduce connection overhead but may impact load distribution
    pub subset_size: usize,
    /// Unique identifier for this proxy instance
    /// Used to deterministically select which subset this proxy uses
    pub proxy_id: String,
    /// Inner load balancing algorithm for selecting within the subset
    pub inner_algorithm: SubsetInnerAlgorithm,
}

impl Default for SubsetConfig {
    fn default() -> Self {
        Self {
            subset_size: 10,
            // Default to a random proxy ID (each instance gets unique subset)
            proxy_id: format!("proxy-{}", rand::random::<u32>()),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        }
    }
}

/// Inner algorithm for selecting within the subset
#[derive(Debug, Clone, Copy, Default)]
pub enum SubsetInnerAlgorithm {
    /// Round-robin within subset (default)
    #[default]
    RoundRobin,
    /// Random selection within subset
    Random,
    /// Least connections within subset
    LeastConnections,
}

/// Deterministic Subsetting load balancer
pub struct SubsetBalancer {
    /// Full list of all targets (for subset calculation)
    all_targets: Vec<UpstreamTarget>,
    /// Current subset of targets for this proxy
    subset: Arc<RwLock<Vec<UpstreamTarget>>>,
    /// Round-robin counter for inner algorithm
    current: AtomicUsize,
    /// Connection counts per target (for least connections)
    connections: Arc<RwLock<HashMap<String, usize>>>,
    /// Health status per target
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Configuration
    config: SubsetConfig,
}

impl SubsetBalancer {
    /// Create a new Subset balancer
    pub fn new(targets: Vec<UpstreamTarget>, config: SubsetConfig) -> Self {
        let mut health_status = HashMap::new();
        let mut connections = HashMap::new();

        for target in &targets {
            let addr = target.full_address();
            health_status.insert(addr.clone(), true);
            connections.insert(addr, 0);
        }

        let subset = Self::compute_subset(&targets, &config);

        info!(
            total_targets = targets.len(),
            subset_size = subset.len(),
            proxy_id = %config.proxy_id,
            algorithm = "deterministic_subset",
            "Created subset balancer"
        );

        for target in &subset {
            debug!(
                target = %target.full_address(),
                proxy_id = %config.proxy_id,
                "Target included in subset"
            );
        }

        Self {
            all_targets: targets,
            subset: Arc::new(RwLock::new(subset)),
            current: AtomicUsize::new(0),
            connections: Arc::new(RwLock::new(connections)),
            health_status: Arc::new(RwLock::new(health_status)),
            config,
        }
    }

    /// Compute the subset of targets for this proxy instance
    fn compute_subset(targets: &[UpstreamTarget], config: &SubsetConfig) -> Vec<UpstreamTarget> {
        if targets.is_empty() {
            return Vec::new();
        }

        let subset_size = config.subset_size.min(targets.len());

        // Hash each target to get a score relative to this proxy
        let mut scored_targets: Vec<_> = targets
            .iter()
            .map(|t| {
                let score = Self::subset_score(&t.full_address(), &config.proxy_id);
                (t.clone(), score)
            })
            .collect();

        // Sort by score and take the top N
        scored_targets.sort_by_key(|(_, score)| *score);
        scored_targets
            .into_iter()
            .take(subset_size)
            .map(|(t, _)| t)
            .collect()
    }

    /// Calculate a deterministic score for a target-proxy pair
    /// Lower scores mean the target is "closer" to this proxy
    fn subset_score(target_addr: &str, proxy_id: &str) -> u64 {
        // Combine target and proxy identifiers
        let combined = format!("{}:{}", target_addr, proxy_id);
        xxh3_64(combined.as_bytes())
    }

    /// Rebuild subset when health changes significantly
    async fn rebuild_subset_if_needed(&self) {
        let health = self.health_status.read().await;
        let current_subset = self.subset.read().await;

        // Count healthy targets in current subset
        let healthy_in_subset = current_subset
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .count();

        drop(current_subset);
        drop(health);

        // If less than half the subset is healthy, try to rebuild
        if healthy_in_subset < self.config.subset_size / 2 {
            self.rebuild_subset().await;
        }
    }

    /// Rebuild the subset considering health status
    async fn rebuild_subset(&self) {
        let health = self.health_status.read().await;

        // Get all healthy targets
        let healthy_targets: Vec<_> = self
            .all_targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .cloned()
            .collect();

        drop(health);

        if healthy_targets.is_empty() {
            // Keep current subset as fallback
            return;
        }

        // Recompute subset from healthy targets
        let new_subset = Self::compute_subset(&healthy_targets, &self.config);

        info!(
            new_subset_size = new_subset.len(),
            healthy_total = healthy_targets.len(),
            proxy_id = %self.config.proxy_id,
            algorithm = "deterministic_subset",
            "Rebuilt subset from healthy targets"
        );

        let mut subset = self.subset.write().await;
        *subset = new_subset;
    }

    /// Select using inner algorithm
    async fn select_from_subset<'a>(
        &self,
        healthy: &[&'a UpstreamTarget],
    ) -> Option<&'a UpstreamTarget> {
        if healthy.is_empty() {
            return None;
        }

        match self.config.inner_algorithm {
            SubsetInnerAlgorithm::RoundRobin => {
                let idx = self.current.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(healthy[idx])
            }
            SubsetInnerAlgorithm::Random => {
                use rand::seq::SliceRandom;
                let mut rng = rand::rng();
                healthy.choose(&mut rng).copied()
            }
            SubsetInnerAlgorithm::LeastConnections => {
                let conns = self.connections.read().await;
                healthy
                    .iter()
                    .min_by_key(|t| conns.get(&t.full_address()).copied().unwrap_or(0))
                    .copied()
            }
        }
    }
}

#[async_trait]
impl LoadBalancer for SubsetBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!(
            total_targets = self.all_targets.len(),
            algorithm = "deterministic_subset",
            "Selecting upstream target"
        );

        // Check if we need to rebuild subset
        self.rebuild_subset_if_needed().await;

        let health = self.health_status.read().await;
        let subset = self.subset.read().await;

        // Get healthy targets from our subset
        let healthy_subset: Vec<_> = subset
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();

        drop(health);

        if healthy_subset.is_empty() {
            warn!(
                subset_size = subset.len(),
                total_targets = self.all_targets.len(),
                proxy_id = %self.config.proxy_id,
                algorithm = "deterministic_subset",
                "No healthy targets in subset"
            );
            drop(subset);
            return Err(SentinelError::NoHealthyUpstream);
        }

        let target = self
            .select_from_subset(&healthy_subset)
            .await
            .ok_or(SentinelError::NoHealthyUpstream)?;

        // Track connections if using least connections
        if matches!(
            self.config.inner_algorithm,
            SubsetInnerAlgorithm::LeastConnections
        ) {
            let mut conns = self.connections.write().await;
            *conns.entry(target.full_address()).or_insert(0) += 1;
        }

        trace!(
            selected_target = %target.full_address(),
            subset_size = subset.len(),
            healthy_count = healthy_subset.len(),
            proxy_id = %self.config.proxy_id,
            algorithm = "deterministic_subset",
            "Selected target from subset"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn release(&self, selection: &TargetSelection) {
        if matches!(
            self.config.inner_algorithm,
            SubsetInnerAlgorithm::LeastConnections
        ) {
            let mut conns = self.connections.write().await;
            if let Some(count) = conns.get_mut(&selection.address) {
                *count = count.saturating_sub(1);
            }
        }
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        let prev_health = {
            let health = self.health_status.read().await;
            *health.get(address).unwrap_or(&true)
        };

        trace!(
            target = %address,
            healthy = healthy,
            prev_healthy = prev_health,
            algorithm = "deterministic_subset",
            "Updating target health status"
        );

        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);

        // If health changed, consider rebuilding subset
        if prev_health != healthy {
            self.rebuild_subset_if_needed().await;
        }
    }

    async fn healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(addr, &healthy)| if healthy { Some(addr.clone()) } else { None })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_targets(count: usize) -> Vec<UpstreamTarget> {
        (0..count)
            .map(|i| UpstreamTarget::new(format!("backend-{}", i), 8080, 100))
            .collect()
    }

    #[test]
    fn test_subset_size_limited() {
        let targets = make_targets(100);
        let config = SubsetConfig {
            subset_size: 10,
            proxy_id: "test-proxy".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };

        let balancer = SubsetBalancer::new(targets, config);
        let subset = balancer.subset.blocking_read();
        assert_eq!(subset.len(), 10);
    }

    #[test]
    fn test_subset_deterministic() {
        let targets = make_targets(50);
        let config1 = SubsetConfig {
            subset_size: 10,
            proxy_id: "proxy-a".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };
        let config2 = SubsetConfig {
            subset_size: 10,
            proxy_id: "proxy-a".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };

        let balancer1 = SubsetBalancer::new(targets.clone(), config1);
        let balancer2 = SubsetBalancer::new(targets, config2);

        let subset1: Vec<_> = balancer1
            .subset
            .blocking_read()
            .iter()
            .map(|t| t.full_address())
            .collect();
        let subset2: Vec<_> = balancer2
            .subset
            .blocking_read()
            .iter()
            .map(|t| t.full_address())
            .collect();

        // Same proxy ID should get same subset
        assert_eq!(subset1, subset2);
    }

    #[test]
    fn test_different_proxies_get_different_subsets() {
        let targets = make_targets(50);
        let config1 = SubsetConfig {
            subset_size: 10,
            proxy_id: "proxy-a".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };
        let config2 = SubsetConfig {
            subset_size: 10,
            proxy_id: "proxy-b".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };

        let balancer1 = SubsetBalancer::new(targets.clone(), config1);
        let balancer2 = SubsetBalancer::new(targets, config2);

        let subset1: Vec<_> = balancer1
            .subset
            .blocking_read()
            .iter()
            .map(|t| t.full_address())
            .collect();
        let subset2: Vec<_> = balancer2
            .subset
            .blocking_read()
            .iter()
            .map(|t| t.full_address())
            .collect();

        // Different proxy IDs should (very likely) get different subsets
        assert_ne!(subset1, subset2);
    }

    #[tokio::test]
    async fn test_selects_from_subset_only() {
        let targets = make_targets(50);
        let config = SubsetConfig {
            subset_size: 5,
            proxy_id: "test-proxy".to_string(),
            inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
        };

        let balancer = SubsetBalancer::new(targets, config);

        // Get the subset addresses
        let subset_addrs: Vec<_> = balancer
            .subset
            .read()
            .await
            .iter()
            .map(|t| t.full_address())
            .collect();

        // All selections should be from the subset
        for _ in 0..20 {
            let selection = balancer.select(None).await.unwrap();
            assert!(
                subset_addrs.contains(&selection.address),
                "Selected {} which is not in subset {:?}",
                selection.address,
                subset_addrs
            );
        }
    }

    #[test]
    fn test_even_distribution_across_proxies() {
        // With many proxies, each backend should be selected by roughly
        // (num_proxies * subset_size / num_backends) proxies
        let targets = make_targets(100);
        let num_proxies = 100;
        let subset_size = 10;

        let mut backend_counts: HashMap<String, usize> = HashMap::new();

        for i in 0..num_proxies {
            let config = SubsetConfig {
                subset_size,
                proxy_id: format!("proxy-{}", i),
                inner_algorithm: SubsetInnerAlgorithm::RoundRobin,
            };

            // Use compute_subset directly to avoid async/blocking issues
            let subset = SubsetBalancer::compute_subset(&targets, &config);

            for target in subset.iter() {
                *backend_counts.entry(target.full_address()).or_insert(0) += 1;
            }
        }

        // Each backend should be selected by roughly 10 proxies (100 * 10 / 100)
        let expected = (num_proxies * subset_size) / targets.len();

        // Verify no backend is completely starved or overwhelmed
        // With consistent hashing, some variance is expected
        let min_count = *backend_counts.values().min().unwrap_or(&0);
        let max_count = *backend_counts.values().max().unwrap_or(&0);

        // All backends should be selected at least once
        assert!(min_count > 0, "Some backends were never selected");

        // No backend should receive more than 3x the expected traffic
        assert!(
            max_count <= expected * 3,
            "Backend received too much traffic: {} (expected ~{})",
            max_count,
            expected
        );

        // The distribution should not be wildly skewed
        // Standard deviation should be reasonable
        let mean = (num_proxies * subset_size) as f64 / targets.len() as f64;
        let variance: f64 = backend_counts
            .values()
            .map(|&c| (c as f64 - mean).powi(2))
            .sum::<f64>()
            / targets.len() as f64;
        let std_dev = variance.sqrt();

        // Standard deviation should be less than the mean (coefficient of variation < 1)
        assert!(
            std_dev < mean,
            "Distribution too uneven: std_dev={:.2}, mean={:.2}",
            std_dev,
            mean
        );
    }
}
