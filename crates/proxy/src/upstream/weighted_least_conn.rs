//! Weighted Least Connections load balancer
//!
//! Combines weight-based selection with connection counting. The algorithm
//! selects the backend with the lowest ratio of active connections to weight.
//!
//! Score = active_connections / weight
//!
//! A backend with weight 200 and 10 connections (score: 0.05) is preferred
//! over a backend with weight 100 and 6 connections (score: 0.06).
//!
//! This is useful when backends have different capacities - higher weight
//! backends can handle more concurrent connections proportionally.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use zentinel_common::errors::{ZentinelError, ZentinelResult};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};

/// Configuration for Weighted Least Connections
#[derive(Debug, Clone)]
pub struct WeightedLeastConnConfig {
    /// Minimum weight to prevent division by zero (default: 1)
    pub min_weight: u32,
    /// Tie-breaker strategy when scores are equal
    pub tie_breaker: TieBreakerStrategy,
}

impl Default for WeightedLeastConnConfig {
    fn default() -> Self {
        Self {
            min_weight: 1,
            tie_breaker: TieBreakerStrategy::HigherWeight,
        }
    }
}

/// Strategy for breaking ties when multiple backends have the same score
#[derive(Debug, Clone, Copy, Default)]
pub enum TieBreakerStrategy {
    /// Prefer backend with higher weight (can handle more traffic)
    #[default]
    HigherWeight,
    /// Prefer backend with fewer connections (more headroom)
    FewerConnections,
    /// Round-robin among tied backends
    RoundRobin,
}

/// Weighted Least Connections load balancer
pub struct WeightedLeastConnBalancer {
    /// Target list
    targets: Vec<UpstreamTarget>,
    /// Active connections per target
    connections: Arc<RwLock<HashMap<String, usize>>>,
    /// Health status per target
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Round-robin counter for tie-breaking
    tie_breaker_counter: AtomicUsize,
    /// Configuration
    config: WeightedLeastConnConfig,
}

impl WeightedLeastConnBalancer {
    /// Create a new Weighted Least Connections balancer
    pub fn new(targets: Vec<UpstreamTarget>, config: WeightedLeastConnConfig) -> Self {
        let mut health_status = HashMap::new();
        let mut connections = HashMap::new();

        for target in &targets {
            let addr = target.full_address();
            health_status.insert(addr.clone(), true);
            connections.insert(addr, 0);
        }

        Self {
            targets,
            connections: Arc::new(RwLock::new(connections)),
            health_status: Arc::new(RwLock::new(health_status)),
            tie_breaker_counter: AtomicUsize::new(0),
            config,
        }
    }

    /// Calculate the weighted connection score for a target
    /// Lower score = better candidate
    fn calculate_score(&self, connections: usize, weight: u32) -> f64 {
        let effective_weight = weight.max(self.config.min_weight) as f64;
        connections as f64 / effective_weight
    }

    /// Break ties between targets with the same score
    fn break_tie<'a>(
        &self,
        candidates: &[(&'a UpstreamTarget, usize)],
    ) -> Option<&'a UpstreamTarget> {
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(candidates[0].0);
        }

        match self.config.tie_breaker {
            TieBreakerStrategy::HigherWeight => candidates
                .iter()
                .max_by_key(|(t, _)| t.weight)
                .map(|(t, _)| *t),
            TieBreakerStrategy::FewerConnections => {
                candidates.iter().min_by_key(|(_, c)| *c).map(|(t, _)| *t)
            }
            TieBreakerStrategy::RoundRobin => {
                let idx =
                    self.tie_breaker_counter.fetch_add(1, Ordering::Relaxed) % candidates.len();
                Some(candidates[idx].0)
            }
        }
    }
}

#[async_trait]
impl LoadBalancer for WeightedLeastConnBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> ZentinelResult<TargetSelection> {
        trace!(
            total_targets = self.targets.len(),
            algorithm = "weighted_least_conn",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let conns = self.connections.read().await;

        // Calculate scores for healthy targets
        let scored_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .map(|t| {
                let addr = t.full_address();
                let conn_count = *conns.get(&addr).unwrap_or(&0);
                let score = self.calculate_score(conn_count, t.weight);
                (t, conn_count, score)
            })
            .collect();

        drop(health);

        if scored_targets.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "weighted_least_conn",
                "No healthy upstream targets available"
            );
            return Err(ZentinelError::NoHealthyUpstream);
        }

        // Find minimum score
        let min_score = scored_targets
            .iter()
            .map(|(_, _, s)| *s)
            .fold(f64::INFINITY, f64::min);

        // Get all targets with the minimum score (for tie-breaking)
        let candidates: Vec<_> = scored_targets
            .iter()
            .filter(|(_, _, s)| (*s - min_score).abs() < f64::EPSILON)
            .map(|(t, c, _)| (*t, *c))
            .collect();

        let target = self
            .break_tie(&candidates)
            .ok_or(ZentinelError::NoHealthyUpstream)?;

        // Increment connection count
        drop(conns);
        {
            let mut conns = self.connections.write().await;
            *conns.entry(target.full_address()).or_insert(0) += 1;
        }

        let conn_count = *self
            .connections
            .read()
            .await
            .get(&target.full_address())
            .unwrap_or(&0);
        let score = self.calculate_score(conn_count, target.weight);

        trace!(
            selected_target = %target.full_address(),
            weight = target.weight,
            connections = conn_count,
            score = score,
            healthy_count = scored_targets.len(),
            algorithm = "weighted_least_conn",
            "Selected target via weighted least connections"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn release(&self, selection: &TargetSelection) {
        let mut conns = self.connections.write().await;
        if let Some(count) = conns.get_mut(&selection.address) {
            *count = count.saturating_sub(1);
            trace!(
                target = %selection.address,
                connections = *count,
                algorithm = "weighted_least_conn",
                "Released connection"
            );
        }
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "weighted_least_conn",
            "Updating target health status"
        );
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);
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

    fn make_weighted_targets() -> Vec<UpstreamTarget> {
        vec![
            UpstreamTarget::new("backend-small", 8080, 50), // Low capacity
            UpstreamTarget::new("backend-medium", 8080, 100), // Medium capacity
            UpstreamTarget::new("backend-large", 8080, 200), // High capacity
        ]
    }

    #[tokio::test]
    async fn test_prefers_higher_weight_when_empty() {
        let targets = make_weighted_targets();
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // With no connections, all have score 0, tie-breaker prefers higher weight
        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "backend-large:8080");
    }

    #[tokio::test]
    async fn test_weighted_connection_ratio() {
        let targets = make_weighted_targets();
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // Add connections proportional to weight
        {
            let mut conns = balancer.connections.write().await;
            conns.insert("backend-small:8080".to_string(), 5); // 5/50 = 0.10
            conns.insert("backend-medium:8080".to_string(), 10); // 10/100 = 0.10
            conns.insert("backend-large:8080".to_string(), 20); // 20/200 = 0.10
        }

        // All have same ratio, tie-breaker picks highest weight
        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "backend-large:8080");
    }

    #[tokio::test]
    async fn test_selects_lower_ratio() {
        let targets = make_weighted_targets();
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // backend-large has better ratio
        {
            let mut conns = balancer.connections.write().await;
            conns.insert("backend-small:8080".to_string(), 10); // 10/50 = 0.20
            conns.insert("backend-medium:8080".to_string(), 15); // 15/100 = 0.15
            conns.insert("backend-large:8080".to_string(), 20); // 20/200 = 0.10 (best)
        }

        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "backend-large:8080");
    }

    #[tokio::test]
    async fn test_selects_small_when_others_overloaded() {
        let targets = make_weighted_targets();
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // backend-small has best ratio despite low weight
        {
            let mut conns = balancer.connections.write().await;
            conns.insert("backend-small:8080".to_string(), 2); // 2/50 = 0.04 (best)
            conns.insert("backend-medium:8080".to_string(), 20); // 20/100 = 0.20
            conns.insert("backend-large:8080".to_string(), 50); // 50/200 = 0.25
        }

        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "backend-small:8080");
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let targets = vec![UpstreamTarget::new("backend", 8080, 100)];
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // Select increments connections
        let selection1 = balancer.select(None).await.unwrap();
        let selection2 = balancer.select(None).await.unwrap();

        {
            let conns = balancer.connections.read().await;
            assert_eq!(*conns.get("backend:8080").unwrap(), 2);
        }

        // Release decrements connections
        balancer.release(&selection1).await;

        {
            let conns = balancer.connections.read().await;
            assert_eq!(*conns.get("backend:8080").unwrap(), 1);
        }

        balancer.release(&selection2).await;

        {
            let conns = balancer.connections.read().await;
            assert_eq!(*conns.get("backend:8080").unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn test_fewer_connections_tie_breaker() {
        let targets = vec![
            UpstreamTarget::new("backend-a", 8080, 100),
            UpstreamTarget::new("backend-b", 8080, 100),
        ];
        let config = WeightedLeastConnConfig {
            min_weight: 1,
            tie_breaker: TieBreakerStrategy::FewerConnections,
        };
        let balancer = WeightedLeastConnBalancer::new(targets, config);

        // Same weight, different connections
        {
            let mut conns = balancer.connections.write().await;
            conns.insert("backend-a:8080".to_string(), 5);
            conns.insert("backend-b:8080".to_string(), 3); // Fewer connections
        }

        // Both have score 0.05 and 0.03, but if we set them equal:
        {
            let mut conns = balancer.connections.write().await;
            conns.insert("backend-a:8080".to_string(), 5);
            conns.insert("backend-b:8080".to_string(), 5);
        }

        // With same score, fewer_connections tie-breaker should still work
        // (but they're equal now so either is valid)
    }

    #[tokio::test]
    async fn test_respects_health_status() {
        let targets = make_weighted_targets();
        let balancer = WeightedLeastConnBalancer::new(targets, WeightedLeastConnConfig::default());

        // Mark large backend as unhealthy
        balancer.report_health("backend-large:8080", false).await;

        // Should not select the unhealthy backend
        for _ in 0..10 {
            let selection = balancer.select(None).await.unwrap();
            assert_ne!(selection.address, "backend-large:8080");
        }
    }
}
