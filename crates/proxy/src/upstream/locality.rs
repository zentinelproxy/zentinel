//! Locality-aware load balancer
//!
//! Prefers targets in the same zone/region as the proxy, falling back to
//! other zones when local targets are unhealthy or overloaded. Useful for
//! multi-region deployments to minimize latency and cross-zone traffic costs.

use async_trait::async_trait;
use rand::seq::IndexedRandom;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use sentinel_common::errors::{SentinelError, SentinelResult};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};

/// Configuration for locality-aware load balancing
#[derive(Debug, Clone)]
pub struct LocalityAwareConfig {
    /// The local zone/region identifier for this proxy instance
    pub local_zone: String,
    /// Fallback strategy when no local targets are healthy
    pub fallback_strategy: LocalityFallback,
    /// Minimum healthy local targets before considering fallback
    pub min_local_healthy: usize,
    /// Whether to use weighted selection within a zone
    pub use_weights: bool,
    /// Zone priority order for fallback (closest first)
    /// If empty, all non-local zones are treated equally
    pub zone_priority: Vec<String>,
}

impl Default for LocalityAwareConfig {
    fn default() -> Self {
        Self {
            local_zone: std::env::var("SENTINEL_ZONE")
                .or_else(|_| std::env::var("ZONE"))
                .or_else(|_| std::env::var("REGION"))
                .unwrap_or_else(|_| "default".to_string()),
            fallback_strategy: LocalityFallback::RoundRobin,
            min_local_healthy: 1,
            use_weights: true,
            zone_priority: Vec::new(),
        }
    }
}

/// Fallback strategy when local targets are unavailable
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalityFallback {
    /// Round-robin across fallback targets
    RoundRobin,
    /// Random selection from fallback targets
    Random,
    /// Fail immediately if no local targets
    FailLocal,
}

/// Target with zone information
#[derive(Debug, Clone)]
struct ZonedTarget {
    target: UpstreamTarget,
    zone: String,
}

/// Locality-aware load balancer
pub struct LocalityAwareBalancer {
    /// All targets with zone information
    targets: Vec<ZonedTarget>,
    /// Health status per target address
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Round-robin counter for local zone
    local_counter: AtomicUsize,
    /// Round-robin counter for fallback
    fallback_counter: AtomicUsize,
    /// Configuration
    config: LocalityAwareConfig,
}

impl LocalityAwareBalancer {
    /// Create a new locality-aware balancer
    ///
    /// Zone information is extracted from target addresses using the format:
    /// - `zone:host:port` - explicit zone prefix
    /// - Or via target metadata (weight field encodes zone in high bits)
    /// - Or defaults to "unknown" zone
    pub fn new(targets: Vec<UpstreamTarget>, config: LocalityAwareConfig) -> Self {
        let mut health_status = HashMap::new();
        let mut zoned_targets = Vec::with_capacity(targets.len());

        for target in targets {
            health_status.insert(target.full_address(), true);

            // Extract zone from address if it contains zone prefix
            // Format: "zone:host:port" or just "host:port"
            let (zone, actual_target) = Self::parse_zone_from_target(&target);

            zoned_targets.push(ZonedTarget {
                target: actual_target,
                zone,
            });
        }

        debug!(
            local_zone = %config.local_zone,
            total_targets = zoned_targets.len(),
            local_targets = zoned_targets.iter().filter(|t| t.zone == config.local_zone).count(),
            "Created locality-aware balancer"
        );

        Self {
            targets: zoned_targets,
            health_status: Arc::new(RwLock::new(health_status)),
            local_counter: AtomicUsize::new(0),
            fallback_counter: AtomicUsize::new(0),
            config,
        }
    }

    /// Parse zone from target address
    ///
    /// Supports formats:
    /// - `zone=us-west-1,host:port` - zone in metadata prefix
    /// - `us-west-1/host:port` - zone as path prefix
    /// - `host:port` - no zone, defaults to "unknown"
    fn parse_zone_from_target(target: &UpstreamTarget) -> (String, UpstreamTarget) {
        let addr = &target.address;

        // Check for zone= prefix (e.g., "zone=us-west-1,10.0.0.1")
        if let Some(rest) = addr.strip_prefix("zone=") {
            if let Some((zone, host)) = rest.split_once(',') {
                return (
                    zone.to_string(),
                    UpstreamTarget::new(host, target.port, target.weight),
                );
            }
        }

        // Check for zone/ prefix (e.g., "us-west-1/10.0.0.1")
        if let Some((zone, host)) = addr.split_once('/') {
            // Ensure it's not an IP with port
            if !zone.contains(':') && !zone.contains('.') {
                return (
                    zone.to_string(),
                    UpstreamTarget::new(host, target.port, target.weight),
                );
            }
        }

        // No zone prefix, return as-is with unknown zone
        ("unknown".to_string(), target.clone())
    }

    /// Get healthy targets in a specific zone
    async fn healthy_in_zone(&self, zone: &str) -> Vec<&ZonedTarget> {
        let health = self.health_status.read().await;
        self.targets
            .iter()
            .filter(|t| {
                t.zone == zone && *health.get(&t.target.full_address()).unwrap_or(&true)
            })
            .collect()
    }

    /// Get all healthy targets not in the local zone, sorted by priority
    async fn healthy_fallback(&self) -> Vec<&ZonedTarget> {
        let health = self.health_status.read().await;
        let local_zone = &self.config.local_zone;

        let mut fallback: Vec<_> = self
            .targets
            .iter()
            .filter(|t| {
                t.zone != *local_zone && *health.get(&t.target.full_address()).unwrap_or(&true)
            })
            .collect();

        // Sort by zone priority if specified
        if !self.config.zone_priority.is_empty() {
            fallback.sort_by(|a, b| {
                let priority_a = self
                    .config
                    .zone_priority
                    .iter()
                    .position(|z| z == &a.zone)
                    .unwrap_or(usize::MAX);
                let priority_b = self
                    .config
                    .zone_priority
                    .iter()
                    .position(|z| z == &b.zone)
                    .unwrap_or(usize::MAX);
                priority_a.cmp(&priority_b)
            });
        }

        fallback
    }

    /// Select from targets using round-robin
    fn select_round_robin<'a>(
        &self,
        targets: &[&'a ZonedTarget],
        counter: &AtomicUsize,
    ) -> Option<&'a ZonedTarget> {
        if targets.is_empty() {
            return None;
        }

        if self.config.use_weights {
            // Weighted round-robin
            let total_weight: u32 = targets.iter().map(|t| t.target.weight).sum();
            if total_weight == 0 {
                return targets.first().copied();
            }

            let idx = counter.fetch_add(1, Ordering::Relaxed);
            let mut weight_idx = (idx as u32) % total_weight;

            for target in targets {
                if weight_idx < target.target.weight {
                    return Some(target);
                }
                weight_idx -= target.target.weight;
            }

            targets.first().copied()
        } else {
            let idx = counter.fetch_add(1, Ordering::Relaxed) % targets.len();
            Some(targets[idx])
        }
    }

    /// Select from targets using random selection
    fn select_random<'a>(&self, targets: &[&'a ZonedTarget]) -> Option<&'a ZonedTarget> {
        use rand::seq::SliceRandom;

        if targets.is_empty() {
            return None;
        }

        let mut rng = rand::rng();
        targets.choose(&mut rng).copied()
    }
}

#[async_trait]
impl LoadBalancer for LocalityAwareBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!(
            total_targets = self.targets.len(),
            local_zone = %self.config.local_zone,
            algorithm = "locality_aware",
            "Selecting upstream target"
        );

        // First, try local zone
        let local_healthy = self.healthy_in_zone(&self.config.local_zone).await;

        if local_healthy.len() >= self.config.min_local_healthy {
            // Use local targets
            let selected = self
                .select_round_robin(&local_healthy, &self.local_counter)
                .ok_or(SentinelError::NoHealthyUpstream)?;

            trace!(
                selected_target = %selected.target.full_address(),
                zone = %selected.zone,
                local_healthy = local_healthy.len(),
                algorithm = "locality_aware",
                "Selected local target"
            );

            return Ok(TargetSelection {
                address: selected.target.full_address(),
                weight: selected.target.weight,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("zone".to_string(), selected.zone.clone());
                    m.insert("locality".to_string(), "local".to_string());
                    m
                },
            });
        }

        // Not enough local targets, check fallback strategy
        match self.config.fallback_strategy {
            LocalityFallback::FailLocal => {
                warn!(
                    local_zone = %self.config.local_zone,
                    local_healthy = local_healthy.len(),
                    min_required = self.config.min_local_healthy,
                    algorithm = "locality_aware",
                    "No healthy local targets and fallback disabled"
                );
                return Err(SentinelError::NoHealthyUpstream);
            }
            LocalityFallback::RoundRobin | LocalityFallback::Random => {
                // Fall back to remote zones
            }
        }

        // Get fallback targets (sorted by zone priority)
        let fallback_targets = self.healthy_fallback().await;

        // If we have some local targets, combine them with fallback
        let all_targets: Vec<&ZonedTarget> = if !local_healthy.is_empty() {
            // Local first, then fallback
            local_healthy
                .into_iter()
                .chain(fallback_targets.into_iter())
                .collect()
        } else {
            fallback_targets
        };

        if all_targets.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "locality_aware",
                "No healthy upstream targets available"
            );
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Select based on fallback strategy
        let selected = match self.config.fallback_strategy {
            LocalityFallback::RoundRobin => {
                self.select_round_robin(&all_targets, &self.fallback_counter)
            }
            LocalityFallback::Random => self.select_random(&all_targets),
            LocalityFallback::FailLocal => unreachable!(),
        }
        .ok_or(SentinelError::NoHealthyUpstream)?;

        let is_local = selected.zone == self.config.local_zone;
        debug!(
            selected_target = %selected.target.full_address(),
            zone = %selected.zone,
            is_local = is_local,
            fallback_used = !is_local,
            algorithm = "locality_aware",
            "Selected target (fallback path)"
        );

        Ok(TargetSelection {
            address: selected.target.full_address(),
            weight: selected.target.weight,
            metadata: {
                let mut m = HashMap::new();
                m.insert("zone".to_string(), selected.zone.clone());
                m.insert(
                    "locality".to_string(),
                    if is_local { "local" } else { "remote" }.to_string(),
                );
                m
            },
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "locality_aware",
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

    fn make_zoned_targets() -> Vec<UpstreamTarget> {
        vec![
            // Local zone (us-west-1)
            UpstreamTarget::new("zone=us-west-1,10.0.0.1", 8080, 100),
            UpstreamTarget::new("zone=us-west-1,10.0.0.2", 8080, 100),
            // Remote zone (us-east-1)
            UpstreamTarget::new("zone=us-east-1,10.1.0.1", 8080, 100),
            UpstreamTarget::new("zone=us-east-1,10.1.0.2", 8080, 100),
            // Another remote zone (eu-west-1)
            UpstreamTarget::new("zone=eu-west-1,10.2.0.1", 8080, 100),
        ]
    }

    #[test]
    fn test_zone_parsing() {
        // Test zone= prefix
        let target = UpstreamTarget::new("zone=us-west-1,10.0.0.1", 8080, 100);
        let (zone, parsed) = LocalityAwareBalancer::parse_zone_from_target(&target);
        assert_eq!(zone, "us-west-1");
        assert_eq!(parsed.address, "10.0.0.1");

        // Test zone/ prefix
        let target = UpstreamTarget::new("us-east-1/10.0.0.1", 8080, 100);
        let (zone, parsed) = LocalityAwareBalancer::parse_zone_from_target(&target);
        assert_eq!(zone, "us-east-1");
        assert_eq!(parsed.address, "10.0.0.1");

        // Test no zone
        let target = UpstreamTarget::new("10.0.0.1", 8080, 100);
        let (zone, parsed) = LocalityAwareBalancer::parse_zone_from_target(&target);
        assert_eq!(zone, "unknown");
        assert_eq!(parsed.address, "10.0.0.1");
    }

    #[tokio::test]
    async fn test_prefers_local_zone() {
        let targets = make_zoned_targets();
        let config = LocalityAwareConfig {
            local_zone: "us-west-1".to_string(),
            ..Default::default()
        };
        let balancer = LocalityAwareBalancer::new(targets, config);

        // All selections should be from local zone
        for _ in 0..10 {
            let selection = balancer.select(None).await.unwrap();
            assert!(
                selection.address.starts_with("10.0.0."),
                "Expected local target, got {}",
                selection.address
            );
            assert_eq!(selection.metadata.get("locality").unwrap(), "local");
        }
    }

    #[tokio::test]
    async fn test_fallback_when_local_unhealthy() {
        let targets = make_zoned_targets();
        let config = LocalityAwareConfig {
            local_zone: "us-west-1".to_string(),
            min_local_healthy: 1,
            ..Default::default()
        };
        let balancer = LocalityAwareBalancer::new(targets, config);

        // Mark local targets as unhealthy
        balancer.report_health("10.0.0.1:8080", false).await;
        balancer.report_health("10.0.0.2:8080", false).await;

        // Should now use fallback targets
        let selection = balancer.select(None).await.unwrap();
        assert!(
            !selection.address.starts_with("10.0.0."),
            "Expected fallback target, got {}",
            selection.address
        );
        assert_eq!(selection.metadata.get("locality").unwrap(), "remote");
    }

    #[tokio::test]
    async fn test_zone_priority() {
        let targets = make_zoned_targets();
        let config = LocalityAwareConfig {
            local_zone: "us-west-1".to_string(),
            min_local_healthy: 1,
            zone_priority: vec!["us-east-1".to_string(), "eu-west-1".to_string()],
            ..Default::default()
        };
        let balancer = LocalityAwareBalancer::new(targets, config);

        // Mark local targets as unhealthy
        balancer.report_health("10.0.0.1:8080", false).await;
        balancer.report_health("10.0.0.2:8080", false).await;

        // Should prefer us-east-1 over eu-west-1
        let selection = balancer.select(None).await.unwrap();
        assert!(
            selection.address.starts_with("10.1.0."),
            "Expected us-east-1 target, got {}",
            selection.address
        );
    }

    #[tokio::test]
    async fn test_fail_local_strategy() {
        let targets = make_zoned_targets();
        let config = LocalityAwareConfig {
            local_zone: "us-west-1".to_string(),
            fallback_strategy: LocalityFallback::FailLocal,
            ..Default::default()
        };
        let balancer = LocalityAwareBalancer::new(targets, config);

        // Mark local targets as unhealthy
        balancer.report_health("10.0.0.1:8080", false).await;
        balancer.report_health("10.0.0.2:8080", false).await;

        // Should fail
        let result = balancer.select(None).await;
        assert!(result.is_err());
    }
}
