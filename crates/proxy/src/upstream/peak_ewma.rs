//! Peak EWMA load balancer
//!
//! Implements Twitter Finagle's Peak EWMA (Exponentially Weighted Moving Average)
//! algorithm. This algorithm tracks the latency of each backend using an
//! exponentially weighted moving average, and selects the backend with the
//! lowest predicted completion time.
//!
//! The "peak" aspect means we use the maximum of:
//! - Current EWMA latency
//! - Most recent observed latency (to quickly react to latency spikes)
//!
//! Reference: <https://twitter.github.io/finagle/guide/Clients.html#power-of-two-choices-p2c-least-loaded>

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use sentinel_common::errors::{SentinelError, SentinelResult};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};

/// Configuration for Peak EWMA load balancer
#[derive(Debug, Clone)]
pub struct PeakEwmaConfig {
    /// Decay time for EWMA calculation (default: 10 seconds)
    /// Lower values make the algorithm more responsive to recent latency changes
    pub decay_time: Duration,
    /// Initial latency estimate for new backends (default: 1ms)
    pub initial_latency: Duration,
    /// Penalty multiplier for backends with active connections (default: 1.5)
    /// Higher values favor backends with fewer connections
    pub load_penalty: f64,
}

impl Default for PeakEwmaConfig {
    fn default() -> Self {
        Self {
            decay_time: Duration::from_secs(10),
            initial_latency: Duration::from_millis(1),
            load_penalty: 1.5,
        }
    }
}

/// Per-target statistics for EWMA tracking
struct TargetStats {
    /// EWMA latency in nanoseconds
    ewma_ns: AtomicU64,
    /// Last observed latency in nanoseconds
    last_latency_ns: AtomicU64,
    /// Timestamp of last update (as nanos since some epoch)
    last_update_ns: AtomicU64,
    /// Number of active connections
    active_connections: AtomicU64,
    /// Epoch for relative timestamps
    epoch: Instant,
}

impl TargetStats {
    fn new(initial_latency: Duration) -> Self {
        let initial_ns = initial_latency.as_nanos() as u64;
        Self {
            ewma_ns: AtomicU64::new(initial_ns),
            last_latency_ns: AtomicU64::new(initial_ns),
            last_update_ns: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Update EWMA with a new latency observation
    fn update(&self, latency: Duration, decay_time: Duration) {
        let latency_ns = latency.as_nanos() as u64;
        let now_ns = self.epoch.elapsed().as_nanos() as u64;
        let last_update = self.last_update_ns.load(Ordering::Relaxed);

        // Calculate decay factor: e^(-elapsed / decay_time)
        let elapsed_ns = now_ns.saturating_sub(last_update);
        let decay = (-((elapsed_ns as f64) / (decay_time.as_nanos() as f64))).exp();

        // EWMA update: new_ewma = old_ewma * decay + new_value * (1 - decay)
        let old_ewma = self.ewma_ns.load(Ordering::Relaxed);
        let new_ewma = ((old_ewma as f64) * decay + (latency_ns as f64) * (1.0 - decay)) as u64;

        self.ewma_ns.store(new_ewma, Ordering::Relaxed);
        self.last_latency_ns.store(latency_ns, Ordering::Relaxed);
        self.last_update_ns.store(now_ns, Ordering::Relaxed);
    }

    /// Get the peak latency (max of EWMA and last observed)
    fn peak_latency_ns(&self) -> u64 {
        let ewma = self.ewma_ns.load(Ordering::Relaxed);
        let last = self.last_latency_ns.load(Ordering::Relaxed);
        ewma.max(last)
    }

    /// Calculate the load score (latency * (1 + active_connections * penalty))
    fn load_score(&self, load_penalty: f64) -> f64 {
        let latency = self.peak_latency_ns() as f64;
        let active = self.active_connections.load(Ordering::Relaxed) as f64;
        latency * (1.0 + active * load_penalty)
    }

    fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Peak EWMA load balancer
pub struct PeakEwmaBalancer {
    /// Original target list
    targets: Vec<UpstreamTarget>,
    /// Per-target statistics
    stats: HashMap<String, Arc<TargetStats>>,
    /// Health status per target
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Configuration
    config: PeakEwmaConfig,
}

impl PeakEwmaBalancer {
    /// Create a new Peak EWMA balancer
    pub fn new(targets: Vec<UpstreamTarget>, config: PeakEwmaConfig) -> Self {
        let mut health_status = HashMap::new();
        let mut stats = HashMap::new();

        for target in &targets {
            let addr = target.full_address();
            health_status.insert(addr.clone(), true);
            stats.insert(addr, Arc::new(TargetStats::new(config.initial_latency)));
        }

        Self {
            targets,
            stats,
            health_status: Arc::new(RwLock::new(health_status)),
            config,
        }
    }
}

#[async_trait]
impl LoadBalancer for PeakEwmaBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!(
            total_targets = self.targets.len(),
            algorithm = "peak_ewma",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;
        let healthy_targets: Vec<_> = self
            .targets
            .iter()
            .filter(|t| *health.get(&t.full_address()).unwrap_or(&true))
            .collect();
        drop(health);

        if healthy_targets.is_empty() {
            warn!(
                total_targets = self.targets.len(),
                algorithm = "peak_ewma",
                "No healthy upstream targets available"
            );
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Find target with lowest load score
        let mut best_target = None;
        let mut best_score = f64::MAX;

        for target in &healthy_targets {
            let addr = target.full_address();
            if let Some(stats) = self.stats.get(&addr) {
                let score = stats.load_score(self.config.load_penalty);
                trace!(
                    target = %addr,
                    score = score,
                    ewma_ns = stats.ewma_ns.load(Ordering::Relaxed),
                    active_connections = stats.active_connections.load(Ordering::Relaxed),
                    "Evaluating target load score"
                );
                if score < best_score {
                    best_score = score;
                    best_target = Some(target);
                }
            }
        }

        let target = best_target.ok_or(SentinelError::NoHealthyUpstream)?;

        // Increment active connections for selected target
        if let Some(stats) = self.stats.get(&target.full_address()) {
            stats.increment_connections();
        }

        trace!(
            selected_target = %target.full_address(),
            load_score = best_score,
            healthy_count = healthy_targets.len(),
            algorithm = "peak_ewma",
            "Selected target via Peak EWMA"
        );

        Ok(TargetSelection {
            address: target.full_address(),
            weight: target.weight,
            metadata: HashMap::new(),
        })
    }

    async fn release(&self, selection: &TargetSelection) {
        if let Some(stats) = self.stats.get(&selection.address) {
            stats.decrement_connections();
            trace!(
                target = %selection.address,
                active_connections = stats.active_connections.load(Ordering::Relaxed),
                algorithm = "peak_ewma",
                "Released connection"
            );
        }
    }

    async fn report_result(
        &self,
        selection: &TargetSelection,
        success: bool,
        latency: Option<Duration>,
    ) {
        // Release the connection
        self.release(selection).await;

        // Update EWMA if we have latency data
        if let Some(latency) = latency {
            if let Some(stats) = self.stats.get(&selection.address) {
                stats.update(latency, self.config.decay_time);
                trace!(
                    target = %selection.address,
                    latency_ms = latency.as_millis(),
                    new_ewma_ns = stats.ewma_ns.load(Ordering::Relaxed),
                    algorithm = "peak_ewma",
                    "Updated EWMA latency"
                );
            }
        }

        // Update health if request failed
        if !success {
            self.report_health(&selection.address, false).await;
        }
    }

    async fn report_result_with_latency(
        &self,
        address: &str,
        success: bool,
        latency: Option<Duration>,
    ) {
        // Update EWMA if we have latency data
        if let Some(latency) = latency {
            if let Some(stats) = self.stats.get(address) {
                stats.update(latency, self.config.decay_time);
                debug!(
                    target = %address,
                    latency_ms = latency.as_millis(),
                    new_ewma_ns = stats.ewma_ns.load(Ordering::Relaxed),
                    algorithm = "peak_ewma",
                    "Updated EWMA latency via report_result_with_latency"
                );
            }
        }

        // Update health
        self.report_health(address, success).await;
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "peak_ewma",
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

    fn make_targets(count: usize) -> Vec<UpstreamTarget> {
        (0..count)
            .map(|i| UpstreamTarget::new(format!("backend-{}", i), 8080, 100))
            .collect()
    }

    #[tokio::test]
    async fn test_selects_lowest_latency() {
        let targets = make_targets(3);
        let balancer = PeakEwmaBalancer::new(targets, PeakEwmaConfig::default());

        // Simulate different latencies for each backend
        let addr0 = "backend-0:8080".to_string();
        let addr1 = "backend-1:8080".to_string();
        let addr2 = "backend-2:8080".to_string();

        // Update latencies: backend-1 has lowest
        balancer
            .stats
            .get(&addr0)
            .unwrap()
            .update(Duration::from_millis(100), Duration::from_secs(10));
        balancer
            .stats
            .get(&addr1)
            .unwrap()
            .update(Duration::from_millis(10), Duration::from_secs(10));
        balancer
            .stats
            .get(&addr2)
            .unwrap()
            .update(Duration::from_millis(50), Duration::from_secs(10));

        // Should select backend-1 (lowest latency)
        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, addr1);
    }

    #[tokio::test]
    async fn test_considers_active_connections() {
        let targets = make_targets(2);
        let balancer = PeakEwmaBalancer::new(targets, PeakEwmaConfig::default());

        let addr0 = "backend-0:8080".to_string();
        let addr1 = "backend-1:8080".to_string();

        // Same latency, but backend-0 has active connections
        balancer
            .stats
            .get(&addr0)
            .unwrap()
            .update(Duration::from_millis(10), Duration::from_secs(10));
        balancer
            .stats
            .get(&addr1)
            .unwrap()
            .update(Duration::from_millis(10), Duration::from_secs(10));

        // Add active connections to backend-0
        for _ in 0..5 {
            balancer.stats.get(&addr0).unwrap().increment_connections();
        }

        // Should select backend-1 (no active connections)
        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, addr1);
    }

    #[tokio::test]
    async fn test_ewma_decay() {
        let targets = make_targets(1);
        let config = PeakEwmaConfig {
            decay_time: Duration::from_millis(100),
            initial_latency: Duration::from_millis(50), // Start with 50ms
            load_penalty: 1.5,
        };
        let balancer = PeakEwmaBalancer::new(targets, config);

        let addr = "backend-0:8080".to_string();
        let stats = balancer.stats.get(&addr).unwrap();

        // Wait a bit so the first update has some elapsed time
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Update with high latency
        stats.update(Duration::from_millis(100), Duration::from_millis(100));
        let after_high = stats.ewma_ns.load(Ordering::Relaxed);

        // Wait for decay and update with low latency
        tokio::time::sleep(Duration::from_millis(200)).await;
        stats.update(Duration::from_millis(10), Duration::from_millis(100));
        let after_low = stats.ewma_ns.load(Ordering::Relaxed);

        // After the low latency update (with significant decay time),
        // the EWMA should move toward the low value
        // decay = e^(-200/100) = e^(-2) ≈ 0.135
        // new_ewma ≈ old * 0.135 + 10ms * 0.865 ≈ mostly 10ms
        let low_latency_ns = Duration::from_millis(10).as_nanos() as u64;
        let high_latency_ns = Duration::from_millis(100).as_nanos() as u64;

        // The after_low value should be between low and high, closer to low
        assert!(
            after_low < high_latency_ns,
            "EWMA after low update ({}) should be less than high latency ({})",
            after_low,
            high_latency_ns
        );
        assert!(
            after_low > low_latency_ns,
            "EWMA after low update ({}) should be greater than low latency ({}) due to some carry-over",
            after_low,
            low_latency_ns
        );
    }

    #[tokio::test]
    async fn test_connection_tracking() {
        let targets = make_targets(1);
        let balancer = PeakEwmaBalancer::new(targets, PeakEwmaConfig::default());

        // Select increments connections
        let selection = balancer.select(None).await.unwrap();
        let stats = balancer.stats.get(&selection.address).unwrap();
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 1);

        // Release decrements connections
        balancer.release(&selection).await;
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
    }
}
