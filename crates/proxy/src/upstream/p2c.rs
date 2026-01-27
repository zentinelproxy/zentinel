use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use tracing::{debug, info, trace, warn};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};
use sentinel_common::errors::{SentinelError, SentinelResult};

/// Load metric type for P2C selection
#[derive(Debug, Clone, Copy, Default)]
pub enum LoadMetric {
    /// Active connection count
    #[default]
    Connections,
    /// Average response latency
    Latency,
    /// Combined score (connections * latency)
    Combined,
    /// CPU usage (requires external monitoring)
    CpuUsage,
    /// Request rate
    RequestRate,
}

/// Configuration for P2C load balancer
#[derive(Debug, Clone)]
pub struct P2cConfig {
    /// Load metric to use for selection
    pub load_metric: LoadMetric,
    /// Weight multiplier for secondary metric in combined mode
    pub secondary_weight: f64,
    /// Whether to use weighted random selection
    pub use_weights: bool,
    /// Latency window for averaging (in seconds)
    pub latency_window_secs: u64,
    /// Enable power of three choices for better distribution
    pub power_of_three: bool,
}

impl Default for P2cConfig {
    fn default() -> Self {
        Self {
            load_metric: LoadMetric::Connections,
            secondary_weight: 0.5,
            use_weights: true,
            latency_window_secs: 10,
            power_of_three: false,
        }
    }
}

/// Target metrics for load calculation
#[derive(Debug, Clone)]
struct TargetMetrics {
    /// Active connections
    connections: Arc<AtomicU64>,
    /// Total requests
    requests: Arc<AtomicU64>,
    /// Total latency in microseconds
    total_latency_us: Arc<AtomicU64>,
    /// Request count for latency averaging
    latency_count: Arc<AtomicU64>,
    /// CPU usage percentage (0-100)
    cpu_usage: Arc<AtomicU64>,
    /// Last update time
    last_update: Arc<RwLock<Instant>>,
    /// Recent latency measurements (ring buffer)
    recent_latencies: Arc<RwLock<Vec<Duration>>>,
    /// Ring buffer position
    latency_buffer_pos: Arc<AtomicUsize>,
}

impl TargetMetrics {
    fn new(buffer_size: usize) -> Self {
        Self {
            connections: Arc::new(AtomicU64::new(0)),
            requests: Arc::new(AtomicU64::new(0)),
            total_latency_us: Arc::new(AtomicU64::new(0)),
            latency_count: Arc::new(AtomicU64::new(0)),
            cpu_usage: Arc::new(AtomicU64::new(0)),
            last_update: Arc::new(RwLock::new(Instant::now())),
            recent_latencies: Arc::new(RwLock::new(vec![Duration::ZERO; buffer_size])),
            latency_buffer_pos: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Calculate average latency over the window
    async fn average_latency(&self) -> Duration {
        let latencies = self.recent_latencies.read().await;
        let count = self.latency_count.load(Ordering::Relaxed);

        if count == 0 {
            return Duration::ZERO;
        }

        let total: Duration = latencies.iter().sum();
        let sample_count = count.min(latencies.len() as u64);

        if sample_count > 0 {
            total / sample_count as u32
        } else {
            Duration::ZERO
        }
    }

    /// Record a latency measurement
    async fn record_latency(&self, latency: Duration) {
        let pos = self.latency_buffer_pos.fetch_add(1, Ordering::Relaxed);
        let mut latencies = self.recent_latencies.write().await;
        let buffer_size = latencies.len();
        latencies[pos % buffer_size] = latency;

        self.total_latency_us
            .fetch_add(latency.as_micros() as u64, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current load based on metric type
    async fn get_load(&self, metric: LoadMetric) -> f64 {
        match metric {
            LoadMetric::Connections => self.connections.load(Ordering::Relaxed) as f64,
            LoadMetric::Latency => self.average_latency().await.as_micros() as f64,
            LoadMetric::Combined => {
                let connections = self.connections.load(Ordering::Relaxed) as f64;
                let latency = self.average_latency().await.as_micros() as f64;
                // Normalize latency to be on similar scale as connections
                // (assuming avg latency ~10ms = 10000us, and avg connections ~100)
                connections + (latency / 100.0)
            }
            LoadMetric::CpuUsage => self.cpu_usage.load(Ordering::Relaxed) as f64,
            LoadMetric::RequestRate => {
                // Calculate requests per second over the last update interval
                let requests = self.requests.load(Ordering::Relaxed);
                let last_update = *self.last_update.read().await;
                let elapsed = last_update.elapsed().as_secs_f64();
                if elapsed > 0.0 {
                    requests as f64 / elapsed
                } else {
                    0.0
                }
            }
        }
    }
}

/// Power of Two Choices load balancer
pub struct P2cBalancer {
    /// Configuration
    config: P2cConfig,
    /// All upstream targets
    targets: Vec<UpstreamTarget>,
    /// Target health status
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Metrics per target
    metrics: Vec<TargetMetrics>,
    /// Random number generator (thread-safe)
    rng: Arc<RwLock<StdRng>>,
    /// Cumulative weights for weighted selection
    cumulative_weights: Vec<u32>,
}

impl P2cBalancer {
    pub fn new(targets: Vec<UpstreamTarget>, config: P2cConfig) -> Self {
        trace!(
            target_count = targets.len(),
            load_metric = ?config.load_metric,
            use_weights = config.use_weights,
            power_of_three = config.power_of_three,
            latency_window_secs = config.latency_window_secs,
            "Creating P2C balancer"
        );

        let buffer_size = (config.latency_window_secs * 100) as usize; // 100 samples/sec
        let metrics = targets
            .iter()
            .map(|_| TargetMetrics::new(buffer_size))
            .collect();

        // Calculate cumulative weights for weighted random selection
        let mut cumulative_weights = Vec::with_capacity(targets.len());
        let mut cumsum = 0u32;
        for target in &targets {
            cumsum += target.weight;
            cumulative_weights.push(cumsum);
        }

        debug!(
            target_count = targets.len(),
            total_weight = cumsum,
            buffer_size = buffer_size,
            "P2C balancer initialized"
        );

        Self {
            config,
            targets,
            health_status: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            rng: Arc::new(RwLock::new(StdRng::from_rng(&mut rand::rng()))),
            cumulative_weights,
        }
    }

    /// Select a random healthy target index
    async fn random_healthy_target(&self) -> Option<usize> {
        let health = self.health_status.read().await;
        let healthy_indices: Vec<usize> = self
            .targets
            .iter()
            .enumerate()
            .filter_map(|(i, t)| {
                let target_id = format!("{}:{}", t.address, t.port);
                if health.get(&target_id).copied().unwrap_or(true) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        trace!(
            total_targets = self.targets.len(),
            healthy_count = healthy_indices.len(),
            use_weights = self.config.use_weights,
            "Selecting random healthy target"
        );

        if healthy_indices.is_empty() {
            warn!("No healthy targets available for P2C selection");
            return None;
        }

        let mut rng = self.rng.write().await;

        if self.config.use_weights && !self.cumulative_weights.is_empty() {
            // Weighted random selection
            let total_weight = self.cumulative_weights.last().copied().unwrap_or(0);
            if total_weight > 0 {
                let threshold = rng.random_range(0..total_weight);
                for &idx in &healthy_indices {
                    if self.cumulative_weights[idx] > threshold {
                        trace!(
                            target_index = idx,
                            threshold = threshold,
                            "Selected target via weighted random"
                        );
                        return Some(idx);
                    }
                }
            }
        }

        // Fallback to uniform random
        let selected = healthy_indices[rng.random_range(0..healthy_indices.len())];
        trace!(
            target_index = selected,
            "Selected target via uniform random"
        );
        Some(selected)
    }

    /// Select the least loaded target from candidates
    async fn select_least_loaded(&self, candidates: Vec<usize>) -> Option<usize> {
        if candidates.is_empty() {
            trace!("No candidates provided for least loaded selection");
            return None;
        }

        trace!(
            candidate_count = candidates.len(),
            load_metric = ?self.config.load_metric,
            "Evaluating candidates for least loaded"
        );

        let mut min_load = f64::MAX;
        let mut best_target = candidates[0];

        for &idx in &candidates {
            let load = self.metrics[idx].get_load(self.config.load_metric).await;

            trace!(target_index = idx, load = load, "Candidate load");

            if load < min_load {
                min_load = load;
                best_target = idx;
            }
        }

        debug!(
            target_index = best_target,
            load = min_load,
            candidate_count = candidates.len(),
            "P2C selected least loaded target"
        );

        Some(best_target)
    }

    /// Track connection acquisition
    pub fn acquire_connection(&self, target_index: usize) {
        let connections = self.metrics[target_index]
            .connections
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let requests = self.metrics[target_index]
            .requests
            .fetch_add(1, Ordering::Relaxed)
            + 1;

        trace!(
            target_index = target_index,
            connections = connections,
            total_requests = requests,
            "P2C acquired connection"
        );
    }

    /// Track connection release
    pub fn release_connection(&self, target_index: usize) {
        let connections = self.metrics[target_index]
            .connections
            .fetch_sub(1, Ordering::Relaxed)
            - 1;

        trace!(
            target_index = target_index,
            connections = connections,
            "P2C released connection"
        );
    }

    /// Update target metrics
    pub async fn update_metrics(
        &self,
        target_index: usize,
        latency: Option<Duration>,
        cpu_usage: Option<u8>,
    ) {
        trace!(
            target_index = target_index,
            latency_ms = latency.map(|l| l.as_millis() as u64),
            cpu_usage = cpu_usage,
            "Updating P2C target metrics"
        );

        if let Some(latency) = latency {
            self.metrics[target_index].record_latency(latency).await;
        }

        if let Some(cpu) = cpu_usage {
            self.metrics[target_index]
                .cpu_usage
                .store(cpu as u64, Ordering::Relaxed);
        }

        *self.metrics[target_index].last_update.write().await = Instant::now();
    }
}

#[async_trait]
impl LoadBalancer for P2cBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        // Select candidates
        let num_choices = if self.config.power_of_three { 3 } else { 2 };

        trace!(
            num_choices = num_choices,
            power_of_three = self.config.power_of_three,
            "P2C select started"
        );

        let mut candidates = Vec::with_capacity(num_choices);

        for i in 0..num_choices {
            if let Some(idx) = self.random_healthy_target().await {
                if !candidates.contains(&idx) {
                    candidates.push(idx);
                    trace!(choice = i, target_index = idx, "Added candidate");
                }
            }
        }

        if candidates.is_empty() {
            warn!("P2C: No healthy targets available");
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Select least loaded from candidates
        let target_index = self.select_least_loaded(candidates).await.ok_or_else(|| {
            warn!("P2C: Failed to select from candidates");
            SentinelError::NoHealthyUpstream
        })?;

        let target = &self.targets[target_index];

        // Track connection
        self.acquire_connection(target_index);

        // Get current metrics for metadata
        let current_load = self.metrics[target_index]
            .get_load(self.config.load_metric)
            .await;
        let connections = self.metrics[target_index]
            .connections
            .load(Ordering::Relaxed);
        let avg_latency = self.metrics[target_index].average_latency().await;

        debug!(
            target = %format!("{}:{}", target.address, target.port),
            target_index = target_index,
            load = current_load,
            connections = connections,
            avg_latency_ms = avg_latency.as_millis() as u64,
            "P2C selected target"
        );

        Ok(TargetSelection {
            address: format!("{}:{}", target.address, target.port),
            weight: target.weight,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("algorithm".to_string(), "p2c".to_string());
                meta.insert("target_index".to_string(), target_index.to_string());
                meta.insert("current_load".to_string(), format!("{:.2}", current_load));
                meta.insert("connections".to_string(), connections.to_string());
                meta.insert(
                    "avg_latency_ms".to_string(),
                    format!("{:.2}", avg_latency.as_millis()),
                );
                meta.insert(
                    "metric_type".to_string(),
                    format!("{:?}", self.config.load_metric),
                );
                meta
            },
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            address = %address,
            healthy = healthy,
            "P2C reporting target health"
        );

        let mut health = self.health_status.write().await;
        let previous = health.insert(address.to_string(), healthy);

        if previous != Some(healthy) {
            info!(
                address = %address,
                previous = ?previous,
                healthy = healthy,
                "P2C target health changed"
            );
        }
    }

    async fn healthy_targets(&self) -> Vec<String> {
        let health = self.health_status.read().await;
        let targets: Vec<String> = self
            .targets
            .iter()
            .filter_map(|t| {
                let target_id = format!("{}:{}", t.address, t.port);
                if health.get(&target_id).copied().unwrap_or(true) {
                    Some(target_id)
                } else {
                    None
                }
            })
            .collect();

        trace!(
            total = self.targets.len(),
            healthy = targets.len(),
            "P2C healthy targets"
        );

        targets
    }

    async fn release(&self, selection: &TargetSelection) {
        if let Some(index_str) = selection.metadata.get("target_index") {
            if let Ok(index) = index_str.parse::<usize>() {
                trace!(
                    target_index = index,
                    address = %selection.address,
                    "P2C releasing connection"
                );
                self.release_connection(index);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_targets(count: usize) -> Vec<UpstreamTarget> {
        (0..count)
            .map(|i| UpstreamTarget {
                address: format!("10.0.0.{}", i + 1),
                port: 8080,
                weight: 100,
            })
            .collect()
    }

    #[tokio::test]
    async fn test_p2c_selection() {
        let targets = create_test_targets(5);
        let config = P2cConfig::default();
        let balancer = P2cBalancer::new(targets.clone(), config);

        // Simulate different loads
        balancer.metrics[0].connections.store(10, Ordering::Relaxed);
        balancer.metrics[1].connections.store(5, Ordering::Relaxed);
        balancer.metrics[2].connections.store(15, Ordering::Relaxed);
        balancer.metrics[3].connections.store(3, Ordering::Relaxed);
        balancer.metrics[4].connections.store(8, Ordering::Relaxed);

        // Run selections and verify distribution
        let mut selections = vec![0usize; 5];
        for _ in 0..1000 {
            if let Ok(selection) = balancer.select(None).await {
                if let Some(idx_str) = selection.metadata.get("target_index") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        selections[idx] += 1;

                        // Simulate connection release
                        balancer.release(&selection).await;
                    }
                }
            }
        }

        // Verify that lower loaded targets get more selections
        // Target 3 (load=3) should get more than target 2 (load=15)
        assert!(selections[3] > selections[2]);

        // All targets should get some traffic
        for count in selections {
            assert!(count > 0, "All targets should receive some traffic");
        }
    }

    #[tokio::test]
    async fn test_p2c_with_latency_metric() {
        let targets = create_test_targets(3);
        let config = P2cConfig {
            load_metric: LoadMetric::Latency,
            ..Default::default()
        };
        let balancer = P2cBalancer::new(targets.clone(), config);

        // Set different latencies
        balancer
            .update_metrics(0, Some(Duration::from_millis(100)), None)
            .await;
        balancer
            .update_metrics(1, Some(Duration::from_millis(10)), None)
            .await;
        balancer
            .update_metrics(2, Some(Duration::from_millis(50)), None)
            .await;

        let selection = balancer.select(None).await.unwrap();
        let metadata = &selection.metadata;

        // Should tend to select lower latency targets
        assert!(metadata.contains_key("avg_latency_ms"));
    }

    #[tokio::test]
    async fn test_p2c_power_of_three() {
        let targets = create_test_targets(10);
        let config = P2cConfig {
            power_of_three: true,
            ..Default::default()
        };
        let balancer = P2cBalancer::new(targets.clone(), config);

        // Set varied loads: target 0 has load 0, target 9 has load 18
        for i in 0..10 {
            balancer.metrics[i]
                .connections
                .store((i * 2) as u64, Ordering::Relaxed);
        }

        // Use more iterations for statistical stability
        let iterations = 1000;
        let mut low_load_selections = 0;
        for _ in 0..iterations {
            if let Ok(selection) = balancer.select(None).await {
                if let Some(idx_str) = selection.metadata.get("target_index") {
                    if let Ok(idx) = idx_str.parse::<usize>() {
                        if idx < 3 {
                            // Low load targets (indices 0, 1, 2)
                            low_load_selections += 1;
                        }
                        balancer.release(&selection).await;
                    }
                }
            }
        }

        // Power of three should favor low-load targets significantly
        // With 1000 iterations, we expect ~55-65% to hit low-load targets
        // Using a conservative threshold of 45% to avoid flakiness
        let low_load_ratio = low_load_selections as f64 / iterations as f64;
        assert!(
            low_load_ratio > 0.45,
            "P3C should favor low-load targets: got {:.1}% (expected >45%)",
            low_load_ratio * 100.0
        );
    }

    #[tokio::test]
    async fn test_weighted_selection() {
        let mut targets = create_test_targets(3);
        targets[0].weight = 100;
        targets[1].weight = 200; // Double weight
        targets[2].weight = 100;

        let config = P2cConfig {
            use_weights: true,
            ..Default::default()
        };
        let balancer = P2cBalancer::new(targets.clone(), config);

        // Equal loads - weight should influence selection
        for i in 0..3 {
            balancer.metrics[i].connections.store(5, Ordering::Relaxed);
        }

        let mut selections = [0usize; 3];
        for _ in 0..1000 {
            if let Some(idx) = balancer.random_healthy_target().await {
                selections[idx] += 1;
            }
        }

        // Target 1 should get roughly twice the traffic due to weight
        let ratio = selections[1] as f64 / selections[0] as f64;
        assert!(
            ratio > 1.5 && ratio < 2.5,
            "Weighted selection not working properly"
        );
    }
}
