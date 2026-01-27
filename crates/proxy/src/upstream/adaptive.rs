use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};
use sentinel_common::errors::{SentinelError, SentinelResult};

/// Configuration for adaptive load balancing
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Weight adjustment interval
    pub adjustment_interval: Duration,
    /// Minimum weight (percentage of original)
    pub min_weight_ratio: f64,
    /// Maximum weight (percentage of original)
    pub max_weight_ratio: f64,
    /// Error rate threshold for degradation
    pub error_threshold: f64,
    /// Latency threshold for degradation (p99)
    pub latency_threshold: Duration,
    /// EWMA decay factor (0.0 to 1.0, higher = more recent weight)
    pub ewma_decay: f64,
    /// Recovery rate when target improves
    pub recovery_rate: f64,
    /// Penalty rate when target degrades
    pub penalty_rate: f64,
    /// Enable circuit breaker integration
    pub circuit_breaker: bool,
    /// Minimum requests before adjusting weights
    pub min_requests: u64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            adjustment_interval: Duration::from_secs(10),
            min_weight_ratio: 0.1, // Can go down to 10% of original weight
            max_weight_ratio: 2.0, // Can go up to 200% of original weight
            error_threshold: 0.05, // 5% error rate triggers penalty
            latency_threshold: Duration::from_millis(500),
            ewma_decay: 0.8,    // Recent data weighted at 80%
            recovery_rate: 1.1, // 10% recovery per interval
            penalty_rate: 0.7,  // 30% penalty per interval
            circuit_breaker: true,
            min_requests: 100,
        }
    }
}

/// Performance metrics for a target with EWMA smoothing
#[derive(Debug, Clone)]
struct PerformanceMetrics {
    /// Total requests
    total_requests: Arc<AtomicU64>,
    /// Failed requests
    failed_requests: Arc<AtomicU64>,
    /// Sum of latencies in microseconds
    total_latency_us: Arc<AtomicU64>,
    /// Success count for latency calculation
    success_count: Arc<AtomicU64>,
    /// Active connections
    active_connections: Arc<AtomicU64>,
    /// Current effective weight
    effective_weight: Arc<RwLock<f64>>,
    /// EWMA error rate
    ewma_error_rate: Arc<RwLock<f64>>,
    /// EWMA latency in microseconds
    ewma_latency: Arc<RwLock<f64>>,
    /// Last adjustment time
    last_adjustment: Arc<RwLock<Instant>>,
    /// Consecutive successes
    consecutive_successes: Arc<AtomicU64>,
    /// Consecutive failures
    consecutive_failures: Arc<AtomicU64>,
    /// Circuit breaker state
    circuit_open: Arc<RwLock<bool>>,
    /// Last error time
    last_error: Arc<RwLock<Option<Instant>>>,
}

impl PerformanceMetrics {
    fn new(initial_weight: f64) -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            total_latency_us: Arc::new(AtomicU64::new(0)),
            success_count: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU64::new(0)),
            effective_weight: Arc::new(RwLock::new(initial_weight)),
            ewma_error_rate: Arc::new(RwLock::new(0.0)),
            ewma_latency: Arc::new(RwLock::new(0.0)),
            last_adjustment: Arc::new(RwLock::new(Instant::now())),
            consecutive_successes: Arc::new(AtomicU64::new(0)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
            circuit_open: Arc::new(RwLock::new(false)),
            last_error: Arc::new(RwLock::new(None)),
        }
    }

    /// Update EWMA values with new sample
    async fn update_ewma(&self, error_rate: f64, latency_us: f64, decay: f64) {
        let mut ewma_error = self.ewma_error_rate.write().await;
        *ewma_error = decay * error_rate + (1.0 - decay) * (*ewma_error);

        let mut ewma_lat = self.ewma_latency.write().await;
        *ewma_lat = decay * latency_us + (1.0 - decay) * (*ewma_lat);
    }

    /// Record a request result
    async fn record_result(
        &self,
        success: bool,
        latency: Option<Duration>,
        config: &AdaptiveConfig,
    ) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if success {
            self.consecutive_successes.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.store(0, Ordering::Relaxed);

            if let Some(lat) = latency {
                let lat_us = lat.as_micros() as u64;
                self.total_latency_us.fetch_add(lat_us, Ordering::Relaxed);
                self.success_count.fetch_add(1, Ordering::Relaxed);
            }

            // Check for circuit breaker recovery
            if config.circuit_breaker {
                let successes = self.consecutive_successes.load(Ordering::Relaxed);
                if successes >= 5 && *self.circuit_open.read().await {
                    *self.circuit_open.write().await = false;
                    info!(
                        "Circuit breaker closed after {} consecutive successes",
                        successes
                    );
                }
            }
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
            self.consecutive_failures.fetch_add(1, Ordering::Relaxed);
            self.consecutive_successes.store(0, Ordering::Relaxed);
            *self.last_error.write().await = Some(Instant::now());

            // Check for circuit breaker trip
            if config.circuit_breaker {
                let failures = self.consecutive_failures.load(Ordering::Relaxed);
                if failures >= 5 && !*self.circuit_open.read().await {
                    *self.circuit_open.write().await = true;
                    warn!(
                        "Circuit breaker opened after {} consecutive failures",
                        failures
                    );
                }
            }
        }
    }

    /// Calculate current error rate
    fn current_error_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        let failed = self.failed_requests.load(Ordering::Relaxed);
        failed as f64 / total as f64
    }

    /// Calculate average latency
    fn average_latency(&self) -> Duration {
        let count = self.success_count.load(Ordering::Relaxed);
        if count == 0 {
            return Duration::ZERO;
        }
        let total_us = self.total_latency_us.load(Ordering::Relaxed);
        Duration::from_micros(total_us / count)
    }

    /// Reset interval metrics
    fn reset_interval_metrics(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.failed_requests.store(0, Ordering::Relaxed);
        self.total_latency_us.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
    }
}

/// Score calculation for target selection
#[derive(Debug, Clone)]
struct TargetScore {
    index: usize,
    score: f64,
    weight: f64,
}

/// Adaptive load balancer that adjusts weights based on performance
pub struct AdaptiveBalancer {
    /// Configuration
    config: AdaptiveConfig,
    /// All upstream targets
    targets: Vec<UpstreamTarget>,
    /// Original weights (for ratio calculation)
    original_weights: Vec<f64>,
    /// Performance metrics per target
    metrics: Vec<PerformanceMetrics>,
    /// Target health status
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    /// Last global adjustment time
    last_global_adjustment: Arc<RwLock<Instant>>,
}

impl AdaptiveBalancer {
    pub fn new(targets: Vec<UpstreamTarget>, config: AdaptiveConfig) -> Self {
        trace!(
            target_count = targets.len(),
            adjustment_interval_secs = config.adjustment_interval.as_secs(),
            min_weight_ratio = config.min_weight_ratio,
            max_weight_ratio = config.max_weight_ratio,
            error_threshold = config.error_threshold,
            latency_threshold_ms = config.latency_threshold.as_millis() as u64,
            ewma_decay = config.ewma_decay,
            circuit_breaker = config.circuit_breaker,
            min_requests = config.min_requests,
            "Creating adaptive balancer"
        );

        let original_weights: Vec<f64> = targets.iter().map(|t| t.weight as f64).collect();
        let metrics = original_weights
            .iter()
            .map(|&w| PerformanceMetrics::new(w))
            .collect();

        debug!(
            target_count = targets.len(),
            total_weight = original_weights.iter().sum::<f64>(),
            "Adaptive balancer initialized"
        );

        Self {
            config,
            targets,
            original_weights,
            metrics,
            health_status: Arc::new(RwLock::new(HashMap::new())),
            last_global_adjustment: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Adjust weights based on recent performance
    async fn adjust_weights(&self) {
        let mut last_adjustment = self.last_global_adjustment.write().await;

        let elapsed = last_adjustment.elapsed();
        if elapsed < self.config.adjustment_interval {
            trace!(
                elapsed_secs = elapsed.as_secs(),
                interval_secs = self.config.adjustment_interval.as_secs(),
                "Skipping weight adjustment (interval not reached)"
            );
            return;
        }

        debug!(
            elapsed_secs = elapsed.as_secs(),
            target_count = self.targets.len(),
            "Adjusting weights based on performance metrics"
        );

        for (i, metric) in self.metrics.iter().enumerate() {
            let requests = metric.total_requests.load(Ordering::Relaxed);

            // Skip if insufficient data
            if requests < self.config.min_requests {
                continue;
            }

            // Calculate current metrics
            let error_rate = metric.current_error_rate();
            let avg_latency = metric.average_latency();
            let latency_us = avg_latency.as_micros() as f64;

            // Update EWMA
            metric
                .update_ewma(error_rate, latency_us, self.config.ewma_decay)
                .await;

            // Get smoothed metrics
            let ewma_error = *metric.ewma_error_rate.read().await;
            let ewma_latency_us = *metric.ewma_latency.read().await;
            let ewma_latency = Duration::from_micros(ewma_latency_us as u64);

            // Calculate weight adjustment factor
            let mut adjustment = 1.0;

            // Penalize high error rates
            if ewma_error > self.config.error_threshold {
                let error_factor =
                    1.0 - ((ewma_error - self.config.error_threshold) * 10.0).min(0.9);
                adjustment *= error_factor;
                debug!(
                    "Target {} error rate {:.2}% exceeds threshold, factor: {:.2}",
                    i,
                    ewma_error * 100.0,
                    error_factor
                );
            }

            // Penalize high latencies
            if ewma_latency > self.config.latency_threshold {
                let latency_ratio =
                    self.config.latency_threshold.as_micros() as f64 / ewma_latency_us;
                adjustment *= latency_ratio.max(0.1);
                debug!(
                    "Target {} latency {:?} exceeds threshold, factor: {:.2}",
                    i, ewma_latency, latency_ratio
                );
            }

            // Apply adjustment with damping
            let mut current_weight = *metric.effective_weight.read().await;
            let original = self.original_weights[i];

            if adjustment < 1.0 {
                // Degrade weight
                current_weight *=
                    self.config.penalty_rate + (1.0 - self.config.penalty_rate) * adjustment;
            } else {
                // Recover weight
                current_weight *= self.config.recovery_rate;
            }

            // Apply bounds
            let min_weight = original * self.config.min_weight_ratio;
            let max_weight = original * self.config.max_weight_ratio;
            current_weight = current_weight.max(min_weight).min(max_weight);

            *metric.effective_weight.write().await = current_weight;

            info!(
                "Adjusted weight for target {}: {:.2} (original: {:.2}, error: {:.2}%, latency: {:.0}ms)",
                i,
                current_weight,
                original,
                ewma_error * 100.0,
                ewma_latency.as_millis()
            );

            // Reset interval metrics
            metric.reset_interval_metrics();
        }

        *last_adjustment = Instant::now();
    }

    /// Calculate scores for all healthy targets
    async fn calculate_scores(&self) -> Vec<TargetScore> {
        trace!(
            target_count = self.targets.len(),
            "Calculating scores for all targets"
        );

        let health = self.health_status.read().await;
        let mut scores = Vec::new();

        for (i, target) in self.targets.iter().enumerate() {
            let target_id = format!("{}:{}", target.address, target.port);
            let is_healthy = health.get(&target_id).copied().unwrap_or(true);
            let circuit_open = *self.metrics[i].circuit_open.read().await;

            // Skip unhealthy or circuit-broken targets
            if !is_healthy || circuit_open {
                trace!(
                    target_index = i,
                    target_id = %target_id,
                    is_healthy = is_healthy,
                    circuit_open = circuit_open,
                    "Skipping target from scoring"
                );
                continue;
            }

            let weight = *self.metrics[i].effective_weight.read().await;
            let connections = self.metrics[i].active_connections.load(Ordering::Relaxed) as f64;
            let ewma_error = *self.metrics[i].ewma_error_rate.read().await;
            let ewma_latency = *self.metrics[i].ewma_latency.read().await / 1000.0; // Convert to ms

            // Score formula: weight / (1 + connections + error_penalty + latency_penalty)
            let error_penalty = ewma_error * 100.0; // Scale error rate
            let latency_penalty = (ewma_latency / 10.0).max(0.0); // Normalize latency
            let score = weight / (1.0 + connections + error_penalty + latency_penalty);

            trace!(
                target_index = i,
                target_id = %target_id,
                weight = weight,
                connections = connections,
                ewma_error = ewma_error,
                ewma_latency_ms = ewma_latency,
                error_penalty = error_penalty,
                latency_penalty = latency_penalty,
                score = score,
                "Calculated target score"
            );

            scores.push(TargetScore {
                index: i,
                score,
                weight,
            });
        }

        // Sort by score (highest first)
        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        trace!(
            scored_count = scores.len(),
            top_score = scores.first().map(|s| s.score).unwrap_or(0.0),
            "Scores calculated and sorted"
        );

        scores
    }

    /// Select target using weighted random selection based on scores
    async fn weighted_select(&self, scores: &[TargetScore]) -> Option<usize> {
        if scores.is_empty() {
            trace!("No scores provided for weighted selection");
            return None;
        }

        // Calculate total score
        let total_score: f64 = scores.iter().map(|s| s.score).sum();
        if total_score <= 0.0 {
            trace!(
                fallback_index = scores[0].index,
                "Total score is zero, using fallback"
            );
            return Some(scores[0].index); // Fallback to first
        }

        // Weighted random selection
        use rand::Rng;
        let mut rng = rand::rng();
        let threshold = rng.random::<f64>() * total_score;

        trace!(
            total_score = total_score,
            threshold = threshold,
            candidate_count = scores.len(),
            "Performing weighted random selection"
        );

        let mut cumulative = 0.0;
        for score in scores {
            cumulative += score.score;
            if cumulative >= threshold {
                trace!(
                    selected_index = score.index,
                    selected_score = score.score,
                    cumulative = cumulative,
                    "Selected target via weighted random"
                );
                return Some(score.index);
            }
        }

        // Fallback for floating point edge case - scores is guaranteed non-empty here
        let fallback = scores.last().map(|s| s.index);
        trace!(
            fallback_index = ?fallback,
            "Using fallback selection (floating point edge case)"
        );
        fallback
    }
}

#[async_trait]
impl LoadBalancer for AdaptiveBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!("Adaptive select started");

        // Periodically adjust weights
        self.adjust_weights().await;

        // Calculate scores for all targets
        let scores = self.calculate_scores().await;

        if scores.is_empty() {
            warn!("Adaptive: No healthy targets available");
            return Err(SentinelError::NoHealthyUpstream);
        }

        // Select target based on scores
        let target_index = self.weighted_select(&scores).await.ok_or_else(|| {
            warn!("Adaptive: Failed to select from scores");
            SentinelError::NoHealthyUpstream
        })?;

        let target = &self.targets[target_index];
        let metrics = &self.metrics[target_index];

        // Track connection
        let connections = metrics.active_connections.fetch_add(1, Ordering::Relaxed) + 1;

        let effective_weight = *metrics.effective_weight.read().await;
        let ewma_error = *metrics.ewma_error_rate.read().await;
        let ewma_latency = Duration::from_micros(*metrics.ewma_latency.read().await as u64);

        let score = scores
            .iter()
            .find(|s| s.index == target_index)
            .map(|s| s.score)
            .unwrap_or(0.0);

        debug!(
            target = %format!("{}:{}", target.address, target.port),
            target_index = target_index,
            score = score,
            effective_weight = effective_weight,
            original_weight = self.original_weights[target_index],
            error_rate = ewma_error,
            latency_ms = ewma_latency.as_millis() as u64,
            connections = connections,
            "Adaptive selected target"
        );

        Ok(TargetSelection {
            address: format!("{}:{}", target.address, target.port),
            weight: target.weight,
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("algorithm".to_string(), "adaptive".to_string());
                meta.insert("target_index".to_string(), target_index.to_string());
                meta.insert(
                    "effective_weight".to_string(),
                    format!("{:.2}", effective_weight),
                );
                meta.insert(
                    "original_weight".to_string(),
                    self.original_weights[target_index].to_string(),
                );
                meta.insert("error_rate".to_string(), format!("{:.4}", ewma_error));
                meta.insert(
                    "latency_ms".to_string(),
                    format!("{:.2}", ewma_latency.as_millis()),
                );
                meta.insert("connections".to_string(), connections.to_string());
                meta
            },
        })
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            address = %address,
            healthy = healthy,
            "Adaptive reporting target health"
        );

        let mut health = self.health_status.write().await;
        let previous = health.insert(address.to_string(), healthy);

        if previous != Some(healthy) {
            info!(
                address = %address,
                previous = ?previous,
                healthy = healthy,
                "Adaptive target health changed"
            );

            // Find target index and reset its weight on health change
            for (i, target) in self.targets.iter().enumerate() {
                let target_id = format!("{}:{}", target.address, target.port);
                if target_id == address {
                    if healthy {
                        // Reset to original weight on recovery
                        let original = self.original_weights[i];
                        *self.metrics[i].effective_weight.write().await = original;
                        *self.metrics[i].circuit_open.write().await = false;
                        self.metrics[i]
                            .consecutive_failures
                            .store(0, Ordering::Relaxed);
                        info!(
                            target_index = i,
                            original_weight = original,
                            "Reset target to original weight on recovery"
                        );
                    }
                    break;
                }
            }
        }
    }

    async fn healthy_targets(&self) -> Vec<String> {
        let health = self.health_status.read().await;
        let mut targets = Vec::new();

        for (i, target) in self.targets.iter().enumerate() {
            let target_id = format!("{}:{}", target.address, target.port);
            let is_healthy = health.get(&target_id).copied().unwrap_or(true);
            let circuit_open = *self.metrics[i].circuit_open.read().await;

            if is_healthy && !circuit_open {
                targets.push(target_id);
            }
        }

        trace!(
            total = self.targets.len(),
            healthy = targets.len(),
            "Adaptive healthy targets"
        );

        targets
    }

    async fn release(&self, selection: &TargetSelection) {
        if let Some(index_str) = selection.metadata.get("target_index") {
            if let Ok(index) = index_str.parse::<usize>() {
                let connections = self.metrics[index]
                    .active_connections
                    .fetch_sub(1, Ordering::Relaxed)
                    - 1;
                trace!(
                    target_index = index,
                    address = %selection.address,
                    connections = connections,
                    "Adaptive released connection"
                );
            }
        }
    }

    async fn report_result(
        &self,
        selection: &TargetSelection,
        success: bool,
        latency: Option<Duration>,
    ) {
        if let Some(index_str) = selection.metadata.get("target_index") {
            if let Ok(index) = index_str.parse::<usize>() {
                trace!(
                    target_index = index,
                    address = %selection.address,
                    success = success,
                    latency_ms = latency.map(|l| l.as_millis() as u64),
                    "Adaptive recording result"
                );
                self.metrics[index]
                    .record_result(success, latency, &self.config)
                    .await;
            }
        }
    }

    async fn report_result_with_latency(
        &self,
        address: &str,
        success: bool,
        latency: Option<Duration>,
    ) {
        // Find target index by address
        let target_index = self
            .targets
            .iter()
            .position(|t| format!("{}:{}", t.address, t.port) == address);

        if let Some(index) = target_index {
            trace!(
                target_index = index,
                address = %address,
                success = success,
                latency_ms = latency.map(|l| l.as_millis() as u64),
                "Adaptive recording result with latency"
            );
            self.metrics[index]
                .record_result(success, latency, &self.config)
                .await;
        } else {
            // Fall back to health reporting only
            trace!(
                address = %address,
                success = success,
                "Address not found in adaptive targets, reporting health only"
            );
            self.report_health(address, success).await;
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
    async fn test_weight_degradation() {
        let targets = create_test_targets(3);
        let config = AdaptiveConfig {
            adjustment_interval: Duration::from_millis(10),
            min_requests: 1,
            ..Default::default()
        };
        let balancer = AdaptiveBalancer::new(targets, config);

        // Simulate errors on target 0
        for _ in 0..10 {
            balancer.metrics[0]
                .record_result(false, None, &balancer.config)
                .await;
        }
        balancer.metrics[0]
            .total_requests
            .store(10, Ordering::Relaxed);

        // Simulate success on target 1
        for _ in 0..10 {
            balancer.metrics[1]
                .record_result(true, Some(Duration::from_millis(10)), &balancer.config)
                .await;
        }
        balancer.metrics[1]
            .total_requests
            .store(10, Ordering::Relaxed);

        // Wait for adjustment interval
        tokio::time::sleep(Duration::from_millis(15)).await;

        // Trigger weight adjustment
        balancer.adjust_weights().await;

        // Check that target 0 has degraded weight
        let weight0 = *balancer.metrics[0].effective_weight.read().await;
        let weight1 = *balancer.metrics[1].effective_weight.read().await;

        assert!(weight0 < 100.0, "Target 0 weight should be degraded");
        assert!(weight1 >= 100.0, "Target 1 weight should not be degraded");
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let targets = create_test_targets(2);
        let config = AdaptiveConfig::default();
        let balancer = AdaptiveBalancer::new(targets, config);

        // Simulate consecutive failures
        for _ in 0..5 {
            balancer.metrics[0]
                .record_result(false, None, &balancer.config)
                .await;
        }

        // Circuit should be open
        assert!(*balancer.metrics[0].circuit_open.read().await);

        // Should not select circuit-broken target
        let scores = balancer.calculate_scores().await;
        assert!(!scores.iter().any(|s| s.index == 0));

        // Simulate recovery
        for _ in 0..5 {
            balancer.metrics[0]
                .record_result(true, Some(Duration::from_millis(10)), &balancer.config)
                .await;
        }

        // Circuit should be closed
        assert!(!*balancer.metrics[0].circuit_open.read().await);
    }

    #[tokio::test]
    async fn test_latency_penalty() {
        let targets = create_test_targets(2);
        let config = AdaptiveConfig {
            adjustment_interval: Duration::from_millis(10),
            min_requests: 1,
            latency_threshold: Duration::from_millis(100),
            ..Default::default()
        };
        let balancer = AdaptiveBalancer::new(targets, config);

        // Simulate high latency on target 0
        for _ in 0..10 {
            balancer.metrics[0]
                .record_result(true, Some(Duration::from_millis(500)), &balancer.config)
                .await;
        }
        balancer.metrics[0]
            .total_requests
            .store(10, Ordering::Relaxed);

        // Simulate normal latency on target 1
        for _ in 0..10 {
            balancer.metrics[1]
                .record_result(true, Some(Duration::from_millis(50)), &balancer.config)
                .await;
        }
        balancer.metrics[1]
            .total_requests
            .store(10, Ordering::Relaxed);

        tokio::time::sleep(Duration::from_millis(15)).await;
        balancer.adjust_weights().await;

        let weight0 = *balancer.metrics[0].effective_weight.read().await;
        let weight1 = *balancer.metrics[1].effective_weight.read().await;

        assert!(
            weight0 < weight1,
            "High latency target should have lower weight"
        );
    }
}
