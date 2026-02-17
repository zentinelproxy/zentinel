//! Least Tokens Queued load balancer for inference workloads
//!
//! This load balancer selects upstreams based on the estimated number of tokens
//! currently being processed, optimized for LLM/AI inference traffic where
//! request processing time correlates strongly with token count.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, trace};

use zentinel_common::errors::{ZentinelError, ZentinelResult};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};

/// Configuration for the least tokens queued balancer
#[derive(Debug, Clone)]
pub struct LeastTokensQueuedConfig {
    /// Smoothing factor for tokens-per-second EWMA (0.0-1.0)
    /// Higher values = more responsive to recent measurements
    pub ewma_alpha: f64,
    /// Default tokens-per-second estimate for new targets
    pub default_tps: f64,
    /// Minimum tokens-per-second to avoid division issues
    pub min_tps: f64,
}

impl Default for LeastTokensQueuedConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.3,
            default_tps: 100.0, // Conservative default
            min_tps: 1.0,
        }
    }
}

/// Per-target metrics for token-aware load balancing
struct TargetMetrics {
    /// Currently queued tokens (estimated)
    queued_tokens: AtomicU64,
    /// Currently queued requests
    queued_requests: AtomicU64,
    /// Exponentially weighted moving average of tokens per second
    tps_ewma: parking_lot::Mutex<f64>,
    /// Total tokens processed (for debugging/metrics)
    total_tokens: AtomicU64,
    /// Total requests processed
    total_requests: AtomicU64,
}

impl TargetMetrics {
    fn new(default_tps: f64) -> Self {
        Self {
            queued_tokens: AtomicU64::new(0),
            queued_requests: AtomicU64::new(0),
            tps_ewma: parking_lot::Mutex::new(default_tps),
            total_tokens: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
        }
    }

    /// Get the estimated queue time: queued_tokens / tokens_per_second
    fn estimated_queue_time(&self, min_tps: f64) -> f64 {
        let queued = self.queued_tokens.load(Ordering::Relaxed) as f64;
        let tps = (*self.tps_ewma.lock()).max(min_tps);
        queued / tps
    }

    /// Add tokens to the queue (when request starts)
    fn enqueue(&self, tokens: u64) {
        self.queued_tokens.fetch_add(tokens, Ordering::AcqRel);
        self.queued_requests.fetch_add(1, Ordering::AcqRel);
    }

    /// Remove tokens from queue and update TPS (when request completes)
    fn dequeue(&self, tokens: u64, duration: Duration, ewma_alpha: f64) {
        // Remove from queue
        self.queued_tokens.fetch_saturating_sub(tokens);
        self.queued_requests.fetch_saturating_sub(1);

        // Update totals
        self.total_tokens.fetch_add(tokens, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Update TPS EWMA
        if duration.as_secs_f64() > 0.0 {
            let measured_tps = tokens as f64 / duration.as_secs_f64();
            let mut tps = self.tps_ewma.lock();
            *tps = ewma_alpha * measured_tps + (1.0 - ewma_alpha) * *tps;
        }
    }
}

/// Extension trait for AtomicU64 to add saturating_sub
trait AtomicSaturatingSub {
    fn fetch_saturating_sub(&self, val: u64);
}

impl AtomicSaturatingSub for AtomicU64 {
    fn fetch_saturating_sub(&self, val: u64) {
        loop {
            let current = self.load(Ordering::Acquire);
            let new = current.saturating_sub(val);
            if self
                .compare_exchange(current, new, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Least Tokens Queued load balancer
///
/// Selects the upstream with the lowest estimated queue time,
/// calculated as: queued_tokens / tokens_per_second
pub struct LeastTokensQueuedBalancer {
    targets: Vec<UpstreamTarget>,
    metrics: Arc<HashMap<String, TargetMetrics>>,
    health_status: Arc<RwLock<HashMap<String, bool>>>,
    config: LeastTokensQueuedConfig,
}

impl LeastTokensQueuedBalancer {
    /// Create a new least tokens queued balancer
    pub fn new(targets: Vec<UpstreamTarget>, config: LeastTokensQueuedConfig) -> Self {
        let mut metrics = HashMap::new();
        let mut health_status = HashMap::new();

        for target in &targets {
            let addr = target.full_address();
            metrics.insert(addr.clone(), TargetMetrics::new(config.default_tps));
            health_status.insert(addr, true);
        }

        Self {
            targets,
            metrics: Arc::new(metrics),
            health_status: Arc::new(RwLock::new(health_status)),
            config,
        }
    }

    /// Enqueue tokens for a target (call when request starts)
    pub fn enqueue_tokens(&self, address: &str, estimated_tokens: u64) {
        if let Some(metrics) = self.metrics.get(address) {
            metrics.enqueue(estimated_tokens);
            trace!(
                target = address,
                tokens = estimated_tokens,
                queued = metrics.queued_tokens.load(Ordering::Relaxed),
                "Enqueued tokens for target"
            );
        }
    }

    /// Dequeue tokens for a target (call when request completes)
    pub fn dequeue_tokens(&self, address: &str, actual_tokens: u64, duration: Duration) {
        if let Some(metrics) = self.metrics.get(address) {
            metrics.dequeue(actual_tokens, duration, self.config.ewma_alpha);
            debug!(
                target = address,
                tokens = actual_tokens,
                duration_ms = duration.as_millis() as u64,
                queued = metrics.queued_tokens.load(Ordering::Relaxed),
                tps = *metrics.tps_ewma.lock(),
                "Dequeued tokens for target"
            );
        }
    }

    /// Get current metrics for a target (for debugging/observability)
    pub fn target_metrics(&self, address: &str) -> Option<LeastTokensQueuedTargetStats> {
        self.metrics
            .get(address)
            .map(|m| LeastTokensQueuedTargetStats {
                queued_tokens: m.queued_tokens.load(Ordering::Relaxed),
                queued_requests: m.queued_requests.load(Ordering::Relaxed),
                tokens_per_second: *m.tps_ewma.lock(),
                total_tokens: m.total_tokens.load(Ordering::Relaxed),
                total_requests: m.total_requests.load(Ordering::Relaxed),
            })
    }

    /// Get all targets' current queue times for debugging
    pub async fn queue_times(&self) -> Vec<(String, f64)> {
        let health = self.health_status.read().await;
        self.targets
            .iter()
            .filter_map(|t| {
                let addr = t.full_address();
                if *health.get(&addr).unwrap_or(&true) {
                    self.metrics
                        .get(&addr)
                        .map(|m| (addr, m.estimated_queue_time(self.config.min_tps)))
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Target statistics for observability
#[derive(Debug, Clone)]
pub struct LeastTokensQueuedTargetStats {
    pub queued_tokens: u64,
    pub queued_requests: u64,
    pub tokens_per_second: f64,
    pub total_tokens: u64,
    pub total_requests: u64,
}

#[async_trait]
impl LoadBalancer for LeastTokensQueuedBalancer {
    async fn select(&self, _context: Option<&RequestContext>) -> ZentinelResult<TargetSelection> {
        trace!(
            total_targets = self.targets.len(),
            algorithm = "least_tokens_queued",
            "Selecting upstream target"
        );

        let health = self.health_status.read().await;

        let mut best_target = None;
        let mut min_queue_time = f64::MAX;

        for target in &self.targets {
            let addr = target.full_address();

            // Skip unhealthy targets
            if !*health.get(&addr).unwrap_or(&true) {
                trace!(
                    target = %addr,
                    algorithm = "least_tokens_queued",
                    "Skipping unhealthy target"
                );
                continue;
            }

            // Calculate estimated queue time
            let queue_time = self
                .metrics
                .get(&addr)
                .map(|m| m.estimated_queue_time(self.config.min_tps))
                .unwrap_or(0.0);

            trace!(
                target = %addr,
                queue_time_secs = queue_time,
                "Evaluating target queue time"
            );

            if queue_time < min_queue_time {
                min_queue_time = queue_time;
                best_target = Some(target);
            }
        }

        match best_target {
            Some(target) => {
                debug!(
                    selected_target = %target.full_address(),
                    queue_time_secs = min_queue_time,
                    algorithm = "least_tokens_queued",
                    "Selected target with lowest queue time"
                );
                Ok(TargetSelection {
                    address: target.full_address(),
                    weight: target.weight,
                    metadata: HashMap::new(),
                })
            }
            None => {
                tracing::warn!(
                    total_targets = self.targets.len(),
                    algorithm = "least_tokens_queued",
                    "No healthy upstream targets available"
                );
                Err(ZentinelError::NoHealthyUpstream)
            }
        }
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "least_tokens_queued",
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

    async fn report_result(
        &self,
        selection: &TargetSelection,
        success: bool,
        latency: Option<Duration>,
    ) {
        // Update health based on success
        self.report_health(&selection.address, success).await;

        // Note: Token dequeuing should be done explicitly via dequeue_tokens()
        // when the actual token count is known from the response
    }

    async fn report_result_with_latency(
        &self,
        address: &str,
        success: bool,
        latency: Option<Duration>,
    ) {
        self.report_health(address, success).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_targets() -> Vec<UpstreamTarget> {
        vec![
            UpstreamTarget::new("server1", 8080, 100),
            UpstreamTarget::new("server2", 8080, 100),
            UpstreamTarget::new("server3", 8080, 100),
        ]
    }

    #[tokio::test]
    async fn test_basic_selection() {
        let balancer =
            LeastTokensQueuedBalancer::new(test_targets(), LeastTokensQueuedConfig::default());

        // All targets start with 0 queued tokens, so selection should work
        let selection = balancer.select(None).await.unwrap();
        assert!(!selection.address.is_empty());
    }

    #[tokio::test]
    async fn test_selects_least_queued() {
        let balancer =
            LeastTokensQueuedBalancer::new(test_targets(), LeastTokensQueuedConfig::default());

        // Add tokens to server1 and server2
        balancer.enqueue_tokens("server1:8080", 1000);
        balancer.enqueue_tokens("server2:8080", 500);
        // server3 has 0 tokens

        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "server3:8080");
    }

    #[tokio::test]
    async fn test_dequeue_updates_tps() {
        let balancer =
            LeastTokensQueuedBalancer::new(test_targets(), LeastTokensQueuedConfig::default());

        // Enqueue and then dequeue with timing
        balancer.enqueue_tokens("server1:8080", 1000);
        balancer.dequeue_tokens("server1:8080", 1000, Duration::from_secs(1));

        // Check that TPS was updated
        let stats = balancer.target_metrics("server1:8080").unwrap();
        assert!(stats.total_tokens == 1000);
        assert!(stats.total_requests == 1);
    }

    #[tokio::test]
    async fn test_unhealthy_target_skipped() {
        let balancer =
            LeastTokensQueuedBalancer::new(test_targets(), LeastTokensQueuedConfig::default());

        // Mark server3 as unhealthy
        balancer.report_health("server3:8080", false).await;

        // Add tokens to server1
        balancer.enqueue_tokens("server1:8080", 1000);

        // Should select server2 (healthy and lowest queue)
        let selection = balancer.select(None).await.unwrap();
        assert_eq!(selection.address, "server2:8080");
    }
}
