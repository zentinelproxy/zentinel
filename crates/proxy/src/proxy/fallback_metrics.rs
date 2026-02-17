//! Fallback routing metrics for observability.
//!
//! Provides Prometheus metrics for:
//! - Fallback attempts by route, upstream, and reason
//! - Successful responses after fallback
//! - Exhausted fallback events (all fallbacks tried)

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{register_int_counter_vec, IntCounterVec};
use std::sync::Arc;

use super::context::FallbackReason;

/// Global fallback metrics instance.
static FALLBACK_METRICS: OnceCell<Arc<FallbackMetrics>> = OnceCell::new();

/// Get or initialize the global fallback metrics.
pub fn get_fallback_metrics() -> Option<Arc<FallbackMetrics>> {
    FALLBACK_METRICS.get().cloned()
}

/// Initialize the global fallback metrics.
/// Returns Ok if already initialized or initialization succeeds.
pub fn init_fallback_metrics() -> Result<Arc<FallbackMetrics>> {
    if let Some(metrics) = FALLBACK_METRICS.get() {
        return Ok(metrics.clone());
    }

    let metrics = Arc::new(FallbackMetrics::new()?);
    let _ = FALLBACK_METRICS.set(metrics.clone());
    Ok(metrics)
}

/// Fallback routing metrics collector.
///
/// Tracks fallback attempts, successes, and exhaustion events for
/// observability and alerting.
pub struct FallbackMetrics {
    /// Total fallback attempts
    /// Labels: route, from_upstream, to_upstream, reason
    fallback_attempts: IntCounterVec,

    /// Successful responses after fallback
    /// Labels: route, upstream
    fallback_success: IntCounterVec,

    /// All fallbacks exhausted (no more upstreams to try)
    /// Labels: route
    fallback_exhausted: IntCounterVec,

    /// Model mapping applied during fallback
    /// Labels: route, original_model, mapped_model
    model_mapping_applied: IntCounterVec,
}

impl FallbackMetrics {
    /// Create new fallback metrics and register with Prometheus.
    pub fn new() -> Result<Self> {
        let fallback_attempts = register_int_counter_vec!(
            "zentinel_fallback_attempts_total",
            "Total number of fallback routing attempts",
            &["route", "from_upstream", "to_upstream", "reason"]
        )
        .context("Failed to register fallback_attempts metric")?;

        let fallback_success = register_int_counter_vec!(
            "zentinel_fallback_success_total",
            "Successful responses after fallback routing",
            &["route", "upstream"]
        )
        .context("Failed to register fallback_success metric")?;

        let fallback_exhausted = register_int_counter_vec!(
            "zentinel_fallback_exhausted_total",
            "Number of requests where all fallback upstreams were exhausted",
            &["route"]
        )
        .context("Failed to register fallback_exhausted metric")?;

        let model_mapping_applied = register_int_counter_vec!(
            "zentinel_fallback_model_mapping_total",
            "Number of times model mapping was applied during fallback",
            &["route", "original_model", "mapped_model"]
        )
        .context("Failed to register fallback_model_mapping metric")?;

        Ok(Self {
            fallback_attempts,
            fallback_success,
            fallback_exhausted,
            model_mapping_applied,
        })
    }

    /// Record a fallback attempt.
    ///
    /// Called when fallback routing is triggered from one upstream to another.
    pub fn record_fallback_attempt(
        &self,
        route: &str,
        from_upstream: &str,
        to_upstream: &str,
        reason: &FallbackReason,
    ) {
        let reason_str = Self::reason_label(reason);
        self.fallback_attempts
            .with_label_values(&[route, from_upstream, to_upstream, reason_str])
            .inc();
    }

    /// Record a successful response after fallback.
    ///
    /// Called when a request succeeds after being routed to a fallback upstream.
    pub fn record_fallback_success(&self, route: &str, upstream: &str) {
        self.fallback_success
            .with_label_values(&[route, upstream])
            .inc();
    }

    /// Record that all fallback upstreams were exhausted.
    ///
    /// Called when no more fallback upstreams are available and the request fails.
    pub fn record_fallback_exhausted(&self, route: &str) {
        self.fallback_exhausted.with_label_values(&[route]).inc();
    }

    /// Record model mapping applied during fallback.
    pub fn record_model_mapping(&self, route: &str, original_model: &str, mapped_model: &str) {
        self.model_mapping_applied
            .with_label_values(&[route, original_model, mapped_model])
            .inc();
    }

    /// Convert FallbackReason to a label string.
    fn reason_label(reason: &FallbackReason) -> &'static str {
        match reason {
            FallbackReason::HealthCheckFailed => "health_check_failed",
            FallbackReason::BudgetExhausted => "budget_exhausted",
            FallbackReason::LatencyThreshold { .. } => "latency_threshold",
            FallbackReason::ErrorCode(_) => "error_code",
            FallbackReason::ConnectionError(_) => "connection_error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reason_label() {
        assert_eq!(
            FallbackMetrics::reason_label(&FallbackReason::HealthCheckFailed),
            "health_check_failed"
        );
        assert_eq!(
            FallbackMetrics::reason_label(&FallbackReason::BudgetExhausted),
            "budget_exhausted"
        );
        assert_eq!(
            FallbackMetrics::reason_label(&FallbackReason::LatencyThreshold {
                observed_ms: 5000,
                threshold_ms: 3000
            }),
            "latency_threshold"
        );
        assert_eq!(
            FallbackMetrics::reason_label(&FallbackReason::ErrorCode(503)),
            "error_code"
        );
        assert_eq!(
            FallbackMetrics::reason_label(&FallbackReason::ConnectionError("timeout".to_string())),
            "connection_error"
        );
    }
}
