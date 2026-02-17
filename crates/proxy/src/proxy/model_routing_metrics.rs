//! Model-based routing metrics for observability.
//!
//! Provides Prometheus metrics for:
//! - Model routing decisions by route, model, and upstream
//! - Default upstream fallbacks when no pattern matches
//! - Pattern match counts for tuning

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{register_int_counter_vec, IntCounterVec};
use std::sync::Arc;

/// Global model routing metrics instance.
static MODEL_ROUTING_METRICS: OnceCell<Arc<ModelRoutingMetrics>> = OnceCell::new();

/// Get or initialize the global model routing metrics.
pub fn get_model_routing_metrics() -> Option<Arc<ModelRoutingMetrics>> {
    MODEL_ROUTING_METRICS.get().cloned()
}

/// Initialize the global model routing metrics.
/// Returns Ok if already initialized or initialization succeeds.
pub fn init_model_routing_metrics() -> Result<Arc<ModelRoutingMetrics>> {
    if let Some(metrics) = MODEL_ROUTING_METRICS.get() {
        return Ok(metrics.clone());
    }

    let metrics = Arc::new(ModelRoutingMetrics::new()?);
    let _ = MODEL_ROUTING_METRICS.set(metrics.clone());
    Ok(metrics)
}

/// Model routing metrics collector.
///
/// Tracks model-based routing decisions for observability and capacity planning.
pub struct ModelRoutingMetrics {
    /// Total model routing decisions
    /// Labels: route, model, upstream
    model_routed: IntCounterVec,

    /// Requests using default upstream (no pattern matched)
    /// Labels: route
    default_upstream_used: IntCounterVec,

    /// Requests with no model header detected
    /// Labels: route
    no_model_header: IntCounterVec,

    /// Provider override applied
    /// Labels: route, upstream, provider
    provider_override: IntCounterVec,
}

impl ModelRoutingMetrics {
    /// Create new model routing metrics and register with Prometheus.
    pub fn new() -> Result<Self> {
        let model_routed = register_int_counter_vec!(
            "zentinel_model_routing_total",
            "Total number of requests routed based on model name",
            &["route", "model", "upstream"]
        )
        .context("Failed to register model_routing metric")?;

        let default_upstream_used = register_int_counter_vec!(
            "zentinel_model_routing_default_total",
            "Requests falling back to default upstream (no pattern matched)",
            &["route"]
        )
        .context("Failed to register model_routing_default metric")?;

        let no_model_header = register_int_counter_vec!(
            "zentinel_model_routing_no_header_total",
            "Requests with no model header detected",
            &["route"]
        )
        .context("Failed to register model_routing_no_header metric")?;

        let provider_override = register_int_counter_vec!(
            "zentinel_model_routing_provider_override_total",
            "Requests where provider was overridden by model routing",
            &["route", "upstream", "provider"]
        )
        .context("Failed to register model_routing_provider_override metric")?;

        Ok(Self {
            model_routed,
            default_upstream_used,
            no_model_header,
            provider_override,
        })
    }

    /// Record a model routing decision.
    ///
    /// Called when a request is routed to a specific upstream based on model name.
    pub fn record_model_routed(&self, route: &str, model: &str, upstream: &str) {
        self.model_routed
            .with_label_values(&[route, model, upstream])
            .inc();
    }

    /// Record use of default upstream.
    ///
    /// Called when no model pattern matched and the default upstream is used.
    pub fn record_default_upstream(&self, route: &str) {
        self.default_upstream_used.with_label_values(&[route]).inc();
    }

    /// Record request with no model header.
    ///
    /// Called when model routing is configured but no model header was found.
    pub fn record_no_model_header(&self, route: &str) {
        self.no_model_header.with_label_values(&[route]).inc();
    }

    /// Record provider override.
    ///
    /// Called when model routing overrides the inference provider.
    pub fn record_provider_override(&self, route: &str, upstream: &str, provider: &str) {
        self.provider_override
            .with_label_values(&[route, upstream, provider])
            .inc();
    }
}
