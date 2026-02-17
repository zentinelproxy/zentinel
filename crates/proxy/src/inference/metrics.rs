//! Inference-specific metrics for budget and cost tracking.
//!
//! Provides Prometheus metrics for:
//! - Token budget usage per tenant
//! - Budget alerts and exhaustion events
//! - Cost attribution per model and route

use anyhow::{Context, Result};
use prometheus::{
    register_counter_vec, register_histogram_vec, register_int_counter_vec, register_int_gauge_vec,
    CounterVec, HistogramVec, IntCounterVec, IntGaugeVec,
};

use zentinel_common::budget::{BudgetAlert, BudgetCheckResult, CostResult};
use zentinel_common::ids::Scope;

/// Inference-specific metrics collector.
///
/// Tracks token budgets, costs, and inference-specific metrics with
/// namespace/service labels for multi-tenant observability.
pub struct InferenceMetrics {
    // Budget metrics
    /// Budget limit by tenant (gauge)
    budget_limit: IntGaugeVec,
    /// Tokens used in current period (counter)
    budget_used: IntCounterVec,
    /// Budget remaining (gauge, can be negative)
    budget_remaining: IntGaugeVec,
    /// Budget exhausted events (counter)
    budget_exhausted: IntCounterVec,
    /// Budget alerts fired (counter)
    budget_alerts: IntCounterVec,

    // Cost metrics
    /// Total cost by model and route (counter)
    cost_total: CounterVec,
    /// Input tokens by model and route (counter)
    input_tokens_total: IntCounterVec,
    /// Output tokens by model and route (counter)
    output_tokens_total: IntCounterVec,
    /// Request cost histogram (histogram)
    cost_per_request: HistogramVec,
}

impl InferenceMetrics {
    /// Create new inference metrics and register with Prometheus.
    pub fn new() -> Result<Self> {
        // Cost buckets in dollars (from 0.0001 to 10.0)
        let cost_buckets = vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0,
        ];

        let budget_limit = register_int_gauge_vec!(
            "zentinel_inference_budget_limit",
            "Token budget limit per tenant",
            &["namespace", "service", "route", "tenant"]
        )
        .context("Failed to register inference_budget_limit metric")?;

        let budget_used = register_int_counter_vec!(
            "zentinel_inference_budget_used_total",
            "Total tokens consumed against budget",
            &["namespace", "service", "route", "tenant"]
        )
        .context("Failed to register inference_budget_used metric")?;

        let budget_remaining = register_int_gauge_vec!(
            "zentinel_inference_budget_remaining",
            "Tokens remaining in budget (can be negative if over)",
            &["namespace", "service", "route", "tenant"]
        )
        .context("Failed to register inference_budget_remaining metric")?;

        let budget_exhausted = register_int_counter_vec!(
            "zentinel_inference_budget_exhausted_total",
            "Number of requests blocked due to exhausted budget",
            &["namespace", "service", "route", "tenant"]
        )
        .context("Failed to register inference_budget_exhausted metric")?;

        let budget_alerts = register_int_counter_vec!(
            "zentinel_inference_budget_alerts_total",
            "Number of budget alert thresholds crossed",
            &["namespace", "service", "route", "tenant", "threshold"]
        )
        .context("Failed to register inference_budget_alerts metric")?;

        let cost_total = register_counter_vec!(
            "zentinel_inference_cost_total",
            "Total cost of inference requests",
            &["namespace", "service", "route", "model", "currency"]
        )
        .context("Failed to register inference_cost_total metric")?;

        let input_tokens_total = register_int_counter_vec!(
            "zentinel_inference_input_tokens_total",
            "Total input tokens processed",
            &["namespace", "service", "route", "model"]
        )
        .context("Failed to register inference_input_tokens metric")?;

        let output_tokens_total = register_int_counter_vec!(
            "zentinel_inference_output_tokens_total",
            "Total output tokens generated",
            &["namespace", "service", "route", "model"]
        )
        .context("Failed to register inference_output_tokens metric")?;

        let cost_per_request = register_histogram_vec!(
            "zentinel_inference_cost_per_request",
            "Cost per inference request in dollars",
            &["namespace", "service", "route", "model"],
            cost_buckets
        )
        .context("Failed to register inference_cost_per_request metric")?;

        Ok(Self {
            budget_limit,
            budget_used,
            budget_remaining,
            budget_exhausted,
            budget_alerts,
            cost_total,
            input_tokens_total,
            output_tokens_total,
            cost_per_request,
        })
    }

    /// Extract namespace and service strings from a scope.
    #[inline]
    fn scope_labels(scope: &Scope) -> (&str, &str) {
        match scope {
            Scope::Global => ("", ""),
            Scope::Namespace(ns) => (ns.as_str(), ""),
            Scope::Service { namespace, service } => (namespace.as_str(), service.as_str()),
        }
    }

    /// Record a budget check result.
    pub fn record_budget_check(
        &self,
        route: &str,
        tenant: &str,
        result: &BudgetCheckResult,
        budget_limit: u64,
        scope: &Scope,
    ) {
        let (namespace, service) = Self::scope_labels(scope);

        // Set the budget limit gauge
        self.budget_limit
            .with_label_values(&[namespace, service, route, tenant])
            .set(budget_limit as i64);

        // Record exhausted events
        if matches!(result, BudgetCheckResult::Exhausted { .. }) {
            self.budget_exhausted
                .with_label_values(&[namespace, service, route, tenant])
                .inc();
        }
    }

    /// Record token usage against a budget.
    pub fn record_budget_usage(
        &self,
        route: &str,
        tenant: &str,
        tokens: u64,
        remaining: i64,
        scope: &Scope,
    ) {
        let (namespace, service) = Self::scope_labels(scope);

        self.budget_used
            .with_label_values(&[namespace, service, route, tenant])
            .inc_by(tokens);

        self.budget_remaining
            .with_label_values(&[namespace, service, route, tenant])
            .set(remaining);
    }

    /// Record a budget alert.
    pub fn record_budget_alert(&self, route: &str, alert: &BudgetAlert, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);

        // Format threshold as percentage string
        let threshold_str = format!("{:.0}", alert.threshold * 100.0);

        self.budget_alerts
            .with_label_values(&[namespace, service, route, &alert.tenant, &threshold_str])
            .inc();
    }

    /// Record a cost result.
    pub fn record_cost(&self, route: &str, cost: &CostResult, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);

        // Record total cost
        self.cost_total
            .with_label_values(&[namespace, service, route, &cost.model, &cost.currency])
            .inc_by(cost.total_cost);

        // Record token counts
        self.input_tokens_total
            .with_label_values(&[namespace, service, route, &cost.model])
            .inc_by(cost.input_tokens);

        self.output_tokens_total
            .with_label_values(&[namespace, service, route, &cost.model])
            .inc_by(cost.output_tokens);

        // Record cost histogram
        self.cost_per_request
            .with_label_values(&[namespace, service, route, &cost.model])
            .observe(cost.total_cost);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Prometheus metric registration is global and can conflict between tests.
    // These tests are disabled by default to avoid conflicts.

    #[test]
    #[ignore = "Requires isolated Prometheus registry"]
    fn test_metrics_creation() {
        let metrics = InferenceMetrics::new();
        assert!(metrics.is_ok());
    }

    #[test]
    fn test_scope_labels() {
        let (ns, svc) = InferenceMetrics::scope_labels(&Scope::Global);
        assert_eq!(ns, "");
        assert_eq!(svc, "");

        let ns_scope = Scope::Namespace("api".to_string());
        let (ns, svc) = InferenceMetrics::scope_labels(&ns_scope);
        assert_eq!(ns, "api");
        assert_eq!(svc, "");

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let (ns, svc) = InferenceMetrics::scope_labels(&svc_scope);
        assert_eq!(ns, "api");
        assert_eq!(svc, "payments");
    }
}
