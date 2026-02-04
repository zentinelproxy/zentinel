//! Scope-aware metrics for namespaced configurations.
//!
//! This module provides [`ScopedMetrics`] which extends the base [`crate::observability::RequestMetrics`]
//! with namespace and service labels for multi-tenant observability.
//!
//! # Metric Labels
//!
//! All scoped metrics include these additional labels:
//! - `namespace`: The namespace name (empty string for global scope)
//! - `service`: The service name (empty string if not in a service scope)
//!
//! # Example
//!
//! ```ignore
//! use sentinel_common::{ScopedMetrics, Scope};
//!
//! let metrics = ScopedMetrics::new()?;
//!
//! // Record a request with scope information
//! let scope = Scope::Service {
//!     namespace: "api".into(),
//!     service: "payments".into(),
//! };
//! metrics.record_scoped_request("checkout", "POST", 200, duration, &scope);
//! ```

use anyhow::{Context, Result};
use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge_vec, HistogramVec,
    IntCounterVec, IntGaugeVec,
};
use std::time::Duration;

use crate::ids::Scope;

/// Scope-aware metrics collector.
///
/// Provides metrics with namespace and service labels for hierarchical
/// configuration visibility and multi-tenant observability.
pub struct ScopedMetrics {
    /// Request latency histogram by scope and route
    request_duration: HistogramVec,

    /// Request count by scope, route, and status
    request_count: IntCounterVec,

    /// Active requests gauge by scope
    active_requests: IntGaugeVec,

    /// Upstream connection attempts by scope
    upstream_attempts: IntCounterVec,

    /// Upstream failures by scope
    upstream_failures: IntCounterVec,

    /// Rate limit hits by scope
    rate_limit_hits: IntCounterVec,

    /// Circuit breaker state by scope
    circuit_breaker_state: IntGaugeVec,
}

impl ScopedMetrics {
    /// Create new scoped metrics collector and register with Prometheus.
    pub fn new() -> Result<Self> {
        // Define buckets for latency histograms (in seconds)
        let latency_buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        let request_duration = register_histogram_vec!(
            "sentinel_scoped_request_duration_seconds",
            "Request duration in seconds with scope labels",
            &["namespace", "service", "route", "method"],
            latency_buckets
        )
        .context("Failed to register scoped_request_duration metric")?;

        let request_count = register_int_counter_vec!(
            "sentinel_scoped_requests_total",
            "Total number of requests with scope labels",
            &["namespace", "service", "route", "method", "status"]
        )
        .context("Failed to register scoped_requests_total metric")?;

        let active_requests = register_int_gauge_vec!(
            "sentinel_scoped_active_requests",
            "Number of currently active requests by scope",
            &["namespace", "service"]
        )
        .context("Failed to register scoped_active_requests metric")?;

        let upstream_attempts = register_int_counter_vec!(
            "sentinel_scoped_upstream_attempts_total",
            "Total upstream connection attempts with scope labels",
            &["namespace", "service", "upstream", "route"]
        )
        .context("Failed to register scoped_upstream_attempts metric")?;

        let upstream_failures = register_int_counter_vec!(
            "sentinel_scoped_upstream_failures_total",
            "Total upstream connection failures with scope labels",
            &["namespace", "service", "upstream", "route", "reason"]
        )
        .context("Failed to register scoped_upstream_failures metric")?;

        let rate_limit_hits = register_int_counter_vec!(
            "sentinel_scoped_rate_limit_hits_total",
            "Total rate limit hits with scope labels",
            &["namespace", "service", "route", "policy"]
        )
        .context("Failed to register scoped_rate_limit_hits metric")?;

        let circuit_breaker_state = register_int_gauge_vec!(
            "sentinel_scoped_circuit_breaker_state",
            "Circuit breaker state (0=closed, 1=open) with scope labels",
            &["namespace", "service", "upstream"]
        )
        .context("Failed to register scoped_circuit_breaker_state metric")?;

        Ok(Self {
            request_duration,
            request_count,
            active_requests,
            upstream_attempts,
            upstream_failures,
            rate_limit_hits,
            circuit_breaker_state,
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

    /// Record a completed request with scope information.
    pub fn record_request(
        &self,
        route: &str,
        method: &str,
        status: u16,
        duration: Duration,
        scope: &Scope,
    ) {
        let (namespace, service) = Self::scope_labels(scope);

        self.request_duration
            .with_label_values(&[namespace, service, route, method])
            .observe(duration.as_secs_f64());

        self.request_count
            .with_label_values(&[namespace, service, route, method, &status.to_string()])
            .inc();
    }

    /// Increment active request counter for a scope.
    pub fn inc_active_requests(&self, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);
        self.active_requests
            .with_label_values(&[namespace, service])
            .inc();
    }

    /// Decrement active request counter for a scope.
    pub fn dec_active_requests(&self, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);
        self.active_requests
            .with_label_values(&[namespace, service])
            .dec();
    }

    /// Record an upstream attempt with scope information.
    pub fn record_upstream_attempt(&self, upstream: &str, route: &str, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);
        self.upstream_attempts
            .with_label_values(&[namespace, service, upstream, route])
            .inc();
    }

    /// Record an upstream failure with scope information.
    pub fn record_upstream_failure(
        &self,
        upstream: &str,
        route: &str,
        reason: &str,
        scope: &Scope,
    ) {
        let (namespace, service) = Self::scope_labels(scope);
        self.upstream_failures
            .with_label_values(&[namespace, service, upstream, route, reason])
            .inc();
    }

    /// Record a rate limit hit with scope information.
    pub fn record_rate_limit_hit(&self, route: &str, policy: &str, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);
        self.rate_limit_hits
            .with_label_values(&[namespace, service, route, policy])
            .inc();
    }

    /// Update circuit breaker state with scope information.
    pub fn set_circuit_breaker_state(&self, upstream: &str, is_open: bool, scope: &Scope) {
        let (namespace, service) = Self::scope_labels(scope);
        let state = if is_open { 1 } else { 0 };
        self.circuit_breaker_state
            .with_label_values(&[namespace, service, upstream])
            .set(state);
    }
}

/// Metrics labels for scoped requests.
///
/// Use this struct to pass scope information through the request pipeline
/// for consistent metric labeling.
#[derive(Debug, Clone)]
pub struct ScopeLabels {
    pub namespace: String,
    pub service: String,
}

impl ScopeLabels {
    /// Create labels for global scope.
    pub fn global() -> Self {
        Self {
            namespace: String::new(),
            service: String::new(),
        }
    }

    /// Create labels from a scope.
    pub fn from_scope(scope: &Scope) -> Self {
        match scope {
            Scope::Global => Self::global(),
            Scope::Namespace(ns) => Self {
                namespace: ns.clone(),
                service: String::new(),
            },
            Scope::Service { namespace, service } => Self {
                namespace: namespace.clone(),
                service: service.clone(),
            },
        }
    }

    /// Get the namespace label value (empty string if global).
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the service label value (empty string if not in service scope).
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Check if this is global scope.
    pub fn is_global(&self) -> bool {
        self.namespace.is_empty() && self.service.is_empty()
    }

    /// Check if this is a namespace scope (not service).
    pub fn is_namespace(&self) -> bool {
        !self.namespace.is_empty() && self.service.is_empty()
    }

    /// Check if this is a service scope.
    pub fn is_service(&self) -> bool {
        !self.namespace.is_empty() && !self.service.is_empty()
    }
}

impl Default for ScopeLabels {
    fn default() -> Self {
        Self::global()
    }
}

impl From<&Scope> for ScopeLabels {
    fn from(scope: &Scope) -> Self {
        Self::from_scope(scope)
    }
}

impl From<Scope> for ScopeLabels {
    fn from(scope: Scope) -> Self {
        Self::from_scope(&scope)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_labels_from_global() {
        let labels = ScopeLabels::from_scope(&Scope::Global);
        assert!(labels.is_global());
        assert!(!labels.is_namespace());
        assert!(!labels.is_service());
        assert_eq!(labels.namespace(), "");
        assert_eq!(labels.service(), "");
    }

    #[test]
    fn test_scope_labels_from_namespace() {
        let labels = ScopeLabels::from_scope(&Scope::Namespace("api".to_string()));
        assert!(!labels.is_global());
        assert!(labels.is_namespace());
        assert!(!labels.is_service());
        assert_eq!(labels.namespace(), "api");
        assert_eq!(labels.service(), "");
    }

    #[test]
    fn test_scope_labels_from_service() {
        let labels = ScopeLabels::from_scope(&Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        });
        assert!(!labels.is_global());
        assert!(!labels.is_namespace());
        assert!(labels.is_service());
        assert_eq!(labels.namespace(), "api");
        assert_eq!(labels.service(), "payments");
    }

    #[test]
    fn test_scope_labels_default() {
        let labels = ScopeLabels::default();
        assert!(labels.is_global());
    }

    // Note: ScopedMetrics::new() test requires Prometheus to not already have
    // these metrics registered, which can conflict with other tests.
    // In production, metrics are registered once at startup.
}
