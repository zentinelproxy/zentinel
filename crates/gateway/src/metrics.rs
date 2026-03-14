//! Prometheus metrics for the Gateway API controller.
//!
//! Exposes reconciliation performance, config translation stats, and
//! resource counts for operational visibility.

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry,
};

/// All controller metrics, registered with a Prometheus registry.
pub struct ControllerMetrics {
    /// Total reconciliations by resource type and result.
    pub reconciliations_total: IntCounterVec,
    /// Reconciliation duration in seconds by resource type.
    pub reconciliation_duration_seconds: HistogramVec,
    /// Total config rebuilds (successful).
    pub config_rebuilds_total: IntCounter,
    /// Config rebuild duration in seconds.
    pub config_rebuild_duration_seconds: Histogram,
    /// Total config rebuild failures.
    pub config_rebuild_errors_total: IntCounter,
    /// Number of active Gateways managed by this controller.
    pub active_gateways: IntGauge,
    /// Number of active HTTPRoutes managed by this controller.
    pub active_httproutes: IntGauge,
    /// Number of active upstreams in the translated config.
    pub active_upstreams: IntGauge,
    /// Number of active listeners in the translated config.
    pub active_listeners: IntGauge,
    /// Whether this instance is the leader (1 = leader, 0 = standby).
    pub is_leader: IntGauge,
    /// TLS certificate resolution errors.
    pub tls_errors_total: IntCounter,
}

impl ControllerMetrics {
    /// Create and register all metrics with the given registry.
    pub fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let reconciliations_total = IntCounterVec::new(
            Opts::new(
                "zentinel_gateway_reconciliations_total",
                "Total number of reconciliations by resource type and result",
            ),
            &["resource", "result"],
        )?;
        registry.register(Box::new(reconciliations_total.clone()))?;

        let reconciliation_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "zentinel_gateway_reconciliation_duration_seconds",
                "Duration of reconciliation by resource type",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0]),
            &["resource"],
        )?;
        registry.register(Box::new(reconciliation_duration_seconds.clone()))?;

        let config_rebuilds_total = IntCounter::new(
            "zentinel_gateway_config_rebuilds_total",
            "Total number of successful config rebuilds from Gateway API resources",
        )?;
        registry.register(Box::new(config_rebuilds_total.clone()))?;

        let config_rebuild_duration_seconds = Histogram::with_opts(
            HistogramOpts::new(
                "zentinel_gateway_config_rebuild_duration_seconds",
                "Duration of config rebuild from Gateway API resources",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]),
        )?;
        registry.register(Box::new(config_rebuild_duration_seconds.clone()))?;

        let config_rebuild_errors_total = IntCounter::new(
            "zentinel_gateway_config_rebuild_errors_total",
            "Total number of failed config rebuilds",
        )?;
        registry.register(Box::new(config_rebuild_errors_total.clone()))?;

        let active_gateways = IntGauge::new(
            "zentinel_gateway_active_gateways",
            "Number of Gateway resources managed by this controller",
        )?;
        registry.register(Box::new(active_gateways.clone()))?;

        let active_httproutes = IntGauge::new(
            "zentinel_gateway_active_httproutes",
            "Number of HTTPRoute resources managed by this controller",
        )?;
        registry.register(Box::new(active_httproutes.clone()))?;

        let active_upstreams = IntGauge::new(
            "zentinel_gateway_active_upstreams",
            "Number of upstreams in the translated config",
        )?;
        registry.register(Box::new(active_upstreams.clone()))?;

        let active_listeners = IntGauge::new(
            "zentinel_gateway_active_listeners",
            "Number of listeners in the translated config",
        )?;
        registry.register(Box::new(active_listeners.clone()))?;

        let is_leader = IntGauge::new(
            "zentinel_gateway_is_leader",
            "Whether this instance is the leader (1) or standby (0)",
        )?;
        registry.register(Box::new(is_leader.clone()))?;

        let tls_errors_total = IntCounter::new(
            "zentinel_gateway_tls_errors_total",
            "Total TLS certificate resolution errors",
        )?;
        registry.register(Box::new(tls_errors_total.clone()))?;

        Ok(Self {
            reconciliations_total,
            reconciliation_duration_seconds,
            config_rebuilds_total,
            config_rebuild_duration_seconds,
            config_rebuild_errors_total,
            active_gateways,
            active_httproutes,
            active_upstreams,
            active_listeners,
            is_leader,
            tls_errors_total,
        })
    }

    /// Record a successful reconciliation.
    pub fn record_reconciliation(&self, resource: &str, duration_secs: f64) {
        self.reconciliations_total
            .with_label_values(&[resource, "success"])
            .inc();
        self.reconciliation_duration_seconds
            .with_label_values(&[resource])
            .observe(duration_secs);
    }

    /// Record a failed reconciliation.
    pub fn record_reconciliation_error(&self, resource: &str, duration_secs: f64) {
        self.reconciliations_total
            .with_label_values(&[resource, "error"])
            .inc();
        self.reconciliation_duration_seconds
            .with_label_values(&[resource])
            .observe(duration_secs);
    }

    /// Record a successful config rebuild.
    pub fn record_config_rebuild(&self, duration_secs: f64, listeners: i64, upstreams: i64) {
        self.config_rebuilds_total.inc();
        self.config_rebuild_duration_seconds.observe(duration_secs);
        self.active_listeners.set(listeners);
        self.active_upstreams.set(upstreams);
    }

    /// Record a failed config rebuild.
    pub fn record_config_rebuild_error(&self) {
        self.config_rebuild_errors_total.inc();
    }
}
