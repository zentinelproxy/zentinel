//! Metrics module for Sentinel proxy
//!
//! Provides basic metrics collection for monitoring proxy performance and health.

use prometheus::{
    register_histogram_vec, register_int_counter_vec, register_int_gauge,
    HistogramVec, IntCounterVec, IntGauge,
};

/// Metrics collector for the proxy
pub struct Metrics {
    /// Request duration histogram
    request_duration: HistogramVec,
    /// Request count by status
    request_count: IntCounterVec,
    /// Active requests gauge
    active_requests: IntGauge,
}

impl Metrics {
    /// Create new metrics instance
    pub fn new() -> Self {
        let request_duration = register_histogram_vec!(
            "sentinel_request_duration_seconds",
            "Request duration in seconds",
            &["route", "status"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        .expect("Failed to register request_duration metric");

        let request_count = register_int_counter_vec!(
            "sentinel_requests_total",
            "Total number of requests",
            &["status"]
        )
        .expect("Failed to register request_count metric");

        let active_requests = register_int_gauge!(
            "sentinel_active_requests",
            "Number of currently active requests"
        )
        .expect("Failed to register active_requests metric");

        Self {
            request_duration,
            request_count,
            active_requests,
        }
    }

    /// Record a completed request
    pub fn record_request(&self, status: u16, duration_ms: f64) {
        let status_str = status.to_string();

        self.request_duration
            .with_label_values(&["default", &status_str])
            .observe(duration_ms / 1000.0);

        self.request_count
            .with_label_values(&[&status_str])
            .inc();
    }

    /// Increment active requests
    pub fn inc_active_requests(&self) {
        self.active_requests.inc();
    }

    /// Decrement active requests
    pub fn dec_active_requests(&self) {
        self.active_requests.dec();
    }
}
