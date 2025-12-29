//! Agent metrics collection.

use std::sync::atomic::{AtomicU64, Ordering};

/// Agent metrics collector.
///
/// Tracks call counts, success/failure rates, and decision distributions.
#[derive(Default)]
pub struct AgentMetrics {
    /// Total calls
    pub calls_total: AtomicU64,
    /// Successful calls
    pub calls_success: AtomicU64,
    /// Failed calls
    pub calls_failed: AtomicU64,
    /// Timeout calls
    pub calls_timeout: AtomicU64,
    /// Circuit breaker trips
    pub circuit_breaker_trips: AtomicU64,
    /// Total call duration (microseconds)
    pub duration_total_us: AtomicU64,
    /// Decisions by type
    pub decisions_allow: AtomicU64,
    pub decisions_block: AtomicU64,
    pub decisions_redirect: AtomicU64,
    pub decisions_challenge: AtomicU64,
}

impl AgentMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful call with duration.
    pub fn record_success(&self, duration_us: u64) {
        self.calls_total.fetch_add(1, Ordering::Relaxed);
        self.calls_success.fetch_add(1, Ordering::Relaxed);
        self.duration_total_us.fetch_add(duration_us, Ordering::Relaxed);
    }

    /// Record a failed call.
    pub fn record_failure(&self) {
        self.calls_total.fetch_add(1, Ordering::Relaxed);
        self.calls_failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a timeout.
    pub fn record_timeout(&self) {
        self.calls_total.fetch_add(1, Ordering::Relaxed);
        self.calls_timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// Get average call duration in microseconds.
    pub fn average_duration_us(&self) -> f64 {
        let total = self.duration_total_us.load(Ordering::Relaxed) as f64;
        let success = self.calls_success.load(Ordering::Relaxed) as f64;
        if success > 0.0 {
            total / success
        } else {
            0.0
        }
    }
}
