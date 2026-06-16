//! Protocol-level metrics for Agent Protocol v2.
//!
//! This module provides internal metrics tracking for the protocol layer:
//! - Serialization time histograms
//! - Flow control event counters
//! - Buffer utilization gauges
//! - Request/response counters
//!
//! These metrics are for proxy-side instrumentation, not agent-reported metrics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Protocol-level metrics for the agent pool.
#[derive(Debug, Default)]
pub struct ProtocolMetrics {
    // Counters
    /// Total requests sent
    pub requests_total: AtomicU64,
    /// Total responses received
    pub responses_total: AtomicU64,
    /// Requests that timed out
    pub timeouts_total: AtomicU64,
    /// Connection errors
    pub connection_errors_total: AtomicU64,
    /// Serialization errors
    pub serialization_errors_total: AtomicU64,
    /// Flow control pause events
    pub flow_control_pauses_total: AtomicU64,
    /// Flow control resume events
    pub flow_control_resumes_total: AtomicU64,
    /// Requests rejected due to flow control
    pub flow_control_rejections_total: AtomicU64,
    /// Correlation affinities reclaimed by TTL sweep (requests that ended
    /// without explicit cleanup)
    pub affinity_evictions_total: AtomicU64,
    /// Affinities dropped because the affinity map was at capacity
    pub affinity_rejections_total: AtomicU64,

    // Gauges
    /// Current in-flight requests
    pub in_flight_requests: AtomicU64,
    /// Current correlation affinity entries
    pub correlation_affinities: AtomicU64,
    /// Current buffer utilization (0-100)
    pub buffer_utilization_percent: AtomicU64,
    /// Number of healthy connections
    pub healthy_connections: AtomicU64,
    /// Number of paused connections (flow control)
    pub paused_connections: AtomicU64,

    // Histograms (using simple bucketed approach)
    /// Serialization time histogram
    pub serialization_time: HistogramMetric,
    /// Request duration histogram (end-to-end)
    pub request_duration: HistogramMetric,
}

impl ProtocolMetrics {
    /// Create new protocol metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment requests total.
    #[inline]
    pub fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment responses total.
    #[inline]
    pub fn inc_responses(&self) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment timeouts.
    #[inline]
    pub fn inc_timeouts(&self) {
        self.timeouts_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment connection errors.
    #[inline]
    pub fn inc_connection_errors(&self) {
        self.connection_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment serialization errors.
    #[inline]
    pub fn inc_serialization_errors(&self) {
        self.serialization_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record flow control pause.
    #[inline]
    pub fn record_flow_pause(&self) {
        self.flow_control_pauses_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record flow control resume.
    #[inline]
    pub fn record_flow_resume(&self) {
        self.flow_control_resumes_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record flow control rejection.
    #[inline]
    pub fn record_flow_rejection(&self) {
        self.flow_control_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment affinity TTL evictions.
    #[inline]
    pub fn inc_affinity_evictions(&self, count: u64) {
        self.affinity_evictions_total
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Increment affinity at-capacity rejections.
    #[inline]
    pub fn inc_affinity_rejections(&self) {
        self.affinity_rejections_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Set correlation affinities gauge.
    #[inline]
    pub fn set_correlation_affinities(&self, count: u64) {
        self.correlation_affinities.store(count, Ordering::Relaxed);
    }

    /// Set in-flight requests gauge.
    #[inline]
    pub fn set_in_flight(&self, count: u64) {
        self.in_flight_requests.store(count, Ordering::Relaxed);
    }

    /// Increment in-flight requests.
    #[inline]
    pub fn inc_in_flight(&self) {
        self.in_flight_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement in-flight requests.
    #[inline]
    pub fn dec_in_flight(&self) {
        self.in_flight_requests.fetch_sub(1, Ordering::Relaxed);
    }

    /// Set buffer utilization percentage.
    #[inline]
    pub fn set_buffer_utilization(&self, percent: u64) {
        self.buffer_utilization_percent
            .store(percent.min(100), Ordering::Relaxed);
    }

    /// Set healthy connections gauge.
    #[inline]
    pub fn set_healthy_connections(&self, count: u64) {
        self.healthy_connections.store(count, Ordering::Relaxed);
    }

    /// Set paused connections gauge.
    #[inline]
    pub fn set_paused_connections(&self, count: u64) {
        self.paused_connections.store(count, Ordering::Relaxed);
    }

    /// Record serialization time.
    #[inline]
    pub fn record_serialization_time(&self, duration: Duration) {
        self.serialization_time.record(duration);
    }

    /// Record request duration.
    #[inline]
    pub fn record_request_duration(&self, duration: Duration) {
        self.request_duration.record(duration);
    }

    /// Get a snapshot of all metrics.
    pub fn snapshot(&self) -> ProtocolMetricsSnapshot {
        ProtocolMetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            responses_total: self.responses_total.load(Ordering::Relaxed),
            timeouts_total: self.timeouts_total.load(Ordering::Relaxed),
            connection_errors_total: self.connection_errors_total.load(Ordering::Relaxed),
            serialization_errors_total: self.serialization_errors_total.load(Ordering::Relaxed),
            flow_control_pauses_total: self.flow_control_pauses_total.load(Ordering::Relaxed),
            flow_control_resumes_total: self.flow_control_resumes_total.load(Ordering::Relaxed),
            flow_control_rejections_total: self
                .flow_control_rejections_total
                .load(Ordering::Relaxed),
            affinity_evictions_total: self.affinity_evictions_total.load(Ordering::Relaxed),
            affinity_rejections_total: self.affinity_rejections_total.load(Ordering::Relaxed),
            in_flight_requests: self.in_flight_requests.load(Ordering::Relaxed),
            correlation_affinities: self.correlation_affinities.load(Ordering::Relaxed),
            buffer_utilization_percent: self.buffer_utilization_percent.load(Ordering::Relaxed),
            healthy_connections: self.healthy_connections.load(Ordering::Relaxed),
            paused_connections: self.paused_connections.load(Ordering::Relaxed),
            serialization_time: self.serialization_time.snapshot(),
            request_duration: self.request_duration.snapshot(),
        }
    }

    /// Export metrics in Prometheus text format.
    pub fn to_prometheus(&self, prefix: &str) -> String {
        let snap = self.snapshot();
        let mut output = String::with_capacity(2048);

        // Counters
        output.push_str(&format!(
            "# HELP {prefix}_requests_total Total requests sent to agents\n\
             # TYPE {prefix}_requests_total counter\n\
             {prefix}_requests_total {}\n\n",
            snap.requests_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_responses_total Total responses received from agents\n\
             # TYPE {prefix}_responses_total counter\n\
             {prefix}_responses_total {}\n\n",
            snap.responses_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_timeouts_total Total request timeouts\n\
             # TYPE {prefix}_timeouts_total counter\n\
             {prefix}_timeouts_total {}\n\n",
            snap.timeouts_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_connection_errors_total Total connection errors\n\
             # TYPE {prefix}_connection_errors_total counter\n\
             {prefix}_connection_errors_total {}\n\n",
            snap.connection_errors_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_flow_control_pauses_total Flow control pause events\n\
             # TYPE {prefix}_flow_control_pauses_total counter\n\
             {prefix}_flow_control_pauses_total {}\n\n",
            snap.flow_control_pauses_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_flow_control_rejections_total Requests rejected due to flow control\n\
             # TYPE {prefix}_flow_control_rejections_total counter\n\
             {prefix}_flow_control_rejections_total {}\n\n",
            snap.flow_control_rejections_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_affinity_evictions_total Correlation affinities reclaimed by TTL sweep\n\
             # TYPE {prefix}_affinity_evictions_total counter\n\
             {prefix}_affinity_evictions_total {}\n\n",
            snap.affinity_evictions_total
        ));

        output.push_str(&format!(
            "# HELP {prefix}_affinity_rejections_total Affinities dropped because the map was at capacity\n\
             # TYPE {prefix}_affinity_rejections_total counter\n\
             {prefix}_affinity_rejections_total {}\n\n",
            snap.affinity_rejections_total
        ));

        // Gauges
        output.push_str(&format!(
            "# HELP {prefix}_in_flight_requests Current in-flight requests\n\
             # TYPE {prefix}_in_flight_requests gauge\n\
             {prefix}_in_flight_requests {}\n\n",
            snap.in_flight_requests
        ));

        output.push_str(&format!(
            "# HELP {prefix}_correlation_affinities Current correlation affinity entries\n\
             # TYPE {prefix}_correlation_affinities gauge\n\
             {prefix}_correlation_affinities {}\n\n",
            snap.correlation_affinities
        ));

        output.push_str(&format!(
            "# HELP {prefix}_buffer_utilization_percent Buffer utilization percentage\n\
             # TYPE {prefix}_buffer_utilization_percent gauge\n\
             {prefix}_buffer_utilization_percent {}\n\n",
            snap.buffer_utilization_percent
        ));

        output.push_str(&format!(
            "# HELP {prefix}_healthy_connections Number of healthy agent connections\n\
             # TYPE {prefix}_healthy_connections gauge\n\
             {prefix}_healthy_connections {}\n\n",
            snap.healthy_connections
        ));

        output.push_str(&format!(
            "# HELP {prefix}_paused_connections Number of flow-control paused connections\n\
             # TYPE {prefix}_paused_connections gauge\n\
             {prefix}_paused_connections {}\n\n",
            snap.paused_connections
        ));

        // Histograms
        output.push_str(&snap.serialization_time.to_prometheus(
            &format!("{prefix}_serialization_seconds"),
            "Serialization time in seconds",
        ));

        output.push_str(&snap.request_duration.to_prometheus(
            &format!("{prefix}_request_duration_seconds"),
            "Request duration in seconds",
        ));

        output
    }
}

/// Simple histogram metric using predefined buckets.
#[derive(Debug)]
pub struct HistogramMetric {
    /// Bucket boundaries in microseconds
    buckets: Vec<u64>,
    /// Counts per bucket (one extra for +Inf)
    counts: Vec<AtomicU64>,
    /// Sum of all observations in microseconds
    sum: AtomicU64,
    /// Total count
    count: AtomicU64,
}

impl Default for HistogramMetric {
    fn default() -> Self {
        // Default buckets: 10μs, 50μs, 100μs, 500μs, 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s
        let buckets = vec![
            10, 50, 100, 500, 1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000,
        ];
        let counts = (0..=buckets.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl HistogramMetric {
    /// Create a new histogram with custom bucket boundaries (in microseconds).
    pub fn with_buckets(buckets: Vec<u64>) -> Self {
        let counts = (0..=buckets.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation.
    #[inline]
    pub fn record(&self, duration: Duration) {
        let micros = duration.as_micros() as u64;

        // Update sum and count
        self.sum.fetch_add(micros, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        // Find bucket and increment
        let bucket_idx = self
            .buckets
            .iter()
            .position(|&b| micros <= b)
            .unwrap_or(self.buckets.len());
        self.counts[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of the histogram.
    pub fn snapshot(&self) -> HistogramSnapshot {
        HistogramSnapshot {
            buckets: self.buckets.clone(),
            counts: self
                .counts
                .iter()
                .map(|c| c.load(Ordering::Relaxed))
                .collect(),
            sum: self.sum.load(Ordering::Relaxed),
            count: self.count.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of histogram data.
#[derive(Debug, Clone)]
pub struct HistogramSnapshot {
    /// Bucket boundaries in microseconds
    pub buckets: Vec<u64>,
    /// Counts per bucket
    pub counts: Vec<u64>,
    /// Sum of all observations in microseconds
    pub sum: u64,
    /// Total count
    pub count: u64,
}

impl HistogramSnapshot {
    /// Export to Prometheus format.
    pub fn to_prometheus(&self, name: &str, help: &str) -> String {
        let mut output = String::with_capacity(512);

        output.push_str(&format!("# HELP {name} {help}\n"));
        output.push_str(&format!("# TYPE {name} histogram\n"));

        // Cumulative bucket counts
        let mut cumulative = 0u64;
        for (i, &boundary) in self.buckets.iter().enumerate() {
            cumulative += self.counts[i];
            let le = boundary as f64 / 1_000_000.0; // Convert to seconds
            output.push_str(&format!("{name}_bucket{{le=\"{le:.6}\"}} {cumulative}\n"));
        }

        // +Inf bucket
        cumulative += self.counts.last().copied().unwrap_or(0);
        output.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cumulative}\n"));

        // Sum and count
        let sum_seconds = self.sum as f64 / 1_000_000.0;
        output.push_str(&format!("{name}_sum {sum_seconds:.6}\n"));
        output.push_str(&format!("{name}_count {}\n\n", self.count));

        output
    }

    /// Get the mean value in microseconds.
    pub fn mean_micros(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum as f64 / self.count as f64
        }
    }

    /// Get the approximate percentile value in microseconds.
    pub fn percentile_micros(&self, p: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }

        let target = (self.count as f64 * p / 100.0).ceil() as u64;
        let mut cumulative = 0u64;

        for (i, &count) in self.counts.iter().enumerate() {
            cumulative += count;
            if cumulative >= target {
                return if i < self.buckets.len() {
                    self.buckets[i]
                } else {
                    // +Inf bucket, return last finite bucket
                    self.buckets.last().copied().unwrap_or(0)
                };
            }
        }

        self.buckets.last().copied().unwrap_or(0)
    }
}

/// Snapshot of all protocol metrics.
#[derive(Debug, Clone)]
pub struct ProtocolMetricsSnapshot {
    // Counters
    pub requests_total: u64,
    pub responses_total: u64,
    pub timeouts_total: u64,
    pub connection_errors_total: u64,
    pub serialization_errors_total: u64,
    pub flow_control_pauses_total: u64,
    pub flow_control_resumes_total: u64,
    pub flow_control_rejections_total: u64,
    pub affinity_evictions_total: u64,
    pub affinity_rejections_total: u64,

    // Gauges
    pub in_flight_requests: u64,
    pub correlation_affinities: u64,
    pub buffer_utilization_percent: u64,
    pub healthy_connections: u64,
    pub paused_connections: u64,

    // Histograms
    pub serialization_time: HistogramSnapshot,
    pub request_duration: HistogramSnapshot,
}

/// Helper to measure and record duration.
pub struct DurationRecorder<'a> {
    histogram: &'a HistogramMetric,
    start: Instant,
}

impl<'a> DurationRecorder<'a> {
    /// Start recording duration.
    pub fn new(histogram: &'a HistogramMetric) -> Self {
        Self {
            histogram,
            start: Instant::now(),
        }
    }

    /// Record the elapsed duration.
    pub fn record(self) {
        self.histogram.record(self.start.elapsed());
    }
}

impl Drop for DurationRecorder<'_> {
    fn drop(&mut self) {
        // Don't double-record, this is just a safety net
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increments() {
        let metrics = ProtocolMetrics::new();

        metrics.inc_requests();
        metrics.inc_requests();
        metrics.inc_responses();

        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 2);
        assert_eq!(snap.responses_total, 1);
    }

    #[test]
    fn test_gauge_updates() {
        let metrics = ProtocolMetrics::new();

        metrics.set_in_flight(5);
        metrics.inc_in_flight();
        metrics.dec_in_flight();

        let snap = metrics.snapshot();
        assert_eq!(snap.in_flight_requests, 5);
    }

    #[test]
    fn test_histogram_recording() {
        let metrics = ProtocolMetrics::new();

        metrics.record_serialization_time(Duration::from_micros(50));
        metrics.record_serialization_time(Duration::from_micros(150));
        metrics.record_serialization_time(Duration::from_millis(5));

        let snap = metrics.snapshot();
        assert_eq!(snap.serialization_time.count, 3);
        assert_eq!(snap.serialization_time.sum, 50 + 150 + 5000);
    }

    #[test]
    fn test_histogram_percentile() {
        let hist = HistogramMetric::default();

        // Record 100 observations from 1μs to 100μs
        for i in 1..=100 {
            hist.record(Duration::from_micros(i));
        }

        let snap = hist.snapshot();
        assert_eq!(snap.count, 100);

        // p50 should be around 50μs (in the 50μs bucket)
        let p50 = snap.percentile_micros(50.0);
        assert!(p50 <= 100, "p50 was {}", p50);
    }

    #[test]
    fn test_flow_control_metrics() {
        let metrics = ProtocolMetrics::new();

        metrics.record_flow_pause();
        metrics.record_flow_pause();
        metrics.record_flow_rejection();

        let snap = metrics.snapshot();
        assert_eq!(snap.flow_control_pauses_total, 2);
        assert_eq!(snap.flow_control_rejections_total, 1);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = ProtocolMetrics::new();

        metrics.inc_requests();
        metrics.set_healthy_connections(3);
        metrics.record_serialization_time(Duration::from_micros(100));

        let output = metrics.to_prometheus("agent_protocol");

        assert!(output.contains("agent_protocol_requests_total 1"));
        assert!(output.contains("agent_protocol_healthy_connections 3"));
        assert!(output.contains("agent_protocol_serialization_seconds"));
    }
}
