//! Prometheus metrics endpoint for Zentinel proxy.
//!
//! This module provides:
//! - An HTTP endpoint for Prometheus to scrape metrics
//! - Integration with the UnifiedMetricsAggregator
//! - Standard proxy metrics (requests, latencies, errors)
//! - Agent pool metrics from v2 agents

use pingora_http::ResponseHeader;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zentinel_agent_protocol::v2::{MetricsCollector, UnifiedMetricsAggregator};

/// Metrics manager for the proxy.
///
/// This manages all proxy metrics and provides a Prometheus-compatible
/// export endpoint.
pub struct MetricsManager {
    /// The unified metrics aggregator
    aggregator: Arc<UnifiedMetricsAggregator>,
    /// Whether metrics are enabled
    enabled: bool,
    /// Path for the metrics endpoint
    path: String,
    /// Allowed IP addresses for metrics access (empty = all allowed)
    allowed_ips: Vec<String>,
    /// Pool metrics collectors from v2 agents (agent_id -> collector)
    pool_metrics: RwLock<HashMap<String, Arc<MetricsCollector>>>,
}

impl MetricsManager {
    /// Create a new metrics manager.
    pub fn new(service_name: impl Into<String>, instance_id: impl Into<String>) -> Self {
        Self {
            aggregator: Arc::new(UnifiedMetricsAggregator::new(service_name, instance_id)),
            enabled: true,
            path: "/metrics".to_string(),
            allowed_ips: Vec::new(),
            pool_metrics: RwLock::new(HashMap::new()),
        }
    }

    /// Create from an existing aggregator.
    pub fn with_aggregator(aggregator: Arc<UnifiedMetricsAggregator>) -> Self {
        Self {
            aggregator,
            enabled: true,
            path: "/metrics".to_string(),
            allowed_ips: Vec::new(),
            pool_metrics: RwLock::new(HashMap::new()),
        }
    }

    /// Create from metrics configuration.
    ///
    /// Applies `enabled` and `path` from the config.
    /// The `address` field determines which listener serves the metrics
    /// endpoint but is handled at the listener level, not here.
    pub fn from_config(
        config: &zentinel_config::MetricsConfig,
        service_name: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Self {
        let mut manager = Self::new(service_name, instance_id);
        manager.enabled = config.enabled;
        manager.path = config.path.clone();
        manager
    }

    /// Set the metrics endpoint path.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set allowed IPs for metrics access.
    pub fn allowed_ips(mut self, ips: Vec<String>) -> Self {
        self.allowed_ips = ips;
        self
    }

    /// Disable metrics collection.
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check if metrics are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the metrics path.
    pub fn metrics_path(&self) -> &str {
        &self.path
    }

    /// Get a reference to the aggregator.
    pub fn aggregator(&self) -> &UnifiedMetricsAggregator {
        &self.aggregator
    }

    /// Get an Arc to the aggregator.
    pub fn aggregator_arc(&self) -> Arc<UnifiedMetricsAggregator> {
        Arc::clone(&self.aggregator)
    }

    /// Check if an IP is allowed to access metrics.
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true;
        }
        self.allowed_ips.iter().any(|allowed| allowed == ip)
    }

    /// Register a pool metrics collector for a v2 agent.
    ///
    /// Pool metrics will be included in the /metrics output.
    pub async fn register_pool_metrics(
        &self,
        agent_id: impl Into<String>,
        collector: Arc<MetricsCollector>,
    ) {
        self.pool_metrics
            .write()
            .await
            .insert(agent_id.into(), collector);
    }

    /// Unregister a pool metrics collector.
    pub async fn unregister_pool_metrics(&self, agent_id: &str) {
        self.pool_metrics.write().await.remove(agent_id);
    }

    /// Handle a metrics request.
    ///
    /// Returns the Prometheus text format metrics body, including:
    /// - Proxy metrics from the UnifiedMetricsAggregator
    /// - Pool metrics from all registered v2 agent pools
    pub fn handle_metrics_request(&self) -> MetricsResponse {
        if !self.enabled {
            return MetricsResponse::not_found();
        }

        // Export proxy metrics
        let mut body = self.aggregator.export_prometheus();

        // Append pool metrics from all registered v2 agents
        // Use try_read to avoid blocking - if lock is held, skip pool metrics this scrape
        if let Ok(pool_metrics) = self.pool_metrics.try_read() {
            for (agent_id, collector) in pool_metrics.iter() {
                let pool_output = collector.export_prometheus();
                if !pool_output.is_empty() {
                    // Add a comment separator for clarity
                    body.push_str(&format!("\n# Agent pool metrics: {}\n", agent_id));
                    body.push_str(&pool_output);
                }
            }
        }

        MetricsResponse::ok(body)
    }

    // -------------------------------------------------------------------------
    // Convenience methods for recording proxy metrics
    // -------------------------------------------------------------------------

    /// Increment total requests counter.
    pub fn inc_requests_total(&self, method: &str, status: u16, route: &str) {
        let mut labels = HashMap::new();
        labels.insert("method".to_string(), method.to_string());
        labels.insert("status".to_string(), status.to_string());
        labels.insert("route".to_string(), route.to_string());

        self.aggregator.increment_counter(
            "zentinel_requests_total",
            "Total HTTP requests handled by the proxy",
            labels,
            1,
        );
    }

    /// Record request duration.
    pub fn observe_request_duration(&self, method: &str, route: &str, duration_secs: f64) {
        let mut labels = HashMap::new();
        labels.insert("method".to_string(), method.to_string());
        labels.insert("route".to_string(), route.to_string());

        // Standard latency buckets
        let buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        self.aggregator.observe_histogram(
            "zentinel_request_duration_seconds",
            "HTTP request duration in seconds",
            labels,
            &buckets,
            duration_secs,
        );
    }

    /// Set active connections gauge.
    pub fn set_active_connections(&self, count: f64) {
        self.aggregator.set_gauge(
            "zentinel_active_connections",
            "Number of active client connections",
            HashMap::new(),
            count,
        );
    }

    /// Set active requests gauge.
    pub fn set_active_requests(&self, count: f64) {
        self.aggregator.set_gauge(
            "zentinel_active_requests",
            "Number of requests currently being processed",
            HashMap::new(),
            count,
        );
    }

    /// Increment upstream requests.
    pub fn inc_upstream_requests(&self, upstream: &str, status: u16, success: bool) {
        let mut labels = HashMap::new();
        labels.insert("upstream".to_string(), upstream.to_string());
        labels.insert("status".to_string(), status.to_string());
        labels.insert("success".to_string(), success.to_string());

        self.aggregator.increment_counter(
            "zentinel_upstream_requests_total",
            "Total requests to upstream servers",
            labels,
            1,
        );
    }

    /// Record upstream latency.
    pub fn observe_upstream_duration(&self, upstream: &str, duration_secs: f64) {
        let mut labels = HashMap::new();
        labels.insert("upstream".to_string(), upstream.to_string());

        let buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        self.aggregator.observe_histogram(
            "zentinel_upstream_duration_seconds",
            "Time spent waiting for upstream response",
            labels,
            &buckets,
            duration_secs,
        );
    }

    /// Increment agent requests.
    pub fn inc_agent_requests(&self, agent: &str, decision: &str) {
        let mut labels = HashMap::new();
        labels.insert("agent".to_string(), agent.to_string());
        labels.insert("decision".to_string(), decision.to_string());

        self.aggregator.increment_counter(
            "zentinel_agent_requests_total",
            "Total requests processed by agents",
            labels,
            1,
        );
    }

    /// Record agent processing time.
    pub fn observe_agent_duration(&self, agent: &str, duration_secs: f64) {
        let mut labels = HashMap::new();
        labels.insert("agent".to_string(), agent.to_string());

        let buckets = vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0];

        self.aggregator.observe_histogram(
            "zentinel_agent_duration_seconds",
            "Time spent processing request in agent",
            labels,
            &buckets,
            duration_secs,
        );
    }

    /// Increment circuit breaker trips.
    pub fn inc_circuit_breaker_trips(&self, upstream: &str) {
        let mut labels = HashMap::new();
        labels.insert("upstream".to_string(), upstream.to_string());

        self.aggregator.increment_counter(
            "zentinel_circuit_breaker_trips_total",
            "Number of times circuit breaker has tripped",
            labels,
            1,
        );
    }

    /// Set circuit breaker state.
    pub fn set_circuit_breaker_state(&self, upstream: &str, open: bool) {
        let mut labels = HashMap::new();
        labels.insert("upstream".to_string(), upstream.to_string());

        self.aggregator.set_gauge(
            "zentinel_circuit_breaker_open",
            "Whether circuit breaker is open (1) or closed (0)",
            labels,
            if open { 1.0 } else { 0.0 },
        );
    }

    /// Increment rate limited requests.
    pub fn inc_rate_limited(&self, route: &str) {
        let mut labels = HashMap::new();
        labels.insert("route".to_string(), route.to_string());

        self.aggregator.increment_counter(
            "zentinel_rate_limited_total",
            "Total requests rate limited",
            labels,
            1,
        );
    }

    /// Increment cache hits/misses.
    pub fn inc_cache_access(&self, hit: bool) {
        let mut labels = HashMap::new();
        labels.insert(
            "result".to_string(),
            if hit { "hit" } else { "miss" }.to_string(),
        );

        self.aggregator.increment_counter(
            "zentinel_cache_accesses_total",
            "Total cache accesses",
            labels,
            1,
        );
    }

    /// Set cache size.
    pub fn set_cache_size(&self, size_bytes: f64) {
        self.aggregator.set_gauge(
            "zentinel_cache_size_bytes",
            "Current cache size in bytes",
            HashMap::new(),
            size_bytes,
        );
    }
}

/// Response for metrics requests.
#[derive(Debug)]
pub struct MetricsResponse {
    /// HTTP status code
    pub status: u16,
    /// Content type
    pub content_type: String,
    /// Response body
    pub body: String,
}

impl MetricsResponse {
    /// Create a successful metrics response.
    pub fn ok(body: String) -> Self {
        Self {
            status: 200,
            content_type: "text/plain; version=0.0.4; charset=utf-8".to_string(),
            body,
        }
    }

    /// Create a 404 response.
    pub fn not_found() -> Self {
        Self {
            status: 404,
            content_type: "text/plain".to_string(),
            body: "Metrics not found".to_string(),
        }
    }

    /// Create a 403 response.
    pub fn forbidden() -> Self {
        Self {
            status: 403,
            content_type: "text/plain".to_string(),
            body: "Forbidden".to_string(),
        }
    }

    /// Convert to HTTP response header.
    pub fn to_header(&self) -> ResponseHeader {
        let mut header = ResponseHeader::build(self.status, Some(2)).unwrap();
        header
            .append_header("Content-Type", &self.content_type)
            .ok();
        header
            .append_header("Content-Length", self.body.len().to_string())
            .ok();
        header
    }
}

/// Standard metric names for Zentinel proxy.
pub mod standard {
    /// Total HTTP requests
    pub const REQUESTS_TOTAL: &str = "zentinel_requests_total";
    /// Request duration histogram
    pub const REQUEST_DURATION: &str = "zentinel_request_duration_seconds";
    /// Active connections gauge
    pub const ACTIVE_CONNECTIONS: &str = "zentinel_active_connections";
    /// Active requests gauge
    pub const ACTIVE_REQUESTS: &str = "zentinel_active_requests";
    /// Upstream requests total
    pub const UPSTREAM_REQUESTS: &str = "zentinel_upstream_requests_total";
    /// Upstream duration histogram
    pub const UPSTREAM_DURATION: &str = "zentinel_upstream_duration_seconds";
    /// Agent requests total
    pub const AGENT_REQUESTS: &str = "zentinel_agent_requests_total";
    /// Agent duration histogram
    pub const AGENT_DURATION: &str = "zentinel_agent_duration_seconds";
    /// Circuit breaker trips
    pub const CIRCUIT_BREAKER_TRIPS: &str = "zentinel_circuit_breaker_trips_total";
    /// Circuit breaker state
    pub const CIRCUIT_BREAKER_OPEN: &str = "zentinel_circuit_breaker_open";
    /// Rate limited requests
    pub const RATE_LIMITED: &str = "zentinel_rate_limited_total";
    /// Cache accesses
    pub const CACHE_ACCESSES: &str = "zentinel_cache_accesses_total";
    /// Cache size
    pub const CACHE_SIZE: &str = "zentinel_cache_size_bytes";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_manager_creation() {
        let manager = MetricsManager::new("test-service", "node-1");
        assert!(manager.is_enabled());
        assert_eq!(manager.metrics_path(), "/metrics");
    }

    #[test]
    fn test_metrics_manager_disabled() {
        let manager = MetricsManager::new("test", "1").disable();
        assert!(!manager.is_enabled());

        let response = manager.handle_metrics_request();
        assert_eq!(response.status, 404);
    }

    #[test]
    fn test_metrics_manager_ip_filtering() {
        let manager = MetricsManager::new("test", "1")
            .allowed_ips(vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()]);

        assert!(manager.is_ip_allowed("127.0.0.1"));
        assert!(manager.is_ip_allowed("10.0.0.1"));
        assert!(!manager.is_ip_allowed("192.168.1.1"));
    }

    #[test]
    fn test_metrics_manager_all_ips_allowed() {
        let manager = MetricsManager::new("test", "1");

        // Empty allowed_ips means all IPs are allowed
        assert!(manager.is_ip_allowed("127.0.0.1"));
        assert!(manager.is_ip_allowed("192.168.1.1"));
        assert!(manager.is_ip_allowed("any-ip"));
    }

    #[test]
    fn test_metrics_response() {
        let manager = MetricsManager::new("test", "node-1");

        // Record some metrics
        manager.inc_requests_total("GET", 200, "/api/users");
        manager.set_active_connections(42.0);

        let response = manager.handle_metrics_request();
        assert_eq!(response.status, 200);
        assert!(response.content_type.contains("text/plain"));
        assert!(response.body.contains("zentinel_requests_total"));
        assert!(response.body.contains("zentinel_active_connections"));
        assert!(response.body.contains("zentinel_info"));
    }

    #[test]
    fn test_request_duration_histogram() {
        let manager = MetricsManager::new("test", "1");

        manager.observe_request_duration("GET", "/api", 0.05);
        manager.observe_request_duration("GET", "/api", 0.15);
        manager.observe_request_duration("GET", "/api", 0.5);

        let response = manager.handle_metrics_request();
        assert!(response
            .body
            .contains("zentinel_request_duration_seconds_bucket"));
        assert!(response
            .body
            .contains("zentinel_request_duration_seconds_sum"));
        assert!(response
            .body
            .contains("zentinel_request_duration_seconds_count"));
        // Verify count is 3 (with labels, the format is {labels} 3)
        assert!(response.body.contains("} 3\n") || response.body.contains(" 3\n"));
    }

    #[test]
    fn test_custom_path() {
        let manager = MetricsManager::new("test", "1").path("/internal/metrics");
        assert_eq!(manager.metrics_path(), "/internal/metrics");
    }

    #[test]
    fn test_upstream_metrics() {
        let manager = MetricsManager::new("test", "1");

        manager.inc_upstream_requests("backend-1", 200, true);
        manager.observe_upstream_duration("backend-1", 0.1);

        let response = manager.handle_metrics_request();
        assert!(response.body.contains("zentinel_upstream_requests_total"));
        assert!(response.body.contains("zentinel_upstream_duration_seconds"));
    }

    #[test]
    fn test_agent_metrics() {
        let manager = MetricsManager::new("test", "1");

        manager.inc_agent_requests("waf", "allow");
        manager.observe_agent_duration("waf", 0.005);

        let response = manager.handle_metrics_request();
        assert!(response.body.contains("zentinel_agent_requests_total"));
        assert!(response.body.contains("zentinel_agent_duration_seconds"));
    }
}
