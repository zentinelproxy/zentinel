//! Observability module for Sentinel proxy
//!
//! Provides metrics, logging, and tracing infrastructure with a focus on
//! production reliability and sleepable operations.

use anyhow::{Context, Result};
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec, CounterVec, Gauge, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec,
};
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize the tracing/logging subsystem
pub fn init_tracing() -> Result<()> {
    // Use JSON format for structured logging in production
    let json_layer =
        if std::env::var("SENTINEL_LOG_FORMAT").unwrap_or_else(|_| "json".to_string()) == "json" {
            Some(
                fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_file(true)
                    .with_line_number(true),
            )
        } else {
            None
        };

    // Pretty format for development
    let pretty_layer = if std::env::var("SENTINEL_LOG_FORMAT")
        .unwrap_or_else(|_| "json".to_string())
        == "pretty"
    {
        Some(
            fmt::layer()
                .pretty()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true),
        )
    } else {
        None
    };

    // Configure log level from environment
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        .with(pretty_layer)
        .init();

    info!("Tracing initialized");
    Ok(())
}

/// Request metrics collector
pub struct RequestMetrics {
    /// Request latency histogram by route
    request_duration: HistogramVec,
    /// Request count by route and status code
    request_count: IntCounterVec,
    /// Active requests gauge
    active_requests: IntGauge,
    /// Upstream connection attempts
    upstream_attempts: IntCounterVec,
    /// Upstream failures
    upstream_failures: IntCounterVec,
    /// Circuit breaker state (0 = closed, 1 = open)
    circuit_breaker_state: IntGaugeVec,
    /// Agent call latency
    agent_latency: HistogramVec,
    /// Agent call timeouts
    agent_timeouts: IntCounterVec,
    /// Blocked requests by reason
    blocked_requests: CounterVec,
    /// Request body size histogram
    request_body_size: HistogramVec,
    /// Response body size histogram
    response_body_size: HistogramVec,
    /// TLS handshake duration
    tls_handshake_duration: HistogramVec,
    /// Connection pool metrics
    connection_pool_size: IntGaugeVec,
    connection_pool_idle: IntGaugeVec,
    connection_pool_acquired: IntCounterVec,
    /// System metrics
    memory_usage: IntGauge,
    cpu_usage: Gauge,
    open_connections: IntGauge,
}

impl RequestMetrics {
    /// Create new metrics collector and register with Prometheus
    pub fn new() -> Result<Self> {
        // Define buckets for latency histograms (in seconds)
        let latency_buckets = vec![
            0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ];

        // Define buckets for body size (in bytes)
        let size_buckets = vec![
            100.0,
            1_000.0,
            10_000.0,
            100_000.0,
            1_000_000.0,
            10_000_000.0,
            100_000_000.0,
        ];

        let request_duration = register_histogram_vec!(
            "sentinel_request_duration_seconds",
            "Request duration in seconds",
            &["route", "method"],
            latency_buckets.clone()
        )
        .context("Failed to register request_duration metric")?;

        let request_count = register_int_counter_vec!(
            "sentinel_requests_total",
            "Total number of requests",
            &["route", "method", "status"]
        )
        .context("Failed to register request_count metric")?;

        let active_requests = register_int_gauge!(
            "sentinel_active_requests",
            "Number of currently active requests"
        )
        .context("Failed to register active_requests metric")?;

        let upstream_attempts = register_int_counter_vec!(
            "sentinel_upstream_attempts_total",
            "Total upstream connection attempts",
            &["upstream", "route"]
        )
        .context("Failed to register upstream_attempts metric")?;

        let upstream_failures = register_int_counter_vec!(
            "sentinel_upstream_failures_total",
            "Total upstream connection failures",
            &["upstream", "route", "reason"]
        )
        .context("Failed to register upstream_failures metric")?;

        let circuit_breaker_state = register_int_gauge_vec!(
            "sentinel_circuit_breaker_state",
            "Circuit breaker state (0=closed, 1=open)",
            &["component", "route"]
        )
        .context("Failed to register circuit_breaker_state metric")?;

        let agent_latency = register_histogram_vec!(
            "sentinel_agent_latency_seconds",
            "Agent call latency in seconds",
            &["agent", "event"],
            latency_buckets.clone()
        )
        .context("Failed to register agent_latency metric")?;

        let agent_timeouts = register_int_counter_vec!(
            "sentinel_agent_timeouts_total",
            "Total agent call timeouts",
            &["agent", "event"]
        )
        .context("Failed to register agent_timeouts metric")?;

        let blocked_requests = register_counter_vec!(
            "sentinel_blocked_requests_total",
            "Total blocked requests by reason",
            &["reason"]
        )
        .context("Failed to register blocked_requests metric")?;

        let request_body_size = register_histogram_vec!(
            "sentinel_request_body_size_bytes",
            "Request body size in bytes",
            &["route"],
            size_buckets.clone()
        )
        .context("Failed to register request_body_size metric")?;

        let response_body_size = register_histogram_vec!(
            "sentinel_response_body_size_bytes",
            "Response body size in bytes",
            &["route"],
            size_buckets.clone()
        )
        .context("Failed to register response_body_size metric")?;

        let tls_handshake_duration = register_histogram_vec!(
            "sentinel_tls_handshake_duration_seconds",
            "TLS handshake duration in seconds",
            &["version"],
            latency_buckets
        )
        .context("Failed to register tls_handshake_duration metric")?;

        let connection_pool_size = register_int_gauge_vec!(
            "sentinel_connection_pool_size",
            "Total connections in pool",
            &["upstream"]
        )
        .context("Failed to register connection_pool_size metric")?;

        let connection_pool_idle = register_int_gauge_vec!(
            "sentinel_connection_pool_idle",
            "Idle connections in pool",
            &["upstream"]
        )
        .context("Failed to register connection_pool_idle metric")?;

        let connection_pool_acquired = register_int_counter_vec!(
            "sentinel_connection_pool_acquired_total",
            "Total connections acquired from pool",
            &["upstream"]
        )
        .context("Failed to register connection_pool_acquired metric")?;

        let memory_usage = register_int_gauge!(
            "sentinel_memory_usage_bytes",
            "Current memory usage in bytes"
        )
        .context("Failed to register memory_usage metric")?;

        let cpu_usage =
            register_gauge!("sentinel_cpu_usage_percent", "Current CPU usage percentage")
                .context("Failed to register cpu_usage metric")?;

        let open_connections =
            register_int_gauge!("sentinel_open_connections", "Number of open connections")
                .context("Failed to register open_connections metric")?;

        Ok(Self {
            request_duration,
            request_count,
            active_requests,
            upstream_attempts,
            upstream_failures,
            circuit_breaker_state,
            agent_latency,
            agent_timeouts,
            blocked_requests,
            request_body_size,
            response_body_size,
            tls_handshake_duration,
            connection_pool_size,
            connection_pool_idle,
            connection_pool_acquired,
            memory_usage,
            cpu_usage,
            open_connections,
        })
    }

    /// Record a completed request
    pub fn record_request(&self, route: &str, method: &str, status: u16, duration: Duration) {
        self.request_duration
            .with_label_values(&[route, method])
            .observe(duration.as_secs_f64());

        self.request_count
            .with_label_values(&[route, method, &status.to_string()])
            .inc();
    }

    /// Increment active request counter
    pub fn inc_active_requests(&self) {
        self.active_requests.inc();
    }

    /// Decrement active request counter
    pub fn dec_active_requests(&self) {
        self.active_requests.dec();
    }

    /// Record an upstream attempt
    pub fn record_upstream_attempt(&self, upstream: &str, route: &str) {
        self.upstream_attempts
            .with_label_values(&[upstream, route])
            .inc();
    }

    /// Record an upstream failure
    pub fn record_upstream_failure(&self, upstream: &str, route: &str, reason: &str) {
        self.upstream_failures
            .with_label_values(&[upstream, route, reason])
            .inc();
    }

    /// Update circuit breaker state
    pub fn set_circuit_breaker_state(&self, component: &str, route: &str, is_open: bool) {
        let state = if is_open { 1 } else { 0 };
        self.circuit_breaker_state
            .with_label_values(&[component, route])
            .set(state);
    }

    /// Record agent call latency
    pub fn record_agent_latency(&self, agent: &str, event: &str, duration: Duration) {
        self.agent_latency
            .with_label_values(&[agent, event])
            .observe(duration.as_secs_f64());
    }

    /// Record agent timeout
    pub fn record_agent_timeout(&self, agent: &str, event: &str) {
        self.agent_timeouts.with_label_values(&[agent, event]).inc();
    }

    /// Record a blocked request
    pub fn record_blocked_request(&self, reason: &str) {
        self.blocked_requests.with_label_values(&[reason]).inc();
    }

    /// Record request body size
    pub fn record_request_body_size(&self, route: &str, size_bytes: usize) {
        self.request_body_size
            .with_label_values(&[route])
            .observe(size_bytes as f64);
    }

    /// Record response body size
    pub fn record_response_body_size(&self, route: &str, size_bytes: usize) {
        self.response_body_size
            .with_label_values(&[route])
            .observe(size_bytes as f64);
    }

    /// Record TLS handshake duration
    pub fn record_tls_handshake(&self, version: &str, duration: Duration) {
        self.tls_handshake_duration
            .with_label_values(&[version])
            .observe(duration.as_secs_f64());
    }

    /// Update connection pool metrics
    pub fn update_connection_pool(&self, upstream: &str, size: i64, idle: i64) {
        self.connection_pool_size
            .with_label_values(&[upstream])
            .set(size);
        self.connection_pool_idle
            .with_label_values(&[upstream])
            .set(idle);
    }

    /// Record connection acquisition from pool
    pub fn record_connection_acquired(&self, upstream: &str) {
        self.connection_pool_acquired
            .with_label_values(&[upstream])
            .inc();
    }

    /// Update system metrics
    pub fn update_system_metrics(&self) {
        use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

        // Create system with specific refresh kinds
        let mut system = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );

        // Get memory usage
        self.memory_usage.set(system.total_memory() as i64);

        // Get CPU usage
        system.refresh_cpu_usage();
        self.cpu_usage.set(system.global_cpu_usage() as f64);
    }

    /// Set open connections count
    pub fn set_open_connections(&self, count: i64) {
        self.open_connections.set(count);
    }
}

/// Structured log entry for audit logging
#[derive(Debug, serde::Serialize)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub correlation_id: String,
    pub event_type: String,
    pub route: Option<String>,
    pub client_addr: Option<String>,
    pub user_agent: Option<String>,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub duration_ms: u64,
    pub upstream: Option<String>,
    pub waf_decision: Option<WafDecision>,
    pub agent_decisions: Vec<AgentDecision>,
    pub error: Option<String>,
    pub tags: Vec<String>,
}

/// WAF decision details for audit logging
#[derive(Debug, serde::Serialize)]
pub struct WafDecision {
    pub action: String,
    pub rule_ids: Vec<String>,
    pub confidence: f32,
    pub reason: String,
    pub matched_data: Option<String>,
}

/// Agent decision details for audit logging
#[derive(Debug, serde::Serialize)]
pub struct AgentDecision {
    pub agent_name: String,
    pub event: String,
    pub action: String,
    pub latency_ms: u64,
    pub metadata: serde_json::Value,
}

impl AuditLogEntry {
    /// Create a new audit log entry
    pub fn new(correlation_id: String, method: String, path: String) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            correlation_id,
            event_type: "request".to_string(),
            route: None,
            client_addr: None,
            user_agent: None,
            method,
            path,
            status: None,
            duration_ms: 0,
            upstream: None,
            waf_decision: None,
            agent_decisions: vec![],
            error: None,
            tags: vec![],
        }
    }

    /// Write the audit log entry
    pub fn write(&self) {
        match serde_json::to_string(self) {
            Ok(json) => println!("AUDIT: {}", json),
            Err(e) => error!("Failed to serialize audit log: {}", e),
        }
    }
}

/// Health check status for components
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Component health information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub consecutive_failures: u32,
    pub error_message: Option<String>,
}

/// Global health status aggregator
///
/// Tracks the health of all system components (upstreams, agents, etc.)
/// and provides aggregate status for health endpoints.
pub struct ComponentHealthTracker {
    components: parking_lot::RwLock<Vec<ComponentHealth>>,
}

impl ComponentHealthTracker {
    /// Create new health checker
    pub fn new() -> Self {
        Self {
            components: parking_lot::RwLock::new(vec![]),
        }
    }

    /// Update component health
    pub fn update_component(&self, name: String, status: HealthStatus, error: Option<String>) {
        let mut components = self.components.write();

        if let Some(component) = components.iter_mut().find(|c| c.name == name) {
            component.status = status;
            component.last_check = chrono::Utc::now();
            component.error_message = error;

            if status != HealthStatus::Healthy {
                component.consecutive_failures += 1;
            } else {
                component.consecutive_failures = 0;
            }
        } else {
            components.push(ComponentHealth {
                name,
                status,
                last_check: chrono::Utc::now(),
                consecutive_failures: if status != HealthStatus::Healthy {
                    1
                } else {
                    0
                },
                error_message: error,
            });
        }
    }

    /// Get overall health status
    pub fn get_status(&self) -> HealthStatus {
        let components = self.components.read();

        if components.is_empty() {
            return HealthStatus::Healthy;
        }

        let unhealthy_count = components
            .iter()
            .filter(|c| c.status == HealthStatus::Unhealthy)
            .count();
        let degraded_count = components
            .iter()
            .filter(|c| c.status == HealthStatus::Degraded)
            .count();

        if unhealthy_count > 0 {
            HealthStatus::Unhealthy
        } else if degraded_count > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    /// Get detailed health report
    pub fn get_report(&self) -> Vec<ComponentHealth> {
        self.components.read().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = RequestMetrics::new().expect("Failed to create metrics");

        // Record a request
        metrics.record_request("test_route", "GET", 200, Duration::from_millis(100));

        // Verify active requests tracking
        metrics.inc_active_requests();
        metrics.dec_active_requests();

        // Record upstream attempt
        metrics.record_upstream_attempt("backend1", "test_route");
    }

    #[test]
    fn test_audit_log() {
        let mut entry = AuditLogEntry::new(
            "test-correlation-id".to_string(),
            "GET".to_string(),
            "/api/test".to_string(),
        );

        entry.status = Some(200);
        entry.duration_ms = 150;
        entry.tags.push("test".to_string());

        // This would write to stdout in production
        // For testing, we just verify it serializes correctly
        let json = serde_json::to_string(&entry).expect("Failed to serialize audit log");
        assert!(json.contains("test-correlation-id"));
    }

    #[test]
    fn test_health_checker() {
        let checker = ComponentHealthTracker::new();

        // Initially healthy
        assert_eq!(checker.get_status(), HealthStatus::Healthy);

        // Add healthy component
        checker.update_component("upstream1".to_string(), HealthStatus::Healthy, None);
        assert_eq!(checker.get_status(), HealthStatus::Healthy);

        // Add degraded component
        checker.update_component(
            "agent1".to_string(),
            HealthStatus::Degraded,
            Some("Slow response".to_string()),
        );
        assert_eq!(checker.get_status(), HealthStatus::Degraded);

        // Add unhealthy component
        checker.update_component(
            "upstream2".to_string(),
            HealthStatus::Unhealthy,
            Some("Connection refused".to_string()),
        );
        assert_eq!(checker.get_status(), HealthStatus::Unhealthy);
    }
}
