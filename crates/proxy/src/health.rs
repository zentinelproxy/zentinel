//! Health checking module for Sentinel proxy
//!
//! This module implements active and passive health checking for upstream servers,
//! supporting HTTP, TCP, and gRPC health checks with configurable thresholds.

use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time;
use tracing::{debug, info, warn};

use sentinel_common::{
    errors::SentinelResult,
    types::HealthCheckType,
};
use sentinel_config::{HealthCheck as HealthCheckConfig, UpstreamTarget};

/// Active health checker for upstream targets
///
/// Performs periodic health checks on upstream targets using HTTP, TCP, or gRPC
/// protocols to determine their availability for load balancing.
pub struct ActiveHealthChecker {
    /// Check configuration
    config: HealthCheckConfig,
    /// Health checker implementation
    checker: Arc<dyn HealthCheckImpl>,
    /// Health status per target
    health_status: Arc<RwLock<HashMap<String, HealthStatus>>>,
    /// Check task handles
    check_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal
    shutdown_tx: Arc<tokio::sync::broadcast::Sender<()>>,
}

/// Health status for a target
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Is target healthy
    pub healthy: bool,
    /// Consecutive successes
    pub consecutive_successes: u32,
    /// Consecutive failures
    pub consecutive_failures: u32,
    /// Last check time
    pub last_check: Instant,
    /// Last successful check
    pub last_success: Option<Instant>,
    /// Last error message
    pub last_error: Option<String>,
    /// Total checks performed
    pub total_checks: u64,
    /// Total successful checks
    pub total_successes: u64,
    /// Average response time (ms)
    pub avg_response_time: f64,
}

/// Health check implementation trait
#[async_trait]
trait HealthCheckImpl: Send + Sync {
    /// Perform health check on a target
    async fn check(&self, target: &str) -> Result<Duration, String>;

    /// Get check type name
    fn check_type(&self) -> &str;
}

/// HTTP health check implementation
struct HttpHealthCheck {
    path: String,
    expected_status: u16,
    host: Option<String>,
    timeout: Duration,
}

/// TCP health check implementation
struct TcpHealthCheck {
    timeout: Duration,
}

/// gRPC health check implementation
struct GrpcHealthCheck {
    service: String,
    timeout: Duration,
}

impl ActiveHealthChecker {
    /// Create new active health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        let checker: Arc<dyn HealthCheckImpl> = match &config.check_type {
            HealthCheckType::Http {
                path,
                expected_status,
                host,
            } => Arc::new(HttpHealthCheck {
                path: path.clone(),
                expected_status: *expected_status,
                host: host.clone(),
                timeout: Duration::from_secs(config.timeout_secs),
            }),
            HealthCheckType::Tcp => Arc::new(TcpHealthCheck {
                timeout: Duration::from_secs(config.timeout_secs),
            }),
            HealthCheckType::Grpc { service } => Arc::new(GrpcHealthCheck {
                service: service.clone(),
                timeout: Duration::from_secs(config.timeout_secs),
            }),
        };

        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);

        Self {
            config,
            checker,
            health_status: Arc::new(RwLock::new(HashMap::new())),
            check_handles: Arc::new(RwLock::new(Vec::new())),
            shutdown_tx: Arc::new(shutdown_tx),
        }
    }

    /// Start health checking for targets
    pub async fn start(&self, targets: &[UpstreamTarget]) -> SentinelResult<()> {
        let mut handles = self.check_handles.write().await;

        for target in targets {
            let address = target.address.clone();

            // Initialize health status
            self.health_status
                .write()
                .await
                .insert(address.clone(), HealthStatus::new());

            // Spawn health check task
            let handle = self.spawn_check_task(address);
            handles.push(handle);
        }

        info!(
            "Started health checking for {} targets, interval: {}s",
            targets.len(),
            self.config.interval_secs
        );

        Ok(())
    }

    /// Spawn health check task for a target
    fn spawn_check_task(&self, target: String) -> tokio::task::JoinHandle<()> {
        let interval = Duration::from_secs(self.config.interval_secs);
        let checker = Arc::clone(&self.checker);
        let health_status = Arc::clone(&self.health_status);
        let healthy_threshold = self.config.healthy_threshold;
        let unhealthy_threshold = self.config.unhealthy_threshold;
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            interval_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Perform health check
                        let start = Instant::now();
                        let result = checker.check(&target).await;
                        let _duration = start.elapsed();

                        // Update health status
                        let mut status_map = health_status.write().await;
                        if let Some(status) = status_map.get_mut(&target) {
                            status.last_check = Instant::now();
                            status.total_checks += 1;

                            match result {
                                Ok(response_time) => {
                                    status.consecutive_successes += 1;
                                    status.consecutive_failures = 0;
                                    status.last_success = Some(Instant::now());
                                    status.last_error = None;
                                    status.total_successes += 1;

                                    // Update average response time
                                    let response_ms = response_time.as_millis() as f64;
                                    status.avg_response_time =
                                        (status.avg_response_time * (status.total_successes - 1) as f64
                                        + response_ms) / status.total_successes as f64;

                                    // Check if should mark as healthy
                                    if !status.healthy && status.consecutive_successes >= healthy_threshold {
                                        status.healthy = true;
                                        info!(
                                            target = %target,
                                            consecutive_successes = status.consecutive_successes,
                                            "Target marked as healthy"
                                        );
                                    }

                                    debug!(
                                        target = %target,
                                        response_time_ms = response_ms,
                                        "Health check succeeded"
                                    );
                                }
                                Err(error) => {
                                    status.consecutive_failures += 1;
                                    status.consecutive_successes = 0;
                                    status.last_error = Some(error.clone());

                                    // Check if should mark as unhealthy
                                    if status.healthy && status.consecutive_failures >= unhealthy_threshold {
                                        status.healthy = false;
                                        warn!(
                                            target = %target,
                                            consecutive_failures = status.consecutive_failures,
                                            error = %error,
                                            "Target marked as unhealthy"
                                        );
                                    }

                                    debug!(
                                        target = %target,
                                        error = %error,
                                        "Health check failed"
                                    );
                                }
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!(target = %target, "Stopping health check task");
                        break;
                    }
                }
            }
        })
    }

    /// Stop health checking
    pub async fn stop(&self) {
        info!("Stopping health checker");

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for all tasks to complete
        let mut handles = self.check_handles.write().await;
        for handle in handles.drain(..) {
            let _ = handle.await;
        }
    }

    /// Get health status for a target
    pub async fn get_status(&self, target: &str) -> Option<HealthStatus> {
        self.health_status.read().await.get(target).cloned()
    }

    /// Get all health statuses
    pub async fn get_all_statuses(&self) -> HashMap<String, HealthStatus> {
        self.health_status.read().await.clone()
    }

    /// Check if target is healthy
    pub async fn is_healthy(&self, target: &str) -> bool {
        self.health_status
            .read()
            .await
            .get(target)
            .map(|s| s.healthy)
            .unwrap_or(false)
    }

    /// Get healthy targets
    pub async fn get_healthy_targets(&self) -> Vec<String> {
        self.health_status
            .read()
            .await
            .iter()
            .filter_map(|(target, status)| {
                if status.healthy {
                    Some(target.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Mark target as unhealthy (for passive health checking)
    pub async fn mark_unhealthy(&self, target: &str, reason: String) {
        if let Some(status) = self.health_status.write().await.get_mut(target) {
            if status.healthy {
                status.healthy = false;
                status.consecutive_failures = self.config.unhealthy_threshold;
                status.consecutive_successes = 0;
                status.last_error = Some(reason.clone());
                warn!(
                    target = %target,
                    reason = %reason,
                    "Target marked unhealthy by passive check"
                );
            }
        }
    }
}

impl HealthStatus {
    /// Create new health status (initially healthy)
    pub fn new() -> Self {
        Self {
            healthy: true,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_check: Instant::now(),
            last_success: Some(Instant::now()),
            last_error: None,
            total_checks: 0,
            total_successes: 0,
            avg_response_time: 0.0,
        }
    }

    /// Get health score (0.0 - 1.0)
    pub fn health_score(&self) -> f64 {
        if self.total_checks == 0 {
            return 1.0;
        }
        self.total_successes as f64 / self.total_checks as f64
    }

    /// Check if status is degraded (healthy but with recent failures)
    pub fn is_degraded(&self) -> bool {
        self.healthy && self.consecutive_failures > 0
    }
}

#[async_trait]
impl HealthCheckImpl for HttpHealthCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // Parse target address
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        // Connect with timeout
        let stream = time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Build HTTP request
        let host = self.host.as_deref().unwrap_or(target);
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Sentinel-HealthCheck/1.0\r\nConnection: close\r\n\r\n",
            self.path,
            host
        );

        // Send request and read response
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let mut response = vec![0u8; 1024];
        let n = stream
            .read(&mut response)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Empty response".to_string());
        }

        // Parse status code
        let response_str = String::from_utf8_lossy(&response[..n]);
        let status_code = parse_http_status(&response_str)
            .ok_or_else(|| "Failed to parse HTTP status".to_string())?;

        if status_code == self.expected_status {
            Ok(start.elapsed())
        } else {
            Err(format!(
                "Unexpected status code: {} (expected {})",
                status_code, self.expected_status
            ))
        }
    }

    fn check_type(&self) -> &str {
        "HTTP"
    }
}

#[async_trait]
impl HealthCheckImpl for TcpHealthCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // Parse target address
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        // Connect with timeout
        time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "TCP"
    }
}

#[async_trait]
impl HealthCheckImpl for GrpcHealthCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // TODO: Implement gRPC health check
        // This would use the gRPC health checking protocol:
        // https://github.com/grpc/grpc/blob/master/doc/health-checking.md

        // For now, fall back to TCP check
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "gRPC"
    }
}

/// Parse HTTP status code from response
fn parse_http_status(response: &str) -> Option<u16> {
    response
        .lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// Passive health checker that monitors request outcomes
///
/// Observes request success/failure rates to detect unhealthy targets
/// without performing explicit health checks. Works in combination with
/// `ActiveHealthChecker` for comprehensive health monitoring.
pub struct PassiveHealthChecker {
    /// Failure rate threshold (0.0 - 1.0)
    failure_rate_threshold: f64,
    /// Window size for calculating failure rate
    window_size: usize,
    /// Request outcomes per target (ring buffer)
    outcomes: Arc<RwLock<HashMap<String, Vec<bool>>>>,
    /// Active health checker reference
    active_checker: Option<Arc<ActiveHealthChecker>>,
}

impl PassiveHealthChecker {
    /// Create new passive health checker
    pub fn new(
        failure_rate_threshold: f64,
        window_size: usize,
        active_checker: Option<Arc<ActiveHealthChecker>>,
    ) -> Self {
        Self {
            failure_rate_threshold,
            window_size,
            outcomes: Arc::new(RwLock::new(HashMap::new())),
            active_checker,
        }
    }

    /// Record request outcome
    pub async fn record_outcome(&self, target: &str, success: bool) {
        let mut outcomes = self.outcomes.write().await;
        let target_outcomes = outcomes
            .entry(target.to_string())
            .or_insert_with(|| Vec::with_capacity(self.window_size));

        // Add outcome to ring buffer
        if target_outcomes.len() >= self.window_size {
            target_outcomes.remove(0);
        }
        target_outcomes.push(success);

        // Calculate failure rate
        let failures = target_outcomes.iter().filter(|&&s| !s).count();
        let failure_rate = failures as f64 / target_outcomes.len() as f64;

        // Mark unhealthy if failure rate exceeds threshold
        if failure_rate > self.failure_rate_threshold {
            if let Some(ref checker) = self.active_checker {
                checker
                    .mark_unhealthy(
                        target,
                        format!(
                            "Failure rate {:.2}% exceeds threshold",
                            failure_rate * 100.0
                        ),
                    )
                    .await;
            }
        }
    }

    /// Get failure rate for a target
    pub async fn get_failure_rate(&self, target: &str) -> Option<f64> {
        let outcomes = self.outcomes.read().await;
        outcomes.get(target).map(|target_outcomes| {
            let failures = target_outcomes.iter().filter(|&&s| !s).count();
            failures as f64 / target_outcomes.len() as f64
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_config::HealthCheck as HealthCheckConfig;

    #[tokio::test]
    async fn test_health_status() {
        let status = HealthStatus::new();
        assert!(status.healthy);
        assert_eq!(status.health_score(), 1.0);
        assert!(!status.is_degraded());
    }

    #[tokio::test]
    async fn test_passive_health_checker() {
        let checker = PassiveHealthChecker::new(0.5, 10, None);

        // Record some outcomes
        for _ in 0..5 {
            checker.record_outcome("target1", true).await;
        }
        for _ in 0..3 {
            checker.record_outcome("target1", false).await;
        }

        let failure_rate = checker.get_failure_rate("target1").await.unwrap();
        assert!(failure_rate > 0.3 && failure_rate < 0.4);
    }

    #[test]
    fn test_parse_http_status() {
        let response = "HTTP/1.1 200 OK\r\n";
        assert_eq!(parse_http_status(response), Some(200));

        let response = "HTTP/1.1 404 Not Found\r\n";
        assert_eq!(parse_http_status(response), Some(404));

        let response = "Invalid response";
        assert_eq!(parse_http_status(response), None);
    }
}
