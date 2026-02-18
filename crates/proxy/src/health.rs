//! Health checking module for Zentinel proxy
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
use tracing::{debug, info, trace, warn};

use zentinel_common::{errors::ZentinelResult, types::HealthCheckType};
use zentinel_config::{HealthCheck as HealthCheckConfig, UpstreamTarget};

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
    health_status: Arc<RwLock<HashMap<String, TargetHealthInfo>>>,
    /// Check task handles
    check_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal
    shutdown_tx: Arc<tokio::sync::broadcast::Sender<()>>,
}

/// Health status information for a target
#[derive(Debug, Clone)]
pub struct TargetHealthInfo {
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

/// gRPC health check implementation.
///
/// Currently uses TCP connectivity check as a fallback since full gRPC
/// health checking protocol (grpc.health.v1.Health) requires the `tonic`
/// crate for HTTP/2 and Protocol Buffers support.
///
/// Full implementation would:
/// 1. Establish HTTP/2 connection
/// 2. Call `grpc.health.v1.Health/Check` with service name
/// 3. Parse `HealthCheckResponse` for SERVING/NOT_SERVING status
///
/// See: https://github.com/grpc/grpc/blob/master/doc/health-checking.md
struct GrpcHealthCheck {
    service: String,
    timeout: Duration,
}

/// Inference health check implementation for LLM/AI backends.
///
/// Probes the models endpoint to verify the inference server is running
/// and expected models are available. Typically used with OpenAI-compatible
/// APIs that expose a `/v1/models` endpoint.
///
/// The check:
/// 1. Sends GET request to the configured endpoint (default: `/v1/models`)
/// 2. Expects HTTP 200 response
/// 3. Optionally parses response to verify expected models are available
struct InferenceHealthCheck {
    endpoint: String,
    expected_models: Vec<String>,
    timeout: Duration,
}

/// Inference probe health check - sends minimal completion request
///
/// Verifies model can actually process requests, not just that server is running.
struct InferenceProbeCheck {
    config: zentinel_common::InferenceProbeConfig,
    timeout: Duration,
}

/// Model status endpoint health check
///
/// Queries provider-specific status endpoints to verify model readiness.
struct ModelStatusCheck {
    config: zentinel_common::ModelStatusConfig,
    timeout: Duration,
}

/// Queue depth health check
///
/// Monitors queue depth from headers or response body to detect overload.
struct QueueDepthCheck {
    config: zentinel_common::QueueDepthConfig,
    models_endpoint: String,
    timeout: Duration,
}

/// Composite inference health check that runs multiple sub-checks
///
/// Runs base inference check plus any configured readiness checks.
/// All enabled checks must pass for the target to be considered healthy.
struct CompositeInferenceHealthCheck {
    base_check: InferenceHealthCheck,
    inference_probe: Option<InferenceProbeCheck>,
    model_status: Option<ModelStatusCheck>,
    queue_depth: Option<QueueDepthCheck>,
}

impl ActiveHealthChecker {
    /// Create new active health checker
    pub fn new(config: HealthCheckConfig) -> Self {
        debug!(
            check_type = ?config.check_type,
            interval_secs = config.interval_secs,
            timeout_secs = config.timeout_secs,
            healthy_threshold = config.healthy_threshold,
            unhealthy_threshold = config.unhealthy_threshold,
            "Creating active health checker"
        );

        let checker: Arc<dyn HealthCheckImpl> = match &config.check_type {
            HealthCheckType::Http {
                path,
                expected_status,
                host,
            } => {
                trace!(
                    path = %path,
                    expected_status = expected_status,
                    host = host.as_deref().unwrap_or("(default)"),
                    "Configuring HTTP health check"
                );
                Arc::new(HttpHealthCheck {
                    path: path.clone(),
                    expected_status: *expected_status,
                    host: host.clone(),
                    timeout: Duration::from_secs(config.timeout_secs),
                })
            }
            HealthCheckType::Tcp => {
                trace!("Configuring TCP health check");
                Arc::new(TcpHealthCheck {
                    timeout: Duration::from_secs(config.timeout_secs),
                })
            }
            HealthCheckType::Grpc { service } => {
                trace!(
                    service = %service,
                    "Configuring gRPC health check"
                );
                Arc::new(GrpcHealthCheck {
                    service: service.clone(),
                    timeout: Duration::from_secs(config.timeout_secs),
                })
            }
            HealthCheckType::Inference {
                endpoint,
                expected_models,
                readiness,
            } => {
                trace!(
                    endpoint = %endpoint,
                    expected_models = ?expected_models,
                    has_readiness = readiness.is_some(),
                    "Configuring inference health check"
                );

                let base_timeout = Duration::from_secs(config.timeout_secs);
                let base_check = InferenceHealthCheck {
                    endpoint: endpoint.clone(),
                    expected_models: expected_models.clone(),
                    timeout: base_timeout,
                };

                if let Some(ref readiness_config) = readiness {
                    // Create composite check with sub-checks
                    let inference_probe =
                        readiness_config
                            .inference_probe
                            .as_ref()
                            .map(|cfg| InferenceProbeCheck {
                                config: cfg.clone(),
                                timeout: Duration::from_secs(cfg.timeout_secs),
                            });

                    let model_status =
                        readiness_config
                            .model_status
                            .as_ref()
                            .map(|cfg| ModelStatusCheck {
                                config: cfg.clone(),
                                timeout: Duration::from_secs(cfg.timeout_secs),
                            });

                    let queue_depth =
                        readiness_config
                            .queue_depth
                            .as_ref()
                            .map(|cfg| QueueDepthCheck {
                                config: cfg.clone(),
                                models_endpoint: endpoint.clone(),
                                timeout: Duration::from_secs(cfg.timeout_secs),
                            });

                    Arc::new(CompositeInferenceHealthCheck {
                        base_check,
                        inference_probe,
                        model_status,
                        queue_depth,
                    })
                } else {
                    // Simple inference check without readiness sub-checks
                    Arc::new(base_check)
                }
            }
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
    pub async fn start(&self, targets: &[UpstreamTarget]) -> ZentinelResult<()> {
        info!(
            target_count = targets.len(),
            interval_secs = self.config.interval_secs,
            check_type = self.checker.check_type(),
            "Starting health checking"
        );

        let mut handles = self.check_handles.write().await;

        for target in targets {
            let address = target.address.clone();

            trace!(
                target = %address,
                "Initializing health status for target"
            );

            // Initialize health status
            self.health_status
                .write()
                .await
                .insert(address.clone(), TargetHealthInfo::new());

            // Spawn health check task
            debug!(
                target = %address,
                "Spawning health check task"
            );
            let handle = self.spawn_check_task(address);
            handles.push(handle);
        }

        info!(
            target_count = targets.len(),
            interval_secs = self.config.interval_secs,
            healthy_threshold = self.config.healthy_threshold,
            unhealthy_threshold = self.config.unhealthy_threshold,
            "Health checking started successfully"
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
        let check_type = self.checker.check_type().to_string();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);
            interval_timer.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

            trace!(
                target = %target,
                check_type = %check_type,
                interval_ms = interval.as_millis(),
                "Health check task started"
            );

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        // Perform health check
                        trace!(
                            target = %target,
                            check_type = %check_type,
                            "Performing health check"
                        );
                        let start = Instant::now();
                        let result = checker.check(&target).await;
                        let check_duration = start.elapsed();

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
                                            avg_response_ms = format!("{:.2}", status.avg_response_time),
                                            total_checks = status.total_checks,
                                            "Target marked as healthy"
                                        );
                                    }

                                    trace!(
                                        target = %target,
                                        response_time_ms = response_ms,
                                        check_duration_ms = check_duration.as_millis(),
                                        consecutive_successes = status.consecutive_successes,
                                        health_score = format!("{:.2}", status.health_score()),
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
                                            total_checks = status.total_checks,
                                            health_score = format!("{:.2}", status.health_score()),
                                            "Target marked as unhealthy"
                                        );
                                    } else {
                                        debug!(
                                            target = %target,
                                            error = %error,
                                            consecutive_failures = status.consecutive_failures,
                                            unhealthy_threshold = unhealthy_threshold,
                                            "Health check failed"
                                        );
                                    }
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

            debug!(target = %target, "Health check task stopped");
        })
    }

    /// Stop health checking
    pub async fn stop(&self) {
        let task_count = self.check_handles.read().await.len();
        info!(task_count = task_count, "Stopping health checker");

        // Send shutdown signal
        let _ = self.shutdown_tx.send(());

        // Wait for all tasks to complete
        let mut handles = self.check_handles.write().await;
        for handle in handles.drain(..) {
            let _ = handle.await;
        }

        info!("Health checker stopped successfully");
    }

    /// Get health status for a target
    pub async fn get_status(&self, target: &str) -> Option<TargetHealthInfo> {
        self.health_status.read().await.get(target).cloned()
    }

    /// Get all health statuses
    pub async fn get_all_statuses(&self) -> HashMap<String, TargetHealthInfo> {
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

impl Default for TargetHealthInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetHealthInfo {
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
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Zentinel-HealthCheck/1.0\r\nConnection: close\r\n\r\n",
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

        // NOTE: Full gRPC health check requires `tonic` crate for HTTP/2 support.
        // This implementation uses TCP connectivity as a reasonable fallback.
        // The gRPC health checking protocol (grpc.health.v1.Health/Check) would
        // return SERVING, NOT_SERVING, or UNKNOWN for the specified service.

        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        // TCP connectivity check as fallback
        let stream = time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Verify connection is writable (basic health indicator)
        stream
            .writable()
            .await
            .map_err(|e| format!("Connection not writable: {}", e))?;

        debug!(
            target = %target,
            service = %self.service,
            "gRPC health check using TCP fallback (full gRPC protocol requires tonic)"
        );

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "gRPC"
    }
}

#[async_trait]
impl HealthCheckImpl for InferenceHealthCheck {
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

        // Build HTTP request for the models endpoint
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Zentinel-HealthCheck/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            self.endpoint,
            target
        );

        // Send request and read response
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response (larger buffer for JSON response)
        let mut response = vec![0u8; 8192];
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

        if status_code != 200 {
            return Err(format!(
                "Unexpected status code: {} (expected 200)",
                status_code
            ));
        }

        // If expected models are specified, verify they're in the response
        if !self.expected_models.is_empty() {
            // Find the JSON body (after headers)
            if let Some(body_start) = response_str.find("\r\n\r\n") {
                let body = &response_str[body_start + 4..];

                // Check if each expected model is mentioned in the response
                for model in &self.expected_models {
                    if !body.contains(model) {
                        return Err(format!("Expected model '{}' not found in response", model));
                    }
                }

                debug!(
                    target = %target,
                    endpoint = %self.endpoint,
                    expected_models = ?self.expected_models,
                    "All expected models found in inference health check"
                );
            } else {
                return Err("Could not find response body".to_string());
            }
        }

        trace!(
            target = %target,
            endpoint = %self.endpoint,
            response_time_ms = start.elapsed().as_millis(),
            "Inference health check passed"
        );

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "Inference"
    }
}

#[async_trait]
impl HealthCheckImpl for InferenceProbeCheck {
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

        // Build completion request body
        let body = format!(
            r#"{{"model":"{}","prompt":"{}","max_tokens":{}}}"#,
            self.config.model, self.config.prompt, self.config.max_tokens
        );

        // Build HTTP request
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Zentinel-HealthCheck/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.config.endpoint,
            target,
            body.len(),
            body
        );

        // Send request
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response
        let mut response = vec![0u8; 16384];
        let n = stream
            .read(&mut response)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Empty response".to_string());
        }

        let latency = start.elapsed();

        // Parse status code
        let response_str = String::from_utf8_lossy(&response[..n]);
        let status_code = parse_http_status(&response_str)
            .ok_or_else(|| "Failed to parse HTTP status".to_string())?;

        if status_code != 200 {
            return Err(format!(
                "Inference probe failed: status {} (expected 200)",
                status_code
            ));
        }

        // Verify response contains choices array
        if let Some(body_start) = response_str.find("\r\n\r\n") {
            let body = &response_str[body_start + 4..];
            if !body.contains("\"choices\"") {
                return Err("Inference probe response missing 'choices' field".to_string());
            }
        }

        // Check latency threshold if configured
        if let Some(max_ms) = self.config.max_latency_ms {
            if latency.as_millis() as u64 > max_ms {
                return Err(format!(
                    "Inference probe latency {}ms exceeds threshold {}ms",
                    latency.as_millis(),
                    max_ms
                ));
            }
        }

        trace!(
            target = %target,
            model = %self.config.model,
            latency_ms = latency.as_millis(),
            "Inference probe health check passed"
        );

        Ok(latency)
    }

    fn check_type(&self) -> &str {
        "InferenceProbe"
    }
}

#[async_trait]
impl HealthCheckImpl for ModelStatusCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // Parse target address
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        // Check each model's status
        for model in &self.config.models {
            let endpoint = self.config.endpoint_pattern.replace("{model}", model);

            // Connect with timeout
            let stream = time::timeout(self.timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
                .map_err(|e| format!("Connection failed: {}", e))?;

            // Build HTTP request
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Zentinel-HealthCheck/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                endpoint,
                target
            );

            // Send request
            let mut stream = stream;
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|e| format!("Failed to send request: {}", e))?;

            // Read response
            let mut response = vec![0u8; 8192];
            let n = stream
                .read(&mut response)
                .await
                .map_err(|e| format!("Failed to read response: {}", e))?;

            if n == 0 {
                return Err(format!("Empty response for model '{}'", model));
            }

            let response_str = String::from_utf8_lossy(&response[..n]);
            let status_code = parse_http_status(&response_str)
                .ok_or_else(|| "Failed to parse HTTP status".to_string())?;

            if status_code != 200 {
                return Err(format!(
                    "Model '{}' status check failed: HTTP {}",
                    model, status_code
                ));
            }

            // Extract status field from JSON body
            if let Some(body_start) = response_str.find("\r\n\r\n") {
                let body = &response_str[body_start + 4..];
                let status = extract_json_field(body, &self.config.status_field);

                match status {
                    Some(s) if s == self.config.expected_status => {
                        trace!(
                            target = %target,
                            model = %model,
                            status = %s,
                            "Model status check passed"
                        );
                    }
                    Some(s) => {
                        return Err(format!(
                            "Model '{}' status '{}' != expected '{}'",
                            model, s, self.config.expected_status
                        ));
                    }
                    None => {
                        return Err(format!(
                            "Model '{}' status field '{}' not found",
                            model, self.config.status_field
                        ));
                    }
                }
            }
        }

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "ModelStatus"
    }
}

#[async_trait]
impl HealthCheckImpl for QueueDepthCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // Parse target address
        let addr: SocketAddr = target
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        let endpoint = self
            .config
            .endpoint
            .as_ref()
            .unwrap_or(&self.models_endpoint);

        // Connect with timeout
        let stream = time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("Connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Build HTTP request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Zentinel-HealthCheck/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            endpoint,
            target
        );

        // Send request
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        // Read response
        let mut response = vec![0u8; 8192];
        let n = stream
            .read(&mut response)
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if n == 0 {
            return Err("Empty response".to_string());
        }

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Extract queue depth from header or body
        let queue_depth = if let Some(ref header_name) = self.config.header {
            extract_header_value(&response_str, header_name).and_then(|v| v.parse::<u64>().ok())
        } else if let Some(ref field) = self.config.body_field {
            if let Some(body_start) = response_str.find("\r\n\r\n") {
                let body = &response_str[body_start + 4..];
                extract_json_field(body, field).and_then(|v| v.parse::<u64>().ok())
            } else {
                None
            }
        } else {
            return Err("No queue depth source configured (header or body_field)".to_string());
        };

        let depth = queue_depth.ok_or_else(|| "Could not extract queue depth".to_string())?;

        // Check thresholds
        if depth >= self.config.unhealthy_threshold {
            return Err(format!(
                "Queue depth {} exceeds unhealthy threshold {}",
                depth, self.config.unhealthy_threshold
            ));
        }

        if depth >= self.config.degraded_threshold {
            warn!(
                target = %target,
                queue_depth = depth,
                threshold = self.config.degraded_threshold,
                "Queue depth exceeds degraded threshold"
            );
        }

        trace!(
            target = %target,
            queue_depth = depth,
            "Queue depth check passed"
        );

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "QueueDepth"
    }
}

#[async_trait]
impl HealthCheckImpl for CompositeInferenceHealthCheck {
    async fn check(&self, target: &str) -> Result<Duration, String> {
        let start = Instant::now();

        // Run base inference check first (always required)
        self.base_check.check(target).await?;

        // Run optional sub-checks (all must pass)
        if let Some(ref probe) = self.inference_probe {
            probe.check(target).await?;
        }

        if let Some(ref status) = self.model_status {
            status.check(target).await?;
        }

        if let Some(ref queue) = self.queue_depth {
            queue.check(target).await?;
        }

        trace!(
            target = %target,
            total_time_ms = start.elapsed().as_millis(),
            "Composite inference health check passed"
        );

        Ok(start.elapsed())
    }

    fn check_type(&self) -> &str {
        "CompositeInference"
    }
}

/// Extract a header value from HTTP response
fn extract_header_value(response: &str, header_name: &str) -> Option<String> {
    let header_lower = header_name.to_lowercase();
    for line in response.lines() {
        if line.is_empty() || line == "\r" {
            break; // End of headers
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().to_lowercase() == header_lower {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Extract a field from JSON body using dot notation (e.g., "status" or "state.loaded")
fn extract_json_field(body: &str, field_path: &str) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(body).ok()?;
    let parts: Vec<&str> = field_path.split('.').collect();
    let mut current = &json;

    for part in parts {
        current = current.get(part)?;
    }

    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
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
    /// Last error per target
    last_errors: Arc<RwLock<HashMap<String, String>>>,
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
        debug!(
            failure_rate_threshold = format!("{:.2}", failure_rate_threshold),
            window_size = window_size,
            has_active_checker = active_checker.is_some(),
            "Creating passive health checker"
        );
        Self {
            failure_rate_threshold,
            window_size,
            outcomes: Arc::new(RwLock::new(HashMap::new())),
            last_errors: Arc::new(RwLock::new(HashMap::new())),
            active_checker,
        }
    }

    /// Record request outcome with optional error message
    pub async fn record_outcome(&self, target: &str, success: bool, error: Option<&str>) {
        trace!(
            target = %target,
            success = success,
            error = ?error,
            "Recording request outcome"
        );

        // Track last error
        if let Some(err_msg) = error {
            self.last_errors
                .write()
                .await
                .insert(target.to_string(), err_msg.to_string());
        } else if success {
            // Clear last error on success
            self.last_errors.write().await.remove(target);
        }

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

        trace!(
            target = %target,
            failure_rate = format!("{:.2}", failure_rate),
            window_samples = target_outcomes.len(),
            failures = failures,
            "Updated failure rate"
        );

        // Mark unhealthy if failure rate exceeds threshold
        if failure_rate > self.failure_rate_threshold {
            warn!(
                target = %target,
                failure_rate = format!("{:.2}", failure_rate * 100.0),
                threshold = format!("{:.2}", self.failure_rate_threshold * 100.0),
                window_samples = target_outcomes.len(),
                "Failure rate exceeds threshold"
            );
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

    /// Get last error for a target
    pub async fn get_last_error(&self, target: &str) -> Option<String> {
        self.last_errors.read().await.get(target).cloned()
    }
}

// ============================================================================
// Warmth Tracker (Passive Cold Model Detection)
// ============================================================================

use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use zentinel_common::{ColdModelAction, WarmthDetectionConfig};

/// Warmth tracker for detecting cold models after idle periods
///
/// This is a passive tracker that observes actual request latency rather than
/// sending active probes. It tracks baseline latency per target and detects
/// when first-request latency after an idle period indicates a cold model.
pub struct WarmthTracker {
    /// Configuration for warmth detection
    config: WarmthDetectionConfig,
    /// Per-target warmth state
    targets: DashMap<String, TargetWarmthState>,
}

/// Per-target warmth tracking state
struct TargetWarmthState {
    /// Baseline latency in milliseconds (EWMA)
    baseline_latency_ms: AtomicU64,
    /// Number of samples collected for baseline
    sample_count: AtomicU32,
    /// Last request timestamp (millis since epoch)
    last_request_ms: AtomicU64,
    /// Currently considered cold
    is_cold: AtomicBool,
    /// Total cold starts detected (for metrics)
    cold_start_count: AtomicU64,
}

impl TargetWarmthState {
    fn new() -> Self {
        Self {
            baseline_latency_ms: AtomicU64::new(0),
            sample_count: AtomicU32::new(0),
            last_request_ms: AtomicU64::new(0),
            is_cold: AtomicBool::new(false),
            cold_start_count: AtomicU64::new(0),
        }
    }

    fn update_baseline(&self, latency_ms: u64, sample_size: u32) {
        let count = self.sample_count.fetch_add(1, Ordering::Relaxed);
        let current = self.baseline_latency_ms.load(Ordering::Relaxed);

        if count < sample_size {
            // Building initial baseline - simple average
            let new_baseline = if count == 0 {
                latency_ms
            } else {
                (current * count as u64 + latency_ms) / (count as u64 + 1)
            };
            self.baseline_latency_ms
                .store(new_baseline, Ordering::Relaxed);
        } else {
            // EWMA update: new = alpha * sample + (1 - alpha) * old
            // Using alpha = 0.1 for smooth updates
            let alpha = 0.1_f64;
            let new_baseline = (alpha * latency_ms as f64 + (1.0 - alpha) * current as f64) as u64;
            self.baseline_latency_ms
                .store(new_baseline, Ordering::Relaxed);
        }
    }
}

impl WarmthTracker {
    /// Create a new warmth tracker with the given configuration
    pub fn new(config: WarmthDetectionConfig) -> Self {
        Self {
            config,
            targets: DashMap::new(),
        }
    }

    /// Create a warmth tracker with default configuration
    pub fn with_defaults() -> Self {
        Self::new(WarmthDetectionConfig {
            sample_size: 10,
            cold_threshold_multiplier: 3.0,
            idle_cold_timeout_secs: 300,
            cold_action: ColdModelAction::LogOnly,
        })
    }

    /// Record a completed request and detect cold starts
    ///
    /// Returns true if a cold start was detected
    pub fn record_request(&self, target: &str, latency: Duration) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let latency_ms = latency.as_millis() as u64;
        let idle_threshold_ms = self.config.idle_cold_timeout_secs * 1000;

        let state = self
            .targets
            .entry(target.to_string())
            .or_insert_with(TargetWarmthState::new);

        let last_request = state.last_request_ms.load(Ordering::Relaxed);
        let idle_duration_ms = if last_request > 0 {
            now_ms.saturating_sub(last_request)
        } else {
            0
        };

        // Update last request time
        state.last_request_ms.store(now_ms, Ordering::Relaxed);

        // Check if this might be a cold start (first request after idle period)
        if idle_duration_ms >= idle_threshold_ms {
            let baseline = state.baseline_latency_ms.load(Ordering::Relaxed);

            // Only check if we have a baseline
            if baseline > 0 {
                let threshold = (baseline as f64 * self.config.cold_threshold_multiplier) as u64;

                if latency_ms > threshold {
                    // Cold start detected!
                    state.is_cold.store(true, Ordering::Release);
                    state.cold_start_count.fetch_add(1, Ordering::Relaxed);

                    warn!(
                        target = %target,
                        latency_ms = latency_ms,
                        baseline_ms = baseline,
                        threshold_ms = threshold,
                        idle_duration_secs = idle_duration_ms / 1000,
                        cold_action = ?self.config.cold_action,
                        "Cold model detected - latency spike after idle period"
                    );

                    return true;
                }
            }
        }

        // Normal request - update baseline and clear cold flag
        state.is_cold.store(false, Ordering::Release);
        state.update_baseline(latency_ms, self.config.sample_size);

        trace!(
            target = %target,
            latency_ms = latency_ms,
            baseline_ms = state.baseline_latency_ms.load(Ordering::Relaxed),
            sample_count = state.sample_count.load(Ordering::Relaxed),
            "Recorded request latency for warmth tracking"
        );

        false
    }

    /// Check if a target is currently considered cold
    pub fn is_cold(&self, target: &str) -> bool {
        self.targets
            .get(target)
            .map(|s| s.is_cold.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// Get the configured action for cold models
    pub fn cold_action(&self) -> ColdModelAction {
        self.config.cold_action
    }

    /// Get baseline latency for a target (in ms)
    pub fn baseline_latency_ms(&self, target: &str) -> Option<u64> {
        self.targets
            .get(target)
            .map(|s| s.baseline_latency_ms.load(Ordering::Relaxed))
    }

    /// Get cold start count for a target
    pub fn cold_start_count(&self, target: &str) -> u64 {
        self.targets
            .get(target)
            .map(|s| s.cold_start_count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Check if warmth tracking should affect load balancing for this target
    pub fn should_deprioritize(&self, target: &str) -> bool {
        if !self.is_cold(target) {
            return false;
        }

        match self.config.cold_action {
            ColdModelAction::LogOnly => false,
            ColdModelAction::MarkDegraded | ColdModelAction::MarkUnhealthy => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_status() {
        let status = TargetHealthInfo::new();
        assert!(status.healthy);
        assert_eq!(status.health_score(), 1.0);
        assert!(!status.is_degraded());
    }

    #[tokio::test]
    async fn test_passive_health_checker() {
        let checker = PassiveHealthChecker::new(0.5, 10, None);

        // Record some outcomes
        for _ in 0..5 {
            checker.record_outcome("target1", true, None).await;
        }
        for _ in 0..3 {
            checker
                .record_outcome("target1", false, Some("HTTP 503"))
                .await;
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

    #[test]
    fn test_warmth_tracker_baseline() {
        let tracker = WarmthTracker::with_defaults();

        // First few requests should build baseline
        for i in 0..10 {
            let cold = tracker.record_request("target1", Duration::from_millis(100));
            assert!(!cold, "Should not detect cold on request {}", i);
        }

        // Check baseline was established
        let baseline = tracker.baseline_latency_ms("target1");
        assert!(baseline.is_some());
        assert!(baseline.unwrap() > 0 && baseline.unwrap() <= 100);
    }

    #[test]
    fn test_warmth_tracker_cold_detection() {
        let config = WarmthDetectionConfig {
            sample_size: 5,
            cold_threshold_multiplier: 2.0,
            idle_cold_timeout_secs: 0, // Immediate idle for testing
            cold_action: ColdModelAction::MarkDegraded,
        };
        let tracker = WarmthTracker::new(config);

        // Build baseline with 100ms latency
        for _ in 0..5 {
            tracker.record_request("target1", Duration::from_millis(100));
        }

        // Wait a tiny bit to simulate idle
        std::thread::sleep(Duration::from_millis(10));

        // Next request with 3x latency (> 2x threshold) should detect cold
        let cold = tracker.record_request("target1", Duration::from_millis(300));
        assert!(cold, "Should detect cold start");
        assert!(tracker.is_cold("target1"));
        assert_eq!(tracker.cold_start_count("target1"), 1);
    }

    #[test]
    fn test_warmth_tracker_no_cold_on_normal_latency() {
        let config = WarmthDetectionConfig {
            sample_size: 5,
            cold_threshold_multiplier: 3.0,
            idle_cold_timeout_secs: 0,
            cold_action: ColdModelAction::LogOnly,
        };
        let tracker = WarmthTracker::new(config);

        // Build baseline
        for _ in 0..5 {
            tracker.record_request("target1", Duration::from_millis(100));
        }

        std::thread::sleep(Duration::from_millis(10));

        // Request with only 1.5x latency (< 3x threshold) should not detect cold
        let cold = tracker.record_request("target1", Duration::from_millis(150));
        assert!(!cold, "Should not detect cold for normal variation");
        assert!(!tracker.is_cold("target1"));
    }

    #[test]
    fn test_warmth_tracker_deprioritize() {
        let config = WarmthDetectionConfig {
            sample_size: 2,
            cold_threshold_multiplier: 2.0,
            idle_cold_timeout_secs: 0,
            cold_action: ColdModelAction::MarkDegraded,
        };
        let tracker = WarmthTracker::new(config);

        // Build baseline and trigger cold
        tracker.record_request("target1", Duration::from_millis(100));
        tracker.record_request("target1", Duration::from_millis(100));
        std::thread::sleep(Duration::from_millis(10));
        tracker.record_request("target1", Duration::from_millis(300));

        // Should deprioritize when cold and action is MarkDegraded
        assert!(tracker.should_deprioritize("target1"));

        // New normal request clears cold flag
        tracker.record_request("target1", Duration::from_millis(100));
        assert!(!tracker.should_deprioritize("target1"));
    }
}
