//! Individual agent implementation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_agent_protocol::{AgentClient, AgentResponse, ConfigureEvent, Decision, EventType, GrpcTlsConfig, HttpTlsConfig};
use sentinel_common::{errors::SentinelError, errors::SentinelResult, CircuitBreaker};
use sentinel_config::{AgentConfig, AgentEvent, AgentTransport};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use super::metrics::AgentMetrics;
use super::pool::AgentConnectionPool;

/// Individual agent configuration and state.
pub struct Agent {
    /// Agent configuration
    pub(super) config: AgentConfig,
    /// Agent client
    pub(super) client: Arc<RwLock<Option<AgentClient>>>,
    /// Connection pool
    pub(super) pool: Arc<AgentConnectionPool>,
    /// Circuit breaker
    pub(super) circuit_breaker: Arc<CircuitBreaker>,
    /// Agent-specific metrics
    pub(super) metrics: Arc<AgentMetrics>,
    /// Last successful call
    pub(super) last_success: Arc<RwLock<Option<Instant>>>,
    /// Consecutive failures
    pub(super) consecutive_failures: AtomicU32,
}

impl Agent {
    /// Create a new agent.
    pub fn new(
        config: AgentConfig,
        pool: Arc<AgentConnectionPool>,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        trace!(
            agent_id = %config.id,
            agent_type = ?config.agent_type,
            timeout_ms = config.timeout_ms,
            events = ?config.events,
            "Creating agent instance"
        );
        Self {
            config,
            client: Arc::new(RwLock::new(None)),
            pool,
            circuit_breaker,
            metrics: Arc::new(AgentMetrics::default()),
            last_success: Arc::new(RwLock::new(None)),
            consecutive_failures: AtomicU32::new(0),
        }
    }

    /// Get the agent ID.
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Get the agent's circuit breaker.
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Get the agent's failure mode.
    pub fn failure_mode(&self) -> sentinel_config::FailureMode {
        self.config.failure_mode
    }

    /// Get the agent's timeout in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }

    /// Get the agent's metrics.
    pub fn metrics(&self) -> &AgentMetrics {
        &self.metrics
    }

    /// Check if agent handles a specific event type.
    pub fn handles_event(&self, event_type: EventType) -> bool {
        self.config.events.iter().any(|e| match (e, event_type) {
            (AgentEvent::RequestHeaders, EventType::RequestHeaders) => true,
            (AgentEvent::RequestBody, EventType::RequestBodyChunk) => true,
            (AgentEvent::ResponseHeaders, EventType::ResponseHeaders) => true,
            (AgentEvent::ResponseBody, EventType::ResponseBodyChunk) => true,
            (AgentEvent::Log, EventType::RequestComplete) => true,
            (AgentEvent::WebSocketFrame, EventType::WebSocketFrame) => true,
            _ => false,
        })
    }

    /// Initialize agent connection.
    pub async fn initialize(&self) -> SentinelResult<()> {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        debug!(
            agent_id = %self.config.id,
            transport = ?self.config.transport,
            timeout_ms = self.config.timeout_ms,
            "Initializing agent connection"
        );

        let start = Instant::now();

        match &self.config.transport {
            AgentTransport::UnixSocket { path } => {
                trace!(
                    agent_id = %self.config.id,
                    socket_path = %path.display(),
                    "Connecting to agent via Unix socket"
                );

                let client = AgentClient::unix_socket(&self.config.id, path, timeout)
                    .await
                    .map_err(|e| {
                        error!(
                            agent_id = %self.config.id,
                            socket_path = %path.display(),
                            error = %e,
                            "Failed to connect to agent via Unix socket"
                        );
                        SentinelError::Agent {
                            agent: self.config.id.clone(),
                            message: format!("Failed to connect via Unix socket: {}", e),
                            event: "initialize".to_string(),
                            source: None,
                        }
                    })?;

                *self.client.write().await = Some(client);

                info!(
                    agent_id = %self.config.id,
                    socket_path = %path.display(),
                    connect_time_ms = start.elapsed().as_millis(),
                    "Agent connected via Unix socket"
                );

                // Send Configure event if config is present
                self.send_configure_event().await?;

                Ok(())
            }
            AgentTransport::Grpc { address, tls } => {
                trace!(
                    agent_id = %self.config.id,
                    address = %address,
                    tls_enabled = tls.is_some(),
                    "Connecting to agent via gRPC"
                );

                let client = match tls {
                    Some(tls_config) => {
                        // Build TLS configuration
                        let mut grpc_tls = GrpcTlsConfig::new();

                        // Load CA certificate if provided
                        if let Some(ca_path) = &tls_config.ca_cert {
                            grpc_tls = grpc_tls.with_ca_cert_file(ca_path).await.map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    ca_path = %ca_path.display(),
                                    error = %e,
                                    "Failed to load CA certificate for gRPC TLS"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load CA certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Load client certificate and key for mTLS if provided
                        if let (Some(cert_path), Some(key_path)) = (&tls_config.client_cert, &tls_config.client_key) {
                            grpc_tls = grpc_tls.with_client_cert_files(cert_path, key_path).await.map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    cert_path = %cert_path.display(),
                                    key_path = %key_path.display(),
                                    error = %e,
                                    "Failed to load client certificate for gRPC mTLS"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load client certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Handle insecure skip verify
                        if tls_config.insecure_skip_verify {
                            warn!(
                                agent_id = %self.config.id,
                                address = %address,
                                "SECURITY WARNING: TLS certificate verification disabled for agent"
                            );
                            grpc_tls = grpc_tls.with_insecure_skip_verify();
                        }

                        debug!(
                            agent_id = %self.config.id,
                            address = %address,
                            has_ca_cert = tls_config.ca_cert.is_some(),
                            has_client_cert = tls_config.client_cert.is_some(),
                            "Connecting to agent via gRPC with TLS"
                        );

                        AgentClient::grpc_tls(&self.config.id, address, timeout, grpc_tls)
                            .await
                            .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    address = %address,
                                    error = %e,
                                    "Failed to connect to agent via gRPC with TLS"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to connect via gRPC TLS: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?
                    }
                    None => {
                        // Plain gRPC without TLS
                        AgentClient::grpc(&self.config.id, address, timeout)
                            .await
                            .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    address = %address,
                                    error = %e,
                                    "Failed to connect to agent via gRPC"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to connect via gRPC: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?
                    }
                };

                *self.client.write().await = Some(client);

                info!(
                    agent_id = %self.config.id,
                    address = %address,
                    tls_enabled = tls.is_some(),
                    connect_time_ms = start.elapsed().as_millis(),
                    "Agent connected via gRPC"
                );

                // Send Configure event if config is present
                self.send_configure_event().await?;

                Ok(())
            }
            AgentTransport::Http { url, tls } => {
                trace!(
                    agent_id = %self.config.id,
                    url = %url,
                    tls_enabled = tls.is_some(),
                    "Connecting to agent via HTTP"
                );

                let client = match tls {
                    Some(tls_config) => {
                        // Build TLS configuration
                        let mut http_tls = HttpTlsConfig::new();

                        // Load CA certificate if provided
                        if let Some(ca_path) = &tls_config.ca_cert {
                            http_tls = http_tls.with_ca_cert_file(ca_path).await.map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    ca_path = %ca_path.display(),
                                    error = %e,
                                    "Failed to load CA certificate for HTTP TLS"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load CA certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Load client certificate and key for mTLS if provided
                        if let (Some(cert_path), Some(key_path)) = (&tls_config.client_cert, &tls_config.client_key) {
                            http_tls = http_tls.with_client_cert_files(cert_path, key_path).await.map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    cert_path = %cert_path.display(),
                                    key_path = %key_path.display(),
                                    error = %e,
                                    "Failed to load client certificate for HTTP mTLS"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load client certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Handle insecure skip verify
                        if tls_config.insecure_skip_verify {
                            warn!(
                                agent_id = %self.config.id,
                                url = %url,
                                "SECURITY WARNING: TLS certificate verification disabled for HTTP agent"
                            );
                            http_tls = http_tls.with_insecure_skip_verify();
                        }

                        debug!(
                            agent_id = %self.config.id,
                            url = %url,
                            has_ca_cert = tls_config.ca_cert.is_some(),
                            has_client_cert = tls_config.client_cert.is_some(),
                            "Connecting to agent via HTTP with TLS"
                        );

                        AgentClient::http_tls(&self.config.id, url, timeout, http_tls)
                            .await
                            .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    url = %url,
                                    error = %e,
                                    "Failed to create HTTP TLS agent client"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to create HTTP TLS client: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?
                    }
                    None => {
                        // Plain HTTP without TLS
                        AgentClient::http(&self.config.id, url, timeout)
                            .await
                            .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    url = %url,
                                    error = %e,
                                    "Failed to create HTTP agent client"
                                );
                                SentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to create HTTP client: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?
                    }
                };

                *self.client.write().await = Some(client);

                info!(
                    agent_id = %self.config.id,
                    url = %url,
                    tls_enabled = tls.is_some(),
                    connect_time_ms = start.elapsed().as_millis(),
                    "Agent connected via HTTP"
                );

                // Send Configure event if config is present
                self.send_configure_event().await?;

                Ok(())
            }
        }
    }

    /// Send Configure event to agent if config is present.
    async fn send_configure_event(&self) -> SentinelResult<()> {
        // Only send Configure if agent has config
        let config = match &self.config.config {
            Some(c) => c.clone(),
            None => {
                trace!(
                    agent_id = %self.config.id,
                    "No config for agent, skipping Configure event"
                );
                return Ok(());
            }
        };

        let event = ConfigureEvent {
            agent_id: self.config.id.clone(),
            config,
        };

        debug!(
            agent_id = %self.config.id,
            "Sending Configure event to agent"
        );

        let mut client_guard = self.client.write().await;
        let client = client_guard.as_mut().ok_or_else(|| SentinelError::Agent {
            agent: self.config.id.clone(),
            message: "No client connection for Configure event".to_string(),
            event: "configure".to_string(),
            source: None,
        })?;

        let response = client.send_event(EventType::Configure, &event).await.map_err(|e| {
            error!(
                agent_id = %self.config.id,
                error = %e,
                "Failed to send Configure event"
            );
            SentinelError::Agent {
                agent: self.config.id.clone(),
                message: format!("Configure event failed: {}", e),
                event: "configure".to_string(),
                source: None,
            }
        })?;

        // Check if agent accepted the configuration
        if !matches!(response.decision, Decision::Allow) {
            error!(
                agent_id = %self.config.id,
                decision = ?response.decision,
                "Agent rejected configuration"
            );
            return Err(SentinelError::Agent {
                agent: self.config.id.clone(),
                message: "Agent rejected configuration".to_string(),
                event: "configure".to_string(),
                source: None,
            });
        }

        info!(
            agent_id = %self.config.id,
            "Agent accepted configuration"
        );

        Ok(())
    }

    /// Call agent with event.
    pub async fn call_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> SentinelResult<AgentResponse> {
        trace!(
            agent_id = %self.config.id,
            event_type = ?event_type,
            "Preparing to call agent"
        );

        // Get or create connection
        let mut client_guard = self.client.write().await;

        if client_guard.is_none() {
            trace!(
                agent_id = %self.config.id,
                "No existing connection, initializing"
            );
            drop(client_guard);
            self.initialize().await?;
            client_guard = self.client.write().await;
        }

        let client = client_guard.as_mut().ok_or_else(|| {
            error!(
                agent_id = %self.config.id,
                event_type = ?event_type,
                "No client connection available after initialization"
            );
            SentinelError::Agent {
                agent: self.config.id.clone(),
                message: "No client connection".to_string(),
                event: format!("{:?}", event_type),
                source: None,
            }
        })?;

        // Make the call
        let call_num = self.metrics.calls_total.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            agent_id = %self.config.id,
            event_type = ?event_type,
            call_num = call_num,
            "Sending event to agent"
        );

        let result = client.send_event(event_type, event).await;

        // Handle result - clear stale connection on connection errors
        match result {
            Ok(response) => Ok(response),
            Err(e) => {
                let error_str = e.to_string();
                let is_connection_error = error_str.contains("Broken pipe")
                    || error_str.contains("Connection reset")
                    || error_str.contains("Connection refused")
                    || error_str.contains("not connected")
                    || error_str.contains("transport error");

                error!(
                    agent_id = %self.config.id,
                    event_type = ?event_type,
                    error = %e,
                    is_connection_error = is_connection_error,
                    "Agent call failed"
                );

                // Drop the client guard to release the lock
                drop(client_guard);

                // Clear cached client on connection errors to force reconnect on next call
                if is_connection_error {
                    warn!(
                        agent_id = %self.config.id,
                        "Clearing cached client due to connection error, next call will reconnect"
                    );
                    *self.client.write().await = None;
                }

                Err(SentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: format!("{:?}", event_type),
                    source: None,
                })
            }
        }
    }

    /// Record successful call.
    pub async fn record_success(&self, duration: Duration) {
        let success_count = self.metrics.calls_success.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics
            .duration_total_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_success.write().await = Some(Instant::now());

        trace!(
            agent_id = %self.config.id,
            duration_ms = duration.as_millis(),
            total_successes = success_count,
            "Recorded agent call success"
        );

        self.circuit_breaker.record_success().await;
    }

    /// Record failed call.
    pub async fn record_failure(&self) {
        let fail_count = self.metrics.calls_failed.fetch_add(1, Ordering::Relaxed) + 1;
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        debug!(
            agent_id = %self.config.id,
            total_failures = fail_count,
            consecutive_failures = consecutive,
            "Recorded agent call failure"
        );

        self.circuit_breaker.record_failure().await;
    }

    /// Record timeout.
    pub async fn record_timeout(&self) {
        let timeout_count = self.metrics.calls_timeout.fetch_add(1, Ordering::Relaxed) + 1;
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        debug!(
            agent_id = %self.config.id,
            total_timeouts = timeout_count,
            consecutive_failures = consecutive,
            timeout_ms = self.config.timeout_ms,
            "Recorded agent call timeout"
        );

        self.circuit_breaker.record_failure().await;
    }

    /// Shutdown agent.
    pub async fn shutdown(&self) {
        debug!(
            agent_id = %self.config.id,
            "Shutting down agent"
        );

        if let Some(client) = self.client.write().await.take() {
            trace!(
                agent_id = %self.config.id,
                "Closing agent client connection"
            );
            let _ = client.close().await;
        }

        let stats = (
            self.metrics.calls_total.load(Ordering::Relaxed),
            self.metrics.calls_success.load(Ordering::Relaxed),
            self.metrics.calls_failed.load(Ordering::Relaxed),
            self.metrics.calls_timeout.load(Ordering::Relaxed),
        );

        info!(
            agent_id = %self.config.id,
            total_calls = stats.0,
            successes = stats.1,
            failures = stats.2,
            timeouts = stats.3,
            "Agent shutdown complete"
        );
    }
}
