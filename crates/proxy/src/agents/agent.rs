//! Individual agent implementation.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};
use zentinel_agent_protocol::{
    AgentClient, AgentResponse, ConfigureEvent, Decision, EventType, GrpcTlsConfig, HttpTlsConfig,
};
use zentinel_common::{errors::ZentinelError, errors::ZentinelResult, CircuitBreaker};
use zentinel_config::{AgentConfig, AgentEvent, AgentTransport};

use super::metrics::AgentMetrics;
use super::pool::AgentConnectionPool;

/// Zentinel value indicating no timestamp recorded (Option::None equivalent)
const NO_TIMESTAMP: u64 = 0;

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
    /// Base instant for timestamp calculations
    pub(super) base_instant: Instant,
    /// Last successful call (nanoseconds since base_instant, 0 = never)
    pub(super) last_success_ns: AtomicU64,
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
            base_instant: Instant::now(),
            last_success_ns: AtomicU64::new(NO_TIMESTAMP),
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
    pub fn failure_mode(&self) -> zentinel_config::FailureMode {
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
    pub async fn initialize(&self) -> ZentinelResult<()> {
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
                        ZentinelError::Agent {
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
                                ZentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load CA certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Load client certificate and key for mTLS if provided
                        if let (Some(cert_path), Some(key_path)) =
                            (&tls_config.client_cert, &tls_config.client_key)
                        {
                            grpc_tls = grpc_tls
                                .with_client_cert_files(cert_path, key_path)
                                .await
                                .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    cert_path = %cert_path.display(),
                                    key_path = %key_path.display(),
                                    error = %e,
                                    "Failed to load client certificate for gRPC mTLS"
                                );
                                ZentinelError::Agent {
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
                                ZentinelError::Agent {
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
                                ZentinelError::Agent {
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
                                ZentinelError::Agent {
                                    agent: self.config.id.clone(),
                                    message: format!("Failed to load CA certificate: {}", e),
                                    event: "initialize".to_string(),
                                    source: None,
                                }
                            })?;
                        }

                        // Load client certificate and key for mTLS if provided
                        if let (Some(cert_path), Some(key_path)) =
                            (&tls_config.client_cert, &tls_config.client_key)
                        {
                            http_tls = http_tls
                                .with_client_cert_files(cert_path, key_path)
                                .await
                                .map_err(|e| {
                                error!(
                                    agent_id = %self.config.id,
                                    cert_path = %cert_path.display(),
                                    key_path = %key_path.display(),
                                    error = %e,
                                    "Failed to load client certificate for HTTP mTLS"
                                );
                                ZentinelError::Agent {
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
                                ZentinelError::Agent {
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
                                ZentinelError::Agent {
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

    /// Create a new client connection (for pooling).
    ///
    /// This creates a new AgentClient without storing it in `self.client`.
    /// Use this when you need a new connection for the pool.
    async fn create_client(&self) -> ZentinelResult<AgentClient> {
        let timeout = Duration::from_millis(self.config.timeout_ms);

        trace!(
            agent_id = %self.config.id,
            transport = ?self.config.transport,
            "Creating new client connection for pool"
        );

        match &self.config.transport {
            AgentTransport::UnixSocket { path } => {
                AgentClient::unix_socket(&self.config.id, path, timeout)
                    .await
                    .map_err(|e| {
                        error!(
                            agent_id = %self.config.id,
                            socket_path = %path.display(),
                            error = %e,
                            "Failed to create Unix socket client"
                        );
                        ZentinelError::Agent {
                            agent: self.config.id.clone(),
                            message: format!("Failed to connect via Unix socket: {}", e),
                            event: "create_client".to_string(),
                            source: None,
                        }
                    })
            }
            AgentTransport::Grpc { address, tls } => match tls {
                Some(tls_config) => {
                    let mut grpc_tls = GrpcTlsConfig::new();

                    if let Some(ca_path) = &tls_config.ca_cert {
                        grpc_tls = grpc_tls.with_ca_cert_file(ca_path).await.map_err(|e| {
                            ZentinelError::Agent {
                                agent: self.config.id.clone(),
                                message: format!("Failed to load CA certificate: {}", e),
                                event: "create_client".to_string(),
                                source: None,
                            }
                        })?;
                    }

                    if let (Some(cert_path), Some(key_path)) =
                        (&tls_config.client_cert, &tls_config.client_key)
                    {
                        grpc_tls = grpc_tls
                            .with_client_cert_files(cert_path, key_path)
                            .await
                            .map_err(|e| ZentinelError::Agent {
                                agent: self.config.id.clone(),
                                message: format!("Failed to load client certificate: {}", e),
                                event: "create_client".to_string(),
                                source: None,
                            })?;
                    }

                    if tls_config.insecure_skip_verify {
                        grpc_tls = grpc_tls.with_insecure_skip_verify();
                    }

                    AgentClient::grpc_tls(&self.config.id, address, timeout, grpc_tls)
                        .await
                        .map_err(|e| ZentinelError::Agent {
                            agent: self.config.id.clone(),
                            message: format!("Failed to connect via gRPC TLS: {}", e),
                            event: "create_client".to_string(),
                            source: None,
                        })
                }
                None => AgentClient::grpc(&self.config.id, address, timeout)
                    .await
                    .map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to connect via gRPC: {}", e),
                        event: "create_client".to_string(),
                        source: None,
                    }),
            },
            AgentTransport::Http { url, tls } => match tls {
                Some(tls_config) => {
                    let mut http_tls = HttpTlsConfig::new();

                    if let Some(ca_path) = &tls_config.ca_cert {
                        http_tls = http_tls.with_ca_cert_file(ca_path).await.map_err(|e| {
                            ZentinelError::Agent {
                                agent: self.config.id.clone(),
                                message: format!("Failed to load CA certificate: {}", e),
                                event: "create_client".to_string(),
                                source: None,
                            }
                        })?;
                    }

                    if let (Some(cert_path), Some(key_path)) =
                        (&tls_config.client_cert, &tls_config.client_key)
                    {
                        http_tls = http_tls
                            .with_client_cert_files(cert_path, key_path)
                            .await
                            .map_err(|e| ZentinelError::Agent {
                                agent: self.config.id.clone(),
                                message: format!("Failed to load client certificate: {}", e),
                                event: "create_client".to_string(),
                                source: None,
                            })?;
                    }

                    if tls_config.insecure_skip_verify {
                        http_tls = http_tls.with_insecure_skip_verify();
                    }

                    AgentClient::http_tls(&self.config.id, url, timeout, http_tls)
                        .await
                        .map_err(|e| ZentinelError::Agent {
                            agent: self.config.id.clone(),
                            message: format!("Failed to create HTTP TLS client: {}", e),
                            event: "create_client".to_string(),
                            source: None,
                        })
                }
                None => AgentClient::http(&self.config.id, url, timeout)
                    .await
                    .map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to create HTTP client: {}", e),
                        event: "create_client".to_string(),
                        source: None,
                    }),
            },
        }
    }

    /// Send Configure event to agent if config is present.
    async fn send_configure_event(&self) -> ZentinelResult<()> {
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
        let client = client_guard.as_mut().ok_or_else(|| ZentinelError::Agent {
            agent: self.config.id.clone(),
            message: "No client connection for Configure event".to_string(),
            event: "configure".to_string(),
            source: None,
        })?;

        let response = client
            .send_event(EventType::Configure, &event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    error = %e,
                    "Failed to send Configure event"
                );
                ZentinelError::Agent {
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
            return Err(ZentinelError::Agent {
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
    ///
    /// Uses connection pooling for concurrent request handling. Multiple requests
    /// can execute simultaneously using different connections from the pool.
    pub async fn call_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> ZentinelResult<AgentResponse> {
        trace!(
            agent_id = %self.config.id,
            event_type = ?event_type,
            "Preparing to call agent"
        );

        // Try to get a connection from the pool (fast path)
        let mut pooled_conn = self.pool.try_get();

        // If no pooled connection, try to create a new one
        if pooled_conn.is_none() {
            if self.pool.can_create() {
                trace!(
                    agent_id = %self.config.id,
                    "No pooled connection available, creating new connection"
                );
                match self.create_client().await {
                    Ok(client) => {
                        self.pool.register_created();
                        pooled_conn = Some(super::pool::PooledConnection::new(client));
                    }
                    Err(e) => {
                        error!(
                            agent_id = %self.config.id,
                            error = %e,
                            "Failed to create new connection"
                        );
                        return Err(e);
                    }
                }
            } else {
                // Pool is at capacity, fall back to single client with lock
                // This ensures we don't create unbounded connections
                trace!(
                    agent_id = %self.config.id,
                    "Pool at capacity, using fallback client"
                );
                return self.call_event_fallback(event_type, event).await;
            }
        }

        let mut conn = pooled_conn.expect("Connection should be available");

        // Make the call
        let call_num = self.metrics.calls_total.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            agent_id = %self.config.id,
            event_type = ?event_type,
            call_num = call_num,
            pool_active = self.pool.active_count(),
            "Sending event to agent via pooled connection"
        );

        let result = conn.client.send_event(event_type, event).await;

        // Handle result
        match result {
            Ok(response) => {
                // Return connection to pool on success
                self.pool.return_connection(conn);
                Ok(response)
            }
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

                // Don't return connection to pool on error - mark it as failed
                self.pool.mark_failed();
                // Connection will be dropped here

                Err(ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: format!("{:?}", event_type),
                    source: None,
                })
            }
        }
    }

    /// Fallback call method using the single cached client (for when pool is exhausted).
    async fn call_event_fallback<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> ZentinelResult<AgentResponse> {
        // Get or create connection using the fallback single client
        let mut client_guard = self.client.write().await;

        if client_guard.is_none() {
            trace!(
                agent_id = %self.config.id,
                "No existing fallback connection, initializing"
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
            ZentinelError::Agent {
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
            "Sending event to agent via fallback client"
        );

        let result = client.send_event(event_type, event).await;

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
                    "Agent call failed (fallback)"
                );

                drop(client_guard);

                if is_connection_error {
                    warn!(
                        agent_id = %self.config.id,
                        "Clearing cached fallback client due to connection error"
                    );
                    *self.client.write().await = None;
                }

                Err(ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: format!("{:?}", event_type),
                    source: None,
                })
            }
        }
    }

    /// Record successful call (lock-free).
    pub async fn record_success(&self, duration: Duration) {
        let success_count = self.metrics.calls_success.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics
            .duration_total_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        // Store timestamp as nanoseconds since base_instant (lock-free)
        self.last_success_ns.store(
            self.base_instant.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );

        trace!(
            agent_id = %self.config.id,
            duration_ms = duration.as_millis(),
            total_successes = success_count,
            "Recorded agent call success"
        );

        self.circuit_breaker.record_success(); // Lock-free
    }

    /// Get the time since last successful call (for monitoring).
    /// Returns None if no successful call has been recorded.
    #[inline]
    pub fn time_since_last_success(&self) -> Option<Duration> {
        let last_ns = self.last_success_ns.load(Ordering::Relaxed);
        if last_ns == NO_TIMESTAMP {
            return None;
        }
        let current_ns = self.base_instant.elapsed().as_nanos() as u64;
        Some(Duration::from_nanos(current_ns.saturating_sub(last_ns)))
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

        self.circuit_breaker.record_failure(); // Lock-free
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

        self.circuit_breaker.record_failure(); // Lock-free
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
