//! Individual agent implementation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_agent_protocol::{AgentClient, AgentResponse, EventType};
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
                Ok(())
            }
            AgentTransport::Grpc { address, tls: _ } => {
                trace!(
                    agent_id = %self.config.id,
                    address = %address,
                    "Connecting to agent via gRPC"
                );

                // TODO: Add TLS support for gRPC connections
                let client = AgentClient::grpc(&self.config.id, address, timeout)
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
                    })?;

                *self.client.write().await = Some(client);

                info!(
                    agent_id = %self.config.id,
                    address = %address,
                    connect_time_ms = start.elapsed().as_millis(),
                    "Agent connected via gRPC"
                );
                Ok(())
            }
            AgentTransport::Http { url, tls: _ } => {
                warn!(
                    agent_id = %self.config.id,
                    url = %url,
                    "HTTP transport not yet implemented, agent will not be available"
                );
                Ok(())
            }
        }
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

        client.send_event(event_type, event).await.map_err(|e| {
            error!(
                agent_id = %self.config.id,
                event_type = ?event_type,
                error = %e,
                "Agent call failed"
            );
            SentinelError::Agent {
                agent: self.config.id.clone(),
                message: e.to_string(),
                event: format!("{:?}", event_type),
                source: None,
            }
        })
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
