//! Individual agent implementation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_agent_protocol::{AgentClient, AgentResponse, EventType};
use sentinel_common::{errors::SentinelError, errors::SentinelResult, CircuitBreaker};
use sentinel_config::{AgentConfig, AgentEvent, AgentTransport};
use tokio::sync::RwLock;
use tracing::warn;

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
        self.config.failure_mode.clone()
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
            _ => false,
        })
    }

    /// Initialize agent connection.
    pub async fn initialize(&self) -> SentinelResult<()> {
        match &self.config.transport {
            AgentTransport::UnixSocket { path } => {
                let client = AgentClient::unix_socket(
                    &self.config.id,
                    path,
                    Duration::from_millis(self.config.timeout_ms),
                )
                .await
                .map_err(|e| SentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: format!("Failed to connect: {}", e),
                    event: "initialize".to_string(),
                    source: None,
                })?;

                *self.client.write().await = Some(client);
                Ok(())
            }
            _ => {
                warn!(
                    "Unsupported agent transport: {:?}",
                    self.config.transport
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
        // Get or create connection
        let mut client_guard = self.client.write().await;

        if client_guard.is_none() {
            drop(client_guard);
            self.initialize().await?;
            client_guard = self.client.write().await;
        }

        let client = client_guard.as_mut().ok_or_else(|| SentinelError::Agent {
            agent: self.config.id.clone(),
            message: "No client connection".to_string(),
            event: format!("{:?}", event_type),
            source: None,
        })?;

        // Make the call
        self.metrics.calls_total.fetch_add(1, Ordering::Relaxed);

        client.send_event(event_type, event).await.map_err(|e| {
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
        self.metrics.calls_success.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .duration_total_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_success.write().await = Some(Instant::now());

        self.circuit_breaker.record_success().await;
    }

    /// Record failed call.
    pub async fn record_failure(&self) {
        self.metrics.calls_failed.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);

        self.circuit_breaker.record_failure().await;
    }

    /// Record timeout.
    pub async fn record_timeout(&self) {
        self.metrics.calls_timeout.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);

        self.circuit_breaker.record_failure().await;
    }

    /// Shutdown agent.
    pub async fn shutdown(&self) {
        if let Some(client) = self.client.write().await.take() {
            let _ = client.close().await;
        }
    }
}
