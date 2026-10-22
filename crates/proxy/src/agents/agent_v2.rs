//! Protocol v2 agent implementation.
//!
//! This module provides v2 agent support using the bidirectional streaming
//! protocol with capabilities, health reporting, and metrics export.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use tracing::{debug, error, info, trace, warn};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentPool, AgentPoolConfig as ProtocolPoolConfig, AgentPoolStats,
    CancelReason, ConfigPusher, ConfigUpdateType, LoadBalanceStrategy as ProtocolLBStrategy,
    MetricsCollector,
};
use zentinel_agent_protocol::{
    AgentResponse, EventType, GuardrailInspectEvent, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseBodyChunkEvent, ResponseHeadersEvent,
};
use zentinel_common::{
    errors::{ZentinelError, ZentinelResult},
    CircuitBreaker,
};
use zentinel_config::{AgentConfig, AgentEvent, FailureMode, LoadBalanceStrategy};

use super::metrics::AgentMetrics;

/// Zentinel value indicating no timestamp recorded
const NO_TIMESTAMP: u64 = 0;

/// Added to an agent's longest timeout to give its retirement ceiling.
const RETIREMENT_MARGIN: Duration = Duration::from_secs(1);

/// The shortest wait the pool gives an agent to acknowledge its
/// configuration (the protocol crate's `MIN_CONFIGURE_TIMEOUT`).
const MIN_CONFIGURE_WAIT: Duration = Duration::from_secs(5);

/// Protocol v2 agent with connection pooling and bidirectional streaming.
pub struct AgentV2 {
    /// Agent configuration
    config: AgentConfig,
    /// V2 connection pool
    pool: Arc<AgentPool>,
    /// Circuit breaker
    circuit_breaker: Arc<CircuitBreaker>,
    /// Agent-specific metrics
    metrics: Arc<AgentMetrics>,
    /// Base instant for timestamp calculations
    base_instant: Instant,
    /// Last successful call (nanoseconds since base_instant, 0 = never)
    last_success_ns: AtomicU64,
    /// Consecutive failures
    consecutive_failures: AtomicU32,
    /// Background pool maintenance task (health checks, reconnection,
    /// affinity/session cleanup). Spawned by `initialize`, aborted by `shutdown`.
    maintenance_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Set once the pool has been closed (by `shutdown`, the retirement
    /// ceiling, or the last reference being dropped), so it closes once.
    closed: AtomicBool,
    /// Set by `retire`: the agent is no longer configured and closes when
    /// its last in-flight call lets go of it.
    retired: AtomicBool,
    /// The retirement ceiling's timer, aborted if the agent closes first.
    ceiling_handle: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The pool's connect timeout, for [`startup_wait`](Self::startup_wait).
    connect_timeout: Duration,
}

impl AgentV2 {
    /// Create a new v2 agent.
    pub fn new(config: AgentConfig, circuit_breaker: Arc<CircuitBreaker>) -> Self {
        trace!(
            agent_id = %config.id,
            agent_type = ?config.agent_type,
            timeout_ms = config.timeout_ms,
            events = ?config.events,
            "Creating v2 agent instance"
        );

        // Convert config pool settings to protocol pool config
        let mut pool_config = config
            .pool
            .as_ref()
            .map(|p| ProtocolPoolConfig {
                connections_per_agent: p.connections_per_agent,
                load_balance_strategy: convert_lb_strategy(p.load_balance_strategy),
                connect_timeout: Duration::from_millis(p.connect_timeout_ms),
                request_timeout: Duration::from_millis(config.timeout_ms),
                reconnect_interval: Duration::from_millis(p.reconnect_interval_ms),
                max_reconnect_attempts: p.max_reconnect_attempts,
                drain_timeout: Duration::from_millis(p.drain_timeout_ms),
                max_concurrent_per_connection: p.max_concurrent_per_connection,
                health_check_interval: Duration::from_millis(p.health_check_interval_ms),
                ..Default::default()
            })
            .unwrap_or_default();
        // The agent's own `connect-timeout-ms` bounds each new connection's
        // connect and handshake (#599); without it, the pool's default.
        if let Some(ms) = config.connect_timeout_ms {
            pool_config.connect_timeout = Duration::from_millis(ms);
        }
        let connect_timeout = pool_config.connect_timeout;

        let pool = Arc::new(AgentPool::with_config(pool_config));

        Self {
            config,
            pool,
            circuit_breaker,
            metrics: Arc::new(AgentMetrics::default()),
            base_instant: Instant::now(),
            last_success_ns: AtomicU64::new(NO_TIMESTAMP),
            consecutive_failures: AtomicU32::new(0),
            maintenance_handle: std::sync::Mutex::new(None),
            closed: AtomicBool::new(false),
            retired: AtomicBool::new(false),
            ceiling_handle: std::sync::Mutex::new(None),
            connect_timeout,
        }
    }

    /// The longest startup waits for this agent's first connections: its
    /// connect timeout, plus the shortest wait for its configuration to be
    /// acknowledged. Past it the proxy serves without the agent, whose
    /// filters follow their failure mode until the connection is made (#599).
    pub fn startup_wait(&self) -> Duration {
        self.connect_timeout + MIN_CONFIGURE_WAIT
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
    pub fn failure_mode(&self) -> FailureMode {
        self.config.failure_mode
    }

    /// Get the agent's timeout in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        self.config.timeout_ms
    }

    /// Maximum request body size (bytes) this agent will inspect.
    pub fn max_request_body_bytes(&self) -> usize {
        self.config
            .max_request_body_bytes
            .unwrap_or(super::DEFAULT_AGENT_MAX_BODY_BYTES)
    }

    /// Maximum response body size (bytes) this agent will inspect.
    pub fn max_response_body_bytes(&self) -> usize {
        self.config
            .max_response_body_bytes
            .unwrap_or(super::DEFAULT_AGENT_MAX_BODY_BYTES)
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
            (AgentEvent::Guardrail, EventType::GuardrailInspect) => true,
            _ => false,
        })
    }

    /// Initialize agent connection(s).
    pub async fn initialize(&self) -> ZentinelResult<()> {
        let endpoint = self.get_endpoint()?;

        debug!(
            agent_id = %self.config.id,
            endpoint = %endpoint,
            "Initializing v2 agent pool"
        );

        let start = Instant::now();

        // Maintenance is spawned before registration, not after.
        //
        // It used to be after, behind a `?`, so a registration that failed took
        // the maintenance loop with it -- the one thing that could have
        // recovered the agent. The comment on the spawn already said "without
        // this, a crashed-and-restarted agent would stay unreachable"; the
        // early return made that true on exactly the path where it mattered.
        {
            let pool = Arc::clone(&self.pool);
            let handle = tokio::spawn(async move { pool.run_maintenance().await });
            let mut guard = self
                .maintenance_handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(old) = guard.replace(handle) {
                old.abort();
            }
        }

        // Add agent to pool - pool will establish connections.
        //
        // The agent's `config { }` block travels with every connection the
        // pool makes, so each pooled connection and every reconnect after the
        // agent restarts delivers it before carrying a request (#593). It
        // used to be handed to a `send_configure` that dropped it.
        self.pool
            .add_agent_with_config(&self.config.id, &endpoint, self.config.config.clone())
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    endpoint = %endpoint,
                    error = %e,
                    "Failed to add agent to v2 pool"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: format!("Failed to initialize v2 agent: {}", e),
                    event: "initialize".to_string(),
                    source: None,
                }
            })?;

        info!(
            agent_id = %self.config.id,
            endpoint = %endpoint,
            connect_time_ms = start.elapsed().as_millis(),
            has_config = self.config.config.is_some(),
            "V2 agent pool initialized"
        );

        Ok(())
    }

    /// Clear the connection affinity for a completed request.
    pub fn clear_correlation_affinity(&self, correlation_id: &str) {
        self.pool.clear_correlation_affinity(correlation_id);
    }

    /// Get endpoint from transport config.
    fn get_endpoint(&self) -> ZentinelResult<String> {
        use zentinel_config::AgentTransport;
        match &self.config.transport {
            AgentTransport::Grpc { address, .. } => Ok(address.clone()),
            AgentTransport::UnixSocket { path } => {
                // For UDS, format as unix:path
                Ok(format!("unix:{}", path.display()))
            }
            AgentTransport::Http { url, .. } => {
                // V2 doesn't support HTTP transport
                Err(ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: "HTTP transport not supported for v2 protocol".to_string(),
                    event: "initialize".to_string(),
                    source: None,
                })
            }
        }
    }

    /// Call agent with request headers event.
    pub async fn call_request_headers(
        &self,
        event: &RequestHeadersEvent,
    ) -> ZentinelResult<AgentResponse> {
        let call_num = self.metrics.calls_total.fetch_add(1, Ordering::Relaxed) + 1;

        // Get correlation_id from event metadata
        let correlation_id = &event.metadata.correlation_id;

        trace!(
            agent_id = %self.config.id,
            call_num = call_num,
            correlation_id = %correlation_id,
            "Sending request headers to v2 agent"
        );

        self.pool
            .send_request_headers(&self.config.id, correlation_id, event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "V2 agent request headers call failed"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "request_headers".to_string(),
                    source: None,
                }
            })
    }

    /// Call agent with request body chunk event.
    ///
    /// For streaming body inspection, chunks are sent sequentially with
    /// increasing `chunk_index`. The agent responds after processing each chunk.
    pub async fn call_request_body_chunk(
        &self,
        event: &RequestBodyChunkEvent,
    ) -> ZentinelResult<AgentResponse> {
        let correlation_id = &event.correlation_id;

        trace!(
            agent_id = %self.config.id,
            correlation_id = %correlation_id,
            chunk_index = event.chunk_index,
            is_last = event.is_last,
            "Sending request body chunk to v2 agent"
        );

        self.pool
            .send_request_body_chunk(&self.config.id, correlation_id, event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "V2 agent request body chunk call failed"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "request_body_chunk".to_string(),
                    source: None,
                }
            })
    }

    /// Call agent with response headers event.
    ///
    /// Called when upstream response headers are received, allowing the agent
    /// to inspect/modify response headers before they're sent to the client.
    pub async fn call_response_headers(
        &self,
        event: &ResponseHeadersEvent,
    ) -> ZentinelResult<AgentResponse> {
        let correlation_id = &event.correlation_id;

        trace!(
            agent_id = %self.config.id,
            correlation_id = %correlation_id,
            status = event.status,
            "Sending response headers to v2 agent"
        );

        self.pool
            .send_response_headers(&self.config.id, correlation_id, event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "V2 agent response headers call failed"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "response_headers".to_string(),
                    source: None,
                }
            })
    }

    /// Call agent with response body chunk event.
    ///
    /// For streaming response body inspection, chunks are sent sequentially.
    /// The agent can inspect and optionally modify response body data.
    pub async fn call_response_body_chunk(
        &self,
        event: &ResponseBodyChunkEvent,
    ) -> ZentinelResult<AgentResponse> {
        let correlation_id = &event.correlation_id;

        trace!(
            agent_id = %self.config.id,
            correlation_id = %correlation_id,
            chunk_index = event.chunk_index,
            is_last = event.is_last,
            "Sending response body chunk to v2 agent"
        );

        self.pool
            .send_response_body_chunk(&self.config.id, correlation_id, event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "V2 agent response body chunk call failed"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "response_body_chunk".to_string(),
                    source: None,
                }
            })
    }

    /// Call agent with guardrail inspect event.
    pub async fn call_guardrail_inspect(
        &self,
        event: &GuardrailInspectEvent,
    ) -> ZentinelResult<AgentResponse> {
        let call_num = self.metrics.calls_total.fetch_add(1, Ordering::Relaxed) + 1;

        let correlation_id = &event.correlation_id;

        trace!(
            agent_id = %self.config.id,
            call_num = call_num,
            correlation_id = %correlation_id,
            inspection_type = ?event.inspection_type,
            "Sending guardrail inspect to v2 agent"
        );

        self.pool
            .send_guardrail_inspect(&self.config.id, correlation_id, event)
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "V2 agent guardrail inspect call failed"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "guardrail_inspect".to_string(),
                    source: None,
                }
            })
    }

    /// Call agent with a generic event, dispatching to the appropriate typed method.
    ///
    /// The event is serialized and deserialized to convert between the generic
    /// type and the specific event struct expected by each typed method.
    pub async fn call_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> ZentinelResult<AgentResponse> {
        let json = serde_json::to_value(event).map_err(|e| ZentinelError::Agent {
            agent: self.config.id.clone(),
            message: format!("Failed to serialize event: {}", e),
            event: format!("{:?}", event_type),
            source: None,
        })?;

        match event_type {
            EventType::RequestHeaders => {
                let typed: RequestHeadersEvent =
                    serde_json::from_value(json).map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to deserialize RequestHeadersEvent: {}", e),
                        event: format!("{:?}", event_type),
                        source: None,
                    })?;
                self.call_request_headers(&typed).await
            }
            EventType::RequestBodyChunk => {
                let typed: RequestBodyChunkEvent =
                    serde_json::from_value(json).map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to deserialize RequestBodyChunkEvent: {}", e),
                        event: format!("{:?}", event_type),
                        source: None,
                    })?;
                self.call_request_body_chunk(&typed).await
            }
            EventType::ResponseHeaders => {
                let typed: ResponseHeadersEvent =
                    serde_json::from_value(json).map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to deserialize ResponseHeadersEvent: {}", e),
                        event: format!("{:?}", event_type),
                        source: None,
                    })?;
                self.call_response_headers(&typed).await
            }
            EventType::ResponseBodyChunk => {
                let typed: ResponseBodyChunkEvent =
                    serde_json::from_value(json).map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to deserialize ResponseBodyChunkEvent: {}", e),
                        event: format!("{:?}", event_type),
                        source: None,
                    })?;
                self.call_response_body_chunk(&typed).await
            }
            EventType::GuardrailInspect => {
                let typed: GuardrailInspectEvent =
                    serde_json::from_value(json).map_err(|e| ZentinelError::Agent {
                        agent: self.config.id.clone(),
                        message: format!("Failed to deserialize GuardrailInspectEvent: {}", e),
                        event: format!("{:?}", event_type),
                        source: None,
                    })?;
                self.call_guardrail_inspect(&typed).await
            }
            _ => Err(ZentinelError::Agent {
                agent: self.config.id.clone(),
                message: format!("Unsupported event type {:?}", event_type),
                event: format!("{:?}", event_type),
                source: None,
            }),
        }
    }

    /// Cancel an in-flight request.
    pub async fn cancel_request(
        &self,
        correlation_id: &str,
        reason: CancelReason,
    ) -> ZentinelResult<()> {
        trace!(
            agent_id = %self.config.id,
            correlation_id = %correlation_id,
            reason = ?reason,
            "Cancelling request on v2 agent"
        );

        self.pool
            .cancel_request(&self.config.id, correlation_id, reason)
            .await
            .map_err(|e| {
                warn!(
                    agent_id = %self.config.id,
                    correlation_id = %correlation_id,
                    error = %e,
                    "Failed to cancel request on v2 agent"
                );
                ZentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: format!("Cancel failed: {}", e),
                    event: "cancel".to_string(),
                    source: None,
                }
            })
    }

    /// Get agent capabilities.
    pub async fn capabilities(&self) -> Option<AgentCapabilities> {
        self.pool.agent_capabilities(&self.config.id).await
    }

    /// Check if agent is healthy.
    pub async fn is_healthy(&self) -> bool {
        self.pool.is_agent_healthy(&self.config.id)
    }

    /// Record successful call (lock-free).
    pub fn record_success(&self, duration: Duration) {
        let success_count = self.metrics.calls_success.fetch_add(1, Ordering::Relaxed) + 1;
        self.metrics
            .duration_total_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.last_success_ns.store(
            self.base_instant.elapsed().as_nanos() as u64,
            Ordering::Relaxed,
        );

        trace!(
            agent_id = %self.config.id,
            duration_ms = duration.as_millis(),
            total_successes = success_count,
            "Recorded v2 agent call success"
        );

        self.circuit_breaker.record_success();
    }

    /// Get the time since last successful call.
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
    pub fn record_failure(&self) {
        let fail_count = self.metrics.calls_failed.fetch_add(1, Ordering::Relaxed) + 1;
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        debug!(
            agent_id = %self.config.id,
            total_failures = fail_count,
            consecutive_failures = consecutive,
            "Recorded v2 agent call failure"
        );

        self.circuit_breaker.record_failure();
    }

    /// Record timeout.
    pub fn record_timeout(&self) {
        let timeout_count = self.metrics.calls_timeout.fetch_add(1, Ordering::Relaxed) + 1;
        let consecutive = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        debug!(
            agent_id = %self.config.id,
            total_timeouts = timeout_count,
            consecutive_failures = consecutive,
            timeout_ms = self.config.timeout_ms,
            "Recorded v2 agent call timeout"
        );

        self.circuit_breaker.record_failure();
    }

    /// Get pool statistics.
    pub async fn pool_stats(&self) -> Option<AgentPoolStats> {
        self.pool.agent_stats(&self.config.id).await
    }

    /// Get the pool's metrics collector.
    ///
    /// Returns a reference to the shared metrics collector that aggregates
    /// metrics reports from all agents in this pool.
    pub fn pool_metrics_collector(&self) -> &MetricsCollector {
        self.pool.metrics_collector()
    }

    /// Get an Arc to the pool's metrics collector.
    ///
    /// This is useful for registering the collector with a MetricsManager.
    pub fn pool_metrics_collector_arc(&self) -> Arc<MetricsCollector> {
        self.pool.metrics_collector_arc()
    }

    /// Export agent metrics in Prometheus format.
    ///
    /// Returns a string containing all metrics collected from agents
    /// in Prometheus exposition format.
    pub fn export_prometheus(&self) -> String {
        self.pool.export_prometheus()
    }

    /// Get the pool's config pusher.
    ///
    /// Returns a reference to the shared config pusher that distributes
    /// configuration updates to agents.
    pub fn config_pusher(&self) -> &ConfigPusher {
        self.pool.config_pusher()
    }

    /// Push a configuration update to this agent.
    ///
    /// Returns the push ID if the agent supports config push, None otherwise.
    pub fn push_config(&self, update_type: ConfigUpdateType) -> Option<String> {
        self.pool.push_config_to_agent(&self.config.id, update_type)
    }

    /// Whether this agent's pool has been closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// The agent's connection pool, for tests that watch it close.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> Arc<AgentPool> {
        Arc::clone(&self.pool)
    }

    /// The longest a retired agent stays open for calls still holding it:
    /// its longest timeout, plus a margin.
    ///
    /// A call that started before the retirement ends within its timeout, so
    /// past this point whatever still holds the agent is hung (or queued
    /// behind a hung call), and the pool is closed under it.
    pub fn retirement_ceiling(&self) -> Duration {
        Duration::from_millis(self.config.timeout_ms.max(self.config.chunk_timeout_ms))
            + RETIREMENT_MARGIN
    }

    /// Retire an agent that is no longer configured (removed or replaced by
    /// a reload).
    ///
    /// The caller has already taken the agent out of the manager's map, so
    /// no new call can reach it, and hands over its reference here. Calls
    /// already in flight each hold their own `Arc`, and finish on this
    /// agent. The pool closes when the last of them lets go (see `Drop`), or
    /// at [`retirement_ceiling`](Self::retirement_ceiling), whichever comes
    /// first. Either way "Retired agent closed" is logged with how.
    pub fn retire(self: Arc<Self>) {
        let ceiling = self.retirement_ceiling();
        self.retire_within(ceiling);
    }

    /// [`retire`](Self::retire), with an explicit ceiling.
    pub(crate) fn retire_within(self: Arc<Self>, ceiling: Duration) {
        if self.retired.swap(true, Ordering::AcqRel) {
            return;
        }
        let holders = Arc::strong_count(&self) - 1;
        info!(
            agent_id = %self.config.id,
            in_flight_holders = holders,
            ceiling_ms = ceiling.as_millis() as u64,
            "Retiring agent; it closes when its last call finishes"
        );

        // Without a runtime there is no timer; the last reference still
        // closes the pool.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let weak: Weak<Self> = Arc::downgrade(&self);
            let handle = runtime.spawn(async move {
                tokio::time::sleep(ceiling).await;
                // A weak reference: the timer must not keep the agent alive.
                let Some(agent) = weak.upgrade() else {
                    return;
                };
                if agent.is_closed() {
                    return;
                }
                warn!(
                    agent_id = %agent.config.id,
                    ceiling_ms = ceiling.as_millis() as u64,
                    in_flight_holders = Arc::strong_count(&agent) - 1,
                    "Retired agent still in use at its ceiling; closing it under its calls"
                );
                agent.shutdown().await;
                info!(
                    agent_id = %agent.config.id,
                    closed_by = "ceiling",
                    "Retired agent closed"
                );
            });
            *self
                .ceiling_handle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle);
        }
        // `self` is dropped here: if no call holds the agent, this was the
        // last reference and `Drop` closes the pool now.
    }

    /// Shutdown agent.
    ///
    /// This removes the agent from the pool and closes all connections.
    pub async fn shutdown(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        debug!(
            agent_id = %self.config.id,
            "Shutting down v2 agent"
        );

        // Stop background pool maintenance
        if let Some(handle) = self
            .maintenance_handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            handle.abort();
        }

        // Remove from pool - this gracefully closes connections
        if let Err(e) = self.pool.remove_agent(&self.config.id).await {
            warn!(
                agent_id = %self.config.id,
                error = %e,
                "Error removing agent from pool during shutdown"
            );
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
            "V2 agent shutdown complete"
        );
    }
}

impl Drop for AgentV2 {
    /// The last reference is gone: close the pool if nothing else has.
    ///
    /// Closing the pool's connections is async, so it is spawned on the
    /// current runtime. Without one (the process is tearing down), the
    /// maintenance task is aborted and the connections close as the pool is
    /// dropped.
    fn drop(&mut self) {
        let ceiling = self
            .ceiling_handle
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = ceiling {
            handle.abort();
        }
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let maintenance = self
            .maintenance_handle
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(handle) = maintenance {
            handle.abort();
        }

        let retired = *self.retired.get_mut();
        let id = self.config.id.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let pool = Arc::clone(&self.pool);
                runtime.spawn(async move {
                    // Not registered (never initialized) is fine: nothing to close.
                    let _ = pool.remove_agent(&id).await;
                    if retired {
                        info!(agent_id = %id, closed_by = "last_reference", "Retired agent closed");
                    } else {
                        debug!(agent_id = %id, "Dropped agent closed");
                    }
                });
            }
            Err(_) => {
                if retired {
                    info!(
                        agent_id = %id,
                        closed_by = "last_reference_without_runtime",
                        "Retired agent closed"
                    );
                }
            }
        }
    }
}

/// Convert config load balance strategy to protocol load balance strategy.
fn convert_lb_strategy(strategy: LoadBalanceStrategy) -> ProtocolLBStrategy {
    match strategy {
        LoadBalanceStrategy::RoundRobin => ProtocolLBStrategy::RoundRobin,
        LoadBalanceStrategy::LeastConnections => ProtocolLBStrategy::LeastConnections,
        LoadBalanceStrategy::HealthBased => ProtocolLBStrategy::HealthBased,
        LoadBalanceStrategy::Random => ProtocolLBStrategy::Random,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_lb_strategy() {
        assert_eq!(
            convert_lb_strategy(LoadBalanceStrategy::RoundRobin),
            ProtocolLBStrategy::RoundRobin
        );
        assert_eq!(
            convert_lb_strategy(LoadBalanceStrategy::LeastConnections),
            ProtocolLBStrategy::LeastConnections
        );
        assert_eq!(
            convert_lb_strategy(LoadBalanceStrategy::HealthBased),
            ProtocolLBStrategy::HealthBased
        );
        assert_eq!(
            convert_lb_strategy(LoadBalanceStrategy::Random),
            ProtocolLBStrategy::Random
        );
    }
}
