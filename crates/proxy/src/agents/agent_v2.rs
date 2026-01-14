//! Protocol v2 agent implementation.
//!
//! This module provides v2 agent support using the bidirectional streaming
//! protocol with capabilities, health reporting, and metrics export.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_agent_protocol::v2::{
    AgentCapabilities, AgentPool, AgentPoolConfig as ProtocolPoolConfig,
    AgentPoolStats, CancelReason, ConfigPusher, ConfigUpdateType,
    LoadBalanceStrategy as ProtocolLBStrategy, MetricsCollector,
};
use sentinel_agent_protocol::{
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseBodyChunkEvent, ResponseHeadersEvent,
};
use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    CircuitBreaker,
};
use sentinel_config::{AgentConfig, AgentEvent, FailureMode, LoadBalanceStrategy};
use tracing::{debug, error, info, trace, warn};

use super::metrics::AgentMetrics;

/// Sentinel value indicating no timestamp recorded
const NO_TIMESTAMP: u64 = 0;

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
}

impl AgentV2 {
    /// Create a new v2 agent.
    pub fn new(
        config: AgentConfig,
        circuit_breaker: Arc<CircuitBreaker>,
    ) -> Self {
        trace!(
            agent_id = %config.id,
            agent_type = ?config.agent_type,
            timeout_ms = config.timeout_ms,
            events = ?config.events,
            "Creating v2 agent instance"
        );

        // Convert config pool settings to protocol pool config
        let pool_config = config.pool.as_ref().map(|p| ProtocolPoolConfig {
            connections_per_agent: p.connections_per_agent,
            load_balance_strategy: convert_lb_strategy(p.load_balance_strategy),
            connect_timeout: Duration::from_millis(p.connect_timeout_ms),
            request_timeout: Duration::from_millis(config.timeout_ms),
            reconnect_interval: Duration::from_millis(p.reconnect_interval_ms),
            max_reconnect_attempts: p.max_reconnect_attempts,
            drain_timeout: Duration::from_millis(p.drain_timeout_ms),
            max_concurrent_per_connection: p.max_concurrent_per_connection,
            health_check_interval: Duration::from_millis(p.health_check_interval_ms),
        }).unwrap_or_default();

        let pool = Arc::new(AgentPool::with_config(pool_config));

        Self {
            config,
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
    pub fn failure_mode(&self) -> FailureMode {
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

    /// Initialize agent connection(s).
    pub async fn initialize(&self) -> SentinelResult<()> {
        let endpoint = self.get_endpoint()?;

        debug!(
            agent_id = %self.config.id,
            endpoint = %endpoint,
            "Initializing v2 agent pool"
        );

        let start = Instant::now();

        // Add agent to pool - pool will establish connections
        self.pool.add_agent(&self.config.id, &endpoint).await
            .map_err(|e| {
                error!(
                    agent_id = %self.config.id,
                    endpoint = %endpoint,
                    error = %e,
                    "Failed to add agent to v2 pool"
                );
                SentinelError::Agent {
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
            "V2 agent pool initialized"
        );

        // Send configuration if present
        if let Some(config_value) = &self.config.config {
            self.send_configure(config_value.clone()).await?;
        }

        Ok(())
    }

    /// Get endpoint from transport config.
    fn get_endpoint(&self) -> SentinelResult<String> {
        use sentinel_config::AgentTransport;
        match &self.config.transport {
            AgentTransport::Grpc { address, .. } => Ok(address.clone()),
            AgentTransport::UnixSocket { path } => {
                // For UDS, format as unix:path
                Ok(format!("unix:{}", path.display()))
            }
            AgentTransport::Http { url, .. } => {
                // V2 doesn't support HTTP transport
                Err(SentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: "HTTP transport not supported for v2 protocol".to_string(),
                    event: "initialize".to_string(),
                    source: None,
                })
            }
        }
    }

    /// Send configuration to the agent.
    ///
    /// Note: Configuration is sent through the control stream when connections
    /// are established. This is a placeholder for explicit config updates.
    async fn send_configure(&self, _config: serde_json::Value) -> SentinelResult<()> {
        debug!(
            agent_id = %self.config.id,
            "Configuration will be sent through control stream on connection"
        );

        // Configuration is handled by the pool's connections during initialization
        // For explicit config updates, we'd need to iterate through connections
        // and send configure through their control streams

        info!(
            agent_id = %self.config.id,
            "V2 agent configuration noted"
        );

        Ok(())
    }

    /// Call agent with request headers event.
    pub async fn call_request_headers(
        &self,
        event: &RequestHeadersEvent,
    ) -> SentinelResult<AgentResponse> {
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
                SentinelError::Agent {
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
    ) -> SentinelResult<AgentResponse> {
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
                SentinelError::Agent {
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
    ) -> SentinelResult<AgentResponse> {
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
                SentinelError::Agent {
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
    ) -> SentinelResult<AgentResponse> {
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
                SentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: e.to_string(),
                    event: "response_body_chunk".to_string(),
                    source: None,
                }
            })
    }

    /// Cancel an in-flight request.
    pub async fn cancel_request(
        &self,
        correlation_id: &str,
        reason: CancelReason,
    ) -> SentinelResult<()> {
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
                SentinelError::Agent {
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
    pub fn is_healthy(&self) -> bool {
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

    /// Send a configuration update to this agent via the control stream.
    ///
    /// This is a direct config push using the `ConfigureEvent` message.
    pub async fn send_configuration(&self, config: serde_json::Value) -> SentinelResult<()> {
        // Get a connection and send the configure event
        // For now, we rely on the pool's config push mechanism
        // which tracks acknowledgments and retries
        if let Some(push_id) = self.push_config(ConfigUpdateType::RequestReload) {
            debug!(
                agent_id = %self.config.id,
                push_id = %push_id,
                "Configuration push initiated"
            );
            Ok(())
        } else {
            warn!(
                agent_id = %self.config.id,
                "Agent does not support config push"
            );
            Err(SentinelError::Agent {
                agent: self.config.id.clone(),
                message: "Agent does not support config push".to_string(),
                event: "send_configuration".to_string(),
                source: None,
            })
        }
    }

    /// Shutdown agent.
    ///
    /// This removes the agent from the pool and closes all connections.
    pub async fn shutdown(&self) {
        debug!(
            agent_id = %self.config.id,
            "Shutting down v2 agent"
        );

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
