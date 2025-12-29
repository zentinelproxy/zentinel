//! Agent manager for coordinating external processing agents.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sentinel_agent_protocol::{
    EventType, RequestBodyChunkEvent, RequestHeadersEvent, ResponseHeadersEvent,
};
use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::CircuitBreakerConfig,
    CircuitBreaker,
};
use sentinel_config::{AgentConfig, FailureMode};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

use super::agent::Agent;
use super::context::AgentCallContext;
use super::decision::AgentDecision;
use super::metrics::AgentMetrics;
use super::pool::AgentConnectionPool;

/// Agent manager handling all external agents.
pub struct AgentManager {
    /// Configured agents
    agents: Arc<RwLock<HashMap<String, Arc<Agent>>>>,
    /// Connection pools for agents
    connection_pools: Arc<RwLock<HashMap<String, Arc<AgentConnectionPool>>>>,
    /// Circuit breakers per agent
    circuit_breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
    /// Global agent metrics
    metrics: Arc<AgentMetrics>,
    /// Maximum concurrent agent calls
    #[allow(dead_code)]
    max_concurrent_calls: usize,
    /// Global semaphore for agent calls
    call_semaphore: Arc<Semaphore>,
}

impl AgentManager {
    /// Create new agent manager.
    pub async fn new(
        agents: Vec<AgentConfig>,
        max_concurrent_calls: usize,
    ) -> SentinelResult<Self> {
        let mut agent_map = HashMap::new();
        let mut pools = HashMap::new();
        let mut breakers = HashMap::new();

        for config in agents {
            let pool = Arc::new(AgentConnectionPool::new(
                10, // max connections
                2,  // min idle
                5,  // max idle
                Duration::from_secs(60),
            ));

            let circuit_breaker = Arc::new(CircuitBreaker::new(
                config
                    .circuit_breaker
                    .clone()
                    .unwrap_or_else(CircuitBreakerConfig::default),
            ));

            let agent = Arc::new(Agent::new(
                config.clone(),
                Arc::clone(&pool),
                Arc::clone(&circuit_breaker),
            ));

            agent_map.insert(config.id.clone(), agent);
            pools.insert(config.id.clone(), pool);
            breakers.insert(config.id.clone(), circuit_breaker);
        }

        Ok(Self {
            agents: Arc::new(RwLock::new(agent_map)),
            connection_pools: Arc::new(RwLock::new(pools)),
            circuit_breakers: Arc::new(RwLock::new(breakers)),
            metrics: Arc::new(AgentMetrics::default()),
            max_concurrent_calls,
            call_semaphore: Arc::new(Semaphore::new(max_concurrent_calls)),
        })
    }

    /// Process request headers through agents.
    pub async fn process_request_headers(
        &self,
        ctx: &AgentCallContext,
        headers: &HashMap<String, Vec<String>>,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        let event = RequestHeadersEvent {
            metadata: ctx.metadata.clone(),
            method: headers
                .get(":method")
                .and_then(|v| v.first())
                .unwrap_or(&"GET".to_string())
                .clone(),
            uri: headers
                .get(":path")
                .and_then(|v| v.first())
                .unwrap_or(&"/".to_string())
                .clone(),
            headers: headers.clone(),
        };

        self.process_event(EventType::RequestHeaders, &event, route_agents, ctx)
            .await
    }

    /// Process request body chunk through agents.
    pub async fn process_request_body(
        &self,
        ctx: &AgentCallContext,
        data: &[u8],
        is_last: bool,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        // Check body size limits
        let max_size = 1024 * 1024; // 1MB default
        if data.len() > max_size {
            warn!(
                correlation_id = %ctx.correlation_id,
                size = data.len(),
                "Request body exceeds agent inspection limit"
            );
            return Ok(AgentDecision::default_allow());
        }

        let event = RequestBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size: ctx.request_body.as_ref().map(|b| b.len()),
        };

        self.process_event(EventType::RequestBodyChunk, &event, route_agents, ctx)
            .await
    }

    /// Process response headers through agents.
    pub async fn process_response_headers(
        &self,
        ctx: &AgentCallContext,
        status: u16,
        headers: &HashMap<String, Vec<String>>,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        let event = ResponseHeadersEvent {
            correlation_id: ctx.correlation_id.to_string(),
            status,
            headers: headers.clone(),
        };

        self.process_event(EventType::ResponseHeaders, &event, route_agents, ctx)
            .await
    }

    /// Process an event through relevant agents.
    async fn process_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
        route_agents: &[String],
        ctx: &AgentCallContext,
    ) -> SentinelResult<AgentDecision> {
        // Get relevant agents for this route and event type
        let agents = self.agents.read().await;
        let relevant_agents: Vec<_> = route_agents
            .iter()
            .filter_map(|id| agents.get(id))
            .filter(|agent| agent.handles_event(event_type))
            .collect();

        if relevant_agents.is_empty() {
            return Ok(AgentDecision::default_allow());
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            agent_count = relevant_agents.len(),
            "Processing event through agents"
        );

        // Process through each agent sequentially
        let mut combined_decision = AgentDecision::default_allow();

        for agent in relevant_agents {
            // Acquire semaphore permit
            let _permit = self.call_semaphore.acquire().await.map_err(|_| {
                SentinelError::Internal {
                    message: "Failed to acquire agent call permit".to_string(),
                    correlation_id: Some(ctx.correlation_id.to_string()),
                    source: None,
                }
            })?;

            // Check circuit breaker
            if !agent.circuit_breaker().is_closed().await {
                warn!(
                    agent_id = %agent.id(),
                    correlation_id = %ctx.correlation_id,
                    "Circuit breaker open, skipping agent"
                );

                // Handle based on failure mode
                if agent.failure_mode() == FailureMode::Closed {
                    return Ok(AgentDecision::block(503, "Service unavailable"));
                }
                continue;
            }

            // Call agent with timeout
            let start = Instant::now();
            let timeout = Duration::from_millis(agent.timeout_ms());

            match tokio::time::timeout(timeout, agent.call_event(event_type, event)).await {
                Ok(Ok(response)) => {
                    let duration = start.elapsed();
                    agent.record_success(duration).await;

                    // Merge response into combined decision
                    combined_decision.merge(response.into());

                    // If decision is to block/redirect/challenge, stop processing
                    if !combined_decision.is_allow() {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    agent.record_failure().await;
                    error!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        error = %e,
                        "Agent call failed"
                    );

                    if agent.failure_mode() == FailureMode::Closed {
                        return Err(e);
                    }
                }
                Err(_) => {
                    agent.record_timeout().await;
                    warn!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        timeout_ms = agent.timeout_ms(),
                        "Agent call timed out"
                    );

                    if agent.failure_mode() == FailureMode::Closed {
                        return Ok(AgentDecision::block(504, "Gateway timeout"));
                    }
                }
            }
        }

        Ok(combined_decision)
    }

    /// Initialize agent connections.
    pub async fn initialize(&self) -> SentinelResult<()> {
        let agents = self.agents.read().await;

        for (id, agent) in agents.iter() {
            info!("Initializing agent: {}", id);
            if let Err(e) = agent.initialize().await {
                error!("Failed to initialize agent {}: {}", id, e);
                // Continue with other agents
            }
        }

        Ok(())
    }

    /// Shutdown all agents.
    pub async fn shutdown(&self) {
        info!("Shutting down agent manager");

        let agents = self.agents.read().await;
        for (id, agent) in agents.iter() {
            debug!("Shutting down agent: {}", id);
            agent.shutdown().await;
        }
    }

    /// Get agent metrics.
    pub fn metrics(&self) -> &AgentMetrics {
        &self.metrics
    }
}
