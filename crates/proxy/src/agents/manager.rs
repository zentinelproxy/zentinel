//! Agent manager for coordinating external processing agents.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use pingora_timeout::timeout;
use sentinel_agent_protocol::{
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent, ResponseBodyChunkEvent,
    ResponseHeadersEvent, WebSocketFrameEvent,
};
use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::CircuitBreakerConfig,
    CircuitBreaker,
};
use sentinel_config::{AgentConfig, FailureMode};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, trace, warn};

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
    /// Per-agent semaphores for queue isolation (prevents noisy neighbor problem)
    agent_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
}

impl AgentManager {
    /// Create new agent manager.
    ///
    /// Each agent gets its own semaphore for queue isolation, preventing a slow
    /// agent from affecting other agents (noisy neighbor problem). The concurrency
    /// limit is configured per-agent via `max_concurrent_calls` in the agent config.
    pub async fn new(agents: Vec<AgentConfig>) -> SentinelResult<Self> {
        info!(agent_count = agents.len(), "Creating agent manager");

        let mut agent_map = HashMap::new();
        let mut pools = HashMap::new();
        let mut breakers = HashMap::new();
        let mut semaphores = HashMap::new();

        for config in agents {
            debug!(
                agent_id = %config.id,
                transport = ?config.transport,
                timeout_ms = config.timeout_ms,
                failure_mode = ?config.failure_mode,
                max_concurrent_calls = config.max_concurrent_calls,
                "Configuring agent"
            );

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

            // Create per-agent semaphore for queue isolation
            let semaphore = Arc::new(Semaphore::new(config.max_concurrent_calls));

            trace!(
                agent_id = %config.id,
                max_concurrent_calls = config.max_concurrent_calls,
                "Creating agent instance with isolated queue"
            );

            let agent = Arc::new(Agent::new(
                config.clone(),
                Arc::clone(&pool),
                Arc::clone(&circuit_breaker),
            ));

            agent_map.insert(config.id.clone(), agent);
            pools.insert(config.id.clone(), pool);
            breakers.insert(config.id.clone(), circuit_breaker);
            semaphores.insert(config.id.clone(), semaphore);

            debug!(
                agent_id = %config.id,
                "Agent configured successfully"
            );
        }

        info!(
            configured_agents = agent_map.len(),
            "Agent manager created successfully with per-agent queue isolation"
        );

        Ok(Self {
            agents: Arc::new(RwLock::new(agent_map)),
            connection_pools: Arc::new(RwLock::new(pools)),
            circuit_breakers: Arc::new(RwLock::new(breakers)),
            metrics: Arc::new(AgentMetrics::default()),
            agent_semaphores: Arc::new(RwLock::new(semaphores)),
        })
    }

    /// Process request headers through agents.
    ///
    /// # Arguments
    /// * `ctx` - Agent call context with correlation ID and metadata
    /// * `headers` - Request headers to send to agents
    /// * `route_agents` - List of (agent_id, failure_mode) tuples from filter chain
    pub async fn process_request_headers(
        &self,
        ctx: &AgentCallContext,
        headers: &HashMap<String, Vec<String>>,
        route_agents: &[(String, FailureMode)],
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

        self.process_event_with_failure_modes(EventType::RequestHeaders, &event, route_agents, ctx)
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
            chunk_index: 0, // Buffer mode sends entire body as single chunk
            bytes_received: data.len(),
        };

        self.process_event(EventType::RequestBodyChunk, &event, route_agents, ctx)
            .await
    }

    /// Process a single request body chunk through agents (streaming mode).
    ///
    /// Unlike `process_request_body` which is used for buffered mode, this method
    /// is designed for streaming where chunks are sent individually as they arrive.
    pub async fn process_request_body_streaming(
        &self,
        ctx: &AgentCallContext,
        data: &[u8],
        is_last: bool,
        chunk_index: u32,
        bytes_received: usize,
        total_size: Option<usize>,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            chunk_index = chunk_index,
            chunk_size = data.len(),
            bytes_received = bytes_received,
            is_last = is_last,
            "Processing streaming request body chunk"
        );

        let event = RequestBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size,
            chunk_index,
            bytes_received,
        };

        self.process_event(EventType::RequestBodyChunk, &event, route_agents, ctx)
            .await
    }

    /// Process a single response body chunk through agents (streaming mode).
    pub async fn process_response_body_streaming(
        &self,
        ctx: &AgentCallContext,
        data: &[u8],
        is_last: bool,
        chunk_index: u32,
        bytes_sent: usize,
        total_size: Option<usize>,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            chunk_index = chunk_index,
            chunk_size = data.len(),
            bytes_sent = bytes_sent,
            is_last = is_last,
            "Processing streaming response body chunk"
        );

        let event = ResponseBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size,
            chunk_index,
            bytes_sent,
        };

        self.process_event(EventType::ResponseBodyChunk, &event, route_agents, ctx)
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

    /// Process a WebSocket frame through agents.
    ///
    /// This is used for WebSocket frame inspection after an upgrade.
    /// Returns the agent response directly to allow the caller to access
    /// the websocket_decision field.
    pub async fn process_websocket_frame(
        &self,
        route_id: &str,
        event: WebSocketFrameEvent,
    ) -> SentinelResult<AgentResponse> {
        trace!(
            correlation_id = %event.correlation_id,
            route_id = %route_id,
            frame_index = event.frame_index,
            opcode = %event.opcode,
            "Processing WebSocket frame through agents"
        );

        // Get relevant agents for this route that handle WebSocket frames
        let agents = self.agents.read().await;
        let relevant_agents: Vec<_> = agents
            .values()
            .filter(|agent| agent.handles_event(EventType::WebSocketFrame))
            .collect();

        if relevant_agents.is_empty() {
            trace!(
                correlation_id = %event.correlation_id,
                "No agents handle WebSocket frames, allowing"
            );
            return Ok(AgentResponse::websocket_allow());
        }

        debug!(
            correlation_id = %event.correlation_id,
            route_id = %route_id,
            agent_count = relevant_agents.len(),
            "Processing WebSocket frame through agents"
        );

        // Process through each agent sequentially
        for agent in relevant_agents {
            // Check circuit breaker
            if !agent.circuit_breaker().is_closed().await {
                warn!(
                    agent_id = %agent.id(),
                    correlation_id = %event.correlation_id,
                    failure_mode = ?agent.failure_mode(),
                    "Circuit breaker open, skipping agent for WebSocket frame"
                );

                if agent.failure_mode() == FailureMode::Closed {
                    debug!(
                        correlation_id = %event.correlation_id,
                        agent_id = %agent.id(),
                        "Closing WebSocket due to circuit breaker (fail-closed mode)"
                    );
                    return Ok(AgentResponse::websocket_close(
                        1011,
                        "Service unavailable".to_string(),
                    ));
                }
                continue;
            }

            // Call agent with timeout
            let start = Instant::now();
            let timeout_duration = Duration::from_millis(agent.timeout_ms());

            match timeout(
                timeout_duration,
                agent.call_event(EventType::WebSocketFrame, &event),
            )
            .await
            {
                Ok(Ok(response)) => {
                    let duration = start.elapsed();
                    agent.record_success(duration).await;

                    trace!(
                        correlation_id = %event.correlation_id,
                        agent_id = %agent.id(),
                        duration_ms = duration.as_millis(),
                        "WebSocket frame agent call succeeded"
                    );

                    // If agent returned a WebSocket decision that's not Allow, return immediately
                    if let Some(ref ws_decision) = response.websocket_decision {
                        if !matches!(
                            ws_decision,
                            sentinel_agent_protocol::WebSocketDecision::Allow
                        ) {
                            debug!(
                                correlation_id = %event.correlation_id,
                                agent_id = %agent.id(),
                                decision = ?ws_decision,
                                "Agent returned non-allow WebSocket decision"
                            );
                            return Ok(response);
                        }
                    }
                }
                Ok(Err(e)) => {
                    agent.record_failure().await;
                    error!(
                        agent_id = %agent.id(),
                        correlation_id = %event.correlation_id,
                        error = %e,
                        duration_ms = start.elapsed().as_millis(),
                        failure_mode = ?agent.failure_mode(),
                        "WebSocket frame agent call failed"
                    );

                    if agent.failure_mode() == FailureMode::Closed {
                        return Ok(AgentResponse::websocket_close(
                            1011,
                            "Agent error".to_string(),
                        ));
                    }
                }
                Err(_) => {
                    agent.record_timeout().await;
                    warn!(
                        agent_id = %agent.id(),
                        correlation_id = %event.correlation_id,
                        timeout_ms = agent.timeout_ms(),
                        failure_mode = ?agent.failure_mode(),
                        "WebSocket frame agent call timed out"
                    );

                    if agent.failure_mode() == FailureMode::Closed {
                        return Ok(AgentResponse::websocket_close(
                            1011,
                            "Gateway timeout".to_string(),
                        ));
                    }
                }
            }
        }

        // All agents allowed the frame
        Ok(AgentResponse::websocket_allow())
    }

    /// Process an event through relevant agents.
    async fn process_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
        route_agents: &[String],
        ctx: &AgentCallContext,
    ) -> SentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            route_agents = ?route_agents,
            "Starting agent event processing"
        );

        // Get relevant agents for this route and event type
        let agents = self.agents.read().await;
        let relevant_agents: Vec<_> = route_agents
            .iter()
            .filter_map(|id| agents.get(id))
            .filter(|agent| agent.handles_event(event_type))
            .collect();

        if relevant_agents.is_empty() {
            trace!(
                correlation_id = %ctx.correlation_id,
                event_type = ?event_type,
                "No relevant agents for event, allowing request"
            );
            return Ok(AgentDecision::default_allow());
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            agent_count = relevant_agents.len(),
            agent_ids = ?relevant_agents.iter().map(|a| a.id()).collect::<Vec<_>>(),
            "Processing event through agents"
        );

        // Process through each agent sequentially
        let mut combined_decision = AgentDecision::default_allow();

        for (agent_index, agent) in relevant_agents.iter().enumerate() {
            trace!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent.id(),
                agent_index = agent_index,
                event_type = ?event_type,
                "Processing event through agent"
            );

            // Acquire per-agent semaphore permit (queue isolation)
            let semaphores = self.agent_semaphores.read().await;
            let agent_semaphore = semaphores.get(agent.id()).cloned();
            drop(semaphores); // Release lock before awaiting

            let _permit = match agent_semaphore {
                Some(semaphore) => {
                    trace!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Acquiring per-agent semaphore permit"
                    );
                    Some(semaphore.acquire_owned().await.map_err(|_| {
                        error!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            "Failed to acquire agent call semaphore permit"
                        );
                        SentinelError::Internal {
                            message: "Failed to acquire agent call permit".to_string(),
                            correlation_id: Some(ctx.correlation_id.to_string()),
                            source: None,
                        }
                    })?)
                }
                None => {
                    // No semaphore found (shouldn't happen, but fail gracefully)
                    warn!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "No semaphore found for agent, proceeding without queue isolation"
                    );
                    None
                }
            };

            // Check circuit breaker
            if !agent.circuit_breaker().is_closed().await {
                warn!(
                    agent_id = %agent.id(),
                    correlation_id = %ctx.correlation_id,
                    failure_mode = ?agent.failure_mode(),
                    "Circuit breaker open, skipping agent"
                );

                // Handle based on failure mode
                if agent.failure_mode() == FailureMode::Closed {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Blocking request due to circuit breaker (fail-closed mode)"
                    );
                    return Ok(AgentDecision::block(503, "Service unavailable"));
                }
                continue;
            }

            // Call agent with timeout (using pingora-timeout for efficiency)
            let start = Instant::now();
            let timeout_duration = Duration::from_millis(agent.timeout_ms());

            trace!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent.id(),
                timeout_ms = agent.timeout_ms(),
                "Calling agent"
            );

            match timeout(timeout_duration, agent.call_event(event_type, event)).await {
                Ok(Ok(response)) => {
                    let duration = start.elapsed();
                    agent.record_success(duration).await;

                    trace!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        duration_ms = duration.as_millis(),
                        decision = ?response,
                        "Agent call succeeded"
                    );

                    // Merge response into combined decision
                    combined_decision.merge(response.into());

                    // If decision is to block/redirect/challenge, stop processing
                    if !combined_decision.is_allow() {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            decision = ?combined_decision,
                            "Agent returned blocking decision, stopping agent chain"
                        );
                        break;
                    }
                }
                Ok(Err(e)) => {
                    agent.record_failure().await;
                    error!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        error = %e,
                        duration_ms = start.elapsed().as_millis(),
                        failure_mode = ?agent.failure_mode(),
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
                        failure_mode = ?agent.failure_mode(),
                        "Agent call timed out"
                    );

                    if agent.failure_mode() == FailureMode::Closed {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            "Blocking request due to timeout (fail-closed mode)"
                        );
                        return Ok(AgentDecision::block(504, "Gateway timeout"));
                    }
                }
            }
        }

        trace!(
            correlation_id = %ctx.correlation_id,
            decision = ?combined_decision,
            agents_processed = relevant_agents.len(),
            "Agent event processing completed"
        );

        Ok(combined_decision)
    }

    /// Process an event through relevant agents with per-filter failure modes.
    ///
    /// This is the preferred method for processing events as it respects the
    /// failure mode configured on each filter, not just the agent's default.
    async fn process_event_with_failure_modes<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
        route_agents: &[(String, FailureMode)],
        ctx: &AgentCallContext,
    ) -> SentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            route_agents = ?route_agents.iter().map(|(id, _)| id).collect::<Vec<_>>(),
            "Starting agent event processing with failure modes"
        );

        // Get relevant agents for this route and event type, preserving failure modes
        let agents = self.agents.read().await;
        let relevant_agents: Vec<_> = route_agents
            .iter()
            .filter_map(|(id, failure_mode)| {
                agents.get(id).map(|agent| (agent, *failure_mode))
            })
            .filter(|(agent, _)| agent.handles_event(event_type))
            .collect();

        if relevant_agents.is_empty() {
            trace!(
                correlation_id = %ctx.correlation_id,
                event_type = ?event_type,
                "No relevant agents for event, allowing request"
            );
            return Ok(AgentDecision::default_allow());
        }

        debug!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            agent_count = relevant_agents.len(),
            agent_ids = ?relevant_agents.iter().map(|(a, _)| a.id()).collect::<Vec<_>>(),
            "Processing event through agents"
        );

        // Process through each agent sequentially
        let mut combined_decision = AgentDecision::default_allow();

        for (agent_index, (agent, filter_failure_mode)) in relevant_agents.iter().enumerate() {
            trace!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent.id(),
                agent_index = agent_index,
                event_type = ?event_type,
                filter_failure_mode = ?filter_failure_mode,
                "Processing event through agent with filter failure mode"
            );

            // Acquire per-agent semaphore permit (queue isolation)
            let semaphores = self.agent_semaphores.read().await;
            let agent_semaphore = semaphores.get(agent.id()).cloned();
            drop(semaphores); // Release lock before awaiting

            let _permit = if let Some(semaphore) = agent_semaphore {
                trace!(
                    correlation_id = %ctx.correlation_id,
                    agent_id = %agent.id(),
                    "Acquiring per-agent semaphore permit"
                );
                Some(semaphore.acquire_owned().await.map_err(|_| {
                    error!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Failed to acquire agent call semaphore permit"
                    );
                    SentinelError::Internal {
                        message: "Failed to acquire agent call permit".to_string(),
                        correlation_id: Some(ctx.correlation_id.to_string()),
                        source: None,
                    }
                })?)
            } else {
                // No semaphore found (shouldn't happen, but fail gracefully)
                warn!(
                    correlation_id = %ctx.correlation_id,
                    agent_id = %agent.id(),
                    "No semaphore found for agent, proceeding without queue isolation"
                );
                None
            };

            // Check circuit breaker
            if !agent.circuit_breaker().is_closed().await {
                warn!(
                    agent_id = %agent.id(),
                    correlation_id = %ctx.correlation_id,
                    filter_failure_mode = ?filter_failure_mode,
                    "Circuit breaker open, skipping agent"
                );

                // Handle based on filter's failure mode (not agent's default)
                if *filter_failure_mode == FailureMode::Closed {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Blocking request due to circuit breaker (filter fail-closed mode)"
                    );
                    return Ok(AgentDecision::block(503, "Service unavailable"));
                }
                // Fail-open: continue to next agent
                continue;
            }

            // Call agent with timeout
            let start = Instant::now();
            let timeout_duration = Duration::from_millis(agent.timeout_ms());

            trace!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent.id(),
                timeout_ms = agent.timeout_ms(),
                "Calling agent"
            );

            match timeout(timeout_duration, agent.call_event(event_type, event)).await {
                Ok(Ok(response)) => {
                    let duration = start.elapsed();
                    agent.record_success(duration).await;

                    trace!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        duration_ms = duration.as_millis(),
                        decision = ?response,
                        "Agent call succeeded"
                    );

                    // Merge response into combined decision
                    combined_decision.merge(response.into());

                    // If decision is to block/redirect/challenge, stop processing
                    if !combined_decision.is_allow() {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            decision = ?combined_decision,
                            "Agent returned blocking decision, stopping agent chain"
                        );
                        break;
                    }
                }
                Ok(Err(e)) => {
                    agent.record_failure().await;
                    error!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        error = %e,
                        duration_ms = start.elapsed().as_millis(),
                        filter_failure_mode = ?filter_failure_mode,
                        "Agent call failed"
                    );

                    // Use filter's failure mode, not agent's default
                    if *filter_failure_mode == FailureMode::Closed {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            "Blocking request due to agent failure (filter fail-closed mode)"
                        );
                        return Ok(AgentDecision::block(503, "Agent unavailable"));
                    }
                    // Fail-open: continue to next agent (or proceed without this agent)
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Continuing despite agent failure (filter fail-open mode)"
                    );
                }
                Err(_) => {
                    agent.record_timeout().await;
                    warn!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        timeout_ms = agent.timeout_ms(),
                        filter_failure_mode = ?filter_failure_mode,
                        "Agent call timed out"
                    );

                    // Use filter's failure mode, not agent's default
                    if *filter_failure_mode == FailureMode::Closed {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            "Blocking request due to timeout (filter fail-closed mode)"
                        );
                        return Ok(AgentDecision::block(504, "Gateway timeout"));
                    }
                    // Fail-open: continue to next agent
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Continuing despite timeout (filter fail-open mode)"
                    );
                }
            }
        }

        trace!(
            correlation_id = %ctx.correlation_id,
            decision = ?combined_decision,
            agents_processed = relevant_agents.len(),
            "Agent event processing with failure modes completed"
        );

        Ok(combined_decision)
    }

    /// Initialize agent connections.
    pub async fn initialize(&self) -> SentinelResult<()> {
        let agents = self.agents.read().await;

        info!(agent_count = agents.len(), "Initializing agent connections");

        let mut initialized_count = 0;
        let mut failed_count = 0;

        for (id, agent) in agents.iter() {
            debug!(agent_id = %id, "Initializing agent connection");
            if let Err(e) = agent.initialize().await {
                error!(
                    agent_id = %id,
                    error = %e,
                    "Failed to initialize agent"
                );
                failed_count += 1;
                // Continue with other agents
            } else {
                trace!(agent_id = %id, "Agent initialized successfully");
                initialized_count += 1;
            }
        }

        info!(
            initialized = initialized_count,
            failed = failed_count,
            total = agents.len(),
            "Agent initialization complete"
        );

        Ok(())
    }

    /// Shutdown all agents.
    pub async fn shutdown(&self) {
        let agents = self.agents.read().await;

        info!(agent_count = agents.len(), "Shutting down agent manager");

        for (id, agent) in agents.iter() {
            debug!(agent_id = %id, "Shutting down agent");
            agent.shutdown().await;
            trace!(agent_id = %id, "Agent shutdown complete");
        }

        info!("Agent manager shutdown complete");
    }

    /// Get agent metrics.
    pub fn metrics(&self) -> &AgentMetrics {
        &self.metrics
    }

    /// Get agent IDs that handle a specific event type.
    ///
    /// This is useful for pre-filtering agents before making calls,
    /// e.g., to check if any agents handle WebSocket frames.
    pub fn get_agents_for_event(&self, event_type: EventType) -> Vec<String> {
        // Use try_read to avoid blocking - return empty if lock is held
        // This is acceptable since this is only used for informational purposes
        if let Ok(agents) = self.agents.try_read() {
            agents
                .values()
                .filter(|agent| agent.handles_event(event_type))
                .map(|agent| agent.id().to_string())
                .collect()
        } else {
            Vec::new()
        }
    }
}
