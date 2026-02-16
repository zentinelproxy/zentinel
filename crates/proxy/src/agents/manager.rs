//! Agent manager for coordinating external processing agents.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::future::join_all;
use pingora_timeout::timeout;
use sentinel_agent_protocol::{
    v2::MetricsCollector, AgentResponse, EventType, GuardrailInspectEvent, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketFrameEvent,
};
use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::CircuitBreakerConfig,
    CircuitBreaker,
};
use sentinel_config::{AgentConfig, AgentProtocolVersion, FailureMode};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, trace, warn};

use super::agent::Agent;
use super::agent_v2::AgentV2;
use super::context::AgentCallContext;
use super::decision::AgentDecision;
use super::metrics::AgentMetrics;
use super::pool::AgentConnectionPool;

/// Unified agent wrapper supporting both v1 and v2 protocols.
pub enum UnifiedAgent {
    V1(Arc<Agent>),
    V2(Arc<AgentV2>),
}

impl UnifiedAgent {
    /// Get the agent ID.
    pub fn id(&self) -> &str {
        match self {
            UnifiedAgent::V1(agent) => agent.id(),
            UnifiedAgent::V2(agent) => agent.id(),
        }
    }

    /// Get the agent's circuit breaker.
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        match self {
            UnifiedAgent::V1(agent) => agent.circuit_breaker(),
            UnifiedAgent::V2(agent) => agent.circuit_breaker(),
        }
    }

    /// Get the agent's failure mode.
    pub fn failure_mode(&self) -> FailureMode {
        match self {
            UnifiedAgent::V1(agent) => agent.failure_mode(),
            UnifiedAgent::V2(agent) => agent.failure_mode(),
        }
    }

    /// Get the agent's timeout in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        match self {
            UnifiedAgent::V1(agent) => agent.timeout_ms(),
            UnifiedAgent::V2(agent) => agent.timeout_ms(),
        }
    }

    /// Check if agent handles a specific event type.
    pub fn handles_event(&self, event_type: EventType) -> bool {
        match self {
            UnifiedAgent::V1(agent) => agent.handles_event(event_type),
            UnifiedAgent::V2(agent) => agent.handles_event(event_type),
        }
    }

    /// Initialize agent connection(s).
    pub async fn initialize(&self) -> SentinelResult<()> {
        match self {
            UnifiedAgent::V1(agent) => agent.initialize().await,
            UnifiedAgent::V2(agent) => agent.initialize().await,
        }
    }

    /// Call agent with event.
    ///
    /// For V2 agents, this dispatches to the appropriate typed method based on
    /// event type. The event is serialized and deserialized to convert between
    /// the generic type and the specific event struct.
    pub async fn call_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(event_type, event).await,
            UnifiedAgent::V2(agent) => {
                // V2 uses typed methods - convert to appropriate event type
                let json = serde_json::to_value(event).map_err(|e| SentinelError::Agent {
                    agent: agent.id().to_string(),
                    message: format!("Failed to serialize event: {}", e),
                    event: format!("{:?}", event_type),
                    source: None,
                })?;

                match event_type {
                    EventType::RequestHeaders => {
                        let typed_event: RequestHeadersEvent = serde_json::from_value(json)
                            .map_err(|e| SentinelError::Agent {
                                agent: agent.id().to_string(),
                                message: format!(
                                    "Failed to deserialize RequestHeadersEvent: {}",
                                    e
                                ),
                                event: format!("{:?}", event_type),
                                source: None,
                            })?;
                        agent.call_request_headers(&typed_event).await
                    }
                    EventType::RequestBodyChunk => {
                        let typed_event: RequestBodyChunkEvent = serde_json::from_value(json)
                            .map_err(|e| SentinelError::Agent {
                                agent: agent.id().to_string(),
                                message: format!(
                                    "Failed to deserialize RequestBodyChunkEvent: {}",
                                    e
                                ),
                                event: format!("{:?}", event_type),
                                source: None,
                            })?;
                        agent.call_request_body_chunk(&typed_event).await
                    }
                    EventType::ResponseHeaders => {
                        let typed_event: ResponseHeadersEvent = serde_json::from_value(json)
                            .map_err(|e| SentinelError::Agent {
                                agent: agent.id().to_string(),
                                message: format!(
                                    "Failed to deserialize ResponseHeadersEvent: {}",
                                    e
                                ),
                                event: format!("{:?}", event_type),
                                source: None,
                            })?;
                        agent.call_response_headers(&typed_event).await
                    }
                    EventType::ResponseBodyChunk => {
                        let typed_event: ResponseBodyChunkEvent = serde_json::from_value(json)
                            .map_err(|e| SentinelError::Agent {
                                agent: agent.id().to_string(),
                                message: format!(
                                    "Failed to deserialize ResponseBodyChunkEvent: {}",
                                    e
                                ),
                                event: format!("{:?}", event_type),
                                source: None,
                            })?;
                        agent.call_response_body_chunk(&typed_event).await
                    }
                    EventType::GuardrailInspect => {
                        let typed_event: GuardrailInspectEvent = serde_json::from_value(json)
                            .map_err(|e| SentinelError::Agent {
                                agent: agent.id().to_string(),
                                message: format!(
                                    "Failed to deserialize GuardrailInspectEvent: {}",
                                    e
                                ),
                                event: format!("{:?}", event_type),
                                source: None,
                            })?;
                        agent.call_guardrail_inspect(&typed_event).await
                    }
                    _ => {
                        // For unsupported event types, return error
                        Err(SentinelError::Agent {
                            agent: agent.id().to_string(),
                            message: format!("V2 does not support event type {:?}", event_type),
                            event: format!("{:?}", event_type),
                            source: None,
                        })
                    }
                }
            }
        }
    }

    /// Call agent with request headers event (v2-optimized).
    pub async fn call_request_headers(
        &self,
        event: &RequestHeadersEvent,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(EventType::RequestHeaders, event).await,
            UnifiedAgent::V2(agent) => agent.call_request_headers(event).await,
        }
    }

    /// Call agent with request body chunk event (v2-optimized).
    pub async fn call_request_body_chunk(
        &self,
        event: &RequestBodyChunkEvent,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(EventType::RequestBodyChunk, event).await,
            UnifiedAgent::V2(agent) => agent.call_request_body_chunk(event).await,
        }
    }

    /// Call agent with response headers event (v2-optimized).
    pub async fn call_response_headers(
        &self,
        event: &ResponseHeadersEvent,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(EventType::ResponseHeaders, event).await,
            UnifiedAgent::V2(agent) => agent.call_response_headers(event).await,
        }
    }

    /// Call agent with response body chunk event (v2-optimized).
    pub async fn call_response_body_chunk(
        &self,
        event: &ResponseBodyChunkEvent,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(EventType::ResponseBodyChunk, event).await,
            UnifiedAgent::V2(agent) => agent.call_response_body_chunk(event).await,
        }
    }

    /// Call agent with guardrail inspect event (v2-optimized).
    pub async fn call_guardrail_inspect(
        &self,
        event: &GuardrailInspectEvent,
    ) -> SentinelResult<AgentResponse> {
        match self {
            UnifiedAgent::V1(agent) => agent.call_event(EventType::GuardrailInspect, event).await,
            UnifiedAgent::V2(agent) => agent.call_guardrail_inspect(event).await,
        }
    }

    /// Record successful call.
    pub async fn record_success(&self, duration: Duration) {
        match self {
            UnifiedAgent::V1(agent) => agent.record_success(duration).await,
            UnifiedAgent::V2(agent) => agent.record_success(duration),
        }
    }

    /// Record failed call.
    pub async fn record_failure(&self) {
        match self {
            UnifiedAgent::V1(agent) => agent.record_failure().await,
            UnifiedAgent::V2(agent) => agent.record_failure(),
        }
    }

    /// Record timeout.
    pub async fn record_timeout(&self) {
        match self {
            UnifiedAgent::V1(agent) => agent.record_timeout().await,
            UnifiedAgent::V2(agent) => agent.record_timeout(),
        }
    }

    /// Shutdown agent.
    pub async fn shutdown(&self) {
        match self {
            UnifiedAgent::V1(agent) => agent.shutdown().await,
            UnifiedAgent::V2(agent) => agent.shutdown().await,
        }
    }

    /// Check if this is a v2 agent.
    pub fn is_v2(&self) -> bool {
        matches!(self, UnifiedAgent::V2(_))
    }
}

/// Agent manager handling all external agents.
///
/// Supports both v1 and v2 protocol agents. V1 agents use simple request/response,
/// while v2 agents support bidirectional streaming with capabilities, health
/// reporting, metrics export, and flow control.
pub struct AgentManager {
    /// Configured agents (unified wrapper for v1 and v2)
    agents: Arc<RwLock<HashMap<String, Arc<UnifiedAgent>>>>,
    /// Connection pools for v1 agents only
    connection_pools: Arc<RwLock<HashMap<String, Arc<AgentConnectionPool>>>>,
    /// Circuit breakers per agent (v1 only - v2 has circuit breakers in pool)
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
    ///
    /// Supports both v1 and v2 protocol agents based on the `protocol_version` field.
    pub async fn new(agents: Vec<AgentConfig>) -> SentinelResult<Self> {
        info!(agent_count = agents.len(), "Creating agent manager");

        let mut agent_map = HashMap::new();
        let mut pools = HashMap::new();
        let mut breakers = HashMap::new();
        let mut semaphores = HashMap::new();

        let mut v1_count = 0;
        let mut v2_count = 0;

        for config in agents {
            debug!(
                agent_id = %config.id,
                transport = ?config.transport,
                timeout_ms = config.timeout_ms,
                failure_mode = ?config.failure_mode,
                max_concurrent_calls = config.max_concurrent_calls,
                protocol_version = ?config.protocol_version,
                "Configuring agent"
            );

            // Create per-agent semaphore for queue isolation
            let semaphore = Arc::new(Semaphore::new(config.max_concurrent_calls));

            let unified_agent = match config.protocol_version {
                AgentProtocolVersion::V1 => {
                    // V1: Create pool and circuit breaker externally
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

                    trace!(
                        agent_id = %config.id,
                        max_concurrent_calls = config.max_concurrent_calls,
                        "Creating v1 agent instance with isolated queue"
                    );

                    let agent = Arc::new(Agent::new(
                        config.clone(),
                        Arc::clone(&pool),
                        Arc::clone(&circuit_breaker),
                    ));

                    pools.insert(config.id.clone(), pool);
                    breakers.insert(config.id.clone(), circuit_breaker);
                    v1_count += 1;

                    Arc::new(UnifiedAgent::V1(agent))
                }
                AgentProtocolVersion::V2 => {
                    // V2: Pool and circuit breaker are internal to AgentV2
                    let circuit_breaker = Arc::new(CircuitBreaker::new(
                        config
                            .circuit_breaker
                            .clone()
                            .unwrap_or_else(CircuitBreakerConfig::default),
                    ));

                    trace!(
                        agent_id = %config.id,
                        max_concurrent_calls = config.max_concurrent_calls,
                        pool_config = ?config.pool,
                        "Creating v2 agent instance with internal pool"
                    );

                    let agent = Arc::new(AgentV2::new(config.clone(), circuit_breaker));

                    v2_count += 1;

                    Arc::new(UnifiedAgent::V2(agent))
                }
            };

            agent_map.insert(config.id.clone(), unified_agent);
            semaphores.insert(config.id.clone(), semaphore);

            debug!(
                agent_id = %config.id,
                protocol_version = ?config.protocol_version,
                "Agent configured successfully"
            );
        }

        info!(
            configured_agents = agent_map.len(),
            v1_agents = v1_count,
            v2_agents = v2_count,
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
        mut headers: HashMap<String, Vec<String>>,
        route_agents: &[(String, FailureMode)],
    ) -> SentinelResult<AgentDecision> {
        let method = headers
            .remove(":method")
            .and_then(|mut v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.swap_remove(0))
                }
            })
            .unwrap_or_else(|| "GET".to_string());
        let uri = headers
            .remove(":path")
            .and_then(|mut v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v.swap_remove(0))
                }
            })
            .unwrap_or_else(|| "/".to_string());
        let event = RequestHeadersEvent {
            metadata: ctx.metadata.clone(),
            method,
            uri,
            headers,
        };

        // Use parallel processing for better latency with multiple agents
        self.process_event_parallel(EventType::RequestHeaders, &event, route_agents, ctx)
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
            if !agent.circuit_breaker().is_closed() {
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
            if !agent.circuit_breaker().is_closed() {
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
            .filter_map(|(id, failure_mode)| agents.get(id).map(|agent| (agent, *failure_mode)))
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
            if !agent.circuit_breaker().is_closed() {
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

    /// Process an event through relevant agents in parallel.
    ///
    /// This method executes all agent calls concurrently using `join_all`, which
    /// significantly improves latency when multiple agents are configured. The
    /// tradeoff is that if one agent blocks, other agents may still complete
    /// their work (slight resource waste in blocking scenarios).
    ///
    /// # Performance
    ///
    /// For N agents with latency L each:
    /// - Sequential: O(N * L)
    /// - Parallel: O(L) (assuming sufficient concurrency)
    ///
    /// This is the preferred method for most use cases.
    async fn process_event_parallel<T: serde::Serialize + Sync>(
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
            "Starting parallel agent event processing"
        );

        // Get relevant agents for this route and event type
        let agents = self.agents.read().await;
        let semaphores = self.agent_semaphores.read().await;

        // Collect agent info upfront to minimize lock duration
        let agent_info: Vec<_> = route_agents
            .iter()
            .filter_map(|(id, failure_mode)| {
                let agent = agents.get(id)?;
                if !agent.handles_event(event_type) {
                    return None;
                }
                let semaphore = semaphores.get(id).cloned();
                Some((Arc::clone(agent), *failure_mode, semaphore))
            })
            .collect();

        // Release locks early
        drop(agents);
        drop(semaphores);

        if agent_info.is_empty() {
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
            agent_count = agent_info.len(),
            agent_ids = ?agent_info.iter().map(|(a, _, _)| a.id()).collect::<Vec<_>>(),
            "Processing event through agents in parallel"
        );

        // Spawn all agent calls concurrently
        let futures: Vec<_> = agent_info
            .iter()
            .map(|(agent, filter_failure_mode, semaphore)| {
                let agent = Arc::clone(agent);
                let filter_failure_mode = *filter_failure_mode;
                let semaphore = semaphore.clone();
                let correlation_id = ctx.correlation_id.clone();

                async move {
                    // Acquire per-agent semaphore permit (queue isolation)
                    let _permit = if let Some(sem) = semaphore {
                        match sem.acquire_owned().await {
                            Ok(permit) => Some(permit),
                            Err(_) => {
                                error!(
                                    correlation_id = %correlation_id,
                                    agent_id = %agent.id(),
                                    "Failed to acquire agent semaphore permit"
                                );
                                return Err((
                                    agent.id().to_string(),
                                    filter_failure_mode,
                                    "Failed to acquire permit".to_string(),
                                ));
                            }
                        }
                    } else {
                        None
                    };

                    // Check circuit breaker
                    if !agent.circuit_breaker().is_closed() {
                        warn!(
                            agent_id = %agent.id(),
                            correlation_id = %correlation_id,
                            filter_failure_mode = ?filter_failure_mode,
                            "Circuit breaker open, skipping agent"
                        );
                        return Err((
                            agent.id().to_string(),
                            filter_failure_mode,
                            "Circuit breaker open".to_string(),
                        ));
                    }

                    // Call agent with timeout
                    let start = Instant::now();
                    let timeout_duration = Duration::from_millis(agent.timeout_ms());

                    match timeout(timeout_duration, agent.call_event(event_type, event)).await {
                        Ok(Ok(response)) => {
                            let duration = start.elapsed();
                            agent.record_success(duration).await;
                            trace!(
                                correlation_id = %correlation_id,
                                agent_id = %agent.id(),
                                duration_ms = duration.as_millis(),
                                "Parallel agent call succeeded"
                            );
                            Ok((agent.id().to_string(), response))
                        }
                        Ok(Err(e)) => {
                            agent.record_failure().await;
                            error!(
                                agent_id = %agent.id(),
                                correlation_id = %correlation_id,
                                error = %e,
                                duration_ms = start.elapsed().as_millis(),
                                filter_failure_mode = ?filter_failure_mode,
                                "Parallel agent call failed"
                            );
                            Err((
                                agent.id().to_string(),
                                filter_failure_mode,
                                format!("Agent error: {}", e),
                            ))
                        }
                        Err(_) => {
                            agent.record_timeout().await;
                            warn!(
                                agent_id = %agent.id(),
                                correlation_id = %correlation_id,
                                timeout_ms = agent.timeout_ms(),
                                filter_failure_mode = ?filter_failure_mode,
                                "Parallel agent call timed out"
                            );
                            Err((
                                agent.id().to_string(),
                                filter_failure_mode,
                                "Timeout".to_string(),
                            ))
                        }
                    }
                }
            })
            .collect();

        // Execute all agent calls in parallel
        let results = join_all(futures).await;

        // Process results and merge decisions
        let mut combined_decision = AgentDecision::default_allow();
        let mut blocking_error: Option<AgentDecision> = None;

        for result in results {
            match result {
                Ok((agent_id, response)) => {
                    let decision: AgentDecision = response.into();

                    // Check for blocking decision
                    if !decision.is_allow() {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent_id,
                            decision = ?decision,
                            "Agent returned blocking decision"
                        );
                        // Return first blocking decision immediately
                        return Ok(decision);
                    }

                    combined_decision.merge(decision);
                }
                Err((agent_id, failure_mode, reason)) => {
                    // Handle failure based on filter's failure mode
                    if failure_mode == FailureMode::Closed && blocking_error.is_none() {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent_id,
                            reason = %reason,
                            "Agent failure in fail-closed mode"
                        );
                        // Store blocking error but continue processing other results
                        // in case another agent returned a more specific block
                        let status = if reason.contains("Timeout") { 504 } else { 503 };
                        let message = if reason.contains("Timeout") {
                            "Gateway timeout"
                        } else {
                            "Service unavailable"
                        };
                        blocking_error = Some(AgentDecision::block(status, message));
                    } else {
                        // Fail-open: log and continue
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent_id,
                            reason = %reason,
                            "Agent failure in fail-open mode, continuing"
                        );
                    }
                }
            }
        }

        // If we have a fail-closed error and no explicit block, return the error
        if let Some(error_decision) = blocking_error {
            return Ok(error_decision);
        }

        trace!(
            correlation_id = %ctx.correlation_id,
            decision = ?combined_decision,
            agents_processed = agent_info.len(),
            "Parallel agent event processing completed"
        );

        Ok(combined_decision)
    }

    /// Call a named agent with a guardrail inspect event.
    ///
    /// Looks up the agent by name, checks circuit breaker and timeout,
    /// then sends the event and returns the response.
    pub async fn call_guardrail_agent(
        &self,
        agent_name: &str,
        event: GuardrailInspectEvent,
    ) -> SentinelResult<AgentResponse> {
        let agents = self.agents.read().await;
        let agent = agents.get(agent_name).ok_or_else(|| SentinelError::Agent {
            agent: agent_name.to_string(),
            message: format!("Agent '{}' not found", agent_name),
            event: "guardrail_inspect".to_string(),
            source: None,
        })?;

        let agent = Arc::clone(agent);
        drop(agents); // Release lock before calling

        // Acquire per-agent semaphore permit
        let semaphores = self.agent_semaphores.read().await;
        let semaphore = semaphores.get(agent_name).cloned();
        drop(semaphores);

        let _permit = if let Some(sem) = semaphore {
            Some(
                sem.acquire_owned()
                    .await
                    .map_err(|_| SentinelError::Agent {
                        agent: agent_name.to_string(),
                        message: "Failed to acquire agent call permit".to_string(),
                        event: "guardrail_inspect".to_string(),
                        source: None,
                    })?,
            )
        } else {
            None
        };

        // Check circuit breaker
        if !agent.circuit_breaker().is_closed() {
            return Err(SentinelError::Agent {
                agent: agent_name.to_string(),
                message: "Circuit breaker open".to_string(),
                event: "guardrail_inspect".to_string(),
                source: None,
            });
        }

        let start = Instant::now();
        let timeout_duration = Duration::from_millis(agent.timeout_ms());

        match timeout(timeout_duration, agent.call_guardrail_inspect(&event)).await {
            Ok(Ok(response)) => {
                agent.record_success(start.elapsed()).await;
                Ok(response)
            }
            Ok(Err(e)) => {
                agent.record_failure().await;
                Err(e)
            }
            Err(_) => {
                agent.record_timeout().await;
                Err(SentinelError::Agent {
                    agent: agent_name.to_string(),
                    message: format!(
                        "Guardrail agent call timed out after {}ms",
                        timeout_duration.as_millis()
                    ),
                    event: "guardrail_inspect".to_string(),
                    source: None,
                })
            }
        }
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

    /// Get pool metrics collectors from all v2 agents.
    ///
    /// Returns a vector of (agent_id, MetricsCollector) pairs for all v2 agents.
    /// These can be registered with the MetricsManager to include agent pool
    /// metrics in the /metrics endpoint output.
    pub async fn get_v2_pool_metrics(&self) -> Vec<(String, Arc<MetricsCollector>)> {
        let agents = self.agents.read().await;
        agents
            .iter()
            .filter_map(|(id, agent)| {
                if let UnifiedAgent::V2(v2_agent) = agent.as_ref() {
                    Some((id.clone(), v2_agent.pool_metrics_collector_arc()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Export prometheus metrics from all v2 agent pools.
    ///
    /// Returns the combined prometheus-formatted metrics from all v2 agent pools.
    pub async fn export_v2_pool_metrics(&self) -> String {
        let agents = self.agents.read().await;
        let mut output = String::new();

        for (id, agent) in agents.iter() {
            if let UnifiedAgent::V2(v2_agent) = agent.as_ref() {
                let pool_metrics = v2_agent.export_prometheus();
                if !pool_metrics.is_empty() {
                    output.push_str(&format!("\n# Agent pool metrics: {}\n", id));
                    output.push_str(&pool_metrics);
                }
            }
        }

        output
    }

    /// Get a v2 agent's metrics collector by ID.
    ///
    /// Returns None if the agent doesn't exist or is not a v2 agent.
    pub async fn get_v2_metrics_collector(&self, agent_id: &str) -> Option<Arc<MetricsCollector>> {
        let agents = self.agents.read().await;
        if let Some(agent) = agents.get(agent_id) {
            if let UnifiedAgent::V2(v2_agent) = agent.as_ref() {
                Some(v2_agent.pool_metrics_collector_arc())
            } else {
                None
            }
        } else {
            None
        }
    }
}
