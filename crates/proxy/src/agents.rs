//! Agent integration module for Sentinel proxy
//!
//! This module provides integration with external processing agents for WAF,
//! auth, rate limiting, and custom logic. It implements the SPOE-inspired
//! protocol with bounded behavior and failure isolation.

#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::STANDARD};
use sentinel_agent_protocol::{
    AgentClient, AgentResponse, Decision, EventType, HeaderOp,
    RequestHeadersEvent, RequestBodyChunkEvent, ResponseHeadersEvent, RequestMetadata, AuditMetadata,
};
use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    types::{CorrelationId, CircuitBreakerConfig},
    CircuitBreaker,
};
use sentinel_config::{AgentConfig, AgentEvent, AgentTransport, FailureMode};

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
// Note: AtomicU32 still used by AgentMetrics, AgentConnectionPool, Agent
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, warn};

/// Agent manager handling all external agents
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
    max_concurrent_calls: usize,
    /// Global semaphore for agent calls
    call_semaphore: Arc<Semaphore>,
}

/// Individual agent configuration and state
pub struct Agent {
    /// Agent configuration
    config: AgentConfig,
    /// Agent client
    client: Arc<RwLock<Option<AgentClient>>>,
    /// Connection pool
    pool: Arc<AgentConnectionPool>,
    /// Circuit breaker
    circuit_breaker: Arc<CircuitBreaker>,
    /// Agent-specific metrics
    metrics: Arc<AgentMetrics>,
    /// Last successful call
    last_success: Arc<RwLock<Option<Instant>>>,
    /// Consecutive failures
    consecutive_failures: AtomicU32,
}

/// Agent connection pool for efficient connection reuse
pub struct AgentConnectionPool {
    /// Pool configuration
    max_connections: usize,
    min_idle: usize,
    max_idle: usize,
    idle_timeout: Duration,
    /// Available connections
    connections: Arc<RwLock<Vec<AgentConnection>>>,
    /// Active connections count
    active_count: AtomicU32,
    /// Total connections created
    total_created: AtomicU64,
}

/// Pooled agent connection
struct AgentConnection {
    /// The actual client
    client: AgentClient,
    /// Creation time
    created_at: Instant,
    /// Last used time
    last_used: Instant,
    /// Is healthy
    healthy: bool,
}

// CircuitBreaker is imported from sentinel_common

/// Agent metrics collector
#[derive(Default)]
pub struct AgentMetrics {
    /// Total calls
    pub calls_total: AtomicU64,
    /// Successful calls
    pub calls_success: AtomicU64,
    /// Failed calls
    pub calls_failed: AtomicU64,
    /// Timeout calls
    pub calls_timeout: AtomicU64,
    /// Circuit breaker trips
    pub circuit_breaker_trips: AtomicU64,
    /// Total call duration (microseconds)
    pub duration_total_us: AtomicU64,
    /// Decisions by type
    pub decisions_allow: AtomicU64,
    pub decisions_block: AtomicU64,
    pub decisions_redirect: AtomicU64,
    pub decisions_challenge: AtomicU64,
}

/// Agent call context
pub struct AgentCallContext {
    /// Correlation ID
    pub correlation_id: CorrelationId,
    /// Request metadata
    pub metadata: RequestMetadata,
    /// Route ID
    pub route_id: Option<String>,
    /// Upstream ID
    pub upstream_id: Option<String>,
    /// Request body buffer (if body inspection enabled)
    pub request_body: Option<Vec<u8>>,
    /// Response body buffer (if body inspection enabled)
    pub response_body: Option<Vec<u8>>,
}

impl AgentManager {
    /// Create new agent manager
    pub async fn new(agents: Vec<AgentConfig>, max_concurrent_calls: usize) -> SentinelResult<Self> {
        let mut agent_map = HashMap::new();
        let mut pools = HashMap::new();
        let mut breakers = HashMap::new();

        for config in agents {
            let pool = Arc::new(AgentConnectionPool::new(
                10,  // max connections
                2,   // min idle
                5,   // max idle
                Duration::from_secs(60),
            ));

            let circuit_breaker = Arc::new(CircuitBreaker::new(
                config.circuit_breaker.clone()
                    .unwrap_or_else(|| CircuitBreakerConfig::default()),
            ));

            let agent = Arc::new(Agent {
                config: config.clone(),
                client: Arc::new(RwLock::new(None)),
                pool: Arc::clone(&pool),
                circuit_breaker: Arc::clone(&circuit_breaker),
                metrics: Arc::new(AgentMetrics::default()),
                last_success: Arc::new(RwLock::new(None)),
                consecutive_failures: AtomicU32::new(0),
            });

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

    /// Process request headers through agents
    pub async fn process_request_headers(
        &self,
        ctx: &AgentCallContext,
        headers: &HashMap<String, Vec<String>>,
        route_agents: &[String],
    ) -> SentinelResult<AgentDecision> {
        let event = RequestHeadersEvent {
            metadata: ctx.metadata.clone(),
            method: headers.get(":method")
                .and_then(|v| v.first())
                .unwrap_or(&"GET".to_string())
                .clone(),
            uri: headers.get(":path")
                .and_then(|v| v.first())
                .unwrap_or(&"/".to_string())
                .clone(),
            headers: headers.clone(),
        };

        self.process_event(
            EventType::RequestHeaders,
            &event,
            route_agents,
            ctx,
        ).await
    }

    /// Process request body chunk through agents
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

        self.process_event(
            EventType::RequestBodyChunk,
            &event,
            route_agents,
            ctx,
        ).await
    }

    /// Process response headers through agents
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

        self.process_event(
            EventType::ResponseHeaders,
            &event,
            route_agents,
            ctx,
        ).await
    }

    /// Process an event through relevant agents
    async fn process_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
        route_agents: &[String],
        ctx: &AgentCallContext,
    ) -> SentinelResult<AgentDecision> {
        // Get relevant agents for this route and event type
        let agents = self.agents.read().await;
        let relevant_agents: Vec<_> = route_agents.iter()
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
            let _permit = self.call_semaphore.acquire().await
                .map_err(|_| SentinelError::Internal {
                    message: "Failed to acquire agent call permit".to_string(),
                    correlation_id: Some(ctx.correlation_id.to_string()),
                    source: None,
                })?;

            // Check circuit breaker
            if !agent.circuit_breaker.is_closed().await {
                warn!(
                    agent_id = %agent.config.id,
                    correlation_id = %ctx.correlation_id,
                    "Circuit breaker open, skipping agent"
                );

                // Handle based on failure mode
                if agent.config.failure_mode == FailureMode::Closed {
                    return Ok(AgentDecision::block(503, "Service unavailable"));
                }
                continue;
            }

            // Call agent with timeout
            let start = Instant::now();
            let timeout = Duration::from_millis(agent.config.timeout_ms);

            match tokio::time::timeout(
                timeout,
                agent.call_event(event_type, event),
            ).await {
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
                        agent_id = %agent.config.id,
                        correlation_id = %ctx.correlation_id,
                        error = %e,
                        "Agent call failed"
                    );

                    if agent.config.failure_mode == FailureMode::Closed {
                        return Err(e);
                    }
                }
                Err(_) => {
                    agent.record_timeout().await;
                    warn!(
                        agent_id = %agent.config.id,
                        correlation_id = %ctx.correlation_id,
                        timeout_ms = agent.config.timeout_ms,
                        "Agent call timed out"
                    );

                    if agent.config.failure_mode == FailureMode::Closed {
                        return Ok(AgentDecision::block(504, "Gateway timeout"));
                    }
                }
            }
        }

        Ok(combined_decision)
    }

    /// Initialize agent connections
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

    /// Shutdown all agents
    pub async fn shutdown(&self) {
        info!("Shutting down agent manager");

        let agents = self.agents.read().await;
        for (id, agent) in agents.iter() {
            debug!("Shutting down agent: {}", id);
            agent.shutdown().await;
        }
    }

    /// Get agent metrics
    pub fn metrics(&self) -> &AgentMetrics {
        &self.metrics
    }
}

impl Agent {
    /// Check if agent handles a specific event type
    fn handles_event(&self, event_type: EventType) -> bool {
        self.config.events.iter().any(|e| match (e, event_type) {
            (AgentEvent::RequestHeaders, EventType::RequestHeaders) => true,
            (AgentEvent::RequestBody, EventType::RequestBodyChunk) => true,
            (AgentEvent::ResponseHeaders, EventType::ResponseHeaders) => true,
            (AgentEvent::ResponseBody, EventType::ResponseBodyChunk) => true,
            (AgentEvent::Log, EventType::RequestComplete) => true,
            _ => false,
        })
    }

    /// Initialize agent connection
    async fn initialize(&self) -> SentinelResult<()> {
        match &self.config.transport {
            AgentTransport::UnixSocket { path } => {
                let client = AgentClient::unix_socket(
                    &self.config.id,
                    path,
                    Duration::from_millis(self.config.timeout_ms),
                ).await.map_err(|e| SentinelError::Agent {
                    agent: self.config.id.clone(),
                    message: format!("Failed to connect: {}", e),
                    event: "initialize".to_string(),
                    source: None,
                })?;

                *self.client.write().await = Some(client);
                Ok(())
            }
            _ => {
                warn!("Unsupported agent transport: {:?}", self.config.transport);
                Ok(())
            }
        }
    }

    /// Call agent with event
    async fn call_event<T: serde::Serialize>(
        &self,
        event_type: EventType,
        event: &T,
    ) -> SentinelResult<AgentResponse> {
        // Get or create connection
        let mut client_guard = self.client.write().await;

        if client_guard.is_none() {
            self.initialize().await?;
        }

        let client = client_guard.as_mut()
            .ok_or_else(|| SentinelError::Agent {
                agent: self.config.id.clone(),
                message: "No client connection".to_string(),
                event: format!("{:?}", event_type),
                source: None,
            })?;

        // Make the call
        self.metrics.calls_total.fetch_add(1, Ordering::Relaxed);

        client.send_event(event_type, event).await
            .map_err(|e| SentinelError::Agent {
                agent: self.config.id.clone(),
                message: e.to_string(),
                event: format!("{:?}", event_type),
                source: None,
            })
    }

    /// Record successful call
    async fn record_success(&self, duration: Duration) {
        self.metrics.calls_success.fetch_add(1, Ordering::Relaxed);
        self.metrics.duration_total_us.fetch_add(
            duration.as_micros() as u64,
            Ordering::Relaxed
        );
        self.consecutive_failures.store(0, Ordering::Relaxed);
        *self.last_success.write().await = Some(Instant::now());

        self.circuit_breaker.record_success().await;
    }

    /// Record failed call
    async fn record_failure(&self) {
        self.metrics.calls_failed.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);

        self.circuit_breaker.record_failure().await;
    }

    /// Record timeout
    async fn record_timeout(&self) {
        self.metrics.calls_timeout.fetch_add(1, Ordering::Relaxed);
        self.consecutive_failures.fetch_add(1, Ordering::Relaxed);

        self.circuit_breaker.record_failure().await;
    }

    /// Shutdown agent
    async fn shutdown(&self) {
        if let Some(client) = self.client.write().await.take() {
            let _ = client.close().await;
        }
    }
}

/// Agent decision combining all agent responses
#[derive(Debug, Clone)]
pub struct AgentDecision {
    /// Final decision
    pub action: AgentAction,
    /// Header modifications for request
    pub request_headers: Vec<HeaderOp>,
    /// Header modifications for response
    pub response_headers: Vec<HeaderOp>,
    /// Audit metadata from all agents
    pub audit: Vec<AuditMetadata>,
    /// Routing metadata updates
    pub routing_metadata: HashMap<String, String>,
}

/// Agent action types
#[derive(Debug, Clone)]
pub enum AgentAction {
    /// Allow request to proceed
    Allow,
    /// Block request
    Block {
        status: u16,
        body: Option<String>,
        headers: Option<HashMap<String, String>>,
    },
    /// Redirect request
    Redirect {
        url: String,
        status: u16,
    },
    /// Challenge client
    Challenge {
        challenge_type: String,
        params: HashMap<String, String>,
    },
}

impl AgentDecision {
    /// Create default allow decision
    pub fn default_allow() -> Self {
        Self {
            action: AgentAction::Allow,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
        }
    }

    /// Create block decision
    pub fn block(status: u16, message: &str) -> Self {
        Self {
            action: AgentAction::Block {
                status,
                body: Some(message.to_string()),
                headers: None,
            },
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
        }
    }

    /// Check if decision is to allow
    pub fn is_allow(&self) -> bool {
        matches!(self.action, AgentAction::Allow)
    }

    /// Merge another decision into this one
    pub fn merge(&mut self, other: AgentDecision) {
        // If other decision is not allow, use it
        if !other.is_allow() {
            self.action = other.action;
        }

        // Merge header modifications
        self.request_headers.extend(other.request_headers);
        self.response_headers.extend(other.response_headers);

        // Merge audit metadata
        self.audit.extend(other.audit);

        // Merge routing metadata
        self.routing_metadata.extend(other.routing_metadata);
    }
}

impl From<AgentResponse> for AgentDecision {
    fn from(response: AgentResponse) -> Self {
        let action = match response.decision {
            Decision::Allow => AgentAction::Allow,
            Decision::Block { status, body, headers } => {
                AgentAction::Block { status, body, headers }
            }
            Decision::Redirect { url, status } => {
                AgentAction::Redirect { url, status }
            }
            Decision::Challenge { challenge_type, params } => {
                AgentAction::Challenge { challenge_type, params }
            }
        };

        Self {
            action,
            request_headers: response.request_headers,
            response_headers: response.response_headers,
            audit: vec![response.audit],
            routing_metadata: response.routing_metadata,
        }
    }
}

// Connection pool implementation

impl AgentConnectionPool {
    fn new(max_connections: usize, min_idle: usize, max_idle: usize, idle_timeout: Duration) -> Self {
        Self {
            max_connections,
            min_idle,
            max_idle,
            idle_timeout,
            connections: Arc::new(RwLock::new(Vec::new())),
            active_count: AtomicU32::new(0),
            total_created: AtomicU64::new(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_agent_decision_merge() {
        let mut decision1 = AgentDecision::default_allow();
        decision1.request_headers.push(HeaderOp::Set {
            name: "X-Test".to_string(),
            value: "1".to_string(),
        });

        let decision2 = AgentDecision::block(403, "Forbidden");

        decision1.merge(decision2);
        assert!(!decision1.is_allow());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout_seconds: 1,
            half_open_max_requests: 1,
        };

        let breaker = CircuitBreaker::new(config);
        assert!(breaker.is_closed().await);

        // Record failures to open
        for _ in 0..3 {
            breaker.record_failure().await;
        }
        assert!(!breaker.is_closed().await);

        // Wait for timeout
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(breaker.is_closed().await); // Should be half-open now
    }
}
