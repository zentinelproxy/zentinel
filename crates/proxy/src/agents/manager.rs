//! Agent manager for coordinating external processing agents.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::reload::ReloadHook;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures::future::join_all;
use pingora_timeout::timeout;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info, trace, warn};
use zentinel_agent_protocol::{
    v2::MetricsCollector, AgentResponse, EventType, GuardrailInspectEvent, RequestBodyChunkEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketFrameEvent,
};
use zentinel_common::{
    errors::{ZentinelError, ZentinelResult},
    types::CircuitBreakerConfig,
    CircuitBreaker,
};
use zentinel_config::{AgentConfig, BodyStreamingMode, Config, FailureMode};

use super::agent_v2::AgentV2;
use super::context::AgentCallContext;
use super::decision::AgentDecision;
use super::metrics::AgentMetrics;

/// Loads the agents of a configuration before it becomes current.
///
/// Register it on the [`ConfigManager`](crate::reload::ConfigManager): its
/// `pre_reload` hook runs ahead of the swap. Requests read `current()` to find
/// the agent a filter names, and the config manager announces a reload only
/// after it has stored the new config, so loading the agents from the reload
/// handler alone leaves a window in which `current()` names agents that are not
/// loaded yet (a fail-closed filter answers 503 meanwhile). Removing agents,
/// and loading those of a rollback, stay with the reload handler.
pub struct AgentReloadHook {
    manager: Arc<AgentManager>,
}

impl AgentReloadHook {
    pub fn new(manager: Arc<AgentManager>) -> Self {
        Self { manager }
    }
}

#[async_trait::async_trait]
impl ReloadHook for AgentReloadHook {
    async fn pre_reload(&self, _old: &Config, new: &Config) -> ZentinelResult<()> {
        let changes = self.manager.reconcile(&new.agents).await;
        info!(
            added = changes.added,
            replaced = changes.replaced,
            unchanged = changes.unchanged,
            "Agents loaded for the new configuration"
        );
        Ok(())
    }

    async fn post_reload(&self, _old: &Config, _new: &Config) {}

    async fn on_failure(&self, _config: &Config, _error: &ZentinelError) {}

    fn name(&self) -> &str {
        "agents"
    }
}

/// Agent manager handling all external agents.
///
/// All agents use the v2 protocol with bidirectional streaming, capabilities,
/// health reporting, metrics export, and flow control.
pub struct AgentManager {
    /// Configured agents
    agents: Arc<RwLock<HashMap<String, Arc<AgentV2>>>>,
    /// Circuit breakers per agent
    circuit_breakers: Arc<RwLock<HashMap<String, Arc<CircuitBreaker>>>>,
    /// Global agent metrics
    metrics: Arc<AgentMetrics>,
    /// Per-agent semaphores for queue isolation (prevents noisy neighbor problem)
    agent_semaphores: Arc<RwLock<HashMap<String, Arc<Semaphore>>>>,
}

/// What [`AgentManager::reconcile`] did, for the reload log line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AgentReconcile {
    /// Agents in the new config that were not loaded.
    pub added: usize,
    /// Agents whose config changed, rebuilt with a new connection pool.
    pub replaced: usize,
    /// Agents whose config is the same, kept with their connections.
    pub unchanged: usize,
}

/// Two agent configs are the same when they serialize to the same value.
/// `AgentConfig` holds types without `PartialEq`, and a config that fails to
/// serialize is never "the same": the agent is rebuilt.
///
/// This includes the `config { }` block, which is delivered on every new
/// connection (#603): changing it rebuilds the agent, so its new connections
/// get the new block. It compares the settings, including file paths, not the
/// contents of the files they name.
fn same_agent_config(a: &AgentConfig, b: &AgentConfig) -> bool {
    match (serde_json::to_value(a), serde_json::to_value(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The proxy-side circuit breaker for one agent.
///
/// Named `agent:<id>` so "Circuit breaker opened" says which agent; it was
/// unnamed and indistinguishable from upstream breakers in the log.
fn agent_circuit_breaker(config: &AgentConfig) -> CircuitBreaker {
    CircuitBreaker::with_name(
        config.circuit_breaker.unwrap_or_default(),
        format!("agent:{}", config.id),
    )
}

/// An agent as one route's filter chain calls it.
#[derive(Debug, Clone)]
pub struct FilterAgent {
    /// The agent's id.
    pub id: String,
    /// What a failed call means: the filter's failure mode, else the route's.
    ///
    /// This decides on every event path -- request headers and body,
    /// response headers and body, body-size limits -- for an agent that is
    /// not loaded, unreachable, behind an open circuit breaker or too slow.
    /// The agent's own `failure-mode` does not: it is one agent's default,
    /// and a route's filter is the policy for that route (#584).
    pub failure_mode: FailureMode,
    /// The filter's `timeout-ms`, if it set one.
    pub timeout_ms: Option<u64>,
}

impl FilterAgent {
    /// How long this filter waits for its agent, given the agent's own
    /// `timeout-ms`.
    ///
    /// The shorter of the two. The agent's timeout is also its connection
    /// pool's request timeout, so a filter asking to wait longer would be cut
    /// off there anyway; a filter asking for less is a route tightening its
    /// latency budget for this agent, which is what it was written for.
    pub fn effective_timeout_ms(&self, agent_timeout_ms: u64) -> u64 {
        self.timeout_ms
            .map_or(agent_timeout_ms, |t| t.min(agent_timeout_ms))
    }
}

/// An agent that may receive a request body on this route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyAgent {
    /// The agent's id.
    pub id: String,
    /// The agent filter's `max-body-bytes`, if it set one.
    pub max_body_bytes: Option<usize>,
    /// The filter's failure mode, else the route's; see
    /// [`FilterAgent::failure_mode`].
    pub failure_mode: FailureMode,
    /// The filter's `timeout-ms`, if it set one; see
    /// [`FilterAgent::effective_timeout_ms`].
    pub timeout_ms: Option<u64>,
}

impl From<&FilterAgent> for BodyAgent {
    /// The agent of a filter, without a body limit of its own.
    fn from(filter: &FilterAgent) -> Self {
        Self {
            id: filter.id.clone(),
            max_body_bytes: None,
            failure_mode: filter.failure_mode,
            timeout_ms: filter.timeout_ms,
        }
    }
}

impl BodyAgent {
    /// The largest body this filter sends its agent, given the agent's own
    /// limit: the smaller of the two. A filter narrows its agent's limit for
    /// its routes; it cannot raise it.
    pub fn effective_limit(&self, agent_limit: usize) -> usize {
        self.max_body_bytes
            .map_or(agent_limit, |l| l.min(agent_limit))
    }
}

/// How an event path names an agent of a route's filter chain.
trait AgentRef {
    fn agent_id(&self) -> &str;
}

impl AgentRef for FilterAgent {
    fn agent_id(&self) -> &str {
        &self.id
    }
}

impl AgentRef for BodyAgent {
    fn agent_id(&self) -> &str {
        &self.id
    }
}

impl AgentRef for &str {
    fn agent_id(&self) -> &str {
        self
    }
}

/// What one filter's agent id resolved to; see
/// [`AgentManager::resolve_agents`].
enum Resolved<'f, F> {
    /// The agent is loaded. The `Arc` keeps it alive for the call even if a
    /// reload retires it meanwhile, so the call finishes on it.
    Loaded(&'f F, Arc<AgentV2>),
    /// No agent with this id is loaded. Every event path treats this as a
    /// failed call (#571).
    NotLoaded(&'f F),
}

impl AgentManager {
    /// Resolve a filter chain's agent ids to loaded agents. Every lookup of
    /// an agent by id goes through here.
    ///
    /// A loaded agent that does not subscribe to `event_type` is left out
    /// (`None`: no event filter). An id with no loaded agent is never left
    /// out: its agent's subscriptions are unknown, and a filter naming it was
    /// configured to inspect this request. Event paths must answer
    /// [`Resolved::NotLoaded`] as a failed call -- see
    /// [`report_not_loaded`](Self::report_not_loaded) -- so a new event path
    /// cannot skip an unknown agent without a sound.
    ///
    /// The map's lock is held only for the lookup; calls run on the cloned
    /// `Arc`s, so a reload can retire an agent without waiting for them.
    async fn resolve_agents<'f, F: AgentRef>(
        &self,
        filters: &'f [F],
        event_type: Option<EventType>,
    ) -> Vec<Resolved<'f, F>> {
        let agents = self.agents.read().await;
        filters
            .iter()
            .filter_map(|filter| match agents.get(filter.agent_id()) {
                Some(agent) => match event_type {
                    Some(event) if !agent.handles_event(event) => None,
                    _ => Some(Resolved::Loaded(filter, Arc::clone(agent))),
                },
                None => Some(Resolved::NotLoaded(filter)),
            })
            .collect()
    }

    /// Log and count a call to an agent that is not loaded. The caller then
    /// answers it like any failed call of its event path.
    fn report_not_loaded(
        &self,
        correlation_id: &str,
        event_type: EventType,
        agent_id: &str,
        failure_mode: Option<FailureMode>,
    ) {
        self.metrics.record_failure();
        error!(
            correlation_id = %correlation_id,
            agent_id = %agent_id,
            event_type = ?event_type,
            failure_mode = ?failure_mode,
            "Filter references an agent that is not loaded"
        );
    }

    /// Take an agent out of service: no new call reaches it, and it is
    /// retired -- calls already in flight finish on it, and its pool closes
    /// when the last of them does, or at its retirement ceiling (#570).
    ///
    /// Returns whether an agent with this id was loaded.
    pub async fn remove(&self, agent_id: &str) -> bool {
        // Lock order: agents, then semaphores.
        let removed = self.agents.write().await.remove(agent_id);
        self.agent_semaphores.write().await.remove(agent_id);
        match removed {
            Some(agent) => {
                agent.retire();
                true
            }
            None => false,
        }
    }

    /// Create new agent manager.
    ///
    /// Each agent gets its own semaphore for queue isolation, preventing a slow
    /// agent from affecting other agents (noisy neighbor problem). The concurrency
    /// limit is configured per-agent via `max_concurrent_calls` in the agent config.
    pub async fn new(agents: Vec<AgentConfig>) -> ZentinelResult<Self> {
        info!(agent_count = agents.len(), "Creating agent manager");

        let mut agent_map = HashMap::new();
        let breakers = HashMap::new();
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

            // Create per-agent semaphore for queue isolation
            let semaphore = Arc::new(Semaphore::new(config.max_concurrent_calls));

            let circuit_breaker = Arc::new(agent_circuit_breaker(&config));

            trace!(
                agent_id = %config.id,
                max_concurrent_calls = config.max_concurrent_calls,
                pool_config = ?config.pool,
                "Creating agent instance with internal pool"
            );

            let agent = Arc::new(AgentV2::new(config.clone(), circuit_breaker));

            agent_map.insert(config.id.clone(), agent);
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
            circuit_breakers: Arc::new(RwLock::new(breakers)),
            metrics: Arc::new(AgentMetrics::default()),
            agent_semaphores: Arc::new(RwLock::new(semaphores)),
        })
    }

    /// Load the agents of a reloaded config that are not loaded yet, and
    /// rebuild the ones whose config changed.
    ///
    /// The manager was built once at startup and never again. A reload that
    /// added an agent, or renamed one (a route's filter then names an agent
    /// the manager does not have), left the new filters naming an agent that
    /// is not loaded, which is a failed call (#571). The log said the reload
    /// succeeded.
    ///
    /// An agent whose config is unchanged is kept, with its connections and
    /// circuit breaker: reloading an unrelated part of the config must not
    /// drop a working agent. A replaced agent is retired, so the calls in
    /// flight on it finish (#570).
    ///
    /// Changed and added agents connect together, bounded as at startup
    /// (#599): the reload waits for them at most the longest
    /// [`AgentV2::startup_wait`]. One that has not connected by then is loaded
    /// anyway, its connection attempt carries on in the background, and its
    /// filters follow their failure mode until it does. Nothing is locked
    /// while it connects.
    ///
    /// Agents missing from `agents` stay loaded: the routes of the previous
    /// config may still be serving, and they call those agents. Drop them
    /// with [`Self::remove_unlisted`] once the new routes are live.
    pub async fn reconcile(&self, agents: &[AgentConfig]) -> AgentReconcile {
        let mut changes = AgentReconcile::default();

        // Decide under the read lock; build and connect outside any lock.
        let mut build: Vec<&AgentConfig> = Vec::new();
        {
            let loaded = self.agents.read().await;
            for config in agents {
                match loaded.get(&config.id) {
                    Some(old) if same_agent_config(old.config(), config) => changes.unchanged += 1,
                    Some(_) => {
                        changes.replaced += 1;
                        build.push(config);
                    }
                    None => {
                        changes.added += 1;
                        build.push(config);
                    }
                }
            }
        }
        if build.is_empty() {
            return changes;
        }

        let built: Vec<(Arc<AgentV2>, Arc<Semaphore>)> = build
            .into_iter()
            .map(|config| {
                let circuit_breaker = Arc::new(agent_circuit_breaker(config));
                (
                    Arc::new(AgentV2::new(config.clone(), circuit_breaker)),
                    Arc::new(Semaphore::new(config.max_concurrent_calls)),
                )
            })
            .collect();

        let wait = built
            .iter()
            .map(|(agent, _)| agent.startup_wait())
            .max()
            .unwrap_or_default();
        let connecting: Vec<_> = built
            .iter()
            .map(|(agent, _)| {
                let agent = Arc::clone(agent);
                tokio::spawn(async move {
                    if let Err(e) = agent.initialize().await {
                        error!(
                            agent_id = %agent.id(),
                            error = %e,
                            "Failed to initialize agent after reload"
                        );
                    }
                })
            })
            .collect();
        // The tasks outlive the wait: dropping a join handle detaches it.
        match timeout(wait, join_all(connecting)).await {
            Ok(results) => {
                for e in results.into_iter().filter_map(Result::err) {
                    error!(error = %e, "Agent initialization task failed");
                }
            }
            Err(_) => warn!(
                waited_ms = wait.as_millis(),
                "Not waiting any longer for reloaded agents to connect; their filters \
                 follow their failure mode until they do"
            ),
        }

        let mut replaced_agents = Vec::new();
        {
            // Lock order: agents, then semaphores.
            let mut loaded = self.agents.write().await;
            let mut semaphores = self.agent_semaphores.write().await;
            for (agent, semaphore) in built {
                // A replaced agent gets a fresh semaphore while calls in
                // flight hold permits on the old one, so for a short time up
                // to twice `max_concurrent_calls` may run.
                let id = agent.id().to_string();
                semaphores.insert(id.clone(), semaphore);
                if let Some(old) = loaded.insert(id, agent) {
                    replaced_agents.push(old);
                }
            }
        }
        for old in replaced_agents {
            old.retire();
        }

        changes
    }

    /// Whether an agent with this id is loaded.
    pub async fn is_loaded(&self, id: &str) -> bool {
        self.agents.read().await.contains_key(id)
    }

    /// Take out of service the agents that `agents`, the config now in
    /// force, no longer lists. Returns how many.
    pub async fn remove_unlisted(&self, agents: &[AgentConfig]) -> usize {
        let gone: Vec<String> = self
            .agents
            .read()
            .await
            .keys()
            .filter(|id| !agents.iter().any(|a| &a.id == *id))
            .cloned()
            .collect();
        let mut removed = 0;
        for id in &gone {
            if self.remove(id).await {
                removed += 1;
            }
        }
        removed
    }

    /// Check if any of the given route agents handle a specific event type.
    pub async fn any_agent_handles_event(
        &self,
        route_agents: &[FilterAgent],
        event_type: EventType,
    ) -> bool {
        // An agent that is not loaded is not counted: whether it subscribes
        // is unknown, and its failure is answered by the event's dispatch.
        self.resolve_agents(route_agents, Some(event_type))
            .await
            .iter()
            .any(|resolved| matches!(resolved, Resolved::Loaded(..)))
    }

    /// Whether any of a route's body agents subscribes to the request body
    /// (`events "request_body"`); the request-side counterpart of
    /// [`Self::any_agent_handles_event`]. An agent that is not loaded counts:
    /// whether it subscribes is unknown, and the body path answers its
    /// failure by its filter's failure mode, as it always has.
    pub async fn any_body_agent_handles_request_body(&self, body_agents: &[BodyAgent]) -> bool {
        !self
            .resolve_agents(body_agents, Some(EventType::RequestBodyChunk))
            .await
            .is_empty()
    }

    /// The largest response body any of the route's agents inspects: their
    /// `max-response-body-bytes`. A response body is buffered for them up
    /// to this size; one larger is over every agent's limit, and answered by
    /// the body-limit rule without being buffered any further.
    pub async fn response_body_limit(&self, route_agents: &[FilterAgent]) -> usize {
        self.resolve_agents(route_agents, Some(EventType::ResponseBodyChunk))
            .await
            .iter()
            .filter_map(|resolved| match resolved {
                Resolved::Loaded(_, agent) => Some(agent.max_response_body_bytes()),
                // Answered by the dispatch, without a body to inspect.
                Resolved::NotLoaded(_) => None,
            })
            .max()
            .unwrap_or(0)
    }

    /// How the request body is sent to the route's body agents: their
    /// `request-body-mode`s, combined by `most_conservative_body_mode`.
    /// Agents that are not loaded have no say (their call fails on
    /// dispatch, by their filter's failure mode).
    pub async fn request_body_mode(&self, body_agents: &[BodyAgent]) -> BodyStreamingMode {
        let modes: Vec<BodyStreamingMode> = self
            .resolve_agents(body_agents, Some(EventType::RequestBodyChunk))
            .await
            .iter()
            .filter_map(|resolved| match resolved {
                Resolved::Loaded(_, agent) => Some(agent.request_body_mode()),
                Resolved::NotLoaded(_) => None,
            })
            .collect();
        most_conservative_body_mode(&modes)
    }

    /// Process request headers through agents.
    ///
    /// # Arguments
    /// * `ctx` - Agent call context with correlation ID and metadata
    /// * `headers` - Request headers to send to agents
    /// * `route_agents` - The agents of the route's filter chain, each with
    ///   its filter's failure mode and timeout
    pub async fn process_request_headers(
        &self,
        ctx: &AgentCallContext,
        mut headers: HashMap<String, Vec<String>>,
        route_agents: &[FilterAgent],
    ) -> ZentinelResult<AgentDecision> {
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
        route_agents: &[BodyAgent],
    ) -> ZentinelResult<AgentDecision> {
        // Enforce per-agent body inspection limits before dispatch
        let inspecting_agents = match self
            .apply_body_limits(ctx, route_agents, data.len(), EventType::RequestBodyChunk)
            .await
        {
            BodyLimitsResult::Block(decision) => return Ok(*decision),
            BodyLimitsResult::Proceed(agents) => agents,
        };

        let event = RequestBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size: ctx.request_body.as_ref().map(|b| b.len()),
            chunk_index: 0, // Buffer mode sends entire body as single chunk
            bytes_received: data.len(),
        };

        self.process_event(EventType::RequestBodyChunk, &event, &inspecting_agents, ctx)
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
        route_agents: &[BodyAgent],
    ) -> ZentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            chunk_index = chunk_index,
            chunk_size = data.len(),
            bytes_received = bytes_received,
            is_last = is_last,
            "Processing streaming request body chunk"
        );

        // Enforce per-agent body inspection limits on the cumulative size
        let inspecting_agents = match self
            .apply_body_limits(
                ctx,
                route_agents,
                bytes_received,
                EventType::RequestBodyChunk,
            )
            .await
        {
            BodyLimitsResult::Block(decision) => return Ok(*decision),
            BodyLimitsResult::Proceed(agents) => agents,
        };

        let event = RequestBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size,
            chunk_index,
            bytes_received,
        };

        self.process_event(EventType::RequestBodyChunk, &event, &inspecting_agents, ctx)
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
        route_agents: &[FilterAgent],
    ) -> ZentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            chunk_index = chunk_index,
            chunk_size = data.len(),
            bytes_sent = bytes_sent,
            is_last = is_last,
            "Processing streaming response body chunk"
        );

        // Enforce per-agent body inspection limits on the cumulative size.
        // Agent filters' body settings concern request bodies only.
        let route_agents: Vec<BodyAgent> = route_agents.iter().map(BodyAgent::from).collect();
        let inspecting_agents = match self
            .apply_body_limits(ctx, &route_agents, bytes_sent, EventType::ResponseBodyChunk)
            .await
        {
            BodyLimitsResult::Block(decision) => return Ok(*decision),
            BodyLimitsResult::Proceed(agents) => agents,
        };

        let event = ResponseBodyChunkEvent {
            correlation_id: ctx.correlation_id.to_string(),
            data: STANDARD.encode(data),
            is_last,
            total_size,
            chunk_index,
            bytes_sent,
        };

        self.process_event(
            EventType::ResponseBodyChunk,
            &event,
            &inspecting_agents,
            ctx,
        )
        .await
    }

    /// Process response headers through agents.
    pub async fn process_response_headers(
        &self,
        ctx: &AgentCallContext,
        status: u16,
        headers: &HashMap<String, Vec<String>>,
        route_agents: &[FilterAgent],
    ) -> ZentinelResult<AgentDecision> {
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
    ) -> ZentinelResult<AgentResponse> {
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
                    agent.record_success(duration);

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
                            zentinel_agent_protocol::WebSocketDecision::Allow
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
                    agent.record_failure();
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
                    agent.record_timeout();
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
        route_agents: &[FilterAgent],
        ctx: &AgentCallContext,
    ) -> ZentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            route_agents = ?route_agents.iter().map(|a| &a.id).collect::<Vec<_>>(),
            "Starting agent event processing"
        );

        // Get relevant agents for this route and event type
        let relevant_agents = self.resolve_agents(route_agents, Some(event_type)).await;

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
            agent_ids = ?route_agents.iter().map(|a| &a.id).collect::<Vec<_>>(),
            "Processing event through agents"
        );

        // Process through each agent sequentially
        let mut combined_decision = AgentDecision::default_allow();

        for (agent_index, resolved) in relevant_agents.iter().enumerate() {
            let (filter, agent) = match resolved {
                Resolved::Loaded(filter, agent) => (filter, agent),
                // Not loaded: a failed call that cannot be made, answered as
                // an open circuit breaker is below, by the filter's failure
                // mode.
                Resolved::NotLoaded(filter) => {
                    self.report_not_loaded(
                        ctx.correlation_id.as_str(),
                        event_type,
                        &filter.id,
                        Some(filter.failure_mode),
                    );
                    if filter.failure_mode == FailureMode::Closed {
                        return Ok(AgentDecision::block(503, "Service unavailable")
                            .with_decided_by(&filter.id));
                    }
                    continue;
                }
            };
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
                        ZentinelError::Internal {
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
                    failure_mode = ?filter.failure_mode,
                    "Circuit breaker open, skipping agent"
                );

                // Handle based on failure mode
                if filter.failure_mode == FailureMode::Closed {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        "Blocking request due to circuit breaker (fail-closed mode)"
                    );
                    return Ok(AgentDecision::block(503, "Service unavailable")
                        .with_decided_by(agent.id()));
                }
                continue;
            }

            // Call agent with timeout (using pingora-timeout for efficiency).
            // The filter's `timeout-ms` applies here as in the parallel
            // dispatch (#589).
            let start = Instant::now();
            let timeout_ms = filter.effective_timeout_ms(agent.timeout_ms());
            let timeout_duration = Duration::from_millis(timeout_ms);

            trace!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent.id(),
                timeout_ms = timeout_ms,
                "Calling agent"
            );

            match timeout(timeout_duration, agent.call_event(event_type, event)).await {
                Ok(Ok(response)) => {
                    let duration = start.elapsed();
                    agent.record_success(duration);

                    trace!(
                        correlation_id = %ctx.correlation_id,
                        agent_id = %agent.id(),
                        duration_ms = duration.as_millis(),
                        decision = ?response,
                        "Agent call succeeded"
                    );

                    // Merge response into combined decision (attributed to this agent)
                    combined_decision.merge(AgentDecision::from_response(response, agent.id()));

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
                    agent.record_failure();
                    error!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        error = %e,
                        duration_ms = start.elapsed().as_millis(),
                        failure_mode = ?filter.failure_mode,
                        "Agent call failed"
                    );

                    // Answered like the other failures here and like a failed
                    // call on request headers: a 503 decision, not an error
                    // each caller would have to map to a failure mode again.
                    if filter.failure_mode == FailureMode::Closed {
                        return Ok(AgentDecision::block(503, "Service unavailable")
                            .with_decided_by(agent.id()));
                    }
                }
                Err(_) => {
                    agent.record_timeout();
                    warn!(
                        agent_id = %agent.id(),
                        correlation_id = %ctx.correlation_id,
                        timeout_ms = timeout_ms,
                        failure_mode = ?filter.failure_mode,
                        "Agent call timed out"
                    );

                    if filter.failure_mode == FailureMode::Closed {
                        debug!(
                            correlation_id = %ctx.correlation_id,
                            agent_id = %agent.id(),
                            "Blocking request due to timeout (fail-closed mode)"
                        );
                        return Ok(AgentDecision::block(504, "Gateway timeout")
                            .with_decided_by(agent.id()));
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
        route_agents: &[FilterAgent],
        ctx: &AgentCallContext,
    ) -> ZentinelResult<AgentDecision> {
        trace!(
            correlation_id = %ctx.correlation_id,
            event_type = ?event_type,
            route_agents = ?route_agents.iter().map(|a| &a.id).collect::<Vec<_>>(),
            "Starting parallel agent event processing"
        );

        // Get relevant agents for this route and event type
        let resolved = self.resolve_agents(route_agents, Some(event_type)).await;
        let semaphores = self.agent_semaphores.read().await;

        // Collect agent info upfront to minimize lock duration
        let mut not_loaded = Vec::new();
        let agent_info: Vec<_> = resolved
            .into_iter()
            .filter_map(|resolved| match resolved {
                Resolved::Loaded(filter, agent) => {
                    let semaphore = semaphores.get(&filter.id).cloned();
                    let timeout_ms = filter.effective_timeout_ms(agent.timeout_ms());
                    Some((agent, filter.failure_mode, timeout_ms, semaphore))
                }
                Resolved::NotLoaded(filter) => {
                    not_loaded.push(filter);
                    None
                }
            })
            .collect();

        // Release locks early
        drop(semaphores);

        for filter in &not_loaded {
            self.report_not_loaded(
                ctx.correlation_id.as_str(),
                event_type,
                &filter.id,
                Some(filter.failure_mode),
            );
        }

        if agent_info.is_empty() && not_loaded.is_empty() {
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
            agent_ids = ?agent_info.iter().map(|(a, _, _, _)| a.id()).collect::<Vec<_>>(),
            "Processing event through agents in parallel"
        );

        // Spawn all agent calls concurrently
        let futures: Vec<_> = agent_info
            .iter()
            .map(|(agent, filter_failure_mode, timeout_ms, semaphore)| {
                let agent = Arc::clone(agent);
                let filter_failure_mode = *filter_failure_mode;
                let timeout_ms = *timeout_ms;
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
                    let timeout_duration = Duration::from_millis(timeout_ms);

                    match timeout(timeout_duration, agent.call_event(event_type, event)).await {
                        Ok(Ok(response)) => {
                            let duration = start.elapsed();
                            agent.record_success(duration);
                            trace!(
                                correlation_id = %correlation_id,
                                agent_id = %agent.id(),
                                duration_ms = duration.as_millis(),
                                "Parallel agent call succeeded"
                            );
                            Ok((agent.id().to_string(), response))
                        }
                        Ok(Err(e)) => {
                            agent.record_failure();
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
                            agent.record_timeout();
                            warn!(
                                agent_id = %agent.id(),
                                correlation_id = %correlation_id,
                                timeout_ms = timeout_ms,
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
        let mut results = join_all(futures).await;

        // An agent that is not loaded is a call that failed: answered below
        // exactly as one whose agent could not be reached.
        results.extend(not_loaded.iter().map(|filter| {
            Err((
                filter.id.clone(),
                filter.failure_mode,
                "Agent not loaded".to_string(),
            ))
        }));

        // Process results and merge decisions
        let mut combined_decision = AgentDecision::default_allow();
        let mut blocking_error: Option<AgentDecision> = None;

        for result in results {
            match result {
                Ok((agent_id, response)) => {
                    let decision = AgentDecision::from_response(response, &agent_id);

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
                        blocking_error =
                            Some(AgentDecision::block(status, message).with_decided_by(&agent_id));
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
    ) -> ZentinelResult<AgentResponse> {
        let agent = match self
            .resolve_agents(std::slice::from_ref(&agent_name), None)
            .await
            .pop()
        {
            Some(Resolved::Loaded(_, agent)) => agent,
            // Not loaded: a failed call; the guardrail's failure mode
            // decides what it means.
            _ => {
                self.report_not_loaded(
                    &event.correlation_id,
                    EventType::GuardrailInspect,
                    agent_name,
                    None,
                );
                return Err(ZentinelError::Agent {
                    agent: agent_name.to_string(),
                    message: format!("Agent '{}' not found", agent_name),
                    event: "guardrail_inspect".to_string(),
                    source: None,
                });
            }
        };

        // Acquire per-agent semaphore permit
        let semaphores = self.agent_semaphores.read().await;
        let semaphore = semaphores.get(agent_name).cloned();
        drop(semaphores);

        let _permit = if let Some(sem) = semaphore {
            Some(
                sem.acquire_owned()
                    .await
                    .map_err(|_| ZentinelError::Agent {
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
            return Err(ZentinelError::Agent {
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
                agent.record_success(start.elapsed());
                Ok(response)
            }
            Ok(Err(e)) => {
                agent.record_failure();
                Err(e)
            }
            Err(_) => {
                agent.record_timeout();
                Err(ZentinelError::Agent {
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
    ///
    /// Every agent connects at once, and startup waits for them at most the
    /// longest [`AgentV2::startup_wait`] (connect timeout plus five seconds
    /// for the configuration). An agent that has not connected by then --
    /// one that accepts the connection and never answers, say -- does not
    /// hold the listeners closed (#599): its connection attempt carries on
    /// in the background, its filters follow their failure mode meanwhile,
    /// and its pool keeps reconnecting with backoff.
    pub async fn initialize(&self) -> ZentinelResult<()> {
        let agents: Vec<(String, Arc<AgentV2>)> = self
            .agents
            .read()
            .await
            .iter()
            .map(|(id, agent)| (id.clone(), Arc::clone(agent)))
            .collect();

        info!(agent_count = agents.len(), "Initializing agent connections");

        let wait = agents
            .iter()
            .map(|(_, agent)| agent.startup_wait())
            .max()
            .unwrap_or_default();
        let total = agents.len();
        let mut tasks = tokio::task::JoinSet::new();
        for (id, agent) in agents {
            tasks.spawn(async move {
                debug!(agent_id = %id, "Initializing agent connection");
                let result = agent.initialize().await;
                match &result {
                    Err(e) => error!(agent_id = %id, error = %e, "Failed to initialize agent"),
                    Ok(()) => trace!(agent_id = %id, "Agent initialized successfully"),
                }
                (id, result.is_ok())
            });
        }

        let mut initialized_count = 0;
        let mut failed_count = 0;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((_, true)))) => initialized_count += 1,
                Ok(Some(Ok((_, false)))) => failed_count += 1,
                Ok(Some(Err(e))) => {
                    error!(error = %e, "Agent initialization task failed");
                    failed_count += 1;
                }
                Ok(None) => break,
                Err(_) => {
                    // Still connecting: the attempts finish on their own.
                    warn!(
                        still_connecting = tasks.len(),
                        waited_ms = wait.as_millis(),
                        "Not waiting any longer for agents to connect; their filters \
                         follow their failure mode until they do"
                    );
                    tasks.detach_all();
                    break;
                }
            }
        }

        info!(
            initialized = initialized_count,
            failed = failed_count,
            still_connecting = total - initialized_count - failed_count,
            total,
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

    /// Release per-request agent state after a request completes.
    ///
    /// Clears the correlation affinity (headers → body chunk connection
    /// pinning) on every agent pool. Affinities that are never released here
    /// are reclaimed by the pool maintenance TTL sweep.
    pub async fn end_request(&self, correlation_id: &str) {
        let agents = self.agents.read().await;
        for agent in agents.values() {
            agent.clear_correlation_affinity(correlation_id);
        }
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

    /// Get pool metrics collectors from all agents.
    ///
    /// Returns a vector of (agent_id, MetricsCollector) pairs.
    /// These can be registered with the MetricsManager to include agent pool
    /// metrics in the /metrics endpoint output.
    pub async fn get_v2_pool_metrics(&self) -> Vec<(String, Arc<MetricsCollector>)> {
        let agents = self.agents.read().await;
        agents
            .iter()
            .map(|(id, agent)| (id.clone(), agent.pool_metrics_collector_arc()))
            .collect()
    }

    /// Export prometheus metrics from all agent pools.
    ///
    /// Returns the combined prometheus-formatted metrics from all agent pools.
    pub async fn export_v2_pool_metrics(&self) -> String {
        let agents = self.agents.read().await;
        let mut output = String::new();

        for (id, agent) in agents.iter() {
            let pool_metrics = agent.export_prometheus();
            if !pool_metrics.is_empty() {
                output.push_str(&format!("\n# Agent pool metrics: {}\n", id));
                output.push_str(&pool_metrics);
            }
        }

        output
    }

    /// Get an agent's metrics collector by ID.
    ///
    /// Returns None if the agent doesn't exist.
    pub async fn get_v2_metrics_collector(&self, agent_id: &str) -> Option<Arc<MetricsCollector>> {
        match self
            .resolve_agents(std::slice::from_ref(&agent_id), None)
            .await
            .pop()
        {
            Some(Resolved::Loaded(_, agent)) => Some(agent.pool_metrics_collector_arc()),
            _ => None,
        }
    }

    /// Enforce per-agent body inspection limits for a body of `body_size` bytes.
    ///
    /// An agent's limit is its own `max-request-body-bytes` (or
    /// `max-response-body-bytes`), lowered by its filter's `max-body-bytes`.
    /// Agents whose limit is exceeded are handled according to their filter's
    /// failure mode: fail-closed produces a 413 Block decision, fail-open skips that
    /// agent loudly (warn + metric) while agents within their limit still
    /// inspect the body.
    async fn apply_body_limits(
        &self,
        ctx: &AgentCallContext,
        route_agents: &[BodyAgent],
        body_size: usize,
        event_type: EventType,
    ) -> BodyLimitsResult {
        let resolved = self.resolve_agents(route_agents, Some(event_type)).await;
        let limits: Vec<(String, FailureMode, usize)> = resolved
            .iter()
            .map(|resolved| match resolved {
                Resolved::Loaded(body_agent, agent) => {
                    let limit = if event_type == EventType::ResponseBodyChunk {
                        agent.max_response_body_bytes()
                    } else {
                        agent.max_request_body_bytes()
                    };
                    (
                        agent.id().to_string(),
                        body_agent.failure_mode,
                        body_agent.effective_limit(limit),
                    )
                }
                // No limit to enforce; passed on to the dispatch, which
                // answers it as a failed call.
                Resolved::NotLoaded(body_agent) => {
                    (body_agent.id.clone(), body_agent.failure_mode, usize::MAX)
                }
            })
            .collect();

        let outcome = evaluate_body_limits(&limits, body_size);

        for (agent_id, limit) in &outcome.skipped {
            warn!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent_id,
                body_size = body_size,
                limit = limit,
                event_type = ?event_type,
                "Body exceeds agent inspection limit, skipping agent (fail-open)"
            );
            for resolved in &resolved {
                if let Resolved::Loaded(_, agent) = resolved {
                    if agent.id() == agent_id {
                        agent.metrics().record_body_size_skip();
                        break;
                    }
                }
            }
        }

        if let Some((agent_id, limit)) = outcome.blocked_by {
            warn!(
                correlation_id = %ctx.correlation_id,
                agent_id = %agent_id,
                body_size = body_size,
                limit = limit,
                event_type = ?event_type,
                "Body exceeds agent inspection limit, blocking request (fail-closed)"
            );
            return BodyLimitsResult::Block(Box::new(
                AgentDecision::block(413, "Payload too large for security inspection")
                    .with_decided_by(agent_id),
            ));
        }

        let allowed = outcome
            .allowed
            .into_iter()
            .map(|id| {
                let body_agent = route_agents.iter().find(|body_agent| body_agent.id == id);
                FilterAgent {
                    failure_mode: body_agent
                        .map_or(FailureMode::Closed, |body_agent| body_agent.failure_mode),
                    // The filter's timeout reaches the body dispatch too
                    // (#589); it was dropped here before.
                    timeout_ms: body_agent.and_then(|body_agent| body_agent.timeout_ms),
                    id,
                }
            })
            .collect();
        BodyLimitsResult::Proceed(allowed)
    }
}

/// Result of enforcing body inspection limits.
enum BodyLimitsResult {
    /// Agents (within their limits) that may inspect the body, and those
    /// that are not loaded.
    Proceed(Vec<FilterAgent>),
    /// A fail-closed agent's limit was exceeded; the request must be blocked.
    Block(Box<AgentDecision>),
}

/// Outcome of evaluating a body size against per-agent inspection limits.
#[derive(Debug)]
struct BodyLimitOutcome {
    /// Agents whose limit accommodates the body
    allowed: Vec<String>,
    /// Fail-open agents skipped because the body exceeds their limit (id, limit)
    skipped: Vec<(String, usize)>,
    /// First fail-closed agent whose limit was exceeded (id, limit)
    blocked_by: Option<(String, usize)>,
}

/// Evaluate a body size against per-agent `(id, failure_mode, limit)` entries.
fn evaluate_body_limits(
    agents: &[(String, FailureMode, usize)],
    body_size: usize,
) -> BodyLimitOutcome {
    let mut outcome = BodyLimitOutcome {
        allowed: Vec::new(),
        skipped: Vec::new(),
        blocked_by: None,
    };

    for (id, failure_mode, limit) in agents {
        if body_size <= *limit {
            outcome.allowed.push(id.clone());
        } else if *failure_mode == FailureMode::Closed {
            outcome.blocked_by = Some((id.clone(), *limit));
            break;
        } else {
            outcome.skipped.push((id.clone(), *limit));
        }
    }

    outcome
}

/// The body mode for a route whose body agents asked for `modes` (#602).
///
/// One body is sent to all of a route's agents in one way, so when they
/// disagree the mode that gives every agent at least the view it asked
/// for wins: `buffer` (the whole body, up to the inspection limit) over
/// `hybrid` (the largest threshold) over `stream`. An agent written for a
/// buffered body may decide on a fragment it was never meant to see; one
/// written for chunks still works on a single buffered chunk. No agents:
/// `buffer`, the default.
pub fn most_conservative_body_mode(modes: &[BodyStreamingMode]) -> BodyStreamingMode {
    let mut result: Option<BodyStreamingMode> = None;
    for mode in modes {
        result = Some(match (result, *mode) {
            (None, mode) => mode,
            (Some(BodyStreamingMode::Buffer), _) | (_, BodyStreamingMode::Buffer) => {
                BodyStreamingMode::Buffer
            }
            (
                Some(BodyStreamingMode::Hybrid {
                    buffer_threshold: a,
                }),
                BodyStreamingMode::Hybrid {
                    buffer_threshold: b,
                },
            ) => BodyStreamingMode::Hybrid {
                buffer_threshold: a.max(b),
            },
            (Some(hybrid @ BodyStreamingMode::Hybrid { .. }), BodyStreamingMode::Stream)
            | (Some(BodyStreamingMode::Stream), hybrid @ BodyStreamingMode::Hybrid { .. }) => {
                hybrid
            }
            (Some(BodyStreamingMode::Stream), BodyStreamingMode::Stream) => {
                BodyStreamingMode::Stream
            }
        });
    }
    result.unwrap_or(BodyStreamingMode::Buffer)
}

#[cfg(test)]
mod body_mode_tests {
    use super::most_conservative_body_mode;
    use zentinel_config::BodyStreamingMode::{self, Buffer, Hybrid, Stream};

    fn hybrid(buffer_threshold: usize) -> BodyStreamingMode {
        Hybrid { buffer_threshold }
    }

    #[test]
    fn no_agents_buffer() {
        assert_eq!(most_conservative_body_mode(&[]), Buffer);
    }

    #[test]
    fn a_single_agent_gets_its_mode() {
        assert_eq!(most_conservative_body_mode(&[Stream]), Stream);
        assert_eq!(most_conservative_body_mode(&[hybrid(8)]), hybrid(8));
        assert_eq!(most_conservative_body_mode(&[Buffer]), Buffer);
    }

    #[test]
    fn buffer_wins_over_everything() {
        assert_eq!(most_conservative_body_mode(&[Stream, Buffer]), Buffer);
        assert_eq!(most_conservative_body_mode(&[Buffer, hybrid(8)]), Buffer);
        assert_eq!(
            most_conservative_body_mode(&[Stream, hybrid(8), Buffer, Stream]),
            Buffer
        );
    }

    #[test]
    fn hybrid_wins_over_stream_with_the_largest_threshold() {
        assert_eq!(most_conservative_body_mode(&[Stream, hybrid(8)]), hybrid(8));
        assert_eq!(most_conservative_body_mode(&[hybrid(8), Stream]), hybrid(8));
        assert_eq!(
            most_conservative_body_mode(&[hybrid(8), hybrid(64), Stream]),
            hybrid(64)
        );
        assert_eq!(most_conservative_body_mode(&[Stream, Stream]), Stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn agent_from_kdl(circuit_breaker: &str) -> AgentConfig {
        let kdl = format!(
            r#"
            system {{ worker-threads 1 }}
            listeners {{ listener "l" {{ address "127.0.0.1:8080" }} }}
            upstreams {{ upstream "u" {{ target "127.0.0.1:9000" }} }}
            routes {{ route "r" {{ matches {{ path-prefix "/" }}
                                 upstream "u" }} }}
            agents {{
                agent "echo" type="custom" {{
                    unix-socket "/tmp/echo.sock"
                    events "request_headers"
                    {circuit_breaker}
                }}
            }}
            "#
        );
        let config = zentinel_config::Config::from_kdl(&kdl).expect("parses");
        config.agents.into_iter().next().expect("one agent")
    }

    /// Reported in #530: the agent breaker "opened after the first failed
    /// call". It does not. Over UDS on 26.10_3 the first failures against a
    /// dead agent were *timeouts* (logged at WARN, "timed out"), and only the
    /// fifth was an ERROR "call failed", immediately followed by "Circuit
    /// breaker opened". This replays that sequence through the same
    /// AgentV2 recording methods the manager calls.
    #[tokio::test]
    async fn default_agent_breaker_opens_on_the_fifth_consecutive_failure() {
        let config = agent_from_kdl("");
        let agent = AgentV2::new(config.clone(), Arc::new(agent_circuit_breaker(&config)));
        for _ in 0..4 {
            agent.record_timeout();
        }
        assert!(
            agent.circuit_breaker().is_closed(),
            "4 failures < threshold 5"
        );
        agent.record_failure();
        assert!(!agent.circuit_breaker().is_closed(), "5th failure opens");
    }

    #[tokio::test]
    async fn configured_agent_breaker_threshold_is_respected() {
        let config = agent_from_kdl("circuit-breaker { failure-threshold 3 }");
        let agent = AgentV2::new(config.clone(), Arc::new(agent_circuit_breaker(&config)));
        agent.record_failure();
        agent.record_failure();
        assert!(agent.circuit_breaker().is_closed());
        agent.record_failure();
        assert!(!agent.circuit_breaker().is_closed());
    }

    /// A success in between resets the count: failures must be consecutive.
    #[tokio::test]
    async fn a_success_resets_the_agent_breaker_count() {
        let config = agent_from_kdl("");
        let agent = AgentV2::new(config.clone(), Arc::new(agent_circuit_breaker(&config)));
        for _ in 0..4 {
            agent.record_failure();
        }
        agent.record_success(Duration::from_millis(1));
        for _ in 0..4 {
            agent.record_failure();
        }
        assert!(agent.circuit_breaker().is_closed());
    }

    fn limits() -> Vec<(String, FailureMode, usize)> {
        vec![
            ("waf".to_string(), FailureMode::Closed, 1024),
            ("audit".to_string(), FailureMode::Open, 512),
            ("dlp".to_string(), FailureMode::Open, 4096),
        ]
    }

    #[test]
    fn body_within_all_limits_allows_all_agents() {
        let outcome = evaluate_body_limits(&limits(), 256);
        assert_eq!(outcome.allowed, vec!["waf", "audit", "dlp"]);
        assert!(outcome.skipped.is_empty());
        assert!(outcome.blocked_by.is_none());
    }

    #[test]
    fn oversized_body_blocks_on_fail_closed_agent() {
        let outcome = evaluate_body_limits(&limits(), 2048);
        assert_eq!(
            outcome.blocked_by,
            Some(("waf".to_string(), 1024)),
            "fail-closed agent over its limit must block"
        );
    }

    #[test]
    fn oversized_body_skips_fail_open_agent_and_keeps_others() {
        let outcome = evaluate_body_limits(&limits(), 600);
        assert_eq!(outcome.allowed, vec!["waf", "dlp"]);
        assert_eq!(outcome.skipped, vec![("audit".to_string(), 512)]);
        assert!(outcome.blocked_by.is_none());
    }

    #[test]
    fn no_agents_yields_empty_outcome() {
        let outcome = evaluate_body_limits(&[], 1_000_000);
        assert!(outcome.allowed.is_empty());
        assert!(outcome.skipped.is_empty());
        assert!(outcome.blocked_by.is_none());
    }

    /// #542: a filter's `timeout-ms` shortens its agent's timeout and never
    /// extends it; without one, the agent's applies.
    #[test]
    fn a_filter_timeout_can_only_shorten_the_agents() {
        let filter = |timeout_ms| FilterAgent {
            id: "a".to_string(),
            failure_mode: FailureMode::Closed,
            timeout_ms,
        };
        assert_eq!(filter(None).effective_timeout_ms(1000), 1000);
        assert_eq!(filter(Some(100)).effective_timeout_ms(1000), 100);
        assert_eq!(filter(Some(5000)).effective_timeout_ms(1000), 1000);
    }

    /// #553: a filter's `max-body-bytes` lowers its agent's body limit and
    /// never raises it.
    #[test]
    fn a_filter_body_limit_can_only_lower_the_agents() {
        let agent = |max_body_bytes| BodyAgent {
            id: "a".to_string(),
            max_body_bytes,
            failure_mode: FailureMode::Closed,
            timeout_ms: None,
        };
        assert_eq!(agent(None).effective_limit(1024), 1024);
        assert_eq!(agent(Some(16)).effective_limit(1024), 16);
        assert_eq!(agent(Some(1 << 20)).effective_limit(1024), 1024);
    }

    fn call_context() -> AgentCallContext {
        AgentCallContext {
            correlation_id: zentinel_common::CorrelationId::from_string("t"),
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: "t".to_string(),
                request_id: "t".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 0,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: String::new(),
                traceparent: None,
            },
            route_id: None,
            upstream_id: None,
            request_body: None,
            response_body: None,
        }
    }

    /// #553: the filter's limit is enforced like the agent's own. A body over
    /// it is refused for a fail-closed agent, before the agent is called --
    /// the agent here is never connected, so a call would fail differently.
    #[tokio::test]
    async fn a_body_over_the_filter_limit_is_handled_like_one_over_the_agents() {
        let kdl = r#"
            system { worker-threads 1 }
            listeners { listener "l" { address "127.0.0.1:8080" } }
            upstreams { upstream "u" { target "127.0.0.1:9000" } }
            routes { route "r" { matches { path-prefix "/" }
                                 upstream "u" } }
            agents {
                agent "waf" type="custom" {
                    unix-socket "/nonexistent/zentinel-553.sock"
                    events "request_headers" "request_body"
                    failure-mode "closed"
                    max-request-body-bytes 1024
                }
            }
        "#;
        let config = zentinel_config::Config::from_kdl(kdl).expect("parses");
        let manager = AgentManager::new(config.agents).await.expect("manager");

        let limited = [BodyAgent {
            id: "waf".to_string(),
            max_body_bytes: Some(10),
            failure_mode: FailureMode::Closed,
            timeout_ms: None,
        }];
        let decision = manager
            .process_request_body(&call_context(), &[b'x'; 100], true, &limited)
            .await
            .expect("decided without calling the agent");
        match decision.action {
            crate::agents::AgentAction::Block { status, .. } => assert_eq!(status, 413),
            other => panic!("expected a 413 block, got {other:?}"),
        }

        // Without the filter limit the same body is within the agent's 1024
        // bytes, so the agent is called (and, unreachable, fails instead).
        let unlimited = [BodyAgent {
            max_body_bytes: None,
            ..limited[0].clone()
        }];
        let outcome = manager
            .process_request_body(&call_context(), &[b'x'; 100], true, &unlimited)
            .await;
        if let Ok(decision) = outcome {
            assert!(
                !matches!(
                    decision.action,
                    crate::agents::AgentAction::Block { status: 413, .. }
                ),
                "the agent's own limit was not exceeded"
            );
        }
    }

    // ------------------------------------------------------------------
    // #571: an agent that is not loaded is a failed call on every path
    // ------------------------------------------------------------------

    fn filter(id: &str, failure_mode: FailureMode) -> FilterAgent {
        FilterAgent {
            id: id.to_string(),
            failure_mode,
            timeout_ms: None,
        }
    }

    fn body_filter(id: &str, failure_mode: FailureMode) -> BodyAgent {
        BodyAgent::from(&filter(id, failure_mode))
    }

    fn status_of(decision: &AgentDecision) -> Option<u16> {
        match decision.action {
            crate::agents::AgentAction::Block { status, .. } => Some(status),
            _ => None,
        }
    }

    /// Every event path a filter's agent is dispatched on, against a manager
    /// where the agent named is not loaded: `(path, decision)`.
    async fn decisions_for_missing_agent(
        failure_mode: FailureMode,
    ) -> Vec<(&'static str, AgentDecision)> {
        let manager = AgentManager::new(Vec::new()).await.expect("manager");
        let ctx = call_context();
        let filters = [filter("gone", failure_mode)];
        let bodies = [body_filter("gone", failure_mode)];
        let headers = HashMap::new();
        let decide = |path, outcome: ZentinelResult<AgentDecision>| {
            (path, outcome.unwrap_or_else(|e| panic!("{path}: {e}")))
        };
        let decisions = vec![
            decide(
                "request headers",
                manager
                    .process_request_headers(&ctx, HashMap::new(), &filters)
                    .await,
            ),
            decide(
                "request body",
                manager
                    .process_request_body(&ctx, b"x", true, &bodies)
                    .await,
            ),
            decide(
                "request body chunk",
                manager
                    .process_request_body_streaming(&ctx, b"x", false, 3, 64, None, &bodies)
                    .await,
            ),
            decide(
                "response headers",
                manager
                    .process_response_headers(&ctx, 200, &headers, &filters)
                    .await,
            ),
            decide(
                "response body chunk",
                manager
                    .process_response_body_streaming(&ctx, b"x", true, 0, 1, Some(1), &filters)
                    .await,
            ),
        ];
        assert_eq!(
            manager.metrics().calls_failed.load(Ordering::Relaxed),
            decisions.len() as u64,
            "each missing-agent call is counted as a failed call"
        );
        decisions
    }

    /// #571: on main only request headers blocked; the body and response
    /// paths skipped the unknown id and allowed.
    #[tokio::test]
    async fn a_fail_closed_filter_whose_agent_is_not_loaded_blocks_on_every_path() {
        for (path, decision) in decisions_for_missing_agent(FailureMode::Closed).await {
            assert_eq!(status_of(&decision), Some(503), "{path}: {decision:?}");
            assert_eq!(decision.decided_by.as_deref(), Some("gone"), "{path}");
        }
    }

    #[tokio::test]
    async fn a_fail_open_filter_whose_agent_is_not_loaded_allows_on_every_path() {
        for (path, decision) in decisions_for_missing_agent(FailureMode::Open).await {
            assert!(decision.is_allow(), "{path}: {decision:?}");
        }
    }

    /// The case #571 names: an agent filter only the response phase
    /// reaches (the request phase already answered), closed, agent gone.
    #[tokio::test]
    async fn a_response_only_filter_whose_agent_is_not_loaded_fails_closed() {
        let manager = AgentManager::new(Vec::new()).await.expect("manager");
        let decision = manager
            .process_response_headers(
                &call_context(),
                200,
                &HashMap::new(),
                &[filter("response-only", FailureMode::Closed)],
            )
            .await
            .expect("decided");
        assert_eq!(status_of(&decision), Some(503));
        // Not counted as subscribing to response bodies: its failure was
        // answered by the response-headers dispatch.
        assert!(
            !manager
                .any_agent_handles_event(
                    &[filter("response-only", FailureMode::Closed)],
                    EventType::ResponseBodyChunk
                )
                .await
        );
    }

    /// #584: a loaded agent that cannot be reached is answered by its
    /// filter's failure mode on every path, not by the agent's own. Before,
    /// request headers followed the filter and every other path the agent.
    #[tokio::test]
    async fn an_unreachable_agent_follows_its_filters_failure_mode_on_every_path() {
        for (agent_mode, filter_mode) in
            [("open", FailureMode::Closed), ("closed", FailureMode::Open)]
        {
            let kdl = format!(
                r#"
                system {{ worker-threads 1 }}
                listeners {{ listener "l" {{ address "127.0.0.1:8080" }} }}
                upstreams {{ upstream "u" {{ target "127.0.0.1:9000" }} }}
                routes {{ route "r" {{ matches {{ path-prefix "/" }}
                                     upstream "u" }} }}
                agents {{
                    agent "down" type="custom" {{
                        unix-socket "/nonexistent/zentinel-584.sock"
                        events "request_headers" "request_body" "response_headers" "response_body"
                        timeout-ms 200
                        failure-mode "{agent_mode}"
                    }}
                }}
                "#
            );
            let config = zentinel_config::Config::from_kdl(&kdl).expect("parses");
            let manager = AgentManager::new(config.agents).await.expect("manager");
            let ctx = call_context();
            let filters = [filter("down", filter_mode)];
            let bodies = [body_filter("down", filter_mode)];
            let outcomes = [
                (
                    "request headers",
                    manager
                        .process_request_headers(&ctx, HashMap::new(), &filters)
                        .await,
                ),
                (
                    "request body",
                    manager
                        .process_request_body(&ctx, b"x", true, &bodies)
                        .await,
                ),
                (
                    "request body chunk",
                    manager
                        .process_request_body_streaming(&ctx, b"x", false, 3, 64, None, &bodies)
                        .await,
                ),
                (
                    "response headers",
                    manager
                        .process_response_headers(&ctx, 200, &HashMap::new(), &filters)
                        .await,
                ),
                (
                    "response body chunk",
                    manager
                        .process_response_body_streaming(&ctx, b"x", true, 0, 1, Some(1), &filters)
                        .await,
                ),
            ];
            for (path, outcome) in outcomes {
                let decision = outcome.unwrap_or_else(|e| panic!("{path}: {e}"));
                match filter_mode {
                    FailureMode::Closed => {
                        let status = status_of(&decision);
                        assert!(
                            matches!(status, Some(503 | 504)),
                            "{path}, agent {agent_mode}: {decision:?}"
                        );
                        assert_eq!(decision.decided_by.as_deref(), Some("down"), "{path}");
                    }
                    FailureMode::Open => {
                        assert!(
                            decision.is_allow(),
                            "{path}, agent {agent_mode}: {decision:?}"
                        )
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn a_guardrail_whose_agent_is_not_loaded_is_a_failed_call() {
        let manager = AgentManager::new(Vec::new()).await.expect("manager");
        let event = GuardrailInspectEvent {
            correlation_id: "t".to_string(),
            inspection_type: zentinel_agent_protocol::GuardrailInspectionType::PromptInjection,
            content: String::new(),
            model: None,
            categories: Vec::new(),
            route_id: None,
            metadata: HashMap::new(),
        };
        assert!(manager.call_guardrail_agent("gone", event).await.is_err());
        assert_eq!(manager.metrics().calls_failed.load(Ordering::Relaxed), 1);
    }

    // ------------------------------------------------------------------
    // #570: a retired agent closes on its last reference, or its ceiling
    // ------------------------------------------------------------------

    /// Answers request headers after `delay`, marking the request so the
    /// caller can tell this agent answered it.
    struct SlowAgent {
        delay: Duration,
    }

    #[async_trait::async_trait]
    impl zentinel_agent_protocol::v2::server::AgentHandlerV2 for SlowAgent {
        fn capabilities(&self) -> zentinel_agent_protocol::v2::AgentCapabilities {
            zentinel_agent_protocol::v2::AgentCapabilities::new("slow", "Slow Agent", "0.1.0")
        }

        async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
            tokio::time::sleep(self.delay).await;
            AgentResponse::default_allow().add_request_header(
                zentinel_agent_protocol::HeaderOp::Set {
                    name: "x-answered-by".to_string(),
                    value: "old".to_string(),
                },
            )
        }

        async fn on_request_body_chunk(
            &self,
            _event: zentinel_agent_protocol::RequestBodyChunkEvent,
        ) -> AgentResponse {
            tokio::time::sleep(self.delay).await;
            AgentResponse::default_allow()
        }

        async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
            tokio::time::sleep(self.delay).await;
            AgentResponse::default_allow()
        }

        async fn on_response_body_chunk(
            &self,
            _event: zentinel_agent_protocol::ResponseBodyChunkEvent,
        ) -> AgentResponse {
            tokio::time::sleep(self.delay).await;
            AgentResponse::default_allow()
        }
    }

    /// A connected manager with one agent, "slow", answering after `delay`.
    async fn manager_with_slow_agent(
        delay: Duration,
        timeout_ms: u64,
    ) -> (Arc<AgentManager>, tempfile::TempDir) {
        manager_with_slow_agent_on(delay, timeout_ms, r#""request_headers""#).await
    }

    /// [`manager_with_slow_agent`], subscribed to `events` (KDL arguments).
    async fn manager_with_slow_agent_on(
        delay: Duration,
        timeout_ms: u64,
        events: &str,
    ) -> (Arc<AgentManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("slow.sock");
        let server = zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2::new(
            "slow",
            socket.clone(),
            Box::new(SlowAgent { delay }),
        );
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "the agent never listened");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let kdl = format!(
            r#"
            system {{ worker-threads 1 }}
            listeners {{ listener "l" {{ address "127.0.0.1:8080" }} }}
            upstreams {{ upstream "u" {{ target "127.0.0.1:9000" }} }}
            routes {{ route "r" {{ matches {{ path-prefix "/" }}
                                 upstream "u" }} }}
            agents {{
                agent "slow" type="custom" {{
                    unix-socket "{}"
                    events {events}
                    timeout-ms {timeout_ms}
                    failure-mode "closed"
                }}
            }}
            "#,
            socket.display()
        );
        let config = zentinel_config::Config::from_kdl(&kdl).expect("parses");
        let manager = AgentManager::new(config.agents).await.expect("manager");
        manager.initialize().await.expect("initialized");
        (Arc::new(manager), dir)
    }

    // ------------------------------------------------------------------
    // #589: the filter's `timeout-ms` applies on every dispatch path
    // ------------------------------------------------------------------

    /// The decision on each event path for a filter with `timeout-ms 100`
    /// whose agent answers after 2 s and has `timeout-ms 10000` of its own:
    /// `(path, decision, elapsed)`. Request headers go through the parallel
    /// dispatch, the other three through the sequential one.
    async fn decisions_with_filter_timeout(
        filter_timeout_ms: Option<u64>,
    ) -> Vec<(&'static str, AgentDecision, Duration)> {
        let (manager, _dir) = manager_with_slow_agent_on(
            Duration::from_secs(2),
            10_000,
            r#""request_headers" "request_body" "response_headers" "response_body""#,
        )
        .await;
        let ctx = call_context();
        let filters = [FilterAgent {
            id: "slow".to_string(),
            failure_mode: FailureMode::Closed,
            timeout_ms: filter_timeout_ms,
        }];
        let bodies = [BodyAgent::from(&filters[0])];
        let mut decisions = Vec::new();
        macro_rules! time {
            ($path:expr, $call:expr) => {{
                let start = Instant::now();
                let decision = $call.await.unwrap_or_else(|e| panic!("{}: {e}", $path));
                decisions.push(($path, decision, start.elapsed()));
            }};
        }
        time!(
            "request headers",
            manager.process_request_headers(&ctx, headers_for("/"), &filters)
        );
        time!(
            "request body",
            manager.process_request_body(&ctx, b"body", true, &bodies)
        );
        time!(
            "request body (streaming)",
            manager.process_request_body_streaming(&ctx, b"body", true, 0, 4, Some(4), &bodies)
        );
        time!(
            "response headers",
            manager.process_response_headers(&ctx, 200, &HashMap::new(), &filters)
        );
        time!(
            "response body (streaming)",
            manager.process_response_body_streaming(&ctx, b"body", true, 0, 4, Some(4), &filters)
        );
        decisions
    }

    /// #589: a filter's `timeout-ms` shorter than its agent's cuts the call
    /// off at the filter's value in both dispatch modes -- not only the
    /// parallel one used for request headers.
    #[tokio::test]
    async fn a_filter_timeout_applies_in_both_dispatch_modes() {
        for (path, decision, elapsed) in decisions_with_filter_timeout(Some(100)).await {
            assert_eq!(
                status_of(&decision),
                Some(504),
                "{path}: the filter's 100 ms timeout must fail the call closed"
            );
            assert!(
                elapsed < Duration::from_millis(1500),
                "{path}: waited {elapsed:?}, longer than the filter's 100 ms allows"
            );
        }
    }

    /// #589: without a filter timeout, the agent's own (10 s) applies, so the
    /// same 2 s agent answers on every path.
    #[tokio::test]
    async fn without_a_filter_timeout_the_agents_applies_in_both_dispatch_modes() {
        for (path, decision, elapsed) in decisions_with_filter_timeout(None).await {
            assert_eq!(
                status_of(&decision),
                None,
                "{path}: the agent answered within its own timeout"
            );
            assert!(elapsed >= Duration::from_secs(2), "{path}: {elapsed:?}");
        }
    }

    fn headers_for(path: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([(":path".to_string(), vec![path.to_string()])])
    }

    /// #570: a call that started before its agent was removed finishes on
    /// that agent, and the agent's pool closes once the call lets go -- not
    /// before, and not on a timer.
    #[tokio::test]
    async fn a_call_straddling_removal_finishes_on_the_old_agent_then_its_pool_closes() {
        let (manager, _dir) = manager_with_slow_agent(Duration::from_millis(400), 5000).await;
        let (weak, pool) = {
            let agents = manager.agents.read().await;
            (Arc::downgrade(&agents["slow"]), agents["slow"].pool())
        };

        let in_flight = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move {
                manager
                    .process_request_headers(
                        &call_context(),
                        headers_for("/"),
                        &[filter("slow", FailureMode::Closed)],
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(manager.remove("slow").await);
        // New calls no longer reach it: not loaded, fail closed.
        let after = manager
            .process_request_headers(
                &call_context(),
                headers_for("/"),
                &[filter("slow", FailureMode::Closed)],
            )
            .await
            .expect("decided");
        assert_eq!(status_of(&after), Some(503));
        // The call in flight still holds it open.
        assert!(
            weak.upgrade().is_some_and(|a| !a.is_closed()),
            "the in-flight call holds it open"
        );
        assert!(pool.agent_stats("slow").await.is_some(), "pool still open");

        let decision = in_flight.await.expect("joined").expect("decided");
        assert!(decision.is_allow(), "{decision:?}");
        assert!(
            decision.request_headers.iter().any(|op| matches!(
                op,
                zentinel_agent_protocol::HeaderOp::Set { name, value }
                    if name == "x-answered-by" && value == "old"
            )),
            "the old agent answered: {decision:?}"
        );

        // Its last reference is gone: the pool closes now, well before the
        // retirement ceiling (5 s timeout + 1 s here).
        assert_eq!(weak.strong_count(), 0);
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.agent_stats("slow").await.is_some() {
            assert!(Instant::now() < deadline, "pool never closed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// #570 (bounded): a call that hangs cannot keep a retired agent's pool
    /// open past the ceiling.
    #[tokio::test]
    async fn a_hung_call_cannot_keep_a_retired_agent_open_past_its_ceiling() {
        let (manager, _dir) = manager_with_slow_agent(Duration::from_secs(60), 30_000).await;
        let agent = manager.agents.read().await["slow"].clone();
        let pool = agent.pool();
        let weak = Arc::downgrade(&agent);
        assert_eq!(
            agent.retirement_ceiling(),
            Duration::from_millis(31_000),
            "longest timeout (30 s call, 5 s chunk) + 1 s"
        );

        let hung = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move {
                manager
                    .process_request_headers(
                        &call_context(),
                        headers_for("/"),
                        &[filter("slow", FailureMode::Closed)],
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        // What `remove` does, with a short ceiling for the test.
        let removed = manager.agents.write().await.remove("slow").expect("loaded");
        drop(agent);
        removed.retire_within(Duration::from_millis(300));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            weak.upgrade().is_some_and(|a| !a.is_closed()),
            "open before the ceiling"
        );

        let deadline = Instant::now() + Duration::from_secs(3);
        while pool.agent_stats("slow").await.is_some() {
            assert!(
                Instant::now() < deadline,
                "the ceiling never closed the pool"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            weak.upgrade().is_none_or(|a| a.is_closed()),
            "closed under the hung call"
        );
        hung.abort();
    }

    /// With no call holding it, a retired agent closes at once.
    #[tokio::test]
    async fn a_retired_agent_no_call_holds_closes_at_once() {
        let (manager, _dir) = manager_with_slow_agent(Duration::ZERO, 1000).await;
        let pool = manager.agents.read().await["slow"].pool();
        assert!(manager.remove("slow").await);
        assert!(!manager.remove("slow").await, "already gone");
        let deadline = Instant::now() + Duration::from_secs(2);
        while pool.agent_stats("slow").await.is_some() {
            assert!(Instant::now() < deadline, "pool never closed");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn agent_named(id: &str) -> AgentConfig {
        let mut config = agent_from_kdl("");
        config.id = id.to_string();
        config.config = None;
        config
    }

    /// Reload brings the loaded agents in line with the new config: an added
    /// agent is loaded, one whose config changed is rebuilt, an unchanged
    /// one is the very same agent, and one the config dropped is removed.
    #[tokio::test]
    async fn reconcile_loads_rebuilds_keeps_and_removes_agents() {
        let manager = AgentManager::new(vec![agent_named("a"), agent_named("b")])
            .await
            .expect("manager");
        let loaded = |id: &str| manager.agents.try_read().unwrap().get(id).cloned();
        let (a, b) = (loaded("a").unwrap(), loaded("b").unwrap());

        let mut b_changed = agent_named("b");
        b_changed.timeout_ms += 1;
        let next = [agent_named("a"), b_changed, agent_named("c")];

        let changes = manager.reconcile(&next).await;
        assert_eq!(
            changes,
            AgentReconcile {
                added: 1,
                replaced: 1,
                unchanged: 1
            }
        );
        assert!(Arc::ptr_eq(&a, &loaded("a").unwrap()), "unchanged: kept");
        assert!(!Arc::ptr_eq(&b, &loaded("b").unwrap()), "changed: rebuilt");
        assert!(loaded("c").is_some(), "added: loaded");

        // An agent the new config drops stays loaded until the caller has
        // swapped the routes that still call it.
        let only_c = vec![agent_named("c")];
        assert_eq!(
            manager.reconcile(&only_c).await,
            AgentReconcile {
                unchanged: 1,
                ..Default::default()
            }
        );
        assert!(loaded("a").is_some());
        assert_eq!(manager.remove_unlisted(&only_c).await, 2);
        assert!(loaded("a").is_none() && loaded("b").is_none());
        assert!(loaded("c").is_some());
        assert!(manager.agent_semaphores.read().await.contains_key("c"));
        assert!(!manager.agent_semaphores.read().await.contains_key("a"));
    }

    /// The `config { }` block is delivered when a connection is made (#603),
    /// so a reload that changes only that block must rebuild the agent: a
    /// kept agent would go on handing its connections the old block.
    #[tokio::test]
    async fn a_reload_that_changes_only_the_config_block_rebuilds_the_agent() {
        let with_block = |value: serde_json::Value| {
            let mut config = agent_named("a");
            config.config = Some(value);
            config
        };
        let manager = AgentManager::new(vec![with_block(serde_json::json!({"level": 1}))])
            .await
            .expect("manager");
        let before = manager.agents.read().await.get("a").cloned().unwrap();

        let same = [with_block(serde_json::json!({"level": 1}))];
        assert_eq!(manager.reconcile(&same).await.unchanged, 1);

        let changed = [with_block(serde_json::json!({"level": 2}))];
        assert_eq!(manager.reconcile(&changed).await.replaced, 1);
        let after = manager.agents.read().await.get("a").cloned().unwrap();
        assert!(!Arc::ptr_eq(&before, &after), "the agent was rebuilt");
        assert_eq!(
            after.config().config,
            Some(serde_json::json!({"level": 2})),
            "and carries the new block"
        );
    }

    /// A reload that adds an agent which accepts the connection and never
    /// answers must not hold the reload (#599): the agent is loaded, its
    /// connection attempt is bounded by `connect-timeout-ms`, and its
    /// filters follow their failure mode meanwhile.
    #[tokio::test]
    async fn a_silent_agent_added_by_a_reload_does_not_hold_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("silent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).expect("bind");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let mut silent = agent_named("silent");
        silent.transport = zentinel_config::AgentTransport::UnixSocket { path: socket };
        silent.connect_timeout_ms = Some(300);
        let manager = AgentManager::new(Vec::new()).await.expect("manager");

        let started = Instant::now();
        let changes = manager.reconcile(&[silent]).await;
        assert_eq!(changes.added, 1);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "the reload waited {:?} for a silent agent",
            started.elapsed()
        );
        assert!(manager.is_loaded("silent").await);
    }
}
