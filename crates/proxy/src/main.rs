//! Sentinel Proxy - Main entry point (Phase 1)
//!
//! A security-first reverse proxy built on Pingora with sleepable ops at the edge.
//! This version includes full routing, upstream pools, health checking, and hot reload.

use anyhow::{Context, Result};
use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod agents;
mod app;
mod config;
mod errors;
mod health;
mod metrics;
mod reload;
mod routing;
mod static_files;
mod upstream;
mod validation;

use crate::agents::{AgentCallContext, AgentDecision, AgentManager};
use crate::app::{AppState, HealthCheck, ReadinessCheck};
use crate::errors::ErrorHandler;
use crate::health::{HealthChecker, PassiveHealthChecker};
use crate::metrics::Metrics;
use crate::reload::{
    ConfigManager, GracefulReloadCoordinator, ReloadEvent, ReloadTrigger, RouteValidator,
    UpstreamValidator,
};
use crate::routing::{RequestInfo, RouteMatcher};
use crate::static_files::StaticFileServer;
use crate::upstream::UpstreamPool;
use crate::validation::SchemaValidator;

use sentinel_common::{
    observability::{init_tracing, RequestMetrics},
    types::CorrelationId,
};
use sentinel_config::Config;

/// Main proxy service implementing Pingora's ProxyHttp trait (Phase 2)
pub struct SentinelProxy {
    /// Configuration manager with hot reload
    config_manager: Arc<ConfigManager>,
    /// Route matcher
    route_matcher: Arc<RwLock<RouteMatcher>>,
    /// Upstream pools
    upstream_pools: Arc<RwLock<HashMap<String, Arc<UpstreamPool>>>>,
    /// Agent manager for external processing
    agent_manager: Arc<AgentManager>,
    /// Passive health checker
    passive_health: Arc<PassiveHealthChecker>,
    /// Metrics collector
    metrics: Arc<RequestMetrics>,
    /// Application state
    app_state: Arc<AppState>,
    /// Graceful reload coordinator
    reload_coordinator: Arc<GracefulReloadCoordinator>,
}

impl SentinelProxy {
    /// Create new proxy instance with Phase 2 features
    pub async fn new(config_path: &str) -> Result<Self> {
        // Initialize tracing
        init_tracing()?;

        info!("Starting Sentinel Proxy Phase 2");

        // Load initial configuration
        let config =
            Config::from_file(config_path).context("Failed to load initial configuration")?;

        config
            .validate()
            .context("Initial configuration validation failed")?;

        // Create configuration manager
        let config_manager = Arc::new(ConfigManager::new(config_path, config.clone()).await?);

        // Add validators
        config_manager.add_validator(Box::new(RouteValidator)).await;
        config_manager
            .add_validator(Box::new(UpstreamValidator))
            .await;

        // Create route matcher
        let route_matcher = Arc::new(RwLock::new(RouteMatcher::new(config.routes.clone(), None)?));

        // Create upstream pools
        let mut pools = HashMap::new();
        for (name, upstream_config) in config.upstreams.clone() {
            let pool = Arc::new(UpstreamPool::new(upstream_config).await?);
            pools.insert(name, pool);
        }
        let upstream_pools = Arc::new(RwLock::new(pools));

        // Create passive health checker
        let passive_health = Arc::new(PassiveHealthChecker::new(
            0.5,  // 50% failure rate threshold
            100,  // Window size
            None, // Will be linked to active health checkers
        ));

        // Create agent manager
        let agent_manager = Arc::new(AgentManager::new(config.agents.clone(), 1000).await?);
        agent_manager.initialize().await?;

        // Create metrics collector
        let metrics = Arc::new(RequestMetrics::new()?);

        // Create application state
        let app_state = Arc::new(AppState::new(Uuid::new_v4().to_string()));

        // Create reload coordinator
        let reload_coordinator = Arc::new(GracefulReloadCoordinator::new(
            Duration::from_secs(30), // Max drain time
        ));

        // Setup configuration reload subscription
        let mut reload_rx = config_manager.subscribe();
        let route_matcher_clone = Arc::clone(&route_matcher);
        let upstream_pools_clone = Arc::clone(&upstream_pools);
        let config_manager_clone = Arc::clone(&config_manager);

        tokio::spawn(async move {
            while let Ok(event) = reload_rx.recv().await {
                match event {
                    ReloadEvent::Applied { .. } => {
                        // Reload routes and upstreams
                        let new_config = config_manager_clone.current();

                        // Update route matcher
                        if let Ok(new_matcher) = RouteMatcher::new(new_config.routes.clone(), None)
                        {
                            *route_matcher_clone.write().await = new_matcher;
                            info!("Routes reloaded successfully");
                        }

                        // Update upstream pools
                        let mut new_pools = HashMap::new();
                        for (name, upstream_config) in new_config.upstreams.clone() {
                            match UpstreamPool::new(upstream_config).await {
                                Ok(pool) => {
                                    new_pools.insert(name, Arc::new(pool));
                                }
                                Err(e) => {
                                    error!("Failed to create upstream pool: {}", e);
                                }
                            }
                        }

                        // Gracefully swap pools
                        let old_pools = {
                            let mut pools = upstream_pools_clone.write().await;
                            std::mem::replace(&mut *pools, new_pools)
                        };

                        // Shutdown old pools after delay
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            for (name, pool) in old_pools {
                                info!("Shutting down old pool: {}", name);
                                pool.shutdown().await;
                            }
                        });
                    }
                    _ => {}
                }
            }
        });

        // Mark as ready
        app_state.set_ready(true);

        Ok(Self {
            config_manager,
            route_matcher,
            upstream_pools,
            agent_manager,
            passive_health,
            metrics,
            app_state,
            reload_coordinator,
        })
    }

    /// Get or generate correlation ID
    fn get_correlation_id(&self, session: &Session) -> String {
        session
            .req_header()
            .headers
            .get("x-correlation-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    }

    /// Apply security headers
    fn apply_security_headers(&self, header: &mut ResponseHeader) -> Result<(), Box<Error>> {
        header.insert_header("X-Content-Type-Options", "nosniff")?;
        header.insert_header("X-Frame-Options", "DENY")?;
        header.insert_header("X-XSS-Protection", "1; mode=block")?;
        header.insert_header("Referrer-Policy", "strict-origin-when-cross-origin")?;
        header.remove_header("Server");
        header.remove_header("X-Powered-By");
        Ok(())
    }
}

/// Request context maintained throughout the request lifecycle
pub struct RequestContext {
    /// Unique correlation ID for request tracing
    correlation_id: String,
    /// Request start time
    start_time: Instant,
    /// Selected route ID
    route_id: Option<String>,
    /// Selected upstream
    upstream: Option<String>,
    /// Number of upstream attempts
    upstream_attempts: u32,
}

#[async_trait]
impl ProxyHttp for SentinelProxy {
    type CTX = RequestContext;
    fn new_ctx(&self) -> Self::CTX {
        RequestContext {
            correlation_id: String::new(),
            start_time: Instant::now(),
            route_id: None,
            upstream: None,
            upstream_attempts: 0,
        }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // Track active request
        self.reload_coordinator.inc_requests();

        // Initialize correlation ID
        ctx.correlation_id = self.get_correlation_id(session);

        let req_header = session.req_header();

        // Build request info for routing
        let mut headers = HashMap::new();
        for (name, value) in req_header.headers.iter() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value_str.to_string());
            }
        }

        let request_info = RequestInfo {
            method: req_header.method.to_string(),
            path: req_header.uri.path().to_string(),
            host: req_header.uri.host().unwrap_or("").to_string(),
            headers,
            query_params: RequestInfo::parse_query_params(req_header.uri.path()),
        };

        // Match route
        let route_match = self
            .route_matcher
            .read()
            .await
            .match_request(&request_info)
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "No matching route found"))?;

        ctx.route_id = Some(route_match.route_id.to_string());
        ctx.upstream = Some(route_match.config.upstream.clone());

        info!(
            correlation_id = %ctx.correlation_id,
            route_id = %route_match.route_id,
            upstream = %route_match.config.upstream,
            method = %req_header.method,
            path = %req_header.uri.path(),
            "Request matched to route"
        );

        // Get upstream pool
        let pools = self.upstream_pools.read().await;
        let pool = pools.get(&route_match.config.upstream).ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                format!("Upstream pool '{}' not found", route_match.config.upstream),
            )
        })?;

        // Select peer from pool with retries
        let max_retries = route_match
            .config
            .retry_policy
            .as_ref()
            .map(|r| r.max_attempts)
            .unwrap_or(1);

        let mut last_error = None;
        for attempt in 1..=max_retries {
            ctx.upstream_attempts = attempt;

            match pool.select_peer(None).await {
                Ok(peer) => {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        attempt = attempt,
                        "Selected upstream peer"
                    );
                    return Ok(Box::new(peer));
                }
                Err(e) => {
                    warn!(
                        correlation_id = %ctx.correlation_id,
                        attempt = attempt,
                        error = %e,
                        "Failed to select upstream peer"
                    );
                    last_error = Some(e);

                    if attempt < max_retries {
                        // Exponential backoff
                        let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        Err(Error::explain(
            ErrorType::InternalError,
            format!("All upstream attempts failed: {:?}", last_error),
        ))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        // Get client address before mutable borrow
        let client_addr = session
            .client_addr()
            .map(|a| format!("{}", a))
            .unwrap_or_else(|| "unknown".to_string());
        let client_port = session.client_addr().map(|_| 0).unwrap_or(0);

        let req_header = session.req_header_mut();

        // Add correlation ID header
        req_header
            .insert_header("X-Correlation-Id", &ctx.correlation_id)
            .ok();
        req_header.insert_header("X-Forwarded-By", "Sentinel").ok();

        // Get current config for limits
        let config = self.config_manager.current();

        // Enforce header limits
        if req_header.headers.len() > config.limits.max_header_count {
            warn!(
                correlation_id = %ctx.correlation_id,
                header_count = req_header.headers.len(),
                limit = config.limits.max_header_count,
                "Request exceeds header count limit"
            );

            self.metrics.record_blocked_request("header_count_exceeded");
            return Err(Error::explain(ErrorType::InternalError, "Too many headers"));
        }

        // Check header size
        let total_header_size: usize = req_header
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();

        if total_header_size > config.limits.max_header_size_bytes {
            warn!(
                correlation_id = %ctx.correlation_id,
                header_size = total_header_size,
                limit = config.limits.max_header_size_bytes,
                "Request exceeds header size limit"
            );

            self.metrics.record_blocked_request("header_size_exceeded");
            return Err(Error::explain(
                ErrorType::InternalError,
                "Headers too large",
            ));
        }

        // Phase 2: Process through external agents
        if let Some(route_id) = &ctx.route_id {
            // Get route configuration to find which agents to apply
            let routes = config.routes.clone();
            if let Some(route) = routes.iter().find(|r| r.id == *route_id) {
                if !route.agents.is_empty() {
                    debug!(
                        correlation_id = %ctx.correlation_id,
                        route_id = %route_id,
                        agents = ?route.agents,
                        "Processing request through agents"
                    );

                    // Build headers map for agent processing
                    let mut headers_map = HashMap::new();
                    for (name, value) in req_header.headers.iter() {
                        headers_map
                            .entry(name.as_str().to_lowercase())
                            .or_insert_with(Vec::new)
                            .push(value.to_str().unwrap_or("").to_string());
                    }

                    // Create agent call context
                    let agent_ctx = AgentCallContext {
                        correlation_id: CorrelationId::from_string(&ctx.correlation_id),
                        metadata: sentinel_agent_protocol::RequestMetadata {
                            correlation_id: ctx.correlation_id.clone(),
                            request_id: Uuid::new_v4().to_string(),
                            client_ip: client_addr.clone(),
                            client_port,
                            server_name: req_header.uri.host().map(|h| h.to_string()),
                            protocol: "HTTP/1.1".to_string(), // TODO: Get actual protocol
                            tls_version: None,                // TODO: Get from TLS info
                            tls_cipher: None,
                            route_id: Some(route_id.clone()),
                            upstream_id: ctx.upstream.clone(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        },
                        route_id: Some(route_id.clone()),
                        upstream_id: ctx.upstream.clone(),
                        request_body: None,
                        response_body: None,
                    };

                    // Process through agents
                    match self
                        .agent_manager
                        .process_request_headers(&agent_ctx, &headers_map, &route.agents)
                        .await
                    {
                        Ok(decision) => {
                            // Apply agent decision
                            if !decision.is_allow() {
                                match decision.action {
                                    agents::AgentAction::Block { status, body, .. } => {
                                        warn!(
                                            correlation_id = %ctx.correlation_id,
                                            status = status,
                                            "Request blocked by agent"
                                        );
                                        self.metrics.record_blocked_request("agent_blocked");
                                        return Err(Error::explain(
                                            ErrorType::InternalError,
                                            body.unwrap_or_else(|| "Blocked by agent".to_string()),
                                        ));
                                    }
                                    agents::AgentAction::Redirect { url, status } => {
                                        info!(
                                            correlation_id = %ctx.correlation_id,
                                            url = %url,
                                            status = status,
                                            "Request redirected by agent"
                                        );
                                        // TODO: Implement redirect response
                                        return Err(Error::explain(
                                            ErrorType::InternalError,
                                            format!("Redirect to {}", url),
                                        ));
                                    }
                                    _ => {}
                                }
                            }

                            // Apply header modifications
                            for op in decision.request_headers {
                                match op {
                                    sentinel_agent_protocol::HeaderOp::Set { name, value } => {
                                        req_header.insert_header(name, &value).ok();
                                    }
                                    sentinel_agent_protocol::HeaderOp::Add { name, value } => {
                                        req_header.append_header(name, &value).ok();
                                    }
                                    sentinel_agent_protocol::HeaderOp::Remove { name } => {
                                        req_header.remove_header(&name);
                                    }
                                }
                            }

                            debug!(
                                correlation_id = %ctx.correlation_id,
                                "Agent processing completed, request allowed"
                            );
                        }
                        Err(e) => {
                            error!(
                                correlation_id = %ctx.correlation_id,
                                error = %e,
                                "Agent processing failed"
                            );
                            // Check failure mode from route config
                            if route.policies.failure_mode == sentinel_config::FailureMode::Closed {
                                return Err(Error::explain(
                                    ErrorType::InternalError,
                                    "Agent processing failed",
                                ));
                            }
                            // Otherwise fail-open and continue
                        }
                    }
                }
            }
        }

        Ok(false) // Continue processing
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Apply security headers
        self.apply_security_headers(upstream_response).ok();

        // Add correlation ID to response
        upstream_response.insert_header("X-Correlation-Id", &ctx.correlation_id)?;

        // Record metrics
        let status = upstream_response.status.as_u16();
        let duration = ctx.start_time.elapsed();

        self.metrics.record_request(
            ctx.route_id.as_deref().unwrap_or("unknown"),
            "GET", // TODO: Get actual method from context
            status,
            duration,
        );

        // Record passive health check
        if let Some(ref upstream) = ctx.upstream {
            let success = status < 500;
            self.passive_health.record_outcome(upstream, success).await;

            // Report to upstream pool
            if let Some(pool) = self.upstream_pools.read().await.get(upstream) {
                pool.report_result(upstream, success).await;
            }
        }

        info!(
            correlation_id = %ctx.correlation_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
            status = status,
            duration_ms = duration.as_millis(),
            attempts = ctx.upstream_attempts,
            "Request completed"
        );

        Ok(())
    }

    async fn logging(&self, session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        // Decrement active requests
        self.reload_coordinator.dec_requests();

        let req_header = session.req_header();
        let duration = ctx.start_time.elapsed();

        // Structured JSON logging
        let log_entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "correlation_id": ctx.correlation_id,
            "instance_id": self.app_state.instance_id,
            "method": req_header.method.to_string(),
            "path": req_header.uri.path(),
            "route_id": ctx.route_id,
            "upstream": ctx.upstream,
            "status": session.response_written().map(|r| r.status.as_u16()),
            "duration_ms": duration.as_millis(),
            "upstream_attempts": ctx.upstream_attempts,
            "error": _error.map(|e| e.to_string()),
        });

        println!("{}", log_entry);
    }
}

fn main() -> Result<()> {
    // Parse command-line options
    let opt = Opt::parse_args();

    // Get config path from environment or use default
    let config_path =
        std::env::var("SENTINEL_CONFIG").unwrap_or_else(|_| "config/sentinel.kdl".to_string());

    info!("Loading configuration from: {}", config_path);

    // Create runtime for async initialization
    let runtime = tokio::runtime::Runtime::new()?;

    // Create proxy with Phase 1 features
    let proxy = runtime.block_on(async { SentinelProxy::new(&config_path).await })?;

    // Get initial config for server setup
    let config = proxy.config_manager.current();

    // Create Pingora server
    let mut server = Server::new(Some(opt))?;
    server.bootstrap();

    // Create proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // Configure listening addresses from config
    for listener in &config.listeners {
        match listener.protocol {
            sentinel_config::ListenerProtocol::Http => {
                proxy_service.add_tcp(&listener.address);
                info!("HTTP listening on: {}", listener.address);
            }
            sentinel_config::ListenerProtocol::Https => {
                if let Some(ref _tls) = listener.tls {
                    // TODO: Load TLS certificates
                    warn!("HTTPS listener configured but TLS not yet implemented");
                }
            }
            _ => {
                warn!("Unsupported protocol: {:?}", listener.protocol);
            }
        }
    }

    // Add proxy service to server
    server.add_service(proxy_service);

    // Setup signal handlers for graceful shutdown and reload
    setup_signal_handlers();

    info!("Sentinel proxy Phase 1 started successfully");
    info!("Configuration hot reload enabled");
    info!("Health checking enabled");
    info!("Route matching enabled");

    // Run server forever
    server.run_forever();
}

/// Setup signal handlers for graceful operations
fn setup_signal_handlers() {
    use signal_hook::consts::signal::*;
    use signal_hook::iterator::Signals;
    use std::thread;

    let mut signals =
        Signals::new(&[SIGTERM, SIGINT, SIGHUP]).expect("Failed to register signal handlers");

    thread::spawn(move || {
        for sig in signals.forever() {
            match sig {
                SIGTERM | SIGINT => {
                    info!("Received shutdown signal, initiating graceful shutdown");
                    // TODO: Trigger graceful shutdown with connection draining
                    std::process::exit(0);
                }
                SIGHUP => {
                    info!("Received SIGHUP, triggering configuration reload");
                    // TODO: Trigger configuration reload
                }
                _ => {}
            }
        }
    });
}
