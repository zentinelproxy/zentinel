//! Sentinel Proxy Core Implementation
//!
//! This module contains the main SentinelProxy struct and its implementation,
//! split across several submodules for maintainability:
//!
//! - `context`: Request context maintained throughout the request lifecycle
//! - `handlers`: Helper methods for handling different route types
//! - `http_trait`: ProxyHttp trait implementation for Pingora

mod context;
mod handlers;
mod http_trait;

pub use context::RequestContext;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sentinel_common::Registry;

use crate::agents::AgentManager;
use crate::app::AppState;
use crate::builtin_handlers::BuiltinHandlerState;
use crate::cache::{CacheConfig, CacheManager};
use crate::errors::ErrorHandler;
use crate::health::PassiveHealthChecker;
use crate::http_helpers;
use crate::logging::{LogManager, SharedLogManager};
use crate::rate_limit::{RateLimitConfig, RateLimitManager};
use crate::reload::{
    ConfigManager, GracefulReloadCoordinator, ReloadEvent, RouteValidator, UpstreamValidator,
};
use crate::routing::RouteMatcher;
use crate::static_files::StaticFileServer;
use crate::upstream::{ActiveHealthChecker, HealthCheckRunner, UpstreamPool};
use crate::validation::SchemaValidator;

use sentinel_common::TraceIdFormat;
use sentinel_config::Config;

/// Main proxy service implementing Pingora's ProxyHttp trait
pub struct SentinelProxy {
    /// Configuration manager with hot reload
    pub config_manager: Arc<ConfigManager>,
    /// Route matcher
    pub(super) route_matcher: Arc<RwLock<RouteMatcher>>,
    /// Upstream pools (keyed by upstream ID)
    pub(super) upstream_pools: Registry<UpstreamPool>,
    /// Agent manager for external processing
    pub(super) agent_manager: Arc<AgentManager>,
    /// Passive health checker
    pub(super) passive_health: Arc<PassiveHealthChecker>,
    /// Metrics collector
    pub(super) metrics: Arc<sentinel_common::observability::RequestMetrics>,
    /// Application state
    pub(super) app_state: Arc<AppState>,
    /// Graceful reload coordinator
    pub(super) reload_coordinator: Arc<GracefulReloadCoordinator>,
    /// Error handlers per route (keyed by route ID)
    pub(super) error_handlers: Registry<ErrorHandler>,
    /// API schema validators per route (keyed by route ID)
    pub(super) validators: Registry<SchemaValidator>,
    /// Static file servers per route (keyed by route ID)
    pub(super) static_servers: Registry<StaticFileServer>,
    /// Builtin handler state
    pub(super) builtin_state: Arc<BuiltinHandlerState>,
    /// Log manager for file-based logging
    pub(super) log_manager: SharedLogManager,
    /// Trace ID format for request tracing
    pub(super) trace_id_format: TraceIdFormat,
    /// Active health check runner
    pub(super) health_check_runner: Arc<HealthCheckRunner>,
    /// Rate limit manager
    pub(super) rate_limit_manager: Arc<RateLimitManager>,
    /// HTTP cache manager
    pub(super) cache_manager: Arc<CacheManager>,
}

impl SentinelProxy {
    /// Create new proxy instance
    ///
    /// If config_path is None, uses the embedded default configuration.
    /// Note: Tracing must be initialized by the caller before calling this function.
    pub async fn new(config_path: Option<&str>) -> Result<Self> {
        info!("Starting Sentinel Proxy");

        // Load initial configuration
        let (config, effective_config_path) = match config_path {
            Some(path) => {
                let cfg = Config::from_file(path).context("Failed to load configuration file")?;
                (cfg, path.to_string())
            }
            None => {
                let cfg = Config::default_embedded()
                    .context("Failed to load embedded default configuration")?;
                // Use a sentinel path to indicate embedded config
                (cfg, "_embedded_".to_string())
            }
        };

        config
            .validate()
            .context("Initial configuration validation failed")?;

        // Create configuration manager
        let config_manager =
            Arc::new(ConfigManager::new(&effective_config_path, config.clone()).await?);

        // Add validators
        config_manager.add_validator(Box::new(RouteValidator)).await;
        config_manager
            .add_validator(Box::new(UpstreamValidator))
            .await;

        // Create route matcher
        let route_matcher = Arc::new(RwLock::new(RouteMatcher::new(config.routes.clone(), None)?));

        // Create upstream pools and active health checkers
        let mut pools = HashMap::new();
        let mut health_check_runner = HealthCheckRunner::new();

        for (upstream_id, upstream_config) in &config.upstreams {
            let mut config_with_id = upstream_config.clone();
            config_with_id.id = upstream_id.clone();
            let pool = Arc::new(UpstreamPool::new(config_with_id.clone()).await?);
            pools.insert(upstream_id.clone(), pool);

            // Create active health checker if health check is configured
            if let Some(checker) = ActiveHealthChecker::new(&config_with_id) {
                health_check_runner.add_checker(checker);
            }
        }
        let upstream_pools = Registry::from_map(pools);
        let health_check_runner = Arc::new(health_check_runner);

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
        let metrics = Arc::new(sentinel_common::observability::RequestMetrics::new()?);

        // Create application state
        let app_state = Arc::new(AppState::new(Uuid::new_v4().to_string()));

        // Create reload coordinator
        let reload_coordinator = Arc::new(GracefulReloadCoordinator::new(
            Duration::from_secs(30), // Max drain time
        ));

        // Setup configuration reload subscription
        Self::setup_reload_handler(
            config_manager.clone(),
            route_matcher.clone(),
            upstream_pools.clone(),
        )
        .await;

        // Initialize service type components
        let (error_handlers, validators, static_servers) =
            Self::initialize_route_components(&config).await?;

        // Create builtin handler state
        let builtin_state = Arc::new(BuiltinHandlerState::new(
            env!("CARGO_PKG_VERSION").to_string(),
            app_state.instance_id.clone(),
        ));

        // Create log manager for file-based logging
        let log_manager = match LogManager::new(&config.observability.logging) {
            Ok(manager) => {
                if manager.access_log_enabled() {
                    info!("Access logging enabled");
                }
                if manager.error_log_enabled() {
                    info!("Error logging enabled");
                }
                if manager.audit_log_enabled() {
                    info!("Audit logging enabled");
                }
                Arc::new(manager)
            }
            Err(e) => {
                warn!(
                    "Failed to initialize log manager, file logging disabled: {}",
                    e
                );
                Arc::new(LogManager::disabled())
            }
        };

        // Register audit reload hook to log configuration changes
        {
            use crate::reload::AuditReloadHook;
            let audit_hook = AuditReloadHook::new(log_manager.clone());
            config_manager.add_hook(Box::new(audit_hook)).await;
            debug!("Registered audit reload hook");
        }

        // Start active health check runner in background
        if health_check_runner.checker_count() > 0 {
            let runner = health_check_runner.clone();
            tokio::spawn(async move {
                runner.run().await;
            });
            info!(
                "Started active health checking for {} upstreams",
                health_check_runner.checker_count()
            );
        }

        // Mark as ready
        app_state.set_ready(true);

        // Get trace ID format from config
        let trace_id_format = config.server.trace_id_format;

        // Initialize rate limit manager
        let rate_limit_manager = Arc::new(Self::initialize_rate_limiters(&config));

        // Initialize cache manager
        let cache_manager = Arc::new(Self::initialize_cache_manager(&config));

        Ok(Self {
            config_manager,
            route_matcher,
            upstream_pools,
            agent_manager,
            passive_health,
            metrics,
            app_state,
            reload_coordinator,
            error_handlers,
            validators,
            static_servers,
            builtin_state,
            log_manager,
            trace_id_format,
            health_check_runner,
            rate_limit_manager,
            cache_manager,
        })
    }

    /// Setup the configuration reload handler
    async fn setup_reload_handler(
        config_manager: Arc<ConfigManager>,
        route_matcher: Arc<RwLock<RouteMatcher>>,
        upstream_pools: Registry<UpstreamPool>,
    ) {
        let mut reload_rx = config_manager.subscribe();
        let config_manager_clone = config_manager.clone();

        tokio::spawn(async move {
            while let Ok(event) = reload_rx.recv().await {
                if let ReloadEvent::Applied { .. } = event {
                    // Reload routes and upstreams
                    let new_config = config_manager_clone.current();

                    // Update route matcher (sync parking_lot::RwLock)
                    if let Ok(new_matcher) = RouteMatcher::new(new_config.routes.clone(), None) {
                        *route_matcher.write() = new_matcher;
                        info!("Routes reloaded successfully");
                    }

                    // Update upstream pools
                    let mut new_pools = HashMap::new();
                    for (upstream_id, upstream_config) in &new_config.upstreams {
                        let mut config_with_id = upstream_config.clone();
                        config_with_id.id = upstream_id.clone();
                        match UpstreamPool::new(config_with_id).await {
                            Ok(pool) => {
                                new_pools.insert(upstream_id.clone(), Arc::new(pool));
                            }
                            Err(e) => {
                                error!("Failed to create upstream pool {}: {}", upstream_id, e);
                            }
                        }
                    }

                    // Gracefully swap pools
                    let old_pools = upstream_pools.replace(new_pools).await;

                    // Shutdown old pools after delay
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        for (name, pool) in old_pools {
                            info!("Shutting down old pool: {}", name);
                            pool.shutdown().await;
                        }
                    });
                }
            }
        });
    }

    /// Initialize route-specific components (error handlers, validators, static servers)
    async fn initialize_route_components(
        config: &Config,
    ) -> Result<(
        Registry<ErrorHandler>,
        Registry<SchemaValidator>,
        Registry<StaticFileServer>,
    )> {
        let mut error_handlers_map = HashMap::new();
        let mut validators_map = HashMap::new();
        let mut static_servers_map = HashMap::new();

        for route in &config.routes {
            info!(
                "Initializing components for route: {} with service type: {:?}",
                route.id, route.service_type
            );

            // Initialize error handler for each route
            if let Some(ref error_config) = route.error_pages {
                let handler =
                    ErrorHandler::new(route.service_type.clone(), Some(error_config.clone()));
                error_handlers_map.insert(route.id.clone(), Arc::new(handler));
                debug!("Initialized error handler for route: {}", route.id);
            } else {
                // Use default error handler for the service type
                let handler = ErrorHandler::new(route.service_type.clone(), None);
                error_handlers_map.insert(route.id.clone(), Arc::new(handler));
            }

            // Initialize schema validator for API routes
            if route.service_type == sentinel_config::ServiceType::Api {
                if let Some(ref api_schema) = route.api_schema {
                    match SchemaValidator::new(api_schema.clone()) {
                        Ok(validator) => {
                            validators_map.insert(route.id.clone(), Arc::new(validator));
                            info!("Initialized schema validator for route: {}", route.id);
                        }
                        Err(e) => {
                            warn!(
                                "Failed to initialize schema validator for route {}: {}",
                                route.id, e
                            );
                        }
                    }
                }
            }

            // Initialize static file server for static routes
            if route.service_type == sentinel_config::ServiceType::Static {
                if let Some(ref static_config) = route.static_files {
                    let server = StaticFileServer::new(static_config.clone());
                    static_servers_map.insert(route.id.clone(), Arc::new(server));
                    info!("Initialized static file server for route: {}", route.id);
                } else {
                    warn!(
                        "Static route {} has no static_files configuration",
                        route.id
                    );
                }
            }
        }

        Ok((
            Registry::from_map(error_handlers_map),
            Registry::from_map(validators_map),
            Registry::from_map(static_servers_map),
        ))
    }

    /// Get or generate trace ID from session
    pub(super) fn get_trace_id(&self, session: &pingora::proxy::Session) -> String {
        http_helpers::get_or_create_trace_id(session, self.trace_id_format)
    }

    /// Initialize rate limiters from configuration
    fn initialize_rate_limiters(config: &Config) -> RateLimitManager {
        use sentinel_config::RateLimitAction;

        let manager = RateLimitManager::new();

        for route in &config.routes {
            // Check for rate limit in route policies
            if let Some(ref rate_limit) = route.policies.rate_limit {
                let rl_config = RateLimitConfig {
                    max_rps: rate_limit.requests_per_second,
                    burst: rate_limit.burst,
                    key: rate_limit.key.clone(),
                    action: RateLimitAction::Reject,
                    status_code: 429,
                    message: None,
                    backend: sentinel_config::RateLimitBackend::Local,
                };
                manager.register_route(&route.id, rl_config);
                info!(
                    route_id = %route.id,
                    max_rps = rate_limit.requests_per_second,
                    burst = rate_limit.burst,
                    key = ?rate_limit.key,
                    "Registered rate limiter for route"
                );
            }

            // Also check for rate limit filters in the filter chain
            for filter_id in &route.filters {
                if let Some(filter_config) = config.filters.get(filter_id) {
                    if let sentinel_config::Filter::RateLimit(ref rl_filter) = filter_config.filter
                    {
                        let rl_config = RateLimitConfig {
                            max_rps: rl_filter.max_rps,
                            burst: rl_filter.burst,
                            key: rl_filter.key.clone(),
                            action: rl_filter.on_limit.clone(),
                            status_code: rl_filter.status_code,
                            message: rl_filter.limit_message.clone(),
                            backend: rl_filter.backend.clone(),
                        };
                        manager.register_route(&route.id, rl_config);
                        info!(
                            route_id = %route.id,
                            filter_id = %filter_id,
                            max_rps = rl_filter.max_rps,
                            backend = ?rl_filter.backend,
                            "Registered rate limiter from filter for route"
                        );
                    }
                }
            }
        }

        if manager.route_count() > 0 {
            info!(
                route_count = manager.route_count(),
                "Rate limiting initialized"
            );
        }

        manager
    }

    /// Initialize cache manager from configuration
    fn initialize_cache_manager(config: &Config) -> CacheManager {
        let manager = CacheManager::new();

        let mut enabled_count = 0;

        for route in &config.routes {
            // API routes: caching disabled by default (responses often dynamic)
            if route.service_type == sentinel_config::ServiceType::Api {
                let cache_config = CacheConfig {
                    enabled: false, // Disabled until explicitly configured via KDL
                    default_ttl_secs: 60,
                    ..Default::default()
                };
                manager.register_route(&route.id, cache_config);
            }

            // Static routes: enable caching by default (assets are typically cacheable)
            if route.service_type == sentinel_config::ServiceType::Static {
                let cache_config = CacheConfig {
                    enabled: true, // Enable by default for static routes
                    default_ttl_secs: 3600,
                    max_size_bytes: 50 * 1024 * 1024, // 50MB for static
                    stale_while_revalidate_secs: 60,
                    stale_if_error_secs: 300,
                    ..Default::default()
                };
                manager.register_route(&route.id, cache_config);
                enabled_count += 1;
                info!(
                    route_id = %route.id,
                    default_ttl_secs = 3600,
                    "HTTP caching enabled for static route"
                );
            }

            // Web routes: disable by default (HTML often personalized)
            if route.service_type == sentinel_config::ServiceType::Web {
                let cache_config = CacheConfig {
                    enabled: false, // Disabled until explicitly configured
                    default_ttl_secs: 300,
                    ..Default::default()
                };
                manager.register_route(&route.id, cache_config);
            }
        }

        if enabled_count > 0 {
            info!(enabled_routes = enabled_count, "HTTP caching initialized");
        } else {
            debug!("HTTP cache manager initialized (no routes with caching enabled)");
        }

        manager
    }

    /// Apply security headers to response
    pub(super) fn apply_security_headers(
        &self,
        header: &mut ResponseHeader,
    ) -> Result<(), Box<Error>> {
        header.insert_header("X-Content-Type-Options", "nosniff")?;
        header.insert_header("X-Frame-Options", "DENY")?;
        header.insert_header("X-XSS-Protection", "1; mode=block")?;
        header.insert_header("Referrer-Policy", "strict-origin-when-cross-origin")?;
        header.remove_header("Server");
        header.remove_header("X-Powered-By");
        Ok(())
    }
}
