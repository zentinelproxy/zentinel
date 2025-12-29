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
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sentinel_common::Registry;

use crate::agents::AgentManager;
use crate::app::AppState;
use crate::builtin_handlers::BuiltinHandlerState;
use crate::errors::ErrorHandler;
use crate::health::PassiveHealthChecker;
use crate::http_helpers;
use crate::logging::{LogManager, SharedLogManager};
use crate::reload::{
    ConfigManager, GracefulReloadCoordinator, ReloadEvent, RouteValidator, UpstreamValidator,
};
use crate::routing::RouteMatcher;
use crate::static_files::StaticFileServer;
use crate::upstream::UpstreamPool;
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

        // Create upstream pools (skip for static routes as they don't need upstreams)
        let mut pools = HashMap::new();
        for (upstream_id, upstream_config) in &config.upstreams {
            let mut config_with_id = upstream_config.clone();
            config_with_id.id = upstream_id.clone();
            let pool = Arc::new(UpstreamPool::new(config_with_id).await?);
            pools.insert(upstream_id.clone(), pool);
        }
        let upstream_pools = Registry::from_map(pools);

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

        // Mark as ready
        app_state.set_ready(true);

        // Get trace ID format from config
        let trace_id_format = config.server.trace_id_format;

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
                match event {
                    ReloadEvent::Applied { .. } => {
                        // Reload routes and upstreams
                        let new_config = config_manager_clone.current();

                        // Update route matcher
                        if let Ok(new_matcher) = RouteMatcher::new(new_config.routes.clone(), None)
                        {
                            *route_matcher.write().await = new_matcher;
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
                                    error!(
                                        "Failed to create upstream pool {}: {}",
                                        upstream_id, e
                                    );
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
                    _ => {}
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
