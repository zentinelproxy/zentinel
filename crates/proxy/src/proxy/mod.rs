//! Zentinel Proxy Core Implementation
//!
//! This module contains the main ZentinelProxy struct and its implementation,
//! split across several submodules for maintainability:
//!
//! - `context`: Request context maintained throughout the request lifecycle
//! - `handlers`: Helper methods for handling different route types
//! - `http_trait`: ProxyHttp trait implementation for Pingora

mod context;
mod fallback;
mod fallback_metrics;
pub(crate) mod filters;
mod handlers;
mod http_trait;
mod model_routing;
mod model_routing_metrics;

pub use context::{FallbackReason, RequestContext};
pub use fallback::{FallbackDecision, FallbackEvaluator};
pub use fallback_metrics::{get_fallback_metrics, init_fallback_metrics, FallbackMetrics};
pub use model_routing::{extract_model_from_headers, find_upstream_for_model, ModelRoutingResult};
pub use model_routing_metrics::{
    get_model_routing_metrics, init_model_routing_metrics, ModelRoutingMetrics,
};

use anyhow::{Context, Result};
use parking_lot::RwLock;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use zentinel_common::ids::{QualifiedId, Scope};
use zentinel_common::{Registry, ScopedMetrics, ScopedRegistry};

use crate::agents::AgentManager;
use crate::app::AppState;
use crate::builtin_handlers::BuiltinHandlerState;
use crate::cache::{CacheConfig, CacheManager};
use crate::errors::ErrorHandler;
use crate::geo_filter::{GeoDatabaseWatcher, GeoFilterManager};
use crate::health::PassiveHealthChecker;
use crate::http_helpers;
use crate::inference::InferenceRateLimitManager;
use crate::logging::{LogManager, SharedLogManager};
use crate::rate_limit::{RateLimitConfig, RateLimitManager};
use crate::reload::{
    ConfigManager, GracefulReloadCoordinator, ReloadEvent, RouteValidator, UpstreamValidator,
};
use crate::routing::RouteMatcher;
use crate::scoped_routing::ScopedRouteMatcher;
use crate::static_files::StaticFileServer;
use crate::upstream::{ActiveHealthChecker, HealthCheckRunner, UpstreamPool};
use crate::validation::SchemaValidator;

use zentinel_common::TraceIdFormat;
use zentinel_config::{Config, FlattenedConfig};

/// Main proxy service implementing Pingora's ProxyHttp trait
pub struct ZentinelProxy {
    /// Configuration manager with hot reload
    pub config_manager: Arc<ConfigManager>,
    /// Route matcher (global routes only, for backward compatibility)
    pub(super) route_matcher: Arc<RwLock<RouteMatcher>>,
    /// Scoped route matcher (namespace/service aware)
    pub(super) scoped_route_matcher: Arc<tokio::sync::RwLock<ScopedRouteMatcher>>,
    /// Upstream pools (keyed by upstream ID, global only)
    pub(super) upstream_pools: Registry<UpstreamPool>,
    /// Scoped upstream pools (namespace/service aware)
    pub(super) scoped_upstream_pools: ScopedRegistry<UpstreamPool>,
    /// Agent manager for external processing
    pub(super) agent_manager: Arc<AgentManager>,
    /// Passive health checker
    pub(super) passive_health: Arc<PassiveHealthChecker>,
    /// Metrics collector
    pub(super) metrics: Arc<zentinel_common::observability::RequestMetrics>,
    /// Scoped metrics collector (with namespace/service labels)
    pub(super) scoped_metrics: Arc<ScopedMetrics>,
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
    /// GeoIP filter manager
    pub(super) geo_filter_manager: Arc<GeoFilterManager>,
    /// Inference rate limit manager (token-based rate limiting for LLM/AI routes)
    pub(super) inference_rate_limit_manager: Arc<InferenceRateLimitManager>,
    /// Warmth tracker for cold model detection on inference routes
    pub(super) warmth_tracker: Arc<crate::health::WarmthTracker>,
    /// Guardrail processor for semantic inspection (prompt injection, PII detection)
    pub(super) guardrail_processor: Arc<crate::inference::GuardrailProcessor>,
    /// ACME challenge manager for HTTP-01 challenge handling
    /// Present only when ACME is configured for at least one listener
    pub acme_challenges: Option<Arc<crate::acme::ChallengeManager>>,
    /// ACME client for certificate management
    /// Present only when ACME is configured
    pub acme_client: Option<Arc<crate::acme::AcmeClient>>,
}

impl ZentinelProxy {
    /// Create new proxy instance
    ///
    /// If config_path is None, uses the embedded default configuration.
    /// Note: Tracing must be initialized by the caller before calling this function.
    pub async fn new(config_path: Option<&str>) -> Result<Self> {
        info!("Starting Zentinel Proxy");

        // Load initial configuration
        let (config, effective_config_path) = match config_path {
            Some(path) => {
                let cfg = Config::from_file(path).context("Failed to load configuration file")?;
                (cfg, path.to_string())
            }
            None => {
                let cfg = Config::default_embedded()
                    .context("Failed to load embedded default configuration")?;
                // Use a zentinel path to indicate embedded config
                (cfg, "_embedded_".to_string())
            }
        };

        config
            .validate()
            .context("Initial configuration validation failed")?;

        // Configure global cache storage (must be done before cache is accessed)
        if let Some(ref cache_config) = config.cache {
            info!(
                max_size_mb = cache_config.max_size_bytes / 1024 / 1024,
                backend = ?cache_config.backend,
                "Configuring HTTP cache storage"
            );
            crate::cache::configure_cache(cache_config.clone());
            crate::cache::init_disk_cache_state().await;
        }

        // Create configuration manager
        let config_manager =
            Arc::new(ConfigManager::new(&effective_config_path, config.clone()).await?);

        // Add validators
        config_manager.add_validator(Box::new(RouteValidator)).await;
        config_manager
            .add_validator(Box::new(UpstreamValidator))
            .await;

        // Create route matcher (global routes only)
        let route_matcher = Arc::new(RwLock::new(RouteMatcher::new(config.routes.clone(), None)?));

        // Flatten config for namespace/service resources
        let flattened = config.flatten();

        // Create scoped route matcher
        let scoped_route_matcher = Arc::new(tokio::sync::RwLock::new(
            ScopedRouteMatcher::from_flattened(&flattened)
                .await
                .context("Failed to create scoped route matcher")?,
        ));

        // Create upstream pools and active health checkers (global only)
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

        // Create scoped upstream pools from flattened config
        let scoped_upstream_pools =
            Self::create_scoped_upstream_pools(&flattened, &mut health_check_runner).await?;

        let health_check_runner = Arc::new(health_check_runner);

        // Create passive health checker
        let passive_health = Arc::new(PassiveHealthChecker::new(
            0.5,  // 50% failure rate threshold
            100,  // Window size
            None, // Will be linked to active health checkers
        ));

        // Create agent manager (per-agent queue isolation)
        let agent_manager = Arc::new(AgentManager::new(config.agents.clone()).await?);
        agent_manager.initialize().await?;

        // Create metrics collectors
        let metrics = Arc::new(zentinel_common::observability::RequestMetrics::new()?);
        let scoped_metrics =
            Arc::new(ScopedMetrics::new().context("Failed to create scoped metrics collector")?);

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
            scoped_route_matcher.clone(),
            scoped_upstream_pools.clone(),
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

        // Initialize rate limit manager
        let rate_limit_manager = Arc::new(Self::initialize_rate_limiters(&config));

        // Initialize inference rate limit manager (for token-based LLM rate limiting)
        let inference_rate_limit_manager =
            Arc::new(Self::initialize_inference_rate_limiters(&config));

        // Initialize warmth tracker for cold model detection
        let warmth_tracker = Arc::new(crate::health::WarmthTracker::with_defaults());

        // Initialize guardrail processor for semantic inspection
        let guardrail_processor = Arc::new(crate::inference::GuardrailProcessor::new(
            agent_manager.clone(),
        ));

        // Initialize geo filter manager
        let geo_filter_manager = Arc::new(Self::initialize_geo_filters(&config));

        // Start periodic cleanup task for rate limiters and geo caches
        Self::spawn_cleanup_task(rate_limit_manager.clone(), geo_filter_manager.clone());

        // Start geo database file watcher for hot reload
        Self::spawn_geo_database_watcher(geo_filter_manager.clone());

        // Mark as ready
        app_state.set_ready(true);

        // Get trace ID format from config
        let trace_id_format = config.server.trace_id_format;

        // Initialize cache manager
        let cache_manager = Arc::new(Self::initialize_cache_manager(&config));

        // Initialize fallback metrics (best-effort, log warning if fails)
        if let Err(e) = init_fallback_metrics() {
            warn!("Failed to initialize fallback metrics: {}", e);
        }

        // Initialize model routing metrics (best-effort, log warning if fails)
        if let Err(e) = init_model_routing_metrics() {
            warn!("Failed to initialize model routing metrics: {}", e);
        }

        Ok(Self {
            config_manager,
            route_matcher,
            scoped_route_matcher,
            upstream_pools,
            scoped_upstream_pools,
            agent_manager,
            passive_health,
            metrics,
            scoped_metrics,
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
            geo_filter_manager,
            inference_rate_limit_manager,
            warmth_tracker,
            guardrail_processor,
            // ACME challenge manager - initialized later if ACME is configured
            acme_challenges: None,
            acme_client: None,
        })
    }

    /// Setup the configuration reload handler
    async fn setup_reload_handler(
        config_manager: Arc<ConfigManager>,
        route_matcher: Arc<RwLock<RouteMatcher>>,
        upstream_pools: Registry<UpstreamPool>,
        scoped_route_matcher: Arc<tokio::sync::RwLock<ScopedRouteMatcher>>,
        scoped_upstream_pools: ScopedRegistry<UpstreamPool>,
    ) {
        let mut reload_rx = config_manager.subscribe();
        let config_manager_clone = config_manager.clone();

        tokio::spawn(async move {
            while let Ok(event) = reload_rx.recv().await {
                if let ReloadEvent::Applied { .. } = event {
                    // Reload routes and upstreams
                    let new_config = config_manager_clone.current();
                    let flattened = new_config.flatten();

                    // Update route matcher (sync parking_lot::RwLock)
                    if let Ok(new_matcher) = RouteMatcher::new(new_config.routes.clone(), None) {
                        *route_matcher.write() = new_matcher;
                        info!("Global routes reloaded successfully");
                    }

                    // Update scoped route matcher
                    if let Err(e) = scoped_route_matcher
                        .write()
                        .await
                        .load_from_flattened(&flattened)
                        .await
                    {
                        error!("Failed to reload scoped routes: {}", e);
                    } else {
                        info!(
                            "Scoped routes reloaded ({} scopes)",
                            scoped_route_matcher.read().await.scope_count().await
                        );
                    }

                    // Update global upstream pools
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

                    // Gracefully swap global pools
                    let old_pools = upstream_pools.replace(new_pools).await;

                    // Update scoped upstream pools
                    let new_scoped_pools = Self::build_scoped_pools_list(&flattened).await;
                    let old_scoped_pools =
                        scoped_upstream_pools.replace_all(new_scoped_pools).await;

                    info!(
                        "Scoped upstream pools reloaded ({} pools)",
                        scoped_upstream_pools.len().await
                    );

                    // Shutdown old pools after delay
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_secs(60)).await;

                        // Shutdown old global pools
                        for (name, pool) in old_pools {
                            info!("Shutting down old global pool: {}", name);
                            pool.shutdown().await;
                        }

                        // Shutdown old scoped pools
                        for (name, pool) in old_scoped_pools {
                            info!("Shutting down old scoped pool: {}", name);
                            pool.shutdown().await;
                        }
                    });
                }
            }
        });
    }

    /// Create scoped upstream pools from flattened config
    async fn create_scoped_upstream_pools(
        flattened: &FlattenedConfig,
        health_check_runner: &mut HealthCheckRunner,
    ) -> Result<ScopedRegistry<UpstreamPool>> {
        let registry = ScopedRegistry::new();

        for (qid, upstream_config) in &flattened.upstreams {
            let mut config_with_id = upstream_config.clone();
            config_with_id.id = qid.canonical();

            let pool = Arc::new(
                UpstreamPool::new(config_with_id.clone())
                    .await
                    .with_context(|| {
                        format!("Failed to create upstream pool '{}'", qid.canonical())
                    })?,
            );

            // Track exports
            let is_exported = flattened
                .exported_upstreams
                .contains_key(&upstream_config.id);

            if is_exported {
                registry.insert_exported(qid.clone(), pool).await;
            } else {
                registry.insert(qid.clone(), pool).await;
            }

            // Create active health checker if configured
            if let Some(checker) = ActiveHealthChecker::new(&config_with_id) {
                health_check_runner.add_checker(checker);
            }

            debug!(
                upstream_id = %qid.canonical(),
                scope = ?qid.scope,
                exported = is_exported,
                "Created scoped upstream pool"
            );
        }

        info!("Created {} scoped upstream pools", registry.len().await);

        Ok(registry)
    }

    /// Build list of scoped pools for atomic replacement
    async fn build_scoped_pools_list(
        flattened: &FlattenedConfig,
    ) -> Vec<(QualifiedId, Arc<UpstreamPool>, bool)> {
        let mut result = Vec::new();

        for (qid, upstream_config) in &flattened.upstreams {
            let mut config_with_id = upstream_config.clone();
            config_with_id.id = qid.canonical();

            match UpstreamPool::new(config_with_id).await {
                Ok(pool) => {
                    let is_exported = flattened
                        .exported_upstreams
                        .contains_key(&upstream_config.id);
                    result.push((qid.clone(), Arc::new(pool), is_exported));
                }
                Err(e) => {
                    error!(
                        "Failed to create scoped upstream pool {}: {}",
                        qid.canonical(),
                        e
                    );
                }
            }
        }

        result
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
            if route.service_type == zentinel_config::ServiceType::Api {
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
            if route.service_type == zentinel_config::ServiceType::Static {
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
        use zentinel_config::RateLimitAction;

        // Create manager with global rate limit if configured
        let manager = if let Some(ref global) = config.rate_limits.global {
            info!(
                max_rps = global.max_rps,
                burst = global.burst,
                key = ?global.key,
                "Initializing global rate limiter"
            );
            RateLimitManager::with_global_limit(global.max_rps, global.burst)
        } else {
            RateLimitManager::new()
        };

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
                    backend: zentinel_config::RateLimitBackend::Local,
                    max_delay_ms: 5000, // Default for policy-based rate limits
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
                    if let zentinel_config::Filter::RateLimit(ref rl_filter) = filter_config.filter
                    {
                        let rl_config = RateLimitConfig {
                            max_rps: rl_filter.max_rps,
                            burst: rl_filter.burst,
                            key: rl_filter.key.clone(),
                            action: rl_filter.on_limit.clone(),
                            status_code: rl_filter.status_code,
                            message: rl_filter.limit_message.clone(),
                            backend: rl_filter.backend.clone(),
                            max_delay_ms: rl_filter.max_delay_ms,
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

    /// Initialize inference rate limiters from configuration
    ///
    /// This creates token-based rate limiters for routes with `service-type "inference"`
    /// and inference config blocks.
    fn initialize_inference_rate_limiters(config: &Config) -> InferenceRateLimitManager {
        let manager = InferenceRateLimitManager::new();

        for route in &config.routes {
            // Only initialize for inference service type routes with inference config
            if route.service_type == zentinel_config::ServiceType::Inference {
                if let Some(ref inference_config) = route.inference {
                    manager.register_route(&route.id, inference_config);
                }
            }
        }

        if manager.route_count() > 0 {
            info!(
                route_count = manager.route_count(),
                "Inference rate limiting initialized"
            );
        }

        manager
    }

    /// Initialize cache manager from configuration
    fn initialize_cache_manager(config: &Config) -> CacheManager {
        let manager = CacheManager::new();

        let mut enabled_count = 0;

        for route in &config.routes {
            // Use per-route cache config if present, otherwise fall back to service-type defaults
            let cache_config = if let Some(ref rc) = route.policies.cache {
                CacheConfig {
                    enabled: rc.enabled,
                    default_ttl_secs: rc.default_ttl_secs,
                    max_size_bytes: rc.max_size_bytes,
                    cache_private: rc.cache_private,
                    stale_while_revalidate_secs: rc.stale_while_revalidate_secs,
                    stale_if_error_secs: rc.stale_if_error_secs,
                    cacheable_methods: rc.cacheable_methods.clone(),
                    cacheable_status_codes: rc.cacheable_status_codes.clone(),
                }
            } else {
                match route.service_type {
                    zentinel_config::ServiceType::Static => CacheConfig {
                        enabled: true,
                        default_ttl_secs: 3600,
                        max_size_bytes: 50 * 1024 * 1024, // 50MB for static
                        stale_while_revalidate_secs: 60,
                        stale_if_error_secs: 300,
                        ..Default::default()
                    },
                    zentinel_config::ServiceType::Api => CacheConfig {
                        enabled: false,
                        default_ttl_secs: 60,
                        ..Default::default()
                    },
                    zentinel_config::ServiceType::Web => CacheConfig {
                        enabled: false,
                        default_ttl_secs: 300,
                        ..Default::default()
                    },
                    _ => CacheConfig::default(),
                }
            };

            if cache_config.enabled {
                enabled_count += 1;
                info!(
                    route_id = %route.id,
                    default_ttl_secs = cache_config.default_ttl_secs,
                    from_config = route.policies.cache.is_some(),
                    "HTTP caching enabled for route"
                );
            }
            manager.register_route(&route.id, cache_config);
        }

        if enabled_count > 0 {
            info!(enabled_routes = enabled_count, "HTTP caching initialized");
        } else {
            debug!("HTTP cache manager initialized (no routes with caching enabled)");
        }

        manager
    }

    /// Initialize geo filters from configuration
    fn initialize_geo_filters(config: &Config) -> GeoFilterManager {
        let manager = GeoFilterManager::new();

        for (filter_id, filter_config) in &config.filters {
            if let zentinel_config::Filter::Geo(ref geo_filter) = filter_config.filter {
                match manager.register_filter(filter_id, geo_filter.clone()) {
                    Ok(_) => {
                        info!(
                            filter_id = %filter_id,
                            database_path = %geo_filter.database_path,
                            action = ?geo_filter.action,
                            countries_count = geo_filter.countries.len(),
                            "Registered geo filter"
                        );
                    }
                    Err(e) => {
                        error!(
                            filter_id = %filter_id,
                            error = %e,
                            "Failed to register geo filter"
                        );
                    }
                }
            }
        }

        let filter_ids = manager.filter_ids();
        if !filter_ids.is_empty() {
            info!(
                filter_count = filter_ids.len(),
                filter_ids = ?filter_ids,
                "GeoIP filtering initialized"
            );
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

    /// Spawn background task to periodically clean up idle rate limiters and expired geo caches
    fn spawn_cleanup_task(
        rate_limit_manager: Arc<RateLimitManager>,
        geo_filter_manager: Arc<GeoFilterManager>,
    ) {
        // Cleanup interval: 5 minutes
        const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            // First tick completes immediately; skip it
            interval.tick().await;

            loop {
                interval.tick().await;

                // Clean up rate limiters (removes entries when pool exceeds max size)
                rate_limit_manager.cleanup();

                // Clean up expired geo filter caches
                geo_filter_manager.clear_expired_caches();

                debug!("Periodic cleanup completed");
            }
        });

        info!(
            interval_secs = CLEANUP_INTERVAL.as_secs(),
            "Started periodic cleanup task"
        );
    }

    /// Spawn background task to watch geo database files for changes
    fn spawn_geo_database_watcher(geo_filter_manager: Arc<GeoFilterManager>) {
        let watcher = Arc::new(GeoDatabaseWatcher::new(geo_filter_manager));

        // Try to start watching
        match watcher.start_watching() {
            Ok(mut rx) => {
                let watcher_clone = watcher.clone();
                tokio::spawn(async move {
                    // Debounce interval
                    const DEBOUNCE_MS: u64 = 500;

                    while let Some(path) = rx.recv().await {
                        // Debounce rapid changes (e.g., temp file then rename)
                        tokio::time::sleep(Duration::from_millis(DEBOUNCE_MS)).await;

                        // Drain any additional events for the same path during debounce
                        while rx.try_recv().is_ok() {}

                        // Handle the change
                        watcher_clone.handle_change(&path);
                    }
                });

                info!("Started geo database file watcher");
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to start geo database file watcher, auto-reload disabled"
                );
            }
        }
    }
}
