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
mod forwarded;
mod handlers;
mod http_trait;
pub(crate) mod listener_addr;
mod model_routing;
mod model_routing_metrics;
mod sync_filter;

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
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use zentinel_common::ids::Scope;
use zentinel_common::{Registry, ScopedMetrics};

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
    ConfigManager, GracefulReloadCoordinator, ReloadEvent, RouteMatcherValidator, RouteValidator,
    UpstreamValidator,
};
use crate::routing::RouteMatcher;

use crate::static_files::StaticFileServer;
use crate::upstream::{HealthCheckRunner, UpstreamPool};
use crate::validation::SchemaValidator;
use listener_addr::ListenerMatchers;

use zentinel_common::TraceIdFormat;
use zentinel_config::Config;

/// Main proxy service implementing Pingora's ProxyHttp trait
pub struct ZentinelProxy {
    /// Configuration manager with hot reload
    pub config_manager: Arc<ConfigManager>,
    /// Route matcher of the global (unbound) listeners: the global routes,
    /// and those of every namespace and service without a listener of its own
    /// (#548).
    pub(super) route_matcher: Arc<RwLock<RouteMatcher>>,
    /// Per-listener route matchers for listeners bound to a namespace or a
    /// service, resolved from the accepted connection's local address. A
    /// request arriving on one of these listeners is matched only against the
    /// routes that scope serves (isolated from the global set). Listeners
    /// absent from this map use [`Self::route_matcher`].
    pub(super) listener_matchers: Arc<RwLock<ListenerMatchers>>,
    /// Upstream pools, keyed by upstream id: a global upstream by its own id,
    /// a namespace's or service's by its qualified id (`ns:name`,
    /// `ns:svc:name`), which is what a lowered route names (#548).
    pub(super) upstream_pools: Registry<UpstreamPool>,
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
    /// Requests in flight, proxy-wide and per namespace, for
    /// `limits { max-in-flight-requests }`. Lives as long as the proxy, not a
    /// config, so a reload keeps counting the requests already running.
    pub(super) in_flight: Arc<zentinel_common::limits::InFlightLimiter>,
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
    /// ACME clients for certificate management
    /// Present only when ACME is configured
    pub acme_clients: Vec<Arc<crate::acme::AcmeClient>>,
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

        // Everything below runs on the configuration with namespace and
        // service resources moved to the top level under their qualified ids,
        // so scoped routes, upstreams, filters and agents are built like
        // global ones (#548). The config manager keeps this lowered form, so
        // request-time lookups see the same ids.
        let (config, scope_problems) = config.lower_scopes_reporting();
        for problem in scope_problems
            .iter()
            .chain(&crate::routing::unservable_scoped_routes(&config))
        {
            warn!("{problem}");
        }

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

        Self::add_reload_validators(&config_manager).await;

        // Route matcher of the global listeners
        let route_matcher = Arc::new(RwLock::new(crate::routing::compile_route_set(
            &config,
            &Scope::Global,
            crate::routing::routes_served_on(&config, &Scope::Global),
        )?));

        // Build per-listener route matchers for listeners bound to a namespace
        // or service (empty unless any listener is).
        let listener_matchers = Arc::new(RwLock::new(Self::build_listener_matchers(&config)?));

        // Active health checks are started further down, once. The runner
        // exists before the pools so each pool can attach to its upstream's
        // health results.
        let health_check_runner = Arc::new(HealthCheckRunner::new());

        // Create upstream pools: global ones and, lowered, scoped ones. Each
        // pool is built once; the separate registry of scoped pools that
        // used to be built from the flattened config held a second copy of
        // every pool (global ones included) that no request ever reached.
        let mut pools = HashMap::new();
        for (upstream_id, upstream_config) in &config.upstreams {
            let mut config_with_id = upstream_config.clone();
            config_with_id.id = upstream_id.clone();
            let pool = UpstreamPool::new(config_with_id)
                .await?
                .with_active_health(health_check_runner.view(upstream_id));
            pools.insert(upstream_id.clone(), Arc::new(pool));
        }
        let upstream_pools = Registry::from_map(pools);

        // Keep discovery-backed pools up to date. The supervisor reads the
        // registry on each tick, so it also covers pools installed by a later
        // config reload; it is a no-op when no upstream uses discovery.
        crate::upstream::discovery_refresh::spawn(upstream_pools.clone());

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

        // Initialize rate limit manager. Built before the reload handler,
        // which rebuilds its limiters from every reloaded config.
        let rate_limit_manager = Arc::new(Self::initialize_rate_limiters(&config));

        // Setup configuration reload subscription

        Self::setup_reload_handler(
            config_manager.clone(),
            route_matcher.clone(),
            listener_matchers.clone(),
            upstream_pools.clone(),
            health_check_runner.clone(),
            rate_limit_manager.clone(),
            agent_manager.clone(),
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

        // Create log manager for file-based logging. An access or error log
        // that cannot be opened is reported by `LogManager::new` and left off;
        // a configured audit log that cannot be opened stops startup.
        let log_manager = LogManager::new(&config.observability.logging)?;
        if log_manager.access_log_enabled() {
            info!("Access logging enabled");
        }
        if log_manager.error_log_enabled() {
            info!("Error logging enabled");
        }
        if log_manager.audit_log_enabled() {
            info!("Audit logging enabled");
        }
        let log_manager = Arc::new(log_manager);

        // Register audit reload hook to log configuration changes
        {
            use crate::reload::AuditReloadHook;
            let audit_hook = AuditReloadHook::new(log_manager.clone());
            config_manager.add_hook(Box::new(audit_hook)).await;
            debug!("Registered audit reload hook");
        }

        // Load added and changed agents before a new configuration becomes
        // current, so no filter in it names an agent that is not loaded.
        config_manager
            .add_hook(Box::new(crate::agents::AgentReloadHook::new(
                agent_manager.clone(),
            )))
            .await;

        // Start active health checking (one probe loop per upstream)
        health_check_runner.apply(Self::health_check_upstreams(&config));
        if health_check_runner.checker_count() > 0 {
            info!(
                upstreams = ?health_check_runner.upstream_ids(),
                "Started active health checking for {} upstreams",
                health_check_runner.checker_count()
            );
        }

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

        // Initialize TLS metrics (best-effort, log warning if fails)
        if let Err(e) = crate::tls_metrics::init_tls_metrics() {
            warn!("Failed to initialize TLS metrics: {}", e);
        }

        Ok(Self {
            config_manager,
            route_matcher,
            listener_matchers,
            upstream_pools,
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
            in_flight: Arc::new(zentinel_common::limits::InFlightLimiter::new()),
            cache_manager,
            geo_filter_manager,
            inference_rate_limit_manager,
            warmth_tracker,
            guardrail_processor,
            // ACME challenge manager - initialized later if ACME is configured
            acme_challenges: None,
            acme_clients: Vec::new(),
        })
    }

    /// Shared HTTP cache statistics.
    ///
    /// Exposed so the standalone metrics server can include cache counters in
    /// its Prometheus output, matching the builtin `/metrics` route handler.
    pub fn http_cache_stats(&self) -> Arc<crate::cache::HttpCacheStats> {
        self.cache_manager.stats()
    }

    /// The validators every reload must pass before its configuration is
    /// stored.
    async fn add_reload_validators(config_manager: &ConfigManager) {
        config_manager.add_validator(Box::new(RouteValidator)).await;
        // The route matchers the reload handler builds must compile, or the
        // reload would be stored and then only half applied (#577).
        config_manager
            .add_validator(Box::new(RouteMatcherValidator))
            .await;
        config_manager
            .add_validator(Box::new(UpstreamValidator))
            .await;
    }

    /// Build per-listener route matchers for listeners bound to a namespace
    /// or a service.
    ///
    /// `config` is the lowered configuration (see
    /// [`Config::lower_scopes`]). A listener bound to a scope -- a top-level
    /// listener with `namespace`, or one declared in a namespace or service --
    /// serves the routes [`Config::routes_served_on`] gives for that scope, in
    /// isolation from the global ones. Global listeners are omitted: they use
    /// the global matcher. Listeners of one scope share one matcher.
    ///
    /// Fails if the route set of any scope does not compile. It used to log
    /// and leave that listener serving no routes at all.
    fn build_listener_matchers(
        config: &Config,
    ) -> std::result::Result<ListenerMatchers, crate::routing::RouteSetError> {
        let mut by_scope: HashMap<Scope, Arc<RouteMatcher>> = HashMap::new();
        for (scope, routes) in crate::routing::route_sets(config) {
            if scope.is_global() {
                continue;
            }
            let route_count = routes.len();
            let matcher = crate::routing::compile_route_set(config, &scope, routes)?;
            info!(
                scope = %scope,
                routes = route_count,
                "Compiled route set of a namespace or service listener"
            );
            by_scope.insert(scope, Arc::new(matcher));
        }

        let mut matchers = ListenerMatchers::default();
        for listener in &config.listeners {
            let scope = listener.scope();
            let Some(matcher) = by_scope.get(&scope) else {
                continue;
            };
            info!(
                listener_id = %listener.id,
                address = %listener.address,
                scope = %scope,
                "Listener bound to the route set of its scope"
            );
            if !matchers.insert(&listener.address, Arc::clone(matcher)) {
                error!(
                    listener_id = %listener.id,
                    address = %listener.address,
                    "Listener address is not a socket address; the routes of its scope \
                     will not be served on it"
                );
            }
        }
        Ok(matchers)
    }

    /// Setup the configuration reload handler
    async fn setup_reload_handler(
        config_manager: Arc<ConfigManager>,
        route_matcher: Arc<RwLock<RouteMatcher>>,
        listener_matchers: Arc<RwLock<ListenerMatchers>>,
        upstream_pools: Registry<UpstreamPool>,
        health_check_runner: Arc<HealthCheckRunner>,
        rate_limit_manager: Arc<RateLimitManager>,
        agent_manager: Arc<AgentManager>,
    ) {
        let mut reload_rx = config_manager.subscribe();
        let config_manager_clone = config_manager.clone();

        tokio::spawn(async move {
            loop {
                // A rollback changes `current()` just as a reload does, so
                // everything below is re-synced to it as well (#577).
                let rolled_back = match reload_rx.recv().await {
                    Ok(ReloadEvent::Applied { .. }) => false,
                    Ok(ReloadEvent::RolledBack { reason, .. }) => {
                        info!(%reason, "Configuration rolled back, re-applying it");
                        true
                    }
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Reload handler lagged by {n} events, applying latest config");
                        // Fall through to reload with the latest config
                        false
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                {
                    // Reload routes and upstreams. The config manager holds
                    // the lowered configuration, so namespace and service
                    // routes, upstreams and filters are rebuilt here too.
                    let new_config = config_manager_clone.current();

                    // Compile every route set FIRST (most critical for
                    // traffic), and change nothing unless all of them compile.
                    // `RouteMatcherValidator` rejects such a configuration
                    // before it is stored, so this is a backstop: hand
                    // `current()` back to the previous configuration, whose
                    // `RolledBack` event re-syncs everything to it.
                    let global_routes =
                        crate::routing::routes_served_on(&new_config, &Scope::Global);
                    let global_route_count = global_routes.len();
                    let compiled = crate::routing::compile_route_set(
                        &new_config,
                        &Scope::Global,
                        global_routes,
                    )
                    .and_then(|global| Ok((global, Self::build_listener_matchers(&new_config)?)));
                    let (new_matcher, new_listener_matchers) = match compiled {
                        Ok(compiled) => compiled,
                        // Already the previous configuration: rolling back
                        // again would loop.
                        Err(e) if rolled_back => {
                            error!(
                                error = %e,
                                "Rolled-back configuration does not compile; routes, rate \
                                 limiters, health checks and upstream pools left unchanged"
                            );
                            continue;
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                "Reloaded configuration does not compile; rolling back"
                            );
                            if let Err(e) = config_manager_clone
                                .rollback(format!("route matcher build failed: {e}"))
                                .await
                            {
                                error!(
                                    error = %e,
                                    "Rollback failed; routes, rate limiters, health checks \
                                     and upstream pools left unchanged"
                                );
                            }
                            continue;
                        }
                    };

                    // From here the handler changes shared state, so it must not
                    // interleave with a newer reload: that reload's hook loads
                    // its agents and stores its configuration, and this event's
                    // (older) configuration would then remove an agent the
                    // newer one names, or replace its version of a changed one.
                    // Not taken before `recv()` or the compile above, and never
                    // while rolling back (`rollback` does not take the mutex,
                    // and the branches above `continue` before this point).
                    let reload_guard = config_manager_clone.lock_reloads().await;
                    if !Arc::ptr_eq(&config_manager_clone.current(), &new_config) {
                        debug!(
                            "Configuration changed while this event was handled; \
                             leaving it to the newer event"
                        );
                        continue;
                    }

                    // Every agent the new configuration names must be loaded
                    // before its routes go live. `AgentReloadHook` loaded them
                    // before the configuration became current; this covers what
                    // does not pass through a hook (a rollback re-activates the
                    // previous configuration, whose agents may have been removed
                    // since) and is a no-op otherwise.
                    let changes = agent_manager.reconcile(&new_config.agents).await;
                    if changes.added + changes.replaced > 0 {
                        info!(
                            added = changes.added,
                            replaced = changes.replaced,
                            unchanged = changes.unchanged,
                            "Agents reloaded"
                        );
                    }

                    *route_matcher.write() = new_matcher;
                    info!(
                        routes = global_route_count,
                        "Routes of the global listeners reloaded successfully"
                    );

                    // Swap in the per-listener (namespace- and service-bound)
                    // route matchers
                    *listener_matchers.write() = new_listener_matchers;

                    // Only now, with the routes that called them gone, take the
                    // agents the new configuration dropped out of service; calls
                    // in flight on them finish (`AgentManager::remove`).
                    let removed = agent_manager.remove_unlisted(&new_config.agents).await;
                    if removed > 0 {
                        info!(removed, "Agents removed");
                    }
                    drop(reload_guard);

                    // Rebuild rate limiters. They were built once at startup, so a
                    // changed, added or removed limit (route filter or policy,
                    // `global`, `default-rps`) only took effect after a restart.
                    // Unchanged limiters keep their buckets.
                    let changes =
                        rate_limit_manager.reconcile(Self::initialize_rate_limiters(&new_config));
                    info!(
                        added = changes.added,
                        replaced = changes.replaced,
                        removed = changes.removed,
                        unchanged = changes.unchanged,
                        "Rate limiters reloaded"
                    );

                    // Reconcile active health checks with the new config:
                    // start added checks, restart changed ones, stop removed
                    // ones. Done before the pool update so a pool-build
                    // timeout cannot leave the old probes in place.
                    let changes =
                        health_check_runner.apply(Self::health_check_upstreams(&new_config));
                    info!(
                        started = changes.started,
                        restarted = changes.restarted,
                        stopped = changes.stopped,
                        unchanged = changes.unchanged,
                        "Health checks reloaded"
                    );

                    // Update upstream pools with timeout to avoid blocking
                    // the reload handler on DNS resolution / connection attempts
                    let pool_update = async {
                        let mut new_pools = HashMap::new();
                        for (upstream_id, upstream_config) in &new_config.upstreams {
                            let mut config_with_id = upstream_config.clone();
                            config_with_id.id = upstream_id.clone();
                            match UpstreamPool::new(config_with_id).await {
                                Ok(pool) => {
                                    let pool = pool
                                        .with_active_health(health_check_runner.view(upstream_id));
                                    new_pools.insert(upstream_id.clone(), Arc::new(pool));
                                }
                                Err(e) => {
                                    error!("Failed to create upstream pool {}: {}", upstream_id, e);
                                }
                            }
                        }
                        new_pools
                    };

                    match tokio::time::timeout(Duration::from_secs(10), pool_update).await {
                        Ok(new_pools) => {
                            let old_pools = upstream_pools.replace(new_pools).await;

                            // Track drain lifecycle for old pools
                            tokio::spawn(async move {
                                let tracker = crate::upstream::drain::DrainTracker::default();
                                tracker.track_pools(old_pools).await;
                            });
                        }
                        Err(_) => {
                            warn!("Upstream pool update timed out after 10s, routes still updated");
                        }
                    }
                }
            }
        });
    }

    /// Every upstream with its id set, which is what the health check
    /// runner keys its probe loops by. In the lowered configuration a
    /// namespace's or service's upstream is keyed by its qualified id
    /// (`ns:name`), which is also its pool's id.
    fn health_check_upstreams(
        config: &Config,
    ) -> impl Iterator<Item = zentinel_config::UpstreamConfig> + '_ {
        config.upstreams.iter().map(|(id, upstream)| {
            let mut upstream = upstream.clone();
            upstream.id = id.clone();
            upstream
        })
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
            // `key` was parsed and dropped: the global limit was always per
            // client IP whatever the config said.
            RateLimitManager::with_global_limit_keyed(
                global.max_rps,
                global.burst,
                global.key.clone(),
            )
        } else {
            RateLimitManager::new()
        };

        let default_limit = Self::default_route_rate_limit(&config.rate_limits);
        if let Some(ref default) = default_limit {
            info!(
                max_rps = default.max_rps,
                burst = default.burst,
                key = ?default.key,
                "Default rate limit applies to routes without their own limit"
            );
        }
        let mut defaulted_routes = 0usize;

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
                    max_keys: crate::rate_limit::DEFAULT_MAX_RATE_LIMIT_KEYS,
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
                            max_keys: rl_filter.max_keys,
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

            // `rate-limits { default-rps }` covers every route that has no
            // limit of its own. A route's own limit (policy or filter) replaces
            // the default rather than stacking with it.
            if let Some(ref default) = default_limit {
                if !manager.has_route_specific_limiter(&route.id) {
                    manager.register_route(&route.id, default.clone());
                    defaulted_routes += 1;
                    debug!(route_id = %route.id, "Registered default rate limiter for route");
                }
            }
        }

        if manager.route_count() > 0 {
            info!(
                route_count = manager.route_count(),
                defaulted_routes, "Rate limiting initialized"
            );
        }

        manager
    }

    /// The limiter for routes without one of their own, from
    /// `rate-limits { default-rps N default-burst M key "..." }`.
    ///
    /// These keys were parsed and documented ("Default for routes without
    /// explicit limits") but nothing outside the config crate read them, so a
    /// configured default limited nothing. It uses the same limiter as a
    /// route's `rate-limit` filter: rejects with 429 and the usual
    /// `X-RateLimit-*` / `Retry-After` headers, keyed by `key` (client IP
    /// unless set). Each route gets its own bucket, as with a per-route filter.
    fn default_route_rate_limit(
        rate_limits: &zentinel_config::GlobalRateLimitConfig,
    ) -> Option<RateLimitConfig> {
        let max_rps = rate_limits.default_rps?;
        Some(RateLimitConfig {
            max_rps,
            burst: rate_limits.default_burst.unwrap_or(max_rps),
            key: rate_limits.key.clone(),
            action: zentinel_config::RateLimitAction::Reject,
            status_code: 429,
            message: None,
            backend: zentinel_config::RateLimitBackend::Local,
            max_delay_ms: 5000,
            max_keys: crate::rate_limit::DEFAULT_MAX_RATE_LIMIT_KEYS,
        })
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
                // Pre-compile exclude_paths glob patterns into regex at registration time
                let exclude_paths = rc
                    .exclude_paths
                    .iter()
                    .filter_map(|pattern| {
                        let regex_str = crate::cache::compile_glob_to_regex(pattern);
                        match regex::Regex::new(&regex_str) {
                            Ok(re) => Some(re),
                            Err(e) => {
                                warn!(
                                    route_id = %route.id,
                                    pattern = %pattern,
                                    error = %e,
                                    "Failed to compile cache exclude-path pattern"
                                );
                                None
                            }
                        }
                    })
                    .collect();

                CacheConfig {
                    enabled: rc.enabled,
                    default_ttl_secs: rc.default_ttl_secs,
                    max_size_bytes: rc.max_size_bytes,
                    cache_private: rc.cache_private,
                    stale_while_revalidate_secs: rc.stale_while_revalidate_secs,
                    stale_if_error_secs: rc.stale_if_error_secs,
                    cacheable_methods: rc.cacheable_methods.clone(),
                    cacheable_status_codes: rc.cacheable_status_codes.clone(),
                    exclude_extensions: rc.exclude_extensions.clone(),
                    exclude_paths,
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

#[cfg(test)]
mod listener_matcher_tests {
    use super::*;
    use crate::routing::RequestInfo;
    use std::net::SocketAddr;

    fn local(s: &str) -> SocketAddr {
        s.parse().expect("test address parses")
    }

    const KDL: &str = r#"
        schema-version "1.0"
        system { worker-threads 0 }
        listeners {
            listener "public" { address "0.0.0.0:8080" }
            listener "admin" {
                address "127.0.0.1:9000"
                namespace "ops"
            }
        }
        routes {
            route "api" {
                matches { path-prefix "/api" }
                upstream "backend"
            }
        }
        upstreams {
            upstream "backend" { target "127.0.0.1:3000" }
        }
        namespace "ops" {
            routes {
                route "metrics" {
                    matches { path "/metrics" }
                    service-type "builtin"
                    builtin-handler "metrics"
                }
            }
        }
    "#;

    #[test]
    fn namespace_listener_matches_only_its_own_routes() {
        let config = zentinel_config::Config::from_kdl(KDL)
            .expect("config parses")
            .lower_scopes();
        let matchers = ZentinelProxy::build_listener_matchers(&config).unwrap();

        // Only the namespace-bound listener gets a dedicated matcher.
        assert_eq!(matchers.len(), 1);
        assert!(!matchers.contains_configured("0.0.0.0:8080"));
        let admin = matchers
            .get(local("127.0.0.1:9000"))
            .expect("admin listener bound to namespace");

        // Isolated: the admin listener serves the namespace route...
        assert!(admin
            .match_request(&RequestInfo::new("GET", "/metrics", "x"))
            .is_some());
        // ...but NOT the global route.
        assert!(admin
            .match_request(&RequestInfo::new("GET", "/api/users", "x"))
            .is_none());
    }

    #[test]
    fn no_namespace_listeners_yields_empty_map() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:3000"
                }
            }
        "#;
        let config = zentinel_config::Config::from_kdl(kdl)
            .expect("config parses")
            .lower_scopes();
        let matchers = ZentinelProxy::build_listener_matchers(&config).unwrap();
        assert!(matchers.is_empty());
    }

    /// A namespaced listener bound to `0.0.0.0` used to be unreachable: the
    /// matcher was stored under the configured `0.0.0.0:8080`, but a connection
    /// accepted on that bind reports the concrete interface from
    /// `getsockname()`, so the lookup always missed and the request silently
    /// fell back to the *global* route set.
    const WILDCARD_KDL: &str = r#"
        schema-version "1.0"
        system { worker-threads 0 }
        listeners {
            listener "public" {
                address "0.0.0.0:8080"
                namespace "iso"
            }
        }
        routes {
            route "global-secret" {
                matches { path "/secret" }
                service-type "builtin"
                builtin-handler "config"
            }
        }
        namespace "iso" {
            routes {
                route "only" {
                    matches { path "/ok" }
                    service-type "builtin"
                    builtin-handler "health"
                }
            }
        }
    "#;

    #[test]
    fn wildcard_bound_namespace_listener_resolves_from_concrete_local_addr() {
        let config = zentinel_config::Config::from_kdl(WILDCARD_KDL)
            .expect("config parses")
            .lower_scopes();
        let matchers = ZentinelProxy::build_listener_matchers(&config).unwrap();

        // Every interface a `0.0.0.0` bind can accept on must resolve.
        for arrival in ["127.0.0.1:8080", "203.0.113.5:8080", "10.0.0.7:8080"] {
            let matcher = matchers
                .get(local(arrival))
                .unwrap_or_else(|| panic!("no matcher for connection arriving on {arrival}"));

            // The namespace route is live...
            assert!(
                matcher
                    .match_request(&RequestInfo::new("GET", "/ok", "x"))
                    .is_some(),
                "namespace route should match on {arrival}"
            );
            // ...and the global route stays out of reach, which is the
            // isolation guarantee `namespace` is documented to provide.
            assert!(
                matcher
                    .match_request(&RequestInfo::new("GET", "/secret", "x"))
                    .is_none(),
                "global route must not leak into namespace on {arrival}"
            );
        }
    }

    #[test]
    fn wildcard_listener_does_not_capture_other_ports() {
        let config = zentinel_config::Config::from_kdl(WILDCARD_KDL)
            .expect("config parses")
            .lower_scopes();
        let matchers = ZentinelProxy::build_listener_matchers(&config).unwrap();
        assert!(matchers.get(local("203.0.113.5:9090")).is_none());
    }

    /// #548: a namespace without a listener of its own is served on the
    /// global listeners, a service with one only there, and a listener
    /// declared inside a namespace serves that namespace.
    #[test]
    fn scoped_routes_are_matched_on_the_listeners_of_their_scope() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "public" { address "0.0.0.0:8080" }
            }
            routes {
                route "health" {
                    matches { path "/health" }
                    builtin-handler "health"
                }
            }
            namespace "api" {
                upstreams {
                    upstream "backend" { target "127.0.0.1:3000" }
                }
                routes {
                    route "main" {
                        matches { path-prefix "/api" }
                        upstream "backend"
                    }
                }
                service "pay" {
                    listener {
                        id "pay"
                        address "127.0.0.1:9100"
                    }
                    routes {
                        route "main" {
                            matches { path-prefix "/" }
                            upstream "backend"
                        }
                    }
                }
            }
            namespace "web" {
                listeners {
                    listener "web" { address "127.0.0.1:9200" }
                }
                routes {
                    route "main" {
                        matches { path-prefix "/" }
                        service-type "builtin"
                        builtin-handler "status"
                    }
                }
            }
        "#;
        let config = zentinel_config::Config::from_kdl(kdl)
            .expect("config parses")
            .lower_scopes();
        let req = |path| RequestInfo::new("GET", path, "x");

        let global = RouteMatcher::new(config.routes_served_on(&Scope::Global), None).unwrap();
        let matched = global.match_request(&req("/api/x")).expect("api:main");
        assert_eq!(matched.route_id.as_str(), "api:main");
        assert_eq!(matched.config.upstream.as_deref(), Some("api:backend"));
        assert!(global.match_request(&req("/other")).is_none());

        let matchers = ZentinelProxy::build_listener_matchers(&config).unwrap();
        assert_eq!(matchers.len(), 2);
        let pay = matchers.get(local("127.0.0.1:9100")).expect("pay listener");
        let matched = pay.match_request(&req("/api/x")).expect("pay route");
        assert_eq!(matched.route_id.as_str(), "api:pay:main");
        assert_eq!(matched.config.upstream.as_deref(), Some("api:backend"));
        assert!(pay
            .match_request(&req("/health"))
            .is_some_and(|m| m.route_id.as_str() == "api:pay:main"));
        let web = matchers.get(local("127.0.0.1:9200")).expect("web listener");
        assert_eq!(
            web.match_request(&req("/health"))
                .unwrap()
                .route_id
                .as_str(),
            "web:main"
        );
        assert!(matchers.get(local("127.0.0.1:8080")).is_none());
    }

    /// A namespace route that does not compile was never compiled before
    /// #548 and did not stop the proxy from starting; it is left out of the
    /// route set (and reported) rather than failing the whole set.
    #[test]
    fn a_scoped_route_that_does_not_compile_is_left_out() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners { listener "public" { address "0.0.0.0:8080" } }
            routes {
                route "health" {
                    matches { path "/health" }
                    builtin-handler "health"
                }
            }
            namespace "api" {
                routes {
                    route "broken" {
                        matches { path-regex "^/(unclosed" }
                        builtin-handler "status"
                    }
                    route "fine" {
                        matches { path "/fine" }
                        builtin-handler "status"
                    }
                }
            }
        "#;
        let config = zentinel_config::Config::from_kdl(kdl)
            .expect("config parses")
            .lower_scopes();
        let served: Vec<String> = crate::routing::routes_served_on(&config, &Scope::Global)
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(served, ["health", "api:fine"]);
        let problems = crate::routing::unservable_scoped_routes(&config);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            problems[0].contains("'api:broken' is being ignored"),
            "{problems:?}"
        );
    }

    /// Per-listener timeouts resolve through the same path, and used to be
    /// inert on wildcard binds for the same reason.
    #[test]
    fn per_listener_timeouts_resolve_on_wildcard_bind() {
        let kdl = r#"
            schema-version "1.0"
            system { worker-threads 0 }
            listeners {
                listener "public" {
                    address "0.0.0.0:8080"
                    request-timeout-secs 17
                    keepalive-timeout-secs 23
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" { target "127.0.0.1:3000" }
            }
        "#;
        let config = zentinel_config::Config::from_kdl(kdl)
            .expect("config parses")
            .lower_scopes();
        let listener =
            super::listener_addr::listener_for_addr(&config.listeners, local("203.0.113.5:8080"))
                .expect("wildcard listener resolves from a concrete local address");

        assert_eq!(listener.id, "public");
        assert_eq!(listener.request_timeout_secs, 17);
        assert_eq!(listener.keepalive_timeout_secs, 23);
    }
}

#[cfg(test)]
mod health_check_wiring_tests {
    use super::*;
    use crate::reload::ReloadTrigger;
    use std::collections::BTreeSet;

    fn config_kdl(targets: &[String], health_check: &str) -> String {
        let targets: String = targets
            .iter()
            .map(|t| format!("target \"{t}\"\n"))
            .collect();
        format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "http" {{ address "127.0.0.1:19290" protocol "http" }}
            }}
            routes {{
                route "default" {{
                    matches {{ path-prefix "/" }}
                    upstream "backend"
                }}
            }}
            upstreams {{
                upstream "backend" {{
                    {targets}
                    {health_check}
                }}
            }}
            "#
        )
    }

    const CHECK: &str = r#"health-check {
        type "http" { path "/health" }
        interval-secs 1
        healthy-threshold 1
        unhealthy-threshold 1
    }"#;

    fn init_crypto_provider() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    /// An HTTP server that answers every request with `status`.
    async fn backend(status: u16) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    /// Distinct targets chosen in `n` selections.
    async fn selected(proxy: &ZentinelProxy, n: usize) -> BTreeSet<String> {
        let pool = proxy
            .upstream_pools
            .get("backend")
            .await
            .expect("pool exists");
        let mut seen = BTreeSet::new();
        for _ in 0..n {
            let peer = pool.select_peer(None).await.expect("a target is selected");
            seen.insert(pingora_core::upstreams::peer::Peer::address(&peer).to_string());
        }
        seen
    }

    /// Poll `selected` until it returns `expected`, for up to 6 s.
    async fn routes_to(proxy: &ZentinelProxy, expected: &BTreeSet<String>) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
        while tokio::time::Instant::now() < deadline {
            if &selected(proxy, 20).await == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    async fn reload_and_wait_for(proxy: &ZentinelProxy, expected: usize) -> usize {
        proxy
            .config_manager
            .reload(ReloadTrigger::Signal)
            .await
            .expect("reload succeeds");
        // The reload handler applies the new config on its own task.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while proxy.health_check_runner.checker_count() != expected
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        proxy.health_check_runner.checker_count()
    }

    /// Three defects, one test: `ZentinelProxy::new` registers process-global
    /// metrics, so only one proxy can be built per test binary.
    ///
    /// 1. Startup registered each global upstream's health check twice: once
    ///    from `config.upstreams`, once from the flattened config, which lists
    ///    the global upstreams again. Every target was probed twice per
    ///    interval, and the log said "health checking for 2 upstreams" for one.
    /// 2. Probe results never reached target selection: a target failing its
    ///    health check stayed in rotation.
    /// 3. A SIGHUP reload rebuilt routes and pools but never touched the
    ///    health check runner, so a check added by a reload never probed and
    ///    one removed by a reload kept probing.
    #[tokio::test]
    async fn health_checks_route_around_failures_and_follow_reloads() {
        init_crypto_provider();
        let good = backend(200).await;
        let bad = backend(500).await;
        let targets = [good.clone(), bad.clone()];
        let only_good: BTreeSet<String> = [good.clone()].into();
        let both: BTreeSet<String> = targets.iter().cloned().collect();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("zentinel.kdl");
        std::fs::write(&path, config_kdl(&targets, CHECK)).expect("write config");

        let proxy = ZentinelProxy::new(Some(path.to_str().unwrap()))
            .await
            .expect("proxy builds");
        assert_eq!(
            proxy.health_check_runner.checker_count(),
            1,
            "one upstream with a health check must get exactly one checker"
        );

        // The failing target leaves rotation once probed...
        assert!(
            routes_to(&proxy, &only_good).await,
            "a target failing its health check stayed in rotation"
        );

        // ...comes back when the check is removed, in the reloaded pools...
        std::fs::write(&path, config_kdl(&targets, "")).expect("write config");
        assert_eq!(
            reload_and_wait_for(&proxy, 0).await,
            0,
            "a health check removed by reload was not stopped"
        );
        assert!(
            routes_to(&proxy, &both).await,
            "removing the health check did not readmit the target"
        );

        // ...and a check added by reload takes it out again.
        std::fs::write(&path, config_kdl(&targets, CHECK)).expect("write config");
        assert_eq!(
            reload_and_wait_for(&proxy, 1).await,
            1,
            "a health check added by reload was not started"
        );
        assert!(
            routes_to(&proxy, &only_good).await,
            "a health check added by reload did not take the failing target out"
        );
    }
}

#[cfg(test)]
mod default_rate_limit_tests {
    use super::*;

    struct NoHeaders;
    impl crate::rate_limit::HeaderAccessor for NoHeaders {
        fn get_header(&self, _name: &str) -> Option<String> {
            None
        }
    }

    fn config(rate_limits: &str) -> Config {
        let kdl = format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "http" {{ address "127.0.0.1:19290" protocol "http" }}
            }}
            {rate_limits}
            filters {{
                filter "own-limit" {{
                    type "rate-limit"
                    max-rps 4
                    burst 4
                }}
            }}
            routes {{
                route "plain" {{
                    matches {{ path-prefix "/plain" }}
                    upstream "backend"
                }}
                route "own" {{
                    matches {{ path-prefix "/own" }}
                    upstream "backend"
                    filters "own-limit"
                }}
            }}
            upstreams {{
                upstream "backend" {{ target "127.0.0.1:19291" }}
            }}
            "#
        );
        Config::from_kdl(&kdl).expect("config parses")
    }

    /// Status of `n` back-to-back requests from one client to a route.
    async fn statuses(manager: &RateLimitManager, route: &str, n: usize) -> Vec<u16> {
        let mut statuses = Vec::with_capacity(n);
        for _ in 0..n {
            let r = manager
                .check(route, "203.0.113.7", "/", Option::<&NoHeaders>::None)
                .await;
            statuses.push(if r.allowed { 200 } else { r.status_code });
        }
        statuses
    }

    /// `rate-limits { default-rps }` was parsed and documented as the limit
    /// for routes without one of their own, and nothing read it: every
    /// request to such a route was allowed.
    #[tokio::test]
    async fn default_rps_limits_routes_without_their_own_limit() {
        let config = config("rate-limits { default-rps 2; default-burst 2 }");
        assert_eq!(config.rate_limits.default_rps, Some(2));
        let manager = ZentinelProxy::initialize_rate_limiters(&config);

        assert_eq!(
            statuses(&manager, "plain", 4).await,
            vec![200, 200, 429, 429]
        );

        // The headers come from the same result: limit and remaining.
        let limited = manager
            .check("plain", "203.0.113.7", "/", Option::<&NoHeaders>::None)
            .await;
        assert_eq!(limited.limit, 2);
        assert_eq!(limited.remaining, 0);

        // Another client has its own bucket.
        let other = manager
            .check("plain", "198.51.100.1", "/", Option::<&NoHeaders>::None)
            .await;
        assert!(other.allowed);
    }

    #[tokio::test]
    async fn a_route_with_its_own_limit_ignores_the_default() {
        let config = config("rate-limits { default-rps 2 }");
        let manager = ZentinelProxy::initialize_rate_limiters(&config);

        assert_eq!(
            statuses(&manager, "own", 6).await,
            vec![200, 200, 200, 200, 429, 429]
        );
    }

    /// `global { key }` was parsed and ignored: the global limiter was
    /// always keyed by client IP. Keyed by path, clients share one bucket
    /// per path.
    #[tokio::test]
    async fn the_global_limit_uses_its_configured_key() {
        let config = config("rate-limits { global { max-rps 2; burst 2; key \"path\" } }");
        let manager = ZentinelProxy::initialize_rate_limiters(&config);
        let check = |ip: &'static str, path: &'static str| {
            let manager = &manager;
            async move {
                manager
                    .check("plain", ip, path, Option::<&NoHeaders>::None)
                    .await
                    .allowed
            }
        };

        assert!(check("198.51.100.1", "/x").await);
        assert!(check("198.51.100.2", "/x").await);
        assert!(
            !check("198.51.100.3", "/x").await,
            "a path-keyed global limit was applied per client IP"
        );
        // Another path has its own bucket.
        assert!(check("198.51.100.1", "/y").await);
    }

    #[tokio::test]
    async fn without_a_default_unlimited_routes_stay_unlimited() {
        let config = config("");
        let manager = ZentinelProxy::initialize_rate_limiters(&config);

        assert!(!manager.has_route_limiter("plain"));
        assert_eq!(statuses(&manager, "plain", 10).await, vec![200; 10]);
        assert_eq!(
            statuses(&manager, "own", 6).await,
            vec![200, 200, 200, 200, 429, 429]
        );
    }

    /// What a reload does: `reconcile` with limiters built from the new
    /// config. Limiters were built once at startup, so none of these
    /// changes took effect before a restart.
    #[tokio::test]
    async fn reload_applies_changed_added_and_removed_limits() {
        let manager =
            ZentinelProxy::initialize_rate_limiters(&config("rate-limits { default-rps 100 }"));
        assert_eq!(statuses(&manager, "plain", 8).await, vec![200; 8]);

        // Changed: the default drops to 1/s with a bucket of 1.
        let changes = manager.reconcile(ZentinelProxy::initialize_rate_limiters(&config(
            "rate-limits { default-rps 1; default-burst 1 }",
        )));
        assert_eq!(changes.replaced, 1, "{changes:?}");
        assert_eq!(
            statuses(&manager, "plain", 4).await,
            vec![200, 429, 429, 429]
        );

        // Removed: the route is unlimited again.
        let changes = manager.reconcile(ZentinelProxy::initialize_rate_limiters(&config("")));
        assert_eq!(changes.removed, 1, "{changes:?}");
        assert!(!manager.has_route_limiter("plain"));
        assert_eq!(statuses(&manager, "plain", 8).await, vec![200; 8]);

        // Added: a global limit appears.
        let changes = manager.reconcile(ZentinelProxy::initialize_rate_limiters(&config(
            "rate-limits { global { max-rps 1; burst 2 } }",
        )));
        assert_eq!(changes.added, 1, "{changes:?}");
        assert_eq!(statuses(&manager, "plain", 3).await, vec![200, 200, 429]);
    }

    /// Reloading an unrelated part of the config must not refill every
    /// bucket: a client at its limit stays there.
    #[tokio::test]
    async fn reload_keeps_buckets_of_unchanged_limits() {
        let kdl = "rate-limits { default-rps 1; default-burst 2 }";
        let manager = ZentinelProxy::initialize_rate_limiters(&config(kdl));
        // The "own" filter (4/4) is untouched by any of this.
        assert_eq!(statuses(&manager, "plain", 3).await, vec![200, 200, 429]);
        assert_eq!(
            statuses(&manager, "own", 5).await,
            vec![200, 200, 200, 200, 429]
        );

        let changes = manager.reconcile(ZentinelProxy::initialize_rate_limiters(&config(kdl)));
        assert_eq!(
            (
                changes.unchanged,
                changes.added,
                changes.replaced,
                changes.removed
            ),
            (2, 0, 0, 0)
        );
        assert_eq!(statuses(&manager, "plain", 1).await, vec![429]);
        assert_eq!(statuses(&manager, "own", 1).await, vec![429]);
    }
}

/// #577: a rollback must re-sync everything the reload handler maintains, and
/// a reload must be applied completely or not at all.
#[cfg(test)]
mod reload_rollback_tests {
    use super::*;
    use crate::reload::ReloadTrigger;
    use crate::routing::RequestInfo;

    /// One route `id` matching `regex`, plus `extra` top-level blocks.
    fn kdl(id: &str, regex: &str, extra: &str) -> String {
        format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 0 }}
            listeners {{
                listener "http" {{ address "127.0.0.1:19291" protocol "http" }}
            }}
            routes {{
                route "{id}" {{
                    matches {{ path-regex "{regex}" }}
                    builtin-handler "status"
                }}
            }}
            {extra}
            "#
        )
    }

    /// Config A: route `a` with a default rate limit, so it has a limiter.
    fn config_a() -> String {
        kdl("a", "^/a", "rate-limits { default-rps 100 }")
    }

    /// A route whose pattern is not a valid regex. `Config::validate` does
    /// not compile route patterns, so only the route matcher rejects it.
    fn uncompilable() -> String {
        kdl("broken", "^/(unclosed", "")
    }

    struct Harness {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        manager: Arc<ConfigManager>,
        routes: Arc<RwLock<RouteMatcher>>,
        limits: Arc<RateLimitManager>,
        agents: Arc<AgentManager>,
    }

    impl Harness {
        /// The reload handler as `ZentinelProxy::new` sets it up, on config
        /// A, with or without the reload validators.
        async fn start(validators: bool) -> Self {
            Self::start_with(validators, &config_a()).await
        }

        /// As [`Self::start`], on `initial_kdl`.
        async fn start_with(validators: bool, initial_kdl: &str) -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("zentinel.kdl");
            std::fs::write(&path, initial_kdl).expect("write config");
            let initial = Config::from_kdl(initial_kdl).expect("initial config parses");
            let agents = Arc::new(
                AgentManager::new(initial.agents.clone())
                    .await
                    .expect("agent manager"),
            );
            let manager = Arc::new(ConfigManager::new(&path, initial).await.expect("manager"));
            manager
                .add_hook(Box::new(crate::agents::AgentReloadHook::new(Arc::clone(
                    &agents,
                ))))
                .await;
            if validators {
                ZentinelProxy::add_reload_validators(&manager).await;
            }
            let config = manager.current();
            let routes = Arc::new(RwLock::new(
                crate::routing::compile_route_set(
                    &config,
                    &Scope::Global,
                    crate::routing::routes_served_on(&config, &Scope::Global),
                )
                .expect("config A compiles"),
            ));
            let listeners = Arc::new(RwLock::new(
                ZentinelProxy::build_listener_matchers(&config).expect("config A compiles"),
            ));
            let limits = Arc::new(ZentinelProxy::initialize_rate_limiters(&config));
            ZentinelProxy::setup_reload_handler(
                Arc::clone(&manager),
                Arc::clone(&routes),
                listeners,
                Registry::from_map(HashMap::new()),
                Arc::new(HealthCheckRunner::new()),
                Arc::clone(&limits),
                Arc::clone(&agents),
            )
            .await;
            Self {
                _dir: dir,
                path,
                manager,
                routes,
                limits,
                agents,
            }
        }

        fn write(&self, kdl: &str) {
            std::fs::write(&self.path, kdl).expect("write config");
        }

        /// The route the global matcher picks for `path`.
        fn routed(&self, path: &str) -> Option<String> {
            self.routes
                .read()
                .match_request(&RequestInfo::new("GET", path, "x"))
                .map(|m| m.route_id.as_str().to_string())
        }

        fn current_routes(&self) -> Vec<String> {
            self.manager
                .current()
                .routes
                .iter()
                .map(|r| r.id.clone())
                .collect()
        }

        /// Whether the proxy is on config A in every way checked here.
        fn on_config_a(&self) -> bool {
            self.current_routes() == ["a"]
                && self.routed("/a").as_deref() == Some("a")
                && self.limits.has_route_specific_limiter("a")
        }
    }

    /// The reload handler applies events on its own task.
    async fn eventually(check: impl Fn() -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        check()
    }

    /// The handler ignored `RolledBack`: after a rollback `current()` was
    /// config A again while routes and rate limiters stayed on config B.
    #[tokio::test]
    async fn a_rollback_re_applies_the_previous_config() {
        let h = Harness::start(true).await;
        assert!(h.on_config_a());

        h.write(&kdl("b", "^/b", ""));
        h.manager
            .reload(ReloadTrigger::Manual)
            .await
            .expect("config B reloads");
        assert!(
            eventually(|| h.routed("/b").as_deref() == Some("b")).await,
            "config B was not applied"
        );
        assert!(!h.limits.has_route_specific_limiter("a"));

        h.manager
            .rollback("test".to_string())
            .await
            .expect("rollback");
        assert!(
            eventually(|| h.on_config_a() && h.routed("/b").is_none()).await,
            "after the rollback current() is {:?} but /a routes to {:?}, /b to {:?}, \
             and route a has a limiter: {}",
            h.current_routes(),
            h.routed("/a"),
            h.routed("/b"),
            h.limits.has_route_specific_limiter("a")
        );
    }

    /// A reload whose routes cannot compile used to be stored as `current()`
    /// and then only half applied. It is now rejected before it is stored.
    #[tokio::test]
    async fn a_reload_whose_routes_do_not_compile_is_rejected() {
        let h = Harness::start(true).await;
        h.write(&uncompilable());
        let err = h
            .manager
            .reload(ReloadTrigger::Manual)
            .await
            .expect_err("routes that do not compile must be rejected");
        assert!(err.to_string().contains("global"), "{err}");
        assert!(err.to_string().contains("unclosed"), "{err}");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(h.on_config_a());
    }

    /// The backstop, should a configuration whose routes cannot compile get
    /// past validation: the handler rebuilt rate limiters, health checks and
    /// pools from it while keeping the old routes, and left it as
    /// `current()`. It now changes nothing and rolls back.
    #[tokio::test]
    async fn routes_that_fail_in_the_handler_roll_the_reload_back() {
        let h = Harness::start(false).await;
        h.write(&uncompilable());
        h.manager
            .reload(ReloadTrigger::Manual)
            .await
            .expect("without the validators the reload is stored");
        assert!(
            eventually(|| h.on_config_a()).await,
            "after a failed route build current() is {:?}, /a routes to {:?}, \
             and route a has a limiter: {}",
            h.current_routes(),
            h.routed("/a"),
            h.limits.has_route_specific_limiter("a")
        );
        assert_eq!(
            h.manager
                .stats()
                .rollbacks
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "exactly one rollback"
        );
    }

    /// A top-level `agents` block with one agent, `id`, whose socket is absent.
    fn agent(id: &str) -> String {
        format!(
            r#"agents {{
                agent "{id}" {{
                    type "custom"
                    unix-socket path="/tmp/zentinel-no-such-{id}.sock"
                    events "request_headers"
                    timeout-ms 1000
                    failure-mode "closed"
                }}
            }}"#
        )
    }

    /// Wait for `cond`, which the reload handler makes true shortly after the
    /// reload returns.
    async fn wait_until(what: &str, mut cond: impl AsyncFnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while tokio::time::Instant::now() < deadline {
            if cond().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    /// A reload drops agent `one` for `two`; a rollback to the config that
    /// names `one` must find it loaded again, or its filters would run
    /// nothing.
    #[tokio::test]
    async fn a_rollback_loads_the_agents_of_the_previous_config() {
        let h = Harness::start_with(true, &kdl("a", "^/a", &agent("one"))).await;
        assert!(h.agents.is_loaded("one").await);

        h.write(&kdl("a", "^/a", &agent("two")));
        h.manager
            .reload(ReloadTrigger::Manual)
            .await
            .expect("the reload applies");
        wait_until("`two` loaded and `one` removed", async || {
            h.agents.is_loaded("two").await && !h.agents.is_loaded("one").await
        })
        .await;

        h.manager
            .rollback("test".to_string())
            .await
            .expect("rollback");
        wait_until("`one` loaded again", async || {
            h.agents.is_loaded("one").await
        })
        .await;
    }
}
