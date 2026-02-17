//! Scope-aware route matching for namespaced configurations.
//!
//! This module provides [`ScopedRouteMatcher`] which extends route matching
//! with scope awareness, allowing routes to be organized hierarchically
//! (global → namespace → service) with proper visibility rules.
//!
//! # Visibility Rules
//!
//! - **Global routes**: Visible from all scopes
//! - **Namespace routes**: Visible from that namespace and its services
//! - **Service routes**: Only visible from that specific service
//!
//! When a request comes in on a listener, the listener's scope determines
//! which routes are considered for matching.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, trace};

use zentinel_common::ids::{QualifiedId, Scope};
use zentinel_common::RouteId;
use zentinel_config::{FlattenedConfig, RouteConfig};

use crate::routing::{RequestInfo, RouteError, RouteMatch, RouteMatcher};

/// Scope-aware route matcher.
///
/// Maintains separate route matchers for each scope and provides
/// scope-aware request matching following visibility rules.
pub struct ScopedRouteMatcher {
    /// Route matchers indexed by scope
    matchers: Arc<RwLock<HashMap<Scope, RouteMatcher>>>,

    /// Routes indexed by qualified ID for direct lookup
    routes_by_qid: Arc<RwLock<HashMap<String, Arc<RouteConfig>>>>,

    /// Default route per scope
    default_routes: Arc<RwLock<HashMap<Scope, RouteId>>>,

    /// Global fallback route (used when no scope-specific default exists)
    global_default: Arc<RwLock<Option<RouteId>>>,
}

/// Extended route match with scope information.
#[derive(Debug, Clone)]
pub struct ScopedRouteMatch {
    /// The route match result
    pub inner: RouteMatch,

    /// The qualified ID of the matched route
    pub qualified_id: QualifiedId,

    /// The scope where the route was found
    pub matched_scope: Scope,
}

impl ScopedRouteMatch {
    /// Get the route ID string
    pub fn route_id(&self) -> &str {
        self.inner.route_id.as_str()
    }

    /// Get the route configuration
    pub fn config(&self) -> &Arc<RouteConfig> {
        &self.inner.config
    }

    /// Get namespace if the route is in a namespace or service scope
    pub fn namespace(&self) -> Option<&str> {
        match &self.matched_scope {
            Scope::Global => None,
            Scope::Namespace(ns) => Some(ns),
            Scope::Service { namespace, .. } => Some(namespace),
        }
    }

    /// Get service if the route is in a service scope
    pub fn service(&self) -> Option<&str> {
        match &self.matched_scope {
            Scope::Service { service, .. } => Some(service),
            _ => None,
        }
    }
}

impl ScopedRouteMatcher {
    /// Create a new empty scoped route matcher.
    pub fn new() -> Self {
        Self {
            matchers: Arc::new(RwLock::new(HashMap::new())),
            routes_by_qid: Arc::new(RwLock::new(HashMap::new())),
            default_routes: Arc::new(RwLock::new(HashMap::new())),
            global_default: Arc::new(RwLock::new(None)),
        }
    }

    /// Create a scoped route matcher from a flattened configuration.
    pub async fn from_flattened(config: &FlattenedConfig) -> Result<Self, RouteError> {
        let matcher = Self::new();
        matcher.load_from_flattened(config).await?;
        Ok(matcher)
    }

    /// Load routes from a flattened configuration.
    pub async fn load_from_flattened(&self, config: &FlattenedConfig) -> Result<(), RouteError> {
        // Group routes by scope
        let mut routes_by_scope: HashMap<Scope, Vec<RouteConfig>> = HashMap::new();
        let mut routes_map = HashMap::new();

        for (qid, route) in &config.routes {
            routes_by_scope
                .entry(qid.scope.clone())
                .or_default()
                .push(route.clone());
            routes_map.insert(qid.canonical(), Arc::new(route.clone()));
        }

        // Create matchers for each scope
        let mut matchers = HashMap::new();
        for (scope, routes) in routes_by_scope {
            debug!(
                scope = ?scope,
                route_count = routes.len(),
                "Creating route matcher for scope"
            );
            let matcher = RouteMatcher::new(routes, None)?;
            matchers.insert(scope, matcher);
        }

        // Update state atomically
        *self.matchers.write().await = matchers;
        *self.routes_by_qid.write().await = routes_map;

        Ok(())
    }

    /// Set the default route for a specific scope.
    pub async fn set_default_route(&self, scope: Scope, route_id: impl Into<String>) {
        self.default_routes
            .write()
            .await
            .insert(scope, RouteId::new(route_id));
    }

    /// Set the global default route.
    pub async fn set_global_default(&self, route_id: impl Into<String>) {
        *self.global_default.write().await = Some(RouteId::new(route_id));
    }

    /// Match a request within a specific scope.
    ///
    /// Searches through the scope chain (most specific to least specific):
    /// 1. The exact scope (service or namespace)
    /// 2. Parent namespace (if in service scope)
    /// 3. Global scope
    ///
    /// The first matching route wins ("most specific wins" rule).
    pub async fn match_request(
        &self,
        req: &RequestInfo<'_>,
        from_scope: &Scope,
    ) -> Option<ScopedRouteMatch> {
        trace!(
            method = %req.method,
            path = %req.path,
            host = %req.host,
            scope = ?from_scope,
            "Starting scoped route matching"
        );

        let matchers = self.matchers.read().await;
        let routes_by_qid = self.routes_by_qid.read().await;

        // Try each scope in the chain (most specific first)
        for scope in from_scope.chain() {
            if let Some(matcher) = matchers.get(&scope) {
                if let Some(route_match) = matcher.match_request(req) {
                    // Find the qualified ID for this route
                    let qid = QualifiedId {
                        name: route_match.route_id.as_str().to_string(),
                        scope: scope.clone(),
                    };

                    debug!(
                        route_id = %route_match.route_id,
                        scope = ?scope,
                        from_scope = ?from_scope,
                        "Route matched in scope"
                    );

                    return Some(ScopedRouteMatch {
                        inner: route_match,
                        qualified_id: qid,
                        matched_scope: scope,
                    });
                }
            }
        }

        // Try default routes
        let defaults = self.default_routes.read().await;
        for scope in from_scope.chain() {
            if let Some(default_id) = defaults.get(&scope) {
                let qid = QualifiedId {
                    name: default_id.as_str().to_string(),
                    scope: scope.clone(),
                };
                if let Some(config) = routes_by_qid.get(&qid.canonical()) {
                    debug!(
                        route_id = %default_id,
                        scope = ?scope,
                        "Using scope default route"
                    );
                    return Some(ScopedRouteMatch {
                        inner: RouteMatch {
                            route_id: default_id.clone(),
                            config: Arc::clone(config),
                        },
                        qualified_id: qid,
                        matched_scope: scope,
                    });
                }
            }
        }

        // Try global default
        if let Some(ref global_default) = *self.global_default.read().await {
            let qid = QualifiedId::global(global_default.as_str());
            if let Some(config) = routes_by_qid.get(&qid.canonical()) {
                debug!(
                    route_id = %global_default,
                    "Using global default route"
                );
                return Some(ScopedRouteMatch {
                    inner: RouteMatch {
                        route_id: global_default.clone(),
                        config: Arc::clone(config),
                    },
                    qualified_id: qid,
                    matched_scope: Scope::Global,
                });
            }
        }

        debug!(
            method = %req.method,
            path = %req.path,
            from_scope = ?from_scope,
            "No route matched in any visible scope"
        );
        None
    }

    /// Get a route by its qualified ID.
    pub async fn get_route(&self, qid: &QualifiedId) -> Option<Arc<RouteConfig>> {
        self.routes_by_qid
            .read()
            .await
            .get(&qid.canonical())
            .cloned()
    }

    /// Check if any matcher needs headers for matching.
    pub async fn needs_headers(&self) -> bool {
        self.matchers
            .read()
            .await
            .values()
            .any(|m| m.needs_headers())
    }

    /// Check if any matcher needs query params for matching.
    pub async fn needs_query_params(&self) -> bool {
        self.matchers
            .read()
            .await
            .values()
            .any(|m| m.needs_query_params())
    }

    /// Clear all route caches.
    pub async fn clear_caches(&self) {
        for matcher in self.matchers.read().await.values() {
            matcher.clear_cache();
        }
    }

    /// Get the number of scopes with routes.
    pub async fn scope_count(&self) -> usize {
        self.matchers.read().await.len()
    }

    /// Get the total number of routes across all scopes.
    pub async fn total_routes(&self) -> usize {
        self.routes_by_qid.read().await.len()
    }

    /// Get all scopes that have routes.
    pub async fn scopes(&self) -> Vec<Scope> {
        self.matchers.read().await.keys().cloned().collect()
    }
}

impl Default for ScopedRouteMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RoutePolicies, ServiceType};

    fn test_route(id: &str, path_prefix: &str) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::Normal,
            matches: vec![MatchCondition::PathPrefix(path_prefix.to_string())],
            upstream: Some("test-upstream".to_string()),
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            circuit_breaker: None,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            shadow: None,
            fallback: None,
        }
    }

    fn mock_flattened_config() -> FlattenedConfig {
        let mut config = FlattenedConfig::new();

        // Global route
        config.routes.push((
            QualifiedId::global("global-route"),
            test_route("global-route", "/"),
        ));

        // Namespace routes
        config.routes.push((
            QualifiedId::namespaced("api", "api-route"),
            test_route("api-route", "/api/"),
        ));

        // Service route
        config.routes.push((
            QualifiedId::in_service("api", "payments", "payments-route"),
            test_route("payments-route", "/payments/"),
        ));

        config
    }

    #[tokio::test]
    async fn test_match_from_global_scope() {
        let config = mock_flattened_config();
        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        let req = RequestInfo::new("GET", "/test", "example.com");
        let result = matcher.match_request(&req, &Scope::Global).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "global-route");
        assert_eq!(route_match.matched_scope, Scope::Global);
    }

    #[tokio::test]
    async fn test_match_from_namespace_scope() {
        let config = mock_flattened_config();
        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        let ns_scope = Scope::Namespace("api".to_string());

        // Should match namespace-specific route
        let req = RequestInfo::new("GET", "/api/users", "example.com");
        let result = matcher.match_request(&req, &ns_scope).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "api-route");
        assert_eq!(
            route_match.matched_scope,
            Scope::Namespace("api".to_string())
        );

        // Should fall back to global route
        let req = RequestInfo::new("GET", "/other", "example.com");
        let result = matcher.match_request(&req, &ns_scope).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "global-route");
        assert_eq!(route_match.matched_scope, Scope::Global);
    }

    #[tokio::test]
    async fn test_match_from_service_scope() {
        let config = mock_flattened_config();
        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // Should match service-specific route first
        let req = RequestInfo::new("GET", "/payments/checkout", "example.com");
        let result = matcher.match_request(&req, &svc_scope).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "payments-route");
        assert!(matches!(route_match.matched_scope, Scope::Service { .. }));

        // Should fall back to namespace route
        let req = RequestInfo::new("GET", "/api/users", "example.com");
        let result = matcher.match_request(&req, &svc_scope).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "api-route");

        // Should fall back to global route
        let req = RequestInfo::new("GET", "/other", "example.com");
        let result = matcher.match_request(&req, &svc_scope).await;

        assert!(result.is_some());
        let route_match = result.unwrap();
        assert_eq!(route_match.route_id(), "global-route");
    }

    #[tokio::test]
    async fn test_scope_info_in_match() {
        let config = mock_flattened_config();
        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        let req = RequestInfo::new("GET", "/payments/checkout", "example.com");
        let result = matcher.match_request(&req, &svc_scope).await.unwrap();

        assert_eq!(result.namespace(), Some("api"));
        assert_eq!(result.service(), Some("payments"));
    }

    #[tokio::test]
    async fn test_default_route() {
        let config = mock_flattened_config();
        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        matcher.set_global_default("global-route").await;

        // Request that doesn't match any specific route pattern
        let req = RequestInfo::new("GET", "/nonexistent", "example.com");

        // From global scope
        let result = matcher.match_request(&req, &Scope::Global).await;
        // The global-route has "/" prefix, so it will match
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_no_match() {
        let mut config = FlattenedConfig::new();
        // Add a route that won't match our test request
        config.routes.push((
            QualifiedId::global("specific-route"),
            test_route("specific-route", "/specific/"),
        ));

        let matcher = ScopedRouteMatcher::from_flattened(&config).await.unwrap();

        let req = RequestInfo::new("GET", "/other", "example.com");
        let result = matcher.match_request(&req, &Scope::Global).await;

        assert!(result.is_none());
    }
}
