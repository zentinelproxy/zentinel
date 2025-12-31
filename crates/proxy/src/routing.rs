//! Route matching and selection module for Sentinel proxy
//!
//! This module implements the routing logic for matching incoming requests
//! to configured routes based on various criteria (path, host, headers, etc.)
//! with support for priority-based evaluation.

use dashmap::DashMap;
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

use sentinel_common::types::Priority;
use sentinel_common::RouteId;
use sentinel_config::{MatchCondition, RouteConfig, RoutePolicies};

/// Route matcher for efficient route selection
pub struct RouteMatcher {
    /// Routes sorted by priority (highest first)
    routes: Vec<CompiledRoute>,
    /// Default route ID if no match found
    default_route: Option<RouteId>,
    /// Cache for frequently matched routes (lock-free concurrent access)
    cache: Arc<RouteCache>,
    /// Whether any route requires header matching (optimization flag)
    needs_headers: bool,
    /// Whether any route requires query param matching (optimization flag)
    needs_query_params: bool,
}

/// Compiled route with pre-processed match conditions
struct CompiledRoute {
    /// Route configuration
    config: Arc<RouteConfig>,
    /// Route ID for quick lookup
    id: RouteId,
    /// Priority for ordering
    priority: Priority,
    /// Compiled match conditions
    matchers: Vec<CompiledMatcher>,
}

/// Compiled match condition for efficient evaluation
enum CompiledMatcher {
    /// Exact path match
    Path(String),
    /// Path prefix match
    PathPrefix(String),
    /// Regex path match
    PathRegex(Regex),
    /// Host match (exact or wildcard)
    Host(HostMatcher),
    /// Header presence or value match
    Header { name: String, value: Option<String> },
    /// HTTP method match
    Method(Vec<String>),
    /// Query parameter match
    QueryParam { name: String, value: Option<String> },
}

/// Host matching logic
enum HostMatcher {
    /// Exact host match
    Exact(String),
    /// Wildcard match (*.example.com)
    Wildcard { suffix: String },
    /// Regex match
    Regex(Regex),
}

/// Route cache for performance (lock-free concurrent access)
struct RouteCache {
    /// Cache entries (cache key -> route ID) - lock-free concurrent map
    entries: DashMap<String, RouteId>,
    /// Maximum cache size
    max_size: usize,
    /// Current entry count (approximate, for eviction decisions)
    entry_count: AtomicUsize,
}

impl RouteMatcher {
    /// Create a new route matcher from configuration
    pub fn new(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
    ) -> Result<Self, RouteError> {
        info!(
            route_count = routes.len(),
            default_route = ?default_route,
            "Initializing route matcher"
        );

        let mut compiled_routes = Vec::new();

        for route in routes {
            trace!(
                route_id = %route.id,
                priority = ?route.priority,
                match_count = route.matches.len(),
                "Compiling route"
            );
            let compiled = CompiledRoute::compile(route)?;
            compiled_routes.push(compiled);
        }

        // Sort by priority (highest first), then by specificity
        compiled_routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.specificity().cmp(&a.specificity()))
        });

        // Log final route order
        for (index, route) in compiled_routes.iter().enumerate() {
            debug!(
                route_id = %route.id,
                order = index,
                priority = ?route.priority,
                specificity = route.specificity(),
                "Route compiled and ordered"
            );
        }

        // Determine if any routes need headers or query params (optimization)
        let needs_headers = compiled_routes.iter().any(|r| {
            r.matchers
                .iter()
                .any(|m| matches!(m, CompiledMatcher::Header { .. }))
        });
        let needs_query_params = compiled_routes.iter().any(|r| {
            r.matchers
                .iter()
                .any(|m| matches!(m, CompiledMatcher::QueryParam { .. }))
        });

        info!(
            compiled_routes = compiled_routes.len(),
            needs_headers,
            needs_query_params,
            "Route matcher initialized"
        );

        Ok(Self {
            routes: compiled_routes,
            default_route: default_route.map(RouteId::new),
            cache: Arc::new(RouteCache::new(1000)),
            needs_headers,
            needs_query_params,
        })
    }

    /// Check if any route requires header matching
    #[inline]
    pub fn needs_headers(&self) -> bool {
        self.needs_headers
    }

    /// Check if any route requires query param matching
    #[inline]
    pub fn needs_query_params(&self) -> bool {
        self.needs_query_params
    }

    /// Match a request to a route
    pub fn match_request(&self, req: &RequestInfo<'_>) -> Option<RouteMatch> {
        trace!(
            method = %req.method,
            path = %req.path,
            host = %req.host,
            "Starting route matching"
        );

        // Check cache first (lock-free read)
        let cache_key = req.cache_key();
        if let Some(route_id_ref) = self.cache.get(&cache_key) {
            let route_id = route_id_ref.clone();
            drop(route_id_ref); // Release the ref before further processing
            trace!(
                route_id = %route_id,
                cache_key = %cache_key,
                "Route cache hit"
            );
            if let Some(route) = self.find_route_by_id(&route_id) {
                debug!(
                    route_id = %route_id,
                    method = %req.method,
                    path = %req.path,
                    source = "cache",
                    "Route matched from cache"
                );
                return Some(RouteMatch {
                    route_id,
                    config: route.config.clone(),
                });
            }
        }

        trace!(
            cache_key = %cache_key,
            route_count = self.routes.len(),
            "Cache miss, evaluating routes"
        );

        // Evaluate routes in priority order
        for (index, route) in self.routes.iter().enumerate() {
            trace!(
                route_id = %route.id,
                route_index = index,
                priority = ?route.priority,
                matcher_count = route.matchers.len(),
                "Evaluating route"
            );

            if route.matches(req) {
                debug!(
                    route_id = %route.id,
                    method = %req.method,
                    path = %req.path,
                    host = %req.host,
                    priority = ?route.priority,
                    route_index = index,
                    "Route matched"
                );

                // Update cache (lock-free insert)
                self.cache.insert(cache_key.clone(), route.id.clone());

                trace!(
                    route_id = %route.id,
                    cache_key = %cache_key,
                    "Route added to cache"
                );

                return Some(RouteMatch {
                    route_id: route.id.clone(),
                    config: route.config.clone(),
                });
            }
        }

        // Use default route if configured
        if let Some(ref default_id) = self.default_route {
            debug!(
                route_id = %default_id,
                method = %req.method,
                path = %req.path,
                "Using default route (no explicit match)"
            );
            if let Some(route) = self.find_route_by_id(default_id) {
                return Some(RouteMatch {
                    route_id: default_id.clone(),
                    config: route.config.clone(),
                });
            }
        }

        debug!(
            method = %req.method,
            path = %req.path,
            host = %req.host,
            routes_evaluated = self.routes.len(),
            "No route matched"
        );
        None
    }

    /// Find a route by ID
    fn find_route_by_id(&self, id: &RouteId) -> Option<&CompiledRoute> {
        self.routes.iter().find(|r| r.id == *id)
    }

    /// Clear the route cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            entries: self.cache.len(),
            max_size: self.cache.max_size,
            hit_rate: 0.0, // TODO: Track hits and misses
        }
    }
}

impl CompiledRoute {
    /// Compile a route configuration into an optimized matcher
    fn compile(config: RouteConfig) -> Result<Self, RouteError> {
        let mut matchers = Vec::new();

        for condition in &config.matches {
            let compiled = match condition {
                MatchCondition::Path(path) => CompiledMatcher::Path(path.clone()),
                MatchCondition::PathPrefix(prefix) => CompiledMatcher::PathPrefix(prefix.clone()),
                MatchCondition::PathRegex(pattern) => {
                    let regex = Regex::new(pattern).map_err(|e| RouteError::InvalidRegex {
                        pattern: pattern.clone(),
                        error: e.to_string(),
                    })?;
                    CompiledMatcher::PathRegex(regex)
                }
                MatchCondition::Host(host) => CompiledMatcher::Host(HostMatcher::parse(host)),
                MatchCondition::Header { name, value } => CompiledMatcher::Header {
                    name: name.to_lowercase(),
                    value: value.clone(),
                },
                MatchCondition::Method(methods) => {
                    CompiledMatcher::Method(methods.iter().map(|m| m.to_uppercase()).collect())
                }
                MatchCondition::QueryParam { name, value } => CompiledMatcher::QueryParam {
                    name: name.clone(),
                    value: value.clone(),
                },
            };
            matchers.push(compiled);
        }

        Ok(Self {
            id: RouteId::new(&config.id),
            priority: config.priority,
            config: Arc::new(config),
            matchers,
        })
    }

    /// Check if this route matches the request
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        // All matchers must pass (AND logic)
        for (index, matcher) in self.matchers.iter().enumerate() {
            let result = matcher.matches(req);
            if !result {
                trace!(
                    route_id = %self.id,
                    matcher_index = index,
                    matcher_type = ?matcher,
                    path = %req.path,
                    "Matcher did not match"
                );
                return false;
            }
            trace!(
                route_id = %self.id,
                matcher_index = index,
                matcher_type = ?matcher,
                "Matcher passed"
            );
        }
        true
    }

    /// Calculate route specificity for tie-breaking
    fn specificity(&self) -> u32 {
        let mut score = 0;
        for matcher in &self.matchers {
            score += match matcher {
                CompiledMatcher::Path(_) => 1000,     // Exact path is most specific
                CompiledMatcher::PathRegex(_) => 500, // Regex is moderately specific
                CompiledMatcher::PathPrefix(_) => 100, // Prefix is least specific
                CompiledMatcher::Host(_) => 50,
                CompiledMatcher::Header { value, .. } => {
                    if value.is_some() {
                        30
                    } else {
                        20
                    }
                }
                CompiledMatcher::Method(_) => 10,
                CompiledMatcher::QueryParam { value, .. } => {
                    if value.is_some() {
                        25
                    } else {
                        15
                    }
                }
            };
        }
        score
    }
}

impl CompiledMatcher {
    /// Check if this matcher matches the request
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        match self {
            Self::Path(path) => req.path == *path,
            Self::PathPrefix(prefix) => req.path.starts_with(prefix),
            Self::PathRegex(regex) => regex.is_match(req.path),
            Self::Host(host_matcher) => host_matcher.matches(req.host),
            Self::Header { name, value } => {
                if let Some(header_value) = req.headers().get(name) {
                    value.as_ref().map_or(true, |v| header_value == v)
                } else {
                    false
                }
            }
            Self::Method(methods) => methods.iter().any(|m| m == req.method),
            Self::QueryParam { name, value } => {
                if let Some(param_value) = req.query_params().get(name) {
                    value.as_ref().map_or(true, |v| param_value == v)
                } else {
                    false
                }
            }
        }
    }
}

impl HostMatcher {
    /// Parse a host pattern into a matcher
    fn parse(pattern: &str) -> Self {
        if pattern.starts_with("*.") {
            // Wildcard pattern
            Self::Wildcard {
                suffix: pattern[2..].to_string(),
            }
        } else if pattern.contains('*') || pattern.contains('[') {
            // Treat as regex if it contains other special characters
            if let Ok(regex) = Regex::new(pattern) {
                Self::Regex(regex)
            } else {
                // Fall back to exact match if regex compilation fails
                warn!("Invalid host regex pattern: {}, using exact match", pattern);
                Self::Exact(pattern.to_string())
            }
        } else {
            // Exact match
            Self::Exact(pattern.to_string())
        }
    }

    /// Check if this matcher matches the host
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(pattern) => host == pattern,
            Self::Wildcard { suffix } => {
                host.ends_with(suffix)
                    && host.len() > suffix.len()
                    && host[..host.len() - suffix.len()].ends_with('.')
            }
            Self::Regex(regex) => regex.is_match(host),
        }
    }
}

impl RouteCache {
    /// Create a new route cache
    fn new(max_size: usize) -> Self {
        Self {
            entries: DashMap::with_capacity(max_size),
            max_size,
            entry_count: AtomicUsize::new(0),
        }
    }

    /// Get a route from cache (lock-free)
    fn get(&self, key: &str) -> Option<dashmap::mapref::one::Ref<'_, String, RouteId>> {
        self.entries.get(key)
    }

    /// Insert a route into cache (lock-free)
    fn insert(&self, key: String, route_id: RouteId) {
        // Check if we need to evict (approximate check to avoid overhead)
        let current_count = self.entry_count.load(Ordering::Relaxed);
        if current_count >= self.max_size {
            // Evict ~10% of entries randomly for simplicity
            // This is faster than true LRU and good enough for a cache
            self.evict_random();
        }

        if self.entries.insert(key, route_id).is_none() {
            // Only increment if this was a new entry
            self.entry_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Evict random entries when cache is full
    fn evict_random(&self) {
        let to_evict = self.max_size / 10; // Evict ~10%
        let mut evicted = 0;

        // Iterate and remove some entries
        self.entries.retain(|_, _| {
            if evicted < to_evict {
                evicted += 1;
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });

        // Update count (approximate)
        self.entry_count.store(self.entries.len(), Ordering::Relaxed);
    }

    /// Get current cache size
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Clear all cache entries
    fn clear(&self) {
        self.entries.clear();
        self.entry_count.store(0, Ordering::Relaxed);
    }
}

/// Request information for route matching (zero-copy where possible)
#[derive(Debug)]
pub struct RequestInfo<'a> {
    /// HTTP method (borrowed from request header)
    pub method: &'a str,
    /// Request path (borrowed from request header)
    pub path: &'a str,
    /// Host header value (borrowed from request header)
    pub host: &'a str,
    /// Headers for matching (lazy-initialized, only if needed)
    headers: Option<HashMap<String, String>>,
    /// Query parameters (lazy-initialized, only if needed)
    query_params: Option<HashMap<String, String>>,
}

impl<'a> RequestInfo<'a> {
    /// Create a new RequestInfo with borrowed references (zero-copy for common case)
    #[inline]
    pub fn new(method: &'a str, path: &'a str, host: &'a str) -> Self {
        Self {
            method,
            path,
            host,
            headers: None,
            query_params: None,
        }
    }

    /// Set headers for header-based matching (only call if RouteMatcher.needs_headers())
    #[inline]
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        self.headers = Some(headers);
        self
    }

    /// Set query params for query-based matching (only call if RouteMatcher.needs_query_params())
    #[inline]
    pub fn with_query_params(mut self, params: HashMap<String, String>) -> Self {
        self.query_params = Some(params);
        self
    }

    /// Get headers (returns empty map if not set)
    #[inline]
    pub fn headers(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        self.headers.as_ref().unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Get query params (returns empty map if not set)
    #[inline]
    pub fn query_params(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        self.query_params.as_ref().unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Generate a cache key for this request
    fn cache_key(&self) -> String {
        format!("{}:{}:{}", self.method, self.host, self.path)
    }

    /// Parse query parameters from path (only call when needed)
    pub fn parse_query_params(path: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if let Some(query_start) = path.find('?') {
            let query = &path[query_start + 1..];
            for pair in query.split('&') {
                if let Some(eq_pos) = pair.find('=') {
                    let key = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];
                    params.insert(
                        urlencoding::decode(key)
                            .unwrap_or_else(|_| key.into())
                            .into_owned(),
                        urlencoding::decode(value)
                            .unwrap_or_else(|_| value.into())
                            .into_owned(),
                    );
                } else {
                    params.insert(
                        urlencoding::decode(pair)
                            .unwrap_or_else(|_| pair.into())
                            .into_owned(),
                        String::new(),
                    );
                }
            }
        }
        params
    }

    /// Build headers map from request header iterator (only call when needed)
    pub fn build_headers<'b, I>(iter: I) -> HashMap<String, String>
    where
        I: Iterator<Item = (&'b http::header::HeaderName, &'b http::header::HeaderValue)>,
    {
        let mut headers = HashMap::new();
        for (name, value) in iter {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value_str.to_string());
            }
        }
        headers
    }
}

/// Route match result
#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub route_id: RouteId,
    pub config: Arc<RouteConfig>,
}

impl RouteMatch {
    /// Access route policies (convenience accessor to avoid repeated .config.policies)
    #[inline]
    pub fn policies(&self) -> &RoutePolicies {
        &self.config.policies
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entries: usize,
    pub max_size: usize,
    pub hit_rate: f64,
}

/// Route matching errors
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },

    #[error("Invalid route configuration: {0}")]
    InvalidConfig(String),

    #[error("Duplicate route ID: {0}")]
    DuplicateRouteId(String),
}

impl std::fmt::Debug for CompiledMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(p) => write!(f, "Path({})", p),
            Self::PathPrefix(p) => write!(f, "PathPrefix({})", p),
            Self::PathRegex(_) => write!(f, "PathRegex(...)"),
            Self::Host(_) => write!(f, "Host(...)"),
            Self::Header { name, .. } => write!(f, "Header({})", name),
            Self::Method(m) => write!(f, "Method({:?})", m),
            Self::QueryParam { name, .. } => write!(f, "QueryParam({})", name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_common::types::Priority;
    use sentinel_config::{MatchCondition, RouteConfig};

    fn create_test_route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::Normal,
            matches,
            upstream: Some("test_upstream".to_string()),
            service_type: sentinel_config::ServiceType::Web,
            policies: Default::default(),
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
        }
    }

    #[test]
    fn test_path_matching() {
        let routes = vec![
            create_test_route(
                "exact",
                vec![MatchCondition::Path("/api/v1/users".to_string())],
            ),
            create_test_route(
                "prefix",
                vec![MatchCondition::PathPrefix("/api/".to_string())],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/api/v1/users",
            host: "example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "exact");
    }

    #[test]
    fn test_host_wildcard_matching() {
        let routes = vec![create_test_route(
            "wildcard",
            vec![MatchCondition::Host("*.example.com".to_string())],
        )];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/",
            host: "api.example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "wildcard");
    }

    #[test]
    fn test_priority_ordering() {
        let mut route1 =
            create_test_route("low", vec![MatchCondition::PathPrefix("/".to_string())]);
        route1.priority = Priority::Low;

        let mut route2 =
            create_test_route("high", vec![MatchCondition::PathPrefix("/".to_string())]);
        route2.priority = Priority::High;

        let routes = vec![route1, route2];
        let matcher = RouteMatcher::new(routes, None).unwrap();

        let req = RequestInfo {
            method: "GET",
            path: "/test",
            host: "example.com",
            headers: None,
            query_params: None,
        };

        let result = matcher.match_request(&req).unwrap();
        assert_eq!(result.route_id.as_str(), "high");
    }

    #[test]
    fn test_query_param_parsing() {
        let params = RequestInfo::parse_query_params("/path?foo=bar&baz=qux&empty=");
        assert_eq!(params.get("foo"), Some(&"bar".to_string()));
        assert_eq!(params.get("baz"), Some(&"qux".to_string()));
        assert_eq!(params.get("empty"), Some(&"".to_string()));
    }
}
