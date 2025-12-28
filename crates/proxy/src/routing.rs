//! Route matching and selection module for Sentinel proxy
//!
//! This module implements the routing logic for matching incoming requests
//! to configured routes based on various criteria (path, host, headers, etc.)
//! with support for priority-based evaluation.

use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

use sentinel_common::types::{Priority, RouteId};
use sentinel_config::{MatchCondition, RouteConfig, RoutePolicies};

/// Route matcher for efficient route selection
pub struct RouteMatcher {
    /// Routes sorted by priority (highest first)
    routes: Vec<CompiledRoute>,
    /// Default route ID if no match found
    default_route: Option<RouteId>,
    /// Cache for frequently matched routes (LRU-style)
    cache: Arc<parking_lot::RwLock<RouteCache>>,
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

/// Route cache for performance
struct RouteCache {
    /// Cache entries (cache key -> route ID)
    entries: HashMap<String, RouteId>,
    /// Maximum cache size
    max_size: usize,
    /// Access counter for LRU eviction
    access_counter: u64,
    /// Access timestamps for cache entries
    access_times: HashMap<String, u64>,
}

impl RouteMatcher {
    /// Create a new route matcher from configuration
    pub fn new(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
    ) -> Result<Self, RouteError> {
        let mut compiled_routes = Vec::new();

        for route in routes {
            let compiled = CompiledRoute::compile(route)?;
            compiled_routes.push(compiled);
        }

        // Sort by priority (highest first), then by specificity
        compiled_routes.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| b.specificity().cmp(&a.specificity()))
        });

        Ok(Self {
            routes: compiled_routes,
            default_route: default_route.map(RouteId::new),
            cache: Arc::new(parking_lot::RwLock::new(RouteCache::new(1000))),
        })
    }

    /// Match a request to a route
    pub fn match_request(&self, req: &RequestInfo) -> Option<RouteMatch> {
        // Check cache first
        let cache_key = req.cache_key();
        if let Some(route_id) = self.cache.write().get(&cache_key) {
            debug!(route_id = %route_id, "Cache hit for route");
            if let Some(route) = self.find_route_by_id(&route_id) {
                return Some(RouteMatch {
                    route_id,
                    config: route.config.clone(),
                    policies: route.config.policies.clone(),
                });
            }
        }

        // Evaluate routes in priority order
        for route in &self.routes {
            if route.matches(req) {
                debug!(
                    route_id = %route.id,
                    priority = ?route.priority,
                    "Route matched"
                );

                // Update cache
                self.cache
                    .write()
                    .insert(cache_key.clone(), route.id.clone());

                return Some(RouteMatch {
                    route_id: route.id.clone(),
                    config: route.config.clone(),
                    policies: route.config.policies.clone(),
                });
            }
        }

        // Use default route if configured
        if let Some(ref default_id) = self.default_route {
            debug!(route_id = %default_id, "Using default route");
            if let Some(route) = self.find_route_by_id(default_id) {
                return Some(RouteMatch {
                    route_id: default_id.clone(),
                    config: route.config.clone(),
                    policies: route.config.policies.clone(),
                });
            }
        }

        debug!("No route matched");
        None
    }

    /// Find a route by ID
    fn find_route_by_id(&self, id: &RouteId) -> Option<&CompiledRoute> {
        self.routes.iter().find(|r| r.id == *id)
    }

    /// Clear the route cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read();
        CacheStats {
            entries: cache.entries.len(),
            max_size: cache.max_size,
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
    fn matches(&self, req: &RequestInfo) -> bool {
        // All matchers must pass (AND logic)
        for matcher in &self.matchers {
            if !matcher.matches(req) {
                trace!(
                    route_id = %self.id,
                    matcher = ?matcher,
                    "Matcher failed"
                );
                return false;
            }
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
    fn matches(&self, req: &RequestInfo) -> bool {
        match self {
            Self::Path(path) => req.path == *path,
            Self::PathPrefix(prefix) => req.path.starts_with(prefix),
            Self::PathRegex(regex) => regex.is_match(&req.path),
            Self::Host(host_matcher) => host_matcher.matches(&req.host),
            Self::Header { name, value } => {
                if let Some(header_value) = req.headers.get(name) {
                    value.as_ref().map_or(true, |v| header_value == v)
                } else {
                    false
                }
            }
            Self::Method(methods) => methods.contains(&req.method),
            Self::QueryParam { name, value } => {
                if let Some(param_value) = req.query_params.get(name) {
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
            entries: HashMap::new(),
            max_size,
            access_counter: 0,
            access_times: HashMap::new(),
        }
    }

    /// Get a route from cache
    fn get(&mut self, key: &str) -> Option<RouteId> {
        if let Some(route_id) = self.entries.get(key) {
            self.access_counter += 1;
            self.access_times
                .insert(key.to_string(), self.access_counter);
            Some(route_id.clone())
        } else {
            None
        }
    }

    /// Insert a route into cache
    fn insert(&mut self, key: String, route_id: RouteId) {
        // Evict least recently used if at capacity
        if self.entries.len() >= self.max_size {
            self.evict_lru();
        }

        self.access_counter += 1;
        self.access_times.insert(key.clone(), self.access_counter);
        self.entries.insert(key, route_id);
    }

    /// Evict the least recently used entry
    fn evict_lru(&mut self) {
        if let Some((key, _)) = self
            .access_times
            .iter()
            .min_by_key(|(_, &time)| time)
            .map(|(k, v)| (k.clone(), *v))
        {
            self.entries.remove(&key);
            self.access_times.remove(&key);
        }
    }

    /// Clear all cache entries
    fn clear(&mut self) {
        self.entries.clear();
        self.access_times.clear();
        self.access_counter = 0;
    }
}

/// Request information for route matching
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

impl RequestInfo {
    /// Generate a cache key for this request
    fn cache_key(&self) -> String {
        format!("{}:{}:{}", self.method, self.host, self.path)
    }

    /// Parse query parameters from path
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
}

/// Route match result
#[derive(Debug, Clone)]
pub struct RouteMatch {
    pub route_id: RouteId,
    pub config: Arc<RouteConfig>,
    pub policies: RoutePolicies,
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
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            host: "example.com".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
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
            method: "GET".to_string(),
            path: "/".to_string(),
            host: "api.example.com".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
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
            method: "GET".to_string(),
            path: "/test".to_string(),
            host: "example.com".to_string(),
            headers: HashMap::new(),
            query_params: HashMap::new(),
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
