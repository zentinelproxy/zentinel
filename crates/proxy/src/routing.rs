//! Route matching and selection module for Zentinel proxy
//!
//! This module implements the routing logic for matching incoming requests
//! to configured routes based on various criteria (path, host, headers, etc.)
//! with support for priority-based evaluation.

use dashmap::DashMap;
use prometheus::{register_int_counter, IntCounter};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use tracing::{debug, info, trace, warn};

/// Entries evicted from the route-match cache to enforce `route-cache-size`.
static ROUTE_CACHE_EVICTIONS: LazyLock<Option<IntCounter>> = LazyLock::new(|| {
    register_int_counter!(
        "zentinel_route_cache_evictions_total",
        "Route-match cache entries evicted to enforce route-cache-size"
    )
    .ok()
});

use zentinel_common::ids::Scope;
use zentinel_common::types::Priority;
use zentinel_common::RouteId;
use zentinel_config::{MatchCondition, RouteConfig, RoutePolicies};

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
    /// Cache hits counter
    hits: AtomicU64,
    /// Cache misses counter
    misses: AtomicU64,
}

impl RouteMatcher {
    /// Create a new route matcher from configuration with the default
    /// route-cache size (1000 entries).
    pub fn new(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
    ) -> Result<Self, RouteError> {
        Self::with_cache_size(routes, default_route, 1000)
    }

    /// Create a new route matcher with an explicit route-cache size
    /// (`system { route-cache-size N }`).
    pub fn with_cache_size(
        routes: Vec<RouteConfig>,
        default_route: Option<String>,
        cache_size: usize,
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
            needs_headers, needs_query_params, "Route matcher initialized"
        );

        Ok(Self {
            routes: compiled_routes,
            default_route: default_route.map(RouteId::new),
            cache: Arc::new(RouteCache::new(cache_size)),
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

        // Check cache first (lock-free read, zero-allocation on hit)
        let cached = req.with_cache_key(|key| {
            self.cache.get(key).map(|r| {
                let route_id = r.clone();
                drop(r);
                route_id
            })
        });
        if let Some(route_id) = cached {
            trace!(
                route_id = %route_id,
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

        // Record cache miss
        self.cache.record_miss();

        trace!(
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

                // Update cache — allocate key only on miss (rare after warmup)
                req.with_cache_key(|key| {
                    self.cache.insert(key.to_string(), route.id.clone());
                });

                trace!(
                    route_id = %route.id,
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
            hit_rate: self.cache.hit_rate(),
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

    /// Check if this route matches the request.
    ///
    /// Host matchers use OR logic (match any host), all other matchers use AND.
    /// This matches Gateway API semantics where multiple hostnames on an
    /// HTTPRoute are alternatives, not conjunctions.
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        // Partition matchers into host matchers and non-host matchers
        let mut has_host_matchers = false;
        let mut any_host_matched = false;

        for matcher in &self.matchers {
            match matcher {
                CompiledMatcher::Host(_) => {
                    has_host_matchers = true;
                    if matcher.matches(req) {
                        any_host_matched = true;
                    }
                }
                _ => {
                    if !matcher.matches(req) {
                        trace!(
                            route_id = %self.id,
                            matcher_type = ?matcher,
                            path = %req.path,
                            "Matcher did not match"
                        );
                        return false;
                    }
                }
            }
        }

        // If there are host matchers, at least one must match (OR logic)
        if has_host_matchers && !any_host_matched {
            trace!(
                route_id = %self.id,
                host = %req.host,
                "No host matcher matched"
            );
            return false;
        }

        true
    }

    /// Calculate route specificity for tie-breaking.
    ///
    /// Per Gateway API precedence rules:
    /// 1. Path specificity is primary (exact > longest prefix > regex)
    /// 2. Host specificity is secondary (exact > wildcard)
    /// 3. Header/method/query conditions add specificity
    ///
    /// Host matchers use OR logic, so multiple hosts don't increase
    /// specificity — we use the max host score, not the sum.
    fn specificity(&self) -> u32 {
        let mut path_score = 0u32;
        let mut host_score = 0u32;
        let mut condition_score = 0u32;

        for matcher in &self.matchers {
            match matcher {
                CompiledMatcher::Path(_) => path_score = path_score.max(10000),
                CompiledMatcher::PathRegex(_) => path_score = path_score.max(5000),
                CompiledMatcher::PathPrefix(p) => {
                    path_score = path_score.max(1000 + p.len() as u32)
                }
                CompiledMatcher::Host(host) => {
                    let s = match host {
                        HostMatcher::Exact(_) => 70,
                        HostMatcher::Regex(_) => 60,
                        HostMatcher::Wildcard { .. } => 50,
                    };
                    host_score = host_score.max(s);
                }
                CompiledMatcher::Header { value, .. } => {
                    condition_score += if value.is_some() { 30 } else { 20 };
                }
                CompiledMatcher::Method(_) => condition_score += 10,
                CompiledMatcher::QueryParam { value, .. } => {
                    condition_score += if value.is_some() { 25 } else { 15 };
                }
            }
        }

        path_score + host_score + condition_score
    }
}

impl CompiledMatcher {
    /// Check if this matcher matches the request
    fn matches(&self, req: &RequestInfo<'_>) -> bool {
        match self {
            Self::Path(path) => req.path == *path,
            Self::PathPrefix(prefix) => {
                if !req.path.starts_with(prefix) {
                    return false;
                }
                // Enforce segment boundary per Gateway API spec:
                // PathPrefix "/v2" must NOT match "/v2example", only "/v2", "/v2/", "/v2/anything"
                prefix == "/"
                    || req.path.len() == prefix.len()
                    || prefix.ends_with('/')
                    || req.path.as_bytes()[prefix.len()] == b'/'
                    || req.path.as_bytes()[prefix.len()] == b'?'
            }
            Self::PathRegex(regex) => regex.is_match(req.path),
            Self::Host(host_matcher) => host_matcher.matches(req.host),
            Self::Header { name, value } => {
                if let Some(header_value) = req.headers().get(name) {
                    value.as_ref().is_none_or(|v| header_value == v)
                } else {
                    false
                }
            }
            Self::Method(methods) => methods.iter().any(|m| m == req.method),
            Self::QueryParam { name, value } => {
                if let Some(param_value) = req.query_params().get(name) {
                    value.as_ref().is_none_or(|v| param_value == v)
                } else {
                    false
                }
            }
        }
    }
}

/// Normalize a host for comparison.
///
/// Three things, each of which was a way for a route to silently not match:
///
/// * **Port removed.** `Host: example.com:8080` must match `example.com`, per
///   the Gateway API spec.
/// * **Trailing dot removed.** `example.com.` names the same host as
///   `example.com`. Without this a restrictive host route could be skipped by
///   appending a dot, falling through to whatever permissive route follows.
/// * **Lowercased.** Host comparison is case-insensitive (RFC 3986 §3.2.2).
///   Both sides are normalized, so neither a mixed-case request nor a
///   mixed-case config silently matches nothing.
fn normalize_host(host: &str) -> String {
    // An IPv6 literal is bracketed and full of colons, so its port is
    // whatever follows the closing bracket. Splitting on the first colon
    // would reduce `[::1]:8080` to `[`.
    let without_port = if host.starts_with('[') {
        match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        host.split(':').next().unwrap_or(host)
    };

    let without_dot = without_port.strip_suffix('.').unwrap_or(without_port);
    without_dot.to_ascii_lowercase()
}

impl HostMatcher {
    /// Parse a host pattern into a matcher.
    ///
    /// The pattern is normalized the same way request hosts are, so a route
    /// written `host "Example.com"` matches `example.com`. Without that it
    /// matched nothing at all, silently.
    fn parse(pattern: &str) -> Self {
        let pattern = normalize_host(pattern);
        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard pattern
            Self::Wildcard {
                suffix: suffix.to_string(),
            }
        } else if pattern.contains('*') || pattern.contains('[') {
            // Treat as regex if it contains other special characters.
            // Built case-insensitively rather than by lowercasing the pattern,
            // which would corrupt character classes such as [A-Z].
            match regex::RegexBuilder::new(&pattern)
                .case_insensitive(true)
                .build()
            {
                Ok(regex) => Self::Regex(regex),
                Err(_) => {
                    // Fall back to exact match if regex compilation fails
                    warn!("Invalid host regex pattern: {}, using exact match", pattern);
                    Self::Exact(pattern)
                }
            }
        } else {
            // Exact match
            Self::Exact(pattern)
        }
    }

    /// Check if this matcher matches the host.
    fn matches(&self, host: &str) -> bool {
        let host = normalize_host(host);
        let host = host.as_str();
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
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Get a route from cache (lock-free)
    fn get(&self, key: &str) -> Option<dashmap::mapref::one::Ref<'_, String, RouteId>> {
        let result = self.entries.get(key);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Record a cache miss
    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the hit rate (0.0 to 1.0)
    fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
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
        let to_evict = (self.max_size / 10).max(1); // Evict ~10%
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
        self.entry_count
            .store(self.entries.len(), Ordering::Relaxed);

        debug!(
            evicted = evicted,
            remaining = self.entries.len(),
            max_size = self.max_size,
            "Route cache at capacity; evicted entries"
        );
        if let Some(counter) = ROUTE_CACHE_EVICTIONS.as_ref() {
            counter.inc_by(evicted as u64);
        }
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
        self.headers
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Get query params (returns empty map if not set)
    #[inline]
    pub fn query_params(&self) -> &HashMap<String, String> {
        static EMPTY: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
        self.query_params
            .as_ref()
            .unwrap_or_else(|| EMPTY.get_or_init(HashMap::new))
    }

    /// Generate a cache key for this request using a thread-local buffer
    /// to avoid per-request heap allocation.
    fn with_cache_key<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        use std::cell::RefCell;
        use std::fmt::Write;

        thread_local! {
            static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
        }

        BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            let _ = write!(buf, "{}:{}:{}", self.method, self.host, self.path);
            // Include headers in cache key when header-based routing is active,
            // otherwise different header combinations can poison the cache.
            if let Some(ref headers) = self.headers {
                let mut pairs: Vec<_> = headers.iter().collect();
                pairs.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in pairs {
                    let _ = write!(buf, "\n{k}={v}");
                }
            }
            // Query parameters, for the same reason. `path` here comes from
            // `Uri::path()` and carries no query string, so without this two
            // requests differing only in their query share a cache entry: once
            // `/api?version=v2` is cached, `/api?version=v1` is served the v2
            // route and reaches the wrong upstream.
            //
            // The separator differs from the header one so a header and a
            // query parameter with the same name and value cannot produce the
            // same key.
            if let Some(ref params) = self.query_params {
                let mut pairs: Vec<_> = params.iter().collect();
                pairs.sort_by_key(|(k, _)| k.as_str());
                for (k, v) in pairs {
                    let _ = write!(buf, "\t{k}={v}");
                }
            }
            f(&buf)
        })
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

/// The routes of `config` (the lowered configuration) served on a listener
/// of `scope`, without the namespace and service routes that do not compile.
///
/// Namespace and service routes were never compiled before #548 -- they were
/// served nowhere, or on a namespace-bound listener whose matcher was skipped
/// with an error when it did not build -- so one with an invalid pattern did
/// not stop the proxy from starting. Compiling them now must not either:
/// such a route is left out (see [`unservable_scoped_routes`]), while a
/// global route that does not compile still fails startup as it always did.
pub fn routes_served_on(
    config: &zentinel_config::Config,
    scope: &zentinel_common::ids::Scope,
) -> Vec<RouteConfig> {
    config
        .routes_served_on(scope)
        .into_iter()
        .filter(|route| config.route_scope(&route.id).is_global() || route_compiles(route).is_ok())
        .collect()
}

/// A message for every namespace or service route [`routes_served_on`]
/// leaves out, for the log and for `zentinel test` / `zentinel lint`.
pub fn unservable_scoped_routes(config: &zentinel_config::Config) -> Vec<String> {
    config
        .routes
        .iter()
        .filter(|route| !config.route_scope(&route.id).is_global())
        .filter_map(|route| {
            route_compiles(route).err().map(|e| {
                format!(
                    "Route '{}' is being ignored: {e}. Fix the route to serve it.",
                    route.id
                )
            })
        })
        .collect()
}

fn route_compiles(route: &RouteConfig) -> Result<(), RouteError> {
    RouteMatcher::with_cache_size(vec![route.clone()], None, 1).map(|_| ())
}

/// Every route set the proxy compiles into a matcher of its own: the routes
/// of the global listeners first, then those of each namespace or service
/// scope that has a listener, once per scope, in listener order.
///
/// `config` is the lowered configuration. Startup, the reload handler and
/// [`crate::reload::RouteMatcherValidator`] all go through this, so a reload
/// is validated against exactly the matchers it would build.
pub fn route_sets(config: &zentinel_config::Config) -> Vec<(Scope, Vec<RouteConfig>)> {
    let mut scopes = vec![Scope::Global];
    for listener in &config.listeners {
        let scope = listener.scope();
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes
        .into_iter()
        .map(|scope| {
            let routes = routes_served_on(config, &scope);
            (scope, routes)
        })
        .collect()
}

/// Compile one of the [`route_sets`] of `config` with the configured route
/// cache size.
pub fn compile_route_set(
    config: &zentinel_config::Config,
    scope: &Scope,
    routes: Vec<RouteConfig>,
) -> Result<RouteMatcher, RouteSetError> {
    RouteMatcher::with_cache_size(routes, None, config.server.route_cache_size).map_err(|source| {
        RouteSetError {
            scope: scope.clone(),
            source,
        }
    })
}

/// A route set that does not compile, with the scope whose listeners serve it.
#[derive(Debug, thiserror::Error)]
#[error("the routes served on the {scope} listeners do not compile: {source}")]
pub struct RouteSetError {
    pub scope: Scope,
    #[source]
    pub source: RouteError,
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
    use zentinel_common::ids::Scope;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RouteConfig};

    #[test]
    fn route_cache_never_exceeds_max_size() {
        let cache = RouteCache::new(10);
        for i in 0..100 {
            cache.insert(format!("key-{i}"), RouteId::new(format!("route-{i}")));
            assert!(
                cache.len() <= 10,
                "route cache grew past max_size: {}",
                cache.len()
            );
        }
    }

    fn create_test_route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::NORMAL,
            matches,
            upstream: Some("test_upstream".to_string()),
            service_type: zentinel_config::ServiceType::Web,
            policies: Default::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
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
        route1.priority = Priority::LOW;

        let mut route2 =
            create_test_route("high", vec![MatchCondition::PathPrefix("/".to_string())]);
        route2.priority = Priority::HIGH;

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

    #[test]
    fn test_path_prefix_segment_boundary() {
        let routes = vec![
            create_test_route("v2", vec![MatchCondition::PathPrefix("/v2".to_string())]),
            create_test_route(
                "catch-all",
                vec![MatchCondition::PathPrefix("/".to_string())],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        // /v2 exact → v2
        let req = RequestInfo::new("GET", "/v2", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2/ with trailing slash → v2
        let req = RequestInfo::new("GET", "/v2/", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2/anything → v2
        let req = RequestInfo::new("GET", "/v2/anything", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");

        // /v2example must NOT match /v2 prefix — falls to catch-all
        let req = RequestInfo::new("GET", "/v2example", "example.com");
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "catch-all"
        );

        // /v2?query → v2
        let req = RequestInfo::new("GET", "/v2?foo=bar", "example.com");
        assert_eq!(matcher.match_request(&req).unwrap().route_id.as_str(), "v2");
    }

    #[test]
    fn test_header_matching_with_specificity() {
        let routes = vec![
            create_test_route(
                "catch-all",
                vec![MatchCondition::PathPrefix("/".to_string())],
            ),
            create_test_route(
                "header-v2",
                vec![
                    MatchCondition::Header {
                        name: "version".to_string(),
                        value: Some("two".to_string()),
                    },
                    MatchCondition::PathPrefix("/".to_string()),
                ],
            ),
        ];

        let matcher = RouteMatcher::new(routes, None).unwrap();

        // Without headers → catch-all
        let req = RequestInfo::new("GET", "/", "example.com");
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "catch-all"
        );

        // With version:two header → header-v2 (more specific)
        let mut headers = HashMap::new();
        headers.insert("version".to_string(), "two".to_string());
        let req = RequestInfo::new("GET", "/", "example.com").with_headers(headers);
        assert_eq!(
            matcher.match_request(&req).unwrap().route_id.as_str(),
            "header-v2"
        );
    }
}

#[cfg(test)]
mod probe_113 {
    use super::*;
    use zentinel_common::ids::Scope;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RouteConfig};

    fn route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::NORMAL,
            matches,
            upstream: Some("u".to_string()),
            service_type: zentinel_config::ServiceType::Web,
            policies: Default::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
        }
    }

    #[test]
    fn probe_query_param_matching() {
        let build = || {
            RouteMatcher::new(
                vec![
                    route(
                        "v2",
                        vec![
                            MatchCondition::PathPrefix("/api".into()),
                            MatchCondition::QueryParam {
                                name: "version".into(),
                                value: Some("v2".into()),
                            },
                        ],
                    ),
                    route("fallback", vec![MatchCondition::PathPrefix("/api".into())]),
                ],
                None,
            )
            .unwrap()
        };

        // A: correct param, fresh matcher.
        let m = build();
        let mut p1 = std::collections::HashMap::new();
        p1.insert("version".to_string(), "v2".to_string());
        let r = m.match_request(&RequestInfo::new("GET", "/api/x", "h").with_query_params(p1));
        println!(
            "  A version=v2, fresh   -> {:?}",
            r.map(|r| r.route_id.to_string())
        );

        // B: WRONG param, fresh matcher. Should fall through to "fallback".
        let m = build();
        let mut p2 = std::collections::HashMap::new();
        p2.insert("version".to_string(), "v1".to_string());
        let r = m.match_request(&RequestInfo::new("GET", "/api/x", "h").with_query_params(p2));
        println!(
            "  B version=v1, fresh   -> {:?}",
            r.map(|r| r.route_id.to_string())
        );

        // C: NO params, fresh matcher. Should fall through to "fallback".
        let m = build();
        let r = m.match_request(&RequestInfo::new("GET", "/api/x", "h"));
        println!(
            "  C no params, fresh    -> {:?}",
            r.map(|r| r.route_id.to_string())
        );

        // D: cache poisoning -- same matcher, v2 first then v1.
        let m = build();
        let mut pa = std::collections::HashMap::new();
        pa.insert("version".to_string(), "v2".to_string());
        let first = m.match_request(&RequestInfo::new("GET", "/api/x", "h").with_query_params(pa));
        let mut pb = std::collections::HashMap::new();
        pb.insert("version".to_string(), "v1".to_string());
        let second = m.match_request(&RequestInfo::new("GET", "/api/x", "h").with_query_params(pb));
        println!(
            "  D v2 then v1, shared  -> first={:?} second={:?}",
            first.map(|r| r.route_id.to_string()),
            second.map(|r| r.route_id.to_string())
        );
    }
}

#[cfg(test)]
mod route_cache_correctness {
    use super::*;
    use std::collections::HashMap;
    use zentinel_common::ids::Scope;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RouteConfig};

    fn route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::NORMAL,
            matches,
            upstream: Some("u".to_string()),
            service_type: zentinel_config::ServiceType::Web,
            policies: Default::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
        }
    }

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn matched(m: &RouteMatcher, req: &RequestInfo<'_>) -> Option<String> {
        m.match_request(req).map(|r| r.route_id.to_string())
    }

    fn query_matcher() -> RouteMatcher {
        RouteMatcher::new(
            vec![
                route(
                    "v2",
                    vec![
                        MatchCondition::PathPrefix("/api".into()),
                        MatchCondition::QueryParam {
                            name: "version".into(),
                            value: Some("v2".into()),
                        },
                    ],
                ),
                route("fallback", vec![MatchCondition::PathPrefix("/api".into())]),
            ],
            None,
        )
        .unwrap()
    }

    /// Two requests differing only in a query parameter must not share a cache
    /// entry.
    ///
    /// `path` comes from `Uri::path()` and carries no query string, so before
    /// query parameters were part of the cache key, the first request through
    /// a path decided the route for every later request to that path. A
    /// `?version=v2` request would pin `/api` to the v2 route and a subsequent
    /// `?version=v1` would be sent to the wrong upstream.
    #[test]
    fn a_query_parameter_change_is_not_served_from_cache() {
        let m = query_matcher();

        let first = matched(
            &m,
            &RequestInfo::new("GET", "/api/x", "h").with_query_params(params(&[("version", "v2")])),
        );
        let second = matched(
            &m,
            &RequestInfo::new("GET", "/api/x", "h").with_query_params(params(&[("version", "v1")])),
        );

        assert_eq!(first.as_deref(), Some("v2"));
        assert_eq!(
            second.as_deref(),
            Some("fallback"),
            "the second request was served the first request's route from cache"
        );
    }

    /// And in the other order, so the test cannot pass merely because the
    /// first result happened to be the fallback.
    #[test]
    fn the_reverse_order_is_also_correct() {
        let m = query_matcher();

        let first = matched(
            &m,
            &RequestInfo::new("GET", "/api/x", "h").with_query_params(params(&[("version", "v1")])),
        );
        let second = matched(
            &m,
            &RequestInfo::new("GET", "/api/x", "h").with_query_params(params(&[("version", "v2")])),
        );

        assert_eq!(first.as_deref(), Some("fallback"));
        assert_eq!(second.as_deref(), Some("v2"));
    }

    /// A request with no query parameters must not pick up a cached entry from
    /// one that had them.
    #[test]
    fn an_absent_query_parameter_is_distinct_from_a_present_one() {
        let m = query_matcher();

        assert_eq!(
            matched(
                &m,
                &RequestInfo::new("GET", "/api/x", "h")
                    .with_query_params(params(&[("version", "v2")]))
            )
            .as_deref(),
            Some("v2")
        );
        assert_eq!(
            matched(&m, &RequestInfo::new("GET", "/api/x", "h")).as_deref(),
            Some("fallback"),
            "a request without the parameter must not inherit the parameterised route"
        );
    }

    /// Parameter order in the map must not change the key, or the cache would
    /// miss on every request and quietly stop being a cache.
    #[test]
    fn parameter_order_does_not_affect_the_cache_key() {
        let m = query_matcher();

        let a = RequestInfo::new("GET", "/api/x", "h")
            .with_query_params(params(&[("version", "v2"), ("page", "1")]));
        let b = RequestInfo::new("GET", "/api/x", "h")
            .with_query_params(params(&[("page", "1"), ("version", "v2")]));

        assert_eq!(matched(&m, &a).as_deref(), Some("v2"));
        assert_eq!(matched(&m, &b).as_deref(), Some("v2"));

        // Both requests are the same request, so they must share one cache
        // entry. Two entries would mean the key depends on map iteration
        // order, and the cache would miss on almost every request.
        assert_eq!(
            m.cache_stats().entries,
            1,
            "parameter order changed the cache key"
        );
    }

    /// A header and a query parameter with the same name and value must not
    /// collide, or one could stand in for the other.
    #[test]
    fn a_header_and_a_query_parameter_do_not_collide() {
        let m = RouteMatcher::new(
            vec![
                route(
                    "by-header",
                    vec![
                        MatchCondition::PathPrefix("/x".into()),
                        MatchCondition::Header {
                            name: "tenant".into(),
                            value: Some("acme".into()),
                        },
                    ],
                ),
                route(
                    "by-query",
                    vec![
                        MatchCondition::PathPrefix("/x".into()),
                        MatchCondition::QueryParam {
                            name: "tenant".into(),
                            value: Some("acme".into()),
                        },
                    ],
                ),
                route("fallback", vec![MatchCondition::PathPrefix("/x".into())]),
            ],
            None,
        )
        .unwrap();

        let with_header =
            RequestInfo::new("GET", "/x", "h").with_headers(params(&[("tenant", "acme")]));
        let with_query =
            RequestInfo::new("GET", "/x", "h").with_query_params(params(&[("tenant", "acme")]));

        assert_eq!(matched(&m, &with_header).as_deref(), Some("by-header"));
        assert_eq!(
            matched(&m, &with_query).as_deref(),
            Some("by-query"),
            "a query parameter was served the header route's cache entry"
        );
    }
}

/// Route matching edge cases (#113).
///
/// The matcher decides which upstream every request reaches, so a wrong
/// answer is a wrong backend rather than an error anyone sees. These pin the
/// behaviour that is easy to get wrong and impossible to notice.
#[cfg(test)]
mod route_matching_edges {
    use super::*;
    use std::collections::HashMap;
    use zentinel_common::ids::Scope;
    use zentinel_common::types::Priority;
    use zentinel_config::{MatchCondition, RouteConfig};

    fn route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        route_with_priority(id, matches, Priority::NORMAL)
    }

    fn route_with_priority(
        id: &str,
        matches: Vec<MatchCondition>,
        priority: Priority,
    ) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority,
            matches,
            upstream: Some("u".to_string()),
            service_type: zentinel_config::ServiceType::Web,
            policies: Default::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
        }
    }

    fn matcher(routes: Vec<RouteConfig>) -> RouteMatcher {
        RouteMatcher::new(routes, None).expect("routes should compile")
    }

    fn hit(m: &RouteMatcher, method: &str, path: &str, host: &str) -> Option<String> {
        m.match_request(&RequestInfo::new(method, path, host))
            .map(|r| r.route_id.to_string())
    }

    fn pairs(kv: &[(&str, &str)]) -> HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // -- Host -------------------------------------------------------------

    /// Host comparison is case-insensitive (RFC 3986 §3.2.2). Both sides are
    /// normalized: a mixed-case request must match, and just as importantly a
    /// route written `host "Example.com"` must not silently match nothing.
    #[test]
    fn host_matching_ignores_case_on_both_sides() {
        let m = matcher(vec![route(
            "h",
            vec![MatchCondition::Host("example.com".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/", "example.com").as_deref(), Some("h"));
        assert_eq!(hit(&m, "GET", "/", "EXAMPLE.COM").as_deref(), Some("h"));
        assert_eq!(hit(&m, "GET", "/", "ExAmPlE.cOm").as_deref(), Some("h"));

        let m = matcher(vec![route(
            "h",
            vec![MatchCondition::Host("Example.COM".into())],
        )]);
        assert_eq!(
            hit(&m, "GET", "/", "example.com").as_deref(),
            Some("h"),
            "a mixed-case config host must still match"
        );
    }

    /// A trailing dot names the same host. Without normalizing it, a
    /// restrictive host route can be skipped by appending a dot and falling
    /// through to whatever permissive route follows.
    #[test]
    fn a_trailing_dot_does_not_bypass_a_host_route() {
        // Priority is explicit so the outcome turns on the host match alone,
        // not on how a host-only route ranks against a path catch-all.
        let m = matcher(vec![
            route_with_priority(
                "restricted",
                vec![
                    MatchCondition::Host("admin.example.com".into()),
                    MatchCondition::PathPrefix("/".into()),
                ],
                Priority::HIGH,
            ),
            route_with_priority(
                "catchall",
                vec![MatchCondition::PathPrefix("/".into())],
                Priority::LOW,
            ),
        ]);

        assert_eq!(
            hit(&m, "GET", "/", "admin.example.com").as_deref(),
            Some("restricted")
        );
        assert_eq!(
            hit(&m, "GET", "/", "admin.example.com.").as_deref(),
            Some("restricted"),
            "a trailing dot must not route around the host match"
        );
        // A genuinely different host still falls through.
        assert_eq!(
            hit(&m, "GET", "/", "other.com").as_deref(),
            Some("catchall")
        );
    }

    /// Path specificity outranks host specificity, so a route matching only a
    /// host loses to a catch-all that matches a path.
    ///
    /// This is the documented ordering rather than a defect, but it is
    /// surprising enough to pin: an operator adding a host-only route
    /// alongside a `path-prefix "/"` catch-all gets the catch-all, and the
    /// host route never fires. Give the host route a path condition, or a
    /// higher priority.
    #[test]
    fn a_host_only_route_loses_to_a_path_catchall() {
        let m = matcher(vec![
            route(
                "host_only",
                vec![MatchCondition::Host("admin.example.com".into())],
            ),
            route("catchall", vec![MatchCondition::PathPrefix("/".into())]),
        ]);
        assert_eq!(
            hit(&m, "GET", "/", "admin.example.com").as_deref(),
            Some("catchall")
        );

        // Adding the path condition is what makes it win.
        let m = matcher(vec![
            route(
                "host_and_path",
                vec![
                    MatchCondition::Host("admin.example.com".into()),
                    MatchCondition::PathPrefix("/".into()),
                ],
            ),
            route("catchall", vec![MatchCondition::PathPrefix("/".into())]),
        ]);
        assert_eq!(
            hit(&m, "GET", "/", "admin.example.com").as_deref(),
            Some("host_and_path")
        );
    }

    #[test]
    fn a_port_is_ignored_when_matching_a_host() {
        let m = matcher(vec![route(
            "h",
            vec![MatchCondition::Host("example.com".into())],
        )]);
        assert_eq!(
            hit(&m, "GET", "/", "example.com:8443").as_deref(),
            Some("h")
        );
        assert_eq!(hit(&m, "GET", "/", "example.com:80").as_deref(), Some("h"));
    }

    /// An IPv6 literal is bracketed and full of colons, so splitting on the
    /// first one to strip a port reduces `[::1]:8080` to `[`.
    #[test]
    fn an_ipv6_host_is_not_mangled_by_port_stripping() {
        assert_eq!(normalize_host("[::1]:8080"), "[::1]");
        assert_eq!(normalize_host("[2001:DB8::1]"), "[2001:db8::1]");
        assert_eq!(normalize_host("[::1]"), "[::1]");
    }

    #[test]
    fn wildcard_hosts_also_ignore_case_port_and_trailing_dot() {
        let m = matcher(vec![route(
            "w",
            vec![MatchCondition::Host("*.example.com".into())],
        )]);
        for host in [
            "api.example.com",
            "API.EXAMPLE.COM",
            "api.example.com:8443",
            "api.example.com.",
        ] {
            assert_eq!(
                hit(&m, "GET", "/", host).as_deref(),
                Some("w"),
                "host {host}"
            );
        }
    }

    /// A wildcard covers one or more labels beneath the suffix, never the bare
    /// suffix itself. `*.example.com` must not match `example.com`.
    #[test]
    fn a_wildcard_does_not_match_its_own_suffix() {
        let m = matcher(vec![route(
            "w",
            vec![MatchCondition::Host("*.example.com".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/", "example.com").as_deref(), None);
        assert_eq!(hit(&m, "GET", "/", "notexample.com").as_deref(), None);
    }

    /// Several host conditions on one route are alternatives, while a host and
    /// a path condition must both hold. Getting this backwards would either
    /// make multi-host routes unreachable or make every route far too broad.
    #[test]
    fn hosts_are_alternatives_but_other_conditions_are_required() {
        let m = matcher(vec![route(
            "multi",
            vec![
                MatchCondition::Host("a.com".into()),
                MatchCondition::Host("b.com".into()),
                MatchCondition::PathPrefix("/x".into()),
            ],
        )]);

        assert_eq!(hit(&m, "GET", "/x", "a.com").as_deref(), Some("multi"));
        assert_eq!(hit(&m, "GET", "/x", "b.com").as_deref(), Some("multi"));
        assert_eq!(
            hit(&m, "GET", "/x", "c.com").as_deref(),
            None,
            "an unlisted host must not match"
        );
        assert_eq!(
            hit(&m, "GET", "/y", "a.com").as_deref(),
            None,
            "the path is still required"
        );
    }

    // -- Path -------------------------------------------------------------

    #[test]
    fn an_exact_path_does_not_match_children_or_a_trailing_slash() {
        let m = matcher(vec![route(
            "exact",
            vec![MatchCondition::Path("/api".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/api", "h").as_deref(), Some("exact"));
        assert_eq!(hit(&m, "GET", "/api/", "h").as_deref(), None);
        assert_eq!(hit(&m, "GET", "/api/users", "h").as_deref(), None);
        assert_eq!(hit(&m, "GET", "/apiv2", "h").as_deref(), None);
    }

    /// A prefix must stop at a path segment boundary, or `/api` would claim
    /// `/apikeys` and route it to the wrong backend.
    #[test]
    fn a_prefix_stops_at_a_segment_boundary() {
        let m = matcher(vec![route(
            "p",
            vec![MatchCondition::PathPrefix("/api".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/api", "h").as_deref(), Some("p"));
        assert_eq!(hit(&m, "GET", "/api/", "h").as_deref(), Some("p"));
        assert_eq!(hit(&m, "GET", "/api/users", "h").as_deref(), Some("p"));
        assert_eq!(hit(&m, "GET", "/apikeys", "h").as_deref(), None);
        assert_eq!(hit(&m, "GET", "/apiv2/users", "h").as_deref(), None);
    }

    /// An unusable regex must fail the load rather than becoming a route that
    /// silently never matches.
    #[test]
    fn an_invalid_path_regex_is_rejected_at_load() {
        for pattern in ["(unclosed", "a{2,1}", "[z-a]"] {
            assert!(
                RouteMatcher::new(
                    vec![route("r", vec![MatchCondition::PathRegex(pattern.into())])],
                    None,
                )
                .is_err(),
                "{pattern:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_path_regex_is_anchored_as_written() {
        let m = matcher(vec![route(
            "r",
            vec![MatchCondition::PathRegex("^/v[0-9]+/users$".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/v1/users", "h").as_deref(), Some("r"));
        assert_eq!(hit(&m, "GET", "/v42/users", "h").as_deref(), Some("r"));
        assert_eq!(hit(&m, "GET", "/v1/users/1", "h").as_deref(), None);
        assert_eq!(hit(&m, "GET", "/x/v1/users", "h").as_deref(), None);
    }

    // -- Method, header, query --------------------------------------------

    #[test]
    fn a_method_condition_accepts_any_of_its_methods() {
        let m = matcher(vec![route(
            "rw",
            vec![MatchCondition::Method(vec!["POST".into(), "PUT".into()])],
        )]);
        assert_eq!(hit(&m, "POST", "/x", "h").as_deref(), Some("rw"));
        assert_eq!(hit(&m, "PUT", "/x", "h").as_deref(), Some("rw"));
        assert_eq!(hit(&m, "GET", "/x", "h").as_deref(), None);
        assert_eq!(hit(&m, "DELETE", "/x", "h").as_deref(), None);
    }

    /// A header condition with no value matches on presence alone; with a
    /// value it must match exactly. Conflating the two would make a
    /// presence check accept any value, or a value check accept none.
    #[test]
    fn a_header_condition_distinguishes_presence_from_value() {
        let present = matcher(vec![route(
            "any",
            vec![MatchCondition::Header {
                name: "x-key".into(),
                value: None,
            }],
        )]);
        let exact = matcher(vec![route(
            "exact",
            vec![MatchCondition::Header {
                name: "x-key".into(),
                value: Some("secret".into()),
            }],
        )]);

        let with_other =
            RequestInfo::new("GET", "/x", "h").with_headers(pairs(&[("x-key", "other")]));
        let with_secret =
            RequestInfo::new("GET", "/x", "h").with_headers(pairs(&[("x-key", "secret")]));
        let without = RequestInfo::new("GET", "/x", "h").with_headers(pairs(&[("y", "1")]));

        assert!(present.match_request(&with_other).is_some());
        assert!(present.match_request(&without).is_none());
        assert!(exact.match_request(&with_secret).is_some());
        assert!(exact.match_request(&with_other).is_none());
    }

    #[test]
    fn a_query_condition_distinguishes_presence_from_value() {
        let present = matcher(vec![route(
            "any",
            vec![MatchCondition::QueryParam {
                name: "debug".into(),
                value: None,
            }],
        )]);
        let exact = matcher(vec![route(
            "exact",
            vec![MatchCondition::QueryParam {
                name: "v".into(),
                value: Some("2".into()),
            }],
        )]);

        assert!(present
            .match_request(
                &RequestInfo::new("GET", "/x", "h").with_query_params(pairs(&[("debug", "0")]))
            )
            .is_some());
        assert!(present
            .match_request(&RequestInfo::new("GET", "/x", "h"))
            .is_none());
        assert!(exact
            .match_request(
                &RequestInfo::new("GET", "/x", "h").with_query_params(pairs(&[("v", "2")]))
            )
            .is_some());
        assert!(exact
            .match_request(
                &RequestInfo::new("GET", "/x", "h").with_query_params(pairs(&[("v", "1")]))
            )
            .is_none());
    }

    // -- Selection --------------------------------------------------------

    #[test]
    fn higher_priority_wins_regardless_of_declaration_order() {
        let m = matcher(vec![
            route_with_priority(
                "low",
                vec![MatchCondition::PathPrefix("/a".into())],
                Priority::LOW,
            ),
            route_with_priority(
                "high",
                vec![MatchCondition::PathPrefix("/a".into())],
                Priority::HIGH,
            ),
        ]);
        assert_eq!(hit(&m, "GET", "/a", "h").as_deref(), Some("high"));
    }

    /// Equal priorities must resolve the same way every time. If this depended
    /// on hash or iteration order, two identically configured proxies would
    /// route the same request differently.
    #[test]
    fn equal_priorities_resolve_deterministically() {
        for _ in 0..10 {
            let m = matcher(vec![
                route("first", vec![MatchCondition::PathPrefix("/a".into())]),
                route("second", vec![MatchCondition::PathPrefix("/a".into())]),
            ]);
            assert_eq!(hit(&m, "GET", "/a", "h").as_deref(), Some("first"));
        }
    }

    /// A route with no conditions matches everything, so it is only ever
    /// correct as a catch-all and must not shadow a more specific route.
    #[test]
    fn a_route_with_no_conditions_matches_anything() {
        let m = matcher(vec![route("catchall", vec![])]);
        assert_eq!(
            hit(&m, "GET", "/anything", "h").as_deref(),
            Some("catchall")
        );
        assert_eq!(
            hit(&m, "POST", "/", "other.host").as_deref(),
            Some("catchall")
        );
    }

    #[test]
    fn no_match_returns_none_rather_than_an_arbitrary_route() {
        let m = matcher(vec![route(
            "api",
            vec![MatchCondition::PathPrefix("/api".into())],
        )]);
        assert_eq!(hit(&m, "GET", "/other", "h").as_deref(), None);
    }
}
