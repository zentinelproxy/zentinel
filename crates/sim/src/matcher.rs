//! Route matching logic for the simulator
//!
//! This module implements route matching without any runtime dependencies,
//! making it suitable for WASM compilation. The logic mirrors the actual
//! proxy behavior in `zentinel-proxy::routing`.

use regex::Regex;

use zentinel_common::types::Priority;
use zentinel_config::{MatchCondition, RouteConfig};

use crate::trace::{ConditionDetail, MatchStep};
use crate::types::{MatchedRoute, SimulatedRequest};

/// Route matcher for simulating routing decisions
pub struct RouteMatcher {
    /// Compiled routes sorted by priority
    routes: Vec<CompiledRoute>,
    /// Default route ID
    default_route: Option<String>,
}

/// A compiled route with pre-processed matchers
struct CompiledRoute {
    /// Original route config
    config: RouteConfig,
    /// Compiled match conditions
    matchers: Vec<CompiledMatcher>,
    /// Route specificity score (for tie-breaking)
    specificity: u32,
}

/// Compiled match condition for efficient evaluation
enum CompiledMatcher {
    /// Exact path match
    Path(String),
    /// Path prefix match
    PathPrefix(String),
    /// Regex path match
    PathRegex { pattern: String, regex: Regex },
    /// Host match
    Host(HostMatcher),
    /// Header presence/value match
    Header { name: String, value: Option<String> },
    /// HTTP method match
    Method(Vec<String>),
    /// Query parameter match
    QueryParam { name: String, value: Option<String> },
}

/// Host matching variants
enum HostMatcher {
    /// Exact host match
    Exact(String),
    /// Wildcard match (*.example.com)
    Wildcard { suffix: String },
    /// Regex match
    Regex { pattern: String, regex: Regex },
}

/// Route matching error
#[derive(Debug, thiserror::Error)]
pub enum RouteMatchError {
    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },
}

impl RouteMatcher {
    /// Create a new route matcher from configuration
    pub fn new(
        routes: &[RouteConfig],
        default_route: Option<&str>,
    ) -> Result<Self, RouteMatchError> {
        let mut compiled_routes = Vec::new();

        for route in routes {
            compiled_routes.push(CompiledRoute::compile(route.clone())?);
        }

        // Sort by priority (highest first), then by specificity
        compiled_routes.sort_by(|a, b| {
            b.config
                .priority
                .cmp(&a.config.priority)
                .then_with(|| b.specificity.cmp(&a.specificity))
        });

        Ok(Self {
            routes: compiled_routes,
            default_route: default_route.map(|s| s.to_string()),
        })
    }

    /// Match a request and return the matched route with full trace
    pub fn match_with_trace(
        &self,
        request: &SimulatedRequest,
    ) -> (Option<MatchedRoute>, Vec<MatchStep>) {
        let mut trace = Vec::new();
        let path = request.path_without_query();

        for route in &self.routes {
            let (matched, conditions) = route.evaluate(request, path);

            if matched {
                trace.push(MatchStep::matched(route.config.id.clone(), conditions));

                let matched_route = MatchedRoute {
                    id: route.config.id.clone(),
                    priority: route.config.priority.as_i32(),
                    upstream: route.config.upstream.clone(),
                    service_type: format!("{:?}", route.config.service_type),
                };

                // Add skipped entries for remaining routes
                for remaining in self.routes.iter().skip(trace.len()) {
                    trace.push(MatchStep::skipped(
                        remaining.config.id.clone(),
                        "Higher priority route already matched",
                    ));
                }

                return (Some(matched_route), trace);
            } else {
                trace.push(MatchStep::no_match(route.config.id.clone(), conditions));
            }
        }

        // Try default route
        if let Some(ref default_id) = self.default_route {
            if let Some(route) = self.routes.iter().find(|r| r.config.id == *default_id) {
                let matched_route = MatchedRoute {
                    id: route.config.id.clone(),
                    priority: route.config.priority.as_i32(),
                    upstream: route.config.upstream.clone(),
                    service_type: format!("{:?}", route.config.service_type),
                };

                trace.push(MatchStep {
                    route_id: default_id.clone(),
                    result: crate::trace::MatchStepResult::Match,
                    reason: "Default route (no explicit match)".to_string(),
                    conditions_checked: 0,
                    conditions_passed: 0,
                    condition_details: Vec::new(),
                });

                return (Some(matched_route), trace);
            }
        }

        (None, trace)
    }

    /// Simple match without trace (for internal use)
    pub fn match_request(&self, request: &SimulatedRequest) -> Option<MatchedRoute> {
        let path = request.path_without_query();

        for route in &self.routes {
            if route.matches(request, path) {
                return Some(MatchedRoute {
                    id: route.config.id.clone(),
                    priority: route.config.priority.as_i32(),
                    upstream: route.config.upstream.clone(),
                    service_type: format!("{:?}", route.config.service_type),
                });
            }
        }

        // Try default route
        if let Some(ref default_id) = self.default_route {
            if let Some(route) = self.routes.iter().find(|r| r.config.id == *default_id) {
                return Some(MatchedRoute {
                    id: route.config.id.clone(),
                    priority: route.config.priority.as_i32(),
                    upstream: route.config.upstream.clone(),
                    service_type: format!("{:?}", route.config.service_type),
                });
            }
        }

        None
    }
}

impl CompiledRoute {
    /// Compile a route configuration
    fn compile(config: RouteConfig) -> Result<Self, RouteMatchError> {
        let mut matchers = Vec::new();

        for condition in &config.matches {
            matchers.push(CompiledMatcher::compile(condition)?);
        }

        let specificity = Self::calculate_specificity(&matchers);

        Ok(Self {
            config,
            matchers,
            specificity,
        })
    }

    /// Calculate route specificity for priority tie-breaking
    fn calculate_specificity(matchers: &[CompiledMatcher]) -> u32 {
        let mut score = 0;
        for matcher in matchers {
            score += match matcher {
                CompiledMatcher::Path(_) => 1000,     // Exact path most specific
                CompiledMatcher::PathRegex { .. } => 500,
                CompiledMatcher::PathPrefix(_) => 100,
                CompiledMatcher::Host(_) => 50,
                CompiledMatcher::Header { value, .. } => {
                    if value.is_some() { 30 } else { 20 }
                }
                CompiledMatcher::Method(_) => 10,
                CompiledMatcher::QueryParam { value, .. } => {
                    if value.is_some() { 25 } else { 15 }
                }
            };
        }
        score
    }

    /// Check if this route matches the request (simple bool)
    fn matches(&self, request: &SimulatedRequest, path: &str) -> bool {
        self.matchers.iter().all(|m| m.matches(request, path))
    }

    /// Evaluate this route and return match result with condition details
    fn evaluate(
        &self,
        request: &SimulatedRequest,
        path: &str,
    ) -> (bool, Vec<ConditionDetail>) {
        let mut all_matched = true;
        let mut conditions = Vec::new();

        for matcher in &self.matchers {
            let (matched, detail) = matcher.evaluate(request, path);
            if !matched {
                all_matched = false;
            }
            conditions.push(detail);
        }

        (all_matched, conditions)
    }
}

impl CompiledMatcher {
    /// Compile a match condition
    fn compile(condition: &MatchCondition) -> Result<Self, RouteMatchError> {
        Ok(match condition {
            MatchCondition::Path(path) => Self::Path(path.clone()),
            MatchCondition::PathPrefix(prefix) => Self::PathPrefix(prefix.clone()),
            MatchCondition::PathRegex(pattern) => {
                let regex = Regex::new(pattern).map_err(|e| RouteMatchError::InvalidRegex {
                    pattern: pattern.clone(),
                    error: e.to_string(),
                })?;
                Self::PathRegex {
                    pattern: pattern.clone(),
                    regex,
                }
            }
            MatchCondition::Host(host) => Self::Host(HostMatcher::parse(host)),
            MatchCondition::Header { name, value } => Self::Header {
                name: name.to_lowercase(),
                value: value.clone(),
            },
            MatchCondition::Method(methods) => {
                Self::Method(methods.iter().map(|m| m.to_uppercase()).collect())
            }
            MatchCondition::QueryParam { name, value } => Self::QueryParam {
                name: name.clone(),
                value: value.clone(),
            },
        })
    }

    /// Check if this matcher matches (simple bool)
    fn matches(&self, request: &SimulatedRequest, path: &str) -> bool {
        match self {
            Self::Path(pattern) => path == pattern,
            Self::PathPrefix(prefix) => path.starts_with(prefix),
            Self::PathRegex { regex, .. } => regex.is_match(path),
            Self::Host(host_matcher) => host_matcher.matches(&request.host),
            Self::Header { name, value } => {
                if let Some(header_value) = request.headers.get(name) {
                    value.as_ref().is_none_or(|v| header_value == v)
                } else {
                    false
                }
            }
            Self::Method(methods) => methods.iter().any(|m| m == &request.method),
            Self::QueryParam { name, value } => {
                if let Some(param_value) = request.query_params.get(name) {
                    value.as_ref().is_none_or(|v| param_value == v)
                } else {
                    false
                }
            }
        }
    }

    /// Evaluate this matcher and return result with details
    fn evaluate(&self, request: &SimulatedRequest, path: &str) -> (bool, ConditionDetail) {
        match self {
            Self::Path(pattern) => {
                let matched = path == pattern;
                (matched, ConditionDetail::path(pattern, path, matched))
            }
            Self::PathPrefix(prefix) => {
                let matched = path.starts_with(prefix);
                (matched, ConditionDetail::path_prefix(prefix, path, matched))
            }
            Self::PathRegex { pattern, regex } => {
                let matched = regex.is_match(path);
                (matched, ConditionDetail::path_regex(pattern, path, matched))
            }
            Self::Host(host_matcher) => {
                let matched = host_matcher.matches(&request.host);
                let pattern = host_matcher.pattern();
                (
                    matched,
                    ConditionDetail::host(&pattern, &request.host, matched),
                )
            }
            Self::Header { name, value } => {
                let actual = request.headers.get(name).map(|s| s.as_str());
                let matched = if let Some(actual_value) = actual {
                    value.as_ref().is_none_or(|v| actual_value == v)
                } else {
                    false
                };
                (
                    matched,
                    ConditionDetail::header(name, value.as_deref(), actual, matched),
                )
            }
            Self::Method(methods) => {
                let matched = methods.iter().any(|m| m == &request.method);
                (
                    matched,
                    ConditionDetail::method(methods, &request.method, matched),
                )
            }
            Self::QueryParam { name, value } => {
                let actual = request.query_params.get(name).map(|s| s.as_str());
                let matched = if let Some(actual_value) = actual {
                    value.as_ref().is_none_or(|v| actual_value == v)
                } else {
                    false
                };
                (
                    matched,
                    ConditionDetail::query_param(name, value.as_deref(), actual, matched),
                )
            }
        }
    }
}

impl HostMatcher {
    /// Parse a host pattern into a matcher
    fn parse(pattern: &str) -> Self {
        if pattern.starts_with("*.") {
            Self::Wildcard {
                suffix: pattern[1..].to_string(), // Keep the dot: ".example.com"
            }
        } else if pattern.contains('*') || pattern.contains('[') {
            // Treat as regex
            if let Ok(regex) = Regex::new(pattern) {
                Self::Regex {
                    pattern: pattern.to_string(),
                    regex,
                }
            } else {
                Self::Exact(pattern.to_string())
            }
        } else {
            Self::Exact(pattern.to_string())
        }
    }

    /// Check if this matcher matches the host
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Exact(pattern) => host == pattern,
            Self::Wildcard { suffix } => {
                // Host must end with suffix (e.g., ".example.com")
                // and have at least one character before the suffix
                host.ends_with(suffix) && host.len() > suffix.len()
            }
            Self::Regex { regex, .. } => regex.is_match(host),
        }
    }

    /// Get the pattern string for display
    fn pattern(&self) -> String {
        match self {
            Self::Exact(p) => p.clone(),
            Self::Wildcard { suffix } => format!("*{}", suffix),
            Self::Regex { pattern, .. } => pattern.clone(),
        }
    }
}

// Extension trait for Priority to get i32 value
trait PriorityExt {
    fn as_i32(&self) -> i32;
}

impl PriorityExt for Priority {
    fn as_i32(&self) -> i32 {
        match self {
            Priority::Critical => 1000,
            Priority::High => 100,
            Priority::Normal => 0,
            Priority::Low => -100,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{MatchCondition, RouteConfig, ServiceType};

    fn create_route(id: &str, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::Normal,
            matches,
            upstream: Some("test-upstream".to_string()),
            service_type: ServiceType::Web,
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
            shadow: None,
            inference: None,
            fallback: None,
        }
    }

    #[test]
    fn test_path_prefix_matching() {
        let routes = vec![
            create_route("api", vec![MatchCondition::PathPrefix("/api".to_string())]),
            create_route("static", vec![MatchCondition::PathPrefix("/static".to_string())]),
        ];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let request = SimulatedRequest::new("GET", "example.com", "/api/users");
        let result = matcher.match_request(&request);

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "api");
    }

    #[test]
    fn test_exact_path_matching() {
        let routes = vec![
            create_route("exact", vec![MatchCondition::Path("/api/v1/users".to_string())]),
            create_route("prefix", vec![MatchCondition::PathPrefix("/api".to_string())]),
        ];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        // Exact match should win due to higher specificity
        let request = SimulatedRequest::new("GET", "example.com", "/api/v1/users");
        let result = matcher.match_request(&request);

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "exact");
    }

    #[test]
    fn test_host_wildcard_matching() {
        let routes = vec![create_route(
            "wildcard",
            vec![MatchCondition::Host("*.example.com".to_string())],
        )];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let request = SimulatedRequest::new("GET", "api.example.com", "/");
        let result = matcher.match_request(&request);

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "wildcard");

        // Should not match bare domain
        let request2 = SimulatedRequest::new("GET", "example.com", "/");
        let result2 = matcher.match_request(&request2);
        assert!(result2.is_none());
    }

    #[test]
    fn test_method_matching() {
        let routes = vec![create_route(
            "post-only",
            vec![
                MatchCondition::PathPrefix("/api".to_string()),
                MatchCondition::Method(vec!["POST".to_string()]),
            ],
        )];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let get_request = SimulatedRequest::new("GET", "example.com", "/api/users");
        assert!(matcher.match_request(&get_request).is_none());

        let post_request = SimulatedRequest::new("POST", "example.com", "/api/users");
        assert!(matcher.match_request(&post_request).is_some());
    }

    #[test]
    fn test_header_matching() {
        let routes = vec![create_route(
            "with-auth",
            vec![MatchCondition::Header {
                name: "Authorization".to_string(),
                value: None,
            }],
        )];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let without_auth = SimulatedRequest::new("GET", "example.com", "/api");
        assert!(matcher.match_request(&without_auth).is_none());

        let with_auth =
            SimulatedRequest::new("GET", "example.com", "/api").with_header("Authorization", "Bearer token");
        assert!(matcher.match_request(&with_auth).is_some());
    }

    #[test]
    fn test_match_trace() {
        let routes = vec![
            create_route("static", vec![MatchCondition::PathPrefix("/static".to_string())]),
            create_route("api", vec![MatchCondition::PathPrefix("/api".to_string())]),
        ];

        let matcher = RouteMatcher::new(&routes, None).unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");

        let (matched, trace) = matcher.match_with_trace(&request);

        assert!(matched.is_some());
        assert_eq!(matched.unwrap().id, "api");

        // Should have trace entries
        assert!(!trace.is_empty());

        // First route should not match
        assert_eq!(trace[0].route_id, "static");
        assert_eq!(trace[0].result, crate::trace::MatchStepResult::NoMatch);

        // Second route should match
        assert_eq!(trace[1].route_id, "api");
        assert_eq!(trace[1].result, crate::trace::MatchStepResult::Match);
    }

    #[test]
    fn test_query_param_matching() {
        let routes = vec![create_route(
            "versioned",
            vec![MatchCondition::QueryParam {
                name: "version".to_string(),
                value: Some("2".to_string()),
            }],
        )];

        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let without_version = SimulatedRequest::new("GET", "example.com", "/api");
        assert!(matcher.match_request(&without_version).is_none());

        let with_wrong_version = SimulatedRequest::new("GET", "example.com", "/api?version=1");
        assert!(matcher.match_request(&with_wrong_version).is_none());

        let with_correct_version = SimulatedRequest::new("GET", "example.com", "/api?version=2");
        assert!(matcher.match_request(&with_correct_version).is_some());
    }

    #[test]
    fn test_priority_ordering() {
        let mut low_priority = create_route("low", vec![MatchCondition::PathPrefix("/".to_string())]);
        low_priority.priority = Priority::Low;

        let mut high_priority = create_route("high", vec![MatchCondition::PathPrefix("/".to_string())]);
        high_priority.priority = Priority::High;

        // Add in wrong order to verify sorting
        let routes = vec![low_priority, high_priority];
        let matcher = RouteMatcher::new(&routes, None).unwrap();

        let request = SimulatedRequest::new("GET", "example.com", "/test");
        let result = matcher.match_request(&request);

        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "high");
    }
}
