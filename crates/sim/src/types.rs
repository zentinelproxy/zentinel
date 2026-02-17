//! Core types for the Zentinel configuration simulator
//!
//! These types represent simulated requests, route decisions, and the
//! detailed trace information that explains routing behavior.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::trace::MatchStep;

// ============================================================================
// Simulated Request
// ============================================================================

/// A simulated HTTP request for route matching
///
/// This represents the key attributes of an HTTP request that affect routing
/// decisions. Unlike a real request, this is a simple data structure that can
/// be easily constructed in the browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedRequest {
    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,

    /// Host header value (e.g., "api.example.com")
    pub host: String,

    /// Request path including query string (e.g., "/api/v2/users?page=1")
    pub path: String,

    /// Request headers (lowercase keys)
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Query parameters (parsed from path or provided explicitly)
    #[serde(default)]
    pub query_params: HashMap<String, String>,
}

impl SimulatedRequest {
    /// Create a new simulated request with minimal required fields
    pub fn new(method: &str, host: &str, path: &str) -> Self {
        let query_params = Self::parse_query_params(path);

        Self {
            method: method.to_uppercase(),
            host: host.to_string(),
            path: path.to_string(),
            headers: HashMap::new(),
            query_params,
        }
    }

    /// Add a header to the request
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_lowercase(), value.to_string());
        self
    }

    /// Add multiple headers to the request
    pub fn with_headers(mut self, headers: HashMap<String, String>) -> Self {
        for (k, v) in headers {
            self.headers.insert(k.to_lowercase(), v);
        }
        self
    }

    /// Add a query parameter
    pub fn with_query_param(mut self, name: &str, value: &str) -> Self {
        self.query_params.insert(name.to_string(), value.to_string());
        self
    }

    /// Parse query parameters from a path string
    pub fn parse_query_params(path: &str) -> HashMap<String, String> {
        let mut params = HashMap::new();

        if let Some(query_start) = path.find('?') {
            let query = &path[query_start + 1..];
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                if let Some(eq_pos) = pair.find('=') {
                    let key = &pair[..eq_pos];
                    let value = &pair[eq_pos + 1..];
                    // Simple URL decoding (handles %20, etc.)
                    let key = Self::simple_url_decode(key);
                    let value = Self::simple_url_decode(value);
                    params.insert(key, value);
                } else {
                    params.insert(Self::simple_url_decode(pair), String::new());
                }
            }
        }

        params
    }

    /// Simple URL decoding (handles common cases)
    fn simple_url_decode(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                        continue;
                    }
                }
                result.push('%');
                result.push_str(&hex);
            } else if c == '+' {
                result.push(' ');
            } else {
                result.push(c);
            }
        }

        result
    }

    /// Get the path without query string
    pub fn path_without_query(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }

    /// Generate a cache key for this request (used internally)
    pub fn cache_key(&self) -> String {
        format!("{}:{}:{}", self.method, self.host, self.path_without_query())
    }
}

// ============================================================================
// Route Decision
// ============================================================================

/// The result of simulating a routing decision
///
/// Contains the matched route (if any), a trace of the matching process,
/// and details about what would happen if this request were processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteDecision {
    /// The matched route, if any
    pub matched_route: Option<MatchedRoute>,

    /// Trace of all routes evaluated and why they matched/didn't match
    pub match_trace: Vec<MatchStep>,

    /// Policies that would be applied from the matched route
    pub applied_policies: Option<AppliedPolicies>,

    /// Simulated upstream selection
    pub upstream_selection: Option<UpstreamSelection>,

    /// Agent hooks that would fire for this request
    pub agent_hooks: Vec<AgentHook>,

    /// Warnings about potential issues
    pub warnings: Vec<Warning>,
}

/// Information about a matched route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRoute {
    /// Route ID
    pub id: String,

    /// Route priority
    pub priority: i32,

    /// Target upstream (if any)
    pub upstream: Option<String>,

    /// Service type
    pub service_type: String,
}

// ============================================================================
// Applied Policies
// ============================================================================

/// Policies that would be applied from the matched route
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppliedPolicies {
    /// Request timeout in seconds
    pub timeout_secs: Option<u64>,

    /// Maximum body size (human-readable string)
    pub max_body_size: Option<String>,

    /// Failure mode ("open" or "closed")
    pub failure_mode: String,

    /// Rate limit configuration
    pub rate_limit: Option<RateLimitInfo>,

    /// Cache configuration
    pub cache: Option<CacheInfo>,

    /// Whether request buffering is enabled
    pub buffer_requests: bool,

    /// Whether response buffering is enabled
    pub buffer_responses: bool,
}

/// Rate limit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    /// Maximum requests per second
    pub requests_per_second: u32,

    /// Burst capacity
    pub burst: u32,

    /// Rate limit key type
    pub key: String,
}

/// Cache configuration info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheInfo {
    /// Whether caching is enabled
    pub enabled: bool,

    /// Default TTL in seconds
    pub ttl_secs: u64,
}

// ============================================================================
// Upstream Selection
// ============================================================================

/// Simulated upstream selection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamSelection {
    /// Upstream pool ID
    pub upstream_id: String,

    /// Selected target address
    pub selected_target: String,

    /// Load balancer algorithm used
    pub load_balancer: String,

    /// Explanation of why this target was selected
    pub selection_reason: String,

    /// Simulated health status of the target
    pub health_status: String,
}

// ============================================================================
// Agent Hooks
// ============================================================================

/// Information about an agent hook that would fire
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHook {
    /// Agent ID
    pub agent_id: String,

    /// Hook type (on_request_headers, on_request_body, etc.)
    pub hook: String,

    /// Timeout in milliseconds
    pub timeout_ms: u64,

    /// Failure mode for this agent
    pub failure_mode: String,

    /// Body inspection config (for body hooks)
    pub body_inspection: Option<BodyInspectionInfo>,
}

/// Body inspection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyInspectionInfo {
    /// Whether body inspection is enabled
    pub enabled: bool,

    /// Maximum bytes to inspect
    pub max_bytes: usize,
}

// ============================================================================
// Warnings
// ============================================================================

/// A warning about a potential configuration issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    /// Warning code (e.g., "SHADOW_NO_BODY_BUFFER")
    pub code: String,

    /// Human-readable warning message
    pub message: String,
}

// ============================================================================
// Validation
// ============================================================================

/// Result of validating a configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Whether the configuration is valid
    pub valid: bool,

    /// Validation errors (if any)
    pub errors: Vec<ValidationError>,

    /// Warnings (non-fatal issues)
    pub warnings: Vec<Warning>,

    /// The parsed configuration (if valid)
    #[serde(skip)]
    pub effective_config: Option<zentinel_config::Config>,
}

/// A validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    /// Error message
    pub message: String,

    /// Severity level
    pub severity: ValidationSeverity,

    /// Location in the config file (if available)
    pub location: Option<SourceLocation>,

    /// Hint for fixing the error
    pub hint: Option<String>,
}

/// Validation error severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ValidationSeverity {
    /// Fatal error - config cannot be used
    Error,
    /// Warning - config can be used but may have issues
    Warning,
    /// Informational hint
    Hint,
}

/// Source location for error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Line number (1-indexed)
    pub line: usize,

    /// Column number (1-indexed)
    pub column: usize,

    /// Byte offset span (start, end)
    pub span: Option<(usize, usize)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulated_request_new() {
        let req = SimulatedRequest::new("get", "example.com", "/api/users");
        assert_eq!(req.method, "GET"); // Should be uppercased
        assert_eq!(req.host, "example.com");
        assert_eq!(req.path, "/api/users");
    }

    #[test]
    fn test_simulated_request_with_query() {
        let req = SimulatedRequest::new("GET", "example.com", "/api/users?page=1&limit=10");
        assert_eq!(req.query_params.get("page"), Some(&"1".to_string()));
        assert_eq!(req.query_params.get("limit"), Some(&"10".to_string()));
    }

    #[test]
    fn test_simulated_request_url_decode() {
        let req = SimulatedRequest::new("GET", "example.com", "/api/search?q=hello%20world");
        assert_eq!(req.query_params.get("q"), Some(&"hello world".to_string()));
    }

    #[test]
    fn test_simulated_request_with_headers() {
        let req = SimulatedRequest::new("GET", "example.com", "/api")
            .with_header("Authorization", "Bearer token123")
            .with_header("X-Custom-Header", "value");

        assert_eq!(
            req.headers.get("authorization"),
            Some(&"Bearer token123".to_string())
        );
        assert_eq!(
            req.headers.get("x-custom-header"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_path_without_query() {
        let req = SimulatedRequest::new("GET", "example.com", "/api/users?page=1");
        assert_eq!(req.path_without_query(), "/api/users");
    }
}
