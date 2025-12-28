//! Request context for the proxy request lifecycle.
//!
//! The `RequestContext` struct maintains state throughout a single request,
//! including timing, routing decisions, and metadata for logging.

use std::time::Instant;

/// Request context maintained throughout the request lifecycle.
///
/// This struct uses a hybrid approach:
/// - Immutable fields (start_time) are private with getters
/// - Mutable fields are public(crate) for efficient access within the proxy module
pub struct RequestContext {
    /// Request start time (immutable after creation)
    start_time: Instant,

    // === Tracing ===
    /// Unique trace ID for request tracing (also used as correlation_id)
    pub(crate) trace_id: String,

    // === Routing ===
    /// Selected route ID
    pub(crate) route_id: Option<String>,
    /// Selected upstream
    pub(crate) upstream: Option<String>,
    /// Number of upstream attempts
    pub(crate) upstream_attempts: u32,

    // === Request metadata (cached for logging) ===
    /// HTTP method
    pub(crate) method: String,
    /// Request path
    pub(crate) path: String,
    /// Query string
    pub(crate) query: Option<String>,

    // === Client info ===
    /// Client IP address
    pub(crate) client_ip: String,
    /// User-Agent header
    pub(crate) user_agent: Option<String>,
    /// Referer header
    pub(crate) referer: Option<String>,
    /// Host header
    pub(crate) host: Option<String>,

    // === Response tracking ===
    /// Response body bytes (set during response)
    pub(crate) response_bytes: u64,
}

impl RequestContext {
    /// Create a new empty request context with the current timestamp.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            trace_id: String::new(),
            route_id: None,
            upstream: None,
            upstream_attempts: 0,
            method: String::new(),
            path: String::new(),
            query: None,
            client_ip: String::new(),
            user_agent: None,
            referer: None,
            host: None,
            response_bytes: 0,
        }
    }

    // === Immutable field accessors ===

    /// Get the request start time.
    #[inline]
    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    /// Get elapsed duration since request start.
    #[inline]
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    // === Read-only accessors ===

    /// Get trace_id (alias for backwards compatibility with correlation_id usage).
    #[inline]
    pub fn correlation_id(&self) -> &str {
        &self.trace_id
    }

    /// Get the trace ID.
    #[inline]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Get the route ID, if set.
    #[inline]
    pub fn route_id(&self) -> Option<&str> {
        self.route_id.as_deref()
    }

    /// Get the upstream ID, if set.
    #[inline]
    pub fn upstream(&self) -> Option<&str> {
        self.upstream.as_deref()
    }

    /// Get the number of upstream attempts.
    #[inline]
    pub fn upstream_attempts(&self) -> u32 {
        self.upstream_attempts
    }

    /// Get the HTTP method.
    #[inline]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get the request path.
    #[inline]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the query string, if present.
    #[inline]
    pub fn query(&self) -> Option<&str> {
        self.query.as_deref()
    }

    /// Get the client IP address.
    #[inline]
    pub fn client_ip(&self) -> &str {
        &self.client_ip
    }

    /// Get the User-Agent header, if present.
    #[inline]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// Get the Referer header, if present.
    #[inline]
    pub fn referer(&self) -> Option<&str> {
        self.referer.as_deref()
    }

    /// Get the Host header, if present.
    #[inline]
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Get the response body size in bytes.
    #[inline]
    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    // === Mutation helpers ===

    /// Set the trace ID.
    #[inline]
    pub fn set_trace_id(&mut self, trace_id: impl Into<String>) {
        self.trace_id = trace_id.into();
    }

    /// Set the route ID.
    #[inline]
    pub fn set_route_id(&mut self, route_id: impl Into<String>) {
        self.route_id = Some(route_id.into());
    }

    /// Set the upstream ID.
    #[inline]
    pub fn set_upstream(&mut self, upstream: impl Into<String>) {
        self.upstream = Some(upstream.into());
    }

    /// Increment upstream attempt counter.
    #[inline]
    pub fn inc_upstream_attempts(&mut self) {
        self.upstream_attempts += 1;
    }

    /// Set response bytes.
    #[inline]
    pub fn set_response_bytes(&mut self, bytes: u64) {
        self.response_bytes = bytes;
    }
}

impl Default for RequestContext {
    fn default() -> Self {
        Self::new()
    }
}
