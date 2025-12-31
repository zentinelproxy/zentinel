//! Request context for the proxy request lifecycle.
//!
//! The `RequestContext` struct maintains state throughout a single request,
//! including timing, routing decisions, and metadata for logging.

use std::sync::Arc;
use std::time::Instant;

use sentinel_config::{BodyStreamingMode, Config, RouteConfig, ServiceType};

use crate::websocket::WebSocketHandler;

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

    // === Global config (cached once per request) ===
    /// Cached global configuration snapshot for this request
    pub(crate) config: Option<Arc<Config>>,

    // === Routing ===
    /// Selected route ID
    pub(crate) route_id: Option<String>,
    /// Cached route configuration (avoids duplicate route matching)
    pub(crate) route_config: Option<Arc<RouteConfig>>,
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

    // === Body tracking ===
    /// Request body bytes received
    pub(crate) request_body_bytes: u64,
    /// Response body bytes (set during response)
    pub(crate) response_bytes: u64,

    // === Connection tracking ===
    /// Whether the upstream connection was reused
    pub(crate) connection_reused: bool,
    /// Whether this request is a WebSocket upgrade
    pub(crate) is_websocket_upgrade: bool,

    // === WebSocket Inspection ===
    /// Whether WebSocket frame inspection is enabled for this connection
    pub(crate) websocket_inspection_enabled: bool,
    /// Whether to skip inspection (e.g., due to compression negotiation)
    pub(crate) websocket_skip_inspection: bool,
    /// Agent IDs for WebSocket frame inspection
    pub(crate) websocket_inspection_agents: Vec<String>,
    /// WebSocket frame handler (created after 101 upgrade)
    pub(crate) websocket_handler: Option<Arc<WebSocketHandler>>,

    // === Caching ===
    /// Whether this request is eligible for caching
    pub(crate) cache_eligible: bool,

    // === Body Inspection ===
    /// Whether body inspection is enabled for this request
    pub(crate) body_inspection_enabled: bool,
    /// Bytes already sent to agent for inspection
    pub(crate) body_bytes_inspected: u64,
    /// Accumulated body buffer for agent inspection
    pub(crate) body_buffer: Vec<u8>,
    /// Agent IDs to use for body inspection
    pub(crate) body_inspection_agents: Vec<String>,

    // === Body Streaming ===
    /// Body streaming mode for request body inspection
    pub(crate) request_body_streaming_mode: BodyStreamingMode,
    /// Current chunk index for request body streaming
    pub(crate) request_body_chunk_index: u32,
    /// Whether agent needs more data (streaming mode)
    pub(crate) agent_needs_more: bool,
    /// Body streaming mode for response body inspection
    pub(crate) response_body_streaming_mode: BodyStreamingMode,
    /// Current chunk index for response body streaming
    pub(crate) response_body_chunk_index: u32,
    /// Response body bytes inspected
    pub(crate) response_body_bytes_inspected: u64,
    /// Response body inspection enabled
    pub(crate) response_body_inspection_enabled: bool,
    /// Agent IDs for response body inspection
    pub(crate) response_body_inspection_agents: Vec<String>,
}

impl RequestContext {
    /// Create a new empty request context with the current timestamp.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            trace_id: String::new(),
            config: None,
            route_id: None,
            route_config: None,
            upstream: None,
            upstream_attempts: 0,
            method: String::new(),
            path: String::new(),
            query: None,
            client_ip: String::new(),
            user_agent: None,
            referer: None,
            host: None,
            request_body_bytes: 0,
            response_bytes: 0,
            connection_reused: false,
            is_websocket_upgrade: false,
            websocket_inspection_enabled: false,
            websocket_skip_inspection: false,
            websocket_inspection_agents: Vec::new(),
            websocket_handler: None,
            cache_eligible: false,
            body_inspection_enabled: false,
            body_bytes_inspected: 0,
            body_buffer: Vec::new(),
            body_inspection_agents: Vec::new(),
            request_body_streaming_mode: BodyStreamingMode::Buffer,
            request_body_chunk_index: 0,
            agent_needs_more: false,
            response_body_streaming_mode: BodyStreamingMode::Buffer,
            response_body_chunk_index: 0,
            response_body_bytes_inspected: 0,
            response_body_inspection_enabled: false,
            response_body_inspection_agents: Vec::new(),
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

    /// Get the cached route configuration, if set.
    #[inline]
    pub fn route_config(&self) -> Option<&Arc<RouteConfig>> {
        self.route_config.as_ref()
    }

    /// Get the cached global configuration, if set.
    #[inline]
    pub fn global_config(&self) -> Option<&Arc<Config>> {
        self.config.as_ref()
    }

    /// Get the service type from cached route config.
    #[inline]
    pub fn service_type(&self) -> Option<ServiceType> {
        self.route_config.as_ref().map(|c| c.service_type.clone())
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
