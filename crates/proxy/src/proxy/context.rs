//! Request context for the proxy request lifecycle.
//!
//! The `RequestContext` struct maintains state throughout a single request,
//! including timing, routing decisions, and metadata for logging.

use std::sync::Arc;
use std::time::Instant;

use zentinel_config::{BodyStreamingMode, Config, RouteConfig, ServiceType};

use crate::inference::StreamingTokenCounter;
use crate::websocket::WebSocketHandler;

/// Reason why fallback routing was triggered
#[derive(Debug, Clone)]
pub enum FallbackReason {
    /// Primary upstream health check failed
    HealthCheckFailed,
    /// Token budget exhausted for the request
    BudgetExhausted,
    /// Response latency exceeded threshold
    LatencyThreshold { observed_ms: u64, threshold_ms: u64 },
    /// Upstream returned an error code that triggers fallback
    ErrorCode(u16),
    /// Connection to upstream failed
    ConnectionError(String),
}

impl std::fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FallbackReason::HealthCheckFailed => write!(f, "health_check_failed"),
            FallbackReason::BudgetExhausted => write!(f, "budget_exhausted"),
            FallbackReason::LatencyThreshold {
                observed_ms,
                threshold_ms,
            } => write!(
                f,
                "latency_threshold_{}ms_exceeded_{}ms",
                observed_ms, threshold_ms
            ),
            FallbackReason::ErrorCode(code) => write!(f, "error_code_{}", code),
            FallbackReason::ConnectionError(msg) => write!(f, "connection_error_{}", msg),
        }
    }
}

/// Rate limit header information for response headers
#[derive(Debug, Clone)]
pub struct RateLimitHeaderInfo {
    /// Maximum requests allowed per window
    pub limit: u32,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Unix timestamp (seconds) when the window resets
    pub reset_at: u64,
}

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
    /// Selected upstream pool ID
    pub(crate) upstream: Option<String>,
    /// Selected upstream peer address (IP:port) for feedback reporting
    pub(crate) selected_upstream_address: Option<String>,
    /// Number of upstream attempts
    pub(crate) upstream_attempts: u32,

    // === Scope (for namespaced configurations) ===
    /// Namespace for this request (if routed to a namespace scope)
    pub(crate) namespace: Option<String>,
    /// Service for this request (if routed to a service scope)
    pub(crate) service: Option<String>,

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

    // === Body Decompression ===
    /// Whether decompression is enabled for body inspection
    pub(crate) decompression_enabled: bool,
    /// Content-Encoding of the request body (if compressed)
    pub(crate) body_content_encoding: Option<String>,
    /// Maximum decompression ratio allowed
    pub(crate) max_decompression_ratio: f64,
    /// Maximum decompressed size allowed
    pub(crate) max_decompression_bytes: usize,
    /// Whether decompression was performed
    pub(crate) body_was_decompressed: bool,

    // === Rate Limiting ===
    /// Rate limit info for response headers (set during request_filter)
    pub(crate) rate_limit_info: Option<RateLimitHeaderInfo>,

    // === GeoIP Filtering ===
    /// Country code from GeoIP lookup (ISO 3166-1 alpha-2)
    pub(crate) geo_country_code: Option<String>,
    /// Whether a geo lookup was performed for this request
    pub(crate) geo_lookup_performed: bool,

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

    // === OpenTelemetry Tracing ===
    /// OpenTelemetry request span (if tracing enabled)
    pub(crate) otel_span: Option<crate::otel::RequestSpan>,
    /// W3C trace context parsed from incoming request
    pub(crate) trace_context: Option<crate::otel::TraceContext>,

    // === Inference Rate Limiting ===
    /// Whether inference rate limiting is enabled for this route
    pub(crate) inference_rate_limit_enabled: bool,
    /// Estimated tokens for this request (used for rate limiting)
    pub(crate) inference_estimated_tokens: u64,
    /// Rate limit key used (client IP, API key, etc.)
    pub(crate) inference_rate_limit_key: Option<String>,
    /// Model name detected from request
    pub(crate) inference_model: Option<String>,
    /// Provider override from model-based routing (for cross-provider routing)
    pub(crate) inference_provider_override: Option<zentinel_config::InferenceProvider>,
    /// Whether model-based routing was used to select the upstream
    pub(crate) model_routing_used: bool,
    /// Actual tokens from response (filled in after response)
    pub(crate) inference_actual_tokens: Option<u64>,

    // === Token Budget Tracking ===
    /// Whether budget tracking is enabled for this route
    pub(crate) inference_budget_enabled: bool,
    /// Budget remaining after this request (set after response)
    pub(crate) inference_budget_remaining: Option<i64>,
    /// Period reset timestamp (Unix seconds)
    pub(crate) inference_budget_period_reset: Option<u64>,
    /// Whether budget was exhausted (429 sent)
    pub(crate) inference_budget_exhausted: bool,

    // === Cost Attribution ===
    /// Whether cost attribution is enabled for this route
    pub(crate) inference_cost_enabled: bool,
    /// Calculated cost for this request (set after response)
    pub(crate) inference_request_cost: Option<f64>,
    /// Input tokens for cost calculation
    pub(crate) inference_input_tokens: u64,
    /// Output tokens for cost calculation
    pub(crate) inference_output_tokens: u64,

    // === Streaming Token Counting ===
    /// Whether this is a streaming (SSE) response
    pub(crate) inference_streaming_response: bool,
    /// Streaming token counter for SSE responses
    pub(crate) inference_streaming_counter: Option<StreamingTokenCounter>,

    // === Fallback Routing ===
    /// Current fallback attempt number (0 = primary, 1+ = fallback)
    pub(crate) fallback_attempt: u32,
    /// List of upstream IDs that have been tried
    pub(crate) tried_upstreams: Vec<String>,
    /// Reason for triggering fallback (if fallback was used)
    pub(crate) fallback_reason: Option<FallbackReason>,
    /// Original upstream ID before fallback (primary)
    pub(crate) original_upstream: Option<String>,
    /// Model mapping applied: (original_model, mapped_model)
    pub(crate) model_mapping_applied: Option<(String, String)>,
    /// Whether fallback should be retried after response
    pub(crate) should_retry_with_fallback: bool,

    // === Semantic Guardrails ===
    /// Whether guardrails are enabled for this route
    pub(crate) guardrails_enabled: bool,
    /// Prompt injection detected but allowed (add warning header)
    pub(crate) guardrail_warning: bool,
    /// Categories of prompt injection detected (for logging)
    pub(crate) guardrail_detection_categories: Vec<String>,
    /// PII categories detected in response (for logging)
    pub(crate) pii_detection_categories: Vec<String>,

    // === Shadow Traffic ===
    /// Pending shadow request info (stored for deferred execution after body buffering)
    pub(crate) shadow_pending: Option<ShadowPendingRequest>,
    /// Whether shadow request was sent for this request
    pub(crate) shadow_sent: bool,

    // === Sticky Sessions ===
    /// Whether a new sticky session assignment was made (needs Set-Cookie header)
    pub(crate) sticky_session_new_assignment: bool,
    /// Set-Cookie header value to include in response (full header value)
    pub(crate) sticky_session_set_cookie: Option<String>,
    /// Target index for sticky session (for logging)
    pub(crate) sticky_target_index: Option<usize>,

    // === Listener Overrides ===
    /// Keepalive timeout from listener config (seconds, for response phase)
    pub(crate) listener_keepalive_timeout_secs: Option<u64>,

    // === Filter Overrides ===
    /// Upstream connect timeout override from Timeout filter (seconds)
    pub(crate) filter_connect_timeout_secs: Option<u64>,
    /// Upstream read timeout override from Timeout filter (seconds)
    pub(crate) filter_upstream_timeout_secs: Option<u64>,
    /// CORS origin matched by a CORS filter (for response headers)
    pub(crate) cors_origin: Option<String>,
    /// Whether response compression is enabled by a Compress filter
    pub(crate) compress_enabled: bool,
}

/// Pending shadow request information stored in context for deferred execution
#[derive(Clone)]
pub struct ShadowPendingRequest {
    /// Cloned request headers for shadow
    pub headers: pingora::http::RequestHeader,
    /// Shadow manager (wrapped in Arc for Clone)
    pub manager: std::sync::Arc<crate::shadow::ShadowManager>,
    /// Request context for shadow (client IP, path, method, etc.)
    pub request_ctx: crate::upstream::RequestContext,
    /// Whether body should be included
    pub include_body: bool,
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
            selected_upstream_address: None,
            upstream_attempts: 0,
            namespace: None,
            service: None,
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
            decompression_enabled: false,
            body_content_encoding: None,
            max_decompression_ratio: 100.0,
            max_decompression_bytes: 10 * 1024 * 1024, // 10MB
            body_was_decompressed: false,
            rate_limit_info: None,
            geo_country_code: None,
            geo_lookup_performed: false,
            request_body_streaming_mode: BodyStreamingMode::Buffer,
            request_body_chunk_index: 0,
            agent_needs_more: false,
            response_body_streaming_mode: BodyStreamingMode::Buffer,
            response_body_chunk_index: 0,
            response_body_bytes_inspected: 0,
            response_body_inspection_enabled: false,
            response_body_inspection_agents: Vec::new(),
            otel_span: None,
            trace_context: None,
            inference_rate_limit_enabled: false,
            inference_estimated_tokens: 0,
            inference_rate_limit_key: None,
            inference_model: None,
            inference_provider_override: None,
            model_routing_used: false,
            inference_actual_tokens: None,
            inference_budget_enabled: false,
            inference_budget_remaining: None,
            inference_budget_period_reset: None,
            inference_budget_exhausted: false,
            inference_cost_enabled: false,
            inference_request_cost: None,
            inference_input_tokens: 0,
            inference_output_tokens: 0,
            inference_streaming_response: false,
            inference_streaming_counter: None,
            fallback_attempt: 0,
            tried_upstreams: Vec::new(),
            fallback_reason: None,
            original_upstream: None,
            model_mapping_applied: None,
            should_retry_with_fallback: false,
            guardrails_enabled: false,
            guardrail_warning: false,
            guardrail_detection_categories: Vec::new(),
            pii_detection_categories: Vec::new(),
            shadow_pending: None,
            shadow_sent: false,
            sticky_session_new_assignment: false,
            sticky_session_set_cookie: None,
            sticky_target_index: None,
            listener_keepalive_timeout_secs: None,
            filter_connect_timeout_secs: None,
            filter_upstream_timeout_secs: None,
            cors_origin: None,
            compress_enabled: false,
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

    /// Get the selected upstream peer address (IP:port), if set.
    #[inline]
    pub fn selected_upstream_address(&self) -> Option<&str> {
        self.selected_upstream_address.as_deref()
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

    /// Get the GeoIP country code, if determined.
    #[inline]
    pub fn geo_country_code(&self) -> Option<&str> {
        self.geo_country_code.as_deref()
    }

    /// Check if a geo lookup was performed for this request.
    #[inline]
    pub fn geo_lookup_performed(&self) -> bool {
        self.geo_lookup_performed
    }

    /// Get traceparent header value for distributed tracing.
    ///
    /// Returns the W3C Trace Context traceparent header value if tracing is enabled.
    /// Format: `{version}-{trace-id}-{span-id}-{trace-flags}`
    #[inline]
    pub fn traceparent(&self) -> Option<String> {
        self.otel_span.as_ref().map(|span| {
            let sampled = self
                .trace_context
                .as_ref()
                .map(|c| c.sampled)
                .unwrap_or(true);
            crate::otel::create_traceparent(&span.trace_id, &span.span_id, sampled)
        })
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

    /// Set the selected upstream peer address (IP:port).
    #[inline]
    pub fn set_selected_upstream_address(&mut self, address: impl Into<String>) {
        self.selected_upstream_address = Some(address.into());
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

    // === Fallback accessors ===

    /// Get the current fallback attempt number (0 = primary).
    #[inline]
    pub fn fallback_attempt(&self) -> u32 {
        self.fallback_attempt
    }

    /// Get the list of upstreams that have been tried.
    #[inline]
    pub fn tried_upstreams(&self) -> &[String] {
        &self.tried_upstreams
    }

    /// Get the fallback reason, if fallback was triggered.
    #[inline]
    pub fn fallback_reason(&self) -> Option<&FallbackReason> {
        self.fallback_reason.as_ref()
    }

    /// Get the original upstream ID (before fallback).
    #[inline]
    pub fn original_upstream(&self) -> Option<&str> {
        self.original_upstream.as_deref()
    }

    /// Get the model mapping that was applied: (original, mapped).
    #[inline]
    pub fn model_mapping_applied(&self) -> Option<&(String, String)> {
        self.model_mapping_applied.as_ref()
    }

    /// Check if fallback was used for this request.
    #[inline]
    pub fn used_fallback(&self) -> bool {
        self.fallback_attempt > 0
    }

    /// Record that a fallback attempt is being made.
    #[inline]
    pub fn record_fallback(&mut self, reason: FallbackReason, new_upstream: &str) {
        if self.fallback_attempt == 0 {
            // First fallback - save original upstream
            self.original_upstream = self.upstream.clone();
        }
        self.fallback_attempt += 1;
        self.fallback_reason = Some(reason);
        if let Some(current) = &self.upstream {
            self.tried_upstreams.push(current.clone());
        }
        self.upstream = Some(new_upstream.to_string());
    }

    /// Record model mapping applied during fallback.
    #[inline]
    pub fn record_model_mapping(&mut self, original: String, mapped: String) {
        self.model_mapping_applied = Some((original, mapped));
    }

    // === Model Routing accessors ===

    /// Check if model-based routing was used to select the upstream.
    #[inline]
    pub fn used_model_routing(&self) -> bool {
        self.model_routing_used
    }

    /// Get the provider override from model-based routing (if any).
    #[inline]
    pub fn inference_provider_override(&self) -> Option<zentinel_config::InferenceProvider> {
        self.inference_provider_override
    }

    /// Record model-based routing result.
    ///
    /// Called when model-based routing selects an upstream based on the model name.
    #[inline]
    pub fn record_model_routing(
        &mut self,
        upstream: &str,
        model: Option<String>,
        provider_override: Option<zentinel_config::InferenceProvider>,
    ) {
        self.upstream = Some(upstream.to_string());
        self.model_routing_used = true;
        if model.is_some() {
            self.inference_model = model;
        }
        self.inference_provider_override = provider_override;
    }
}

impl Default for RequestContext {
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

    #[test]
    fn test_rate_limit_header_info() {
        let info = RateLimitHeaderInfo {
            limit: 100,
            remaining: 42,
            reset_at: 1704067200,
        };

        assert_eq!(info.limit, 100);
        assert_eq!(info.remaining, 42);
        assert_eq!(info.reset_at, 1704067200);
    }

    #[test]
    fn test_request_context_default() {
        let ctx = RequestContext::new();

        assert!(ctx.trace_id.is_empty());
        assert!(ctx.rate_limit_info.is_none());
        assert!(ctx.route_id.is_none());
        assert!(ctx.config.is_none());
    }

    #[test]
    fn test_request_context_rate_limit_info() {
        let mut ctx = RequestContext::new();

        // Initially no rate limit info
        assert!(ctx.rate_limit_info.is_none());

        // Set rate limit info
        ctx.rate_limit_info = Some(RateLimitHeaderInfo {
            limit: 50,
            remaining: 25,
            reset_at: 1704067300,
        });

        assert!(ctx.rate_limit_info.is_some());
        let info = ctx.rate_limit_info.as_ref().unwrap();
        assert_eq!(info.limit, 50);
        assert_eq!(info.remaining, 25);
        assert_eq!(info.reset_at, 1704067300);
    }

    #[test]
    fn test_request_context_elapsed() {
        let ctx = RequestContext::new();

        // Elapsed time should be very small (less than 1 second)
        let elapsed = ctx.elapsed();
        assert!(elapsed.as_secs() < 1);
    }

    #[test]
    fn test_request_context_setters() {
        let mut ctx = RequestContext::new();

        ctx.set_trace_id("trace-123");
        assert_eq!(ctx.trace_id(), "trace-123");
        assert_eq!(ctx.correlation_id(), "trace-123");

        ctx.set_route_id("my-route");
        assert_eq!(ctx.route_id(), Some("my-route"));

        ctx.set_upstream("backend-pool");
        assert_eq!(ctx.upstream(), Some("backend-pool"));

        ctx.inc_upstream_attempts();
        ctx.inc_upstream_attempts();
        assert_eq!(ctx.upstream_attempts(), 2);

        ctx.set_response_bytes(1024);
        assert_eq!(ctx.response_bytes(), 1024);
    }

    #[test]
    fn test_fallback_tracking() {
        let mut ctx = RequestContext::new();

        // Initially no fallback
        assert_eq!(ctx.fallback_attempt(), 0);
        assert!(!ctx.used_fallback());
        assert!(ctx.tried_upstreams().is_empty());
        assert!(ctx.fallback_reason().is_none());
        assert!(ctx.original_upstream().is_none());

        // Set initial upstream
        ctx.set_upstream("openai-primary");

        // Record first fallback
        ctx.record_fallback(FallbackReason::HealthCheckFailed, "anthropic-fallback");

        assert_eq!(ctx.fallback_attempt(), 1);
        assert!(ctx.used_fallback());
        assert_eq!(ctx.tried_upstreams(), &["openai-primary".to_string()]);
        assert!(matches!(
            ctx.fallback_reason(),
            Some(FallbackReason::HealthCheckFailed)
        ));
        assert_eq!(ctx.original_upstream(), Some("openai-primary"));
        assert_eq!(ctx.upstream(), Some("anthropic-fallback"));

        // Record second fallback
        ctx.record_fallback(FallbackReason::ErrorCode(503), "local-gpu");

        assert_eq!(ctx.fallback_attempt(), 2);
        assert_eq!(
            ctx.tried_upstreams(),
            &[
                "openai-primary".to_string(),
                "anthropic-fallback".to_string()
            ]
        );
        assert!(matches!(
            ctx.fallback_reason(),
            Some(FallbackReason::ErrorCode(503))
        ));
        // Original upstream should still be the first one
        assert_eq!(ctx.original_upstream(), Some("openai-primary"));
        assert_eq!(ctx.upstream(), Some("local-gpu"));
    }

    #[test]
    fn test_model_mapping_tracking() {
        let mut ctx = RequestContext::new();

        assert!(ctx.model_mapping_applied().is_none());

        ctx.record_model_mapping("gpt-4".to_string(), "claude-3-opus".to_string());

        let mapping = ctx.model_mapping_applied().unwrap();
        assert_eq!(mapping.0, "gpt-4");
        assert_eq!(mapping.1, "claude-3-opus");
    }

    #[test]
    fn test_fallback_reason_display() {
        assert_eq!(
            FallbackReason::HealthCheckFailed.to_string(),
            "health_check_failed"
        );
        assert_eq!(
            FallbackReason::BudgetExhausted.to_string(),
            "budget_exhausted"
        );
        assert_eq!(
            FallbackReason::LatencyThreshold {
                observed_ms: 5500,
                threshold_ms: 5000
            }
            .to_string(),
            "latency_threshold_5500ms_exceeded_5000ms"
        );
        assert_eq!(FallbackReason::ErrorCode(502).to_string(), "error_code_502");
        assert_eq!(
            FallbackReason::ConnectionError("timeout".to_string()).to_string(),
            "connection_error_timeout"
        );
    }
}
