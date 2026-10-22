//! Request context for the proxy request lifecycle.
//!
//! The `RequestContext` struct maintains state throughout a single request,
//! including timing, routing decisions, and metadata for logging.

use std::sync::Arc;
use std::time::Instant;

use zentinel_common::ids::Scope;
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

/// Cache status for the Cache-Status response header (RFC 9211)
#[derive(Debug, Clone)]
pub(crate) enum CacheStatus {
    /// Cache hit from memory tier (hybrid cache)
    HitMemory,
    /// Cache hit from disk tier, promoted to memory (hybrid cache)
    HitDisk,
    /// Cache hit (non-hybrid / tier unknown)
    Hit,
    /// Cache hit but response was stale (revalidation needed)
    HitStale,
    /// Cache miss (response fetched from upstream)
    Miss,
    /// Cache bypassed (not eligible for caching)
    Bypass(&'static str),
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

/// An agent's decision to answer the client itself instead of letting the
/// request through: what the client is answered with. A `Block` in any
/// phase; in the request phases a `Redirect` or a `Challenge` too
/// (see [`AgentBlock::for_request`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentBlock {
    pub status: u16,
    /// The agent's own body. Without one the route's error page for
    /// `status` is sent, or the proxy's default refusal.
    pub body: Option<String>,
    /// Headers the agent asked for on its block response, whichever body it
    /// gets. Framing headers are not taken from it.
    pub headers: Vec<(String, String)>,
}

/// The redirect statuses an agent's `Redirect` is answered with; any other
/// status falls back to [`REDIRECT_FALLBACK_STATUS`].
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];
const REDIRECT_FALLBACK_STATUS: u16 = 302;

impl AgentBlock {
    /// The block response for `action`, if it is a block.
    ///
    /// Used by the response phases, which act on `Block` only so far:
    /// `Redirect` and `Challenge` there are #588.
    pub(crate) fn from_action(action: &crate::agents::AgentAction) -> Option<Self> {
        use crate::agents::AgentAction;
        match action {
            AgentAction::Block {
                status,
                body,
                headers,
            } => {
                let mut headers: Vec<(String, String)> = headers
                    .iter()
                    .flatten()
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect();
                // A stable order: the agent's map has none.
                headers.sort();
                Some(Self {
                    status: *status,
                    body: body.clone(),
                    headers,
                })
            }
            // #588: not yet acted on in the response phase.
            AgentAction::Allow | AgentAction::Redirect { .. } | AgentAction::Challenge { .. } => {
                None
            }
        }
    }

    /// The response for an agent's decision in a request phase (request
    /// headers or request body), or `None` to let the request through.
    ///
    /// Only `Allow` lets it through. The match is exhaustive on purpose: a
    /// decision type added later must be given a response here, it cannot
    /// fall through to `Allow` (#595).
    ///
    /// - `Block`: the agent's status, body and headers.
    /// - `Redirect` (#594): see [`AgentBlock::redirect`].
    /// - `Challenge` (#595): see [`AgentBlock::challenge`].
    pub(crate) fn for_request(action: &crate::agents::AgentAction) -> Option<Self> {
        use crate::agents::AgentAction;
        match action {
            AgentAction::Allow => None,
            AgentAction::Block { .. } => Self::from_action(action),
            AgentAction::Redirect { url, status } => Some(Self::redirect(url, *status)),
            AgentAction::Challenge { params, .. } => Some(Self::challenge(params)),
        }
    }

    /// An agent's `Redirect`: the agent's status with `Location: url`.
    ///
    /// The status must be one of 301, 302, 303, 307 or 308; any other falls
    /// back to 302. A URL that cannot be a header value (a control
    /// character, say) cannot be redirected to: the request is refused with
    /// a 500 instead of being let through or sent without a `Location`.
    pub(crate) fn redirect(url: &str, status: u16) -> Self {
        if http::HeaderValue::from_str(url).is_err() {
            return Self {
                status: 500,
                body: None,
                headers: Vec::new(),
            };
        }
        let status = if REDIRECT_STATUSES.contains(&status) {
            status
        } else {
            REDIRECT_FALLBACK_STATUS
        };
        Self {
            status,
            body: None,
            headers: vec![("Location".to_string(), url.to_string())],
        }
    }

    /// An agent's `Challenge`. The proxy cannot run a challenge itself, so
    /// it fails closed: the request is never let through, and the client
    /// is answered with the challenge as far as the agent's parameters
    /// define one. Parameter names are matched case-insensitively:
    ///
    /// - `www-authenticate`: an HTTP authentication challenge. The answer
    ///   is `401 Unauthorized` with this value as its `WWW-Authenticate`
    ///   header.
    /// - otherwise (a CAPTCHA, JavaScript or proof-of-work challenge, ...)
    ///   the answer is `403 Forbidden`.
    /// - `body`: the response body, e.g. the challenge page. Without one the
    ///   route's error page for the status is sent, or the default refusal.
    /// - `content-type`: the Content-Type of `body`; ignored without one.
    ///
    /// Other parameters (`token`, `challenge_url`, ...) are not sent to the
    /// client: their meaning is the agent's, and an agent that wants them
    /// in front of the client puts them into `body`.
    pub(crate) fn challenge(params: &std::collections::HashMap<String, String>) -> Self {
        let param = |name: &str| {
            // The lowest-sorting key wins should two differ only in case,
            // so the answer does not depend on the map's order.
            params
                .iter()
                .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                .min_by(|a, b| a.0.cmp(b.0))
                .map(|(_, value)| value.clone())
        };
        let mut headers = Vec::new();
        let status = match param("www-authenticate") {
            Some(challenge) => {
                headers.push(("WWW-Authenticate".to_string(), challenge));
                401
            }
            None => 403,
        };
        let body = param("body");
        if body.is_some() {
            if let Some(content_type) = param("content-type") {
                headers.push(("Content-Type".to_string(), content_type));
            }
        }
        Self {
            status,
            body,
            headers,
        }
    }

    /// The decision type `action` names, for logs and audit entries.
    pub(crate) fn action_name(action: &crate::agents::AgentAction) -> &'static str {
        use crate::agents::AgentAction;
        match action {
            AgentAction::Allow => "allow",
            AgentAction::Block { .. } => "block",
            AgentAction::Redirect { .. } => "redirect",
            AgentAction::Challenge { .. } => "challenge",
        }
    }

    /// Set the agent's headers on its block response. Headers that frame
    /// the body or the connection stay the proxy's: an agent setting them
    /// would misframe the response.
    pub(crate) fn apply_headers(&self, header: &mut pingora_http::ResponseHeader) {
        const PROXY_OWNED: [&str; 6] = [
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "upgrade",
            "x-correlation-id",
        ];
        for (name, value) in &self.headers {
            if PROXY_OWNED
                .iter()
                .any(|owned| name.eq_ignore_ascii_case(owned))
            {
                continue;
            }
            let _ = header.insert_header(name.clone(), value.as_str());
        }
    }
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
    /// The pool the peer was selected from, for `fail_to_connect`, which is
    /// synchronous and so cannot look it up in the registry.
    pub(crate) selected_pool: Option<Arc<crate::upstream::UpstreamPool>>,
    /// Number of upstream attempts
    pub(crate) upstream_attempts: u32,
    /// Times the request itself has been sent upstream.
    ///
    /// Distinct from `upstream_attempts`, which counts tries at *selecting* a
    /// backend. This one backs the route's `retry-policy` and is incremented
    /// in `upstream_peer`, which Pingora re-enters on every retry.
    pub(crate) request_attempts: u32,

    // === Scope (for namespaced configurations) ===
    /// Namespace for this request (if routed to a namespace scope)
    pub(crate) namespace: Option<String>,
    /// Service for this request (if routed to a service scope)
    pub(crate) service: Option<String>,

    // === Concurrency ===
    /// This request's slots in the `max-in-flight-requests` counters. Held
    /// here so they are released when Pingora drops the context, which it
    /// does however the request ends; releasing in `logging()` alone would
    /// depend on every exit path reaching it.
    pub(crate) in_flight: Vec<zentinel_common::limits::InFlightPermit>,

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
    /// Cache status for Cache-Status response header (RFC 9211)
    pub(crate) cache_status: Option<CacheStatus>,

    // === Body Inspection ===
    /// Whether body inspection is enabled for this request
    pub(crate) body_inspection_enabled: bool,
    /// Bytes already sent to agent for inspection
    pub(crate) body_bytes_inspected: u64,
    /// Accumulated body buffer for agent inspection
    pub(crate) body_buffer: Vec<u8>,
    /// Agents to use for body inspection.
    ///
    /// Agents whose filter sets `inspect-body #false` are left out, and each
    /// carries its filter's `max-body-bytes`.
    pub(crate) body_inspection_agents: Vec<crate::agents::BodyAgent>,
    /// Response-header changes agents asked for in the request phases
    /// (request headers, request body), applied to the client's response
    /// in `response_filter` before the response phases' own (#596).
    pub(crate) agent_response_headers: Vec<zentinel_agent_protocol::HeaderOp>,

    // === Agentic protocol policy (MCP / A2A) ===
    /// Request body accumulated for MCP/A2A policy evaluation.
    ///
    /// Separate from `body_buffer`, which serves agent inspection and is
    /// governed by the WAF's streaming mode. Policy here is resolved from the
    /// JSON-RPC envelope and must see the whole envelope before the request
    /// reaches an upstream, whatever the agent configuration happens to be.
    pub(crate) agentic_body: Vec<u8>,
    /// Set when the body exceeded what the evaluator will parse, so evaluation
    /// treats it as uninspectable rather than judging a truncated prefix.
    pub(crate) agentic_body_oversize: bool,
    /// MCP method resolved **from the body**, for metrics and audit. Recording
    /// the header value instead would describe what a client claimed rather
    /// than what the upstream will execute.
    pub(crate) mcp_method: Option<String>,
    /// MCP tool or resource resolved from the body.
    pub(crate) mcp_target: Option<String>,
    /// A2A method resolved from the body.
    pub(crate) a2a_method: Option<String>,
    /// Set when the response to this request is an MCP listing whose entries
    /// the route's tool policy governs, and must be rewritten before it
    /// reaches the client. See [`crate::agentic::listing`].
    pub(crate) mcp_listing: Option<crate::agentic::listing::Plan>,
    /// Response bytes held back for that rewrite. For a JSON response this is
    /// the whole body; for an event stream it holds only the event currently
    /// being assembled, so a stream that stays open is not withheld with it.
    pub(crate) mcp_listing_body: Vec<u8>,
    /// A tool call on a multiplexing route that is being **proxied** rather
    /// than answered by the gateway.
    ///
    /// Set in `request_filter` once the body has named the upstream, because
    /// that is the last hook before a peer is chosen. Carries the body to send
    /// on, with the upstream's prefix stripped from the tool name, since the
    /// downstream body has been consumed by then and pingora has nothing left
    /// to forward.
    pub(crate) mcp_proxied_call: Option<crate::agentic::multiplex::ProxiedCall>,

    /// A request body read whole in `request_filter` for API schema
    /// validation, waiting to be handed back to pingora.
    ///
    /// Reading the body there consumes it. Without this, a request that passed
    /// validation reached the upstream with headers promising a body that never
    /// came, and timed out (504 after 30 s) instead of being served.
    pub(crate) validated_request_body: Option<bytes::Bytes>,

    /// The body of a custom error page that replaces an upstream error
    /// response, sent by `response_body_filter` in place of the upstream's.
    ///
    /// The page's headers are set in `response_filter`; without the body to
    /// go with them, the client got the upstream's body under the page's
    /// Content-Type and Content-Length.
    pub(crate) error_page_body: Option<bytes::Bytes>,

    /// An agent's `Block` decision, for the response that answers it. An
    /// agent's own body is sent as it is, in place of the route's error
    /// page: the agent chose what to tell the client (#557).
    pub(crate) agent_block: Option<AgentBlock>,

    /// An agent blocked the response (#584). On response headers the block
    /// response was written in place of the upstream's; on the response
    /// body the response was aborted. Either way nothing more may be
    /// written to the client, and the upstream did nothing wrong.
    pub(crate) response_blocked: bool,

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

    // === Response-Phase Agent Processing ===
    /// The route's agent filters (saved in request phase for response phase)
    pub(crate) route_agents: Vec<crate::agents::FilterAgent>,
    /// Whether response-phase agent processing is enabled (agent subscribes to response events)
    pub(crate) response_agent_processing_enabled: bool,
    /// Accumulated response body buffer for agent processing (when agent needs full body)
    pub(crate) response_agent_body_buffer: Vec<u8>,
    /// The most response body any of the route's agents inspects: the
    /// buffer above never grows past it. A body that does is decided on at
    /// that point, by the agents' body limits.
    pub(crate) response_agent_body_limit: usize,
    /// Whether response body has been fully received by agent
    pub(crate) response_agent_body_complete: bool,
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
            selected_pool: None,
            upstream_attempts: 0,
            request_attempts: 0,
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
            cache_status: None,
            body_inspection_enabled: false,
            body_bytes_inspected: 0,
            body_buffer: Vec::new(),
            agentic_body: Vec::new(),
            agentic_body_oversize: false,
            mcp_method: None,
            mcp_target: None,
            mcp_listing: None,
            mcp_listing_body: Vec::new(),
            mcp_proxied_call: None,
            validated_request_body: None,
            error_page_body: None,
            agent_block: None,
            response_blocked: false,
            a2a_method: None,
            body_inspection_agents: Vec::new(),
            agent_response_headers: Vec::new(),
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
            route_agents: Vec::new(),
            response_agent_processing_enabled: false,
            response_agent_body_buffer: Vec::new(),
            response_agent_body_limit: usize::MAX,
            response_agent_body_complete: false,
            in_flight: Vec::new(),
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
    /// Times the request itself has been sent upstream.
    pub fn request_attempts(&self) -> u32 {
        self.request_attempts
    }

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

    /// The client IP as the `SocketAddr` upstream selection takes.
    ///
    /// `client_ip` holds a bare address, so the port is 0: `ip-hash` and
    /// client-IP consistent hashing must map one client to one target, not
    /// one connection.
    pub(crate) fn client_socket_addr(&self) -> Option<std::net::SocketAddr> {
        self.client_ip
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, 0))
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

    /// The request body limit that applies to this request, given the
    /// global `limits` one.
    ///
    /// A route's `policies { max-body-size }` can only tighten the global
    /// limit, never lift it: the global limit is the operator's bound on what
    /// the proxy accepts at all. Until #517 the route setting was parsed and
    /// then never read, so a route limited to 1 KB accepted the global 10 MB.
    ///
    /// The `limits { max-body-size }` of the route's namespace and service
    /// tighten it the same way; the smallest of them all applies.
    pub(crate) fn max_body_size(&self, global_limit: usize) -> usize {
        let scoped = self.scoped_min(global_limit, |l| l.max_body_size_bytes);
        self.route_config
            .as_ref()
            .and_then(|route| route.policies.max_body_size)
            .map_or(scoped, |route_limit| route_limit.0.min(scoped))
    }

    /// `max-header-count` for this request: the global one, or the
    /// namespace's or service's if smaller.
    pub(crate) fn max_header_count(&self, global_limit: usize) -> usize {
        self.scoped_min(global_limit, |l| l.max_header_count)
    }

    /// `max-header-size` for this request: the global one, or the
    /// namespace's or service's if smaller.
    pub(crate) fn max_header_size(&self, global_limit: usize) -> usize {
        self.scoped_min(global_limit, |l| l.max_header_size_bytes)
    }

    /// The smallest of `global` and the value `key` reads from each scoped
    /// `limits` block that applies.
    fn scoped_min(
        &self,
        global: usize,
        key: impl Fn(&zentinel_common::limits::Limits) -> usize,
    ) -> usize {
        self.scope_limits()
            .into_iter()
            .map(|(_, limits)| key(limits))
            .fold(global, usize::min)
    }

    /// The scope this request was routed in, from `namespace` and `service`.
    pub(crate) fn scope(&self) -> Scope {
        match (&self.namespace, &self.service) {
            (Some(namespace), Some(service)) => Scope::Service {
                namespace: namespace.clone(),
                service: service.clone(),
            },
            (Some(namespace), None) => Scope::Namespace(namespace.clone()),
            (None, _) => Scope::Global,
        }
    }

    /// The `limits` blocks of the namespace and the service this request was
    /// routed in, each with the scope it belongs to, namespace first.
    ///
    /// Until #542 a namespace's were parsed and never applied, and a
    /// service's until #548. A scoped block holds only the keys it writes
    /// (the rest unbounded), so taking the smaller of it and the global value
    /// never applies a default the scope did not ask for. Looked up in the
    /// request's config snapshot, so it changes with a reload like everything
    /// else.
    pub(crate) fn scope_limits(&self) -> Vec<(Scope, &zentinel_common::limits::Limits)> {
        self.config
            .as_ref()
            .map(|config| config.scope_limits(&self.scope()))
            .unwrap_or_default()
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

    mod agent_block {
        use super::super::AgentBlock;
        use crate::agents::AgentAction;
        use std::collections::HashMap;

        fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        }

        fn challenge(pairs: &[(&str, &str)]) -> AgentAction {
            AgentAction::Challenge {
                challenge_type: "captcha".to_string(),
                params: params(pairs),
            }
        }

        #[test]
        fn only_allow_lets_a_request_through() {
            assert_eq!(AgentBlock::for_request(&AgentAction::Allow), None);
            for action in [
                AgentAction::Block {
                    status: 403,
                    body: None,
                    headers: None,
                },
                AgentAction::Redirect {
                    url: "https://example.com/".to_string(),
                    status: 302,
                },
                challenge(&[]),
            ] {
                assert!(AgentBlock::for_request(&action).is_some(), "{action:?}");
            }
        }

        #[test]
        fn a_block_is_answered_as_the_agent_asked() {
            let action = AgentAction::Block {
                status: 451,
                body: Some("no".to_string()),
                headers: Some(HashMap::from([("X-B".to_string(), "1".to_string())])),
            };
            let block = AgentBlock::for_request(&action).unwrap();
            assert_eq!(Some(block.clone()), AgentBlock::from_action(&action));
            assert_eq!(block.status, 451);
            assert_eq!(block.body.as_deref(), Some("no"));
            assert_eq!(block.headers, vec![("X-B".to_string(), "1".to_string())]);
        }

        #[test]
        fn the_response_phases_still_act_on_blocks_only() {
            // #588 decides Redirect and Challenge there.
            assert_eq!(AgentBlock::from_action(&challenge(&[])), None);
            assert_eq!(
                AgentBlock::from_action(&AgentAction::Redirect {
                    url: "/x".to_string(),
                    status: 302
                }),
                None
            );
        }

        #[test]
        fn a_redirect_keeps_a_redirect_status_and_sets_location() {
            for status in [301, 302, 303, 307, 308] {
                let block = AgentBlock::for_request(&AgentAction::Redirect {
                    url: "https://example.com/login?next=%2F".to_string(),
                    status,
                })
                .unwrap();
                assert_eq!(block.status, status);
                assert_eq!(block.body, None);
                assert_eq!(
                    block.headers,
                    vec![(
                        "Location".to_string(),
                        "https://example.com/login?next=%2F".to_string()
                    )]
                );
            }
        }

        #[test]
        fn a_redirect_with_another_status_falls_back_to_302() {
            for status in [0, 200, 300, 304, 305, 403, 500] {
                let block = AgentBlock::redirect("/elsewhere", status);
                assert_eq!(block.status, 302, "{status}");
                assert_eq!(
                    block.headers,
                    vec![("Location".to_string(), "/elsewhere".to_string())]
                );
            }
        }

        #[test]
        fn a_redirect_to_a_url_that_is_no_header_value_is_refused() {
            let block = AgentBlock::redirect("/a\r\nSet-Cookie: x=1", 302);
            assert_eq!(block.status, 500);
            assert!(block.headers.is_empty());
        }

        #[test]
        fn a_challenge_without_parameters_is_a_bare_403() {
            let block = AgentBlock::for_request(&challenge(&[])).unwrap();
            assert_eq!(block.status, 403);
            assert_eq!(block.body, None);
            assert!(block.headers.is_empty());
        }

        #[test]
        fn a_www_authenticate_challenge_is_a_401_with_the_header() {
            let block =
                AgentBlock::for_request(&challenge(&[("WWW-Authenticate", "Basic realm=\"z\"")]))
                    .unwrap();
            assert_eq!(block.status, 401);
            assert_eq!(
                block.headers,
                vec![(
                    "WWW-Authenticate".to_string(),
                    "Basic realm=\"z\"".to_string()
                )]
            );
        }

        #[test]
        fn a_challenge_page_is_sent_with_its_content_type() {
            let block = AgentBlock::challenge(&params(&[
                ("body", "<html>solve me</html>"),
                ("Content-Type", "text/html"),
                ("token", "secret-token"),
                ("challenge_url", "https://example.com/c"),
            ]));
            assert_eq!(block.status, 403);
            assert_eq!(block.body.as_deref(), Some("<html>solve me</html>"));
            // Only the content type: other parameters are the agent's.
            assert_eq!(
                block.headers,
                vec![("Content-Type".to_string(), "text/html".to_string())]
            );
        }

        #[test]
        fn a_content_type_without_a_body_is_ignored() {
            let block = AgentBlock::challenge(&params(&[("content-type", "text/html")]));
            assert_eq!(block.status, 403);
            assert!(block.headers.is_empty());
        }

        #[test]
        fn action_names() {
            assert_eq!(AgentBlock::action_name(&AgentAction::Allow), "allow");
            assert_eq!(AgentBlock::action_name(&challenge(&[])), "challenge");
        }
    }

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

    fn ctx_with_route_limit(limit: Option<usize>) -> RequestContext {
        let mut route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": "r",
            "matches": [],
        }))
        .unwrap();
        route.policies.max_body_size = limit.map(zentinel_common::types::ByteSize);
        let mut ctx = RequestContext::new();
        ctx.route_config = Some(Arc::new(route));
        ctx
    }

    #[test]
    fn a_route_body_limit_tightens_the_global_one() {
        assert_eq!(ctx_with_route_limit(Some(1024)).max_body_size(10_000), 1024);
    }

    #[test]
    fn a_route_body_limit_cannot_lift_the_global_one() {
        assert_eq!(
            ctx_with_route_limit(Some(1 << 30)).max_body_size(10_000),
            10_000
        );
    }

    #[test]
    fn without_a_route_limit_the_global_one_applies() {
        assert_eq!(ctx_with_route_limit(None).max_body_size(10_000), 10_000);
        assert_eq!(RequestContext::new().max_body_size(10_000), 10_000);
    }

    fn ctx_in_namespace(ns_limits: &str, route_limit: Option<usize>) -> RequestContext {
        let config = zentinel_config::Config::from_kdl(&format!(
            r#"
            schema-version "1.0"
            system {{ worker-threads 1 }}
            listeners {{ listener "l" {{ address "127.0.0.1:8080"; namespace "ns"; }} }}
            namespace "ns" {{
                limits {{ {ns_limits} }}
            }}
            "#
        ))
        .unwrap();
        let mut ctx = ctx_with_route_limit(route_limit);
        ctx.config = Some(Arc::new(config));
        ctx.namespace = Some("ns".to_string());
        ctx
    }

    /// #542: namespace limits tighten the global ones and are tightened by
    /// the route's; the smallest applies.
    #[test]
    fn the_smallest_of_global_namespace_and_route_body_limits_applies() {
        let ctx = ctx_in_namespace("max-body-size 2000", None);
        assert_eq!(ctx.max_body_size(10_000), 2000);
        assert_eq!(ctx.max_body_size(1500), 1500);
        let ctx = ctx_in_namespace("max-body-size 2000", Some(500));
        assert_eq!(ctx.max_body_size(10_000), 500);
        let ctx = ctx_in_namespace("max-body-size 2000", Some(5000));
        assert_eq!(ctx.max_body_size(10_000), 2000);
    }

    #[test]
    fn namespace_header_limits_tighten_but_never_loosen() {
        let ctx = ctx_in_namespace("max-header-count 10\n max-header-size 512", None);
        assert_eq!(ctx.max_header_count(100), 10);
        assert_eq!(ctx.max_header_size(8192), 512);
        assert_eq!(ctx.max_header_size(256), 256);
        // A key the namespace does not write leaves the global value alone,
        // even where the global one is above the default.
        let ctx = ctx_in_namespace("max-body-size 2000", None);
        assert_eq!(ctx.max_header_size(65_536), 65_536);
        assert_eq!(ctx.max_header_count(500), 500);
    }

    #[test]
    fn a_request_outside_a_namespace_gets_the_global_limits() {
        let mut ctx = ctx_in_namespace("max-body-size 2000", None);
        ctx.namespace = None;
        assert_eq!(ctx.max_body_size(10_000), 10_000);
        assert!(ctx.scope_limits().is_empty());
    }

    /// #548: a service's limits apply to its routes too, within its
    /// namespace's; the smallest of global, namespace, service and route
    /// applies.
    #[test]
    fn service_limits_tighten_the_namespace_ones() {
        let config = zentinel_config::Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners { listener "l" { address "127.0.0.1:8080"; } }
            namespace "ns" {
                limits { max-body-size 2000; max-header-count 50; }
                service "svc" {
                    limits { max-body-size 700; }
                }
                service "open" {}
            }
            namespace "bare" {
                service "svc" {
                    limits { max-header-size 300; }
                }
            }
            "#,
        )
        .unwrap()
        .lower_scopes();
        let config = Arc::new(config);
        let ctx = |ns: &str, svc: Option<&str>, route_limit| {
            let mut ctx = ctx_with_route_limit(route_limit);
            ctx.config = Some(Arc::clone(&config));
            ctx.namespace = Some(ns.to_string());
            ctx.service = svc.map(str::to_string);
            ctx
        };

        let svc = ctx("ns", Some("svc"), None);
        assert_eq!(svc.max_body_size(10_000), 700);
        assert_eq!(svc.max_header_count(100), 50);
        assert_eq!(ctx("ns", Some("svc"), Some(300)).max_body_size(10_000), 300);
        // A service without limits gets its namespace's.
        assert_eq!(ctx("ns", Some("open"), None).max_body_size(10_000), 2000);
        // A namespace without limits, and a service with them: the service's
        // block is attributed to the service, not the namespace.
        let bare = ctx("bare", Some("svc"), None);
        assert_eq!(bare.max_header_size(8192), 300);
        let scopes: Vec<_> = bare.scope_limits().into_iter().map(|(s, _)| s).collect();
        assert_eq!(
            scopes,
            vec![Scope::Service {
                namespace: "bare".into(),
                service: "svc".into()
            }]
        );
    }

    /// #542: the in-flight slot is released when the context is dropped,
    /// which Pingora does on every exit path -- response sent, upstream
    /// error, client gone -- including a request task that is cancelled
    /// outright and never reaches `logging()`.
    #[tokio::test]
    async fn in_flight_slots_are_released_when_the_context_is_dropped() {
        let limiter = std::sync::Arc::new(zentinel_common::limits::InFlightLimiter::new());

        let mut ctx = RequestContext::new();
        ctx.in_flight
            .push(limiter.try_acquire_global(Some(1)).unwrap());
        assert!(limiter.try_acquire_global(Some(1)).is_none());
        drop(ctx);
        assert_eq!(limiter.global(), 0);

        // A request task cancelled while it waits on the upstream.
        let held = std::sync::Arc::clone(&limiter);
        let task = tokio::spawn(async move {
            let mut ctx = RequestContext::new();
            ctx.in_flight
                .push(held.try_acquire_global(Some(1)).unwrap());
            std::future::pending::<()>().await;
            drop(ctx);
        });
        while limiter.global() == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        assert_eq!(limiter.global(), 0);
    }
}
