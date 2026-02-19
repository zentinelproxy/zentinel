//! ProxyHttp trait implementation for ZentinelProxy.
//!
//! This module contains the Pingora ProxyHttp trait implementation which defines
//! the core request/response lifecycle handling.

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::protocols::Digest;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::Peer;
use pingora_cache::{
    CacheKey, CacheMeta, ForcedFreshness, HitHandler, NoCacheReason, RespCacheable,
};
use pingora_timeout::sleep;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

use crate::cache::{get_cache_eviction, get_cache_lock, get_cache_storage};
use crate::inference::{
    extract_inference_content, is_sse_response, PromptInjectionResult, StreamingTokenCounter,
};
use crate::logging::{AccessLogEntry, AuditEventType, AuditLogEntry};
use crate::rate_limit::HeaderAccessor;
use crate::routing::RequestInfo;

use super::context::{FallbackReason, RequestContext};
use super::fallback::FallbackEvaluator;
use super::fallback_metrics::get_fallback_metrics;
use super::model_routing;
use super::model_routing_metrics::get_model_routing_metrics;
use super::ZentinelProxy;

/// Helper type for rate limiting when we don't need header access
struct NoHeaderAccessor;
impl HeaderAccessor for NoHeaderAccessor {
    fn get_header(&self, _name: &str) -> Option<String> {
        None
    }
}

#[async_trait]
impl ProxyHttp for ZentinelProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX {
        RequestContext::new()
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        error!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
            peer_address = %peer.address(),
            error = %e,
            "Failed to connect to upstream peer"
        );
        // Custom error pages are handled in response_filter
        e
    }

    /// Early request filter - runs before upstream selection
    /// Used to handle builtin routes that don't need an upstream connection
    async fn early_request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Extract request info for routing
        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let path = req_header.uri.path();
        let host = req_header
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        // Handle ACME HTTP-01 challenges before any other processing
        if let Some(ref challenge_manager) = self.acme_challenges {
            if let Some(token) = crate::acme::ChallengeManager::extract_token(path) {
                if let Some(key_authorization) = challenge_manager.get_response(token) {
                    debug!(
                        token = %token,
                        "Serving ACME HTTP-01 challenge response"
                    );

                    // Build response
                    let mut resp = ResponseHeader::build(200, None)?;
                    resp.insert_header("Content-Type", "text/plain")?;
                    resp.insert_header("Content-Length", key_authorization.len().to_string())?;

                    // Send response
                    session.write_response_header(Box::new(resp), false).await?;
                    session
                        .write_response_body(Some(Bytes::from(key_authorization)), true)
                        .await?;

                    // Return error to signal request is complete
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "ACME challenge served",
                    ));
                } else {
                    // Token not found - could be a stale request or attack
                    warn!(
                        token = %token,
                        "ACME challenge token not found"
                    );
                }
            }
        }

        ctx.method = method.to_string();
        ctx.path = path.to_string();
        ctx.host = Some(host.to_string());

        // Match route to determine service type
        let route_match = {
            let route_matcher = self.route_matcher.read();
            let request_info = RequestInfo::new(method, path, host);
            match route_matcher.match_request(&request_info) {
                Some(m) => m,
                None => return Ok(()), // No matching route, let upstream_peer handle it
            }
        };

        ctx.trace_id = self.get_trace_id(session);
        ctx.route_id = Some(route_match.route_id.to_string());
        ctx.route_config = Some(route_match.config.clone());

        // Parse incoming W3C trace context if present
        if let Some(traceparent) = req_header.headers.get(crate::otel::TRACEPARENT_HEADER) {
            if let Ok(s) = traceparent.to_str() {
                ctx.trace_context = crate::otel::TraceContext::parse_traceparent(s);
            }
        }

        // Start OpenTelemetry request span if tracing is enabled
        if let Some(tracer) = crate::otel::get_tracer() {
            ctx.otel_span = Some(tracer.start_span(method, path, ctx.trace_context.as_ref()));
        }

        // Check if this is a builtin handler route
        if route_match.config.service_type == zentinel_config::ServiceType::Builtin {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_match.route_id,
                builtin_handler = ?route_match.config.builtin_handler,
                "Handling builtin route in early_request_filter"
            );

            // Handle the builtin route directly
            let handled = self
                .handle_builtin_route(session, ctx, &route_match)
                .await?;

            if handled {
                // Return error to signal that request is complete (Pingora will not continue)
                return Err(Error::explain(
                    ErrorType::InternalError,
                    "Builtin handler complete",
                ));
            }
        }

        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // Track active request
        self.reload_coordinator.inc_requests();

        // Cache global config once per request (avoids repeated Arc clones)
        if ctx.config.is_none() {
            ctx.config = Some(self.config_manager.current());
        }

        // Cache client address for logging if not already set
        if ctx.client_ip.is_empty() {
            ctx.client_ip = session
                .client_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".to_string());
        }

        let req_header = session.req_header();

        // Cache request info for access logging if not already set
        if ctx.method.is_empty() {
            ctx.method = req_header.method.to_string();
            ctx.path = req_header.uri.path().to_string();
            ctx.query = req_header.uri.query().map(|q| q.to_string());
            ctx.host = req_header
                .headers
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
        }
        ctx.user_agent = req_header
            .headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        ctx.referer = req_header
            .headers
            .get("referer")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        trace!(
            correlation_id = %ctx.trace_id,
            client_ip = %ctx.client_ip,
            "Request received, initializing context"
        );

        // Use cached route info if already set by early_request_filter
        let route_match = if let Some(ref route_config) = ctx.route_config {
            let route_id = ctx.route_id.as_deref().unwrap_or("");
            crate::routing::RouteMatch {
                route_id: zentinel_common::RouteId::new(route_id),
                config: route_config.clone(),
            }
        } else {
            // Match route using sync RwLock (scoped to ensure lock is released before async ops)
            let (match_result, route_duration) = {
                let route_matcher = self.route_matcher.read();
                let host = ctx.host.as_deref().unwrap_or("");

                // Build request info (zero-copy for common case)
                let mut request_info = RequestInfo::new(&ctx.method, &ctx.path, host);

                // Only build headers HashMap if any route needs header matching
                if route_matcher.needs_headers() {
                    request_info = request_info
                        .with_headers(RequestInfo::build_headers(req_header.headers.iter()));
                }

                // Only parse query params if any route needs query param matching
                if route_matcher.needs_query_params() {
                    request_info =
                        request_info.with_query_params(RequestInfo::parse_query_params(&ctx.path));
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    method = %request_info.method,
                    path = %request_info.path,
                    host = %request_info.host,
                    "Built request info for route matching"
                );

                let route_start = std::time::Instant::now();
                let route_match = route_matcher.match_request(&request_info).ok_or_else(|| {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        method = %request_info.method,
                        path = %request_info.path,
                        host = %request_info.host,
                        "No matching route found for request"
                    );
                    Error::explain(ErrorType::InternalError, "No matching route found")
                })?;
                let route_duration = route_start.elapsed();
                // Lock is dropped here when block ends
                (route_match, route_duration)
            };

            ctx.route_id = Some(match_result.route_id.to_string());
            ctx.route_config = Some(match_result.config.clone());

            // Set trace_id if not already set by early_request_filter
            if ctx.trace_id.is_empty() {
                ctx.trace_id = self.get_trace_id(session);

                // Parse incoming W3C trace context if present
                if let Some(traceparent) = req_header.headers.get(crate::otel::TRACEPARENT_HEADER) {
                    if let Ok(s) = traceparent.to_str() {
                        ctx.trace_context = crate::otel::TraceContext::parse_traceparent(s);
                    }
                }

                // Start OpenTelemetry request span if tracing is enabled
                if let Some(tracer) = crate::otel::get_tracer() {
                    ctx.otel_span =
                        Some(tracer.start_span(&ctx.method, &ctx.path, ctx.trace_context.as_ref()));
                }
            }

            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %match_result.route_id,
                route_duration_us = route_duration.as_micros(),
                service_type = ?match_result.config.service_type,
                "Route matched"
            );
            match_result
        };

        // Check if this is a builtin handler route (no upstream needed)
        if route_match.config.service_type == zentinel_config::ServiceType::Builtin {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_match.route_id,
                builtin_handler = ?route_match.config.builtin_handler,
                "Route type is builtin, skipping upstream"
            );
            // Mark as builtin route for later processing in request_filter
            ctx.upstream = Some(format!("_builtin_{}", route_match.route_id));
            // Return error to skip upstream connection for builtin routes
            return Err(Error::explain(
                ErrorType::InternalError,
                "Builtin handler handled in request_filter",
            ));
        }

        // Check if this is a static file route
        if route_match.config.service_type == zentinel_config::ServiceType::Static {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_match.route_id,
                "Route type is static, checking for static server"
            );
            // Static routes don't need an upstream
            if self
                .static_servers
                .get(route_match.route_id.as_str())
                .await
                .is_some()
            {
                // Mark this as a static route for later processing
                ctx.upstream = Some(format!("_static_{}", route_match.route_id));
                info!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_match.route_id,
                    path = %ctx.path,
                    "Serving static file"
                );
                // Return error to avoid upstream connection for static routes
                return Err(Error::explain(
                    ErrorType::InternalError,
                    "Static file serving handled in request_filter",
                ));
            }
        }

        // === Model-based routing (for inference routes) ===
        // Check if model routing is configured and select upstream based on model
        let mut model_routing_applied = false;
        if let Some(ref inference) = route_match.config.inference {
            if let Some(ref model_routing) = inference.model_routing {
                // Try to extract model from headers (fast path - no body parsing needed)
                let model = model_routing::extract_model_from_headers(&req_header.headers);

                if let Some(ref model_name) = model {
                    // Find upstream for this model
                    if let Some(routing_result) =
                        model_routing::find_upstream_for_model(model_routing, model_name)
                    {
                        debug!(
                            correlation_id = %ctx.trace_id,
                            route_id = %route_match.route_id,
                            model = %model_name,
                            upstream = %routing_result.upstream,
                            is_default = routing_result.is_default,
                            provider_override = ?routing_result.provider,
                            "Model-based routing selected upstream"
                        );

                        ctx.record_model_routing(
                            &routing_result.upstream,
                            Some(model_name.clone()),
                            routing_result.provider,
                        );
                        model_routing_applied = true;

                        // Record metrics
                        if let Some(metrics) = get_model_routing_metrics() {
                            metrics.record_model_routed(
                                route_match.route_id.as_str(),
                                model_name,
                                &routing_result.upstream,
                            );
                            if routing_result.is_default {
                                metrics.record_default_upstream(route_match.route_id.as_str());
                            }
                            if let Some(provider) = routing_result.provider {
                                metrics.record_provider_override(
                                    route_match.route_id.as_str(),
                                    &routing_result.upstream,
                                    provider.as_str(),
                                );
                            }
                        }
                    }
                } else if let Some(ref default_upstream) = model_routing.default_upstream {
                    // No model in headers, use default upstream
                    debug!(
                        correlation_id = %ctx.trace_id,
                        route_id = %route_match.route_id,
                        upstream = %default_upstream,
                        "Model-based routing using default upstream (no model header)"
                    );
                    ctx.record_model_routing(default_upstream, None, None);
                    model_routing_applied = true;

                    // Record metrics for no model header case
                    if let Some(metrics) = get_model_routing_metrics() {
                        metrics.record_no_model_header(route_match.route_id.as_str());
                    }
                }
            }
        }

        // Regular route with upstream (if model routing didn't set it)
        if !model_routing_applied {
            if let Some(ref upstream) = route_match.config.upstream {
                ctx.upstream = Some(upstream.clone());
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_match.route_id,
                    upstream = %upstream,
                    "Upstream configured for route"
                );
            } else {
                error!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_match.route_id,
                    "Route has no upstream configured"
                );
                return Err(Error::explain(
                    ErrorType::InternalError,
                    format!(
                        "Route '{}' has no upstream configured",
                        route_match.route_id
                    ),
                ));
            }
        }

        // === Fallback routing evaluation (pre-request) ===
        // Check if fallback should be triggered due to health or budget conditions
        if let Some(ref fallback_config) = route_match.config.fallback {
            let upstream_name = ctx.upstream.as_ref().unwrap();

            // Check if primary upstream is healthy
            let is_healthy = if let Some(pool) = self.upstream_pools.get(upstream_name).await {
                pool.has_healthy_targets().await
            } else {
                false // Pool not found, treat as unhealthy
            };

            // Check if budget is exhausted (for inference routes)
            let is_budget_exhausted = ctx.inference_budget_exhausted;

            // Get model name for model mapping (inference routes)
            let current_model = ctx.inference_model.as_deref();

            // Create fallback evaluator
            let evaluator = FallbackEvaluator::new(
                fallback_config,
                ctx.tried_upstreams(),
                ctx.fallback_attempt,
            );

            // Evaluate pre-request fallback conditions
            if let Some(decision) = evaluator.should_fallback_before_request(
                upstream_name,
                is_healthy,
                is_budget_exhausted,
                current_model,
            ) {
                info!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_match.route_id,
                    from_upstream = %upstream_name,
                    to_upstream = %decision.next_upstream,
                    reason = %decision.reason,
                    fallback_attempt = ctx.fallback_attempt + 1,
                    "Triggering fallback routing"
                );

                // Record fallback metrics
                if let Some(metrics) = get_fallback_metrics() {
                    metrics.record_fallback_attempt(
                        route_match.route_id.as_str(),
                        upstream_name,
                        &decision.next_upstream,
                        &decision.reason,
                    );
                }

                // Record fallback in context
                ctx.record_fallback(decision.reason, &decision.next_upstream);

                // Apply model mapping if present
                if let Some((original, mapped)) = decision.model_mapping {
                    // Record model mapping metrics
                    if let Some(metrics) = get_fallback_metrics() {
                        metrics.record_model_mapping(
                            route_match.route_id.as_str(),
                            &original,
                            &mapped,
                        );
                    }

                    ctx.record_model_mapping(original, mapped);
                    trace!(
                        correlation_id = %ctx.trace_id,
                        original_model = ?ctx.model_mapping_applied().map(|m| &m.0),
                        mapped_model = ?ctx.model_mapping_applied().map(|m| &m.1),
                        "Applied model mapping for fallback"
                    );
                }
            }
        }

        debug!(
            correlation_id = %ctx.trace_id,
            route_id = %route_match.route_id,
            upstream = ?ctx.upstream,
            method = %req_header.method,
            path = %req_header.uri.path(),
            host = ctx.host.as_deref().unwrap_or("-"),
            client_ip = %ctx.client_ip,
            "Processing request"
        );

        // Get upstream pool (skip for static routes)
        if ctx
            .upstream
            .as_ref()
            .is_some_and(|u| u.starts_with("_static_"))
        {
            // Static routes are handled in request_filter, should not reach here
            return Err(Error::explain(
                ErrorType::InternalError,
                "Static route should be handled in request_filter",
            ));
        }

        let upstream_name = ctx
            .upstream
            .as_ref()
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "No upstream configured"))?;

        trace!(
            correlation_id = %ctx.trace_id,
            upstream = %upstream_name,
            "Looking up upstream pool"
        );

        let pool = self
            .upstream_pools
            .get(upstream_name)
            .await
            .ok_or_else(|| {
                error!(
                    correlation_id = %ctx.trace_id,
                    upstream = %upstream_name,
                    "Upstream pool not found"
                );
                Error::explain(
                    ErrorType::InternalError,
                    format!("Upstream pool '{}' not found", upstream_name),
                )
            })?;

        // Select peer from pool with retries
        let max_retries = route_match
            .config
            .retry_policy
            .as_ref()
            .map(|r| r.max_attempts)
            .unwrap_or(1);

        trace!(
            correlation_id = %ctx.trace_id,
            upstream = %upstream_name,
            max_retries = max_retries,
            "Starting upstream peer selection"
        );

        let mut last_error = None;
        let selection_start = std::time::Instant::now();

        for attempt in 1..=max_retries {
            ctx.upstream_attempts = attempt;

            trace!(
                correlation_id = %ctx.trace_id,
                upstream = %upstream_name,
                attempt = attempt,
                max_retries = max_retries,
                "Attempting to select upstream peer"
            );

            match pool.select_peer_with_metadata(None).await {
                Ok((mut peer, metadata)) => {
                    let selection_duration = selection_start.elapsed();
                    // Store selected peer address for feedback reporting in logging()
                    let peer_addr = peer.address().to_string();
                    ctx.selected_upstream_address = Some(peer_addr.clone());

                    // Copy sticky session metadata to context for response_filter
                    if metadata.contains_key("sticky_session_new") {
                        ctx.sticky_session_new_assignment = true;
                        ctx.sticky_session_set_cookie =
                            metadata.get("sticky_set_cookie_header").cloned();
                        ctx.sticky_target_index = metadata
                            .get("sticky_target_index")
                            .and_then(|s| s.parse().ok());

                        trace!(
                            correlation_id = %ctx.trace_id,
                            sticky_target_index = ?ctx.sticky_target_index,
                            "New sticky session assignment, will set cookie"
                        );
                    }

                    debug!(
                        correlation_id = %ctx.trace_id,
                        upstream = %upstream_name,
                        peer_address = %peer_addr,
                        attempt = attempt,
                        selection_duration_us = selection_duration.as_micros(),
                        sticky_session_hit = metadata.contains_key("sticky_session_hit"),
                        sticky_session_new = ctx.sticky_session_new_assignment,
                        "Selected upstream peer"
                    );
                    // Apply per-route policy timeout (lowest priority)
                    if let Some(ref rc) = ctx.route_config {
                        if let Some(timeout_secs) = rc.policies.timeout_secs {
                            peer.options.read_timeout = Some(Duration::from_secs(timeout_secs));
                        }
                    }

                    // Apply filter timeout overrides (higher priority, overwrites policy)
                    if let Some(connect_secs) = ctx.filter_connect_timeout_secs {
                        peer.options.connection_timeout = Some(Duration::from_secs(connect_secs));
                    }
                    if let Some(upstream_secs) = ctx.filter_upstream_timeout_secs {
                        peer.options.read_timeout = Some(Duration::from_secs(upstream_secs));
                    }

                    return Ok(Box::new(peer));
                }
                Err(e) => {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        upstream = %upstream_name,
                        attempt = attempt,
                        max_retries = max_retries,
                        error = %e,
                        "Failed to select upstream peer"
                    );
                    last_error = Some(e);

                    if attempt < max_retries {
                        // Exponential backoff (using pingora-timeout for efficiency)
                        let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                        trace!(
                            correlation_id = %ctx.trace_id,
                            backoff_ms = backoff.as_millis(),
                            "Backing off before retry"
                        );
                        sleep(backoff).await;
                    }
                }
            }
        }

        let selection_duration = selection_start.elapsed();
        error!(
            correlation_id = %ctx.trace_id,
            upstream = %upstream_name,
            attempts = max_retries,
            selection_duration_ms = selection_duration.as_millis(),
            last_error = ?last_error,
            "All upstream selection attempts failed"
        );

        // Record exhausted metric if fallback was used but all upstreams failed
        if ctx.used_fallback() {
            if let Some(metrics) = get_fallback_metrics() {
                metrics.record_fallback_exhausted(ctx.route_id.as_deref().unwrap_or("unknown"));
            }
        }

        Err(Error::explain(
            ErrorType::InternalError,
            format!("All upstream attempts failed: {:?}", last_error),
        ))
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<bool, Box<Error>> {
        trace!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            "Starting request filter phase"
        );

        // Apply per-listener timeouts from config
        if let Some(server_addr) = session.downstream_session.server_addr() {
            let server_addr_str = server_addr.to_string();
            let config = ctx
                .config
                .get_or_insert_with(|| self.config_manager.current());
            for listener in &config.listeners {
                if listener.address == server_addr_str {
                    // Apply downstream read timeout
                    session.downstream_session.set_read_timeout(Some(
                        std::time::Duration::from_secs(listener.request_timeout_secs),
                    ));
                    // Store keepalive for response phase
                    ctx.listener_keepalive_timeout_secs = Some(listener.keepalive_timeout_secs);
                    break;
                }
            }
        }

        // Check rate limiting early (before other processing)
        // Fast path: skip if no rate limiting is configured for this route
        if let Some(route_id) = ctx.route_id.as_deref() {
            if self.rate_limit_manager.has_route_limiter(route_id) {
                let rate_result = self.rate_limit_manager.check(
                    route_id,
                    &ctx.client_ip,
                    &ctx.path,
                    Option::<&NoHeaderAccessor>::None,
                );

                // Store rate limit info for response headers (even if allowed)
                if rate_result.limit > 0 {
                    ctx.rate_limit_info = Some(super::context::RateLimitHeaderInfo {
                        limit: rate_result.limit,
                        remaining: rate_result.remaining,
                        reset_at: rate_result.reset_at,
                    });
                }

                if !rate_result.allowed {
                    use zentinel_config::RateLimitAction;

                    match rate_result.action {
                        RateLimitAction::Reject => {
                            warn!(
                                correlation_id = %ctx.trace_id,
                                route_id = route_id,
                                client_ip = %ctx.client_ip,
                                limiter = %rate_result.limiter,
                                limit = rate_result.limit,
                                remaining = rate_result.remaining,
                                "Request rate limited"
                            );
                            self.metrics.record_blocked_request("rate_limited");

                            // Audit log the rate limit
                            let audit_entry = AuditLogEntry::rate_limited(
                                &ctx.trace_id,
                                &ctx.method,
                                &ctx.path,
                                &ctx.client_ip,
                                &rate_result.limiter,
                            )
                            .with_route_id(route_id)
                            .with_status_code(rate_result.status_code);
                            self.log_manager.log_audit(&audit_entry);

                            // Send rate limit response with headers
                            let body = rate_result
                                .message
                                .unwrap_or_else(|| "Rate limit exceeded".to_string());

                            // Build response with rate limit headers
                            let retry_after = rate_result.reset_at.saturating_sub(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            );
                            crate::http_helpers::write_rate_limit_error(
                                session,
                                rate_result.status_code,
                                &body,
                                rate_result.limit,
                                rate_result.remaining,
                                rate_result.reset_at,
                                retry_after,
                            )
                            .await?;
                            return Ok(true); // Request complete, don't continue
                        }
                        RateLimitAction::LogOnly => {
                            debug!(
                                correlation_id = %ctx.trace_id,
                                route_id = route_id,
                                "Rate limit exceeded (log only mode)"
                            );
                            // Continue processing
                        }
                        RateLimitAction::Delay => {
                            // Apply delay if suggested by rate limiter
                            if let Some(delay_ms) = rate_result.suggested_delay_ms {
                                // Cap delay at the configured maximum
                                let actual_delay = delay_ms.min(rate_result.max_delay_ms);

                                if actual_delay > 0 {
                                    debug!(
                                        correlation_id = %ctx.trace_id,
                                        route_id = route_id,
                                        suggested_delay_ms = delay_ms,
                                        max_delay_ms = rate_result.max_delay_ms,
                                        actual_delay_ms = actual_delay,
                                        "Applying rate limit delay"
                                    );

                                    tokio::time::sleep(std::time::Duration::from_millis(
                                        actual_delay,
                                    ))
                                    .await;
                                }
                            }
                            // Continue processing after delay
                        }
                    }
                }
            }
        }

        // Inference rate limiting (token-based, for LLM/AI routes)
        // This runs after regular rate limiting and checks service type
        if let Some(route_id) = ctx.route_id.as_deref() {
            if let Some(ref route_config) = ctx.route_config {
                if route_config.service_type == zentinel_config::ServiceType::Inference
                    && self.inference_rate_limit_manager.has_route(route_id)
                {
                    // For inference rate limiting, we need access to the request body
                    // to estimate tokens. We'll use buffered body if available.
                    let headers = &session.req_header().headers;

                    // Try to get buffered body, or use empty (will estimate from headers only)
                    let body = ctx.body_buffer.as_slice();

                    // Use client IP as the rate limit key (could be enhanced to use API key header)
                    let rate_limit_key = &ctx.client_ip;

                    if let Some(check_result) = self.inference_rate_limit_manager.check(
                        route_id,
                        rate_limit_key,
                        headers,
                        body,
                    ) {
                        // Store inference rate limiting context for recording actual tokens later
                        ctx.inference_rate_limit_enabled = true;
                        ctx.inference_estimated_tokens = check_result.estimated_tokens;
                        ctx.inference_rate_limit_key = Some(rate_limit_key.to_string());
                        ctx.inference_model = check_result.model.clone();

                        if !check_result.is_allowed() {
                            let retry_after_ms = check_result.retry_after_ms();
                            let retry_after_secs = retry_after_ms.div_ceil(1000);

                            warn!(
                                correlation_id = %ctx.trace_id,
                                route_id = route_id,
                                client_ip = %ctx.client_ip,
                                estimated_tokens = check_result.estimated_tokens,
                                model = ?check_result.model,
                                retry_after_ms = retry_after_ms,
                                "Inference rate limit exceeded (tokens)"
                            );
                            self.metrics
                                .record_blocked_request("inference_rate_limited");

                            // Audit log the token rate limit
                            let audit_entry = AuditLogEntry::new(
                                &ctx.trace_id,
                                AuditEventType::RateLimitExceeded,
                                &ctx.method,
                                &ctx.path,
                                &ctx.client_ip,
                            )
                            .with_route_id(route_id)
                            .with_status_code(429)
                            .with_reason(format!(
                                "Token rate limit exceeded: estimated {} tokens, model={:?}",
                                check_result.estimated_tokens, check_result.model
                            ));
                            self.log_manager.log_audit(&audit_entry);

                            // Send 429 response with appropriate headers
                            let body = "Token rate limit exceeded";
                            let reset_at = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs()
                                + retry_after_secs;

                            // Use simplified error write for inference rate limit
                            crate::http_helpers::write_rate_limit_error(
                                session,
                                429,
                                body,
                                0, // No request limit
                                0, // No remaining
                                reset_at,
                                retry_after_secs,
                            )
                            .await?;
                            return Ok(true); // Request complete, don't continue
                        }

                        trace!(
                            correlation_id = %ctx.trace_id,
                            route_id = route_id,
                            estimated_tokens = check_result.estimated_tokens,
                            model = ?check_result.model,
                            "Inference rate limit check passed"
                        );

                        // Check budget tracking (cumulative per-period limits)
                        if self.inference_rate_limit_manager.has_budget(route_id) {
                            ctx.inference_budget_enabled = true;

                            if let Some(budget_result) =
                                self.inference_rate_limit_manager.check_budget(
                                    route_id,
                                    rate_limit_key,
                                    check_result.estimated_tokens,
                                )
                            {
                                if !budget_result.is_allowed() {
                                    let retry_after_secs = budget_result.retry_after_secs();

                                    warn!(
                                        correlation_id = %ctx.trace_id,
                                        route_id = route_id,
                                        client_ip = %ctx.client_ip,
                                        estimated_tokens = check_result.estimated_tokens,
                                        retry_after_secs = retry_after_secs,
                                        "Token budget exhausted"
                                    );

                                    ctx.inference_budget_exhausted = true;
                                    self.metrics.record_blocked_request("budget_exhausted");

                                    // Audit log the budget exhaustion
                                    let audit_entry = AuditLogEntry::new(
                                        &ctx.trace_id,
                                        AuditEventType::RateLimitExceeded,
                                        &ctx.method,
                                        &ctx.path,
                                        &ctx.client_ip,
                                    )
                                    .with_route_id(route_id)
                                    .with_status_code(429)
                                    .with_reason("Token budget exhausted".to_string());
                                    self.log_manager.log_audit(&audit_entry);

                                    // Send 429 response with budget headers
                                    let body = "Token budget exhausted";
                                    let reset_at = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                        + retry_after_secs;

                                    crate::http_helpers::write_rate_limit_error(
                                        session,
                                        429,
                                        body,
                                        0,
                                        0,
                                        reset_at,
                                        retry_after_secs,
                                    )
                                    .await?;
                                    return Ok(true);
                                }

                                // Capture budget status for response headers
                                let remaining = match &budget_result {
                                    zentinel_common::budget::BudgetCheckResult::Allowed {
                                        remaining,
                                    } => *remaining as i64,
                                    zentinel_common::budget::BudgetCheckResult::Soft {
                                        remaining,
                                        ..
                                    } => *remaining,
                                    _ => 0,
                                };
                                ctx.inference_budget_remaining = Some(remaining);

                                // Get period reset time from budget status
                                if let Some(status) = self
                                    .inference_rate_limit_manager
                                    .budget_status(route_id, rate_limit_key)
                                {
                                    ctx.inference_budget_period_reset = Some(status.period_end);
                                }

                                trace!(
                                    correlation_id = %ctx.trace_id,
                                    route_id = route_id,
                                    budget_remaining = remaining,
                                    "Token budget check passed"
                                );
                            }
                        }

                        // Check if cost attribution is enabled
                        if self
                            .inference_rate_limit_manager
                            .has_cost_attribution(route_id)
                        {
                            ctx.inference_cost_enabled = true;
                        }
                    }
                }
            }
        }

        // Prompt injection guardrail (for inference routes)
        if let Some(ref route_config) = ctx.route_config {
            if let Some(ref inference) = route_config.inference {
                if let Some(ref guardrails) = inference.guardrails {
                    if let Some(ref pi_config) = guardrails.prompt_injection {
                        if pi_config.enabled && !ctx.body_buffer.is_empty() {
                            ctx.guardrails_enabled = true;

                            // Extract content from request body
                            if let Some(content) = extract_inference_content(&ctx.body_buffer) {
                                let result = self
                                    .guardrail_processor
                                    .check_prompt_injection(
                                        pi_config,
                                        &content,
                                        ctx.inference_model.as_deref(),
                                        ctx.route_id.as_deref(),
                                        &ctx.trace_id,
                                    )
                                    .await;

                                match result {
                                    PromptInjectionResult::Blocked {
                                        status,
                                        message,
                                        detections,
                                    } => {
                                        warn!(
                                            correlation_id = %ctx.trace_id,
                                            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                                            detection_count = detections.len(),
                                            "Prompt injection detected, blocking request"
                                        );

                                        self.metrics.record_blocked_request("prompt_injection");

                                        // Store detection categories for logging
                                        ctx.guardrail_detection_categories =
                                            detections.iter().map(|d| d.category.clone()).collect();

                                        // Audit log the block
                                        let audit_entry = AuditLogEntry::new(
                                            &ctx.trace_id,
                                            AuditEventType::Blocked,
                                            &ctx.method,
                                            &ctx.path,
                                            &ctx.client_ip,
                                        )
                                        .with_route_id(ctx.route_id.as_deref().unwrap_or("unknown"))
                                        .with_status_code(status)
                                        .with_reason("Prompt injection detected".to_string());
                                        self.log_manager.log_audit(&audit_entry);

                                        // Send error response
                                        crate::http_helpers::write_json_error(
                                            session,
                                            status,
                                            "prompt_injection_blocked",
                                            Some(&message),
                                        )
                                        .await?;
                                        return Ok(true);
                                    }
                                    PromptInjectionResult::Detected { detections } => {
                                        // Log but allow
                                        warn!(
                                            correlation_id = %ctx.trace_id,
                                            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                                            detection_count = detections.len(),
                                            "Prompt injection detected (logged only)"
                                        );
                                        ctx.guardrail_detection_categories =
                                            detections.iter().map(|d| d.category.clone()).collect();
                                    }
                                    PromptInjectionResult::Warning { detections } => {
                                        // Set flag for response header
                                        ctx.guardrail_warning = true;
                                        ctx.guardrail_detection_categories =
                                            detections.iter().map(|d| d.category.clone()).collect();
                                        debug!(
                                            correlation_id = %ctx.trace_id,
                                            "Prompt injection warning set"
                                        );
                                    }
                                    PromptInjectionResult::Clean => {
                                        trace!(
                                            correlation_id = %ctx.trace_id,
                                            "No prompt injection detected"
                                        );
                                    }
                                    PromptInjectionResult::Error { message } => {
                                        // Already logged in processor, just trace here
                                        trace!(
                                            correlation_id = %ctx.trace_id,
                                            error = %message,
                                            "Prompt injection check error (failure mode applied)"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Geo filtering
        if let Some(route_id) = ctx.route_id.as_deref() {
            if let Some(ref route_config) = ctx.route_config {
                for filter_id in &route_config.filters {
                    if let Some(result) = self.geo_filter_manager.check(filter_id, &ctx.client_ip) {
                        // Store country code for response header
                        ctx.geo_country_code = result.country_code.clone();
                        ctx.geo_lookup_performed = true;

                        if !result.allowed {
                            warn!(
                                correlation_id = %ctx.trace_id,
                                route_id = route_id,
                                client_ip = %ctx.client_ip,
                                country = ?result.country_code,
                                filter_id = %filter_id,
                                "Request blocked by geo filter"
                            );
                            self.metrics.record_blocked_request("geo_blocked");

                            // Audit log the geo block
                            let audit_entry = AuditLogEntry::new(
                                &ctx.trace_id,
                                AuditEventType::Blocked,
                                &ctx.method,
                                &ctx.path,
                                &ctx.client_ip,
                            )
                            .with_route_id(route_id)
                            .with_status_code(result.status_code)
                            .with_reason(format!(
                                "Geo blocked: country={}, filter={}",
                                result.country_code.as_deref().unwrap_or("unknown"),
                                filter_id
                            ));
                            self.log_manager.log_audit(&audit_entry);

                            // Send geo block response
                            let body = result
                                .block_message
                                .unwrap_or_else(|| "Access denied".to_string());

                            crate::http_helpers::write_error(
                                session,
                                result.status_code,
                                &body,
                                "text/plain",
                            )
                            .await?;
                            return Ok(true); // Request complete, don't continue
                        }

                        // Only check first geo filter that matches
                        break;
                    }
                }
            }
        }

        // Route-level filters (CORS preflight, Timeout, Log)
        // Clone the Arc to avoid borrow conflict between &Config and &mut ctx
        let config_for_filters = std::sync::Arc::clone(
            ctx.config
                .get_or_insert_with(|| self.config_manager.current()),
        );
        if super::filters::apply_request_filters(session, ctx, &config_for_filters).await? {
            return Ok(true); // Filter handled request (e.g. CORS preflight)
        }

        // Check for WebSocket upgrade requests
        let is_websocket_upgrade = session
            .req_header()
            .headers
            .get(http::header::UPGRADE)
            .map(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            .unwrap_or(false);

        if is_websocket_upgrade {
            ctx.is_websocket_upgrade = true;

            // Check if route allows WebSocket upgrades
            if let Some(ref route_config) = ctx.route_config {
                if !route_config.websocket {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                        client_ip = %ctx.client_ip,
                        "WebSocket upgrade rejected: not enabled for route"
                    );

                    self.metrics.record_blocked_request("websocket_not_enabled");

                    // Audit log the rejection
                    let audit_entry = AuditLogEntry::new(
                        &ctx.trace_id,
                        AuditEventType::Blocked,
                        &ctx.method,
                        &ctx.path,
                        &ctx.client_ip,
                    )
                    .with_route_id(ctx.route_id.as_deref().unwrap_or("unknown"))
                    .with_action("websocket_rejected")
                    .with_reason("WebSocket not enabled for route");
                    self.log_manager.log_audit(&audit_entry);

                    // Send 403 Forbidden response
                    crate::http_helpers::write_error(
                        session,
                        403,
                        "WebSocket not enabled for this route",
                        "text/plain",
                    )
                    .await?;
                    return Ok(true); // Request complete, don't continue
                }

                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "WebSocket upgrade request allowed"
                );

                // Check for WebSocket frame inspection
                if route_config.websocket_inspection {
                    // Check for compression negotiation - skip inspection if permessage-deflate
                    let has_compression = session
                        .req_header()
                        .headers
                        .get("Sec-WebSocket-Extensions")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.contains("permessage-deflate"))
                        .unwrap_or(false);

                    if has_compression {
                        debug!(
                            correlation_id = %ctx.trace_id,
                            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                            "WebSocket inspection skipped: permessage-deflate negotiated"
                        );
                        ctx.websocket_skip_inspection = true;
                    } else {
                        ctx.websocket_inspection_enabled = true;

                        // Get agents that handle WebSocketFrame events
                        ctx.websocket_inspection_agents = self.agent_manager.get_agents_for_event(
                            zentinel_agent_protocol::EventType::WebSocketFrame,
                        );

                        debug!(
                            correlation_id = %ctx.trace_id,
                            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                            agent_count = ctx.websocket_inspection_agents.len(),
                            "WebSocket frame inspection enabled"
                        );
                    }
                }
            }
        }

        // Use cached route config from upstream_peer (avoids duplicate route matching)
        // Handle static file and builtin routes
        if let Some(route_config) = ctx.route_config.clone() {
            if route_config.service_type == zentinel_config::ServiceType::Static {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "Handling static file route"
                );
                // Create a minimal RouteMatch for the handler
                let route_match = crate::routing::RouteMatch {
                    route_id: zentinel_common::RouteId::new(ctx.route_id.as_deref().unwrap_or("")),
                    config: route_config.clone(),
                };
                return self.handle_static_route(session, ctx, &route_match).await;
            } else if route_config.service_type == zentinel_config::ServiceType::Builtin {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    builtin_handler = ?route_config.builtin_handler,
                    "Handling builtin route"
                );
                // Create a minimal RouteMatch for the handler
                let route_match = crate::routing::RouteMatch {
                    route_id: zentinel_common::RouteId::new(ctx.route_id.as_deref().unwrap_or("")),
                    config: route_config.clone(),
                };
                return self.handle_builtin_route(session, ctx, &route_match).await;
            }
        }

        // API validation for API routes
        if let Some(route_id) = ctx.route_id.clone() {
            if let Some(validator) = self.validators.get(&route_id).await {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_id,
                    "Running API schema validation"
                );
                if let Some(result) = self
                    .validate_api_request(session, ctx, &route_id, &validator)
                    .await?
                {
                    debug!(
                        correlation_id = %ctx.trace_id,
                        route_id = %route_id,
                        validation_passed = result,
                        "API validation complete"
                    );
                    return Ok(result);
                }
            }
        }

        // Get client address before mutable borrow
        let client_addr = session
            .client_addr()
            .map(|a| format!("{}", a))
            .unwrap_or_else(|| "unknown".to_string());
        let client_port = session.client_addr().map(|_| 0).unwrap_or(0);

        let req_header = session.req_header_mut();

        // Add correlation ID header
        req_header
            .insert_header("X-Correlation-Id", &ctx.trace_id)
            .ok();
        req_header.insert_header("X-Forwarded-By", "Zentinel").ok();

        // Use cached config (set in upstream_peer, or fetch now if needed)
        let config = ctx
            .config
            .get_or_insert_with(|| self.config_manager.current());

        // Enforce header limits (fast path: skip if limits are very high)
        const HEADER_LIMIT_THRESHOLD: usize = 1024 * 1024; // 1MB = effectively unlimited

        // Header count check - O(1)
        let header_count = req_header.headers.len();
        if config.limits.max_header_count < HEADER_LIMIT_THRESHOLD
            && header_count > config.limits.max_header_count
        {
            warn!(
                correlation_id = %ctx.trace_id,
                header_count = header_count,
                limit = config.limits.max_header_count,
                "Request blocked: exceeds header count limit"
            );

            self.metrics.record_blocked_request("header_count_exceeded");
            return Err(Error::explain(ErrorType::InternalError, "Too many headers"));
        }

        // Header size check - O(n), skip if limit is very high
        if config.limits.max_header_size_bytes < HEADER_LIMIT_THRESHOLD {
            let total_header_size: usize = req_header
                .headers
                .iter()
                .map(|(k, v)| k.as_str().len() + v.len())
                .sum();

            if total_header_size > config.limits.max_header_size_bytes {
                warn!(
                    correlation_id = %ctx.trace_id,
                    header_size = total_header_size,
                    limit = config.limits.max_header_size_bytes,
                    "Request blocked: exceeds header size limit"
                );

                self.metrics.record_blocked_request("header_size_exceeded");
                return Err(Error::explain(
                    ErrorType::InternalError,
                    "Headers too large",
                ));
            }
        }

        // Process through external agents
        trace!(
            correlation_id = %ctx.trace_id,
            "Processing request through agents"
        );
        if let Err(e) = self
            .process_agents(session, ctx, &client_addr, client_port)
            .await
        {
            // Check if this is an HTTPStatus error (e.g., agent block or fail-closed)
            // In that case, we need to send a proper HTTP response instead of just closing the connection
            if let ErrorType::HTTPStatus(status) = e.etype() {
                // Extract the message from the error (the context part after "HTTPStatus context:")
                let error_msg = e.to_string();
                let body = error_msg
                    .split("context:")
                    .nth(1)
                    .map(|s| s.trim())
                    .unwrap_or("Request blocked");
                debug!(
                    correlation_id = %ctx.trace_id,
                    status = status,
                    body = %body,
                    "Sending HTTP error response for agent block"
                );
                crate::http_helpers::write_error(session, *status, body, "text/plain").await?;
                return Ok(true); // Request complete, don't continue to upstream
            }
            // For other errors, propagate them
            return Err(e);
        }

        trace!(
            correlation_id = %ctx.trace_id,
            "Request filter phase complete, forwarding to upstream"
        );

        Ok(false) // Continue processing
    }

    /// Process incoming request body chunks.
    /// Used for body size enforcement and WAF/agent inspection.
    ///
    /// Supports two modes:
    /// - **Buffer mode** (default): Buffer chunks until end of stream or limit, then send to agents
    /// - **Stream mode**: Send each chunk immediately to agents as it arrives
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        use zentinel_config::BodyStreamingMode;

        // Handle WebSocket frame inspection (client -> server)
        if ctx.is_websocket_upgrade {
            if let Some(ref handler) = ctx.websocket_handler {
                let result = handler.process_client_data(body.take()).await;
                match result {
                    crate::websocket::ProcessResult::Forward(data) => {
                        *body = data;
                    }
                    crate::websocket::ProcessResult::Close(reason) => {
                        warn!(
                            correlation_id = %ctx.trace_id,
                            code = reason.code,
                            reason = %reason.reason,
                            "WebSocket connection closed by agent (client->server)"
                        );
                        // Return an error to close the connection
                        return Err(Error::explain(
                            ErrorType::InternalError,
                            format!("WebSocket closed: {} {}", reason.code, reason.reason),
                        ));
                    }
                }
            }
            // Skip normal body processing for WebSocket
            return Ok(());
        }

        // Track request body size
        let chunk_len = body.as_ref().map(|b| b.len()).unwrap_or(0);
        if chunk_len > 0 {
            ctx.request_body_bytes += chunk_len as u64;

            trace!(
                correlation_id = %ctx.trace_id,
                chunk_size = chunk_len,
                total_body_bytes = ctx.request_body_bytes,
                end_of_stream = end_of_stream,
                streaming_mode = ?ctx.request_body_streaming_mode,
                "Processing request body chunk"
            );

            // Check body size limit (use cached config)
            let config = ctx
                .config
                .get_or_insert_with(|| self.config_manager.current());
            if ctx.request_body_bytes > config.limits.max_body_size_bytes as u64 {
                warn!(
                    correlation_id = %ctx.trace_id,
                    body_bytes = ctx.request_body_bytes,
                    limit = config.limits.max_body_size_bytes,
                    "Request body size limit exceeded"
                );
                self.metrics.record_blocked_request("body_size_exceeded");
                return Err(Error::explain(
                    ErrorType::InternalError,
                    "Request body too large",
                ));
            }
        }

        // Body inspection for agents (WAF, etc.)
        if ctx.body_inspection_enabled && !ctx.body_inspection_agents.is_empty() {
            let config = ctx
                .config
                .get_or_insert_with(|| self.config_manager.current());
            let max_inspection_bytes = config
                .waf
                .as_ref()
                .map(|w| w.body_inspection.max_inspection_bytes as u64)
                .unwrap_or(1024 * 1024);

            match ctx.request_body_streaming_mode {
                BodyStreamingMode::Stream => {
                    // Stream mode: send each chunk immediately
                    if body.is_some() {
                        self.process_body_chunk_streaming(body, end_of_stream, ctx)
                            .await?;
                    } else if end_of_stream && ctx.agent_needs_more {
                        // Send final empty chunk to signal end
                        self.process_body_chunk_streaming(body, end_of_stream, ctx)
                            .await?;
                    }
                }
                BodyStreamingMode::Hybrid { buffer_threshold } => {
                    // Hybrid mode: buffer up to threshold, then stream
                    if ctx.body_bytes_inspected < buffer_threshold as u64 {
                        // Still in buffering phase
                        if let Some(ref chunk) = body {
                            let bytes_to_buffer = std::cmp::min(
                                chunk.len(),
                                (buffer_threshold as u64 - ctx.body_bytes_inspected) as usize,
                            );
                            ctx.body_buffer.extend_from_slice(&chunk[..bytes_to_buffer]);
                            ctx.body_bytes_inspected += bytes_to_buffer as u64;

                            // If we've reached threshold or end of stream, switch to streaming
                            if ctx.body_bytes_inspected >= buffer_threshold as u64 || end_of_stream
                            {
                                // Send buffered content first
                                self.send_buffered_body_to_agents(
                                    end_of_stream && chunk.len() == bytes_to_buffer,
                                    ctx,
                                )
                                .await?;
                                ctx.body_buffer.clear();

                                // If there's remaining data in this chunk, stream it
                                if bytes_to_buffer < chunk.len() {
                                    let remaining = chunk.slice(bytes_to_buffer..);
                                    let mut remaining_body = Some(remaining);
                                    self.process_body_chunk_streaming(
                                        &mut remaining_body,
                                        end_of_stream,
                                        ctx,
                                    )
                                    .await?;
                                }
                            }
                        }
                    } else {
                        // Past threshold, stream directly
                        self.process_body_chunk_streaming(body, end_of_stream, ctx)
                            .await?;
                    }
                }
                BodyStreamingMode::Buffer => {
                    // Buffer mode: collect chunks until ready to send
                    if let Some(ref chunk) = body {
                        if ctx.body_bytes_inspected < max_inspection_bytes {
                            let bytes_to_inspect = std::cmp::min(
                                chunk.len() as u64,
                                max_inspection_bytes - ctx.body_bytes_inspected,
                            ) as usize;

                            ctx.body_buffer
                                .extend_from_slice(&chunk[..bytes_to_inspect]);
                            ctx.body_bytes_inspected += bytes_to_inspect as u64;

                            trace!(
                                correlation_id = %ctx.trace_id,
                                bytes_inspected = ctx.body_bytes_inspected,
                                max_inspection_bytes = max_inspection_bytes,
                                buffer_size = ctx.body_buffer.len(),
                                "Buffering body for agent inspection"
                            );
                        }
                    }

                    // Send when complete or limit reached
                    let should_send =
                        end_of_stream || ctx.body_bytes_inspected >= max_inspection_bytes;
                    if should_send && !ctx.body_buffer.is_empty() {
                        self.send_buffered_body_to_agents(end_of_stream, ctx)
                            .await?;
                        ctx.body_buffer.clear();
                    }
                }
            }
        }

        if end_of_stream {
            trace!(
                correlation_id = %ctx.trace_id,
                total_body_bytes = ctx.request_body_bytes,
                bytes_inspected = ctx.body_bytes_inspected,
                "Request body complete"
            );
        }

        Ok(())
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        let status = upstream_response.status.as_u16();
        let duration = ctx.elapsed();

        trace!(
            correlation_id = %ctx.trace_id,
            status = status,
            "Starting response filter phase"
        );

        // Handle WebSocket 101 Switching Protocols
        if status == 101 && ctx.is_websocket_upgrade {
            if ctx.websocket_inspection_enabled && !ctx.websocket_skip_inspection {
                // Create WebSocket inspector and handler with metrics
                let inspector = crate::websocket::WebSocketInspector::with_metrics(
                    self.agent_manager.clone(),
                    ctx.route_id
                        .clone()
                        .unwrap_or_else(|| "unknown".to_string()),
                    ctx.trace_id.clone(),
                    ctx.client_ip.clone(),
                    100, // 100ms timeout per frame inspection
                    Some(self.metrics.clone()),
                );

                let handler = crate::websocket::WebSocketHandler::new(
                    std::sync::Arc::new(inspector),
                    1024 * 1024, // 1MB max frame size
                );

                ctx.websocket_handler = Some(std::sync::Arc::new(handler));

                info!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    agent_count = ctx.websocket_inspection_agents.len(),
                    "WebSocket upgrade successful, frame inspection enabled"
                );
            } else if ctx.websocket_skip_inspection {
                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "WebSocket upgrade successful, inspection skipped (compression negotiated)"
                );
            } else {
                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "WebSocket upgrade successful"
                );
            }
        }

        // Apply security headers
        trace!(
            correlation_id = %ctx.trace_id,
            "Applying security headers"
        );
        self.apply_security_headers(upstream_response).ok();

        // Add correlation ID to response
        upstream_response.insert_header("X-Correlation-Id", &ctx.trace_id)?;

        // Add rate limit headers if rate limiting was applied
        if let Some(ref rate_info) = ctx.rate_limit_info {
            upstream_response.insert_header("X-RateLimit-Limit", rate_info.limit.to_string())?;
            upstream_response
                .insert_header("X-RateLimit-Remaining", rate_info.remaining.to_string())?;
            upstream_response.insert_header("X-RateLimit-Reset", rate_info.reset_at.to_string())?;
        }

        // Add token budget headers if budget tracking was enabled
        if ctx.inference_budget_enabled {
            if let Some(remaining) = ctx.inference_budget_remaining {
                upstream_response.insert_header("X-Budget-Remaining", remaining.to_string())?;
            }
            if let Some(period_reset) = ctx.inference_budget_period_reset {
                // Format as ISO 8601 timestamp
                let reset_datetime = chrono::DateTime::from_timestamp(period_reset as i64, 0)
                    .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| period_reset.to_string());
                upstream_response.insert_header("X-Budget-Period-Reset", reset_datetime)?;
            }
        }

        // Add GeoIP country header if geo lookup was performed
        if let Some(ref country_code) = ctx.geo_country_code {
            upstream_response.insert_header("X-GeoIP-Country", country_code)?;
        }

        // Apply route-specific response header modifications (policies)
        if let Some(ref route_config) = ctx.route_config {
            let mods = &route_config.policies.response_headers;
            // Rename runs before set/add/remove
            for (old_name, new_name) in &mods.rename {
                if let Some(value) = upstream_response
                    .headers
                    .get(old_name)
                    .and_then(|v| v.to_str().ok())
                {
                    let owned = value.to_string();
                    upstream_response
                        .insert_header(new_name.clone(), &owned)
                        .ok();
                    upstream_response.remove_header(old_name);
                }
            }
            for (name, value) in &mods.set {
                upstream_response
                    .insert_header(name.clone(), value.as_str())
                    .ok();
            }
            for (name, value) in &mods.add {
                upstream_response
                    .append_header(name.clone(), value.as_str())
                    .ok();
            }
            for name in &mods.remove {
                upstream_response.remove_header(name);
            }
        }

        // Inject Cache-Status header (RFC 9211) if enabled
        if let Some(ref cache_status) = ctx.cache_status {
            let status_header_enabled = ctx
                .config
                .as_ref()
                .and_then(|c| c.cache.as_ref())
                .map(|c| c.status_header)
                .unwrap_or(false);

            if status_header_enabled {
                let value = match cache_status {
                    super::context::CacheStatus::Hit => "zentinel; hit",
                    super::context::CacheStatus::HitStale => "zentinel; fwd=stale",
                    super::context::CacheStatus::Miss => "zentinel; fwd=miss",
                    super::context::CacheStatus::Bypass(reason) => {
                        // Leak a static string for the formatted bypass value
                        // This is fine since there are only a few fixed reason strings
                        match *reason {
                            "method" => "zentinel; fwd=bypass; detail=method",
                            "disabled" => "zentinel; fwd=bypass; detail=disabled",
                            "no-route" => "zentinel; fwd=bypass; detail=no-route",
                            _ => "zentinel; fwd=bypass",
                        }
                    }
                };
                upstream_response
                    .insert_header("Cache-Status", value)
                    .ok();
            }
        }

        // Apply response-phase route filters (Headers, CORS, Compress, Log)
        if let Some(config) = ctx.config.as_ref().map(std::sync::Arc::clone) {
            super::filters::apply_response_filters(upstream_response, ctx, &config);
        }

        // Enable Pingora response compression if Compress filter marked it eligible
        if ctx.compress_enabled {
            session.upstream_compression.adjust_level(6);
        }

        // Apply per-listener keepalive timeout
        if let Some(keepalive_secs) = ctx.listener_keepalive_timeout_secs {
            session
                .downstream_session
                .set_keepalive(Some(keepalive_secs));
        }

        // Add sticky session cookie if a new assignment was made
        if ctx.sticky_session_new_assignment {
            if let Some(ref set_cookie_header) = ctx.sticky_session_set_cookie {
                upstream_response.insert_header("Set-Cookie", set_cookie_header)?;
                trace!(
                    correlation_id = %ctx.trace_id,
                    sticky_target_index = ?ctx.sticky_target_index,
                    "Added sticky session Set-Cookie header"
                );
            }
        }

        // Add guardrail warning header if prompt injection was detected (warn mode)
        if ctx.guardrail_warning {
            upstream_response.insert_header("X-Guardrail-Warning", "prompt-injection-detected")?;
        }

        // Add fallback routing headers if fallback was used
        if ctx.used_fallback() {
            upstream_response.insert_header("X-Fallback-Used", "true")?;

            if let Some(ref upstream) = ctx.upstream {
                upstream_response.insert_header("X-Fallback-Upstream", upstream)?;
            }

            if let Some(ref reason) = ctx.fallback_reason {
                upstream_response.insert_header("X-Fallback-Reason", reason.to_string())?;
            }

            if let Some(ref original) = ctx.original_upstream {
                upstream_response.insert_header("X-Original-Upstream", original)?;
            }

            if let Some(ref mapping) = ctx.model_mapping_applied {
                upstream_response
                    .insert_header("X-Model-Mapping", format!("{} -> {}", mapping.0, mapping.1))?;
            }

            trace!(
                correlation_id = %ctx.trace_id,
                fallback_attempt = ctx.fallback_attempt,
                fallback_upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
                original_upstream = ctx.original_upstream.as_deref().unwrap_or("unknown"),
                "Added fallback response headers"
            );

            // Record fallback success metrics for successful responses (2xx/3xx)
            if status < 400 {
                if let Some(metrics) = get_fallback_metrics() {
                    metrics.record_fallback_success(
                        ctx.route_id.as_deref().unwrap_or("unknown"),
                        ctx.upstream.as_deref().unwrap_or("unknown"),
                    );
                }
            }
        }

        // Initialize streaming token counter for SSE responses on inference routes
        if ctx.inference_rate_limit_enabled {
            // Check if this is an SSE response
            let content_type = upstream_response
                .headers
                .get("content-type")
                .and_then(|ct| ct.to_str().ok());

            if is_sse_response(content_type) {
                // Get provider from route config
                let provider = ctx
                    .route_config
                    .as_ref()
                    .and_then(|r| r.inference.as_ref())
                    .map(|i| i.provider)
                    .unwrap_or_default();

                ctx.inference_streaming_response = true;
                ctx.inference_streaming_counter = Some(StreamingTokenCounter::new(
                    provider,
                    ctx.inference_model.clone(),
                ));

                trace!(
                    correlation_id = %ctx.trace_id,
                    content_type = ?content_type,
                    model = ?ctx.inference_model,
                    "Initialized streaming token counter for SSE response"
                );
            }
        }

        // Generate custom error pages for error responses
        if status >= 400 {
            trace!(
                correlation_id = %ctx.trace_id,
                status = status,
                "Handling error response"
            );
            self.handle_error_response(upstream_response, ctx).await?;
        }

        // Record metrics
        self.metrics.record_request(
            ctx.route_id.as_deref().unwrap_or("unknown"),
            &ctx.method,
            status,
            duration,
        );

        // Record OpenTelemetry span status
        if let Some(ref mut span) = ctx.otel_span {
            span.set_status(status);
            if let Some(ref upstream) = ctx.upstream {
                span.set_upstream(upstream, "");
            }
            if status >= 500 {
                span.record_error(&format!("HTTP {}", status));
            }
        }

        // Record passive health check
        if let Some(ref upstream) = ctx.upstream {
            let success = status < 500;

            trace!(
                correlation_id = %ctx.trace_id,
                upstream = %upstream,
                success = success,
                status = status,
                "Recording passive health check result"
            );

            let error_msg = if !success {
                Some(format!("HTTP {}", status))
            } else {
                None
            };
            self.passive_health
                .record_outcome(upstream, success, error_msg.as_deref())
                .await;

            // Report to upstream pool
            if let Some(pool) = self.upstream_pools.get(upstream).await {
                pool.report_result(upstream, success).await;
            }

            if !success {
                warn!(
                    correlation_id = %ctx.trace_id,
                    upstream = %upstream,
                    status = status,
                    "Upstream returned error status"
                );
            }
        }

        // Final request completion log
        if status >= 500 {
            error!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                upstream = ctx.upstream.as_deref().unwrap_or("none"),
                method = %ctx.method,
                path = %ctx.path,
                status = status,
                duration_ms = duration.as_millis(),
                attempts = ctx.upstream_attempts,
                "Request completed with server error"
            );
        } else if status >= 400 {
            warn!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                upstream = ctx.upstream.as_deref().unwrap_or("none"),
                method = %ctx.method,
                path = %ctx.path,
                status = status,
                duration_ms = duration.as_millis(),
                "Request completed with client error"
            );
        } else {
            debug!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                upstream = ctx.upstream.as_deref().unwrap_or("none"),
                method = %ctx.method,
                path = %ctx.path,
                status = status,
                duration_ms = duration.as_millis(),
                attempts = ctx.upstream_attempts,
                "Request completed"
            );
        }

        Ok(())
    }

    /// Modify the request before sending to upstream.
    /// Used for header modifications, adding authentication, etc.
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut pingora::http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        trace!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            "Applying upstream request modifications"
        );

        // Add trace ID header for upstream correlation
        upstream_request
            .insert_header("X-Trace-Id", &ctx.trace_id)
            .ok();

        // Add W3C traceparent header for distributed tracing
        if let Some(ref span) = ctx.otel_span {
            let sampled = ctx
                .trace_context
                .as_ref()
                .map(|c| c.sampled)
                .unwrap_or(true);
            let traceparent =
                crate::otel::create_traceparent(&span.trace_id, &span.span_id, sampled);
            upstream_request
                .insert_header(crate::otel::TRACEPARENT_HEADER, &traceparent)
                .ok();
        }

        // Add request metadata headers
        upstream_request
            .insert_header("X-Forwarded-By", "Zentinel")
            .ok();

        // Apply route-specific request header modifications
        // Note: Pingora's IntoCaseHeaderName requires owned String for header names,
        // so we clone names but pass values by reference to avoid cloning both.
        if let Some(ref route_config) = ctx.route_config {
            let mods = &route_config.policies.request_headers;

            // Rename runs before set/add/remove
            for (old_name, new_name) in &mods.rename {
                if let Some(value) = upstream_request
                    .headers
                    .get(old_name)
                    .and_then(|v| v.to_str().ok())
                {
                    let owned = value.to_string();
                    upstream_request
                        .insert_header(new_name.clone(), &owned)
                        .ok();
                    upstream_request.remove_header(old_name);
                }
            }

            // Set headers (overwrite existing)
            for (name, value) in &mods.set {
                upstream_request
                    .insert_header(name.clone(), value.as_str())
                    .ok();
            }

            // Add headers (append)
            for (name, value) in &mods.add {
                upstream_request
                    .append_header(name.clone(), value.as_str())
                    .ok();
            }

            // Remove headers
            for name in &mods.remove {
                upstream_request.remove_header(name);
            }

            trace!(
                correlation_id = %ctx.trace_id,
                "Applied request header modifications"
            );
        }

        // Apply request-phase Headers filters
        if let Some(ref config) = ctx.config {
            super::filters::apply_request_headers_filters(upstream_request, ctx, config);
        }

        // Remove sensitive headers that shouldn't go to upstream
        upstream_request.remove_header("X-Internal-Token");
        upstream_request.remove_header("Authorization-Internal");

        // === Traffic Mirroring / Shadowing ===
        // Check if this route has shadow configuration
        if let Some(ref route_config) = ctx.route_config {
            if let Some(ref shadow_config) = route_config.shadow {
                // Get snapshot of upstream pools for shadow manager
                let pools_snapshot = self.upstream_pools.snapshot().await;
                let upstream_pools = std::sync::Arc::new(pools_snapshot);

                // Get route ID for metrics labeling
                let route_id = ctx
                    .route_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());

                // Create shadow manager
                let shadow_manager = crate::shadow::ShadowManager::new(
                    upstream_pools,
                    shadow_config.clone(),
                    Some(std::sync::Arc::clone(&self.metrics)),
                    route_id,
                );

                // Check if we should shadow this request (sampling + header check)
                if shadow_manager.should_shadow(upstream_request) {
                    trace!(
                        correlation_id = %ctx.trace_id,
                        shadow_upstream = %shadow_config.upstream,
                        percentage = shadow_config.percentage,
                        "Shadowing request"
                    );

                    // Clone headers for shadow request
                    let shadow_headers = upstream_request.clone();

                    // Create request context for shadow (simplified from proxy context)
                    let shadow_ctx = crate::upstream::RequestContext {
                        client_ip: ctx.client_ip.parse().ok(),
                        headers: std::collections::HashMap::new(), // Empty for now
                        path: ctx.path.clone(),
                        method: ctx.method.clone(),
                    };

                    // Determine if we should buffer the body
                    let buffer_body = shadow_config.buffer_body
                        && crate::shadow::should_buffer_method(&ctx.method);

                    if buffer_body {
                        // Body buffering requested - defer shadow request until body is available
                        // Store shadow info in context; will be fired in logging phase
                        // or when request body filter completes
                        trace!(
                            correlation_id = %ctx.trace_id,
                            "Deferring shadow request until body is buffered"
                        );
                        ctx.shadow_pending = Some(crate::proxy::context::ShadowPendingRequest {
                            headers: shadow_headers,
                            manager: std::sync::Arc::new(shadow_manager),
                            request_ctx: shadow_ctx,
                            include_body: true,
                        });
                        // Enable body inspection to capture the body for shadow
                        // (only if not already enabled for other reasons)
                        if !ctx.body_inspection_enabled {
                            ctx.body_inspection_enabled = true;
                            // Set a reasonable buffer limit from shadow config
                            // (body_buffer will accumulate chunks)
                        }
                    } else {
                        // No body buffering needed - fire shadow request immediately
                        shadow_manager.shadow_request(shadow_headers, None, shadow_ctx);
                        ctx.shadow_sent = true;
                    }
                }
            }
        }

        Ok(())
    }

    /// Process response body chunks from upstream.
    /// Used for response size tracking and WAF inspection.
    ///
    /// Note: Response body inspection is currently buffered only (streaming mode not supported
    /// for responses due to Pingora's synchronous filter design).
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>, Box<Error>> {
        // Handle WebSocket frame inspection (server -> client)
        // Note: This filter is synchronous, so we use block_in_place for async agent calls
        if ctx.is_websocket_upgrade {
            if let Some(ref handler) = ctx.websocket_handler {
                let handler = handler.clone();
                let data = body.take();

                // Use block_in_place to run async handler from sync context
                // This is safe because Pingora uses a multi-threaded tokio runtime
                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(async { handler.process_server_data(data).await })
                });

                match result {
                    crate::websocket::ProcessResult::Forward(data) => {
                        *body = data;
                    }
                    crate::websocket::ProcessResult::Close(reason) => {
                        warn!(
                            correlation_id = %ctx.trace_id,
                            code = reason.code,
                            reason = %reason.reason,
                            "WebSocket connection closed by agent (server->client)"
                        );
                        // For sync filter, we can't return an error that closes the connection
                        // Instead, inject a close frame
                        let close_frame =
                            crate::websocket::WebSocketFrame::close(reason.code, &reason.reason);
                        let codec = crate::websocket::WebSocketCodec::new(1024 * 1024);
                        if let Ok(encoded) = codec.encode_frame(&close_frame, false) {
                            *body = Some(Bytes::from(encoded));
                        }
                    }
                }
            }
            // Skip normal body processing for WebSocket
            return Ok(None);
        }

        // Track response body size
        if let Some(ref chunk) = body {
            ctx.response_bytes += chunk.len() as u64;

            trace!(
                correlation_id = %ctx.trace_id,
                chunk_size = chunk.len(),
                total_response_bytes = ctx.response_bytes,
                end_of_stream = end_of_stream,
                "Processing response body chunk"
            );

            // Process SSE chunks for streaming token counting
            if let Some(ref mut counter) = ctx.inference_streaming_counter {
                let result = counter.process_chunk(chunk);

                if result.content.is_some() || result.is_done {
                    trace!(
                        correlation_id = %ctx.trace_id,
                        has_content = result.content.is_some(),
                        is_done = result.is_done,
                        chunks_processed = counter.chunks_processed(),
                        accumulated_content_len = counter.content().len(),
                        "Processed SSE chunk for token counting"
                    );
                }
            }

            // Response body inspection (buffered mode only)
            // Note: Streaming mode for response bodies is not currently supported
            // due to Pingora's synchronous response_body_filter design
            if ctx.response_body_inspection_enabled
                && !ctx.response_body_inspection_agents.is_empty()
            {
                let config = ctx
                    .config
                    .get_or_insert_with(|| self.config_manager.current());
                let max_inspection_bytes = config
                    .waf
                    .as_ref()
                    .map(|w| w.body_inspection.max_inspection_bytes as u64)
                    .unwrap_or(1024 * 1024);

                if ctx.response_body_bytes_inspected < max_inspection_bytes {
                    let bytes_to_inspect = std::cmp::min(
                        chunk.len() as u64,
                        max_inspection_bytes - ctx.response_body_bytes_inspected,
                    ) as usize;

                    // Buffer for later processing (during logging phase)
                    // Response body inspection happens asynchronously and results
                    // are logged rather than blocking the response
                    ctx.response_body_bytes_inspected += bytes_to_inspect as u64;
                    ctx.response_body_chunk_index += 1;

                    trace!(
                        correlation_id = %ctx.trace_id,
                        bytes_inspected = ctx.response_body_bytes_inspected,
                        max_inspection_bytes = max_inspection_bytes,
                        chunk_index = ctx.response_body_chunk_index,
                        "Tracking response body for inspection"
                    );
                }
            }
        }

        if end_of_stream {
            trace!(
                correlation_id = %ctx.trace_id,
                total_response_bytes = ctx.response_bytes,
                response_bytes_inspected = ctx.response_body_bytes_inspected,
                "Response body complete"
            );
        }

        // Return None to indicate no delay needed
        Ok(None)
    }

    /// Called when a connection to upstream is established or reused.
    /// Logs connection reuse statistics for observability.
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        #[cfg(unix)] _fd: RawFd,
        #[cfg(windows)] _sock: std::os::windows::io::RawSocket,
        digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Track connection reuse for metrics
        ctx.connection_reused = reused;

        // Log connection establishment/reuse
        if reused {
            trace!(
                correlation_id = %ctx.trace_id,
                upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
                peer_address = %peer.address(),
                "Reusing existing upstream connection"
            );
        } else {
            debug!(
                correlation_id = %ctx.trace_id,
                upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
                peer_address = %peer.address(),
                ssl = digest.as_ref().map(|d| d.ssl_digest.is_some()).unwrap_or(false),
                "Established new upstream connection"
            );
        }

        Ok(())
    }

    // =========================================================================
    // HTTP Caching - Pingora Cache Integration
    // =========================================================================

    /// Decide if the request should use caching.
    ///
    /// This method is called early in the request lifecycle to determine if
    /// the response should be served from cache or if the response should
    /// be cached.
    fn request_cache_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<()> {
        // Check if route has caching enabled
        let route_id = match ctx.route_id.as_deref() {
            Some(id) => id,
            None => {
                trace!(
                    correlation_id = %ctx.trace_id,
                    "Cache filter: no route ID, skipping cache"
                );
                return Ok(());
            }
        };

        // Check if caching is enabled for this route
        if !self.cache_manager.is_enabled(route_id) {
            ctx.cache_status = Some(super::context::CacheStatus::Bypass("disabled"));
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                "Cache disabled for route"
            );
            return Ok(());
        }

        // Check if method is cacheable (typically GET/HEAD)
        if !self
            .cache_manager
            .is_method_cacheable(route_id, &ctx.method)
        {
            ctx.cache_status = Some(super::context::CacheStatus::Bypass("method"));
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                method = %ctx.method,
                "Method not cacheable"
            );
            return Ok(());
        }

        // Enable caching for this request using Pingora's cache infrastructure
        debug!(
            correlation_id = %ctx.trace_id,
            route_id = %route_id,
            method = %ctx.method,
            path = %ctx.path,
            "Enabling HTTP caching for request"
        );

        // Get static references to cache infrastructure
        let storage = get_cache_storage();
        let eviction = get_cache_eviction();
        let cache_lock = get_cache_lock();

        // Enable the cache with storage, eviction, and lock
        session.cache.enable(
            storage,
            Some(eviction),
            None, // predictor - optional
            Some(cache_lock),
            None, // option overrides
        );

        // Mark request as cache-eligible in context
        ctx.cache_eligible = true;

        trace!(
            correlation_id = %ctx.trace_id,
            route_id = %route_id,
            cache_enabled = session.cache.enabled(),
            "Cache enabled for request"
        );

        Ok(())
    }

    /// Generate the cache key for this request.
    ///
    /// The cache key uniquely identifies the cached response. It typically
    /// includes the method, host, path, and potentially query parameters.
    fn cache_key_callback(&self, session: &Session, ctx: &mut Self::CTX) -> Result<CacheKey> {
        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let path = req_header.uri.path();
        let host = ctx.host.as_deref().unwrap_or("unknown");
        let query = req_header.uri.query();

        // Generate cache key using our cache manager
        let key_string = crate::cache::CacheManager::generate_cache_key(method, host, path, query);

        trace!(
            correlation_id = %ctx.trace_id,
            cache_key = %key_string,
            "Generated cache key"
        );

        // Use Pingora's default cache key generator which handles
        // proper hashing and internal format
        Ok(CacheKey::default(req_header))
    }

    /// Called when a cache miss occurs.
    ///
    /// This is called when the cache lookup found no matching entry.
    /// We can use this to log and track cache misses.
    fn cache_miss(&self, session: &mut Session, ctx: &mut Self::CTX) {
        // Let Pingora handle the cache miss
        session.cache.cache_miss();

        ctx.cache_status = Some(super::context::CacheStatus::Miss);

        // Track statistics
        if let Some(route_id) = ctx.route_id.as_deref() {
            self.cache_manager.stats().record_miss();

            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                path = %ctx.path,
                "Cache miss"
            );
        }
    }

    /// Called after a successful cache lookup.
    ///
    /// This filter allows inspecting the cached response before serving it.
    /// Returns `None` to serve the cached response, or a `ForcedFreshness`
    /// to override the freshness decision.
    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedFreshness>>
    where
        Self::CTX: Send + Sync,
    {
        // Check if this cache entry should be invalidated due to a purge request
        let req_header = session.req_header();
        let method = req_header.method.as_str();
        let path = req_header.uri.path();
        let host = req_header.uri.host().unwrap_or("localhost");
        let query = req_header.uri.query();

        // Generate the cache key for this request
        let cache_key = crate::cache::CacheManager::generate_cache_key(method, host, path, query);

        // Check if this key should be invalidated
        if self.cache_manager.should_invalidate(&cache_key) {
            info!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                cache_key = %cache_key,
                "Cache entry invalidated by purge request"
            );
            // Force expiration so the entry is refetched from upstream
            return Ok(Some(ForcedFreshness::ForceExpired));
        }

        // Track cache hit statistics
        if is_fresh {
            ctx.cache_status = Some(super::context::CacheStatus::Hit);
            self.cache_manager.stats().record_hit();

            debug!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                is_fresh = is_fresh,
                "Cache hit (fresh)"
            );
        } else {
            ctx.cache_status = Some(super::context::CacheStatus::HitStale);

            trace!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                is_fresh = is_fresh,
                "Cache hit (stale)"
            );
        }

        // Serve the cached response without invalidation
        Ok(None)
    }

    /// Decide if the response should be cached.
    ///
    /// Called after receiving the response from upstream to determine
    /// if it should be stored in the cache.
    fn response_cache_filter(
        &self,
        _session: &Session,
        resp: &ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<RespCacheable> {
        let route_id = match ctx.route_id.as_deref() {
            Some(id) => id,
            None => {
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                    "no_route",
                )));
            }
        };

        // Check if caching is enabled for this route
        if !self.cache_manager.is_enabled(route_id) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom(
                "disabled",
            )));
        }

        let status = resp.status.as_u16();

        // Check if status code is cacheable
        if !self.cache_manager.is_status_cacheable(route_id, status) {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                status = status,
                "Status code not cacheable"
            );
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        // Check Cache-Control header for no-store, no-cache, private
        if let Some(cache_control) = resp.headers.get("cache-control") {
            if let Ok(cc_str) = cache_control.to_str() {
                if crate::cache::CacheManager::is_no_cache(cc_str) {
                    trace!(
                        correlation_id = %ctx.trace_id,
                        route_id = %route_id,
                        cache_control = %cc_str,
                        "Response has no-cache directive"
                    );
                    return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
                }
            }
        }

        // Calculate TTL from Cache-Control or use default
        let cache_control = resp
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok());
        let ttl = self.cache_manager.calculate_ttl(route_id, cache_control);

        if ttl.is_zero() {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                "TTL is zero, not caching"
            );
            return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
        }

        // Get route cache config for stale settings
        let config = self
            .cache_manager
            .get_route_config(route_id)
            .unwrap_or_default();

        // Create timestamps for cache metadata
        let now = std::time::SystemTime::now();
        let fresh_until = now + ttl;

        // Clone the response header for storage
        let header = resp.clone();

        // Create CacheMeta with proper timestamps and TTLs
        let cache_meta = CacheMeta::new(
            fresh_until,
            now,
            config.stale_while_revalidate_secs as u32,
            config.stale_if_error_secs as u32,
            header,
        );

        // Track the cache store
        self.cache_manager.stats().record_store();

        debug!(
            correlation_id = %ctx.trace_id,
            route_id = %route_id,
            status = status,
            ttl_secs = ttl.as_secs(),
            stale_while_revalidate_secs = config.stale_while_revalidate_secs,
            stale_if_error_secs = config.stale_if_error_secs,
            "Caching response"
        );

        Ok(RespCacheable::Cacheable(cache_meta))
    }

    /// Decide whether to serve stale content on error or during revalidation.
    ///
    /// This implements stale-while-revalidate and stale-if-error semantics.
    fn should_serve_stale(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
        error: Option<&Error>,
    ) -> bool {
        let route_id = match ctx.route_id.as_deref() {
            Some(id) => id,
            None => return false,
        };

        // Get route cache config for stale settings
        let config = match self.cache_manager.get_route_config(route_id) {
            Some(c) => c,
            None => return false,
        };

        // If there's an upstream error, use stale-if-error
        if let Some(e) = error {
            // Only serve stale for upstream errors
            if e.esource() == &pingora::ErrorSource::Upstream {
                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_id,
                    error = %e,
                    stale_if_error_secs = config.stale_if_error_secs,
                    "Considering stale-if-error"
                );
                return config.stale_if_error_secs > 0;
            }
        }

        // During stale-while-revalidate (error is None)
        if error.is_none() && config.stale_while_revalidate_secs > 0 {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                stale_while_revalidate_secs = config.stale_while_revalidate_secs,
                "Allowing stale-while-revalidate"
            );
            return true;
        }

        false
    }

    /// Handle Range header for byte-range requests (streaming support).
    ///
    /// This method is called when a Range header is present in the request.
    /// It allows proper handling of:
    /// - Video streaming (HTML5 video seeking)
    /// - Large file downloads with resume support
    /// - Partial content delivery
    ///
    /// Uses Pingora's built-in range handling with route-specific logging.
    fn range_header_filter(
        &self,
        session: &mut Session,
        response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::RangeType
    where
        Self::CTX: Send + Sync,
    {
        // Check if route supports range requests
        let supports_range = ctx.route_config.as_ref().is_none_or(|config| {
            // Static file routes and media routes should support range requests
            matches!(
                config.service_type,
                zentinel_config::ServiceType::Static | zentinel_config::ServiceType::Web
            )
        });

        if !supports_range {
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                "Range request not supported for this route type"
            );
            return pingora_proxy::RangeType::None;
        }

        // Use Pingora's built-in range header parsing and handling
        let range_type = pingora_proxy::range_header_filter(session.req_header(), response, None);

        match &range_type {
            pingora_proxy::RangeType::None => {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "No range request or not applicable"
                );
            }
            pingora_proxy::RangeType::Single(range) => {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    range_start = range.start,
                    range_end = range.end,
                    "Processing single-range request"
                );
            }
            pingora_proxy::RangeType::Multi(multi) => {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    range_count = multi.ranges.len(),
                    "Processing multi-range request"
                );
            }
            pingora_proxy::RangeType::Invalid => {
                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "Invalid range header"
                );
            }
        }

        range_type
    }

    /// Handle fatal proxy errors by generating custom error pages.
    /// Called when the proxy itself fails to process the request.
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let error_code = match e.etype() {
            // Connection errors
            ErrorType::ConnectRefused => 503,
            ErrorType::ConnectTimedout => 504,
            ErrorType::ConnectNoRoute => 502,

            // Timeout errors
            ErrorType::ReadTimedout => 504,
            ErrorType::WriteTimedout => 504,

            // TLS errors
            ErrorType::TLSHandshakeFailure => 502,
            ErrorType::InvalidCert => 502,

            // Protocol errors
            ErrorType::InvalidHTTPHeader => 400,
            ErrorType::H2Error => 502,

            // Resource errors
            ErrorType::ConnectProxyFailure => 502,
            ErrorType::ConnectionClosed => 502,

            // Explicit HTTP status (e.g., from agent fail-closed blocking)
            ErrorType::HTTPStatus(status) => *status,

            // Internal errors - return 502 for upstream issues (more accurate than 500)
            ErrorType::InternalError => {
                // Check if this is an upstream-related error
                let error_str = e.to_string();
                if error_str.contains("upstream")
                    || error_str.contains("DNS")
                    || error_str.contains("resolve")
                {
                    502
                } else {
                    500
                }
            }

            // Default to 502 for unknown errors
            _ => 502,
        };

        error!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
            error_type = ?e.etype(),
            error = %e,
            error_code = error_code,
            "Proxy error occurred"
        );

        // Record the error in metrics
        self.metrics
            .record_blocked_request(&format!("proxy_error_{}", error_code));

        // Write error response to ensure client receives a proper HTTP response
        // This is necessary because some errors occur before the upstream connection
        // is established, and Pingora may not send a response automatically
        let error_message = match error_code {
            400 => "Bad Request",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Internal Server Error",
        };

        // Build a minimal error response body
        let body = format!(
            r#"{{"error":"{} {}","trace_id":"{}"}}"#,
            error_code, error_message, ctx.trace_id
        );

        // Write the response header
        let mut header = pingora::http::ResponseHeader::build(error_code, None).unwrap();
        header
            .insert_header("Content-Type", "application/json")
            .ok();
        header
            .insert_header("Content-Length", body.len().to_string())
            .ok();
        header
            .insert_header("X-Correlation-Id", ctx.trace_id.as_str())
            .ok();
        header.insert_header("Connection", "close").ok();

        // Write headers and body
        if let Err(write_err) = session.write_response_header(Box::new(header), false).await {
            warn!(
                correlation_id = %ctx.trace_id,
                error = %write_err,
                "Failed to write error response header"
            );
        } else {
            // Write the body
            if let Err(write_err) = session
                .write_response_body(Some(bytes::Bytes::from(body)), true)
                .await
            {
                warn!(
                    correlation_id = %ctx.trace_id,
                    error = %write_err,
                    "Failed to write error response body"
                );
            }
        }

        // Return the error response info
        // can_reuse_downstream: false since we already wrote and closed the response
        pingora_proxy::FailToProxy {
            error_code,
            can_reuse_downstream: false,
        }
    }

    /// Handle errors that occur during proxying after upstream connection is established.
    ///
    /// This method enables retry logic and circuit breaker integration.
    /// It's called when an error occurs during the request/response exchange
    /// with the upstream server.
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Self::CTX,
        client_reused: bool,
    ) -> Box<Error> {
        let error_type = e.etype().clone();
        let upstream_id = ctx.upstream.as_deref().unwrap_or("unknown");

        // Classify error for retry decisions
        let is_retryable = matches!(
            error_type,
            ErrorType::ConnectTimedout
                | ErrorType::ReadTimedout
                | ErrorType::WriteTimedout
                | ErrorType::ConnectionClosed
                | ErrorType::ConnectRefused
        );

        // Log the error with context
        warn!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            upstream = %upstream_id,
            peer_address = %peer.address(),
            error_type = ?error_type,
            error = %e,
            client_reused = client_reused,
            is_retryable = is_retryable,
            "Error during proxy operation"
        );

        // Record failure with circuit breaker via upstream pool
        // This is done asynchronously since we can't await in a sync fn
        let peer_address = peer.address().to_string();
        let upstream_pools = self.upstream_pools.clone();
        let upstream_id_owned = upstream_id.to_string();
        tokio::spawn(async move {
            if let Some(pool) = upstream_pools.get(&upstream_id_owned).await {
                pool.report_result(&peer_address, false).await;
            }
        });

        // Metrics tracking
        self.metrics
            .record_blocked_request(&format!("proxy_error_{:?}", error_type));

        // Create enhanced error with retry information
        let mut enhanced_error = e.more_context(format!(
            "Upstream: {}, Peer: {}, Attempts: {}",
            upstream_id,
            peer.address(),
            ctx.upstream_attempts
        ));

        // Determine if retry should be attempted:
        // - Only retry if error is retryable type
        // - Only retry reused connections if buffer isn't truncated
        // - Track retry metrics
        if is_retryable {
            let can_retry = if client_reused {
                // For reused connections, check if retry buffer is intact
                !session.as_ref().retry_buffer_truncated()
            } else {
                // Fresh connections can always retry
                true
            };

            enhanced_error.retry.decide_reuse(can_retry);

            if can_retry {
                debug!(
                    correlation_id = %ctx.trace_id,
                    upstream = %upstream_id,
                    error_type = ?error_type,
                    "Error is retryable, will attempt retry"
                );
            }
        } else {
            // Non-retryable error - don't retry
            enhanced_error.retry.decide_reuse(false);
        }

        enhanced_error
    }

    async fn logging(&self, session: &mut Session, _error: Option<&Error>, ctx: &mut Self::CTX) {
        // Decrement active requests
        self.reload_coordinator.dec_requests();

        // === Fire pending shadow request (if body buffering was enabled) ===
        if !ctx.shadow_sent {
            if let Some(shadow_pending) = ctx.shadow_pending.take() {
                let body = if shadow_pending.include_body && !ctx.body_buffer.is_empty() {
                    // Clone the buffered body for the shadow request
                    Some(ctx.body_buffer.clone())
                } else {
                    None
                };

                trace!(
                    correlation_id = %ctx.trace_id,
                    body_size = body.as_ref().map(|b| b.len()).unwrap_or(0),
                    "Firing deferred shadow request with buffered body"
                );

                shadow_pending.manager.shadow_request(
                    shadow_pending.headers,
                    body,
                    shadow_pending.request_ctx,
                );
                ctx.shadow_sent = true;
            }
        }

        let duration = ctx.elapsed();

        // Get response status
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        // Report result to load balancer for adaptive LB feedback
        // This enables latency-aware weight adjustment
        if let (Some(ref peer_addr), Some(ref upstream_id)) =
            (&ctx.selected_upstream_address, &ctx.upstream)
        {
            // Success = status code < 500 (client errors are not upstream failures)
            let success = status > 0 && status < 500;

            if let Some(pool) = self.upstream_pools.get(upstream_id).await {
                pool.report_result_with_latency(peer_addr, success, Some(duration))
                    .await;
                trace!(
                    correlation_id = %ctx.trace_id,
                    upstream = %upstream_id,
                    peer_address = %peer_addr,
                    success = success,
                    duration_ms = duration.as_millis(),
                    status = status,
                    "Reported result to adaptive load balancer"
                );
            }

            // Track warmth for inference routes (cold model detection)
            if ctx.inference_rate_limit_enabled && success {
                let cold_detected = self.warmth_tracker.record_request(peer_addr, duration);
                if cold_detected {
                    debug!(
                        correlation_id = %ctx.trace_id,
                        upstream = %upstream_id,
                        peer_address = %peer_addr,
                        duration_ms = duration.as_millis(),
                        "Cold model detected on inference upstream"
                    );
                }
            }
        }

        // Record actual token usage for inference rate limiting
        // This adjusts the token bucket based on actual vs estimated tokens
        if ctx.inference_rate_limit_enabled {
            if let (Some(route_id), Some(ref rate_limit_key)) =
                (ctx.route_id.as_deref(), &ctx.inference_rate_limit_key)
            {
                // Try to extract actual tokens from response headers
                let response_headers = session
                    .response_written()
                    .map(|r| &r.headers)
                    .cloned()
                    .unwrap_or_default();

                // For streaming responses, finalize the streaming token counter
                let streaming_result = if ctx.inference_streaming_response {
                    ctx.inference_streaming_counter
                        .as_ref()
                        .map(|counter| counter.finalize())
                } else {
                    None
                };

                // Log streaming token count info
                if let Some(ref result) = streaming_result {
                    debug!(
                        correlation_id = %ctx.trace_id,
                        output_tokens = result.output_tokens,
                        input_tokens = ?result.input_tokens,
                        source = ?result.source,
                        content_length = result.content_length,
                        "Finalized streaming token count"
                    );
                }

                // PII detection guardrail (for streaming inference responses)
                if ctx.inference_streaming_response {
                    if let Some(ref route_config) = ctx.route_config {
                        if let Some(ref inference) = route_config.inference {
                            if let Some(ref guardrails) = inference.guardrails {
                                if let Some(ref pii_config) = guardrails.pii_detection {
                                    if pii_config.enabled {
                                        // Get accumulated content from streaming counter
                                        if let Some(ref counter) = ctx.inference_streaming_counter {
                                            let response_content = counter.content();
                                            if !response_content.is_empty() {
                                                let pii_result = self
                                                    .guardrail_processor
                                                    .check_pii(
                                                        pii_config,
                                                        response_content,
                                                        ctx.route_id.as_deref(),
                                                        &ctx.trace_id,
                                                    )
                                                    .await;

                                                match pii_result {
                                                    crate::inference::PiiCheckResult::Detected {
                                                        detections,
                                                        redacted_content: _,
                                                    } => {
                                                        warn!(
                                                            correlation_id = %ctx.trace_id,
                                                            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                                                            detection_count = detections.len(),
                                                            "PII detected in inference response"
                                                        );

                                                        // Store detection categories for logging
                                                        ctx.pii_detection_categories = detections
                                                            .iter()
                                                            .map(|d| d.category.clone())
                                                            .collect();

                                                        // Record metrics for each category
                                                        for detection in &detections {
                                                            self.metrics.record_pii_detected(
                                                                ctx.route_id.as_deref().unwrap_or("unknown"),
                                                                &detection.category,
                                                            );
                                                        }
                                                    }
                                                    crate::inference::PiiCheckResult::Clean => {
                                                        trace!(
                                                            correlation_id = %ctx.trace_id,
                                                            "No PII detected in response"
                                                        );
                                                    }
                                                    crate::inference::PiiCheckResult::Error { message } => {
                                                        debug!(
                                                            correlation_id = %ctx.trace_id,
                                                            error = %message,
                                                            "PII detection check failed"
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Response body would require buffering, which is expensive
                // For non-streaming, most LLM APIs provide token counts in headers
                // For streaming, we use the accumulated SSE content
                let empty_body: &[u8] = &[];

                if let Some(actual_estimate) = self.inference_rate_limit_manager.record_actual(
                    route_id,
                    rate_limit_key,
                    &response_headers,
                    empty_body,
                    ctx.inference_estimated_tokens,
                ) {
                    // Use streaming result if available and header extraction failed
                    let (actual_tokens, source_info) = if let Some(ref streaming) = streaming_result
                    {
                        // Prefer API-provided counts from streaming, otherwise use tiktoken count
                        if streaming.total_tokens.is_some() {
                            (streaming.total_tokens.unwrap(), "streaming_api")
                        } else if actual_estimate.source == crate::inference::TokenSource::Estimated
                        {
                            // Header extraction failed, use streaming tiktoken count
                            // Estimate total by adding input estimate + output from streaming
                            let total = ctx.inference_input_tokens + streaming.output_tokens;
                            (total, "streaming_tiktoken")
                        } else {
                            (actual_estimate.tokens, "headers")
                        }
                    } else {
                        (actual_estimate.tokens, "headers")
                    };

                    ctx.inference_actual_tokens = Some(actual_tokens);

                    debug!(
                        correlation_id = %ctx.trace_id,
                        route_id = route_id,
                        estimated_tokens = ctx.inference_estimated_tokens,
                        actual_tokens = actual_tokens,
                        source = source_info,
                        streaming_response = ctx.inference_streaming_response,
                        model = ?ctx.inference_model,
                        "Recorded actual inference tokens"
                    );

                    // Record budget usage with actual tokens (if budget tracking enabled)
                    if ctx.inference_budget_enabled {
                        let alerts = self.inference_rate_limit_manager.record_budget(
                            route_id,
                            rate_limit_key,
                            actual_tokens,
                        );

                        // Log any budget alerts that fired
                        for alert in alerts.iter() {
                            warn!(
                                correlation_id = %ctx.trace_id,
                                route_id = route_id,
                                tenant = %alert.tenant,
                                threshold_pct = alert.threshold * 100.0,
                                tokens_used = alert.tokens_used,
                                tokens_limit = alert.tokens_limit,
                                "Token budget alert threshold crossed"
                            );
                        }

                        // Update context with remaining budget
                        if let Some(status) = self
                            .inference_rate_limit_manager
                            .budget_status(route_id, rate_limit_key)
                        {
                            ctx.inference_budget_remaining = Some(status.tokens_remaining as i64);
                        }
                    }

                    // Calculate cost if cost attribution is enabled
                    if ctx.inference_cost_enabled {
                        if let Some(model) = ctx.inference_model.as_deref() {
                            // Use streaming result for more accurate input/output split if available
                            let (input_tokens, output_tokens) = if let Some(ref streaming) =
                                streaming_result
                            {
                                // Streaming gives us accurate output tokens
                                let input =
                                    streaming.input_tokens.unwrap_or(ctx.inference_input_tokens);
                                let output = streaming.output_tokens;
                                (input, output)
                            } else {
                                // Fallback: estimate output from total - input
                                let input = ctx.inference_input_tokens;
                                let output = actual_tokens.saturating_sub(input);
                                (input, output)
                            };
                            ctx.inference_output_tokens = output_tokens;

                            if let Some(cost_result) = self
                                .inference_rate_limit_manager
                                .calculate_cost(route_id, model, input_tokens, output_tokens)
                            {
                                ctx.inference_request_cost = Some(cost_result.total_cost);

                                trace!(
                                    correlation_id = %ctx.trace_id,
                                    route_id = route_id,
                                    model = model,
                                    input_tokens = input_tokens,
                                    output_tokens = output_tokens,
                                    total_cost = cost_result.total_cost,
                                    currency = %cost_result.currency,
                                    "Calculated inference request cost"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Write to access log file if configured (check sampling before allocating entry)
        if self.log_manager.should_log_access(status) {
            let access_entry = AccessLogEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                trace_id: ctx.trace_id.clone(),
                method: ctx.method.clone(),
                path: ctx.path.clone(),
                query: ctx.query.clone(),
                protocol: "HTTP/1.1".to_string(),
                status,
                body_bytes: ctx.response_bytes,
                duration_ms: duration.as_millis() as u64,
                client_ip: ctx.client_ip.clone(),
                user_agent: ctx.user_agent.clone(),
                referer: ctx.referer.clone(),
                host: ctx.host.clone(),
                route_id: ctx.route_id.clone(),
                upstream: ctx.upstream.clone(),
                upstream_attempts: ctx.upstream_attempts,
                instance_id: self.app_state.instance_id.clone(),
                namespace: ctx.namespace.clone(),
                service: ctx.service.clone(),
                // New fields
                body_bytes_sent: ctx.response_bytes,
                upstream_addr: ctx.selected_upstream_address.clone(),
                connection_reused: ctx.connection_reused,
                rate_limit_hit: status == 429,
                geo_country: ctx.geo_country_code.clone(),
            };
            self.log_manager.log_access(&access_entry);
        }

        // Log to tracing at debug level (avoid allocations if debug disabled)
        if tracing::enabled!(tracing::Level::DEBUG) {
            debug!(
                trace_id = %ctx.trace_id,
                method = %ctx.method,
                path = %ctx.path,
                route_id = ?ctx.route_id,
                upstream = ?ctx.upstream,
                status = status,
                duration_ms = duration.as_millis() as u64,
                upstream_attempts = ctx.upstream_attempts,
                error = ?_error.map(|e| e.to_string()),
                "Request completed"
            );
        }

        // Log WebSocket upgrades at info level
        if ctx.is_websocket_upgrade && status == 101 {
            info!(
                trace_id = %ctx.trace_id,
                route_id = ?ctx.route_id,
                upstream = ?ctx.upstream,
                client_ip = %ctx.client_ip,
                "WebSocket connection established"
            );
        }

        // End OpenTelemetry span
        if let Some(span) = ctx.otel_span.take() {
            span.end();
        }
    }
}

// =============================================================================
// Helper methods for body streaming (not part of ProxyHttp trait)
// =============================================================================

impl ZentinelProxy {
    /// Process a single body chunk in streaming mode.
    async fn process_body_chunk_streaming(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut RequestContext,
    ) -> Result<(), Box<Error>> {
        // Clone the chunk data to avoid borrowing issues when mutating body later
        let chunk_data: Vec<u8> = body.as_ref().map(|b| b.to_vec()).unwrap_or_default();
        let chunk_index = ctx.request_body_chunk_index;
        ctx.request_body_chunk_index += 1;
        ctx.body_bytes_inspected += chunk_data.len() as u64;

        debug!(
            correlation_id = %ctx.trace_id,
            chunk_index = chunk_index,
            chunk_size = chunk_data.len(),
            end_of_stream = end_of_stream,
            "Streaming body chunk to agents"
        );

        // Create agent call context
        let agent_ctx = crate::agents::AgentCallContext {
            correlation_id: zentinel_common::CorrelationId::from_string(&ctx.trace_id),
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: ctx.trace_id.clone(),
                request_id: ctx.trace_id.clone(),
                client_ip: ctx.client_ip.clone(),
                client_port: 0,
                server_name: ctx.host.clone(),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: ctx.route_id.clone(),
                upstream_id: ctx.upstream.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                traceparent: ctx.traceparent(),
            },
            route_id: ctx.route_id.clone(),
            upstream_id: ctx.upstream.clone(),
            request_body: None, // Not used in streaming mode
            response_body: None,
        };

        let agent_ids = ctx.body_inspection_agents.clone();
        let total_size = None; // Unknown in streaming mode

        match self
            .agent_manager
            .process_request_body_streaming(
                &agent_ctx,
                &chunk_data,
                end_of_stream,
                chunk_index,
                ctx.body_bytes_inspected as usize,
                total_size,
                &agent_ids,
            )
            .await
        {
            Ok(decision) => {
                // Track if agent needs more data
                ctx.agent_needs_more = decision.needs_more;

                // Apply body mutation if present
                if let Some(ref mutation) = decision.request_body_mutation {
                    if !mutation.is_pass_through() {
                        if mutation.is_drop() {
                            // Drop the chunk
                            *body = None;
                            trace!(
                                correlation_id = %ctx.trace_id,
                                chunk_index = chunk_index,
                                "Agent dropped body chunk"
                            );
                        } else if let Some(ref new_data) = mutation.data {
                            // Replace chunk with mutated content
                            *body = Some(Bytes::from(new_data.clone()));
                            trace!(
                                correlation_id = %ctx.trace_id,
                                chunk_index = chunk_index,
                                original_size = chunk_data.len(),
                                new_size = new_data.len(),
                                "Agent mutated body chunk"
                            );
                        }
                    }
                }

                // Check decision (only final if needs_more is false)
                if !decision.needs_more && !decision.is_allow() {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        action = ?decision.action,
                        "Agent blocked request body"
                    );
                    self.metrics.record_blocked_request("agent_body_inspection");

                    let (status, message) = match &decision.action {
                        crate::agents::AgentAction::Block { status, body, .. } => (
                            *status,
                            body.clone().unwrap_or_else(|| "Blocked".to_string()),
                        ),
                        _ => (403, "Forbidden".to_string()),
                    };

                    return Err(Error::explain(ErrorType::HTTPStatus(status), message));
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    needs_more = decision.needs_more,
                    "Agent processed body chunk"
                );
            }
            Err(e) => {
                let fail_closed = ctx
                    .route_config
                    .as_ref()
                    .map(|r| r.policies.failure_mode == zentinel_config::FailureMode::Closed)
                    .unwrap_or(false);

                if fail_closed {
                    error!(
                        correlation_id = %ctx.trace_id,
                        error = %e,
                        "Agent streaming body inspection failed, blocking (fail-closed)"
                    );
                    return Err(Error::explain(
                        ErrorType::HTTPStatus(503),
                        "Service unavailable",
                    ));
                } else {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        error = %e,
                        "Agent streaming body inspection failed, allowing (fail-open)"
                    );
                }
            }
        }

        Ok(())
    }

    /// Send buffered body to agents (buffer mode).
    async fn send_buffered_body_to_agents(
        &self,
        end_of_stream: bool,
        ctx: &mut RequestContext,
    ) -> Result<(), Box<Error>> {
        debug!(
            correlation_id = %ctx.trace_id,
            buffer_size = ctx.body_buffer.len(),
            end_of_stream = end_of_stream,
            agent_count = ctx.body_inspection_agents.len(),
            decompression_enabled = ctx.decompression_enabled,
            "Sending buffered body to agents for inspection"
        );

        // Decompress body if enabled and we have a supported encoding
        let body_for_inspection = if ctx.decompression_enabled {
            if let Some(ref encoding) = ctx.body_content_encoding {
                let config = crate::decompression::DecompressionConfig {
                    max_ratio: ctx.max_decompression_ratio,
                    max_output_bytes: ctx.max_decompression_bytes,
                };

                match crate::decompression::decompress_body(&ctx.body_buffer, encoding, &config) {
                    Ok(result) => {
                        ctx.body_was_decompressed = true;
                        self.metrics
                            .record_decompression_success(encoding, result.ratio);
                        debug!(
                            correlation_id = %ctx.trace_id,
                            encoding = %encoding,
                            compressed_size = result.compressed_size,
                            decompressed_size = result.decompressed_size,
                            ratio = result.ratio,
                            "Body decompressed for agent inspection"
                        );
                        result.data
                    }
                    Err(e) => {
                        // Record failure metric
                        let failure_reason = match &e {
                            crate::decompression::DecompressionError::RatioExceeded { .. } => {
                                "ratio_exceeded"
                            }
                            crate::decompression::DecompressionError::SizeExceeded { .. } => {
                                "size_exceeded"
                            }
                            crate::decompression::DecompressionError::InvalidData { .. } => {
                                "invalid_data"
                            }
                            crate::decompression::DecompressionError::UnsupportedEncoding {
                                ..
                            } => "unsupported",
                            crate::decompression::DecompressionError::IoError(_) => "io_error",
                        };
                        self.metrics
                            .record_decompression_failure(encoding, failure_reason);

                        // Decompression failed - decide based on failure mode
                        let fail_closed = ctx
                            .route_config
                            .as_ref()
                            .map(|r| {
                                r.policies.failure_mode == zentinel_config::FailureMode::Closed
                            })
                            .unwrap_or(false);

                        if fail_closed {
                            error!(
                                correlation_id = %ctx.trace_id,
                                error = %e,
                                encoding = %encoding,
                                "Decompression failed, blocking (fail-closed)"
                            );
                            return Err(Error::explain(
                                ErrorType::HTTPStatus(400),
                                "Invalid compressed body",
                            ));
                        } else {
                            warn!(
                                correlation_id = %ctx.trace_id,
                                error = %e,
                                encoding = %encoding,
                                "Decompression failed, sending compressed body (fail-open)"
                            );
                            ctx.body_buffer.clone()
                        }
                    }
                }
            } else {
                ctx.body_buffer.clone()
            }
        } else {
            ctx.body_buffer.clone()
        };

        let agent_ctx = crate::agents::AgentCallContext {
            correlation_id: zentinel_common::CorrelationId::from_string(&ctx.trace_id),
            metadata: zentinel_agent_protocol::RequestMetadata {
                correlation_id: ctx.trace_id.clone(),
                request_id: ctx.trace_id.clone(),
                client_ip: ctx.client_ip.clone(),
                client_port: 0,
                server_name: ctx.host.clone(),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: ctx.route_id.clone(),
                upstream_id: ctx.upstream.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                traceparent: ctx.traceparent(),
            },
            route_id: ctx.route_id.clone(),
            upstream_id: ctx.upstream.clone(),
            request_body: Some(body_for_inspection.clone()),
            response_body: None,
        };

        let agent_ids = ctx.body_inspection_agents.clone();
        match self
            .agent_manager
            .process_request_body(&agent_ctx, &body_for_inspection, end_of_stream, &agent_ids)
            .await
        {
            Ok(decision) => {
                if !decision.is_allow() {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        action = ?decision.action,
                        "Agent blocked request body"
                    );
                    self.metrics.record_blocked_request("agent_body_inspection");

                    let (status, message) = match &decision.action {
                        crate::agents::AgentAction::Block { status, body, .. } => (
                            *status,
                            body.clone().unwrap_or_else(|| "Blocked".to_string()),
                        ),
                        _ => (403, "Forbidden".to_string()),
                    };

                    return Err(Error::explain(ErrorType::HTTPStatus(status), message));
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    "Agent allowed request body"
                );
            }
            Err(e) => {
                let fail_closed = ctx
                    .route_config
                    .as_ref()
                    .map(|r| r.policies.failure_mode == zentinel_config::FailureMode::Closed)
                    .unwrap_or(false);

                if fail_closed {
                    error!(
                        correlation_id = %ctx.trace_id,
                        error = %e,
                        "Agent body inspection failed, blocking (fail-closed)"
                    );
                    return Err(Error::explain(
                        ErrorType::HTTPStatus(503),
                        "Service unavailable",
                    ));
                } else {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        error = %e,
                        "Agent body inspection failed, allowing (fail-open)"
                    );
                }
            }
        }

        Ok(())
    }
}
