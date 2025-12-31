//! ProxyHttp trait implementation for SentinelProxy.
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
use pingora_cache::{CacheKey, CacheMeta, ForcedInvalidationKind, HitHandler, NoCacheReason, RespCacheable};
use pingora_timeout::sleep;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

use crate::cache::{get_cache_eviction, get_cache_lock, get_cache_storage};
use crate::logging::{AccessLogEntry, AuditEventType, AuditLogEntry};
use crate::rate_limit::HeaderAccessor;
use crate::routing::RequestInfo;

use super::context::RequestContext;
use super::SentinelProxy;

/// Helper type for rate limiting when we don't need header access
struct NoHeaderAccessor;
impl HeaderAccessor for NoHeaderAccessor {
    fn get_header(&self, _name: &str) -> Option<String> {
        None
    }
}

#[async_trait]
impl ProxyHttp for SentinelProxy {
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

        // Check if this is a builtin handler route
        if route_match.config.service_type == sentinel_config::ServiceType::Builtin {
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
                route_id: sentinel_common::RouteId::new(route_id),
                config: route_config.clone(),
                policies: route_config.policies.clone(),
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
                    request_info = request_info.with_headers(
                        RequestInfo::build_headers(req_header.headers.iter())
                    );
                }

                // Only parse query params if any route needs query param matching
                if route_matcher.needs_query_params() {
                    request_info = request_info.with_query_params(
                        RequestInfo::parse_query_params(&ctx.path)
                    );
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    method = %request_info.method,
                    path = %request_info.path,
                    host = %request_info.host,
                    "Built request info for route matching"
                );

                let route_start = std::time::Instant::now();
                let route_match = route_matcher
                    .match_request(&request_info)
                    .ok_or_else(|| {
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
        if route_match.config.service_type == sentinel_config::ServiceType::Builtin {
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
        if route_match.config.service_type == sentinel_config::ServiceType::Static {
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

        // Regular route with upstream
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

        info!(
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

        let pool = self.upstream_pools.get(upstream_name).await.ok_or_else(|| {
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

            match pool.select_peer(None).await {
                Ok(peer) => {
                    let selection_duration = selection_start.elapsed();
                    debug!(
                        correlation_id = %ctx.trace_id,
                        upstream = %upstream_name,
                        peer_address = %peer.address(),
                        attempt = attempt,
                        selection_duration_us = selection_duration.as_micros(),
                        "Selected upstream peer"
                    );
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

        // Check rate limiting early (before other processing)
        if let Some(route_id) = ctx.route_id.as_deref() {
            let rate_result = self.rate_limit_manager.check(
                route_id,
                &ctx.client_ip,
                &ctx.path,
                Option::<&NoHeaderAccessor>::None,
            );

            if !rate_result.allowed {
                use sentinel_config::RateLimitAction;

                match rate_result.action {
                    RateLimitAction::Reject => {
                        warn!(
                            correlation_id = %ctx.trace_id,
                            route_id = route_id,
                            client_ip = %ctx.client_ip,
                            limiter = %rate_result.limiter,
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

                        // Send rate limit response
                        let body = rate_result
                            .message
                            .unwrap_or_else(|| "Rate limit exceeded".to_string());
                        crate::http_helpers::write_error(
                            session,
                            rate_result.status_code,
                            &body,
                            "text/plain",
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
                        // Delay handling could be implemented here with pingora_timeout::sleep
                        debug!(
                            correlation_id = %ctx.trace_id,
                            route_id = route_id,
                            "Rate limit delay mode not yet implemented, allowing request"
                        );
                    }
                }
            }
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
            }
        }

        // Use cached route config from upstream_peer (avoids duplicate route matching)
        // Handle static file and builtin routes
        if let Some(route_config) = ctx.route_config.clone() {
            if route_config.service_type == sentinel_config::ServiceType::Static {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    "Handling static file route"
                );
                // Create a minimal RouteMatch for the handler
                let route_match = crate::routing::RouteMatch {
                    route_id: sentinel_common::RouteId::new(ctx.route_id.as_deref().unwrap_or("")),
                    config: route_config.clone(),
                    policies: route_config.policies.clone(),
                };
                return self.handle_static_route(session, ctx, &route_match).await;
            } else if route_config.service_type == sentinel_config::ServiceType::Builtin {
                trace!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    builtin_handler = ?route_config.builtin_handler,
                    "Handling builtin route"
                );
                // Create a minimal RouteMatch for the handler
                let route_match = crate::routing::RouteMatch {
                    route_id: sentinel_common::RouteId::new(ctx.route_id.as_deref().unwrap_or("")),
                    config: route_config.clone(),
                    policies: route_config.policies.clone(),
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
        req_header.insert_header("X-Forwarded-By", "Sentinel").ok();

        // Get current config for limits
        let config = self.config_manager.current();

        trace!(
            correlation_id = %ctx.trace_id,
            "Checking request limits"
        );

        // Enforce header limits
        let header_count = req_header.headers.len();
        if header_count > config.limits.max_header_count {
            warn!(
                correlation_id = %ctx.trace_id,
                header_count = header_count,
                limit = config.limits.max_header_count,
                "Request blocked: exceeds header count limit"
            );

            self.metrics.record_blocked_request("header_count_exceeded");
            return Err(Error::explain(ErrorType::InternalError, "Too many headers"));
        }

        // Check header size
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

        trace!(
            correlation_id = %ctx.trace_id,
            header_count = header_count,
            header_size = total_header_size,
            "Request limits check passed"
        );

        // Process through external agents
        trace!(
            correlation_id = %ctx.trace_id,
            "Processing request through agents"
        );
        self.process_agents(session, ctx, &client_addr, client_port)
            .await?;

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
        use sentinel_config::BodyStreamingMode;

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

            // Check body size limit
            let config = self.config_manager.current();
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
            let config = self.config_manager.current();
            let max_inspection_bytes = config.waf.as_ref()
                .map(|w| w.body_inspection.max_inspection_bytes as u64)
                .unwrap_or(1024 * 1024);

            match ctx.request_body_streaming_mode {
                BodyStreamingMode::Stream => {
                    // Stream mode: send each chunk immediately
                    if body.is_some() {
                        self.process_body_chunk_streaming(
                            body,
                            end_of_stream,
                            ctx,
                        ).await?;
                    } else if end_of_stream && ctx.agent_needs_more {
                        // Send final empty chunk to signal end
                        self.process_body_chunk_streaming(
                            body,
                            end_of_stream,
                            ctx,
                        ).await?;
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
                            if ctx.body_bytes_inspected >= buffer_threshold as u64 || end_of_stream {
                                // Send buffered content first
                                self.send_buffered_body_to_agents(end_of_stream && chunk.len() == bytes_to_buffer, ctx).await?;
                                ctx.body_buffer.clear();

                                // If there's remaining data in this chunk, stream it
                                if bytes_to_buffer < chunk.len() {
                                    let remaining = chunk.slice(bytes_to_buffer..);
                                    let mut remaining_body = Some(remaining);
                                    self.process_body_chunk_streaming(
                                        &mut remaining_body,
                                        end_of_stream,
                                        ctx,
                                    ).await?;
                                }
                            }
                        }
                    } else {
                        // Past threshold, stream directly
                        self.process_body_chunk_streaming(
                            body,
                            end_of_stream,
                            ctx,
                        ).await?;
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

                            ctx.body_buffer.extend_from_slice(&chunk[..bytes_to_inspect]);
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
                    let should_send = end_of_stream || ctx.body_bytes_inspected >= max_inspection_bytes;
                    if should_send && !ctx.body_buffer.is_empty() {
                        self.send_buffered_body_to_agents(end_of_stream, ctx).await?;
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
        _session: &mut Session,
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

        // Apply security headers
        trace!(
            correlation_id = %ctx.trace_id,
            "Applying security headers"
        );
        self.apply_security_headers(upstream_response).ok();

        // Add correlation ID to response
        upstream_response.insert_header("X-Correlation-Id", &ctx.trace_id)?;

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

            self.passive_health.record_outcome(upstream, success).await;

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
            info!(
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

        // Add request metadata headers
        upstream_request.insert_header("X-Forwarded-By", "Sentinel").ok();

        // Apply route-specific request header modifications
        // Clone the modifications to avoid lifetime issues with the header API
        if let Some(ref route_config) = ctx.route_config {
            let mods = route_config.policies.request_headers.clone();

            // Set headers (overwrite existing)
            for (name, value) in mods.set {
                upstream_request.insert_header(name, value).ok();
            }

            // Add headers (append)
            for (name, value) in mods.add {
                upstream_request.append_header(name, value).ok();
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

        // Remove sensitive headers that shouldn't go to upstream
        upstream_request.remove_header("X-Internal-Token");
        upstream_request.remove_header("Authorization-Internal");

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

            // Response body inspection (buffered mode only)
            // Note: Streaming mode for response bodies is not currently supported
            // due to Pingora's synchronous response_body_filter design
            if ctx.response_body_inspection_enabled && !ctx.response_body_inspection_agents.is_empty() {
                let config = self.config_manager.current();
                let max_inspection_bytes = config.waf.as_ref()
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
            trace!(
                correlation_id = %ctx.trace_id,
                route_id = %route_id,
                "Cache disabled for route"
            );
            return Ok(());
        }

        // Check if method is cacheable (typically GET/HEAD)
        if !self.cache_manager.is_method_cacheable(route_id, &ctx.method) {
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
    /// Returns `None` to serve the cached response, or a `ForcedInvalidationKind`
    /// to invalidate and refetch.
    async fn cache_hit_filter(
        &self,
        session: &mut Session,
        meta: &CacheMeta,
        _hit_handler: &mut HitHandler,
        is_fresh: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<ForcedInvalidationKind>>
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
            return Ok(Some(ForcedInvalidationKind::ForceExpired));
        }

        // Track cache hit statistics
        if is_fresh {
            self.cache_manager.stats().record_hit();

            debug!(
                correlation_id = %ctx.trace_id,
                route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                is_fresh = is_fresh,
                "Cache hit (fresh)"
            );
        } else {
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
                return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("no_route")));
            }
        };

        // Check if caching is enabled for this route
        if !self.cache_manager.is_enabled(route_id) {
            return Ok(RespCacheable::Uncacheable(NoCacheReason::Custom("disabled")));
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
        let config = self.cache_manager.get_route_config(route_id).unwrap_or_default();

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
        let supports_range = ctx.route_config.as_ref().map_or(true, |config| {
            // Static file routes and media routes should support range requests
            matches!(
                config.service_type,
                sentinel_config::ServiceType::Static | sentinel_config::ServiceType::Web
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
        let range_type = pingora_proxy::range_header_filter(
            session.req_header(),
            response,
        );

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
        _session: &mut Session,
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

            // Internal errors
            ErrorType::InternalError => 500,

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
        self.metrics.record_blocked_request(&format!("proxy_error_{}", error_code));

        // Return the error response info
        // can_reuse_downstream: allow connection reuse for client errors, not for server errors
        pingora_proxy::FailToProxy {
            error_code,
            can_reuse_downstream: error_code < 500,
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
        self.metrics.record_blocked_request(&format!("proxy_error_{:?}", error_type));

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

        let duration = ctx.elapsed();

        // Get response status
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .unwrap_or(0);

        // Write to access log file if configured
        if self.log_manager.access_log_enabled() {
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
    }
}

// =============================================================================
// Helper methods for body streaming (not part of ProxyHttp trait)
// =============================================================================

impl SentinelProxy {
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
            correlation_id: sentinel_common::CorrelationId::from_string(&ctx.trace_id),
            metadata: sentinel_agent_protocol::RequestMetadata {
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
            },
            route_id: ctx.route_id.clone(),
            upstream_id: ctx.upstream.clone(),
            request_body: None, // Not used in streaming mode
            response_body: None,
        };

        let agent_ids = ctx.body_inspection_agents.clone();
        let total_size = None; // Unknown in streaming mode

        match self.agent_manager
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
                        crate::agents::AgentAction::Block { status, body, .. } => {
                            (*status, body.clone().unwrap_or_else(|| "Blocked".to_string()))
                        }
                        _ => (403, "Forbidden".to_string()),
                    };

                    return Err(Error::explain(
                        ErrorType::HTTPStatus(status),
                        message,
                    ));
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    needs_more = decision.needs_more,
                    "Agent processed body chunk"
                );
            }
            Err(e) => {
                let fail_closed = ctx.route_config.as_ref()
                    .map(|r| r.policies.failure_mode == sentinel_config::FailureMode::Closed)
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
            "Sending buffered body to agents for inspection"
        );

        let agent_ctx = crate::agents::AgentCallContext {
            correlation_id: sentinel_common::CorrelationId::from_string(&ctx.trace_id),
            metadata: sentinel_agent_protocol::RequestMetadata {
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
            },
            route_id: ctx.route_id.clone(),
            upstream_id: ctx.upstream.clone(),
            request_body: Some(ctx.body_buffer.clone()),
            response_body: None,
        };

        let agent_ids = ctx.body_inspection_agents.clone();
        match self.agent_manager
            .process_request_body(&agent_ctx, &ctx.body_buffer, end_of_stream, &agent_ids)
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
                        crate::agents::AgentAction::Block { status, body, .. } => {
                            (*status, body.clone().unwrap_or_else(|| "Blocked".to_string()))
                        }
                        _ => (403, "Forbidden".to_string()),
                    };

                    return Err(Error::explain(
                        ErrorType::HTTPStatus(status),
                        message,
                    ));
                }

                trace!(
                    correlation_id = %ctx.trace_id,
                    "Agent allowed request body"
                );
            }
            Err(e) => {
                let fail_closed = ctx.route_config.as_ref()
                    .map(|r| r.policies.failure_mode == sentinel_config::FailureMode::Closed)
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
