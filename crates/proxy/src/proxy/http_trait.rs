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
use pingora_timeout::sleep;
use std::os::unix::io::RawFd;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

use crate::logging::AccessLogEntry;
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
    /// Used for body size enforcement and WAF inspection.
    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Track request body size
        if let Some(ref chunk) = body {
            ctx.request_body_bytes += chunk.len() as u64;

            trace!(
                correlation_id = %ctx.trace_id,
                chunk_size = chunk.len(),
                total_body_bytes = ctx.request_body_bytes,
                end_of_stream = end_of_stream,
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

            // TODO: Send body chunk to WAF agent for inspection if WAF is enabled
            // This is where we'd call the agent with RequestBodyChunkEvent
        }

        if end_of_stream {
            trace!(
                correlation_id = %ctx.trace_id,
                total_body_bytes = ctx.request_body_bytes,
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

            // TODO: Send body chunk to WAF agent for response inspection if enabled
            // This is where we'd call the agent with ResponseBodyChunkEvent
        }

        if end_of_stream {
            trace!(
                correlation_id = %ctx.trace_id,
                total_response_bytes = ctx.response_bytes,
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
    // Caching (Infrastructure Only - pingora-cache integration pending)
    // =========================================================================
    // Note: The cache infrastructure is available via self.cache_manager
    // but the pingora-cache ProxyHttp methods are not yet implemented
    // due to API instability. The CacheManager provides:
    // - Per-route cache configuration
    // - Cache key generation
    // - TTL calculation from Cache-Control headers
    // - Cache statistics tracking
    //
    // When pingora-cache stabilizes, implement:
    // - request_cache_filter()
    // - cache_key_callback()
    // - cache_hit_filter()
    // - cache_miss()
    // - should_serve_stale()
    // - response_cache_filter()

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
    }
}
