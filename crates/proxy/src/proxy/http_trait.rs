//! ProxyHttp trait implementation for SentinelProxy.
//!
//! This module contains the Pingora ProxyHttp trait implementation which defines
//! the core request/response lifecycle handling.

use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::Peer;
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};

use crate::logging::AccessLogEntry;
use crate::routing::RequestInfo;

use super::context::RequestContext;
use super::SentinelProxy;

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
                        // Exponential backoff
                        let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                        trace!(
                            correlation_id = %ctx.trace_id,
                            backoff_ms = backoff.as_millis(),
                            "Backing off before retry"
                        );
                        tokio::time::sleep(backoff).await;
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
