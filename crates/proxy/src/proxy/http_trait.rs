//! ProxyHttp trait implementation for SentinelProxy.
//!
//! This module contains the Pingora ProxyHttp trait implementation which defines
//! the core request/response lifecycle handling.

use async_trait::async_trait;
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

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
        _peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<Error>,
    ) -> Box<Error> {
        // Log and return the error
        // Custom error pages are handled in response_filter
        e
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>, Box<Error>> {
        // Track active request
        self.reload_coordinator.inc_requests();

        // Initialize trace ID
        ctx.trace_id = self.get_trace_id(session);

        // Cache client address for logging
        ctx.client_ip = session
            .client_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let req_header = session.req_header();

        // Cache request info for access logging
        ctx.method = req_header.method.to_string();
        ctx.path = req_header.uri.path().to_string();
        ctx.query = req_header.uri.query().map(|q| q.to_string());
        ctx.host = req_header
            .headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
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

        // Build request info for routing
        let mut headers = HashMap::new();
        for (name, value) in req_header.headers.iter() {
            if let Ok(value_str) = value.to_str() {
                headers.insert(name.as_str().to_lowercase(), value_str.to_string());
            }
        }

        let request_info = RequestInfo {
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            host: ctx.host.clone().unwrap_or_default(),
            headers,
            query_params: RequestInfo::parse_query_params(&ctx.path),
        };

        // Match route
        let route_match = self
            .route_matcher
            .read()
            .await
            .match_request(&request_info)
            .ok_or_else(|| Error::explain(ErrorType::InternalError, "No matching route found"))?;

        ctx.route_id = Some(route_match.route_id.to_string());

        // Check if this is a static file route
        if route_match.config.service_type == sentinel_config::ServiceType::Static {
            // Static routes don't need an upstream
            if self
                .static_servers
                .get(route_match.route_id.as_str())
                .await
                .is_some()
            {
                // Mark this as a static route for later processing
                ctx.upstream = Some(format!("_static_{}", route_match.route_id));
                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = %route_match.route_id,
                    "Route is configured for static file serving"
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
        } else {
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
            "Request matched to route"
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
        let pool = self.upstream_pools.get(upstream_name).await.ok_or_else(|| {
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

        let mut last_error = None;
        for attempt in 1..=max_retries {
            ctx.upstream_attempts = attempt;

            match pool.select_peer(None).await {
                Ok(peer) => {
                    debug!(
                        correlation_id = %ctx.trace_id,
                        attempt = attempt,
                        "Selected upstream peer"
                    );
                    return Ok(Box::new(peer));
                }
                Err(e) => {
                    warn!(
                        correlation_id = %ctx.trace_id,
                        attempt = attempt,
                        error = %e,
                        "Failed to select upstream peer"
                    );
                    last_error = Some(e);

                    if attempt < max_retries {
                        // Exponential backoff
                        let backoff = Duration::from_millis(100 * 2_u64.pow(attempt - 1));
                        tokio::time::sleep(backoff).await;
                    }
                }
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
        // First, determine the route for this request (needed before upstream_peer)
        let req_header = session.req_header();
        let route_info = {
            let mut headers = HashMap::new();
            for (name, value) in req_header.headers.iter() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.as_str().to_lowercase(), value_str.to_string());
                }
            }
            let host = headers.get("host").cloned().unwrap_or_default();
            let request_info = RequestInfo {
                path: req_header.uri.path().to_string(),
                method: req_header.method.as_str().to_string(),
                host,
                headers,
                query_params: HashMap::new(),
            };
            self.route_matcher.read().await.match_request(&request_info)
        };

        // Handle static file routes
        if let Some(route_match) = &route_info {
            if route_match.config.service_type == sentinel_config::ServiceType::Static {
                return self.handle_static_route(session, ctx, route_match).await;
            } else if route_match.config.service_type == sentinel_config::ServiceType::Builtin {
                return self.handle_builtin_route(session, ctx, route_match).await;
            }
        }

        // API validation for API routes
        if let Some(route_id) = ctx.route_id.clone() {
            if let Some(validator) = self.validators.get(&route_id).await {
                if let Some(result) = self
                    .validate_api_request(session, ctx, &route_id, &validator)
                    .await?
                {
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

        // Enforce header limits
        if req_header.headers.len() > config.limits.max_header_count {
            warn!(
                correlation_id = %ctx.trace_id,
                header_count = req_header.headers.len(),
                limit = config.limits.max_header_count,
                "Request exceeds header count limit"
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
                "Request exceeds header size limit"
            );

            self.metrics.record_blocked_request("header_size_exceeded");
            return Err(Error::explain(
                ErrorType::InternalError,
                "Headers too large",
            ));
        }

        // Process through external agents
        self.process_agents(session, ctx, &client_addr, client_port)
            .await?;

        Ok(false) // Continue processing
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<(), Box<Error>> {
        // Apply security headers
        self.apply_security_headers(upstream_response).ok();

        // Add correlation ID to response
        upstream_response.insert_header("X-Correlation-Id", &ctx.trace_id)?;

        // Record metrics
        let status = upstream_response.status.as_u16();
        let duration = ctx.elapsed();

        // Generate custom error pages for error responses
        if status >= 400 {
            self.handle_error_response(upstream_response, ctx).await?;
        }

        self.metrics.record_request(
            ctx.route_id.as_deref().unwrap_or("unknown"),
            "GET", // TODO: Get actual method from context
            status,
            duration,
        );

        // Record passive health check
        if let Some(ref upstream) = ctx.upstream {
            let success = status < 500;
            self.passive_health.record_outcome(upstream, success).await;

            // Report to upstream pool
            if let Some(pool) = self.upstream_pools.get(upstream).await {
                pool.report_result(upstream, success).await;
            }
        }

        info!(
            correlation_id = %ctx.trace_id,
            route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
            upstream = ctx.upstream.as_deref().unwrap_or("unknown"),
            status = status,
            duration_ms = duration.as_millis(),
            attempts = ctx.upstream_attempts,
            "Request completed"
        );

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

        // Also log to stdout for tracing
        let log_entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "trace_id": ctx.trace_id,
            "instance_id": self.app_state.instance_id,
            "method": ctx.method,
            "path": ctx.path,
            "route_id": ctx.route_id,
            "upstream": ctx.upstream,
            "status": status,
            "duration_ms": duration.as_millis(),
            "upstream_attempts": ctx.upstream_attempts,
            "error": _error.map(|e| e.to_string()),
        });

        debug!("{}", log_entry);
    }
}
