//! Request and response handlers for the proxy.
//!
//! This module contains handler methods for different route types:
//! - Static file serving
//! - Builtin handlers (health, metrics, config, upstreams)
//! - API validation
//! - Agent processing
//! - Error responses

use std::collections::HashMap;
use std::sync::Arc;

use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::Session;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::builtin_handlers;
use crate::routing::RouteMatch;
use crate::validation::SchemaValidator;

use super::context::RequestContext;
use super::SentinelProxy;

use sentinel_common::types::CorrelationId;

impl SentinelProxy {
    /// Handle static file route
    pub(super) async fn handle_static_route(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_match: &RouteMatch,
    ) -> Result<bool, Box<Error>> {
        ctx.route_id = Some(route_match.route_id.to_string());
        let route_id = route_match.route_id.as_str();

        if let Some(static_server) = self.static_servers.get(route_id).await {
            // Clone the path to avoid borrow issues with session
            let (path, static_req) = {
                let req_header = session.req_header();
                let path = req_header.uri.path().to_string();
                let static_req = http::Request::builder()
                    .method(req_header.method.clone())
                    .uri(req_header.uri.clone())
                    .body(())
                    .expect("request builder with valid method and uri cannot fail");
                (path, static_req)
            };

            match static_server.serve(&static_req, &path).await {
                Ok(response) => {
                    self.write_http_response(session, response).await?;

                    info!(
                        correlation_id = %ctx.trace_id,
                        route_id = route_id,
                        path = path,
                        "Served static file"
                    );

                    return Ok(true); // Skip upstream
                }
                Err(e) => {
                    error!(
                        correlation_id = %ctx.trace_id,
                        route_id = route_id,
                        path = path,
                        error = %e,
                        "Failed to serve static file"
                    );

                    // Return error using error handler
                    if let Some(error_handler) = self.error_handlers.get(route_id).await {
                        let status = if e.to_string().contains("404")
                            || e.to_string().contains("Not Found")
                        {
                            http::StatusCode::NOT_FOUND
                        } else {
                            http::StatusCode::INTERNAL_SERVER_ERROR
                        };

                        if let Ok(error_response) = error_handler.generate_response(
                            status,
                            Some(format!("Failed to serve file: {}", path)),
                            &ctx.trace_id,
                            None,
                        ) {
                            self.write_http_response(session, error_response).await?;
                        }
                    }

                    return Ok(true); // Skip upstream even on error
                }
            }
        }

        Ok(false)
    }

    /// Handle builtin route (status, health, metrics, config, upstreams)
    pub(super) async fn handle_builtin_route(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_match: &RouteMatch,
    ) -> Result<bool, Box<Error>> {
        ctx.route_id = Some(route_match.route_id.to_string());
        let route_id = route_match.route_id.as_str();

        if let Some(handler) = route_match.config.builtin_handler {
            let request_id = self.get_trace_id(session);
            ctx.trace_id = request_id.clone();

            // Get current config for config dump handler
            let config = Some(self.config_manager.current());

            // Build upstream health snapshot for upstreams handler
            let upstreams = self.build_upstream_health_snapshot().await;

            let response = builtin_handlers::execute_handler(
                handler,
                &self.builtin_state,
                &request_id,
                config,
                upstreams,
            );

            self.write_http_response(session, response).await?;

            info!(
                correlation_id = %ctx.trace_id,
                route_id = route_id,
                handler = ?handler,
                "Served builtin handler"
            );

            return Ok(true); // Skip upstream
        } else {
            warn!(
                "Builtin route {} has no builtin_handler configured",
                route_id
            );
        }

        Ok(false)
    }

    /// Build upstream health snapshot for the upstreams admin endpoint
    pub(super) async fn build_upstream_health_snapshot(
        &self,
    ) -> Option<builtin_handlers::UpstreamHealthSnapshot> {
        let config = self.config_manager.current();

        if config.upstreams.is_empty() {
            return None;
        }

        let mut upstreams = HashMap::new();

        for (upstream_id, upstream_config) in &config.upstreams {
            let mut targets = Vec::new();

            for target in &upstream_config.targets {
                // Get failure rate from passive health checker
                let failure_rate = self.passive_health.get_failure_rate(&target.address).await;

                // Determine health status based on failure rate
                let status = match failure_rate {
                    Some(rate) if rate > 0.5 => builtin_handlers::TargetHealthStatus::Unhealthy,
                    Some(_) => builtin_handlers::TargetHealthStatus::Healthy,
                    None => builtin_handlers::TargetHealthStatus::Unknown,
                };

                targets.push(builtin_handlers::TargetStatus {
                    address: target.address.clone(),
                    weight: target.weight,
                    status,
                    failure_rate,
                    last_error: None, // TODO: Track last error in passive health checker
                });
            }

            upstreams.insert(
                upstream_id.clone(),
                builtin_handlers::UpstreamStatus {
                    id: upstream_id.clone(),
                    load_balancing: format!("{:?}", upstream_config.load_balancing),
                    targets,
                },
            );
        }

        Some(builtin_handlers::UpstreamHealthSnapshot { upstreams })
    }

    /// Validate API request body
    pub(super) async fn validate_api_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_id: &str,
        validator: &Arc<SchemaValidator>,
    ) -> Result<Option<bool>, Box<Error>> {
        // Clone necessary data from req_header before making mutable calls
        let (method, uri, path) = {
            let req_header = session.req_header();
            (
                req_header.method.clone(),
                req_header.uri.clone(),
                req_header.uri.path().to_string(),
            )
        };

        // Only validate for methods that typically have bodies
        if !matches!(method.as_str(), "POST" | "PUT" | "PATCH") {
            return Ok(None);
        }

        // Read the request body for validation
        let body_bytes = session.read_request_body().await.map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("Failed to read body: {}", e),
            )
        })?;

        let body_slice = body_bytes.as_ref().map(|b| b.as_ref()).unwrap_or(&[]);

        // Validate the request body
        if let Err(validation_error) = validator
            .validate_request(
                &http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(())
                    .expect("request builder with valid method and uri cannot fail"),
                body_slice,
                &path,
                &ctx.trace_id,
            )
            .await
        {
            warn!(
                correlation_id = %ctx.trace_id,
                route_id = route_id,
                error = %validation_error,
                "Request validation failed"
            );

            // Return validation error response
            if let Some(error_handler) = self.error_handlers.get(route_id).await {
                let error_details = serde_json::json!({
                    "validation_error": validation_error.to_string()
                });

                if let Ok(error_response) = error_handler.generate_response(
                    http::StatusCode::BAD_REQUEST,
                    Some("Request validation failed".to_string()),
                    &ctx.trace_id,
                    Some(error_details),
                ) {
                    self.write_http_response(session, error_response).await?;
                    self.metrics.record_blocked_request("validation_failed");
                    return Ok(Some(true)); // Skip upstream on validation failure
                }
            }

            return Err(Error::explain(
                ErrorType::HTTPStatus(400),
                "Request validation failed",
            ));
        }

        info!(
            correlation_id = %ctx.trace_id,
            route_id = route_id,
            "Request validation passed"
        );

        Ok(None)
    }

    /// Process request through external agents
    pub(super) async fn process_agents(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        client_addr: &str,
        client_port: u16,
    ) -> Result<(), Box<Error>> {
        use crate::agents::AgentAction;

        let config = self.config_manager.current();

        let Some(ref route_id) = ctx.route_id else {
            return Ok(());
        };

        // Get route configuration to find which agents to apply
        let routes = config.routes.clone();
        let Some(route) = routes.iter().find(|r| r.id == *route_id) else {
            return Ok(());
        };

        // Extract agent IDs from filter chain by looking up filter definitions
        let agent_ids: Vec<String> = route
            .filters
            .iter()
            .filter_map(|filter_id| {
                config.filters.get(filter_id).and_then(|filter_config| {
                    if let sentinel_config::Filter::Agent(agent_filter) = &filter_config.filter {
                        Some(agent_filter.agent.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        if agent_ids.is_empty() {
            return Ok(());
        }

        debug!(
            correlation_id = %ctx.trace_id,
            route_id = %route_id,
            agents = ?agent_ids,
            "Processing request through agents"
        );

        let req_header = session.req_header_mut();

        // Build headers map for agent processing
        let mut headers_map = HashMap::new();
        for (name, value) in req_header.headers.iter() {
            headers_map
                .entry(name.as_str().to_lowercase())
                .or_insert_with(Vec::new)
                .push(value.to_str().unwrap_or("").to_string());
        }

        // Create agent call context
        let agent_ctx = crate::agents::AgentCallContext {
            correlation_id: CorrelationId::from_string(&ctx.trace_id),
            metadata: sentinel_agent_protocol::RequestMetadata {
                correlation_id: ctx.trace_id.clone(),
                request_id: Uuid::new_v4().to_string(),
                client_ip: client_addr.to_string(),
                client_port,
                server_name: req_header.uri.host().map(|h| h.to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some(route_id.clone()),
                upstream_id: ctx.upstream.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
            },
            route_id: Some(route_id.clone()),
            upstream_id: ctx.upstream.clone(),
            request_body: None,
            response_body: None,
        };

        // Process through agents
        match self
            .agent_manager
            .process_request_headers(&agent_ctx, &headers_map, &agent_ids)
            .await
        {
            Ok(decision) => {
                // Apply agent decision
                if !decision.is_allow() {
                    match decision.action {
                        AgentAction::Block { status, body, .. } => {
                            warn!(
                                correlation_id = %ctx.trace_id,
                                status = status,
                                "Request blocked by agent"
                            );
                            self.metrics.record_blocked_request("agent_blocked");
                            return Err(Error::explain(
                                ErrorType::InternalError,
                                body.unwrap_or_else(|| "Blocked by agent".to_string()),
                            ));
                        }
                        AgentAction::Redirect { url, status } => {
                            info!(
                                correlation_id = %ctx.trace_id,
                                url = %url,
                                status = status,
                                "Request redirected by agent"
                            );
                            return Err(Error::explain(
                                ErrorType::InternalError,
                                format!("Redirect to {}", url),
                            ));
                        }
                        _ => {}
                    }
                }

                // Apply header modifications
                for op in decision.request_headers {
                    match op {
                        sentinel_agent_protocol::HeaderOp::Set { name, value } => {
                            req_header.insert_header(name, &value).ok();
                        }
                        sentinel_agent_protocol::HeaderOp::Add { name, value } => {
                            req_header.append_header(name, &value).ok();
                        }
                        sentinel_agent_protocol::HeaderOp::Remove { name } => {
                            req_header.remove_header(&name);
                        }
                    }
                }

                debug!(
                    correlation_id = %ctx.trace_id,
                    "Agent processing completed, request allowed"
                );
            }
            Err(e) => {
                error!(
                    correlation_id = %ctx.trace_id,
                    error = %e,
                    "Agent processing failed"
                );
                // Check failure mode from route config
                if route.policies.failure_mode == sentinel_config::FailureMode::Closed {
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "Agent processing failed",
                    ));
                }
                // Otherwise fail-open and continue
            }
        }

        Ok(())
    }

    /// Handle error responses with custom error pages
    pub(super) async fn handle_error_response(
        &self,
        upstream_response: &mut ResponseHeader,
        ctx: &RequestContext,
    ) -> Result<(), Box<Error>> {
        let status = upstream_response.status.as_u16();

        let Some(ref route_id) = ctx.route_id else {
            return Ok(());
        };

        let Some(error_handler) = self.error_handlers.get(route_id).await else {
            return Ok(());
        };

        // Get the status code
        let status_code =
            http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);

        // Try to generate a custom error page
        match error_handler.generate_response(
            status_code,
            None, // Use default message for status
            &ctx.trace_id,
            None,
        ) {
            Ok(error_response) => {
                // Replace the upstream response with our custom error page
                upstream_response.set_status(status_code.as_u16())?;

                // Convert to owned strings to avoid lifetime issues
                let headers_owned: Vec<(String, String)> = error_response
                    .headers()
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            v.to_str().unwrap_or("").to_string(),
                        )
                    })
                    .collect();

                for (key, value) in headers_owned {
                    upstream_response.insert_header(key, &value)?;
                }

                debug!(
                    correlation_id = %ctx.trace_id,
                    route_id = route_id,
                    status = status,
                    "Generated custom error page"
                );
            }
            Err(e) => {
                warn!(
                    correlation_id = %ctx.trace_id,
                    route_id = route_id,
                    error = %e,
                    "Failed to generate custom error page"
                );
            }
        }

        Ok(())
    }

    /// Write HTTP response to session
    pub(super) async fn write_http_response(
        &self,
        session: &mut Session,
        response: http::Response<http_body_util::Full<bytes::Bytes>>,
    ) -> Result<(), Box<Error>> {
        let status = response.status().as_u16();

        // Collect headers to owned strings
        let headers_owned: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().unwrap_or("").to_string(),
                )
            })
            .collect();

        // Get the body
        let full_body = response.into_body();
        let body_bytes: bytes::Bytes = http_body_util::BodyExt::collect(full_body)
            .await
            .map(|collected| collected.to_bytes())
            .unwrap_or_default();

        let mut resp_header = ResponseHeader::build(status, None)?;
        for (key, value) in headers_owned {
            resp_header.insert_header(key, &value)?;
        }

        session.set_keepalive(None);
        session
            .write_response_header(Box::new(resp_header), false)
            .await?;
        session.write_response_body(Some(body_bytes), true).await?;

        Ok(())
    }
}
