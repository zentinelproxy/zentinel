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
use crate::logging::{AuditEventType, AuditLogEntry};
use crate::routing::RouteMatch;
use crate::validation::SchemaValidator;

use super::context::{AgentBlock, RequestContext};
use super::ZentinelProxy;

use zentinel_common::CorrelationId;

impl ZentinelProxy {
    /// Handle static file route
    pub(super) async fn handle_static_route(
        &self,
        session: &mut Session,
        ctx: &mut RequestContext,
        route_match: &RouteMatch,
    ) -> Result<bool, Box<Error>> {
        ctx.route_id = Some(route_match.route_id.to_string());
        ctx.trace_id = self.get_trace_id(session);
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

            // Get cache stats from cache manager
            let cache_stats = Some(self.cache_manager.stats());

            // Parse cache purge request for PURGE handler
            let cache_purge = if matches!(handler, zentinel_config::BuiltinHandler::CachePurge) {
                // Extract purge pattern from request path or X-Purge-Pattern header
                let path = session.req_header().uri.path().to_string();
                Some(builtin_handlers::CachePurgeRequest {
                    pattern: path,
                    wildcard: session
                        .req_header()
                        .headers
                        .get("X-Purge-Wildcard")
                        .map(|v| v.to_str().unwrap_or("false") == "true")
                        .unwrap_or(false),
                })
            } else {
                None
            };

            let response = builtin_handlers::execute_handler(
                handler,
                &self.builtin_state,
                &request_id,
                config,
                upstreams,
                cache_stats,
                cache_purge,
                Some(&self.cache_manager),
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

                let last_error = self.passive_health.get_last_error(&target.address).await;

                targets.push(builtin_handlers::TargetStatus {
                    address: target.address.clone(),
                    weight: target.weight,
                    status,
                    failure_rate,
                    last_error,
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

        // Read the whole body: validating only the first chunk let anything
        // after it through unchecked.
        //
        // Retry buffering keeps pingora's body loop running after the body
        // has been consumed here, which is what lets `request_body_filter`
        // hand it back for forwarding (see `validated_request_body`). The
        // buffer is sized to the body limit -- the route's own if it has one,
        // never above the global one: pingora's default of 64 KiB dropped
        // anything larger, the loop never ran, and the upstream waited for a
        // body that never came (#531).
        let global_limit = ctx
            .config
            .get_or_insert_with(|| self.config_manager.current())
            .limits
            .max_body_size_bytes;
        let limit = ctx.max_body_size(global_limit);
        session.enable_retry_buffering_with_limit(limit);
        let mut body = Vec::new();
        while let Some(chunk) = session.read_request_body().await.map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("Failed to read body: {}", e),
            )
        })? {
            if body.len() + chunk.len() > limit {
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    "Request body exceeds the configured limit",
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let body_slice = body.as_slice();

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

        ctx.validated_request_body = Some(bytes::Bytes::from(body));
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
        // Use cached route config from context (already matched in upstream_peer)
        let Some(ref route_config) = ctx.route_config else {
            return Ok(());
        };

        // Fast path: if route has no filters, skip agent processing entirely
        if route_config.filters.is_empty() {
            return Ok(());
        }

        let Some(ref route_id) = ctx.route_id else {
            return Ok(());
        };

        // Use cached config (or fetch if not yet cached)
        let config = ctx
            .config
            .get_or_insert_with(|| self.config_manager.current());

        // The agents of the filter chain, each with its filter's failure mode
        // and timeout. `phase` is not read: the agent's own `events` decide
        // what it receives (reported by lint, #542).
        let agent_filters: Vec<crate::agents::FilterAgent> = route_config
            .filters
            .iter()
            .filter_map(|filter_id| {
                config.filters.get(filter_id).and_then(|filter_config| {
                    if let zentinel_config::Filter::Agent(agent_filter) = &filter_config.filter {
                        Some(crate::agents::FilterAgent {
                            id: agent_filter.agent.clone(),
                            // Filter's failure mode if specified, otherwise the route's policy
                            failure_mode: agent_filter
                                .failure_mode
                                .unwrap_or(route_config.policies.failure_mode),
                            timeout_ms: agent_filter.timeout_ms,
                        })
                    } else {
                        None
                    }
                })
            })
            .collect();

        if agent_filters.is_empty() {
            return Ok(());
        }

        // Extract just the agent IDs for logging and response processing
        let agent_ids: Vec<String> = agent_filters.iter().map(|a| a.id.clone()).collect();

        // The agents the request body may go to: a filter's `inspect-body
        // #false` keeps it from its agent on this route, and its
        // `max-body-bytes` lowers the agent's own limit (#553). Whether an
        // agent receives bodies at all stays with its `events`.
        let body_agents: Vec<crate::agents::BodyAgent> = route_config
            .filters
            .iter()
            .filter_map(|filter_id| match &config.filters.get(filter_id)?.filter {
                zentinel_config::Filter::Agent(agent_filter)
                    if agent_filter.sends_request_body() =>
                {
                    Some(crate::agents::BodyAgent {
                        id: agent_filter.agent.clone(),
                        max_body_bytes: agent_filter.max_body_bytes,
                        failure_mode: agent_filter
                            .failure_mode
                            .unwrap_or(route_config.policies.failure_mode),
                        timeout_ms: agent_filter.timeout_ms,
                    })
                }
                _ => None,
            })
            .collect();

        // Save the agent filters in context for response-phase processing
        ctx.route_agents = agent_filters.clone();

        debug!(
            correlation_id = %ctx.trace_id,
            route_id = %route_id,
            agents = ?agent_ids,
            "Processing request through agents"
        );

        // Set up body inspection: for the route's agents that subscribe to
        // the request body, unless `waf { body-inspection {
        // inspect-request-body #false } }` turns it off. It used to need a
        // `waf` block: without one, an agent subscribed to `request_body`
        // silently never got a body, while response bodies went to their
        // agents regardless.
        let body_inspection_enabled = config
            .waf
            .as_ref()
            .map(|w| w.body_inspection.inspect_request_body)
            .unwrap_or(true);

        if body_inspection_enabled
            && !body_agents.is_empty()
            && self
                .agent_manager
                .any_body_agent_handles_request_body(&body_agents)
                .await
        {
            // Check content-type allowlist
            let content_type = session
                .req_header()
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            let allowed_types = config
                .waf
                .as_ref()
                .map(|w| &w.body_inspection.content_types)
                .cloned()
                .unwrap_or_default();

            let is_allowed_type = allowed_types
                .iter()
                .any(|allowed| content_type.starts_with(allowed));

            if is_allowed_type || allowed_types.is_empty() {
                ctx.body_inspection_enabled = true;
                // The agents' `request-body-mode`, most conservative
                // first when they disagree (#602). It was never set, so
                // every body was buffered whatever the agents asked for.
                ctx.request_body_streaming_mode =
                    self.agent_manager.request_body_mode(&body_agents).await;
                ctx.body_inspection_agents = body_agents;

                // Set up decompression if enabled in WAF config
                let decompress_enabled = config
                    .waf
                    .as_ref()
                    .map(|w| w.body_inspection.decompress)
                    .unwrap_or(false);

                if decompress_enabled {
                    // Get Content-Encoding header
                    let content_encoding = session
                        .req_header()
                        .headers
                        .get("content-encoding")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    if let Some(ref encoding) = content_encoding {
                        if crate::decompression::is_supported_encoding(encoding) {
                            ctx.decompression_enabled = true;
                            ctx.body_content_encoding = Some(encoding.clone());
                            ctx.max_decompression_ratio = config
                                .waf
                                .as_ref()
                                .map(|w| w.body_inspection.max_decompression_ratio as f64)
                                .unwrap_or(100.0);
                            // Use 10x max inspection bytes as decompression limit
                            ctx.max_decompression_bytes = config
                                .waf
                                .as_ref()
                                .map(|w| w.body_inspection.max_inspection_bytes * 10)
                                .unwrap_or(10 * 1024 * 1024);

                            debug!(
                                correlation_id = %ctx.trace_id,
                                encoding = %encoding,
                                max_ratio = ctx.max_decompression_ratio,
                                max_bytes = ctx.max_decompression_bytes,
                                "Decompression enabled for body inspection"
                            );
                        }
                    }
                }

                debug!(
                    correlation_id = %ctx.trace_id,
                    content_type = %content_type,
                    agent_count = ctx.body_inspection_agents.len(),
                    decompression = ctx.decompression_enabled,
                    "Body inspection enabled for request"
                );
            } else {
                tracing::trace!(
                    correlation_id = %ctx.trace_id,
                    content_type = %content_type,
                    allowed_types = ?allowed_types,
                    "Body inspection skipped: content-type not in allowlist"
                );
            }
        }

        let req_header = session.req_header_mut();

        // Build headers map for agent processing
        // HTTP header names are already lowercase (Pingora normalizes HTTP/1.1; HTTP/2 is lowercase by spec)
        let mut headers_map: HashMap<String, Vec<String>> =
            HashMap::with_capacity(req_header.headers.len() + 2);
        for (name, value) in req_header.headers.iter() {
            headers_map
                .entry(name.as_str().to_string())
                .or_default()
                .push(value.to_str().unwrap_or("").to_string());
        }

        // Add HTTP/2 pseudo-headers for agent processing
        headers_map.insert(
            ":method".to_string(),
            vec![req_header.method.as_str().to_string()],
        );
        // Include full path with query string for WAF inspection
        let full_path = req_header
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| req_header.uri.path().to_string());
        headers_map.insert(":path".to_string(), vec![full_path]);

        // Create agent call context
        let agent_ctx = crate::agents::AgentCallContext {
            correlation_id: CorrelationId::from_string(&ctx.trace_id),
            metadata: zentinel_agent_protocol::RequestMetadata {
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
                traceparent: ctx.traceparent(),
            },
            route_id: Some(route_id.clone()),
            upstream_id: ctx.upstream.clone(),
            request_body: None,
            response_body: None,
        };

        // Process through agents (passing filter-specific failure modes)
        match self
            .agent_manager
            .process_request_headers(&agent_ctx, headers_map, &agent_filters)
            .await
        {
            Ok(decision) => {
                // Anything but Allow answers the client here (#595).
                self.refuse_on_agent_request_decision(
                    ctx,
                    &decision,
                    "request_headers",
                    "agent_blocked",
                )?;

                // Apply header modifications. The response-header changes
                // are for the client's response, and applied to it in
                // `response_filter` (#596).
                let crate::agents::AgentDecision {
                    request_headers,
                    response_headers,
                    ..
                } = decision;
                ctx.agent_response_headers.extend(response_headers);
                for op in request_headers {
                    match op {
                        zentinel_agent_protocol::HeaderOp::Set { name, value } => {
                            req_header.insert_header(name, &value).ok();
                        }
                        zentinel_agent_protocol::HeaderOp::Add { name, value } => {
                            req_header.append_header(name, &value).ok();
                        }
                        zentinel_agent_protocol::HeaderOp::Remove { name } => {
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
                // Not reached today: every agent failure (not loaded,
                // circuit open, call error, timeout) comes back as a
                // decision above, decided by its filter's failure mode
                // (#584), and the parallel dispatch returns no error of its
                // own. Should one appear, it is no single agent's, and
                // follows the same rule: one closed filter refuses (#597).
                // The route's policy is already each filter's default.
                let fail_closed = agent_filters
                    .iter()
                    .any(|agent| agent.failure_mode == zentinel_config::FailureMode::Closed);
                error!(
                    correlation_id = %ctx.trace_id,
                    error = %e,
                    fail_closed = fail_closed,
                    "Agent processing failed"
                );
                if fail_closed {
                    return Err(Error::explain(
                        ErrorType::HTTPStatus(503),
                        "Agent processing failed",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Replace an upstream error response with the route's custom error page,
    /// when one is configured for its status.
    ///
    /// Only a configured page replaces anything. The route's error handler
    /// always exists, and its default output is meant for errors the proxy
    /// raises itself; applied here it relabelled every upstream 4xx/5xx with
    /// its own Content-Type and Content-Length while the upstream body went
    /// through, so a JSON 404 reached the client as `text/html` (#522).
    pub(super) async fn handle_error_response(
        &self,
        upstream_response: &mut ResponseHeader,
        ctx: &mut RequestContext,
    ) -> Result<(), Box<Error>> {
        let Some(ref route_id) = ctx.route_id else {
            return Ok(());
        };

        let Some(error_handler) = self.error_handlers.get(route_id).await else {
            return Ok(());
        };

        if let Some(body) =
            substitute_error_page(&error_handler, upstream_response, &ctx.trace_id).await?
        {
            debug!(
                correlation_id = %ctx.trace_id,
                route_id = route_id,
                status = upstream_response.status.as_u16(),
                "Generated custom error page"
            );
            ctx.error_page_body = Some(body);
        }

        Ok(())
    }

    /// The response for an error the proxy raises itself: the route's custom
    /// page for the status when it has one, `error`'s default otherwise, and
    /// `error`'s headers either way (#557).
    pub(super) async fn proxy_error_response(
        &self,
        ctx: &RequestContext,
        error: ProxyError<'_>,
    ) -> Result<(ResponseHeader, bytes::Bytes), Box<Error>> {
        let handler = match ctx.route_id.as_deref() {
            Some(route_id) => self.error_handlers.get(route_id).await,
            None => None,
        };
        build_proxy_error(handler.as_deref(), error, &ctx.trace_id).await
    }

    /// Act on an agent's decision in a request phase (request headers, or
    /// the request body, streamed or buffered): `Ok(())` for `Allow`, and
    /// for every other decision an `HTTPStatus` error that stops the
    /// request before it is proxied, with the response for it -- see
    /// [`AgentBlock::for_request`] -- left in `ctx.agent_block` for the
    /// error path to send.
    ///
    /// Logs the decision (a block at WARN; a redirect, and a challenge with
    /// its type, at INFO), counts refusals under `metric`, and audits it.
    pub(super) fn refuse_on_agent_request_decision(
        &self,
        ctx: &mut RequestContext,
        decision: &crate::agents::AgentDecision,
        phase: &'static str,
        metric: &str,
    ) -> Result<(), Box<Error>> {
        use crate::agents::AgentAction;

        let Some(block) = AgentBlock::for_request(&decision.action) else {
            return Ok(());
        };
        let agent_id = decision.decided_by.as_deref().unwrap_or("unknown");
        let action = AgentBlock::action_name(&decision.action);
        let (reason, default_message) = match &decision.action {
            AgentAction::Allow => return Ok(()),
            AgentAction::Block { body, .. } => {
                warn!(
                    correlation_id = %ctx.trace_id,
                    agent_id = %agent_id,
                    phase = phase,
                    status = block.status,
                    "Request blocked by agent"
                );
                self.metrics.record_blocked_request(metric);
                (
                    body.clone()
                        .unwrap_or_else(|| "Blocked by agent".to_string()),
                    "Blocked by agent",
                )
            }
            AgentAction::Redirect { url, status } => {
                info!(
                    correlation_id = %ctx.trace_id,
                    agent_id = %agent_id,
                    phase = phase,
                    url = %url,
                    requested_status = status,
                    status = block.status,
                    "Request redirected by agent"
                );
                (format!("Redirected to {url}"), "Redirected by agent")
            }
            AgentAction::Challenge {
                challenge_type,
                params,
            } => {
                // Parameter names only: their values may be tokens.
                let mut param_names: Vec<&str> = params.keys().map(String::as_str).collect();
                param_names.sort_unstable();
                info!(
                    correlation_id = %ctx.trace_id,
                    agent_id = %agent_id,
                    phase = phase,
                    challenge_type = %challenge_type,
                    params = ?param_names,
                    status = block.status,
                    "Request challenged by agent; not proxied"
                );
                self.metrics.record_blocked_request(metric);
                (
                    format!("Challenge: {challenge_type}"),
                    "Challenged by agent",
                )
            }
        };

        let mut tags: Vec<String> = decision
            .audit
            .iter()
            .flat_map(|a| a.tags.iter().cloned())
            .collect();
        if let Some(ref agent_id) = decision.decided_by {
            tags.push(format!("agent:{agent_id}"));
        }
        let rule_ids: Vec<String> = decision
            .audit
            .iter()
            .flat_map(|a| a.rule_ids.iter().cloned())
            .collect();
        let audit_entry = AuditLogEntry::new(
            &ctx.trace_id,
            AuditEventType::AgentDecision,
            &ctx.method,
            &ctx.path,
            &ctx.client_ip,
        )
        .with_route_id(ctx.route_id.as_deref().unwrap_or("unknown"))
        .with_agent_id(agent_id)
        .with_action(action)
        .with_status_code(block.status)
        .with_reason(reason)
        .with_tags(tags)
        .with_rule_ids(rule_ids)
        .with_metadata("phase", phase);
        self.log_manager.log_audit(&audit_entry);

        let status = block.status;
        let message = block
            .body
            .clone()
            .unwrap_or_else(|| default_message.to_string());
        // An agent's own body is sent as it is; without one, the route's
        // error page for the status applies (#557).
        ctx.agent_block = Some(block);
        Err(Error::explain(ErrorType::HTTPStatus(status), message))
    }

    /// Keep what an allowed request-body decision asks of the headers
    /// (#596).
    ///
    /// Its response-header changes are kept for `response_filter`, which
    /// applies them to the client's response like those from the
    /// request-headers phase. Its request-header changes cannot be applied:
    /// Pingora sends the upstream request's header (after
    /// `upstream_request_filter`) before it reads the client's body and runs
    /// `request_body_filter`, in buffer mode as in stream mode, so the
    /// upstream already has the header by the time any body decision is
    /// made. They are dropped, with a warning once per agent so that an
    /// agent relying on them is noticed; an agent that needs to change
    /// request headers does it on `request_headers`.
    pub(super) fn keep_body_phase_header_ops(
        ctx: &mut RequestContext,
        decision: &mut crate::agents::AgentDecision,
    ) {
        ctx.agent_response_headers
            .append(&mut decision.response_headers);
        if decision.request_headers.is_empty() {
            return;
        }
        let names: Vec<&str> = decision
            .request_headers
            .iter()
            .map(|op| match op {
                zentinel_agent_protocol::HeaderOp::Set { name, .. }
                | zentinel_agent_protocol::HeaderOp::Add { name, .. }
                | zentinel_agent_protocol::HeaderOp::Remove { name } => name.as_str(),
            })
            .collect();
        debug!(
            correlation_id = %ctx.trace_id,
            agents = ?decision.request_headers_from,
            headers = ?names,
            "Dropping request-header changes from the request-body phase"
        );
        for agent_id in &decision.request_headers_from {
            if first_body_phase_request_header_warning(agent_id) {
                warn!(
                    agent_id = %agent_id,
                    headers = ?names,
                    "Agent changed request headers on the request body; the upstream \
                     request's headers are already sent then, so these changes are \
                     dropped. Change request headers on request_headers instead. \
                     (Logged once per agent.)"
                );
            }
        }
        decision.request_headers.clear();
        decision.request_headers_from.clear();
    }

    /// The response answering an agent's block: the agent's own body as
    /// plain text when it gave one, else the route's page for the status, or
    /// `default` where the route has none -- with the agent's headers either
    /// way. Every agent block, in any phase, is answered through here.
    pub(super) async fn agent_block_response(
        &self,
        ctx: &RequestContext,
        block: &AgentBlock,
        default: ProxyError<'_>,
    ) -> Result<(ResponseHeader, bytes::Bytes), Box<Error>> {
        let (mut header, body) = match &block.body {
            Some(body) => {
                build_proxy_error(None, ProxyError::text(block.status, body), &ctx.trace_id).await?
            }
            None => self.proxy_error_response(ctx, default).await?,
        };
        block.apply_headers(&mut header);
        Ok((header, body))
    }

    /// Log, count and audit an agent's refusal of the upstream's response:
    /// a block (#584), redirect or challenge (#588), as a request-phase
    /// decision is. Logged at WARN with the decision type as `action`;
    /// a redirect is not counted as a blocked request, as in the request
    /// phases.
    ///
    /// `aborted` is `None` for a block on response headers, which replaced
    /// the response. For one on the response body it is the body bytes
    /// already sent to the client and those withheld: the status has
    /// usually gone out, so the response is aborted rather than replaced.
    pub(super) fn record_response_block(
        &self,
        ctx: &RequestContext,
        decision: &crate::agents::AgentDecision,
        status: u16,
        aborted: Option<(u64, usize)>,
    ) {
        let phase = if aborted.is_some() {
            "response_body"
        } else {
            "response_headers"
        };
        let agent_id = decision.decided_by.as_deref().unwrap_or("unknown");
        // The route's filter that runs this agent, for the log: a route may
        // run one agent through several filters, the first is named.
        let filter_id = ctx
            .route_config
            .as_ref()
            .zip(ctx.config.as_ref())
            .and_then(|(route, config)| {
                route.filters.iter().find(|filter_id| {
                    matches!(
                        config.filters.get(*filter_id).map(|f| &f.filter),
                        Some(zentinel_config::Filter::Agent(agent)) if agent.agent == agent_id
                    )
                })
            })
            .map(String::as_str)
            .unwrap_or("unknown");
        let action = AgentBlock::action_name(&decision.action);
        // A redirect sends the client elsewhere; it is no refusal to count.
        let counted = !matches!(decision.action, crate::agents::AgentAction::Redirect { .. });

        match aborted {
            None => {
                warn!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    agent_id = %agent_id,
                    filter_id = %filter_id,
                    action = action,
                    status = status,
                    "Response refused by agent, upstream response replaced"
                );
                if counted {
                    self.metrics
                        .record_blocked_request("agent_response_blocked");
                }
            }
            Some((bytes_sent, bytes_withheld)) => {
                warn!(
                    correlation_id = %ctx.trace_id,
                    route_id = ctx.route_id.as_deref().unwrap_or("unknown"),
                    agent_id = %agent_id,
                    filter_id = %filter_id,
                    action = action,
                    status = status,
                    body_bytes_sent = bytes_sent,
                    body_bytes_withheld = bytes_withheld,
                    "Response body refused by agent, aborting the response"
                );
                if counted {
                    self.metrics
                        .record_blocked_request("agent_response_body_blocked");
                }
            }
        }

        let mut tags: Vec<String> = decision
            .audit
            .iter()
            .flat_map(|a| a.tags.iter().cloned())
            .collect();
        tags.push(format!("agent:{agent_id}"));
        let rule_ids: Vec<String> = decision
            .audit
            .iter()
            .flat_map(|a| a.rule_ids.iter().cloned())
            .collect();
        let reason = match &decision.action {
            crate::agents::AgentAction::Block {
                body: Some(body), ..
            } => body.clone(),
            crate::agents::AgentAction::Redirect { url, .. } => format!("Redirected to {url}"),
            crate::agents::AgentAction::Challenge { challenge_type, .. } => {
                format!("Challenge: {challenge_type}")
            }
            _ => "Response blocked by agent".to_string(),
        };
        let audit_entry = AuditLogEntry::new(
            &ctx.trace_id,
            AuditEventType::AgentDecision,
            &ctx.method,
            &ctx.path,
            &ctx.client_ip,
        )
        .with_route_id(ctx.route_id.as_deref().unwrap_or("unknown"))
        .with_agent_id(agent_id)
        .with_action(action)
        .with_status_code(status)
        .with_reason(reason)
        .with_tags(tags)
        .with_rule_ids(rule_ids)
        .with_metadata("phase", phase)
        .with_metadata("filter_id", filter_id);
        let audit_entry = match aborted {
            Some((bytes_sent, _)) => {
                audit_entry.with_metadata("body_bytes_sent", bytes_sent.to_string())
            }
            None => audit_entry,
        };
        self.log_manager.log_audit(&audit_entry);
    }

    /// Answer the request with an error the proxy raises itself, through the
    /// route's error pages (see [`Self::proxy_error_response`]). The
    /// connection is not kept alive afterwards.
    ///
    /// Every refusal written from a request filter (rate limits, in-flight
    /// limit, geo, guardrail, WebSocket, agent blocks without a body of their
    /// own) goes through here, so a route's page applies to it just as it
    /// does to errors that reach `fail_to_proxy`. Before #557 only the
    /// latter used the pages.
    pub(super) async fn write_proxy_error(
        &self,
        session: &mut Session,
        ctx: &RequestContext,
        error: ProxyError<'_>,
    ) -> Result<(), Box<Error>> {
        let (header, body) = self.proxy_error_response(ctx, error).await?;
        session.set_keepalive(None);
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(body), true).await?;
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
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
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

/// Rewrite `response` into `handler`'s custom page for its status, returning
/// the page's body for `response_body_filter` to send in place of the
/// upstream's. `None` leaves the upstream response as it is.
///
/// Headers and body are replaced together: a page's Content-Type and
/// Content-Length describe the page, not whatever the upstream sent. The
/// upstream's framing and encoding headers go for the same reason.
async fn substitute_error_page(
    handler: &crate::errors::ErrorHandler,
    response: &mut ResponseHeader,
    trace_id: &str,
) -> Result<Option<bytes::Bytes>, Box<Error>> {
    let status = response.status;
    if !handler.has_custom_page(status.as_u16()) {
        return Ok(None);
    }

    let page = match handler.generate_response(status, None, trace_id, None) {
        Ok(page) => page,
        Err(e) => {
            warn!(
                correlation_id = %trace_id,
                status = status.as_u16(),
                error = %e,
                "Failed to generate custom error page, passing the upstream response through"
            );
            return Ok(None);
        }
    };

    let (parts, body) = page.into_parts();
    let body: bytes::Bytes = http_body_util::BodyExt::collect(body)
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    for name in [
        http::header::CONTENT_LENGTH,
        http::header::TRANSFER_ENCODING,
        http::header::CONTENT_ENCODING,
        http::header::ETAG,
        http::header::LAST_MODIFIED,
    ] {
        response.remove_header(&name);
    }
    for (key, value) in parts.headers.iter() {
        response.insert_header(key.clone(), value.clone())?;
    }
    response.insert_header(http::header::CONTENT_LENGTH, body.len().to_string())?;

    Ok(Some(body))
}

/// An error the proxy answers itself, and what it answers with when the
/// route has no custom page for the status.
pub(super) struct ProxyError<'a> {
    pub status: u16,
    /// The proxy's wording for this error, used in the page when the page
    /// sets no `message` of its own (the page's wins). `None` uses the
    /// status's generic wording.
    pub message: Option<&'a str>,
    /// The body sent when the route has no page for `status`.
    pub default_body: bytes::Bytes,
    /// The Content-Type of `default_body`.
    pub default_content_type: &'a str,
    /// Headers the response carries whichever body it gets (`Retry-After`,
    /// the `X-RateLimit-*` headers). Set after the page's own headers, so a
    /// page cannot replace a value the proxy computed for this request.
    pub headers: Vec<(&'static str, String)>,
}

impl<'a> ProxyError<'a> {
    /// A plain-text error whose default body is `message`.
    pub fn text(status: u16, message: &'a str) -> Self {
        Self {
            status,
            message: Some(message),
            default_body: bytes::Bytes::copy_from_slice(message.as_bytes()),
            default_content_type: "text/plain",
            headers: Vec::new(),
        }
    }

    /// Add a header the response carries whichever body it gets.
    pub fn with_header(mut self, name: &'static str, value: impl ToString) -> Self {
        self.headers.push((name, value.to_string()));
        self
    }
}

/// The headers of a rate-limit refusal: `X-RateLimit-Limit`,
/// `X-RateLimit-Remaining`, `X-RateLimit-Reset` and, when positive,
/// `Retry-After`.
pub(super) fn rate_limit_headers(
    limit: u32,
    remaining: u32,
    reset_at: u64,
    retry_after: u64,
) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("X-RateLimit-Limit", limit.to_string()),
        ("X-RateLimit-Remaining", remaining.to_string()),
        ("X-RateLimit-Reset", reset_at.to_string()),
    ];
    if retry_after > 0 {
        headers.push(("Retry-After", retry_after.to_string()));
    }
    headers
}

/// `handler`'s custom page for `status`, as a response header and body, or
/// `None` when it has no page for `status` (or the page cannot be built, which
/// is logged) and the caller's default applies.
async fn render_error_page(
    handler: &crate::errors::ErrorHandler,
    status: u16,
    message: Option<&str>,
    trace_id: &str,
) -> Option<(ResponseHeader, bytes::Bytes)> {
    if !handler.has_custom_page(status) {
        return None;
    }
    let status_code = http::StatusCode::from_u16(status).ok()?;
    let page =
        match handler.generate_response(status_code, message.map(str::to_string), trace_id, None) {
            Ok(page) => page,
            Err(e) => {
                warn!(
                    correlation_id = %trace_id,
                    status = status,
                    error = %e,
                    "Failed to generate custom error page, sending the default error body"
                );
                return None;
            }
        };
    let (parts, body) = page.into_parts();
    let body = http_body_util::BodyExt::collect(body)
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();
    let mut header = ResponseHeader::build(status, None).ok()?;
    for (key, value) in parts.headers.iter() {
        header.insert_header(key.clone(), value.clone()).ok()?;
    }
    Some((header, body))
}

/// The response for `error`: `handler`'s page for its status if there is
/// one, its default body otherwise, plus its headers, `Content-Length` and
/// `X-Correlation-Id`.
pub(super) async fn build_proxy_error(
    handler: Option<&crate::errors::ErrorHandler>,
    error: ProxyError<'_>,
    trace_id: &str,
) -> Result<(ResponseHeader, bytes::Bytes), Box<Error>> {
    let page = match handler {
        Some(handler) => render_error_page(handler, error.status, error.message, trace_id).await,
        None => None,
    };
    let (mut header, body) = match page {
        Some(page) => page,
        None => {
            let mut header = ResponseHeader::build(error.status, None)?;
            header.insert_header("Content-Type", error.default_content_type)?;
            (header, error.default_body)
        }
    };
    for (name, value) in error.headers {
        header.insert_header(name, value)?;
    }
    header.insert_header("Content-Length", body.len().to_string())?;
    header.insert_header("X-Correlation-Id", trace_id)?;
    Ok((header, body))
}

/// Whether this is the first time `agent_id` changed request headers on
/// the request body in this process; see
/// [`ZentinelProxy::keep_body_phase_header_ops`].
fn first_body_phase_request_header_warning(agent_id: &str) -> bool {
    static WARNED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::LazyLock::new(Default::default);
    WARNED
        .lock()
        .map(|mut warned| warned.insert(agent_id.to_string()))
        .unwrap_or(false)
}

/// Apply an agent's header changes to a response header.
pub(super) fn apply_agent_response_header_ops(
    response: &mut ResponseHeader,
    ops: &[zentinel_agent_protocol::HeaderOp],
) {
    for op in ops {
        match op {
            zentinel_agent_protocol::HeaderOp::Set { name, value } => {
                response.insert_header(name.clone(), value.as_str()).ok();
            }
            zentinel_agent_protocol::HeaderOp::Add { name, value } => {
                response.append_header(name.clone(), value.as_str()).ok();
            }
            zentinel_agent_protocol::HeaderOp::Remove { name } => {
                response.remove_header(name);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::ErrorHandler;
    use zentinel_config::{ErrorFormat, ErrorPage, ErrorPageConfig, ServiceType};

    fn upstream_error(status: u16, content_type: &str, body: &str) -> ResponseHeader {
        let mut resp = ResponseHeader::build(status, None).unwrap();
        resp.insert_header("Content-Type", content_type).unwrap();
        resp.insert_header("Content-Length", body.len().to_string())
            .unwrap();
        resp
    }

    fn header<'a>(resp: &'a ResponseHeader, name: &str) -> Option<&'a str> {
        resp.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// #522: with no custom page configured -- the only state the KDL config
    /// can produce today -- an upstream error keeps its own headers.
    #[tokio::test]
    async fn an_upstream_error_without_a_custom_page_is_left_untouched() {
        for service_type in [ServiceType::Web, ServiceType::Api] {
            let handler = ErrorHandler::new(service_type, None);

            for (status, content_type, body) in [
                (404, "application/json", r#"{"error":"no such user"}"#),
                (500, "text/plain", "boom"),
            ] {
                let mut resp = upstream_error(status, content_type, body);
                let replaced = substitute_error_page(&handler, &mut resp, "t")
                    .await
                    .unwrap();

                assert!(replaced.is_none());
                assert_eq!(resp.status.as_u16(), status);
                assert_eq!(header(&resp, "content-type"), Some(content_type));
                assert_eq!(
                    header(&resp, "content-length"),
                    Some(body.len().to_string().as_str())
                );
            }
        }
    }

    /// A configured page replaces headers and body together, so the headers
    /// describe the bytes the client actually receives.
    #[tokio::test]
    async fn a_custom_page_replaces_headers_and_body_together() {
        let mut pages = HashMap::new();
        pages.insert(
            503,
            ErrorPage {
                format: ErrorFormat::Text,
                template: None,
                message: None,
                headers: HashMap::new(),
            },
        );
        let handler = ErrorHandler::new(
            ServiceType::Web,
            Some(ErrorPageConfig {
                pages,
                default_format: ErrorFormat::Html,
                include_stack_trace: false,
                template_dir: None,
            }),
        );

        let mut resp = upstream_error(503, "application/json", r#"{"down":true}"#);
        resp.insert_header("Content-Encoding", "gzip").unwrap();
        let body = substitute_error_page(&handler, &mut resp, "t")
            .await
            .unwrap()
            .expect("a configured page replaces the response");

        assert_eq!(resp.status.as_u16(), 503);
        assert_eq!(
            header(&resp, "content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(
            header(&resp, "content-length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(header(&resp, "content-encoding"), None);

        // Statuses without a page of their own still pass through.
        let mut other = upstream_error(404, "application/json", "{}");
        assert!(substitute_error_page(&handler, &mut other, "t")
            .await
            .unwrap()
            .is_none());
        assert_eq!(header(&other, "content-type"), Some("application/json"));
    }

    /// #542: a route's `error-pages` block reaches the error handler. No KDL
    /// parser read it before, so no page could be configured and upstream
    /// errors always passed through.
    #[tokio::test]
    async fn a_page_configured_in_kdl_replaces_the_upstream_error() {
        let config = zentinel_config::Config::from_kdl(
            r#"
            system { worker-threads 1 }
            listeners {
                listener "http" {
                    address "127.0.0.1:8080"
                    protocol "http"
                }
            }
            upstreams {
                upstream "u" {
                    target "127.0.0.1:9" { weight 1 }
                }
            }
            routes {
                route "r" {
                    matches { path-prefix "/" }
                    upstream "u"
                    error-pages {
                        pages {
                            "404" {
                                format "json"
                                message "No such thing here"
                                headers {
                                    Cache-Control "no-store"
                                }
                            }
                        }
                    }
                }
            }
            "#,
        )
        .expect("config loads");
        let route = &config.routes[0];
        let handler = ErrorHandler::new(route.service_type.clone(), route.error_pages.clone());

        let mut resp = upstream_error(404, "text/html", "<h1>nginx 404</h1>");
        let body = substitute_error_page(&handler, &mut resp, "trace-1")
            .await
            .unwrap()
            .expect("the configured 404 page replaces the upstream's");
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "No such thing here");
        assert_eq!(
            header(&resp, "content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(header(&resp, "cache-control"), Some("no-store"));

        // A status without a page is still the upstream's own (#522).
        let mut other = upstream_error(500, "text/plain", "boom");
        assert!(substitute_error_page(&handler, &mut other, "t")
            .await
            .unwrap()
            .is_none());
        assert_eq!(header(&other, "content-type"), Some("text/plain"));
    }

    fn handler_with_pages(pages: Vec<(u16, ErrorPage)>) -> ErrorHandler {
        ErrorHandler::new(
            ServiceType::Web,
            Some(ErrorPageConfig {
                pages: pages.into_iter().collect(),
                default_format: ErrorFormat::Html,
                include_stack_trace: false,
                template_dir: None,
            }),
        )
    }

    fn json_page(message: Option<&str>, headers: &[(&str, &str)]) -> ErrorPage {
        ErrorPage {
            format: ErrorFormat::Json,
            template: None,
            message: message.map(str::to_string),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn rate_limited(body: &str) -> ProxyError<'_> {
        ProxyError {
            default_content_type: "text/plain; charset=utf-8",
            headers: rate_limit_headers(10, 0, 1_700_000_000, 7),
            ..ProxyError::text(429, body)
        }
    }

    /// #557: a refusal the proxy writes itself (here a rate limit) gets the
    /// route's page for its status, and keeps the headers the refusal
    /// needs. A page header of the same name does not replace the value the
    /// proxy computed for the request.
    #[tokio::test]
    async fn a_proxy_refusal_uses_the_routes_page_and_keeps_its_headers() {
        let handler = handler_with_pages(vec![(
            429,
            json_page(
                Some("Slow down"),
                &[("Retry-After", "999"), ("Cache-Control", "no-store")],
            ),
        )]);

        let (resp, body) = build_proxy_error(
            Some(&handler),
            rate_limited("Rate limit exceeded"),
            "trace-1",
        )
        .await
        .unwrap();

        assert_eq!(resp.status.as_u16(), 429);
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Slow down");
        assert_eq!(
            header(&resp, "content-type"),
            Some("application/json; charset=utf-8")
        );
        assert_eq!(header(&resp, "cache-control"), Some("no-store"));
        assert_eq!(header(&resp, "retry-after"), Some("7"));
        assert_eq!(header(&resp, "x-ratelimit-limit"), Some("10"));
        assert_eq!(header(&resp, "x-ratelimit-remaining"), Some("0"));
        assert_eq!(header(&resp, "x-ratelimit-reset"), Some("1700000000"));
        assert_eq!(
            header(&resp, "content-length"),
            Some(body.len().to_string().as_str())
        );
        assert_eq!(header(&resp, "x-correlation-id"), Some("trace-1"));
    }

    /// A status without a page keeps the refusal's own default body and
    /// Content-Type, with its headers.
    #[tokio::test]
    async fn a_proxy_refusal_without_a_page_keeps_its_default() {
        let handler = handler_with_pages(vec![(503, json_page(None, &[]))]);

        for handler in [Some(&handler), None] {
            let (resp, body) = build_proxy_error(handler, rate_limited("Rate limit exceeded"), "t")
                .await
                .unwrap();

            assert_eq!(resp.status.as_u16(), 429);
            assert_eq!(&body[..], b"Rate limit exceeded");
            assert_eq!(
                header(&resp, "content-type"),
                Some("text/plain; charset=utf-8")
            );
            assert_eq!(header(&resp, "retry-after"), Some("7"));
            assert_eq!(header(&resp, "content-length"), Some("19"));
        }
    }

    /// The proxy's wording for the refusal fills a page that sets no message
    /// of its own; a page's message wins over it.
    #[tokio::test]
    async fn the_refusals_message_fills_a_page_without_one() {
        let handler = handler_with_pages(vec![
            (403, json_page(None, &[])),
            (451, json_page(Some("Not here"), &[])),
        ]);

        let (_, body) = build_proxy_error(
            Some(&handler),
            ProxyError::text(403, "WebSocket not enabled for this route"),
            "t",
        )
        .await
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "WebSocket not enabled for this route");

        let (_, body) =
            build_proxy_error(Some(&handler), ProxyError::text(451, "Access denied"), "t")
                .await
                .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "Not here");
    }

    #[test]
    fn retry_after_is_left_out_when_not_positive() {
        let headers = rate_limit_headers(5, 1, 42, 0);
        assert!(headers.iter().all(|(name, _)| *name != "Retry-After"));
        assert_eq!(headers.len(), 3);
    }
}
