//! Route KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::trace;

use zentinel_common::budget::{
    BudgetPeriod, CostAttributionConfig, ModelPricing, TokenBudgetConfig,
};

use crate::routes::*;

use super::helpers::{
    get_bool_entry, get_first_arg_string, get_float_entry, get_int_entry, get_string_entry,
};

/// Parse routes configuration block
pub fn parse_routes(node: &kdl::KdlNode) -> Result<Vec<RouteConfig>> {
    trace!("Parsing routes configuration block");
    let mut routes = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "route" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!("Route requires an ID argument, e.g., route \"api\" {{ ... }}")
                })?;

                trace!(route_id = %id, "Parsing route");

                // Parse matches
                let matches = parse_match_conditions(child)?;

                // Parse priority
                let priority = parse_priority(child);

                // Parse upstream
                let upstream = parse_upstream_ref(child);

                // Parse static-files
                let static_files = parse_static_file_config_opt(child)?;

                // Parse api-schema
                let api_schema = parse_api_schema_config_opt(child)?;

                // Parse inference config
                let inference = parse_inference_config_opt(child)?;

                // Parse filters
                let filters = parse_route_filter_refs(child)?;

                // Parse builtin-handler
                let builtin_handler =
                    get_string_entry(child, "builtin-handler").and_then(|s| match s.as_str() {
                        "status" => Some(BuiltinHandler::Status),
                        "health" => Some(BuiltinHandler::Health),
                        "metrics" => Some(BuiltinHandler::Metrics),
                        "not-found" | "not_found" => Some(BuiltinHandler::NotFound),
                        "config" => Some(BuiltinHandler::Config),
                        "upstreams" => Some(BuiltinHandler::Upstreams),
                        "cache-purge" | "cache_purge" => Some(BuiltinHandler::CachePurge),
                        "cache-stats" | "cache_stats" => Some(BuiltinHandler::CacheStats),
                        _ => None,
                    });

                // Parse cache configuration
                let cache_config = parse_cache_config_opt(child)?;

                // Parse shadow (traffic mirroring) configuration
                let shadow = parse_shadow_config_opt(child)?;

                // Determine service type
                let service_type = if static_files.is_some() {
                    ServiceType::Static
                } else if builtin_handler.is_some() {
                    ServiceType::Builtin
                } else if api_schema.is_some() {
                    ServiceType::Api
                } else if inference.is_some() {
                    ServiceType::Inference
                } else {
                    ServiceType::Web
                };

                trace!(
                    route_id = %id,
                    service_type = ?service_type,
                    match_count = matches.len(),
                    filter_count = filters.len(),
                    has_upstream = upstream.is_some(),
                    "Parsed route"
                );

                // Parse policies block (request-headers, response-headers, etc.)
                let (request_headers, response_headers) =
                    parse_route_header_policies(child)?;

                // Build route policies with optional cache config
                let policies = RoutePolicies {
                    request_headers,
                    response_headers,
                    cache: cache_config,
                    ..RoutePolicies::default()
                };

                routes.push(RouteConfig {
                    id,
                    priority,
                    matches,
                    upstream,
                    service_type,
                    policies,
                    filters,
                    builtin_handler,
                    waf_enabled: get_bool_entry(child, "waf-enabled").unwrap_or(false),
                    circuit_breaker: None,
                    retry_policy: None,
                    static_files,
                    api_schema,
                    inference,
                    error_pages: None,
                    websocket: get_bool_entry(child, "websocket").unwrap_or(false),
                    websocket_inspection: get_bool_entry(child, "websocket-inspection")
                        .unwrap_or(false),
                    shadow,
                    fallback: parse_fallback_config_opt(child)?,
                });
            }
        }
    }

    trace!(route_count = routes.len(), "Finished parsing routes");
    Ok(routes)
}

fn parse_match_conditions(node: &kdl::KdlNode) -> Result<Vec<MatchCondition>> {
    let mut matches = Vec::new();

    if let Some(route_children) = node.children() {
        if let Some(matches_node) = route_children.get("matches") {
            if let Some(match_children) = matches_node.children() {
                for match_node in match_children.nodes() {
                    match match_node.name().value() {
                        "path-prefix" => {
                            if let Some(prefix) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::PathPrefix(prefix));
                            }
                        }
                        "path" => {
                            if let Some(path) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::Path(path));
                            }
                        }
                        "host" => {
                            if let Some(host) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::Host(host));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(matches)
}

fn parse_priority(node: &kdl::KdlNode) -> zentinel_common::types::Priority {
    match get_string_entry(node, "priority").as_deref() {
        Some("high") => zentinel_common::types::Priority::High,
        Some("low") => zentinel_common::types::Priority::Low,
        _ => zentinel_common::types::Priority::Normal,
    }
}

fn parse_upstream_ref(node: &kdl::KdlNode) -> Option<String> {
    if let Some(route_children) = node.children() {
        if let Some(upstream_node) = route_children.get("upstream") {
            let entry = upstream_node.entries().first();
            if let Some(s) = entry.and_then(|e| e.value().as_string()) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn parse_static_file_config_opt(node: &kdl::KdlNode) -> Result<Option<StaticFileConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(static_node) = route_children.get("static-files") {
            return Ok(Some(parse_static_file_config(static_node)?));
        }
    }
    Ok(None)
}

fn parse_route_filter_refs(node: &kdl::KdlNode) -> Result<Vec<String>> {
    let mut filter_ids = Vec::new();

    if let Some(route_children) = node.children() {
        if let Some(filters_node) = route_children.get("filters") {
            for entry in filters_node.entries() {
                if let Some(id) = entry.value().as_string() {
                    filter_ids.push(id.to_string());
                }
            }
        }
    }

    Ok(filter_ids)
}

/// Parse route-level header policies from the `policies` block.
///
/// Example KDL:
/// ```kdl
/// policies {
///     request-headers {
///         rename {
///             X-Old-Name "X-New-Name"
///         }
///         set {
///             X-Custom "value"
///         }
///         add {
///             X-Extra "extra"
///         }
///         remove "X-Internal"
///     }
///     response-headers {
///         set {
///             X-Powered-By "Zentinel"
///         }
///     }
/// }
/// ```
fn parse_route_header_policies(
    node: &kdl::KdlNode,
) -> Result<(HeaderModifications, HeaderModifications)> {
    let mut request_headers = HeaderModifications::default();
    let mut response_headers = HeaderModifications::default();

    if let Some(route_children) = node.children() {
        if let Some(policies_node) = route_children.get("policies") {
            if let Some(policy_children) = policies_node.children() {
                if let Some(req_node) = policy_children.get("request-headers") {
                    request_headers = parse_header_modifications(req_node)?;
                }
                if let Some(resp_node) = policy_children.get("response-headers") {
                    response_headers = parse_header_modifications(resp_node)?;
                }
            }
        }
    }

    Ok((request_headers, response_headers))
}

/// Parse a header modifications block (rename, set, add, remove).
fn parse_header_modifications(node: &kdl::KdlNode) -> Result<HeaderModifications> {
    let mut rename = HashMap::new();
    let mut set = HashMap::new();
    let mut add = HashMap::new();
    let mut remove = Vec::new();

    if let Some(children) = node.children() {
        if let Some(rename_node) = children.get("rename") {
            if let Some(rename_children) = rename_node.children() {
                for entry_node in rename_children.nodes() {
                    let old_name = entry_node.name().value().to_string();
                    if let Some(new_name) = get_first_arg_string(entry_node) {
                        rename.insert(old_name, new_name);
                    }
                }
            }
        }
        if let Some(set_node) = children.get("set") {
            if let Some(set_children) = set_node.children() {
                for entry_node in set_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        set.insert(name, value);
                    }
                }
            }
        }
        if let Some(add_node) = children.get("add") {
            if let Some(add_children) = add_node.children() {
                for entry_node in add_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        add.insert(name, value);
                    }
                }
            }
        }
        if let Some(remove_node) = children.get("remove") {
            for entry in remove_node.entries() {
                if let Some(name) = entry.value().as_string() {
                    remove.push(name.to_string());
                }
            }
        }
    }

    Ok(HeaderModifications {
        rename,
        set,
        add,
        remove,
    })
}

/// Parse static file configuration block
pub fn parse_static_file_config(node: &kdl::KdlNode) -> Result<StaticFileConfig> {
    let root = get_string_entry(node, "root").ok_or_else(|| {
        anyhow::anyhow!(
            "Static files configuration requires a 'root' directory, e.g., root \"/var/www/html\""
        )
    })?;

    Ok(StaticFileConfig {
        root: PathBuf::from(root),
        index: get_string_entry(node, "index").unwrap_or_else(|| "index.html".to_string()),
        directory_listing: get_bool_entry(node, "directory-listing").unwrap_or(false),
        cache_control: get_string_entry(node, "cache-control")
            .unwrap_or_else(|| "public, max-age=3600".to_string()),
        compress: get_bool_entry(node, "compress").unwrap_or(true),
        mime_types: HashMap::new(),
        fallback: get_string_entry(node, "fallback"),
    })
}

/// Parse optional cache configuration from a route
fn parse_cache_config_opt(node: &kdl::KdlNode) -> Result<Option<RouteCacheConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(cache_node) = route_children.get("cache") {
            return Ok(Some(parse_cache_config(cache_node)?));
        }
    }
    Ok(None)
}

/// Parse cache configuration block
///
/// Example KDL:
/// ```kdl
/// cache {
///     enabled true
///     default-ttl-secs 3600
///     max-size-bytes 10485760
///     cache-private false
///     stale-while-revalidate-secs 60
///     stale-if-error-secs 300
///     cacheable-methods "GET" "HEAD"
///     cacheable-status-codes 200 203 204 206 300 301 308 404 410
///     vary-headers "Accept" "Accept-Encoding"
///     ignore-query-params "utm_source" "utm_medium"
/// }
/// ```
fn parse_cache_config(node: &kdl::KdlNode) -> Result<RouteCacheConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);
    let default_ttl_secs = get_int_entry(node, "default-ttl-secs").unwrap_or(3600) as u64;
    let max_size_bytes = get_int_entry(node, "max-size-bytes").unwrap_or(10 * 1024 * 1024) as usize;
    let cache_private = get_bool_entry(node, "cache-private").unwrap_or(false);
    let stale_while_revalidate_secs =
        get_int_entry(node, "stale-while-revalidate-secs").unwrap_or(60) as u64;
    let stale_if_error_secs = get_int_entry(node, "stale-if-error-secs").unwrap_or(300) as u64;

    // Parse cacheable methods (string arguments)
    let cacheable_methods = if let Some(children) = node.children() {
        if let Some(methods_node) = children.get("cacheable-methods") {
            methods_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            vec!["GET".to_string(), "HEAD".to_string()]
        }
    } else {
        vec!["GET".to_string(), "HEAD".to_string()]
    };

    // Parse cacheable status codes (integer arguments)
    let cacheable_status_codes = if let Some(children) = node.children() {
        if let Some(codes_node) = children.get("cacheable-status-codes") {
            codes_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                .collect()
        } else {
            vec![200, 203, 204, 206, 300, 301, 308, 404, 410]
        }
    } else {
        vec![200, 203, 204, 206, 300, 301, 308, 404, 410]
    };

    // Parse vary headers
    let vary_headers = if let Some(children) = node.children() {
        if let Some(vary_node) = children.get("vary-headers") {
            vary_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Parse ignore query params
    let ignore_query_params = if let Some(children) = node.children() {
        if let Some(ignore_node) = children.get("ignore-query-params") {
            ignore_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    trace!(
        enabled = enabled,
        default_ttl = default_ttl_secs,
        max_size = max_size_bytes,
        "Parsed cache configuration"
    );

    Ok(RouteCacheConfig {
        enabled,
        default_ttl_secs,
        max_size_bytes,
        cache_private,
        stale_while_revalidate_secs,
        stale_if_error_secs,
        cacheable_methods,
        cacheable_status_codes,
        vary_headers,
        ignore_query_params,
    })
}

/// Parse optional API schema configuration from a route
fn parse_api_schema_config_opt(node: &kdl::KdlNode) -> Result<Option<ApiSchemaConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(api_schema_node) = route_children.get("api-schema") {
            return Ok(Some(parse_api_schema_config(api_schema_node)?));
        }
    }
    Ok(None)
}

/// Parse API schema configuration block
///
/// Example KDL with external file:
/// ```kdl
/// api-schema {
///     schema-file "/etc/zentinel/schemas/api-v1.yaml"
///     validate-requests #true
///     validate-responses #false
///     strict-mode #false
/// }
/// ```
///
/// Example KDL with inline OpenAPI spec:
/// ```kdl
/// api-schema {
///     validate-requests #true
///     schema-content r#"
/// openapi: 3.0.0
/// info:
///   title: User API
///   version: 1.0.0
/// paths:
///   /api/users:
///     post:
///       requestBody:
///         content:
///           application/json:
///             schema:
///               type: object
///               required: [email, password]
///               properties:
///                 email: { type: string, format: email }
///                 password: { type: string, minLength: 8 }
///     "#
/// }
/// ```
///
/// Example KDL with inline JSON schema:
/// ```kdl
/// api-schema {
///     validate-requests #true
///     request-schema {
///         type "object"
///         properties {
///             email {
///                 type "string"
///             }
///             password {
///                 type "string"
///                 minLength 8
///             }
///         }
///         required "email" "password"
///     }
/// }
/// ```
fn parse_api_schema_config(node: &kdl::KdlNode) -> Result<ApiSchemaConfig> {
    let schema_file = get_string_entry(node, "schema-file").map(PathBuf::from);
    let schema_content = get_string_entry(node, "schema-content");
    let validate_requests = get_bool_entry(node, "validate-requests").unwrap_or(true);
    let validate_responses = get_bool_entry(node, "validate-responses").unwrap_or(false);
    let strict_mode = get_bool_entry(node, "strict-mode").unwrap_or(false);

    // Validate mutually exclusive options
    if schema_file.is_some() && schema_content.is_some() {
        return Err(anyhow::anyhow!(
            "schema-file and schema-content are mutually exclusive. Use one or the other."
        ));
    }

    // Parse inline request schema if present
    let request_schema = if let Some(children) = node.children() {
        if let Some(schema_node) = children.get("request-schema") {
            Some(super::kdl_to_json(schema_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse inline response schema if present
    let response_schema = if let Some(children) = node.children() {
        if let Some(schema_node) = children.get("response-schema") {
            Some(super::kdl_to_json(schema_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        has_schema_file = schema_file.is_some(),
        has_schema_content = schema_content.is_some(),
        has_request_schema = request_schema.is_some(),
        has_response_schema = response_schema.is_some(),
        validate_requests = validate_requests,
        validate_responses = validate_responses,
        strict_mode = strict_mode,
        "Parsed API schema configuration"
    );

    Ok(ApiSchemaConfig {
        schema_file,
        schema_content,
        request_schema,
        response_schema,
        validate_requests,
        validate_responses,
        strict_mode,
    })
}

/// Parse optional shadow (traffic mirroring) configuration from a route
fn parse_shadow_config_opt(node: &kdl::KdlNode) -> Result<Option<ShadowConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(shadow_node) = route_children.get("shadow") {
            return Ok(Some(parse_shadow_config(shadow_node)?));
        }
    }
    Ok(None)
}

/// Parse shadow (traffic mirroring) configuration block
///
/// Example KDL:
/// ```kdl
/// shadow {
///     upstream "canary"
///     percentage 10.0
///     sample-header "X-Debug-Shadow" "true"
///     timeout-ms 5000
///     buffer-body #true
///     max-body-bytes 1048576
/// }
/// ```
fn parse_shadow_config(node: &kdl::KdlNode) -> Result<ShadowConfig> {
    // Upstream is required
    let upstream = get_string_entry(node, "upstream").ok_or_else(|| {
        anyhow::anyhow!(
            "Shadow configuration requires an 'upstream' field, e.g., upstream \"canary\""
        )
    })?;

    let percentage = if let Some(pct_str) = get_string_entry(node, "percentage") {
        pct_str.parse::<f64>().unwrap_or(100.0)
    } else {
        get_int_entry(node, "percentage")
            .map(|v| v as f64)
            .unwrap_or(100.0)
    };

    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(5000) as u64;
    let buffer_body = get_bool_entry(node, "buffer-body").unwrap_or(false);
    let max_body_bytes = get_int_entry(node, "max-body-bytes").unwrap_or(1048576) as usize;

    // Parse sample-header if present (tuple of name, value)
    let sample_header = if let Some(children) = node.children() {
        if let Some(header_node) = children.get("sample-header") {
            let entries: Vec<_> = header_node.entries().iter().collect();
            if entries.len() >= 2 {
                let name = entries[0]
                    .value()
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("sample-header name must be a string"))?;
                let value = entries[1]
                    .value()
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("sample-header value must be a string"))?;
                Some((name.to_string(), value.to_string()))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        upstream = %upstream,
        percentage = percentage,
        timeout_ms = timeout_ms,
        buffer_body = buffer_body,
        max_body_bytes = max_body_bytes,
        has_sample_header = sample_header.is_some(),
        "Parsed shadow configuration"
    );

    Ok(ShadowConfig {
        upstream,
        percentage,
        sample_header,
        timeout_ms,
        buffer_body,
        max_body_bytes,
    })
}

/// Parse optional fallback configuration from a route
fn parse_fallback_config_opt(node: &kdl::KdlNode) -> Result<Option<FallbackConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(fallback_node) = route_children.get("fallback") {
            return Ok(Some(parse_fallback_config(fallback_node)?));
        }
    }
    Ok(None)
}

/// Parse fallback configuration block
///
/// Example KDL:
/// ```kdl
/// fallback {
///     max-attempts 2
///
///     triggers {
///         on-health-failure true
///         on-budget-exhausted true
///         on-latency-threshold-ms 5000
///         on-error-codes 429 500 502 503 504
///         on-connection-error true
///     }
///
///     fallback-upstream "anthropic-fallback" {
///         provider "anthropic"
///         skip-if-unhealthy true
///
///         model-mapping {
///             "gpt-4" "claude-3-opus"
///             "gpt-4o" "claude-3-5-sonnet"
///         }
///     }
/// }
/// ```
fn parse_fallback_config(node: &kdl::KdlNode) -> Result<FallbackConfig> {
    let max_attempts = get_int_entry(node, "max-attempts").unwrap_or(3) as u32;

    // Parse triggers
    let triggers = if let Some(children) = node.children() {
        if let Some(triggers_node) = children.get("triggers") {
            parse_fallback_triggers(triggers_node)?
        } else {
            FallbackTriggers::default()
        }
    } else {
        FallbackTriggers::default()
    };

    // Parse fallback upstreams
    let upstreams = parse_fallback_upstreams(node)?;

    trace!(
        max_attempts = max_attempts,
        upstream_count = upstreams.len(),
        on_health_failure = triggers.on_health_failure,
        on_connection_error = triggers.on_connection_error,
        "Parsed fallback configuration"
    );

    Ok(FallbackConfig {
        upstreams,
        triggers,
        max_attempts,
    })
}

/// Parse fallback triggers block
fn parse_fallback_triggers(node: &kdl::KdlNode) -> Result<FallbackTriggers> {
    let on_health_failure = get_bool_entry(node, "on-health-failure").unwrap_or(true);
    let on_budget_exhausted = get_bool_entry(node, "on-budget-exhausted").unwrap_or(false);
    let on_latency_threshold_ms = get_int_entry(node, "on-latency-threshold-ms").map(|v| v as u64);
    let on_connection_error = get_bool_entry(node, "on-connection-error").unwrap_or(true);

    // Parse error codes (integer arguments)
    let on_error_codes = if let Some(children) = node.children() {
        if let Some(codes_node) = children.get("on-error-codes") {
            codes_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        // Also check for inline arguments
        node.children()
            .and_then(|c| c.get("on-error-codes"))
            .map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(FallbackTriggers {
        on_health_failure,
        on_budget_exhausted,
        on_latency_threshold_ms,
        on_error_codes,
        on_connection_error,
    })
}

/// Parse fallback upstreams from fallback block
fn parse_fallback_upstreams(node: &kdl::KdlNode) -> Result<Vec<FallbackUpstream>> {
    let mut upstreams = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "fallback-upstream" {
                let upstream_id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "fallback-upstream requires an upstream ID, e.g., fallback-upstream \"anthropic\" {{ ... }}"
                    )
                })?;

                let provider = parse_inference_provider(child);
                let skip_if_unhealthy = get_bool_entry(child, "skip-if-unhealthy").unwrap_or(false);
                let model_mapping = parse_model_mapping(child)?;

                trace!(
                    upstream = %upstream_id,
                    provider = ?provider,
                    skip_if_unhealthy = skip_if_unhealthy,
                    model_mapping_count = model_mapping.len(),
                    "Parsed fallback upstream"
                );

                upstreams.push(FallbackUpstream {
                    upstream: upstream_id,
                    provider,
                    model_mapping,
                    skip_if_unhealthy,
                });
            }
        }
    }

    Ok(upstreams)
}

/// Parse model mapping block
///
/// Example KDL:
/// ```kdl
/// model-mapping {
///     "gpt-4" "claude-3-opus"
///     "gpt-4o" "claude-3-5-sonnet"
/// }
/// ```
fn parse_model_mapping(node: &kdl::KdlNode) -> Result<HashMap<String, String>> {
    let mut mapping = HashMap::new();

    if let Some(children) = node.children() {
        if let Some(mapping_node) = children.get("model-mapping") {
            if let Some(mapping_children) = mapping_node.children() {
                for entry_node in mapping_children.nodes() {
                    // Each node is like: "gpt-4" "claude-3-opus"
                    let entries: Vec<_> = entry_node
                        .entries()
                        .iter()
                        .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                        .collect();

                    // The node name is the source model, first entry is target
                    let source = entry_node.name().value().to_string();
                    if let Some(target) = entries.first() {
                        mapping.insert(source, target.clone());
                    }
                }
            }

            // Also handle inline format: model-mapping { "gpt-4" "claude-3-opus" }
            // where entries are pairs
            let entries: Vec<_> = mapping_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect();

            // Process pairs
            for chunk in entries.chunks(2) {
                if chunk.len() == 2 {
                    mapping.insert(chunk[0].clone(), chunk[1].clone());
                }
            }
        }
    }

    Ok(mapping)
}

/// Parse inference provider from node
fn parse_inference_provider(node: &kdl::KdlNode) -> InferenceProvider {
    match get_string_entry(node, "provider").as_deref() {
        Some("openai") => InferenceProvider::OpenAi,
        Some("anthropic") => InferenceProvider::Anthropic,
        _ => InferenceProvider::Generic,
    }
}

/// Parse optional model routing configuration from an inference block.
///
/// Example KDL:
/// ```kdl
/// model-routing {
///     model "gpt-4" upstream="openai-primary"
///     model "gpt-4*" upstream="openai-primary"
///     model "claude-*" upstream="anthropic-backend" provider="anthropic"
///     default-upstream "openai-primary"
/// }
/// ```
fn parse_model_routing_config_opt(node: &kdl::KdlNode) -> Result<Option<ModelRoutingConfig>> {
    if let Some(children) = node.children() {
        if let Some(routing_node) = children.get("model-routing") {
            return Ok(Some(parse_model_routing_config(routing_node)?));
        }
    }
    Ok(None)
}

/// Parse model routing configuration block.
fn parse_model_routing_config(node: &kdl::KdlNode) -> Result<ModelRoutingConfig> {
    let mut mappings = Vec::new();
    let mut default_upstream = None;

    // Get default-upstream if present (as entry or child)
    if let Some(def) = get_string_entry(node, "default-upstream") {
        default_upstream = Some(def);
    }

    // Parse children
    if let Some(children) = node.children() {
        // Check for default-upstream as a child node
        if let Some(def_node) = children.get("default-upstream") {
            if let Some(first_entry) = def_node.entries().first() {
                if let Some(val) = first_entry.value().as_string() {
                    default_upstream = Some(val.to_string());
                }
            }
        }

        // Parse model entries
        for model_node in children.nodes() {
            if model_node.name().value() == "model" {
                if let Some(mapping) = parse_model_upstream_mapping(model_node)? {
                    mappings.push(mapping);
                }
            }
        }
    }

    tracing::trace!(
        mappings_count = mappings.len(),
        default_upstream = ?default_upstream,
        "Parsed model routing configuration"
    );

    Ok(ModelRoutingConfig {
        mappings,
        default_upstream,
    })
}

/// Parse a single model-to-upstream mapping entry.
///
/// Example KDL:
/// ```kdl
/// model "gpt-4" upstream="openai-primary"
/// model "claude-*" upstream="anthropic-backend" provider="anthropic"
/// ```
fn parse_model_upstream_mapping(node: &kdl::KdlNode) -> Result<Option<ModelUpstreamMapping>> {
    // Get the model pattern from the first positional entry (no name)
    let model_pattern = node
        .entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string());

    let model_pattern = match model_pattern {
        Some(p) => p,
        None => return Ok(None), // No model pattern specified
    };

    // Get upstream from inline entry (e.g., upstream="openai-primary")
    let upstream = node
        .entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some("upstream"))
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Model mapping requires 'upstream' attribute"))?;

    // Get optional provider override from inline entry
    let provider_str = node
        .entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some("provider"))
        .and_then(|e| e.value().as_string());

    let provider = match provider_str {
        Some("openai") => Some(InferenceProvider::OpenAi),
        Some("anthropic") => Some(InferenceProvider::Anthropic),
        Some("generic") => Some(InferenceProvider::Generic),
        Some(_) | None => None,
    };

    tracing::trace!(
        model_pattern = %model_pattern,
        upstream = %upstream,
        provider = ?provider,
        "Parsed model upstream mapping"
    );

    Ok(Some(ModelUpstreamMapping {
        model_pattern,
        upstream,
        provider,
    }))
}

/// Parse optional inference configuration from a route
fn parse_inference_config_opt(node: &kdl::KdlNode) -> Result<Option<InferenceConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(inference_node) = route_children.get("inference") {
            return Ok(Some(parse_inference_config(inference_node)?));
        }
    }
    Ok(None)
}

/// Parse inference configuration block
///
/// Example KDL:
/// ```kdl
/// inference {
///     provider "openai"
///     model-header "x-model"
///
///     rate-limit {
///         tokens-per-minute 100000
///         requests-per-minute 500
///         burst-tokens 10000
///         estimation-method "chars"
///     }
///
///     routing {
///         strategy "least-tokens-queued"
///         queue-depth-header "x-queue-depth"
///     }
/// }
/// ```
fn parse_inference_config(node: &kdl::KdlNode) -> Result<InferenceConfig> {
    // Parse provider
    let provider = match get_string_entry(node, "provider").as_deref() {
        Some("openai") | Some("open-ai") | Some("open_ai") => InferenceProvider::OpenAi,
        Some("anthropic") => InferenceProvider::Anthropic,
        Some("generic") | None => InferenceProvider::Generic,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown inference provider '{}'. Valid providers: openai, anthropic, generic",
                other
            ));
        }
    };

    let model_header = get_string_entry(node, "model-header");

    // Parse rate-limit sub-block
    let rate_limit = if let Some(children) = node.children() {
        if let Some(rl_node) = children.get("rate-limit") {
            Some(parse_token_rate_limit(rl_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse routing sub-block
    let routing = if let Some(children) = node.children() {
        if let Some(routing_node) = children.get("routing") {
            Some(parse_inference_routing(routing_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse budget sub-block
    let budget = if let Some(children) = node.children() {
        if let Some(budget_node) = children.get("budget") {
            Some(parse_token_budget(budget_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse cost-attribution sub-block
    let cost_attribution = if let Some(children) = node.children() {
        if let Some(cost_node) = children.get("cost-attribution") {
            Some(parse_cost_attribution(cost_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        provider = ?provider,
        has_rate_limit = rate_limit.is_some(),
        has_routing = routing.is_some(),
        has_budget = budget.is_some(),
        has_cost = cost_attribution.is_some(),
        "Parsed inference configuration"
    );

    // Parse model-routing block if present
    let model_routing = parse_model_routing_config_opt(node)?;

    // Parse guardrails block if present
    let guardrails = parse_guardrails_config_opt(node)?;

    Ok(InferenceConfig {
        provider,
        model_header,
        rate_limit,
        budget,
        cost_attribution,
        routing,
        model_routing,
        guardrails,
    })
}

/// Parse token rate limit configuration
fn parse_token_rate_limit(node: &kdl::KdlNode) -> Result<TokenRateLimit> {
    let tokens_per_minute = get_int_entry(node, "tokens-per-minute")
        .ok_or_else(|| anyhow::anyhow!("Token rate limit requires 'tokens-per-minute'"))?
        as u64;

    let requests_per_minute = get_int_entry(node, "requests-per-minute").map(|v| v as u64);

    let burst_tokens = get_int_entry(node, "burst-tokens").unwrap_or(10000) as u64;

    let estimation_method = match get_string_entry(node, "estimation-method").as_deref() {
        Some("chars") | Some("characters") | None => TokenEstimation::Chars,
        Some("words") => TokenEstimation::Words,
        Some("tiktoken") => TokenEstimation::Tiktoken,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown token estimation method '{}'. Valid methods: chars, words, tiktoken",
                other
            ));
        }
    };

    Ok(TokenRateLimit {
        tokens_per_minute,
        requests_per_minute,
        burst_tokens,
        estimation_method,
    })
}

/// Parse inference routing configuration
fn parse_inference_routing(node: &kdl::KdlNode) -> Result<InferenceRouting> {
    let strategy = match get_string_entry(node, "strategy").as_deref() {
        Some("least-tokens-queued") | Some("least_tokens_queued") | None => {
            InferenceRoutingStrategy::LeastTokensQueued
        }
        Some("round-robin") | Some("round_robin") => InferenceRoutingStrategy::RoundRobin,
        Some("least-latency") | Some("least_latency") => InferenceRoutingStrategy::LeastLatency,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown inference routing strategy '{}'. Valid strategies: least-tokens-queued, round-robin, least-latency",
                other
            ));
        }
    };

    let queue_depth_header = get_string_entry(node, "queue-depth-header");

    Ok(InferenceRouting {
        strategy,
        queue_depth_header,
    })
}

/// Parse token budget configuration
///
/// KDL format:
/// ```kdl
/// budget {
///     period "daily"
///     limit 1000000
///     alert-thresholds 0.80 0.90 0.95
///     enforce true
///     rollover false
///     burst-allowance 0.10
/// }
/// ```
fn parse_token_budget(node: &kdl::KdlNode) -> Result<TokenBudgetConfig> {
    let period = match get_string_entry(node, "period").as_deref() {
        Some("hourly") => BudgetPeriod::Hourly,
        Some("daily") | None => BudgetPeriod::Daily,
        Some("monthly") => BudgetPeriod::Monthly,
        Some(other) => {
            // Try to parse as custom seconds
            if let Ok(seconds) = other.parse::<u64>() {
                BudgetPeriod::Custom { seconds }
            } else {
                return Err(anyhow::anyhow!(
                    "Unknown budget period '{}'. Valid periods: hourly, daily, monthly, or a number of seconds",
                    other
                ));
            }
        }
    };

    let limit = get_int_entry(node, "limit")
        .ok_or_else(|| anyhow::anyhow!("Token budget requires 'limit'"))? as u64;

    // Parse alert-thresholds as a list of floats from arguments
    let alert_thresholds = if let Some(children) = node.children() {
        if let Some(threshold_node) = children.get("alert-thresholds") {
            threshold_node
                .entries()
                .iter()
                .filter_map(|e| {
                    e.value()
                        .as_float()
                        .or_else(|| e.value().as_integer().map(|i| i as f64))
                })
                .collect()
        } else {
            vec![0.80, 0.90, 0.95]
        }
    } else {
        vec![0.80, 0.90, 0.95]
    };

    let enforce = get_bool_entry(node, "enforce").unwrap_or(true);
    let rollover = get_bool_entry(node, "rollover").unwrap_or(false);
    let burst_allowance = get_float_entry(node, "burst-allowance");

    trace!(
        period = ?period,
        limit = limit,
        alert_thresholds = ?alert_thresholds,
        enforce = enforce,
        rollover = rollover,
        burst_allowance = ?burst_allowance,
        "Parsed token budget configuration"
    );

    Ok(TokenBudgetConfig {
        period,
        limit,
        alert_thresholds,
        enforce,
        rollover,
        burst_allowance,
    })
}

/// Parse cost attribution configuration
///
/// KDL format:
/// ```kdl
/// cost-attribution {
///     enabled true
///     default-input-cost 1.0
///     default-output-cost 2.0
///     currency "USD"
///
///     pricing {
///         model "gpt-4*" {
///             input-cost-per-million 30.0
///             output-cost-per-million 60.0
///         }
///         model "gpt-3.5*" {
///             input-cost-per-million 0.5
///             output-cost-per-million 1.5
///         }
///     }
/// }
/// ```
fn parse_cost_attribution(node: &kdl::KdlNode) -> Result<CostAttributionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(true);
    let default_input_cost = get_float_entry(node, "default-input-cost").unwrap_or(1.0);
    let default_output_cost = get_float_entry(node, "default-output-cost").unwrap_or(2.0);
    let currency = get_string_entry(node, "currency").unwrap_or_else(|| "USD".to_string());

    // Parse pricing sub-block
    let pricing = if let Some(children) = node.children() {
        if let Some(pricing_node) = children.get("pricing") {
            parse_model_pricing_list(pricing_node)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    trace!(
        enabled = enabled,
        default_input_cost = default_input_cost,
        default_output_cost = default_output_cost,
        currency = %currency,
        pricing_rules = pricing.len(),
        "Parsed cost attribution configuration"
    );

    Ok(CostAttributionConfig {
        enabled,
        pricing,
        default_input_cost,
        default_output_cost,
        currency,
    })
}

/// Parse model pricing list
fn parse_model_pricing_list(node: &kdl::KdlNode) -> Result<Vec<ModelPricing>> {
    let mut pricing = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "model" {
                let pattern = get_first_arg_string(child)
                    .ok_or_else(|| anyhow::anyhow!("Model pricing requires a pattern argument"))?;

                let input_cost =
                    get_float_entry(child, "input-cost-per-million").ok_or_else(|| {
                        anyhow::anyhow!("Model pricing requires 'input-cost-per-million'")
                    })?;

                let output_cost =
                    get_float_entry(child, "output-cost-per-million").ok_or_else(|| {
                        anyhow::anyhow!("Model pricing requires 'output-cost-per-million'")
                    })?;

                let currency = get_string_entry(child, "currency");

                pricing.push(ModelPricing {
                    model_pattern: pattern,
                    input_cost_per_million: input_cost,
                    output_cost_per_million: output_cost,
                    currency,
                });
            }
        }
    }

    Ok(pricing)
}

// ============================================================================
// Guardrails Configuration Parsing
// ============================================================================

/// Parse optional guardrails configuration from an inference block.
///
/// Example KDL:
/// ```kdl
/// guardrails {
///     prompt-injection {
///         enabled true
///         agent "prompt-guard"
///         action "block"
///         block-status 400
///         block-message "Request blocked: potential prompt injection detected"
///         timeout-ms 500
///         failure-mode "open"
///     }
///
///     pii-detection {
///         enabled true
///         agent "pii-scanner"
///         action "log"
///         categories "ssn" "credit-card" "email" "phone"
///         timeout-ms 1000
///         failure-mode "open"
///     }
/// }
/// ```
fn parse_guardrails_config_opt(node: &kdl::KdlNode) -> Result<Option<GuardrailsConfig>> {
    if let Some(children) = node.children() {
        if let Some(guardrails_node) = children.get("guardrails") {
            return Ok(Some(parse_guardrails_config(guardrails_node)?));
        }
    }
    Ok(None)
}

/// Parse guardrails configuration block.
fn parse_guardrails_config(node: &kdl::KdlNode) -> Result<GuardrailsConfig> {
    // Parse prompt-injection sub-block
    let prompt_injection = if let Some(children) = node.children() {
        if let Some(pi_node) = children.get("prompt-injection") {
            Some(parse_prompt_injection_config(pi_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse pii-detection sub-block
    let pii_detection = if let Some(children) = node.children() {
        if let Some(pii_node) = children.get("pii-detection") {
            Some(parse_pii_detection_config(pii_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        has_prompt_injection = prompt_injection.is_some(),
        has_pii_detection = pii_detection.is_some(),
        "Parsed guardrails configuration"
    );

    Ok(GuardrailsConfig {
        prompt_injection,
        pii_detection,
    })
}

/// Parse prompt injection detection configuration.
fn parse_prompt_injection_config(node: &kdl::KdlNode) -> Result<PromptInjectionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);

    let agent = get_string_entry(node, "agent")
        .ok_or_else(|| anyhow::anyhow!("Prompt injection config requires 'agent' field"))?;

    let action = match get_string_entry(node, "action").as_deref() {
        Some("block") => GuardrailAction::Block,
        Some("log") | None => GuardrailAction::Log,
        Some("warn") => GuardrailAction::Warn,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown guardrail action '{}'. Valid actions: block, log, warn",
                other
            ));
        }
    };

    let block_status = get_int_entry(node, "block-status").unwrap_or(400) as u16;
    let block_message = get_string_entry(node, "block-message");
    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(500) as u64;

    let failure_mode = match get_string_entry(node, "failure-mode").as_deref() {
        Some("open") | None => GuardrailFailureMode::Open,
        Some("closed") => GuardrailFailureMode::Closed,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown failure mode '{}'. Valid modes: open, closed",
                other
            ));
        }
    };

    trace!(
        enabled = enabled,
        agent = %agent,
        action = ?action,
        block_status = block_status,
        timeout_ms = timeout_ms,
        failure_mode = ?failure_mode,
        "Parsed prompt injection configuration"
    );

    Ok(PromptInjectionConfig {
        enabled,
        agent,
        action,
        block_status,
        block_message,
        timeout_ms,
        failure_mode,
    })
}

/// Parse PII detection configuration.
fn parse_pii_detection_config(node: &kdl::KdlNode) -> Result<PiiDetectionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);

    let agent = get_string_entry(node, "agent")
        .ok_or_else(|| anyhow::anyhow!("PII detection config requires 'agent' field"))?;

    let action = match get_string_entry(node, "action").as_deref() {
        Some("log") | None => PiiAction::Log,
        Some("redact") => PiiAction::Redact,
        Some("block") => PiiAction::Block,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown PII action '{}'. Valid actions: log, redact, block",
                other
            ));
        }
    };

    // Parse categories as string arguments
    let categories = if let Some(children) = node.children() {
        if let Some(cat_node) = children.get("categories") {
            cat_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(1000) as u64;

    let failure_mode = match get_string_entry(node, "failure-mode").as_deref() {
        Some("open") | None => GuardrailFailureMode::Open,
        Some("closed") => GuardrailFailureMode::Closed,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown failure mode '{}'. Valid modes: open, closed",
                other
            ));
        }
    };

    trace!(
        enabled = enabled,
        agent = %agent,
        action = ?action,
        categories = ?categories,
        timeout_ms = timeout_ms,
        failure_mode = ?failure_mode,
        "Parsed PII detection configuration"
    );

    Ok(PiiDetectionConfig {
        enabled,
        agent,
        action,
        categories,
        timeout_ms,
        failure_mode,
    })
}
