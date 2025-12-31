//! Route KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::trace;

use crate::routes::*;

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

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

                // Parse filters
                let filters = parse_route_filter_refs(child)?;

                // Parse builtin-handler
                let builtin_handler = get_string_entry(child, "builtin-handler").and_then(|s| {
                    match s.as_str() {
                        "status" => Some(BuiltinHandler::Status),
                        "health" => Some(BuiltinHandler::Health),
                        "metrics" => Some(BuiltinHandler::Metrics),
                        "not-found" | "not_found" => Some(BuiltinHandler::NotFound),
                        "config" => Some(BuiltinHandler::Config),
                        "upstreams" => Some(BuiltinHandler::Upstreams),
                        "cache-purge" | "cache_purge" => Some(BuiltinHandler::CachePurge),
                        "cache-stats" | "cache_stats" => Some(BuiltinHandler::CacheStats),
                        _ => None,
                    }
                });

                // Parse cache configuration
                let cache_config = parse_cache_config_opt(child)?;

                // Determine service type
                let service_type = if static_files.is_some() {
                    ServiceType::Static
                } else if builtin_handler.is_some() {
                    ServiceType::Builtin
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

                // Build route policies with optional cache config
                let policies = RoutePolicies {
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
                    api_schema: None,
                    error_pages: None,
                    websocket: get_bool_entry(child, "websocket").unwrap_or(false),
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

fn parse_priority(node: &kdl::KdlNode) -> sentinel_common::types::Priority {
    match get_string_entry(node, "priority").as_deref() {
        Some("high") => sentinel_common::types::Priority::High,
        Some("low") => sentinel_common::types::Priority::Low,
        _ => sentinel_common::types::Priority::Normal,
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
