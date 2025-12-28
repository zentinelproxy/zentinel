//! Route KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::routes::*;

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

/// Parse routes configuration block
pub fn parse_routes(node: &kdl::KdlNode) -> Result<Vec<RouteConfig>> {
    let mut routes = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "route" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!("Route requires an ID argument, e.g., route \"api\" {{ ... }}")
                })?;

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
                        _ => None,
                    }
                });

                // Determine service type
                let service_type = if static_files.is_some() {
                    ServiceType::Static
                } else if builtin_handler.is_some() {
                    ServiceType::Builtin
                } else {
                    ServiceType::Web
                };

                routes.push(RouteConfig {
                    id,
                    priority,
                    matches,
                    upstream,
                    service_type,
                    policies: RoutePolicies::default(),
                    filters,
                    builtin_handler,
                    waf_enabled: get_bool_entry(child, "waf-enabled").unwrap_or(false),
                    circuit_breaker: None,
                    retry_policy: None,
                    static_files,
                    api_schema: None,
                    error_pages: None,
                });
            }
        }
    }

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
