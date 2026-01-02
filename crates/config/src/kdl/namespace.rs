//! KDL parsing for namespace and service configuration blocks.
//!
//! This module handles parsing of the hierarchical namespace/service
//! configuration structure from KDL format.

use anyhow::{Context, Result};
use tracing::trace;

use crate::namespace::{ExportConfig, NamespaceConfig, ServiceConfig};
use crate::ListenerConfig;

use super::helpers::get_first_arg_string;
use super::{parse_filter_definitions, parse_listeners, parse_routes, parse_upstreams};

// ============================================================================
// Namespace Parsing
// ============================================================================

/// Parse a namespace block from KDL.
///
/// # Example KDL
///
/// ```kdl
/// namespace "api" {
///     limits { ... }
///     listeners { ... }
///     upstreams { ... }
///     routes { ... }
///     agents { ... }
///     filters { ... }
///     service "payments" { ... }
///     exports { ... }
/// }
/// ```
pub fn parse_namespace(node: &kdl::KdlNode) -> Result<NamespaceConfig> {
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow::anyhow!("Namespace requires an ID as first argument"))?;

    trace!(namespace_id = %id, "Parsing namespace");

    let mut ns = NamespaceConfig::new(id.clone());

    let children = node.children().ok_or_else(|| {
        anyhow::anyhow!(
            "Namespace '{}' requires a configuration block with braces {{}}",
            id
        )
    })?;

    for child in children.nodes() {
        let child_name = child.name().value();
        trace!(namespace = %id, block = child_name, "Parsing namespace child block");

        match child_name {
            "limits" => {
                ns.limits = Some(super::parse_limits_config(child)?);
                trace!(namespace = %id, "Parsed namespace limits");
            }
            "listeners" => {
                ns.listeners = parse_listeners(child)?;
                trace!(namespace = %id, count = ns.listeners.len(), "Parsed namespace listeners");
            }
            "upstreams" => {
                ns.upstreams = parse_upstreams(child)?;
                trace!(namespace = %id, count = ns.upstreams.len(), "Parsed namespace upstreams");
            }
            "routes" => {
                ns.routes = parse_routes(child)?;
                trace!(namespace = %id, count = ns.routes.len(), "Parsed namespace routes");
            }
            "agents" => {
                ns.agents = super::parse_agents(child)?;
                trace!(namespace = %id, count = ns.agents.len(), "Parsed namespace agents");
            }
            "filters" => {
                ns.filters = parse_filter_definitions(child)?;
                trace!(namespace = %id, count = ns.filters.len(), "Parsed namespace filters");
            }
            "service" => {
                let service = parse_service(child)?;
                trace!(namespace = %id, service = %service.id, "Parsed service");
                ns.services.push(service);
            }
            "exports" => {
                ns.exports = parse_exports(child)?;
                trace!(namespace = %id, exports = ns.exports.len(), "Parsed exports");
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown block '{}' in namespace '{}'\n\
                     Valid blocks are: limits, listeners, upstreams, routes, agents, filters, service, exports",
                    other, id
                ));
            }
        }
    }

    Ok(ns)
}

/// Parse multiple namespace blocks from a document.
pub fn parse_namespaces(nodes: &[&kdl::KdlNode]) -> Result<Vec<NamespaceConfig>> {
    let mut namespaces = Vec::with_capacity(nodes.len());
    for node in nodes {
        namespaces.push(parse_namespace(node)?);
    }
    Ok(namespaces)
}

// ============================================================================
// Service Parsing
// ============================================================================

/// Parse a service block from KDL.
///
/// # Example KDL
///
/// ```kdl
/// service "payments" {
///     listener {
///         address "0.0.0.0:8443"
///         protocol "https"
///     }
///     upstreams { ... }
///     routes { ... }
///     agents { ... }
///     filters { ... }
///     limits { ... }
/// }
/// ```
pub fn parse_service(node: &kdl::KdlNode) -> Result<ServiceConfig> {
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow::anyhow!("Service requires an ID as first argument"))?;

    trace!(service_id = %id, "Parsing service");

    let mut svc = ServiceConfig::new(id.clone());

    let children = node.children().ok_or_else(|| {
        anyhow::anyhow!(
            "Service '{}' requires a configuration block with braces {{}}",
            id
        )
    })?;

    for child in children.nodes() {
        let child_name = child.name().value();
        trace!(service = %id, block = child_name, "Parsing service child block");

        match child_name {
            "listener" => {
                // Service has a singular listener, not a collection
                svc.listener = Some(parse_single_listener(child)?);
                trace!(service = %id, "Parsed service listener");
            }
            "upstreams" => {
                svc.upstreams = parse_upstreams(child)?;
                trace!(service = %id, count = svc.upstreams.len(), "Parsed service upstreams");
            }
            "routes" => {
                svc.routes = parse_routes(child)?;
                trace!(service = %id, count = svc.routes.len(), "Parsed service routes");
            }
            "agents" => {
                svc.agents = super::parse_agents(child)?;
                trace!(service = %id, count = svc.agents.len(), "Parsed service agents");
            }
            "filters" => {
                svc.filters = parse_filter_definitions(child)?;
                trace!(service = %id, count = svc.filters.len(), "Parsed service filters");
            }
            "limits" => {
                svc.limits = Some(super::parse_limits_config(child)?);
                trace!(service = %id, "Parsed service limits");
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown block '{}' in service '{}'\n\
                     Valid blocks are: listener, upstreams, routes, agents, filters, limits",
                    other, id
                ));
            }
        }
    }

    Ok(svc)
}

// ============================================================================
// Single Listener Parsing (for services)
// ============================================================================

/// Parse a single listener block (used for services).
///
/// Unlike the `listeners` block which contains multiple `listener` children,
/// a service's `listener` block directly contains the listener configuration.
///
/// # Example KDL
///
/// ```kdl
/// listener {
///     id "payments-https"
///     address "0.0.0.0:8443"
///     protocol "https"
///     tls { ... }
/// }
/// ```
fn parse_single_listener(node: &kdl::KdlNode) -> Result<ListenerConfig> {
    use super::helpers::{get_int_entry, get_string_entry};
    use crate::server::ListenerProtocol;

    // Get ID from first argument or from 'id' property in node
    let id = get_first_arg_string(node)
        .or_else(|| get_string_entry(node, "id"))
        .unwrap_or_else(|| "service-listener".to_string());

    let address = get_string_entry(node, "address")
        .ok_or_else(|| anyhow::anyhow!("Listener '{}' requires an 'address'", id))?;

    let protocol_str = get_string_entry(node, "protocol").unwrap_or_else(|| "http".to_string());
    let protocol = match protocol_str.to_lowercase().as_str() {
        "http" => ListenerProtocol::Http,
        "https" => ListenerProtocol::Https,
        "h2" | "http2" => ListenerProtocol::Http2,
        "h3" | "http3" => ListenerProtocol::Http3,
        other => {
            return Err(anyhow::anyhow!(
                "Invalid protocol '{}' for listener '{}'. Valid protocols: http, https, h2, h3",
                other, id
            ))
        }
    };

    // Parse TLS config if present
    let tls = if let Some(children) = node.children() {
        children
            .nodes()
            .iter()
            .find(|n| n.name().value() == "tls")
            .map(|n| super::server::parse_tls_config(n, &id))
            .transpose()
            .context("Failed to parse TLS config")?
    } else {
        None
    };

    Ok(ListenerConfig {
        id,
        address,
        protocol,
        tls,
        default_route: get_string_entry(node, "default-route"),
        request_timeout_secs: get_int_entry(node, "request-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or(60),
        keepalive_timeout_secs: get_int_entry(node, "keepalive-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or(75),
        max_concurrent_streams: get_int_entry(node, "max-concurrent-streams")
            .map(|v| v as u32)
            .unwrap_or(100),
    })
}

// ============================================================================
// Export Parsing
// ============================================================================

/// Parse an exports block from KDL.
///
/// # Example KDL
///
/// ```kdl
/// exports {
///     upstreams "shared-auth" "shared-cache"
///     agents "global-waf"
///     filters "rate-limiter"
/// }
/// ```
fn parse_exports(node: &kdl::KdlNode) -> Result<ExportConfig> {
    let mut exports = ExportConfig::default();

    let children = match node.children() {
        Some(c) => c,
        None => return Ok(exports), // Empty exports block is valid
    };

    for child in children.nodes() {
        let child_name = child.name().value();

        match child_name {
            "upstreams" => {
                exports.upstreams = parse_string_list(child);
            }
            "agents" => {
                exports.agents = parse_string_list(child);
            }
            "filters" => {
                exports.filters = parse_string_list(child);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown export type '{}'\n\
                     Valid export types are: upstreams, agents, filters",
                    other
                ));
            }
        }
    }

    Ok(exports)
}

/// Parse a list of string arguments from a KDL node.
///
/// # Example KDL
///
/// ```kdl
/// upstreams "shared-auth" "shared-cache" "another"
/// ```
fn parse_string_list(node: &kdl::KdlNode) -> Vec<String> {
    node.entries()
        .iter()
        .filter_map(|entry| {
            if entry.name().is_none() {
                // It's a positional argument
                entry.value().as_string().map(|s| s.to_string())
            } else {
                None
            }
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_kdl_node(kdl: &str) -> kdl::KdlNode {
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        doc.nodes().first().unwrap().clone()
    }

    #[test]
    fn test_parse_empty_namespace() {
        let kdl = r#"namespace "api" {}"#;
        let node = parse_kdl_node(kdl);
        let ns = parse_namespace(&node).unwrap();
        assert_eq!(ns.id, "api");
        assert!(ns.is_empty());
    }

    #[test]
    fn test_parse_namespace_with_upstreams() {
        let kdl = r#"
            namespace "api" {
                upstreams {
                    upstream "backend" {
                        target "127.0.0.1:8080"
                    }
                }
            }
        "#;
        let node = parse_kdl_node(kdl);
        let ns = parse_namespace(&node).unwrap();
        assert_eq!(ns.id, "api");
        assert_eq!(ns.upstreams.len(), 1);
        assert!(ns.upstreams.contains_key("backend"));
    }

    #[test]
    fn test_parse_empty_service() {
        let kdl = r#"service "payments" {}"#;
        let node = parse_kdl_node(kdl);
        let svc = parse_service(&node).unwrap();
        assert_eq!(svc.id, "payments");
        assert!(svc.is_empty());
    }

    #[test]
    fn test_parse_service_with_listener() {
        let kdl = r#"
            service "payments" {
                listener {
                    id "payments-https"
                    address "0.0.0.0:8443"
                    protocol "https"
                }
            }
        "#;
        let node = parse_kdl_node(kdl);
        let svc = parse_service(&node).unwrap();
        assert_eq!(svc.id, "payments");
        assert!(svc.listener.is_some());
        let listener = svc.listener.unwrap();
        assert_eq!(listener.id, "payments-https");
        assert_eq!(listener.address, "0.0.0.0:8443");
    }

    #[test]
    fn test_parse_exports() {
        let kdl = r#"
            exports {
                upstreams "shared-auth" "shared-cache"
                agents "global-waf"
            }
        "#;
        let node = parse_kdl_node(kdl);
        let exports = parse_exports(&node).unwrap();
        assert_eq!(exports.upstreams.len(), 2);
        assert_eq!(exports.upstreams[0], "shared-auth");
        assert_eq!(exports.upstreams[1], "shared-cache");
        assert_eq!(exports.agents.len(), 1);
        assert_eq!(exports.agents[0], "global-waf");
    }

    #[test]
    fn test_parse_string_list() {
        let kdl = r#"items "a" "b" "c""#;
        let node = parse_kdl_node(kdl);
        let list = parse_string_list(&node);
        assert_eq!(list, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_namespace_requires_id() {
        let kdl = r#"namespace {}"#;
        let node = parse_kdl_node(kdl);
        let result = parse_namespace(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires an ID"));
    }

    #[test]
    fn test_service_requires_id() {
        let kdl = r#"service {}"#;
        let node = parse_kdl_node(kdl);
        let result = parse_service(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("requires an ID"));
    }
}
