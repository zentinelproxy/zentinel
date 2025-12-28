//! KDL configuration parsing.
//!
//! This module contains all functions for parsing KDL configuration files
//! into Sentinel configuration structures. It is organized into submodules:
//!
//! - `helpers`: Common parsing utility functions
//! - `server`: Server and listener parsing
//! - `routes`: Route and static file parsing
//! - `upstreams`: Upstream target parsing
//! - `filters`: Filter definition parsing

mod filters;
mod helpers;
mod routes;
mod server;
mod upstreams;

// Re-export commonly used items
pub use helpers::{
    get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry, offset_to_line_col,
};

pub use filters::{parse_filter_definitions, parse_single_filter_definition};
pub use routes::{parse_routes, parse_static_file_config};
pub use server::{parse_listeners, parse_server_config};
pub use upstreams::parse_upstreams;

use anyhow::Result;
use std::collections::HashMap;

use sentinel_common::limits::Limits;

use crate::observability::ObservabilityConfig;
use crate::waf::WafConfig;
use crate::{AgentConfig, Config};

// ============================================================================
// Top-Level Document Parser
// ============================================================================

/// Convert a parsed KDL document to Config
pub fn parse_kdl_document(doc: kdl::KdlDocument) -> Result<Config> {
    let mut server = None;
    let mut listeners = Vec::new();
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();
    let mut filters = HashMap::new();
    let mut agents = Vec::new();
    let mut waf = None;
    let mut limits = None;
    let mut observability = None;

    for node in doc.nodes() {
        match node.name().value() {
            "server" => {
                server = Some(parse_server_config(node)?);
            }
            "listeners" => {
                listeners = parse_listeners(node)?;
            }
            "routes" => {
                routes = parse_routes(node)?;
            }
            "upstreams" => {
                upstreams = parse_upstreams(node)?;
            }
            "filters" => {
                filters = parse_filter_definitions(node)?;
            }
            "agents" => {
                agents = parse_agents(node)?;
            }
            "waf" => {
                waf = Some(parse_waf_config(node)?);
            }
            "limits" => {
                limits = Some(parse_limits_config(node)?);
            }
            "observability" => {
                observability = Some(parse_observability_config(node)?);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown top-level configuration block: '{}'\n\
                     Valid blocks are: server, listeners, routes, upstreams, filters, agents, waf, limits, observability",
                    other
                ));
            }
        }
    }

    // Validate required sections
    let server = server.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing required 'server' configuration block\n\
             Example:\n\
             server {{\n\
                 worker-threads 4\n\
                 max-connections 10000\n\
             }}"
        )
    })?;

    if listeners.is_empty() {
        return Err(anyhow::anyhow!(
            "Missing required 'listeners' configuration block\n\
             Example:\n\
             listeners {{\n\
                 listener \"http\" {{\n\
                     address \"0.0.0.0:8080\"\n\
                     protocol \"http\"\n\
                 }}\n\
             }}"
        ));
    }

    Ok(Config {
        server,
        listeners,
        routes,
        upstreams,
        filters,
        agents,
        waf,
        limits: limits.unwrap_or_default(),
        observability: observability.unwrap_or_default(),
        default_upstream: None,
    })
}

// ============================================================================
// Agent Parsing
// ============================================================================

/// Parse agents configuration block
pub fn parse_agents(_node: &kdl::KdlNode) -> Result<Vec<AgentConfig>> {
    // TODO: Implement full agent parsing
    Ok(vec![])
}

// ============================================================================
// WAF Parsing
// ============================================================================

/// Parse WAF configuration block
pub fn parse_waf_config(_node: &kdl::KdlNode) -> Result<WafConfig> {
    // TODO: Implement full WAF config parsing
    Err(anyhow::anyhow!(
        "WAF configuration parsing not yet implemented"
    ))
}

// ============================================================================
// Limits Parsing
// ============================================================================

/// Parse limits configuration block
pub fn parse_limits_config(node: &kdl::KdlNode) -> Result<Limits> {
    let mut limits = Limits::default();

    if let Some(v) = get_int_entry(node, "max-header-size") {
        limits.max_header_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-header-count") {
        limits.max_header_count = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-body-size") {
        limits.max_body_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-connections-per-client") {
        limits.max_connections_per_client = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-total-connections") {
        limits.max_total_connections = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-in-flight-requests") {
        limits.max_in_flight_requests = v as usize;
    }

    Ok(limits)
}

// ============================================================================
// Observability Parsing
// ============================================================================

/// Parse observability configuration block
pub fn parse_observability_config(_node: &kdl::KdlNode) -> Result<ObservabilityConfig> {
    // TODO: Implement full observability config parsing
    Ok(ObservabilityConfig::default())
}
