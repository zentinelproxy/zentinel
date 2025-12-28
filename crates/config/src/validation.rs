//! Configuration validation functions
//!
//! This module contains all validation logic for the configuration,
//! including semantic validation and cross-reference checking.

use std::collections::HashSet;
use std::net::SocketAddr;

use crate::{Config, Filter, ServiceType};
use sentinel_common::types::Priority;

// ============================================================================
// Field Validators
// ============================================================================

/// Validate socket address format
pub fn validate_socket_addr(addr: &str) -> Result<(), validator::ValidationError> {
    addr.parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|_| {
            let mut err = validator::ValidationError::new("invalid_socket_address");
            err.message = Some(std::borrow::Cow::Owned(format!(
                "Invalid socket address '{}'. Expected format: IP:PORT (e.g., '127.0.0.1:8080' or '0.0.0.0:443')",
                addr
            )));
            err
        })
}

// ============================================================================
// Semantic Validation
// ============================================================================

/// Comprehensive semantic validation for the entire configuration
pub fn validate_config_semantics(config: &Config) -> Result<(), validator::ValidationError> {
    let mut errors: Vec<String> = Vec::new();

    // Collect IDs for cross-reference validation
    let route_ids: HashSet<_> = config.routes.iter().map(|r| r.id.as_str()).collect();
    let upstream_ids: HashSet<_> = config.upstreams.keys().map(|s| s.as_str()).collect();
    let agent_ids: HashSet<_> = config.agents.iter().map(|a| a.id.as_str()).collect();
    let filter_ids: HashSet<_> = config.filters.keys().map(|s| s.as_str()).collect();

    // Validate routes
    validate_routes(config, &route_ids, &upstream_ids, &filter_ids, &mut errors);

    // Validate listeners
    validate_listeners(config, &route_ids, &mut errors);

    // Validate filters
    validate_filters(config, &agent_ids, &mut errors);

    // Validate upstreams
    validate_upstreams(config, &mut errors);

    // Validate duplicates
    validate_duplicates(config, &mut errors);

    // Warn about orphaned upstreams
    warn_orphaned_upstreams(config, &upstream_ids);

    // Build final error
    build_validation_result(errors)
}

fn validate_routes(
    config: &Config,
    route_ids: &HashSet<&str>,
    upstream_ids: &HashSet<&str>,
    filter_ids: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    // Routes needing upstreams
    let routes_needing_upstreams: Vec<_> = config
        .routes
        .iter()
        .filter(|r| r.service_type != ServiceType::Static && r.upstream.is_some())
        .collect();

    let routes_missing_upstream_config: Vec<_> = config
        .routes
        .iter()
        .filter(|r| {
            r.service_type != ServiceType::Static
                && r.service_type != ServiceType::Builtin
                && r.upstream.is_none()
                && r.static_files.is_none()
        })
        .collect();

    // Validate routes have valid upstream references
    for route in &routes_needing_upstreams {
        if let Some(ref upstream_id) = route.upstream {
            if !upstream_ids.contains(upstream_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references upstream '{}' which doesn't exist.\n\
                     Available upstreams: {}\n\
                     Hint: Add an upstream block or fix the reference.",
                    route.id,
                    upstream_id,
                    format_available(upstream_ids)
                ));
            }
        }
    }

    // Validate non-static routes without upstream or static-files
    for route in &routes_missing_upstream_config {
        errors.push(format!(
            "Route '{}' has no upstream and no static-files configuration.\n\
             Each route must either:\n\
             1. Reference an upstream: upstream \"my-backend\"\n\
             2. Serve static files: static-files {{ root \"/var/www/html\" }}",
            route.id
        ));
    }

    // Validate filter references in routes
    for route in &config.routes {
        for filter_id in &route.filters {
            if !filter_ids.contains(filter_id.as_str()) {
                errors.push(format!(
                    "Route '{}' references filter '{}' which doesn't exist.\n\
                     Available filters: {}",
                    route.id,
                    filter_id,
                    format_available(filter_ids)
                ));
            }
        }
    }

    // Validate routes have at least one match condition
    for route in &config.routes {
        if route.matches.is_empty() && route.priority != Priority::Low {
            errors.push(format!(
                "Route '{}' has no match conditions.\n\
                 Add at least one match condition or set priority to \"low\" for catch-all routes.",
                route.id
            ));
        }
    }

    // Validate static file configurations
    for route in &config.routes {
        if let Some(ref static_config) = route.static_files {
            if !static_config.root.exists() {
                errors.push(format!(
                    "Route '{}' static files root directory '{}' does not exist.",
                    route.id,
                    static_config.root.display()
                ));
            } else if !static_config.root.is_dir() {
                errors.push(format!(
                    "Route '{}' static files root '{}' exists but is not a directory.",
                    route.id,
                    static_config.root.display()
                ));
            }

            if route.upstream.is_some() {
                errors.push(format!(
                    "Route '{}' has both 'upstream' and 'static-files' configured.\n\
                     A route can only serve one type of content.",
                    route.id
                ));
            }
        }
    }
}

fn validate_listeners(
    config: &Config,
    route_ids: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    for listener in &config.listeners {
        if let Some(ref default_route) = listener.default_route {
            if !route_ids.contains(default_route.as_str()) {
                errors.push(format!(
                    "Listener '{}' references default-route '{}' which doesn't exist.\n\
                     Available routes: {}",
                    listener.id,
                    default_route,
                    format_available(route_ids)
                ));
            }
        }
    }
}

fn validate_filters(
    config: &Config,
    agent_ids: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    for (filter_id, filter_config) in &config.filters {
        if let Filter::Agent(agent_filter) = &filter_config.filter {
            if !agent_ids.contains(agent_filter.agent.as_str()) {
                errors.push(format!(
                    "Filter '{}' references agent '{}' which doesn't exist.\n\
                     Available agents: {}",
                    filter_id,
                    agent_filter.agent,
                    format_available(agent_ids)
                ));
            }
        }
    }
}

fn validate_upstreams(config: &Config, errors: &mut Vec<String>) {
    for (upstream_id, upstream) in &config.upstreams {
        if upstream.targets.is_empty() {
            errors.push(format!(
                "Upstream '{}' has no targets defined.\n\
                 Each upstream must have at least one target.",
                upstream_id
            ));
        }

        for (i, target) in upstream.targets.iter().enumerate() {
            if target.address.parse::<SocketAddr>().is_err() {
                let parts: Vec<&str> = target.address.rsplitn(2, ':').collect();
                if parts.len() != 2 || parts[0].parse::<u16>().is_err() {
                    errors.push(format!(
                        "Upstream '{}' target #{} has invalid address '{}'.\n\
                         Expected format: HOST:PORT",
                        upstream_id,
                        i + 1,
                        target.address
                    ));
                }
            }
        }
    }
}

fn validate_duplicates(config: &Config, errors: &mut Vec<String>) {
    // Duplicate route IDs
    let mut seen_routes = HashSet::new();
    for route in &config.routes {
        if !seen_routes.insert(&route.id) {
            errors.push(format!(
                "Duplicate route ID '{}'. Each route must have a unique identifier.",
                route.id
            ));
        }
    }

    // Duplicate listener IDs
    let mut seen_listeners = HashSet::new();
    for listener in &config.listeners {
        if !seen_listeners.insert(&listener.id) {
            errors.push(format!(
                "Duplicate listener ID '{}'. Each listener must have a unique identifier.",
                listener.id
            ));
        }
    }

    // Duplicate listener addresses
    let mut seen_addresses = HashSet::new();
    for listener in &config.listeners {
        if !seen_addresses.insert(&listener.address) {
            errors.push(format!(
                "Duplicate listener address '{}'. Multiple listeners cannot bind to the same address.",
                listener.address
            ));
        }
    }
}

fn warn_orphaned_upstreams(config: &Config, upstream_ids: &HashSet<&str>) {
    let referenced_upstreams: HashSet<_> = config
        .routes
        .iter()
        .filter_map(|r| r.upstream.as_ref())
        .map(|s| s.as_str())
        .collect();

    for upstream_id in upstream_ids {
        if !referenced_upstreams.contains(*upstream_id) {
            tracing::warn!(
                upstream_id = %upstream_id,
                "Upstream '{}' is defined but not referenced by any route.",
                upstream_id
            );
        }
    }
}

fn format_available(ids: &HashSet<&str>) -> String {
    if ids.is_empty() {
        "(none defined)".to_string()
    } else {
        ids.iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn build_validation_result(errors: Vec<String>) -> Result<(), validator::ValidationError> {
    if errors.is_empty() {
        Ok(())
    } else {
        let mut err = validator::ValidationError::new("config_validation_failed");
        let error_summary = if errors.len() == 1 {
            errors[0].clone()
        } else {
            format!(
                "Configuration has {} issues:\n\n{}",
                errors.len(),
                errors
                    .iter()
                    .enumerate()
                    .map(|(i, e)| format!("{}. {}", i + 1, e))
                    .collect::<Vec<_>>()
                    .join("\n\n")
            )
        };
        err.message = Some(std::borrow::Cow::Owned(error_summary));
        Err(err)
    }
}
