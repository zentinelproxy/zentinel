//! Configuration validation functions
//!
//! This module contains all validation logic for the configuration,
//! including semantic validation and cross-reference checking.
//!
//! # Scoped Validation
//!
//! The [`ValidationContext`] provides scope-aware validation for namespaced
//! configurations. It tracks resources by scope and validates cross-references
//! using the resolution rules (local → parent → exported → global).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use tracing::{debug, trace, warn};

use crate::{Config, Filter, NamespaceConfig, ServiceConfig, ServiceType};
use sentinel_common::ids::Scope;
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
// Validation Context
// ============================================================================

/// Context for scope-aware configuration validation.
///
/// This struct tracks all resources by scope and enables validation of
/// cross-references between scopes following the resolution rules.
#[derive(Debug, Default)]
pub struct ValidationContext {
    /// All canonical IDs for duplicate detection (e.g., "api:payments:checkout")
    pub all_ids: HashSet<String>,

    /// Upstreams indexed by scope
    upstreams_by_scope: HashMap<Scope, HashSet<String>>,

    /// Agents indexed by scope
    agents_by_scope: HashMap<Scope, HashSet<String>>,

    /// Filters indexed by scope
    filters_by_scope: HashMap<Scope, HashSet<String>>,

    /// Routes indexed by scope
    routes_by_scope: HashMap<Scope, HashSet<String>>,

    /// Exported upstream names (local name only)
    exported_upstreams: HashSet<String>,

    /// Exported agent names (local name only)
    exported_agents: HashSet<String>,

    /// Exported filter names (local name only)
    exported_filters: HashSet<String>,
}

impl ValidationContext {
    /// Create a new validation context from a configuration.
    pub fn from_config(config: &Config) -> Self {
        let mut ctx = Self::default();

        // Register global resources
        ctx.register_global_resources(config);

        // Register namespace and service resources
        for ns in &config.namespaces {
            ctx.register_namespace_resources(ns);
        }

        ctx
    }

    fn register_global_resources(&mut self, config: &Config) {
        let scope = Scope::Global;

        // Global upstreams
        for id in config.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(id.clone());
        }

        // Global agents
        for agent in &config.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids.insert(agent.id.clone());
        }

        // Global filters
        for id in config.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(id.clone());
        }

        // Global routes
        for route in &config.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids.insert(route.id.clone());
        }
    }

    fn register_namespace_resources(&mut self, ns: &NamespaceConfig) {
        let scope = Scope::Namespace(ns.id.clone());

        // Namespace upstreams
        for id in ns.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, id));

            // Track exports
            if ns.exports.upstreams.contains(id) {
                self.exported_upstreams.insert(id.clone());
            }
        }

        // Namespace agents
        for agent in &ns.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, agent.id));

            // Track exports
            if ns.exports.agents.contains(&agent.id) {
                self.exported_agents.insert(agent.id.clone());
            }
        }

        // Namespace filters
        for id in ns.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, id));

            // Track exports
            if ns.exports.filters.contains(id) {
                self.exported_filters.insert(id.clone());
            }
        }

        // Namespace routes
        for route in &ns.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids.insert(format!("{}:{}", ns.id, route.id));
        }

        // Register services within namespace
        for svc in &ns.services {
            self.register_service_resources(&ns.id, svc);
        }
    }

    fn register_service_resources(&mut self, ns_id: &str, svc: &ServiceConfig) {
        let scope = Scope::Service {
            namespace: ns_id.to_string(),
            service: svc.id.clone(),
        };

        // Service upstreams
        for id in svc.upstreams.keys() {
            self.upstreams_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}:{}", ns_id, svc.id, id));
        }

        // Service agents
        for agent in &svc.agents {
            self.agents_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(agent.id.clone());
            self.all_ids
                .insert(format!("{}:{}:{}", ns_id, svc.id, agent.id));
        }

        // Service filters
        for id in svc.filters.keys() {
            self.filters_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(id.clone());
            self.all_ids.insert(format!("{}:{}:{}", ns_id, svc.id, id));
        }

        // Service routes
        for route in &svc.routes {
            self.routes_by_scope
                .entry(scope.clone())
                .or_default()
                .insert(route.id.clone());
            self.all_ids
                .insert(format!("{}:{}:{}", ns_id, svc.id, route.id));
        }
    }

    /// Check if an upstream reference can be resolved from the given scope.
    ///
    /// Resolution order: local scope → parent scope → exported → global
    pub fn can_resolve_upstream(&self, reference: &str, from_scope: &Scope) -> bool {
        // Check if it's a qualified reference (contains ':')
        if reference.contains(':') {
            // Qualified references must match exactly
            return self.all_ids.contains(reference);
        }

        // Unqualified reference - search scope chain
        for scope in from_scope.chain() {
            if let Some(upstreams) = self.upstreams_by_scope.get(&scope) {
                if upstreams.contains(reference) {
                    return true;
                }
            }
        }

        // Check exports (for cross-namespace access)
        if self.exported_upstreams.contains(reference) {
            return true;
        }

        false
    }

    /// Check if an agent reference can be resolved from the given scope.
    pub fn can_resolve_agent(&self, reference: &str, from_scope: &Scope) -> bool {
        if reference.contains(':') {
            return self.all_ids.contains(reference);
        }

        for scope in from_scope.chain() {
            if let Some(agents) = self.agents_by_scope.get(&scope) {
                if agents.contains(reference) {
                    return true;
                }
            }
        }

        if self.exported_agents.contains(reference) {
            return true;
        }

        false
    }

    /// Check if a filter reference can be resolved from the given scope.
    pub fn can_resolve_filter(&self, reference: &str, from_scope: &Scope) -> bool {
        if reference.contains(':') {
            return self.all_ids.contains(reference);
        }

        for scope in from_scope.chain() {
            if let Some(filters) = self.filters_by_scope.get(&scope) {
                if filters.contains(reference) {
                    return true;
                }
            }
        }

        if self.exported_filters.contains(reference) {
            return true;
        }

        false
    }

    /// Get all upstreams available from a given scope.
    pub fn available_upstreams(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(upstreams) = self.upstreams_by_scope.get(&scope) {
                available.extend(upstreams.iter().cloned());
            }
        }

        available.extend(self.exported_upstreams.iter().cloned());
        available
    }

    /// Get all agents available from a given scope.
    pub fn available_agents(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(agents) = self.agents_by_scope.get(&scope) {
                available.extend(agents.iter().cloned());
            }
        }

        available.extend(self.exported_agents.iter().cloned());
        available
    }

    /// Get all filters available from a given scope.
    pub fn available_filters(&self, from_scope: &Scope) -> HashSet<String> {
        let mut available = HashSet::new();

        for scope in from_scope.chain() {
            if let Some(filters) = self.filters_by_scope.get(&scope) {
                available.extend(filters.iter().cloned());
            }
        }

        available.extend(self.exported_filters.iter().cloned());
        available
    }
}

// ============================================================================
// Semantic Validation
// ============================================================================

/// Comprehensive semantic validation for the entire configuration
pub fn validate_config_semantics(config: &Config) -> Result<(), validator::ValidationError> {
    trace!(
        routes = config.routes.len(),
        upstreams = config.upstreams.len(),
        agents = config.agents.len(),
        filters = config.filters.len(),
        listeners = config.listeners.len(),
        "Starting semantic validation"
    );

    let mut errors: Vec<String> = Vec::new();

    // Collect IDs for cross-reference validation
    let route_ids: HashSet<_> = config.routes.iter().map(|r| r.id.as_str()).collect();
    let upstream_ids: HashSet<_> = config.upstreams.keys().map(|s| s.as_str()).collect();
    let agent_ids: HashSet<_> = config.agents.iter().map(|a| a.id.as_str()).collect();
    let filter_ids: HashSet<_> = config.filters.keys().map(|s| s.as_str()).collect();

    trace!(
        route_count = route_ids.len(),
        upstream_count = upstream_ids.len(),
        agent_count = agent_ids.len(),
        filter_count = filter_ids.len(),
        "Collected IDs for cross-reference validation"
    );

    // Validate routes
    trace!("Validating routes");
    validate_routes(config, &route_ids, &upstream_ids, &filter_ids, &mut errors);

    // Validate listeners
    trace!("Validating listeners");
    validate_listeners(config, &route_ids, &mut errors);

    // Validate filters
    trace!("Validating filters");
    validate_filters(config, &agent_ids, &mut errors);

    // Validate upstreams
    trace!("Validating upstreams");
    validate_upstreams(config, &mut errors);

    // Validate duplicates
    trace!("Checking for duplicates");
    validate_duplicates(config, &mut errors);

    // Validate namespaces and services
    trace!("Validating namespaces");
    let ctx = ValidationContext::from_config(config);
    validate_namespaces(config, &ctx, &mut errors);

    // Warn about orphaned upstreams
    warn_orphaned_upstreams(config, &upstream_ids);

    // Build final error
    if errors.is_empty() {
        debug!("Semantic validation passed");
    } else {
        debug!(
            error_count = errors.len(),
            "Semantic validation found errors"
        );
    }

    build_validation_result(errors)
}

fn validate_routes(
    config: &Config,
    _route_ids: &HashSet<&str>,
    upstream_ids: &HashSet<&str>,
    filter_ids: &HashSet<&str>,
    errors: &mut Vec<String>,
) {
    trace!(
        route_count = config.routes.len(),
        "Validating route configurations"
    );

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

    trace!(
        routes_with_upstreams = routes_needing_upstreams.len(),
        routes_missing_config = routes_missing_upstream_config.len(),
        "Categorized routes for validation"
    );

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

fn validate_listeners(config: &Config, route_ids: &HashSet<&str>, errors: &mut Vec<String>) {
    trace!(
        listener_count = config.listeners.len(),
        "Validating listener configurations"
    );

    for listener in &config.listeners {
        trace!(listener_id = %listener.id, "Validating listener");
        if let Some(ref default_route) = listener.default_route {
            if !route_ids.contains(default_route.as_str()) {
                warn!(
                    listener_id = %listener.id,
                    default_route = %default_route,
                    "Listener references non-existent default route"
                );
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

fn validate_filters(config: &Config, agent_ids: &HashSet<&str>, errors: &mut Vec<String>) {
    trace!(
        filter_count = config.filters.len(),
        "Validating filter configurations"
    );

    for (filter_id, filter_config) in &config.filters {
        trace!(filter_id = %filter_id, "Validating filter");
        if let Filter::Agent(agent_filter) = &filter_config.filter {
            if !agent_ids.contains(agent_filter.agent.as_str()) {
                warn!(
                    filter_id = %filter_id,
                    agent_id = %agent_filter.agent,
                    "Filter references non-existent agent"
                );
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
    trace!(
        upstream_count = config.upstreams.len(),
        "Validating upstream configurations"
    );

    for (upstream_id, upstream) in &config.upstreams {
        trace!(
            upstream_id = %upstream_id,
            target_count = upstream.targets.len(),
            "Validating upstream"
        );

        if upstream.targets.is_empty() {
            warn!(upstream_id = %upstream_id, "Upstream has no targets");
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
                    warn!(
                        upstream_id = %upstream_id,
                        target_index = i,
                        address = %target.address,
                        "Invalid target address format"
                    );
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
    trace!("Checking for duplicate identifiers");

    // Duplicate route IDs
    let mut seen_routes = HashSet::new();
    for route in &config.routes {
        if !seen_routes.insert(&route.id) {
            warn!(route_id = %route.id, "Duplicate route ID found");
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
            warn!(listener_id = %listener.id, "Duplicate listener ID found");
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
            warn!(address = %listener.address, "Duplicate listener address found");
            errors.push(format!(
                "Duplicate listener address '{}'. Multiple listeners cannot bind to the same address.",
                listener.address
            ));
        }
    }

    trace!(
        unique_routes = seen_routes.len(),
        unique_listeners = seen_listeners.len(),
        unique_addresses = seen_addresses.len(),
        "Duplicate check complete"
    );
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

// ============================================================================
// Namespace Validation
// ============================================================================

fn validate_namespaces(config: &Config, ctx: &ValidationContext, errors: &mut Vec<String>) {
    trace!(
        namespace_count = config.namespaces.len(),
        "Validating namespace configurations"
    );

    // Check for duplicate namespace IDs
    let mut seen_ns_ids = HashSet::new();
    for ns in &config.namespaces {
        if !seen_ns_ids.insert(&ns.id) {
            errors.push(format!(
                "Duplicate namespace ID '{}'. Each namespace must have a unique identifier.",
                ns.id
            ));
        }

        // Validate IDs don't contain reserved ':' character
        if ns.id.contains(':') {
            errors.push(format!(
                "Namespace ID '{}' contains reserved character ':'. \
                 The colon is reserved for qualified references.",
                ns.id
            ));
        }

        validate_namespace_resources(ns, ctx, errors);
    }
}

fn validate_namespace_resources(ns: &NamespaceConfig, ctx: &ValidationContext, errors: &mut Vec<String>) {
    let scope = Scope::Namespace(ns.id.clone());

    // Validate namespace routes reference valid upstreams/filters
    for route in &ns.routes {
        if let Some(ref upstream) = route.upstream {
            if !ctx.can_resolve_upstream(upstream, &scope) {
                let available = ctx.available_upstreams(&scope);
                errors.push(format!(
                    "Route '{}' in namespace '{}' references upstream '{}' which cannot be resolved.\n\
                     Available upstreams: {}",
                    route.id,
                    ns.id,
                    upstream,
                    format_available_owned(&available)
                ));
            }
        }

        for filter_id in &route.filters {
            if !ctx.can_resolve_filter(filter_id, &scope) {
                let available = ctx.available_filters(&scope);
                errors.push(format!(
                    "Route '{}' in namespace '{}' references filter '{}' which cannot be resolved.\n\
                     Available filters: {}",
                    route.id,
                    ns.id,
                    filter_id,
                    format_available_owned(&available)
                ));
            }
        }
    }

    // Validate exports reference existing resources
    for export_name in &ns.exports.upstreams {
        if !ns.upstreams.contains_key(export_name) {
            errors.push(format!(
                "Namespace '{}' exports upstream '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    for export_name in &ns.exports.agents {
        if !ns.agents.iter().any(|a| &a.id == export_name) {
            errors.push(format!(
                "Namespace '{}' exports agent '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    for export_name in &ns.exports.filters {
        if !ns.filters.contains_key(export_name) {
            errors.push(format!(
                "Namespace '{}' exports filter '{}' which doesn't exist in this namespace.",
                ns.id, export_name
            ));
        }
    }

    // Validate services within namespace
    let mut seen_svc_ids = HashSet::new();
    for svc in &ns.services {
        if !seen_svc_ids.insert(&svc.id) {
            errors.push(format!(
                "Duplicate service ID '{}' in namespace '{}'. Each service must have a unique identifier.",
                svc.id, ns.id
            ));
        }

        if svc.id.contains(':') {
            errors.push(format!(
                "Service ID '{}' in namespace '{}' contains reserved character ':'.",
                svc.id, ns.id
            ));
        }

        validate_service_resources(&ns.id, svc, ctx, errors);
    }
}

fn validate_service_resources(
    ns_id: &str,
    svc: &ServiceConfig,
    ctx: &ValidationContext,
    errors: &mut Vec<String>,
) {
    let scope = Scope::Service {
        namespace: ns_id.to_string(),
        service: svc.id.clone(),
    };

    // Validate service routes reference valid upstreams/filters
    for route in &svc.routes {
        if let Some(ref upstream) = route.upstream {
            if !ctx.can_resolve_upstream(upstream, &scope) {
                let available = ctx.available_upstreams(&scope);
                errors.push(format!(
                    "Route '{}' in service '{}:{}' references upstream '{}' which cannot be resolved.\n\
                     Available upstreams: {}",
                    route.id,
                    ns_id,
                    svc.id,
                    upstream,
                    format_available_owned(&available)
                ));
            }
        }

        for filter_id in &route.filters {
            if !ctx.can_resolve_filter(filter_id, &scope) {
                let available = ctx.available_filters(&scope);
                errors.push(format!(
                    "Route '{}' in service '{}:{}' references filter '{}' which cannot be resolved.\n\
                     Available filters: {}",
                    route.id,
                    ns_id,
                    svc.id,
                    filter_id,
                    format_available_owned(&available)
                ));
            }
        }
    }
}

fn format_available_owned(ids: &HashSet<String>) -> String {
    if ids.is_empty() {
        "(none defined)".to_string()
    } else {
        let mut sorted: Vec<_> = ids.iter().collect();
        sorted.sort();
        sorted
            .iter()
            .map(|s| format!("'{}'", s))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ============================================================================
// Result Building
// ============================================================================

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::{ExportConfig, NamespaceConfig, ServiceConfig};
    use crate::{
        ConnectionPoolConfig, HttpVersionConfig, MatchCondition, RoutePolicies, RouteConfig,
        UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use sentinel_common::types::LoadBalancingAlgorithm;

    fn test_upstream(id: &str) -> UpstreamConfig {
        UpstreamConfig {
            id: id.to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8080".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            health_check: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
        }
    }

    fn test_route(id: &str, upstream: Option<&str>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority: Priority::Normal,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: upstream.map(String::from),
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            circuit_breaker: None,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
        }
    }

    #[test]
    fn test_validation_context_from_config() {
        let mut config = Config::default_for_testing();

        // Add a namespace with an upstream
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.routes.push(test_route("ns-route", Some("ns-backend")));
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Should have global upstream
        assert!(ctx.can_resolve_upstream("default", &Scope::Global));

        // Should have namespace upstream from namespace scope
        let ns_scope = Scope::Namespace("api".to_string());
        assert!(ctx.can_resolve_upstream("ns-backend", &ns_scope));

        // Should also see global from namespace scope
        assert!(ctx.can_resolve_upstream("default", &ns_scope));

        // Global scope should NOT see namespace-local upstream
        assert!(!ctx.can_resolve_upstream("ns-backend", &Scope::Global));
    }

    #[test]
    fn test_validation_context_exports() {
        let mut config = Config::default_for_testing();

        // Add a namespace with exported upstream
        let mut ns = NamespaceConfig::new("shared");
        ns.upstreams
            .insert("shared-backend".to_string(), test_upstream("shared-backend"));
        ns.exports = ExportConfig {
            upstreams: vec!["shared-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Exported upstream should be visible from global scope
        assert!(ctx.can_resolve_upstream("shared-backend", &Scope::Global));

        // And from other namespaces
        let other_ns = Scope::Namespace("other".to_string());
        assert!(ctx.can_resolve_upstream("shared-backend", &other_ns));
    }

    #[test]
    fn test_validation_context_service_scope() {
        let mut config = Config::default_for_testing();

        // Add a namespace with a service
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));

        let mut svc = ServiceConfig::new("payments");
        svc.upstreams
            .insert("svc-backend".to_string(), test_upstream("svc-backend"));
        ns.services.push(svc);

        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // Service should see its own upstream
        assert!(ctx.can_resolve_upstream("svc-backend", &svc_scope));

        // Service should see namespace upstream
        assert!(ctx.can_resolve_upstream("ns-backend", &svc_scope));

        // Service should see global upstream
        assert!(ctx.can_resolve_upstream("default", &svc_scope));

        // Namespace scope should NOT see service-local upstream
        let ns_scope = Scope::Namespace("api".to_string());
        assert!(!ctx.can_resolve_upstream("svc-backend", &ns_scope));
    }

    #[test]
    fn test_validation_context_qualified_references() {
        let mut config = Config::default_for_testing();

        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("backend".to_string(), test_upstream("backend"));
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Qualified reference should work
        assert!(ctx.can_resolve_upstream("api:backend", &Scope::Global));

        // Wrong qualified reference should fail
        assert!(!ctx.can_resolve_upstream("other:backend", &Scope::Global));
    }

    #[test]
    fn test_available_upstreams() {
        let mut config = Config::default_for_testing();

        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.exports = ExportConfig {
            upstreams: vec!["ns-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };
        config.namespaces.push(ns);

        let ctx = ValidationContext::from_config(&config);

        // Global scope should see: default (global) + ns-backend (exported)
        let global_available = ctx.available_upstreams(&Scope::Global);
        assert!(global_available.contains("default"));
        assert!(global_available.contains("ns-backend"));

        // Namespace scope should see: default (global) + ns-backend (local) + exported
        let ns_scope = Scope::Namespace("api".to_string());
        let ns_available = ctx.available_upstreams(&ns_scope);
        assert!(ns_available.contains("default"));
        assert!(ns_available.contains("ns-backend"));
    }
}
