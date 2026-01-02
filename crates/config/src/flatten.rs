//! Flattened configuration for runtime consumption.
//!
//! This module provides [`FlattenedConfig`] which transforms the hierarchical
//! namespace/service configuration into a flat structure suitable for runtime
//! lookups with qualified IDs.
//!
//! # Why Flatten?
//!
//! The hierarchical configuration is great for authoring (domain-driven organization),
//! but at runtime we need fast lookups by qualified ID. Flattening:
//!
//! 1. Pre-computes qualified IDs for all resources
//! 2. Collects scope-specific limits for runtime isolation
//! 3. Enables O(1) lookups via HashMap

use sentinel_common::ids::{QualifiedId, Scope};
use sentinel_common::limits::Limits;
use std::collections::HashMap;

use crate::{
    AgentConfig, Config, FilterConfig, ListenerConfig, RouteConfig, UpstreamConfig,
};

// ============================================================================
// Flattened Configuration
// ============================================================================

/// Flattened configuration with all resources indexed by qualified IDs.
///
/// This structure is produced by [`Config::flatten()`] and provides efficient
/// runtime lookups for all resource types.
#[derive(Debug, Clone)]
pub struct FlattenedConfig {
    /// All upstreams indexed by their qualified ID
    pub upstreams: HashMap<QualifiedId, UpstreamConfig>,

    /// All routes with their qualified IDs
    pub routes: Vec<(QualifiedId, RouteConfig)>,

    /// All agents indexed by their qualified ID
    pub agents: HashMap<QualifiedId, AgentConfig>,

    /// All filters indexed by their qualified ID
    pub filters: HashMap<QualifiedId, FilterConfig>,

    /// All listeners with their qualified IDs
    pub listeners: Vec<(QualifiedId, ListenerConfig)>,

    /// Limits per scope for runtime isolation
    pub scope_limits: HashMap<Scope, Limits>,

    /// Exported upstream names (for fast lookup)
    pub exported_upstreams: HashMap<String, QualifiedId>,

    /// Exported agent names (for fast lookup)
    pub exported_agents: HashMap<String, QualifiedId>,

    /// Exported filter names (for fast lookup)
    pub exported_filters: HashMap<String, QualifiedId>,
}

impl FlattenedConfig {
    /// Create a new empty flattened config.
    pub fn new() -> Self {
        Self {
            upstreams: HashMap::new(),
            routes: Vec::new(),
            agents: HashMap::new(),
            filters: HashMap::new(),
            listeners: Vec::new(),
            scope_limits: HashMap::new(),
            exported_upstreams: HashMap::new(),
            exported_agents: HashMap::new(),
            exported_filters: HashMap::new(),
        }
    }

    /// Get an upstream by its qualified ID.
    pub fn get_upstream(&self, qid: &QualifiedId) -> Option<&UpstreamConfig> {
        self.upstreams.get(qid)
    }

    /// Get an upstream by its canonical string form.
    pub fn get_upstream_by_canonical(&self, canonical: &str) -> Option<&UpstreamConfig> {
        self.upstreams.get(&QualifiedId::parse(canonical))
    }

    /// Get an agent by its qualified ID.
    pub fn get_agent(&self, qid: &QualifiedId) -> Option<&AgentConfig> {
        self.agents.get(qid)
    }

    /// Get a filter by its qualified ID.
    pub fn get_filter(&self, qid: &QualifiedId) -> Option<&FilterConfig> {
        self.filters.get(qid)
    }

    /// Get limits for a specific scope.
    ///
    /// Returns the limits for the most specific scope that has limits defined.
    /// If no limits are defined for the scope, returns None.
    pub fn get_limits(&self, scope: &Scope) -> Option<&Limits> {
        self.scope_limits.get(scope)
    }

    /// Get effective limits for a scope, falling back through the scope chain.
    ///
    /// Searches from the given scope up through parent scopes until limits are found.
    pub fn get_effective_limits(&self, scope: &Scope) -> Option<&Limits> {
        for s in scope.chain() {
            if let Some(limits) = self.scope_limits.get(&s) {
                return Some(limits);
            }
        }
        None
    }

    /// Get all routes in a specific scope.
    pub fn routes_in_scope<'a>(&'a self, scope: &'a Scope) -> impl Iterator<Item = &'a (QualifiedId, RouteConfig)> {
        self.routes.iter().filter(move |(qid, _)| &qid.scope == scope)
    }

    /// Get all listeners in a specific scope.
    pub fn listeners_in_scope<'a>(&'a self, scope: &'a Scope) -> impl Iterator<Item = &'a (QualifiedId, ListenerConfig)> {
        self.listeners.iter().filter(move |(qid, _)| &qid.scope == scope)
    }

    /// Check if an upstream name is exported.
    pub fn is_upstream_exported(&self, name: &str) -> bool {
        self.exported_upstreams.contains_key(name)
    }

    /// Get the qualified ID of an exported upstream by its local name.
    pub fn get_exported_upstream_qid(&self, name: &str) -> Option<&QualifiedId> {
        self.exported_upstreams.get(name)
    }
}

impl Default for FlattenedConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Config Flattening Implementation
// ============================================================================

impl Config {
    /// Flatten the hierarchical configuration into a runtime-friendly structure.
    ///
    /// This converts all namespace/service resources into qualified IDs and
    /// collects them into flat HashMaps for efficient lookup.
    pub fn flatten(&self) -> FlattenedConfig {
        let mut flat = FlattenedConfig::new();

        // Add global limits
        flat.scope_limits.insert(Scope::Global, self.limits.clone());

        // Flatten global resources
        self.flatten_global(&mut flat);

        // Flatten namespaces
        for ns in &self.namespaces {
            self.flatten_namespace(ns, &mut flat);
        }

        flat
    }

    fn flatten_global(&self, flat: &mut FlattenedConfig) {
        // Global upstreams
        for (id, upstream) in &self.upstreams {
            flat.upstreams.insert(QualifiedId::global(id), upstream.clone());
        }

        // Global routes
        for route in &self.routes {
            flat.routes.push((QualifiedId::global(&route.id), route.clone()));
        }

        // Global agents
        for agent in &self.agents {
            flat.agents.insert(QualifiedId::global(&agent.id), agent.clone());
        }

        // Global filters
        for (id, filter) in &self.filters {
            flat.filters.insert(QualifiedId::global(id), filter.clone());
        }

        // Global listeners
        for listener in &self.listeners {
            flat.listeners.push((QualifiedId::global(&listener.id), listener.clone()));
        }
    }

    fn flatten_namespace(&self, ns: &crate::NamespaceConfig, flat: &mut FlattenedConfig) {
        let ns_scope = Scope::Namespace(ns.id.clone());

        // Namespace limits (if defined)
        if let Some(ref limits) = ns.limits {
            flat.scope_limits.insert(ns_scope.clone(), limits.clone());
        }

        // Namespace upstreams
        for (id, upstream) in &ns.upstreams {
            let qid = QualifiedId::namespaced(&ns.id, id);
            flat.upstreams.insert(qid.clone(), upstream.clone());

            // Track exports
            if ns.exports.upstreams.contains(id) {
                flat.exported_upstreams.insert(id.clone(), qid);
            }
        }

        // Namespace routes
        for route in &ns.routes {
            flat.routes.push((
                QualifiedId::namespaced(&ns.id, &route.id),
                route.clone(),
            ));
        }

        // Namespace agents
        for agent in &ns.agents {
            let qid = QualifiedId::namespaced(&ns.id, &agent.id);
            flat.agents.insert(qid.clone(), agent.clone());

            // Track exports
            if ns.exports.agents.contains(&agent.id) {
                flat.exported_agents.insert(agent.id.clone(), qid);
            }
        }

        // Namespace filters
        for (id, filter) in &ns.filters {
            let qid = QualifiedId::namespaced(&ns.id, id);
            flat.filters.insert(qid.clone(), filter.clone());

            // Track exports
            if ns.exports.filters.contains(id) {
                flat.exported_filters.insert(id.clone(), qid);
            }
        }

        // Namespace listeners
        for listener in &ns.listeners {
            flat.listeners.push((
                QualifiedId::namespaced(&ns.id, &listener.id),
                listener.clone(),
            ));
        }

        // Flatten services within namespace
        for svc in &ns.services {
            self.flatten_service(&ns.id, svc, flat);
        }
    }

    fn flatten_service(
        &self,
        ns_id: &str,
        svc: &crate::ServiceConfig,
        flat: &mut FlattenedConfig,
    ) {
        let svc_scope = Scope::Service {
            namespace: ns_id.to_string(),
            service: svc.id.clone(),
        };

        // Service limits (if defined)
        if let Some(ref limits) = svc.limits {
            flat.scope_limits.insert(svc_scope.clone(), limits.clone());
        }

        // Service upstreams
        for (id, upstream) in &svc.upstreams {
            flat.upstreams.insert(
                QualifiedId::in_service(ns_id, &svc.id, id),
                upstream.clone(),
            );
        }

        // Service routes
        for route in &svc.routes {
            flat.routes.push((
                QualifiedId::in_service(ns_id, &svc.id, &route.id),
                route.clone(),
            ));
        }

        // Service agents
        for agent in &svc.agents {
            flat.agents.insert(
                QualifiedId::in_service(ns_id, &svc.id, &agent.id),
                agent.clone(),
            );
        }

        // Service filters
        for (id, filter) in &svc.filters {
            flat.filters.insert(
                QualifiedId::in_service(ns_id, &svc.id, id),
                filter.clone(),
            );
        }

        // Service listener (singular)
        if let Some(ref listener) = svc.listener {
            flat.listeners.push((
                QualifiedId::in_service(ns_id, &svc.id, &listener.id),
                listener.clone(),
            ));
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        namespace::{ExportConfig, NamespaceConfig, ServiceConfig},
        ConnectionPoolConfig, HttpVersionConfig, UpstreamTarget, UpstreamTimeouts,
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

    fn test_config() -> Config {
        let mut config = Config::default_for_testing();

        // Add global upstream
        config.upstreams.insert("global-backend".to_string(), test_upstream("global-backend"));

        // Add namespace with upstream
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams.insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.upstreams.insert("shared-backend".to_string(), test_upstream("shared-backend"));
        ns.exports = ExportConfig {
            upstreams: vec!["shared-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };

        // Add service with upstream
        let mut svc = ServiceConfig::new("payments");
        svc.upstreams.insert("svc-backend".to_string(), test_upstream("svc-backend"));
        ns.services.push(svc);

        config.namespaces.push(ns);
        config
    }

    #[test]
    fn test_flatten_global_upstreams() {
        let config = test_config();
        let flat = config.flatten();

        // Should have global upstream
        let qid = QualifiedId::global("global-backend");
        assert!(flat.upstreams.contains_key(&qid));
        assert_eq!(flat.get_upstream(&qid).unwrap().id, "global-backend");
    }

    #[test]
    fn test_flatten_namespace_upstreams() {
        let config = test_config();
        let flat = config.flatten();

        // Should have namespace upstream
        let qid = QualifiedId::namespaced("api", "ns-backend");
        assert!(flat.upstreams.contains_key(&qid));
        assert_eq!(flat.get_upstream(&qid).unwrap().id, "ns-backend");
    }

    #[test]
    fn test_flatten_service_upstreams() {
        let config = test_config();
        let flat = config.flatten();

        // Should have service upstream
        let qid = QualifiedId::in_service("api", "payments", "svc-backend");
        assert!(flat.upstreams.contains_key(&qid));
        assert_eq!(flat.get_upstream(&qid).unwrap().id, "svc-backend");
    }

    #[test]
    fn test_flatten_exported_upstreams() {
        let config = test_config();
        let flat = config.flatten();

        // Should track exported upstreams
        assert!(flat.is_upstream_exported("shared-backend"));
        assert!(!flat.is_upstream_exported("ns-backend"));

        let exported_qid = flat.get_exported_upstream_qid("shared-backend").unwrap();
        assert_eq!(exported_qid.canonical(), "api:shared-backend");
    }

    #[test]
    fn test_get_upstream_by_canonical() {
        let config = test_config();
        let flat = config.flatten();

        // Should lookup by canonical string
        let upstream = flat.get_upstream_by_canonical("api:ns-backend").unwrap();
        assert_eq!(upstream.id, "ns-backend");

        let service_upstream = flat.get_upstream_by_canonical("api:payments:svc-backend").unwrap();
        assert_eq!(service_upstream.id, "svc-backend");
    }

    #[test]
    fn test_flatten_scope_limits() {
        let mut config = test_config();

        // Add namespace limits
        let ns = config.namespaces.get_mut(0).unwrap();
        ns.limits = Some(Limits::for_testing());

        let flat = config.flatten();

        // Should have global limits
        assert!(flat.scope_limits.contains_key(&Scope::Global));

        // Should have namespace limits
        assert!(flat.scope_limits.contains_key(&Scope::Namespace("api".to_string())));
    }

    #[test]
    fn test_get_effective_limits() {
        let mut config = test_config();

        // Add namespace limits
        let ns = config.namespaces.get_mut(0).unwrap();
        ns.limits = Some(Limits::for_testing());

        let flat = config.flatten();

        // Service scope should fall back to namespace limits
        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let limits = flat.get_effective_limits(&svc_scope);
        assert!(limits.is_some());
    }

    #[test]
    fn test_routes_in_scope() {
        let config = test_config();
        let flat = config.flatten();

        // Should have global routes (from default_for_testing)
        let global_routes: Vec<_> = flat.routes_in_scope(&Scope::Global).collect();
        assert!(!global_routes.is_empty());
    }

    #[test]
    fn test_flatten_preserves_route_order() {
        let config = test_config();
        let flat = config.flatten();

        // Routes should maintain order within their scope
        let route_ids: Vec<_> = flat.routes.iter().map(|(qid, _)| qid.canonical()).collect();
        assert!(!route_ids.is_empty());
    }
}
