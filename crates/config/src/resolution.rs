//! Resource resolution with scoped lookups.
//!
//! This module provides the [`ResourceResolver`] which handles looking up
//! resources across the configuration hierarchy following the "most specific wins"
//! resolution order: Service → Namespace → Exported → Global.
//!
//! # Resolution Rules
//!
//! When resolving an unqualified reference (e.g., `"backend"`):
//! 1. Check the current scope (service-local if in a service)
//! 2. Check the parent namespace scope
//! 3. Check exported resources from other namespaces
//! 4. Check global resources
//!
//! Qualified references (e.g., `"api:backend"`) bypass this chain and
//! resolve directly to the specified scope.

use zentinel_common::ids::{QualifiedId, Scope};

use crate::{AgentConfig, Config, FilterConfig, NamespaceConfig, ServiceConfig, UpstreamConfig};

// ============================================================================
// Resource Resolver
// ============================================================================

/// Resolver for looking up resources across the configuration hierarchy.
///
/// The resolver implements the "most specific wins" resolution strategy,
/// searching from the most specific scope (service) to the least specific
/// (global) until a match is found.
///
/// # Example
///
/// ```ignore
/// let resolver = ResourceResolver::new(&config);
///
/// // From within a service, "backend" resolves through the chain:
/// // 1. api:payments:backend (service-local)
/// // 2. api:backend (namespace)
/// // 3. backend (exported or global)
/// let scope = Scope::Service {
///     namespace: "api".to_string(),
///     service: "payments".to_string(),
/// };
/// let upstream = resolver.resolve_upstream("backend", &scope);
/// ```
pub struct ResourceResolver<'a> {
    config: &'a Config,
}

impl<'a> ResourceResolver<'a> {
    /// Create a new resolver for the given configuration.
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    /// Get the underlying configuration.
    pub fn config(&self) -> &'a Config {
        self.config
    }

    // ========================================================================
    // Upstream Resolution
    // ========================================================================

    /// Resolve an upstream reference from the given scope.
    ///
    /// Resolution order for unqualified references:
    /// 1. Service-local (if in a service scope)
    /// 2. Namespace-local (if in a namespace or service scope)
    /// 3. Exported from any namespace
    /// 4. Global
    ///
    /// Qualified references (containing `:`) resolve directly.
    pub fn resolve_upstream(
        &self,
        reference: &str,
        from_scope: &Scope,
    ) -> Option<&'a UpstreamConfig> {
        // Qualified reference - direct lookup
        if reference.contains(':') {
            return self.resolve_upstream_qualified(&QualifiedId::parse(reference));
        }

        // Unqualified - search scope chain
        match from_scope {
            Scope::Service { namespace, service } => {
                // 1. Service-local
                if let Some(upstream) = self.find_service_upstream(namespace, service, reference) {
                    return Some(upstream);
                }
                // 2. Namespace-local
                if let Some(upstream) = self.find_namespace_upstream(namespace, reference) {
                    return Some(upstream);
                }
                // 3. Exported
                if let Some(upstream) = self.find_exported_upstream(reference) {
                    return Some(upstream);
                }
                // 4. Global
                self.config.upstreams.get(reference)
            }
            Scope::Namespace(namespace) => {
                // 1. Namespace-local
                if let Some(upstream) = self.find_namespace_upstream(namespace, reference) {
                    return Some(upstream);
                }
                // 2. Exported
                if let Some(upstream) = self.find_exported_upstream(reference) {
                    return Some(upstream);
                }
                // 3. Global
                self.config.upstreams.get(reference)
            }
            Scope::Global => {
                // 1. Global
                if let Some(upstream) = self.config.upstreams.get(reference) {
                    return Some(upstream);
                }
                // 2. Exported (visible from anywhere including global)
                self.find_exported_upstream(reference)
            }
        }
    }

    /// Resolve a qualified upstream ID directly.
    fn resolve_upstream_qualified(&self, qid: &QualifiedId) -> Option<&'a UpstreamConfig> {
        match &qid.scope {
            Scope::Global => self.config.upstreams.get(&qid.name),
            Scope::Namespace(ns) => self.find_namespace_upstream(ns, &qid.name),
            Scope::Service { namespace, service } => {
                self.find_service_upstream(namespace, service, &qid.name)
            }
        }
    }

    fn find_namespace_upstream(&self, ns_id: &str, name: &str) -> Option<&'a UpstreamConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.upstreams.get(name))
    }

    fn find_service_upstream(
        &self,
        ns_id: &str,
        svc_id: &str,
        name: &str,
    ) -> Option<&'a UpstreamConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.services.iter().find(|s| s.id == svc_id))
            .and_then(|svc| svc.upstreams.get(name))
    }

    fn find_exported_upstream(&self, name: &str) -> Option<&'a UpstreamConfig> {
        for ns in &self.config.namespaces {
            if ns.exports.upstreams.contains(&name.to_string()) {
                if let Some(upstream) = ns.upstreams.get(name) {
                    return Some(upstream);
                }
            }
        }
        None
    }

    // ========================================================================
    // Agent Resolution
    // ========================================================================

    /// Resolve an agent reference from the given scope.
    pub fn resolve_agent(&self, reference: &str, from_scope: &Scope) -> Option<&'a AgentConfig> {
        // Qualified reference - direct lookup
        if reference.contains(':') {
            return self.resolve_agent_qualified(&QualifiedId::parse(reference));
        }

        // Unqualified - search scope chain
        match from_scope {
            Scope::Service { namespace, service } => {
                // 1. Service-local
                if let Some(agent) = self.find_service_agent(namespace, service, reference) {
                    return Some(agent);
                }
                // 2. Namespace-local
                if let Some(agent) = self.find_namespace_agent(namespace, reference) {
                    return Some(agent);
                }
                // 3. Exported
                if let Some(agent) = self.find_exported_agent(reference) {
                    return Some(agent);
                }
                // 4. Global
                self.config.agents.iter().find(|a| a.id == reference)
            }
            Scope::Namespace(namespace) => {
                // 1. Namespace-local
                if let Some(agent) = self.find_namespace_agent(namespace, reference) {
                    return Some(agent);
                }
                // 2. Exported
                if let Some(agent) = self.find_exported_agent(reference) {
                    return Some(agent);
                }
                // 3. Global
                self.config.agents.iter().find(|a| a.id == reference)
            }
            Scope::Global => {
                // 1. Global
                if let Some(agent) = self.config.agents.iter().find(|a| a.id == reference) {
                    return Some(agent);
                }
                // 2. Exported (visible from anywhere including global)
                self.find_exported_agent(reference)
            }
        }
    }

    fn resolve_agent_qualified(&self, qid: &QualifiedId) -> Option<&'a AgentConfig> {
        match &qid.scope {
            Scope::Global => self.config.agents.iter().find(|a| a.id == qid.name),
            Scope::Namespace(ns) => self.find_namespace_agent(ns, &qid.name),
            Scope::Service { namespace, service } => {
                self.find_service_agent(namespace, service, &qid.name)
            }
        }
    }

    fn find_namespace_agent(&self, ns_id: &str, name: &str) -> Option<&'a AgentConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.agents.iter().find(|a| a.id == name))
    }

    fn find_service_agent(&self, ns_id: &str, svc_id: &str, name: &str) -> Option<&'a AgentConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.services.iter().find(|s| s.id == svc_id))
            .and_then(|svc| svc.agents.iter().find(|a| a.id == name))
    }

    fn find_exported_agent(&self, name: &str) -> Option<&'a AgentConfig> {
        for ns in &self.config.namespaces {
            if ns.exports.agents.contains(&name.to_string()) {
                if let Some(agent) = ns.agents.iter().find(|a| a.id == name) {
                    return Some(agent);
                }
            }
        }
        None
    }

    // ========================================================================
    // Filter Resolution
    // ========================================================================

    /// Resolve a filter reference from the given scope.
    pub fn resolve_filter(&self, reference: &str, from_scope: &Scope) -> Option<&'a FilterConfig> {
        // Qualified reference - direct lookup
        if reference.contains(':') {
            return self.resolve_filter_qualified(&QualifiedId::parse(reference));
        }

        // Unqualified - search scope chain
        match from_scope {
            Scope::Service { namespace, service } => {
                // 1. Service-local
                if let Some(filter) = self.find_service_filter(namespace, service, reference) {
                    return Some(filter);
                }
                // 2. Namespace-local
                if let Some(filter) = self.find_namespace_filter(namespace, reference) {
                    return Some(filter);
                }
                // 3. Exported
                if let Some(filter) = self.find_exported_filter(reference) {
                    return Some(filter);
                }
                // 4. Global
                self.config.filters.get(reference)
            }
            Scope::Namespace(namespace) => {
                // 1. Namespace-local
                if let Some(filter) = self.find_namespace_filter(namespace, reference) {
                    return Some(filter);
                }
                // 2. Exported
                if let Some(filter) = self.find_exported_filter(reference) {
                    return Some(filter);
                }
                // 3. Global
                self.config.filters.get(reference)
            }
            Scope::Global => {
                // 1. Global
                if let Some(filter) = self.config.filters.get(reference) {
                    return Some(filter);
                }
                // 2. Exported (visible from anywhere including global)
                self.find_exported_filter(reference)
            }
        }
    }

    fn resolve_filter_qualified(&self, qid: &QualifiedId) -> Option<&'a FilterConfig> {
        match &qid.scope {
            Scope::Global => self.config.filters.get(&qid.name),
            Scope::Namespace(ns) => self.find_namespace_filter(ns, &qid.name),
            Scope::Service { namespace, service } => {
                self.find_service_filter(namespace, service, &qid.name)
            }
        }
    }

    fn find_namespace_filter(&self, ns_id: &str, name: &str) -> Option<&'a FilterConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.filters.get(name))
    }

    fn find_service_filter(
        &self,
        ns_id: &str,
        svc_id: &str,
        name: &str,
    ) -> Option<&'a FilterConfig> {
        self.config
            .namespaces
            .iter()
            .find(|ns| ns.id == ns_id)
            .and_then(|ns| ns.services.iter().find(|s| s.id == svc_id))
            .and_then(|svc| svc.filters.get(name))
    }

    fn find_exported_filter(&self, name: &str) -> Option<&'a FilterConfig> {
        for ns in &self.config.namespaces {
            if ns.exports.filters.contains(&name.to_string()) {
                if let Some(filter) = ns.filters.get(name) {
                    return Some(filter);
                }
            }
        }
        None
    }

    // ========================================================================
    // Namespace/Service Lookups
    // ========================================================================

    /// Get a namespace by ID.
    pub fn get_namespace(&self, id: &str) -> Option<&'a NamespaceConfig> {
        self.config.namespaces.iter().find(|ns| ns.id == id)
    }

    /// Get a service by namespace and service ID.
    pub fn get_service(&self, namespace: &str, service: &str) -> Option<&'a ServiceConfig> {
        self.get_namespace(namespace)
            .and_then(|ns| ns.services.iter().find(|s| s.id == service))
    }

    /// Check if an upstream reference can be resolved from the given scope.
    pub fn can_resolve_upstream(&self, reference: &str, from_scope: &Scope) -> bool {
        self.resolve_upstream(reference, from_scope).is_some()
    }

    /// Check if an agent reference can be resolved from the given scope.
    pub fn can_resolve_agent(&self, reference: &str, from_scope: &Scope) -> bool {
        self.resolve_agent(reference, from_scope).is_some()
    }

    /// Check if a filter reference can be resolved from the given scope.
    pub fn can_resolve_filter(&self, reference: &str, from_scope: &Scope) -> bool {
        self.resolve_filter(reference, from_scope).is_some()
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
    use zentinel_common::types::LoadBalancingAlgorithm;
    use std::collections::HashMap;

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
            sticky_session: None,
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
        config.upstreams.insert(
            "global-backend".to_string(),
            test_upstream("global-backend"),
        );

        // Add namespace with upstream
        let mut ns = NamespaceConfig::new("api");
        ns.upstreams
            .insert("ns-backend".to_string(), test_upstream("ns-backend"));
        ns.upstreams.insert(
            "shared-backend".to_string(),
            test_upstream("shared-backend"),
        );
        ns.exports = ExportConfig {
            upstreams: vec!["shared-backend".to_string()],
            agents: vec![],
            filters: vec![],
        };

        // Add service with upstream
        let mut svc = ServiceConfig::new("payments");
        svc.upstreams
            .insert("svc-backend".to_string(), test_upstream("svc-backend"));
        ns.services.push(svc);

        config.namespaces.push(ns);
        config
    }

    #[test]
    fn test_resolve_global_upstream_from_global() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let result = resolver.resolve_upstream("global-backend", &Scope::Global);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "global-backend");
    }

    #[test]
    fn test_resolve_global_upstream_from_namespace() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let scope = Scope::Namespace("api".to_string());
        let result = resolver.resolve_upstream("global-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "global-backend");
    }

    #[test]
    fn test_resolve_namespace_upstream_from_namespace() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let scope = Scope::Namespace("api".to_string());
        let result = resolver.resolve_upstream("ns-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "ns-backend");
    }

    #[test]
    fn test_namespace_upstream_not_visible_from_global() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let result = resolver.resolve_upstream("ns-backend", &Scope::Global);
        assert!(result.is_none());
    }

    #[test]
    fn test_resolve_service_upstream_from_service() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let result = resolver.resolve_upstream("svc-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "svc-backend");
    }

    #[test]
    fn test_service_can_access_namespace_upstream() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let result = resolver.resolve_upstream("ns-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "ns-backend");
    }

    #[test]
    fn test_service_can_access_global_upstream() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let result = resolver.resolve_upstream("global-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "global-backend");
    }

    #[test]
    fn test_exported_upstream_visible_globally() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        // Exported upstream should be visible from global scope
        let result = resolver.resolve_upstream("shared-backend", &Scope::Global);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "shared-backend");
    }

    #[test]
    fn test_exported_upstream_visible_from_other_namespace() {
        let mut config = test_config();

        // Add another namespace
        let other_ns = NamespaceConfig::new("web");
        config.namespaces.push(other_ns);

        let resolver = ResourceResolver::new(&config);

        // Should be able to access exported upstream from api namespace
        let scope = Scope::Namespace("web".to_string());
        let result = resolver.resolve_upstream("shared-backend", &scope);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "shared-backend");
    }

    #[test]
    fn test_qualified_reference_direct_lookup() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        // Qualified reference bypasses scope chain
        let result = resolver.resolve_upstream("api:ns-backend", &Scope::Global);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "ns-backend");
    }

    #[test]
    fn test_qualified_service_reference() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        // Qualified service reference
        let result = resolver.resolve_upstream("api:payments:svc-backend", &Scope::Global);
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "svc-backend");
    }

    #[test]
    fn test_nonexistent_upstream() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        let result = resolver.resolve_upstream("nonexistent", &Scope::Global);
        assert!(result.is_none());
    }

    #[test]
    fn test_can_resolve_upstream() {
        let config = test_config();
        let resolver = ResourceResolver::new(&config);

        assert!(resolver.can_resolve_upstream("global-backend", &Scope::Global));
        assert!(!resolver.can_resolve_upstream("ns-backend", &Scope::Global));
        assert!(resolver.can_resolve_upstream("ns-backend", &Scope::Namespace("api".to_string())));
    }
}
