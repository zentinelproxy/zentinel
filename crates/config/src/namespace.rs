//! Namespace and service configuration for hierarchical organization.
//!
//! This module provides configuration types for organizing Sentinel resources
//! into logical groups using namespaces and services.
//!
//! # Hierarchy
//!
//! ```text
//! Config (root)
//! ├── Global resources (listeners, routes, upstreams, agents, filters)
//! └── namespaces[]
//!     ├── Namespace-level resources
//!     └── services[]
//!         └── Service-level resources
//! ```
//!
//! # Scoping Rules
//!
//! - **Global resources**: Visible everywhere in the configuration
//! - **Namespace resources**: Visible within the namespace and its services
//! - **Service resources**: Local to the specific service
//! - **Exports**: Namespace resources can be exported to make them globally visible
//!
//! Resolution follows "most specific wins": Service → Namespace → Exported → Global

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sentinel_common::limits::Limits;

use crate::{
    AgentConfig, FilterConfig, ListenerConfig, RouteConfig, UpstreamConfig,
};

// ============================================================================
// Namespace Configuration
// ============================================================================

/// Configuration for a namespace - a logical grouping of related resources.
///
/// Namespaces provide domain-driven boundaries within the configuration,
/// allowing operators to organize resources by team, service domain, or
/// any other logical grouping.
///
/// # Example KDL
///
/// ```kdl
/// namespace "api" {
///     limits {
///         max-body-size 10485760
///     }
///
///     upstreams {
///         upstream "backend" { ... }
///     }
///
///     routes {
///         route "users" {
///             upstream "backend"  // Resolves to api:backend
///         }
///     }
///
///     service "payments" {
///         // Service-specific configuration
///     }
///
///     exports {
///         upstreams "backend"  // Make globally visible
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NamespaceConfig {
    /// Unique namespace identifier.
    ///
    /// Must not contain the `:` character as it's reserved for
    /// qualified ID syntax (e.g., `namespace:resource`).
    pub id: String,

    /// Namespace-level limits.
    ///
    /// These limits override global limits and are overridden by
    /// service-level limits. If not specified, global limits apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,

    /// Namespace-level listeners.
    ///
    /// Listeners at the namespace level are shared across all
    /// services within the namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listeners: Vec<ListenerConfig>,

    /// Namespace-level upstreams.
    ///
    /// These upstreams are visible to all routes within the namespace
    /// and its services. They can be referenced without qualification
    /// from within the namespace.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Namespace-level routes.
    ///
    /// Routes defined at the namespace level can reference namespace
    /// upstreams without qualification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,

    /// Namespace-level agents.
    ///
    /// Agents at this level are visible to all filters within the
    /// namespace and its services.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentConfig>,

    /// Namespace-level filters.
    ///
    /// Filters at this level can be referenced by routes within
    /// the namespace and its services.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub filters: HashMap<String, FilterConfig>,

    /// Services within this namespace.
    ///
    /// Services provide more granular grouping within a namespace,
    /// typically representing individual microservices or API groups.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceConfig>,

    /// Resources exported from this namespace.
    ///
    /// Exported resources become globally visible and can be
    /// referenced from any scope without qualification.
    #[serde(default, skip_serializing_if = "ExportConfig::is_empty")]
    pub exports: ExportConfig,
}

impl NamespaceConfig {
    /// Create a new namespace with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }

    /// Returns true if this namespace contains no resources.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
            && self.upstreams.is_empty()
            && self.routes.is_empty()
            && self.agents.is_empty()
            && self.filters.is_empty()
            && self.services.is_empty()
            && self.limits.is_none()
    }

    /// Get a service by ID within this namespace.
    pub fn get_service(&self, id: &str) -> Option<&ServiceConfig> {
        self.services.iter().find(|s| s.id == id)
    }

    /// Get a mutable service by ID within this namespace.
    pub fn get_service_mut(&mut self, id: &str) -> Option<&mut ServiceConfig> {
        self.services.iter_mut().find(|s| s.id == id)
    }
}

// ============================================================================
// Service Configuration
// ============================================================================

/// Configuration for a service within a namespace.
///
/// Services represent individual microservices, API groups, or logical
/// components that need their own listener, routes, and backend configuration.
///
/// # Example KDL
///
/// ```kdl
/// service "payments" {
///     listener {
///         address "0.0.0.0:8443"
///         protocol "https"
///         tls { ... }
///     }
///
///     upstreams {
///         upstream "payments-backend" { ... }
///     }
///
///     routes {
///         route "checkout" {
///             upstream "payments-backend"  // Service-local
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceConfig {
    /// Unique service identifier within the namespace.
    ///
    /// Must not contain the `:` character as it's reserved for
    /// qualified ID syntax (e.g., `namespace:service:resource`).
    pub id: String,

    /// Service-specific listener.
    ///
    /// Unlike namespace listeners (which are collections), a service
    /// typically has a single dedicated listener for its traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listener: Option<ListenerConfig>,

    /// Service-local upstreams.
    ///
    /// These upstreams are only visible within this service.
    /// They shadow any namespace or global upstreams with the same name.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Service-local routes.
    ///
    /// Routes can reference service-local, namespace, or global upstreams.
    /// Resolution follows "most specific wins".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteConfig>,

    /// Service-local agents.
    ///
    /// These agents are only visible within this service.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<AgentConfig>,

    /// Service-local filters.
    ///
    /// These filters can only be referenced by routes within this service.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub filters: HashMap<String, FilterConfig>,

    /// Service-level limits.
    ///
    /// These limits override both global and namespace limits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}

impl ServiceConfig {
    /// Create a new service with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            ..Default::default()
        }
    }

    /// Returns true if this service contains no resources.
    pub fn is_empty(&self) -> bool {
        self.listener.is_none()
            && self.upstreams.is_empty()
            && self.routes.is_empty()
            && self.agents.is_empty()
            && self.filters.is_empty()
            && self.limits.is_none()
    }
}

// ============================================================================
// Export Configuration
// ============================================================================

/// Configuration for exporting namespace resources globally.
///
/// Exported resources become visible from any scope in the configuration,
/// allowing namespaces to share common resources (like shared auth upstreams
/// or common filters) with other parts of the system.
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportConfig {
    /// Upstream IDs to export globally.
    ///
    /// These upstreams become visible from any scope and can be
    /// referenced without namespace qualification.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,

    /// Agent IDs to export globally.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,

    /// Filter IDs to export globally.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<String>,
}

impl ExportConfig {
    /// Returns true if no resources are exported.
    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty() && self.agents.is_empty() && self.filters.is_empty()
    }

    /// Returns the total number of exported resources.
    pub fn len(&self) -> usize {
        self.upstreams.len() + self.agents.len() + self.filters.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionPoolConfig, HttpVersionConfig, UpstreamTarget, UpstreamTimeouts};
    use sentinel_common::types::LoadBalancingAlgorithm;

    /// Create a minimal upstream config for testing
    fn test_upstream() -> UpstreamConfig {
        UpstreamConfig {
            id: "test-upstream".to_string(),
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

    #[test]
    fn test_namespace_new() {
        let ns = NamespaceConfig::new("api");
        assert_eq!(ns.id, "api");
        assert!(ns.is_empty());
    }

    #[test]
    fn test_namespace_is_empty() {
        let mut ns = NamespaceConfig::new("api");
        assert!(ns.is_empty());

        ns.upstreams.insert("backend".to_string(), test_upstream());
        assert!(!ns.is_empty());
    }

    #[test]
    fn test_service_new() {
        let svc = ServiceConfig::new("payments");
        assert_eq!(svc.id, "payments");
        assert!(svc.is_empty());
    }

    #[test]
    fn test_service_is_empty() {
        let mut svc = ServiceConfig::new("payments");
        assert!(svc.is_empty());

        svc.upstreams.insert("backend".to_string(), test_upstream());
        assert!(!svc.is_empty());
    }

    #[test]
    fn test_export_config_is_empty() {
        let exports = ExportConfig::default();
        assert!(exports.is_empty());
        assert_eq!(exports.len(), 0);
    }

    #[test]
    fn test_export_config_len() {
        let exports = ExportConfig {
            upstreams: vec!["a".to_string(), "b".to_string()],
            agents: vec!["c".to_string()],
            filters: vec![],
        };
        assert!(!exports.is_empty());
        assert_eq!(exports.len(), 3);
    }

    #[test]
    fn test_namespace_get_service() {
        let mut ns = NamespaceConfig::new("api");
        ns.services.push(ServiceConfig::new("payments"));
        ns.services.push(ServiceConfig::new("users"));

        assert!(ns.get_service("payments").is_some());
        assert!(ns.get_service("users").is_some());
        assert!(ns.get_service("orders").is_none());
    }

    #[test]
    fn test_namespace_serialization() {
        let ns = NamespaceConfig {
            id: "api".to_string(),
            limits: None,
            listeners: vec![],
            upstreams: HashMap::new(),
            routes: vec![],
            agents: vec![],
            filters: HashMap::new(),
            services: vec![ServiceConfig::new("payments")],
            exports: ExportConfig::default(),
        };

        let json = serde_json::to_string(&ns).unwrap();
        let parsed: NamespaceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "api");
        assert_eq!(parsed.services.len(), 1);
        assert_eq!(parsed.services[0].id, "payments");
    }
}
