//! Type-safe identifier newtypes for Sentinel proxy.
//!
//! These types provide compile-time safety for identifiers, preventing
//! accidental mixing of different ID types (e.g., passing a RouteId
//! where an UpstreamId is expected).
//!
//! # Scoped Identifiers
//!
//! Sentinel supports hierarchical configuration through namespaces and services.
//! The [`Scope`] enum represents where a resource is defined, and [`QualifiedId`]
//! combines a local name with its scope for unambiguous identification.
//!
//! ```
//! use sentinel_common::ids::{Scope, QualifiedId};
//!
//! // Global resource
//! let global = QualifiedId::global("shared-auth");
//! assert_eq!(global.canonical(), "shared-auth");
//!
//! // Namespace-scoped resource
//! let namespaced = QualifiedId::namespaced("api", "backend");
//! assert_eq!(namespaced.canonical(), "api:backend");
//!
//! // Service-scoped resource
//! let service = QualifiedId::in_service("api", "payments", "checkout");
//! assert_eq!(service.canonical(), "api:payments:checkout");
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ============================================================================
// Scope and Qualified ID Types
// ============================================================================

/// Represents where a resource is defined in the configuration hierarchy.
///
/// Sentinel supports three levels of scoping:
/// - **Global**: Resources defined at the root level, visible everywhere
/// - **Namespace**: Resources scoped to a namespace, visible within that namespace
/// - **Service**: Resources scoped to a service within a namespace
///
/// The resolution order follows "most specific wins": Service → Namespace → Global.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Scope {
    /// Global scope - visible everywhere in the configuration
    Global,
    /// Namespace scope - visible within the namespace and its services
    Namespace(String),
    /// Service scope - local to a specific service within a namespace
    Service {
        namespace: String,
        service: String,
    },
}

impl Scope {
    /// Returns true if this is the global scope
    pub fn is_global(&self) -> bool {
        matches!(self, Scope::Global)
    }

    /// Returns true if this is a namespace scope
    pub fn is_namespace(&self) -> bool {
        matches!(self, Scope::Namespace(_))
    }

    /// Returns true if this is a service scope
    pub fn is_service(&self) -> bool {
        matches!(self, Scope::Service { .. })
    }

    /// Returns the namespace name if this scope is within a namespace
    pub fn namespace(&self) -> Option<&str> {
        match self {
            Scope::Global => None,
            Scope::Namespace(ns) => Some(ns),
            Scope::Service { namespace, .. } => Some(namespace),
        }
    }

    /// Returns the service name if this is a service scope
    pub fn service(&self) -> Option<&str> {
        match self {
            Scope::Service { service, .. } => Some(service),
            _ => None,
        }
    }

    /// Returns the parent scope (Service → Namespace → Global)
    pub fn parent(&self) -> Option<Scope> {
        match self {
            Scope::Global => None,
            Scope::Namespace(_) => Some(Scope::Global),
            Scope::Service { namespace, .. } => Some(Scope::Namespace(namespace.clone())),
        }
    }

    /// Returns the scope chain from most specific to least specific
    pub fn chain(&self) -> Vec<Scope> {
        let mut chain = vec![self.clone()];
        let mut current = self.clone();
        while let Some(parent) = current.parent() {
            chain.push(parent.clone());
            current = parent;
        }
        chain
    }
}

impl Default for Scope {
    fn default() -> Self {
        Scope::Global
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Global => write!(f, "global"),
            Scope::Namespace(ns) => write!(f, "namespace:{}", ns),
            Scope::Service { namespace, service } => {
                write!(f, "service:{}:{}", namespace, service)
            }
        }
    }
}

/// A qualified identifier combining a local name with its scope.
///
/// Qualified IDs enable unambiguous resource identification across
/// the configuration hierarchy. They support both qualified references
/// (e.g., `api:backend`) and unqualified references that resolve
/// through the scope chain.
///
/// # Canonical Form
///
/// The canonical string representation uses `:` as a separator:
/// - Global: `"name"`
/// - Namespace: `"namespace:name"`
/// - Service: `"namespace:service:name"`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QualifiedId {
    /// The local name within the scope
    pub name: String,
    /// The scope where this resource is defined
    pub scope: Scope,
}

impl QualifiedId {
    /// Create a new qualified ID with the given name and scope
    pub fn new(name: impl Into<String>, scope: Scope) -> Self {
        Self {
            name: name.into(),
            scope,
        }
    }

    /// Create a global-scope qualified ID
    pub fn global(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: Scope::Global,
        }
    }

    /// Create a namespace-scoped qualified ID
    pub fn namespaced(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            scope: Scope::Namespace(namespace.into()),
        }
    }

    /// Create a service-scoped qualified ID
    pub fn in_service(
        namespace: impl Into<String>,
        service: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            scope: Scope::Service {
                namespace: namespace.into(),
                service: service.into(),
            },
        }
    }

    /// Returns the canonical string form of this qualified ID
    ///
    /// Format:
    /// - Global: `"name"`
    /// - Namespace: `"namespace:name"`
    /// - Service: `"namespace:service:name"`
    pub fn canonical(&self) -> String {
        match &self.scope {
            Scope::Global => self.name.clone(),
            Scope::Namespace(ns) => format!("{}:{}", ns, self.name),
            Scope::Service { namespace, service } => {
                format!("{}:{}:{}", namespace, service, self.name)
            }
        }
    }

    /// Parse a qualified ID from its canonical string form
    ///
    /// Parsing rules:
    /// - No colons: Global scope (`"name"` → Global)
    /// - One colon: Namespace scope (`"ns:name"` → Namespace)
    /// - Two+ colons: Service scope (`"ns:svc:name"` → Service)
    pub fn parse(s: &str) -> Self {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            [name] => Self::global(*name),
            [namespace, name] => Self::namespaced(*namespace, *name),
            [namespace, service, name] => Self::in_service(*namespace, *service, *name),
            _ => Self::global(s), // Fallback for empty string
        }
    }

    /// Returns true if this ID is in the global scope
    pub fn is_global(&self) -> bool {
        self.scope.is_global()
    }

    /// Returns true if this is a qualified (non-global) ID
    pub fn is_qualified(&self) -> bool {
        !self.scope.is_global()
    }

    /// Returns the local name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the scope
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
}

impl fmt::Display for QualifiedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

impl From<&str> for QualifiedId {
    fn from(s: &str) -> Self {
        Self::parse(s)
    }
}

impl From<String> for QualifiedId {
    fn from(s: String) -> Self {
        Self::parse(&s)
    }
}

// ============================================================================
// Original ID Types
// ============================================================================

/// Unique correlation ID for request tracing across components.
///
/// Correlation IDs follow requests through the entire proxy pipeline,
/// enabling end-to-end tracing and log correlation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(String);

impl CorrelationId {
    /// Create a new random correlation ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from an existing string
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert to owned String
    pub fn into_string(self) -> String {
        self.0
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for CorrelationId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for CorrelationId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Unique request ID for internal tracking.
///
/// Request IDs are generated per-request and used for internal
/// metrics, logging, and debugging.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(String);

impl RequestId {
    /// Create a new random request ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Get the inner string value
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Route identifier.
///
/// Identifies a configured route in the proxy. Routes define
/// how requests are matched and forwarded to upstreams.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RouteId(String);

impl RouteId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Upstream identifier.
///
/// Identifies a configured upstream pool. Upstreams are groups
/// of backend servers that handle requests.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UpstreamId(String);

impl UpstreamId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UpstreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Agent identifier.
///
/// Identifies a configured external processing agent (WAF, auth, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Scope Tests
    // ========================================================================

    #[test]
    fn test_scope_global() {
        let scope = Scope::Global;
        assert!(scope.is_global());
        assert!(!scope.is_namespace());
        assert!(!scope.is_service());
        assert_eq!(scope.namespace(), None);
        assert_eq!(scope.service(), None);
        assert_eq!(scope.parent(), None);
    }

    #[test]
    fn test_scope_namespace() {
        let scope = Scope::Namespace("api".to_string());
        assert!(!scope.is_global());
        assert!(scope.is_namespace());
        assert!(!scope.is_service());
        assert_eq!(scope.namespace(), Some("api"));
        assert_eq!(scope.service(), None);
        assert_eq!(scope.parent(), Some(Scope::Global));
    }

    #[test]
    fn test_scope_service() {
        let scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        assert!(!scope.is_global());
        assert!(!scope.is_namespace());
        assert!(scope.is_service());
        assert_eq!(scope.namespace(), Some("api"));
        assert_eq!(scope.service(), Some("payments"));
        assert_eq!(
            scope.parent(),
            Some(Scope::Namespace("api".to_string()))
        );
    }

    #[test]
    fn test_scope_chain() {
        let service_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let chain = service_scope.chain();
        assert_eq!(chain.len(), 3);
        assert_eq!(
            chain[0],
            Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string()
            }
        );
        assert_eq!(chain[1], Scope::Namespace("api".to_string()));
        assert_eq!(chain[2], Scope::Global);
    }

    #[test]
    fn test_scope_display() {
        assert_eq!(Scope::Global.to_string(), "global");
        assert_eq!(
            Scope::Namespace("api".to_string()).to_string(),
            "namespace:api"
        );
        assert_eq!(
            Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string()
            }
            .to_string(),
            "service:api:payments"
        );
    }

    // ========================================================================
    // QualifiedId Tests
    // ========================================================================

    #[test]
    fn test_qualified_id_global() {
        let qid = QualifiedId::global("backend");
        assert_eq!(qid.name(), "backend");
        assert_eq!(qid.scope(), &Scope::Global);
        assert_eq!(qid.canonical(), "backend");
        assert!(qid.is_global());
        assert!(!qid.is_qualified());
    }

    #[test]
    fn test_qualified_id_namespaced() {
        let qid = QualifiedId::namespaced("api", "backend");
        assert_eq!(qid.name(), "backend");
        assert_eq!(qid.scope(), &Scope::Namespace("api".to_string()));
        assert_eq!(qid.canonical(), "api:backend");
        assert!(!qid.is_global());
        assert!(qid.is_qualified());
    }

    #[test]
    fn test_qualified_id_service() {
        let qid = QualifiedId::in_service("api", "payments", "checkout");
        assert_eq!(qid.name(), "checkout");
        assert_eq!(
            qid.scope(),
            &Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string()
            }
        );
        assert_eq!(qid.canonical(), "api:payments:checkout");
        assert!(!qid.is_global());
        assert!(qid.is_qualified());
    }

    #[test]
    fn test_qualified_id_parse_global() {
        let qid = QualifiedId::parse("backend");
        assert_eq!(qid.name(), "backend");
        assert_eq!(qid.scope(), &Scope::Global);
    }

    #[test]
    fn test_qualified_id_parse_namespaced() {
        let qid = QualifiedId::parse("api:backend");
        assert_eq!(qid.name(), "backend");
        assert_eq!(qid.scope(), &Scope::Namespace("api".to_string()));
    }

    #[test]
    fn test_qualified_id_parse_service() {
        let qid = QualifiedId::parse("api:payments:checkout");
        assert_eq!(qid.name(), "checkout");
        assert_eq!(
            qid.scope(),
            &Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string()
            }
        );
    }

    #[test]
    fn test_qualified_id_parse_with_extra_colons() {
        // Names can contain colons after the service part
        let qid = QualifiedId::parse("api:payments:item:with:colons");
        assert_eq!(qid.name(), "item:with:colons");
        assert_eq!(
            qid.scope(),
            &Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string()
            }
        );
    }

    #[test]
    fn test_qualified_id_from_str() {
        let qid: QualifiedId = "api:backend".into();
        assert_eq!(qid.canonical(), "api:backend");
    }

    #[test]
    fn test_qualified_id_display() {
        let qid = QualifiedId::in_service("ns", "svc", "resource");
        assert_eq!(qid.to_string(), "ns:svc:resource");
    }

    #[test]
    fn test_qualified_id_equality() {
        let qid1 = QualifiedId::namespaced("api", "backend");
        let qid2 = QualifiedId::parse("api:backend");
        assert_eq!(qid1, qid2);
    }

    #[test]
    fn test_qualified_id_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(QualifiedId::global("backend"));
        set.insert(QualifiedId::namespaced("api", "backend"));
        set.insert(QualifiedId::in_service("api", "svc", "backend"));

        // All three should be distinct
        assert_eq!(set.len(), 3);

        // Should find the namespaced one
        assert!(set.contains(&QualifiedId::parse("api:backend")));
    }

    // ========================================================================
    // Original ID Type Tests
    // ========================================================================

    #[test]
    fn test_correlation_id() {
        let id1 = CorrelationId::new();
        let id2 = CorrelationId::from_string("test-id");

        assert_ne!(id1, id2);
        assert_eq!(id2.as_str(), "test-id");
    }

    #[test]
    fn test_route_id() {
        let id = RouteId::new("my-route");
        assert_eq!(id.as_str(), "my-route");
        assert_eq!(id.to_string(), "my-route");
    }

    #[test]
    fn test_upstream_id() {
        let id = UpstreamId::new("backend-pool");
        assert_eq!(id.as_str(), "backend-pool");
    }

    #[test]
    fn test_agent_id() {
        let id = AgentId::new("waf-agent");
        assert_eq!(id.as_str(), "waf-agent");
    }
}
