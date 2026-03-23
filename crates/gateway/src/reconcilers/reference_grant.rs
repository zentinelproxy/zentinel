//! ReferenceGrant index for cross-namespace reference validation.
//!
//! Maintains an in-memory index of all ReferenceGrant resources to quickly
//! check whether a cross-namespace reference is permitted.

use gateway_api::referencegrants::ReferenceGrant;
use kube::ResourceExt;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

/// A permitted cross-namespace reference.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PermittedReference {
    /// Namespace where the ReferenceGrant lives (target namespace).
    pub target_namespace: String,
    /// Source namespace that is granted permission.
    pub source_namespace: String,
    /// Source group (e.g., "gateway.networking.k8s.io").
    pub source_group: String,
    /// Source kind (e.g., "HTTPRoute", "Gateway").
    pub source_kind: String,
    /// Target group (e.g., "" for core, "gateway.networking.k8s.io").
    pub target_group: String,
    /// Target kind (e.g., "Service", "Secret").
    pub target_kind: String,
    /// Target name, if restricted. Empty means all resources of that kind.
    pub target_name: String,
}

/// Query parameters for checking a cross-namespace reference.
pub struct ReferenceQuery<'a> {
    pub source_namespace: &'a str,
    pub source_group: &'a str,
    pub source_kind: &'a str,
    pub target_namespace: &'a str,
    pub target_group: &'a str,
    pub target_kind: &'a str,
    pub target_name: &'a str,
}

/// In-memory index of ReferenceGrant permissions.
///
/// This is rebuilt whenever ReferenceGrant resources change. Lookups use
/// a `parking_lot::RwLock` for fast concurrent reads.
pub struct ReferenceGrantIndex {
    grants: Arc<parking_lot::RwLock<HashSet<PermittedReference>>>,
}

impl ReferenceGrantIndex {
    pub fn new() -> Self {
        Self {
            grants: Arc::new(parking_lot::RwLock::new(HashSet::new())),
        }
    }

    /// Rebuild the index from a list of ReferenceGrant resources.
    pub fn rebuild(&self, grants: Vec<ReferenceGrant>) {
        let mut permitted = HashSet::new();

        for grant in &grants {
            let target_ns: String = grant.namespace().unwrap_or_default().to_string();

            for from in &grant.spec.from {
                let source_ns = from.namespace.clone();
                let source_group = from.group.clone();
                let source_kind = from.kind.clone();

                for to in &grant.spec.to {
                    let target_group = to.group.clone();
                    let target_kind = to.kind.clone();
                    let target_name: String = to.name.clone().unwrap_or_default();

                    permitted.insert(PermittedReference {
                        target_namespace: target_ns.clone(),
                        source_namespace: source_ns.clone(),
                        source_group: source_group.clone(),
                        source_kind: source_kind.clone(),
                        target_group,
                        target_kind,
                        target_name,
                    });
                }
            }
        }

        info!(count = permitted.len(), "Rebuilt ReferenceGrant index");
        *self.grants.write() = permitted;
    }

    /// Check if a cross-namespace reference is permitted.
    ///
    /// Returns `true` if either:
    /// - The source and target are in the same namespace (no grant needed)
    /// - A matching ReferenceGrant exists (all fields must match)
    pub fn is_permitted(&self, q: &ReferenceQuery<'_>) -> bool {
        let source_namespace = q.source_namespace;
        let source_group = q.source_group;
        let source_kind = q.source_kind;
        let target_namespace = q.target_namespace;
        let target_group = q.target_group;
        let target_kind = q.target_kind;
        let target_name = q.target_name;

        // Same-namespace references are always allowed
        if source_namespace == target_namespace {
            return true;
        }

        let grants = self.grants.read();

        // Check for exact name match
        let exact = PermittedReference {
            target_namespace: target_namespace.to_string(),
            source_namespace: source_namespace.to_string(),
            source_group: source_group.to_string(),
            source_kind: source_kind.to_string(),
            target_group: target_group.to_string(),
            target_kind: target_kind.to_string(),
            target_name: target_name.to_string(),
        };
        if grants.contains(&exact) {
            debug!(
                source_ns = source_namespace,
                target_ns = target_namespace,
                target_kind = target_kind,
                target_name = target_name,
                "Cross-namespace reference permitted (exact match)"
            );
            return true;
        }

        // Check for wildcard (empty name = all resources of that kind)
        let wildcard = PermittedReference {
            target_namespace: target_namespace.to_string(),
            source_namespace: source_namespace.to_string(),
            source_group: source_group.to_string(),
            source_kind: source_kind.to_string(),
            target_group: target_group.to_string(),
            target_kind: target_kind.to_string(),
            target_name: String::new(),
        };
        if grants.contains(&wildcard) {
            debug!(
                source_ns = source_namespace,
                target_ns = target_namespace,
                target_kind = target_kind,
                target_name = target_name,
                "Cross-namespace reference permitted (wildcard)"
            );
            return true;
        }

        false
    }
}

impl Default for ReferenceGrantIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_namespace_always_permitted() {
        let index = ReferenceGrantIndex::new();
        assert!(index.is_permitted(&ReferenceQuery {
            source_namespace: "default",
            source_group: "gateway.networking.k8s.io",
            source_kind: "HTTPRoute",
            target_namespace: "default",
            target_group: "",
            target_kind: "Service",
            target_name: "my-svc",
        }));
    }

    #[test]
    fn cross_namespace_denied_without_grant() {
        let index = ReferenceGrantIndex::new();
        assert!(!index.is_permitted(&ReferenceQuery {
            source_namespace: "web",
            source_group: "gateway.networking.k8s.io",
            source_kind: "HTTPRoute",
            target_namespace: "backend",
            target_group: "",
            target_kind: "Service",
            target_name: "api",
        }));
    }
}
