//! Scoped registry for hierarchical component storage.
//!
//! This module provides [`ScopedRegistry<T>`] which extends the basic [`Registry`](super::Registry)
//! pattern with scope-aware lookups. Components are indexed by their [`QualifiedId`] and can be
//! resolved using the scope chain (service → namespace → global).
//!
//! # Example
//!
//! ```ignore
//! use zentinel_common::{ScopedRegistry, QualifiedId, Scope};
//!
//! let registry: ScopedRegistry<UpstreamPool> = ScopedRegistry::new();
//!
//! // Insert components at different scopes
//! registry.insert(QualifiedId::global("shared-pool"), pool1).await;
//! registry.insert(QualifiedId::namespaced("api", "backend"), pool2).await;
//!
//! // Resolve from a service scope - will search service → namespace → global
//! let scope = Scope::Service { namespace: "api".into(), service: "payments".into() };
//! let pool = registry.resolve("backend", &scope).await;
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::ids::{QualifiedId, Scope};

/// A thread-safe registry with scope-aware resolution.
///
/// Items are stored with their full [`QualifiedId`] but can be looked up
/// using just a local name and a scope. The registry will search through
/// the scope chain (most specific to least specific) to find a match.
#[derive(Debug)]
pub struct ScopedRegistry<T> {
    /// Items indexed by canonical ID (e.g., "api:payments:backend")
    items: Arc<RwLock<HashMap<String, Arc<T>>>>,

    /// Local names available at each scope for fast resolution
    /// Maps scope → set of local names available at that scope
    scope_index: Arc<RwLock<HashMap<Scope, HashSet<String>>>>,

    /// Exported names (local names that are globally visible)
    exported: Arc<RwLock<HashSet<String>>>,
}

impl<T> ScopedRegistry<T> {
    /// Create a new empty scoped registry.
    pub fn new() -> Self {
        Self {
            items: Arc::new(RwLock::new(HashMap::new())),
            scope_index: Arc::new(RwLock::new(HashMap::new())),
            exported: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Get an item by its exact canonical ID.
    pub async fn get_by_canonical(&self, canonical: &str) -> Option<Arc<T>> {
        self.items.read().await.get(canonical).cloned()
    }

    /// Get an item by its qualified ID.
    pub async fn get(&self, qid: &QualifiedId) -> Option<Arc<T>> {
        self.get_by_canonical(&qid.canonical()).await
    }

    /// Resolve an item by local name from a given scope.
    ///
    /// Searches through the scope chain (most specific to least specific):
    /// 1. Local scope (service or namespace)
    /// 2. Parent scope (namespace if in service)
    /// 3. Exported names
    /// 4. Global scope
    ///
    /// If the reference contains ':', it's treated as a qualified reference
    /// and looked up directly.
    pub async fn resolve(&self, reference: &str, from_scope: &Scope) -> Option<Arc<T>> {
        // Qualified references bypass scope chain
        if reference.contains(':') {
            return self.get_by_canonical(reference).await;
        }

        let items = self.items.read().await;
        let scope_index = self.scope_index.read().await;
        let exported = self.exported.read().await;

        // Search through scope chain
        for scope in from_scope.chain() {
            if let Some(names) = scope_index.get(&scope) {
                if names.contains(reference) {
                    // Construct the canonical ID for this scope
                    let qid = match &scope {
                        Scope::Global => QualifiedId::global(reference),
                        Scope::Namespace(ns) => QualifiedId::namespaced(ns, reference),
                        Scope::Service { namespace, service } => {
                            QualifiedId::in_service(namespace, service, reference)
                        }
                    };
                    if let Some(item) = items.get(&qid.canonical()) {
                        return Some(Arc::clone(item));
                    }
                }
            }
        }

        // Check exported names
        if exported.contains(reference) {
            // Find the first matching exported item
            for (canonical, item) in items.iter() {
                if canonical.ends_with(&format!(":{}", reference)) || canonical == reference {
                    return Some(Arc::clone(item));
                }
            }
        }

        None
    }

    /// Insert an item with its qualified ID.
    pub async fn insert(&self, qid: QualifiedId, item: Arc<T>) -> Option<Arc<T>> {
        let canonical = qid.canonical();
        let local_name = qid.name.clone();
        let scope = qid.scope.clone();

        // Update scope index
        self.scope_index
            .write()
            .await
            .entry(scope)
            .or_default()
            .insert(local_name);

        // Insert item
        self.items.write().await.insert(canonical, item)
    }

    /// Insert an item and mark it as exported (globally visible).
    pub async fn insert_exported(&self, qid: QualifiedId, item: Arc<T>) -> Option<Arc<T>> {
        let local_name = qid.name.clone();
        self.exported.write().await.insert(local_name);
        self.insert(qid, item).await
    }

    /// Mark a local name as exported.
    pub async fn mark_exported(&self, local_name: impl Into<String>) {
        self.exported.write().await.insert(local_name.into());
    }

    /// Remove an item by its qualified ID.
    pub async fn remove(&self, qid: &QualifiedId) -> Option<Arc<T>> {
        let canonical = qid.canonical();
        let local_name = &qid.name;
        let scope = &qid.scope;

        // Remove from scope index
        if let Some(names) = self.scope_index.write().await.get_mut(scope) {
            names.remove(local_name);
        }

        // Remove from exported if present
        self.exported.write().await.remove(local_name);

        // Remove item
        self.items.write().await.remove(&canonical)
    }

    /// Check if an item exists by canonical ID.
    pub async fn contains(&self, qid: &QualifiedId) -> bool {
        self.items.read().await.contains_key(&qid.canonical())
    }

    /// Check if a name can be resolved from a given scope.
    pub async fn can_resolve(&self, reference: &str, from_scope: &Scope) -> bool {
        self.resolve(reference, from_scope).await.is_some()
    }

    /// Get all canonical IDs in the registry.
    pub async fn keys(&self) -> Vec<String> {
        self.items.read().await.keys().cloned().collect()
    }

    /// Get the number of items in the registry.
    pub async fn len(&self) -> usize {
        self.items.read().await.len()
    }

    /// Check if the registry is empty.
    pub async fn is_empty(&self) -> bool {
        self.items.read().await.is_empty()
    }

    /// Clear all items from the registry.
    pub async fn clear(&self) {
        self.items.write().await.clear();
        self.scope_index.write().await.clear();
        self.exported.write().await.clear();
    }

    /// Get all items in a specific scope.
    pub async fn items_in_scope(&self, scope: &Scope) -> Vec<(QualifiedId, Arc<T>)> {
        let items = self.items.read().await;
        let scope_index = self.scope_index.read().await;

        let mut result = Vec::new();

        if let Some(names) = scope_index.get(scope) {
            for name in names {
                let qid = match scope {
                    Scope::Global => QualifiedId::global(name),
                    Scope::Namespace(ns) => QualifiedId::namespaced(ns, name),
                    Scope::Service { namespace, service } => {
                        QualifiedId::in_service(namespace, service, name)
                    }
                };
                if let Some(item) = items.get(&qid.canonical()) {
                    result.push((qid, Arc::clone(item)));
                }
            }
        }

        result
    }

    /// Get all items that are visible from a given scope.
    ///
    /// This includes items in the scope chain plus exported items.
    pub async fn visible_from(&self, scope: &Scope) -> Vec<(QualifiedId, Arc<T>)> {
        let items = self.items.read().await;
        let scope_index = self.scope_index.read().await;
        let exported = self.exported.read().await;

        let mut result = Vec::new();
        let mut seen = HashSet::new();

        // Add items from scope chain
        for s in scope.chain() {
            if let Some(names) = scope_index.get(&s) {
                for name in names {
                    if seen.insert(name.clone()) {
                        let qid = match &s {
                            Scope::Global => QualifiedId::global(name),
                            Scope::Namespace(ns) => QualifiedId::namespaced(ns, name),
                            Scope::Service { namespace, service } => {
                                QualifiedId::in_service(namespace, service, name)
                            }
                        };
                        if let Some(item) = items.get(&qid.canonical()) {
                            result.push((qid, Arc::clone(item)));
                        }
                    }
                }
            }
        }

        // Add exported items not already visible
        for (canonical, item) in items.iter() {
            let qid = QualifiedId::parse(canonical);
            if exported.contains(&qid.name) && !seen.contains(&qid.name) {
                result.push((qid, Arc::clone(item)));
            }
        }

        result
    }

    /// Replace all items atomically.
    ///
    /// Takes a list of (QualifiedId, item, is_exported) tuples.
    pub async fn replace_all(
        &self,
        new_items: Vec<(QualifiedId, Arc<T>, bool)>,
    ) -> HashMap<String, Arc<T>> {
        let mut items_map = HashMap::new();
        let mut scope_index_map: HashMap<Scope, HashSet<String>> = HashMap::new();
        let mut exported_set = HashSet::new();

        for (qid, item, is_exported) in new_items {
            let canonical = qid.canonical();
            let local_name = qid.name.clone();
            let scope = qid.scope.clone();

            items_map.insert(canonical, item);
            scope_index_map
                .entry(scope)
                .or_default()
                .insert(local_name.clone());

            if is_exported {
                exported_set.insert(local_name);
            }
        }

        let old_items = std::mem::replace(&mut *self.items.write().await, items_map);
        *self.scope_index.write().await = scope_index_map;
        *self.exported.write().await = exported_set;

        old_items
    }

    /// Get a snapshot of all items.
    pub async fn snapshot(&self) -> HashMap<String, Arc<T>> {
        self.items.read().await.clone()
    }
}

impl<T> Default for ScopedRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for ScopedRegistry<T> {
    fn clone(&self) -> Self {
        Self {
            items: Arc::clone(&self.items),
            scope_index: Arc::clone(&self.scope_index),
            exported: Arc::clone(&self.exported),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_insert_and_get() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        let qid = QualifiedId::global("test-pool");
        registry
            .insert(qid.clone(), Arc::new("global-pool".to_string()))
            .await;

        // Get by QualifiedId
        let item = registry.get(&qid).await;
        assert!(item.is_some());
        assert_eq!(item.unwrap().as_str(), "global-pool");

        // Get by canonical
        let item = registry.get_by_canonical("test-pool").await;
        assert!(item.is_some());
    }

    #[tokio::test]
    async fn test_resolve_from_global_scope() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        registry
            .insert(
                QualifiedId::global("shared-pool"),
                Arc::new("global".to_string()),
            )
            .await;

        let result = registry.resolve("shared-pool", &Scope::Global).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "global");
    }

    #[tokio::test]
    async fn test_resolve_from_namespace_scope() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        // Global pool
        registry
            .insert(
                QualifiedId::global("shared-pool"),
                Arc::new("global".to_string()),
            )
            .await;

        // Namespace pool
        registry
            .insert(
                QualifiedId::namespaced("api", "backend"),
                Arc::new("namespace".to_string()),
            )
            .await;

        let ns_scope = Scope::Namespace("api".to_string());

        // Should find namespace-local pool
        let result = registry.resolve("backend", &ns_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "namespace");

        // Should also find global pool
        let result = registry.resolve("shared-pool", &ns_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "global");
    }

    #[tokio::test]
    async fn test_resolve_from_service_scope() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        // Global pool
        registry
            .insert(
                QualifiedId::global("global-pool"),
                Arc::new("global".to_string()),
            )
            .await;

        // Namespace pool
        registry
            .insert(
                QualifiedId::namespaced("api", "ns-pool"),
                Arc::new("namespace".to_string()),
            )
            .await;

        // Service pool
        registry
            .insert(
                QualifiedId::in_service("api", "payments", "svc-pool"),
                Arc::new("service".to_string()),
            )
            .await;

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // Should find service-local pool
        let result = registry.resolve("svc-pool", &svc_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "service");

        // Should find namespace pool
        let result = registry.resolve("ns-pool", &svc_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "namespace");

        // Should find global pool
        let result = registry.resolve("global-pool", &svc_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "global");
    }

    #[tokio::test]
    async fn test_scope_shadowing() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        // Same name at different scopes
        registry
            .insert(
                QualifiedId::global("backend"),
                Arc::new("global".to_string()),
            )
            .await;
        registry
            .insert(
                QualifiedId::namespaced("api", "backend"),
                Arc::new("namespace".to_string()),
            )
            .await;

        let ns_scope = Scope::Namespace("api".to_string());

        // Namespace scope should see the namespace-local version
        let result = registry.resolve("backend", &ns_scope).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "namespace");

        // Global scope should see the global version
        let result = registry.resolve("backend", &Scope::Global).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "global");
    }

    #[tokio::test]
    async fn test_exported_visibility() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        // Insert as exported
        registry
            .insert_exported(
                QualifiedId::namespaced("shared", "common-pool"),
                Arc::new("exported".to_string()),
            )
            .await;

        // Should be visible from global scope via export
        let result = registry.resolve("common-pool", &Scope::Global).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "exported");

        // Should be visible from other namespaces
        let other_ns = Scope::Namespace("other".to_string());
        let result = registry.resolve("common-pool", &other_ns).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_qualified_reference() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        registry
            .insert(
                QualifiedId::namespaced("api", "backend"),
                Arc::new("api-backend".to_string()),
            )
            .await;

        // Qualified reference works from any scope
        let result = registry.resolve("api:backend", &Scope::Global).await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "api-backend");

        // Non-matching qualified reference fails
        let result = registry.resolve("other:backend", &Scope::Global).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_items_in_scope() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        registry
            .insert(QualifiedId::global("a"), Arc::new("ga".to_string()))
            .await;
        registry
            .insert(QualifiedId::global("b"), Arc::new("gb".to_string()))
            .await;
        registry
            .insert(
                QualifiedId::namespaced("api", "c"),
                Arc::new("nc".to_string()),
            )
            .await;

        let global_items = registry.items_in_scope(&Scope::Global).await;
        assert_eq!(global_items.len(), 2);

        let ns_items = registry
            .items_in_scope(&Scope::Namespace("api".to_string()))
            .await;
        assert_eq!(ns_items.len(), 1);
    }

    #[tokio::test]
    async fn test_replace_all() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        registry
            .insert(QualifiedId::global("old"), Arc::new("old".to_string()))
            .await;

        let new_items = vec![
            (
                QualifiedId::global("new1"),
                Arc::new("new1".to_string()),
                false,
            ),
            (
                QualifiedId::namespaced("api", "new2"),
                Arc::new("new2".to_string()),
                true,
            ),
        ];

        let old = registry.replace_all(new_items).await;

        assert!(old.contains_key("old"));
        assert!(!registry.contains(&QualifiedId::global("old")).await);
        assert!(registry.contains(&QualifiedId::global("new1")).await);
        assert!(
            registry
                .contains(&QualifiedId::namespaced("api", "new2"))
                .await
        );

        // new2 should be exported
        let result = registry.resolve("new2", &Scope::Global).await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_visible_from_scope() {
        let registry: ScopedRegistry<String> = ScopedRegistry::new();

        registry
            .insert(
                QualifiedId::global("global-pool"),
                Arc::new("g".to_string()),
            )
            .await;
        registry
            .insert(
                QualifiedId::namespaced("api", "ns-pool"),
                Arc::new("n".to_string()),
            )
            .await;
        registry
            .insert_exported(
                QualifiedId::namespaced("shared", "exported-pool"),
                Arc::new("e".to_string()),
            )
            .await;

        let ns_scope = Scope::Namespace("api".to_string());
        let visible = registry.visible_from(&ns_scope).await;

        // Should see: global-pool, ns-pool, exported-pool
        assert_eq!(visible.len(), 3);
    }
}
