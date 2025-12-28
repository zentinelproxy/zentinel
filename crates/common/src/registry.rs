//! Generic registry for thread-safe storage of named components.
//!
//! This module provides a `Registry<T>` type that wraps the common
//! `Arc<RwLock<HashMap<String, Arc<T>>>>` pattern used throughout Sentinel.
//!
//! # Example
//!
//! ```ignore
//! use sentinel_common::Registry;
//!
//! let registry: Registry<MyService> = Registry::new();
//!
//! // Insert a component
//! registry.insert("service-1", Arc::new(MyService::new())).await;
//!
//! // Get a component
//! if let Some(service) = registry.get("service-1").await {
//!     service.do_something();
//! }
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A thread-safe registry for named components.
///
/// Provides concurrent read access with exclusive write access,
/// suitable for storing configuration-driven components that are
/// read frequently but updated rarely (e.g., during config reload).
#[derive(Debug)]
pub struct Registry<T> {
    items: Arc<RwLock<HashMap<String, Arc<T>>>>,
}

impl<T> Registry<T> {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            items: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a registry with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Arc::new(RwLock::new(HashMap::with_capacity(capacity))),
        }
    }

    /// Create a registry from an existing HashMap.
    pub fn from_map(map: HashMap<String, Arc<T>>) -> Self {
        Self {
            items: Arc::new(RwLock::new(map)),
        }
    }

    /// Get a component by ID.
    pub async fn get(&self, id: &str) -> Option<Arc<T>> {
        self.items.read().await.get(id).cloned()
    }

    /// Check if a component exists.
    pub async fn contains(&self, id: &str) -> bool {
        self.items.read().await.contains_key(id)
    }

    /// Insert a component, returning the previous value if any.
    pub async fn insert(&self, id: impl Into<String>, item: Arc<T>) -> Option<Arc<T>> {
        self.items.write().await.insert(id.into(), item)
    }

    /// Remove a component by ID.
    pub async fn remove(&self, id: &str) -> Option<Arc<T>> {
        self.items.write().await.remove(id)
    }

    /// Get all component IDs.
    pub async fn keys(&self) -> Vec<String> {
        self.items.read().await.keys().cloned().collect()
    }

    /// Get the number of components.
    pub async fn len(&self) -> usize {
        self.items.read().await.len()
    }

    /// Check if the registry is empty.
    pub async fn is_empty(&self) -> bool {
        self.items.read().await.is_empty()
    }

    /// Clear all components.
    pub async fn clear(&self) {
        self.items.write().await.clear()
    }

    /// Replace all items atomically, returning the old map.
    pub async fn replace(&self, new_items: HashMap<String, Arc<T>>) -> HashMap<String, Arc<T>> {
        let mut guard = self.items.write().await;
        std::mem::replace(&mut *guard, new_items)
    }

    /// Get a snapshot of all items.
    pub async fn snapshot(&self) -> HashMap<String, Arc<T>> {
        self.items.read().await.clone()
    }

    /// Execute a function while holding the read lock.
    ///
    /// Useful for operations that need to access multiple items atomically.
    pub async fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&HashMap<String, Arc<T>>) -> R,
    {
        f(&*self.items.read().await)
    }

    /// Execute a function while holding the write lock.
    ///
    /// Useful for operations that need to modify multiple items atomically.
    pub async fn with_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<String, Arc<T>>) -> R,
    {
        f(&mut *self.items.write().await)
    }
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for Registry<T> {
    fn clone(&self) -> Self {
        Self {
            items: Arc::clone(&self.items),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_basic_operations() {
        let registry: Registry<String> = Registry::new();

        // Insert
        registry.insert("key1", Arc::new("value1".to_string())).await;
        registry.insert("key2", Arc::new("value2".to_string())).await;

        // Get
        assert_eq!(
            registry.get("key1").await.as_deref().map(|s| s.as_str()),
            Some("value1")
        );
        assert!(registry.get("nonexistent").await.is_none());

        // Contains
        assert!(registry.contains("key1").await);
        assert!(!registry.contains("nonexistent").await);

        // Len
        assert_eq!(registry.len().await, 2);

        // Keys
        let keys = registry.keys().await;
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));

        // Remove
        let removed = registry.remove("key1").await;
        assert!(removed.is_some());
        assert!(!registry.contains("key1").await);
        assert_eq!(registry.len().await, 1);

        // Clear
        registry.clear().await;
        assert!(registry.is_empty().await);
    }

    #[tokio::test]
    async fn test_registry_replace() {
        let registry: Registry<i32> = Registry::new();
        registry.insert("a", Arc::new(1)).await;
        registry.insert("b", Arc::new(2)).await;

        let mut new_items = HashMap::new();
        new_items.insert("c".to_string(), Arc::new(3));
        new_items.insert("d".to_string(), Arc::new(4));

        let old = registry.replace(new_items).await;

        assert!(old.contains_key("a"));
        assert!(old.contains_key("b"));
        assert!(!registry.contains("a").await);
        assert!(registry.contains("c").await);
        assert!(registry.contains("d").await);
    }

    #[tokio::test]
    async fn test_registry_with_read() {
        let registry: Registry<i32> = Registry::new();
        registry.insert("a", Arc::new(1)).await;
        registry.insert("b", Arc::new(2)).await;

        let sum = registry
            .with_read(|items| items.values().map(|v| **v).sum::<i32>())
            .await;

        assert_eq!(sum, 3);
    }

    #[tokio::test]
    async fn test_registry_clone_shares_data() {
        let registry1: Registry<String> = Registry::new();
        let registry2 = registry1.clone();

        registry1
            .insert("key", Arc::new("value".to_string()))
            .await;

        // Clone should see the same data
        assert!(registry2.contains("key").await);
    }
}
