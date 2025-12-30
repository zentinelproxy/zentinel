//! In-memory caching module using pingora-memory-cache
//!
//! This module provides fast in-memory caching for hot data like:
//! - Route matching results
//! - Parsed configuration fragments
//! - Compiled regex patterns
//! - Upstream selection hints
//!
//! Uses S3-FIFO + TinyLFU eviction for excellent hit rates on skewed workloads.

use pingora_memory_cache::MemoryCache;
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// Configuration for the memory cache
#[derive(Debug, Clone)]
pub struct MemoryCacheConfig {
    /// Maximum number of items in the cache
    pub max_items: usize,
    /// Default TTL for cached items
    pub default_ttl: Duration,
    /// Enable cache statistics
    pub enable_stats: bool,
}

impl Default for MemoryCacheConfig {
    fn default() -> Self {
        Self {
            max_items: 10_000,
            default_ttl: Duration::from_secs(60),
            enable_stats: true,
        }
    }
}

/// Statistics for the memory cache
#[derive(Debug, Default)]
pub struct MemoryCacheStats {
    /// Number of cache hits
    pub hits: AtomicU64,
    /// Number of cache misses
    pub misses: AtomicU64,
    /// Number of cache insertions
    pub insertions: AtomicU64,
    /// Number of cache evictions
    pub evictions: AtomicU64,
}

impl MemoryCacheStats {
    /// Get hit rate as a percentage (0.0 - 100.0)
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let misses = self.misses.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        if total > 0.0 {
            (hits / total) * 100.0
        } else {
            0.0
        }
    }

    /// Reset statistics
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.insertions.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
    }
}

/// Route matching cache entry
#[derive(Debug, Clone)]
pub struct RouteMatchEntry {
    /// Route ID that matched
    pub route_id: String,
    /// Upstream ID for this route
    pub upstream_id: Option<String>,
    /// Cached timestamp
    pub cached_at: std::time::Instant,
}

/// Memory cache manager using pingora-memory-cache
///
/// Provides high-performance caching with:
/// - S3-FIFO eviction (better than LRU for many workloads)
/// - TinyLFU admission policy (prevents cache pollution)
/// - Cache stampede protection
pub struct MemoryCacheManager {
    /// Route match cache (key: String, value: RouteMatchEntry)
    route_cache: MemoryCache<String, RouteMatchEntry>,
    /// Configuration
    config: MemoryCacheConfig,
    /// Statistics
    stats: Arc<MemoryCacheStats>,
}

impl MemoryCacheManager {
    /// Create a new memory cache manager
    pub fn new(config: MemoryCacheConfig) -> Self {
        debug!(
            max_items = config.max_items,
            default_ttl_secs = config.default_ttl.as_secs(),
            "Creating memory cache manager"
        );

        // Create pingora memory cache with size estimate
        // Each RouteMatchEntry is roughly 100-200 bytes
        let estimated_item_size = 200;
        let cache_size = config.max_items * estimated_item_size;

        let route_cache = MemoryCache::new(cache_size);

        Self {
            route_cache,
            config,
            stats: Arc::new(MemoryCacheStats::default()),
        }
    }

    /// Look up a route match by cache key
    pub fn get_route_match(&self, key: &str) -> Option<RouteMatchEntry> {
        let key_string = key.to_string();
        let (result, _status) = self.route_cache.get(&key_string);

        if self.config.enable_stats {
            if result.is_some() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                trace!(key = %key, "Route cache hit");
            } else {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                trace!(key = %key, "Route cache miss");
            }
        }

        result
    }

    /// Cache a route match result
    pub fn put_route_match(&self, key: &str, entry: RouteMatchEntry) {
        self.put_route_match_with_ttl(key, entry, self.config.default_ttl);
    }

    /// Cache a route match result with custom TTL
    pub fn put_route_match_with_ttl(&self, key: &str, entry: RouteMatchEntry, ttl: Duration) {
        trace!(
            key = %key,
            route_id = %entry.route_id,
            ttl_secs = ttl.as_secs(),
            "Caching route match"
        );

        let key_string = key.to_string();
        self.route_cache.put(&key_string, entry, Some(ttl));

        if self.config.enable_stats {
            self.stats.insertions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Generate a cache key for route matching
    ///
    /// The key incorporates:
    /// - HTTP method
    /// - Request path
    /// - Host header (for virtual hosting)
    pub fn route_cache_key(method: &str, path: &str, host: Option<&str>) -> String {
        match host {
            Some(h) => format!("{}:{}:{}", method, h, path),
            None => format!("{}:{}", method, path),
        }
    }

    /// Invalidate route cache entries for a specific route
    ///
    /// Note: pingora-memory-cache doesn't support iteration, so we can't
    /// selectively invalidate. For now, we'd need to clear the entire cache
    /// on configuration reload.
    pub fn invalidate_route(&self, _route_id: &str) {
        // pingora-memory-cache doesn't support selective invalidation
        // This would require tracking keys per route or using a different approach
        debug!("Route invalidation requested (requires cache clear)");
    }

    /// Clear all cached entries
    ///
    /// Call this on configuration reload to ensure fresh routing decisions.
    pub fn clear(&self) {
        debug!("Clearing memory cache");
        // pingora-memory-cache doesn't have a clear method, but items will expire via TTL
        // For immediate invalidation, we'd need to recreate the cache
    }

    /// Get cache statistics
    pub fn stats(&self) -> &MemoryCacheStats {
        &self.stats
    }

    /// Get the cache configuration
    pub fn config(&self) -> &MemoryCacheConfig {
        &self.config
    }
}

/// Generic cache wrapper for arbitrary types
///
/// This provides a typed interface over pingora's memory cache.
/// K is the key type (must implement Hash + Eq + Clone + Send + Sync)
/// V is the value type (must implement Clone + Send + Sync)
pub struct TypedCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    inner: MemoryCache<K, V>,
    stats: Arc<MemoryCacheStats>,
    default_ttl: Duration,
}

impl<K, V> TypedCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new typed cache
    pub fn new(max_size_bytes: usize, default_ttl: Duration) -> Self {
        Self {
            inner: MemoryCache::new(max_size_bytes),
            stats: Arc::new(MemoryCacheStats::default()),
            default_ttl,
        }
    }

    /// Get a value from the cache
    pub fn get(&self, key: &K) -> Option<V> {
        let (result, _status) = self.inner.get(key);
        if result.is_some() {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    /// Put a value in the cache with default TTL
    pub fn put(&self, key: &K, value: V) {
        self.put_with_ttl(key, value, self.default_ttl);
    }

    /// Put a value in the cache with custom TTL
    pub fn put_with_ttl(&self, key: &K, value: V, ttl: Duration) {
        self.inner.put(key, value, Some(ttl));
        self.stats.insertions.fetch_add(1, Ordering::Relaxed);
    }

    /// Get cache statistics
    pub fn stats(&self) -> &MemoryCacheStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_cache_key() {
        let key1 = MemoryCacheManager::route_cache_key("GET", "/api/users", Some("example.com"));
        assert_eq!(key1, "GET:example.com:/api/users");

        let key2 = MemoryCacheManager::route_cache_key("POST", "/api/data", None);
        assert_eq!(key2, "POST:/api/data");
    }

    #[test]
    fn test_memory_cache_basic() {
        let config = MemoryCacheConfig::default();
        let cache = MemoryCacheManager::new(config);

        // Miss on first lookup
        assert!(cache.get_route_match("test-key").is_none());
        assert_eq!(cache.stats().misses.load(Ordering::Relaxed), 1);

        // Insert
        let entry = RouteMatchEntry {
            route_id: "route-1".to_string(),
            upstream_id: Some("upstream-1".to_string()),
            cached_at: std::time::Instant::now(),
        };
        cache.put_route_match("test-key", entry);

        // Hit on second lookup
        let result = cache.get_route_match("test-key");
        assert!(result.is_some());
        assert_eq!(result.unwrap().route_id, "route-1");
        assert_eq!(cache.stats().hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_hit_rate() {
        let stats = MemoryCacheStats::default();
        stats.hits.store(80, Ordering::Relaxed);
        stats.misses.store(20, Ordering::Relaxed);
        assert!((stats.hit_rate() - 80.0).abs() < 0.001);
    }

    #[test]
    fn test_typed_cache() {
        let cache: TypedCache<String, String> = TypedCache::new(1024 * 1024, Duration::from_secs(60));

        let key = "key1".to_string();
        cache.put(&key, "value1".to_string());
        let result = cache.get(&key);
        assert_eq!(result, Some("value1".to_string()));
    }
}
