//! HTTP caching infrastructure for Sentinel
//!
//! This module provides the foundation for HTTP response caching.
//! Note: Pingora's cache integration is still experimental, so this module
//! provides a stable API wrapper that can be extended as pingora-cache matures.
//!
//! Current features:
//! - Cache configuration per route
//! - Cache statistics tracking
//! - Cache key generation
//! - TTL calculation from Cache-Control headers

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// Cache configuration for a route
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Whether caching is enabled for this route
    pub enabled: bool,
    /// Default TTL in seconds if no Cache-Control header
    pub default_ttl_secs: u64,
    /// Maximum cacheable response size in bytes
    pub max_size_bytes: usize,
    /// Whether to cache private responses
    pub cache_private: bool,
    /// Stale-while-revalidate grace period in seconds
    pub stale_while_revalidate_secs: u64,
    /// Stale-if-error grace period in seconds
    pub stale_if_error_secs: u64,
    /// Methods that are cacheable (GET, HEAD)
    pub cacheable_methods: Vec<String>,
    /// Status codes that are cacheable
    pub cacheable_status_codes: Vec<u16>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default for safety
            default_ttl_secs: 3600,
            max_size_bytes: 10 * 1024 * 1024, // 10MB
            cache_private: false,
            stale_while_revalidate_secs: 60,
            stale_if_error_secs: 300,
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
            cacheable_status_codes: vec![200, 203, 204, 206, 300, 301, 308, 404, 410],
        }
    }
}

/// HTTP cache statistics
#[derive(Debug, Default)]
pub struct HttpCacheStats {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    stores: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

impl HttpCacheStats {
    /// Record a cache hit
    pub fn record_hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a cache miss
    pub fn record_miss(&self) {
        self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a cache store
    pub fn record_store(&self) {
        self.stores.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record an eviction
    pub fn record_eviction(&self) {
        self.evictions.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get current hit count
    pub fn hits(&self) -> u64 {
        self.hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current miss count
    pub fn misses(&self) -> u64 {
        self.misses.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get hit ratio (0.0 to 1.0)
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits() as f64;
        let total = hits + self.misses() as f64;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }
}

/// Cache manager for HTTP responses
///
/// This provides a foundation for HTTP caching that can be extended
/// to use pingora-cache's full capabilities when they stabilize.
pub struct CacheManager {
    /// Per-route cache configurations
    route_configs: RwLock<HashMap<String, CacheConfig>>,
    /// Global cache statistics
    stats: Arc<HttpCacheStats>,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new() -> Self {
        Self {
            route_configs: RwLock::new(HashMap::new()),
            stats: Arc::new(HttpCacheStats::default()),
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> Arc<HttpCacheStats> {
        self.stats.clone()
    }

    /// Register cache configuration for a route
    pub fn register_route(&self, route_id: &str, config: CacheConfig) {
        trace!(
            route_id = route_id,
            enabled = config.enabled,
            default_ttl = config.default_ttl_secs,
            "Registering cache configuration for route"
        );
        self.route_configs.write().insert(route_id.to_string(), config);
    }

    /// Get cache configuration for a route
    pub fn get_route_config(&self, route_id: &str) -> Option<CacheConfig> {
        self.route_configs.read().get(route_id).cloned()
    }

    /// Check if caching is enabled for a route
    pub fn is_enabled(&self, route_id: &str) -> bool {
        self.route_configs
            .read()
            .get(route_id)
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Generate a cache key string from request info
    pub fn generate_cache_key(
        method: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
    ) -> String {
        match query {
            Some(q) => format!("{}:{}:{}?{}", method, host, path, q),
            None => format!("{}:{}:{}", method, host, path),
        }
    }

    /// Check if a method is cacheable for a route
    pub fn is_method_cacheable(&self, route_id: &str, method: &str) -> bool {
        self.route_configs
            .read()
            .get(route_id)
            .map(|c| c.cacheable_methods.iter().any(|m| m.eq_ignore_ascii_case(method)))
            .unwrap_or(false)
    }

    /// Check if a status code is cacheable for a route
    pub fn is_status_cacheable(&self, route_id: &str, status: u16) -> bool {
        self.route_configs
            .read()
            .get(route_id)
            .map(|c| c.cacheable_status_codes.contains(&status))
            .unwrap_or(false)
    }

    /// Parse max-age from Cache-Control header value
    pub fn parse_max_age(header_value: &str) -> Option<u64> {
        // Simple parsing of max-age directive
        for directive in header_value.split(',') {
            let directive = directive.trim();
            if let Some(value) = directive.strip_prefix("max-age=") {
                if let Ok(secs) = value.trim().parse::<u64>() {
                    return Some(secs);
                }
            }
            if let Some(value) = directive.strip_prefix("s-maxage=") {
                if let Ok(secs) = value.trim().parse::<u64>() {
                    return Some(secs);
                }
            }
        }
        None
    }

    /// Check if Cache-Control indicates no caching
    pub fn is_no_cache(header_value: &str) -> bool {
        let lower = header_value.to_lowercase();
        lower.contains("no-store") || lower.contains("no-cache") || lower.contains("private")
    }

    /// Calculate TTL from Cache-Control or use default
    pub fn calculate_ttl(&self, route_id: &str, cache_control: Option<&str>) -> Duration {
        let config = self.get_route_config(route_id).unwrap_or_default();

        if let Some(cc) = cache_control {
            // Check for no-store or no-cache
            if Self::is_no_cache(cc) && !config.cache_private {
                return Duration::ZERO;
            }

            // Use max-age if present
            if let Some(max_age) = Self::parse_max_age(cc) {
                return Duration::from_secs(max_age);
            }
        }

        // Fall back to default TTL
        Duration::from_secs(config.default_ttl_secs)
    }

    /// Determine if response should be served stale
    pub fn should_serve_stale(
        &self,
        route_id: &str,
        stale_duration: Duration,
        is_error: bool,
    ) -> bool {
        let config = self.get_route_config(route_id).unwrap_or_default();

        if is_error {
            stale_duration.as_secs() <= config.stale_if_error_secs
        } else {
            stale_duration.as_secs() <= config.stale_while_revalidate_secs
        }
    }

    /// Get count of registered routes with caching
    pub fn route_count(&self) -> usize {
        self.route_configs.read().len()
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_generation() {
        let key = CacheManager::generate_cache_key("GET", "example.com", "/api/users", None);
        assert_eq!(key, "GET:example.com:/api/users");

        let key_with_query = CacheManager::generate_cache_key(
            "GET",
            "example.com",
            "/api/users",
            Some("page=1&limit=10"),
        );
        assert_eq!(key_with_query, "GET:example.com:/api/users?page=1&limit=10");
    }

    #[test]
    fn test_cache_config_defaults() {
        let config = CacheConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.default_ttl_secs, 3600);
        assert!(config.cacheable_methods.contains(&"GET".to_string()));
        assert!(config.cacheable_status_codes.contains(&200));
    }

    #[test]
    fn test_route_config_registration() {
        let manager = CacheManager::new();

        manager.register_route("api", CacheConfig {
            enabled: true,
            default_ttl_secs: 300,
            ..Default::default()
        });

        assert!(manager.is_enabled("api"));
        assert!(!manager.is_enabled("unknown"));
    }

    #[test]
    fn test_method_cacheability() {
        let manager = CacheManager::new();

        manager.register_route("api", CacheConfig {
            enabled: true,
            cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
            ..Default::default()
        });

        assert!(manager.is_method_cacheable("api", "GET"));
        assert!(manager.is_method_cacheable("api", "get"));
        assert!(!manager.is_method_cacheable("api", "POST"));
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(CacheManager::parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(CacheManager::parse_max_age("public, max-age=300"), Some(300));
        assert_eq!(CacheManager::parse_max_age("s-maxage=600, max-age=300"), Some(600));
        assert_eq!(CacheManager::parse_max_age("no-store"), None);
    }

    #[test]
    fn test_is_no_cache() {
        assert!(CacheManager::is_no_cache("no-store"));
        assert!(CacheManager::is_no_cache("no-cache"));
        assert!(CacheManager::is_no_cache("private"));
        assert!(CacheManager::is_no_cache("private, max-age=300"));
        assert!(!CacheManager::is_no_cache("public, max-age=3600"));
    }

    #[test]
    fn test_cache_stats() {
        let stats = HttpCacheStats::default();

        stats.record_hit();
        stats.record_hit();
        stats.record_miss();

        assert_eq!(stats.hits(), 2);
        assert_eq!(stats.misses(), 1);
        assert!((stats.hit_ratio() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_calculate_ttl() {
        let manager = CacheManager::new();
        manager.register_route("api", CacheConfig {
            enabled: true,
            default_ttl_secs: 600,
            ..Default::default()
        });

        // Uses max-age from header
        let ttl = manager.calculate_ttl("api", Some("max-age=3600"));
        assert_eq!(ttl.as_secs(), 3600);

        // Falls back to default
        let ttl = manager.calculate_ttl("api", None);
        assert_eq!(ttl.as_secs(), 600);

        // No-store returns zero
        let ttl = manager.calculate_ttl("api", Some("no-store"));
        assert_eq!(ttl.as_secs(), 0);
    }
}
