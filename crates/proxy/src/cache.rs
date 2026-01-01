//! HTTP caching infrastructure for Sentinel
//!
//! This module provides the foundation for HTTP response caching using
//! Pingora's cache infrastructure.
//!
//! Current features:
//! - Cache configuration per route
//! - Cache statistics tracking
//! - Cache key generation
//! - TTL calculation from Cache-Control headers
//! - In-memory cache storage backend (for development/testing)
//!
//! # Storage Backends
//!
//! The default storage is an in-memory cache suitable for development and
//! single-instance deployments. For production with large cache sizes or
//! persistence needs, consider implementing a disk-based storage backend.

use once_cell::sync::{Lazy, OnceCell};
use parking_lot::RwLock;
use pingora_cache::eviction::simple_lru::Manager as LruEvictionManager;
use pingora_cache::lock::CacheLock;
use pingora_cache::storage::Storage;
use pingora_cache::MemCache;
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use sentinel_config::CacheStorageConfig;

// ============================================================================
// Cache Configuration
// ============================================================================

/// Default cache size: 100MB
const DEFAULT_CACHE_SIZE_BYTES: usize = 100 * 1024 * 1024;

/// Default eviction limit: 100MB
const DEFAULT_EVICTION_LIMIT_BYTES: usize = 100 * 1024 * 1024;

/// Default lock timeout: 10 seconds
const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 10;

/// Global cache configuration holder
///
/// This should be set during proxy startup, before the cache is accessed.
/// If not set, default values will be used.
static CACHE_CONFIG: OnceCell<CacheStorageConfig> = OnceCell::new();

/// Configure the global cache storage settings.
///
/// This must be called before the first cache access to take effect.
/// If called after cache initialization, returns false and logs a warning.
///
/// # Example
/// ```ignore
/// use sentinel_config::CacheStorageConfig;
/// use sentinel_proxy::cache::configure_cache;
///
/// let config = CacheStorageConfig {
///     max_size_bytes: 200 * 1024 * 1024, // 200MB
///     lock_timeout_secs: 15,
///     ..Default::default()
/// };
/// configure_cache(config);
/// ```
pub fn configure_cache(config: CacheStorageConfig) -> bool {
    match CACHE_CONFIG.set(config) {
        Ok(()) => {
            info!("Cache storage configured");
            true
        }
        Err(_) => {
            warn!("Cache already initialized, configuration ignored");
            false
        }
    }
}

/// Get the current cache configuration
fn get_cache_config() -> &'static CacheStorageConfig {
    CACHE_CONFIG.get_or_init(CacheStorageConfig::default)
}

/// Check if caching is globally enabled
pub fn is_cache_enabled() -> bool {
    get_cache_config().enabled
}

// ============================================================================
// Static Cache Storage
// ============================================================================

/// Static in-memory cache storage instance
///
/// This provides a `&'static` reference required by Pingora's cache API.
/// Note: MemCache is marked "for testing only" in pingora-cache. For production
/// deployments with large cache requirements, consider implementing a disk-based
/// storage backend.
static HTTP_CACHE_STORAGE: Lazy<MemCache> = Lazy::new(|| {
    let config = get_cache_config();
    info!(
        cache_size_mb = config.max_size_bytes / 1024 / 1024,
        backend = ?config.backend,
        "Initializing HTTP cache storage"
    );
    MemCache::new()
});

/// Static LRU eviction manager for cache entries
static HTTP_CACHE_EVICTION: Lazy<LruEvictionManager> = Lazy::new(|| {
    let config = get_cache_config();
    let limit = config.eviction_limit_bytes.unwrap_or(config.max_size_bytes);
    info!(
        eviction_limit_mb = limit / 1024 / 1024,
        "Initializing HTTP cache eviction manager"
    );
    LruEvictionManager::new(limit)
});

/// Static cache lock for preventing thundering herd
static HTTP_CACHE_LOCK: Lazy<CacheLock> = Lazy::new(|| {
    let config = get_cache_config();
    info!(
        lock_timeout_secs = config.lock_timeout_secs,
        "Initializing HTTP cache lock"
    );
    CacheLock::new(Duration::from_secs(config.lock_timeout_secs))
});

/// Get a static reference to the HTTP cache storage
///
/// This is used by the ProxyHttp implementation to enable caching.
pub fn get_cache_storage() -> &'static (dyn Storage + Sync) {
    &*HTTP_CACHE_STORAGE
}

/// Get a static reference to the cache eviction manager
pub fn get_cache_eviction() -> &'static LruEvictionManager {
    &HTTP_CACHE_EVICTION
}

/// Get a static reference to the cache lock
pub fn get_cache_lock() -> &'static CacheLock {
    &HTTP_CACHE_LOCK
}

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
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record a cache store
    pub fn record_store(&self) {
        self.stores
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record an eviction
    pub fn record_eviction(&self) {
        self.evictions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// Get current store count
    pub fn stores(&self) -> u64 {
        self.stores.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get current eviction count
    pub fn evictions(&self) -> u64 {
        self.evictions.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Purge entry with expiration tracking
#[derive(Debug, Clone)]
struct PurgeEntry {
    /// When this purge was registered
    created_at: Instant,
    /// Pattern for wildcard matching (None for exact key purges)
    pattern: Option<String>,
}

/// Default purge entry lifetime (how long a purge entry stays active)
const PURGE_ENTRY_LIFETIME: Duration = Duration::from_secs(60);

/// Cache manager for HTTP responses
///
/// This provides a foundation for HTTP caching that can be extended
/// to use pingora-cache's full capabilities when they stabilize.
pub struct CacheManager {
    /// Per-route cache configurations
    route_configs: RwLock<HashMap<String, CacheConfig>>,
    /// Global cache statistics
    stats: Arc<HttpCacheStats>,
    /// Exact keys that have been purged (with timestamp for cleanup)
    purged_keys: RwLock<HashMap<String, Instant>>,
    /// Wildcard patterns for purging (with timestamp for cleanup)
    purge_patterns: RwLock<Vec<PurgeEntry>>,
    /// Compiled regex patterns for efficient matching
    compiled_patterns: RwLock<Vec<(Regex, Instant)>>,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new() -> Self {
        Self {
            route_configs: RwLock::new(HashMap::new()),
            stats: Arc::new(HttpCacheStats::default()),
            purged_keys: RwLock::new(HashMap::new()),
            purge_patterns: RwLock::new(Vec::new()),
            compiled_patterns: RwLock::new(Vec::new()),
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
        self.route_configs
            .write()
            .insert(route_id.to_string(), config);
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
    pub fn generate_cache_key(method: &str, host: &str, path: &str, query: Option<&str>) -> String {
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
            .map(|c| {
                c.cacheable_methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(method))
            })
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

    // ========================================================================
    // Cache Purge API
    // ========================================================================

    /// Purge a single cache entry by exact key (path).
    ///
    /// Returns the number of entries purged (0 or 1).
    /// The purge is tracked so that subsequent cache hits for this key
    /// will be invalidated via `ForcedInvalidationKind`.
    pub fn purge(&self, path: &str) -> usize {
        // Generate cache key for common methods
        // Since we don't know the exact method/host, we purge all variants
        let keys_to_purge: Vec<String> =
            vec![format!("GET:*:{}", path), format!("HEAD:*:{}", path)];

        let now = Instant::now();
        let mut purged = self.purged_keys.write();

        for key in &keys_to_purge {
            purged.insert(key.clone(), now);
        }

        // Also add the raw path for flexible matching
        purged.insert(path.to_string(), now);

        debug!(
            path = %path,
            purged_keys = keys_to_purge.len() + 1,
            "Purged cache entry"
        );

        self.stats.record_eviction();
        1
    }

    /// Purge cache entries matching a wildcard pattern.
    ///
    /// Supports glob-style patterns:
    /// - `*` matches any sequence of characters except `/`
    /// - `**` matches any sequence of characters including `/`
    /// - `?` matches any single character
    ///
    /// Returns the number of pattern registrations (actual purges happen on cache hit).
    pub fn purge_wildcard(&self, pattern: &str) -> usize {
        // Convert glob pattern to regex
        let regex_pattern = glob_to_regex(pattern);

        match Regex::new(&regex_pattern) {
            Ok(regex) => {
                let now = Instant::now();

                // Store the compiled pattern
                self.compiled_patterns.write().push((regex, now));

                // Store the original pattern for debugging
                self.purge_patterns.write().push(PurgeEntry {
                    created_at: now,
                    pattern: Some(pattern.to_string()),
                });

                debug!(
                    pattern = %pattern,
                    regex = %regex_pattern,
                    "Registered wildcard cache purge"
                );

                self.stats.record_eviction();
                1
            }
            Err(e) => {
                warn!(
                    pattern = %pattern,
                    error = %e,
                    "Failed to compile purge pattern as regex"
                );
                0
            }
        }
    }

    /// Check if a cache key should be invalidated due to a purge request.
    ///
    /// This is called from `cache_hit_filter` to determine if a cached
    /// response should be re-fetched from upstream.
    pub fn should_invalidate(&self, cache_key: &str) -> bool {
        // First, cleanup expired entries
        self.cleanup_expired_purges();

        // Check exact key matches
        {
            let purged = self.purged_keys.read();
            if purged.contains_key(cache_key) {
                trace!(cache_key = %cache_key, "Cache key matches purged key");
                return true;
            }

            // Also check if the path portion matches
            // Cache key format: "METHOD:HOST:PATH" or "METHOD:HOST:PATH?QUERY"
            if let Some(path) = extract_path_from_cache_key(cache_key) {
                if purged.contains_key(path) {
                    trace!(cache_key = %cache_key, path = %path, "Cache path matches purged path");
                    return true;
                }
            }
        }

        // Check wildcard patterns
        {
            let patterns = self.compiled_patterns.read();
            let path = extract_path_from_cache_key(cache_key).unwrap_or(cache_key);

            for (regex, _) in patterns.iter() {
                if regex.is_match(path) {
                    trace!(
                        cache_key = %cache_key,
                        path = %path,
                        pattern = %regex.as_str(),
                        "Cache key matches purge pattern"
                    );
                    return true;
                }
            }
        }

        false
    }

    /// Remove expired purge entries to prevent memory growth.
    fn cleanup_expired_purges(&self) {
        let now = Instant::now();

        // Cleanup exact keys
        {
            let mut purged = self.purged_keys.write();
            purged.retain(|_, created_at| now.duration_since(*created_at) < PURGE_ENTRY_LIFETIME);
        }

        // Cleanup patterns
        {
            let mut patterns = self.purge_patterns.write();
            patterns.retain(|entry| now.duration_since(entry.created_at) < PURGE_ENTRY_LIFETIME);
        }

        // Cleanup compiled patterns
        {
            let mut compiled = self.compiled_patterns.write();
            compiled
                .retain(|(_, created_at)| now.duration_since(*created_at) < PURGE_ENTRY_LIFETIME);
        }
    }

    /// Get count of active purge entries (for stats/debugging)
    pub fn active_purge_count(&self) -> usize {
        self.purged_keys.read().len() + self.purge_patterns.read().len()
    }

    /// Clear all purge entries (for testing)
    #[cfg(test)]
    pub fn clear_purges(&self) {
        self.purged_keys.write().clear();
        self.purge_patterns.write().clear();
        self.compiled_patterns.write().clear();
    }
}

/// Convert a glob-style pattern to a regex pattern.
///
/// - `*` becomes `[^/]*` (match any except /)
/// - `**` becomes `.*` (match anything)
/// - `?` becomes `.` (match single char)
/// - Other regex special chars are escaped
fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::with_capacity(pattern.len() * 2);
    regex.push('^');

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        match c {
            '*' => {
                // Check for ** (match anything including /)
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    regex.push_str(".*");
                    i += 2;
                } else {
                    // Single * matches anything except /
                    regex.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                regex.push('.');
                i += 1;
            }
            // Escape regex special characters
            '.' | '+' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
                i += 1;
            }
            _ => {
                regex.push(c);
                i += 1;
            }
        }
    }

    regex.push('$');
    regex
}

/// Extract the path portion from a cache key.
///
/// Cache key format: "METHOD:HOST:PATH" or "METHOD:HOST:PATH?QUERY"
fn extract_path_from_cache_key(cache_key: &str) -> Option<&str> {
    // Find the second colon (after METHOD:HOST:)
    let mut colon_count = 0;
    for (i, c) in cache_key.char_indices() {
        if c == ':' {
            colon_count += 1;
            if colon_count == 2 {
                // Return everything after this colon
                return Some(&cache_key[i + 1..]);
            }
        }
    }
    None
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

        manager.register_route(
            "api",
            CacheConfig {
                enabled: true,
                default_ttl_secs: 300,
                ..Default::default()
            },
        );

        assert!(manager.is_enabled("api"));
        assert!(!manager.is_enabled("unknown"));
    }

    #[test]
    fn test_method_cacheability() {
        let manager = CacheManager::new();

        manager.register_route(
            "api",
            CacheConfig {
                enabled: true,
                cacheable_methods: vec!["GET".to_string(), "HEAD".to_string()],
                ..Default::default()
            },
        );

        assert!(manager.is_method_cacheable("api", "GET"));
        assert!(manager.is_method_cacheable("api", "get"));
        assert!(!manager.is_method_cacheable("api", "POST"));
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(CacheManager::parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(
            CacheManager::parse_max_age("public, max-age=300"),
            Some(300)
        );
        assert_eq!(
            CacheManager::parse_max_age("s-maxage=600, max-age=300"),
            Some(600)
        );
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
        manager.register_route(
            "api",
            CacheConfig {
                enabled: true,
                default_ttl_secs: 600,
                ..Default::default()
            },
        );

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

    // ========================================================================
    // Cache Purge Tests
    // ========================================================================

    #[test]
    fn test_purge_single_entry() {
        let manager = CacheManager::new();

        // Purge a single path
        let count = manager.purge("/api/users/123");
        assert_eq!(count, 1);

        // Should have active purge entries
        assert!(manager.active_purge_count() > 0);

        // Should invalidate matching cache key
        let cache_key =
            CacheManager::generate_cache_key("GET", "example.com", "/api/users/123", None);
        assert!(manager.should_invalidate(&cache_key));

        // Should not invalidate non-matching cache key
        let other_key =
            CacheManager::generate_cache_key("GET", "example.com", "/api/users/456", None);
        assert!(!manager.should_invalidate(&other_key));

        // Clean up for next test
        manager.clear_purges();
    }

    #[test]
    fn test_purge_wildcard_pattern() {
        let manager = CacheManager::new();

        // Purge with wildcard pattern
        let count = manager.purge_wildcard("/api/users/*");
        assert_eq!(count, 1);

        // Should invalidate matching paths
        assert!(manager.should_invalidate("/api/users/123"));
        assert!(manager.should_invalidate("/api/users/456"));
        assert!(manager.should_invalidate("/api/users/abc"));

        // Should not invalidate non-matching paths
        assert!(!manager.should_invalidate("/api/posts/123"));
        assert!(!manager.should_invalidate("/api/users")); // No trailing /

        manager.clear_purges();
    }

    #[test]
    fn test_purge_double_wildcard() {
        let manager = CacheManager::new();

        // Purge with ** pattern (matches anything including /)
        let count = manager.purge_wildcard("/api/**");
        assert_eq!(count, 1);

        // Should match any path under /api/
        assert!(manager.should_invalidate("/api/users/123"));
        assert!(manager.should_invalidate("/api/posts/456/comments"));
        assert!(manager.should_invalidate("/api/deep/nested/path"));

        // Should not match other paths
        assert!(!manager.should_invalidate("/other/path"));

        manager.clear_purges();
    }

    #[test]
    fn test_glob_to_regex() {
        // Test single * pattern
        let regex = glob_to_regex("/api/users/*");
        assert_eq!(regex, "^/api/users/[^/]*$");

        // Test ** pattern
        let regex = glob_to_regex("/api/**");
        assert_eq!(regex, "^/api/.*$");

        // Test ? pattern
        let regex = glob_to_regex("/api/user?");
        assert_eq!(regex, "^/api/user.$");

        // Test escaping special chars
        let regex = glob_to_regex("/api/v1.0/users");
        assert_eq!(regex, "^/api/v1\\.0/users$");
    }

    #[test]
    fn test_extract_path_from_cache_key() {
        // Test standard cache key
        let path = extract_path_from_cache_key("GET:example.com:/api/users");
        assert_eq!(path, Some("/api/users"));

        // Test cache key with query
        let path = extract_path_from_cache_key("GET:example.com:/api/users?page=1");
        assert_eq!(path, Some("/api/users?page=1"));

        // Test invalid cache key (no second colon)
        let path = extract_path_from_cache_key("invalid");
        assert_eq!(path, None);
    }

    #[test]
    fn test_purge_eviction_stats() {
        let manager = CacheManager::new();

        let initial_evictions = manager.stats().evictions();

        // Each purge should record an eviction
        manager.purge("/path1");
        manager.purge("/path2");
        manager.purge_wildcard("/pattern/*");

        assert_eq!(manager.stats().evictions(), initial_evictions + 3);

        manager.clear_purges();
    }
}
