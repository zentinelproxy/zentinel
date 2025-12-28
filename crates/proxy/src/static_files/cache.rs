//! File caching for static file serving
//!
//! This module provides in-memory caching for small static files
//! with pre-computed compressed variants.

use bytes::Bytes;
use dashmap::DashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

/// Maximum age for cached files (1 hour)
const DEFAULT_MAX_AGE_SECS: u64 = 3600;

/// File cache for improved performance
///
/// Caches small files in memory with their compressed variants
/// to avoid repeated disk I/O and compression overhead.
pub struct FileCache {
    entries: DashMap<PathBuf, CachedFile>,
    max_size: usize,
    max_age: Duration,
}

/// Cached file entry
///
/// Contains the file content, pre-compressed variants, and metadata.
pub struct CachedFile {
    /// Original file content
    pub content: Bytes,
    /// Pre-compressed gzip content (if compressible)
    pub gzip_content: Option<Bytes>,
    /// Pre-compressed brotli content (if compressible)
    pub brotli_content: Option<Bytes>,
    /// MIME content type
    pub content_type: String,
    /// ETag for conditional requests
    pub etag: String,
    /// Last modification time
    pub last_modified: SystemTime,
    /// When this entry was cached
    pub cached_at: Instant,
    /// Original file size
    pub size: u64,
}

impl FileCache {
    /// Create a new file cache
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum total cache size in bytes
    /// * `max_age_secs` - Maximum age of cached entries in seconds
    pub fn new(max_size: usize, max_age_secs: u64) -> Self {
        Self {
            entries: DashMap::new(),
            max_size,
            max_age: Duration::from_secs(max_age_secs),
        }
    }

    /// Create a cache with default settings (100MB, 1 hour)
    pub fn with_defaults() -> Self {
        Self::new(100 * 1024 * 1024, DEFAULT_MAX_AGE_SECS)
    }

    /// Get a cached file by path
    pub fn get(&self, path: &std::path::Path) -> Option<CachedFile> {
        self.entries.get(path).map(|entry| entry.clone())
    }

    /// Insert a file into the cache
    pub fn insert(&self, path: PathBuf, file: CachedFile) {
        // Simple cache eviction - remove old entries
        self.evict_stale();

        // Check cache size limit (simplified entry count limit)
        if self.entries.len() > 1000 {
            self.evict_oldest(100);
        }

        self.entries.insert(path, file);
    }

    /// Remove stale entries from the cache
    fn evict_stale(&self) {
        self.entries.retain(|_, v| v.is_fresh());
    }

    /// Remove the N oldest entries from the cache
    fn evict_oldest(&self, count: usize) {
        let mut oldest: Vec<_> = self
            .entries
            .iter()
            .map(|e| (e.key().clone(), e.cached_at))
            .collect();

        oldest.sort_by_key(|e| e.1);

        for (path, _) in oldest.iter().take(count) {
            self.entries.remove(path);
        }
    }

    /// Get current cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_size: usize = self.entries.iter().map(|e| e.size as usize).sum();
        let total_compressed: usize = self
            .entries
            .iter()
            .map(|e| {
                e.gzip_content.as_ref().map_or(0, |b| b.len())
                    + e.brotli_content.as_ref().map_or(0, |b| b.len())
            })
            .sum();

        CacheStats {
            entry_count: self.entries.len(),
            total_size,
            total_compressed,
            max_size: self.max_size,
        }
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        self.entries.clear();
    }
}

impl CachedFile {
    /// Check if the cached entry is still fresh
    pub fn is_fresh(&self) -> bool {
        self.cached_at.elapsed() < Duration::from_secs(DEFAULT_MAX_AGE_SECS)
    }
}

impl Clone for CachedFile {
    fn clone(&self) -> Self {
        Self {
            content: self.content.clone(),
            gzip_content: self.gzip_content.clone(),
            brotli_content: self.brotli_content.clone(),
            content_type: self.content_type.clone(),
            etag: self.etag.clone(),
            last_modified: self.last_modified,
            cached_at: self.cached_at,
            size: self.size,
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cached entries
    pub entry_count: usize,
    /// Total size of original content
    pub total_size: usize,
    /// Total size of compressed content
    pub total_compressed: usize,
    /// Maximum cache size
    pub max_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_get() {
        let cache = FileCache::with_defaults();
        let path = PathBuf::from("/test/file.txt");

        let cached = CachedFile {
            content: Bytes::from_static(b"Hello, World!"),
            gzip_content: None,
            brotli_content: None,
            content_type: "text/plain".to_string(),
            etag: "abc123".to_string(),
            last_modified: SystemTime::now(),
            cached_at: Instant::now(),
            size: 13,
        };

        cache.insert(path.clone(), cached);

        let retrieved = cache.get(&path);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().content, Bytes::from_static(b"Hello, World!"));
    }

    #[test]
    fn test_cache_stats() {
        let cache = FileCache::with_defaults();

        let cached = CachedFile {
            content: Bytes::from_static(b"Test content"),
            gzip_content: Some(Bytes::from_static(b"compressed")),
            brotli_content: None,
            content_type: "text/plain".to_string(),
            etag: "test".to_string(),
            last_modified: SystemTime::now(),
            cached_at: Instant::now(),
            size: 12,
        };

        cache.insert(PathBuf::from("/test.txt"), cached);

        let stats = cache.stats();
        assert_eq!(stats.entry_count, 1);
        assert_eq!(stats.total_size, 12);
    }

    #[test]
    fn test_cache_clear() {
        let cache = FileCache::with_defaults();

        for i in 0..10 {
            cache.insert(
                PathBuf::from(format!("/file{}.txt", i)),
                CachedFile {
                    content: Bytes::from_static(b"test"),
                    gzip_content: None,
                    brotli_content: None,
                    content_type: "text/plain".to_string(),
                    etag: format!("etag{}", i),
                    last_modified: SystemTime::now(),
                    cached_at: Instant::now(),
                    size: 4,
                },
            );
        }

        assert_eq!(cache.stats().entry_count, 10);
        cache.clear();
        assert_eq!(cache.stats().entry_count, 0);
    }
}
