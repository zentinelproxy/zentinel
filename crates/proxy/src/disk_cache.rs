//! Disk-based cache storage backend
//!
//! Implements Pingora's `Storage` trait using the local filesystem. Each cached
//! response is stored as a pair of files (`.meta` + `.body`) distributed across
//! sharded subdirectories to keep per-directory inode counts manageable.
//!
//! # Directory layout
//!
//! ```text
//! <base_path>/
//!   shard-00/
//!     <2-char-hex-prefix>/
//!       <combined-hex-hash>.meta
//!       <combined-hex-hash>.body
//!     tmp/
//!   shard-01/
//!     ...
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use pingora_cache::eviction::EvictionManager;
use pingora_cache::key::{CacheHashKey, CacheKey, CompactCacheKey};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::trace::SpanHandle;
use pingora_core::{Error, ErrorType, Result};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// ============================================================================
// DiskCacheStorage
// ============================================================================

/// Disk-based cache storage backend implementing Pingora's `Storage` trait.
///
/// All disk I/O is performed via `tokio::task::spawn_blocking` to avoid
/// blocking the async runtime.
pub struct DiskCacheStorage {
    base_path: PathBuf,
    num_shards: u32,
    #[allow(dead_code)]
    max_size_bytes: usize,
    /// Tracks in-flight writes: combined_hash -> set of temp_ids
    inflight: Arc<RwLock<HashMap<String, HashSet<u64>>>>,
    next_temp_id: AtomicU64,
}

impl DiskCacheStorage {
    /// Create a new `DiskCacheStorage`.
    ///
    /// Creates the shard directory structure and cleans up any orphaned `.tmp`
    /// files left behind by interrupted writes.
    pub fn new(path: &Path, shards: u32, max_size: usize) -> Self {
        let base = path.to_path_buf();

        // Create shard dirs, hex-prefix subdirs, and tmp dirs
        for shard in 0..shards {
            let shard_dir = base.join(format!("shard-{:02}", shard));

            // Create all 256 hex-prefix subdirs
            for prefix in 0..=255u8 {
                let prefix_dir = shard_dir.join(format!("{:02x}", prefix));
                if let Err(e) = std::fs::create_dir_all(&prefix_dir) {
                    error!(path = %prefix_dir.display(), error = %e, "Failed to create prefix dir");
                }
            }

            // Create tmp dir and clean orphaned files
            let tmp_dir = shard_dir.join("tmp");
            if let Err(e) = std::fs::create_dir_all(&tmp_dir) {
                error!(path = %tmp_dir.display(), error = %e, "Failed to create tmp dir");
            } else {
                Self::clean_orphaned_tmp(&tmp_dir);
            }
        }

        info!(
            path = %base.display(),
            shards,
            max_size_mb = max_size / 1024 / 1024,
            "Disk cache storage initialized"
        );

        Self {
            base_path: base,
            num_shards: shards,
            max_size_bytes: max_size,
            inflight: Arc::new(RwLock::new(HashMap::new())),
            next_temp_id: AtomicU64::new(1),
        }
    }

    /// Remove orphaned .tmp files from a tmp directory.
    fn clean_orphaned_tmp(tmp_dir: &Path) {
        let entries = match std::fs::read_dir(tmp_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        let mut cleaned = 0u64;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                if let Err(e) = std::fs::remove_file(&path) {
                    warn!(path = %path.display(), error = %e, "Failed to clean orphaned tmp file");
                } else {
                    cleaned += 1;
                }
            }
        }
        if cleaned > 0 {
            info!(dir = %tmp_dir.display(), cleaned, "Cleaned orphaned tmp files");
        }
    }

    // ========================================================================
    // Path helpers
    // ========================================================================

    /// Compute the shard index for a combined hex hash string.
    fn shard_for_key(combined: &str, num_shards: u32) -> u32 {
        // Use first two hex chars (one byte) to determine shard
        let byte = u8::from_str_radix(&combined[..2], 16).unwrap_or(0);
        (byte as u32) % num_shards
    }

    /// Compute the 2-char hex prefix subdirectory for a combined hex hash.
    fn prefix_for_key(combined: &str) -> &str {
        // Use chars 2..4 (second byte) as prefix subdir
        &combined[2..4]
    }

    /// Full path to the `.meta` file for a given combined hex hash.
    fn meta_path(&self, combined: &str) -> PathBuf {
        let shard = Self::shard_for_key(combined, self.num_shards);
        let prefix = Self::prefix_for_key(combined);
        self.base_path
            .join(format!("shard-{:02}", shard))
            .join(prefix)
            .join(format!("{}.meta", combined))
    }

    /// Full path to the `.body` file for a given combined hex hash.
    fn body_path(&self, combined: &str) -> PathBuf {
        let shard = Self::shard_for_key(combined, self.num_shards);
        let prefix = Self::prefix_for_key(combined);
        self.base_path
            .join(format!("shard-{:02}", shard))
            .join(prefix)
            .join(format!("{}.body", combined))
    }

    /// Path to the tmp directory for a given combined hex hash (shard-local).
    fn tmp_dir_for_key(&self, combined: &str) -> PathBuf {
        let shard = Self::shard_for_key(combined, self.num_shards);
        self.base_path
            .join(format!("shard-{:02}", shard))
            .join("tmp")
    }
}

// ============================================================================
// Meta file serialization helpers
// ============================================================================

/// Serialize CacheMeta to the on-disk format.
///
/// Format: `[4 bytes: internal_meta_len as u32 LE][internal_meta bytes][header bytes]`
fn serialize_meta_to_disk(meta: &CacheMeta) -> Result<Vec<u8>> {
    let (internal, header) = meta.serialize()?;
    let internal_len = internal.len() as u32;
    let mut buf = Vec::with_capacity(4 + internal.len() + header.len());
    buf.extend_from_slice(&internal_len.to_le_bytes());
    buf.extend_from_slice(&internal);
    buf.extend_from_slice(&header);
    Ok(buf)
}

/// Deserialize CacheMeta from the on-disk format.
fn deserialize_meta_from_disk(data: &[u8]) -> Result<CacheMeta> {
    if data.len() < 4 {
        return Error::e_explain(ErrorType::FileReadError, "meta file too short");
    }
    let internal_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + internal_len {
        return Error::e_explain(ErrorType::FileReadError, "meta file truncated");
    }
    let internal = &data[4..4 + internal_len];
    let header = &data[4 + internal_len..];
    CacheMeta::deserialize(internal, header)
}

// ============================================================================
// DiskHitHandler
// ============================================================================

/// Hit handler for disk cache lookups.
///
/// Loads the full body into memory for seekable access.
pub struct DiskHitHandler {
    body: Vec<u8>,
    meta_size: usize,
    done: bool,
    range_start: usize,
    range_end: usize,
}

#[async_trait]
impl HandleHit for DiskHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(Bytes::copy_from_slice(
            &self.body[self.range_start..self.range_end],
        )))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.body.len() {
            return Error::e_explain(
                ErrorType::InternalError,
                format!("seek start out of range {} >= {}", start, self.body.len()),
            );
        }
        self.range_start = start;
        if let Some(end) = end {
            self.range_end = std::cmp::min(self.body.len(), end);
        }
        self.done = false;
        Ok(())
    }

    fn get_eviction_weight(&self) -> usize {
        self.meta_size + self.body.len()
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

// ============================================================================
// DiskMissHandler
// ============================================================================

/// Miss handler for disk cache writes.
///
/// Accumulates the response body in memory, then atomically writes both
/// `.meta` and `.body` files to disk via temp-file + rename.
pub struct DiskMissHandler {
    body_buffer: Vec<u8>,
    serialized_meta: Vec<u8>,
    combined: String,
    meta_path: PathBuf,
    body_path: PathBuf,
    tmp_dir: PathBuf,
    temp_id: u64,
    inflight: Arc<RwLock<HashMap<String, HashSet<u64>>>>,
    finished: bool,
}

#[async_trait]
impl HandleMiss for DiskMissHandler {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        self.body_buffer.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        self.finished = true;
        let body = std::mem::take(&mut self.body_buffer);
        let meta = self.serialized_meta.clone();
        let meta_path = self.meta_path.clone();
        let body_path = self.body_path.clone();
        let tmp_dir = self.tmp_dir.clone();
        let temp_id = self.temp_id;

        let size = meta.len() + body.len();

        // Write to disk via spawn_blocking
        tokio::task::spawn_blocking(move || {
            let tmp_meta = tmp_dir.join(format!("{}.meta.tmp", temp_id));
            let tmp_body = tmp_dir.join(format!("{}.body.tmp", temp_id));

            // Write meta temp file
            if let Err(e) = std::fs::write(&tmp_meta, &meta) {
                error!(path = %tmp_meta.display(), error = %e, "Failed to write tmp meta");
                let _ = std::fs::remove_file(&tmp_meta);
                return Err(Error::explain(
                    ErrorType::WriteError,
                    format!("failed to write meta: {}", e),
                ));
            }

            // Write body temp file
            if let Err(e) = std::fs::write(&tmp_body, &body) {
                error!(path = %tmp_body.display(), error = %e, "Failed to write tmp body");
                let _ = std::fs::remove_file(&tmp_meta);
                let _ = std::fs::remove_file(&tmp_body);
                return Err(Error::explain(
                    ErrorType::WriteError,
                    format!("failed to write body: {}", e),
                ));
            }

            // Atomic rename meta
            if let Err(e) = std::fs::rename(&tmp_meta, &meta_path) {
                error!(error = %e, "Failed to rename tmp meta to final path");
                let _ = std::fs::remove_file(&tmp_meta);
                let _ = std::fs::remove_file(&tmp_body);
                return Err(Error::explain(
                    ErrorType::WriteError,
                    format!("failed to rename meta: {}", e),
                ));
            }

            // Atomic rename body
            if let Err(e) = std::fs::rename(&tmp_body, &body_path) {
                error!(error = %e, "Failed to rename tmp body to final path");
                // Meta already renamed; remove it to stay consistent
                let _ = std::fs::remove_file(&meta_path);
                return Err(Error::explain(
                    ErrorType::WriteError,
                    format!("failed to rename body: {}", e),
                ));
            }

            Ok(())
        })
        .await
        .map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("spawn_blocking join error: {}", e),
            )
        })??;

        // Remove from inflight tracking
        {
            let mut inflight = self.inflight.write().await;
            if let Some(set) = inflight.get_mut(&self.combined) {
                set.remove(&self.temp_id);
                if set.is_empty() {
                    inflight.remove(&self.combined);
                }
            }
        }

        debug!(combined = %self.combined, size, "Disk cache entry written");
        Ok(MissFinishType::Created(size))
    }
}

impl Drop for DiskMissHandler {
    fn drop(&mut self) {
        if !self.finished {
            // Clean up inflight tracking if finish() was never called.
            // We can't do async in Drop, so use try_write.
            if let Ok(mut inflight) = self.inflight.try_write() {
                if let Some(set) = inflight.get_mut(&self.combined) {
                    set.remove(&self.temp_id);
                    if set.is_empty() {
                        inflight.remove(&self.combined);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Storage trait implementation
// ============================================================================

#[async_trait]
impl Storage for DiskCacheStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let combined = key.combined();
        let meta_path = self.meta_path(&combined);
        let body_path = self.body_path(&combined);

        let result =
            tokio::task::spawn_blocking(move || -> Result<Option<(CacheMeta, HitHandler)>> {
                let meta_data = match std::fs::read(&meta_path) {
                    Ok(d) => d,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => {
                        debug!(error = %e, "Failed to read cache meta file");
                        return Ok(None);
                    }
                };

                let body_data = match std::fs::read(&body_path) {
                    Ok(d) => d,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => {
                        debug!(error = %e, "Failed to read cache body file");
                        return Ok(None);
                    }
                };

                let meta = match deserialize_meta_from_disk(&meta_data) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(error = %e, "Corrupted cache meta, removing entry");
                        let _ = std::fs::remove_file(&meta_path);
                        let _ = std::fs::remove_file(&body_path);
                        return Ok(None);
                    }
                };

                let body_len = body_data.len();
                let hit_handler = DiskHitHandler {
                    body: body_data,
                    meta_size: meta_data.len(),
                    done: false,
                    range_start: 0,
                    range_end: body_len,
                };

                Ok(Some((meta, Box::new(hit_handler) as HitHandler)))
            })
            .await
            .map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("spawn_blocking join error: {}", e),
                )
            })??;

        Ok(result)
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let combined = key.combined();
        let serialized_meta = serialize_meta_to_disk(meta)?;
        let meta_path = self.meta_path(&combined);
        let body_path = self.body_path(&combined);
        let tmp_dir = self.tmp_dir_for_key(&combined);
        let temp_id = self.next_temp_id.fetch_add(1, Ordering::Relaxed);

        // Register in inflight tracking
        {
            let mut inflight = self.inflight.write().await;
            inflight
                .entry(combined.clone())
                .or_default()
                .insert(temp_id);
        }

        Ok(Box::new(DiskMissHandler {
            body_buffer: Vec::new(),
            serialized_meta,
            combined,
            meta_path,
            body_path,
            tmp_dir,
            temp_id,
            inflight: self.inflight.clone(),
            finished: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let combined = key.combined();
        let meta_path = self.meta_path(&combined);
        let body_path = self.body_path(&combined);

        let removed = tokio::task::spawn_blocking(move || {
            let meta_removed = std::fs::remove_file(&meta_path).is_ok();
            let body_removed = std::fs::remove_file(&body_path).is_ok();
            meta_removed || body_removed
        })
        .await
        .map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("spawn_blocking join error: {}", e),
            )
        })?;

        // Also remove from inflight tracking
        {
            let mut inflight = self.inflight.write().await;
            inflight.remove(&combined);
        }

        Ok(removed)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let combined = key.combined();
        let serialized = serialize_meta_to_disk(meta)?;
        let meta_path = self.meta_path(&combined);
        let tmp_dir = self.tmp_dir_for_key(&combined);

        tokio::task::spawn_blocking(move || {
            // Atomic rewrite: write to tmp, rename over existing
            let tmp_path = tmp_dir.join(format!("{}.meta.update.tmp", combined));
            std::fs::write(&tmp_path, &serialized).map_err(|e| {
                Error::explain(
                    ErrorType::WriteError,
                    format!("failed to write updated meta: {}", e),
                )
            })?;
            std::fs::rename(&tmp_path, &meta_path).map_err(|e| {
                let _ = std::fs::remove_file(&tmp_path);
                Error::explain(
                    ErrorType::WriteError,
                    format!("failed to rename updated meta: {}", e),
                )
            })?;
            Ok(true)
        })
        .await
        .map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("spawn_blocking join error: {}", e),
            )
        })?
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

// ============================================================================
// Eviction state rebuild
// ============================================================================

/// Scan disk entries and register them with the eviction manager.
///
/// This is called at startup to rebuild the LRU eviction state from the
/// files on disk.
pub async fn rebuild_eviction_state(
    base_path: &Path,
    num_shards: u32,
    eviction: &'static pingora_cache::eviction::simple_lru::Manager,
) {
    let base = base_path.to_path_buf();
    let result = tokio::task::spawn_blocking(move || {
        let mut count = 0usize;
        let mut total_size = 0usize;

        for shard in 0..num_shards {
            let shard_dir = base.join(format!("shard-{:02}", shard));

            for prefix in 0..=255u8 {
                let prefix_dir = shard_dir.join(format!("{:02x}", prefix));
                let entries = match std::fs::read_dir(&prefix_dir) {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                for entry in entries.flatten() {
                    let path = entry.path();
                    let ext = path.extension().and_then(|e| e.to_str());
                    if ext != Some("body") {
                        continue;
                    }

                    // Extract combined hash from filename
                    let stem = match path.file_stem().and_then(|s| s.to_str()) {
                        Some(s) => s.to_string(),
                        None => continue,
                    };

                    // Get file size for weight
                    let body_size = match std::fs::metadata(&path) {
                        Ok(m) => m.len() as usize,
                        Err(_) => continue,
                    };

                    // Also add meta size
                    let meta_path = prefix_dir.join(format!("{}.meta", stem));
                    let meta_size = std::fs::metadata(&meta_path)
                        .map(|m| m.len() as usize)
                        .unwrap_or(0);

                    let size = body_size + meta_size;

                    // Reconstruct CompactCacheKey from the combined hex hash
                    if let Some(primary) = pingora_cache::key::str2hex(&stem) {
                        let compact = CompactCacheKey {
                            primary,
                            variance: None,
                            user_tag: "".into(),
                        };

                        // Admit to eviction manager (use epoch as fresh_until since
                        // we don't know the actual TTL without parsing meta)
                        let _ = eviction.admit(
                            compact,
                            size,
                            std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
                        );

                        count += 1;
                        total_size += size;
                    }
                }
            }
        }

        (count, total_size)
    })
    .await;

    match result {
        Ok((count, total_size)) => {
            info!(
                entries = count,
                total_size_mb = total_size / 1024 / 1024,
                "Rebuilt disk cache eviction state"
            );
        }
        Err(e) => {
            error!(error = %e, "Failed to rebuild disk cache eviction state");
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use pingora_cache::trace::Span;
    use pingora_http::ResponseHeader;
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn create_test_meta() -> CacheMeta {
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.append_header("content-type", "text/plain").unwrap();
        header.append_header("x-test", "disk-cache").unwrap();
        CacheMeta::new(
            SystemTime::now() + std::time::Duration::from_secs(3600),
            SystemTime::now(),
            60,
            300,
            header,
        )
    }

    fn span() -> SpanHandle {
        Span::inactive().handle()
    }

    #[test]
    fn test_directory_creation() {
        let tmp = TempDir::new().unwrap();
        let _storage = DiskCacheStorage::new(tmp.path(), 4, 100 * 1024 * 1024);

        // Verify shard dirs exist
        for shard in 0..4u32 {
            let shard_dir = tmp.path().join(format!("shard-{:02}", shard));
            assert!(shard_dir.is_dir(), "shard dir should exist");

            // Verify some prefix dirs exist
            assert!(shard_dir.join("00").is_dir());
            assert!(shard_dir.join("ff").is_dir());
            assert!(shard_dir.join("a5").is_dir());

            // Verify tmp dir exists
            assert!(shard_dir.join("tmp").is_dir());
        }

        // Shard-04 should not exist
        assert!(!tmp.path().join("shard-04").exists());
    }

    #[test]
    fn test_path_helpers() {
        let tmp = TempDir::new().unwrap();
        let storage = DiskCacheStorage::new(tmp.path(), 16, 100 * 1024 * 1024);

        // "ab" prefix -> shard = 0xab % 16 = 11, prefix subdir = second byte
        let combined = "abcd1234567890abcdef1234567890ab";

        let shard = DiskCacheStorage::shard_for_key(combined, 16);
        assert_eq!(shard, 0xab % 16); // 171 % 16 = 11

        let prefix = DiskCacheStorage::prefix_for_key(combined);
        assert_eq!(prefix, "cd");

        let meta = storage.meta_path(combined);
        assert!(meta.to_str().unwrap().contains("shard-11"));
        assert!(meta.to_str().unwrap().contains("/cd/"));
        assert!(meta.to_str().unwrap().ends_with(".meta"));

        let body = storage.body_path(combined);
        assert!(body.to_str().unwrap().contains("shard-11"));
        assert!(body.to_str().unwrap().contains("/cd/"));
        assert!(body.to_str().unwrap().ends_with(".body"));
    }

    #[tokio::test]
    async fn test_write_and_read() {
        static STORAGE: Lazy<DiskCacheStorage> = Lazy::new(|| {
            let path = std::env::temp_dir().join("zentinel-disk-cache-test-write-read");
            let _ = std::fs::remove_dir_all(&path);
            DiskCacheStorage::new(&path, 4, 100 * 1024 * 1024)
        });
        let trace = &span();

        let key = CacheKey::new("", "test-write-read", "1");
        let meta = create_test_meta();

        // Lookup should return None initially
        let result = STORAGE.lookup(&key, trace).await.unwrap();
        assert!(result.is_none());

        // Write via miss handler
        let mut miss_handler = STORAGE.get_miss_handler(&key, &meta, trace).await.unwrap();
        miss_handler
            .write_body(b"hello "[..].into(), false)
            .await
            .unwrap();
        miss_handler
            .write_body(b"world"[..].into(), true)
            .await
            .unwrap();
        let finish_result = miss_handler.finish().await.unwrap();
        assert!(matches!(finish_result, MissFinishType::Created(_)));

        // Lookup should now return the cached entry
        let (read_meta, mut hit_handler) = STORAGE.lookup(&key, trace).await.unwrap().unwrap();
        assert_eq!(read_meta.response_header().status.as_u16(), 200);

        let body = hit_handler.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"hello world");

        // Second read should return None
        let body2 = hit_handler.read_body().await.unwrap();
        assert!(body2.is_none());

        // Cleanup
        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join("zentinel-disk-cache-test-write-read"),
        );
    }

    #[tokio::test]
    async fn test_purge() {
        static STORAGE: Lazy<DiskCacheStorage> = Lazy::new(|| {
            let path = std::env::temp_dir().join("zentinel-disk-cache-test-purge");
            let _ = std::fs::remove_dir_all(&path);
            DiskCacheStorage::new(&path, 4, 100 * 1024 * 1024)
        });
        let trace = &span();

        let key = CacheKey::new("", "test-purge", "1");
        let meta = create_test_meta();

        // Write an entry
        let mut miss_handler = STORAGE.get_miss_handler(&key, &meta, trace).await.unwrap();
        miss_handler
            .write_body(b"purge-me"[..].into(), true)
            .await
            .unwrap();
        miss_handler.finish().await.unwrap();

        // Verify it's there
        assert!(STORAGE.lookup(&key, trace).await.unwrap().is_some());

        // Purge it
        let compact = key.to_compact();
        let purged = STORAGE
            .purge(&compact, PurgeType::Invalidation, trace)
            .await
            .unwrap();
        assert!(purged);

        // Verify it's gone
        assert!(STORAGE.lookup(&key, trace).await.unwrap().is_none());

        // Cleanup
        let _ =
            std::fs::remove_dir_all(std::env::temp_dir().join("zentinel-disk-cache-test-purge"));
    }

    #[tokio::test]
    async fn test_update_meta() {
        static STORAGE: Lazy<DiskCacheStorage> = Lazy::new(|| {
            let path = std::env::temp_dir().join("zentinel-disk-cache-test-update-meta");
            let _ = std::fs::remove_dir_all(&path);
            DiskCacheStorage::new(&path, 4, 100 * 1024 * 1024)
        });
        let trace = &span();

        let key = CacheKey::new("", "test-update-meta", "1");
        let meta = create_test_meta();

        // Write an entry
        let mut miss_handler = STORAGE.get_miss_handler(&key, &meta, trace).await.unwrap();
        miss_handler
            .write_body(b"body-data"[..].into(), true)
            .await
            .unwrap();
        miss_handler.finish().await.unwrap();

        // Create updated meta with different header
        let mut new_header = ResponseHeader::build(200, None).unwrap();
        new_header
            .append_header("content-type", "application/json")
            .unwrap();
        new_header.append_header("x-updated", "true").unwrap();
        let new_meta = CacheMeta::new(
            SystemTime::now() + std::time::Duration::from_secs(7200),
            SystemTime::now(),
            120,
            600,
            new_header,
        );

        // Update meta
        let updated = STORAGE.update_meta(&key, &new_meta, trace).await.unwrap();
        assert!(updated);

        // Verify updated meta
        let (read_meta, _hit) = STORAGE.lookup(&key, trace).await.unwrap().unwrap();
        let headers = read_meta.response_header().headers.clone();
        assert_eq!(headers.get("x-updated").unwrap().to_str().unwrap(), "true");

        // Cleanup
        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join("zentinel-disk-cache-test-update-meta"),
        );
    }

    #[tokio::test]
    async fn test_miss_handler_drop() {
        static STORAGE: Lazy<DiskCacheStorage> = Lazy::new(|| {
            let path = std::env::temp_dir().join("zentinel-disk-cache-test-miss-drop");
            let _ = std::fs::remove_dir_all(&path);
            DiskCacheStorage::new(&path, 4, 100 * 1024 * 1024)
        });
        let trace = &span();

        let key = CacheKey::new("", "test-miss-drop", "1");
        let meta = create_test_meta();

        // Create miss handler and write some data but don't finish
        {
            let mut miss_handler = STORAGE.get_miss_handler(&key, &meta, trace).await.unwrap();
            miss_handler
                .write_body(b"incomplete"[..].into(), false)
                .await
                .unwrap();
            // Drop without finish
        }

        // Verify no files were written
        assert!(STORAGE.lookup(&key, trace).await.unwrap().is_none());

        // Verify inflight tracking was cleaned up
        assert!(STORAGE.inflight.read().await.is_empty());

        // Cleanup
        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join("zentinel-disk-cache-test-miss-drop"),
        );
    }

    #[tokio::test]
    async fn test_corrupted_meta() {
        static STORAGE: Lazy<DiskCacheStorage> = Lazy::new(|| {
            let path = std::env::temp_dir().join("zentinel-disk-cache-test-corrupted");
            let _ = std::fs::remove_dir_all(&path);
            DiskCacheStorage::new(&path, 4, 100 * 1024 * 1024)
        });
        let trace = &span();

        let key = CacheKey::new("", "test-corrupted", "1");
        let combined = key.combined();

        // Write garbage to the meta file
        let meta_path = STORAGE.meta_path(&combined);
        let body_path = STORAGE.body_path(&combined);
        std::fs::write(&meta_path, b"not-valid-meta-data").unwrap();
        std::fs::write(&body_path, b"some-body").unwrap();

        // Lookup should gracefully return None
        let result = STORAGE.lookup(&key, trace).await.unwrap();
        assert!(result.is_none());

        // Corrupted files should have been cleaned up
        assert!(!meta_path.exists());
        assert!(!body_path.exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(
            std::env::temp_dir().join("zentinel-disk-cache-test-corrupted"),
        );
    }

    #[test]
    fn test_orphan_cleanup() {
        let tmp = TempDir::new().unwrap();

        // Pre-create a shard with tmp dir and orphaned files
        let shard_tmp = tmp.path().join("shard-00").join("tmp");
        std::fs::create_dir_all(&shard_tmp).unwrap();
        std::fs::write(shard_tmp.join("orphan1.tmp"), b"data1").unwrap();
        std::fs::write(shard_tmp.join("orphan2.tmp"), b"data2").unwrap();
        // Non-tmp file should be left alone
        std::fs::write(shard_tmp.join("keep.txt"), b"keep").unwrap();

        assert!(shard_tmp.join("orphan1.tmp").exists());
        assert!(shard_tmp.join("orphan2.tmp").exists());

        // Creating storage should clean orphaned .tmp files
        let _storage = DiskCacheStorage::new(tmp.path(), 4, 100 * 1024 * 1024);

        assert!(!shard_tmp.join("orphan1.tmp").exists());
        assert!(!shard_tmp.join("orphan2.tmp").exists());
        assert!(shard_tmp.join("keep.txt").exists());
    }

    #[test]
    fn test_meta_serialization_roundtrip() {
        let meta = create_test_meta();
        let serialized = serialize_meta_to_disk(&meta).unwrap();
        let deserialized = deserialize_meta_from_disk(&serialized).unwrap();

        assert_eq!(
            meta.response_header().status.as_u16(),
            deserialized.response_header().status.as_u16(),
        );
    }
}
