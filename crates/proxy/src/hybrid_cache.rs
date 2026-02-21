//! Hybrid cache storage backend
//!
//! Combines memory (hot) and disk (cold) tiers. Lookups check memory first,
//! falling back to disk with automatic promotion on hit. Writes go to both
//! tiers so that entries are immediately available in memory and durable on
//! disk.

use async_trait::async_trait;
use bytes::Bytes;
use futures::FutureExt;
use pingora_cache::key::{CacheHashKey, CacheKey, CompactCacheKey};
use pingora_cache::meta::CacheMeta;
use pingora_cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeType, Storage,
};
use pingora_cache::trace::SpanHandle;
use pingora_cache::MemCache;
use pingora_core::Result;
use std::any::Any;
use std::panic::AssertUnwindSafe;
use tracing::{debug, warn};

use crate::disk_cache::DiskCacheStorage;

// ============================================================================
// HybridCacheStorage
// ============================================================================

/// Two-tier cache: memory for hot entries, disk for cold, with automatic
/// promotion on disk hits.
pub struct HybridCacheStorage {
    memory: &'static MemCache,
    disk: &'static DiskCacheStorage,
}

impl HybridCacheStorage {
    pub fn new(memory: &'static MemCache, disk: &'static DiskCacheStorage) -> Self {
        Self { memory, disk }
    }
}

#[async_trait]
impl Storage for HybridCacheStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        // Fast path: check memory first
        if let Some(hit) = self.memory.lookup(key, trace).await? {
            debug!("hybrid cache: memory hit");
            return Ok(Some(hit));
        }

        // Slow path: check disk
        let (meta, mut disk_hit) = match self.disk.lookup(key, trace).await? {
            Some(hit) => hit,
            None => return Ok(None),
        };
        debug!("hybrid cache: disk hit, promoting to memory");

        // Read the full body from the disk hit handler
        let mut body_parts: Vec<Bytes> = Vec::new();
        while let Some(chunk) = disk_hit.read_body().await? {
            body_parts.push(chunk);
        }
        let full_body: Bytes = if body_parts.len() == 1 {
            body_parts.into_iter().next().unwrap()
        } else {
            let total: usize = body_parts.iter().map(|b| b.len()).sum();
            let mut buf = Vec::with_capacity(total);
            for part in &body_parts {
                buf.extend_from_slice(part);
            }
            Bytes::from(buf)
        };

        // Serialize meta before spawning (CacheMeta is not Send-safe to move
        // across spawn boundaries without serialization)
        let serialized_meta = meta.serialize()?;
        let promote_body = full_body.clone();
        let key_clone = key.clone();

        // Spawn background promotion into memory tier
        let mem = self.memory;
        tokio::spawn(async move {
            let promote_meta = match CacheMeta::deserialize(&serialized_meta.0, &serialized_meta.1)
            {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "hybrid cache: failed to deserialize meta for promotion");
                    return;
                }
            };
            let inactive_span = pingora_cache::trace::Span::inactive().handle();
            match mem
                .get_miss_handler(&key_clone, &promote_meta, &inactive_span)
                .await
            {
                Ok(mut handler) => {
                    if let Err(e) = handler.write_body(promote_body, true).await {
                        warn!(error = %e, "hybrid cache: promotion write_body failed");
                        return;
                    }
                    if let Err(e) = handler.finish().await {
                        warn!(error = %e, "hybrid cache: promotion finish failed");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "hybrid cache: promotion get_miss_handler failed");
                }
            }
        });

        // Return a hit handler wrapping the already-read body
        let handler = HybridHitHandler::new(full_body);
        Ok(Some((meta, Box::new(handler))))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let mem_handler = self.memory.get_miss_handler(key, meta, trace).await?;
        let disk_handler = self.disk.get_miss_handler(key, meta, trace).await?;

        Ok(Box::new(HybridMissHandler {
            mem_handler: Some(mem_handler),
            disk_handler: Some(disk_handler),
            finished: false,
        }))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        purge_type: PurgeType,
        trace: &SpanHandle,
    ) -> Result<bool> {
        match purge_type {
            PurgeType::Eviction => {
                // Capacity demotion: remove from memory only, disk copy stays.
                debug!("hybrid cache: eviction demotion, keeping disk copy");
                self.memory.purge(key, purge_type, trace).await
            }
            PurgeType::Invalidation => {
                let mem = self.memory.purge(key, purge_type, trace).await?;
                let disk = self.disk.purge(key, purge_type, trace).await?;
                Ok(mem || disk)
            }
        }
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        trace: &SpanHandle,
    ) -> Result<bool> {
        // MemCache::update_meta panics if the key is not in its cache map.
        // The entry may only exist on disk, so we catch the panic.
        let mem_updated =
            match AssertUnwindSafe(self.memory.update_meta(key, meta, trace))
                .catch_unwind()
                .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    warn!(error = %e, "hybrid cache: memory update_meta error");
                    false
                }
                Err(_) => {
                    debug!("hybrid cache: key not in memory tier, skipping memory update_meta");
                    false
                }
            };

        let disk_updated = self.disk.update_meta(key, meta, trace).await?;
        Ok(mem_updated || disk_updated)
    }

    fn support_streaming_partial_write(&self) -> bool {
        // Delegate to memory tier which supports streaming partial writes
        self.memory.support_streaming_partial_write()
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

// ============================================================================
// HybridHitHandler — wraps an already-read body from a disk-promoted hit
// ============================================================================

pub struct HybridHitHandler {
    body: Bytes,
    done: bool,
    range_start: usize,
    range_end: usize,
}

impl HybridHitHandler {
    fn new(body: Bytes) -> Self {
        let len = body.len();
        Self {
            body,
            done: false,
            range_start: 0,
            range_end: len,
        }
    }
}

#[async_trait]
impl HandleHit for HybridHitHandler {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(self.body.slice(self.range_start..self.range_end)))
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
            return pingora_core::Error::e_explain(
                pingora_core::ErrorType::InternalError,
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
        self.body.len()
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}

// ============================================================================
// HybridMissHandler — writes to both tiers
// ============================================================================

struct HybridMissHandler {
    mem_handler: Option<MissHandler>,
    disk_handler: Option<MissHandler>,
    finished: bool,
}

#[async_trait]
impl HandleMiss for HybridMissHandler {
    async fn write_body(&mut self, data: Bytes, eof: bool) -> Result<()> {
        // Bytes::clone is a cheap Arc ref-count bump
        if let Some(ref mut mem) = self.mem_handler {
            mem.write_body(data.clone(), eof).await?;
        }
        if let Some(ref mut disk) = self.disk_handler {
            disk.write_body(data, eof).await?;
        }
        Ok(())
    }

    async fn finish(mut self: Box<Self>) -> Result<MissFinishType> {
        self.finished = true;

        // Finish memory first for immediate availability
        let mem_size = if let Some(mem) = self.mem_handler.take() {
            match mem.finish().await {
                Ok(MissFinishType::Created(s)) => s,
                Ok(MissFinishType::Appended(s, _)) => s,
                Err(e) => {
                    warn!(error = %e, "hybrid cache: memory finish failed");
                    0
                }
            }
        } else {
            0
        };

        // Finish disk for durability; failure is non-fatal
        if let Some(disk) = self.disk_handler.take() {
            if let Err(e) = disk.finish().await {
                warn!(error = %e, "hybrid cache: disk finish failed (non-fatal)");
            }
        }

        Ok(MissFinishType::Created(mem_size))
    }

    fn streaming_write_tag(&self) -> Option<&[u8]> {
        // Delegate to memory handler for streaming partial write support
        self.mem_handler
            .as_ref()
            .and_then(|h| h.streaming_write_tag())
    }
}

impl Drop for HybridMissHandler {
    fn drop(&mut self) {
        // Inner handlers clean up their own state via their Drop impls
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
    use std::path::Path;
    use std::time::SystemTime;

    fn create_test_meta() -> CacheMeta {
        let mut header = ResponseHeader::build(200, None).unwrap();
        header.append_header("content-type", "text/plain").unwrap();
        header.append_header("x-test", "hybrid").unwrap();
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

    fn test_disk(name: &str) -> DiskCacheStorage {
        let path = std::env::temp_dir().join(format!("zentinel-hybrid-test-{}", name));
        let _ = std::fs::remove_dir_all(&path);
        DiskCacheStorage::new(&path, 2, 50 * 1024 * 1024)
    }

    fn cleanup_disk(name: &str) {
        let path = std::env::temp_dir().join(format!("zentinel-hybrid-test-{}", name));
        let _ = std::fs::remove_dir_all(&path);
    }

    // ---------- test 1: miss then hit ----------

    static HYBRID_1_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_1_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("miss-then-hit"));
    static HYBRID_1: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_1_MEM, &HYBRID_1_DISK));

    #[tokio::test]
    async fn test_hybrid_miss_then_hit() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-miss-hit", "1");
        let meta = create_test_meta();

        // Lookup should miss
        assert!(HYBRID_1.lookup(&key, trace).await.unwrap().is_none());

        // Write via miss handler
        let mut handler = HYBRID_1.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"hello hybrid"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        // Lookup should hit
        let (read_meta, mut hit) = HYBRID_1.lookup(&key, trace).await.unwrap().unwrap();
        assert_eq!(read_meta.response_header().status.as_u16(), 200);
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"hello hybrid");

        // Second read should return None
        assert!(hit.read_body().await.unwrap().is_none());

        cleanup_disk("miss-then-hit");
    }

    // ---------- test 2: disk promotion ----------

    static HYBRID_2_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_2_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("disk-promotion"));
    static HYBRID_2: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_2_MEM, &HYBRID_2_DISK));

    #[tokio::test]
    async fn test_hybrid_disk_promotion() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-promote", "1");
        let meta = create_test_meta();

        // Write directly to disk tier only
        let mut disk_handler = HYBRID_2_DISK
            .get_miss_handler(&key, &meta, trace)
            .await
            .unwrap();
        disk_handler
            .write_body(Bytes::from_static(b"cold data"), true)
            .await
            .unwrap();
        disk_handler.finish().await.unwrap();

        // Memory should have nothing
        assert!(HYBRID_2_MEM.lookup(&key, trace).await.unwrap().is_none());

        // Hybrid lookup triggers disk hit + promotion
        let (_meta, mut hit) = HYBRID_2.lookup(&key, trace).await.unwrap().unwrap();
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"cold data");

        // Give the background promotion task time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now memory should have the entry
        let mem_result = HYBRID_2_MEM.lookup(&key, trace).await.unwrap();
        assert!(mem_result.is_some(), "entry should be promoted to memory");

        cleanup_disk("disk-promotion");
    }

    // ---------- test 3: purge both tiers ----------

    static HYBRID_3_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_3_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("purge-both"));
    static HYBRID_3: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_3_MEM, &HYBRID_3_DISK));

    #[tokio::test]
    async fn test_hybrid_purge_both_tiers() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-purge", "1");
        let meta = create_test_meta();

        // Write via hybrid (goes to both tiers)
        let mut handler = HYBRID_3.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"purge me"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        // Verify both tiers have it
        assert!(HYBRID_3_MEM.lookup(&key, trace).await.unwrap().is_some());
        assert!(HYBRID_3_DISK.lookup(&key, trace).await.unwrap().is_some());

        // Purge
        let compact = key.to_compact();
        let purged = HYBRID_3
            .purge(&compact, PurgeType::Invalidation, trace)
            .await
            .unwrap();
        assert!(purged);

        // Both tiers should be empty
        assert!(HYBRID_3_MEM.lookup(&key, trace).await.unwrap().is_none());
        assert!(HYBRID_3_DISK.lookup(&key, trace).await.unwrap().is_none());

        cleanup_disk("purge-both");
    }

    // ---------- test 4: update meta ----------

    static HYBRID_4_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_4_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("update-meta"));
    static HYBRID_4: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_4_MEM, &HYBRID_4_DISK));

    #[tokio::test]
    async fn test_hybrid_update_meta() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-update-meta", "1");
        let meta = create_test_meta();

        // Write entry
        let mut handler = HYBRID_4.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"update me"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

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

        // Update meta via hybrid
        let updated = HYBRID_4
            .update_meta(&key, &new_meta, trace)
            .await
            .unwrap();
        assert!(updated);

        // Verify lookup returns updated headers
        let (read_meta, _hit) = HYBRID_4.lookup(&key, trace).await.unwrap().unwrap();
        let headers = read_meta.response_header().headers.clone();
        assert_eq!(headers.get("x-updated").unwrap().to_str().unwrap(), "true");

        cleanup_disk("update-meta");
    }

    // ---------- test 5: miss handler drop ----------

    static HYBRID_5_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_5_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("miss-drop"));
    static HYBRID_5: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_5_MEM, &HYBRID_5_DISK));

    #[tokio::test]
    async fn test_hybrid_miss_handler_drop() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-miss-drop", "1");
        let meta = create_test_meta();

        // Create miss handler, write data, drop without finish
        {
            let mut handler = HYBRID_5.get_miss_handler(&key, &meta, trace).await.unwrap();
            handler
                .write_body(Bytes::from_static(b"incomplete"), false)
                .await
                .unwrap();
            // Drop without calling finish
        }

        // Neither tier should have the entry
        assert!(HYBRID_5_MEM.lookup(&key, trace).await.unwrap().is_none());
        assert!(HYBRID_5_DISK.lookup(&key, trace).await.unwrap().is_none());

        cleanup_disk("miss-drop");
    }

    // ---------- test 6: chunked write ----------

    static HYBRID_6_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_6_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("chunked-write"));
    static HYBRID_6: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_6_MEM, &HYBRID_6_DISK));

    #[tokio::test]
    async fn test_hybrid_chunked_write() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-chunked", "1");
        let meta = create_test_meta();

        let mut handler = HYBRID_6.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"chunk1-"), false)
            .await
            .unwrap();
        handler
            .write_body(Bytes::from_static(b"chunk2-"), false)
            .await
            .unwrap();
        handler
            .write_body(Bytes::from_static(b"chunk3"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        let (_meta, mut hit) = HYBRID_6.lookup(&key, trace).await.unwrap().unwrap();
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"chunk1-chunk2-chunk3");

        cleanup_disk("chunked-write");
    }

    // ---------- test 7: seek ----------

    static HYBRID_7_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_7_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("seek"));
    static HYBRID_7: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_7_MEM, &HYBRID_7_DISK));

    #[tokio::test]
    async fn test_hybrid_seek() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-seek", "1");
        let meta = create_test_meta();

        // Write directly to disk so lookup returns HybridHitHandler
        let mut disk_handler = HYBRID_7_DISK
            .get_miss_handler(&key, &meta, trace)
            .await
            .unwrap();
        disk_handler
            .write_body(Bytes::from_static(b"0123456789"), true)
            .await
            .unwrap();
        disk_handler.finish().await.unwrap();

        let (_meta, mut hit) = HYBRID_7.lookup(&key, trace).await.unwrap().unwrap();
        assert!(hit.can_seek());

        // Seek to a range
        hit.seek(3, Some(7)).unwrap();
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"3456");

        // Seek again
        hit.seek(0, Some(3)).unwrap();
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"012");

        // Out of range should fail
        assert!(hit.seek(100, None).is_err());

        cleanup_disk("seek");
    }

    // ---------- test 8: eviction demotion ----------

    static HYBRID_8_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_8_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("eviction-demotion"));
    static HYBRID_8: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_8_MEM, &HYBRID_8_DISK));

    #[tokio::test]
    async fn test_hybrid_eviction_demotion() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-evict-demote", "1");
        let meta = create_test_meta();

        // Write via hybrid (goes to both tiers)
        let mut handler = HYBRID_8.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"demote me"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        // Verify both tiers have it
        assert!(HYBRID_8_MEM.lookup(&key, trace).await.unwrap().is_some());
        assert!(HYBRID_8_DISK.lookup(&key, trace).await.unwrap().is_some());

        // Eviction purge — should only remove from memory
        let compact = key.to_compact();
        let purged = HYBRID_8
            .purge(&compact, PurgeType::Eviction, trace)
            .await
            .unwrap();
        assert!(purged);

        // Memory should be empty, disk should still have it
        assert!(HYBRID_8_MEM.lookup(&key, trace).await.unwrap().is_none());
        assert!(HYBRID_8_DISK.lookup(&key, trace).await.unwrap().is_some());

        cleanup_disk("eviction-demotion");
    }

    // ---------- test 9: eviction then disk hit ----------

    static HYBRID_9_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_9_DISK: Lazy<DiskCacheStorage> = Lazy::new(|| test_disk("evict-then-hit"));
    static HYBRID_9: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_9_MEM, &HYBRID_9_DISK));

    #[tokio::test]
    async fn test_hybrid_eviction_then_disk_hit() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-evict-hit", "1");
        let meta = create_test_meta();

        // Write via hybrid (goes to both tiers)
        let mut handler = HYBRID_9.get_miss_handler(&key, &meta, trace).await.unwrap();
        handler
            .write_body(Bytes::from_static(b"evict and find"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        // Evict from memory
        let compact = key.to_compact();
        HYBRID_9
            .purge(&compact, PurgeType::Eviction, trace)
            .await
            .unwrap();

        // Memory empty
        assert!(HYBRID_9_MEM.lookup(&key, trace).await.unwrap().is_none());

        // Hybrid lookup should find it on disk and promote
        let (_meta, mut hit) = HYBRID_9.lookup(&key, trace).await.unwrap().unwrap();
        let body = hit.read_body().await.unwrap().unwrap();
        assert_eq!(body.as_ref(), b"evict and find");

        // Give background promotion time to complete
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Memory should now have the entry again
        let mem_result = HYBRID_9_MEM.lookup(&key, trace).await.unwrap();
        assert!(mem_result.is_some(), "entry should be re-promoted to memory");

        cleanup_disk("evict-then-hit");
    }

    // ---------- test 10: invalidation clears both ----------

    static HYBRID_10_MEM: Lazy<MemCache> = Lazy::new(MemCache::new);
    static HYBRID_10_DISK: Lazy<DiskCacheStorage> =
        Lazy::new(|| test_disk("invalidation-both"));
    static HYBRID_10: Lazy<HybridCacheStorage> =
        Lazy::new(|| HybridCacheStorage::new(&HYBRID_10_MEM, &HYBRID_10_DISK));

    #[tokio::test]
    async fn test_hybrid_invalidation_clears_both() {
        let trace = &span();
        let key = CacheKey::new("", "hybrid-invalidate", "1");
        let meta = create_test_meta();

        // Write via hybrid (goes to both tiers)
        let mut handler = HYBRID_10
            .get_miss_handler(&key, &meta, trace)
            .await
            .unwrap();
        handler
            .write_body(Bytes::from_static(b"invalidate me"), true)
            .await
            .unwrap();
        handler.finish().await.unwrap();

        // Verify both tiers have it
        assert!(HYBRID_10_MEM.lookup(&key, trace).await.unwrap().is_some());
        assert!(HYBRID_10_DISK.lookup(&key, trace).await.unwrap().is_some());

        // Invalidation purge — should remove from both tiers
        let compact = key.to_compact();
        let purged = HYBRID_10
            .purge(&compact, PurgeType::Invalidation, trace)
            .await
            .unwrap();
        assert!(purged);

        // Both tiers should be empty
        assert!(HYBRID_10_MEM.lookup(&key, trace).await.unwrap().is_none());
        assert!(HYBRID_10_DISK.lookup(&key, trace).await.unwrap().is_none());

        cleanup_disk("invalidation-both");
    }
}
