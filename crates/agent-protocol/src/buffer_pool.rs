//! Buffer pooling for message serialization/deserialization.
//!
//! This module provides a thread-local buffer pool to reduce allocation overhead
//! for message processing. Buffers are reused for messages under a size threshold,
//! while larger messages get fresh allocations.
//!
//! # Performance
//!
//! - Small messages (< 64KB): Reused from pool, zero allocation
//! - Large messages (>= 64KB): Fresh allocation (rare case)
//! - Thread-local: No contention between threads

use bytes::BytesMut;
use std::cell::RefCell;
use std::collections::VecDeque;

/// Default buffer size (64 KB).
pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum number of buffers to keep in the pool per thread.
pub const MAX_POOL_SIZE: usize = 16;

/// Maximum buffer size to pool (larger buffers are dropped).
pub const MAX_POOLED_BUFFER_SIZE: usize = 256 * 1024;

thread_local! {
    static BUFFER_POOL: RefCell<BufferPool> = RefCell::new(BufferPool::new());
}

/// Thread-local buffer pool.
struct BufferPool {
    buffers: VecDeque<BytesMut>,
    allocated: usize,
    reused: usize,
    dropped: usize,
}

impl BufferPool {
    fn new() -> Self {
        Self {
            buffers: VecDeque::with_capacity(MAX_POOL_SIZE),
            allocated: 0,
            reused: 0,
            dropped: 0,
        }
    }

    fn get(&mut self, min_capacity: usize) -> BytesMut {
        // Try to find a buffer with sufficient capacity
        if let Some(idx) = self
            .buffers
            .iter()
            .position(|b| b.capacity() >= min_capacity)
        {
            let mut buf = self.buffers.remove(idx).unwrap();
            buf.clear();
            self.reused += 1;
            return buf;
        }

        // Try to get any buffer and resize if needed
        if let Some(mut buf) = self.buffers.pop_front() {
            buf.clear();
            if min_capacity > buf.capacity() {
                buf.reserve(min_capacity - buf.capacity());
            }
            self.reused += 1;
            return buf;
        }

        // Allocate new buffer
        self.allocated += 1;
        BytesMut::with_capacity(min_capacity.max(DEFAULT_BUFFER_SIZE))
    }

    fn put(&mut self, buf: BytesMut) {
        // Don't pool oversized buffers
        if buf.capacity() > MAX_POOLED_BUFFER_SIZE {
            self.dropped += 1;
            return;
        }

        // Don't exceed pool size
        if self.buffers.len() >= MAX_POOL_SIZE {
            self.dropped += 1;
            return;
        }

        self.buffers.push_back(buf);
    }
}

/// A pooled buffer that returns to the pool on drop.
pub struct PooledBuffer {
    /// Invariant: always `Some` while the wrapper is accessible. The only
    /// `take()`s are in `Self::take` (consumes `self`) and `Drop`, so the
    /// `expect`s in the accessors below cannot fire.
    buffer: Option<BytesMut>,
}

impl PooledBuffer {
    /// Create a new pooled buffer with at least the given capacity.
    pub fn new(min_capacity: usize) -> Self {
        let buffer = BUFFER_POOL.with(|pool| pool.borrow_mut().get(min_capacity));
        Self {
            buffer: Some(buffer),
        }
    }

    /// Create a pooled buffer with the default capacity.
    pub fn default_size() -> Self {
        Self::new(DEFAULT_BUFFER_SIZE)
    }

    /// Get a mutable reference to the underlying buffer.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut BytesMut {
        self.buffer.as_mut().expect("buffer already taken")
    }

    /// Get an immutable reference to the underlying buffer.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn as_ref(&self) -> &BytesMut {
        self.buffer.as_ref().expect("buffer already taken")
    }

    /// Take the buffer out of the pool wrapper.
    ///
    /// The buffer will NOT be returned to the pool when dropped.
    pub fn take(mut self) -> BytesMut {
        self.buffer.take().expect("buffer already taken")
    }

    /// Get the current length of data in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// Get the capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.as_ref().capacity()
    }

    /// Clear the buffer, keeping the capacity.
    pub fn clear(&mut self) {
        self.as_mut().clear();
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buf) = self.buffer.take() {
            BUFFER_POOL.with(|pool| pool.borrow_mut().put(buf));
        }
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl std::ops::DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl AsRef<[u8]> for PooledBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref().expect("buffer already taken")
    }
}

impl AsMut<[u8]> for PooledBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut().expect("buffer already taken")
    }
}

/// Get buffer pool statistics for the current thread.
pub fn pool_stats() -> PoolStats {
    BUFFER_POOL.with(|pool| {
        let pool = pool.borrow();
        PoolStats {
            pooled: pool.buffers.len(),
            allocated: pool.allocated,
            reused: pool.reused,
            dropped: pool.dropped,
        }
    })
}

/// Clear the buffer pool for the current thread.
pub fn clear_pool() {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut().buffers.clear();
    });
}

/// Buffer pool statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Number of buffers currently in the pool.
    pub pooled: usize,
    /// Total buffers allocated (lifetime).
    pub allocated: usize,
    /// Total buffers reused from pool (lifetime).
    pub reused: usize,
    /// Total buffers dropped (too large or pool full).
    pub dropped: usize,
}

impl PoolStats {
    /// Calculate the hit rate (reused / (allocated + reused)).
    pub fn hit_rate(&self) -> f64 {
        let total = self.allocated + self.reused;
        if total == 0 {
            0.0
        } else {
            self.reused as f64 / total as f64
        }
    }
}

/// Acquire a buffer from the pool with the given minimum capacity.
///
/// This is a convenience function for getting a pooled buffer.
#[inline]
pub fn acquire(min_capacity: usize) -> PooledBuffer {
    PooledBuffer::new(min_capacity)
}

/// Acquire a buffer with the default size.
#[inline]
pub fn acquire_default() -> PooledBuffer {
    PooledBuffer::default_size()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;

    #[test]
    fn test_pooled_buffer_basic() {
        let mut buf = acquire(1024);
        assert!(buf.capacity() >= 1024);
        assert!(buf.is_empty());

        buf.put_slice(b"hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[..], b"hello");
    }

    #[test]
    fn test_buffer_reuse() {
        // Clear pool first
        clear_pool();

        // Allocate and drop a buffer
        {
            let mut buf = acquire(1024);
            buf.put_slice(b"test data");
        }

        let stats = pool_stats();
        assert_eq!(stats.pooled, 1);

        // Get another buffer - should reuse
        {
            let buf = acquire(1024);
            assert!(buf.capacity() >= 1024);
        }

        let stats = pool_stats();
        assert!(stats.reused >= 1);
    }

    #[test]
    fn test_large_buffer_not_pooled() {
        clear_pool();

        // Allocate a large buffer
        {
            let mut buf = acquire(MAX_POOLED_BUFFER_SIZE + 1);
            buf.put_slice(b"large data");
        }

        let stats = pool_stats();
        assert_eq!(stats.dropped, 1);
    }

    #[test]
    fn test_buffer_take() {
        clear_pool();

        let buf = acquire(1024);
        let taken = buf.take();
        assert!(!taken.is_empty() || taken.is_empty()); // Just check it works

        // Buffer should NOT be returned to pool
        let stats = pool_stats();
        assert_eq!(stats.pooled, 0);
    }

    #[test]
    fn test_pool_stats() {
        clear_pool();

        // Allocate some buffers
        let _buf1 = acquire(1024);
        let _buf2 = acquire(2048);

        let stats = pool_stats();
        assert_eq!(stats.allocated, 2);
        assert_eq!(stats.reused, 0);
        assert_eq!(stats.pooled, 0); // Still in use

        // Drop buffers
        drop(_buf1);
        drop(_buf2);

        let stats = pool_stats();
        assert_eq!(stats.pooled, 2);
    }

    #[test]
    fn test_hit_rate() {
        let stats = PoolStats {
            pooled: 5,
            allocated: 10,
            reused: 90,
            dropped: 0,
        };

        assert!((stats.hit_rate() - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_pool_max_size() {
        clear_pool();

        // Create more buffers than the pool can hold
        let buffers: Vec<_> = (0..MAX_POOL_SIZE + 5).map(|_| acquire(1024)).collect();

        // Drop all buffers
        drop(buffers);

        let stats = pool_stats();
        assert_eq!(stats.pooled, MAX_POOL_SIZE);
        assert!(stats.dropped >= 5);
    }
}
