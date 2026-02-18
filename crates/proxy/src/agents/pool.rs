//! Agent connection pooling.
//!
//! This module provides connection pooling for agent clients. Instead of serializing
//! all requests through a single connection, the pool maintains multiple connections
//! and distributes requests across them.
//!
//! # Performance
//!
//! The pool uses `parking_lot::Mutex` for fast, low-contention access. Pool operations
//! (get/return) complete in ~100-500ns, much faster than tokio's async mutex.
//!
//! # Usage
//!
//! ```ignore
//! let pool = AgentConnectionPool::new(8, 2, 4, Duration::from_secs(60));
//!
//! // Get a connection (creates new if pool empty)
//! if let Some(conn) = pool.try_get() {
//!     // Use connection...
//!     pool.return_connection(conn);
//! }
//! ```

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tracing::{debug, trace, warn};
use zentinel_agent_protocol::AgentClient;

/// Agent connection pool for efficient connection reuse.
///
/// The pool maintains a set of idle connections that can be reused across requests,
/// avoiding the overhead of creating a new connection for each request.
pub struct AgentConnectionPool {
    /// Pool configuration
    max_connections: usize,
    min_idle: usize,
    max_idle: usize,
    idle_timeout: Duration,
    /// Available connections (fast sync mutex)
    connections: Mutex<VecDeque<PooledConnection>>,
    /// Active connections count (connections currently in use)
    active_count: AtomicU32,
    /// Total connections created over lifetime
    total_created: AtomicU64,
    /// Total connections returned to pool
    total_returned: AtomicU64,
    /// Total connections acquired from pool
    total_acquired: AtomicU64,
    /// Total connections that timed out (evicted due to idle timeout)
    total_timed_out: AtomicU64,
}

/// A pooled agent connection with metadata.
pub struct PooledConnection {
    /// The actual client
    pub client: AgentClient,
    /// Creation time
    pub created_at: Instant,
    /// Last time this connection was returned to the pool
    pub last_returned: Instant,
    /// Number of times this connection has been used
    pub use_count: u64,
}

impl PooledConnection {
    /// Create a new pooled connection.
    pub fn new(client: AgentClient) -> Self {
        let now = Instant::now();
        Self {
            client,
            created_at: now,
            last_returned: now,
            use_count: 0,
        }
    }

    /// Check if this connection has exceeded the idle timeout.
    #[inline]
    pub fn is_expired(&self, idle_timeout: Duration) -> bool {
        self.last_returned.elapsed() > idle_timeout
    }
}

impl AgentConnectionPool {
    /// Create a new connection pool.
    ///
    /// # Arguments
    ///
    /// * `max_connections` - Maximum total connections (active + idle)
    /// * `min_idle` - Minimum idle connections to maintain
    /// * `max_idle` - Maximum idle connections to keep in pool
    /// * `idle_timeout` - How long an idle connection can stay in the pool
    pub fn new(
        max_connections: usize,
        min_idle: usize,
        max_idle: usize,
        idle_timeout: Duration,
    ) -> Self {
        trace!(
            max_connections = max_connections,
            min_idle = min_idle,
            max_idle = max_idle,
            idle_timeout_secs = idle_timeout.as_secs(),
            "Creating agent connection pool"
        );

        debug!(
            max_connections = max_connections,
            "Agent connection pool initialized"
        );

        Self {
            max_connections,
            min_idle,
            max_idle,
            idle_timeout,
            connections: Mutex::new(VecDeque::with_capacity(max_idle)),
            active_count: AtomicU32::new(0),
            total_created: AtomicU64::new(0),
            total_returned: AtomicU64::new(0),
            total_acquired: AtomicU64::new(0),
            total_timed_out: AtomicU64::new(0),
        }
    }

    /// Try to get a connection from the pool.
    ///
    /// Returns `Some(connection)` if an idle connection is available,
    /// `None` if the pool is empty (caller should create a new connection).
    ///
    /// # Performance
    ///
    /// This operation is O(1) and completes in ~100-500ns.
    #[inline]
    pub fn try_get(&self) -> Option<PooledConnection> {
        let mut pool = self.connections.lock();

        // Evict expired connections from the front (oldest first)
        while let Some(conn) = pool.front() {
            if conn.is_expired(self.idle_timeout) {
                pool.pop_front();
                self.total_timed_out.fetch_add(1, Ordering::Relaxed);
                trace!("Evicted expired connection from pool");
            } else {
                break;
            }
        }

        // Get the most recently returned connection (from the back)
        // This provides better cache locality and keeps connections warm
        if let Some(mut conn) = pool.pop_back() {
            self.active_count.fetch_add(1, Ordering::Relaxed);
            self.total_acquired.fetch_add(1, Ordering::Relaxed);
            conn.use_count += 1;
            trace!(
                pool_size = pool.len(),
                use_count = conn.use_count,
                "Acquired connection from pool"
            );
            return Some(conn);
        }

        None
    }

    /// Return a connection to the pool.
    ///
    /// If the pool is at capacity, the connection is dropped.
    ///
    /// # Performance
    ///
    /// This operation is O(1) and completes in ~100-500ns.
    #[inline]
    pub fn return_connection(&self, mut conn: PooledConnection) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
        conn.last_returned = Instant::now();

        let mut pool = self.connections.lock();

        // Don't exceed max_idle
        if pool.len() >= self.max_idle {
            trace!(
                pool_size = pool.len(),
                max_idle = self.max_idle,
                "Pool at capacity, dropping connection"
            );
            // Connection will be dropped here
            return;
        }

        // Add to the back (most recently used)
        pool.push_back(conn);
        self.total_returned.fetch_add(1, Ordering::Relaxed);

        trace!(pool_size = pool.len(), "Returned connection to pool");
    }

    /// Check if we can create a new connection without exceeding limits.
    ///
    /// Returns `true` if a new connection can be created.
    #[inline]
    pub fn can_create(&self) -> bool {
        let active = self.active_count.load(Ordering::Relaxed) as usize;
        let idle = self.connections.lock().len();
        active + idle < self.max_connections
    }

    /// Register that a new connection was created.
    ///
    /// Call this after successfully creating a new connection.
    #[inline]
    pub fn register_created(&self) {
        self.active_count.fetch_add(1, Ordering::Relaxed);
        self.total_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Mark a connection as failed (without returning it to pool).
    ///
    /// Call this when a connection fails and should not be reused.
    #[inline]
    pub fn mark_failed(&self) {
        self.active_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get active connection count (connections currently in use).
    #[inline]
    pub fn active_count(&self) -> u32 {
        self.active_count.load(Ordering::Relaxed)
    }

    /// Get idle connection count (connections waiting in pool).
    #[inline]
    pub fn idle_count(&self) -> usize {
        self.connections.lock().len()
    }

    /// Get total connections created over lifetime.
    #[inline]
    pub fn total_created(&self) -> u64 {
        self.total_created.load(Ordering::Relaxed)
    }

    /// Get total connections acquired from pool.
    #[inline]
    pub fn total_acquired(&self) -> u64 {
        self.total_acquired.load(Ordering::Relaxed)
    }

    /// Get total connections returned to pool.
    #[inline]
    pub fn total_returned(&self) -> u64 {
        self.total_returned.load(Ordering::Relaxed)
    }

    /// Get pool statistics.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            active: self.active_count.load(Ordering::Relaxed),
            idle: self.connections.lock().len() as u32,
            total_created: self.total_created.load(Ordering::Relaxed),
            total_acquired: self.total_acquired.load(Ordering::Relaxed),
            total_returned: self.total_returned.load(Ordering::Relaxed),
            total_timed_out: self.total_timed_out.load(Ordering::Relaxed),
            max_connections: self.max_connections as u32,
            max_idle: self.max_idle as u32,
        }
    }

    /// Evict all idle connections from the pool.
    ///
    /// Useful for graceful shutdown or when the agent configuration changes.
    pub fn clear(&self) {
        let mut pool = self.connections.lock();
        let count = pool.len();
        pool.clear();
        debug!(evicted = count, "Cleared all connections from pool");
    }

    /// Evict expired connections from the pool.
    ///
    /// Call this periodically to clean up stale connections.
    pub fn evict_expired(&self) -> usize {
        let mut pool = self.connections.lock();
        let before = pool.len();

        pool.retain(|conn| !conn.is_expired(self.idle_timeout));

        let evicted = before - pool.len();
        if evicted > 0 {
            self.total_timed_out
                .fetch_add(evicted as u64, Ordering::Relaxed);
            debug!(evicted = evicted, "Evicted expired connections");
        }
        evicted
    }
}

/// Pool statistics for monitoring.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Currently active connections (in use)
    pub active: u32,
    /// Currently idle connections (in pool)
    pub idle: u32,
    /// Total connections created over lifetime
    pub total_created: u64,
    /// Total connections acquired from pool
    pub total_acquired: u64,
    /// Total connections returned to pool
    pub total_returned: u64,
    /// Total connections evicted due to timeout
    pub total_timed_out: u64,
    /// Maximum allowed connections
    pub max_connections: u32,
    /// Maximum idle connections to keep
    pub max_idle: u32,
}

impl PoolStats {
    /// Calculate pool hit rate (connections reused vs created).
    pub fn hit_rate(&self) -> f64 {
        if self.total_acquired == 0 {
            return 0.0;
        }
        self.total_acquired as f64 / (self.total_acquired + self.total_created) as f64
    }

    /// Calculate utilization (active / max).
    pub fn utilization(&self) -> f64 {
        if self.max_connections == 0 {
            return 0.0;
        }
        self.active as f64 / self.max_connections as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock client for testing
    fn mock_client() -> AgentClient {
        // We can't easily create a real AgentClient in tests, so we'll test
        // the pool logic with the actual pool operations
        unimplemented!("Tests require integration setup")
    }

    #[test]
    fn test_pool_creation() {
        let pool = AgentConnectionPool::new(8, 2, 4, Duration::from_secs(60));
        assert_eq!(pool.active_count(), 0);
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.total_created(), 0);
    }

    #[test]
    fn test_pool_can_create() {
        let pool = AgentConnectionPool::new(2, 0, 2, Duration::from_secs(60));
        assert!(pool.can_create());

        // Simulate creating connections
        pool.register_created();
        assert!(pool.can_create());

        pool.register_created();
        assert!(!pool.can_create()); // At max
    }

    #[test]
    fn test_pool_stats() {
        let pool = AgentConnectionPool::new(8, 2, 4, Duration::from_secs(60));
        let stats = pool.stats();
        assert_eq!(stats.active, 0);
        assert_eq!(stats.idle, 0);
        assert_eq!(stats.max_connections, 8);
        assert_eq!(stats.max_idle, 4);
    }

    #[test]
    fn test_try_get_empty_pool() {
        let pool = AgentConnectionPool::new(8, 2, 4, Duration::from_secs(60));
        assert!(pool.try_get().is_none());
    }

    #[test]
    fn test_hit_rate() {
        let stats = PoolStats {
            active: 2,
            idle: 3,
            total_created: 10,
            total_acquired: 90,
            total_returned: 88,
            total_timed_out: 2,
            max_connections: 20,
            max_idle: 10,
        };

        // 90 acquired from pool, 10 created = 90% hit rate
        assert!((stats.hit_rate() - 0.9).abs() < 0.01);

        // 2 active out of 20 max = 10% utilization
        assert!((stats.utilization() - 0.1).abs() < 0.01);
    }
}
