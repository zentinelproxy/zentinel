//! Limits and rate limiting for Sentinel proxy
//!
//! This module implements bounded limits for all resources to ensure predictable
//! behavior and prevent resource exhaustion - core to "sleepable ops".

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

use crate::errors::{LimitType, SentinelError, SentinelResult};

/// System-wide limits configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    // Header limits
    pub max_header_size_bytes: usize,
    pub max_header_count: usize,
    pub max_header_name_bytes: usize,
    pub max_header_value_bytes: usize,

    // Body limits
    pub max_body_size_bytes: usize,
    pub max_body_buffer_bytes: usize,
    pub max_body_inspection_bytes: usize,

    // Decompression limits
    pub max_decompression_ratio: f32,
    pub max_decompressed_size_bytes: usize,

    // Connection limits
    pub max_connections_per_client: usize,
    pub max_connections_per_route: usize,
    pub max_total_connections: usize,
    pub max_idle_connections_per_upstream: usize,

    // Request limits
    pub max_in_flight_requests: usize,
    pub max_in_flight_requests_per_worker: usize,
    pub max_queued_requests: usize,

    // Agent limits
    pub max_agent_queue_depth: usize,
    pub max_agent_body_bytes: usize,
    pub max_agent_response_bytes: usize,

    // Rate limits
    pub max_requests_per_second_global: Option<u32>,
    pub max_requests_per_second_per_client: Option<u32>,
    pub max_requests_per_second_per_route: Option<u32>,

    // Memory limits
    pub max_memory_bytes: Option<usize>,
    pub max_memory_percent: Option<f32>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            // Conservative header limits
            max_header_size_bytes: 8192,  // 8KB total headers
            max_header_count: 100,        // Max 100 headers
            max_header_name_bytes: 256,   // 256 bytes per header name
            max_header_value_bytes: 4096, // 4KB per header value

            // Body limits - 10MB default, 1MB buffer
            max_body_size_bytes: 10 * 1024 * 1024,
            max_body_buffer_bytes: 1024 * 1024,
            max_body_inspection_bytes: 1024 * 1024,

            // Decompression protection
            max_decompression_ratio: 100.0,
            max_decompressed_size_bytes: 100 * 1024 * 1024, // 100MB

            // Connection limits
            max_connections_per_client: 100,
            max_connections_per_route: 1000,
            max_total_connections: 10000,
            max_idle_connections_per_upstream: 100,

            // Request concurrency
            max_in_flight_requests: 10000,
            max_in_flight_requests_per_worker: 1000,
            max_queued_requests: 1000,

            // Agent communication
            max_agent_queue_depth: 100,
            max_agent_body_bytes: 1024 * 1024,   // 1MB to agents
            max_agent_response_bytes: 10 * 1024, // 10KB from agents

            // Rate limits (optional by default)
            max_requests_per_second_global: None,
            max_requests_per_second_per_client: None,
            max_requests_per_second_per_route: None,

            // Memory limits (optional by default)
            max_memory_bytes: None,
            max_memory_percent: None,
        }
    }
}

impl Limits {
    /// Create limits suitable for testing (more permissive)
    pub fn for_testing() -> Self {
        Self {
            max_header_size_bytes: 16384,
            max_header_count: 200,
            max_body_size_bytes: 100 * 1024 * 1024, // 100MB
            max_in_flight_requests: 100000,
            ..Default::default()
        }
    }

    /// Create limits suitable for production (more restrictive)
    pub fn for_production() -> Self {
        Self {
            max_header_size_bytes: 4096,
            max_header_count: 50,
            max_body_size_bytes: 1024 * 1024, // 1MB
            max_in_flight_requests: 5000,
            max_requests_per_second_global: Some(10000),
            max_requests_per_second_per_client: Some(100),
            max_memory_percent: Some(80.0),
            ..Default::default()
        }
    }

    /// Validate the limits configuration
    pub fn validate(&self) -> SentinelResult<()> {
        if self.max_header_size_bytes == 0 {
            return Err(SentinelError::Config {
                message: "max_header_size_bytes must be greater than 0".to_string(),
                source: None,
            });
        }

        if self.max_header_count == 0 {
            return Err(SentinelError::Config {
                message: "max_header_count must be greater than 0".to_string(),
                source: None,
            });
        }

        if self.max_body_buffer_bytes > self.max_body_size_bytes {
            return Err(SentinelError::Config {
                message: "max_body_buffer_bytes cannot exceed max_body_size_bytes".to_string(),
                source: None,
            });
        }

        if self.max_decompression_ratio <= 0.0 {
            return Err(SentinelError::Config {
                message: "max_decompression_ratio must be positive".to_string(),
                source: None,
            });
        }

        if let Some(pct) = self.max_memory_percent {
            if pct <= 0.0 || pct > 100.0 {
                return Err(SentinelError::Config {
                    message: "max_memory_percent must be between 0 and 100".to_string(),
                    source: None,
                });
            }
        }

        Ok(())
    }

    /// Check if a header size exceeds limits
    pub fn check_header_size(&self, size: usize) -> SentinelResult<()> {
        if size > self.max_header_size_bytes {
            return Err(SentinelError::limit_exceeded(
                LimitType::HeaderSize,
                size,
                self.max_header_size_bytes,
            ));
        }
        Ok(())
    }

    /// Check if header count exceeds limits
    pub fn check_header_count(&self, count: usize) -> SentinelResult<()> {
        if count > self.max_header_count {
            return Err(SentinelError::limit_exceeded(
                LimitType::HeaderCount,
                count,
                self.max_header_count,
            ));
        }
        Ok(())
    }

    /// Check if body size exceeds limits
    pub fn check_body_size(&self, size: usize) -> SentinelResult<()> {
        if size > self.max_body_size_bytes {
            return Err(SentinelError::limit_exceeded(
                LimitType::BodySize,
                size,
                self.max_body_size_bytes,
            ));
        }
        Ok(())
    }
}

/// Token bucket rate limiter implementation
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u32,
    tokens: Arc<RwLock<f64>>,
    refill_rate: f64,
    last_refill: Arc<RwLock<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter with specified capacity and refill rate
    pub fn new(capacity: u32, refill_per_second: u32) -> Self {
        trace!(
            capacity = capacity,
            refill_per_second = refill_per_second,
            "Creating rate limiter"
        );
        Self {
            capacity,
            tokens: Arc::new(RwLock::new(capacity as f64)),
            refill_rate: refill_per_second as f64,
            last_refill: Arc::new(RwLock::new(Instant::now())),
        }
    }

    /// Try to acquire tokens, returns true if successful
    pub fn try_acquire(&self, tokens: u32) -> bool {
        self.refill();

        let mut available_tokens = self.tokens.write();
        if *available_tokens >= tokens as f64 {
            *available_tokens -= tokens as f64;
            trace!(
                tokens_requested = tokens,
                tokens_remaining = *available_tokens as u32,
                "Rate limiter: tokens acquired"
            );
            true
        } else {
            trace!(
                tokens_requested = tokens,
                tokens_available = *available_tokens as u32,
                "Rate limiter: insufficient tokens"
            );
            false
        }
    }

    /// Check if tokens are available without consuming
    pub fn check(&self, tokens: u32) -> bool {
        self.refill();
        let available_tokens = self.tokens.read();
        *available_tokens >= tokens as f64
    }

    /// Get current available tokens
    pub fn available(&self) -> u32 {
        self.refill();
        let tokens = self.tokens.read();
        *tokens as u32
    }

    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let now = Instant::now();
        let mut last_refill = self.last_refill.write();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();

        if elapsed > 0.0 {
            let mut tokens = self.tokens.write();
            let tokens_to_add = elapsed * self.refill_rate;
            *tokens = (*tokens + tokens_to_add).min(self.capacity as f64);
            *last_refill = now;
        }
    }

    /// Reset the rate limiter to full capacity
    pub fn reset(&self) {
        let mut tokens = self.tokens.write();
        *tokens = self.capacity as f64;
        let mut last_refill = self.last_refill.write();
        *last_refill = Instant::now();
    }

    /// Get the time of last activity (used for cleanup of idle limiters)
    pub fn last_accessed(&self) -> Instant {
        *self.last_refill.read()
    }
}

/// Multi-level rate limiter for different scopes
pub struct MultiRateLimiter {
    global: Option<RateLimiter>,
    per_client: Arc<RwLock<HashMap<String, RateLimiter>>>,
    per_route: Arc<RwLock<HashMap<String, RateLimiter>>>,
    client_limit: Option<(u32, u32)>, // (capacity, refill_per_second)
    route_limit: Option<(u32, u32)>,  // (capacity, refill_per_second)
}

impl MultiRateLimiter {
    /// Create a new multi-level rate limiter
    pub fn new(limits: &Limits) -> Self {
        let global = limits
            .max_requests_per_second_global
            .map(|rps| RateLimiter::new(rps * 10, rps)); // 10 second burst

        let client_limit = limits
            .max_requests_per_second_per_client
            .map(|rps| (rps * 10, rps));

        let route_limit = limits
            .max_requests_per_second_per_route
            .map(|rps| (rps * 10, rps));

        Self {
            global,
            per_client: Arc::new(RwLock::new(HashMap::new())),
            per_route: Arc::new(RwLock::new(HashMap::new())),
            client_limit,
            route_limit,
        }
    }

    /// Check if request is allowed for client and route
    pub fn check_request(&self, client_id: &str, route: &str) -> SentinelResult<()> {
        trace!(
            client_id = %client_id,
            route = %route,
            "Checking rate limits"
        );

        // Check global rate limit
        if let Some(ref limiter) = self.global {
            if !limiter.try_acquire(1) {
                warn!(
                    client_id = %client_id,
                    route = %route,
                    "Global rate limit exceeded"
                );
                return Err(SentinelError::RateLimit {
                    message: "Global rate limit exceeded".to_string(),
                    limit: limiter.capacity,
                    window_seconds: 10,
                    retry_after_seconds: Some(1),
                });
            }
        }

        // Check per-client rate limit
        if let Some((capacity, refill)) = self.client_limit {
            let mut limiters = self.per_client.write();
            let limiter = limiters
                .entry(client_id.to_string())
                .or_insert_with(|| RateLimiter::new(capacity, refill));

            if !limiter.try_acquire(1) {
                warn!(
                    client_id = %client_id,
                    route = %route,
                    "Per-client rate limit exceeded"
                );
                return Err(SentinelError::RateLimit {
                    message: format!("Rate limit exceeded for client {}", client_id),
                    limit: capacity,
                    window_seconds: 10,
                    retry_after_seconds: Some(1),
                });
            }
        }

        // Check per-route rate limit
        if let Some((capacity, refill)) = self.route_limit {
            let mut limiters = self.per_route.write();
            let limiter = limiters
                .entry(route.to_string())
                .or_insert_with(|| RateLimiter::new(capacity, refill));

            if !limiter.try_acquire(1) {
                warn!(
                    client_id = %client_id,
                    route = %route,
                    "Per-route rate limit exceeded"
                );
                return Err(SentinelError::RateLimit {
                    message: format!("Rate limit exceeded for route {}", route),
                    limit: capacity,
                    window_seconds: 10,
                    retry_after_seconds: Some(1),
                });
            }
        }

        trace!(
            client_id = %client_id,
            route = %route,
            "Rate limits check passed"
        );
        Ok(())
    }

    /// Clean up old rate limiters that haven't been used recently
    ///
    /// Returns the number of entries removed (clients, routes).
    pub fn cleanup(&self, max_age: Duration) -> (usize, usize) {
        let now = Instant::now();

        // Clean up per-client limiters
        let clients_before = self.per_client.read().len();
        self.per_client.write().retain(|client_id, limiter| {
            let age = now.duration_since(limiter.last_accessed());
            let keep = age < max_age;
            if !keep {
                trace!(
                    client_id = %client_id,
                    age_secs = age.as_secs(),
                    "Removing idle client rate limiter"
                );
            }
            keep
        });
        let clients_removed = clients_before - self.per_client.read().len();

        // Clean up per-route limiters
        let routes_before = self.per_route.read().len();
        self.per_route.write().retain(|route, limiter| {
            let age = now.duration_since(limiter.last_accessed());
            let keep = age < max_age;
            if !keep {
                trace!(
                    route = %route,
                    age_secs = age.as_secs(),
                    "Removing idle route rate limiter"
                );
            }
            keep
        });
        let routes_removed = routes_before - self.per_route.read().len();

        if clients_removed > 0 || routes_removed > 0 {
            debug!(
                clients_removed = clients_removed,
                routes_removed = routes_removed,
                clients_remaining = self.per_client.read().len(),
                routes_remaining = self.per_route.read().len(),
                "Rate limiter cleanup completed"
            );
        }

        (clients_removed, routes_removed)
    }

    /// Get the current number of tracked clients and routes
    pub fn entry_counts(&self) -> (usize, usize) {
        (self.per_client.read().len(), self.per_route.read().len())
    }
}

/// Connection limiter for managing concurrent connections
pub struct ConnectionLimiter {
    per_client: Arc<RwLock<HashMap<String, usize>>>,
    per_route: Arc<RwLock<HashMap<String, usize>>>,
    total: Arc<RwLock<usize>>,
    limits: Limits,
}

impl ConnectionLimiter {
    pub fn new(limits: Limits) -> Self {
        debug!(
            max_total = limits.max_total_connections,
            max_per_client = limits.max_connections_per_client,
            max_per_route = limits.max_connections_per_route,
            "Creating connection limiter"
        );
        Self {
            per_client: Arc::new(RwLock::new(HashMap::new())),
            per_route: Arc::new(RwLock::new(HashMap::new())),
            total: Arc::new(RwLock::new(0)),
            limits,
        }
    }

    /// Try to acquire a connection slot
    pub fn try_acquire(&self, client_id: &str, route: &str) -> SentinelResult<ConnectionGuard<'_>> {
        trace!(
            client_id = %client_id,
            route = %route,
            "Attempting to acquire connection slot"
        );

        // Check total connections
        {
            let mut total = self.total.write();
            if *total >= self.limits.max_total_connections {
                warn!(
                    current = *total,
                    max = self.limits.max_total_connections,
                    "Total connection limit exceeded"
                );
                return Err(SentinelError::limit_exceeded(
                    LimitType::ConnectionCount,
                    *total,
                    self.limits.max_total_connections,
                ));
            }
            *total += 1;
        }

        // Check per-client connections
        {
            let mut per_client = self.per_client.write();
            let client_count = per_client.entry(client_id.to_string()).or_insert(0);
            if *client_count >= self.limits.max_connections_per_client {
                // Rollback total count
                *self.total.write() -= 1;
                warn!(
                    client_id = %client_id,
                    current = *client_count,
                    max = self.limits.max_connections_per_client,
                    "Per-client connection limit exceeded"
                );
                return Err(SentinelError::limit_exceeded(
                    LimitType::ConnectionCount,
                    *client_count,
                    self.limits.max_connections_per_client,
                ));
            }
            *client_count += 1;
        }

        // Check per-route connections
        {
            let mut per_route = self.per_route.write();
            let route_count = per_route.entry(route.to_string()).or_insert(0);
            if *route_count >= self.limits.max_connections_per_route {
                // Rollback counts
                *self.total.write() -= 1;
                *self.per_client.write().get_mut(client_id).unwrap() -= 1;
                warn!(
                    route = %route,
                    current = *route_count,
                    max = self.limits.max_connections_per_route,
                    "Per-route connection limit exceeded"
                );
                return Err(SentinelError::limit_exceeded(
                    LimitType::ConnectionCount,
                    *route_count,
                    self.limits.max_connections_per_route,
                ));
            }
            *route_count += 1;
        }

        trace!(
            client_id = %client_id,
            route = %route,
            "Connection slot acquired"
        );

        Ok(ConnectionGuard {
            limiter: self,
            client_id: client_id.to_string(),
            route: route.to_string(),
        })
    }

    /// Release a connection slot
    fn release(&self, client_id: &str, route: &str) {
        trace!(
            client_id = %client_id,
            route = %route,
            "Releasing connection slot"
        );

        *self.total.write() -= 1;

        if let Some(count) = self.per_client.write().get_mut(client_id) {
            *count = count.saturating_sub(1);
        }

        if let Some(count) = self.per_route.write().get_mut(route) {
            *count = count.saturating_sub(1);
        }
    }

    /// Get current connection statistics
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            total: *self.total.read(),
            per_client_count: self.per_client.read().len(),
            per_route_count: self.per_route.read().len(),
        }
    }
}

/// RAII guard for connection slots
pub struct ConnectionGuard<'a> {
    limiter: &'a ConnectionLimiter,
    client_id: String,
    route: String,
}

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.limiter.release(&self.client_id, &self.route);
    }
}

/// Connection statistics
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionStats {
    pub total: usize,
    pub per_client_count: usize,
    pub per_route_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_limits_validation() {
        let mut limits = Limits::default();
        assert!(limits.validate().is_ok());

        limits.max_header_size_bytes = 0;
        assert!(limits.validate().is_err());

        limits = Limits::default();
        limits.max_body_buffer_bytes = limits.max_body_size_bytes + 1;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 10);

        // Should allow initial burst
        for _ in 0..10 {
            assert!(limiter.try_acquire(1));
        }

        // Should be exhausted
        assert!(!limiter.try_acquire(1));

        // Wait for refill
        thread::sleep(Duration::from_millis(200));

        // Should have some tokens refilled (approximately 2)
        assert!(limiter.try_acquire(1));
        assert!(limiter.available() > 0);
    }

    #[test]
    fn test_connection_limiter() {
        let limits = Limits {
            max_total_connections: 100,
            max_connections_per_client: 10,
            max_connections_per_route: 50,
            ..Default::default()
        };

        let limiter = ConnectionLimiter::new(limits);

        // Acquire connections
        let _guard1 = limiter.try_acquire("client1", "route1").unwrap();
        let _guard2 = limiter.try_acquire("client1", "route1").unwrap();

        let stats = limiter.stats();
        assert_eq!(stats.total, 2);

        // Guards will release on drop
    }

    #[test]
    fn test_rate_limiter_last_accessed() {
        let limiter = RateLimiter::new(10, 10);
        let before = Instant::now();

        // Access the limiter
        limiter.try_acquire(1);

        let last_accessed = limiter.last_accessed();
        assert!(last_accessed >= before);
        assert!(last_accessed <= Instant::now());
    }

    #[test]
    fn test_multi_rate_limiter_entry_counts() {
        let limits = Limits {
            max_requests_per_second_per_client: Some(100),
            max_requests_per_second_per_route: Some(1000),
            ..Default::default()
        };

        let limiter = MultiRateLimiter::new(&limits);

        // Initially empty
        assert_eq!(limiter.entry_counts(), (0, 0));

        // Make requests from different clients/routes
        let _ = limiter.check_request("client1", "route1");
        let _ = limiter.check_request("client2", "route1");
        let _ = limiter.check_request("client1", "route2");

        // Should have 2 clients and 2 routes
        assert_eq!(limiter.entry_counts(), (2, 2));
    }

    #[test]
    fn test_multi_rate_limiter_cleanup() {
        let limits = Limits {
            max_requests_per_second_per_client: Some(100),
            max_requests_per_second_per_route: Some(1000),
            ..Default::default()
        };

        let limiter = MultiRateLimiter::new(&limits);

        // Make requests to create entries
        let _ = limiter.check_request("client1", "route1");
        let _ = limiter.check_request("client2", "route2");

        assert_eq!(limiter.entry_counts(), (2, 2));

        // Cleanup with very long max_age should remove nothing
        let (clients_removed, routes_removed) = limiter.cleanup(Duration::from_secs(3600));
        assert_eq!(clients_removed, 0);
        assert_eq!(routes_removed, 0);
        assert_eq!(limiter.entry_counts(), (2, 2));

        // Wait a bit
        thread::sleep(Duration::from_millis(50));

        // Cleanup with very short max_age should remove all
        let (clients_removed, routes_removed) = limiter.cleanup(Duration::from_millis(10));
        assert_eq!(clients_removed, 2);
        assert_eq!(routes_removed, 2);
        assert_eq!(limiter.entry_counts(), (0, 0));
    }

    #[test]
    fn test_multi_rate_limiter_cleanup_partial() {
        let limits = Limits {
            max_requests_per_second_per_client: Some(100),
            max_requests_per_second_per_route: Some(1000),
            ..Default::default()
        };

        let limiter = MultiRateLimiter::new(&limits);

        // Create old entry
        let _ = limiter.check_request("old_client", "old_route");

        // Wait
        thread::sleep(Duration::from_millis(60));

        // Create new entry
        let _ = limiter.check_request("new_client", "new_route");

        assert_eq!(limiter.entry_counts(), (2, 2));

        // Cleanup with age that only removes old entries
        let (clients_removed, routes_removed) = limiter.cleanup(Duration::from_millis(30));
        assert_eq!(clients_removed, 1);
        assert_eq!(routes_removed, 1);
        assert_eq!(limiter.entry_counts(), (1, 1));

        // Verify the new entries remain
        // (they were accessed recently so should still exist)
    }
}
