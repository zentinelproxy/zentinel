//! Rate limiting using pingora-limits
//!
//! This module provides efficient per-route, per-client rate limiting using
//! Pingora's optimized rate limiting primitives. Supports both local (single-instance)
//! and distributed (Redis-backed) rate limiting.
//!
//! # Local Rate Limiting
//!
//! Uses `pingora-limits::Rate` for efficient in-memory rate limiting.
//! Suitable for single-instance deployments.
//!
//! # Distributed Rate Limiting
//!
//! Uses Redis sorted sets for sliding window rate limiting across multiple instances.
//! Requires the `distributed-rate-limit` feature.

use dashmap::DashMap;
use parking_lot::RwLock;
use pingora_limits::rate::Rate;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace, warn};

use sentinel_config::{RateLimitAction, RateLimitBackend, RateLimitKey};

#[cfg(feature = "distributed-rate-limit")]
use crate::distributed_rate_limit::{create_redis_rate_limiter, RedisRateLimiter};

/// Rate limiter outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitOutcome {
    /// Request is allowed
    Allowed,
    /// Request is rate limited
    Limited,
}

/// Rate limiter configuration
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per second
    pub max_rps: u32,
    /// Burst size
    pub burst: u32,
    /// Key type for bucketing
    pub key: RateLimitKey,
    /// Action when limited
    pub action: RateLimitAction,
    /// HTTP status code to return when limited
    pub status_code: u16,
    /// Custom message
    pub message: Option<String>,
    /// Backend for rate limiting (local or distributed)
    pub backend: RateLimitBackend,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_rps: 100,
            burst: 10,
            key: RateLimitKey::ClientIp,
            action: RateLimitAction::Reject,
            status_code: 429,
            message: None,
            backend: RateLimitBackend::Local,
        }
    }
}

/// Per-key rate limiter using pingora-limits Rate
///
/// Uses a sliding window algorithm with 1-second granularity.
struct KeyRateLimiter {
    /// The rate limiter instance (tracks requests in current window)
    rate: Rate,
    /// Maximum requests per window
    max_requests: isize,
}

impl KeyRateLimiter {
    fn new(max_rps: u32) -> Self {
        Self {
            rate: Rate::new(Duration::from_secs(1)),
            max_requests: max_rps as isize,
        }
    }

    /// Check if a request should be allowed
    fn check(&self) -> RateLimitOutcome {
        // Rate::observe() returns the current count and whether it was a new window
        let curr_count = self.rate.observe(&(), 1);

        if curr_count > self.max_requests {
            RateLimitOutcome::Limited
        } else {
            RateLimitOutcome::Allowed
        }
    }
}

/// Backend type for rate limiting
pub enum RateLimitBackendType {
    /// Local in-memory backend
    Local {
        /// Rate limiters by key (e.g., client IP -> limiter)
        limiters: DashMap<String, Arc<KeyRateLimiter>>,
    },
    /// Distributed Redis backend
    #[cfg(feature = "distributed-rate-limit")]
    Distributed {
        /// Redis rate limiter
        redis: Arc<RedisRateLimiter>,
        /// Local fallback
        local_fallback: DashMap<String, Arc<KeyRateLimiter>>,
    },
}

/// Thread-safe rate limiter pool managing multiple rate limiters by key
pub struct RateLimiterPool {
    /// Backend for rate limiting
    backend: RateLimitBackendType,
    /// Configuration
    config: RwLock<RateLimitConfig>,
}

impl RateLimiterPool {
    /// Create a new rate limiter pool with the given configuration (local backend)
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            backend: RateLimitBackendType::Local {
                limiters: DashMap::new(),
            },
            config: RwLock::new(config),
        }
    }

    /// Create a new rate limiter pool with a distributed Redis backend
    #[cfg(feature = "distributed-rate-limit")]
    pub fn with_redis(config: RateLimitConfig, redis: Arc<RedisRateLimiter>) -> Self {
        Self {
            backend: RateLimitBackendType::Distributed {
                redis,
                local_fallback: DashMap::new(),
            },
            config: RwLock::new(config),
        }
    }

    /// Check if a request should be rate limited (synchronous, local only)
    ///
    /// Returns the outcome and the current request count.
    /// For distributed backends, this falls back to local limiting.
    pub fn check(&self, key: &str) -> (RateLimitOutcome, isize) {
        let config = self.config.read();
        let max_rps = config.max_rps;
        drop(config);

        let limiters = match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters,
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback,
        };

        // Get or create limiter for this key
        let limiter = limiters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(KeyRateLimiter::new(max_rps)))
            .clone();

        let outcome = limiter.check();
        let count = limiter.rate.observe(&(), 0); // Get current count without incrementing

        (outcome, count)
    }

    /// Check if a request should be rate limited (async, supports distributed backends)
    ///
    /// Returns the outcome and the current request count.
    #[cfg(feature = "distributed-rate-limit")]
    pub async fn check_async(&self, key: &str) -> (RateLimitOutcome, i64) {
        match &self.backend {
            RateLimitBackendType::Local { .. } => {
                let (outcome, count) = self.check(key);
                (outcome, count as i64)
            }
            RateLimitBackendType::Distributed {
                redis,
                local_fallback,
            } => {
                // Try Redis first
                match redis.check(key).await {
                    Ok((outcome, count)) => (outcome, count),
                    Err(e) => {
                        warn!(
                            error = %e,
                            key = key,
                            "Redis rate limit check failed, falling back to local"
                        );
                        redis.mark_unhealthy();

                        // Fallback to local
                        if redis.fallback_enabled() {
                            let config = self.config.read();
                            let max_rps = config.max_rps;
                            drop(config);

                            let limiter = local_fallback
                                .entry(key.to_string())
                                .or_insert_with(|| Arc::new(KeyRateLimiter::new(max_rps)))
                                .clone();

                            let outcome = limiter.check();
                            let count = limiter.rate.observe(&(), 0);
                            (outcome, count as i64)
                        } else {
                            // Fail open if no fallback
                            (RateLimitOutcome::Allowed, 0)
                        }
                    }
                }
            }
        }
    }

    /// Check if this pool uses a distributed backend
    pub fn is_distributed(&self) -> bool {
        match &self.backend {
            RateLimitBackendType::Local { .. } => false,
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { .. } => true,
        }
    }

    /// Get the rate limit key from request context
    pub fn extract_key(
        &self,
        client_ip: &str,
        path: &str,
        route_id: &str,
        headers: Option<&impl HeaderAccessor>,
    ) -> String {
        let config = self.config.read();
        match &config.key {
            RateLimitKey::ClientIp => client_ip.to_string(),
            RateLimitKey::Path => path.to_string(),
            RateLimitKey::Route => route_id.to_string(),
            RateLimitKey::ClientIpAndPath => format!("{}:{}", client_ip, path),
            RateLimitKey::Header(header_name) => headers
                .and_then(|h| h.get_header(header_name))
                .unwrap_or_else(|| "unknown".to_string()),
        }
    }

    /// Get the action to take when rate limited
    pub fn action(&self) -> RateLimitAction {
        self.config.read().action.clone()
    }

    /// Get the HTTP status code for rate limit responses
    pub fn status_code(&self) -> u16 {
        self.config.read().status_code
    }

    /// Get the custom message for rate limit responses
    pub fn message(&self) -> Option<String> {
        self.config.read().message.clone()
    }

    /// Update the configuration
    pub fn update_config(&self, config: RateLimitConfig) {
        *self.config.write() = config;
        // Clear existing limiters so they get recreated with new config
        self.clear_local_limiters();
    }

    /// Clear local limiters (for config updates)
    fn clear_local_limiters(&self) {
        match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters.clear(),
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback.clear(),
        }
    }

    /// Get the number of local limiter entries
    fn local_limiter_count(&self) -> usize {
        match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters.len(),
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback.len(),
        }
    }

    /// Clean up expired entries (call periodically)
    pub fn cleanup(&self) {
        // Remove entries that haven't been accessed recently
        // In practice, Rate handles its own window cleanup, so this is mainly
        // for memory management when many unique keys are seen
        let max_entries = 100_000; // Prevent unbounded growth

        let limiters = match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters,
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback,
        };

        if limiters.len() > max_entries {
            // Simple eviction: clear half
            let to_remove: Vec<_> = limiters
                .iter()
                .take(max_entries / 2)
                .map(|e| e.key().clone())
                .collect();

            for key in to_remove {
                limiters.remove(&key);
            }

            debug!(
                entries_before = max_entries,
                entries_after = limiters.len(),
                "Rate limiter pool cleanup completed"
            );
        }
    }
}

/// Trait for accessing headers (allows abstracting over different header types)
pub trait HeaderAccessor {
    fn get_header(&self, name: &str) -> Option<String>;
}

/// Route-level rate limiter manager
pub struct RateLimitManager {
    /// Per-route rate limiter pools
    route_limiters: DashMap<String, Arc<RateLimiterPool>>,
    /// Global rate limiter (optional)
    global_limiter: Option<Arc<RateLimiterPool>>,
}

impl RateLimitManager {
    /// Create a new rate limit manager
    pub fn new() -> Self {
        Self {
            route_limiters: DashMap::new(),
            global_limiter: None,
        }
    }

    /// Create a new rate limit manager with a global rate limit
    pub fn with_global_limit(max_rps: u32, burst: u32) -> Self {
        let config = RateLimitConfig {
            max_rps,
            burst,
            key: RateLimitKey::ClientIp,
            action: RateLimitAction::Reject,
            status_code: 429,
            message: None,
            backend: RateLimitBackend::Local,
        };
        Self {
            route_limiters: DashMap::new(),
            global_limiter: Some(Arc::new(RateLimiterPool::new(config))),
        }
    }

    /// Register a rate limiter for a route
    pub fn register_route(&self, route_id: &str, config: RateLimitConfig) {
        trace!(
            route_id = route_id,
            max_rps = config.max_rps,
            burst = config.burst,
            key = ?config.key,
            "Registering rate limiter for route"
        );

        self.route_limiters
            .insert(route_id.to_string(), Arc::new(RateLimiterPool::new(config)));
    }

    /// Check if a request should be rate limited
    ///
    /// Checks both global and route-specific limits.
    pub fn check(
        &self,
        route_id: &str,
        client_ip: &str,
        path: &str,
        headers: Option<&impl HeaderAccessor>,
    ) -> RateLimitResult {
        // Check global limit first
        if let Some(ref global) = self.global_limiter {
            let key = global.extract_key(client_ip, path, route_id, headers);
            let (outcome, count) = global.check(&key);

            if outcome == RateLimitOutcome::Limited {
                warn!(
                    route_id = route_id,
                    client_ip = client_ip,
                    key = key,
                    count = count,
                    "Request rate limited by global limiter"
                );
                return RateLimitResult {
                    allowed: false,
                    action: global.action(),
                    status_code: global.status_code(),
                    message: global.message(),
                    limiter: "global".to_string(),
                };
            }
        }

        // Check route-specific limit
        if let Some(pool) = self.route_limiters.get(route_id) {
            let key = pool.extract_key(client_ip, path, route_id, headers);
            let (outcome, count) = pool.check(&key);

            if outcome == RateLimitOutcome::Limited {
                warn!(
                    route_id = route_id,
                    client_ip = client_ip,
                    key = key,
                    count = count,
                    "Request rate limited by route limiter"
                );
                return RateLimitResult {
                    allowed: false,
                    action: pool.action(),
                    status_code: pool.status_code(),
                    message: pool.message(),
                    limiter: route_id.to_string(),
                };
            }

            trace!(
                route_id = route_id,
                key = key,
                count = count,
                "Request allowed by rate limiter"
            );
        }

        RateLimitResult {
            allowed: true,
            action: RateLimitAction::Reject,
            status_code: 429,
            message: None,
            limiter: String::new(),
        }
    }

    /// Perform periodic cleanup
    pub fn cleanup(&self) {
        if let Some(ref global) = self.global_limiter {
            global.cleanup();
        }
        for entry in self.route_limiters.iter() {
            entry.value().cleanup();
        }
    }

    /// Get the number of registered route limiters
    pub fn route_count(&self) -> usize {
        self.route_limiters.len()
    }

    /// Check if any rate limiting is configured (fast path)
    ///
    /// Returns true if there's a global limiter or any route-specific limiters.
    /// Use this to skip rate limit checks entirely when no limiting is configured.
    #[inline]
    pub fn is_enabled(&self) -> bool {
        self.global_limiter.is_some() || !self.route_limiters.is_empty()
    }

    /// Check if a specific route has rate limiting configured (fast path)
    #[inline]
    pub fn has_route_limiter(&self, route_id: &str) -> bool {
        self.global_limiter.is_some() || self.route_limiters.contains_key(route_id)
    }
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Action to take if limited
    pub action: RateLimitAction,
    /// HTTP status code for rejection
    pub status_code: u16,
    /// Custom message
    pub message: Option<String>,
    /// Which limiter triggered (for logging)
    pub limiter: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let config = RateLimitConfig {
            max_rps: 10,
            burst: 5,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Should allow first 10 requests
        for _ in 0..10 {
            let (outcome, _) = pool.check("127.0.0.1");
            assert_eq!(outcome, RateLimitOutcome::Allowed);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            max_rps: 5,
            burst: 2,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Should allow first 5 requests
        for _ in 0..5 {
            let (outcome, _) = pool.check("127.0.0.1");
            assert_eq!(outcome, RateLimitOutcome::Allowed);
        }

        // 6th request should be limited
        let (outcome, _) = pool.check("127.0.0.1");
        assert_eq!(outcome, RateLimitOutcome::Limited);
    }

    #[test]
    fn test_rate_limiter_separate_keys() {
        let config = RateLimitConfig {
            max_rps: 2,
            burst: 1,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Each IP gets its own bucket
        let (outcome1, _) = pool.check("192.168.1.1");
        let (outcome2, _) = pool.check("192.168.1.2");
        let (outcome3, _) = pool.check("192.168.1.1");
        let (outcome4, _) = pool.check("192.168.1.2");

        assert_eq!(outcome1, RateLimitOutcome::Allowed);
        assert_eq!(outcome2, RateLimitOutcome::Allowed);
        assert_eq!(outcome3, RateLimitOutcome::Allowed);
        assert_eq!(outcome4, RateLimitOutcome::Allowed);

        // Both should hit limit now
        let (outcome5, _) = pool.check("192.168.1.1");
        let (outcome6, _) = pool.check("192.168.1.2");

        assert_eq!(outcome5, RateLimitOutcome::Limited);
        assert_eq!(outcome6, RateLimitOutcome::Limited);
    }

    #[test]
    fn test_rate_limit_manager() {
        let manager = RateLimitManager::new();

        manager.register_route(
            "api",
            RateLimitConfig {
                max_rps: 5,
                burst: 2,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // Route without limiter should always pass
        let result = manager.check("web", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(result.allowed);

        // Route with limiter should enforce limits
        for _ in 0..5 {
            let result = manager.check("api", "127.0.0.1", "/api/test", Option::<&NoHeaders>::None);
            assert!(result.allowed);
        }

        let result = manager.check("api", "127.0.0.1", "/api/test", Option::<&NoHeaders>::None);
        assert!(!result.allowed);
        assert_eq!(result.status_code, 429);
    }

    // Helper type for tests that don't need header access
    struct NoHeaders;
    impl HeaderAccessor for NoHeaders {
        fn get_header(&self, _name: &str) -> Option<String> {
            None
        }
    }
}
