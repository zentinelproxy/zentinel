//! Distributed rate limiting with Redis backend
//!
//! This module provides a Redis-backed rate limiter for multi-instance deployments.
//! Uses a sliding window algorithm implemented with Redis sorted sets.
//!
//! # Algorithm
//!
//! Uses a sliding window log algorithm:
//! 1. Store each request timestamp in a Redis sorted set
//! 2. Remove timestamps older than the window (1 second)
//! 3. Count remaining timestamps
//! 4. Allow if count <= max_rps
//!
//! This provides accurate rate limiting across multiple instances with minimal
//! Redis operations (single MULTI/EXEC transaction per request).

use std::sync::atomic::{AtomicU64, Ordering};

use tracing::warn;

#[cfg(feature = "distributed-rate-limit")]
use redis::aio::ConnectionManager;

use sentinel_config::RedisBackendConfig;

use crate::rate_limit::{RateLimitConfig, RateLimitOutcome};

/// Statistics for distributed rate limiting
#[derive(Debug, Default)]
pub struct DistributedRateLimitStats {
    /// Total requests checked
    pub total_checks: AtomicU64,
    /// Requests allowed
    pub allowed: AtomicU64,
    /// Requests limited
    pub limited: AtomicU64,
    /// Redis errors (fallback to local)
    pub redis_errors: AtomicU64,
    /// Local fallback invocations
    pub local_fallbacks: AtomicU64,
}

impl DistributedRateLimitStats {
    pub fn record_check(&self, outcome: RateLimitOutcome) {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        match outcome {
            RateLimitOutcome::Allowed => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            RateLimitOutcome::Limited => {
                self.limited.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn record_redis_error(&self) {
        self.redis_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_local_fallback(&self) {
        self.local_fallbacks.fetch_add(1, Ordering::Relaxed);
    }
}

/// Redis-backed distributed rate limiter
#[cfg(feature = "distributed-rate-limit")]
pub struct RedisRateLimiter {
    /// Redis connection manager (handles reconnection)
    connection: ConnectionManager,
    /// Configuration
    config: RwLock<RedisConfig>,
    /// Whether Redis is currently healthy
    healthy: AtomicBool,
    /// Statistics
    pub stats: Arc<DistributedRateLimitStats>,
}

#[cfg(feature = "distributed-rate-limit")]
#[derive(Debug, Clone)]
struct RedisConfig {
    key_prefix: String,
    max_rps: u32,
    window_secs: u64,
    timeout: Duration,
    fallback_local: bool,
}

#[cfg(feature = "distributed-rate-limit")]
impl RedisRateLimiter {
    /// Create a new Redis rate limiter
    pub async fn new(
        backend_config: &RedisBackendConfig,
        rate_config: &RateLimitConfig,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(backend_config.url.as_str())?;
        let connection = ConnectionManager::new(client).await?;

        debug!(
            url = %backend_config.url,
            prefix = %backend_config.key_prefix,
            max_rps = rate_config.max_rps,
            "Redis rate limiter initialized"
        );

        Ok(Self {
            connection,
            config: RwLock::new(RedisConfig {
                key_prefix: backend_config.key_prefix.clone(),
                max_rps: rate_config.max_rps,
                window_secs: 1,
                timeout: Duration::from_millis(backend_config.timeout_ms),
                fallback_local: backend_config.fallback_local,
            }),
            healthy: AtomicBool::new(true),
            stats: Arc::new(DistributedRateLimitStats::default()),
        })
    }

    /// Check if a request should be rate limited
    ///
    /// Returns the outcome and the current request count in the window.
    pub async fn check(&self, key: &str) -> Result<(RateLimitOutcome, i64), redis::RedisError> {
        let config = self.config.read().clone();
        let full_key = format!("{}{}", config.key_prefix, key);

        // Use sliding window log algorithm with Redis sorted sets
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as f64;

        let window_start = now - (config.window_secs as f64 * 1000.0);

        // Atomic operation: remove old entries, add new entry, count entries
        let mut conn = self.connection.clone();

        let result: Result<(i64,), _> = tokio::time::timeout(config.timeout, async {
            redis::pipe()
                .atomic()
                // Remove timestamps older than window
                .zrembyscore(&full_key, 0.0, window_start)
                .ignore()
                // Add current timestamp with score = timestamp
                .zadd(&full_key, now, now.to_string())
                .ignore()
                // Set expiration to prevent memory leaks
                .expire(&full_key, (config.window_secs * 2) as i64)
                .ignore()
                // Count entries in window
                .zcount(&full_key, window_start, now)
                .query_async(&mut conn)
                .await
        })
        .await
        .map_err(|_| {
            redis::RedisError::from((redis::ErrorKind::IoError, "Redis operation timed out"))
        })?;

        let (count,) = result?;

        self.healthy.store(true, Ordering::Relaxed);

        let outcome = if count > config.max_rps as i64 {
            RateLimitOutcome::Limited
        } else {
            RateLimitOutcome::Allowed
        };

        trace!(
            key = key,
            count = count,
            max_rps = config.max_rps,
            outcome = ?outcome,
            "Redis rate limit check"
        );

        self.stats.record_check(outcome);
        Ok((outcome, count))
    }

    /// Update configuration
    pub fn update_config(
        &self,
        backend_config: &RedisBackendConfig,
        rate_config: &RateLimitConfig,
    ) {
        let mut config = self.config.write();
        config.key_prefix = backend_config.key_prefix.clone();
        config.max_rps = rate_config.max_rps;
        config.timeout = Duration::from_millis(backend_config.timeout_ms);
        config.fallback_local = backend_config.fallback_local;
    }

    /// Check if Redis is currently healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Mark Redis as unhealthy (will trigger fallback)
    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
        self.stats.record_redis_error();
    }

    /// Check if fallback to local is enabled
    pub fn fallback_enabled(&self) -> bool {
        self.config.read().fallback_local
    }
}

/// Stub for when distributed-rate-limit feature is disabled
#[cfg(not(feature = "distributed-rate-limit"))]
pub struct RedisRateLimiter;

#[cfg(not(feature = "distributed-rate-limit"))]
impl RedisRateLimiter {
    pub async fn new(
        _backend_config: &RedisBackendConfig,
        _rate_config: &RateLimitConfig,
    ) -> Result<Self, String> {
        Err("Distributed rate limiting requires the 'distributed-rate-limit' feature".to_string())
    }
}

/// Create a Redis rate limiter from configuration
#[cfg(feature = "distributed-rate-limit")]
pub async fn create_redis_rate_limiter(
    backend_config: &RedisBackendConfig,
    rate_config: &RateLimitConfig,
) -> Option<RedisRateLimiter> {
    match RedisRateLimiter::new(backend_config, rate_config).await {
        Ok(limiter) => {
            debug!(
                url = %backend_config.url,
                "Redis rate limiter created successfully"
            );
            Some(limiter)
        }
        Err(e) => {
            error!(
                error = %e,
                url = %backend_config.url,
                "Failed to create Redis rate limiter"
            );
            if backend_config.fallback_local {
                warn!("Falling back to local rate limiting");
            }
            None
        }
    }
}

#[cfg(not(feature = "distributed-rate-limit"))]
pub async fn create_redis_rate_limiter(
    _backend_config: &RedisBackendConfig,
    _rate_config: &RateLimitConfig,
) -> Option<RedisRateLimiter> {
    warn!(
        "Distributed rate limiting requested but feature is disabled. Using local rate limiting."
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_recording() {
        let stats = DistributedRateLimitStats::default();

        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Limited);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 3);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_redis_errors() {
        let stats = DistributedRateLimitStats::default();

        stats.record_redis_error();
        stats.record_redis_error();
        stats.record_local_fallback();

        assert_eq!(stats.redis_errors.load(Ordering::Relaxed), 2);
        assert_eq!(stats.local_fallbacks.load(Ordering::Relaxed), 1);
    }
}
