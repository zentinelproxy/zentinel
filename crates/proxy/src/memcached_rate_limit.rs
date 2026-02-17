//! Distributed rate limiting with Memcached backend
//!
//! This module provides a Memcached-backed rate limiter for multi-instance deployments.
//! Uses a counter-based sliding window algorithm.
//!
//! # Algorithm
//!
//! Uses a fixed window counter algorithm with Memcached:
//! 1. Generate a time-windowed key (current second)
//! 2. Increment the counter atomically
//! 3. Allow if count <= max_rps
//!
//! Note: This is slightly less accurate than Redis sorted sets but more efficient
//! for Memcached's simpler data model.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "distributed-rate-limit-memcached")]
use async_memcached::AsciiProtocol;
use parking_lot::RwLock;
use tracing::{debug, error, trace, warn};

use zentinel_config::MemcachedBackendConfig;

use crate::rate_limit::{RateLimitConfig, RateLimitOutcome};

/// Statistics for Memcached-based distributed rate limiting
#[derive(Debug, Default)]
pub struct MemcachedRateLimitStats {
    /// Total requests checked
    pub total_checks: AtomicU64,
    /// Requests allowed
    pub allowed: AtomicU64,
    /// Requests limited
    pub limited: AtomicU64,
    /// Memcached errors (fallback to local)
    pub memcached_errors: AtomicU64,
    /// Local fallback invocations
    pub local_fallbacks: AtomicU64,
}

impl MemcachedRateLimitStats {
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

    pub fn record_memcached_error(&self) {
        self.memcached_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_local_fallback(&self) {
        self.local_fallbacks.fetch_add(1, Ordering::Relaxed);
    }
}

/// Memcached-backed distributed rate limiter
#[cfg(feature = "distributed-rate-limit-memcached")]
pub struct MemcachedRateLimiter {
    /// Memcached client
    client: RwLock<async_memcached::Client>,
    /// Configuration
    config: RwLock<MemcachedConfig>,
    /// Whether Memcached is currently healthy
    healthy: AtomicBool,
    /// Statistics
    pub stats: Arc<MemcachedRateLimitStats>,
}

#[cfg(feature = "distributed-rate-limit-memcached")]
#[derive(Debug, Clone)]
struct MemcachedConfig {
    key_prefix: String,
    max_rps: u32,
    window_secs: u64,
    timeout: Duration,
    fallback_local: bool,
    ttl_secs: u32,
}

#[cfg(feature = "distributed-rate-limit-memcached")]
impl MemcachedRateLimiter {
    /// Create a new Memcached rate limiter
    pub async fn new(
        backend_config: &MemcachedBackendConfig,
        rate_config: &RateLimitConfig,
    ) -> Result<Self, async_memcached::Error> {
        // Parse the URL to get host:port
        let addr = backend_config
            .url
            .trim_start_matches("memcache://")
            .trim_start_matches("memcached://");

        let client = async_memcached::Client::new(addr).await?;

        debug!(
            url = %backend_config.url,
            prefix = %backend_config.key_prefix,
            max_rps = rate_config.max_rps,
            "Memcached rate limiter initialized"
        );

        Ok(Self {
            client: RwLock::new(client),
            config: RwLock::new(MemcachedConfig {
                key_prefix: backend_config.key_prefix.clone(),
                max_rps: rate_config.max_rps,
                window_secs: 1,
                timeout: Duration::from_millis(backend_config.timeout_ms),
                fallback_local: backend_config.fallback_local,
                ttl_secs: backend_config.ttl_secs,
            }),
            healthy: AtomicBool::new(true),
            stats: Arc::new(MemcachedRateLimitStats::default()),
        })
    }

    /// Check if a request should be rate limited
    ///
    /// Returns the outcome and the current request count in the window.
    pub async fn check(
        &self,
        key: &str,
    ) -> Result<(RateLimitOutcome, u64), async_memcached::Error> {
        let config = self.config.read().clone();

        // Generate time-windowed key
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let window_key = format!("{}{}:{}", config.key_prefix, key, now);

        // Increment counter atomically
        // The write guard must be held across awaits because async_memcached::Client
        // requires &mut self for operations and is not internally synchronized.
        #[allow(clippy::await_holding_lock)]
        let result = tokio::time::timeout(config.timeout, async {
            let mut client = self.client.write();
            // Try to increment; if key doesn't exist, it will return an error
            match client.increment(&window_key, 1).await {
                Ok(count) => Ok(count),
                Err(async_memcached::Error::Protocol(async_memcached::Status::NotFound)) => {
                    // Key doesn't exist, set it to 1 with TTL
                    client
                        .set(&window_key, &b"1"[..], Some(config.ttl_secs as i64), None)
                        .await
                        .map(|_| 1u64)
                }
                Err(e) => Err(e),
            }
        })
        .await
        .map_err(|_| {
            async_memcached::Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Memcached operation timed out",
            ))
        })??;

        self.healthy.store(true, Ordering::Relaxed);

        let outcome = if result > config.max_rps as u64 {
            RateLimitOutcome::Limited
        } else {
            RateLimitOutcome::Allowed
        };

        trace!(
            key = key,
            count = result,
            max_rps = config.max_rps,
            outcome = ?outcome,
            "Memcached rate limit check"
        );

        self.stats.record_check(outcome);
        Ok((outcome, result))
    }

    /// Update configuration
    pub fn update_config(
        &self,
        backend_config: &MemcachedBackendConfig,
        rate_config: &RateLimitConfig,
    ) {
        let mut config = self.config.write();
        config.key_prefix = backend_config.key_prefix.clone();
        config.max_rps = rate_config.max_rps;
        config.timeout = Duration::from_millis(backend_config.timeout_ms);
        config.fallback_local = backend_config.fallback_local;
        config.ttl_secs = backend_config.ttl_secs;
    }

    /// Check if Memcached is currently healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// Mark Memcached as unhealthy (will trigger fallback)
    pub fn mark_unhealthy(&self) {
        self.healthy.store(false, Ordering::Relaxed);
        self.stats.record_memcached_error();
    }

    /// Check if fallback to local is enabled
    pub fn fallback_enabled(&self) -> bool {
        self.config.read().fallback_local
    }
}

/// Stub for when distributed-rate-limit-memcached feature is disabled
#[cfg(not(feature = "distributed-rate-limit-memcached"))]
pub struct MemcachedRateLimiter;

#[cfg(not(feature = "distributed-rate-limit-memcached"))]
impl MemcachedRateLimiter {
    pub async fn new(
        _backend_config: &MemcachedBackendConfig,
        _rate_config: &RateLimitConfig,
    ) -> Result<Self, String> {
        Err(
            "Memcached rate limiting requires the 'distributed-rate-limit-memcached' feature"
                .to_string(),
        )
    }
}

/// Create a Memcached rate limiter from configuration
#[cfg(feature = "distributed-rate-limit-memcached")]
pub async fn create_memcached_rate_limiter(
    backend_config: &MemcachedBackendConfig,
    rate_config: &RateLimitConfig,
) -> Option<MemcachedRateLimiter> {
    match MemcachedRateLimiter::new(backend_config, rate_config).await {
        Ok(limiter) => {
            debug!(
                url = %backend_config.url,
                "Memcached rate limiter created successfully"
            );
            Some(limiter)
        }
        Err(e) => {
            error!(
                error = %e,
                url = %backend_config.url,
                "Failed to create Memcached rate limiter"
            );
            if backend_config.fallback_local {
                warn!("Falling back to local rate limiting");
            }
            None
        }
    }
}

#[cfg(not(feature = "distributed-rate-limit-memcached"))]
pub async fn create_memcached_rate_limiter(
    _backend_config: &MemcachedBackendConfig,
    _rate_config: &RateLimitConfig,
) -> Option<MemcachedRateLimiter> {
    warn!("Memcached rate limiting requested but feature is disabled. Using local rate limiting.");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_recording() {
        let stats = MemcachedRateLimitStats::default();

        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Limited);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 3);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_stats_memcached_errors() {
        let stats = MemcachedRateLimitStats::default();

        stats.record_memcached_error();
        stats.record_memcached_error();
        stats.record_local_fallback();

        assert_eq!(stats.memcached_errors.load(Ordering::Relaxed), 2);
        assert_eq!(stats.local_fallbacks.load(Ordering::Relaxed), 1);
    }
}
