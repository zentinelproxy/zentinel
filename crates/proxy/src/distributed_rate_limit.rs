//! Distributed rate limiting with Redis backend
//!
//! This module provides a Redis-backed rate limiter for multi-instance deployments.
//!
//! # Algorithm
//!
//! The same token bucket as the local limiter ([`TokenBucket`]), stored in a
//! Redis hash per key (`tokens`, `at`) and advanced by one Lua script. The
//! script runs atomically on the server, so concurrent requests from any
//! number of instances each see the bucket the previous one left, and it
//! reads the clock with `TIME`, so instances with skewed clocks still agree
//! on how much has refilled. It is sent with EVALSHA (falling back to EVAL
//! the first time a server sees it): one round trip per request.
//!
//! The key expires once the bucket would be full again, which is what a
//! missing key means, so idle clients cost no memory.
//!
//! The previous implementation logged request timestamps in a sorted set and
//! counted the last second: `burst` was ignored, and the same config admitted
//! a different sequence than the local limiter.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(feature = "distributed-rate-limit-redis")]
use std::time::Duration;

#[cfg(feature = "distributed-rate-limit-redis")]
use redis::aio::ConnectionManager;
#[cfg(feature = "distributed-rate-limit-redis")]
use tracing::{debug, error, trace, warn};

use zentinel_config::RedisBackendConfig;

#[cfg(feature = "distributed-rate-limit-redis")]
use crate::rate_limit::{RateLimitCheckInfo, TokenBucket};
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

/// One token-bucket step on the server: `TokenBucket::take_at` in Lua.
///
/// `KEYS[1]` is the bucket; `ARGV[1]` its size and `ARGV[2]` the refill rate per
/// second. Returns `{allowed (0|1), tokens left}`; tokens come back as a
/// string because Redis truncates Lua numbers in replies to integers.
///
/// Keep the arithmetic in the same order as `TokenBucket::take`: both run on
/// IEEE doubles, so the same inputs give bit-identical buckets.
///
/// Numbers are written with `%.17g`, which round-trips a double exactly
/// (Lua's `tostring` keeps 14 digits, and would print a microsecond
/// timestamp as `1.76e+15`).
pub const TOKEN_BUCKET_SCRIPT: &str = r#"
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000000 + tonumber(time[2])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'at')
local tokens = tonumber(state[1])
local at = tonumber(state[2])
if tokens == nil or at == nil then
  tokens = capacity
  at = now
end
local elapsed = math.max(now - at, 0) / 1000000
tokens = math.min(tokens + elapsed * rate, capacity)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
if now > at then
  at = now
end
local encoded = string.format('%.17g', tokens)
redis.call('HSET', KEYS[1], 'tokens', encoded, 'at', string.format('%.17g', at))
local ttl = 86400000
if rate > 0 then
  ttl = math.ceil((capacity - tokens) / rate * 1000) + 1000
end
redis.call('PEXPIRE', KEYS[1], ttl)
return {allowed, encoded}
"#;

/// After a failed connection attempt, requests fall back without trying
/// again for this long, so an outage costs each request nothing rather than
/// a connect timeout.
#[cfg(feature = "distributed-rate-limit-redis")]
const RECONNECT_BACKOFF_MS: u64 = 1000;

/// Redis-backed distributed rate limiter
#[cfg(feature = "distributed-rate-limit-redis")]
pub struct RedisRateLimiter {
    client: redis::Client,
    /// Opened on first use and then kept: the connection manager
    /// reconnects by itself once it has connected once.
    connection: tokio::sync::OnceCell<ConnectionManager>,
    /// Unix milliseconds before which no new connection is attempted
    retry_connect_at_ms: AtomicU64,
    script: redis::Script,
    /// Prepended to every bucket key
    key_prefix: String,
    bucket: TokenBucket,
    /// Reported as the limit in `X-RateLimit-Limit`
    max_rps: u32,
    timeout: Duration,
    fallback_local: bool,
    /// Whether Redis is currently healthy
    healthy: AtomicBool,
    /// Statistics
    pub stats: Arc<DistributedRateLimitStats>,
}

#[cfg(feature = "distributed-rate-limit-redis")]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(feature = "distributed-rate-limit-redis")]
impl RedisRateLimiter {
    /// Create a limiter and connect now, failing if Redis is unreachable.
    pub async fn new(
        backend_config: &RedisBackendConfig,
        rate_config: &RateLimitConfig,
    ) -> Result<Self, redis::RedisError> {
        let limiter = Self::build(
            backend_config,
            rate_config,
            backend_config.key_prefix.clone(),
        )?;
        limiter
            .connection
            .get_or_try_init(|| ConnectionManager::new(limiter.client.clone()))
            .await?;

        debug!(
            url = %backend_config.url,
            prefix = %backend_config.key_prefix,
            max_rps = rate_config.max_rps,
            burst = rate_config.burst,
            "Redis rate limiter initialized"
        );
        Ok(limiter)
    }

    /// Create a limiter for one pool that connects on first use.
    ///
    /// Building limiters (at startup and on every reload) then never waits
    /// on Redis, and a Redis that is down at startup is used once it is up
    /// instead of never. Keys are `<key-prefix><scope>:<key>`.
    pub fn lazy(
        backend_config: &RedisBackendConfig,
        rate_config: &RateLimitConfig,
        scope: &str,
    ) -> Result<Self, redis::RedisError> {
        Self::build(
            backend_config,
            rate_config,
            format!("{}{}:", backend_config.key_prefix, scope),
        )
    }

    fn build(
        backend_config: &RedisBackendConfig,
        rate_config: &RateLimitConfig,
        key_prefix: String,
    ) -> Result<Self, redis::RedisError> {
        Ok(Self {
            client: redis::Client::open(backend_config.url.as_str())?,
            connection: tokio::sync::OnceCell::new(),
            retry_connect_at_ms: AtomicU64::new(0),
            script: redis::Script::new(TOKEN_BUCKET_SCRIPT),
            key_prefix,
            bucket: TokenBucket::new(rate_config.max_rps, rate_config.burst),
            max_rps: rate_config.max_rps,
            timeout: Duration::from_millis(backend_config.timeout_ms),
            fallback_local: backend_config.fallback_local,
            healthy: AtomicBool::new(true),
            stats: Arc::new(DistributedRateLimitStats::default()),
        })
    }

    async fn connection(&self) -> Result<ConnectionManager, redis::RedisError> {
        if let Some(conn) = self.connection.get() {
            return Ok(conn.clone());
        }
        if now_ms() < self.retry_connect_at_ms.load(Ordering::Relaxed) {
            return Err(redis::RedisError::from((
                redis::ErrorKind::Io,
                "Redis unreachable, not retrying the connection yet",
            )));
        }
        self.connection
            .get_or_try_init(|| ConnectionManager::new(self.client.clone()))
            .await
            .cloned()
    }

    /// Take a token for `key`.
    ///
    /// Returns the same information, computed the same way, as the local
    /// limiter: it drives `X-RateLimit-*` and `Retry-After`.
    pub async fn check(&self, key: &str) -> Result<RateLimitCheckInfo, redis::RedisError> {
        let full_key = format!("{}{}", self.key_prefix, key);

        let result: Result<(i64, String), redis::RedisError> =
            match tokio::time::timeout(self.timeout, async {
                let mut conn = self.connection().await?;
                let mut invocation = self.script.key(&full_key);
                invocation
                    .arg(self.bucket.capacity() as u64)
                    .arg(self.bucket.refill_per_sec() as u64);
                invocation.invoke_async(&mut conn).await
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(redis::RedisError::from((
                    redis::ErrorKind::Io,
                    "Redis operation timed out",
                ))),
            };
        let (allowed, tokens) = result.inspect_err(|_| {
            if self.connection.get().is_none() {
                self.retry_connect_at_ms
                    .store(now_ms() + RECONNECT_BACKOFF_MS, Ordering::Relaxed);
            }
        })?;

        let tokens: f64 = tokens.parse().map_err(|_| {
            redis::RedisError::from((
                redis::ErrorKind::Parse,
                "Rate limit script returned a non-numeric token count",
            ))
        })?;
        let outcome = if allowed == 1 {
            RateLimitOutcome::Allowed
        } else {
            RateLimitOutcome::Limited
        };

        self.healthy.store(true, Ordering::Relaxed);

        trace!(
            key = key,
            tokens = tokens,
            max_rps = self.max_rps,
            outcome = ?outcome,
            "Redis rate limit check"
        );

        self.stats.record_check(outcome);
        Ok(self.bucket.describe(tokens, outcome, self.max_rps))
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
        self.fallback_local
    }
}

/// Stub for when the Redis backend is not compiled in
#[cfg(not(feature = "distributed-rate-limit-redis"))]
pub struct RedisRateLimiter;

#[cfg(not(feature = "distributed-rate-limit-redis"))]
impl RedisRateLimiter {
    pub async fn new(
        _backend_config: &RedisBackendConfig,
        _rate_config: &RateLimitConfig,
    ) -> Result<Self, String> {
        Err("Redis rate limiting requires the 'distributed-rate-limit-redis' feature".to_string())
    }
}

/// Create a Redis rate limiter from configuration
#[cfg(feature = "distributed-rate-limit-redis")]
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

#[cfg(not(feature = "distributed-rate-limit-redis"))]
pub async fn create_redis_rate_limiter(
    _backend_config: &RedisBackendConfig,
    _rate_config: &RateLimitConfig,
) -> Option<RedisRateLimiter> {
    tracing::warn!(
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

    /// The script's arithmetic must stay `TokenBucket::take`'s. Without a
    /// Lua interpreter in the test suite, pin the lines that carry it.
    #[test]
    fn script_mirrors_token_bucket_take() {
        for line in [
            "tokens = math.min(tokens + elapsed * rate, capacity)",
            "if tokens >= 1 then",
            "tokens = tokens - 1",
            "local elapsed = math.max(now - at, 0) / 1000000",
            "redis.call('TIME')",
        ] {
            assert!(
                TOKEN_BUCKET_SCRIPT.contains(line),
                "token bucket script lost `{line}`"
            );
        }
    }
}
