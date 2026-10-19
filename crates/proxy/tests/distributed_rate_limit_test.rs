//! Integration tests for distributed rate limiting (Redis and Memcached)
//!
//! These tests require running Redis and/or Memcached instances; each one
//! skips (and passes) when its server is unreachable.
//!
//! To run with Docker:
//! ```bash
//! docker compose -f docker-compose.yml -f docker-compose.test.yml --profile persistence up -d
//! cargo test -p zentinel-proxy --test distributed_rate_limit_test --features distributed-rate-limit
//! ```
//!
//! Environment variables:
//! - `REDIS_URL`: Redis connection URL (default: redis://127.0.0.1:6379)
//! - `MEMCACHED_URL`: Memcached connection URL (default: memcache://127.0.0.1:11211)
//! - `SKIP_REDIS_TESTS`: Set to skip Redis tests if Redis is unavailable
//! - `SKIP_MEMCACHED_TESTS`: Set to skip Memcached tests if Memcached is unavailable

/// What a sequence of checks returned, in the terms that reach the client:
/// the outcome and the `X-RateLimit-Remaining` / `X-RateLimit-Limit` values.
#[cfg(any(
    feature = "distributed-rate-limit-redis",
    feature = "distributed-rate-limit-memcached"
))]
fn summary(
    infos: &[zentinel_proxy::rate_limit::RateLimitCheckInfo],
) -> Vec<(zentinel_proxy::rate_limit::RateLimitOutcome, u32, u32)> {
    infos
        .iter()
        .map(|i| (i.outcome, i.remaining, i.limit))
        .collect()
}

/// The same checks against an in-memory pool with the same limit.
#[cfg(any(
    feature = "distributed-rate-limit-redis",
    feature = "distributed-rate-limit-memcached"
))]
fn local_summary(
    max_rps: u32,
    burst: u32,
    n: usize,
) -> Vec<(zentinel_proxy::rate_limit::RateLimitOutcome, u32, u32)> {
    let pool = zentinel_proxy::rate_limit::RateLimiterPool::new(
        zentinel_proxy::rate_limit::RateLimitConfig {
            max_rps,
            burst,
            ..Default::default()
        },
    );
    let infos: Vec<_> = (0..n).map(|_| pool.check("k")).collect();
    summary(&infos)
}

// Only compile when feature is enabled
#[cfg(feature = "distributed-rate-limit-redis")]
mod redis_tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use zentinel_config::{RateLimitBackend, RedisBackendConfig};
    use zentinel_proxy::distributed_rate_limit::RedisRateLimiter;
    use zentinel_proxy::rate_limit::{RateLimitConfig, RateLimitOutcome, RateLimiterPool};

    use super::{local_summary, summary};

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }

    fn should_skip_redis() -> bool {
        std::env::var("SKIP_REDIS_TESTS").is_ok()
    }

    fn test_redis_config(max_rps: u32, burst: u32) -> (RedisBackendConfig, RateLimitConfig) {
        let backend = RedisBackendConfig {
            url: redis_url(),
            key_prefix: format!("zentinel:test:{}:", uuid::Uuid::new_v4()),
            pool_size: 4,
            timeout_ms: 1000,
            fallback_local: true,
        };
        let rate = RateLimitConfig {
            max_rps,
            burst,
            ..Default::default()
        };
        (backend, rate)
    }

    /// Whether to run the Redis tests. Unreachable means skip -- unless
    /// `ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS` is set, as in CI, where a
    /// skipped test would pass without having tested anything.
    async fn is_redis_available() -> bool {
        let reachable = redis_reachable().await;
        if !reachable && std::env::var("ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS").is_ok() {
            panic!("Redis is required (ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS) but not reachable");
        }
        reachable
    }

    async fn redis_reachable() -> bool {
        if should_skip_redis() {
            return false;
        }
        let Ok(client) = redis::Client::open(redis_url().as_str()) else {
            return false;
        };
        matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                redis::aio::ConnectionManager::new(client),
            )
            .await,
            Ok(Ok(_))
        )
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_allows_under_limit() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(10, 10);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        // A fresh key has a full bucket: the first request leaves burst - 1.
        for i in 0..5 {
            let info = limiter.check(&format!("test-key-{}", i)).await.unwrap();
            assert_eq!(info.outcome, RateLimitOutcome::Allowed, "request {i}");
            assert_eq!(info.remaining, 9);
            assert_eq!(info.limit, 10);
        }
    }

    /// `burst` is the bucket size: the fixed-window counter this replaced
    /// allowed `max-rps` per second whatever `burst` said.
    #[tokio::test]
    async fn test_redis_rate_limiter_honours_burst() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(1, 3);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let mut infos = Vec::new();
        for _ in 0..5 {
            infos.push(limiter.check("burst-key").await.unwrap());
        }
        assert_eq!(summary(&infos), local_summary(1, 3, 5));
        assert_eq!(
            infos.iter().map(|i| i.outcome).collect::<Vec<_>>(),
            [
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Limited,
                RateLimitOutcome::Limited,
            ]
        );
        // One token at 1/s is at most a second away; Retry-After is built
        // from this exactly as for the local limiter.
        let wait = infos[4]
            .retry_after_ms
            .expect("limited checks know the wait");
        assert!(wait > 0 && wait <= 1000, "retry after {wait} ms");
    }

    /// And a burst larger than max-rps is allowed at once.
    #[tokio::test]
    async fn test_redis_rate_limiter_matches_local_limiter() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        for (max_rps, burst) in [(5, 5), (5, 12), (100, 3), (2, 1)] {
            let (backend, rate) = test_redis_config(max_rps, burst);
            let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
            let n = burst as usize + 3;
            let mut infos = Vec::new();
            for _ in 0..n {
                infos.push(limiter.check("same-key").await.unwrap());
            }
            // A fast refill can top up a token between checks here and not
            // in the in-memory run; compare where that cannot happen.
            if max_rps <= 5 {
                assert_eq!(
                    summary(&infos),
                    local_summary(max_rps, burst, n),
                    "max-rps {max_rps} burst {burst}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_separate_keys() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(3, 3);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        for _ in 0..3 {
            limiter.check("key-a").await.unwrap();
        }
        assert_eq!(
            limiter.check("key-a").await.unwrap().outcome,
            RateLimitOutcome::Limited
        );
        assert_eq!(
            limiter.check("key-b").await.unwrap().outcome,
            RateLimitOutcome::Allowed
        );
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_refills() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(5, 5);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "test-refill-key";

        for _ in 0..5 {
            limiter.check(key).await.unwrap();
        }
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Limited
        );

        // 5/s refills a token every 200 ms
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Allowed
        );
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Limited
        );
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_stats_tracking() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(3, 3);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "test-stats-key";

        for _ in 0..5 {
            let _ = limiter.check(key).await;
        }

        let stats = &limiter.stats;
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 5);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_health_tracking() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(10, 10);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        assert!(limiter.is_healthy());
        let _ = limiter.check("health-test").await;
        assert!(limiter.is_healthy());
        limiter.mark_unhealthy();
        assert!(!limiter.is_healthy());
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_key_prefix() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (mut backend1, rate1) = test_redis_config(5, 5);
        backend1.key_prefix = format!("prefix-a:{}:", uuid::Uuid::new_v4());
        let limiter1 = RedisRateLimiter::new(&backend1, &rate1).await.unwrap();

        let (mut backend2, rate2) = test_redis_config(5, 5);
        backend2.key_prefix = format!("prefix-b:{}:", uuid::Uuid::new_v4());
        let limiter2 = RedisRateLimiter::new(&backend2, &rate2).await.unwrap();

        let key = "shared-key";
        for _ in 0..5 {
            limiter1.check(key).await.unwrap();
        }
        assert_eq!(
            limiter1.check(key).await.unwrap().outcome,
            RateLimitOutcome::Limited
        );
        assert_eq!(
            limiter2.check(key).await.unwrap().outcome,
            RateLimitOutcome::Allowed
        );
    }

    /// The script runs atomically: concurrent checks take exactly `burst`
    /// tokens between them, never more.
    #[tokio::test]
    async fn test_redis_rate_limiter_concurrent_requests() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        // 1/s refill: nothing measurable refills while the test runs.
        let (backend, rate) = test_redis_config(1, 20);
        let limiter = std::sync::Arc::new(RedisRateLimiter::new(&backend, &rate).await.unwrap());
        let key = "concurrent-key";

        let mut handles = Vec::new();
        for _ in 0..50 {
            let limiter = limiter.clone();
            let key = key.to_string();
            handles.push(tokio::spawn(async move { limiter.check(&key).await }));
        }

        let mut allowed = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent request should not error");
            if result.unwrap().outcome == RateLimitOutcome::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20, "exactly the burst is admitted");
    }

    /// Two pools on the same backend and route, as two proxy instances would
    /// have, draw from one bucket.
    #[tokio::test]
    async fn test_redis_pools_share_one_bucket_across_instances() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, mut rate) = test_redis_config(1, 4);
        rate.backend = RateLimitBackend::Redis(backend);
        let instance_a = RateLimiterPool::with_scope(rate.clone(), "api");
        let instance_b = RateLimiterPool::with_scope(rate.clone(), "api");
        let other_route = RateLimiterPool::with_scope(rate, "web");
        assert!(instance_a.is_distributed());

        let mut outcomes = Vec::new();
        for i in 0..6 {
            let pool = if i % 2 == 0 { &instance_a } else { &instance_b };
            outcomes.push(pool.check_async("203.0.113.7").await.outcome);
        }
        assert_eq!(
            outcomes,
            [
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Limited,
                RateLimitOutcome::Limited,
            ]
        );
        // Another route has its own bucket, as it does locally.
        assert_eq!(
            other_route.check_async("203.0.113.7").await.outcome,
            RateLimitOutcome::Allowed
        );
    }
}

#[cfg(feature = "distributed-rate-limit-memcached")]
mod memcached_tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use zentinel_config::{MemcachedBackendConfig, RateLimitBackend};
    use zentinel_proxy::memcached_rate_limit::MemcachedRateLimiter;
    use zentinel_proxy::rate_limit::{RateLimitConfig, RateLimitOutcome, RateLimiterPool};

    use super::{local_summary, summary};

    fn memcached_url() -> String {
        std::env::var("MEMCACHED_URL").unwrap_or_else(|_| "memcache://127.0.0.1:11211".to_string())
    }

    fn should_skip_memcached() -> bool {
        std::env::var("SKIP_MEMCACHED_TESTS").is_ok()
    }

    fn test_memcached_config(
        max_rps: u32,
        burst: u32,
    ) -> (MemcachedBackendConfig, RateLimitConfig) {
        let backend = MemcachedBackendConfig {
            url: memcached_url(),
            key_prefix: format!("zentinel:test:{}:", uuid::Uuid::new_v4()),
            pool_size: 4,
            timeout_ms: 1000,
            fallback_local: true,
            ttl_secs: 2,
        };
        let rate = RateLimitConfig {
            max_rps,
            burst,
            ..Default::default()
        };
        (backend, rate)
    }

    /// Whether to run the memcached tests. Unreachable means skip -- unless
    /// `ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS` is set, as in CI, where a
    /// skipped test would pass without having tested anything.
    async fn is_memcached_available() -> bool {
        let reachable = memcached_reachable().await;
        if !reachable && std::env::var("ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS").is_ok() {
            panic!("memcached is required (ZENTINEL_REQUIRE_DISTRIBUTED_BACKENDS) but not reachable");
        }
        reachable
    }

    async fn memcached_reachable() -> bool {
        if should_skip_memcached() {
            return false;
        }
        let addr = memcached_url()
            .trim_start_matches("memcache://")
            .trim_start_matches("memcached://")
            .to_string();
        matches!(
            tokio::time::timeout(Duration::from_secs(2), async_memcached::Client::new(addr)).await,
            Ok(Ok(_))
        )
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_allows_under_limit() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(10, 10);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();

        for i in 0..5 {
            let info = limiter.check(&format!("mc-test-key-{}", i)).await.unwrap();
            assert_eq!(info.outcome, RateLimitOutcome::Allowed, "request {i}");
            assert_eq!(info.remaining, 9);
        }
    }

    /// `burst` is the bucket size, and the sequence is the local limiter's.
    #[tokio::test]
    async fn test_memcached_rate_limiter_matches_local_limiter() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        for (max_rps, burst) in [(1, 3), (5, 5), (5, 12), (2, 1)] {
            let (backend, rate) = test_memcached_config(max_rps, burst);
            let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
            let n = burst as usize + 3;
            let mut infos = Vec::new();
            for _ in 0..n {
                infos.push(limiter.check("same-key").await.unwrap());
            }
            assert_eq!(
                summary(&infos),
                local_summary(max_rps, burst, n),
                "max-rps {max_rps} burst {burst}"
            );
        }
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_separate_keys() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(3, 3);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();

        for _ in 0..3 {
            limiter.check("mc-key-a").await.unwrap();
        }
        assert_eq!(
            limiter.check("mc-key-a").await.unwrap().outcome,
            RateLimitOutcome::Limited
        );
        assert_eq!(
            limiter.check("mc-key-b").await.unwrap().outcome,
            RateLimitOutcome::Allowed
        );
        // Keys memcached cannot store verbatim are hashed, not rejected.
        assert_eq!(
            limiter
                .check("a header value with spaces")
                .await
                .unwrap()
                .outcome,
            RateLimitOutcome::Allowed
        );
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_refills() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(5, 5);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-test-refill-key";

        for _ in 0..5 {
            limiter.check(key).await.unwrap();
        }
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Limited
        );

        // 5/s refills a token every 200 ms
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Allowed
        );
        assert_eq!(
            limiter.check(key).await.unwrap().outcome,
            RateLimitOutcome::Limited
        );
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_stats_tracking() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(3, 3);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-test-stats-key";

        for _ in 0..5 {
            let _ = limiter.check(key).await;
        }

        let stats = &limiter.stats;
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 5);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 2);
    }

    /// Two instances (separate connections, so their CAS writes really do
    /// race) checking concurrently take exactly `burst` tokens in total.
    #[tokio::test]
    async fn test_memcached_instances_share_one_bucket() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, mut rate) = test_memcached_config(1, 20);
        rate.backend = RateLimitBackend::Memcached(backend);
        let instance_a = std::sync::Arc::new(RateLimiterPool::with_scope(rate.clone(), "api"));
        let instance_b = std::sync::Arc::new(RateLimiterPool::with_scope(rate, "api"));
        assert!(instance_a.is_distributed());

        let mut handles = Vec::new();
        for i in 0..50 {
            let pool = if i % 2 == 0 {
                instance_a.clone()
            } else {
                instance_b.clone()
            };
            handles.push(tokio::spawn(async move {
                pool.check_async("203.0.113.7").await.outcome
            }));
        }
        let mut allowed = 0;
        for handle in handles {
            if handle.await.unwrap() == RateLimitOutcome::Allowed {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 20, "exactly the burst is admitted");
    }
}

#[cfg(feature = "distributed-rate-limit-redis")]
mod fallback_tests {
    use std::time::Duration;

    use zentinel_config::RedisBackendConfig;
    use zentinel_proxy::distributed_rate_limit::RedisRateLimiter;
    use zentinel_proxy::rate_limit::RateLimitConfig;

    #[tokio::test]
    async fn test_fallback_enabled_config() {
        // Test that fallback configuration is properly read
        let backend = RedisBackendConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: "test:".to_string(),
            pool_size: 4,
            timeout_ms: 1000,
            fallback_local: true,
        };
        let rate = RateLimitConfig {
            max_rps: 10,
            burst: 20,
            ..Default::default()
        };

        // If Redis is available, test fallback_enabled
        if let Ok(limiter) = RedisRateLimiter::new(&backend, &rate).await {
            assert!(limiter.fallback_enabled(), "Fallback should be enabled");
        }
    }

    #[tokio::test]
    async fn test_fallback_disabled_config() {
        let backend = RedisBackendConfig {
            url: "redis://127.0.0.1:6379".to_string(),
            key_prefix: "test:".to_string(),
            pool_size: 4,
            timeout_ms: 1000,
            fallback_local: false,
        };
        let rate = RateLimitConfig {
            max_rps: 10,
            burst: 20,
            ..Default::default()
        };

        // If Redis is available, test fallback_enabled
        if let Ok(limiter) = RedisRateLimiter::new(&backend, &rate).await {
            assert!(!limiter.fallback_enabled(), "Fallback should be disabled");
        }
    }

    #[tokio::test]
    async fn test_invalid_redis_url_fails_gracefully() {
        let backend = RedisBackendConfig {
            url: "redis://invalid-host-that-does-not-exist:6379".to_string(),
            key_prefix: "test:".to_string(),
            pool_size: 4,
            timeout_ms: 500, // Short timeout
            fallback_local: true,
        };
        let rate = RateLimitConfig {
            max_rps: 10,
            burst: 20,
            ..Default::default()
        };

        // Should fail to connect but not panic
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            RedisRateLimiter::new(&backend, &rate),
        )
        .await;

        // Either times out or returns error - both are acceptable
        match result {
            Ok(Err(_)) => { /* Expected: connection error */ }
            Err(_) => { /* Expected: timeout */ }
            Ok(Ok(_)) => panic!("Should not connect to invalid host"),
        }
    }
}

/// A backend that cannot be reached: these run without any server.
#[cfg(any(
    feature = "distributed-rate-limit-redis",
    feature = "distributed-rate-limit-memcached"
))]
mod unreachable_backend_tests {
    use zentinel_config::RateLimitBackend;
    use zentinel_proxy::rate_limit::{RateLimitConfig, RateLimitOutcome, RateLimiterPool};

    // Nothing listens here (a closed port refuses at once, so the checks
    // do not wait out a timeout).
    const NOWHERE: &str = "127.0.0.1:1";

    #[cfg(feature = "distributed-rate-limit-redis")]
    fn redis(fallback_local: bool) -> RateLimitBackend {
        RateLimitBackend::Redis(zentinel_config::RedisBackendConfig {
            url: format!("redis://{NOWHERE}"),
            key_prefix: "test:".to_string(),
            pool_size: 1,
            timeout_ms: 500,
            fallback_local,
        })
    }

    #[cfg(feature = "distributed-rate-limit-memcached")]
    fn memcached(fallback_local: bool) -> RateLimitBackend {
        RateLimitBackend::Memcached(zentinel_config::MemcachedBackendConfig {
            url: format!("memcache://{NOWHERE}"),
            key_prefix: "test:".to_string(),
            pool_size: 1,
            timeout_ms: 500,
            fallback_local,
            ttl_secs: 2,
        })
    }

    async fn outcomes(backend: RateLimitBackend, n: usize) -> Vec<RateLimitOutcome> {
        let pool = RateLimiterPool::with_scope(
            RateLimitConfig {
                max_rps: 1,
                burst: 2,
                backend,
                ..Default::default()
            },
            "route",
        );
        let mut outcomes = Vec::new();
        for _ in 0..n {
            outcomes.push(pool.check_async("203.0.113.7").await.outcome);
        }
        outcomes
    }

    const A: RateLimitOutcome = RateLimitOutcome::Allowed;
    const L: RateLimitOutcome = RateLimitOutcome::Limited;

    /// With `fallback-local`, a backend outage limits per instance with the
    /// same bucket rather than letting everything through.
    #[cfg(feature = "distributed-rate-limit-redis")]
    #[tokio::test]
    async fn redis_outage_falls_back_to_local_buckets() {
        assert_eq!(outcomes(redis(true), 4).await, [A, A, L, L]);
    }

    #[cfg(feature = "distributed-rate-limit-redis")]
    #[tokio::test]
    async fn redis_outage_without_fallback_fails_open() {
        assert_eq!(outcomes(redis(false), 4).await, [A, A, A, A]);
    }

    #[cfg(feature = "distributed-rate-limit-memcached")]
    #[tokio::test]
    async fn memcached_outage_falls_back_to_local_buckets() {
        assert_eq!(outcomes(memcached(true), 4).await, [A, A, L, L]);
    }

    #[cfg(feature = "distributed-rate-limit-memcached")]
    #[tokio::test]
    async fn memcached_outage_without_fallback_fails_open() {
        assert_eq!(outcomes(memcached(false), 4).await, [A, A, A, A]);
    }
}

// Tests that run without external dependencies
mod unit_tests {
    #[cfg(any(
        feature = "distributed-rate-limit-redis",
        feature = "distributed-rate-limit-memcached"
    ))]
    use std::sync::atomic::Ordering;

    #[cfg(feature = "distributed-rate-limit-redis")]
    use zentinel_proxy::distributed_rate_limit::DistributedRateLimitStats;

    #[cfg(feature = "distributed-rate-limit-memcached")]
    use zentinel_proxy::memcached_rate_limit::MemcachedRateLimitStats;

    #[cfg(any(
        feature = "distributed-rate-limit-redis",
        feature = "distributed-rate-limit-memcached"
    ))]
    use zentinel_proxy::rate_limit::RateLimitOutcome;

    #[cfg(feature = "distributed-rate-limit-redis")]
    #[test]
    fn test_distributed_stats_default() {
        let stats = DistributedRateLimitStats::default();
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 0);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 0);
        assert_eq!(stats.redis_errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.local_fallbacks.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "distributed-rate-limit-redis")]
    #[test]
    fn test_distributed_stats_record_allowed() {
        let stats = DistributedRateLimitStats::default();
        stats.record_check(RateLimitOutcome::Allowed);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "distributed-rate-limit-redis")]
    #[test]
    fn test_distributed_stats_record_limited() {
        let stats = DistributedRateLimitStats::default();
        stats.record_check(RateLimitOutcome::Limited);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "distributed-rate-limit-redis")]
    #[test]
    fn test_distributed_stats_errors_and_fallbacks() {
        let stats = DistributedRateLimitStats::default();

        stats.record_redis_error();
        stats.record_redis_error();
        stats.record_local_fallback();

        assert_eq!(stats.redis_errors.load(Ordering::Relaxed), 2);
        assert_eq!(stats.local_fallbacks.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "distributed-rate-limit-memcached")]
    #[test]
    fn test_memcached_stats_default() {
        let stats = MemcachedRateLimitStats::default();
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 0);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "distributed-rate-limit-memcached")]
    #[test]
    fn test_memcached_stats_record_mixed() {
        let stats = MemcachedRateLimitStats::default();

        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Allowed);
        stats.record_check(RateLimitOutcome::Limited);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 3);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 1);
    }
}
