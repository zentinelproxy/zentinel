//! Integration tests for distributed rate limiting (Redis and Memcached)
//!
//! These tests require running Redis and/or Memcached instances.
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

// Only compile when feature is enabled
#[cfg(feature = "distributed-rate-limit")]
mod redis_tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use zentinel_config::RedisBackendConfig;
    use zentinel_proxy::distributed_rate_limit::RedisRateLimiter;
    use zentinel_proxy::rate_limit::{RateLimitConfig, RateLimitOutcome};

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }

    fn should_skip_redis() -> bool {
        std::env::var("SKIP_REDIS_TESTS").is_ok()
    }

    fn test_redis_config(max_rps: u32) -> (RedisBackendConfig, RateLimitConfig) {
        let backend = RedisBackendConfig {
            url: redis_url(),
            key_prefix: format!("zentinel:test:{}:", uuid::Uuid::new_v4()),
            pool_size: 4,
            timeout_ms: 1000,
            fallback_local: true,
        };
        let rate = RateLimitConfig {
            max_rps,
            burst: max_rps * 2,
            ..Default::default()
        };
        (backend, rate)
    }

    async fn is_redis_available() -> bool {
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

        let (backend, rate) = test_redis_config(10);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        // Should allow requests under the limit
        for i in 0..5 {
            let (outcome, count) = limiter.check(&format!("test-key-{}", i)).await.unwrap();
            assert_eq!(
                outcome,
                RateLimitOutcome::Allowed,
                "Request {} should be allowed",
                i
            );
            assert_eq!(count, 1, "First request for each key should have count 1");
        }
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_blocks_over_limit() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(5);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "test-block-key";

        // First 5 requests should be allowed
        for i in 0..5 {
            let (outcome, _) = limiter.check(key).await.unwrap();
            assert_eq!(
                outcome,
                RateLimitOutcome::Allowed,
                "Request {} should be allowed",
                i
            );
        }

        // 6th request should be limited
        let (outcome, count) = limiter.check(key).await.unwrap();
        assert_eq!(
            outcome,
            RateLimitOutcome::Limited,
            "Request 6 should be limited"
        );
        assert!(count > 5, "Count should be greater than limit");
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_separate_keys() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(3);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        // Exhaust limit for key A
        for _ in 0..3 {
            limiter.check("key-a").await.unwrap();
        }
        let (outcome_a, _) = limiter.check("key-a").await.unwrap();
        assert_eq!(outcome_a, RateLimitOutcome::Limited);

        // Key B should still be allowed
        let (outcome_b, _) = limiter.check("key-b").await.unwrap();
        assert_eq!(outcome_b, RateLimitOutcome::Allowed);
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_sliding_window() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(5);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "test-sliding-key";

        // Exhaust limit
        for _ in 0..5 {
            limiter.check(key).await.unwrap();
        }
        let (outcome, _) = limiter.check(key).await.unwrap();
        assert_eq!(outcome, RateLimitOutcome::Limited);

        // Wait for window to slide (1 second + buffer)
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // Should be allowed again
        let (outcome, _) = limiter.check(key).await.unwrap();
        assert_eq!(
            outcome,
            RateLimitOutcome::Allowed,
            "Should allow after window reset"
        );
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_stats_tracking() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(3);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "test-stats-key";

        // Make 5 requests (3 allowed, 2 limited)
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

        let (backend, rate) = test_redis_config(10);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();

        // Should start healthy
        assert!(limiter.is_healthy());

        // After successful check, should remain healthy
        let _ = limiter.check("health-test").await;
        assert!(limiter.is_healthy());

        // Manually mark unhealthy
        limiter.mark_unhealthy();
        assert!(!limiter.is_healthy());
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_key_prefix() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        // Create two limiters with different prefixes
        let (mut backend1, rate1) = test_redis_config(5);
        backend1.key_prefix = "prefix-a:".to_string();
        let limiter1 = RedisRateLimiter::new(&backend1, &rate1).await.unwrap();

        let (mut backend2, rate2) = test_redis_config(5);
        backend2.key_prefix = "prefix-b:".to_string();
        let limiter2 = RedisRateLimiter::new(&backend2, &rate2).await.unwrap();

        let key = "shared-key";

        // Exhaust limit on limiter1
        for _ in 0..5 {
            limiter1.check(key).await.unwrap();
        }
        let (outcome1, _) = limiter1.check(key).await.unwrap();
        assert_eq!(outcome1, RateLimitOutcome::Limited);

        // limiter2 should still allow (different prefix = different key)
        let (outcome2, _) = limiter2.check(key).await.unwrap();
        assert_eq!(outcome2, RateLimitOutcome::Allowed);
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_concurrent_requests() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(100);
        let limiter = std::sync::Arc::new(RedisRateLimiter::new(&backend, &rate).await.unwrap());
        let key = "concurrent-key";

        // Spawn 50 concurrent requests
        let mut handles = Vec::new();
        for _ in 0..50 {
            let limiter = limiter.clone();
            let key = key.to_string();
            handles.push(tokio::spawn(async move { limiter.check(&key).await }));
        }

        // All should complete without error
        let mut allowed = 0;
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent request should not error");
            if result.unwrap().0 == RateLimitOutcome::Allowed {
                allowed += 1;
            }
        }

        // All 50 should be allowed (limit is 100)
        assert_eq!(allowed, 50, "All 50 concurrent requests should be allowed");
    }

    #[tokio::test]
    async fn test_redis_rate_limiter_config_update() {
        if !is_redis_available().await {
            eprintln!("Skipping test: Redis not available");
            return;
        }

        let (backend, rate) = test_redis_config(5);
        let limiter = RedisRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "config-update-key";

        // Exhaust initial limit
        for _ in 0..5 {
            limiter.check(key).await.unwrap();
        }
        let (outcome, _) = limiter.check(key).await.unwrap();
        assert_eq!(outcome, RateLimitOutcome::Limited);

        // Update config to higher limit
        let new_rate = RateLimitConfig {
            max_rps: 20,
            burst: 40,
            ..Default::default()
        };
        limiter.update_config(&backend, &new_rate);

        // New key should use new limit (6 should still fail due to existing count)
        // But after window reset, 20 should be allowed
        tokio::time::sleep(Duration::from_millis(1100)).await;

        for _ in 0..10 {
            let (outcome, _) = limiter.check(key).await.unwrap();
            assert_eq!(outcome, RateLimitOutcome::Allowed);
        }
    }
}

#[cfg(feature = "distributed-rate-limit-memcached")]
mod memcached_tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use zentinel_config::MemcachedBackendConfig;
    use zentinel_proxy::memcached_rate_limit::MemcachedRateLimiter;
    use zentinel_proxy::rate_limit::{RateLimitConfig, RateLimitOutcome};

    fn memcached_url() -> String {
        std::env::var("MEMCACHED_URL").unwrap_or_else(|_| "memcache://127.0.0.1:11211".to_string())
    }

    fn should_skip_memcached() -> bool {
        std::env::var("SKIP_MEMCACHED_TESTS").is_ok()
    }

    fn test_memcached_config(max_rps: u32) -> (MemcachedBackendConfig, RateLimitConfig) {
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
            burst: max_rps * 2,
            ..Default::default()
        };
        (backend, rate)
    }

    async fn is_memcached_available() -> bool {
        if should_skip_memcached() {
            return false;
        }
        // Try to connect to memcached
        matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                async_memcached::Client::new(memcached_url()),
            )
            .await,
            Ok(Ok(_))
        )
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_allows_under_limit() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(10);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();

        // Should allow requests under the limit
        for i in 0..5 {
            let (outcome, count) = limiter.check(&format!("mc-test-key-{}", i)).await.unwrap();
            assert_eq!(
                outcome,
                RateLimitOutcome::Allowed,
                "Request {} should be allowed",
                i
            );
            assert_eq!(count, 1, "First request for each key should have count 1");
        }
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_blocks_over_limit() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(5);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-test-block-key";

        // First 5 requests should be allowed
        for i in 0..5 {
            let (outcome, _) = limiter.check(key).await.unwrap();
            assert_eq!(
                outcome,
                RateLimitOutcome::Allowed,
                "Request {} should be allowed",
                i
            );
        }

        // 6th request should be limited
        let (outcome, count) = limiter.check(key).await.unwrap();
        assert_eq!(
            outcome,
            RateLimitOutcome::Limited,
            "Request 6 should be limited"
        );
        assert!(count > 5, "Count should be greater than limit");
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_separate_keys() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(3);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();

        // Exhaust limit for key A
        for _ in 0..3 {
            limiter.check("mc-key-a").await.unwrap();
        }
        let (outcome_a, _) = limiter.check("mc-key-a").await.unwrap();
        assert_eq!(outcome_a, RateLimitOutcome::Limited);

        // Key B should still be allowed
        let (outcome_b, _) = limiter.check("mc-key-b").await.unwrap();
        assert_eq!(outcome_b, RateLimitOutcome::Allowed);
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_window_expiry() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(5);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-test-expiry-key";

        // Exhaust limit
        for _ in 0..5 {
            limiter.check(key).await.unwrap();
        }
        let (outcome, _) = limiter.check(key).await.unwrap();
        assert_eq!(outcome, RateLimitOutcome::Limited);

        // Wait for TTL to expire (2 seconds + buffer)
        tokio::time::sleep(Duration::from_millis(2200)).await;

        // Should be allowed again
        let (outcome, _) = limiter.check(key).await.unwrap();
        assert_eq!(
            outcome,
            RateLimitOutcome::Allowed,
            "Should allow after TTL expiry"
        );
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_stats_tracking() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(3);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-test-stats-key";

        // Make 5 requests (3 allowed, 2 limited)
        for _ in 0..5 {
            let _ = limiter.check(key).await;
        }

        let stats = &limiter.stats;
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 5);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_memcached_rate_limiter_sequential_requests() {
        if !is_memcached_available().await {
            eprintln!("Skipping test: Memcached not available");
            return;
        }

        let (backend, rate) = test_memcached_config(100);
        let limiter = MemcachedRateLimiter::new(&backend, &rate).await.unwrap();
        let key = "mc-sequential-key";

        // Run 50 sequential requests (MemcachedRateLimiter is not Send due to RwLock guard)
        let mut allowed = 0;
        for _ in 0..50 {
            let result = limiter.check(key).await;
            assert!(result.is_ok(), "Request should not error");
            if result.unwrap().0 == RateLimitOutcome::Allowed {
                allowed += 1;
            }
        }

        // All 50 should be allowed (limit is 100)
        assert_eq!(allowed, 50, "All 50 requests should be allowed");
    }
}

#[cfg(feature = "distributed-rate-limit")]
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

// Tests that run without external dependencies
mod unit_tests {
    #[cfg(any(
        feature = "distributed-rate-limit",
        feature = "distributed-rate-limit-memcached"
    ))]
    use std::sync::atomic::Ordering;

    #[cfg(feature = "distributed-rate-limit")]
    use zentinel_proxy::distributed_rate_limit::DistributedRateLimitStats;

    #[cfg(feature = "distributed-rate-limit-memcached")]
    use zentinel_proxy::memcached_rate_limit::MemcachedRateLimitStats;

    #[cfg(any(
        feature = "distributed-rate-limit",
        feature = "distributed-rate-limit-memcached"
    ))]
    use zentinel_proxy::rate_limit::RateLimitOutcome;

    #[cfg(feature = "distributed-rate-limit")]
    #[test]
    fn test_distributed_stats_default() {
        let stats = DistributedRateLimitStats::default();
        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 0);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 0);
        assert_eq!(stats.redis_errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.local_fallbacks.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "distributed-rate-limit")]
    #[test]
    fn test_distributed_stats_record_allowed() {
        let stats = DistributedRateLimitStats::default();
        stats.record_check(RateLimitOutcome::Allowed);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 1);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "distributed-rate-limit")]
    #[test]
    fn test_distributed_stats_record_limited() {
        let stats = DistributedRateLimitStats::default();
        stats.record_check(RateLimitOutcome::Limited);

        assert_eq!(stats.total_checks.load(Ordering::Relaxed), 1);
        assert_eq!(stats.allowed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.limited.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "distributed-rate-limit")]
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
