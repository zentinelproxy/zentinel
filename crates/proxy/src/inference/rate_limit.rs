//! Token-based rate limiting for inference endpoints
//!
//! Provides dual-bucket rate limiting that tracks both:
//! - Tokens per minute (primary limit for LLM APIs)
//! - Requests per minute (secondary limit to prevent abuse)

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use zentinel_config::TokenRateLimit;

/// Result of a rate limit check
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRateLimitResult {
    /// Request is allowed
    Allowed,
    /// Token limit exceeded
    TokensExceeded {
        /// Milliseconds until retry is allowed
        retry_after_ms: u64,
    },
    /// Request limit exceeded
    RequestsExceeded {
        /// Milliseconds until retry is allowed
        retry_after_ms: u64,
    },
}

impl TokenRateLimitResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Get retry-after value in milliseconds (0 if allowed)
    pub fn retry_after_ms(&self) -> u64 {
        match self {
            Self::Allowed => 0,
            Self::TokensExceeded { retry_after_ms } => *retry_after_ms,
            Self::RequestsExceeded { retry_after_ms } => *retry_after_ms,
        }
    }
}

/// Token bucket for rate limiting
struct TokenBucket {
    /// Current token count
    tokens: AtomicU64,
    /// Maximum tokens (burst capacity)
    max_tokens: u64,
    /// Tokens added per millisecond
    refill_rate: f64,
    /// Last refill timestamp
    last_refill: std::sync::Mutex<Instant>,
}

impl TokenBucket {
    fn new(tokens_per_minute: u64, burst_tokens: u64) -> Self {
        // Calculate refill rate: tokens per millisecond
        let refill_rate = tokens_per_minute as f64 / 60_000.0;

        Self {
            tokens: AtomicU64::new(burst_tokens),
            max_tokens: burst_tokens,
            refill_rate,
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Try to consume tokens from the bucket
    fn try_consume(&self, amount: u64) -> Result<(), u64> {
        // First, refill based on elapsed time
        self.refill();

        // Try to consume
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current < amount {
                // Not enough tokens - calculate wait time
                let needed = amount - current;
                let wait_ms = (needed as f64 / self.refill_rate).ceil() as u64;
                return Err(wait_ms);
            }

            // Try to atomically subtract
            if self
                .tokens
                .compare_exchange(
                    current,
                    current - amount,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                return Ok(());
            }
            // CAS failed, retry
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);

        if elapsed.as_millis() > 0 {
            let refill_amount = (elapsed.as_millis() as f64 * self.refill_rate) as u64;
            if refill_amount > 0 {
                let current = self.tokens.load(Ordering::Acquire);
                let new_tokens = (current + refill_amount).min(self.max_tokens);
                self.tokens.store(new_tokens, Ordering::Release);
                *last = now;
            }
        }
    }

    /// Get current token count
    fn current_tokens(&self) -> u64 {
        self.refill();
        self.tokens.load(Ordering::Acquire)
    }
}

/// Token-based rate limiter for inference endpoints
///
/// Tracks rate limits per key (typically client IP or API key).
pub struct TokenRateLimiter {
    /// Token buckets per key
    token_buckets: DashMap<String, TokenBucket>,
    /// Request buckets per key (optional)
    request_buckets: Option<DashMap<String, TokenBucket>>,
    /// Configuration
    config: TokenRateLimit,
}

impl TokenRateLimiter {
    /// Create a new token rate limiter
    pub fn new(config: TokenRateLimit) -> Self {
        let request_buckets = config.requests_per_minute.map(|rpm| DashMap::new());

        Self {
            token_buckets: DashMap::new(),
            request_buckets,
            config,
        }
    }

    /// Check if a request is allowed
    ///
    /// Both token and request limits must pass for the request to be allowed.
    pub fn check(&self, key: &str, estimated_tokens: u64) -> TokenRateLimitResult {
        // Check token limit
        let token_bucket = self
            .token_buckets
            .entry(key.to_string())
            .or_insert_with(|| {
                TokenBucket::new(self.config.tokens_per_minute, self.config.burst_tokens)
            });

        if let Err(retry_ms) = token_bucket.try_consume(estimated_tokens) {
            trace!(
                key = key,
                estimated_tokens = estimated_tokens,
                retry_after_ms = retry_ms,
                "Token rate limit exceeded"
            );
            return TokenRateLimitResult::TokensExceeded {
                retry_after_ms: retry_ms,
            };
        }

        // Check request limit if configured
        if let (Some(rpm), Some(ref request_buckets)) =
            (self.config.requests_per_minute, &self.request_buckets)
        {
            let request_bucket = request_buckets.entry(key.to_string()).or_insert_with(|| {
                // For request limiting, use burst = rpm / 6 (10 second burst)
                let burst = rpm.max(1) / 6;
                TokenBucket::new(rpm, burst.max(1))
            });

            if let Err(retry_ms) = request_bucket.try_consume(1) {
                trace!(
                    key = key,
                    retry_after_ms = retry_ms,
                    "Request rate limit exceeded"
                );
                return TokenRateLimitResult::RequestsExceeded {
                    retry_after_ms: retry_ms,
                };
            }
        }

        trace!(
            key = key,
            estimated_tokens = estimated_tokens,
            "Rate limit check passed"
        );
        TokenRateLimitResult::Allowed
    }

    /// Record actual token usage after response
    ///
    /// This allows adjusting the bucket based on actual vs estimated usage.
    /// If actual < estimated, refund the difference.
    /// If actual > estimated, consume the extra (best effort).
    pub fn record_actual(&self, key: &str, actual_tokens: u64, estimated_tokens: u64) {
        if let Some(bucket) = self.token_buckets.get(key) {
            if actual_tokens < estimated_tokens {
                // Refund over-estimation
                let refund = estimated_tokens - actual_tokens;
                let current = bucket.tokens.load(Ordering::Acquire);
                let new_tokens = (current + refund).min(bucket.max_tokens);
                bucket.tokens.store(new_tokens, Ordering::Release);

                debug!(
                    key = key,
                    actual = actual_tokens,
                    estimated = estimated_tokens,
                    refund = refund,
                    "Refunded over-estimated tokens"
                );
            } else if actual_tokens > estimated_tokens {
                // Under-estimation - try to consume extra (don't block)
                let extra = actual_tokens - estimated_tokens;
                let current = bucket.tokens.load(Ordering::Acquire);
                let to_consume = extra.min(current);
                if to_consume > 0 {
                    bucket.tokens.fetch_sub(to_consume, Ordering::AcqRel);
                }

                debug!(
                    key = key,
                    actual = actual_tokens,
                    estimated = estimated_tokens,
                    consumed_extra = to_consume,
                    "Consumed under-estimated tokens"
                );
            }
        }
    }

    /// Get current token count for a key
    pub fn current_tokens(&self, key: &str) -> Option<u64> {
        self.token_buckets.get(key).map(|b| b.current_tokens())
    }

    /// Get stats for metrics
    pub fn stats(&self) -> TokenRateLimiterStats {
        TokenRateLimiterStats {
            active_keys: self.token_buckets.len(),
            tokens_per_minute: self.config.tokens_per_minute,
            requests_per_minute: self.config.requests_per_minute,
        }
    }
}

/// Stats for the token rate limiter
#[derive(Debug, Clone)]
pub struct TokenRateLimiterStats {
    /// Number of active rate limit keys
    pub active_keys: usize,
    /// Configured tokens per minute
    pub tokens_per_minute: u64,
    /// Configured requests per minute (if any)
    pub requests_per_minute: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::TokenEstimation;

    fn test_config() -> TokenRateLimit {
        TokenRateLimit {
            tokens_per_minute: 1000,
            requests_per_minute: Some(10),
            burst_tokens: 200,
            estimation_method: TokenEstimation::Chars,
        }
    }

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = TokenRateLimiter::new(test_config());

        // First request should succeed
        let result = limiter.check("test-key", 50);
        assert!(result.is_allowed());

        // Should still have tokens
        let current = limiter.current_tokens("test-key").unwrap();
        assert!(current > 0);
    }

    #[test]
    fn test_token_exhaustion() {
        let limiter = TokenRateLimiter::new(test_config());

        // Exhaust tokens
        for _ in 0..4 {
            let _ = limiter.check("test-key", 50);
        }

        // This should exceed the 200 burst tokens
        let result = limiter.check("test-key", 50);
        assert!(!result.is_allowed());
        assert!(matches!(
            result,
            TokenRateLimitResult::TokensExceeded { .. }
        ));
    }

    #[test]
    fn test_actual_token_refund() {
        let limiter = TokenRateLimiter::new(test_config());

        // Consume with high estimate
        let _ = limiter.check("test-key", 100);
        let before = limiter.current_tokens("test-key").unwrap();

        // Record actual as lower
        limiter.record_actual("test-key", 50, 100);
        let after = limiter.current_tokens("test-key").unwrap();

        // Should have refunded 50 tokens
        assert!(after > before);
    }
}
