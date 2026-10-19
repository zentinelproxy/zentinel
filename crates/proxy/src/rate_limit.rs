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
use prometheus::{register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, trace, warn};

use zentinel_config::{RateLimitAction, RateLimitBackend, RateLimitKey};

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

/// Detailed rate limit check result from a pool
#[derive(Debug, Clone)]
pub struct RateLimitCheckInfo {
    /// Whether the request is allowed or limited
    pub outcome: RateLimitOutcome,
    /// Current request count in the window
    pub current_count: i64,
    /// Maximum requests allowed per window
    pub limit: u32,
    /// Remaining requests in current window (0 if over limit)
    pub remaining: u32,
    /// Unix timestamp (seconds) when the window resets
    pub reset_at: u64,
    /// How long until the next request would be allowed, when the backend
    /// knows exactly (the local token bucket does). `None` falls back to
    /// estimating it from `current_count` and `limit`.
    pub retry_after_ms: Option<u64>,
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
    /// Maximum delay in milliseconds for Delay action
    pub max_delay_ms: u64,
    /// Maximum number of distinct keys tracked in memory
    pub max_keys: usize,
}

/// Default bound on distinct rate-limit keys tracked per pool.
pub const DEFAULT_MAX_RATE_LIMIT_KEYS: usize = 100_000;

/// Keys not seen within this many seconds are considered idle and evictable.
/// Rate windows are 1 second, so any state older than this is meaningless.
const IDLE_KEY_TTL_SECS: u64 = 10;

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
            max_delay_ms: 5000,
            max_keys: DEFAULT_MAX_RATE_LIMIT_KEYS,
        }
    }
}

/// Per-key token bucket.
///
/// Holds up to `burst` tokens and refills at `max_rps` tokens per second;
/// each request takes one. That is what `max-rps` and `burst` are documented
/// to mean ("token bucket", "burst: token bucket size"). The previous limiter
/// counted requests in a one-second window and ignored `burst` entirely, so
/// `burst` changed nothing for route filters, `global` or `default-burst`.
struct KeyRateLimiter {
    bucket: parking_lot::Mutex<Bucket>,
    /// Bucket size
    capacity: f64,
    /// Tokens added per second
    refill_per_sec: f64,
    /// Unix timestamp (seconds) of the last check, for idle eviction
    last_seen: AtomicU64,
}

struct Bucket {
    tokens: f64,
    refilled_at: std::time::Instant,
}

/// Result of taking a token from a [`KeyRateLimiter`].
struct BucketCheck {
    outcome: RateLimitOutcome,
    /// Whole tokens left after this request
    remaining: u32,
    /// Tokens in use (bucket size minus what is left), for logs
    used: i64,
    /// Milliseconds until a token is available (0 when one is)
    retry_after_ms: u64,
    /// Milliseconds until the bucket is full again
    refill_ms: u64,
}

impl KeyRateLimiter {
    fn new(max_rps: u32, burst: u32) -> Self {
        // A bucket smaller than one token could never admit anything.
        let capacity = f64::from(burst.max(1));
        Self {
            bucket: parking_lot::Mutex::new(Bucket {
                tokens: capacity,
                refilled_at: std::time::Instant::now(),
            }),
            capacity,
            refill_per_sec: f64::from(max_rps),
            last_seen: AtomicU64::new(current_unix_timestamp()),
        }
    }

    fn touch(&self) {
        self.last_seen
            .store(current_unix_timestamp(), Ordering::Relaxed);
    }

    fn idle_secs(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_seen.load(Ordering::Relaxed))
    }

    fn ms_for(&self, tokens: f64) -> u64 {
        if tokens <= 0.0 {
            0
        } else if self.refill_per_sec <= 0.0 {
            u64::MAX / 2
        } else {
            (tokens / self.refill_per_sec * 1000.0).ceil() as u64
        }
    }

    /// Take a token if one is available
    fn check(&self) -> BucketCheck {
        let mut bucket = self.bucket.lock();
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(bucket.refilled_at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.refilled_at = now;

        let outcome = if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            RateLimitOutcome::Allowed
        } else {
            RateLimitOutcome::Limited
        };

        BucketCheck {
            outcome,
            remaining: bucket.tokens.floor() as u32,
            used: (self.capacity - bucket.tokens).ceil() as i64,
            retry_after_ms: self.ms_for(1.0 - bucket.tokens),
            refill_ms: self.ms_for(self.capacity - bucket.tokens),
        }
    }

    /// Check a request and describe the result
    fn check_info(&self, max_rps: u32) -> RateLimitCheckInfo {
        self.touch();
        let check = self.check();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis() as u64;
        // When limited, the window "resets" when the next token arrives (this
        // drives Retry-After); otherwise when the bucket is full again.
        let until_ms = if check.outcome == RateLimitOutcome::Limited {
            check.retry_after_ms
        } else {
            check.refill_ms
        };
        RateLimitCheckInfo {
            outcome: check.outcome,
            current_count: check.used,
            limit: max_rps,
            remaining: check.remaining,
            reset_at: (now_ms + until_ms).div_ceil(1000).max(now_ms / 1000 + 1),
            retry_after_ms: (check.outcome == RateLimitOutcome::Limited)
                .then_some(check.retry_after_ms),
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
    /// Scope label for metrics (route ID or "global")
    scope: String,
    /// Guard so only one task sweeps the key map at a time
    sweeping: AtomicBool,
}

/// Prometheus metrics for rate limiter key maps.
struct RateLimitPoolMetrics {
    /// Distinct keys currently tracked, per scope
    keys: IntGaugeVec,
    /// Keys evicted to enforce the max-keys bound, per scope
    evictions: IntCounterVec,
}

static POOL_METRICS: LazyLock<Option<RateLimitPoolMetrics>> = LazyLock::new(|| {
    let keys = register_int_gauge_vec!(
        "zentinel_rate_limit_keys",
        "Distinct rate-limit keys currently tracked in memory",
        &["scope"]
    )
    .ok()?;
    let evictions = register_int_counter_vec!(
        "zentinel_rate_limit_key_evictions_total",
        "Rate-limit keys evicted to enforce the max-keys bound",
        &["scope"]
    )
    .ok()?;
    Some(RateLimitPoolMetrics { keys, evictions })
});

/// Get current unix timestamp in seconds
fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Calculate window reset timestamp (next second boundary for 1-second windows)
fn calculate_reset_timestamp() -> u64 {
    current_unix_timestamp() + 1
}

impl RateLimiterPool {
    /// Create a new rate limiter pool with the given configuration (local backend)
    pub fn new(config: RateLimitConfig) -> Self {
        Self::with_scope(config, "default")
    }

    /// Create a new rate limiter pool with a metrics scope (route ID or "global")
    pub fn with_scope(config: RateLimitConfig, scope: impl Into<String>) -> Self {
        Self {
            backend: RateLimitBackendType::Local {
                limiters: DashMap::new(),
            },
            config: RwLock::new(config),
            scope: scope.into(),
            sweeping: AtomicBool::new(false),
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
            scope: "default".to_string(),
            sweeping: AtomicBool::new(false),
        }
    }

    /// Check if a request should be rate limited (synchronous, local only)
    ///
    /// Returns detailed rate limit information including remaining quota.
    /// For distributed backends, this falls back to local limiting.
    pub fn check(&self, key: &str) -> RateLimitCheckInfo {
        let config = self.config.read();
        let max_rps = config.max_rps;
        let burst = config.burst;
        let max_keys = config.max_keys;
        drop(config);

        let limiters = match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters,
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback,
        };

        // Get or create limiter for this key, enforcing the key-map bound
        let limiter = self.get_or_create_limiter(limiters, key, max_rps, burst, max_keys);
        limiter.check_info(max_rps)
    }

    /// Check if a request should be rate limited (async, supports distributed backends)
    ///
    /// Returns detailed rate limit information including remaining quota.
    #[cfg(feature = "distributed-rate-limit")]
    pub async fn check_async(&self, key: &str) -> RateLimitCheckInfo {
        let max_rps = self.config.read().max_rps;

        match &self.backend {
            RateLimitBackendType::Local { .. } => self.check(key),
            RateLimitBackendType::Distributed {
                redis,
                local_fallback,
            } => {
                // Try Redis first
                match redis.check(key).await {
                    Ok((outcome, count)) => {
                        let remaining = if count >= max_rps as i64 {
                            0
                        } else {
                            (max_rps as i64 - count) as u32
                        };
                        RateLimitCheckInfo {
                            outcome,
                            current_count: count,
                            limit: max_rps,
                            remaining,
                            reset_at: calculate_reset_timestamp(),
                            retry_after_ms: None,
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            key = key,
                            "Redis rate limit check failed, falling back to local"
                        );
                        redis.mark_unhealthy();

                        // Fallback to local
                        if redis.fallback_enabled() {
                            let (burst, max_keys) = {
                                let config = self.config.read();
                                (config.burst, config.max_keys)
                            };
                            let limiter = self.get_or_create_limiter(
                                local_fallback,
                                key,
                                max_rps,
                                burst,
                                max_keys,
                            );
                            limiter.check_info(max_rps)
                        } else {
                            // Fail open if no fallback
                            RateLimitCheckInfo {
                                outcome: RateLimitOutcome::Allowed,
                                current_count: 0,
                                limit: max_rps,
                                remaining: max_rps,
                                reset_at: calculate_reset_timestamp(),
                                retry_after_ms: None,
                            }
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

    /// Whether this limiter is keyed on something only the request body can
    /// supply, and so cannot be evaluated until the body has been parsed.
    pub fn needs_request_body(&self) -> bool {
        matches!(
            self.config.read().key,
            RateLimitKey::McpTool | RateLimitKey::ClientIpAndMcpTool
        )
    }

    /// Get the rate limit key from request context.
    ///
    /// `mcp_tool` is the tool or resource resolved **from the request body** by
    /// the MCP policy engine, and is `None` before the body has been read. Only
    /// the MCP-keyed variants consult it; see [`Self::needs_request_body`].
    pub fn extract_key(
        &self,
        client_ip: &str,
        path: &str,
        route_id: &str,
        headers: Option<&impl HeaderAccessor>,
        mcp_tool: Option<&str>,
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
            // A request that names no tool -- `initialize`, `tools/list`, or a
            // body that could not be parsed -- shares one bucket rather than
            // escaping the limit.
            RateLimitKey::McpTool => mcp_tool.unwrap_or("unknown").to_string(),
            RateLimitKey::ClientIpAndMcpTool => {
                format!("{}:{}", client_ip, mcp_tool.unwrap_or("unknown"))
            }
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

    /// Get the maximum delay in milliseconds for Delay action
    pub fn max_delay_ms(&self) -> u64 {
        self.config.read().max_delay_ms
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

    /// Get or create the limiter for a key, enforcing the `max_keys` bound.
    ///
    /// When the map is at capacity and a new key arrives, idle entries (not
    /// seen within [`IDLE_KEY_TTL_SECS`]) are swept first; if the map is still
    /// at capacity, the longest-idle entries are evicted down to 90% of the
    /// bound and an eviction metric is incremented.
    fn get_or_create_limiter(
        &self,
        limiters: &DashMap<String, Arc<KeyRateLimiter>>,
        key: &str,
        max_rps: u32,
        burst: u32,
        max_keys: usize,
    ) -> Arc<KeyRateLimiter> {
        if let Some(limiter) = limiters.get(key) {
            return limiter.clone();
        }

        if limiters.len() >= max_keys {
            self.evict_keys(limiters, max_keys);
        }

        let limiter = limiters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(KeyRateLimiter::new(max_rps, burst)))
            .clone();

        if let Some(metrics) = POOL_METRICS.as_ref() {
            metrics
                .keys
                .with_label_values(&[&self.scope])
                .set(limiters.len() as i64);
        }

        limiter
    }

    /// Evict entries so a new key can be admitted without exceeding `max_keys`.
    fn evict_keys(&self, limiters: &DashMap<String, Arc<KeyRateLimiter>>, max_keys: usize) {
        // Only one task sweeps at a time; concurrent inserts may briefly
        // overshoot the bound by the number of racing requests.
        if self
            .sweeping
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let now = current_unix_timestamp();
        let before = limiters.len();

        // First pass: drop idle entries (their 1s window state is stale anyway)
        limiters.retain(|_, limiter| limiter.idle_secs(now) <= IDLE_KEY_TTL_SECS);

        // Second pass: still at capacity means all keys are active; evict the
        // longest-idle entries down to 90% so inserts don't thrash the sweep.
        if limiters.len() >= max_keys {
            // Floor and stay below the cap so the pending insert never pushes
            // the map past max_keys (div_ceil would leave target == max_keys
            // for small caps and evict nothing).
            let target = ((max_keys * 9) / 10).min(max_keys.saturating_sub(1));
            let mut entries: Vec<(String, u64)> = limiters
                .iter()
                .map(|e| (e.key().clone(), e.value().idle_secs(now)))
                .collect();
            // Most idle first
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (key, _) in entries.iter().take(limiters.len().saturating_sub(target)) {
                limiters.remove(key);
            }
        }

        let evicted = before.saturating_sub(limiters.len());
        if evicted > 0 {
            warn!(
                scope = %self.scope,
                evicted = evicted,
                remaining = limiters.len(),
                max_keys = max_keys,
                "Rate limiter key map at capacity, evicted entries"
            );
            if let Some(metrics) = POOL_METRICS.as_ref() {
                metrics
                    .evictions
                    .with_label_values(&[&self.scope])
                    .inc_by(evicted as u64);
                metrics
                    .keys
                    .with_label_values(&[&self.scope])
                    .set(limiters.len() as i64);
            }
        }

        self.sweeping.store(false, Ordering::Release);
    }

    /// Clean up idle entries (call periodically)
    pub fn cleanup(&self) {
        let limiters = match &self.backend {
            RateLimitBackendType::Local { limiters } => limiters,
            #[cfg(feature = "distributed-rate-limit")]
            RateLimitBackendType::Distributed { local_fallback, .. } => local_fallback,
        };

        let now = current_unix_timestamp();
        let before = limiters.len();
        limiters.retain(|_, limiter| limiter.idle_secs(now) <= IDLE_KEY_TTL_SECS);

        if let Some(metrics) = POOL_METRICS.as_ref() {
            metrics
                .keys
                .with_label_values(&[&self.scope])
                .set(limiters.len() as i64);
        }

        if before != limiters.len() {
            debug!(
                scope = %self.scope,
                removed = before - limiters.len(),
                remaining = limiters.len(),
                "Rate limiter pool cleanup completed"
            );
        }
    }
}

/// Trait for accessing headers (allows abstracting over different header types)
pub trait HeaderAccessor {
    fn get_header(&self, name: &str) -> Option<String>;
}

/// Stands in where a limiter provably cannot consult headers.
///
/// The body-keyed path never reads them: its key comes from the parsed body.
/// `extract_key` is generic over the accessor, so it still needs a type to
/// instantiate with.
struct NoHeaders;

impl HeaderAccessor for NoHeaders {
    fn get_header(&self, _name: &str) -> Option<String> {
        None
    }
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
            max_delay_ms: 5000,
            max_keys: DEFAULT_MAX_RATE_LIMIT_KEYS,
        };
        Self {
            route_limiters: DashMap::new(),
            global_limiter: Some(Arc::new(RateLimiterPool::with_scope(config, "global"))),
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

        self.route_limiters.insert(
            route_id.to_string(),
            Arc::new(RateLimiterPool::with_scope(config, route_id)),
        );
    }

    /// Check if a request should be rate limited
    ///
    /// Checks both global and route-specific limits.
    /// Returns detailed rate limit information for response headers.
    /// Evaluate the limiters that key on something only the body supplies.
    ///
    /// The counterpart to [`Self::check`], which skips these. Called once the
    /// MCP policy engine has resolved the tool **from the request body** --
    /// never from the mirrored `Mcp-Name` header, which a client can set to
    /// anything while the body calls something else.
    ///
    /// Returns `None` when this route has no body-keyed limiter, which is the
    /// common case and stays free.
    pub fn check_body_keyed(
        &self,
        route_id: &str,
        client_ip: &str,
        path: &str,
        mcp_tool: Option<&str>,
    ) -> Option<RateLimitResult> {
        let pool = self
            .route_limiters
            .get(route_id)
            .filter(|p| p.needs_request_body())?;

        let key = pool.extract_key(
            client_ip,
            path,
            route_id,
            Option::<&NoHeaders>::None,
            mcp_tool,
        );
        let check_info = pool.check(&key);

        if check_info.outcome == RateLimitOutcome::Limited {
            warn!(
                route_id = route_id,
                client_ip = client_ip,
                key = key,
                mcp_tool = ?mcp_tool,
                count = check_info.current_count,
                "Request rate limited by MCP tool limiter"
            );
            let suggested_delay_ms = if let Some(ms) = check_info.retry_after_ms {
                Some(ms)
            } else if check_info.current_count > check_info.limit as i64 {
                let excess = check_info.current_count - check_info.limit as i64;
                Some((excess as u64 * 1000) / check_info.limit as u64)
            } else {
                None
            };
            return Some(RateLimitResult {
                allowed: false,
                action: pool.action(),
                status_code: pool.status_code(),
                message: pool.message(),
                limiter: route_id.to_string(),
                limit: check_info.limit,
                remaining: check_info.remaining,
                reset_at: check_info.reset_at,
                suggested_delay_ms,
                max_delay_ms: pool.max_delay_ms(),
            });
        }

        trace!(
            route_id = route_id,
            key = key,
            mcp_tool = ?mcp_tool,
            remaining = check_info.remaining,
            "Request allowed by MCP tool limiter"
        );
        None
    }

    pub fn check(
        &self,
        route_id: &str,
        client_ip: &str,
        path: &str,
        headers: Option<&impl HeaderAccessor>,
    ) -> RateLimitResult {
        // Track the most restrictive limit info for headers
        let mut best_limit_info: Option<RateLimitCheckInfo> = None;

        // Check global limit first. A limiter keyed on the request body is
        // deferred to `check_body_keyed` -- evaluating it here would key on
        // "unknown" and burn the request's quota against the wrong bucket.
        if let Some(global) = self
            .global_limiter
            .as_ref()
            .filter(|g| !g.needs_request_body())
        {
            let key = global.extract_key(client_ip, path, route_id, headers, None);
            let check_info = global.check(&key);

            if check_info.outcome == RateLimitOutcome::Limited {
                warn!(
                    route_id = route_id,
                    client_ip = client_ip,
                    key = key,
                    count = check_info.current_count,
                    "Request rate limited by global limiter"
                );
                // Calculate suggested delay based on how far over limit
                let suggested_delay_ms = if let Some(ms) = check_info.retry_after_ms {
                    Some(ms)
                } else if check_info.current_count > check_info.limit as i64 {
                    let excess = check_info.current_count - check_info.limit as i64;
                    Some((excess as u64 * 1000) / check_info.limit as u64)
                } else {
                    None
                };
                return RateLimitResult {
                    allowed: false,
                    action: global.action(),
                    status_code: global.status_code(),
                    message: global.message(),
                    limiter: "global".to_string(),
                    limit: check_info.limit,
                    remaining: check_info.remaining,
                    reset_at: check_info.reset_at,
                    suggested_delay_ms,
                    max_delay_ms: global.max_delay_ms(),
                };
            }

            best_limit_info = Some(check_info);
        }

        // Check route-specific limit, same deferral as above.
        if let Some(pool) = self
            .route_limiters
            .get(route_id)
            .filter(|p| !p.needs_request_body())
        {
            let key = pool.extract_key(client_ip, path, route_id, headers, None);
            let check_info = pool.check(&key);

            if check_info.outcome == RateLimitOutcome::Limited {
                warn!(
                    route_id = route_id,
                    client_ip = client_ip,
                    key = key,
                    count = check_info.current_count,
                    "Request rate limited by route limiter"
                );
                // Calculate suggested delay based on how far over limit
                let suggested_delay_ms = if let Some(ms) = check_info.retry_after_ms {
                    Some(ms)
                } else if check_info.current_count > check_info.limit as i64 {
                    let excess = check_info.current_count - check_info.limit as i64;
                    Some((excess as u64 * 1000) / check_info.limit as u64)
                } else {
                    None
                };
                return RateLimitResult {
                    allowed: false,
                    action: pool.action(),
                    status_code: pool.status_code(),
                    message: pool.message(),
                    limiter: route_id.to_string(),
                    limit: check_info.limit,
                    remaining: check_info.remaining,
                    reset_at: check_info.reset_at,
                    suggested_delay_ms,
                    max_delay_ms: pool.max_delay_ms(),
                };
            }

            trace!(
                route_id = route_id,
                key = key,
                count = check_info.current_count,
                remaining = check_info.remaining,
                "Request allowed by rate limiter"
            );

            // Use the more restrictive limit info (lower remaining)
            if let Some(ref existing) = best_limit_info {
                if check_info.remaining < existing.remaining {
                    best_limit_info = Some(check_info);
                }
            } else {
                best_limit_info = Some(check_info);
            }
        }

        // Return allowed with rate limit info for headers
        let (limit, remaining, reset_at) = best_limit_info
            .map(|info| (info.limit, info.remaining, info.reset_at))
            .unwrap_or((0, 0, 0));

        RateLimitResult {
            allowed: true,
            action: RateLimitAction::Reject,
            status_code: 429,
            message: None,
            limiter: String::new(),
            limit,
            remaining,
            reset_at,
            suggested_delay_ms: None,
            max_delay_ms: 5000, // Default max delay for allowed requests (unused)
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
    /// Whether this route has a limiter of its own (not counting the global one)
    pub fn has_route_specific_limiter(&self, route_id: &str) -> bool {
        self.route_limiters.contains_key(route_id)
    }

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
    /// Maximum requests allowed per window
    pub limit: u32,
    /// Remaining requests in current window
    pub remaining: u32,
    /// Unix timestamp (seconds) when the window resets
    pub reset_at: u64,
    /// Suggested delay in milliseconds (for Delay action)
    pub suggested_delay_ms: Option<u64>,
    /// Maximum delay in milliseconds (configured cap for Delay action)
    pub max_delay_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let config = RateLimitConfig {
            max_rps: 10,
            burst: 10,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Should allow first 10 requests
        for i in 0..10 {
            let info = pool.check("127.0.0.1");
            assert_eq!(info.outcome, RateLimitOutcome::Allowed);
            assert_eq!(info.limit, 10);
            assert_eq!(info.remaining, 10 - i - 1);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let config = RateLimitConfig {
            max_rps: 5,
            burst: 5,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Should allow first 5 requests
        for _ in 0..5 {
            let info = pool.check("127.0.0.1");
            assert_eq!(info.outcome, RateLimitOutcome::Allowed);
        }

        // 6th request should be limited
        let info = pool.check("127.0.0.1");
        assert_eq!(info.outcome, RateLimitOutcome::Limited);
        assert_eq!(info.remaining, 0);
    }

    #[test]
    fn test_rate_limiter_separate_keys() {
        let config = RateLimitConfig {
            max_rps: 2,
            burst: 2,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Each IP gets its own bucket
        let info1 = pool.check("192.168.1.1");
        let info2 = pool.check("192.168.1.2");
        let info3 = pool.check("192.168.1.1");
        let info4 = pool.check("192.168.1.2");

        assert_eq!(info1.outcome, RateLimitOutcome::Allowed);
        assert_eq!(info2.outcome, RateLimitOutcome::Allowed);
        assert_eq!(info3.outcome, RateLimitOutcome::Allowed);
        assert_eq!(info4.outcome, RateLimitOutcome::Allowed);

        // Both should hit limit now
        let info5 = pool.check("192.168.1.1");
        let info6 = pool.check("192.168.1.2");

        assert_eq!(info5.outcome, RateLimitOutcome::Limited);
        assert_eq!(info6.outcome, RateLimitOutcome::Limited);
    }

    #[test]
    fn test_rate_limit_info_fields() {
        let config = RateLimitConfig {
            max_rps: 5,
            burst: 5,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        let info = pool.check("10.0.0.1");
        assert_eq!(info.limit, 5);
        assert_eq!(info.remaining, 4); // 5 - 1 = 4
        assert!(info.reset_at > 0);
        assert_eq!(info.outcome, RateLimitOutcome::Allowed);
    }

    #[test]
    fn test_rate_limit_manager() {
        let manager = RateLimitManager::new();

        manager.register_route(
            "api",
            RateLimitConfig {
                max_rps: 5,
                burst: 5,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // Route without limiter should always pass (no rate limit info)
        let result = manager.check("web", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(result.allowed);
        assert_eq!(result.limit, 0); // No limiter configured

        // Route with limiter should enforce limits and return rate limit info
        for i in 0..5 {
            let result = manager.check("api", "127.0.0.1", "/api/test", Option::<&NoHeaders>::None);
            assert!(result.allowed);
            assert_eq!(result.limit, 5);
            assert_eq!(result.remaining, 5 - i as u32 - 1);
        }

        let result = manager.check("api", "127.0.0.1", "/api/test", Option::<&NoHeaders>::None);
        assert!(!result.allowed);
        assert_eq!(result.status_code, 429);
        assert_eq!(result.limit, 5);
        assert_eq!(result.remaining, 0);
        assert!(result.reset_at > 0);
    }

    #[test]
    fn test_rate_limit_result_with_delay() {
        let manager = RateLimitManager::new();

        manager.register_route(
            "api",
            RateLimitConfig {
                max_rps: 2,
                burst: 2,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // Use up the limit
        manager.check("api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        manager.check("api", "127.0.0.1", "/", Option::<&NoHeaders>::None);

        // Third request should be limited with suggested delay
        let result = manager.check("api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result.allowed);
        assert!(result.suggested_delay_ms.is_some());
    }

    // Helper type for tests that don't need header access
    struct NoHeaders;
    impl HeaderAccessor for NoHeaders {
        fn get_header(&self, _name: &str) -> Option<String> {
            None
        }
    }

    #[test]
    fn test_global_rate_limiter() {
        let manager = RateLimitManager::with_global_limit(3, 3);

        // Global limiter should apply to all routes
        for i in 0..3 {
            let result = manager.check("any-route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
            assert!(result.allowed, "Request {} should be allowed", i);
            assert_eq!(result.limit, 3);
            assert_eq!(result.remaining, 3 - i as u32 - 1);
        }

        // 4th request should be blocked by global limiter
        let result = manager.check(
            "different-route",
            "127.0.0.1",
            "/",
            Option::<&NoHeaders>::None,
        );
        assert!(!result.allowed);
        assert_eq!(result.limiter, "global");
    }

    #[test]
    fn test_global_and_route_limiters() {
        let manager = RateLimitManager::with_global_limit(10, 10);

        // Register a more restrictive route limiter
        manager.register_route(
            "strict-api",
            RateLimitConfig {
                max_rps: 2,
                burst: 2,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // Route limiter should trigger first (more restrictive)
        let result1 = manager.check("strict-api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        let result2 = manager.check("strict-api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(result1.allowed);
        assert!(result2.allowed);

        // 3rd request should be blocked by route limiter
        let result3 = manager.check("strict-api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result3.allowed);
        assert_eq!(result3.limiter, "strict-api");

        // Different route should still work (global not exhausted)
        let result4 = manager.check("other-route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(result4.allowed);
    }

    #[test]
    fn test_suggested_delay_calculation() {
        let manager = RateLimitManager::new();

        manager.register_route(
            "api",
            RateLimitConfig {
                max_rps: 10,
                burst: 10,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // Exhaust the limit
        for _ in 0..10 {
            manager.check("api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        }

        // Requests over limit should have suggested delay
        let result = manager.check("api", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result.allowed);
        assert!(result.suggested_delay_ms.is_some());

        // Delay should be proportional to how far over limit
        // Formula: (excess * 1000) / limit
        // With 1 excess request and limit of 10: (1 * 1000) / 10 = 100ms
        let delay = result.suggested_delay_ms.unwrap();
        assert!(delay > 0, "Delay should be positive");
        assert!(delay <= 1000, "Delay should be reasonable");
    }

    #[test]
    fn test_reset_timestamp_is_future() {
        let config = RateLimitConfig {
            max_rps: 5,
            burst: 5,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        let info = pool.check("10.0.0.1");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Reset timestamp should be in the future (within the next second)
        assert!(info.reset_at >= now, "Reset time should be >= now");
        assert!(
            info.reset_at <= now + 2,
            "Reset time should be within 2 seconds"
        );
    }

    #[test]
    fn test_rate_limit_check_info_remaining_clamps_to_zero() {
        let config = RateLimitConfig {
            max_rps: 2,
            burst: 2,
            key: RateLimitKey::ClientIp,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Exhaust the limit
        pool.check("10.0.0.1");
        pool.check("10.0.0.1");

        // Over-limit requests should show remaining as 0, not negative
        let info = pool.check("10.0.0.1");
        assert_eq!(info.remaining, 0);
        assert_eq!(info.outcome, RateLimitOutcome::Limited);
    }

    #[test]
    fn test_rate_limit_result_fields() {
        // Create a result by checking a rate limited request
        let manager = RateLimitManager::new();
        manager.register_route(
            "test",
            RateLimitConfig {
                max_rps: 1,
                burst: 1,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );

        // First request allowed
        let allowed_result = manager.check("test", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(allowed_result.allowed);
        assert_eq!(allowed_result.limit, 1);
        assert!(allowed_result.reset_at > 0);

        // Second request should be blocked
        let blocked_result = manager.check("test", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!blocked_result.allowed);
        assert_eq!(blocked_result.status_code, 429);
        assert_eq!(blocked_result.remaining, 0);
    }

    #[test]
    fn test_has_route_limiter() {
        let manager = RateLimitManager::new();
        assert!(!manager.has_route_limiter("test-route"));

        manager.register_route(
            "test-route",
            RateLimitConfig {
                max_rps: 10,
                burst: 10,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );
        assert!(manager.has_route_limiter("test-route"));
        assert!(!manager.has_route_limiter("other-route"));
    }

    #[test]
    fn test_global_limiter_is_enabled() {
        let manager = RateLimitManager::with_global_limit(100, 100);
        // Global limiter should be enabled
        assert!(manager.is_enabled());
    }

    #[test]
    fn test_is_enabled() {
        let empty_manager = RateLimitManager::new();
        assert!(!empty_manager.is_enabled());

        let global_manager = RateLimitManager::with_global_limit(100, 100);
        assert!(global_manager.is_enabled());

        let route_manager = RateLimitManager::new();
        route_manager.register_route(
            "test",
            RateLimitConfig {
                max_rps: 10,
                burst: 10,
                key: RateLimitKey::ClientIp,
                ..Default::default()
            },
        );
        assert!(route_manager.is_enabled());
    }

    fn pool_key_count(pool: &RateLimiterPool) -> usize {
        pool.local_limiter_count()
    }

    #[test]
    fn key_map_never_exceeds_max_keys() {
        let config = RateLimitConfig {
            max_rps: 100,
            max_keys: 10,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        for i in 0..100 {
            pool.check(&format!("client-{i}"));
        }

        // Active keys force second-pass eviction down to ~90% of the cap, so
        // the map may hold at most max_keys entries (cap + the new insert - evictions)
        assert!(
            pool_key_count(&pool) <= 10,
            "key map grew past max_keys: {}",
            pool_key_count(&pool)
        );
    }

    #[test]
    fn eviction_keeps_recently_seen_keys_usable() {
        let config = RateLimitConfig {
            max_rps: 2,
            burst: 2,
            max_keys: 5,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        // Saturate one key to its limit
        pool.check("hot");
        pool.check("hot");
        assert_eq!(pool.check("hot").outcome, RateLimitOutcome::Limited);

        // Flood with new keys to force eviction; limiter must keep functioning
        for i in 0..50 {
            let info = pool.check(&format!("cold-{i}"));
            assert_eq!(info.outcome, RateLimitOutcome::Allowed);
        }
        assert!(pool_key_count(&pool) <= 5);
    }

    #[test]
    fn cleanup_retains_active_keys() {
        let config = RateLimitConfig {
            max_rps: 100,
            max_keys: 100,
            ..Default::default()
        };
        let pool = RateLimiterPool::new(config);

        pool.check("active");
        pool.cleanup();

        // Key was just seen, so periodic cleanup must not remove it
        assert_eq!(pool_key_count(&pool), 1);
    }
}

#[cfg(test)]
mod mcp_tool_key_tests {
    use super::*;
    use zentinel_config::RateLimitKey;

    fn pool_keyed(key: RateLimitKey, max_rps: u32) -> RateLimiterPool {
        RateLimiterPool::new(RateLimitConfig {
            max_rps,
            burst: max_rps,
            key,
            ..Default::default()
        })
    }

    #[test]
    fn only_the_mcp_keys_need_the_body() {
        for key in [RateLimitKey::McpTool, RateLimitKey::ClientIpAndMcpTool] {
            assert!(pool_keyed(key, 10).needs_request_body());
        }
        for key in [
            RateLimitKey::ClientIp,
            RateLimitKey::Path,
            RateLimitKey::Route,
            RateLimitKey::ClientIpAndPath,
            RateLimitKey::Header("x-api-key".into()),
        ] {
            assert!(!pool_keyed(key, 10).needs_request_body());
        }
    }

    #[test]
    fn the_key_is_the_tool_from_the_body() {
        let pool = pool_keyed(RateLimitKey::McpTool, 10);
        let key = pool.extract_key(
            "10.0.0.1",
            "/mcp",
            "api",
            Option::<&NoHeaders>::None,
            Some("delete_everything"),
        );
        assert_eq!(key, "delete_everything");
    }

    #[test]
    fn the_combined_key_separates_clients() {
        let pool = pool_keyed(RateLimitKey::ClientIpAndMcpTool, 10);
        let a = pool.extract_key(
            "10.0.0.1",
            "/mcp",
            "api",
            Option::<&NoHeaders>::None,
            Some("search"),
        );
        let b = pool.extract_key(
            "10.0.0.2",
            "/mcp",
            "api",
            Option::<&NoHeaders>::None,
            Some("search"),
        );
        assert_ne!(a, b, "two clients calling one tool must not share a bucket");
    }

    #[test]
    fn a_request_naming_no_tool_shares_one_bucket_rather_than_escaping() {
        // `initialize`, `tools/list`, or an unparseable body name no tool. They
        // must not each get their own unlimited bucket, and must not bypass the
        // limit altogether.
        let pool = pool_keyed(RateLimitKey::McpTool, 10);
        let key = pool.extract_key("10.0.0.1", "/mcp", "api", Option::<&NoHeaders>::None, None);
        assert_eq!(key, "unknown");
    }

    #[test]
    fn one_tool_exhausting_its_quota_leaves_another_untouched() {
        // The point of keying on the tool: an expensive tool being hammered
        // must not deny a client the cheap ones.
        let pool = pool_keyed(RateLimitKey::McpTool, 2);
        for _ in 0..5 {
            pool.check("expensive_tool");
        }
        assert_eq!(
            pool.check("expensive_tool").outcome,
            RateLimitOutcome::Limited
        );
        assert_ne!(
            pool.check("cheap_tool").outcome,
            RateLimitOutcome::Limited,
            "a different tool must have its own quota"
        );
    }
}

#[cfg(test)]
mod burst_tests {
    use super::*;

    fn outcomes(pool: &RateLimiterPool, n: usize) -> Vec<RateLimitOutcome> {
        (0..n).map(|_| pool.check("203.0.113.7").outcome).collect()
    }

    use RateLimitOutcome::{Allowed as A, Limited as L};

    /// `burst` is documented as the token bucket size, and was ignored: the
    /// local limiter counted requests per one-second window and admitted
    /// `max_rps` of them back to back whatever `burst` said.
    #[test]
    fn burst_is_the_bucket_size() {
        let pool = RateLimiterPool::new(RateLimitConfig {
            max_rps: 10,
            burst: 3,
            ..Default::default()
        });
        assert_eq!(outcomes(&pool, 5), vec![A, A, A, L, L]);
    }

    #[test]
    fn the_bucket_refills_at_max_rps_and_never_beyond_burst() {
        let pool = RateLimiterPool::new(RateLimitConfig {
            max_rps: 10,
            burst: 3,
            ..Default::default()
        });
        assert_eq!(outcomes(&pool, 4), vec![A, A, A, L]);

        // 10 tokens/s: after 150 ms one token is back, not three.
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(outcomes(&pool, 2), vec![A, L]);

        // A long idle period refills to `burst`, not to idle_time * max_rps.
        std::thread::sleep(Duration::from_millis(1200));
        assert_eq!(outcomes(&pool, 4), vec![A, A, A, L]);
    }

    #[test]
    fn a_limited_request_says_when_to_retry() {
        let pool = RateLimiterPool::new(RateLimitConfig {
            max_rps: 2,
            burst: 1,
            ..Default::default()
        });
        assert_eq!(pool.check("k").outcome, A);
        let limited = pool.check("k");
        assert_eq!(limited.outcome, L);
        assert_eq!(limited.remaining, 0);
        // One token at 2/s is at most 500 ms away.
        let wait = limited
            .retry_after_ms
            .expect("local limiter knows the wait");
        assert!(wait > 0 && wait <= 500, "retry after {wait} ms");
        assert!(limited.reset_at > current_unix_timestamp());
    }

    #[test]
    fn the_global_limit_honours_its_burst() {
        let manager = RateLimitManager::with_global_limit(10, 2);
        let allowed: Vec<bool> = (0..4)
            .map(|_| {
                manager
                    .check("any", "203.0.113.7", "/", Option::<&NoHeaders>::None)
                    .allowed
            })
            .collect();
        assert_eq!(allowed, vec![true, true, false, false]);
    }
}
