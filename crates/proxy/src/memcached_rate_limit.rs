//! Distributed rate limiting with Memcached backend
//!
//! This module provides a Memcached-backed rate limiter for multi-instance deployments.
//!
//! # Algorithm
//!
//! The same token bucket as the local limiter ([`TokenBucket`]). Each key
//! holds `"<tokens> <micros>"`, updated with a compare-and-swap loop over the
//! meta protocol (memcached 1.6+): read the value and its CAS token, run the
//! bucket step, write back only if nobody wrote in between, and otherwise
//! start again from what they wrote. A missing key is a full bucket and is
//! created with an add, which fails if another instance created it first. So
//! no update is lost and every request takes exactly one token from the
//! bucket every other instance sees.
//!
//! Memcached has no clock to share, so each instance uses its own. The stored
//! time never moves backwards (see [`TokenBucket::take_at`]): skew between
//! instances can make the limit stricter, by at most the skew's worth of
//! refill, but never looser. Run NTP and this is negligible.
//!
//! Under contention a check takes a round trip per lost race; after
//! [`MAX_CAS_ATTEMPTS`] it gives up and is treated as a backend failure (the
//! local fallback, if enabled, answers). Requests within one instance share
//! one connection and so never race each other.
//!
//! The previous implementation counted requests per one-second window
//! (`INCR` on `key:<unix second>`) and ignored `burst`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(feature = "distributed-rate-limit-memcached")]
use std::time::Duration;

#[cfg(feature = "distributed-rate-limit-memcached")]
use async_memcached::MetaProtocol;
#[cfg(feature = "distributed-rate-limit-memcached")]
use tracing::{debug, error, trace, warn};

use zentinel_config::MemcachedBackendConfig;

#[cfg(feature = "distributed-rate-limit-memcached")]
use crate::rate_limit::RateLimitCheckInfo;
use crate::rate_limit::{BucketState, RateLimitConfig, RateLimitOutcome, TokenBucket};

/// The address `async_memcached::Client::new` needs for a configured URL.
///
/// The client parses its argument as a URL: `tcp://host:port` and
/// `unix:///path` work, and a bare `host:port` only happens to work for a
/// hostname -- `127.0.0.1:11211` is not a valid URL, so it failed to connect,
/// and `url "memcache://127.0.0.1:11211"` (the documented form) never reached
/// memcached: every check fell back. Always hand it an explicit scheme.
pub(crate) fn memcached_dsn(url: &str) -> String {
    if url.starts_with("tcp://") || url.starts_with("unix://") {
        return url.to_string();
    }
    let rest = url
        .strip_prefix("memcache://")
        .or_else(|| url.strip_prefix("memcached://"))
        .unwrap_or(url);
    format!("tcp://{rest}")
}

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

/// Lost CAS races tolerated per check before it counts as a failure
pub const MAX_CAS_ATTEMPTS: usize = 16;

/// The store operations the CAS loop needs. A trait so the loop can be
/// tested against an in-memory store that loses races on purpose.
#[allow(async_fn_in_trait)]
pub trait CasStore {
    type Error;

    /// The value and its CAS token, or `None` if the key is missing
    async fn get_with_cas(&mut self, key: &str) -> Result<Option<(Vec<u8>, u64)>, Self::Error>;

    /// Store only if the key is missing. `Ok(false)` if it exists.
    async fn add(&mut self, key: &str, value: &str, ttl_secs: u32) -> Result<bool, Self::Error>;

    /// Store only if the key is unchanged since `cas` was read. `Ok(false)`
    /// if it changed or disappeared.
    async fn compare_and_swap(
        &mut self,
        key: &str,
        value: &str,
        cas: u64,
        ttl_secs: u32,
    ) -> Result<bool, Self::Error>;
}

/// Why [`take_token`] could not answer
#[derive(Debug)]
pub enum TakeError<E> {
    /// The store failed
    Store(E),
    /// Every attempt lost a race with another writer
    Contended,
}

/// Take a token from the bucket at `key`, retrying lost CAS races.
///
/// Returns the tokens left and the outcome. `min_ttl_secs` is a floor for
/// the stored key's lifetime; it otherwise lives until the bucket is full.
pub async fn take_token<S: CasStore>(
    store: &mut S,
    key: &str,
    bucket: &TokenBucket,
    min_ttl_secs: u32,
    now_us: impl Fn() -> u64,
) -> Result<(f64, RateLimitOutcome), TakeError<S::Error>> {
    for _ in 0..MAX_CAS_ATTEMPTS {
        let current = store.get_with_cas(key).await.map_err(TakeError::Store)?;
        let (stored, cas) = match &current {
            // An unreadable value (such as an old fixed-window counter)
            // counts as a full bucket, and is overwritten.
            Some((raw, cas)) => (BucketState::decode(raw), Some(*cas)),
            None => (None, None),
        };

        let (state, outcome) = bucket.take_at(stored, now_us());
        let ttl_secs = (bucket.ttl_ms(state.tokens).div_ceil(1000) as u32).max(min_ttl_secs);
        let value = state.encode();

        let written = match cas {
            Some(cas) => store
                .compare_and_swap(key, &value, cas, ttl_secs)
                .await
                .map_err(TakeError::Store)?,
            None => store
                .add(key, &value, ttl_secs)
                .await
                .map_err(TakeError::Store)?,
        };
        if written {
            return Ok((state.tokens, outcome));
        }
    }
    Err(TakeError::Contended)
}

/// Memcached keys are at most 250 bytes of printable ASCII without spaces.
/// Rate-limit keys can be header values or paths of any length and content,
/// so anything else is replaced by its hash.
pub fn memcached_key(prefix: &str, key: &str) -> String {
    let full = format!("{prefix}{key}");
    if full.len() <= 250 && full.bytes().all(|b| b.is_ascii_graphic()) {
        full
    } else {
        format!(
            "{}h:{:032x}",
            prefix
                .chars()
                .filter(|c| c.is_ascii_graphic())
                .take(200)
                .collect::<String>(),
            xxhash_rust::xxh3::xxh3_128(key.as_bytes())
        )
    }
}

#[cfg(feature = "distributed-rate-limit-memcached")]
impl CasStore for async_memcached::Client {
    type Error = async_memcached::Error;

    async fn get_with_cas(&mut self, key: &str) -> Result<Option<(Vec<u8>, u64)>, Self::Error> {
        let value = self.meta_get(key, false, None, Some(&["v", "c"])).await?;
        Ok(value.and_then(|v| Some((v.data.unwrap_or_default(), v.cas?))))
    }

    async fn add(&mut self, key: &str, value: &str, ttl_secs: u32) -> Result<bool, Self::Error> {
        let ttl = format!("T{ttl_secs}");
        match self
            .meta_set(key, value, false, None, Some(&["ME", &ttl]))
            .await
        {
            Ok(_) => Ok(true),
            Err(async_memcached::Error::Protocol(
                async_memcached::Status::NotStored | async_memcached::Status::Exists,
            )) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn compare_and_swap(
        &mut self,
        key: &str,
        value: &str,
        cas: u64,
        ttl_secs: u32,
    ) -> Result<bool, Self::Error> {
        let cas = format!("C{cas}");
        let ttl = format!("T{ttl_secs}");
        match self
            .meta_set(key, value, false, None, Some(&[&cas, &ttl]))
            .await
        {
            Ok(_) => Ok(true),
            Err(async_memcached::Error::Protocol(
                async_memcached::Status::Exists | async_memcached::Status::NotFound,
            )) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// After a failed connection attempt, requests fall back without trying
/// again for this long, so an outage costs each request nothing rather than
/// a connect timeout.
#[cfg(feature = "distributed-rate-limit-memcached")]
const RECONNECT_BACKOFF_MS: u64 = 1000;

/// Memcached-backed distributed rate limiter
#[cfg(feature = "distributed-rate-limit-memcached")]
pub struct MemcachedRateLimiter {
    /// host:port
    addr: String,
    /// The connection, opened on first use. Dropped after any error or
    /// timeout: an interrupted request leaves its reply unread on the
    /// socket, and the next request would read it as its own.
    ///
    /// A tokio mutex because the guard is held across the round trips. The
    /// parking_lot lock this replaces blocked a runtime thread while held,
    /// and made the check future `!Send`, so it could not run in a request.
    client: tokio::sync::Mutex<Option<async_memcached::Client>>,
    /// Unix milliseconds before which no new connection is attempted
    retry_connect_at_ms: AtomicU64,
    /// Prepended to every bucket key
    key_prefix: String,
    bucket: TokenBucket,
    /// Reported as the limit in `X-RateLimit-Limit`
    max_rps: u32,
    timeout: Duration,
    fallback_local: bool,
    /// Lower bound for stored keys' lifetime (`memcached-ttl-secs`)
    ttl_secs: u32,
    /// Whether Memcached is currently healthy
    healthy: AtomicBool,
    /// Statistics
    pub stats: Arc<MemcachedRateLimitStats>,
}

#[cfg(feature = "distributed-rate-limit-memcached")]
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(feature = "distributed-rate-limit-memcached")]
fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

#[cfg(feature = "distributed-rate-limit-memcached")]
fn io_error(message: &'static str) -> async_memcached::Error {
    async_memcached::Error::Io(std::io::Error::other(message))
}

#[cfg(feature = "distributed-rate-limit-memcached")]
impl MemcachedRateLimiter {
    /// Create a limiter and connect now, failing if memcached is unreachable.
    pub async fn new(
        backend_config: &MemcachedBackendConfig,
        rate_config: &RateLimitConfig,
    ) -> Result<Self, async_memcached::Error> {
        let limiter = Self::build(
            backend_config,
            rate_config,
            backend_config.key_prefix.clone(),
        );
        let client = async_memcached::Client::new(&limiter.addr).await?;
        *limiter.client.lock().await = Some(client);

        debug!(
            url = %backend_config.url,
            prefix = %backend_config.key_prefix,
            max_rps = rate_config.max_rps,
            burst = rate_config.burst,
            "Memcached rate limiter initialized"
        );
        Ok(limiter)
    }

    /// Create a limiter for one pool that connects on first use, so that
    /// building limiters never waits on memcached. Keys are
    /// `<key-prefix><scope>:<key>`.
    pub fn lazy(
        backend_config: &MemcachedBackendConfig,
        rate_config: &RateLimitConfig,
        scope: &str,
    ) -> Self {
        Self::build(
            backend_config,
            rate_config,
            format!("{}{}:", backend_config.key_prefix, scope),
        )
    }

    fn build(
        backend_config: &MemcachedBackendConfig,
        rate_config: &RateLimitConfig,
        key_prefix: String,
    ) -> Self {
        let addr = memcached_dsn(&backend_config.url);
        Self {
            addr,
            client: tokio::sync::Mutex::new(None),
            retry_connect_at_ms: AtomicU64::new(0),
            key_prefix,
            bucket: TokenBucket::new(rate_config.max_rps, rate_config.burst),
            max_rps: rate_config.max_rps,
            timeout: Duration::from_millis(backend_config.timeout_ms),
            fallback_local: backend_config.fallback_local,
            ttl_secs: backend_config.ttl_secs,
            healthy: AtomicBool::new(true),
            stats: Arc::new(MemcachedRateLimitStats::default()),
        }
    }

    /// Take a token for `key`.
    ///
    /// Returns the same information, computed the same way, as the local
    /// limiter: it drives `X-RateLimit-*` and `Retry-After`.
    pub async fn check(&self, key: &str) -> Result<RateLimitCheckInfo, async_memcached::Error> {
        let full_key = memcached_key(&self.key_prefix, key);

        let mut guard = self.client.lock().await;
        let result = tokio::time::timeout(self.timeout, async {
            if guard.is_none() {
                if now_ms() < self.retry_connect_at_ms.load(Ordering::Relaxed) {
                    return Err(io_error(
                        "Memcached unreachable, not retrying the connection yet",
                    ));
                }
                match async_memcached::Client::new(&self.addr).await {
                    Ok(client) => *guard = Some(client),
                    Err(e) => {
                        self.retry_connect_at_ms
                            .store(now_ms() + RECONNECT_BACKOFF_MS, Ordering::Relaxed);
                        return Err(e);
                    }
                }
            }
            let client = guard.as_mut().expect("connected above");
            take_token(client, &full_key, &self.bucket, self.ttl_secs, now_us)
                .await
                .map_err(|e| match e {
                    TakeError::Store(e) => e,
                    TakeError::Contended => {
                        io_error("Memcached rate limit update lost every CAS race")
                    }
                })
        })
        .await
        .unwrap_or_else(|_| Err(io_error("Memcached operation timed out")));

        let (tokens, outcome) = match result {
            Ok(taken) => taken,
            Err(e) => {
                // The connection may hold half a reply; start over on a new one.
                *guard = None;
                return Err(e);
            }
        };
        drop(guard);

        self.healthy.store(true, Ordering::Relaxed);

        trace!(
            key = key,
            tokens = tokens,
            max_rps = self.max_rps,
            outcome = ?outcome,
            "Memcached rate limit check"
        );

        self.stats.record_check(outcome);
        Ok(self.bucket.describe(tokens, outcome, self.max_rps))
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
        self.fallback_local
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
    tracing::warn!(
        "Memcached rate limiting requested but feature is disabled. Using local rate limiting."
    );
    None
}

#[cfg(test)]
mod tests {

    #[test]
    fn memcached_urls_become_explicit_tcp_dsns() {
        // An IP without a scheme is not a URL; this is the form that never connected.
        assert_eq!(
            super::memcached_dsn("memcache://127.0.0.1:11211"),
            "tcp://127.0.0.1:11211"
        );
        assert_eq!(
            super::memcached_dsn("memcached://cache.internal:11211"),
            "tcp://cache.internal:11211"
        );
        assert_eq!(
            super::memcached_dsn("127.0.0.1:11211"),
            "tcp://127.0.0.1:11211"
        );
        assert_eq!(
            super::memcached_dsn("tcp://10.0.0.5:11211"),
            "tcp://10.0.0.5:11211"
        );
        assert_eq!(
            super::memcached_dsn("unix:///run/memcached.sock"),
            "unix:///run/memcached.sock"
        );
    }

    use super::*;
    use std::collections::HashMap;

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

    /// An in-memory store with memcached's add/CAS semantics. Before each
    /// of the first `interfere` writes, another "instance" takes a token
    /// from the same bucket, so that write loses its race.
    struct FakeStore {
        items: HashMap<String, (String, u64)>,
        next_cas: u64,
        interfere: usize,
        bucket: TokenBucket,
        now_us: u64,
        writes: usize,
    }

    impl FakeStore {
        fn new(bucket: TokenBucket, interfere: usize) -> Self {
            Self {
                items: HashMap::new(),
                next_cas: 1,
                interfere,
                bucket,
                now_us: 1_000_000,
                writes: 0,
            }
        }

        fn store(&mut self, key: &str, value: String) {
            self.next_cas += 1;
            self.items.insert(key.to_string(), (value, self.next_cas));
        }

        /// The other instance's request: take a token directly.
        fn rival_takes(&mut self, key: &str) {
            let stored = self
                .items
                .get(key)
                .and_then(|(v, _)| BucketState::decode(v.as_bytes()));
            let (state, _) = self.bucket.take_at(stored, self.now_us);
            self.store(key, state.encode());
        }

        fn before_write(&mut self, key: &str) {
            self.writes += 1;
            if self.interfere > 0 {
                self.interfere -= 1;
                self.rival_takes(key);
            }
        }
    }

    impl CasStore for FakeStore {
        type Error = ();

        async fn get_with_cas(&mut self, key: &str) -> Result<Option<(Vec<u8>, u64)>, ()> {
            Ok(self
                .items
                .get(key)
                .map(|(v, cas)| (v.clone().into_bytes(), *cas)))
        }

        async fn add(&mut self, key: &str, value: &str, _ttl: u32) -> Result<bool, ()> {
            self.before_write(key);
            if self.items.contains_key(key) {
                return Ok(false);
            }
            self.store(key, value.to_string());
            Ok(true)
        }

        async fn compare_and_swap(
            &mut self,
            key: &str,
            value: &str,
            cas: u64,
            _ttl: u32,
        ) -> Result<bool, ()> {
            self.before_write(key);
            match self.items.get(key) {
                Some((_, current)) if *current == cas => {
                    self.store(key, value.to_string());
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }

    fn take(store: &mut FakeStore, key: &str) -> Result<(f64, RateLimitOutcome), TakeError<()>> {
        let bucket = store.bucket;
        let now = store.now_us;
        futures::executor::block_on(take_token(store, key, &bucket, 0, || now))
    }

    /// Same admit/deny sequence as the local token bucket: `burst` at once,
    /// then one per 1/max-rps seconds.
    #[test]
    fn cas_loop_is_a_token_bucket() {
        let mut store = FakeStore::new(TokenBucket::new(2, 3), 0);
        let outcomes: Vec<_> = (0..5).map(|_| take(&mut store, "k").unwrap().1).collect();
        assert_eq!(
            outcomes,
            [
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Allowed,
                RateLimitOutcome::Limited,
                RateLimitOutcome::Limited,
            ]
        );
        // Half a second at 2/s refills one token.
        store.now_us += 500_000;
        assert_eq!(take(&mut store, "k").unwrap().1, RateLimitOutcome::Allowed);
        assert_eq!(take(&mut store, "k").unwrap().1, RateLimitOutcome::Limited);
    }

    /// A lost race is retried against what the winner wrote, so both
    /// requests take a token: none is lost, none is double-counted.
    #[test]
    fn lost_races_are_retried_without_losing_updates() {
        let mut store = FakeStore::new(TokenBucket::new(1, 3), 2);
        // Our first write (the add) and second (a CAS) each lose to a rival
        // request; the third lands. Three tokens taken in all.
        let (tokens, outcome) = take(&mut store, "k").unwrap();
        assert_eq!(outcome, RateLimitOutcome::Allowed);
        assert_eq!(tokens, 0.0);
        assert_eq!(store.writes, 3);
        assert_eq!(take(&mut store, "k").unwrap().1, RateLimitOutcome::Limited);
    }

    #[test]
    fn endless_contention_is_an_error_not_an_answer() {
        let mut store = FakeStore::new(TokenBucket::new(1000, 1000), usize::MAX);
        assert!(matches!(take(&mut store, "k"), Err(TakeError::Contended)));
        assert_eq!(store.writes, MAX_CAS_ATTEMPTS);
    }

    /// A value in the old format (a bare counter) must not wedge the key.
    #[test]
    fn an_old_counter_value_reads_as_a_full_bucket() {
        let mut store = FakeStore::new(TokenBucket::new(1, 2), 0);
        store.store("k", "57".to_string());
        assert_eq!(
            take(&mut store, "k").unwrap(),
            (1.0, RateLimitOutcome::Allowed)
        );
    }

    #[test]
    fn keys_memcached_cannot_store_are_hashed() {
        assert_eq!(memcached_key("p:route:", "10.0.0.1"), "p:route:10.0.0.1");
        for key in ["has space", "new\nline", &"x".repeat(300), "ünïcode"] {
            let hashed = memcached_key("p:route:", key);
            assert!(hashed.starts_with("p:route:h:"), "{hashed}");
            assert!(hashed.len() <= 250 && hashed.bytes().all(|b| b.is_ascii_graphic()));
        }
        assert_ne!(memcached_key("p:", "a b"), memcached_key("p:", "a c"));
    }
}
