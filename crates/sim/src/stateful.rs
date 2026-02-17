//! Stateful policy simulation for Zentinel configurations
//!
//! This module enables simulation of multiple requests with state tracking for:
//! - Rate limiting (token bucket)
//! - Caching (hit/miss/expiry)
//! - Circuit breakers (state transitions)
//! - Load balancer position (round-robin)
//!
//! # Example
//!
//! ```ignore
//! let requests = vec![
//!     TimestampedRequest { request: req1, timestamp: 0.0 },
//!     TimestampedRequest { request: req2, timestamp: 0.5 },
//! ];
//! let result = simulate_sequence(&config, &requests);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::matcher::RouteMatcher;
use crate::trace::MatchStep;
use crate::types::{MatchedRoute, SimulatedRequest};
use zentinel_config::Config;

// ============================================================================
// Input Types
// ============================================================================

/// A request with an associated timestamp for stateful simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedRequest {
    /// The HTTP request to simulate
    #[serde(flatten)]
    pub request: SimulatedRequest,

    /// Timestamp in seconds since simulation start (defaults to 0.0)
    #[serde(default)]
    pub timestamp: f64,
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of simulating a sequence of requests with state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatefulSimulationResult {
    /// Results for each individual request
    pub results: Vec<RequestResult>,

    /// State transitions that occurred during simulation
    pub state_transitions: Vec<StateTransition>,

    /// Final state after all requests
    pub final_state: FinalState,

    /// Summary statistics
    pub summary: SimulationSummary,
}

/// Result for a single request in the sequence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResult {
    /// Index in the request sequence (0-based)
    pub request_index: usize,

    /// Timestamp of this request
    pub timestamp: f64,

    /// The matched route (if any)
    pub matched_route: Option<MatchedRoute>,

    /// Whether the request was rate limited
    pub rate_limited: bool,

    /// Whether this was a cache hit
    pub cache_hit: bool,

    /// Whether the circuit breaker was open
    pub circuit_open: bool,

    /// Selected upstream target (if applicable)
    pub selected_target: Option<String>,

    /// Detailed route matching trace
    pub decision_trace: Vec<MatchStep>,
}

impl RequestResult {
    /// Create a result for a rate-limited request
    pub fn rate_limited(index: usize, timestamp: f64, trace: Vec<MatchStep>) -> Self {
        Self {
            request_index: index,
            timestamp,
            matched_route: None,
            rate_limited: true,
            cache_hit: false,
            circuit_open: false,
            selected_target: None,
            decision_trace: trace,
        }
    }
}

/// A state transition that occurred during simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Request index that triggered this transition
    pub request_index: usize,

    /// Timestamp when the transition occurred
    pub timestamp: f64,

    /// Component type (rate_limit, cache, circuit_breaker, load_balancer)
    pub component: String,

    /// Key identifying the specific instance (e.g., route ID, upstream ID)
    pub key: String,

    /// Human-readable description of the change
    pub change: String,

    /// State before the transition
    pub before: serde_json::Value,

    /// State after the transition
    pub after: serde_json::Value,
}

/// Final state after all requests have been processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalState {
    /// Rate limit bucket states
    pub rate_limits: HashMap<String, TokenBucketSnapshot>,

    /// Cache state summary
    pub cache: CacheSnapshot,

    /// Circuit breaker states
    pub circuit_breakers: HashMap<String, CircuitBreakerSnapshot>,

    /// Load balancer positions
    pub load_balancers: HashMap<String, usize>,
}

/// Summary statistics for the simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationSummary {
    /// Total requests processed
    pub total_requests: usize,

    /// Requests that were rate limited
    pub rate_limited_count: usize,

    /// Cache hits
    pub cache_hits: usize,

    /// Cache misses
    pub cache_misses: usize,

    /// Requests blocked by open circuit breakers
    pub circuit_blocked_count: usize,

    /// Requests that matched a route
    pub matched_count: usize,

    /// Requests that didn't match any route
    pub unmatched_count: usize,
}

// ============================================================================
// State Snapshots (for serialization)
// ============================================================================

/// Snapshot of a token bucket's state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucketSnapshot {
    /// Current token count
    pub tokens: f64,

    /// Maximum tokens (burst capacity)
    pub max_tokens: f64,

    /// Refill rate (tokens per second)
    pub refill_rate: f64,

    /// Last update timestamp
    pub last_update: f64,
}

/// Snapshot of cache state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSnapshot {
    /// Number of entries in cache
    pub entry_count: usize,

    /// Total hits
    pub hits: u64,

    /// Total misses
    pub misses: u64,

    /// Hit rate (0.0 - 1.0)
    pub hit_rate: f64,
}

/// Snapshot of a circuit breaker's state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerSnapshot {
    /// Current state
    pub state: String,

    /// Consecutive failure count
    pub failure_count: u32,

    /// Consecutive success count
    pub success_count: u32,

    /// Time of last failure (if any)
    pub last_failure_at: Option<f64>,
}

// ============================================================================
// Internal State Tracking
// ============================================================================

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_update: f64,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_update: 0.0,
        }
    }

    /// Try to consume a token, returns true if allowed
    fn consume(&mut self, timestamp: f64) -> bool {
        // Refill tokens based on elapsed time
        let elapsed = (timestamp - self.last_update).max(0.0);
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = timestamp;

        // Try to consume one token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn snapshot(&self) -> TokenBucketSnapshot {
        TokenBucketSnapshot {
            tokens: self.tokens,
            max_tokens: self.max_tokens,
            refill_rate: self.refill_rate,
            last_update: self.last_update,
        }
    }
}

/// Rate limit state tracker
#[derive(Debug, Default)]
struct RateLimitState {
    buckets: HashMap<String, TokenBucket>,
}

impl RateLimitState {
    fn new() -> Self {
        Self::default()
    }

    /// Initialize buckets from config
    fn init_from_config(&mut self, config: &Config) {
        for route in &config.routes {
            if let Some(ref rl) = route.policies.rate_limit {
                let key = format!("route:{}", route.id);
                let bucket = TokenBucket::new(rl.burst as f64, rl.requests_per_second as f64);
                self.buckets.insert(key, bucket);
            }
        }
    }

    /// Check and consume a token, returning (allowed, transition)
    fn check_and_consume(
        &mut self,
        route_id: &str,
        timestamp: f64,
        request_index: usize,
    ) -> (bool, Option<StateTransition>) {
        let key = format!("route:{}", route_id);

        if let Some(bucket) = self.buckets.get_mut(&key) {
            let before = bucket.snapshot();
            let allowed = bucket.consume(timestamp);
            let after = bucket.snapshot();

            let transition = if (before.tokens - after.tokens).abs() > 0.01 || !allowed {
                Some(StateTransition {
                    request_index,
                    timestamp,
                    component: "rate_limit".to_string(),
                    key: key.clone(),
                    change: if allowed {
                        format!(
                            "Consumed token: {:.1} -> {:.1}",
                            before.tokens, after.tokens
                        )
                    } else {
                        format!("Rate limited: {:.1} tokens available", after.tokens)
                    },
                    before: serde_json::to_value(&before).unwrap_or_default(),
                    after: serde_json::to_value(&after).unwrap_or_default(),
                })
            } else {
                None
            };

            (allowed, transition)
        } else {
            (true, None) // No rate limit configured
        }
    }

    fn snapshot(&self) -> HashMap<String, TokenBucketSnapshot> {
        self.buckets
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect()
    }
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    inserted_at: f64,
    ttl_secs: u64,
}

impl CacheEntry {
    fn is_expired(&self, current_time: f64) -> bool {
        current_time > self.inserted_at + self.ttl_secs as f64
    }
}

/// Cache state tracker
#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    hits: u64,
    misses: u64,
}

impl CacheState {
    fn new() -> Self {
        Self::default()
    }

    /// Check cache and update, returning (is_hit, transition)
    fn check_and_update(
        &mut self,
        cache_key: &str,
        ttl_secs: u64,
        timestamp: f64,
        request_index: usize,
        should_cache: bool,
    ) -> (bool, Option<StateTransition>) {
        if !should_cache {
            return (false, None);
        }

        // Check for existing entry
        if let Some(entry) = self.entries.get(cache_key) {
            if !entry.is_expired(timestamp) {
                self.hits += 1;
                return (
                    true,
                    Some(StateTransition {
                        request_index,
                        timestamp,
                        component: "cache".to_string(),
                        key: cache_key.to_string(),
                        change: format!(
                            "Cache HIT (entry age: {:.1}s, TTL: {}s)",
                            timestamp - entry.inserted_at,
                            entry.ttl_secs
                        ),
                        before: serde_json::json!({ "status": "cached" }),
                        after: serde_json::json!({ "status": "hit", "hits": self.hits }),
                    }),
                );
            }
            // Entry expired, will be replaced
        }

        // Cache miss - add entry
        self.misses += 1;
        self.entries.insert(
            cache_key.to_string(),
            CacheEntry {
                inserted_at: timestamp,
                ttl_secs,
            },
        );

        (
            false,
            Some(StateTransition {
                request_index,
                timestamp,
                component: "cache".to_string(),
                key: cache_key.to_string(),
                change: format!("Cache MISS - stored with TTL {}s", ttl_secs),
                before: serde_json::json!({ "status": "not_cached" }),
                after: serde_json::json!({ "status": "stored", "misses": self.misses }),
            }),
        )
    }

    fn snapshot(&self) -> CacheSnapshot {
        let total = self.hits + self.misses;
        CacheSnapshot {
            entry_count: self.entries.len(),
            hits: self.hits,
            misses: self.misses,
            hit_rate: if total > 0 {
                self.hits as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Circuit breaker
#[derive(Debug, Clone)]
struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    failure_threshold: u32,
    success_threshold: u32,
    timeout_secs: u64,
    last_failure_at: Option<f64>,
}

impl CircuitBreaker {
    fn new(failure_threshold: u32, success_threshold: u32, timeout_secs: u64) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            failure_threshold,
            success_threshold,
            timeout_secs,
            last_failure_at: None,
        }
    }

    /// Check if circuit allows request, update state based on time
    fn allows_request(&mut self, timestamp: f64) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has passed
                if let Some(last_failure) = self.last_failure_at {
                    if timestamp >= last_failure + self.timeout_secs as f64 {
                        self.state = CircuitState::HalfOpen;
                        self.success_count = 0;
                        return true; // Allow one request in half-open
                    }
                }
                false
            }
            CircuitState::HalfOpen => true, // Allow requests in half-open
        }
    }

    /// Record a success (simulated - always success in simulation)
    fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failure (for simulation, can be triggered explicitly)
    #[allow(dead_code)]
    fn record_failure(&mut self, timestamp: f64) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitState::Open;
                    self.last_failure_at = Some(timestamp);
                }
            }
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.last_failure_at = Some(timestamp);
                self.success_count = 0;
            }
            CircuitState::Open => {}
        }
    }

    fn snapshot(&self) -> CircuitBreakerSnapshot {
        CircuitBreakerSnapshot {
            state: self.state.to_string(),
            failure_count: self.failure_count,
            success_count: self.success_count,
            last_failure_at: self.last_failure_at,
        }
    }
}

/// Circuit breaker state tracker
#[derive(Debug, Default)]
struct CircuitBreakerState {
    breakers: HashMap<String, CircuitBreaker>,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self::default()
    }

    /// Initialize circuit breakers from config
    fn init_from_config(&mut self, config: &Config) {
        // Per-route circuit breakers
        for route in &config.routes {
            if let Some(ref cb) = route.circuit_breaker {
                let key = format!("route:{}", route.id);
                self.breakers.insert(
                    key,
                    CircuitBreaker::new(
                        cb.failure_threshold,
                        cb.success_threshold,
                        cb.timeout_seconds,
                    ),
                );
            }
        }
    }

    /// Check circuit breaker for a route
    fn check(
        &mut self,
        route_id: &str,
        timestamp: f64,
        request_index: usize,
    ) -> (bool, Option<StateTransition>) {
        let key = format!("route:{}", route_id);

        if let Some(cb) = self.breakers.get_mut(&key) {
            let before = cb.snapshot();
            let allowed = cb.allows_request(timestamp);

            if allowed {
                cb.record_success(); // Simulate success
            }

            let after = cb.snapshot();

            let transition = if before.state != after.state {
                Some(StateTransition {
                    request_index,
                    timestamp,
                    component: "circuit_breaker".to_string(),
                    key: key.clone(),
                    change: format!("State: {} -> {}", before.state, after.state),
                    before: serde_json::to_value(&before).unwrap_or_default(),
                    after: serde_json::to_value(&after).unwrap_or_default(),
                })
            } else {
                None
            };

            (!allowed, transition) // Return true if circuit is OPEN (blocked)
        } else {
            (false, None) // No circuit breaker, not blocked
        }
    }

    fn snapshot(&self) -> HashMap<String, CircuitBreakerSnapshot> {
        self.breakers
            .iter()
            .map(|(k, v)| (k.clone(), v.snapshot()))
            .collect()
    }
}

/// Load balancer state (tracks round-robin position)
#[derive(Debug, Default)]
struct LoadBalancerState {
    positions: HashMap<String, usize>,
}

impl LoadBalancerState {
    fn new() -> Self {
        Self::default()
    }

    /// Select next target using round-robin, returning (target, transition)
    fn select_target(
        &mut self,
        config: &Config,
        upstream_id: &str,
        request_index: usize,
        timestamp: f64,
    ) -> (Option<String>, Option<StateTransition>) {
        let upstream = match config.upstreams.get(upstream_id) {
            Some(u) => u,
            None => return (None, None),
        };

        if upstream.targets.is_empty() {
            return (None, None);
        }

        let position = self.positions.entry(upstream_id.to_string()).or_insert(0);
        let before_pos = *position;

        let target = &upstream.targets[*position % upstream.targets.len()];
        *position = (*position + 1) % upstream.targets.len();

        let after_pos = *position;

        let transition = StateTransition {
            request_index,
            timestamp,
            component: "load_balancer".to_string(),
            key: upstream_id.to_string(),
            change: format!(
                "Round-robin: position {} -> {} (selected {})",
                before_pos, after_pos, target.address
            ),
            before: serde_json::json!({ "position": before_pos }),
            after: serde_json::json!({ "position": after_pos }),
        };

        (Some(target.address.clone()), Some(transition))
    }

    fn snapshot(&self) -> HashMap<String, usize> {
        self.positions.clone()
    }
}

// ============================================================================
// Main Simulation Function
// ============================================================================

/// Simulate a sequence of requests with state tracking
///
/// This function processes each request in order, maintaining state for:
/// - Rate limiting (token bucket per route)
/// - Caching (entries with TTL)
/// - Circuit breakers (per upstream)
/// - Load balancer position (round-robin)
///
/// # Arguments
///
/// * `config` - The parsed Zentinel configuration
/// * `requests` - Sequence of timestamped requests to simulate
///
/// # Returns
///
/// A `StatefulSimulationResult` containing per-request results, state transitions,
/// and final state snapshots.
pub fn simulate_sequence(
    config: &Config,
    requests: &[TimestampedRequest],
) -> StatefulSimulationResult {
    // Initialize state trackers
    let mut rate_limits = RateLimitState::new();
    rate_limits.init_from_config(config);

    let mut cache = CacheState::new();

    let mut circuit_breakers = CircuitBreakerState::new();
    circuit_breakers.init_from_config(config);

    let mut load_balancers = LoadBalancerState::new();

    // Results and transitions
    let mut results = Vec::with_capacity(requests.len());
    let mut transitions = Vec::new();

    // Summary counters
    let mut rate_limited_count = 0;
    let mut cache_hits = 0;
    let mut cache_misses = 0;
    let mut circuit_blocked_count = 0;
    let mut matched_count = 0;
    let mut unmatched_count = 0;

    // Build route matcher once
    let matcher = match RouteMatcher::new(&config.routes, None) {
        Ok(m) => m,
        Err(_) => {
            return StatefulSimulationResult {
                results: vec![],
                state_transitions: vec![],
                final_state: FinalState {
                    rate_limits: HashMap::new(),
                    cache: CacheSnapshot {
                        entry_count: 0,
                        hits: 0,
                        misses: 0,
                        hit_rate: 0.0,
                    },
                    circuit_breakers: HashMap::new(),
                    load_balancers: HashMap::new(),
                },
                summary: SimulationSummary {
                    total_requests: 0,
                    rate_limited_count: 0,
                    cache_hits: 0,
                    cache_misses: 0,
                    circuit_blocked_count: 0,
                    matched_count: 0,
                    unmatched_count: 0,
                },
            };
        }
    };

    for (idx, timestamped) in requests.iter().enumerate() {
        let timestamp = if timestamped.timestamp == 0.0 && idx > 0 {
            idx as f64 // Auto-assign timestamps if not provided
        } else {
            timestamped.timestamp
        };

        let request = &timestamped.request;

        // 1. Route matching
        let (matched_route, trace) = matcher.match_with_trace(request);

        if matched_route.is_none() {
            unmatched_count += 1;
            results.push(RequestResult {
                request_index: idx,
                timestamp,
                matched_route: None,
                rate_limited: false,
                cache_hit: false,
                circuit_open: false,
                selected_target: None,
                decision_trace: trace,
            });
            continue;
        }

        matched_count += 1;
        let route = matched_route.as_ref().unwrap();

        // 2. Check rate limit
        let (allowed, rl_transition) =
            rate_limits.check_and_consume(&route.id, timestamp, idx);

        if let Some(t) = rl_transition {
            transitions.push(t);
        }

        if !allowed {
            rate_limited_count += 1;
            results.push(RequestResult::rate_limited(idx, timestamp, trace));
            continue;
        }

        // 3. Check cache
        let cache_key = request.cache_key();
        let route_config = config.routes.iter().find(|r| r.id == route.id);
        let (cache_enabled, cache_ttl) = route_config
            .and_then(|rc| rc.policies.cache.as_ref())
            .map(|c| (c.enabled, c.default_ttl_secs))
            .unwrap_or((false, 0));

        let (is_cache_hit, cache_transition) =
            cache.check_and_update(&cache_key, cache_ttl, timestamp, idx, cache_enabled);

        if let Some(t) = cache_transition {
            transitions.push(t);
        }

        if is_cache_hit {
            cache_hits += 1;
        } else if cache_enabled {
            cache_misses += 1;
        }

        // 4. Check circuit breaker (only if not cache hit)
        let mut circuit_open = false;
        if !is_cache_hit {
            let (blocked, cb_transition) =
                circuit_breakers.check(&route.id, timestamp, idx);
            if let Some(t) = cb_transition {
                transitions.push(t);
            }
            if blocked {
                circuit_open = true;
                circuit_blocked_count += 1;
            }
        }

        // 5. Select upstream target (if not cache hit and circuit not open)
        let selected_target = if !is_cache_hit && !circuit_open {
            if let Some(ref upstream_id) = route.upstream {
                let (target, lb_transition) =
                    load_balancers.select_target(config, upstream_id, idx, timestamp);
                if let Some(t) = lb_transition {
                    transitions.push(t);
                }
                target
            } else {
                None
            }
        } else {
            None
        };

        results.push(RequestResult {
            request_index: idx,
            timestamp,
            matched_route: matched_route.clone(),
            rate_limited: false,
            cache_hit: is_cache_hit,
            circuit_open,
            selected_target,
            decision_trace: trace,
        });
    }

    StatefulSimulationResult {
        results,
        state_transitions: transitions,
        final_state: FinalState {
            rate_limits: rate_limits.snapshot(),
            cache: cache.snapshot(),
            circuit_breakers: circuit_breakers.snapshot(),
            load_balancers: load_balancers.snapshot(),
        },
        summary: SimulationSummary {
            total_requests: requests.len(),
            rate_limited_count,
            cache_hits,
            cache_misses,
            circuit_blocked_count,
            matched_count,
            unmatched_count,
        },
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10.0, 5.0); // 10 max, 5 per second

        // Consume at t=0
        assert!(bucket.consume(0.0));
        assert!((bucket.tokens - 9.0).abs() < 0.01);

        // Consume at t=0 again (no refill)
        assert!(bucket.consume(0.0));
        assert!((bucket.tokens - 8.0).abs() < 0.01);

        // Wait 1 second, should refill 5 tokens (8 + 5 = 13, capped at 10)
        // Then consume 1, leaving 9 tokens
        assert!(bucket.consume(1.0));
        assert!(
            (bucket.tokens - 9.0).abs() < 0.01,
            "Expected ~9.0 tokens, got {}",
            bucket.tokens
        );
    }

    #[test]
    fn test_token_bucket_rate_limit() {
        let mut bucket = TokenBucket::new(2.0, 1.0); // 2 max, 1 per second

        // Consume all tokens
        assert!(bucket.consume(0.0)); // 1 left
        assert!(bucket.consume(0.0)); // 0 left
        assert!(!bucket.consume(0.0)); // Rate limited!

        // Wait and try again
        assert!(bucket.consume(1.0)); // Refilled 1 token
        assert!(!bucket.consume(1.0)); // Rate limited again
    }

    #[test]
    fn test_cache_hit_miss() {
        let mut cache = CacheState::new();

        // First request - miss
        let (hit, _) = cache.check_and_update("key1", 60, 0.0, 0, true);
        assert!(!hit);
        assert_eq!(cache.misses, 1);
        assert_eq!(cache.hits, 0);

        // Second request same key - hit
        let (hit, _) = cache.check_and_update("key1", 60, 1.0, 1, true);
        assert!(hit);
        assert_eq!(cache.hits, 1);

        // Different key - miss
        let (hit, _) = cache.check_and_update("key2", 60, 2.0, 2, true);
        assert!(!hit);
        assert_eq!(cache.misses, 2);
    }

    #[test]
    fn test_cache_expiry() {
        let mut cache = CacheState::new();

        // Store with 10s TTL
        let (hit, _) = cache.check_and_update("key1", 10, 0.0, 0, true);
        assert!(!hit);

        // Access at t=5 - still valid
        let (hit, _) = cache.check_and_update("key1", 10, 5.0, 1, true);
        assert!(hit);

        // Access at t=15 - expired
        let (hit, _) = cache.check_and_update("key1", 10, 15.0, 2, true);
        assert!(!hit); // Miss because expired
    }

    #[test]
    fn test_circuit_breaker_states() {
        let mut cb = CircuitBreaker::new(2, 1, 10); // Open after 2 failures, close after 1 success

        // Initially closed
        assert!(cb.allows_request(0.0));
        assert_eq!(cb.state, CircuitState::Closed);

        // Record failures
        cb.record_failure(1.0);
        assert_eq!(cb.failure_count, 1);
        cb.record_failure(2.0);
        assert_eq!(cb.state, CircuitState::Open);

        // Should not allow requests when open
        assert!(!cb.allows_request(3.0));

        // After timeout, should be half-open
        assert!(cb.allows_request(15.0)); // 2.0 + 10 = 12, so t=15 is past timeout
        assert_eq!(cb.state, CircuitState::HalfOpen);

        // Success in half-open should close
        cb.record_success();
        assert_eq!(cb.state, CircuitState::Closed);
    }

    #[test]
    fn test_load_balancer_round_robin() {
        let mut lb = LoadBalancerState::new();

        // Create a minimal config with 3 targets
        let config_kdl = r#"
            system {}
            listeners {
                listener "http" { address "0.0.0.0:8080" }
            }
            routes {
                route "test" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "server1:8080"
                    target "server2:8080"
                    target "server3:8080"
                }
            }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();

        // Should cycle through targets
        let (t1, _) = lb.select_target(&config, "backend", 0, 0.0);
        assert_eq!(t1, Some("server1:8080".to_string()));

        let (t2, _) = lb.select_target(&config, "backend", 1, 1.0);
        assert_eq!(t2, Some("server2:8080".to_string()));

        let (t3, _) = lb.select_target(&config, "backend", 2, 2.0);
        assert_eq!(t3, Some("server3:8080".to_string()));

        // Should wrap around
        let (t4, _) = lb.select_target(&config, "backend", 3, 3.0);
        assert_eq!(t4, Some("server1:8080".to_string()));
    }
}
