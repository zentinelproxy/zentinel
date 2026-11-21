//! Circuit breaker implementation for resilient service protection
//!
//! This module provides a unified circuit breaker implementation used by both
//! agent connections and upstream pools to prevent cascade failures.
//!
//! # Performance
//!
//! This implementation is **lock-free** using atomics. All operations complete in
//! O(1) time without blocking. The `is_closed()` check is ~10-50ns, making it
//! suitable for the hot path.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::Instant;
use tracing::{debug, info, trace, warn};

use crate::types::{CircuitBreakerConfig, CircuitBreakerState};

// State constants for AtomicU8
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

// The half-open bookkeeping is one word: the number of the current half-open
// period in the high half, the trial slots taken in it in the low half. A
// slot is taken and given back with one compare-and-swap on both, so a slot
// of an earlier period can never be given back into a later one.
const fn pack(period: u32, taken: u32) -> u64 {
    ((period as u64) << 32) | taken as u64
}

const fn period_of(word: u64) -> u32 {
    (word >> 32) as u32
}

const fn taken_of(word: u64) -> u32 {
    word as u32
}

// ============================================================================
// Admission
// ============================================================================

/// How [`CircuitBreaker::admit`] answered a request.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a trial slot must be released if the request ends without a result"]
pub enum Admission {
    /// The request is not let through.
    Refused,
    /// The request is let through and holds no half-open slot: the breaker is
    /// closed, or this is the request that ended the open period.
    Allowed,
    /// The request is let through as a half-open trial and holds a slot.
    Trial(TrialSlot),
}

/// A half-open trial slot, held by the request that was let through as a
/// trial.
///
/// Give it back with [`CircuitBreaker::release_half_open_slot`] if the request
/// ends without a result. It can be given back once, and only during the
/// half-open period it was taken in.
#[derive(Debug, PartialEq, Eq)]
pub struct TrialSlot {
    period: u32,
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// Circuit breaker for protecting services from cascade failures
///
/// Implements the standard circuit breaker pattern with three states:
/// - **Closed**: Normal operation, requests pass through
/// - **Open**: Failures exceeded threshold, requests are rejected
/// - **Half-Open**: Testing recovery, limited requests allowed
///
/// # Half-open trial requests
///
/// In half-open state [`admit`](Self::admit) lets up to
/// `half_open_max_requests` trial requests through, each holding a
/// [`TrialSlot`]. The request that ends the open period is let through as
/// well and holds none. A trial gives its result with
/// [`record_success`](Self::record_success) or
/// [`record_failure`](Self::record_failure). A trial that ends without a
/// result of its own (the client went away, a filter refused the request)
/// hands its slot back with
/// [`release_half_open_slot`](Self::release_half_open_slot). A trial that is
/// lost altogether does not block the breaker for good: when the half-open
/// period began (or last started over) at least `timeout_seconds` ago and
/// every slot is still taken, the next check starts the period over and lets
/// a new trial through.
///
/// [`is_closed`](Self::is_closed) is `admit` for callers that only want to
/// know whether the request may go on; a slot it takes cannot be given back.
///
/// # Performance
///
/// All methods are **synchronous and lock-free**. They use atomic operations
/// and complete in constant time without blocking.
///
/// # Example
///
/// ```ignore
/// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
///
/// // Before making a request
/// if breaker.is_closed() {
///     match make_request().await {
///         Ok(_) => breaker.record_success(),
///         Err(_) => breaker.record_failure(),
///     }
/// }
/// ```
pub struct CircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// Current state (0=Closed, 1=Open, 2=HalfOpen)
    state: AtomicU8,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Consecutive successes
    consecutive_successes: AtomicU64,
    /// Base instant for time calculations
    base_instant: Instant,
    /// Nanoseconds since base_instant when state last changed, or when the
    /// current half-open period last started over
    last_state_change_ns: AtomicU64,
    /// The current half-open period and the trial slots taken in it and not
    /// given back, packed (see `pack`)
    half_open: AtomicU64,
    /// Optional name for logging
    name: Option<String>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        trace!(
            failure_threshold = config.failure_threshold,
            success_threshold = config.success_threshold,
            timeout_seconds = config.timeout_seconds,
            half_open_max_requests = config.half_open_max_requests,
            "Creating circuit breaker"
        );

        let now = Instant::now();
        Self {
            config,
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            base_instant: now,
            last_state_change_ns: AtomicU64::new(0),
            half_open: AtomicU64::new(0),
            name: None,
        }
    }

    /// Create a new circuit breaker with a name for logging
    pub fn with_name(config: CircuitBreakerConfig, name: impl Into<String>) -> Self {
        let name = name.into();

        debug!(
            name = %name,
            failure_threshold = config.failure_threshold,
            success_threshold = config.success_threshold,
            timeout_seconds = config.timeout_seconds,
            "Creating named circuit breaker"
        );

        let now = Instant::now();
        Self {
            config,
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            base_instant: now,
            last_state_change_ns: AtomicU64::new(0),
            half_open: AtomicU64::new(0),
            name: Some(name),
        }
    }

    /// Check if the circuit breaker allows requests (lock-free)
    ///
    /// Returns `true` if requests should be allowed through.
    /// Automatically transitions from Open to HalfOpen after timeout.
    ///
    /// In half-open state a `true` answer may take a trial slot that the
    /// caller cannot give back; use [`admit`](Self::admit) to be able to.
    ///
    /// # Performance
    ///
    /// This method is lock-free and completes in O(1) time (~10-50ns).
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.admit() != Admission::Refused
    }

    /// Decide whether a request is let through, and what it holds (lock-free)
    ///
    /// Like [`is_closed`](Self::is_closed), but a request let through as a
    /// half-open trial gets its [`TrialSlot`] to give back if it ends without
    /// a result.
    ///
    /// # Performance
    ///
    /// This method is lock-free and completes in O(1) time (~10-50ns).
    #[inline]
    pub fn admit(&self) -> Admission {
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_CLOSED => {
                trace!(name = ?self.name, state = "closed", "Circuit breaker check: allowed");
                Admission::Allowed
            }
            STATE_OPEN => {
                // Check if should transition to half-open
                let last_change_ns = self.last_state_change_ns.load(Ordering::Acquire);
                let current_ns = self.base_instant.elapsed().as_nanos() as u64;
                let elapsed_ns = current_ns.saturating_sub(last_change_ns);
                let timeout_ns = self.config.timeout_seconds * 1_000_000_000;

                if elapsed_ns >= timeout_ns {
                    trace!(
                        name = ?self.name,
                        elapsed_secs = elapsed_ns / 1_000_000_000,
                        "Open timeout reached, transitioning to half-open"
                    );
                    if self.transition_to_half_open() {
                        // The request that ends the open period goes through
                        // without a slot of its own.
                        Admission::Allowed
                    } else {
                        // Another request ended it first; this one is
                        // checked against the period that began.
                        match self.state.load(Ordering::Acquire) {
                            STATE_OPEN => Admission::Refused,
                            STATE_HALF_OPEN => self.admit_half_open(),
                            _ => Admission::Allowed,
                        }
                    }
                } else {
                    trace!(
                        name = ?self.name,
                        state = "open",
                        remaining_secs = (timeout_ns - elapsed_ns) / 1_000_000_000,
                        "Circuit breaker check: blocked"
                    );
                    Admission::Refused
                }
            }
            STATE_HALF_OPEN => self.admit_half_open(),
            _ => {
                // Invalid state, treat as closed for safety
                Admission::Allowed
            }
        }
    }

    /// Async version of is_closed for backward compatibility
    ///
    /// This simply calls the synchronous version. Provided for API compatibility
    /// during migration.
    #[inline]
    pub async fn is_closed_async(&self) -> bool {
        self.is_closed()
    }

    /// Record a successful request (lock-free)
    ///
    /// Resets failure counter and may transition from HalfOpen to Closed
    /// if success threshold is reached.
    #[inline]
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            name = ?self.name,
            consecutive_successes = successes,
            success_threshold = self.config.success_threshold,
            "Recorded success"
        );

        let state = self.state.load(Ordering::Acquire);
        if state == STATE_HALF_OPEN && successes >= self.config.success_threshold.into() {
            self.transition_to_closed();
        }
    }

    /// Async version of record_success for backward compatibility
    #[inline]
    pub async fn record_success_async(&self) {
        self.record_success()
    }

    /// Record a failed request (lock-free)
    ///
    /// Increments failure counter and may transition to Open state
    /// if failure threshold is reached.
    ///
    /// Returns `true` if this failure caused the circuit breaker to
    /// transition to Open state (either from Closed or Half-Open).
    #[inline]
    pub fn record_failure(&self) -> bool {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        trace!(
            name = ?self.name,
            consecutive_failures = failures,
            failure_threshold = self.config.failure_threshold,
            "Recorded failure"
        );

        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_CLOSED if failures >= self.config.failure_threshold.into() => {
                self.transition_to_open();
                true
            }
            STATE_HALF_OPEN => {
                debug!(
                    name = ?self.name,
                    "Failure in half-open state, re-opening circuit"
                );
                self.transition_to_open();
                true
            }
            _ => false,
        }
    }

    /// Async version of record_failure for backward compatibility
    #[inline]
    pub async fn record_failure_async(&self) -> bool {
        self.record_failure()
    }

    /// Give back the half-open trial slot of a request that ended without a
    /// result (lock-free)
    ///
    /// A trial request that neither succeeded nor failed, because the client
    /// went away or a filter refused the request, says nothing about the
    /// service. Without this call it would keep its slot, and the breaker
    /// would wait for a result that never comes. The call is not a success
    /// and not a failure: no counter changes.
    ///
    /// Does nothing unless the breaker is still in the half-open period the
    /// slot was taken in: a slot of an earlier period was dropped with it.
    #[inline]
    pub fn release_half_open_slot(&self, slot: TrialSlot) {
        if self.state.load(Ordering::Acquire) != STATE_HALF_OPEN {
            return;
        }
        let released = self
            .half_open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                (period_of(word) == slot.period && taken_of(word) > 0).then(|| word - 1)
            })
            .is_ok();
        trace!(
            name = ?self.name,
            released,
            "Released half-open trial slot"
        );
    }

    /// Get the current state of the circuit breaker (lock-free)
    #[inline]
    pub fn state(&self) -> CircuitBreakerState {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => CircuitBreakerState::Closed,
            STATE_OPEN => CircuitBreakerState::Open,
            STATE_HALF_OPEN => CircuitBreakerState::HalfOpen,
            _ => CircuitBreakerState::Closed, // Default to closed for safety
        }
    }

    /// Async version of state for backward compatibility
    #[inline]
    pub async fn state_async(&self) -> CircuitBreakerState {
        self.state()
    }

    /// Get the number of consecutive failures
    #[inline]
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get the number of consecutive successes
    #[inline]
    pub fn consecutive_successes(&self) -> u64 {
        self.consecutive_successes.load(Ordering::Relaxed)
    }

    /// Reset the circuit breaker to closed state (lock-free)
    pub fn reset(&self) {
        self.state.store(STATE_CLOSED, Ordering::Release);
        self.last_state_change_ns.store(
            self.base_instant.elapsed().as_nanos() as u64,
            Ordering::Release,
        );
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.clear_half_open_slots();

        if let Some(ref name) = self.name {
            info!(name = %name, "Circuit breaker reset");
        } else {
            info!("Circuit breaker reset");
        }
    }

    /// Async version of reset for backward compatibility
    pub async fn reset_async(&self) {
        self.reset()
    }

    // ========================================================================
    // Half-open admission
    // ========================================================================

    /// Let a trial request in if a slot is free.
    ///
    /// A slot is taken with a compare-and-swap, so a check that finds none
    /// free leaves the count as it is, and a slot given back is free again.
    fn admit_half_open(&self) -> Admission {
        let max_requests = self.config.half_open_max_requests;
        let taken = self
            .half_open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                (taken_of(word) < max_requests).then(|| word + 1)
            });
        let admission = match taken {
            Ok(word) => Admission::Trial(TrialSlot {
                period: period_of(word),
            }),
            Err(_) => match self.restart_stalled_half_open() {
                Some(slot) => Admission::Trial(slot),
                None => Admission::Refused,
            },
        };
        trace!(
            name = ?self.name,
            state = "half-open",
            max_requests = self.config.half_open_max_requests,
            allowed = admission != Admission::Refused,
            "Circuit breaker half-open check"
        );
        admission
    }

    /// Start the half-open period over if its trials are not coming back.
    ///
    /// Every slot is taken. When the period began (or last started over) at
    /// least `timeout_seconds` ago, the trials are taken to be lost: a request
    /// dropped before it could report or give its slot back. The calling
    /// request takes the first slot of a fresh period, and the slots of the
    /// old one can no longer be given back. Only one of several concurrent
    /// callers restarts the period.
    fn restart_stalled_half_open(&self) -> Option<TrialSlot> {
        let started_ns = self.last_state_change_ns.load(Ordering::Acquire);
        let now_ns = self.base_instant.elapsed().as_nanos() as u64;
        let timeout_ns = self.config.timeout_seconds.saturating_mul(1_000_000_000);
        if now_ns.saturating_sub(started_ns) < timeout_ns {
            return None;
        }
        if self
            .last_state_change_ns
            .compare_exchange(started_ns, now_ns, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        let period = self.start_half_open_period(1);
        info!(
            name = ?self.name,
            timeout_seconds = self.config.timeout_seconds,
            "Circuit breaker half-open trials did not finish in time, letting a new trial through"
        );
        Some(TrialSlot { period })
    }

    /// Begin a new half-open period with `taken` slots already taken, and
    /// return its number.
    fn start_half_open_period(&self, taken: u32) -> u32 {
        let previous = self
            .half_open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                Some(pack(period_of(word).wrapping_add(1), taken))
            })
            .unwrap_or_else(|word| word);
        period_of(previous).wrapping_add(1)
    }

    /// Clear the slots taken, keeping the period number.
    fn clear_half_open_slots(&self) {
        let _ = self
            .half_open
            .try_update(Ordering::AcqRel, Ordering::Acquire, |word| {
                Some(pack(period_of(word), 0))
            });
    }

    // ========================================================================
    // State Transitions (all lock-free using compare_exchange)
    // ========================================================================

    fn transition_to_open(&self) {
        // Use compare_exchange to handle concurrent transitions
        let current = self.state.load(Ordering::Acquire);
        if current == STATE_OPEN {
            return; // Already open
        }

        // Try to transition to open
        if self
            .state
            .compare_exchange(current, STATE_OPEN, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.last_state_change_ns.store(
                self.base_instant.elapsed().as_nanos() as u64,
                Ordering::Release,
            );
            self.clear_half_open_slots();

            // Count and threshold are logged so an opening can be checked
            // against the configuration without reconstructing the failures
            // from other log lines (some of which are timeouts at WARN).
            let consecutive_failures = self.consecutive_failures.load(Ordering::Relaxed);
            let from = if current == STATE_HALF_OPEN {
                "half-open"
            } else {
                "closed"
            };
            if let Some(ref name) = self.name {
                warn!(
                    name = %name,
                    from,
                    consecutive_failures,
                    failure_threshold = self.config.failure_threshold,
                    "Circuit breaker opened"
                );
            } else {
                warn!(
                    from,
                    consecutive_failures,
                    failure_threshold = self.config.failure_threshold,
                    "Circuit breaker opened"
                );
            }
        }
    }

    fn transition_to_closed(&self) {
        let current = self.state.load(Ordering::Acquire);
        if current == STATE_CLOSED {
            return; // Already closed
        }

        if self
            .state
            .compare_exchange(current, STATE_CLOSED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.last_state_change_ns.store(
                self.base_instant.elapsed().as_nanos() as u64,
                Ordering::Release,
            );
            self.consecutive_failures.store(0, Ordering::Relaxed);
            self.consecutive_successes.store(0, Ordering::Relaxed);
            self.clear_half_open_slots();

            if let Some(ref name) = self.name {
                info!(name = %name, "Circuit breaker closed");
            } else {
                info!("Circuit breaker closed");
            }
        }
    }

    /// Move from Open to HalfOpen. Returns `true` if this call did.
    fn transition_to_half_open(&self) -> bool {
        // Only transition from Open to HalfOpen
        if self.state.load(Ordering::Acquire) != STATE_OPEN {
            return false;
        }

        if self
            .state
            .compare_exchange(
                STATE_OPEN,
                STATE_HALF_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }

        self.last_state_change_ns.store(
            self.base_instant.elapsed().as_nanos() as u64,
            Ordering::Release,
        );
        self.start_half_open_period(0);

        if let Some(ref name) = self.name {
            info!(name = %name, "Circuit breaker half-open");
        } else {
            info!("Circuit breaker half-open");
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout_seconds: 1,
            half_open_max_requests: 2,
        }
    }

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new(test_config());
        assert!(cb.is_closed());
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_opens_after_failure_threshold() {
        let cb = CircuitBreaker::new(test_config());

        // Record failures up to threshold
        for _ in 0..3 {
            cb.record_failure();
        }

        assert!(!cb.is_closed());
        assert_eq!(cb.state(), CircuitBreakerState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(test_config());

        cb.record_failure();
        cb.record_failure();
        cb.record_success();

        // Should still be closed because success reset the counter
        assert!(cb.is_closed());
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[tokio::test]
    async fn test_half_open_transition() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 1,
            timeout_seconds: 0, // Immediate timeout for testing
            half_open_max_requests: 1,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);

        // Wait and check - should transition to half-open
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(cb.is_closed()); // This triggers transition
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);
    }

    #[tokio::test]
    async fn test_closes_after_success_threshold_in_half_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            timeout_seconds: 0,
            half_open_max_requests: 5,
        };
        let cb = CircuitBreaker::new(config);

        // Open the circuit
        cb.record_failure();

        // Wait and transition to half-open
        tokio::time::sleep(Duration::from_millis(10)).await;
        cb.is_closed();

        // Record successes
        cb.record_success();
        cb.record_success();

        assert_eq!(cb.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_named_circuit_breaker() {
        let cb = CircuitBreaker::with_name(test_config(), "test-service");
        assert!(cb.is_closed());
    }

    #[test]
    fn test_reset() {
        let cb = CircuitBreaker::new(test_config());

        // Open the circuit
        for _ in 0..3 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitBreakerState::Open);

        // Reset
        cb.reset();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
        assert_eq!(cb.consecutive_failures(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let cb = Arc::new(CircuitBreaker::new(test_config()));
        let mut handles = vec![];

        // Spawn multiple threads doing concurrent operations
        for _ in 0..10 {
            let cb_clone = Arc::clone(&cb);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    cb_clone.is_closed();
                    cb_clone.record_success();
                    cb_clone.record_failure();
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Should not panic and state should be valid
        let state = cb.state();
        assert!(matches!(
            state,
            CircuitBreakerState::Closed | CircuitBreakerState::Open | CircuitBreakerState::HalfOpen
        ));
    }

    // ------------------------------------------------------------------
    // Half-open trial requests
    // ------------------------------------------------------------------

    /// Make everything the breaker has timed so far `by` older, without
    /// waiting for it.
    fn age(cb: &mut CircuitBreaker, by: Duration) {
        cb.base_instant = cb
            .base_instant
            .checked_sub(by)
            .expect("the monotonic clock is older than the shift");
    }

    /// A breaker whose open period has run out: the next check ends it.
    fn open_period_over(success_threshold: u32, half_open_max_requests: u32) -> CircuitBreaker {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold,
            timeout_seconds: 1,
            half_open_max_requests,
        });
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);
        age(&mut cb, Duration::from_secs(2));
        cb
    }

    /// Everything the breaker lets through until it refuses.
    fn admit_all(cb: &CircuitBreaker) -> Vec<Admission> {
        let mut admitted = Vec::new();
        loop {
            match cb.admit() {
                Admission::Refused => return admitted,
                other => admitted.push(other),
            }
            assert!(admitted.len() < 100, "the breaker never refuses");
        }
    }

    /// The slots among `admitted`.
    fn slots(admitted: Vec<Admission>) -> Vec<TrialSlot> {
        admitted
            .into_iter()
            .filter_map(|a| match a {
                Admission::Trial(slot) => Some(slot),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn half_open_lets_in_the_request_that_ends_the_open_period_and_one_per_slot() {
        let cb = open_period_over(1, 2);
        let admitted = admit_all(&cb);

        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);
        assert_eq!(admitted.len(), 3, "one more than the two slots");
        assert_eq!(
            admitted[0],
            Admission::Allowed,
            "the request that ends the open period holds no slot"
        );
        assert!(matches!(admitted[1], Admission::Trial(_)));
        assert!(matches!(admitted[2], Admission::Trial(_)));
    }

    #[test]
    fn half_open_slot_of_a_trial_without_a_result_is_given_back() {
        let cb = open_period_over(1, 1);
        let mut slots = slots(admit_all(&cb));
        assert_eq!(slots.len(), 1);
        assert!(!cb.is_closed(), "every slot is taken");

        // The trial ended without a result: the client went away, or an
        // agent refused the request.
        cb.release_half_open_slot(slots.remove(0));

        let again = admit_all(&cb);
        assert_eq!(again.len(), 1, "exactly the freed slot lets a trial in");
        assert!(matches!(again[0], Admission::Trial(_)));
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);
        assert_eq!(cb.consecutive_failures(), 1, "a release is not a result");
        assert_eq!(cb.consecutive_successes(), 0, "a release is not a result");
    }

    #[test]
    fn refused_checks_do_not_use_up_slots() {
        let cb = open_period_over(1, 1);
        let mut slots = slots(admit_all(&cb));
        for _ in 0..50 {
            assert!(!cb.is_closed());
        }

        cb.release_half_open_slot(slots.remove(0));

        assert_eq!(admit_all(&cb).len(), 1, "one release frees one slot");
    }

    /// The request that ends the open period holds no slot. A request that
    /// went in while the breaker was closed has none either. Neither has
    /// anything to give back, so neither can free a slot of a trial still
    /// running.
    #[test]
    fn only_a_request_holding_a_slot_has_one_to_give_back() {
        let cb = open_period_over(1, 1);
        let admitted = admit_all(&cb);
        assert_eq!(admitted.len(), 2);
        assert!(
            matches!(admitted[0], Admission::Allowed),
            "no slot, so no way to release one"
        );
        assert!(matches!(admitted[1], Admission::Trial(_)));
        assert!(!cb.is_closed(), "the one slot is still taken");

        let closed = CircuitBreaker::new(test_config());
        assert_eq!(closed.admit(), Admission::Allowed);
    }

    /// A slot of an earlier period is not given back into a later one.
    #[test]
    fn a_slot_of_an_earlier_period_does_not_free_a_slot_of_a_later_one() {
        let mut cb = open_period_over(1, 1);
        let mut old = slots(admit_all(&cb));
        assert_eq!(old.len(), 1);

        // The trial never reports. The period starts over, and the request
        // that finds it so takes the new slot.
        age(&mut cb, Duration::from_secs(2));
        let mut new = slots(admit_all(&cb));
        assert_eq!(new.len(), 1, "the restart lets exactly one trial in");

        cb.release_half_open_slot(old.remove(0));
        assert!(
            !cb.is_closed(),
            "the old trial's release freed the new trial's slot"
        );

        cb.release_half_open_slot(new.remove(0));
        assert_eq!(admit_all(&cb).len(), 1, "the new trial's own release works");
    }

    /// The same, across the breaker opening and half-open starting again.
    #[test]
    fn a_slot_does_not_outlive_the_period_it_was_taken_in() {
        let mut cb = open_period_over(1, 1);
        let mut old = slots(admit_all(&cb));
        assert_eq!(old.len(), 1);

        assert!(cb.record_failure(), "a failed trial opens the breaker");
        age(&mut cb, Duration::from_secs(2));
        let mut new = slots(admit_all(&cb));
        assert_eq!(new.len(), 1, "the next period has its own slot");

        cb.release_half_open_slot(old.remove(0));
        assert!(!cb.is_closed(), "a stale release freed a slot");
        cb.release_half_open_slot(new.remove(0));
        assert_eq!(admit_all(&cb).len(), 1);
    }

    #[test]
    fn release_outside_half_open_changes_nothing() {
        let cb = open_period_over(1, 1);
        let mut slots = slots(admit_all(&cb));
        assert_eq!(slots.len(), 1);
        cb.record_success();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);

        cb.release_half_open_slot(slots.remove(0));
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
        assert_eq!(cb.admit(), Admission::Allowed);

        // Open again, and not yet half-open: nothing to give back into.
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);
        assert_eq!(cb.admit(), Admission::Refused);
    }

    #[test]
    fn half_open_lets_trials_in_again_when_they_never_finish() {
        let mut cb = open_period_over(1, 1);
        assert_eq!(admit_all(&cb).len(), 2);

        // Trials that report nothing, and are never released either: a
        // request dropped mid-flight. The period must not wait for them
        // forever.
        age(&mut cb, Duration::from_secs(2));

        let admitted = admit_all(&cb);
        assert_eq!(
            admitted.len(),
            1,
            "a new period lets in one trial, the limit applies to it again"
        );
        assert!(matches!(admitted[0], Admission::Trial(_)));
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);
    }

    #[test]
    fn half_open_does_not_start_over_before_the_timeout() {
        let cb = open_period_over(1, 1);
        assert_eq!(admit_all(&cb).len(), 2);
        assert_eq!(admit_all(&cb).len(), 0, "still inside the first period");
    }

    #[test]
    fn half_open_closes_after_a_lost_trial() {
        // Default thresholds: two successes close the breaker, one slot.
        let mut cb = open_period_over(2, 1);
        assert!(cb.is_closed(), "the request that ends the open period");
        assert!(cb.is_closed(), "the trial, which is lost");
        cb.record_success();
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen, "one of two");
        assert!(!cb.is_closed(), "no slot left");

        age(&mut cb, Duration::from_secs(2));

        assert!(cb.is_closed(), "the timeout lets another trial in");
        cb.record_success();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn a_failed_trial_still_reopens_the_breaker() {
        let cb = open_period_over(1, 1);
        let mut slots = slots(admit_all(&cb));
        cb.release_half_open_slot(slots.remove(0));
        assert!(matches!(cb.admit(), Admission::Trial(_)));
        assert!(cb.record_failure(), "the failure opens it again");
        assert_eq!(cb.state(), CircuitBreakerState::Open);
        assert!(!cb.is_closed());
    }

    // Backward compatibility tests with async versions
    #[tokio::test]
    async fn test_async_api_compatibility() {
        let cb = CircuitBreaker::new(test_config());

        assert!(cb.is_closed_async().await);
        cb.record_failure_async().await;
        cb.record_success_async().await;
        let _ = cb.state_async().await;
        cb.reset_async().await;

        assert_eq!(cb.state_async().await, CircuitBreakerState::Closed);
    }
}
