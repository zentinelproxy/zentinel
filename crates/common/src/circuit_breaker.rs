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
    /// Nanoseconds since base_instant when state last changed
    last_state_change_ns: AtomicU64,
    /// Half-open requests count
    half_open_requests: AtomicU64,
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
            half_open_requests: AtomicU64::new(0),
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
            half_open_requests: AtomicU64::new(0),
            name: Some(name),
        }
    }

    /// Check if the circuit breaker allows requests (lock-free)
    ///
    /// Returns `true` if requests should be allowed through.
    /// Automatically transitions from Open to HalfOpen after timeout.
    ///
    /// # Performance
    ///
    /// This method is lock-free and completes in O(1) time (~10-50ns).
    #[inline]
    pub fn is_closed(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_CLOSED => {
                trace!(name = ?self.name, state = "closed", "Circuit breaker check: allowed");
                true
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
                    self.transition_to_half_open();
                    true // Allow one request through
                } else {
                    trace!(
                        name = ?self.name,
                        state = "open",
                        remaining_secs = (timeout_ns - elapsed_ns) / 1_000_000_000,
                        "Circuit breaker check: blocked"
                    );
                    false
                }
            }
            STATE_HALF_OPEN => {
                // Allow limited requests
                let current = self.half_open_requests.fetch_add(1, Ordering::Relaxed);
                let allowed = current < self.config.half_open_max_requests.into();
                trace!(
                    name = ?self.name,
                    state = "half-open",
                    request_num = current + 1,
                    max_requests = self.config.half_open_max_requests,
                    allowed = allowed,
                    "Circuit breaker half-open check"
                );
                allowed
            }
            _ => {
                // Invalid state, treat as closed for safety
                true
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
        self.half_open_requests.store(0, Ordering::Relaxed);

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
            self.half_open_requests.store(0, Ordering::Relaxed);

            if let Some(ref name) = self.name {
                info!(name = %name, "Circuit breaker closed");
            } else {
                info!("Circuit breaker closed");
            }
        }
    }

    fn transition_to_half_open(&self) {
        let current = self.state.load(Ordering::Acquire);
        if current == STATE_HALF_OPEN {
            return; // Already half-open
        }

        // Only transition from Open to HalfOpen
        if current != STATE_OPEN {
            return;
        }

        if self
            .state
            .compare_exchange(
                STATE_OPEN,
                STATE_HALF_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.last_state_change_ns.store(
                self.base_instant.elapsed().as_nanos() as u64,
                Ordering::Release,
            );
            self.half_open_requests.store(0, Ordering::Relaxed);

            if let Some(ref name) = self.name {
                info!(name = %name, "Circuit breaker half-open");
            } else {
                info!("Circuit breaker half-open");
            }
        }
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
