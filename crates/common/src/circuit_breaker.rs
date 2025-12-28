//! Circuit breaker implementation for resilient service protection
//!
//! This module provides a unified circuit breaker implementation used by both
//! agent connections and upstream pools to prevent cascade failures.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::types::{CircuitBreakerConfig, CircuitBreakerState};

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
/// # Example
///
/// ```ignore
/// let breaker = CircuitBreaker::new(CircuitBreakerConfig::default());
///
/// // Before making a request
/// if breaker.is_closed().await {
///     match make_request().await {
///         Ok(_) => breaker.record_success().await,
///         Err(_) => breaker.record_failure().await,
///     }
/// }
/// ```
pub struct CircuitBreaker {
    /// Configuration
    config: CircuitBreakerConfig,
    /// Current state
    state: Arc<RwLock<CircuitBreakerState>>,
    /// Consecutive failures
    consecutive_failures: AtomicU64,
    /// Consecutive successes
    consecutive_successes: AtomicU64,
    /// Last state change time
    last_state_change: Arc<RwLock<Instant>>,
    /// Half-open requests count
    half_open_requests: AtomicU64,
    /// Optional name for logging
    name: Option<String>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
            half_open_requests: AtomicU64::new(0),
            name: None,
        }
    }

    /// Create a new circuit breaker with a name for logging
    pub fn with_name(config: CircuitBreakerConfig, name: impl Into<String>) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
            last_state_change: Arc::new(RwLock::new(Instant::now())),
            half_open_requests: AtomicU64::new(0),
            name: Some(name.into()),
        }
    }

    /// Check if the circuit breaker allows requests
    ///
    /// Returns `true` if requests should be allowed through.
    /// Automatically transitions from Open to HalfOpen after timeout.
    pub async fn is_closed(&self) -> bool {
        let state = *self.state.read().await;
        match state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if should transition to half-open
                let last_change = *self.last_state_change.read().await;
                if last_change.elapsed() >= Duration::from_secs(self.config.timeout_seconds) {
                    self.transition_to_half_open().await;
                    true // Allow one request through
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Allow limited requests
                self.half_open_requests.fetch_add(1, Ordering::Relaxed)
                    < self.config.half_open_max_requests.into()
            }
        }
    }

    /// Record a successful request
    ///
    /// Resets failure counter and may transition from HalfOpen to Closed
    /// if success threshold is reached.
    pub async fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

        let state = *self.state.read().await;
        if state == CircuitBreakerState::HalfOpen
            && successes >= self.config.success_threshold.into()
        {
            self.transition_to_closed().await;
        }
    }

    /// Record a failed request
    ///
    /// Increments failure counter and may transition to Open state
    /// if failure threshold is reached.
    pub async fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        let state = *self.state.read().await;
        match state {
            CircuitBreakerState::Closed if failures >= self.config.failure_threshold.into() => {
                self.transition_to_open().await;
            }
            CircuitBreakerState::HalfOpen => {
                self.transition_to_open().await;
            }
            _ => {}
        }
    }

    /// Get the current state of the circuit breaker
    pub async fn state(&self) -> CircuitBreakerState {
        *self.state.read().await
    }

    /// Get the number of consecutive failures
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    /// Get the number of consecutive successes
    pub fn consecutive_successes(&self) -> u64 {
        self.consecutive_successes.load(Ordering::Relaxed)
    }

    /// Reset the circuit breaker to closed state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::Closed;
        *self.last_state_change.write().await = Instant::now();
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.half_open_requests.store(0, Ordering::Relaxed);

        if let Some(ref name) = self.name {
            info!(name = %name, "Circuit breaker reset");
        } else {
            info!("Circuit breaker reset");
        }
    }

    // ========================================================================
    // State Transitions
    // ========================================================================

    async fn transition_to_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::Open;
        *self.last_state_change.write().await = Instant::now();

        if let Some(ref name) = self.name {
            warn!(name = %name, "Circuit breaker opened");
        } else {
            warn!("Circuit breaker opened");
        }
    }

    async fn transition_to_closed(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::Closed;
        *self.last_state_change.write().await = Instant::now();
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.half_open_requests.store(0, Ordering::Relaxed);

        if let Some(ref name) = self.name {
            info!(name = %name, "Circuit breaker closed");
        } else {
            info!("Circuit breaker closed");
        }
    }

    async fn transition_to_half_open(&self) {
        let mut state = self.state.write().await;
        *state = CircuitBreakerState::HalfOpen;
        *self.last_state_change.write().await = Instant::now();
        self.half_open_requests.store(0, Ordering::Relaxed);

        if let Some(ref name) = self.name {
            info!(name = %name, "Circuit breaker half-open");
        } else {
            info!("Circuit breaker half-open");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout_seconds: 1,
            half_open_max_requests: 2,
        }
    }

    #[tokio::test]
    async fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new(test_config());
        assert!(cb.is_closed().await);
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn test_opens_after_failure_threshold() {
        let cb = CircuitBreaker::new(test_config());

        // Record failures up to threshold
        for _ in 0..3 {
            cb.record_failure().await;
        }

        assert!(!cb.is_closed().await);
        assert_eq!(cb.state().await, CircuitBreakerState::Open);
    }

    #[tokio::test]
    async fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(test_config());

        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;

        // Should still be closed because success reset the counter
        assert!(cb.is_closed().await);
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
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Wait and check - should transition to half-open
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(cb.is_closed().await); // This triggers transition
        assert_eq!(cb.state().await, CircuitBreakerState::HalfOpen);
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
        cb.record_failure().await;

        // Wait and transition to half-open
        tokio::time::sleep(Duration::from_millis(10)).await;
        cb.is_closed().await;

        // Record successes
        cb.record_success().await;
        cb.record_success().await;

        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn test_named_circuit_breaker() {
        let cb = CircuitBreaker::with_name(test_config(), "test-service");
        assert!(cb.is_closed().await);
    }

    #[tokio::test]
    async fn test_reset() {
        let cb = CircuitBreaker::new(test_config());

        // Open the circuit
        for _ in 0..3 {
            cb.record_failure().await;
        }
        assert_eq!(cb.state().await, CircuitBreakerState::Open);

        // Reset
        cb.reset().await;
        assert_eq!(cb.state().await, CircuitBreakerState::Closed);
        assert_eq!(cb.consecutive_failures(), 0);
    }
}
