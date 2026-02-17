//! Scope-aware circuit breakers for namespaced configurations.
//!
//! This module provides [`ScopedCircuitBreakerManager`] which extends circuit breakers
//! with per-scope (namespace/service) isolation. Each scope can have its own
//! circuit breaker thresholds defined in the configuration.
//!
//! # Scope Isolation
//!
//! Circuit breakers are maintained independently per scope:
//! - Global scope circuit breakers apply to all requests without namespace/service context
//! - Namespace circuit breakers apply to requests within that namespace
//! - Service circuit breakers apply to requests within that specific service
//!
//! # Resolution
//!
//! When checking circuit breakers, the most specific scope is used first,
//! with each scope having independent failure tracking.

use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

use zentinel_common::ids::Scope;
use zentinel_common::types::{CircuitBreakerConfig, CircuitBreakerState};
use zentinel_common::CircuitBreaker;

/// Scope-aware circuit breaker manager.
///
/// Manages circuit breakers per scope, allowing different failure thresholds
/// for different namespaces and services.
pub struct ScopedCircuitBreakerManager {
    /// Circuit breakers per scope, keyed by "{scope}:{upstream_id}"
    breakers: DashMap<String, Arc<CircuitBreaker>>,

    /// Default config per scope
    scope_configs: DashMap<Scope, CircuitBreakerConfig>,

    /// Fallback config for scopes without explicit configuration
    default_config: CircuitBreakerConfig,
}

impl ScopedCircuitBreakerManager {
    /// Create a new scoped circuit breaker manager with default configuration.
    pub fn new() -> Self {
        Self {
            breakers: DashMap::new(),
            scope_configs: DashMap::new(),
            default_config: CircuitBreakerConfig::default(),
        }
    }

    /// Create a new manager with a custom default configuration.
    pub fn with_default_config(config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            scope_configs: DashMap::new(),
            default_config: config,
        }
    }

    /// Set the circuit breaker configuration for a specific scope.
    pub fn set_scope_config(&self, scope: Scope, config: CircuitBreakerConfig) {
        debug!(
            scope = ?scope,
            failure_threshold = config.failure_threshold,
            success_threshold = config.success_threshold,
            timeout_seconds = config.timeout_seconds,
            "Configured circuit breaker for scope"
        );
        self.scope_configs.insert(scope, config);
    }

    /// Get the effective config for a scope, falling back through the scope chain.
    fn get_effective_config(&self, scope: &Scope) -> CircuitBreakerConfig {
        for s in scope.chain() {
            if let Some(config) = self.scope_configs.get(&s) {
                return config.clone();
            }
        }
        self.default_config.clone()
    }

    /// Get or create a circuit breaker for a scope and upstream.
    ///
    /// The circuit breaker is keyed by both scope and upstream ID to ensure
    /// isolation between different upstreams in the same scope.
    pub fn get_breaker(&self, scope: &Scope, upstream_id: &str) -> Arc<CircuitBreaker> {
        let key = Self::make_key(scope, upstream_id);

        self.breakers
            .entry(key.clone())
            .or_insert_with(|| {
                let config = self.get_effective_config(scope);
                let name = format!("{}:{}", scope_to_label(scope), upstream_id);
                trace!(
                    scope = ?scope,
                    upstream_id = upstream_id,
                    "Creating circuit breaker"
                );
                Arc::new(CircuitBreaker::with_name(config, name))
            })
            .clone()
    }

    /// Check if a request should be allowed for a scope and upstream.
    ///
    /// Returns `true` if the circuit breaker is closed or half-open.
    /// This operation is lock-free and completes in O(1) time.
    pub async fn is_allowed(&self, scope: &Scope, upstream_id: &str) -> bool {
        let breaker = self.get_breaker(scope, upstream_id);
        breaker.is_closed() // Lock-free, no await needed
    }

    /// Record a successful request for a scope and upstream.
    /// This operation is lock-free and completes in O(1) time.
    pub async fn record_success(&self, scope: &Scope, upstream_id: &str) {
        let breaker = self.get_breaker(scope, upstream_id);
        breaker.record_success(); // Lock-free, no await needed
    }

    /// Record a failed request for a scope and upstream.
    /// This operation is lock-free and completes in O(1) time.
    pub async fn record_failure(&self, scope: &Scope, upstream_id: &str) {
        let breaker = self.get_breaker(scope, upstream_id);
        breaker.record_failure(); // Lock-free, no await needed
    }

    /// Get the current state of a circuit breaker.
    /// This operation is lock-free and completes in O(1) time.
    pub async fn state(&self, scope: &Scope, upstream_id: &str) -> CircuitBreakerState {
        let breaker = self.get_breaker(scope, upstream_id);
        breaker.state() // Lock-free, no await needed
    }

    /// Reset a specific circuit breaker.
    /// This operation is lock-free and completes in O(1) time.
    pub async fn reset(&self, scope: &Scope, upstream_id: &str) {
        let breaker = self.get_breaker(scope, upstream_id);
        breaker.reset(); // Lock-free, no await needed
    }

    /// Reset all circuit breakers in a scope.
    /// This operation is lock-free per breaker.
    pub async fn reset_scope(&self, scope: &Scope) {
        let prefix = format!("{}:", scope_to_label(scope));
        let keys_to_reset: Vec<String> = self
            .breakers
            .iter()
            .filter(|entry| entry.key().starts_with(&prefix))
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_reset {
            if let Some(breaker) = self.breakers.get(&key) {
                breaker.reset(); // Lock-free, no await needed
            }
        }
    }

    /// Clear all circuit breakers (for reload).
    pub fn clear(&self) {
        self.breakers.clear();
        self.scope_configs.clear();
    }

    /// Get the number of circuit breakers currently tracked.
    pub fn breaker_count(&self) -> usize {
        self.breakers.len()
    }

    /// Get the number of scopes with custom configurations.
    pub fn scope_count(&self) -> usize {
        self.scope_configs.len()
    }

    /// Get all circuit breakers with their states (for monitoring).
    /// This operation is lock-free per breaker.
    pub async fn get_all_states(&self) -> Vec<ScopedBreakerStatus> {
        let mut statuses = Vec::with_capacity(self.breakers.len());

        for entry in self.breakers.iter() {
            let key = entry.key().clone();
            let breaker = entry.value().clone();
            let state = breaker.state(); // Lock-free, no await needed
            let failures = breaker.consecutive_failures();

            // Parse key back to scope and upstream
            let (scope_label, upstream) = match key.split_once(':') {
                Some((s, u)) => (s.to_string(), u.to_string()),
                None => ("global".to_string(), key.clone()),
            };

            statuses.push(ScopedBreakerStatus {
                key,
                scope_label,
                upstream,
                state,
                consecutive_failures: failures,
            });
        }

        statuses
    }

    fn make_key(scope: &Scope, upstream_id: &str) -> String {
        format!("{}:{}", scope_to_label(scope), upstream_id)
    }
}

impl Default for ScopedCircuitBreakerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Status of a scoped circuit breaker for monitoring.
#[derive(Debug, Clone)]
pub struct ScopedBreakerStatus {
    /// Full key (scope:upstream)
    pub key: String,
    /// Scope label
    pub scope_label: String,
    /// Upstream ID
    pub upstream: String,
    /// Current state
    pub state: CircuitBreakerState,
    /// Number of consecutive failures
    pub consecutive_failures: u64,
}

impl ScopedBreakerStatus {
    /// Check if the circuit breaker is open.
    pub fn is_open(&self) -> bool {
        self.state == CircuitBreakerState::Open
    }

    /// Check if the circuit breaker is half-open.
    pub fn is_half_open(&self) -> bool {
        self.state == CircuitBreakerState::HalfOpen
    }

    /// Check if the circuit breaker is closed.
    pub fn is_closed(&self) -> bool {
        self.state == CircuitBreakerState::Closed
    }
}

/// Convert a scope to a label for use in keys and logging.
fn scope_to_label(scope: &Scope) -> String {
    match scope {
        Scope::Global => "global".to_string(),
        Scope::Namespace(ns) => ns.clone(),
        Scope::Service { namespace, service } => format!("{}/{}", namespace, service),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(failure_threshold: u32) -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold,
            success_threshold: 2,
            timeout_seconds: 1,
            half_open_max_requests: 2,
        }
    }

    #[tokio::test]
    async fn test_scope_isolation() {
        let manager = ScopedCircuitBreakerManager::new();

        // Configure different thresholds for different scopes
        manager.set_scope_config(Scope::Global, test_config(5));
        manager.set_scope_config(Scope::Namespace("api".to_string()), test_config(3));

        let global_scope = Scope::Global;
        let api_scope = Scope::Namespace("api".to_string());

        // Trip the API scope circuit breaker (threshold 3)
        for _ in 0..3 {
            manager.record_failure(&api_scope, "backend").await;
        }

        // API scope should be open
        assert!(!manager.is_allowed(&api_scope, "backend").await);

        // Global scope with same upstream should still be allowed
        assert!(manager.is_allowed(&global_scope, "backend").await);
    }

    #[tokio::test]
    async fn test_scope_chain_config_fallback() {
        let manager = ScopedCircuitBreakerManager::new();

        // Only configure namespace
        manager.set_scope_config(Scope::Namespace("api".to_string()), test_config(2));

        // Service should inherit namespace config
        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // 2 failures should trip it (using namespace threshold)
        manager.record_failure(&svc_scope, "backend").await;
        manager.record_failure(&svc_scope, "backend").await;

        assert!(!manager.is_allowed(&svc_scope, "backend").await);
    }

    #[tokio::test]
    async fn test_service_specific_config() {
        let manager = ScopedCircuitBreakerManager::new();

        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        // Configure service-specific threshold
        manager.set_scope_config(svc_scope.clone(), test_config(1));

        // Single failure should trip it
        manager.record_failure(&svc_scope, "backend").await;

        assert!(!manager.is_allowed(&svc_scope, "backend").await);
    }

    #[tokio::test]
    async fn test_reset_single_breaker() {
        let manager = ScopedCircuitBreakerManager::new();
        manager.set_scope_config(Scope::Global, test_config(1));

        let scope = Scope::Global;

        // Trip the breaker
        manager.record_failure(&scope, "backend").await;
        assert!(!manager.is_allowed(&scope, "backend").await);

        // Reset it
        manager.reset(&scope, "backend").await;
        assert!(manager.is_allowed(&scope, "backend").await);
    }

    #[tokio::test]
    async fn test_reset_scope() {
        let manager = ScopedCircuitBreakerManager::new();
        manager.set_scope_config(Scope::Namespace("api".to_string()), test_config(1));

        let scope = Scope::Namespace("api".to_string());

        // Trip multiple breakers
        manager.record_failure(&scope, "backend1").await;
        manager.record_failure(&scope, "backend2").await;

        assert!(!manager.is_allowed(&scope, "backend1").await);
        assert!(!manager.is_allowed(&scope, "backend2").await);

        // Reset all in scope
        manager.reset_scope(&scope).await;

        assert!(manager.is_allowed(&scope, "backend1").await);
        assert!(manager.is_allowed(&scope, "backend2").await);
    }

    #[tokio::test]
    async fn test_get_all_states() {
        let manager = ScopedCircuitBreakerManager::new();
        manager.set_scope_config(Scope::Global, test_config(5));

        // Create some breakers
        manager.get_breaker(&Scope::Global, "backend1");
        manager.get_breaker(&Scope::Global, "backend2");

        let statuses = manager.get_all_states().await;
        assert_eq!(statuses.len(), 2);
        assert!(statuses.iter().all(|s| s.is_closed()));
    }

    #[tokio::test]
    async fn test_success_recovery() {
        let manager = ScopedCircuitBreakerManager::with_default_config(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            timeout_seconds: 0, // Immediate timeout
            half_open_max_requests: 5,
        });

        let scope = Scope::Global;

        // Trip the breaker
        manager.record_failure(&scope, "backend").await;
        manager.record_failure(&scope, "backend").await;

        assert_eq!(
            manager.state(&scope, "backend").await,
            CircuitBreakerState::Open
        );

        // Wait for timeout and trigger half-open
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        manager.is_allowed(&scope, "backend").await;

        assert_eq!(
            manager.state(&scope, "backend").await,
            CircuitBreakerState::HalfOpen
        );

        // Record successes to close
        manager.record_success(&scope, "backend").await;
        manager.record_success(&scope, "backend").await;

        assert_eq!(
            manager.state(&scope, "backend").await,
            CircuitBreakerState::Closed
        );
    }

    #[test]
    fn test_scope_to_label() {
        assert_eq!(scope_to_label(&Scope::Global), "global");
        assert_eq!(scope_to_label(&Scope::Namespace("api".to_string())), "api");
        assert_eq!(
            scope_to_label(&Scope::Service {
                namespace: "api".to_string(),
                service: "payments".to_string(),
            }),
            "api/payments"
        );
    }

    #[test]
    fn test_clear() {
        let manager = ScopedCircuitBreakerManager::new();
        manager.set_scope_config(Scope::Global, test_config(5));
        manager.get_breaker(&Scope::Global, "backend");

        assert_eq!(manager.breaker_count(), 1);
        assert_eq!(manager.scope_count(), 1);

        manager.clear();

        assert_eq!(manager.breaker_count(), 0);
        assert_eq!(manager.scope_count(), 0);
    }
}
