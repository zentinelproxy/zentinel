//! Scope-aware rate limiting for namespaced configurations.
//!
//! This module provides [`ScopedRateLimitManager`] which extends rate limiting
//! with per-scope (namespace/service) isolation. Each scope can have its own
//! rate limits defined in the configuration.
//!
//! # Scope Isolation
//!
//! Rate limits are enforced independently per scope:
//! - Global scope limits apply to all requests without namespace/service context
//! - Namespace limits apply to requests within that namespace
//! - Service limits apply to requests within that specific service
//!
//! # Resolution
//!
//! When checking rate limits, the most specific scope is used first,
//! falling back to parent scopes if no limit is configured.

use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

use sentinel_common::ids::Scope;
use sentinel_common::limits::Limits;
use sentinel_config::FlattenedConfig;

use crate::rate_limit::{
    HeaderAccessor, RateLimitConfig, RateLimitManager, RateLimitResult, RateLimiterPool,
};

/// Scope-aware rate limit manager.
///
/// Manages rate limiters per scope, allowing different limits for different
/// namespaces and services.
pub struct ScopedRateLimitManager {
    /// Rate limit managers per scope
    scope_managers: DashMap<Scope, Arc<RateLimitManager>>,

    /// Default limits from scope configuration
    scope_limits: DashMap<Scope, Limits>,

    /// Fallback manager for requests without scope context
    fallback_manager: Arc<RateLimitManager>,
}

impl ScopedRateLimitManager {
    /// Create a new scoped rate limit manager.
    pub fn new() -> Self {
        Self {
            scope_managers: DashMap::new(),
            scope_limits: DashMap::new(),
            fallback_manager: Arc::new(RateLimitManager::new()),
        }
    }

    /// Create a scoped rate limit manager from a flattened configuration.
    pub fn from_flattened(config: &FlattenedConfig) -> Self {
        let manager = Self::new();

        // Load scope limits
        for (scope, limits) in &config.scope_limits {
            manager.set_scope_limits(scope.clone(), limits.clone());
        }

        manager
    }

    /// Set limits for a specific scope.
    pub fn set_scope_limits(&self, scope: Scope, limits: Limits) {
        // Create a rate limit manager for this scope if rate limiting is configured
        // Use global RPS limit for scope-level limiting; per-client/per-route
        // limits are handled by the RateLimitManager internally
        if let Some(max_rps) = limits.max_requests_per_second_global {
            // Default burst to 10x RPS (same as MultiRateLimiter)
            let burst = max_rps * 10;
            let scope_manager = RateLimitManager::with_global_limit(max_rps, burst);

            debug!(
                scope = ?scope,
                max_rps = max_rps,
                burst = burst,
                "Configured rate limit for scope"
            );

            self.scope_managers
                .insert(scope.clone(), Arc::new(scope_manager));
        }

        self.scope_limits.insert(scope, limits);
    }

    /// Register a route-specific rate limiter within a scope.
    pub fn register_route(&self, scope: &Scope, route_id: &str, config: RateLimitConfig) {
        let manager = self
            .scope_managers
            .entry(scope.clone())
            .or_insert_with(|| Arc::new(RateLimitManager::new()));

        manager.register_route(route_id, config);

        trace!(
            scope = ?scope,
            route_id = route_id,
            "Registered route rate limiter in scope"
        );
    }

    /// Check rate limit for a request within a scope.
    ///
    /// Checks the scope-specific rate limit, falling back through the scope chain
    /// if no limit is configured for the exact scope.
    pub fn check(
        &self,
        scope: &Scope,
        route_id: &str,
        client_ip: &str,
        path: &str,
        headers: Option<&impl HeaderAccessor>,
    ) -> ScopedRateLimitResult {
        // Try each scope in the chain
        for s in scope.chain() {
            if let Some(manager) = self.scope_managers.get(&s) {
                let result = manager.check(route_id, client_ip, path, headers);

                if !result.allowed {
                    return ScopedRateLimitResult {
                        inner: result,
                        scope: s,
                        scope_limited: true,
                    };
                }

                // If we got rate limit info, return it even if allowed
                if result.limit > 0 {
                    return ScopedRateLimitResult {
                        inner: result,
                        scope: s,
                        scope_limited: false,
                    };
                }
            }
        }

        // No scope-specific limit found, use fallback
        let result = self
            .fallback_manager
            .check(route_id, client_ip, path, headers);

        ScopedRateLimitResult {
            inner: result,
            scope: Scope::Global,
            scope_limited: false,
        }
    }

    /// Check if any rate limiting is configured for a scope.
    pub fn is_enabled_for_scope(&self, scope: &Scope) -> bool {
        for s in scope.chain() {
            if let Some(manager) = self.scope_managers.get(&s) {
                if manager.is_enabled() {
                    return true;
                }
            }
        }
        self.fallback_manager.is_enabled()
    }

    /// Get the effective limits for a scope.
    ///
    /// Returns the limits from the most specific scope in the chain.
    pub fn get_effective_limits(&self, scope: &Scope) -> Option<Limits> {
        for s in scope.chain() {
            if let Some(limits) = self.scope_limits.get(&s) {
                return Some(limits.clone());
            }
        }
        None
    }

    /// Perform periodic cleanup across all scope managers.
    pub fn cleanup(&self) {
        for entry in self.scope_managers.iter() {
            entry.value().cleanup();
        }
        self.fallback_manager.cleanup();
    }

    /// Get the number of scopes with rate limiting configured.
    pub fn scope_count(&self) -> usize {
        self.scope_managers.len()
    }

    /// Clear all scope managers (for reload).
    pub fn clear(&self) {
        self.scope_managers.clear();
        self.scope_limits.clear();
    }

    /// Reload from a new flattened configuration.
    pub fn reload(&self, config: &FlattenedConfig) {
        self.clear();

        for (scope, limits) in &config.scope_limits {
            self.set_scope_limits(scope.clone(), limits.clone());
        }

        debug!(
            scope_count = self.scope_count(),
            "Reloaded scoped rate limit configuration"
        );
    }
}

impl Default for ScopedRateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a scoped rate limit check.
#[derive(Debug, Clone)]
pub struct ScopedRateLimitResult {
    /// The underlying rate limit result
    pub inner: RateLimitResult,

    /// The scope that enforced the limit
    pub scope: Scope,

    /// Whether this request was limited by a scope-specific limit
    pub scope_limited: bool,
}

impl ScopedRateLimitResult {
    /// Whether the request is allowed.
    pub fn allowed(&self) -> bool {
        self.inner.allowed
    }

    /// Get the namespace if the limit was enforced by a namespace or service scope.
    pub fn namespace(&self) -> Option<&str> {
        match &self.scope {
            Scope::Global => None,
            Scope::Namespace(ns) => Some(ns),
            Scope::Service { namespace, .. } => Some(namespace),
        }
    }

    /// Get the service if the limit was enforced by a service scope.
    pub fn service(&self) -> Option<&str> {
        match &self.scope {
            Scope::Service { service, .. } => Some(service),
            _ => None,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_limits_with_rate_limit(rps: u32, _burst: u32) -> Limits {
        let mut limits = Limits::default();
        // Set the global rate limit - burst is derived as rps * 10 internally
        limits.max_requests_per_second_global = Some(rps);
        limits
    }

    struct NoHeaders;
    impl HeaderAccessor for NoHeaders {
        fn get_header(&self, _name: &str) -> Option<String> {
            None
        }
    }

    #[test]
    fn test_scope_isolation() {
        let manager = ScopedRateLimitManager::new();

        // Set different limits for different scopes
        manager.set_scope_limits(Scope::Global, test_limits_with_rate_limit(10, 5));
        manager.set_scope_limits(
            Scope::Namespace("api".to_string()),
            test_limits_with_rate_limit(5, 2),
        );

        // Check from namespace scope - should use namespace limit (5 rps)
        let ns_scope = Scope::Namespace("api".to_string());
        for _ in 0..5 {
            let result = manager.check(&ns_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
            assert!(result.allowed());
        }

        // 6th request should be limited
        let result = manager.check(&ns_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result.allowed());
        assert!(matches!(result.scope, Scope::Namespace(_)));

        // Different namespace should still have quota (uses global)
        let other_ns = Scope::Namespace("other".to_string());
        let result = manager.check(&other_ns, "route", "127.0.0.2", "/", Option::<&NoHeaders>::None);
        assert!(result.allowed());
    }

    #[test]
    fn test_scope_chain_fallback() {
        let manager = ScopedRateLimitManager::new();

        // Only set global limits
        manager.set_scope_limits(Scope::Global, test_limits_with_rate_limit(3, 1));

        // Check from service scope - should fall back to global
        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };

        for _ in 0..3 {
            let result = manager.check(&svc_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
            assert!(result.allowed());
        }

        // 4th request should be limited by global
        let result = manager.check(&svc_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result.allowed());
        assert_eq!(result.scope, Scope::Global);
    }

    #[test]
    fn test_service_scope_limits() {
        let manager = ScopedRateLimitManager::new();

        // Set service-specific limits
        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        manager.set_scope_limits(svc_scope.clone(), test_limits_with_rate_limit(2, 1));

        // Service should use its own limits
        let result1 = manager.check(&svc_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        let result2 = manager.check(&svc_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(result1.allowed());
        assert!(result2.allowed());

        // 3rd should be limited
        let result3 = manager.check(&svc_scope, "route", "127.0.0.1", "/", Option::<&NoHeaders>::None);
        assert!(!result3.allowed());
        assert!(matches!(result3.scope, Scope::Service { .. }));
    }

    #[test]
    fn test_effective_limits() {
        let manager = ScopedRateLimitManager::new();

        manager.set_scope_limits(Scope::Global, test_limits_with_rate_limit(100, 50));
        manager.set_scope_limits(
            Scope::Namespace("api".to_string()),
            test_limits_with_rate_limit(50, 25),
        );

        // Service scope should get namespace limits (no service-specific)
        let svc_scope = Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        };
        let limits = manager.get_effective_limits(&svc_scope).unwrap();
        assert_eq!(limits.max_requests_per_second_global.unwrap(), 50);

        // Unknown namespace should get global limits
        let other_ns = Scope::Namespace("other".to_string());
        let limits = manager.get_effective_limits(&other_ns).unwrap();
        assert_eq!(limits.max_requests_per_second_global.unwrap(), 100);
    }

    #[test]
    fn test_is_enabled_for_scope() {
        let manager = ScopedRateLimitManager::new();

        // Initially not enabled
        assert!(!manager.is_enabled_for_scope(&Scope::Global));

        // Enable for namespace
        manager.set_scope_limits(
            Scope::Namespace("api".to_string()),
            test_limits_with_rate_limit(10, 5),
        );

        // Namespace and its services should be enabled
        assert!(manager.is_enabled_for_scope(&Scope::Namespace("api".to_string())));
        assert!(manager.is_enabled_for_scope(&Scope::Service {
            namespace: "api".to_string(),
            service: "payments".to_string(),
        }));

        // Other namespaces should not
        assert!(!manager.is_enabled_for_scope(&Scope::Namespace("other".to_string())));
    }

    #[test]
    fn test_reload() {
        let manager = ScopedRateLimitManager::new();
        manager.set_scope_limits(Scope::Global, test_limits_with_rate_limit(10, 5));

        assert_eq!(manager.scope_count(), 1);

        // Create new config and reload
        let mut new_config = FlattenedConfig::new();
        new_config.scope_limits.insert(
            Scope::Namespace("api".to_string()),
            test_limits_with_rate_limit(20, 10),
        );
        new_config.scope_limits.insert(
            Scope::Namespace("web".to_string()),
            test_limits_with_rate_limit(30, 15),
        );

        manager.reload(&new_config);

        assert_eq!(manager.scope_count(), 2);
        assert!(manager.is_enabled_for_scope(&Scope::Namespace("api".to_string())));
        assert!(manager.is_enabled_for_scope(&Scope::Namespace("web".to_string())));
    }
}
