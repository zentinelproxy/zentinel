//! Token budget tracker for per-tenant cumulative usage tracking.
//!
//! Unlike rate limiting (tokens per minute), budgets track cumulative usage
//! over longer periods (hourly, daily, monthly) with optional enforcement.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, trace, warn};

use zentinel_common::budget::{
    BudgetAlert, BudgetCheckResult, BudgetPeriod, TenantBudgetStatus, TokenBudgetConfig,
};

/// Per-tenant budget state tracking
struct TenantBudgetState {
    /// Period start time
    period_start: Instant,
    /// Period start time as Unix timestamp (for reporting)
    period_start_unix: u64,
    /// Tokens used in current period
    tokens_used: AtomicU64,
    /// Bitmask of alert thresholds that have been triggered
    /// Bit 0 = first threshold, Bit 1 = second, etc.
    alerts_fired: AtomicU8,
}

impl TenantBudgetState {
    fn new() -> Self {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            period_start: Instant::now(),
            period_start_unix: now_unix,
            tokens_used: AtomicU64::new(0),
            alerts_fired: AtomicU8::new(0),
        }
    }

    fn tokens_used(&self) -> u64 {
        self.tokens_used.load(Ordering::Acquire)
    }

    fn add_tokens(&self, tokens: u64) {
        self.tokens_used.fetch_add(tokens, Ordering::AcqRel);
    }

    fn elapsed(&self) -> Duration {
        self.period_start.elapsed()
    }

    fn reset(&mut self) {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.period_start = Instant::now();
        self.period_start_unix = now_unix;
        self.tokens_used.store(0, Ordering::Release);
        self.alerts_fired.store(0, Ordering::Release);
    }

    fn has_fired_alert(&self, threshold_index: u8) -> bool {
        let mask = 1u8 << threshold_index;
        (self.alerts_fired.load(Ordering::Acquire) & mask) != 0
    }

    fn mark_alert_fired(&self, threshold_index: u8) {
        let mask = 1u8 << threshold_index;
        self.alerts_fired.fetch_or(mask, Ordering::AcqRel);
    }
}

/// Token budget tracker for per-tenant usage tracking.
///
/// Tracks cumulative token usage over configurable periods (hourly, daily, monthly)
/// with support for:
/// - Configurable alert thresholds
/// - Hard or soft enforcement
/// - Optional burst allowance
/// - Period rollover
pub struct TokenBudgetTracker {
    /// Budget configuration
    config: TokenBudgetConfig,
    /// Per-tenant budget state
    tenants: DashMap<String, TenantBudgetState>,
    /// Route ID for logging
    route_id: String,
}

impl TokenBudgetTracker {
    /// Create a new token budget tracker with the given configuration.
    pub fn new(config: TokenBudgetConfig, route_id: impl Into<String>) -> Self {
        let route_id = route_id.into();

        info!(
            route_id = %route_id,
            period = ?config.period,
            limit = config.limit,
            enforce = config.enforce,
            rollover = config.rollover,
            "Created token budget tracker"
        );

        Self {
            config,
            tenants: DashMap::new(),
            route_id,
        }
    }

    /// Check if a request with the given token count is allowed.
    ///
    /// This does NOT consume tokens - call `record()` after the request completes.
    pub fn check(&self, tenant: &str, estimated_tokens: u64) -> BudgetCheckResult {
        let state = self.get_or_create_tenant(tenant);
        let period_secs = self.config.period.as_secs();

        // Check if period has expired
        let elapsed = state.elapsed();
        if elapsed.as_secs() >= period_secs {
            drop(state);
            self.reset_period(tenant);
            return self.check(tenant, estimated_tokens);
        }

        let current_used = state.tokens_used();
        let would_use = current_used + estimated_tokens;

        // Check against limit
        if would_use <= self.config.limit {
            let remaining = self.config.limit.saturating_sub(would_use);
            trace!(
                route_id = %self.route_id,
                tenant = tenant,
                current_used = current_used,
                estimated_tokens = estimated_tokens,
                remaining = remaining,
                "Budget check: allowed"
            );
            return BudgetCheckResult::Allowed { remaining };
        }

        // Check burst allowance
        if let Some(burst) = self.config.burst_allowance {
            let burst_limit = self.config.limit + (self.config.limit as f64 * burst) as u64;
            if would_use <= burst_limit {
                let over_by = would_use - self.config.limit;
                let remaining = (self.config.limit as i64) - (would_use as i64);
                trace!(
                    route_id = %self.route_id,
                    tenant = tenant,
                    over_by = over_by,
                    "Budget check: soft limit (burst)"
                );
                return BudgetCheckResult::Soft { remaining, over_by };
            }
        }

        // Budget exhausted
        if self.config.enforce {
            let retry_after = period_secs.saturating_sub(elapsed.as_secs());
            debug!(
                route_id = %self.route_id,
                tenant = tenant,
                current_used = current_used,
                limit = self.config.limit,
                retry_after_secs = retry_after,
                "Budget exhausted"
            );
            BudgetCheckResult::Exhausted {
                retry_after_secs: retry_after,
            }
        } else {
            // Not enforcing, just log and allow
            let over_by = would_use - self.config.limit;
            let remaining = (self.config.limit as i64) - (would_use as i64);
            debug!(
                route_id = %self.route_id,
                tenant = tenant,
                over_by = over_by,
                "Budget exceeded (not enforced)"
            );
            BudgetCheckResult::Soft { remaining, over_by }
        }
    }

    /// Record actual token usage after a request completes.
    ///
    /// Returns any budget alerts that should be fired.
    pub fn record(&self, tenant: &str, actual_tokens: u64) -> Vec<BudgetAlert> {
        let state = self.get_or_create_tenant(tenant);
        let period_secs = self.config.period.as_secs();

        // Check if period has expired
        let elapsed = state.elapsed();
        if elapsed.as_secs() >= period_secs {
            drop(state);
            self.reset_period(tenant);
            return self.record(tenant, actual_tokens);
        }

        // Add tokens
        state.add_tokens(actual_tokens);
        let new_total = state.tokens_used();

        trace!(
            route_id = %self.route_id,
            tenant = tenant,
            tokens = actual_tokens,
            total = new_total,
            limit = self.config.limit,
            "Recorded token usage"
        );

        // Check for alert thresholds
        let mut alerts = Vec::new();
        let usage_pct = new_total as f64 / self.config.limit as f64;

        for (idx, &threshold) in self.config.alert_thresholds.iter().enumerate() {
            if usage_pct >= threshold && !state.has_fired_alert(idx as u8) {
                state.mark_alert_fired(idx as u8);

                let alert = BudgetAlert {
                    tenant: tenant.to_string(),
                    threshold,
                    tokens_used: new_total,
                    tokens_limit: self.config.limit,
                    period_start: state.period_start_unix,
                };

                info!(
                    route_id = %self.route_id,
                    tenant = tenant,
                    threshold_pct = threshold * 100.0,
                    tokens_used = new_total,
                    tokens_limit = self.config.limit,
                    "Budget alert threshold crossed"
                );

                alerts.push(alert);
            }
        }

        alerts
    }

    /// Get the current budget status for a tenant.
    pub fn status(&self, tenant: &str) -> TenantBudgetStatus {
        let state = self.get_or_create_tenant(tenant);
        let period_secs = self.config.period.as_secs();
        let elapsed = state.elapsed();

        let tokens_used = state.tokens_used();
        let tokens_remaining = self.config.limit.saturating_sub(tokens_used);
        let usage_percent = (tokens_used as f64 / self.config.limit as f64) * 100.0;
        let period_end = state.period_start_unix + period_secs;

        TenantBudgetStatus {
            tokens_used,
            tokens_limit: self.config.limit,
            tokens_remaining,
            usage_percent,
            period_start: state.period_start_unix,
            period_end,
            exhausted: tokens_used >= self.config.limit && self.config.enforce,
        }
    }

    /// Reset the budget period for a tenant.
    pub fn reset_period(&self, tenant: &str) {
        if let Some(mut state) = self.tenants.get_mut(tenant) {
            let old_tokens = state.tokens_used();

            // Handle rollover
            if self.config.rollover && old_tokens < self.config.limit {
                let unused = self.config.limit - old_tokens;
                state.reset();
                // Add back unused tokens (capped at limit)
                let rollover = unused.min(self.config.limit);
                state.add_tokens(rollover);
                info!(
                    route_id = %self.route_id,
                    tenant = tenant,
                    rollover_tokens = rollover,
                    "Period reset with rollover"
                );
            } else {
                state.reset();
                debug!(
                    route_id = %self.route_id,
                    tenant = tenant,
                    previous_tokens = old_tokens,
                    "Period reset"
                );
            }
        }
    }

    /// Get the number of tracked tenants.
    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Get the period duration in seconds.
    pub fn period_secs(&self) -> u64 {
        self.config.period.as_secs()
    }

    /// Get the budget limit.
    pub fn limit(&self) -> u64 {
        self.config.limit
    }

    /// Check if enforcement is enabled.
    pub fn is_enforced(&self) -> bool {
        self.config.enforce
    }

    fn get_or_create_tenant(
        &self,
        tenant: &str,
    ) -> dashmap::mapref::one::Ref<'_, String, TenantBudgetState> {
        self.tenants
            .entry(tenant.to_string())
            .or_insert_with(TenantBudgetState::new);
        self.tenants.get(tenant).expect("Just inserted")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TokenBudgetConfig {
        TokenBudgetConfig {
            period: BudgetPeriod::Custom { seconds: 60 },
            limit: 1000,
            alert_thresholds: vec![0.50, 0.80, 0.95],
            enforce: true,
            rollover: false,
            burst_allowance: None,
        }
    }

    #[test]
    fn test_check_allowed() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        let result = tracker.check("tenant-1", 100);
        assert!(result.is_allowed());

        if let BudgetCheckResult::Allowed { remaining } = result {
            assert_eq!(remaining, 900);
        } else {
            panic!("Expected Allowed result");
        }
    }

    #[test]
    fn test_check_exhausted() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        // Use up the budget
        tracker.record("tenant-1", 1000);

        // Next check should be exhausted
        let result = tracker.check("tenant-1", 100);
        assert!(!result.is_allowed());

        if let BudgetCheckResult::Exhausted { retry_after_secs } = result {
            assert!(retry_after_secs > 0);
        } else {
            panic!("Expected Exhausted result");
        }
    }

    #[test]
    fn test_record_alerts() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        // Record 500 tokens (50% threshold)
        let alerts = tracker.record("tenant-1", 500);
        assert_eq!(alerts.len(), 1);
        assert!((alerts[0].threshold - 0.50).abs() < 0.001);

        // Record 300 more tokens (80% threshold)
        let alerts = tracker.record("tenant-1", 300);
        assert_eq!(alerts.len(), 1);
        assert!((alerts[0].threshold - 0.80).abs() < 0.001);

        // Record 200 more tokens (95% + 100% threshold, but 100% not in thresholds)
        let alerts = tracker.record("tenant-1", 200);
        assert_eq!(alerts.len(), 1);
        assert!((alerts[0].threshold - 0.95).abs() < 0.001);

        // No more alerts
        let alerts = tracker.record("tenant-1", 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_status() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        tracker.record("tenant-1", 400);

        let status = tracker.status("tenant-1");
        assert_eq!(status.tokens_used, 400);
        assert_eq!(status.tokens_limit, 1000);
        assert_eq!(status.tokens_remaining, 600);
        assert!((status.usage_percent - 40.0).abs() < 0.001);
        assert!(!status.exhausted);
    }

    #[test]
    fn test_burst_allowance() {
        let mut config = test_config();
        config.burst_allowance = Some(0.10); // 10% burst

        let tracker = TokenBudgetTracker::new(config, "test-route");

        // Use 1050 tokens (5% over limit, within burst)
        tracker.record("tenant-1", 950);

        let result = tracker.check("tenant-1", 100);
        assert!(result.is_allowed());

        if let BudgetCheckResult::Soft { remaining, over_by } = result {
            assert_eq!(over_by, 50);
            assert_eq!(remaining, -50);
        } else {
            panic!("Expected Soft result");
        }
    }

    #[test]
    fn test_no_enforcement() {
        let mut config = test_config();
        config.enforce = false;

        let tracker = TokenBudgetTracker::new(config, "test-route");

        // Use up budget
        tracker.record("tenant-1", 1000);

        // Should still be allowed (soft)
        let result = tracker.check("tenant-1", 100);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_period_reset() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        tracker.record("tenant-1", 500);
        assert_eq!(tracker.status("tenant-1").tokens_used, 500);

        tracker.reset_period("tenant-1");
        assert_eq!(tracker.status("tenant-1").tokens_used, 0);
    }

    #[test]
    fn test_rollover() {
        let mut config = test_config();
        config.rollover = true;

        let tracker = TokenBudgetTracker::new(config, "test-route");

        // Use 300 tokens (700 unused)
        tracker.record("tenant-1", 300);

        // Reset with rollover
        tracker.reset_period("tenant-1");

        // Should have 700 tokens carried over
        let status = tracker.status("tenant-1");
        assert_eq!(status.tokens_used, 700);
    }

    #[test]
    fn test_multiple_tenants() {
        let tracker = TokenBudgetTracker::new(test_config(), "test-route");

        tracker.record("tenant-1", 500);
        tracker.record("tenant-2", 200);

        assert_eq!(tracker.status("tenant-1").tokens_used, 500);
        assert_eq!(tracker.status("tenant-2").tokens_used, 200);
        assert_eq!(tracker.tenant_count(), 2);
    }
}
