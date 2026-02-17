//! Inference rate limit manager
//!
//! Manages token-based rate limiters, budgets, and cost calculators per route,
//! integrating with the request flow for inference endpoints.

use dashmap::DashMap;
use http::HeaderMap;
use std::sync::Arc;
use tracing::{debug, info, trace};

use zentinel_common::budget::{BudgetAlert, BudgetCheckResult, CostResult};
use zentinel_config::{InferenceConfig, TokenEstimation};

use super::budget::TokenBudgetTracker;
use super::cost::CostCalculator;
use super::providers::create_provider;
use super::rate_limit::{TokenRateLimitResult, TokenRateLimiter};
use super::tokens::{TokenCounter, TokenEstimate, TokenSource};

/// Per-route inference state with rate limiter, budget, and cost tracking.
struct RouteInferenceState {
    /// Token rate limiter (per-minute)
    rate_limiter: Option<TokenRateLimiter>,
    /// Token budget tracker (per-period cumulative)
    budget_tracker: Option<TokenBudgetTracker>,
    /// Cost calculator
    cost_calculator: Option<CostCalculator>,
    /// Token counter (for estimation and actual counting)
    token_counter: TokenCounter,
    /// Route ID for logging
    route_id: String,
}

/// Manager for inference rate limiting, budgets, and cost tracking.
///
/// Each route with inference configuration gets its own TokenRateLimiter,
/// TokenBudgetTracker, and CostCalculator based on the route's configuration.
pub struct InferenceRateLimitManager {
    /// Per-route inference state (keyed by route ID)
    routes: DashMap<String, Arc<RouteInferenceState>>,
}

impl InferenceRateLimitManager {
    /// Create a new inference rate limit manager
    pub fn new() -> Self {
        Self {
            routes: DashMap::new(),
        }
    }

    /// Register a route with inference configuration.
    ///
    /// Creates a TokenRateLimiter, TokenBudgetTracker, and CostCalculator
    /// as configured for the route.
    pub fn register_route(&self, route_id: &str, config: &InferenceConfig) {
        let provider = create_provider(&config.provider);

        // Determine estimation method (from rate_limit or default)
        let estimation_method = config
            .rate_limit
            .as_ref()
            .map(|rl| rl.estimation_method)
            .unwrap_or(TokenEstimation::Chars);

        let token_counter = TokenCounter::new(provider, estimation_method);

        // Create rate limiter if configured
        let rate_limiter = config.rate_limit.as_ref().map(|rl| {
            info!(
                route_id = route_id,
                tokens_per_minute = rl.tokens_per_minute,
                requests_per_minute = ?rl.requests_per_minute,
                burst_tokens = rl.burst_tokens,
                "Registered inference rate limiter"
            );
            TokenRateLimiter::new(rl.clone())
        });

        // Create budget tracker if configured
        let budget_tracker = config.budget.as_ref().map(|budget| {
            info!(
                route_id = route_id,
                period = ?budget.period,
                limit = budget.limit,
                enforce = budget.enforce,
                "Registered token budget tracker"
            );
            TokenBudgetTracker::new(budget.clone(), route_id)
        });

        // Create cost calculator if configured
        let cost_calculator = config.cost_attribution.as_ref().map(|cost| {
            info!(
                route_id = route_id,
                enabled = cost.enabled,
                pricing_rules = cost.pricing.len(),
                "Registered cost calculator"
            );
            CostCalculator::new(cost.clone(), route_id)
        });

        // Only register if at least one feature is enabled
        if rate_limiter.is_some() || budget_tracker.is_some() || cost_calculator.is_some() {
            let state = RouteInferenceState {
                rate_limiter,
                budget_tracker,
                cost_calculator,
                token_counter,
                route_id: route_id.to_string(),
            };

            self.routes.insert(route_id.to_string(), Arc::new(state));

            info!(
                route_id = route_id,
                provider = ?config.provider,
                has_rate_limit = config.rate_limit.is_some(),
                has_budget = config.budget.is_some(),
                has_cost = config.cost_attribution.is_some(),
                "Registered inference route"
            );
        }
    }

    /// Check if a route has inference configuration registered.
    pub fn has_route(&self, route_id: &str) -> bool {
        self.routes.contains_key(route_id)
    }

    /// Check if a route has budget tracking enabled.
    pub fn has_budget(&self, route_id: &str) -> bool {
        self.routes
            .get(route_id)
            .map(|s| s.budget_tracker.is_some())
            .unwrap_or(false)
    }

    /// Check if a route has cost attribution enabled.
    pub fn has_cost_attribution(&self, route_id: &str) -> bool {
        self.routes
            .get(route_id)
            .map(|s| {
                s.cost_calculator
                    .as_ref()
                    .map(|c| c.is_enabled())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }

    /// Check rate limit for a request.
    ///
    /// Returns the rate limit result and the estimated token count.
    pub fn check(
        &self,
        route_id: &str,
        key: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<InferenceCheckResult> {
        let state = self.routes.get(route_id)?;

        // Estimate tokens for the request
        let estimate = state.token_counter.estimate_request(headers, body);

        trace!(
            route_id = route_id,
            key = key,
            estimated_tokens = estimate.tokens,
            model = ?estimate.model,
            "Checking inference rate limit"
        );

        // Check rate limit if configured
        let rate_limit_result = if let Some(ref rate_limiter) = state.rate_limiter {
            rate_limiter.check(key, estimate.tokens)
        } else {
            TokenRateLimitResult::Allowed
        };

        Some(InferenceCheckResult {
            result: rate_limit_result,
            estimated_tokens: estimate.tokens,
            model: estimate.model,
        })
    }

    /// Check budget for a request.
    ///
    /// Returns the budget check result, or None if no budget is configured.
    pub fn check_budget(
        &self,
        route_id: &str,
        tenant: &str,
        estimated_tokens: u64,
    ) -> Option<BudgetCheckResult> {
        let state = self.routes.get(route_id)?;
        let budget_tracker = state.budget_tracker.as_ref()?;

        Some(budget_tracker.check(tenant, estimated_tokens))
    }

    /// Record budget usage after a request completes.
    ///
    /// Returns any budget alerts that were triggered.
    pub fn record_budget(
        &self,
        route_id: &str,
        tenant: &str,
        actual_tokens: u64,
    ) -> Vec<BudgetAlert> {
        if let Some(state) = self.routes.get(route_id) {
            if let Some(ref budget_tracker) = state.budget_tracker {
                return budget_tracker.record(tenant, actual_tokens);
            }
        }
        Vec::new()
    }

    /// Get budget status for a tenant.
    pub fn budget_status(
        &self,
        route_id: &str,
        tenant: &str,
    ) -> Option<zentinel_common::budget::TenantBudgetStatus> {
        let state = self.routes.get(route_id)?;
        let budget_tracker = state.budget_tracker.as_ref()?;
        Some(budget_tracker.status(tenant))
    }

    /// Calculate cost for a request.
    ///
    /// Returns the cost result, or None if cost attribution is not configured.
    pub fn calculate_cost(
        &self,
        route_id: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Option<CostResult> {
        let state = self.routes.get(route_id)?;
        let cost_calculator = state.cost_calculator.as_ref()?;

        if !cost_calculator.is_enabled() {
            return None;
        }

        Some(cost_calculator.calculate(model, input_tokens, output_tokens))
    }

    /// Record actual token usage from response.
    ///
    /// This adjusts the rate limiter based on actual vs estimated usage.
    pub fn record_actual(
        &self,
        route_id: &str,
        key: &str,
        headers: &HeaderMap,
        body: &[u8],
        estimated_tokens: u64,
    ) -> Option<TokenEstimate> {
        let state = self.routes.get(route_id)?;

        // Get actual token count from response
        let actual = state.token_counter.tokens_from_response(headers, body);

        // Only record if we got actual tokens
        if actual.tokens > 0 && actual.source != TokenSource::Estimated {
            // Update rate limiter if configured
            if let Some(ref rate_limiter) = state.rate_limiter {
                rate_limiter.record_actual(key, actual.tokens, estimated_tokens);
            }

            debug!(
                route_id = route_id,
                key = key,
                actual_tokens = actual.tokens,
                estimated_tokens = estimated_tokens,
                source = ?actual.source,
                "Recorded actual token usage"
            );
        }

        Some(actual)
    }

    /// Get the number of registered routes
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Get stats for a route.
    pub fn route_stats(&self, route_id: &str) -> Option<InferenceRouteStats> {
        let state = self.routes.get(route_id)?;

        // Get rate limit stats if available
        let (active_keys, tokens_per_minute, requests_per_minute) =
            if let Some(ref rate_limiter) = state.rate_limiter {
                let stats = rate_limiter.stats();
                (
                    stats.active_keys,
                    stats.tokens_per_minute,
                    stats.requests_per_minute,
                )
            } else {
                (0, 0, None)
            };

        Some(InferenceRouteStats {
            route_id: route_id.to_string(),
            active_keys,
            tokens_per_minute,
            requests_per_minute,
            has_budget: state.budget_tracker.is_some(),
            has_cost_attribution: state
                .cost_calculator
                .as_ref()
                .map(|c| c.is_enabled())
                .unwrap_or(false),
        })
    }

    /// Clean up idle rate limiters (called periodically)
    pub fn cleanup(&self) {
        // Currently, cleanup is handled internally by the rate limiters
        // This is a hook for future cleanup logic
        trace!("Inference rate limit cleanup");
    }
}

impl Default for InferenceRateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of an inference rate limit check
#[derive(Debug)]
pub struct InferenceCheckResult {
    /// Rate limit decision
    pub result: TokenRateLimitResult,
    /// Estimated tokens for this request
    pub estimated_tokens: u64,
    /// Model name if detected
    pub model: Option<String>,
}

impl InferenceCheckResult {
    /// Returns true if the request is allowed
    pub fn is_allowed(&self) -> bool {
        self.result.is_allowed()
    }

    /// Get retry-after value in milliseconds (0 if allowed)
    pub fn retry_after_ms(&self) -> u64 {
        self.result.retry_after_ms()
    }
}

/// Stats for a route's inference configuration.
#[derive(Debug, Clone)]
pub struct InferenceRouteStats {
    /// Route ID
    pub route_id: String,
    /// Number of active rate limit keys
    pub active_keys: usize,
    /// Configured tokens per minute (0 if no rate limiting)
    pub tokens_per_minute: u64,
    /// Configured requests per minute (if any)
    pub requests_per_minute: Option<u64>,
    /// Whether budget tracking is enabled
    pub has_budget: bool,
    /// Whether cost attribution is enabled
    pub has_cost_attribution: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{InferenceProvider, TokenRateLimit};

    fn test_inference_config() -> InferenceConfig {
        InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: Some(TokenRateLimit {
                tokens_per_minute: 10000,
                requests_per_minute: Some(100),
                burst_tokens: 2000,
                estimation_method: TokenEstimation::Chars,
            }),
            budget: None,
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        }
    }

    #[test]
    fn test_register_route() {
        let manager = InferenceRateLimitManager::new();
        manager.register_route("test-route", &test_inference_config());

        assert!(manager.has_route("test-route"));
        assert!(!manager.has_route("other-route"));
    }

    #[test]
    fn test_check_rate_limit() {
        let manager = InferenceRateLimitManager::new();
        manager.register_route("test-route", &test_inference_config());

        let headers = HeaderMap::new();
        let body = br#"{"messages": [{"content": "Hello world"}]}"#;

        let result = manager.check("test-route", "client-1", &headers, body);
        assert!(result.is_some());

        let check = result.unwrap();
        assert!(check.is_allowed());
        assert!(check.estimated_tokens > 0);
    }

    #[test]
    fn test_no_rate_limit_config() {
        let manager = InferenceRateLimitManager::new();

        // Config without any features should not register
        let config = InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: None,
            budget: None,
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        };
        manager.register_route("no-limit-route", &config);

        assert!(!manager.has_route("no-limit-route"));
    }

    #[test]
    fn test_budget_only_config() {
        use zentinel_common::budget::{BudgetPeriod, TokenBudgetConfig};

        let manager = InferenceRateLimitManager::new();

        let config = InferenceConfig {
            provider: InferenceProvider::OpenAi,
            model_header: None,
            rate_limit: None,
            budget: Some(TokenBudgetConfig {
                period: BudgetPeriod::Daily,
                limit: 100000,
                alert_thresholds: vec![0.80, 0.90],
                enforce: true,
                rollover: false,
                burst_allowance: None,
            }),
            cost_attribution: None,
            routing: None,
            model_routing: None,
            guardrails: None,
        };
        manager.register_route("budget-route", &config);

        assert!(manager.has_route("budget-route"));
        assert!(manager.has_budget("budget-route"));
        assert!(!manager.has_cost_attribution("budget-route"));
    }
}
