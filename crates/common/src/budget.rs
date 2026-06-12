//! Token budget management and cost attribution types.
//!
//! This module provides configuration types for:
//! - Per-tenant token budgets with period-based limits
//! - Cost attribution with per-model pricing
//!
//! # Token Budgets
//!
//! Token budgets allow tracking cumulative token usage per tenant over
//! configurable periods (hourly, daily, monthly). This enables:
//! - Quota enforcement for API consumers
//! - Usage alerts at configurable thresholds
//! - Optional rollover of unused tokens
//!
//! # Cost Attribution
//!
//! Cost attribution tracks the monetary cost of inference requests based
//! on model-specific pricing for input and output tokens.

use serde::{Deserialize, Serialize};

// ============================================================================
// Budget Configuration
// ============================================================================

/// Token budget configuration for per-tenant usage tracking.
///
/// Budgets track cumulative token usage over a configurable period,
/// with optional alerts and enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudgetConfig {
    /// Budget period (when the budget resets)
    #[serde(default)]
    pub period: BudgetPeriod,

    /// Total tokens allowed in the period
    pub limit: u64,

    /// Alert thresholds as percentages (e.g., [0.80, 0.90, 0.95])
    /// Triggers alerts when usage crosses these thresholds
    #[serde(default = "default_alert_thresholds")]
    pub alert_thresholds: Vec<f64>,

    /// Whether to enforce the limit (block requests when exhausted)
    #[serde(default = "default_true")]
    pub enforce: bool,

    /// Allow unused tokens to roll over to the next period
    #[serde(default)]
    pub rollover: bool,

    /// Allow burst usage above limit as a percentage (soft limit)
    /// E.g., 0.10 allows 10% burst above the limit
    #[serde(default)]
    pub burst_allowance: Option<f64>,

    /// Maximum number of distinct tenants tracked in memory
    ///
    /// Bounds per-tenant budget state. When the cap is reached, tenants
    /// whose period has expired are evicted first; if none are expired,
    /// the tenants with the oldest periods are evicted.
    #[serde(default = "default_max_tenants")]
    pub max_tenants: usize,
}

fn default_alert_thresholds() -> Vec<f64> {
    vec![0.80, 0.90, 0.95]
}

fn default_true() -> bool {
    true
}

/// Default bound on distinct tenants tracked per budget tracker.
pub fn default_max_tenants() -> usize {
    10_000
}

impl Default for TokenBudgetConfig {
    fn default() -> Self {
        Self {
            period: BudgetPeriod::Daily,
            limit: 1_000_000, // 1M tokens
            alert_thresholds: default_alert_thresholds(),
            enforce: true,
            rollover: false,
            burst_allowance: None,
            max_tenants: default_max_tenants(),
        }
    }
}

/// Budget period defining when the budget resets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetPeriod {
    /// Resets every hour
    Hourly,
    /// Resets every day at midnight UTC
    #[default]
    Daily,
    /// Resets on the first of each month at midnight UTC
    Monthly,
    /// Custom period in seconds
    Custom {
        /// Period duration in seconds
        seconds: u64,
    },
}

impl BudgetPeriod {
    /// Get the period duration in seconds.
    pub fn as_secs(&self) -> u64 {
        match self {
            BudgetPeriod::Hourly => 3600,
            BudgetPeriod::Daily => 86400,
            BudgetPeriod::Monthly => 2_592_000, // 30 days
            BudgetPeriod::Custom { seconds } => *seconds,
        }
    }
}

// ============================================================================
// Cost Attribution Configuration
// ============================================================================

/// Cost attribution configuration for tracking inference costs.
///
/// Allows per-model pricing with separate input/output token rates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostAttributionConfig {
    /// Whether cost attribution is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Per-model pricing rules (evaluated in order, first match wins)
    #[serde(default)]
    pub pricing: Vec<ModelPricing>,

    /// Default cost per million input tokens (fallback)
    #[serde(default = "default_input_cost")]
    pub default_input_cost: f64,

    /// Default cost per million output tokens (fallback)
    #[serde(default = "default_output_cost")]
    pub default_output_cost: f64,

    /// Currency for cost values (default: USD)
    #[serde(default = "default_currency")]
    pub currency: String,
}

fn default_input_cost() -> f64 {
    1.0
}

fn default_output_cost() -> f64 {
    2.0
}

fn default_currency() -> String {
    "USD".to_string()
}

impl Default for CostAttributionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pricing: Vec::new(),
            default_input_cost: default_input_cost(),
            default_output_cost: default_output_cost(),
            currency: default_currency(),
        }
    }
}

/// Per-model pricing configuration.
///
/// The `model_pattern` supports glob-style matching:
/// - `gpt-4*` matches `gpt-4`, `gpt-4-turbo`, `gpt-4o`, etc.
/// - `claude-3-*` matches all Claude 3 variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPricing {
    /// Model name or pattern (glob-style matching with `*`)
    pub model_pattern: String,

    /// Cost per million input tokens
    pub input_cost_per_million: f64,

    /// Cost per million output tokens
    pub output_cost_per_million: f64,

    /// Optional currency override (defaults to parent config currency)
    #[serde(default)]
    pub currency: Option<String>,
}

impl ModelPricing {
    /// Create new model pricing with the given pattern and costs.
    pub fn new(pattern: impl Into<String>, input_cost: f64, output_cost: f64) -> Self {
        Self {
            model_pattern: pattern.into(),
            input_cost_per_million: input_cost,
            output_cost_per_million: output_cost,
            currency: None,
        }
    }

    /// Check if this pricing rule matches the given model name.
    pub fn matches(&self, model: &str) -> bool {
        if self.model_pattern.contains('*') {
            // Glob-style matching
            let pattern = &self.model_pattern;
            if let Some(inner) = pattern.strip_prefix('*').and_then(|p| p.strip_suffix('*')) {
                // *pattern* - contains
                model.contains(inner)
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                // *pattern - ends with
                model.ends_with(suffix)
            } else if let Some(prefix) = pattern.strip_suffix('*') {
                // pattern* - starts with
                model.starts_with(prefix)
            } else {
                // Complex pattern - split and match parts
                let parts: Vec<&str> = pattern.split('*').collect();
                if parts.is_empty() {
                    return true;
                }

                let mut remaining = model;
                for (i, part) in parts.iter().enumerate() {
                    if part.is_empty() {
                        continue;
                    }
                    if i == 0 {
                        // First part must be prefix
                        if !remaining.starts_with(part) {
                            return false;
                        }
                        remaining = &remaining[part.len()..];
                    } else if i == parts.len() - 1 {
                        // Last part must be suffix
                        if !remaining.ends_with(part) {
                            return false;
                        }
                    } else {
                        // Middle parts must exist
                        if let Some(idx) = remaining.find(part) {
                            remaining = &remaining[idx + part.len()..];
                        } else {
                            return false;
                        }
                    }
                }
                true
            }
        } else {
            // Exact match
            self.model_pattern == model
        }
    }

    /// Calculate cost for the given token counts.
    pub fn calculate_cost(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        let input_cost = (input_tokens as f64 / 1_000_000.0) * self.input_cost_per_million;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * self.output_cost_per_million;
        input_cost + output_cost
    }
}

// ============================================================================
// Result Types
// ============================================================================

/// Result of a budget check operation.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetCheckResult {
    /// Request is allowed within budget
    Allowed {
        /// Tokens remaining after this request
        remaining: u64,
    },
    /// Budget is exhausted
    Exhausted {
        /// Seconds until the period resets
        retry_after_secs: u64,
    },
    /// Request allowed via burst allowance (soft limit)
    Soft {
        /// Tokens remaining (negative means over budget)
        remaining: i64,
        /// Amount over the base limit
        over_by: u64,
    },
}

impl BudgetCheckResult {
    /// Returns true if the request should be allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. } | Self::Soft { .. })
    }

    /// Returns the retry-after value in seconds, or 0 if allowed.
    pub fn retry_after_secs(&self) -> u64 {
        match self {
            Self::Exhausted { retry_after_secs } => *retry_after_secs,
            _ => 0,
        }
    }
}

/// Alert generated when budget threshold is crossed.
#[derive(Debug, Clone)]
pub struct BudgetAlert {
    /// Tenant/client identifier
    pub tenant: String,
    /// Threshold that was crossed (e.g., 0.80 for 80%)
    pub threshold: f64,
    /// Current token usage
    pub tokens_used: u64,
    /// Budget limit
    pub tokens_limit: u64,
    /// Current period start time (Unix timestamp)
    pub period_start: u64,
}

impl BudgetAlert {
    /// Get the usage percentage.
    pub fn usage_percent(&self) -> f64 {
        if self.tokens_limit == 0 {
            return 0.0;
        }
        (self.tokens_used as f64 / self.tokens_limit as f64) * 100.0
    }
}

/// Current budget status for a tenant.
#[derive(Debug, Clone)]
pub struct TenantBudgetStatus {
    /// Tokens used in current period
    pub tokens_used: u64,
    /// Budget limit
    pub tokens_limit: u64,
    /// Tokens remaining
    pub tokens_remaining: u64,
    /// Usage percentage
    pub usage_percent: f64,
    /// Period start time (Unix timestamp)
    pub period_start: u64,
    /// Period end time (Unix timestamp)
    pub period_end: u64,
    /// Whether budget is exhausted
    pub exhausted: bool,
}

/// Result of a cost calculation.
#[derive(Debug, Clone)]
pub struct CostResult {
    /// Cost for input tokens
    pub input_cost: f64,
    /// Cost for output tokens
    pub output_cost: f64,
    /// Total cost (input + output)
    pub total_cost: f64,
    /// Currency
    pub currency: String,
    /// Model that was used
    pub model: String,
    /// Number of input tokens
    pub input_tokens: u64,
    /// Number of output tokens
    pub output_tokens: u64,
}

impl CostResult {
    /// Create a new cost result.
    pub fn new(
        model: impl Into<String>,
        input_tokens: u64,
        output_tokens: u64,
        input_cost: f64,
        output_cost: f64,
        currency: impl Into<String>,
    ) -> Self {
        Self {
            input_cost,
            output_cost,
            total_cost: input_cost + output_cost,
            currency: currency.into(),
            model: model.into(),
            input_tokens,
            output_tokens,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_period_as_secs() {
        assert_eq!(BudgetPeriod::Hourly.as_secs(), 3600);
        assert_eq!(BudgetPeriod::Daily.as_secs(), 86400);
        assert_eq!(BudgetPeriod::Monthly.as_secs(), 2_592_000);
        assert_eq!(BudgetPeriod::Custom { seconds: 7200 }.as_secs(), 7200);
    }

    #[test]
    fn test_model_pricing_exact_match() {
        let pricing = ModelPricing::new("gpt-4", 30.0, 60.0);
        assert!(pricing.matches("gpt-4"));
        assert!(!pricing.matches("gpt-4-turbo"));
        assert!(!pricing.matches("gpt-3.5"));
    }

    #[test]
    fn test_model_pricing_prefix_match() {
        let pricing = ModelPricing::new("gpt-4*", 30.0, 60.0);
        assert!(pricing.matches("gpt-4"));
        assert!(pricing.matches("gpt-4-turbo"));
        assert!(pricing.matches("gpt-4o"));
        assert!(!pricing.matches("gpt-3.5"));
    }

    #[test]
    fn test_model_pricing_suffix_match() {
        let pricing = ModelPricing::new("*-turbo", 30.0, 60.0);
        assert!(pricing.matches("gpt-4-turbo"));
        assert!(pricing.matches("gpt-3.5-turbo"));
        assert!(!pricing.matches("gpt-4"));
    }

    #[test]
    fn test_model_pricing_contains_match() {
        let pricing = ModelPricing::new("*claude*", 30.0, 60.0);
        assert!(pricing.matches("claude-3"));
        assert!(pricing.matches("anthropic-claude-3-opus"));
        assert!(!pricing.matches("gpt-4"));
    }

    #[test]
    fn test_model_pricing_calculate_cost() {
        let pricing = ModelPricing::new("gpt-4", 30.0, 60.0);

        // 1M input tokens = $30, 1M output tokens = $60
        let cost = pricing.calculate_cost(1_000_000, 1_000_000);
        assert!((cost - 90.0).abs() < 0.001);

        // 1000 input tokens, 500 output tokens
        let cost = pricing.calculate_cost(1000, 500);
        let expected = (1000.0 / 1_000_000.0) * 30.0 + (500.0 / 1_000_000.0) * 60.0;
        assert!((cost - expected).abs() < 0.0001);
    }

    #[test]
    fn test_budget_check_result_is_allowed() {
        assert!(BudgetCheckResult::Allowed { remaining: 1000 }.is_allowed());
        assert!(BudgetCheckResult::Soft {
            remaining: -100,
            over_by: 100
        }
        .is_allowed());
        assert!(!BudgetCheckResult::Exhausted {
            retry_after_secs: 3600
        }
        .is_allowed());
    }

    #[test]
    fn test_budget_alert_usage_percent() {
        let alert = BudgetAlert {
            tenant: "test".to_string(),
            threshold: 0.80,
            tokens_used: 800_000,
            tokens_limit: 1_000_000,
            period_start: 0,
        };
        assert!((alert.usage_percent() - 80.0).abs() < 0.001);
    }

    #[test]
    fn test_cost_result_new() {
        let result = CostResult::new("gpt-4", 1000, 500, 0.03, 0.03, "USD");
        assert_eq!(result.model, "gpt-4");
        assert_eq!(result.input_tokens, 1000);
        assert_eq!(result.output_tokens, 500);
        assert!((result.total_cost - 0.06).abs() < 0.001);
    }

    #[test]
    fn test_token_budget_config_default() {
        let config = TokenBudgetConfig::default();
        assert_eq!(config.period, BudgetPeriod::Daily);
        assert_eq!(config.limit, 1_000_000);
        assert!(config.enforce);
        assert!(!config.rollover);
        assert!(config.burst_allowance.is_none());
        assert_eq!(config.alert_thresholds, vec![0.80, 0.90, 0.95]);
    }

    #[test]
    fn test_cost_attribution_config_default() {
        let config = CostAttributionConfig::default();
        assert!(!config.enabled);
        assert!(config.pricing.is_empty());
        assert!((config.default_input_cost - 1.0).abs() < 0.001);
        assert!((config.default_output_cost - 2.0).abs() < 0.001);
        assert_eq!(config.currency, "USD");
    }
}
