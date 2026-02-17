//! Cost calculator for inference request attribution.
//!
//! Calculates costs based on per-model pricing for input and output tokens.

use tracing::{debug, trace};

use zentinel_common::budget::{CostAttributionConfig, CostResult, ModelPricing};

/// Cost calculator for inference requests.
///
/// Uses per-model pricing rules to calculate costs for inference requests
/// based on input and output token counts.
pub struct CostCalculator {
    /// Configuration
    config: CostAttributionConfig,
    /// Route ID for logging
    route_id: String,
}

impl CostCalculator {
    /// Create a new cost calculator with the given configuration.
    pub fn new(config: CostAttributionConfig, route_id: impl Into<String>) -> Self {
        let route_id = route_id.into();

        debug!(
            route_id = %route_id,
            enabled = config.enabled,
            pricing_rules = config.pricing.len(),
            default_input = config.default_input_cost,
            default_output = config.default_output_cost,
            currency = %config.currency,
            "Created cost calculator"
        );

        Self { config, route_id }
    }

    /// Check if cost attribution is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Calculate the cost for a request/response.
    ///
    /// Uses the first matching pricing rule, or falls back to default pricing.
    pub fn calculate(&self, model: &str, input_tokens: u64, output_tokens: u64) -> CostResult {
        if !self.config.enabled {
            return CostResult::new(model, input_tokens, output_tokens, 0.0, 0.0, "USD");
        }

        // Find matching pricing rule
        let (input_cost_per_million, output_cost_per_million, currency) =
            if let Some(pricing) = self.find_pricing(model) {
                let currency = pricing
                    .currency
                    .as_ref()
                    .unwrap_or(&self.config.currency)
                    .clone();
                (
                    pricing.input_cost_per_million,
                    pricing.output_cost_per_million,
                    currency,
                )
            } else {
                (
                    self.config.default_input_cost,
                    self.config.default_output_cost,
                    self.config.currency.clone(),
                )
            };

        // Calculate costs
        let input_cost = (input_tokens as f64 / 1_000_000.0) * input_cost_per_million;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * output_cost_per_million;
        let total_cost = input_cost + output_cost;

        trace!(
            route_id = %self.route_id,
            model = model,
            input_tokens = input_tokens,
            output_tokens = output_tokens,
            input_cost = input_cost,
            output_cost = output_cost,
            total_cost = total_cost,
            currency = %currency,
            "Calculated cost"
        );

        CostResult::new(
            model,
            input_tokens,
            output_tokens,
            input_cost,
            output_cost,
            currency,
        )
    }

    /// Find the pricing rule for a model.
    ///
    /// Returns the first matching rule, or None if no rules match.
    pub fn find_pricing(&self, model: &str) -> Option<&ModelPricing> {
        self.config.pricing.iter().find(|p| p.matches(model))
    }

    /// Get the default currency.
    pub fn currency(&self) -> &str {
        &self.config.currency
    }

    /// Get the number of pricing rules.
    pub fn pricing_rule_count(&self) -> usize {
        self.config.pricing.len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CostAttributionConfig {
        CostAttributionConfig {
            enabled: true,
            pricing: vec![
                ModelPricing {
                    model_pattern: "gpt-4*".to_string(),
                    input_cost_per_million: 30.0,
                    output_cost_per_million: 60.0,
                    currency: None,
                },
                ModelPricing {
                    model_pattern: "gpt-3.5*".to_string(),
                    input_cost_per_million: 0.5,
                    output_cost_per_million: 1.5,
                    currency: None,
                },
                ModelPricing {
                    model_pattern: "claude-*".to_string(),
                    input_cost_per_million: 15.0,
                    output_cost_per_million: 75.0,
                    currency: Some("EUR".to_string()),
                },
            ],
            default_input_cost: 1.0,
            default_output_cost: 2.0,
            currency: "USD".to_string(),
        }
    }

    #[test]
    fn test_calculate_gpt4() {
        let calc = CostCalculator::new(test_config(), "test-route");

        // 1000 input tokens, 500 output tokens
        let result = calc.calculate("gpt-4-turbo", 1000, 500);

        assert_eq!(result.model, "gpt-4-turbo");
        assert_eq!(result.input_tokens, 1000);
        assert_eq!(result.output_tokens, 500);
        assert_eq!(result.currency, "USD");

        // $30/1M input = $0.00003 per token, 1000 tokens = $0.03
        assert!((result.input_cost - 0.03).abs() < 0.001);

        // $60/1M output = $0.00006 per token, 500 tokens = $0.03
        assert!((result.output_cost - 0.03).abs() < 0.001);
    }

    #[test]
    fn test_calculate_gpt35() {
        let calc = CostCalculator::new(test_config(), "test-route");

        let result = calc.calculate("gpt-3.5-turbo", 1_000_000, 1_000_000);

        // $0.5/1M input = $0.50 for 1M tokens
        assert!((result.input_cost - 0.5).abs() < 0.001);

        // $1.5/1M output = $1.50 for 1M tokens
        assert!((result.output_cost - 1.5).abs() < 0.001);

        assert!((result.total_cost - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_calculate_claude_with_currency_override() {
        let calc = CostCalculator::new(test_config(), "test-route");

        let result = calc.calculate("claude-3-opus", 1000, 1000);

        // Should use EUR from the pricing rule
        assert_eq!(result.currency, "EUR");
    }

    #[test]
    fn test_calculate_unknown_model_uses_default() {
        let calc = CostCalculator::new(test_config(), "test-route");

        let result = calc.calculate("llama-3", 1_000_000, 1_000_000);

        // Should use default pricing
        assert!((result.input_cost - 1.0).abs() < 0.001);
        assert!((result.output_cost - 2.0).abs() < 0.001);
        assert_eq!(result.currency, "USD");
    }

    #[test]
    fn test_disabled_returns_zero() {
        let mut config = test_config();
        config.enabled = false;

        let calc = CostCalculator::new(config, "test-route");

        let result = calc.calculate("gpt-4", 1000, 500);

        assert!((result.input_cost).abs() < 0.00001);
        assert!((result.output_cost).abs() < 0.00001);
        assert!((result.total_cost).abs() < 0.00001);
    }

    #[test]
    fn test_find_pricing() {
        let calc = CostCalculator::new(test_config(), "test-route");

        assert!(calc.find_pricing("gpt-4").is_some());
        assert!(calc.find_pricing("gpt-4-turbo").is_some());
        assert!(calc.find_pricing("gpt-3.5-turbo").is_some());
        assert!(calc.find_pricing("claude-3-sonnet").is_some());
        assert!(calc.find_pricing("llama-3").is_none());
    }
}
