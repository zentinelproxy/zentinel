//! Fallback routing decision logic for inference backends.
//!
//! This module provides the `FallbackEvaluator` which determines when to trigger
//! fallback routing based on configurable conditions (health failures, budget
//! exhaustion, latency thresholds, error codes).
//!
//! It also handles cross-provider model mapping (e.g., `gpt-4` → `claude-3-opus`)
//! with support for glob patterns in model names.

use zentinel_config::{FallbackConfig, FallbackUpstream};

use super::context::FallbackReason;

/// Decision to fall back to an alternative upstream.
#[derive(Debug, Clone)]
pub struct FallbackDecision {
    /// The upstream to fall back to
    pub next_upstream: String,
    /// Why fallback was triggered
    pub reason: FallbackReason,
    /// Model mapping to apply: (original_model, mapped_model)
    pub model_mapping: Option<(String, String)>,
}

/// Evaluates fallback conditions and selects alternative upstreams.
///
/// The evaluator checks both pre-request conditions (health, budget) and
/// post-response conditions (error codes, latency) to determine if a
/// fallback should be triggered.
pub struct FallbackEvaluator<'a> {
    config: &'a FallbackConfig,
    tried_upstreams: &'a [String],
    current_attempt: u32,
}

impl<'a> FallbackEvaluator<'a> {
    /// Create a new fallback evaluator.
    ///
    /// # Arguments
    /// * `config` - The fallback configuration from the route
    /// * `tried_upstreams` - List of upstreams that have already been tried
    /// * `current_attempt` - Current fallback attempt number (0 = primary)
    pub fn new(
        config: &'a FallbackConfig,
        tried_upstreams: &'a [String],
        current_attempt: u32,
    ) -> Self {
        Self {
            config,
            tried_upstreams,
            current_attempt,
        }
    }

    /// Check if more fallback attempts are allowed.
    pub fn can_attempt_fallback(&self) -> bool {
        self.current_attempt < self.config.max_attempts
    }

    /// Check pre-request conditions to determine if fallback should be used.
    ///
    /// This checks conditions that can be evaluated before sending the request:
    /// - Health check failures (if `on_health_failure` is enabled)
    /// - Budget exhaustion (if `on_budget_exhausted` is enabled)
    ///
    /// # Arguments
    /// * `upstream_id` - The upstream that would be used
    /// * `is_healthy` - Whether the upstream is currently healthy
    /// * `is_budget_exhausted` - Whether the token budget is exhausted
    /// * `current_model` - The model being requested (for model mapping)
    ///
    /// # Returns
    /// `Some(FallbackDecision)` if fallback should be used, `None` otherwise.
    pub fn should_fallback_before_request(
        &self,
        upstream_id: &str,
        is_healthy: bool,
        is_budget_exhausted: bool,
        current_model: Option<&str>,
    ) -> Option<FallbackDecision> {
        if !self.can_attempt_fallback() {
            return None;
        }

        // Check health failure trigger
        if self.config.triggers.on_health_failure && !is_healthy {
            return self.create_fallback_decision(
                FallbackReason::HealthCheckFailed,
                upstream_id,
                current_model,
            );
        }

        // Check budget exhaustion trigger
        if self.config.triggers.on_budget_exhausted && is_budget_exhausted {
            return self.create_fallback_decision(
                FallbackReason::BudgetExhausted,
                upstream_id,
                current_model,
            );
        }

        None
    }

    /// Check post-response conditions to determine if fallback should be used.
    ///
    /// This checks conditions that can only be evaluated after receiving a response:
    /// - Error status codes (if `on_error_codes` is configured)
    /// - Latency threshold exceeded (if `on_latency_threshold_ms` is configured)
    ///
    /// # Arguments
    /// * `upstream_id` - The upstream that was used
    /// * `status_code` - HTTP status code from the response
    /// * `latency_ms` - Request latency in milliseconds
    /// * `current_model` - The model being requested (for model mapping)
    ///
    /// # Returns
    /// `Some(FallbackDecision)` if fallback should be used, `None` otherwise.
    pub fn should_fallback_after_response(
        &self,
        upstream_id: &str,
        status_code: u16,
        latency_ms: u64,
        current_model: Option<&str>,
    ) -> Option<FallbackDecision> {
        if !self.can_attempt_fallback() {
            return None;
        }

        // Check error code trigger
        if !self.config.triggers.on_error_codes.is_empty()
            && self.config.triggers.on_error_codes.contains(&status_code)
        {
            return self.create_fallback_decision(
                FallbackReason::ErrorCode(status_code),
                upstream_id,
                current_model,
            );
        }

        // Check latency threshold trigger
        if let Some(threshold_ms) = self.config.triggers.on_latency_threshold_ms {
            if latency_ms > threshold_ms {
                return self.create_fallback_decision(
                    FallbackReason::LatencyThreshold {
                        observed_ms: latency_ms,
                        threshold_ms,
                    },
                    upstream_id,
                    current_model,
                );
            }
        }

        None
    }

    /// Check if fallback should be triggered due to a connection error.
    ///
    /// # Arguments
    /// * `upstream_id` - The upstream that failed to connect
    /// * `error_message` - Description of the connection error
    /// * `current_model` - The model being requested (for model mapping)
    ///
    /// # Returns
    /// `Some(FallbackDecision)` if fallback should be used, `None` otherwise.
    pub fn should_fallback_on_connection_error(
        &self,
        upstream_id: &str,
        error_message: &str,
        current_model: Option<&str>,
    ) -> Option<FallbackDecision> {
        if !self.can_attempt_fallback() {
            return None;
        }

        if self.config.triggers.on_connection_error {
            return self.create_fallback_decision(
                FallbackReason::ConnectionError(error_message.to_string()),
                upstream_id,
                current_model,
            );
        }

        None
    }

    /// Get the next untried fallback upstream.
    ///
    /// This returns the first fallback upstream that:
    /// 1. Has not been tried yet
    /// 2. Is not marked as `skip_if_unhealthy` with unhealthy status
    ///
    /// Note: Health status check is the caller's responsibility since we
    /// don't have access to the health check state here.
    pub fn next_fallback(&self) -> Option<&FallbackUpstream> {
        self.config.upstreams.iter().find(|fb| {
            // Skip if we've already tried this upstream
            !self.tried_upstreams.contains(&fb.upstream)
        })
    }

    /// Apply model mapping for a fallback upstream.
    ///
    /// Supports glob patterns like `gpt-4*` to match `gpt-4`, `gpt-4-turbo`, etc.
    ///
    /// # Arguments
    /// * `upstream` - The fallback upstream configuration
    /// * `model` - The original model name
    ///
    /// # Returns
    /// The mapped model name, or the original if no mapping matches.
    pub fn map_model(&self, upstream: &FallbackUpstream, model: &str) -> String {
        // Try exact match first
        if let Some(mapped) = upstream.model_mapping.get(model) {
            return mapped.to_string();
        }

        // Try glob pattern matching
        for (pattern, mapped) in &upstream.model_mapping {
            if glob_match(pattern, model) {
                return mapped.to_string();
            }
        }

        // No mapping found - return original
        model.to_string()
    }

    /// Create a fallback decision for the next available upstream.
    fn create_fallback_decision(
        &self,
        reason: FallbackReason,
        _current_upstream: &str,
        current_model: Option<&str>,
    ) -> Option<FallbackDecision> {
        let next = self.next_fallback()?;

        let model_mapping = current_model.and_then(|model| {
            let mapped = self.map_model(next, model);
            if mapped != model {
                Some((model.to_string(), mapped))
            } else {
                None
            }
        });

        Some(FallbackDecision {
            next_upstream: next.upstream.clone(),
            reason,
            model_mapping,
        })
    }
}

/// Simple glob pattern matching for model names.
///
/// Supports:
/// - `*` matches any sequence of characters
/// - All other characters match literally
///
/// # Examples
/// - `gpt-4*` matches `gpt-4`, `gpt-4-turbo`, `gpt-4o`
/// - `claude-*-sonnet` matches `claude-3-sonnet`, `claude-3.5-sonnet`
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    glob_match_recursive(&pattern_chars, &text_chars, 0, 0)
}

fn glob_match_recursive(pattern: &[char], text: &[char], p_idx: usize, t_idx: usize) -> bool {
    // End of pattern
    if p_idx >= pattern.len() {
        return t_idx >= text.len();
    }

    // Wildcard match
    if pattern[p_idx] == '*' {
        // Try matching zero or more characters
        for i in t_idx..=text.len() {
            if glob_match_recursive(pattern, text, p_idx + 1, i) {
                return true;
            }
        }
        return false;
    }

    // Exact character match
    if t_idx < text.len() && pattern[p_idx] == text[t_idx] {
        return glob_match_recursive(pattern, text, p_idx + 1, t_idx + 1);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::{FallbackTriggers, InferenceProvider};
    use std::collections::HashMap;

    fn create_test_config() -> FallbackConfig {
        FallbackConfig {
            upstreams: vec![
                FallbackUpstream {
                    upstream: "anthropic-fallback".to_string(),
                    provider: InferenceProvider::Anthropic,
                    model_mapping: {
                        let mut map = HashMap::new();
                        map.insert("gpt-4".to_string(), "claude-3-opus".to_string());
                        map.insert("gpt-4o".to_string(), "claude-3-5-sonnet".to_string());
                        map.insert("gpt-3.5-turbo".to_string(), "claude-3-haiku".to_string());
                        map
                    },
                    skip_if_unhealthy: true,
                },
                FallbackUpstream {
                    upstream: "local-gpu".to_string(),
                    provider: InferenceProvider::Generic,
                    model_mapping: {
                        let mut map = HashMap::new();
                        map.insert("gpt-4*".to_string(), "llama-3-70b".to_string());
                        map.insert("gpt-3.5*".to_string(), "llama-3-8b".to_string());
                        map
                    },
                    skip_if_unhealthy: true,
                },
            ],
            triggers: FallbackTriggers {
                on_health_failure: true,
                on_budget_exhausted: true,
                on_latency_threshold_ms: Some(5000),
                on_error_codes: vec![429, 500, 502, 503, 504],
                on_connection_error: true,
            },
            max_attempts: 2,
        }
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("gpt-4", "gpt-4"));
        assert!(!glob_match("gpt-4", "gpt-4-turbo"));
    }

    #[test]
    fn test_glob_match_suffix_wildcard() {
        assert!(glob_match("gpt-4*", "gpt-4"));
        assert!(glob_match("gpt-4*", "gpt-4-turbo"));
        assert!(glob_match("gpt-4*", "gpt-4o"));
        assert!(!glob_match("gpt-4*", "gpt-3.5-turbo"));
    }

    #[test]
    fn test_glob_match_middle_wildcard() {
        assert!(glob_match("claude-*-sonnet", "claude-3-sonnet"));
        assert!(glob_match("claude-*-sonnet", "claude-3.5-sonnet"));
        assert!(!glob_match("claude-*-sonnet", "claude-3-opus"));
    }

    #[test]
    fn test_glob_match_prefix_wildcard() {
        assert!(glob_match("*-turbo", "gpt-4-turbo"));
        assert!(glob_match("*-turbo", "gpt-3.5-turbo"));
        assert!(!glob_match("*-turbo", "gpt-4"));
    }

    #[test]
    fn test_can_attempt_fallback() {
        let config = create_test_config();

        let evaluator = FallbackEvaluator::new(&config, &[], 0);
        assert!(evaluator.can_attempt_fallback());

        let evaluator = FallbackEvaluator::new(&config, &[], 1);
        assert!(evaluator.can_attempt_fallback());

        let evaluator = FallbackEvaluator::new(&config, &[], 2);
        assert!(!evaluator.can_attempt_fallback());
    }

    #[test]
    fn test_fallback_on_health_failure() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        // Should trigger fallback when unhealthy
        let decision = evaluator.should_fallback_before_request(
            "openai-primary",
            false, // unhealthy
            false,
            Some("gpt-4"),
        );

        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert_eq!(decision.next_upstream, "anthropic-fallback");
        assert!(matches!(decision.reason, FallbackReason::HealthCheckFailed));
        assert_eq!(
            decision.model_mapping,
            Some(("gpt-4".to_string(), "claude-3-opus".to_string()))
        );
    }

    #[test]
    fn test_fallback_on_budget_exhausted() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        let decision = evaluator.should_fallback_before_request(
            "openai-primary",
            true, // healthy
            true, // budget exhausted
            Some("gpt-4o"),
        );

        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert_eq!(decision.next_upstream, "anthropic-fallback");
        assert!(matches!(decision.reason, FallbackReason::BudgetExhausted));
        assert_eq!(
            decision.model_mapping,
            Some(("gpt-4o".to_string(), "claude-3-5-sonnet".to_string()))
        );
    }

    #[test]
    fn test_fallback_on_error_code() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        // 503 should trigger fallback
        let decision =
            evaluator.should_fallback_after_response("openai-primary", 503, 1000, Some("gpt-4"));
        assert!(decision.is_some());

        // 200 should not trigger fallback
        let decision =
            evaluator.should_fallback_after_response("openai-primary", 200, 1000, Some("gpt-4"));
        assert!(decision.is_none());

        // 404 should not trigger fallback (not in the list)
        let decision =
            evaluator.should_fallback_after_response("openai-primary", 404, 1000, Some("gpt-4"));
        assert!(decision.is_none());
    }

    #[test]
    fn test_fallback_on_latency_threshold() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        // Above threshold should trigger
        let decision = evaluator.should_fallback_after_response(
            "openai-primary",
            200,
            6000, // 6 seconds, above 5 second threshold
            Some("gpt-4"),
        );
        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert!(matches!(
            decision.reason,
            FallbackReason::LatencyThreshold {
                observed_ms: 6000,
                threshold_ms: 5000
            }
        ));

        // Below threshold should not trigger
        let decision = evaluator.should_fallback_after_response(
            "openai-primary",
            200,
            4000, // 4 seconds, below threshold
            Some("gpt-4"),
        );
        assert!(decision.is_none());
    }

    #[test]
    fn test_fallback_on_connection_error() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        let decision = evaluator.should_fallback_on_connection_error(
            "openai-primary",
            "connection refused",
            Some("gpt-4"),
        );

        assert!(decision.is_some());
        let decision = decision.unwrap();
        assert!(matches!(
            decision.reason,
            FallbackReason::ConnectionError(_)
        ));
    }

    #[test]
    fn test_next_fallback_skips_tried() {
        let config = create_test_config();

        // No upstreams tried yet
        let evaluator = FallbackEvaluator::new(&config, &[], 0);
        let next = evaluator.next_fallback().unwrap();
        assert_eq!(next.upstream, "anthropic-fallback");

        // First fallback already tried
        let tried = vec!["anthropic-fallback".to_string()];
        let evaluator = FallbackEvaluator::new(&config, &tried, 1);
        let next = evaluator.next_fallback().unwrap();
        assert_eq!(next.upstream, "local-gpu");

        // Both fallbacks tried
        let tried = vec!["anthropic-fallback".to_string(), "local-gpu".to_string()];
        let evaluator = FallbackEvaluator::new(&config, &tried, 2);
        assert!(evaluator.next_fallback().is_none());
    }

    #[test]
    fn test_model_mapping_exact() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);
        let upstream = &config.upstreams[0]; // anthropic-fallback

        assert_eq!(evaluator.map_model(upstream, "gpt-4"), "claude-3-opus");
        assert_eq!(evaluator.map_model(upstream, "gpt-4o"), "claude-3-5-sonnet");
        assert_eq!(
            evaluator.map_model(upstream, "gpt-3.5-turbo"),
            "claude-3-haiku"
        );
        // Unknown model returns as-is
        assert_eq!(
            evaluator.map_model(upstream, "unknown-model"),
            "unknown-model"
        );
    }

    #[test]
    fn test_model_mapping_glob() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);
        let upstream = &config.upstreams[1]; // local-gpu

        assert_eq!(evaluator.map_model(upstream, "gpt-4"), "llama-3-70b");
        assert_eq!(evaluator.map_model(upstream, "gpt-4-turbo"), "llama-3-70b");
        assert_eq!(evaluator.map_model(upstream, "gpt-4o"), "llama-3-70b");
        assert_eq!(evaluator.map_model(upstream, "gpt-3.5-turbo"), "llama-3-8b");
    }

    #[test]
    fn test_no_fallback_when_healthy_and_budget_ok() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 0);

        let decision = evaluator.should_fallback_before_request(
            "openai-primary",
            true,  // healthy
            false, // budget OK
            Some("gpt-4"),
        );

        assert!(decision.is_none());
    }

    #[test]
    fn test_no_fallback_when_max_attempts_reached() {
        let config = create_test_config();
        let evaluator = FallbackEvaluator::new(&config, &[], 2); // At max

        // Even with unhealthy upstream, should not fallback
        let decision = evaluator.should_fallback_before_request(
            "openai-primary",
            false, // unhealthy
            false,
            Some("gpt-4"),
        );

        assert!(decision.is_none());
    }
}
