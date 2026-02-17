//! Model-based routing for inference requests.
//!
//! Routes inference requests to different upstreams based on the model name.
//! Supports glob patterns for flexible model matching (e.g., `gpt-4*`, `claude-*`).

use zentinel_config::{InferenceProvider, ModelRoutingConfig, ModelUpstreamMapping};

/// Result of model-based routing lookup.
#[derive(Debug, Clone)]
pub struct ModelRoutingResult {
    /// Target upstream for this model
    pub upstream: String,
    /// Provider override if specified (for cross-provider routing)
    pub provider: Option<InferenceProvider>,
    /// Whether this was a default routing (no specific mapping matched)
    pub is_default: bool,
}

/// Find the upstream for a given model name.
///
/// Checks mappings in order (first match wins). If no mapping matches,
/// returns the default upstream if configured, otherwise None.
///
/// # Arguments
/// * `config` - Model routing configuration
/// * `model` - Model name to route
///
/// # Returns
/// `Some(ModelRoutingResult)` if a matching upstream was found, `None` otherwise.
pub fn find_upstream_for_model(
    config: &ModelRoutingConfig,
    model: &str,
) -> Option<ModelRoutingResult> {
    // Check mappings in order (first match wins)
    for mapping in &config.mappings {
        if matches_model_pattern(&mapping.model_pattern, model) {
            return Some(ModelRoutingResult {
                upstream: mapping.upstream.clone(),
                provider: mapping.provider,
                is_default: false,
            });
        }
    }

    // No mapping matched - use default if configured
    config
        .default_upstream
        .as_ref()
        .map(|upstream| ModelRoutingResult {
            upstream: upstream.clone(),
            provider: None,
            is_default: true,
        })
}

/// Check if a model name matches a pattern.
///
/// Supports:
/// - Exact match: `"gpt-4"` matches `"gpt-4"`
/// - Glob patterns with `*` wildcard: `"gpt-4*"` matches `"gpt-4"`, `"gpt-4-turbo"`, `"gpt-4o"`
fn matches_model_pattern(pattern: &str, model: &str) -> bool {
    // Exact match (fast path)
    if pattern == model {
        return true;
    }

    // Glob pattern matching
    glob_match(pattern, model)
}

/// Simple glob pattern matching for model names.
///
/// Supports:
/// - `*` matches any sequence of characters (including empty)
/// - All other characters match literally
///
/// # Examples
/// - `gpt-4*` matches `gpt-4`, `gpt-4-turbo`, `gpt-4o`
/// - `claude-*-sonnet` matches `claude-3-sonnet`, `claude-3.5-sonnet`
/// - `*-turbo` matches `gpt-4-turbo`, `gpt-3.5-turbo`
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

/// Extract model name from request headers.
///
/// Checks common model headers in order of precedence:
/// 1. `x-model` - Explicit model header
/// 2. `x-model-id` - Alternative model header
///
/// # Returns
/// `Some(model_name)` if found in headers, `None` otherwise.
pub fn extract_model_from_headers(headers: &http::HeaderMap) -> Option<String> {
    // Check common model headers
    let header_names = ["x-model", "x-model-id"];

    for name in header_names {
        if let Some(value) = headers.get(name) {
            if let Ok(model) = value.to_str() {
                let model = model.trim();
                if !model.is_empty() {
                    return Some(model.to_string());
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ModelRoutingConfig {
        ModelRoutingConfig {
            mappings: vec![
                ModelUpstreamMapping {
                    model_pattern: "gpt-4".to_string(),
                    upstream: "openai-gpt4".to_string(),
                    provider: Some(InferenceProvider::OpenAi),
                },
                ModelUpstreamMapping {
                    model_pattern: "gpt-4*".to_string(),
                    upstream: "openai-primary".to_string(),
                    provider: Some(InferenceProvider::OpenAi),
                },
                ModelUpstreamMapping {
                    model_pattern: "gpt-3.5*".to_string(),
                    upstream: "openai-secondary".to_string(),
                    provider: Some(InferenceProvider::OpenAi),
                },
                ModelUpstreamMapping {
                    model_pattern: "claude-*".to_string(),
                    upstream: "anthropic-backend".to_string(),
                    provider: Some(InferenceProvider::Anthropic),
                },
                ModelUpstreamMapping {
                    model_pattern: "llama-*".to_string(),
                    upstream: "local-gpu".to_string(),
                    provider: Some(InferenceProvider::Generic),
                },
            ],
            default_upstream: Some("openai-primary".to_string()),
        }
    }

    #[test]
    fn test_exact_match() {
        let config = create_test_config();

        // Exact match for "gpt-4" should match first (more specific)
        let result = find_upstream_for_model(&config, "gpt-4").unwrap();
        assert_eq!(result.upstream, "openai-gpt4");
        assert!(!result.is_default);
    }

    #[test]
    fn test_glob_suffix_match() {
        let config = create_test_config();

        // "gpt-4-turbo" should match "gpt-4*" pattern
        let result = find_upstream_for_model(&config, "gpt-4-turbo").unwrap();
        assert_eq!(result.upstream, "openai-primary");
        assert!(!result.is_default);

        // "gpt-4o" should match "gpt-4*" pattern
        let result = find_upstream_for_model(&config, "gpt-4o").unwrap();
        assert_eq!(result.upstream, "openai-primary");
    }

    #[test]
    fn test_claude_models() {
        let config = create_test_config();

        // All claude models should route to anthropic
        let result = find_upstream_for_model(&config, "claude-3-opus").unwrap();
        assert_eq!(result.upstream, "anthropic-backend");
        assert_eq!(result.provider, Some(InferenceProvider::Anthropic));

        let result = find_upstream_for_model(&config, "claude-3.5-sonnet").unwrap();
        assert_eq!(result.upstream, "anthropic-backend");
    }

    #[test]
    fn test_default_upstream() {
        let config = create_test_config();

        // Unknown model should fall back to default
        let result = find_upstream_for_model(&config, "unknown-model").unwrap();
        assert_eq!(result.upstream, "openai-primary");
        assert!(result.is_default);
        assert!(result.provider.is_none());
    }

    #[test]
    fn test_no_match_no_default() {
        let config = ModelRoutingConfig {
            mappings: vec![ModelUpstreamMapping {
                model_pattern: "gpt-4".to_string(),
                upstream: "openai".to_string(),
                provider: None,
            }],
            default_upstream: None,
        };

        // No match and no default should return None
        let result = find_upstream_for_model(&config, "claude-3-opus");
        assert!(result.is_none());
    }

    #[test]
    fn test_first_match_wins() {
        let config = create_test_config();

        // "gpt-4" exact match should win over "gpt-4*" glob
        let result = find_upstream_for_model(&config, "gpt-4").unwrap();
        assert_eq!(result.upstream, "openai-gpt4");
    }

    #[test]
    fn test_glob_match_patterns() {
        // Test various glob patterns
        assert!(glob_match("gpt-4*", "gpt-4"));
        assert!(glob_match("gpt-4*", "gpt-4-turbo"));
        assert!(glob_match("gpt-4*", "gpt-4o"));
        assert!(!glob_match("gpt-4*", "gpt-3.5-turbo"));

        assert!(glob_match("*-turbo", "gpt-4-turbo"));
        assert!(glob_match("*-turbo", "gpt-3.5-turbo"));
        assert!(!glob_match("*-turbo", "gpt-4"));

        assert!(glob_match("claude-*-sonnet", "claude-3-sonnet"));
        assert!(glob_match("claude-*-sonnet", "claude-3.5-sonnet"));
        assert!(!glob_match("claude-*-sonnet", "claude-3-opus"));

        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn test_extract_model_from_headers() {
        let mut headers = http::HeaderMap::new();

        // No headers
        assert!(extract_model_from_headers(&headers).is_none());

        // x-model header
        headers.insert("x-model", "gpt-4".parse().unwrap());
        assert_eq!(
            extract_model_from_headers(&headers),
            Some("gpt-4".to_string())
        );

        // x-model-id header (lower precedence)
        headers.clear();
        headers.insert("x-model-id", "claude-3-opus".parse().unwrap());
        assert_eq!(
            extract_model_from_headers(&headers),
            Some("claude-3-opus".to_string())
        );

        // Both headers - x-model takes precedence
        headers.insert("x-model", "gpt-4".parse().unwrap());
        assert_eq!(
            extract_model_from_headers(&headers),
            Some("gpt-4".to_string())
        );

        // Empty header value
        headers.clear();
        headers.insert("x-model", "".parse().unwrap());
        assert!(extract_model_from_headers(&headers).is_none());

        // Whitespace-only header value
        headers.clear();
        headers.insert("x-model", "   ".parse().unwrap());
        assert!(extract_model_from_headers(&headers).is_none());
    }
}
