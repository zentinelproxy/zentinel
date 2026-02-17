//! Inference provider adapters for token extraction
//!
//! Each provider has specific headers and body formats for token information:
//! - OpenAI: `x-ratelimit-remaining-tokens` header, `usage.total_tokens` in body
//! - Anthropic: `anthropic-ratelimit-tokens-remaining` header, `usage.input_tokens + output_tokens`
//! - Generic: `x-tokens-used` header, estimation fallback

use http::HeaderMap;
use zentinel_config::{InferenceProvider, TokenEstimation};
use serde_json::Value;
use tracing::trace;

use super::tiktoken::tiktoken_manager;

/// Trait for provider-specific token extraction and estimation
pub trait InferenceProviderAdapter: Send + Sync {
    /// Provider name for logging/metrics
    fn name(&self) -> &'static str;

    /// Extract token count from response headers (primary method)
    fn tokens_from_headers(&self, headers: &HeaderMap) -> Option<u64>;

    /// Extract token count from response body (fallback method)
    fn tokens_from_body(&self, body: &[u8]) -> Option<u64>;

    /// Estimate tokens from request body using the specified method
    fn estimate_request_tokens(&self, body: &[u8], method: TokenEstimation) -> u64;

    /// Extract model name from request (header or body)
    fn extract_model(&self, headers: &HeaderMap, body: &[u8]) -> Option<String>;
}

/// Create a provider adapter based on provider type
pub fn create_provider(provider: &InferenceProvider) -> Box<dyn InferenceProviderAdapter> {
    match provider {
        InferenceProvider::OpenAi => Box::new(OpenAiProvider),
        InferenceProvider::Anthropic => Box::new(AnthropicProvider),
        InferenceProvider::Generic => Box::new(GenericProvider),
    }
}

// ============================================================================
// OpenAI Provider
// ============================================================================

struct OpenAiProvider;

impl InferenceProviderAdapter for OpenAiProvider {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn tokens_from_headers(&self, headers: &HeaderMap) -> Option<u64> {
        // OpenAI uses several headers:
        // - x-ratelimit-remaining-tokens
        // - x-ratelimit-limit-tokens
        // - x-ratelimit-used-tokens (what we want)
        if let Some(value) = headers.get("x-ratelimit-used-tokens") {
            if let Ok(s) = value.to_str() {
                if let Ok(n) = s.parse::<u64>() {
                    trace!(
                        tokens = n,
                        "Got token count from OpenAI x-ratelimit-used-tokens"
                    );
                    return Some(n);
                }
            }
        }

        // Fallback: calculate from limit - remaining
        let limit = headers
            .get("x-ratelimit-limit-tokens")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let remaining = headers
            .get("x-ratelimit-remaining-tokens")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        if let (Some(l), Some(r)) = (limit, remaining) {
            let used = l.saturating_sub(r);
            trace!(
                limit = l,
                remaining = r,
                used = used,
                "Calculated token usage from OpenAI headers"
            );
            return Some(used);
        }

        None
    }

    fn tokens_from_body(&self, body: &[u8]) -> Option<u64> {
        // OpenAI response format:
        // { "usage": { "prompt_tokens": N, "completion_tokens": M, "total_tokens": T } }
        let json: Value = serde_json::from_slice(body).ok()?;
        let total = json.get("usage")?.get("total_tokens")?.as_u64();
        if let Some(t) = total {
            trace!(tokens = t, "Got token count from OpenAI response body");
        }
        total
    }

    fn estimate_request_tokens(&self, body: &[u8], method: TokenEstimation) -> u64 {
        estimate_tokens(body, method)
    }

    fn extract_model(&self, headers: &HeaderMap, body: &[u8]) -> Option<String> {
        // Check header first
        if let Some(model) = headers.get("x-model").and_then(|v| v.to_str().ok()) {
            return Some(model.to_string());
        }

        // Extract from body: { "model": "gpt-4" }
        let json: Value = serde_json::from_slice(body).ok()?;
        json.get("model")?.as_str().map(|s| s.to_string())
    }
}

// ============================================================================
// Anthropic Provider
// ============================================================================

struct AnthropicProvider;

impl InferenceProviderAdapter for AnthropicProvider {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn tokens_from_headers(&self, headers: &HeaderMap) -> Option<u64> {
        // Anthropic uses:
        // - anthropic-ratelimit-tokens-limit
        // - anthropic-ratelimit-tokens-remaining
        // - anthropic-ratelimit-tokens-reset
        let limit = headers
            .get("anthropic-ratelimit-tokens-limit")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let remaining = headers
            .get("anthropic-ratelimit-tokens-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        if let (Some(l), Some(r)) = (limit, remaining) {
            let used = l.saturating_sub(r);
            trace!(
                limit = l,
                remaining = r,
                used = used,
                "Calculated token usage from Anthropic headers"
            );
            return Some(used);
        }

        None
    }

    fn tokens_from_body(&self, body: &[u8]) -> Option<u64> {
        // Anthropic response format:
        // { "usage": { "input_tokens": N, "output_tokens": M } }
        let json: Value = serde_json::from_slice(body).ok()?;
        let usage = json.get("usage")?;

        let input = usage.get("input_tokens")?.as_u64().unwrap_or(0);
        let output = usage.get("output_tokens")?.as_u64().unwrap_or(0);
        let total = input + output;

        trace!(
            input = input,
            output = output,
            total = total,
            "Got token count from Anthropic response body"
        );
        Some(total)
    }

    fn estimate_request_tokens(&self, body: &[u8], method: TokenEstimation) -> u64 {
        estimate_tokens(body, method)
    }

    fn extract_model(&self, headers: &HeaderMap, body: &[u8]) -> Option<String> {
        // Check header first
        if let Some(model) = headers.get("x-model").and_then(|v| v.to_str().ok()) {
            return Some(model.to_string());
        }

        // Anthropic puts model in body: { "model": "claude-3-opus-20240229" }
        let json: Value = serde_json::from_slice(body).ok()?;
        json.get("model")?.as_str().map(|s| s.to_string())
    }
}

// ============================================================================
// Generic Provider
// ============================================================================

struct GenericProvider;

impl InferenceProviderAdapter for GenericProvider {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn tokens_from_headers(&self, headers: &HeaderMap) -> Option<u64> {
        // Generic provider looks for common headers
        let candidates = ["x-tokens-used", "x-token-count", "x-total-tokens"];

        for header in candidates {
            if let Some(value) = headers.get(header) {
                if let Ok(s) = value.to_str() {
                    if let Ok(n) = s.parse::<u64>() {
                        trace!(
                            header = header,
                            tokens = n,
                            "Got token count from generic header"
                        );
                        return Some(n);
                    }
                }
            }
        }

        None
    }

    fn tokens_from_body(&self, body: &[u8]) -> Option<u64> {
        // Try OpenAI format first (most common)
        let json: Value = serde_json::from_slice(body).ok()?;

        // Try usage.total_tokens (OpenAI style)
        if let Some(total) = json
            .get("usage")
            .and_then(|u| u.get("total_tokens"))
            .and_then(|t| t.as_u64())
        {
            return Some(total);
        }

        // Try usage.input_tokens + output_tokens (Anthropic style)
        if let Some(usage) = json.get("usage") {
            let input = usage
                .get("input_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let output = usage
                .get("output_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            if input > 0 || output > 0 {
                return Some(input + output);
            }
        }

        None
    }

    fn estimate_request_tokens(&self, body: &[u8], method: TokenEstimation) -> u64 {
        estimate_tokens(body, method)
    }

    fn extract_model(&self, headers: &HeaderMap, body: &[u8]) -> Option<String> {
        // Check common headers
        let candidates = ["x-model", "x-model-id", "model"];
        for header in candidates {
            if let Some(model) = headers.get(header).and_then(|v| v.to_str().ok()) {
                return Some(model.to_string());
            }
        }

        // Extract from body
        let json: Value = serde_json::from_slice(body).ok()?;
        json.get("model")?.as_str().map(|s| s.to_string())
    }
}

// ============================================================================
// Token Estimation Utilities
// ============================================================================

/// Estimate tokens from body content using the specified method
fn estimate_tokens(body: &[u8], method: TokenEstimation) -> u64 {
    estimate_tokens_with_model(body, method, None)
}

/// Estimate tokens from body content using the specified method, with optional model hint
fn estimate_tokens_with_model(body: &[u8], method: TokenEstimation, model: Option<&str>) -> u64 {
    match method {
        TokenEstimation::Chars => {
            // Simple: ~4 characters per token
            let char_count = String::from_utf8_lossy(body).chars().count();
            (char_count / 4).max(1) as u64
        }
        TokenEstimation::Words => {
            // ~1.3 tokens per word (English average)
            let text = String::from_utf8_lossy(body);
            let word_count = text.split_whitespace().count();
            ((word_count as f64 * 1.3).ceil() as u64).max(1)
        }
        TokenEstimation::Tiktoken => estimate_tokens_tiktoken(body, model),
    }
}

/// Estimate tokens using tiktoken with model-specific encoding
///
/// Uses the global TiktokenManager which:
/// - Caches BPE instances for reuse
/// - Selects the correct encoding based on model name
/// - Parses chat completion requests to extract just the message content
fn estimate_tokens_tiktoken(body: &[u8], model: Option<&str>) -> u64 {
    let manager = tiktoken_manager();

    // Use the chat request parser for accurate counting
    // This extracts message content and handles JSON structure
    let tokens = manager.count_chat_request(body, model);

    trace!(
        token_count = tokens,
        model = ?model,
        tiktoken_available = manager.is_available(),
        "Tiktoken token count"
    );

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_body_parsing() {
        let body =
            br#"{"usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}"#;
        let provider = OpenAiProvider;
        assert_eq!(provider.tokens_from_body(body), Some(150));
    }

    #[test]
    fn test_anthropic_body_parsing() {
        let body = br#"{"usage": {"input_tokens": 100, "output_tokens": 50}}"#;
        let provider = AnthropicProvider;
        assert_eq!(provider.tokens_from_body(body), Some(150));
    }

    #[test]
    fn test_token_estimation_chars() {
        let body = b"Hello world, this is a test message for token counting!";
        let estimate = estimate_tokens(body, TokenEstimation::Chars);
        // 57 chars / 4 = 14 tokens
        assert!(estimate > 0 && estimate < 100);
    }

    #[test]
    fn test_model_extraction() {
        let body = br#"{"model": "gpt-4", "messages": []}"#;
        let provider = OpenAiProvider;
        let headers = HeaderMap::new();
        assert_eq!(
            provider.extract_model(&headers, body),
            Some("gpt-4".to_string())
        );
    }

    #[test]
    fn test_token_estimation_tiktoken() {
        let body = b"Hello world, this is a test message for token counting!";
        let estimate = estimate_tokens(body, TokenEstimation::Tiktoken);
        // Should return a reasonable token count regardless of feature flag
        assert!(estimate > 0 && estimate < 100);
    }

    #[test]
    #[cfg(feature = "tiktoken")]
    fn test_tiktoken_accurate_count() {
        // "Hello world" is typically 2 tokens with cl100k_base
        let body = b"Hello world";
        let estimate = estimate_tokens_tiktoken(body, Some("gpt-4"));
        assert_eq!(estimate, 2);
    }

    #[test]
    fn test_tiktoken_chat_request() {
        let body = br#"{
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "Hello!"}
            ]
        }"#;
        let estimate = estimate_tokens_tiktoken(body, None);
        // Should count message content plus overhead
        assert!(estimate > 0);
    }
}
