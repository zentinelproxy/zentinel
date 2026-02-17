//! Inference routing module for LLM/AI traffic patterns
//!
//! This module provides:
//! - Token-based rate limiting (tokens/minute instead of requests/second)
//! - Token budget tracking (cumulative usage per period)
//! - Cost attribution (per-model pricing)
//! - Multi-provider token counting (OpenAI, Anthropic, generic)
//! - Model-aware load balancing (LeastTokensQueued strategy)
//!
//! # Example Usage
//!
//! ```kdl
//! route "/v1/chat/completions" {
//!     inference {
//!         provider "openai"
//!         rate-limit {
//!             tokens-per-minute 100000
//!             burst-tokens 10000
//!         }
//!         budget {
//!             period "daily"
//!             limit 1000000
//!             enforce true
//!         }
//!         cost-attribution {
//!             pricing {
//!                 model "gpt-4*" {
//!                     input-cost-per-million 30.0
//!                     output-cost-per-million 60.0
//!                 }
//!             }
//!         }
//!         routing {
//!             strategy "least-tokens-queued"
//!         }
//!     }
//!     upstream "llm-pool" { ... }
//! }
//! ```

mod budget;
mod cost;
mod guardrails;
mod manager;
mod metrics;
mod providers;
mod rate_limit;
mod streaming;
mod tiktoken;
mod tokens;

pub use budget::TokenBudgetTracker;
pub use cost::CostCalculator;
pub use guardrails::{
    extract_inference_content, GuardrailProcessor, PiiCheckResult, PromptInjectionResult,
};
pub use manager::{InferenceCheckResult, InferenceRateLimitManager, InferenceRouteStats};
pub use metrics::InferenceMetrics;
pub use providers::{create_provider, InferenceProviderAdapter};
pub use rate_limit::{TokenRateLimitResult, TokenRateLimiter};
pub use streaming::{
    is_sse_response, StreamingTokenCounter, StreamingTokenResult, TokenCountSource,
};
pub use tiktoken::{tiktoken_manager, TiktokenEncoding, TiktokenManager};
pub use tokens::{TokenCounter, TokenEstimate, TokenSource};

use zentinel_config::{InferenceConfig, InferenceProvider};

/// Create a provider adapter based on the configured provider type
pub fn create_inference_provider(config: &InferenceConfig) -> Box<dyn InferenceProviderAdapter> {
    create_provider(&config.provider)
}
