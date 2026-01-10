//! Inference health check configuration types
//!
//! This module provides configuration structures for enhanced model readiness
//! checks beyond basic HTTP 200 verification. These checks help ensure LLM/AI
//! backends are truly ready to serve requests.
//!
//! # Check Types
//!
//! - [`InferenceProbeConfig`]: Send minimal completion request to verify model responds
//! - [`ModelStatusConfig`]: Check provider-specific model status endpoints
//! - [`QueueDepthConfig`]: Monitor queue depth to detect overloaded backends
//! - [`WarmthDetectionConfig`]: Track latency to detect cold models after idle periods

use serde::{Deserialize, Serialize};

/// Configuration for enhanced inference readiness checks
///
/// All fields are optional - only enabled checks are performed.
/// The base inference health check (models endpoint) always runs first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceReadinessConfig {
    /// Send minimal inference request to verify model can respond
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference_probe: Option<InferenceProbeConfig>,

    /// Check provider-specific model status endpoints
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_status: Option<ModelStatusConfig>,

    /// Monitor queue depth from headers or response body
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<QueueDepthConfig>,

    /// Detect cold models after idle periods
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warmth_detection: Option<WarmthDetectionConfig>,
}

/// Configuration for inference probe health check
///
/// Sends a minimal completion request to verify the model can actually
/// process requests, not just that the server is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceProbeConfig {
    /// Endpoint for completion request
    #[serde(default = "default_probe_endpoint")]
    pub endpoint: String,

    /// Model to probe (required)
    pub model: String,

    /// Probe prompt (minimal to reduce cost/latency)
    #[serde(default = "default_probe_prompt")]
    pub prompt: String,

    /// Max tokens in response (keep minimal)
    #[serde(default = "default_probe_max_tokens")]
    pub max_tokens: u32,

    /// Timeout for probe request in seconds
    #[serde(default = "default_probe_timeout")]
    pub timeout_secs: u64,

    /// Mark unhealthy if probe latency exceeds this threshold (ms)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_latency_ms: Option<u64>,
}

/// Configuration for model status endpoint check
///
/// Queries provider-specific status endpoints to verify model readiness.
/// Useful for providers that expose detailed model state information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelStatusConfig {
    /// Endpoint pattern with `{model}` placeholder
    #[serde(default = "default_status_endpoint")]
    pub endpoint_pattern: String,

    /// Models to check status for
    pub models: Vec<String>,

    /// Expected status value (e.g., "ready", "loaded")
    #[serde(default = "default_expected_status")]
    pub expected_status: String,

    /// JSON path to status field (supports dot notation, e.g., "state.loaded")
    #[serde(default = "default_status_field")]
    pub status_field: String,

    /// Timeout for status request in seconds
    #[serde(default = "default_status_timeout")]
    pub timeout_secs: u64,
}

/// Configuration for queue depth monitoring
///
/// Monitors queue depth to detect overloaded backends before they
/// start timing out or returning errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueDepthConfig {
    /// Header containing queue depth (e.g., "x-queue-depth")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,

    /// JSON field in response body containing queue depth
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_field: Option<String>,

    /// Endpoint to query for queue info (defaults to models endpoint)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,

    /// Mark as degraded if queue exceeds this threshold
    pub degraded_threshold: u64,

    /// Mark as unhealthy if queue exceeds this threshold
    pub unhealthy_threshold: u64,

    /// Timeout for queue check in seconds
    #[serde(default = "default_queue_timeout")]
    pub timeout_secs: u64,
}

/// Configuration for cold model detection
///
/// Tracks request latency to detect when models have gone cold after
/// idle periods. This is a passive check that observes actual requests
/// rather than sending probes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmthDetectionConfig {
    /// Number of requests to sample for baseline latency
    #[serde(default = "default_warmth_sample_size")]
    pub sample_size: u32,

    /// Multiplier for cold detection (latency > baseline * multiplier = cold)
    #[serde(default = "default_cold_threshold_multiplier")]
    pub cold_threshold_multiplier: f64,

    /// Time after which a model is considered potentially cold (seconds)
    #[serde(default = "default_idle_cold_timeout")]
    pub idle_cold_timeout_secs: u64,

    /// Action to take when cold model detected
    #[serde(default)]
    pub cold_action: ColdModelAction,
}

impl PartialEq for WarmthDetectionConfig {
    fn eq(&self, other: &Self) -> bool {
        self.sample_size == other.sample_size
            && self.cold_threshold_multiplier.to_bits() == other.cold_threshold_multiplier.to_bits()
            && self.idle_cold_timeout_secs == other.idle_cold_timeout_secs
            && self.cold_action == other.cold_action
    }
}

impl Eq for WarmthDetectionConfig {}

/// Action to take when a cold model is detected
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdModelAction {
    /// Log the cold start but continue serving (observability only)
    #[default]
    LogOnly,
    /// Mark as degraded (lower weight in load balancing)
    MarkDegraded,
    /// Mark as unhealthy until warmed up
    MarkUnhealthy,
}

// Default value functions

fn default_probe_endpoint() -> String {
    "/v1/completions".to_string()
}

fn default_probe_prompt() -> String {
    ".".to_string()
}

fn default_probe_max_tokens() -> u32 {
    1
}

fn default_probe_timeout() -> u64 {
    30
}

fn default_status_endpoint() -> String {
    "/v1/models/{model}/status".to_string()
}

fn default_expected_status() -> String {
    "ready".to_string()
}

fn default_status_field() -> String {
    "status".to_string()
}

fn default_status_timeout() -> u64 {
    5
}

fn default_queue_timeout() -> u64 {
    5
}

fn default_warmth_sample_size() -> u32 {
    10
}

fn default_cold_threshold_multiplier() -> f64 {
    3.0
}

fn default_idle_cold_timeout() -> u64 {
    300 // 5 minutes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inference_readiness_config_defaults() {
        let config: InferenceReadinessConfig = serde_json::from_str("{}").unwrap();
        assert!(config.inference_probe.is_none());
        assert!(config.model_status.is_none());
        assert!(config.queue_depth.is_none());
        assert!(config.warmth_detection.is_none());
    }

    #[test]
    fn test_inference_probe_config_defaults() {
        let json = r#"{"model": "gpt-4"}"#;
        let config: InferenceProbeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.endpoint, "/v1/completions");
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.prompt, ".");
        assert_eq!(config.max_tokens, 1);
        assert_eq!(config.timeout_secs, 30);
        assert!(config.max_latency_ms.is_none());
    }

    #[test]
    fn test_model_status_config_defaults() {
        let json = r#"{"models": ["gpt-4", "gpt-3.5-turbo"]}"#;
        let config: ModelStatusConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.endpoint_pattern, "/v1/models/{model}/status");
        assert_eq!(config.models, vec!["gpt-4", "gpt-3.5-turbo"]);
        assert_eq!(config.expected_status, "ready");
        assert_eq!(config.status_field, "status");
        assert_eq!(config.timeout_secs, 5);
    }

    #[test]
    fn test_queue_depth_config() {
        let json = r#"{
            "header": "x-queue-depth",
            "degraded_threshold": 50,
            "unhealthy_threshold": 200
        }"#;
        let config: QueueDepthConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.header, Some("x-queue-depth".to_string()));
        assert!(config.body_field.is_none());
        assert_eq!(config.degraded_threshold, 50);
        assert_eq!(config.unhealthy_threshold, 200);
        assert_eq!(config.timeout_secs, 5);
    }

    #[test]
    fn test_warmth_detection_defaults() {
        let json = "{}";
        let config: WarmthDetectionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.sample_size, 10);
        assert!((config.cold_threshold_multiplier - 3.0).abs() < f64::EPSILON);
        assert_eq!(config.idle_cold_timeout_secs, 300);
        assert_eq!(config.cold_action, ColdModelAction::LogOnly);
    }

    #[test]
    fn test_cold_model_action_serialization() {
        assert_eq!(
            serde_json::to_string(&ColdModelAction::LogOnly).unwrap(),
            r#""log_only""#
        );
        assert_eq!(
            serde_json::to_string(&ColdModelAction::MarkDegraded).unwrap(),
            r#""mark_degraded""#
        );
        assert_eq!(
            serde_json::to_string(&ColdModelAction::MarkUnhealthy).unwrap(),
            r#""mark_unhealthy""#
        );
    }

    #[test]
    fn test_full_config_roundtrip() {
        let config = InferenceReadinessConfig {
            inference_probe: Some(InferenceProbeConfig {
                endpoint: "/v1/completions".to_string(),
                model: "gpt-4".to_string(),
                prompt: ".".to_string(),
                max_tokens: 1,
                timeout_secs: 30,
                max_latency_ms: Some(5000),
            }),
            model_status: None,
            queue_depth: Some(QueueDepthConfig {
                header: Some("x-queue-depth".to_string()),
                body_field: None,
                endpoint: None,
                degraded_threshold: 50,
                unhealthy_threshold: 200,
                timeout_secs: 5,
            }),
            warmth_detection: Some(WarmthDetectionConfig {
                sample_size: 10,
                cold_threshold_multiplier: 3.0,
                idle_cold_timeout_secs: 300,
                cold_action: ColdModelAction::MarkDegraded,
            }),
        };

        let json = serde_json::to_string(&config).unwrap();
        let parsed: InferenceReadinessConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }
}
