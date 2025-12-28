//! WAF (Web Application Firewall) configuration types
//!
//! This module contains configuration types for the WAF engine,
//! rulesets, and body inspection policies.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// WAF Configuration
// ============================================================================

/// WAF configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    /// WAF engine type
    pub engine: WafEngine,

    /// Rule set configuration
    pub ruleset: WafRuleset,

    /// Global WAF mode
    #[serde(default = "default_waf_mode")]
    pub mode: WafMode,

    /// Audit logging
    #[serde(default = "default_waf_audit")]
    pub audit_log: bool,

    /// Body inspection policy
    #[serde(default)]
    pub body_inspection: BodyInspectionPolicy,
}

// ============================================================================
// WAF Engine
// ============================================================================

/// WAF engine type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafEngine {
    ModSecurity,
    Coraza,
    Custom(String),
}

// ============================================================================
// WAF Ruleset
// ============================================================================

/// WAF ruleset configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafRuleset {
    /// CRS version
    pub crs_version: String,

    /// Custom rules directory
    pub custom_rules_dir: Option<PathBuf>,

    /// Paranoia level (1-4)
    #[serde(default = "default_paranoia_level")]
    pub paranoia_level: u8,

    /// Anomaly threshold
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: u32,

    /// Rule exclusions
    #[serde(default)]
    pub exclusions: Vec<RuleExclusion>,
}

/// WAF rule exclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExclusion {
    /// Rule IDs to exclude
    pub rule_ids: Vec<String>,

    /// Exclusion scope
    pub scope: ExclusionScope,
}

/// Exclusion scope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionScope {
    Global,
    Path(String),
    Host(String),
}

// ============================================================================
// WAF Mode
// ============================================================================

/// WAF mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafMode {
    Off,
    Detection,
    Prevention,
}

// ============================================================================
// Body Inspection Policy
// ============================================================================

/// Body inspection policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyInspectionPolicy {
    /// Enable request body inspection
    #[serde(default = "default_inspect_request_body")]
    pub inspect_request_body: bool,

    /// Enable response body inspection
    #[serde(default)]
    pub inspect_response_body: bool,

    /// Maximum body size to inspect
    #[serde(default = "default_max_inspection_size")]
    pub max_inspection_bytes: usize,

    /// Content types to inspect
    #[serde(default = "default_inspected_content_types")]
    pub content_types: Vec<String>,

    /// Enable decompression for inspection
    #[serde(default)]
    pub decompress: bool,

    /// Maximum decompression ratio
    #[serde(default = "default_max_decompression_ratio")]
    pub max_decompression_ratio: f32,
}

impl Default for BodyInspectionPolicy {
    fn default() -> Self {
        Self {
            inspect_request_body: default_inspect_request_body(),
            inspect_response_body: false,
            max_inspection_bytes: default_max_inspection_size(),
            content_types: default_inspected_content_types(),
            decompress: false,
            max_decompression_ratio: default_max_decompression_ratio(),
        }
    }
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_waf_mode() -> WafMode {
    WafMode::Prevention
}

fn default_waf_audit() -> bool {
    true
}

fn default_paranoia_level() -> u8 {
    1
}

fn default_anomaly_threshold() -> u32 {
    5
}

fn default_inspect_request_body() -> bool {
    true
}

fn default_max_inspection_size() -> usize {
    1024 * 1024
}

fn default_inspected_content_types() -> Vec<String> {
    vec![
        "application/x-www-form-urlencoded".to_string(),
        "multipart/form-data".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "text/xml".to_string(),
    ]
}

fn default_max_decompression_ratio() -> f32 {
    100.0
}
