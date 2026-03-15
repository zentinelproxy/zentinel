//! Custom Zentinel policy CRDs for the Gateway API policy attachment model.
//!
//! These CRDs extend the Gateway API with Zentinel-specific features:
//! rate limiting, WAF, and agent attachment. They follow the
//! [Policy Attachment](https://gateway-api.sigs.k8s.io/reference/policy-attachment/)
//! model, targeting Gateway API resources via `targetRef`.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ============================================================================
// ZentinelRateLimitPolicy
// ============================================================================

/// Rate limiting policy that can be attached to Gateway or HTTPRoute resources.
///
/// Example:
/// ```yaml
/// apiVersion: policy.zentinelproxy.io/v1alpha1
/// kind: ZentinelRateLimitPolicy
/// metadata:
///   name: api-rate-limit
/// spec:
///   targetRef:
///     group: gateway.networking.k8s.io
///     kind: HTTPRoute
///     name: api-route
///   maxRequestsPerSecond: 100
///   burst: 20
///   key: client-ip
/// ```
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "policy.zentinelproxy.io",
    version = "v1alpha1",
    kind = "ZentinelRateLimitPolicy",
    plural = "zentinelratelimitpolicies",
    namespaced
)]
#[kube(status = "PolicyStatus")]
pub struct ZentinelRateLimitPolicySpec {
    /// Reference to the target resource (Gateway, HTTPRoute, or GRPCRoute).
    pub target_ref: PolicyTargetRef,

    /// Maximum requests per second.
    pub max_requests_per_second: u32,

    /// Burst size (token bucket capacity).
    #[serde(default = "default_burst")]
    pub burst: u32,

    /// Key to rate limit by.
    #[serde(default)]
    pub key: RateLimitKey,

    /// HTTP status code returned when rate limit is exceeded.
    #[serde(default = "default_rate_limit_status")]
    pub limit_status_code: u16,

    /// Custom message returned when rate limit is exceeded.
    pub limit_message: Option<String>,
}

fn default_burst() -> u32 {
    10
}

fn default_rate_limit_status() -> u16 {
    429
}

/// Rate limit key selector.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum RateLimitKey {
    /// Rate limit per client IP address.
    #[default]
    ClientIp,
    /// Rate limit per HTTP header value.
    Header(String),
    /// Global rate limit (shared across all clients).
    Global,
}

// ============================================================================
// ZentinelWAFPolicy
// ============================================================================

/// WAF policy that can be attached to Gateway or HTTPRoute resources.
///
/// Example:
/// ```yaml
/// apiVersion: policy.zentinelproxy.io/v1alpha1
/// kind: ZentinelWAFPolicy
/// metadata:
///   name: api-waf
/// spec:
///   targetRef:
///     group: gateway.networking.k8s.io
///     kind: HTTPRoute
///     name: api-route
///   mode: block
///   rulesets:
///     - owasp-crs
/// ```
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "policy.zentinelproxy.io",
    version = "v1alpha1",
    kind = "ZentinelWAFPolicy",
    plural = "zentinelwafpolicies",
    namespaced
)]
#[kube(status = "PolicyStatus")]
pub struct ZentinelWAFPolicySpec {
    /// Reference to the target resource.
    pub target_ref: PolicyTargetRef,

    /// WAF mode: detect (log only) or block (reject malicious requests).
    #[serde(default)]
    pub mode: WafMode,

    /// Rule sets to enable.
    #[serde(default)]
    pub rulesets: Vec<String>,

    /// Rule IDs to exclude from enforcement.
    #[serde(default)]
    pub excluded_rules: Vec<String>,

    /// Maximum request body size to inspect (bytes).
    pub max_body_size: Option<u64>,
}

/// WAF enforcement mode.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    /// Log detected threats but don't block requests.
    Detect,
    /// Block requests that match WAF rules.
    #[default]
    Block,
}

// ============================================================================
// ZentinelAgentBinding
// ============================================================================

/// Agent binding that attaches a Zentinel agent to a Gateway or HTTPRoute.
///
/// Example:
/// ```yaml
/// apiVersion: policy.zentinelproxy.io/v1alpha1
/// kind: ZentinelAgentBinding
/// metadata:
///   name: auth-binding
/// spec:
///   targetRef:
///     group: gateway.networking.k8s.io
///     kind: HTTPRoute
///     name: api-route
///   agentRef:
///     name: auth-agent
///     namespace: zentinel-system
///   failureMode: closed
///   timeoutMs: 100
/// ```
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "policy.zentinelproxy.io",
    version = "v1alpha1",
    kind = "ZentinelAgentBinding",
    plural = "zentinelagentbindings",
    namespaced
)]
#[kube(status = "PolicyStatus")]
pub struct ZentinelAgentBindingSpec {
    /// Reference to the target resource.
    pub target_ref: PolicyTargetRef,

    /// Reference to the Zentinel agent to attach.
    pub agent_ref: AgentRef,

    /// Failure mode when the agent is unavailable.
    #[serde(default)]
    pub failure_mode: FailureMode,

    /// Timeout for agent requests in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Which request phases the agent should be invoked for.
    #[serde(default)]
    pub phase: AgentPhase,
}

fn default_timeout_ms() -> u64 {
    100
}

// ============================================================================
// Shared types
// ============================================================================

/// Reference to a target resource for policy attachment.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct PolicyTargetRef {
    /// API group of the target resource.
    pub group: String,
    /// Kind of the target resource.
    pub kind: String,
    /// Name of the target resource.
    pub name: String,
    /// Namespace of the target resource (defaults to policy's namespace).
    pub namespace: Option<String>,
    /// Section name within the target (e.g., listener name on a Gateway).
    pub section_name: Option<String>,
}

/// Reference to a Zentinel agent.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct AgentRef {
    /// Name of the agent.
    pub name: String,
    /// Namespace where the agent runs.
    pub namespace: Option<String>,
}

/// Failure mode for agent communication.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailureMode {
    /// Allow the request if the agent is unavailable.
    Open,
    /// Reject the request if the agent is unavailable.
    #[default]
    Closed,
}

/// Agent invocation phase.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgentPhase {
    /// Invoke during request processing (before upstream).
    #[default]
    Request,
    /// Invoke during response processing (after upstream).
    Response,
    /// Invoke during both request and response.
    Both,
}

/// Shared status for all Zentinel policies.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
pub struct PolicyStatus {
    /// Conditions describing the current state of the policy.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
}

/// A condition on a policy resource.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct PolicyCondition {
    /// Type of the condition.
    pub r#type: String,
    /// Status of the condition (True, False, Unknown).
    pub status: String,
    /// Machine-readable reason for the condition.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// Generation observed when this condition was set.
    pub observed_generation: i64,
    /// Timestamp when this condition was last updated.
    pub last_transition_time: String,
}
