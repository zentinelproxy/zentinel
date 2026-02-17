//! Agent configuration types
//!
//! This module contains configuration types for external processing agents
//! (WAF, auth, rate limiting, custom logic).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use validator::Validate;

use zentinel_common::types::CircuitBreakerConfig;

use crate::routes::FailureMode;

// ============================================================================
// Body Streaming Mode
// ============================================================================

/// Body streaming mode for agent processing
///
/// Controls how request/response bodies are sent to agents:
/// - `Buffer`: Collect entire body before sending (default, backwards compatible)
/// - `Stream`: Send chunks as they arrive (lower latency, lower memory)
/// - `Hybrid`: Buffer small bodies, stream large ones
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum BodyStreamingMode {
    /// Buffer entire body before sending to agent (default)
    ///
    /// - Simpler agent implementation
    /// - Higher memory usage for large bodies
    /// - Agent sees complete body for decisions
    #[default]
    Buffer,

    /// Stream body chunks as they arrive
    ///
    /// - Lower latency and memory usage
    /// - Agent must handle partial data
    /// - Supports progressive decisions
    Stream,

    /// Hybrid: buffer up to threshold, then stream
    ///
    /// - Best of both worlds for mixed workloads
    /// - Small bodies buffered for simplicity
    /// - Large bodies streamed for efficiency
    Hybrid {
        /// Buffer threshold in bytes (default: 64KB)
        #[serde(default = "default_hybrid_threshold")]
        buffer_threshold: usize,
    },
}

fn default_hybrid_threshold() -> usize {
    64 * 1024 // 64KB
}

// ============================================================================
// Agent Configuration
// ============================================================================

/// Agent protocol version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocolVersion {
    /// Protocol v1 (default) - Simple request/response
    #[default]
    V1,
    /// Protocol v2 - Bidirectional streaming with capabilities, health, metrics
    V2,
}

/// V2-specific pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPoolConfig {
    /// Number of connections to maintain per agent (default: 4)
    #[serde(default = "default_connections_per_agent")]
    pub connections_per_agent: usize,

    /// Load balancing strategy (default: round_robin)
    #[serde(default)]
    pub load_balance_strategy: LoadBalanceStrategy,

    /// Connection timeout in milliseconds (default: 5000)
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,

    /// Time between reconnection attempts in milliseconds (default: 5000)
    #[serde(default = "default_reconnect_interval_ms")]
    pub reconnect_interval_ms: u64,

    /// Maximum reconnection attempts before marking unhealthy (default: 3)
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: usize,

    /// Time to wait for in-flight requests during shutdown in milliseconds (default: 30000)
    #[serde(default = "default_drain_timeout_ms")]
    pub drain_timeout_ms: u64,

    /// Maximum concurrent requests per connection (default: 100)
    #[serde(default = "default_max_concurrent_per_connection")]
    pub max_concurrent_per_connection: usize,

    /// Health check interval in milliseconds (default: 10000)
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,
}

impl Default for AgentPoolConfig {
    fn default() -> Self {
        Self {
            connections_per_agent: default_connections_per_agent(),
            load_balance_strategy: LoadBalanceStrategy::default(),
            connect_timeout_ms: default_connect_timeout_ms(),
            reconnect_interval_ms: default_reconnect_interval_ms(),
            max_reconnect_attempts: default_max_reconnect_attempts(),
            drain_timeout_ms: default_drain_timeout_ms(),
            max_concurrent_per_connection: default_max_concurrent_per_connection(),
            health_check_interval_ms: default_health_check_interval_ms(),
        }
    }
}

fn default_connections_per_agent() -> usize {
    4
}
fn default_connect_timeout_ms() -> u64 {
    5000
}
fn default_reconnect_interval_ms() -> u64 {
    5000
}
fn default_max_reconnect_attempts() -> usize {
    3
}
fn default_drain_timeout_ms() -> u64 {
    30000
}
fn default_max_concurrent_per_connection() -> usize {
    100
}
fn default_health_check_interval_ms() -> u64 {
    10000
}

/// Load balancing strategy for v2 agent pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Round-robin across all healthy connections
    #[default]
    RoundRobin,
    /// Route to connection with fewest in-flight requests
    LeastConnections,
    /// Route based on health score (prefer healthier agents)
    HealthBased,
    /// Random selection
    Random,
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AgentConfig {
    /// Unique agent identifier
    pub id: String,

    /// Agent type
    #[serde(rename = "type")]
    pub agent_type: AgentType,

    /// Transport configuration
    pub transport: AgentTransport,

    /// Events this agent handles
    pub events: Vec<AgentEvent>,

    /// Protocol version (default: v1)
    ///
    /// - `v1`: Simple request/response protocol (backwards compatible)
    /// - `v2`: Bidirectional streaming with capabilities, health reporting,
    ///   metrics export, and flow control
    #[serde(default)]
    pub protocol_version: AgentProtocolVersion,

    /// V2 pool configuration (only used when protocol_version is v2)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<AgentPoolConfig>,

    /// Timeout for agent calls
    #[serde(default = "default_agent_timeout")]
    pub timeout_ms: u64,

    /// Failure mode when agent is unavailable
    #[serde(default)]
    pub failure_mode: FailureMode,

    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Maximum request body to send
    pub max_request_body_bytes: Option<usize>,

    /// Maximum response body to send
    pub max_response_body_bytes: Option<usize>,

    /// Request body streaming mode
    ///
    /// Controls how request bodies are sent to this agent:
    /// - `buffer`: Collect entire body before sending (default)
    /// - `stream`: Send chunks as they arrive
    /// - `hybrid`: Buffer small bodies, stream large ones
    #[serde(default)]
    pub request_body_mode: BodyStreamingMode,

    /// Response body streaming mode
    ///
    /// Controls how response bodies are sent to this agent.
    /// Same options as request_body_mode.
    #[serde(default)]
    pub response_body_mode: BodyStreamingMode,

    /// Timeout per body chunk when streaming (milliseconds)
    ///
    /// Only applies when using `stream` or `hybrid` mode.
    /// Default: 5000ms (5 seconds)
    #[serde(default = "default_chunk_timeout")]
    pub chunk_timeout_ms: u64,

    /// Agent-specific configuration
    ///
    /// This configuration is passed to the agent via the Configure event
    /// when the agent connects. The structure depends on the agent type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,

    /// Maximum concurrent calls to this agent
    ///
    /// Limits the number of simultaneous requests that can be processed by this agent.
    /// This provides per-agent queue isolation to prevent a slow agent from affecting
    /// other agents (noisy neighbor problem).
    ///
    /// Default: 100 concurrent calls per agent
    #[serde(default = "default_max_concurrent_calls")]
    pub max_concurrent_calls: usize,
}

fn default_chunk_timeout() -> u64 {
    5000 // 5 seconds
}

fn default_max_concurrent_calls() -> usize {
    100 // Per-agent concurrency limit
}

// ============================================================================
// Agent Type
// ============================================================================

/// Agent type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Waf,
    Auth,
    RateLimit,
    Custom(String),
}

// ============================================================================
// Agent Transport
// ============================================================================

/// Agent transport configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransport {
    /// Unix domain socket
    UnixSocket { path: PathBuf },

    /// gRPC over TCP
    Grpc {
        address: String,
        tls: Option<AgentTlsConfig>,
    },

    /// HTTP REST API
    Http {
        url: String,
        tls: Option<AgentTlsConfig>,
    },
}

/// Agent TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTlsConfig {
    /// Skip certificate verification
    #[serde(default)]
    pub insecure_skip_verify: bool,

    /// CA certificate
    pub ca_cert: Option<PathBuf>,

    /// Client certificate for mTLS
    pub client_cert: Option<PathBuf>,

    /// Client key for mTLS
    pub client_key: Option<PathBuf>,
}

// ============================================================================
// Agent Events
// ============================================================================

/// Agent events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentEvent {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Log,
    /// WebSocket frame inspection (after upgrade)
    WebSocketFrame,
    /// Guardrail inspection (prompt injection, PII detection)
    Guardrail,
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_agent_timeout() -> u64 {
    1000
}
