//! Agent configuration types
//!
//! This module contains configuration types for external processing agents
//! (WAF, auth, rate limiting, custom logic).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use validator::Validate;

use sentinel_common::types::CircuitBreakerConfig;

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
}

fn default_chunk_timeout() -> u64 {
    5000 // 5 seconds
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
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_agent_timeout() -> u64 {
    1000
}
