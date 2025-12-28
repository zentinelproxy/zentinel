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
}

// ============================================================================
// Default Value Functions
// ============================================================================

fn default_agent_timeout() -> u64 {
    1000
}
