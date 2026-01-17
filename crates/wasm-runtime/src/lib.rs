//! WebAssembly Agent Runtime for Sentinel
//!
//! This crate provides a sandboxed runtime for executing WASM agents in-process.
//! WASM agents offer lower latency than external agents (~10-50μs vs ~40-50μs)
//! while maintaining crash isolation through WebAssembly's sandboxing.
//!
//! # When to Use WASM Agents
//!
//! WASM agents are ideal for:
//! - Latency-critical operations (<20μs requirement)
//! - Stateless, bounded computations
//! - Simple checks (allowlist/denylist, header validation)
//!
//! Keep using external agents for:
//! - WAF (requires C libraries)
//! - Auth with external IdP calls
//! - ML inference
//! - Unbounded computation
//!
//! # Example
//!
//! ```ignore
//! use sentinel_wasm_runtime::{WasmAgentRuntime, WasmAgentConfig};
//!
//! // Create runtime with resource limits
//! let config = WasmAgentConfig::default();
//! let runtime = WasmAgentRuntime::new(config)?;
//!
//! // Load a WASM agent
//! let agent = runtime.load_agent("my-agent", wasm_bytes).await?;
//!
//! // Process requests
//! let response = agent.on_request_headers(metadata, method, uri, headers).await?;
//! ```

#![allow(dead_code)]

pub mod component;
mod config;
mod error;
mod host;
mod runtime;

pub use config::{WasmAgentConfig, WasmResourceLimits};
pub use error::WasmRuntimeError;
pub use host::WasmAgentInstance;
pub use runtime::WasmAgentRuntime;

/// Re-export types from agent-protocol for convenience
pub use sentinel_agent_protocol::{
    AgentResponse, Decision, EventType, HeaderOp, RequestMetadata,
};
