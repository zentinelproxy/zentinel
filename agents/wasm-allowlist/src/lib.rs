//! WASM Allowlist Agent
//!
//! A simple WASM agent that checks request paths against an allowlist or denylist.
//! This demonstrates how to build WASM agents for Zentinel.
//!
//! # Configuration
//!
//! ```json
//! {
//!     "mode": "denylist",
//!     "paths": ["/admin", "/internal"],
//!     "status_code": 403,
//!     "message": "Access Denied"
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Global configuration (set once during configure)
static CONFIG: OnceLock<AgentConfig> = OnceLock::new();

/// Agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Mode: "allowlist" or "denylist"
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Paths to check
    #[serde(default)]
    pub paths: Vec<String>,
    /// Status code to return when blocking
    #[serde(default = "default_status")]
    pub status_code: u16,
    /// Message to return when blocking
    #[serde(default = "default_message")]
    pub message: String,
}

fn default_mode() -> String { "denylist".to_string() }
fn default_status() -> u16 { 403 }
fn default_message() -> String { "Access Denied".to_string() }

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            mode: default_mode(),
            paths: vec![],
            status_code: default_status(),
            message: default_message(),
        }
    }
}

/// Decision returned by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Block {
        status: u16,
        body: Option<String>,
    },
}

/// Agent response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentResponse {
    pub decision: Decision,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl AgentResponse {
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            tags: vec![],
        }
    }

    pub fn block(status: u16, body: impl Into<String>) -> Self {
        Self {
            decision: Decision::Block {
                status,
                body: Some(body.into()),
            },
            tags: vec!["blocked".to_string()],
        }
    }
}

/// Agent information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub name: String,
    pub version: String,
    pub supported_events: Vec<String>,
    pub max_body_size: u64,
    pub supports_streaming: bool,
}

/// Get agent information.
#[no_mangle]
pub extern "C" fn get_info() -> *const u8 {
    let info = AgentInfo {
        agent_id: "wasm-allowlist".to_string(),
        name: "WASM Allowlist Agent".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        supported_events: vec!["request_headers".to_string()],
        max_body_size: 0, // We don't inspect body
        supports_streaming: false,
    };

    // Serialize to JSON and leak the memory (WASM linear memory)
    let json = serde_json::to_string(&info).unwrap_or_default();
    let ptr = json.as_ptr();
    std::mem::forget(json);
    ptr
}

/// Configure the agent.
///
/// Returns 0 on success, non-zero on error.
#[no_mangle]
pub extern "C" fn configure(config_ptr: *const u8, config_len: usize) -> i32 {
    // Safety: We trust the host to provide valid pointers
    let config_bytes = unsafe {
        if config_ptr.is_null() || config_len == 0 {
            return 1;
        }
        std::slice::from_raw_parts(config_ptr, config_len)
    };

    let config_str = match std::str::from_utf8(config_bytes) {
        Ok(s) => s,
        Err(_) => return 2,
    };

    let config: AgentConfig = match serde_json::from_str(config_str) {
        Ok(c) => c,
        Err(_) => return 3,
    };

    // Validate mode
    if config.mode != "allowlist" && config.mode != "denylist" {
        return 4;
    }

    // Store configuration
    if CONFIG.set(config).is_err() {
        return 5; // Already configured
    }

    0
}

/// Process request headers.
///
/// Returns a pointer to the response JSON.
#[no_mangle]
pub extern "C" fn on_request_headers(
    _metadata_ptr: *const u8,
    _metadata_len: usize,
    _method_ptr: *const u8,
    _method_len: usize,
    uri_ptr: *const u8,
    uri_len: usize,
    _headers_ptr: *const u8,
    _headers_len: usize,
) -> *const u8 {
    let config = match CONFIG.get() {
        Some(c) => c,
        None => {
            // Not configured, allow by default
            let response = AgentResponse::allow();
            let json = serde_json::to_string(&response).unwrap_or_default();
            let ptr = json.as_ptr();
            std::mem::forget(json);
            return ptr;
        }
    };

    // Get URI
    let uri = unsafe {
        if uri_ptr.is_null() || uri_len == 0 {
            ""
        } else {
            std::str::from_utf8(std::slice::from_raw_parts(uri_ptr, uri_len)).unwrap_or("")
        }
    };

    // Check against configured paths
    let matches_path = config.paths.iter().any(|p| uri.starts_with(p));

    let response = match config.mode.as_str() {
        "allowlist" => {
            if matches_path {
                AgentResponse::allow()
            } else {
                AgentResponse::block(config.status_code, &config.message)
            }
        }
        "denylist" => {
            if matches_path {
                AgentResponse::block(config.status_code, &config.message)
            } else {
                AgentResponse::allow()
            }
        }
        _ => AgentResponse::allow(),
    };

    let json = serde_json::to_string(&response).unwrap_or_default();
    let ptr = json.as_ptr();
    std::mem::forget(json);
    ptr
}

/// Health check.
///
/// Returns 0 for healthy, non-zero for unhealthy.
#[no_mangle]
pub extern "C" fn health_check() -> i32 {
    if CONFIG.get().is_some() {
        0 // Healthy
    } else {
        1 // Not configured
    }
}

/// Shutdown.
#[no_mangle]
pub extern "C" fn shutdown() {
    // Nothing to clean up
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = AgentConfig::default();
        assert_eq!(config.mode, "denylist");
        assert_eq!(config.status_code, 403);
    }

    #[test]
    fn test_config_parse() {
        let json = r#"{"mode": "allowlist", "paths": ["/api"], "status_code": 401}"#;
        let config: AgentConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, "allowlist");
        assert_eq!(config.paths, vec!["/api"]);
        assert_eq!(config.status_code, 401);
    }

    #[test]
    fn test_response_allow() {
        let response = AgentResponse::allow();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("allow"));
    }

    #[test]
    fn test_response_block() {
        let response = AgentResponse::block(403, "Forbidden");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("block"));
        assert!(json.contains("403"));
    }
}
