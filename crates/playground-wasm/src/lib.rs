//! WebAssembly bindings for the Zentinel Config Playground
//!
//! This crate provides JavaScript-friendly bindings for the Zentinel
//! configuration simulator, enabling in-browser config validation and
//! route decision tracing.
//!
//! # Usage from JavaScript
//!
//! ```javascript
//! import init, { validate, simulate, get_version } from 'zentinel-playground-wasm';
//!
//! async function main() {
//!     await init();
//!
//!     // Validate a config
//!     const result = validate(`
//!         server { }
//!         listeners {
//!             listener "http" {
//!                 address "0.0.0.0:8080"
//!             }
//!         }
//!         routes {
//!             route "api" {
//!                 matches {
//!                     path-prefix "/api"
//!                 }
//!                 upstream "backend"
//!             }
//!         }
//!         upstreams {
//!             upstream "backend" {
//!                 target "127.0.0.1:8080"
//!             }
//!         }
//!     `);
//!
//!     if (result.valid) {
//!         // Simulate a request
//!         const decision = simulate(configKdl, JSON.stringify({
//!             method: "GET",
//!             host: "example.com",
//!             path: "/api/users",
//!             headers: {},
//!             query_params: {}
//!         }));
//!
//!         console.log("Matched route:", decision.matched_route);
//!         console.log("Match trace:", decision.match_trace);
//!     }
//! }
//! ```

use wasm_bindgen::prelude::*;

use zentinel_sim::{
    validate as sim_validate, simulate as sim_simulate, get_effective_config,
    simulate_sequence as sim_simulate_sequence, simulate_with_agents as sim_simulate_with_agents,
    MockAgentResponse, SimulatedRequest, TimestampedRequest,
};

/// Initialize panic hook for better error messages in the console
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the version of the playground WASM module
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Validate a KDL configuration string
///
/// Returns a JSON object with the following structure:
/// ```json
/// {
///     "valid": true/false,
///     "errors": [...],
///     "warnings": [...],
///     "effective_config": {...}  // Only present if valid
/// }
/// ```
#[wasm_bindgen]
pub fn validate(config_kdl: &str) -> JsValue {
    let result = sim_validate(config_kdl);

    // Convert to a serializable format
    let response = ValidationResponse {
        valid: result.valid,
        errors: result.errors.iter().map(|e| ErrorInfo {
            message: e.message.clone(),
            severity: format!("{:?}", e.severity).to_lowercase(),
            line: e.location.as_ref().map(|l| l.line),
            column: e.location.as_ref().map(|l| l.column),
            hint: e.hint.clone(),
        }).collect(),
        warnings: result.warnings.iter().map(|w| WarningInfo {
            code: w.code.clone(),
            message: w.message.clone(),
        }).collect(),
        effective_config: if result.valid {
            result.effective_config.as_ref().map(|c| get_effective_config(c))
        } else {
            None
        },
    };

    serde_wasm_bindgen::to_value(&response).unwrap_or(JsValue::NULL)
}

/// Simulate routing a request through the configuration
///
/// Takes:
/// - `config_kdl`: KDL configuration string
/// - `request_json`: JSON string representing the request
///
/// Request JSON format:
/// ```json
/// {
///     "method": "GET",
///     "host": "example.com",
///     "path": "/api/users",
///     "headers": { "authorization": "Bearer token" },
///     "query_params": { "page": "1" }
/// }
/// ```
///
/// Returns a JSON object with the routing decision (see RouteDecision).
#[wasm_bindgen]
pub fn simulate(config_kdl: &str, request_json: &str) -> JsValue {
    // Parse config
    let validation = sim_validate(config_kdl);
    if !validation.valid {
        return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Invalid configuration".to_string(),
            details: validation.errors.iter().map(|e| e.message.clone()).collect(),
        }).unwrap_or(JsValue::NULL);
    }

    let config = match validation.effective_config {
        Some(c) => c,
        None => return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Failed to parse configuration".to_string(),
            details: vec![],
        }).unwrap_or(JsValue::NULL),
    };

    // Parse request
    let request: SimulatedRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Invalid request JSON".to_string(),
            details: vec![e.to_string()],
        }).unwrap_or(JsValue::NULL),
    };

    // Run simulation
    let decision = sim_simulate(&config, &request);

    serde_wasm_bindgen::to_value(&decision).unwrap_or(JsValue::NULL)
}

/// Validate and return the effective (normalized) configuration
///
/// This is useful for showing the config with all defaults applied.
#[wasm_bindgen]
pub fn get_normalized_config(config_kdl: &str) -> JsValue {
    let validation = sim_validate(config_kdl);

    if !validation.valid {
        return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Invalid configuration".to_string(),
            details: validation.errors.iter().map(|e| e.message.clone()).collect(),
        }).unwrap_or(JsValue::NULL);
    }

    match validation.effective_config {
        Some(config) => {
            let effective = get_effective_config(&config);
            serde_wasm_bindgen::to_value(&effective).unwrap_or(JsValue::NULL)
        }
        None => JsValue::NULL,
    }
}

/// Create a sample request for testing
///
/// Returns a JSON object that can be passed to `simulate()`.
#[wasm_bindgen]
pub fn create_sample_request(method: &str, host: &str, path: &str) -> JsValue {
    let request = SimulatedRequest::new(method, host, path);
    serde_wasm_bindgen::to_value(&request).unwrap_or(JsValue::NULL)
}

/// Simulate a sequence of requests with stateful policy tracking
///
/// This enables simulation of multiple requests with state tracking for:
/// - Rate limiting (token bucket per route)
/// - Caching (entries with TTL)
/// - Circuit breakers (per upstream)
/// - Load balancer position (round-robin)
///
/// Takes:
/// - `config_kdl`: KDL configuration string
/// - `requests_json`: JSON array of timestamped requests
///
/// Request JSON format:
/// ```json
/// [
///     {
///         "method": "GET",
///         "host": "example.com",
///         "path": "/api/users",
///         "timestamp": 0.0
///     },
///     {
///         "method": "GET",
///         "host": "example.com",
///         "path": "/api/users",
///         "timestamp": 0.1
///     }
/// ]
/// ```
///
/// Returns a JSON object with:
/// - `results`: Array of per-request results
/// - `state_transitions`: Array of state changes that occurred
/// - `final_state`: Final state of all policy components
/// - `summary`: Summary statistics (hit rates, rate limited count, etc.)
#[wasm_bindgen]
pub fn simulate_stateful(config_kdl: &str, requests_json: &str) -> JsValue {
    // Parse config
    let validation = sim_validate(config_kdl);
    if !validation.valid {
        return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Invalid configuration".to_string(),
            details: validation.errors.iter().map(|e| e.message.clone()).collect(),
        })
        .unwrap_or(JsValue::NULL);
    }

    let config = match validation.effective_config {
        Some(c) => c,
        None => {
            return serde_wasm_bindgen::to_value(&SimulationError {
                error: "Failed to parse configuration".to_string(),
                details: vec![],
            })
            .unwrap_or(JsValue::NULL)
        }
    };

    // Parse requests
    let mut requests: Vec<TimestampedRequest> = match serde_json::from_str(requests_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SimulationError {
                error: "Invalid requests JSON".to_string(),
                details: vec![e.to_string()],
            })
            .unwrap_or(JsValue::NULL)
        }
    };

    // Auto-assign timestamps if not provided (default is 0.0)
    for (i, req) in requests.iter_mut().enumerate() {
        if req.timestamp == 0.0 && i > 0 {
            req.timestamp = i as f64;
        }
    }

    // Run stateful simulation
    let result = sim_simulate_sequence(&config, &requests);

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

/// Simulate a request with mock agent responses
///
/// This enables simulation of agent decisions (WAF, auth, custom agents)
/// and shows how they affect the request pipeline.
///
/// Takes:
/// - `config_kdl`: KDL configuration string
/// - `request_json`: JSON string representing the request
/// - `agent_responses_json`: JSON array of mock agent responses
///
/// Mock agent response format:
/// ```json
/// [
///     {
///         "agent_id": "waf",
///         "decision": { "type": "block", "status": 403, "body": "Blocked" },
///         "request_headers": [{ "op": "set", "name": "X-WAF", "value": "checked" }],
///         "response_headers": [],
///         "audit": { "rule_ids": ["942100"], "tags": ["sql-injection"] }
///     }
/// ]
/// ```
///
/// Decision types:
/// - `{ "type": "allow" }` - Allow the request
/// - `{ "type": "block", "status": 403, "body": "..." }` - Block with response
/// - `{ "type": "redirect", "url": "...", "status": 302 }` - Redirect
/// - `{ "type": "challenge", "challenge_type": "captcha", "params": {} }` - Challenge
///
/// Returns a JSON object with:
/// - `matched_route`: The matched route
/// - `agent_chain`: Step-by-step trace of agent execution
/// - `final_decision`: Combined decision ("allow", "block", "redirect", "challenge")
/// - `final_request`: Request after all header mutations
/// - `block_response`: Block details (if blocked)
/// - `redirect_url`: Redirect URL (if redirecting)
/// - `audit_trail`: Combined audit info from all agents
#[wasm_bindgen]
pub fn simulate_with_agents(
    config_kdl: &str,
    request_json: &str,
    agent_responses_json: &str,
) -> JsValue {
    // Validate config
    let validation = sim_validate(config_kdl);
    if !validation.valid {
        return serde_wasm_bindgen::to_value(&SimulationError {
            error: "Invalid configuration".to_string(),
            details: validation.errors.iter().map(|e| e.message.clone()).collect(),
        })
        .unwrap_or(JsValue::NULL);
    }

    let config = match validation.effective_config {
        Some(c) => c,
        None => {
            return serde_wasm_bindgen::to_value(&SimulationError {
                error: "Failed to parse configuration".to_string(),
                details: vec![],
            })
            .unwrap_or(JsValue::NULL)
        }
    };

    // Parse request
    let request: SimulatedRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SimulationError {
                error: "Invalid request JSON".to_string(),
                details: vec![e.to_string()],
            })
            .unwrap_or(JsValue::NULL)
        }
    };

    // Parse mock responses
    let mock_responses: Vec<MockAgentResponse> = match serde_json::from_str(agent_responses_json) {
        Ok(r) => r,
        Err(e) => {
            return serde_wasm_bindgen::to_value(&SimulationError {
                error: "Invalid agent responses JSON".to_string(),
                details: vec![e.to_string()],
            })
            .unwrap_or(JsValue::NULL)
        }
    };

    // Run agent simulation
    let result = sim_simulate_with_agents(&config, &request, &mock_responses);

    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

// ============================================================================
// Internal types for serialization
// ============================================================================

#[derive(serde::Serialize)]
struct ValidationResponse {
    valid: bool,
    errors: Vec<ErrorInfo>,
    warnings: Vec<WarningInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_config: Option<serde_json::Value>,
}

#[derive(serde::Serialize)]
struct ErrorInfo {
    message: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

#[derive(serde::Serialize)]
struct WarningInfo {
    code: String,
    message: String,
}

#[derive(serde::Serialize)]
struct SimulationError {
    error: String,
    details: Vec<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_validate_valid_config() {
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
        "#;

        // This test just verifies the function doesn't panic
        // Full testing is done in zentinel-sim
        let _ = sim_validate(kdl);
    }
}
