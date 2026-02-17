//! Agent decision simulation for Zentinel configurations
//!
//! This module enables simulation of agent responses in the request pipeline,
//! allowing users to provide mock agent decisions and see how they affect
//! the final request/response.
//!
//! # Example
//!
//! ```ignore
//! let mock_responses = vec![
//!     MockAgentResponse {
//!         agent_id: "waf".to_string(),
//!         decision: AgentDecision::Block { status: 403, body: None, headers: HashMap::new() },
//!         ..Default::default()
//!     },
//! ];
//! let result = simulate_with_agents(&config, &request, &mock_responses);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{MatchedRoute, Warning};
use crate::{simulate, RouteDecision, SimulatedRequest};
use zentinel_config::Config;

// ============================================================================
// Input Types
// ============================================================================

/// Mock response from an agent (provided by user)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockAgentResponse {
    /// Which agent this response is for
    pub agent_id: String,

    /// The decision this agent makes
    pub decision: AgentDecision,

    /// Header mutations to apply to the request
    #[serde(default)]
    pub request_headers: Vec<HeaderMutation>,

    /// Header mutations to apply to the response
    #[serde(default)]
    pub response_headers: Vec<HeaderMutation>,

    /// Audit metadata for logging
    #[serde(default)]
    pub audit: AuditInfo,
}

impl Default for MockAgentResponse {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            decision: AgentDecision::Allow,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: AuditInfo::default(),
        }
    }
}

/// Agent decision (WASM-compatible version of protocol::Decision)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentDecision {
    /// Allow the request to proceed
    Allow,

    /// Block the request with a specific response
    Block {
        status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
        #[serde(default)]
        headers: HashMap<String, String>,
    },

    /// Redirect the request to a different URL
    Redirect {
        url: String,
        #[serde(default = "default_redirect_status")]
        status: u16,
    },

    /// Challenge the request (e.g., CAPTCHA)
    Challenge {
        challenge_type: String,
        #[serde(default)]
        params: HashMap<String, String>,
    },
}

fn default_redirect_status() -> u16 {
    302
}

impl std::fmt::Display for AgentDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentDecision::Allow => write!(f, "allow"),
            AgentDecision::Block { .. } => write!(f, "block"),
            AgentDecision::Redirect { .. } => write!(f, "redirect"),
            AgentDecision::Challenge { .. } => write!(f, "challenge"),
        }
    }
}

/// Header mutation operation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HeaderMutation {
    /// Set a header (replace if exists)
    Set { name: String, value: String },

    /// Add to a header (append with comma if exists)
    Add { name: String, value: String },

    /// Remove a header
    Remove { name: String },
}

/// Audit information from an agent
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AuditInfo {
    /// Tags for categorization
    #[serde(default)]
    pub tags: Vec<String>,

    /// Rule IDs that matched
    #[serde(default)]
    pub rule_ids: Vec<String>,

    /// Confidence score (0.0 - 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    /// Reason codes explaining the decision
    #[serde(default)]
    pub reason_codes: Vec<String>,
}

// ============================================================================
// Output Types
// ============================================================================

/// Result of simulating agents for a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSimulationResult {
    /// The matched route (same as regular simulate)
    pub matched_route: Option<MatchedRoute>,

    /// Step-by-step trace of agent execution
    pub agent_chain: Vec<AgentChainStep>,

    /// Final combined decision
    pub final_decision: String,

    /// Request after all mutations applied
    pub final_request: TransformedRequest,

    /// Response headers to add (accumulated from all agents)
    pub response_headers: Vec<HeaderMutation>,

    /// Block response details (if final_decision is "block")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_response: Option<BlockResponse>,

    /// Redirect URL (if final_decision is "redirect")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,

    /// Redirect status (if final_decision is "redirect")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_status: Option<u16>,

    /// Challenge details (if final_decision is "challenge")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<ChallengeInfo>,

    /// Combined audit trail from all agents
    pub audit_trail: Vec<AuditEntry>,

    /// Warnings about missing agents, etc.
    pub warnings: Vec<Warning>,
}

/// One step in the agent chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentChainStep {
    /// Agent ID
    pub agent_id: String,

    /// Agent type (waf, auth, custom, etc.)
    pub agent_type: String,

    /// Hook phase (on_request_headers, on_request_body, etc.)
    pub hook: String,

    /// Decision made by this agent
    pub decision: String,

    /// Number of header mutations applied
    pub mutations_applied: usize,

    /// Whether this decision short-circuited the chain
    pub short_circuited: bool,
}

/// The request after transformations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformedRequest {
    /// HTTP method
    pub method: String,

    /// Host header
    pub host: String,

    /// Request path
    pub path: String,

    /// Headers after mutations
    pub headers: HashMap<String, String>,

    /// Query parameters
    pub query_params: HashMap<String, String>,

    /// Headers that were added
    pub added_headers: Vec<String>,

    /// Headers that were removed
    pub removed_headers: Vec<String>,

    /// Headers that were modified
    pub modified_headers: Vec<String>,
}

impl From<&SimulatedRequest> for TransformedRequest {
    fn from(req: &SimulatedRequest) -> Self {
        Self {
            method: req.method.clone(),
            host: req.host.clone(),
            path: req.path.clone(),
            headers: req.headers.clone(),
            query_params: req.query_params.clone(),
            added_headers: Vec::new(),
            removed_headers: Vec::new(),
            modified_headers: Vec::new(),
        }
    }
}

/// Block response details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    /// HTTP status code
    pub status: u16,

    /// Response body
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Response headers
    pub headers: HashMap<String, String>,

    /// Which agent blocked the request
    pub blocking_agent: String,
}

/// Challenge information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeInfo {
    /// Challenge type (e.g., "captcha")
    pub challenge_type: String,

    /// Challenge parameters
    pub params: HashMap<String, String>,

    /// Which agent issued the challenge
    pub challenging_agent: String,
}

/// Audit entry from one agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Agent ID
    pub agent_id: String,

    /// Tags
    pub tags: Vec<String>,

    /// Rule IDs
    pub rule_ids: Vec<String>,

    /// Confidence score
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    /// Reason codes
    pub reason_codes: Vec<String>,
}

impl AuditEntry {
    fn from_audit_info(info: &AuditInfo, agent_id: &str) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            tags: info.tags.clone(),
            rule_ids: info.rule_ids.clone(),
            confidence: info.confidence,
            reason_codes: info.reason_codes.clone(),
        }
    }
}

// ============================================================================
// Internal Types
// ============================================================================

/// Information about an agent hook to fire
struct AgentHookInfo {
    agent_id: String,
    agent_type: String,
    hook: String,
}

// ============================================================================
// Main Simulation Function
// ============================================================================

/// Simulate a request with mock agent responses
///
/// This function:
/// 1. Matches a route using standard simulation
/// 2. Identifies which agents should fire based on route filters
/// 3. Executes each agent with user-provided mock responses
/// 4. Applies header mutations to build the transformed request
/// 5. Combines decisions (first non-Allow wins)
///
/// # Arguments
///
/// * `config` - The parsed Zentinel configuration
/// * `request` - The simulated HTTP request
/// * `mock_responses` - Mock responses for each agent
///
/// # Returns
///
/// An `AgentSimulationResult` containing the full trace of agent execution.
pub fn simulate_with_agents(
    config: &Config,
    request: &SimulatedRequest,
    mock_responses: &[MockAgentResponse],
) -> AgentSimulationResult {
    // 1. Get base route decision (reuse existing simulate logic)
    let base: RouteDecision = simulate(config, request);

    // 2. Build list of agents that should fire
    let agents_to_fire = get_agents_for_route(&base, config);

    // 3. Build a lookup map for mock responses
    let mock_map: HashMap<&str, &MockAgentResponse> = mock_responses
        .iter()
        .map(|r| (r.agent_id.as_str(), r))
        .collect();

    // 4. Initialize transformed request from original
    let mut transformed = TransformedRequest::from(request);
    let mut response_headers = Vec::new();
    let mut chain_steps = Vec::new();
    let mut audit_trail = Vec::new();
    let mut final_decision = AgentDecision::Allow;
    let mut blocking_agent = String::new();
    let mut warnings = base.warnings.clone();

    // 5. Execute agent chain
    for agent_hook in &agents_to_fire {
        let mock_response = mock_map.get(agent_hook.agent_id.as_str());

        let step = if let Some(mock) = mock_response {
            // Apply this agent's request header mutations
            let mutations = apply_header_mutations(&mut transformed, &mock.request_headers);

            // Accumulate response headers
            response_headers.extend(mock.response_headers.clone());

            // Record audit if non-empty
            if !mock.audit.tags.is_empty()
                || !mock.audit.rule_ids.is_empty()
                || mock.audit.confidence.is_some()
                || !mock.audit.reason_codes.is_empty()
            {
                audit_trail.push(AuditEntry::from_audit_info(&mock.audit, &agent_hook.agent_id));
            }

            // Check if this decision should short-circuit
            let short_circuit = !matches!(mock.decision, AgentDecision::Allow);
            if short_circuit && matches!(final_decision, AgentDecision::Allow) {
                final_decision = mock.decision.clone();
                blocking_agent = agent_hook.agent_id.clone();
            }

            AgentChainStep {
                agent_id: agent_hook.agent_id.clone(),
                agent_type: agent_hook.agent_type.clone(),
                hook: agent_hook.hook.clone(),
                decision: mock.decision.to_string(),
                mutations_applied: mutations,
                short_circuited: short_circuit,
            }
        } else {
            // No mock provided - warn and assume allow
            warnings.push(Warning {
                code: "MISSING_MOCK_RESPONSE".to_string(),
                message: format!(
                    "No mock response provided for agent '{}', assuming Allow",
                    agent_hook.agent_id
                ),
            });

            AgentChainStep {
                agent_id: agent_hook.agent_id.clone(),
                agent_type: agent_hook.agent_type.clone(),
                hook: agent_hook.hook.clone(),
                decision: "allow".to_string(),
                mutations_applied: 0,
                short_circuited: false,
            }
        };

        chain_steps.push(step);
    }

    // 6. Build result
    let (block_response, redirect_url, redirect_status, challenge) =
        extract_decision_details(&final_decision, &blocking_agent);

    AgentSimulationResult {
        matched_route: base.matched_route,
        agent_chain: chain_steps,
        final_decision: final_decision.to_string(),
        final_request: transformed,
        response_headers,
        block_response,
        redirect_url,
        redirect_status,
        challenge,
        audit_trail,
        warnings,
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get list of agents that should fire for this route
fn get_agents_for_route(decision: &RouteDecision, config: &Config) -> Vec<AgentHookInfo> {
    decision
        .agent_hooks
        .iter()
        .map(|h| AgentHookInfo {
            agent_id: h.agent_id.clone(),
            agent_type: get_agent_type(config, &h.agent_id),
            hook: h.hook.clone(),
        })
        .collect()
}

/// Get the type of an agent from config
fn get_agent_type(config: &Config, agent_id: &str) -> String {
    config
        .agents
        .iter()
        .find(|a| a.id == agent_id)
        .map(|a| format!("{:?}", a.agent_type).to_lowercase())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Apply header mutations to transformed request
fn apply_header_mutations(request: &mut TransformedRequest, mutations: &[HeaderMutation]) -> usize {
    let mut count = 0;
    for mutation in mutations {
        match mutation {
            HeaderMutation::Set { name, value } => {
                let lower_name = name.to_lowercase();
                let existed = request.headers.insert(lower_name, value.clone()).is_some();
                if existed {
                    if !request.modified_headers.contains(name) {
                        request.modified_headers.push(name.clone());
                    }
                } else if !request.added_headers.contains(name) {
                    request.added_headers.push(name.clone());
                }
                count += 1;
            }
            HeaderMutation::Add { name, value } => {
                let lower_name = name.to_lowercase();
                request
                    .headers
                    .entry(lower_name)
                    .and_modify(|v| {
                        v.push_str(", ");
                        v.push_str(value);
                    })
                    .or_insert_with(|| value.clone());
                if !request.added_headers.contains(name) {
                    request.added_headers.push(name.clone());
                }
                count += 1;
            }
            HeaderMutation::Remove { name } => {
                let lower_name = name.to_lowercase();
                if request.headers.remove(&lower_name).is_some() {
                    if !request.removed_headers.contains(name) {
                        request.removed_headers.push(name.clone());
                    }
                    count += 1;
                }
            }
        }
    }
    count
}

/// Extract decision details for the result
fn extract_decision_details(
    decision: &AgentDecision,
    blocking_agent: &str,
) -> (
    Option<BlockResponse>,
    Option<String>,
    Option<u16>,
    Option<ChallengeInfo>,
) {
    match decision {
        AgentDecision::Allow => (None, None, None, None),
        AgentDecision::Block {
            status,
            body,
            headers,
        } => (
            Some(BlockResponse {
                status: *status,
                body: body.clone(),
                headers: headers.clone(),
                blocking_agent: blocking_agent.to_string(),
            }),
            None,
            None,
            None,
        ),
        AgentDecision::Redirect { url, status } => (None, Some(url.clone()), Some(*status), None),
        AgentDecision::Challenge {
            challenge_type,
            params,
        } => (
            None,
            None,
            None,
            Some(ChallengeInfo {
                challenge_type: challenge_type.clone(),
                params: params.clone(),
                challenging_agent: blocking_agent.to_string(),
            }),
        ),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_mutation_set() {
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");
        let mut transformed = TransformedRequest::from(&request);

        let mutations = vec![HeaderMutation::Set {
            name: "X-Custom".to_string(),
            value: "test-value".to_string(),
        }];

        let count = apply_header_mutations(&mut transformed, &mutations);

        assert_eq!(count, 1);
        assert_eq!(
            transformed.headers.get("x-custom"),
            Some(&"test-value".to_string())
        );
        assert!(transformed.added_headers.contains(&"X-Custom".to_string()));
    }

    #[test]
    fn test_header_mutation_set_existing() {
        let request =
            SimulatedRequest::new("GET", "example.com", "/api").with_header("X-Existing", "old");
        let mut transformed = TransformedRequest::from(&request);

        let mutations = vec![HeaderMutation::Set {
            name: "X-Existing".to_string(),
            value: "new".to_string(),
        }];

        let count = apply_header_mutations(&mut transformed, &mutations);

        assert_eq!(count, 1);
        assert_eq!(
            transformed.headers.get("x-existing"),
            Some(&"new".to_string())
        );
        assert!(transformed
            .modified_headers
            .contains(&"X-Existing".to_string()));
    }

    #[test]
    fn test_header_mutation_add() {
        let request =
            SimulatedRequest::new("GET", "example.com", "/api").with_header("Accept", "text/html");
        let mut transformed = TransformedRequest::from(&request);

        let mutations = vec![HeaderMutation::Add {
            name: "Accept".to_string(),
            value: "application/json".to_string(),
        }];

        let count = apply_header_mutations(&mut transformed, &mutations);

        assert_eq!(count, 1);
        assert_eq!(
            transformed.headers.get("accept"),
            Some(&"text/html, application/json".to_string())
        );
    }

    #[test]
    fn test_header_mutation_remove() {
        let request = SimulatedRequest::new("GET", "example.com", "/api")
            .with_header("X-Remove-Me", "value");
        let mut transformed = TransformedRequest::from(&request);

        let mutations = vec![HeaderMutation::Remove {
            name: "X-Remove-Me".to_string(),
        }];

        let count = apply_header_mutations(&mut transformed, &mutations);

        assert_eq!(count, 1);
        assert!(transformed.headers.get("x-remove-me").is_none());
        assert!(transformed
            .removed_headers
            .contains(&"X-Remove-Me".to_string()));
    }

    #[test]
    fn test_agent_decision_display() {
        assert_eq!(AgentDecision::Allow.to_string(), "allow");
        assert_eq!(
            AgentDecision::Block {
                status: 403,
                body: None,
                headers: HashMap::new()
            }
            .to_string(),
            "block"
        );
        assert_eq!(
            AgentDecision::Redirect {
                url: "https://example.com".to_string(),
                status: 302
            }
            .to_string(),
            "redirect"
        );
        assert_eq!(
            AgentDecision::Challenge {
                challenge_type: "captcha".to_string(),
                params: HashMap::new()
            }
            .to_string(),
            "challenge"
        );
    }

    #[test]
    fn test_agent_decision_serialization() {
        let decision = AgentDecision::Block {
            status: 403,
            body: Some("Forbidden".to_string()),
            headers: HashMap::new(),
        };

        let json = serde_json::to_string(&decision).unwrap();
        assert!(json.contains("\"type\":\"block\""));
        assert!(json.contains("\"status\":403"));

        let parsed: AgentDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, decision);
    }

    #[test]
    fn test_header_mutation_serialization() {
        let mutation = HeaderMutation::Set {
            name: "X-Test".to_string(),
            value: "value".to_string(),
        };

        let json = serde_json::to_string(&mutation).unwrap();
        assert!(json.contains("\"op\":\"set\""));

        let parsed: HeaderMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mutation);
    }

    #[test]
    fn test_simulate_with_agents_no_route() {
        let config_kdl = r#"
            system {}
            listeners { listener "http" { address "0.0.0.0:8080" } }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    upstream "backend"
                }
            }
            upstreams { upstream "backend" { target "127.0.0.1:8080" } }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/other");

        let result = simulate_with_agents(&config, &request, &[]);

        assert!(result.matched_route.is_none());
        assert!(result.agent_chain.is_empty());
        assert_eq!(result.final_decision, "allow");
    }

    #[test]
    fn test_simulate_with_agents_allow() {
        let config_kdl = r#"
            system {}
            listeners { listener "http" { address "0.0.0.0:8080" } }
            agents {
                agent "auth" {
                    type "auth"
                    unix-socket "/var/run/auth.sock"
                }
            }
            filters {
                filter "auth-filter" {
                    type "agent"
                    agent "auth"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    filters "auth-filter"
                    upstream "backend"
                }
            }
            upstreams { upstream "backend" { target "127.0.0.1:8080" } }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");

        let mock_responses = vec![MockAgentResponse {
            agent_id: "auth".to_string(),
            decision: AgentDecision::Allow,
            request_headers: vec![HeaderMutation::Set {
                name: "X-User-ID".to_string(),
                value: "12345".to_string(),
            }],
            response_headers: vec![],
            audit: AuditInfo::default(),
        }];

        let result = simulate_with_agents(&config, &request, &mock_responses);

        assert!(result.matched_route.is_some());
        assert_eq!(result.final_decision, "allow");
        assert_eq!(result.agent_chain.len(), 1);
        assert_eq!(result.agent_chain[0].decision, "allow");
        assert_eq!(result.agent_chain[0].mutations_applied, 1);
        assert_eq!(
            result.final_request.headers.get("x-user-id"),
            Some(&"12345".to_string())
        );
    }

    #[test]
    fn test_simulate_with_agents_block() {
        let config_kdl = r#"
            system {}
            listeners { listener "http" { address "0.0.0.0:8080" } }
            agents {
                agent "waf" {
                    type "waf"
                    unix-socket "/var/run/waf.sock"
                }
            }
            filters {
                filter "waf-filter" {
                    type "agent"
                    agent "waf"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    filters "waf-filter"
                    upstream "backend"
                }
            }
            upstreams { upstream "backend" { target "127.0.0.1:8080" } }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();
        let request = SimulatedRequest::new("POST", "example.com", "/api/admin");

        let mock_responses = vec![MockAgentResponse {
            agent_id: "waf".to_string(),
            decision: AgentDecision::Block {
                status: 403,
                body: Some("Blocked by WAF".to_string()),
                headers: HashMap::new(),
            },
            request_headers: vec![],
            response_headers: vec![HeaderMutation::Set {
                name: "X-WAF-Result".to_string(),
                value: "blocked".to_string(),
            }],
            audit: AuditInfo {
                rule_ids: vec!["942100".to_string()],
                tags: vec!["sql-injection".to_string()],
                confidence: Some(0.95),
                reason_codes: vec![],
            },
        }];

        let result = simulate_with_agents(&config, &request, &mock_responses);

        assert_eq!(result.final_decision, "block");
        assert!(result.block_response.is_some());
        let block = result.block_response.unwrap();
        assert_eq!(block.status, 403);
        assert_eq!(block.body, Some("Blocked by WAF".to_string()));
        assert_eq!(block.blocking_agent, "waf");

        assert_eq!(result.audit_trail.len(), 1);
        assert_eq!(result.audit_trail[0].rule_ids, vec!["942100".to_string()]);
    }

    #[test]
    fn test_simulate_with_agents_redirect() {
        let config_kdl = r#"
            system {}
            listeners { listener "http" { address "0.0.0.0:8080" } }
            agents {
                agent "auth" {
                    type "auth"
                    unix-socket "/var/run/auth.sock"
                }
            }
            filters {
                filter "auth-filter" {
                    type "agent"
                    agent "auth"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    filters "auth-filter"
                    upstream "backend"
                }
            }
            upstreams { upstream "backend" { target "127.0.0.1:8080" } }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/api/protected");

        let mock_responses = vec![MockAgentResponse {
            agent_id: "auth".to_string(),
            decision: AgentDecision::Redirect {
                url: "https://login.example.com/auth".to_string(),
                status: 302,
            },
            request_headers: vec![],
            response_headers: vec![],
            audit: AuditInfo::default(),
        }];

        let result = simulate_with_agents(&config, &request, &mock_responses);

        assert_eq!(result.final_decision, "redirect");
        assert_eq!(
            result.redirect_url,
            Some("https://login.example.com/auth".to_string())
        );
        assert_eq!(result.redirect_status, Some(302));
    }

    #[test]
    fn test_simulate_with_agents_missing_mock() {
        let config_kdl = r#"
            system {}
            listeners { listener "http" { address "0.0.0.0:8080" } }
            agents {
                agent "auth" {
                    type "auth"
                    unix-socket "/var/run/auth.sock"
                }
            }
            filters {
                filter "auth-filter" {
                    type "agent"
                    agent "auth"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    filters "auth-filter"
                    upstream "backend"
                }
            }
            upstreams { upstream "backend" { target "127.0.0.1:8080" } }
        "#;

        let config = zentinel_config::Config::from_kdl(config_kdl).unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");

        // No mock responses provided
        let result = simulate_with_agents(&config, &request, &[]);

        assert_eq!(result.final_decision, "allow");
        assert!(result
            .warnings
            .iter()
            .any(|w| w.code == "MISSING_MOCK_RESPONSE"));
    }
}
