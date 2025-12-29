//! Agent decision types.

use std::collections::HashMap;

use sentinel_agent_protocol::{AgentResponse, AuditMetadata, Decision, HeaderOp};

/// Agent decision combining all agent responses.
#[derive(Debug, Clone)]
pub struct AgentDecision {
    /// Final decision action
    pub action: AgentAction,
    /// Header modifications for request
    pub request_headers: Vec<HeaderOp>,
    /// Header modifications for response
    pub response_headers: Vec<HeaderOp>,
    /// Audit metadata from all agents
    pub audit: Vec<AuditMetadata>,
    /// Routing metadata updates
    pub routing_metadata: HashMap<String, String>,
}

/// Agent action types.
#[derive(Debug, Clone)]
pub enum AgentAction {
    /// Allow request to proceed
    Allow,
    /// Block request
    Block {
        status: u16,
        body: Option<String>,
        headers: Option<HashMap<String, String>>,
    },
    /// Redirect request
    Redirect { url: String, status: u16 },
    /// Challenge client
    Challenge {
        challenge_type: String,
        params: HashMap<String, String>,
    },
}

impl AgentDecision {
    /// Create default allow decision.
    pub fn default_allow() -> Self {
        Self {
            action: AgentAction::Allow,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
        }
    }

    /// Create block decision.
    pub fn block(status: u16, message: &str) -> Self {
        Self {
            action: AgentAction::Block {
                status,
                body: Some(message.to_string()),
                headers: None,
            },
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
        }
    }

    /// Check if decision is to allow.
    pub fn is_allow(&self) -> bool {
        matches!(self.action, AgentAction::Allow)
    }

    /// Merge another decision into this one.
    ///
    /// If other decision is not allow, use it as the action.
    /// Header modifications, audit metadata, and routing metadata are merged.
    pub fn merge(&mut self, other: AgentDecision) {
        // If other decision is not allow, use it
        if !other.is_allow() {
            self.action = other.action;
        }

        // Merge header modifications
        self.request_headers.extend(other.request_headers);
        self.response_headers.extend(other.response_headers);

        // Merge audit metadata
        self.audit.extend(other.audit);

        // Merge routing metadata
        self.routing_metadata.extend(other.routing_metadata);
    }
}

impl From<AgentResponse> for AgentDecision {
    fn from(response: AgentResponse) -> Self {
        let action = match response.decision {
            Decision::Allow => AgentAction::Allow,
            Decision::Block {
                status,
                body,
                headers,
            } => AgentAction::Block {
                status,
                body,
                headers,
            },
            Decision::Redirect { url, status } => AgentAction::Redirect { url, status },
            Decision::Challenge {
                challenge_type,
                params,
            } => AgentAction::Challenge {
                challenge_type,
                params,
            },
        };

        Self {
            action,
            request_headers: response.request_headers,
            response_headers: response.response_headers,
            audit: vec![response.audit],
            routing_metadata: response.routing_metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_decision_merge() {
        let mut decision1 = AgentDecision::default_allow();
        decision1.request_headers.push(HeaderOp::Set {
            name: "X-Test".to_string(),
            value: "1".to_string(),
        });

        let decision2 = AgentDecision::block(403, "Forbidden");

        decision1.merge(decision2);
        assert!(!decision1.is_allow());
    }
}
