//! Agent decision types.

use std::collections::HashMap;

use zentinel_agent_protocol::{AgentResponse, AuditMetadata, BodyMutation, Decision, HeaderOp};

/// Agent decision combining all agent responses.
#[derive(Debug, Clone)]
pub struct AgentDecision {
    /// Final decision action
    pub action: AgentAction,
    /// ID of the agent that produced the deciding (non-allow) action
    ///
    /// `None` for allow decisions and for decisions not attributable to a
    /// specific agent. Preserved through [`AgentDecision::merge`] so block
    /// logs can always answer "which agent blocked this request".
    pub decided_by: Option<String>,
    /// Header modifications for request
    pub request_headers: Vec<HeaderOp>,
    /// Header modifications for response
    pub response_headers: Vec<HeaderOp>,
    /// Audit metadata from all agents
    pub audit: Vec<AuditMetadata>,
    /// Routing metadata updates
    pub routing_metadata: HashMap<String, String>,
    /// Whether agent needs more data to make final decision (streaming mode)
    pub needs_more: bool,
    /// Mutation for request body chunk (streaming mode)
    pub request_body_mutation: Option<BodyMutation>,
    /// Mutation for response body chunk (streaming mode)
    pub response_body_mutation: Option<BodyMutation>,
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
            decided_by: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
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
            decided_by: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            audit: Vec::new(),
            routing_metadata: HashMap::new(),
            needs_more: false,
            request_body_mutation: None,
            response_body_mutation: None,
        }
    }

    /// Attribute this decision to the agent that produced it.
    pub fn with_decided_by(mut self, agent_id: impl Into<String>) -> Self {
        self.decided_by = Some(agent_id.into());
        self
    }

    /// Convert an agent response into a decision attributed to `agent_id`.
    pub fn from_response(response: AgentResponse, agent_id: &str) -> Self {
        let mut decision: Self = response.into();
        decision.decided_by = Some(agent_id.to_string());
        decision
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
        // If other decision is not allow, use it (and keep its attribution)
        if !other.is_allow() {
            self.action = other.action;
            self.decided_by = other.decided_by;
        }

        // Merge header modifications
        self.request_headers.extend(other.request_headers);
        self.response_headers.extend(other.response_headers);

        // Merge audit metadata
        self.audit.extend(other.audit);

        // Merge routing metadata
        self.routing_metadata.extend(other.routing_metadata);

        // Streaming: if any agent needs more, we need more
        if other.needs_more {
            self.needs_more = true;
        }

        // Body mutations: last one wins
        if other.request_body_mutation.is_some() {
            self.request_body_mutation = other.request_body_mutation;
        }
        if other.response_body_mutation.is_some() {
            self.response_body_mutation = other.response_body_mutation;
        }
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
            decided_by: None,
            request_headers: response.request_headers,
            response_headers: response.response_headers,
            audit: vec![response.audit],
            routing_metadata: response.routing_metadata,
            needs_more: response.needs_more,
            request_body_mutation: response.request_body_mutation,
            response_body_mutation: response.response_body_mutation,
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

    #[test]
    fn merge_preserves_blocking_agent_attribution() {
        let mut combined = AgentDecision::default_allow().with_decided_by("auth");
        // Allow decisions carry no attribution worth keeping
        assert!(combined.is_allow());

        let block = AgentDecision::block(403, "Forbidden").with_decided_by("waf");
        combined.merge(block);

        assert!(!combined.is_allow());
        assert_eq!(combined.decided_by.as_deref(), Some("waf"));
    }

    #[test]
    fn merge_with_allow_keeps_existing_attribution() {
        let mut combined = AgentDecision::block(403, "Forbidden").with_decided_by("waf");
        combined.merge(AgentDecision::default_allow());

        assert_eq!(combined.decided_by.as_deref(), Some("waf"));
    }

    #[test]
    fn from_response_sets_decided_by() {
        let response = AgentResponse::block(403, None);
        let decision = AgentDecision::from_response(response, "waf");
        assert!(!decision.is_allow());
        assert_eq!(decision.decided_by.as_deref(), Some("waf"));
    }
}
