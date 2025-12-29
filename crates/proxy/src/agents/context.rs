//! Agent call context.

use sentinel_agent_protocol::RequestMetadata;
use sentinel_common::types::CorrelationId;

/// Agent call context.
///
/// Contains all information needed for an agent to process a request,
/// including correlation ID, request metadata, and optional body data.
pub struct AgentCallContext {
    /// Correlation ID for request tracing
    pub correlation_id: CorrelationId,
    /// Request metadata
    pub metadata: RequestMetadata,
    /// Route ID
    pub route_id: Option<String>,
    /// Upstream ID
    pub upstream_id: Option<String>,
    /// Request body buffer (if body inspection enabled)
    pub request_body: Option<Vec<u8>>,
    /// Response body buffer (if body inspection enabled)
    pub response_body: Option<Vec<u8>>,
}

impl AgentCallContext {
    /// Create a new agent call context.
    pub fn new(correlation_id: CorrelationId, metadata: RequestMetadata) -> Self {
        Self {
            correlation_id,
            metadata,
            route_id: None,
            upstream_id: None,
            request_body: None,
            response_body: None,
        }
    }

    /// Set the route ID.
    pub fn with_route_id(mut self, route_id: impl Into<String>) -> Self {
        self.route_id = Some(route_id.into());
        self
    }

    /// Set the upstream ID.
    pub fn with_upstream_id(mut self, upstream_id: impl Into<String>) -> Self {
        self.upstream_id = Some(upstream_id.into());
        self
    }
}
