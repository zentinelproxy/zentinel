//! WebAssembly Component Model bindings for Sentinel agents.
//!
//! This module generates type-safe bindings from the WIT interface definition
//! using Wasmtime's `bindgen!` macro. Agents implementing the `sentinel:agent`
//! world can be instantiated and called through these bindings.

use wasmtime::component::bindgen;

// Generate bindings from the WIT file
// This creates:
// - `Agent` type that can be instantiated from a Component
// - Type definitions for all WIT types (RequestMetadata, Decision, etc.)
// - Methods to call the exported functions
bindgen!({
    path: "wit/sentinel-agent.wit",
    world: "agent",
});

// Re-export the generated types for use in host.rs
// Note: The types module path is sentinel::agent::types
pub use sentinel::agent::types::{
    AgentInfo, AgentResponse, AuditMetadata, BlockParams, Decision, HeaderOp, RedirectParams,
    RequestMetadata,
};

// Re-export handler types (includes Header)
pub use exports::sentinel::agent::handler::{Guest as Handler, Header};

// Re-export lifecycle interface
pub use exports::sentinel::agent::lifecycle::Guest as Lifecycle;

/// Convert internal RequestMetadata to WIT RequestMetadata
pub fn request_metadata_to_wit(meta: &sentinel_agent_protocol::RequestMetadata) -> RequestMetadata {
    // Parse timestamp string to milliseconds
    let timestamp_ms = chrono::DateTime::parse_from_rfc3339(&meta.timestamp)
        .map(|dt| dt.timestamp_millis() as u64)
        .unwrap_or_else(|_| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        });

    RequestMetadata {
        correlation_id: meta.correlation_id.clone(),
        request_id: meta.request_id.clone(),
        client_ip: meta.client_ip.clone(),
        client_port: meta.client_port,
        server_name: meta.server_name.clone(),
        protocol: meta.protocol.clone(),
        tls_version: meta.tls_version.clone(),
        route_id: meta.route_id.clone(),
        upstream_id: meta.upstream_id.clone(),
        timestamp_ms,
        traceparent: meta.traceparent.clone(),
    }
}

/// Convert WIT AgentResponse to internal AgentResponse
pub fn agent_response_from_wit(resp: AgentResponse) -> sentinel_agent_protocol::AgentResponse {
    // Start with the appropriate decision
    let mut response = match resp.decision {
        Decision::Allow => sentinel_agent_protocol::AgentResponse::default_allow(),
        Decision::Block(params) => {
            let mut r = sentinel_agent_protocol::AgentResponse::block(params.status, params.body);
            // Add block headers if present
            for h in params.headers {
                r.response_headers
                    .push(sentinel_agent_protocol::HeaderOp::Set {
                        name: h.name,
                        value: h.value,
                    });
            }
            r
        }
        Decision::Redirect(params) => {
            sentinel_agent_protocol::AgentResponse::redirect(params.url, params.status)
        }
    };

    // Apply request header modifications
    for op in resp.request_headers {
        let header_op = match op {
            HeaderOp::Set(h) => sentinel_agent_protocol::HeaderOp::Set {
                name: h.name,
                value: h.value,
            },
            HeaderOp::Add(h) => sentinel_agent_protocol::HeaderOp::Add {
                name: h.name,
                value: h.value,
            },
            HeaderOp::Remove(name) => sentinel_agent_protocol::HeaderOp::Remove { name },
        };
        response.request_headers.push(header_op);
    }

    // Apply response header modifications
    for op in resp.response_headers {
        let header_op = match op {
            HeaderOp::Set(h) => sentinel_agent_protocol::HeaderOp::Set {
                name: h.name,
                value: h.value,
            },
            HeaderOp::Add(h) => sentinel_agent_protocol::HeaderOp::Add {
                name: h.name,
                value: h.value,
            },
            HeaderOp::Remove(name) => sentinel_agent_protocol::HeaderOp::Remove { name },
        };
        response.response_headers.push(header_op);
    }

    // Set audit metadata
    response.audit = sentinel_agent_protocol::AuditMetadata {
        tags: resp.audit.tags,
        rule_ids: resp.audit.rule_ids,
        confidence: resp.audit.confidence,
        ..Default::default()
    };

    // Set needs_more flag
    response.needs_more = resp.needs_more;

    response
}

/// Convert internal headers to WIT Header format
pub fn headers_to_wit(headers: &std::collections::HashMap<String, Vec<String>>) -> Vec<Header> {
    headers
        .iter()
        .flat_map(|(name, values)| {
            values.iter().map(move |value| Header {
                name: name.clone(),
                value: value.clone(),
            })
        })
        .collect()
}

/// Convert WIT AgentInfo to internal WasmAgentInfo
pub fn agent_info_from_wit(info: AgentInfo) -> super::host::WasmAgentInfo {
    super::host::WasmAgentInfo {
        agent_id: info.agent_id,
        name: info.name,
        version: info.version,
        supported_events: info.supported_events,
        max_body_size: info.max_body_size,
        supports_streaming: info.supports_streaming,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_headers_to_wit() {
        let mut headers = HashMap::new();
        headers.insert(
            "content-type".to_string(),
            vec!["application/json".to_string()],
        );
        headers.insert(
            "accept".to_string(),
            vec!["text/html".to_string(), "application/json".to_string()],
        );

        let wit_headers = headers_to_wit(&headers);

        // Should have 3 headers total (1 content-type + 2 accept)
        assert_eq!(wit_headers.len(), 3);
    }

    #[test]
    fn test_allow_decision_conversion() {
        let wit_response = AgentResponse {
            decision: Decision::Allow,
            request_headers: vec![],
            response_headers: vec![],
            audit: AuditMetadata {
                tags: vec![],
                rule_ids: vec![],
                confidence: None,
                reason_codes: vec![],
            },
            needs_more: false,
        };

        let internal = agent_response_from_wit(wit_response);
        assert!(matches!(
            internal.decision,
            sentinel_agent_protocol::Decision::Allow
        ));
    }

    #[test]
    fn test_block_decision_conversion() {
        let wit_response = AgentResponse {
            decision: Decision::Block(BlockParams {
                status: 403,
                body: Some("Forbidden".to_string()),
                headers: vec![Header {
                    name: "X-Blocked-By".to_string(),
                    value: "wasm-agent".to_string(),
                }],
            }),
            request_headers: vec![],
            response_headers: vec![],
            audit: AuditMetadata {
                tags: vec!["security".to_string()],
                rule_ids: vec!["RULE-001".to_string()],
                confidence: Some(0.95),
                reason_codes: vec![],
            },
            needs_more: false,
        };

        let internal = agent_response_from_wit(wit_response);
        match &internal.decision {
            sentinel_agent_protocol::Decision::Block { status, body, .. } => {
                assert_eq!(*status, 403);
                assert_eq!(body.as_deref(), Some("Forbidden"));
            }
            _ => panic!("Expected Block decision"),
        }
        // Check audit metadata
        assert_eq!(internal.audit.tags, vec!["security"]);
        assert_eq!(internal.audit.rule_ids, vec!["RULE-001"]);
        assert_eq!(internal.audit.confidence, Some(0.95));
    }

    #[test]
    fn test_header_op_conversion() {
        let wit_response = AgentResponse {
            decision: Decision::Allow,
            request_headers: vec![
                HeaderOp::Set(Header {
                    name: "X-Custom".to_string(),
                    value: "value1".to_string(),
                }),
                HeaderOp::Add(Header {
                    name: "X-Multi".to_string(),
                    value: "value2".to_string(),
                }),
                HeaderOp::Remove("X-Remove".to_string()),
            ],
            response_headers: vec![],
            audit: AuditMetadata {
                tags: vec![],
                rule_ids: vec![],
                confidence: None,
                reason_codes: vec![],
            },
            needs_more: false,
        };

        let internal = agent_response_from_wit(wit_response);
        assert_eq!(internal.request_headers.len(), 3);

        // Verify each header operation type
        assert!(matches!(
            &internal.request_headers[0],
            sentinel_agent_protocol::HeaderOp::Set { name, value }
            if name == "X-Custom" && value == "value1"
        ));
        assert!(matches!(
            &internal.request_headers[1],
            sentinel_agent_protocol::HeaderOp::Add { name, value }
            if name == "X-Multi" && value == "value2"
        ));
        assert!(matches!(
            &internal.request_headers[2],
            sentinel_agent_protocol::HeaderOp::Remove { name }
            if name == "X-Remove"
        ));
    }
}
