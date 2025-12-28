//! Request processing utilities for Sentinel proxy
//!
//! This module provides helpers for extracting and processing request
//! information from Pingora sessions.

use crate::routing::RequestInfo;
use pingora::proxy::Session;
use std::collections::HashMap;

/// Extract request info from a Pingora session
///
/// Builds a `RequestInfo` struct from the session's request headers,
/// suitable for route matching and processing.
pub fn extract_request_info(session: &Session) -> RequestInfo {
    let req_header = session.req_header();

    let mut headers = HashMap::new();
    for (name, value) in req_header.headers.iter() {
        if let Ok(value_str) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), value_str.to_string());
        }
    }

    let host = headers.get("host").cloned().unwrap_or_default();
    let path = req_header.uri.path().to_string();

    RequestInfo {
        method: req_header.method.as_str().to_string(),
        path: path.clone(),
        host,
        headers,
        query_params: RequestInfo::parse_query_params(&path),
    }
}

/// Extract correlation ID from request headers
///
/// Looks for an existing correlation ID in the request headers,
/// or generates a new one if not present.
pub fn get_or_create_correlation_id(session: &Session) -> String {
    let req_header = session.req_header();

    // Check for existing correlation ID headers (in order of preference)
    let correlation_headers = ["x-correlation-id", "x-request-id", "x-trace-id"];

    for header_name in &correlation_headers {
        if let Some(value) = req_header.headers.get(*header_name) {
            if let Ok(id) = value.to_str() {
                return id.to_string();
            }
        }
    }

    // Generate new correlation ID
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    // Tests would require mocking Pingora session
}
