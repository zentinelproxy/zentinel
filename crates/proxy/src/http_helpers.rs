//! HTTP request and response helpers for Sentinel proxy
//!
//! This module provides utilities for:
//! - Extracting request information from Pingora sessions
//! - Writing HTTP responses to Pingora sessions
//! - Trace ID extraction from headers
//!
//! These helpers reduce boilerplate in the main proxy logic and ensure
//! consistent handling of HTTP operations.

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt, Full};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::Session;
use std::collections::HashMap;

use crate::routing::RequestInfo;
use crate::trace_id::{generate_for_format, TraceIdFormat};

// ============================================================================
// Request Helpers
// ============================================================================

/// Owned request information for external use (non-hot-path)
///
/// This struct owns its data and is used when lifetime management of
/// `RequestInfo<'a>` is impractical (e.g., storing beyond request scope).
#[derive(Debug, Clone)]
pub struct OwnedRequestInfo {
    pub method: String,
    pub path: String,
    pub host: String,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
}

/// Extract request info from a Pingora session
///
/// Builds an `OwnedRequestInfo` struct from the session's request headers.
/// This function allocates all fields.
///
/// For the hot path, use `RequestInfo::new()` with
/// `with_headers()`/`with_query_params()` only when needed.
///
/// # Example
///
/// ```ignore
/// let request_info = extract_request_info(session);
/// ```
pub fn extract_request_info(session: &Session) -> OwnedRequestInfo {
    let req_header = session.req_header();

    let headers = RequestInfo::build_headers(req_header.headers.iter());
    let host = headers.get("host").cloned().unwrap_or_default();
    let path = req_header.uri.path().to_string();
    let method = req_header.method.as_str().to_string();

    OwnedRequestInfo {
        method,
        path: path.clone(),
        host,
        headers,
        query_params: RequestInfo::parse_query_params(&path),
    }
}

/// Extract or generate a trace ID from request headers
///
/// Looks for existing trace ID headers in order of preference:
/// 1. `X-Trace-Id`
/// 2. `X-Correlation-Id`
/// 3. `X-Request-Id`
///
/// If none are found, generates a new TinyFlake trace ID (11 chars).
/// See [`crate::trace_id`] module for TinyFlake format details.
///
/// # Example
///
/// ```ignore
/// let trace_id = get_or_create_trace_id(session, TraceIdFormat::TinyFlake);
/// tracing::info!(trace_id = %trace_id, "Processing request");
/// ```
pub fn get_or_create_trace_id(session: &Session, format: TraceIdFormat) -> String {
    let req_header = session.req_header();

    // Check for existing trace ID headers (in order of preference)
    const TRACE_HEADERS: [&str; 3] = ["x-trace-id", "x-correlation-id", "x-request-id"];

    for header_name in &TRACE_HEADERS {
        if let Some(value) = req_header.headers.get(*header_name) {
            if let Ok(id) = value.to_str() {
                if !id.is_empty() {
                    return id.to_string();
                }
            }
        }
    }

    // Generate new trace ID using configured format
    generate_for_format(format)
}

/// Extract or generate a trace ID (convenience function using TinyFlake default)
///
/// This is a convenience wrapper around [`get_or_create_trace_id`] that uses
/// the default TinyFlake format.
#[inline]
pub fn get_or_create_trace_id_default(session: &Session) -> String {
    get_or_create_trace_id(session, TraceIdFormat::default())
}

// ============================================================================
// Response Helpers
// ============================================================================

/// Write an HTTP response to a Pingora session
///
/// Handles the conversion from `http::Response<Full<Bytes>>` to Pingora's
/// format and writes it to the session.
///
/// # Arguments
///
/// * `session` - The Pingora session to write to
/// * `response` - The HTTP response to write
/// * `keepalive_secs` - Keepalive timeout in seconds (None = disable keepalive)
///
/// # Returns
///
/// Returns `Ok(())` on success or an error if writing fails.
///
/// # Example
///
/// ```ignore
/// let response = Response::builder()
///     .status(200)
///     .body(Full::new(Bytes::from("OK")))?;
/// write_response(session, response, Some(60)).await?;
/// ```
pub async fn write_response(
    session: &mut Session,
    response: Response<Full<Bytes>>,
    keepalive_secs: Option<u64>,
) -> Result<(), Box<Error>> {
    let status = response.status().as_u16();

    // Collect headers to owned strings to avoid lifetime issues
    let headers_owned: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Extract body bytes
    let full_body = response.into_body();
    let body_bytes: Bytes = BodyExt::collect(full_body)
        .await
        .map(|collected| collected.to_bytes())
        .unwrap_or_default();

    // Build Pingora response header
    let mut resp_header = ResponseHeader::build(status, None)?;
    for (key, value) in headers_owned {
        resp_header.insert_header(key, &value)?;
    }

    // Write response to session
    session.set_keepalive(keepalive_secs);
    session
        .write_response_header(Box::new(resp_header), false)
        .await?;
    session.write_response_body(Some(body_bytes), true).await?;

    Ok(())
}

/// Write an error response to a Pingora session
///
/// Convenience wrapper for error responses with status code, body, and content type.
///
/// # Arguments
///
/// * `session` - The Pingora session to write to
/// * `status` - HTTP status code
/// * `body` - Response body as string
/// * `content_type` - Content-Type header value
pub async fn write_error(
    session: &mut Session,
    status: u16,
    body: &str,
    content_type: &str,
) -> Result<(), Box<Error>> {
    let mut resp_header = ResponseHeader::build(status, None)?;
    resp_header.insert_header("Content-Type", content_type)?;
    resp_header.insert_header("Content-Length", body.len().to_string())?;

    session.set_keepalive(None);
    session
        .write_response_header(Box::new(resp_header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
        .await?;

    Ok(())
}

/// Write a plain text error response
///
/// Shorthand for `write_error` with `text/plain; charset=utf-8` content type.
pub async fn write_text_error(
    session: &mut Session,
    status: u16,
    message: &str,
) -> Result<(), Box<Error>> {
    write_error(session, status, message, "text/plain; charset=utf-8").await
}

/// Write a JSON error response
///
/// Creates a JSON object with `error` and optional `message` fields.
///
/// # Example
///
/// ```ignore
/// // Produces: {"error":"not_found","message":"Resource does not exist"}
/// write_json_error(session, 404, "not_found", Some("Resource does not exist")).await?;
/// ```
pub async fn write_json_error(
    session: &mut Session,
    status: u16,
    error: &str,
    message: Option<&str>,
) -> Result<(), Box<Error>> {
    let body = match message {
        Some(msg) => format!(r#"{{"error":"{}","message":"{}"}}"#, error, msg),
        None => format!(r#"{{"error":"{}"}}"#, error),
    };
    write_error(session, status, &body, "application/json").await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // Trace ID generation tests are in crate::trace_id module.
    // Integration tests for get_or_create_trace_id require mocking Pingora session.
    // See crates/proxy/tests/ for integration test examples.
}
