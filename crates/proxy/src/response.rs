//! Response writing utilities for Sentinel proxy
//!
//! This module provides helpers for converting and writing HTTP responses
//! to Pingora sessions, reducing boilerplate in the main proxy logic.

use bytes::Bytes;
use http::Response;
use http_body_util::{BodyExt, Full};
use pingora::http::ResponseHeader;
use pingora::prelude::*;
use pingora::proxy::Session;

/// Write an HTTP response to a Pingora session
///
/// This helper handles the conversion from `http::Response<Full<Bytes>>` to
/// Pingora's format and writes it to the session.
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
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
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
/// Convenience wrapper for error responses with status code and body.
pub async fn write_error(
    session: &mut Session,
    status: u16,
    body: &str,
    content_type: &str,
) -> Result<(), Box<Error>> {
    let mut resp_header = ResponseHeader::build(status, None)?;
    resp_header.insert_header("Content-Type", content_type)?;
    resp_header.insert_header("Content-Length", &body.len().to_string())?;

    session.set_keepalive(None);
    session
        .write_response_header(Box::new(resp_header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(body.as_bytes())), true)
        .await?;

    Ok(())
}

/// Write a simple text error response
pub async fn write_text_error(
    session: &mut Session,
    status: u16,
    message: &str,
) -> Result<(), Box<Error>> {
    write_error(session, status, message, "text/plain; charset=utf-8").await
}

/// Write a JSON error response
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

#[cfg(test)]
mod tests {
    // Tests would require mocking Pingora session
}
