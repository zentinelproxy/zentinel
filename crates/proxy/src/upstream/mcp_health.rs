//! MCP-specific health check for Model Context Protocol upstreams.
//!
//! A TCP check proves a socket is open. An HTTP check proves something answered
//! 200. Neither says the thing behind it still speaks MCP, and many MCP servers
//! expose no `/health` at all -- so for a route whose whole purpose is calling
//! tools, the usual checks confirm the least interesting property available.
//!
//! This one speaks the protocol instead. It sends `initialize`, which is the
//! one method a server must answer without an established session, and treats
//! a JSON-RPC result carrying a `protocolVersion` as proof of life. Given
//! `expected-tools` it goes further and asks `tools/list`, so a server that is
//! up but has lost the backend behind its tools is marked unhealthy rather than
//! left in rotation to fail real calls.
//!
//! # Example
//!
//! ```kdl
//! upstream "mcp-pool" {
//!     target "mcp-1:8090" weight=1
//!     target "mcp-2:8090" weight=1
//!     health-check {
//!         type "mcp" {
//!             path "/mcp"
//!             expected-tools "search_docs" "get_weather"
//!         }
//!         interval-secs 30
//!     }
//! }
//! ```

use async_trait::async_trait;
use pingora_core::{Error, ErrorType::CustomCode, Result};
use pingora_load_balancing::health_check::HealthCheck as PingoraHealthCheck;
use pingora_load_balancing::Backend;
use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, trace};

/// Protocol revision the probe announces.
///
/// Kept equal to the first revision the proxy's own policy will accept, so a
/// server that refuses the probe's version would also have refused the traffic
/// this check exists to protect.
pub const PROBE_PROTOCOL_VERSION: &str = "2026-07-28";

/// Largest response the probe will read. A `tools/list` from a server with a
/// very large surface can be sizeable, and truncating it would look like a
/// missing tool.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Health check that speaks MCP to the backend.
pub struct McpHealthCheck {
    /// Path to POST to.
    path: String,
    /// Tools that must be present for the backend to be healthy. Empty means
    /// the check stops after `initialize`.
    expected_tools: Vec<String>,
    /// Connection and response timeout, applied per request.
    timeout: Duration,
    /// Consecutive successes needed to mark healthy.
    pub consecutive_success: usize,
    /// Consecutive failures needed to mark unhealthy.
    pub consecutive_failure: usize,
}

impl McpHealthCheck {
    /// Create a new MCP health check.
    pub fn new(path: String, expected_tools: Vec<String>, timeout: Duration) -> Self {
        Self {
            path: if path.is_empty() {
                "/".to_string()
            } else {
                path
            },
            expected_tools,
            timeout,
            consecutive_success: 1,
            consecutive_failure: 1,
        }
    }

    /// Run the probe against one address.
    ///
    /// Public because the proxy carries two health-check subsystems -- this
    /// one implements Pingora's trait, `crate::health` implements its own --
    /// and two divergent implementations of the same protocol probe is exactly
    /// the defect shape that keeps a feature working in one place and silently
    /// not in the other. Both call this.
    pub async fn check_backend(&self, addr: &str) -> std::result::Result<(), String> {
        // `initialize` first. It is the only method guaranteed to be answerable
        // without an established session, so it is the only safe liveness probe
        // against a server whose session policy is unknown.
        let (init, session) = self
            .request(addr, r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"PROTOCOL","capabilities":{},"clientInfo":{"name":"zentinel-healthcheck","version":"1.0"}}}"#
                .replace("PROTOCOL", PROBE_PROTOCOL_VERSION)
                .as_str(), None)
            .await?;

        let doc = parse_jsonrpc(&init)?;
        result_of(&doc)?
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| "initialize result carries no protocolVersion".to_string())?;

        if self.expected_tools.is_empty() {
            trace!(addr = %addr, path = %self.path, "MCP health check passed (initialize only)");
            return Ok(());
        }

        // The session id, when the server issued one. A server that requires a
        // session and was not given one answers with an error, which surfaces
        // as an unhealthy backend and the reason why.
        let (listing, _) = self
            .request(
                addr,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
                session.as_deref(),
            )
            .await?;

        let doc = parse_jsonrpc(&listing)?;
        let tools = result_of(&doc)?
            .get("tools")
            .and_then(Value::as_array)
            .ok_or_else(|| "tools/list result carries no tools array".to_string())?;

        let available: Vec<&str> = tools
            .iter()
            .filter_map(|t| t.get("name").and_then(Value::as_str))
            .collect();

        let missing: Vec<&str> = self
            .expected_tools
            .iter()
            .map(String::as_str)
            .filter(|want| !available.contains(want))
            .collect();

        if !missing.is_empty() {
            return Err(format!(
                "missing tools: {}. Available: {:?}",
                missing.join(", "),
                available
            ));
        }

        trace!(
            addr = %addr,
            path = %self.path,
            tool_count = available.len(),
            "MCP health check passed"
        );
        Ok(())
    }

    /// POST one JSON-RPC message and return the body plus any session id.
    async fn request(
        &self,
        addr: &str,
        body: &str,
        session: Option<&str>,
    ) -> std::result::Result<(String, Option<String>), String> {
        let socket_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid address '{addr}': {e}"))?;

        let mut stream = tokio::time::timeout(self.timeout, TcpStream::connect(socket_addr))
            .await
            .map_err(|_| format!("connection timeout after {:?}", self.timeout))?
            .map_err(|e| format!("connection failed: {e}"))?;

        let session_header = session
            .map(|s| format!("Mcp-Session-Id: {s}\r\n"))
            .unwrap_or_default();

        // Both framings are advertised because a Streamable HTTP server may
        // answer either, and a probe that accepted only one would report a
        // conforming server as unhealthy.
        let request = format!(
            "POST {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: Zentinel-HealthCheck/1.0\r\n\
             Content-Type: application/json\r\n\
             Accept: application/json, text/event-stream\r\n\
             MCP-Protocol-Version: {}\r\n\
             {}\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            self.path,
            addr,
            PROBE_PROTOCOL_VERSION,
            session_header,
            body.len(),
            body
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("failed to send request: {e}"))?;

        // Read until the message is complete by its own framing, not until
        // the peer closes.
        //
        // `Connection: close` asks the server to close, but a server may keep
        // the connection open anyway -- and reading to EOF against one that
        // does means every probe blocks for the full timeout and the backend
        // is reported unhealthy while serving perfectly well. Length and
        // chunked framing both say where the body ends; only a response with
        // neither needs EOF to delimit it.
        let mut response = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(self.timeout, stream.read(&mut buf))
                .await
                .map_err(|_| "response timeout".to_string())?
                .map_err(|e| format!("failed to read response: {e}"))?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&buf[..n]);
            if response.len() >= MAX_RESPONSE_BYTES || is_complete(&response) {
                break;
            }
        }

        if response.is_empty() {
            return Err("empty response".to_string());
        }

        let text = String::from_utf8_lossy(&response).into_owned();
        let status = status_code(&text)?;
        if status != 200 {
            return Err(format!("HTTP {status} (expected 200)"));
        }

        let session_id = header_value(&text, "mcp-session-id");
        let body = body_of(&response)?;
        Ok((body, session_id))
    }
}

/// Whether `buf` holds a complete HTTP response, by the response's own framing.
///
/// Returns false while the headers are still arriving, and for a response that
/// announces neither a length nor chunked encoding -- there, only the peer
/// closing marks the end.
fn is_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let Some(head_end) = text.find("\r\n\r\n") else {
        return false;
    };
    let head = &text[..head_end];
    let body = &text[head_end + 4..];

    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();

        if name == "content-length" {
            return match value.parse::<usize>() {
                Ok(len) => body.len() >= len,
                Err(_) => false,
            };
        }
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            return body.ends_with("0\r\n\r\n") || body.ends_with("0\r\n");
        }
    }

    false
}

/// The status code from a response's first line.
fn status_code(response: &str) -> std::result::Result<u16, String> {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "failed to parse HTTP status".to_string())
}

/// A response header's value, matched case-insensitively.
fn header_value(response: &str, name: &str) -> Option<String> {
    let head = response.split("\r\n\r\n").next()?;
    head.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// The body, with chunked framing and SSE framing removed.
///
/// The probe sends `Connection: close` and HTTP/1.1, so a server may still
/// answer chunked; and a Streamable HTTP server may wrap the response in an
/// SSE event. Both are unwrapped here so the caller sees JSON either way.
///
/// Framing is read from the raw bytes: chunk sizes count bytes, and a
/// multi-byte character may be split across two chunks. The body becomes text
/// only once it has been reassembled.
fn body_of(response: &[u8]) -> std::result::Result<String, String> {
    let head_end =
        find(response, b"\r\n\r\n").ok_or_else(|| "could not find response body".to_string())?;
    let body = &response[head_end + 4..];

    let head = String::from_utf8_lossy(&response[..head_end]);
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.contains("chunked"));

    let unchunked = if chunked {
        String::from_utf8_lossy(&dechunk(body)).into_owned()
    } else {
        String::from_utf8_lossy(body).into_owned()
    };

    // SSE: the JSON-RPC response is the payload of a `data:` field.
    if unchunked.contains("data:") {
        let joined: String = unchunked
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|l| l.strip_prefix(' ').unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n");
        if !joined.trim().is_empty() {
            return Ok(joined);
        }
    }

    Ok(unchunked)
}

/// The offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Reassemble a chunked body.
///
/// A chunk that is cut short, or a size line that is not a hexadecimal number,
/// ends the body there.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(line_end) = find(rest, b"\r\n") {
        let (size_line, tail) = (&rest[..line_end], &rest[line_end + 2..]);
        let size = std::str::from_utf8(size_line).ok().and_then(|line| {
            usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16).ok()
        });
        let Some(size @ 1..) = size else {
            break;
        };
        let Some(chunk) = tail.get(..size) else {
            out.extend_from_slice(tail);
            break;
        };
        out.extend_from_slice(chunk);
        let after = &tail[size..];
        rest = after.strip_prefix(b"\r\n").unwrap_or(after);
    }
    out
}

/// Parse a JSON-RPC document.
fn parse_jsonrpc(body: &str) -> std::result::Result<Value, String> {
    serde_json::from_str(body.trim())
        .map_err(|e| format!("response is not valid JSON ({e}): {}", preview(body)))
}

/// The `result` object, or the server's error rendered for an operator.
fn result_of(doc: &Value) -> std::result::Result<&Value, String> {
    if let Some(error) = doc.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("unspecified");
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        return Err(format!("server returned JSON-RPC error {code}: {message}"));
    }
    doc.get("result")
        .ok_or_else(|| "response carries neither result nor error".to_string())
}

fn preview(body: &str) -> String {
    let trimmed = body.trim();
    let end = trimmed
        .char_indices()
        .nth(200)
        .map(|(i, _)| i)
        .unwrap_or(trimmed.len());
    trimmed[..end].to_string()
}

#[async_trait]
impl PingoraHealthCheck for McpHealthCheck {
    async fn check(&self, backend: &Backend) -> Result<()> {
        let addr = backend.addr.to_string();

        match self.check_backend(&addr).await {
            Ok(()) => Ok(()),
            Err(error) => {
                debug!(
                    addr = %addr,
                    path = %self.path,
                    expected_tools = ?self.expected_tools,
                    error = %error,
                    "MCP health check failed"
                );
                Err(Error::explain(CustomCode("mcp health check", 1), error))
            }
        }
    }

    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn check(expected: &[&str]) -> McpHealthCheck {
        McpHealthCheck::new(
            "/mcp".to_string(),
            expected.iter().map(|s| s.to_string()).collect(),
            Duration::from_secs(2),
        )
    }

    /// Serve canned responses in order, one per connection, and return the
    /// address to probe.
    async fn serve(responses: Vec<String>) -> String {
        serve_bytes(responses.into_iter().map(String::into_bytes).collect()).await
    }

    /// As [`serve`], for responses that are not necessarily valid UTF-8.
    async fn serve_bytes(responses: Vec<Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();

        tokio::spawn(async move {
            for body in responses {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                // Read the request head so the client's write completes.
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            }
        });

        addr
    }

    fn http(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
    }

    const INIT_OK: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","capabilities":{},"serverInfo":{"name":"t","version":"1"}}}"#;

    fn listing(names: &[&str]) -> String {
        let entries: Vec<String> = names
            .iter()
            .map(|n| format!(r#"{{"name":"{n}"}}"#))
            .collect();
        format!(
            r#"{{"jsonrpc":"2.0","id":2,"result":{{"tools":[{}]}}}}"#,
            entries.join(",")
        )
    }

    // === The probe against a real socket ===

    #[tokio::test]
    async fn a_server_that_initializes_is_healthy() {
        let addr = serve(vec![http(INIT_OK)]).await;
        assert_eq!(check(&[]).check_backend(&addr).await, Ok(()));
    }

    /// The point of the check: listening is not the same as working. A server
    /// answering `initialize` but no longer offering the tools a route depends
    /// on is unhealthy, and a TCP or plain HTTP check would call it fine.
    #[tokio::test]
    async fn a_server_missing_an_expected_tool_is_unhealthy() {
        let addr = serve(vec![http(INIT_OK), http(&listing(&["search_docs"]))]).await;
        let err = check(&["search_docs", "get_weather"])
            .check_backend(&addr)
            .await
            .expect_err("should be unhealthy");
        assert!(err.contains("missing tools: get_weather"), "{err}");
    }

    #[tokio::test]
    async fn a_server_offering_every_expected_tool_is_healthy() {
        let addr = serve(vec![
            http(INIT_OK),
            http(&listing(&["search_docs", "get_weather", "extra"])),
        ])
        .await;
        assert_eq!(
            check(&["search_docs", "get_weather"])
                .check_backend(&addr)
                .await,
            Ok(())
        );
    }

    /// A JSON-RPC error is a 200 at the HTTP layer. Reporting healthy here is
    /// exactly the failure this check exists to catch.
    #[tokio::test]
    async fn a_jsonrpc_error_is_unhealthy_despite_http_200() {
        let body =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"session required"}}"#;
        let addr = serve(vec![http(body)]).await;
        let err = check(&[])
            .check_backend(&addr)
            .await
            .expect_err("should be unhealthy");
        assert!(err.contains("-32600"), "{err}");
        assert!(err.contains("session required"), "{err}");
    }

    #[tokio::test]
    async fn a_non_200_is_unhealthy() {
        let addr = serve(vec![
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".to_string(),
        ])
        .await;
        let err = check(&[])
            .check_backend(&addr)
            .await
            .expect_err("should be unhealthy");
        assert!(err.contains("HTTP 503"), "{err}");
    }

    /// A server may answer Streamable HTTP with an event stream. Reading only
    /// `application/json` would report a conforming server as unhealthy.
    #[tokio::test]
    async fn an_event_stream_response_is_understood() {
        let framed = format!("event: message\ndata: {INIT_OK}\n\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            framed.len(),
            framed
        );
        let addr = serve(vec![response]).await;
        assert_eq!(check(&[]).check_backend(&addr).await, Ok(()));
    }

    #[tokio::test]
    async fn a_chunked_response_is_reassembled() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            INIT_OK.len(),
            INIT_OK
        );
        let addr = serve(vec![response]).await;
        assert_eq!(check(&[]).check_backend(&addr).await, Ok(()));
    }

    #[tokio::test]
    async fn a_backend_that_is_not_listening_is_unhealthy() {
        // Port 1 on loopback, reserved and not bound.
        let err = check(&[])
            .check_backend("127.0.0.1:1")
            .await
            .expect_err("should be unhealthy");
        assert!(
            err.contains("connection failed") || err.contains("timeout"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_is_unhealthy() {
        let addr = serve(vec![http("<html>not mcp</html>")]).await;
        let err = check(&[])
            .check_backend(&addr)
            .await
            .expect_err("should be unhealthy");
        assert!(err.contains("not valid JSON"), "{err}");
    }

    // === Response parsing ===

    #[test]
    fn a_session_id_is_read_case_insensitively() {
        let r = "HTTP/1.1 200 OK\r\nMCP-Session-Id: abc123\r\n\r\n{}";
        assert_eq!(header_value(r, "mcp-session-id").as_deref(), Some("abc123"));
        assert_eq!(header_value(r, "nope"), None);
    }

    #[test]
    fn chunked_bodies_reassemble() {
        assert_eq!(dechunk(b"5\r\nhello\r\n0\r\n\r\n"), b"hello");
        assert_eq!(dechunk(b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n"), b"foobar");
        assert_eq!(dechunk(b"3;name=value\r\nfoo\r\n0\r\n\r\n"), b"foo");
    }

    #[test]
    fn a_result_is_distinguished_from_an_error() {
        let ok: Value = serde_json::from_str(INIT_OK).expect("json");
        assert!(result_of(&ok).is_ok());

        let bad: Value =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}"#)
                .expect("json");
        assert!(result_of(&bad).is_err());

        let neither: Value = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).expect("json");
        assert!(result_of(&neither).is_err());
    }

    /// A multi-byte character straddling the preview boundary must not panic.
    #[test]
    fn the_error_preview_does_not_split_a_character() {
        let body = "天".repeat(300);
        assert!(!preview(&body).is_empty());
    }

    // === Chunk framing is read from bytes ===

    fn chunked_response(body: &[u8]) -> Vec<u8> {
        [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
            body,
        ]
        .concat()
    }

    #[test]
    fn a_character_split_across_chunks_is_restored() {
        // The two bytes of "\u{e9}" (C3 A9) arrive in separate chunks.
        let response = chunked_response(b"4\r\ncaf\xC3\r\n1\r\n\xA9\r\n0\r\n\r\n");
        assert_eq!(body_of(&response), Ok("caf\u{e9}".to_string()));
    }

    #[test]
    fn a_chunk_holding_whole_multi_byte_characters_reassembles() {
        // "caf\u{e9}" is five bytes, so the chunk size is 5.
        assert_eq!(
            body_of(&chunked_response("5\r\ncaf\u{e9}\r\n0\r\n\r\n".as_bytes())),
            Ok("caf\u{e9}".to_string())
        );
        assert_eq!(
            body_of(&chunked_response(
                "2\r\n\u{e9}\r\n3\r\nabc\r\n0\r\n\r\n".as_bytes()
            )),
            Ok("\u{e9}abc".to_string())
        );
    }

    #[test]
    fn a_chunk_size_that_does_not_match_the_body_does_not_panic() {
        // Larger than what follows: what is there is kept.
        assert_eq!(
            body_of(&chunked_response(b"ff\r\nabc")),
            Ok("abc".to_string())
        );
        // Not a number, or too large for a number: the body ends there.
        assert_eq!(
            body_of(&chunked_response(b"zz\r\nabc\r\n0\r\n\r\n")),
            Ok(String::new())
        );
        assert_eq!(
            body_of(&chunked_response(b"ffffffffffffffffffff\r\nabc")),
            Ok(String::new())
        );
        assert_eq!(body_of(&chunked_response(b"\r\nabc")), Ok(String::new()));
        // A size that stops after the first byte of "\u{e9}" cuts there.
        assert_eq!(
            body_of(&chunked_response(b"3\r\nabc\r\n1\r\n\xC3\xA9\r\n0\r\n\r\n")),
            Ok("abc\u{fffd}".to_string())
        );
    }

    #[tokio::test]
    async fn a_probe_answered_with_a_character_split_across_chunks_is_healthy() {
        let init = INIT_OK.replace(r#""name":"t""#, "\"name\":\"caf\u{e9}\"");
        let bytes = init.as_bytes();
        let split = init.find('\u{e9}').expect("character") + 1;
        let (first, second) = bytes.split_at(split);

        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(format!("{:x}\r\n", first.len()).as_bytes());
        response.extend_from_slice(first);
        response.extend_from_slice(format!("\r\n{:x}\r\n", second.len()).as_bytes());
        response.extend_from_slice(second);
        response.extend_from_slice(b"\r\n0\r\n\r\n");

        let addr = serve_bytes(vec![response]).await;
        assert_eq!(check(&[]).check_backend(&addr).await, Ok(()));
    }
}
