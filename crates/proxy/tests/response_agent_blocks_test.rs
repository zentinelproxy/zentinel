//! An agent's decision in the response phase is acted on (#584): a block,
//! and a redirect or a challenge (#588).
//!
//! On the response side the proxy used to apply only the header and body
//! changes an agent returned and ignore its decision: a block on response
//! headers or on the response body let the upstream response through, and so
//! did a fail-closed response-only filter whose agent was down. This runs the
//! real binary against a local backend and an in-test v2 agent and checks
//! what the client receives in each case.
//!
//! Every upstream body carries a marker no one else sends, so a response
//! containing it proves upstream bytes reached the client.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, Decision, EventType, ResponseBodyChunkEvent, ResponseHeadersEvent,
};

/// In every upstream body; never in anything the proxy or the agent sends.
const MARKER: &str = "UPSTREAM-MARKER-584";
/// In the second chunk of `/…/leak`; the agent blocks a body containing it.
const TRIGGER: &str = "SECRET-TRIGGER";
/// In the chunk after the trigger.
const AFTER: &str = "AFTER-THE-BLOCK";
/// In place of [`TRIGGER`] in `/…/leak-redirect` and `/…/cl-redirect`; the
/// agent redirects a body containing it.
const REDIRECT_TRIGGER: &str = "REDIRECT-TRIGGER";
/// Likewise for a challenge.
const CHALLENGE_TRIGGER: &str = "CHALLENGE-TRIGGER";
/// Where the agent redirects to.
const REDIRECT_TO: &str = "https://example.com/moved";

/// The trigger a backend path asks for.
fn trigger_for(request_line: &str) -> &'static str {
    if request_line.contains("redirect") {
        REDIRECT_TRIGGER
    } else if request_line.contains("challenge") {
        CHALLENGE_TRIGGER
    } else {
        TRIGGER
    }
}

/// Two free ports from a small fixed range, so the test stays clear of
/// ports other local services are likely to use.
fn free_ports(range: std::ops::Range<u16>) -> (u16, u16) {
    let mut free = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok());
    (
        free.next().expect("a free port"),
        free.next()
            .unwrap_or_else(|| panic!("two free ports in {range:?}")),
    )
}

/// A backend whose response says what the agent should do with it:
///
/// - `/…/block`, `/…/bare`: an `X-Test-Verdict` header the agent blocks on
///   (with a body of its own, or without);
/// - `/…/leak`: a chunked body in three chunks, the second carrying
///   [`TRIGGER`] and the third [`AFTER`]; `/…/chunked` the same without
///   the trigger;
/// - `/…/cl-leak`: [`TRIGGER`] and [`AFTER`] in a Content-Length body;
/// - `/…/leak-redirect`, `/…/leak-challenge`, `/…/cl-redirect`,
///   `/…/cl-challenge`: the same with [`REDIRECT_TRIGGER`] or
///   [`CHALLENGE_TRIGGER`] in place of [`TRIGGER`];
/// - `/…/hdr-redirect`, `/…/hdr-challenge`, `/…/hdr-auth`: an
///   `X-Test-Verdict` the agent redirects or challenges on;
/// - anything else: a plain 200.
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    line.clear();
                }
                if request_line.contains("/leak") || request_line.contains("/chunked") {
                    let second = if request_line.contains("/leak") {
                        trigger_for(&request_line)
                    } else {
                        "harmless"
                    };
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    );
                    for chunk in [
                        format!("first {MARKER}\n"),
                        format!("second {second}\n"),
                        format!("third {AFTER}\n"),
                    ] {
                        let _ = write!(stream, "{:x}\r\n{chunk}\r\n", chunk.len());
                        let _ = stream.flush();
                        std::thread::sleep(Duration::from_millis(30));
                    }
                    let _ = stream.write_all(b"0\r\n\r\n");
                    return;
                }
                if request_line.contains("/cl-") {
                    let body = format!("{MARKER} {} {AFTER}\n", trigger_for(&request_line));
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    return;
                }
                let verdict = if request_line.contains("/block") {
                    "X-Test-Verdict: block\r\n"
                } else if request_line.contains("/bare") {
                    "X-Test-Verdict: bare\r\n"
                } else if request_line.contains("/hdr-redirect") {
                    "X-Test-Verdict: redirect\r\n"
                } else if request_line.contains("/hdr-challenge") {
                    "X-Test-Verdict: challenge\r\n"
                } else if request_line.contains("/hdr-auth") {
                    "X-Test-Verdict: auth\r\n"
                } else {
                    ""
                };
                let body = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{verdict}Connection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    /// The body as received, still chunk-encoded if it was.
    raw_body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn body(&self) -> String {
        String::from_utf8_lossy(&self.raw_body).into_owned()
    }

    /// Whether the body arrived whole by its own framing: all of its
    /// Content-Length, or the last chunk of a chunked body. A
    /// close-delimited body counts as complete -- a client cannot tell it
    /// from an aborted one.
    fn complete(&self) -> bool {
        if self
            .header("transfer-encoding")
            .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
        {
            return self.raw_body.ends_with(b"0\r\n\r\n");
        }
        match self.header("content-length") {
            Some(len) => self.raw_body.len() == len.parse::<usize>().unwrap(),
            None => true,
        }
    }
}

/// Send a GET over HTTP/1.1 and read until the proxy closes the connection.
fn get(port: u16, path: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    // A reset ends the read with an error; what arrived before it counts.
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let raw_body = raw.get(split + 4..).unwrap_or_default().to_vec();
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Response {
        status,
        headers,
        raw_body,
    }
}

/// Blocks on response headers by the backend's `X-Test-Verdict`, and on a
/// response body containing [`TRIGGER`].
struct ResponseBlocker;

#[async_trait::async_trait]
impl AgentHandlerV2 for ResponseBlocker {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("resp-blocker", "Response Blocker", "0.1.0")
            .with_event(EventType::ResponseHeaders)
            .with_event(EventType::ResponseBodyChunk)
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let verdict = event
            .headers
            .get("x-test-verdict")
            .and_then(|v| v.first())
            .map(String::as_str);
        match verdict {
            Some("block") => {
                let mut response =
                    AgentResponse::block(451, Some("agent response says no".to_string()));
                response.decision = Decision::Block {
                    status: 451,
                    body: Some("agent response says no".to_string()),
                    headers: Some(HashMap::from([(
                        "X-Blocked-By".to_string(),
                        "resp-blocker".to_string(),
                    )])),
                };
                response
            }
            Some("bare") => AgentResponse::block(403, None),
            Some("redirect") => AgentResponse::redirect(REDIRECT_TO.to_string(), 307),
            Some("challenge") => challenge(&[]),
            Some("auth") => challenge(&[("www-authenticate", "Basic realm=\"584\"")]),
            _ => AgentResponse::default_allow(),
        }
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let data = String::from_utf8_lossy(&data);
        if data.contains(REDIRECT_TRIGGER) {
            AgentResponse::redirect(REDIRECT_TO.to_string(), 307)
        } else if data.contains(CHALLENGE_TRIGGER) {
            challenge(&[])
        } else if data.contains(TRIGGER) {
            AgentResponse::block(403, Some("agent body says no".to_string()))
        } else {
            AgentResponse::default_allow()
        }
    }
}

/// A challenge decision with `params`.
fn challenge(params: &[(&str, &str)]) -> AgentResponse {
    let mut response = AgentResponse::default_allow();
    response.decision = Decision::Challenge {
        challenge_type: "captcha".to_string(),
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    };
    response
}

fn config(port: u16, backend: u16, socket: &std::path::Path, dead: &std::path::Path) -> String {
    format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
agents {{
    agent "resp-blocker" type="custom" {{
        unix-socket "{socket}"
        events "response_headers" "response_body"
        timeout-ms 2000
        failure-mode "closed"
    }}
    // The same agent, inspecting no more than 8 bytes of a response body.
    agent "small" type="custom" {{
        unix-socket "{socket}"
        events "response_headers" "response_body"
        timeout-ms 2000
        max-response-body-bytes 8
    }}
    // Unreachable: nothing listens on its socket. Fails open itself.
    agent "dead-open" type="custom" {{
        unix-socket "{dead}"
        events "response_headers"
        timeout-ms 500
        failure-mode "open"
    }}
    // Unreachable as well; fails closed itself.
    agent "dead-closed" type="custom" {{
        unix-socket "{dead}"
        events "response_headers"
        timeout-ms 500
        failure-mode "closed"
    }}
}}
filters {{
    filter "resp-blocker" {{
        type "agent"
        agent "resp-blocker"
        failure-mode "closed"
    }}
    filter "small-closed" {{
        type "agent"
        agent "small"
        failure-mode "closed"
    }}
    filter "small-open" {{
        type "agent"
        agent "small"
        failure-mode "open"
    }}
    filter "dead-closed-filter" {{
        type "agent"
        agent "dead-open"
        failure-mode "closed"
    }}
    filter "dead-open-filter" {{
        type "agent"
        agent "dead-closed"
        failure-mode "open"
    }}
}}
routes {{
    route "paged" {{
        matches {{ path-prefix "/paged" }}
        upstream "backend"
        filters "resp-blocker"
        error-pages {{
            pages {{
                "403" {{ format "json"; message "Custom 403 page"; }}
            }}
        }}
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        filters "resp-blocker"
    }}
    route "small-closed" {{
        matches {{ path-prefix "/small-closed" }}
        upstream "backend"
        filters "small-closed"
    }}
    route "small-open" {{
        matches {{ path-prefix "/small-open" }}
        upstream "backend"
        filters "small-open"
    }}
    route "fail-closed" {{
        matches {{ path-prefix "/fail-closed" }}
        upstream "backend"
        filters "dead-closed-filter"
    }}
    route "fail-open" {{
        matches {{ path-prefix "/fail-open" }}
        upstream "backend"
        filters "dead-open-filter"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
        dead = dead.display(),
    )
}

/// The proxy with the response-blocking agent running, and its port.
struct Setup {
    port: u16,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("resp-blocker.sock");
    let dead = dir.path().join("nobody-listens.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("resp-blocker", socket.clone(), Box::new(ResponseBlocker));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(ports);
    spawn_backend(backend);
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(port, backend, &socket, &dead)).unwrap();
    let proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Wait until the agent is connected and consulted: an allowed response
    // passes, a blocked one does not.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let fine = get(port, "/open/fine");
        if fine.status == 200 && fine.body().contains(MARKER) {
            break;
        }
        assert!(Instant::now() < deadline, "never served: {fine:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// (a) A block on response headers replaces the upstream response with the
/// block response: the agent's status, body and headers, or the route's
/// page for the status. No upstream byte reaches the client.
#[test]
fn a_block_on_response_headers_replaces_the_upstream_response() {
    let setup = setup(19584..19590);
    let port = setup.port;

    for route in ["/paged", "/open"] {
        let resp = get(port, &format!("{route}/block"));
        assert_eq!(resp.status, 451, "{route}: {resp:?}");
        assert_eq!(resp.body(), "agent response says no", "{route}");
        assert_eq!(resp.header("x-blocked-by"), Some("resp-blocker"), "{route}");
        // The upstream's headers are gone with its body.
        assert_eq!(resp.header("x-test-verdict"), None, "{route}");
        assert!(!resp.body().contains(MARKER), "{route}: {resp:?}");
        assert!(resp.complete(), "{route}: {resp:?}");
    }

    // Without a body of its own, the route's page for the status...
    let resp = get(port, "/paged/bare");
    assert_eq!(resp.status, 403, "{resp:?}");
    let page: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
    assert_eq!(page["message"], "Custom 403 page");
    assert!(!resp.body().contains(MARKER));

    // ... and the default refusal where it has none.
    let resp = get(port, "/open/bare");
    assert_eq!(resp.status, 403, "{resp:?}");
    assert!(!resp.body().contains(MARKER), "{resp:?}");
    assert_eq!(resp.header("x-test-verdict"), None);
}

/// (b) A block on the response body usually comes after the status line
/// has gone out: the proxy aborts the response. The client gets an
/// incomplete body and none of the bytes the agent blocked, nor any after
/// them -- the body is withheld until the agent decides, so none at all.
#[test]
fn a_block_on_the_response_body_aborts_the_response() {
    let setup = setup(19590..19596);
    let port = setup.port;

    for path in ["/paged/leak", "/open/leak"] {
        let resp = get(port, path);
        let body = resp.body();
        // The status went out before the body was inspected.
        assert_eq!(resp.status, 200, "{path}: {resp:?}");
        assert!(!body.contains(TRIGGER), "{path}: {resp:?}");
        assert!(!body.contains(AFTER), "{path}: {resp:?}");
        // Every chunk was withheld until the agent decided.
        assert!(!body.contains(MARKER), "{path}: {resp:?}");
        assert_eq!(
            resp.header("transfer-encoding"),
            Some("chunked"),
            "{path}: {resp:?}"
        );
        assert!(
            !resp.complete(),
            "{path}: the abort must be detectable: {resp:?}"
        );
    }

    // A body that arrives with its header is decided on before the header
    // goes out: nothing has been sent, so the block response replaces the
    // whole response, as on response headers. (Should the body come in
    // separately after all, the abort above applies.)
    let resp = get(port, "/open/cl-leak");
    let body = resp.body();
    assert!(!body.contains(MARKER), "{resp:?}");
    assert!(!body.contains(TRIGGER), "{resp:?}");
    assert!(!body.contains(AFTER), "{resp:?}");
    if resp.status == 200 {
        assert!(!resp.complete(), "{resp:?}");
    } else {
        assert_eq!(resp.status, 403, "{resp:?}");
        assert_eq!(body, "agent body says no");
        assert!(resp.complete(), "{resp:?}");
    }

    // A body the agent allows still arrives whole, in one or more chunks
    // upstream. A chunked one used to lose all but its last chunk.
    for path in ["/open/fine", "/open/chunked"] {
        let resp = get(port, path);
        assert_eq!(resp.status, 200, "{path}");
        assert!(resp.complete(), "{path}: {resp:?}");
        let body = resp.body();
        assert!(body.contains(MARKER), "{path}: {resp:?}");
        if path.ends_with("chunked") {
            assert!(body.contains("harmless"), "{path}: {resp:?}");
            assert!(body.contains(AFTER), "{path}: {resp:?}");
        }
    }
}

/// (c) A fail-closed response-only filter whose agent is unavailable
/// answers 503, even though the agent itself would fail open: the filter's
/// failure mode is the route's policy. (d) The other way round, the
/// filter's `open` wins over the agent's `closed`.
#[test]
fn the_filters_failure_mode_decides_on_the_response_path() {
    let setup = setup(19596..19602);
    let port = setup.port;

    let resp = get(port, "/fail-closed/x");
    assert_eq!(resp.status, 503, "{resp:?}");
    assert!(!resp.body().contains(MARKER), "{resp:?}");

    let resp = get(port, "/fail-open/x");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(resp.body().contains(MARKER), "{resp:?}");
}

/// The response body is withheld for the agents only up to the largest of
/// their `max-response-body-bytes`. A body over it is decided on then, by
/// the filter's failure mode: closed refuses it (413, or an aborted
/// response once the status is out), open sends it on uninspected -- whole.
#[test]
fn a_response_body_over_the_agents_limit_follows_the_filter() {
    let setup = setup(19602..19608);
    let port = setup.port;

    let resp = get(port, "/small-closed/chunked");
    assert!(!resp.body().contains(MARKER), "{resp:?}");
    if resp.status == 200 {
        assert!(!resp.complete(), "{resp:?}");
    } else {
        assert_eq!(resp.status, 413, "{resp:?}");
    }

    let resp = get(port, "/small-open/chunked");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(resp.complete(), "{resp:?}");
    let body = resp.body();
    assert!(body.contains(MARKER), "{resp:?}");
    assert!(body.contains("harmless"), "{resp:?}");
    assert!(body.contains(AFTER), "{resp:?}");
}

/// #588: a redirect or a challenge on response headers replaces the
/// upstream response, as a block does, with the response the request phases
/// give it: the redirect with its `Location`, a challenge as 403, or 401
/// with `WWW-Authenticate`. They used to be ignored and the upstream
/// response sent.
#[test]
fn a_redirect_or_challenge_on_response_headers_replaces_the_upstream_response() {
    let setup = setup(19880..19886);
    let port = setup.port;

    let resp = get(port, "/open/hdr-redirect");
    assert_eq!(resp.status, 307, "{resp:?}");
    assert_eq!(resp.header("location"), Some(REDIRECT_TO), "{resp:?}");
    assert_eq!(resp.header("x-test-verdict"), None, "{resp:?}");
    assert!(!resp.body().contains(MARKER), "{resp:?}");
    assert!(resp.complete(), "{resp:?}");

    let resp = get(port, "/open/hdr-challenge");
    assert_eq!(resp.status, 403, "{resp:?}");
    assert_eq!(resp.header("x-test-verdict"), None, "{resp:?}");
    assert!(!resp.body().contains(MARKER), "{resp:?}");

    // The route's page for the status, as for a block without a body.
    let resp = get(port, "/paged/hdr-challenge");
    assert_eq!(resp.status, 403, "{resp:?}");
    let page: serde_json::Value = serde_json::from_str(&resp.body()).unwrap();
    assert_eq!(page["message"], "Custom 403 page");

    let resp = get(port, "/open/hdr-auth");
    assert_eq!(resp.status, 401, "{resp:?}");
    assert_eq!(
        resp.header("www-authenticate"),
        Some("Basic realm=\"584\""),
        "{resp:?}"
    );
    assert!(!resp.body().contains(MARKER), "{resp:?}");
}

/// #588: a redirect or a challenge on the response body is handled as a
/// block there: after the status has gone out the response is aborted, with
/// none of the body; before, the redirect or challenge replaces it.
#[test]
fn a_redirect_or_challenge_on_the_response_body_is_handled_like_a_block() {
    let setup = setup(19886..19892);
    let port = setup.port;

    for (kind, trigger) in [
        ("redirect", REDIRECT_TRIGGER),
        ("challenge", CHALLENGE_TRIGGER),
    ] {
        let path = format!("/open/leak-{kind}");
        let resp = get(port, &path);
        let body = resp.body();
        assert_eq!(resp.status, 200, "{path}: {resp:?}");
        assert!(!body.contains(MARKER), "{path}: {resp:?}");
        assert!(!body.contains(trigger), "{path}: {resp:?}");
        assert!(!body.contains(AFTER), "{path}: {resp:?}");
        assert!(
            !resp.complete(),
            "{path}: the abort must be detectable: {resp:?}"
        );

        // Decided before the header went out: replaced, or aborted should
        // the body have come in separately.
        let path = format!("/open/cl-{kind}");
        let resp = get(port, &path);
        let body = resp.body();
        assert!(!body.contains(MARKER), "{path}: {resp:?}");
        assert!(!body.contains(trigger), "{path}: {resp:?}");
        if resp.status == 200 {
            assert!(!resp.complete(), "{path}: {resp:?}");
        } else if kind == "redirect" {
            assert_eq!(resp.status, 307, "{path}: {resp:?}");
            assert_eq!(resp.header("location"), Some(REDIRECT_TO), "{path}");
        } else {
            assert_eq!(resp.status, 403, "{path}: {resp:?}");
        }
    }
}
