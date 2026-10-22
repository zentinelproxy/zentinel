//! What becomes of an agent's header changes on an allowed request, for
//! each request phase and header direction (#596).
//!
//! | Phase           | Request headers            | Response headers        |
//! |-----------------|----------------------------|-------------------------|
//! | request headers | sent to the upstream       | sent to the client      |
//! | request body    | dropped (already sent)     | sent to the client      |
//!
//! Response-header changes from both request phases used to be lost, and
//! the request-body phase's request-header changes were silently ignored.
//! Request-body-phase request-header changes still cannot be applied --
//! Pingora sends the upstream request's header before the client's body is
//! read -- so they are dropped with a warning; this checks they really do
//! not arrive, rather than arriving on some requests and not others.
//!
//! Runs the real binary against a backend that records every request it
//! receives and an in-test v2 agent. The streamed body phase is covered in
//! `request_body_streaming_mode_test.rs`.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
    ResponseHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-596";

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

/// A backend answering 200 with [`MARKER`] to everything, recording each
/// request's head (lowercased) and body in `seen`.
fn spawn_backend(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
                let mut length = 0usize;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    head.push_str(&line.to_ascii_lowercase());
                    line.clear();
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                seen.lock()
                    .unwrap()
                    .push(format!("{head}\n{}", String::from_utf8_lossy(&body)));
                let body = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Upstream-Set: upstream\r\n\
                     Connection: close\r\n\r\n{body}",
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
    body: String,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn request(port: u16, method: &str, path: &str, body: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
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
        body: body.to_string(),
    }
}

fn set(name: &str, value: &str) -> HeaderOp {
    HeaderOp::Set {
        name: name.to_string(),
        value: value.to_string(),
    }
}

/// Sets one request and one response header in each request phase, on
/// requests whose path (headers) or body (body) asks for it, and on the
/// response overrides one header the request-headers phase set.
struct Annotator;

#[async_trait::async_trait]
impl AgentHandlerV2 for Annotator {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("annotator", "Annotator", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_event(EventType::ResponseHeaders)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let mut response = AgentResponse::default_allow();
        if event.uri.contains("annotate-headers") {
            response = response
                .add_request_header(set("x-hdr-phase-req", "from-headers-phase"))
                .add_response_header(set("x-hdr-phase-resp", "from-headers-phase"))
                .add_response_header(set("x-overridden", "from-headers-phase"))
                .add_response_header(HeaderOp::Remove {
                    name: "x-upstream-set".to_string(),
                });
        }
        response
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let mut response = AgentResponse::default_allow();
        if String::from_utf8_lossy(&data).contains("annotate-body") {
            response = response
                .add_request_header(set("x-body-phase-req", "from-body-phase"))
                .add_response_header(set("x-body-phase-resp", "from-body-phase"));
        }
        response
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        let _ = event;
        // Unconditionally: an agent consulted on the response has the last
        // word on a header a request phase set.
        AgentResponse::default_allow().add_response_header(set("x-overridden", "from-response"))
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

impl Setup {
    /// The backend's record of the one request containing `what`.
    fn backend_request(&self, what: &str) -> String {
        let seen = self.seen.lock().unwrap();
        let matching: Vec<&String> = seen.iter().filter(|r| r.contains(what)).collect();
        assert_eq!(matching.len(), 1, "requests with {what}: {seen:?}");
        matching[0].clone()
    }
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("annotator.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("annotator", socket.clone(), Box::new(Annotator));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(ports);
    let seen = Arc::new(Mutex::new(Vec::new()));
    spawn_backend(backend, seen.clone());
    let config = format!(
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
    agent "annotator" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body" "response_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "annotator" {{
        type "agent"
        agent "annotator"
        failure-mode "closed"
    }}
}}
waf {{
    mode "off"
    body-inspection {{
        inspect-request-body #true
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "annotator"
        policies {{ failure-mode "closed"; }}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display()
    );
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config).unwrap();
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
    // Wait until the agent is connected and consulted: its response-phase
    // header shows up on an ordinary request.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let probe = request(port, "GET", "/probe", "");
        if probe.status == 200 && probe.header("x-overridden") == Some("from-response") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {probe:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// Request-headers phase: request headers reach the upstream, response
/// headers reach the client, and the response phase still has the last
/// word.
#[test]
fn request_headers_phase_changes_both_directions() {
    let setup = setup(19630..19640);
    let resp = request(setup.port, "GET", "/x/annotate-headers", "");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(resp.body.contains(MARKER), "{resp:?}");

    // Request direction (this worked before #596; kept as a guard).
    let upstream = setup.backend_request("annotate-headers");
    assert!(
        upstream.contains("x-hdr-phase-req: from-headers-phase"),
        "{upstream}"
    );

    // Response direction (#596): set, and removed from the upstream's.
    assert_eq!(
        resp.header("x-hdr-phase-resp"),
        Some("from-headers-phase"),
        "{resp:?}"
    );
    assert_eq!(resp.header("x-upstream-set"), None, "{resp:?}");
    // Applied before the response phase's own changes.
    assert_eq!(
        resp.header("x-overridden"),
        Some("from-response"),
        "{resp:?}"
    );
}

/// Request-body phase (buffered): response headers reach the client;
/// request headers cannot (the upstream request's header is already sent)
/// and are dropped, without failing the request.
#[test]
fn request_body_phase_changes_both_directions() {
    let setup = setup(19640..19650);
    let resp = request(setup.port, "POST", "/upload", "{\"do\":\"annotate-body\"}");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(resp.body.contains(MARKER), "{resp:?}");

    // Response direction (#596).
    assert_eq!(
        resp.header("x-body-phase-resp"),
        Some("from-body-phase"),
        "{resp:?}"
    );

    // Request direction: dropped, the body forwarded whole.
    let upstream = setup.backend_request("annotate-body");
    assert!(!upstream.contains("x-body-phase-req"), "{upstream}");
    assert!(
        upstream.contains("{\"do\":\"annotate-body\"}"),
        "{upstream}"
    );

    // A request the agent does not annotate gets none of it: the changes
    // belong to the request they were made for.
    let resp = request(setup.port, "POST", "/upload", "{\"do\":\"nothing\"}");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.header("x-body-phase-resp"), None, "{resp:?}");
    assert_eq!(resp.header("x-hdr-phase-resp"), None, "{resp:?}");
}
