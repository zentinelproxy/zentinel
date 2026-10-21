//! An agent's `Challenge` or `Redirect` decision in a request phase stops
//! the request (#595, #594).
//!
//! A `Challenge` on request headers used to be proxied as if allowed, and
//! one on the request body became a bare 403. A `Redirect` on request
//! headers answered 500 without a `Location`, and on the request body a
//! 403. This runs the real binary against a local backend that records
//! every request it receives and an in-test v2 agent, and checks what the
//! client gets and that the backend never saw the request.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, Decision, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

/// In every backend body; never in anything the proxy or the agent sends.
const MARKER: &str = "UPSTREAM-MARKER-595";
/// A challenge parameter the agent sends that must not reach the client.
const TOKEN: &str = "SECRET-CHALLENGE-TOKEN";
const PAGE: &str = "<html>CHALLENGE-PAGE-595</html>";
const REALM: &str = "Basic realm=\"zentinel-test\"";
const TARGET: &str = "https://login.example.test/start?next=%2F";

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
/// request's line and body (read whole by its Content-Length) in `seen`.
fn spawn_backend(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                let mut length = 0usize;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    line.clear();
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                seen.lock().unwrap().push(format!(
                    "{} {}",
                    request_line.trim(),
                    String::from_utf8_lossy(&body)
                ));
                let body = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// The decision for a request whose path (on request headers) or body (on
/// the request body) contains `what`.
fn decide(what: &str) -> AgentResponse {
    let challenge = |challenge_type: &str, params: &[(&str, &str)]| {
        let mut response = AgentResponse::default_allow();
        response.decision = Decision::Challenge {
            challenge_type: challenge_type.to_string(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        };
        response
    };
    if what.contains("challenge-auth") {
        challenge("basic", &[("www-authenticate", REALM), ("token", TOKEN)])
    } else if what.contains("challenge-page") {
        challenge(
            "captcha",
            &[
                ("body", PAGE),
                ("content-type", "text/html; charset=utf-8"),
                ("token", TOKEN),
            ],
        )
    } else if what.contains("challenge-bare") {
        challenge("proof_of_work", &[("difficulty", "4"), ("token", TOKEN)])
    } else if let Some(status) = what
        .split("redirect-")
        .nth(1)
        .and_then(|rest| rest.get(..3))
        .and_then(|s| s.parse().ok())
    {
        AgentResponse::redirect(TARGET.to_string(), status)
    } else {
        AgentResponse::default_allow()
    }
}

struct Decider;

#[async_trait::async_trait]
impl AgentHandlerV2 for Decider {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("decider", "Decider", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        decide(&event.uri)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        decide(&String::from_utf8_lossy(&data))
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
    /// Whether the backend received any request containing `what`, in its
    /// request line or its body.
    fn backend_saw(&self, what: &str) -> bool {
        self.seen.lock().unwrap().iter().any(|r| r.contains(what))
    }
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("decider.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("decider", socket.clone(), Box::new(Decider));
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
    agent "decider" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "decider" {{
        type "agent"
        agent "decider"
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
        filters "decider"
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

    let setup = Setup {
        port,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    };
    // Wait until the agent is connected and consulted: an allowed request
    // reaches the backend, and a challenged one is answered by the proxy.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let fine = request(port, "GET", "/fine", "");
        let probe = request(port, "GET", "/probe/challenge-bare", "");
        if fine.status == 200 && fine.body.contains(MARKER) && probe.status == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {fine:?} {probe:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    setup
}

/// The checks shared by both phases: `send(what)` makes a request the agent
/// decides on by `what`, which must never reach the backend.
fn check_challenges_and_redirects(setup: &Setup, phase: &str, send: impl Fn(&str) -> Response) {
    // An HTTP authentication challenge: 401 with its WWW-Authenticate.
    let resp = send("challenge-auth");
    assert_eq!(resp.status, 401, "{phase}: {resp:?}");
    assert_eq!(resp.header("www-authenticate"), Some(REALM), "{phase}");
    assert!(!resp.body.contains(MARKER), "{phase}: {resp:?}");
    assert!(!resp.body.contains(TOKEN), "{phase}: {resp:?}");
    assert!(!setup.backend_saw("challenge-auth"), "{phase}");

    // A challenge page: 403 with the agent's body and content type.
    let resp = send("challenge-page");
    assert_eq!(resp.status, 403, "{phase}: {resp:?}");
    assert_eq!(resp.body, PAGE, "{phase}");
    assert_eq!(
        resp.header("content-type"),
        Some("text/html; charset=utf-8"),
        "{phase}"
    );
    assert_eq!(resp.header("www-authenticate"), None, "{phase}");
    assert!(!setup.backend_saw("challenge-page"), "{phase}");

    // Nothing to answer it with: a plain 403, the token kept back.
    let resp = send("challenge-bare");
    assert_eq!(resp.status, 403, "{phase}: {resp:?}");
    assert!(!resp.body.contains(MARKER), "{phase}: {resp:?}");
    assert!(!resp.body.contains(TOKEN), "{phase}: {resp:?}");
    assert!(
        !resp.headers.iter().any(|(_, v)| v.contains(TOKEN)),
        "{phase}: {resp:?}"
    );
    assert!(!setup.backend_saw("challenge-bare"), "{phase}");

    // Redirects keep their status and carry the Location (#594).
    for status in [301, 302, 307] {
        let what = format!("redirect-{status}");
        let resp = send(&what);
        assert_eq!(resp.status, status, "{phase}: {resp:?}");
        assert_eq!(resp.header("location"), Some(TARGET), "{phase}: {status}");
        assert!(!resp.body.contains(MARKER), "{phase}: {resp:?}");
        assert!(!setup.backend_saw(&what), "{phase}: {status}");
    }
    // A status that is no redirect falls back to 302.
    let resp = send("redirect-200");
    assert_eq!(resp.status, 302, "{phase}: {resp:?}");
    assert_eq!(resp.header("location"), Some(TARGET), "{phase}");
    assert!(!setup.backend_saw("redirect-200"), "{phase}");
}

/// On request headers the request is answered before any upstream is
/// contacted: the backend never sees it.
#[test]
fn request_header_challenges_and_redirects_are_not_proxied() {
    let setup = setup(19610..19616);
    let port = setup.port;
    check_challenges_and_redirects(&setup, "request headers", |what| {
        request(port, "GET", &format!("/x/{what}"), "")
    });
    // Allowed requests still reach the backend.
    let resp = request(port, "GET", "/x/fine", "");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(setup.backend_saw("/x/fine"));
}

/// On the request body (buffered) the request's body never reaches the
/// backend, and the client gets the same answers as on request headers.
#[test]
fn request_body_challenges_and_redirects_are_not_proxied() {
    let setup = setup(19616..19622);
    let port = setup.port;
    check_challenges_and_redirects(&setup, "request body", |what| {
        request(port, "POST", "/upload", &format!("{{\"do\":\"{what}\"}}"))
    });
    // An allowed body still reaches the backend, whole.
    let resp = request(port, "POST", "/upload", "{\"do\":\"fine\"}");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(setup.backend_saw("{\"do\":\"fine\"}"));
}
