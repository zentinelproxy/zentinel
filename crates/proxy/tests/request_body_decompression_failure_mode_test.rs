//! A request body that cannot be decompressed for agent inspection is
//! decided by the body agents' filter `failure-mode`, like every other
//! failure on the body (#597).
//!
//! It used to be decided by the route's `policies { failure-mode }` alone,
//! so a filter set to `open` on a `closed` route refused the request and a
//! filter set to `closed` on an `open` route let an uninspected body
//! through. Runs the real binary with `body-inspection { decompress #true }`,
//! a v2 agent on the request body, and a backend that records what it gets.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestBodyChunkEvent};

const MARKER: &str = "UPSTREAM-MARKER-597";
/// Sent as `Content-Encoding: gzip`, but is no gzip stream.
const NOT_GZIP: &str = "this-is-not-gzip-597";

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

/// A backend answering 200 with [`MARKER`], recording each body it gets.
fn spawn_backend(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
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
                if reader.read_exact(&mut body).is_err() {
                    return;
                }
                seen.lock()
                    .unwrap()
                    .push(String::from_utf8_lossy(&body).into_owned());
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

/// Status and body of a POST of `body`, optionally claimed to be gzip.
fn post(port: u16, body: &str, gzip: bool) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let encoding = if gzip {
        "Content-Encoding: gzip\r\n"
    } else {
        ""
    };
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{encoding}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, raw)
}

/// Allows everything but a body containing `block-me`.
struct Inspector;

#[async_trait::async_trait]
impl AgentHandlerV2 for Inspector {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("inspector", "Inspector", "0.1.0")
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        if String::from_utf8_lossy(&data).contains("block-me") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>, filter_mode: &str, route_mode: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("inspector.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("inspector", socket.clone(), Box::new(Inspector));
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
    agent "inspector" type="custom" {{
        unix-socket "{socket}"
        events "request_body"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "inspector" {{
        type "agent"
        agent "inspector"
        failure-mode "{filter_mode}"
    }}
}}
waf {{
    mode "off"
    body-inspection {{
        inspect-request-body #true
        decompress #true
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "inspector"
        policies {{ failure-mode "{route_mode}"; }}
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
    // Wait until the agent is connected and consulted on bodies.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (blocked, _) = post(port, "{\"do\":\"block-me\"}", false);
        let (fine, _) = post(port, "{\"do\":\"fine\"}", false);
        if blocked == 403 && fine == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {blocked} {fine}"
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

impl Setup {
    fn backend_saw(&self, what: &str) -> bool {
        self.seen.lock().unwrap().iter().any(|b| b.contains(what))
    }
}

/// Filter `open` on a `closed` route: the body goes on undecompressed.
#[test]
fn open_filter_passes_an_undecompressable_body_on_a_closed_route() {
    let setup = setup(19680..19686, "open", "closed");
    let (status, raw) = post(setup.port, NOT_GZIP, true);
    assert_eq!(status, 200, "{raw}");
    assert!(raw.contains(MARKER), "{raw}");
    assert!(setup.backend_saw(NOT_GZIP));
}

/// Filter `closed` on an `open` route: refused with 400, never forwarded.
#[test]
fn closed_filter_refuses_an_undecompressable_body_on_an_open_route() {
    let setup = setup(19686..19692, "closed", "open");
    let (status, raw) = post(setup.port, NOT_GZIP, true);
    assert_eq!(status, 400, "{raw}");
    assert!(!raw.contains(MARKER), "{raw}");
    assert!(!setup.backend_saw(NOT_GZIP));
}
