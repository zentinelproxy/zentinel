//! An agent that subscribes to `request_body` gets request bodies without
//! a `waf` block.
//!
//! Request-body inspection was gated on `waf { body-inspection {
//! inspect-request-body } }`: with no `waf` block at all, an agent with
//! `events "request_body"` silently never got a body -- so it could not
//! block one -- while response bodies went to their agents regardless. Now
//! only an explicit `inspect-request-body #false` keeps bodies from them.
//! Runs the real binary with a v2 agent and a backend that records bodies.

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
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-NOWAF";

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

/// Status and raw response of a request with `body`.
fn send(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
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
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, raw)
}

/// Blocks a body containing `block-me`, and (to show it is connected) the
/// path `/probe-block`; counts the bodies it gets.
struct Inspector {
    bodies: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Inspector {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("inspector", "Inspector", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if event.uri.contains("probe-block") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let data = String::from_utf8_lossy(&data).into_owned();
        self.bodies.lock().unwrap().push(data.clone());
        if data.contains("block-me") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    bodies: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>, waf: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("inspector.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let server = UdsAgentServerV2::new(
        "inspector",
        socket.clone(),
        Box::new(Inspector {
            bodies: bodies.clone(),
        }),
    );
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
        events "request_headers" "request_body"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "inspector" {{
        type "agent"
        agent "inspector"
        failure-mode "closed"
    }}
}}
{waf}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "inspector"
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
    // Wait until the agent is connected and consulted.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (blocked, _) = send(port, "GET", "/probe-block", "");
        let (fine, _) = send(port, "GET", "/fine", "");
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
        bodies,
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

/// No `waf` block: the agent gets the body, and its block is enforced.
#[test]
fn request_body_agent_gets_bodies_without_a_waf_block() {
    let setup = setup(19720..19726, "");
    let (status, raw) = send(setup.port, "POST", "/upload", "{\"do\":\"block-me\"}");
    assert_eq!(status, 403, "{raw}");
    assert!(!raw.contains(MARKER), "{raw}");
    assert!(!setup.backend_saw("block-me"));

    let (status, raw) = send(setup.port, "POST", "/upload", "{\"do\":\"fine-nowaf\"}");
    assert_eq!(status, 200, "{raw}");
    assert!(setup.backend_saw("{\"do\":\"fine-nowaf\"}"));
    let bodies = setup.bodies.lock().unwrap().clone();
    assert!(
        bodies.iter().any(|b| b.contains("fine-nowaf")),
        "{bodies:?}"
    );
}

/// A `waf` block without `body-inspection` keeps inspecting bodies, as
/// before.
#[test]
fn request_body_agent_gets_bodies_with_a_bare_waf_block() {
    let setup = setup(19726..19732, "waf {\n    mode \"off\"\n}");
    let (status, raw) = send(setup.port, "POST", "/upload", "{\"do\":\"block-me\"}");
    assert_eq!(status, 403, "{raw}");
    assert!(!setup.backend_saw("block-me"));
}

/// `inspect-request-body #false` still keeps bodies from the agents.
#[test]
fn inspect_request_body_false_keeps_bodies_from_agents() {
    let setup = setup(
        19732..19738,
        "waf {\n    mode \"off\"\n    body-inspection {\n        inspect-request-body #false\n    }\n}",
    );
    let (status, raw) = send(setup.port, "POST", "/upload", "{\"do\":\"block-me\"}");
    assert_eq!(status, 200, "{raw}");
    assert!(setup.backend_saw("{\"do\":\"block-me\"}"));
    let bodies = setup.bodies.lock().unwrap().clone();
    assert!(bodies.is_empty(), "{bodies:?}");
}
