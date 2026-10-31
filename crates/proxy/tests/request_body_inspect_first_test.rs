//! `request-body-mode "inspect-first"`: the body agents decide on the whole
//! request body before the upstream is contacted (#608).
//!
//! In the other modes Pingora connects to the upstream and sends the request
//! headers before the body is read, so a refused request still reaches the
//! upstream as an aborted request, and request-header changes an agent asks
//! for on the body cannot be applied. This runs the real binary against a
//! backend that records every connection and request, with an in-test v2
//! agent that refuses bodies containing "evil" and otherwise sets a request
//! header, behind an inspect-first route and a default (buffer) route.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestBodyChunkEvent, RequestHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-608";

fn free_ports(range: std::ops::Range<u16>, n: usize) -> Vec<u16> {
    let ports: Vec<u16> = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok())
        .take(n)
        .collect();
    assert_eq!(ports.len(), n, "{n} free ports in {range:?}");
    ports
}

#[derive(Default)]
struct Backend {
    /// Every accepted connection, whether or not a request arrived on it.
    connections: AtomicUsize,
    /// Each request's head (request line and headers) and body.
    requests: Mutex<Vec<(String, String)>>,
}

impl Backend {
    fn requests_to(&self, path: &str) -> Vec<(String, String)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(head, _)| head.contains(&format!(" {path} ")))
            .cloned()
            .collect()
    }
}

fn spawn_backend(port: u16, backend: Arc<Backend>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            backend.connections.fetch_add(1, Ordering::SeqCst);
            let backend = backend.clone();
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
                    head.push_str(&line);
                    line.clear();
                }
                if head.is_empty() {
                    return;
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    // Aborted before the whole body arrived: still recorded,
                    // the upstream saw the request.
                    body.clear();
                }
                backend
                    .requests
                    .lock()
                    .unwrap()
                    .push((head, String::from_utf8_lossy(&body).into_owned()));
                let reply = format!("{MARKER}\n");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            });
        }
    });
}

/// Refuses a body containing "evil"; on any other body, sets
/// `x-body-verdict: clean` on the upstream request.
struct Judge;

#[async_trait::async_trait]
impl AgentHandlerV2 for Judge {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("judge", "Judge", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        if String::from_utf8_lossy(&data).contains("evil") {
            AgentResponse::block(403, Some("refused by judge".to_string()))
        } else {
            AgentResponse::default_allow().add_request_header(HeaderOp::Set {
                name: "x-body-verdict".to_string(),
                value: "clean".to_string(),
            })
        }
    }
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn post(port: u16, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

struct Setup {
    port: u16,
    backend: Arc<Backend>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut sockets = Vec::new();
    for name in ["first", "buffered"] {
        let socket = dir.path().join(format!("{name}.sock"));
        let server = UdsAgentServerV2::new(name, socket.clone(), Box::new(Judge));
        rt.spawn(async move {
            let _ = server.run().await;
        });
        sockets.push(socket);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sockets.iter().all(|s| s.exists()) {
        assert!(Instant::now() < deadline, "the agents never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let ports = free_ports(ports, 2);
    let (port, backend_port) = (ports[0], ports[1]);
    let backend = Arc::new(Backend::default());
    spawn_backend(backend_port, backend.clone());
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
        target "127.0.0.1:{backend_port}"
    }}
}}
agents {{
    agent "first" type="custom" {{
        unix-socket "{first}"
        events "request_headers" "request_body"
        request-body-mode "inspect-first"
        timeout-ms 2000
    }}
    agent "buffered" type="custom" {{
        unix-socket "{buffered}"
        events "request_headers" "request_body"
        timeout-ms 2000
    }}
}}
filters {{
    filter "first" {{
        type "agent"
        agent "first"
        failure-mode "closed"
    }}
    filter "buffered" {{
        type "agent"
        agent "buffered"
        failure-mode "closed"
    }}
}}
routes {{
    route "first" {{
        matches {{ path-prefix "/first" }}
        upstream "backend"
        filters "first"
    }}
    route "buffered" {{
        matches {{ path-prefix "/buffered" }}
        upstream "backend"
        filters "buffered"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        first = sockets[0].display(),
        buffered = sockets[1].display(),
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
    // Wait until both agents are consulted: a clean body comes back with
    // the agent's header applied or at least proxied.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (a, _) = post(port, "/first/warmup", "hello");
        let (b, _) = post(port, "/buffered/warmup", "hello");
        let (c, _) = post(port, "/first/warmup-evil", "evil");
        if a == 200 && b == 200 && c == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agents were never consulted: {a} {b} {c}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        backend,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

#[test]
fn inspect_first_decides_before_the_upstream_is_contacted() {
    let setup = setup(19960..20060);

    // A refused body: the agent's 403, and the upstream never contacted --
    // no connection, no request.
    let connections = setup.backend.connections.load(Ordering::SeqCst);
    for _ in 0..5 {
        let (status, body) = post(setup.port, "/first/upload", "some evil payload");
        assert_eq!(status, 403, "{body}");
        assert!(!body.contains(MARKER), "{body}");
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        setup.backend.connections.load(Ordering::SeqCst),
        connections,
        "a refused inspect-first request must not open an upstream connection"
    );
    assert!(setup.backend.requests_to("/first/upload").is_empty());

    // An allowed body reaches the upstream whole, with the request header
    // the agent set on the body.
    let (status, body) = post(setup.port, "/first/ok", "a clean payload");
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(MARKER), "{body}");
    let seen = setup.backend.requests_to("/first/ok");
    assert_eq!(seen.len(), 1, "{seen:?}");
    let (head, received) = &seen[0];
    assert_eq!(received, "a clean payload");
    assert!(
        head.to_ascii_lowercase().contains("x-body-verdict: clean"),
        "the body-phase header change must reach the upstream: {head}"
    );
}

/// The default (buffer) mode is unchanged: the agent decides on the body
/// after the upstream has the request headers, so a refused body is still
/// refused but the upstream saw the request start, and the body-phase
/// header change cannot be applied.
#[test]
fn the_default_mode_is_unchanged() {
    let setup = setup(20060..20160);

    let (status, body) = post(setup.port, "/buffered/upload", "some evil payload");
    assert_eq!(status, 403, "{body}");
    std::thread::sleep(Duration::from_millis(300));
    let seen = setup.backend.requests_to("/buffered/upload");
    assert_eq!(
        seen.len(),
        1,
        "in buffer mode the upstream gets the request headers: {seen:?}"
    );
    assert!(
        !seen[0].1.contains("evil"),
        "no byte of a refused body reaches the upstream"
    );

    let (status, _) = post(setup.port, "/buffered/ok", "a clean payload");
    assert_eq!(status, 200);
    let seen = setup.backend.requests_to("/buffered/ok");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, "a clean payload");
    assert!(!seen[0].0.to_ascii_lowercase().contains("x-body-verdict"));
}
