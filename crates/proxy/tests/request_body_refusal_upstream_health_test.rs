//! A request an agent refuses on its body is not an upstream failure (#610).
//!
//! Pingora connects to the upstream and sends the request headers before
//! the client's body is read, so when an agent refuses the body the
//! upstream request is abandoned mid-way. That abort used to be reported
//! against the target as a connection failure: it was counted in the
//! target's circuit breaker and logged as `Connection failure reported for
//! target`. A stream of refused uploads -- EICAR to a content scanner, a
//! prompt injection to an AI gateway -- then took a healthy backend out of
//! rotation, and anyone could do that on purpose.
//!
//! The circuit breaker here opens on the first failure, so a single refusal
//! counted against the target would show as an error on the next request. A
//! genuine upstream failure must still open it.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestBodyChunkEvent};

const FAILURE_LOG: &str = "Connection failure reported for target";

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

/// A backend answering 200 to everything, except a body containing
/// `drop-connection`, for which it closes the connection without answering:
/// a genuine upstream failure. Records every body it received.
fn spawn_backend(port: u16, seen: Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let mut length = 0usize;
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    // The proxy abandoned the request.
                    return;
                }
                let body = String::from_utf8_lossy(&body).into_owned();
                seen.lock().unwrap().push(body.clone());
                if body.contains("drop-connection") {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"
                );
            });
        }
    });
}

/// Refuses any body containing `refuse-me`, as a content scanner refuses
/// EICAR.
struct Refuser;

#[async_trait::async_trait]
impl AgentHandlerV2 for Refuser {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("refuser", "Refuser", "0.1.0")
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        if String::from_utf8_lossy(&data).contains("refuse-me") {
            AgentResponse::block(403, Some("REFUSED-BODY".to_string()))
        } else {
            AgentResponse::default_allow().set_needs_more(!event.is_last)
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

fn post(port: u16, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
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

fn failures_logged(log: &PathBuf) -> usize {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .matches(FAILURE_LOG)
        .count()
}

#[test]
fn refused_bodies_leave_the_upstream_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("refuser.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("refuser", socket.clone(), Box::new(Refuser));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(19730..19740);
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
        circuit-breaker {{
            failure-threshold 1
            success-threshold 1
            timeout-seconds 300
        }}
    }}
}}
agents {{
    agent "refuser" type="custom" {{
        unix-socket "{socket}"
        events "request_body"
        request-body-mode "buffer"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "refuser" {{
        type "agent"
        agent "refuser"
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
        filters "refuser"
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
    let log = dir.path().join("zentinel.log");
    let log_file = std::fs::File::create(&log).unwrap();
    let _proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
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
        let (status, body) = post(port, "{\"payload\":\"refuse-me\"}");
        if status == 403 {
            assert_eq!(body, "REFUSED-BODY");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {status} {body}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // N refused bodies.
    for i in 0..10 {
        let (status, body) = post(port, &format!("{{\"n\":{i},\"payload\":\"refuse-me\"}}"));
        assert_eq!(status, 403, "refusal {i}: {body}");
        assert_eq!(body, "REFUSED-BODY", "refusal {i}");
    }
    // Let any accounting spawned off the request path run.
    std::thread::sleep(Duration::from_millis(300));

    let log_text = || std::fs::read_to_string(&log).unwrap_or_default();
    assert_eq!(
        failures_logged(&log),
        0,
        "refused bodies were reported as upstream failures; log:\n{}",
        log_text()
    );
    assert!(
        !seen.lock().unwrap().iter().any(|b| b.contains("refuse-me")),
        "a refused body reached the upstream"
    );

    // The breaker is closed: an allowed request still reaches the target.
    let (status, body) = post(port, "{\"payload\":\"fine\"}");
    assert_eq!(
        status,
        200,
        "the target was taken out of rotation: {body}; log:\n{}",
        log_text()
    );

    // Control: a genuine upstream failure still counts, and with a
    // threshold of one opens the breaker.
    let (status, _) = post(port, "{\"payload\":\"drop-connection\"}");
    assert!(status >= 500, "a dropped connection answered {status}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while failures_logged(&log) == 0 {
        assert!(
            Instant::now() < deadline,
            "a genuine upstream failure was not reported; log:\n{}",
            log_text()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // With its only target's breaker open the upstream has no peer to
    // offer; the exact error status is not what this test is about.
    let (status, body) = post(port, "{\"payload\":\"fine-after-failure\"}");
    assert!(
        status >= 500,
        "the breaker did not open on a genuine failure: {status} {body}"
    );
}
