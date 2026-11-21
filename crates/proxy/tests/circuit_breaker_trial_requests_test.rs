//! What a request tells the circuit breaker about its upstream target.
//!
//! In half-open state the breaker lets a limited number of trial requests
//! through and moves on when they report a result. A trial request that
//! ended without reporting one, because an agent refused its body, kept its
//! slot: the breaker stayed half-open and refused every further request to
//! the target. Only a request that failed because of the target may count
//! against it, and a request the client abandoned says nothing about the
//! target at all.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestBodyChunkEvent};

const BREAKER_OPENED_LOG: &str = "Circuit breaker opened";
/// How often Pingora tries a request with an idempotent method whose connection
/// to the target is dropped without an answer, each try counting as a failure
/// of the target. A POST is tried once.
const ATTEMPTS_PER_FAILED_REQUEST: usize = 16;
/// Logged when a half-open period starts over because its trials never came
/// back. A trial slot that is given back makes this unnecessary.
const PERIOD_RESTARTED_LOG: &str = "half-open trials did not finish in time";

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend answering 200 to everything, except a body containing
/// `drop-connection`, for which it closes the connection without answering:
/// a genuine failure of the target. `GET /hold` is never answered either; the
/// backend waits for the proxy to give up on it.
struct Backend {
    port: u16,
    /// `GET /hold` requests received.
    held: Arc<AtomicUsize>,
    /// Requests whose connection was dropped without an answer.
    dropped: Arc<AtomicUsize>,
    /// Requests the proxy gave up on: a body that never arrived, or a
    /// `GET /hold` the proxy closed the connection of.
    abandoned: Arc<AtomicUsize>,
}

fn spawn_backend() -> Backend {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let held = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let (held_counter, dropped_counter, counter) =
        (held.clone(), dropped.clone(), abandoned.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (held_counter, dropped_counter, counter) = (
                held_counter.clone(),
                dropped_counter.clone(),
                counter.clone(),
            );
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let hold = line.starts_with("GET /hold ");
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
                if hold {
                    held_counter.fetch_add(1, Ordering::SeqCst);
                    let _ = reader.read_to_end(&mut Vec::new());
                    counter.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                let mut body = vec![0; length];
                if reader.read_exact(&mut body).is_err() {
                    counter.fetch_add(1, Ordering::SeqCst);
                    return;
                }
                if String::from_utf8_lossy(&body).contains("drop-connection") {
                    dropped_counter.fetch_add(1, Ordering::SeqCst);
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
    Backend {
        port,
        held,
        dropped,
        abandoned,
    }
}

/// Refuses any body containing `refuse-me`, as a content scanner would.
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

struct Proxy {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, port: u16, config: &str) -> Proxy {
        let path = dir.join("zentinel.kdl");
        std::fs::write(&path, config).unwrap();
        let log = dir.join("zentinel.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        let proxy = Proxy { child, port, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
        proxy
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn parse_status(raw: &[u8]) -> (u16, String) {
    let raw = String::from_utf8_lossy(raw).into_owned();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

fn post(port: u16, body: &str) -> (u16, String) {
    send_with_body(port, "POST", body)
}

fn put(port: u16, body: &str) -> (u16, String) {
    send_with_body(port, "PUT", body)
}

fn send_with_body(port: u16, method: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} /upload HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_status(&raw)
}

/// Send the request head and a `Content-Length`, then leave without sending
/// the body.
fn send_head_and_leave(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: 100\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
}

/// Send a complete request the target does not answer, wait until the target
/// has it, and leave. `nth` is how many such requests the target has received
/// once this one has.
fn send_request_and_leave(proxy: &Proxy, backend: &Backend, nth: usize) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
    write!(
        stream,
        "GET /hold HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    stream.flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while backend.held.load(Ordering::SeqCst) < nth {
        assert!(
            Instant::now() < deadline,
            "request {nth} to wait for never reached the target; log:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Retry `post` until it answers `want`, for at most `within`.
fn post_until(proxy: &Proxy, body: &str, want: u16, within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        let (status, answer) = post(proxy.port, body);
        if status == want {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("still {status} {answer:?} after {within:?}"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn config(port: u16, backend: u16, breaker: &str, agent: Option<&Path>) -> String {
    let (agents, filters) = match agent {
        Some(socket) => (
            format!(
                r#"
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
}}"#,
                socket = socket.display()
            ),
            r#"filters "refuser""#,
        ),
        None => (String::new(), ""),
    };
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
        circuit-breaker {{
            {breaker}
        }}
    }}
}}
{agents}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        {filters}
        policies {{ failure-mode "closed"; }}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

/// A client that sends a request head and goes away is not a failure of the
/// target. The breaker here opens on two failures in a row.
#[test]
fn clients_that_go_away_do_not_open_the_breaker() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend();
    let port = free_port();
    let proxy = Proxy::start(
        dir.path(),
        port,
        &config(
            port,
            backend.port,
            "failure-threshold 2\nsuccess-threshold 1\ntimeout-seconds 300",
            None,
        ),
    );

    let mut waits = 0;
    for i in 1..=8 {
        // Two ways to go away: before the body of a request has come, and
        // while waiting for the answer to a complete one.
        if i % 2 == 0 {
            waits += 1;
            send_request_and_leave(&proxy, &backend, waits);
        } else {
            send_head_and_leave(proxy.port);
        }
        // The proxy has sent the request to the target and dropped the
        // connection once it has noticed the client is gone. When the
        // breaker has opened it no longer contacts the target, and this
        // never happens.
        let deadline = Instant::now() + Duration::from_secs(5);
        while backend.abandoned.load(Ordering::SeqCst) < i {
            assert!(
                Instant::now() < deadline,
                "request {i} of a client that went away never reached the target; \
                 log:\n{}",
                proxy.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    let (status, body) = post(proxy.port, "{\"payload\":\"fine\"}");
    assert_eq!(
        status,
        200,
        "the target was taken out of rotation: {body}; log:\n{}",
        proxy.log()
    );
    assert!(
        !proxy.log().contains(BREAKER_OPENED_LOG),
        "the breaker opened; log:\n{}",
        proxy.log()
    );
}

/// Two trial requests an agent refuses, one after the other, must not leave
/// the breaker half-open: the next request the agent allows reaches the
/// target and closes it.
///
/// A half-open period whose trials never come back starts over after
/// `timeout-seconds`, which would let this test pass without the refused
/// trials giving their slots back. The log says whether it did.
#[test]
fn trials_refused_by_an_agent_do_not_keep_the_breaker_half_open() {
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

    let backend = spawn_backend();
    let port = free_port();
    // One failure opens the breaker; it is half-open three seconds later,
    // and one success closes it again. One trial slot.
    let proxy = Proxy::start(
        dir.path(),
        port,
        &config(
            port,
            backend.port,
            "failure-threshold 1\nsuccess-threshold 1\ntimeout-seconds 3\n\
             half-open-max-requests 1",
            Some(&socket),
        ),
    );

    // Wait until the agent is connected and consulted.
    post_until(
        &proxy,
        "{\"payload\":\"refuse-me\"}",
        403,
        Duration::from_secs(10),
    )
    .unwrap_or_else(|e| panic!("the agent was never consulted: {e}"));

    // A genuine failure of the target opens the breaker.
    let (status, _) = post(proxy.port, "{\"payload\":\"drop-connection\"}");
    assert!(status >= 500, "a dropped connection answered {status}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy.log().contains(BREAKER_OPENED_LOG) {
        assert!(
            Instant::now() < deadline,
            "the breaker did not open; log:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Once the open period is over, requests reach the target again as
    // trials. Two of them are refused by the agent on their bodies, so they
    // report nothing.
    for n in 1..=2 {
        post_until(
            &proxy,
            "{\"payload\":\"refuse-me\"}",
            403,
            Duration::from_secs(10),
        )
        .unwrap_or_else(|e| {
            panic!(
                "trial {n} never reached the agent: {e}; log:\n{}",
                proxy.log()
            )
        });
    }

    // A request the agent allows is the next trial. It succeeds and closes
    // the breaker.
    post_until(
        &proxy,
        "{\"payload\":\"fine\"}",
        200,
        Duration::from_secs(10),
    )
    .unwrap_or_else(|e| panic!("the breaker stayed half-open: {e}; log:\n{}", proxy.log()));
    let (status, body) = post(proxy.port, "{\"payload\":\"fine-again\"}");
    assert_eq!(status, 200, "the breaker did not close: {body}");
    assert!(
        !proxy.log().contains(PERIOD_RESTARTED_LOG),
        "the refused trials kept their slots until the period started over; log:\n{}",
        proxy.log()
    );
}

/// A failed attempt counts once against the target, not once where the error
/// happens and once more when the request ends. The breaker here opens on one
/// failure more than a single request's attempts make. The request is a PUT
/// because a POST is not sent again after the target dropped it, so it would
/// make one attempt.
#[test]
fn a_failed_attempt_is_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend();
    let port = free_port();
    let proxy = Proxy::start(
        dir.path(),
        port,
        &config(
            port,
            backend.port,
            &format!(
                "failure-threshold {}\nsuccess-threshold 1\ntimeout-seconds 300",
                ATTEMPTS_PER_FAILED_REQUEST + 1
            ),
            None,
        ),
    );

    let (status, _) = put(proxy.port, "{\"payload\":\"drop-connection\"}");
    assert!(status >= 500, "a dropped connection answered {status}");
    assert_eq!(
        backend.dropped.load(Ordering::SeqCst),
        ATTEMPTS_PER_FAILED_REQUEST,
        "Pingora's attempt limit is not what ATTEMPTS_PER_FAILED_REQUEST says"
    );

    // One failure short of opening: the next request still reaches the
    // target, and its first attempt is the one that opens the breaker.
    let _ = put(proxy.port, "{\"payload\":\"drop-connection\"}");
    assert!(
        backend.dropped.load(Ordering::SeqCst) > ATTEMPTS_PER_FAILED_REQUEST,
        "the breaker opened after one request's failures: an attempt was counted twice; log:\n{}",
        proxy.log()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy.log().contains(BREAKER_OPENED_LOG) {
        assert!(
            Instant::now() < deadline,
            "the breaker did not open; log:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
