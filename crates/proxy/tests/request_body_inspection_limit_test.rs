//! A request body longer than `max-inspection-bytes` follows the agents'
//! `failure-mode`.
//!
//! In buffer mode the agents got a request body only up to
//! `waf { body-inspection { max-inspection-bytes } }`. A longer body was cut
//! there: the agents were sent the leading part with `is_last` false, the
//! rest of the body never reached them, and the check that applies an
//! agent's `failure-mode` to a body over its limit saw only the length of
//! the part that was buffered, so it never found the body over the limit.
//! A body of exactly the limit whose end came in a later call was never
//! marked as the last one either.
//!
//! Now a body longer than the limit is handled by each agent's
//! `failure-mode`: a `closed` agent refuses it with 413 before any of it
//! reaches the upstream, and an `open` agent is skipped and sent nothing. A
//! body of at most the limit is sent whole, with `is_last` true.
//!
//! Runs the real binary against a backend that records the bodies it gets,
//! with in-test v2 agents that record the body events they are sent.

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

/// The `max-inspection-bytes` the proxy runs with.
const LIMIT: usize = 1024;

/// What an agent was sent of a request body: the length of the data and
/// `is_last`, per event.
type Events = Arc<Mutex<Vec<(usize, bool)>>>;

/// What the backend got: the request line and the body.
type Requests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// A free port on the loopback interface, picked by the OS.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend answering 200 to everything, recording each request's body.
fn spawn_backend(listener: TcpListener, requests: Requests) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let requests = requests.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let mut length = 0usize;
                let mut chunked = false;
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if request_line.is_empty() {
                        request_line = line.trim_end().to_string();
                    } else if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        } else if name.eq_ignore_ascii_case("transfer-encoding") {
                            chunked = value.to_ascii_lowercase().contains("chunked");
                        }
                    }
                    line.clear();
                }
                if request_line.is_empty() {
                    return;
                }
                // What arrived, also when the connection ends early.
                let mut body = Vec::new();
                if chunked {
                    loop {
                        let mut size_line = String::new();
                        if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
                            break;
                        }
                        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
                        if size == 0 {
                            break;
                        }
                        let mut chunk = vec![0; size];
                        if reader.read_exact(&mut chunk).is_err() {
                            break;
                        }
                        body.extend_from_slice(&chunk);
                        let mut crlf = [0; 2];
                        let _ = reader.read_exact(&mut crlf);
                    }
                } else {
                    let mut buf = vec![0; length];
                    let mut got = 0;
                    while got < length {
                        match reader.read(&mut buf[got..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got += n,
                        }
                    }
                    buf.truncate(got);
                    body = buf;
                }
                requests.lock().unwrap().push((request_line, body));
                let reply = "ok\n";
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
            });
        }
    });
}

/// Allows everything, recording the body events it is sent.
struct Recorder {
    events: Events,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
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
        self.events
            .lock()
            .unwrap()
            .push((data.len(), event.is_last));
        AgentResponse::default_allow()
    }
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// How a request body is framed.
enum Framing<'a> {
    /// One `Content-Length` body.
    Length(&'a [u8]),
    /// A chunked body, one chunk per slice, then the terminating chunk.
    Chunked(&'a [&'a [u8]]),
}

/// Send a POST and return the status.
fn post(port: u16, path: &str, framing: Framing<'_>) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request =
        format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n").into_bytes();
    match framing {
        Framing::Length(body) => {
            request.extend_from_slice(
                format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
            request.extend_from_slice(body);
        }
        Framing::Chunked(chunks) => {
            request.extend_from_slice(
                b"Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
            );
            for chunk in chunks {
                request.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                request.extend_from_slice(chunk);
                request.extend_from_slice(b"\r\n");
            }
            request.extend_from_slice(b"0\r\n\r\n");
        }
    }
    // The proxy may answer and close before it has read all of a body it
    // refuses; the status is what counts.
    let _ = stream.write_all(&request);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

struct Setup {
    port: u16,
    requests: Requests,
    /// What the agent of the `/closed` route (failure mode `closed`) was sent.
    closed: Events,
    /// What the agent of the `/open` route (failure mode `open`) was sent.
    open: Events,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(limit: usize) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let closed: Events = Arc::default();
    let open: Events = Arc::default();
    let mut sockets = Vec::new();
    for (name, events) in [("closed", &closed), ("open", &open)] {
        let socket = dir.path().join(format!("{name}.sock"));
        let server = UdsAgentServerV2::new(
            name,
            socket.clone(),
            Box::new(Recorder {
                events: events.clone(),
            }),
        );
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

    // The backend's listener is handed over still open; the proxy's port is
    // picked just before the proxy binds it.
    let backend = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let requests: Requests = Arc::default();
    spawn_backend(backend, requests.clone());
    let port = free_port();
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
    agent "closed" type="custom" {{
        unix-socket "{closed}"
        events "request_headers" "request_body"
        timeout-ms 2000
    }}
    agent "open" type="custom" {{
        unix-socket "{open}"
        events "request_headers" "request_body"
        timeout-ms 2000
    }}
}}
filters {{
    filter "closed" {{
        type "agent"
        agent "closed"
        failure-mode "closed"
    }}
    filter "open" {{
        type "agent"
        agent "open"
        failure-mode "open"
    }}
}}
waf {{
    mode "off"
    body-inspection {{
        max-inspection-bytes {limit}
    }}
}}
routes {{
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        filters "closed"
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        filters "open"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        closed = sockets[0].display(),
        open = sockets[1].display(),
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
    // Wait until the agents are connected and consulted. Under a limit, each
    // has been sent the body of a small request. Under a limit of 0 no body
    // is small enough to be sent, so the closed agent is consulted on the
    // request headers of a request without a body, and passes it.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (a, b, consulted) = if limit == 0 {
            let a = post(port, "/closed/warmup", Framing::Length(b""));
            (a, 200, a == 200)
        } else {
            let a = post(port, "/closed/warmup", Framing::Length(b"hello"));
            let b = post(port, "/open/warmup", Framing::Length(b"hello"));
            let consulted = !closed.lock().unwrap().is_empty() && !open.lock().unwrap().is_empty();
            (a, b, consulted)
        };
        if a == 200 && b == 200 && consulted {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agents were never consulted: {a} {b}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    closed.lock().unwrap().clear();
    open.lock().unwrap().clear();
    requests.lock().unwrap().clear();
    Setup {
        port,
        requests,
        closed,
        open,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

impl Setup {
    /// The bodies the backend got for `path`.
    fn bodies_to(&self, path: &str) -> Vec<Vec<u8>> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(line, _)| line.contains(&format!(" {path} ")))
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// Wait, up to a deadline, until the backend has `count` requests for
    /// `path`.
    fn wait_for_requests(&self, path: &str, count: usize) -> Vec<Vec<u8>> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let bodies = self.bodies_to(path);
            if bodies.len() >= count || Instant::now() >= deadline {
                return bodies;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| b'a' + (i % 26) as u8).collect()
}

/// An agent that fails closed does not decide on a fragment: the body over
/// the limit is refused with 413, and none of it reaches the upstream.
#[test]
fn a_body_over_the_limit_is_refused_for_an_agent_that_fails_closed() {
    let setup = setup(LIMIT);

    // One chunk over the limit, framed by Content-Length.
    let body = body_of(LIMIT + 1);
    let status = post(setup.port, "/closed/length", Framing::Length(&body));
    assert_eq!(status, 413, "a body over max-inspection-bytes is refused");

    // Over the limit in its second chunk.
    let (first, second) = (body_of(LIMIT / 2), body_of(LIMIT / 2 + 1));
    let status = post(
        setup.port,
        "/closed/chunked",
        Framing::Chunked(&[&first, &second]),
    );
    assert_eq!(status, 413, "a body over max-inspection-bytes is refused");

    assert_eq!(
        *setup.closed.lock().unwrap(),
        vec![],
        "the agent is sent no part of a body it cannot be sent whole"
    );
    // The upstream is sent the request's headers before the body is read, so
    // it records a request, whose body never comes. It is waited for, so that
    // what it got is looked at once it has recorded it.
    for path in ["/closed/length", "/closed/chunked"] {
        let received = setup.wait_for_requests(path, 1);
        assert_eq!(received.len(), 1, "the upstream saw the request start");
        assert!(
            received[0].is_empty(),
            "no byte of a refused body reaches the upstream: {} bytes at {path}",
            received[0].len()
        );
    }
}

/// An agent that fails open is skipped for a body over the limit: it is sent
/// nothing, rather than a fragment as if it were the body, and the request
/// goes on with the whole body.
#[test]
fn a_body_over_the_limit_skips_an_agent_that_fails_open() {
    let setup = setup(LIMIT);

    // One chunk over the limit, framed by Content-Length.
    let body = body_of(LIMIT * 3);
    let status = post(setup.port, "/open/length", Framing::Length(&body));
    assert_eq!(status, 200);
    assert_eq!(setup.wait_for_requests("/open/length", 1), vec![body]);

    // Over the limit in its second chunk, with a third one after it.
    let (first, second, third) = (body_of(LIMIT), body_of(10), body_of(20));
    let status = post(
        setup.port,
        "/open/chunked",
        Framing::Chunked(&[&first, &second, &third]),
    );
    assert_eq!(status, 200);
    let expected = [first, second, third].concat();
    assert_eq!(setup.wait_for_requests("/open/chunked", 1), vec![expected]);

    assert_eq!(
        *setup.open.lock().unwrap(),
        vec![],
        "the agent is skipped: it is sent no part of the body"
    );
}

/// A body of exactly the limit is not over it, whether its end comes with
/// its data or apart from it: the agent is sent the whole body, as the last.
#[test]
fn a_body_of_exactly_the_limit_is_sent_whole_as_the_last() {
    let setup = setup(LIMIT);
    let body = body_of(LIMIT);
    let (first, second) = body.split_at(LIMIT / 2);

    for (route, events) in [("closed", &setup.closed), ("open", &setup.open)] {
        // The end of the body comes with its data.
        let path = format!("/{route}/length");
        assert_eq!(post(setup.port, &path, Framing::Length(&body)), 200);
        assert_eq!(
            *events.lock().unwrap(),
            vec![(LIMIT, true)],
            "{route}: Content-Length framing"
        );
        assert_eq!(setup.wait_for_requests(&path, 1), vec![body.clone()]);
        events.lock().unwrap().clear();

        // A chunked body's end is a call of its own, after the last data:
        // the limit is reached in the one chunk, or in the second of two.
        let path = format!("/{route}/chunked");
        assert_eq!(post(setup.port, &path, Framing::Chunked(&[&body])), 200);
        assert_eq!(
            *events.lock().unwrap(),
            vec![(LIMIT, true)],
            "{route}: one chunk"
        );
        assert_eq!(setup.wait_for_requests(&path, 1), vec![body.clone()]);
        events.lock().unwrap().clear();

        let path = format!("/{route}/chunked-in-two");
        let status = post(setup.port, &path, Framing::Chunked(&[first, second]));
        assert_eq!(status, 200);
        assert_eq!(
            *events.lock().unwrap(),
            vec![(LIMIT, true)],
            "{route}: two chunks"
        );
        assert_eq!(
            setup.wait_for_requests(&path, 1),
            vec![body.clone()],
            "{route}: the upstream gets the whole body"
        );
        events.lock().unwrap().clear();
    }
}

/// A body under the limit is sent whole, as it always was.
#[test]
fn a_body_under_the_limit_is_sent_whole() {
    let setup = setup(LIMIT);
    let body = body_of(100);

    for (route, events) in [("closed", &setup.closed), ("open", &setup.open)] {
        let path = format!("/{route}/small");
        assert_eq!(post(setup.port, &path, Framing::Length(&body)), 200);
        assert_eq!(*events.lock().unwrap(), vec![(100, true)], "{route}");
        assert_eq!(setup.wait_for_requests(&path, 1), vec![body.clone()]);
    }
}

/// With `max-inspection-bytes 0` every body that is not empty is longer than
/// the limit: a `closed` agent's filter refuses it with 413, and a request
/// without a body goes through. To keep bodies from the agents altogether,
/// `inspect-request-body #false` is used instead.
#[test]
fn a_limit_of_zero_refuses_a_body_that_is_not_empty() {
    let setup = setup(0);

    let status = post(setup.port, "/closed/body", Framing::Length(b"x"));
    assert_eq!(status, 413, "a body over max-inspection-bytes is refused");
    let status = post(setup.port, "/closed/no-body", Framing::Length(b""));
    assert_eq!(
        status, 200,
        "a request without a body is not over the limit"
    );

    assert_eq!(*setup.closed.lock().unwrap(), vec![], "no body is sent");
    let received = setup.wait_for_requests("/closed/body", 1);
    assert_eq!(
        received,
        vec![Vec::<u8>::new()],
        "no byte reaches the upstream"
    );
}
