//! An agent's `request-body-mode` decides how it gets the request body
//! (#602).
//!
//! The mode was parsed and then ignored: every body was buffered whole
//! before any agent saw it, so `stream` and `hybrid:N` did nothing and the
//! streamed request-body path could not be reached at all. This runs the
//! real binary with a `stream`-mode agent and checks that:
//!
//! - the agent receives the body's first chunk while the client is still
//!   sending the rest;
//! - a `Challenge` or `Block` on a streamed chunk is answered like one on
//!   a buffered body (#595), and the refused chunk is not forwarded;
//! - a response-header change made on a streamed chunk reaches the client
//!   (#596).

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
    AgentResponse, Decision, EventType, HeaderOp, RequestBodyChunkEvent,
};

const MARKER: &str = "UPSTREAM-MARKER-602";
const REALM: &str = "Basic realm=\"zentinel-stream-test\"";
const TOKEN: &str = "SECRET-STREAM-TOKEN";

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

/// Read an HTTP/1.1 body framed by Content-Length or chunked encoding.
/// Returns what arrived, also when the connection ends early.
fn read_body(reader: &mut impl BufRead, length: Option<usize>, chunked: bool) -> Vec<u8> {
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
                break;
            }
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
                .unwrap_or(0);
            if size == 0 {
                let mut trailer = String::new();
                let _ = reader.read_line(&mut trailer);
                break;
            }
            let mut chunk = vec![0; size + 2];
            if reader.read_exact(&mut chunk).is_err() {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    } else if let Some(length) = length {
        let mut chunk = vec![0; length];
        let mut read = 0;
        while read < length {
            match reader.read(&mut chunk[read..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n,
            }
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body
}

/// A backend answering 200 with [`MARKER`] to everything, recording each
/// request's line and the body it received in `seen`.
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
                let (mut length, mut chunked) = (None, false);
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().ok();
                        }
                        if name.eq_ignore_ascii_case("transfer-encoding")
                            && value.to_ascii_lowercase().contains("chunked")
                        {
                            chunked = true;
                        }
                    }
                    line.clear();
                }
                let body = read_body(&mut reader, length, chunked);
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

fn read_response(stream: &mut TcpStream) -> Response {
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

fn connect(port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
}

fn post(port: u16, body: &str) -> Response {
    let mut stream = connect(port);
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    read_response(&mut stream)
}

fn write_chunk(stream: &mut TcpStream, data: &str) {
    write!(stream, "{:x}\r\n{data}\r\n", data.len()).unwrap();
    stream.flush().unwrap();
}

/// One body chunk as the agent received it.
#[derive(Debug, Clone)]
struct Seen {
    data: String,
    is_last: bool,
}

/// Records every request-body chunk it gets, and decides on each by its
/// content.
struct Streamer {
    chunks: Arc<Mutex<Vec<Seen>>>,
}

fn decide(data: &str, is_last: bool) -> AgentResponse {
    if data.contains("challenge-auth") {
        let mut response = AgentResponse::default_allow();
        response.decision = Decision::Challenge {
            challenge_type: "basic".to_string(),
            params: [("www-authenticate", REALM), ("token", TOKEN)]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        };
        response
    } else if data.contains("block-me") {
        AgentResponse::block(403, Some("BLOCKED-ON-STREAMED-CHUNK".to_string()))
    } else if data.contains("annotate") {
        AgentResponse::default_allow().add_response_header(HeaderOp::Set {
            name: "x-stream-phase-resp".to_string(),
            value: "from-streamed-chunk".to_string(),
        })
    } else {
        AgentResponse::default_allow().set_needs_more(!is_last)
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Streamer {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("streamer", "Streamer", "0.1.0")
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let data = String::from_utf8_lossy(&data).into_owned();
        self.chunks.lock().unwrap().push(Seen {
            data: data.clone(),
            is_last: event.is_last,
        });
        decide(&data, event.is_last)
    }
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
    chunks: Arc<Mutex<Vec<Seen>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

impl Setup {
    fn backend_saw(&self, what: &str) -> bool {
        self.seen.lock().unwrap().iter().any(|r| r.contains(what))
    }
}

fn setup(ports: std::ops::Range<u16>, mode: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("streamer.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let chunks = Arc::new(Mutex::new(Vec::new()));
    let server = UdsAgentServerV2::new(
        "streamer",
        socket.clone(),
        Box::new(Streamer {
            chunks: chunks.clone(),
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
    agent "streamer" type="custom" {{
        unix-socket "{socket}"
        events "request_body"
        request-body-mode "{mode}"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "streamer" {{
        type "agent"
        agent "streamer"
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
        filters "streamer"
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
        // Exactly 8 bytes, so that `hybrid:8` also sends it in one piece.
        let probe = post(port, "block-me");
        if probe.status == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {probe:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    chunks.lock().unwrap().clear();
    Setup {
        port,
        seen,
        chunks,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// Start a chunked POST whose first chunk is `first`, and wait until the
/// agent has that chunk -- before the rest of the body is sent. In buffer
/// mode this times out: the agent sees nothing until the body is complete.
fn send_first_chunk(setup: &Setup, mode: &str, first: &str) -> TcpStream {
    setup.chunks.lock().unwrap().clear();
    let mut stream = connect(setup.port);
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    write_chunk(&mut stream, first);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let chunks = setup.chunks.lock().unwrap().clone();
        // Possibly in pieces: `hybrid:N` sends its first N bytes apart.
        let received: String = chunks.iter().map(|c| c.data.as_str()).collect();
        if received.ends_with(first) {
            assert!(!chunks.iter().any(|c| c.is_last), "{mode}: {chunks:?}");
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "{mode}: the agent got nothing before the body was complete: {chunks:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send the last chunk `last` and end the body; the response.
fn finish(mut stream: TcpStream, last: &str) -> Response {
    write_chunk(&mut stream, last);
    write!(stream, "0\r\n\r\n").unwrap();
    stream.flush().unwrap();
    read_response(&mut stream)
}

fn first_chunk_reaches_agent_before_body_completes(setup: &Setup, mode: &str) {
    let stream = send_first_chunk(setup, mode, "{\"part\":\"one-602\",");
    assert!(
        !setup
            .chunks
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.data.contains("two-602")),
        "{mode}"
    );

    // Finish the body: allowed, and forwarded whole.
    let resp = finish(stream, "\"rest\":\"two-602\"}");
    assert_eq!(resp.status, 200, "{mode}: {resp:?}");
    assert!(resp.body.contains(MARKER), "{mode}: {resp:?}");
    assert!(
        setup.backend_saw("{\"part\":\"one-602\",\"rest\":\"two-602\"}"),
        "{mode}: {:?}",
        setup.seen.lock().unwrap()
    );
    let chunks = setup.chunks.lock().unwrap().clone();
    assert!(
        chunks.iter().any(|c| c.data.contains("two-602")),
        "{mode}: {chunks:?}"
    );
    assert!(
        chunks.last().is_some_and(|c| c.is_last),
        "{mode}: {chunks:?}"
    );
}

#[test]
fn stream_mode_agent_receives_chunks_before_body_completes() {
    let setup = setup(19650..19656, "stream");
    first_chunk_reaches_agent_before_body_completes(&setup, "stream");
}

/// `hybrid:N` buffers up to N bytes, then streams: with N below the first
/// chunk's size, the first chunk is sent on as soon as it arrives.
#[test]
fn hybrid_mode_agent_receives_chunks_past_its_threshold() {
    let setup = setup(19656..19662, "hybrid:8");
    first_chunk_reaches_agent_before_body_completes(&setup, "hybrid:8");
}

/// A Challenge or Block decided on a streamed chunk -- after an earlier
/// chunk was allowed and passed on -- is answered like one on a buffered
/// body (#595), and the refused chunk is not forwarded. This site could not
/// be reached before #602.
#[test]
fn streamed_body_challenges_and_blocks_are_refused() {
    let setup = setup(19662..19668, "stream");

    let stream = send_first_chunk(&setup, "stream", "{\"first\":\"allowed-auth\",");
    let resp = finish(stream, "\"do\":\"challenge-auth\"}");
    assert_eq!(resp.status, 401, "{resp:?}");
    assert_eq!(resp.header("www-authenticate"), Some(REALM), "{resp:?}");
    assert!(!resp.body.contains(MARKER), "{resp:?}");
    assert!(!resp.body.contains(TOKEN), "{resp:?}");
    assert!(!setup.backend_saw("challenge-auth"));

    let stream = send_first_chunk(&setup, "stream", "{\"first\":\"allowed-block\",");
    let resp = finish(stream, "\"do\":\"block-me\"}");
    assert_eq!(resp.status, 403, "{resp:?}");
    assert_eq!(resp.body, "BLOCKED-ON-STREAMED-CHUNK", "{resp:?}");
    assert!(!setup.backend_saw("block-me"));

    // Allowed bodies still pass.
    let resp = post(setup.port, "{\"do\":\"fine\"}");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert!(setup.backend_saw("{\"do\":\"fine\"}"));
}

/// A response-header change made on a streamed chunk reaches the client,
/// as on a buffered body (#596).
#[test]
fn streamed_body_response_header_changes_reach_the_client() {
    let setup = setup(19668..19674, "stream");
    let stream = send_first_chunk(&setup, "stream", "{\"first\":\"plain-602\",");
    let resp = finish(stream, "\"do\":\"annotate\"}");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(
        resp.header("x-stream-phase-resp"),
        Some("from-streamed-chunk"),
        "{resp:?}"
    );
    assert!(setup.backend_saw("{\"first\":\"plain-602\",\"do\":\"annotate\"}"));
}
