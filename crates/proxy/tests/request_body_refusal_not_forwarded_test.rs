//! A request body the agents refuse never reaches the upstream.
//!
//! In buffer mode the body went upstream chunk by chunk while it was being
//! buffered for inspection, and the agents were asked only once it was
//! complete. A chunked body's end arrives apart from its last bytes, so by
//! then the upstream had the whole body: the client got the agent's 403 or
//! 429, and the upstream got the request it refused. Hybrid mode's buffered
//! part leaked the same way. The body is now held back until the agents have
//! decided.
//!
//! What still reaches the upstream, by design of the proxy today:
//!
//! - the request line and headers: Pingora connects and sends them before
//!   the client's body is read, so a refused request's upstream sees a
//!   request whose body never comes and whose connection is then closed;
//! - in stream mode, the chunks the agent allowed before the one it refused
//!   (that is what streaming means). The refused chunk itself is never sent.

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
    } else if data.contains("rate-limit-me") {
        // As the ai-gateway agent answers an over-budget body.
        let mut response = AgentResponse::default_allow();
        response.decision = Decision::Block {
            status: 429,
            body: Some("RATE-LIMITED-ON-BODY".to_string()),
            headers: Some(HashMap::from([(
                "retry-after".to_string(),
                "30".to_string(),
            )])),
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

fn chunked(port: u16, parts: &[&str]) -> Response {
    let mut stream = connect(port);
    write!(
        stream,
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    // Writes may fail once the proxy has answered and closed: a refusal
    // can come before the client is done.
    for part in parts {
        let _ = write!(stream, "{:x}\r\n{part}\r\n", part.len()).and_then(|_| stream.flush());
        // Separate reads on the proxy's side.
        std::thread::sleep(Duration::from_millis(150));
    }
    let _ = write!(stream, "0\r\n\r\n");
    read_response(&mut stream)
}

/// Refuse a one-piece body and two-chunk ones whose second chunk is the
/// refused one; the backend gets no refused chunk, and in the modes that
/// buffer, nothing of a refused body at all.
fn check(mode: &str, ports: std::ops::Range<u16>) {
    let setup = setup(ports, mode);
    let buffers = mode != "stream";

    let resp = post(setup.port, "{\"do\":\"block-me\",\"one\":\"piece\"}");
    assert_eq!(resp.status, 403, "{mode}: {resp:?}");
    assert_eq!(resp.body, "BLOCKED-ON-STREAMED-CHUNK", "{mode}: {resp:?}");

    let resp = chunked(
        setup.port,
        &["{\"first\":\"innocent-part\",", "\"do\":\"block-me\"}"],
    );
    assert_eq!(resp.status, 403, "{mode}: {resp:?}");

    let resp = chunked(
        setup.port,
        &["{\"first\":\"innocent-429\",", "\"do\":\"rate-limit-me\"}"],
    );
    assert_eq!(resp.status, 429, "{mode}: {resp:?}");
    assert_eq!(resp.header("retry-after"), Some("30"), "{mode}: {resp:?}");
    assert_eq!(resp.body, "RATE-LIMITED-ON-BODY", "{mode}: {resp:?}");

    // The agent did see the refused chunk: in the modes that buffer, with
    // the part before it, as the complete body.
    let chunks = setup.chunks.lock().unwrap().clone();
    let refused = chunks
        .iter()
        .find(|c| c.data.contains("rate-limit-me"))
        .unwrap_or_else(|| panic!("{mode}: {chunks:?}"));
    if buffers {
        assert!(refused.data.contains("innocent-429"), "{mode}: {chunks:?}");
        assert!(refused.is_last, "{mode}: {chunks:?}");
    }

    // Give anything in flight time to arrive.
    std::thread::sleep(Duration::from_millis(300));
    let seen = setup.seen.lock().unwrap().clone();
    for refused in ["block-me", "rate-limit-me"] {
        assert!(!setup.backend_saw(refused), "{mode}: {seen:?}");
    }
    if buffers {
        for allowed_part in ["innocent-part", "innocent-429"] {
            assert!(!setup.backend_saw(allowed_part), "{mode}: {seen:?}");
        }
    }

    // Allowed bodies, chunked or not, still arrive whole.
    let resp = chunked(setup.port, &["{\"first\":\"ok-part\",", "\"do\":\"fine\"}"]);
    assert_eq!(resp.status, 200, "{mode}: {resp:?}");
    let resp = post(setup.port, "{\"do\":\"fine-cl\"}");
    assert_eq!(resp.status, 200, "{mode}: {resp:?}");
    assert!(
        setup.backend_saw("{\"first\":\"ok-part\",\"do\":\"fine\"}"),
        "{mode}: {:?}",
        setup.seen.lock().unwrap()
    );
    assert!(setup.backend_saw("{\"do\":\"fine-cl\"}"), "{mode}");
}

#[test]
fn buffer_mode_refused_body_never_reaches_the_upstream() {
    check("buffer", 19700..19706);
}

/// Threshold above the body: hybrid buffers all of it.
#[test]
fn hybrid_mode_refused_buffered_part_never_reaches_the_upstream() {
    check("hybrid:4096", 19706..19712);
}

#[test]
fn stream_mode_refused_chunk_never_reaches_the_upstream() {
    check("stream", 19712..19718);
}
