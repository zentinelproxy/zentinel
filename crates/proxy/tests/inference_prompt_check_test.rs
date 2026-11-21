//! The prompt check of an inference route (`guardrails { prompt-injection }`)
//! runs on the request body.
//!
//! The check used to run in `request_filter` against a buffer that is only
//! filled later, in `request_body_filter`, so it found nothing to check and
//! never ran: every body was forwarded, whatever the guardrail's agent would
//! have said. This runs the real binary against a backend that records every
//! request, with an in-test guardrail agent (v2, over a Unix socket) that
//! flags content containing `flagged-phrase`.
//!
//! The routes differ in the guardrail's `failure-mode` and in what else
//! reads the whole body before the upstream is chosen (API schema validation,
//! `request-body-mode "inspect-first"`).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{BufReader as AsyncBufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds::{
    read_message, write_message, MessageType, UdsCapabilities, UdsEncoding, UdsHandshakeResponse,
};
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::{AgentCapabilities, HandshakeResponse};
use zentinel_agent_protocol::{
    AgentResponse, EventType, GuardrailDetection, GuardrailInspectEvent, GuardrailResponse,
    RequestBodyChunkEvent, RequestHeadersEvent,
};

const MARKER: &str = "UPSTREAM-MARKER";
/// With a quote and a backslash in it: the refusal's JSON must stay valid.
const BLOCK_MESSAGE: &str = r#"refused by the "content" check \ done"#;
const UNREADABLE_MESSAGE: &str = "Request blocked: its content could not be read for the check";

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Backend {
    /// Each request's head (request line and headers) and body.
    requests: Mutex<Vec<(String, Vec<u8>)>>,
}

impl Backend {
    fn requests_to(&self, path: &str) -> Vec<(String, Vec<u8>)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(head, _)| head.contains(&format!(" {path} ")))
            .cloned()
            .collect()
    }

    fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

/// Read an HTTP/1.1 body framed by Content-Length or chunked encoding.
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
        body.resize(length, 0);
        let mut read = 0;
        while read < length {
            match reader.read(&mut body[read..]) {
                Ok(0) | Err(_) => break,
                Ok(n) => read += n,
            }
        }
        body.truncate(read);
    }
    body
}

fn spawn_backend(listener: TcpListener, backend: Arc<Backend>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let backend = backend.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = String::new();
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
                    head.push_str(&line);
                    line.clear();
                }
                if head.is_empty() {
                    return;
                }
                let body = read_body(&mut reader, length, chunked);
                backend.requests.lock().unwrap().push((head, body));
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

// ---------------------------------------------------------------------------
// Guardrail agent
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Guard {
    /// Connections whose handshake completed.
    handshakes: AtomicUsize,
    /// The content of every inspection event received.
    seen: Mutex<Vec<String>>,
}

impl Guard {
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

/// The guardrail agent's answer for a piece of content: `None` is no answer
/// at all.
fn verdict(content: &str) -> Option<Result<GuardrailResponse, &'static str>> {
    if content.contains("hang-phrase") {
        None
    } else if content.contains("agent-error-phrase") {
        Some(Err("this is not a guardrail response"))
    } else if content.contains("unlisted-phrase") {
        // A detection the agent reports without listing anything.
        Some(Ok(GuardrailResponse {
            detected: true,
            confidence: 0.9,
            detections: vec![],
            redacted_content: None,
        }))
    } else if content.contains("flagged-phrase") {
        Some(Ok(GuardrailResponse {
            detected: true,
            confidence: 0.9,
            detections: vec![GuardrailDetection::new("flagged", "a flagged phrase")],
            redacted_content: None,
        }))
    } else {
        Some(Ok(GuardrailResponse::default()))
    }
}

async fn serve_guard(socket: PathBuf, guard: Arc<Guard>) {
    let listener = UnixListener::bind(&socket).unwrap();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let guard = guard.clone();
        tokio::spawn(async move {
            let _ = guard_connection(stream, guard).await;
        });
    }
}

async fn guard_connection(stream: UnixStream, guard: Arc<Guard>) -> Option<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = AsyncBufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let (kind, _) = read_message(&mut reader).await.ok()?;
    assert_eq!(kind, MessageType::HandshakeRequest);
    let handshake = HandshakeResponse::success(AgentCapabilities::new("guard", "Guard", "0.1.0"));
    let reply = UdsHandshakeResponse {
        protocol_version: handshake.protocol_version,
        capabilities: UdsCapabilities::from(handshake.capabilities),
        success: true,
        error: None,
        encoding: UdsEncoding::Json,
    };
    write_message(
        &mut writer,
        MessageType::HandshakeResponse,
        &serde_json::to_vec(&reply).ok()?,
    )
    .await
    .ok()?;
    guard.handshakes.fetch_add(1, Ordering::SeqCst);

    loop {
        let (kind, payload) = read_message(&mut reader).await.ok()?;
        match kind {
            MessageType::Ping => {
                write_message(&mut writer, MessageType::Pong, &payload)
                    .await
                    .ok()?;
            }
            MessageType::GuardrailInspect => {
                let event: GuardrailInspectEvent = serde_json::from_slice(&payload).ok()?;
                guard.seen.lock().unwrap().push(event.content.clone());
                let Some(answer) = verdict(&event.content) else {
                    continue;
                };
                let mut response = AgentResponse::default_allow();
                response.audit.custom.insert(
                    "correlation_id".to_string(),
                    serde_json::Value::String(event.correlation_id),
                );
                let raw = match answer {
                    Ok(guardrail) => serde_json::to_string(&guardrail).ok()?,
                    Err(garbage) => garbage.to_string(),
                };
                response
                    .routing_metadata
                    .insert("guardrail_response".to_string(), raw);
                write_message(
                    &mut writer,
                    MessageType::AgentResponse,
                    &serde_json::to_vec(&response).ok()?,
                )
                .await
                .ok()?;
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Body agent (inspect-first)
// ---------------------------------------------------------------------------

/// Allows everything and records each request body chunk it is sent.
#[derive(Clone, Default)]
struct Recorder {
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("first", "First", "0.1.0")
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
        self.bodies.lock().unwrap().push(data);
        AgentResponse::default_allow()
    }
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A prompt check that refuses with 422 and checks within 500 ms.
fn prompt_check(failure_mode: &str) -> String {
    let block_message = BLOCK_MESSAGE.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"
        inference {{
            provider "generic"
            guardrails {{
                prompt-injection {{
                    enabled #true
                    agent "guard"
                    action "block"
                    block-status 422
                    block-message "{block_message}"
                    timeout-ms 500
                    failure-mode "{failure_mode}"
                }}
            }}
        }}"#
    )
}

/// Ports of the proxy's listener come from a range of its own, one for each
/// call, so that tests running side by side do not take each other's. A port
/// chosen by the OS would be free again once probed, and a connection made
/// by another test in the meantime may be given it.
const PROXY_PORTS: std::ops::Range<u16> = 47200..47400;
static NEXT_PROXY_PORT: AtomicU16 = AtomicU16::new(PROXY_PORTS.start);

fn free_proxy_port() -> u16 {
    loop {
        let port = NEXT_PROXY_PORT.fetch_add(1, Ordering::SeqCst);
        assert!(
            PROXY_PORTS.contains(&port),
            "no free port in {PROXY_PORTS:?}"
        );
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

struct Setup {
    port: u16,
    metrics_port: u16,
    audit_log: PathBuf,
    backend: Arc<Backend>,
    guard: Arc<Guard>,
    first_bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();

    let guard = Arc::new(Guard::default());
    let guard_socket = dir.path().join("guard.sock");
    rt.spawn(serve_guard(guard_socket.clone(), guard.clone()));

    let recorder = Recorder::default();
    let first_bodies = recorder.bodies.clone();
    let first_socket = dir.path().join("first.sock");
    let server = UdsAgentServerV2::new("first", first_socket.clone(), Box::new(recorder));
    rt.spawn(async move {
        let _ = server.run().await;
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    while !(guard_socket.exists() && first_socket.exists()) {
        assert!(Instant::now() < deadline, "the agents never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    // The backend's listener is handed over as bound, on a port the OS chose.
    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend = Arc::new(Backend::default());
    spawn_backend(backend_listener, backend.clone());
    let port = free_proxy_port();
    let metrics_port = free_proxy_port();
    let audit_log = dir.path().join("audit.log");

    let closed = prompt_check("closed");
    let open = prompt_check("open");
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
    agent "guard" type="custom" {{
        unix-socket "{guard_socket}"
        events "guardrail"
        timeout-ms 2000
    }}
    agent "first" type="custom" {{
        unix-socket "{first_socket}"
        events "request_headers" "request_body"
        request-body-mode "inspect-first"
        timeout-ms 2000
    }}
}}
filters {{
    filter "first" {{
        type "agent"
        agent "first"
        failure-mode "closed"
    }}
}}
routes {{
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        service-type "inference"
        {closed}
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        service-type "inference"
        {open}
    }}
    route "limited" {{
        matches {{ path-prefix "/limited" }}
        upstream "backend"
        service-type "inference"
        {closed}
        policies {{
            max-body-size 2048
        }}
    }}
    route "schema" {{
        matches {{ path-prefix "/schema" }}
        upstream "backend"
        service-type "inference"
        {closed}
        api-schema {{
            validate-requests #true
            request-schema {{
                type "object"
                required "messages"
            }}
        }}
    }}
    route "first" {{
        matches {{ path-prefix "/first" }}
        upstream "backend"
        service-type "inference"
        filters "first"
        {closed}
    }}
}}
observability {{
    metrics {{
        enabled #true
        address "127.0.0.1:{metrics_port}"
        path "/metrics"
    }}
    logging {{
        audit-log {{
            enabled #true
            file "{audit_log}"
            buffer-size 1
        }}
        // Kept in the temp dir, with the audit log.
        error-log {{
            enabled #true
            file "{error_log}"
        }}
    }}
}}
"#,
        audit_log = audit_log.display(),
        error_log = dir.path().join("error.log").display(),
        guard_socket = guard_socket.display(),
        first_socket = first_socket.display(),
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
    // The guardrail agent is connected, and so is the body agent: a body that
    // passes the route's other checks reaches it.
    let deadline = Instant::now() + Duration::from_secs(10);
    while guard.handshakes.load(Ordering::SeqCst) == 0 {
        assert!(
            Instant::now() < deadline,
            "the guardrail agent never connected"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, _) = send(
            port,
            "POST",
            "/first/warmup",
            Some(chat("warm up").as_bytes()),
        );
        if status == 200 && !first_bodies.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the body agent was never consulted: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    first_bodies.lock().unwrap().clear();
    guard.seen.lock().unwrap().clear();
    backend.requests.lock().unwrap().clear();

    Setup {
        port,
        metrics_port,
        audit_log,
        backend,
        guard,
        first_bodies,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A chat request whose one message says `content`.
fn chat(content: &str) -> String {
    serde_json::json!({
        "model": "m1",
        "messages": [{ "role": "user", "content": content }],
    })
    .to_string()
}

fn parse_response(raw: &[u8]) -> (u16, String) {
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

/// One request, framed by Content-Length (`None` sends no body and no length).
fn send(port: u16, method: &str, path: &str, body: Option<&[u8]>) -> (u16, String) {
    send_with(port, method, path, body, &[])
}

/// [`send`] with more request headers.
fn send_with(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut length = body
        .map(|b| format!("Content-Length: {}\r\n", b.len()))
        .unwrap_or_default();
    for (name, value) in headers {
        length.push_str(&format!("{name}: {value}\r\n"));
    }
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\n{length}\r\n"
    )
    .unwrap();
    stream.write_all(body.unwrap_or_default()).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

/// A POST whose body is sent in chunks, so that its length is not declared.
fn send_chunked(port: u16, path: &str, chunks: &[&[u8]]) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    for chunk in chunks {
        // The proxy may answer and close before the last chunks are sent.
        if write!(stream, "{:x}\r\n", chunk.len()).is_err()
            || stream.write_all(chunk).is_err()
            || stream.write_all(b"\r\n").is_err()
        {
            break;
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    parse_response(&raw)
}

fn post(setup: &Setup, path: &str, body: &str) -> (u16, String) {
    send(setup.port, "POST", path, Some(body.as_bytes()))
}

/// How many requests the proxy has refused for `reason`, from its metrics.
fn blocked_count(setup: &Setup, reason: &str) -> u64 {
    let (status, body) = send(setup.metrics_port, "GET", "/metrics", None);
    assert_eq!(status, 200, "{body}");
    let series = format!("zentinel_blocked_requests_total{{reason=\"{reason}\"}} ");
    body.lines()
        .find_map(|line| line.strip_prefix(series.as_str()))
        .map(|count| count.trim().parse().unwrap())
        .unwrap_or(0)
}

/// The `reason` of each entry of the audit log, once there are `count` of
/// them.
fn audit_reasons(setup: &Setup, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let reasons: Vec<String> = std::fs::read_to_string(&setup.audit_log)
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter_map(|entry| entry["reason"].as_str().map(String::from))
            .collect();
        if reasons.len() >= count || Instant::now() >= deadline {
            return reasons;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The `error` and `message` of a refusal's JSON body.
fn refusal(body: &str) -> (String, String) {
    let json: serde_json::Value =
        serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"));
    let field = |name: &str| json[name].as_str().unwrap_or_default().to_string();
    (field("error"), field("message"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Content the guardrail's agent flags is refused with the route's status
/// and message, and the upstream never sees the request.
#[test]
fn flagged_content_is_refused_before_the_upstream() {
    let setup = setup();

    for route in ["/closed/chat", "/open/chat"] {
        let (status, body) = post(&setup, route, &chat("a flagged-phrase inside"));
        assert_eq!(status, 422, "{route}: {body}");
        assert_eq!(
            refusal(&body),
            (
                "prompt_injection_blocked".to_string(),
                BLOCK_MESSAGE.to_string()
            ),
            "{route}"
        );
        assert!(!body.contains(MARKER), "{route}: {body}");
    }
    assert_eq!(
        setup.guard.seen.lock().unwrap().as_slice(),
        ["a flagged-phrase inside", "a flagged-phrase inside"],
        "the agent is sent the text of the messages"
    );

    // Ordered after the refusals: a request that does reach the upstream.
    let (status, _) = post(&setup, "/closed/chat", &chat("a plain question"));
    assert_eq!(status, 200);
    let requests = setup.backend.requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "only the clean request got through");
    assert!(requests[0].0.contains(" /closed/chat "));
}

/// Content the agent passes reaches the upstream byte for byte, also when
/// it is larger than Pingora's default retry buffer.
#[test]
fn clean_content_reaches_the_upstream_unchanged() {
    let setup = setup();

    let small = chat("a plain question");
    let (status, body) = post(&setup, "/closed/chat", &small);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(MARKER), "{body}");

    let large = chat(&"a plain sentence. ".repeat(12_000));
    assert!(large.len() > 200_000);
    let (status, body) = post(&setup, "/open/chat", &large);
    assert_eq!(status, 200, "{body}");

    let seen = setup.backend.requests_to("/closed/chat");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, small.as_bytes());
    let seen = setup.backend.requests_to("/open/chat");
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].1 == large.as_bytes(),
        "the large body arrived changed"
    );
    assert_eq!(setup.guard.calls(), 2);
}

/// Body that has no content to check follows the guardrail's
/// `failure-mode`: refused when it is closed, forwarded as it is when open.
#[test]
fn content_that_cannot_be_read_follows_the_failure_mode() {
    let setup = setup();

    for body in [
        "plain words, not JSON",
        r#"{"data":1}"#,
        r#"{"messages":[]}"#,
    ] {
        let (status, reply) = post(&setup, "/closed/chat", body);
        assert_eq!(status, 422, "{body}: {reply}");
        assert_eq!(
            refusal(&reply),
            (
                "prompt_injection_blocked".to_string(),
                UNREADABLE_MESSAGE.to_string()
            ),
            "{body}"
        );
    }
    // A body with a `Content-Encoding` is not decompressed: it has no text,
    // whatever it looks like.
    let flagged = chat("a flagged-phrase inside");
    let encoded = [("Content-Encoding", "gzip")];
    let (status, reply) = send_with(
        setup.port,
        "POST",
        "/closed/chat",
        Some(flagged.as_bytes()),
        &encoded,
    );
    assert_eq!(status, 422, "{reply}");
    assert_eq!(refusal(&reply).1, UNREADABLE_MESSAGE);
    assert_eq!(
        setup.backend.request_count(),
        0,
        "nothing reached the upstream"
    );

    for body in [
        "plain words, not JSON",
        r#"{"data":1}"#,
        r#"{"messages":[]}"#,
    ] {
        let (status, reply) = post(&setup, "/open/chat", body);
        assert_eq!(status, 200, "{body}: {reply}");
    }
    let (status, reply) = send_with(
        setup.port,
        "POST",
        "/open/chat",
        Some(flagged.as_bytes()),
        &encoded,
    );
    assert_eq!(status, 200, "{reply}");
    let seen: Vec<_> = setup
        .backend
        .requests_to("/open/chat")
        .into_iter()
        .map(|(_, body)| String::from_utf8(body).unwrap())
        .collect();
    assert_eq!(
        seen,
        [
            "plain words, not JSON",
            r#"{"data":1}"#,
            r#"{"messages":[]}"#,
            flagged.as_str(),
        ]
    );
    assert_eq!(setup.guard.calls(), 0, "there was no content to send");
}

/// A check that fails (the agent's answer is unusable, or none arrives in
/// time) follows the guardrail's `failure-mode` as well.
#[test]
fn a_failed_check_follows_the_failure_mode() {
    let setup = setup();

    let (status, body) = post(&setup, "/closed/chat", &chat("agent-error-phrase"));
    assert_eq!(status, 503, "{body}");
    assert_eq!(
        refusal(&body),
        (
            "prompt_injection_blocked".to_string(),
            "Guardrail check unavailable".to_string()
        )
    );
    let (status, body) = post(&setup, "/closed/chat", &chat("hang-phrase"));
    assert_eq!(status, 504, "{body}");
    assert_eq!(refusal(&body).1, "Guardrail check timed out");
    assert_eq!(setup.backend.request_count(), 0);

    for content in ["agent-error-phrase", "hang-phrase"] {
        let sent = chat(content);
        let (status, body) = post(&setup, "/open/chat", &sent);
        assert_eq!(status, 200, "{content}: {body}");
    }
    let seen = setup.backend.requests_to("/open/chat");
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].1, chat("agent-error-phrase").as_bytes());
    assert_eq!(seen[1].1, chat("hang-phrase").as_bytes());
}

/// A refusal is told to be a detection or a failed check by what the check
/// found, not by what the agent listed: a detection reported without a list
/// is a detection, and a body that could not be checked is not.
#[test]
fn a_refusal_is_counted_for_what_caused_it() {
    let setup = setup();

    let (status, body) = post(&setup, "/closed/chat", &chat("an unlisted-phrase inside"));
    assert_eq!(status, 422, "{body}");
    assert_eq!(
        refusal(&body),
        (
            "prompt_injection_blocked".to_string(),
            BLOCK_MESSAGE.to_string()
        )
    );
    assert_eq!(blocked_count(&setup, "prompt_injection"), 1);
    assert_eq!(blocked_count(&setup, "prompt_check_failed"), 0);
    assert_eq!(
        audit_reasons(&setup, 1),
        ["Prompt injection detected".to_string()]
    );

    let (status, body) = post(&setup, "/closed/chat", "plain words, not JSON");
    assert_eq!(status, 422, "{body}");
    let (status, body) = post(&setup, "/closed/chat", &chat("agent-error-phrase"));
    assert_eq!(status, 503, "{body}");
    assert_eq!(blocked_count(&setup, "prompt_injection"), 1);
    assert_eq!(blocked_count(&setup, "prompt_check_failed"), 2);
    assert_eq!(
        audit_reasons(&setup, 3),
        [
            "Prompt injection detected",
            "Prompt check did not complete",
            "Prompt check did not complete",
        ]
    );

    let (status, body) = post(&setup, "/closed/chat", &chat("a flagged-phrase inside"));
    assert_eq!(status, 422, "{body}");
    assert_eq!(blocked_count(&setup, "prompt_injection"), 2);
    assert_eq!(blocked_count(&setup, "prompt_check_failed"), 2);
}

/// The text of a message given as an array of parts, and of an `input` given
/// as an array of strings, is checked too; parts that are not text are left
/// out.
#[test]
fn content_given_as_a_list_is_checked() {
    let setup = setup();

    let parts = |text: &str| {
        serde_json::json!({
            "model": "m1",
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "image_url", "image_url": { "url": "http://a.example/i.png" } },
                    { "type": "text", "text": text },
                    { "type": "text", "text": "a second part" },
                ],
            }],
        })
        .to_string()
    };
    let inputs = |first: &str| {
        serde_json::json!({ "model": "m1", "input": [first, "another text"] }).to_string()
    };

    let (status, body) = post(&setup, "/closed/chat", &parts("a flagged-phrase inside"));
    assert_eq!(status, 422, "{body}");
    let (status, body) = post(&setup, "/closed/chat", &inputs("a flagged-phrase inside"));
    assert_eq!(status, 422, "{body}");
    assert_eq!(setup.backend.request_count(), 0);

    let clean = parts("a plain question");
    let (status, body) = post(&setup, "/closed/chat", &clean);
    assert_eq!(status, 200, "{body}");
    let clean_inputs = inputs("a plain question");
    let (status, body) = post(&setup, "/closed/chat", &clean_inputs);
    assert_eq!(status, 200, "{body}");

    assert_eq!(
        setup.guard.seen.lock().unwrap().as_slice(),
        [
            "a flagged-phrase inside\na second part",
            "a flagged-phrase inside\nanother text",
            "a plain question\na second part",
            "a plain question\nanother text",
        ],
        "the agent is sent the text parts, and only those"
    );
    let seen = setup.backend.requests_to("/closed/chat");
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(seen[0].1, clean.as_bytes());
    assert_eq!(seen[1].1, clean_inputs.as_bytes());

    // Parts without any text have nothing to check.
    let images = serde_json::json!({
        "messages": [{ "role": "user", "content": [
            { "type": "image_url", "image_url": { "url": "http://a.example/i.png" } },
        ] }],
    })
    .to_string();
    let (status, body) = post(&setup, "/closed/chat", &images);
    assert_eq!(status, 422, "{body}");
    assert_eq!(refusal(&body).1, UNREADABLE_MESSAGE);
}

/// A request with no body has nothing to check and is forwarded.
#[test]
fn a_request_without_a_body_is_not_checked() {
    let setup = setup();

    let (status, body) = send(setup.port, "GET", "/closed/models", None);
    assert_eq!(status, 200, "{body}");
    let (status, body) = send(setup.port, "POST", "/closed/chat", Some(b""));
    assert_eq!(status, 200, "{body}");

    assert_eq!(setup.backend.request_count(), 2);
    assert_eq!(setup.guard.calls(), 0);
}

/// The route's body limit still applies when the body is read first: a body
/// over it is refused with 413 and does not reach the upstream.
#[test]
fn a_body_over_the_limit_is_refused_before_the_upstream() {
    let setup = setup();

    let over = chat(&"x".repeat(4096));
    let (status, body) = send_chunked(
        setup.port,
        "/limited/chat",
        &[&over.as_bytes()[..1000], &over.as_bytes()[1000..]],
    );
    assert_eq!(status, 413, "{body}");

    let within = chat("a plain question");
    let (status, body) = send_chunked(setup.port, "/limited/chat", &[within.as_bytes()]);
    assert_eq!(status, 200, "{body}");
    let seen = setup.backend.requests_to("/limited/chat");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, within.as_bytes());
}

/// API schema validation, which also reads the whole body first, is given
/// the body that the prompt check has already read.
#[test]
fn schema_validation_sees_the_body_the_prompt_check_read() {
    let setup = setup();

    let valid = chat("a plain question");
    let (status, body) = post(&setup, "/schema/chat", &valid);
    assert_eq!(status, 200, "{body}");
    let seen = setup.backend.requests_to("/schema/chat");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, valid.as_bytes());

    // Passes the prompt check, fails the schema (no `messages`).
    let (status, body) = post(&setup, "/schema/chat", r#"{"input":"a plain question"}"#);
    assert_eq!(status, 400, "{body}");

    let (status, body) = post(&setup, "/schema/chat", &chat("a flagged-phrase inside"));
    assert_eq!(status, 422, "{body}");
    assert_eq!(setup.backend.requests_to("/schema/chat").len(), 1);
}

/// A body agent in `inspect-first` mode is sent the body once, and the body
/// that reaches the upstream is whole.
#[test]
fn inspect_first_agents_are_sent_the_body_the_prompt_check_read() {
    let setup = setup();

    let clean = chat("a plain question");
    let (status, body) = post(&setup, "/first/chat", &clean);
    assert_eq!(status, 200, "{body}");
    let seen = setup.backend.requests_to("/first/chat");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].1, clean.as_bytes());
    assert_eq!(
        setup.first_bodies.lock().unwrap().as_slice(),
        [clean.as_bytes().to_vec()],
        "the body agent is sent the whole body once"
    );

    let (status, body) = post(&setup, "/first/chat", &chat("a flagged-phrase inside"));
    assert_eq!(status, 422, "{body}");
    assert_eq!(setup.backend.requests_to("/first/chat").len(), 1);
    assert_eq!(
        setup.first_bodies.lock().unwrap().len(),
        1,
        "a refused body is not sent on to the body agent"
    );
}
