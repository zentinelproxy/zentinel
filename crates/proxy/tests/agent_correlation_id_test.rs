//! The ID the proxy matches agent calls by belongs to one request.
//!
//! Agent calls were correlated by the request's trace ID, which is taken
//! from the client's `X-Trace-Id`, `X-Correlation-Id` or `X-Request-Id`
//! header when one is present. Two concurrent requests that carried the
//! same value got the same correlation ID, so a reply that an agent sent
//! for one of them could be matched to the other.
//!
//! Every agent call of a request now carries one ID the proxy generates
//! for it, whatever the request's headers say and whatever the
//! `trace-id-format` is. The trace ID is unchanged: it stays in the logs,
//! in the response's `X-Correlation-Id`, and in the `X-Correlation-Id`
//! header the agents receive.
//!
//! This runs the real binary against a local backend and an in-test v2
//! agent that records the ID of every event it receives.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent,
    ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketFrameEvent,
};

/// In every upstream response body, so the response body is not empty.
const MARKER: &str = "UPSTREAM-MARKER-CORRELATION";

/// One event as the agent received it.
#[derive(Debug, Clone)]
struct Seen {
    stage: &'static str,
    correlation_id: String,
    /// The `X-Correlation-Id` header of the request, as the agent got it
    /// (request headers only).
    correlation_header: Option<String>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// Records the correlation ID of every event, and allows everything.
struct Recorder {
    seen: Log,
}

impl Recorder {
    fn record(&self, stage: &'static str, correlation_id: &str, header: Option<String>) {
        self.seen.lock().unwrap().push(Seen {
            stage,
            correlation_id: correlation_id.to_string(),
            correlation_header: header,
        });
    }
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::RequestBodyChunk)
            .with_event(EventType::ResponseHeaders)
            .with_event(EventType::ResponseBodyChunk)
            .with_event(EventType::WebSocketFrame)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let header = event
            .headers
            .get("x-correlation-id")
            .and_then(|values| values.first())
            .cloned();
        self.record("request_headers", &event.metadata.correlation_id, header);
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        self.record("request_body", &event.correlation_id, None);
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        self.record("response_headers", &event.correlation_id, None);
        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        self.record("response_body", &event.correlation_id, None);
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.record("websocket_frame", &event.correlation_id, None);
        AgentResponse::websocket_allow()
    }

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        self.record("request_complete", &event.correlation_id, None);
        AgentResponse::default_allow()
    }
}

/// `n` free ports from a small fixed range, so the test stays clear of
/// ports other local services are likely to use.
fn free_ports(range: std::ops::Range<u16>, n: usize) -> Vec<u16> {
    let ports: Vec<u16> = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok())
        .take(n)
        .collect();
    assert_eq!(ports.len(), n, "{n} free ports in {range:?}");
    ports
}

/// A backend that reads the request, and answers 200 with [`MARKER`].
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
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
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
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

/// A WebSocket backend that echoes every text frame.
async fn spawn_echo_backend(port: u16) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_text() && ws.send(message).await.is_err() {
                        break;
                    }
                }
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

struct Setup {
    port: u16,
    seen: Log,
    _proxy: Proxy,
    rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

#[derive(Debug)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Send one request over HTTP/1.1 and read until the proxy closes the
/// connection.
fn send(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let extra: String = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: text/plain\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw);
    let head = raw.split("\r\n\r\n").next().unwrap_or_default();
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
    Response { status, headers }
}

/// Wait until the agent has recorded `stage`; the events recorded so far.
fn wait_for_stage(seen: &Log, stage: &str) -> Vec<Seen> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let events = seen.lock().unwrap().clone();
        if events.iter().any(|e| e.stage == stage) {
            return events;
        }
        assert!(
            Instant::now() < deadline,
            "the agent never got {stage}: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The one ID every event in `events` carries. Fails if the events do not
/// include all of `stages`, or if their IDs differ.
fn one_id(events: &[Seen], stages: &[&str]) -> String {
    for stage in stages {
        assert!(
            events.iter().any(|e| e.stage == *stage),
            "the agent never got {stage}: {events:?}"
        );
    }
    let first = events[0].correlation_id.clone();
    for event in events {
        assert_eq!(
            event.correlation_id, first,
            "every agent call of a request carries the same ID: {events:?}"
        );
    }
    first
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("recorder.sock");
    let seen: Log = Arc::new(Mutex::new(Vec::new()));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new(
        "recorder",
        socket.clone(),
        Box::new(Recorder { seen: seen.clone() }),
    );
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let ports = free_ports(ports, 3);
    let (port, backend, ws_backend) = (ports[0], ports[1], ports[2]);
    spawn_backend(backend);
    rt.block_on(spawn_echo_backend(ws_backend));
    // The same agent twice: `/buffer` gets the request body whole, `/stream`
    // a chunk at a time. `/ws` is inspected by a third that subscribes to no
    // body: an agent that does would have the upgrade response chunked.
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
    upstream "ws-backend" {{
        target "127.0.0.1:{ws_backend}"
    }}
}}
agents {{
    agent "buffered" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body" "response_headers" "response_body"
        request-body-mode "buffer"
        timeout-ms 2000
        failure-mode "open"
    }}
    agent "streamed" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body" "response_headers" "response_body"
        request-body-mode "stream"
        timeout-ms 2000
        failure-mode "open"
    }}
    agent "framed" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "response_headers" "websocket_frame"
        timeout-ms 2000
        failure-mode "open"
    }}
}}
filters {{
    filter "buffered" {{
        type "agent"
        agent "buffered"
        failure-mode "open"
    }}
    filter "streamed" {{
        type "agent"
        agent "streamed"
        failure-mode "open"
    }}
    filter "framed" {{
        type "agent"
        agent "framed"
        failure-mode "open"
    }}
}}
routes {{
    route "buffer" {{
        matches {{ path-prefix "/buffer" }}
        upstream "backend"
        filters "buffered"
    }}
    route "stream" {{
        matches {{ path-prefix "/stream" }}
        upstream "backend"
        filters "streamed"
    }}
    route "ws" {{
        matches {{ path-prefix "/ws" }}
        upstream "ws-backend"
        websocket #true
        websocket-inspection #true
        filters "framed"
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
    // Wait until each agent is connected and consulted: a request before
    // that goes through unconsulted (the agents fail open).
    for route in ["/buffer/probe", "/stream/probe"] {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            seen.lock().unwrap().clear();
            let probe = send(port, "GET", route, &[], "");
            assert_eq!(probe.status, 200, "{probe:?}");
            std::thread::sleep(Duration::from_millis(200));
            if seen
                .lock()
                .unwrap()
                .iter()
                .any(|e| e.stage == "request_complete")
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the agent was never consulted for {route}"
            );
        }
    }
    seen.lock().unwrap().clear();
    Setup {
        port,
        seen,
        _proxy: proxy,
        rt,
        _dir: dir,
    }
}

/// Send a request that goes through every HTTP stage, and the events the
/// agent recorded for it once the request is complete.
fn full_request(setup: &Setup, route: &str, headers: &[(&str, &str)]) -> (Response, Vec<Seen>) {
    setup.seen.lock().unwrap().clear();
    let response = send(setup.port, "POST", route, headers, "a request body");
    assert_eq!(response.status, 200, "{response:?}");
    let events = wait_for_stage(&setup.seen, "request_complete");
    (response, events)
}

const HTTP_STAGES: [&str; 5] = [
    "request_headers",
    "request_body",
    "response_headers",
    "response_body",
    "request_complete",
];

fn assert_generated_uuid(id: &str, client_value: &str) {
    assert_ne!(id, client_value, "the ID is not the client's header value");
    assert!(
        uuid::Uuid::parse_str(id).is_ok(),
        "the agent's correlation ID is a UUID the proxy generated: {id:?}"
    );
}

/// Every agent call of a request whose body is buffered -- its request
/// headers, its body, the response's headers and body, and the
/// notification that it is complete -- carries one ID.
#[test]
fn every_agent_call_of_a_buffered_request_carries_the_same_id() {
    let setup = setup(43000..43100);
    let (_, events) = full_request(&setup, "/buffer/a", &[("X-Request-Id", "client-id-1")]);
    let id = one_id(&events, &HTTP_STAGES);
    assert_generated_uuid(&id, "client-id-1");
}

/// The same for a request body sent to the agent a chunk at a time.
#[test]
fn every_agent_call_of_a_streamed_request_carries_the_same_id() {
    let setup = setup(43100..43200);
    let (_, events) = full_request(&setup, "/stream/a", &[("X-Request-Id", "client-id-2")]);
    let id = one_id(&events, &HTTP_STAGES);
    assert_generated_uuid(&id, "client-id-2");
}

/// A WebSocket connection's frames carry the ID of the request that
/// opened it.
#[test]
fn websocket_frames_carry_the_id_of_the_upgrade_request() {
    let setup = setup(43200..43300);

    // The agent for `/ws` is not probed by `setup`; until it is connected a
    // frame goes through uninspected (it fails open), so try again.
    let deadline = Instant::now() + Duration::from_secs(15);
    let events = loop {
        setup.seen.lock().unwrap().clear();
        setup.rt.block_on(async {
            let mut request = format!("ws://127.0.0.1:{}/ws", setup.port)
                .into_client_request()
                .unwrap();
            request
                .headers_mut()
                .insert("X-Request-Id", "client-id-3".parse().unwrap());
            let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
            ws.send(Message::text("hello")).await.unwrap();
            let echoed = tokio::time::timeout(Duration::from_secs(5), ws.next())
                .await
                .expect("the frame is echoed")
                .unwrap()
                .unwrap();
            assert_eq!(echoed, Message::text("hello"));
            let _ = ws.close(None).await;
        });
        let events = wait_for_stage(&setup.seen, "request_complete");
        if events.iter().any(|e| e.stage == "websocket_frame") {
            break events;
        }
        assert!(
            Instant::now() < deadline,
            "the agent never got a frame: {events:?}"
        );
    };
    let id = one_id(
        &events,
        &[
            "request_headers",
            "response_headers",
            "websocket_frame",
            "request_complete",
        ],
    );
    assert_generated_uuid(&id, "client-id-3");
}

/// Two requests with the same value in a header the trace ID is taken from
/// do not get the same ID.
#[test]
fn requests_with_the_same_trace_header_get_different_ids() {
    let setup = setup(43300..43400);
    for header in ["X-Request-Id", "X-Correlation-Id", "X-Trace-Id"] {
        let (_, first) = full_request(&setup, "/buffer/a", &[(header, "same-value")]);
        let (_, second) = full_request(&setup, "/buffer/b", &[(header, "same-value")]);
        let first = one_id(&first, &HTTP_STAGES);
        let second = one_id(&second, &HTTP_STAGES);
        assert_ne!(
            first, second,
            "{header}: two requests with the same value got the same ID"
        );
        assert_generated_uuid(&first, "same-value");
        assert_generated_uuid(&second, "same-value");
    }
}

/// The trace ID is where it was: the agent gets it in the request's
/// `X-Correlation-Id` header, and the client in the response's.
#[test]
fn trace_id_is_still_sent_in_the_correlation_header() {
    let setup = setup(43400..43500);

    let (response, events) = full_request(&setup, "/buffer/a", &[("X-Request-Id", "client-id-4")]);
    let headers_event = events
        .iter()
        .find(|e| e.stage == "request_headers")
        .expect("the agent got the request headers");
    assert_eq!(
        headers_event.correlation_header.as_deref(),
        Some("client-id-4"),
        "{events:?}"
    );
    assert_eq!(response.header("x-correlation-id"), Some("client-id-4"));
    assert_ne!(headers_event.correlation_id, "client-id-4");

    // Without a header from the client, the trace ID is the one the proxy
    // generated: still what the agent's header and the response carry, and
    // still not the agent's correlation ID.
    let (response, events) = full_request(&setup, "/buffer/b", &[]);
    let headers_event = events
        .iter()
        .find(|e| e.stage == "request_headers")
        .expect("the agent got the request headers");
    let trace_id = response
        .header("x-correlation-id")
        .expect("the response carries the trace ID");
    assert_eq!(
        headers_event.correlation_header.as_deref(),
        Some(trace_id),
        "{events:?}"
    );
    assert_ne!(headers_event.correlation_id, trace_id);
}
