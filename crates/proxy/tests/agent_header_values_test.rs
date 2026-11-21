//! Header values an agent receives, for values with bytes outside visible
//! ASCII.
//!
//! A header value is bytes, not necessarily text. The agent is handed
//! strings, so a value that is valid UTF-8 (`café`) arrives as that
//! text, and one that is not (a lone `0xFF`) arrives with each byte as the
//! Unicode code point of the same value (U+00FF). Neither arrives as an
//! empty string. The upstream and the client keep seeing the original
//! bytes.
//!
//! Runs the real binary against a backend that records each request it
//! receives and an in-test v2 agent that records the headers of each
//! request-headers and response-headers event.

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
    AgentResponse, EventType, RequestHeadersEvent, ResponseHeadersEvent,
};

type Headers = HashMap<String, Vec<String>>;

/// The backend's listener, kept bound so that its port cannot be taken
/// before the backend uses it, and a free port for the proxy to listen on
/// (it is written into the configuration, so it can only be checked here).
fn bind_backend_and_pick_proxy_port(range: std::ops::Range<u16>) -> (TcpListener, u16) {
    let mut free = range
        .clone()
        .filter_map(|port| TcpListener::bind(("127.0.0.1", port)).ok());
    let backend = free.next().expect("a free port");
    let proxy = free
        .next()
        .unwrap_or_else(|| panic!("two free ports in {range:?}"));
    let proxy_port = proxy.local_addr().unwrap().port();
    (backend, proxy_port)
}

/// Whether `haystack` contains `needle` as a contiguous run of bytes.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The header values the backend sends on every response, as raw bytes: one
/// valid UTF-8 value, one that is not UTF-8, and a plain one.
const BACKEND_UTF8: &[u8] = b"X-Backend-Utf8: caf\xc3\xa9\r\n";
const BACKEND_INVALID: &[u8] = b"X-Backend-Invalid: a\xffb\r\n";
const BACKEND_PLAIN: &[u8] = b"X-Backend-Plain: plain\r\n";

/// A backend answering 200 to everything, recording each request's head
/// (raw bytes) in `seen`.
fn spawn_backend(listener: TcpListener, seen: Arc<Mutex<Vec<Vec<u8>>>>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = Vec::new();
                let mut line = Vec::new();
                while reader.read_until(b'\n', &mut line).is_ok()
                    && line != b"\r\n"
                    && !line.is_empty()
                {
                    head.extend_from_slice(&line);
                    line.clear();
                }
                seen.lock().unwrap().push(head);
                let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n".to_vec();
                response.extend_from_slice(BACKEND_UTF8);
                response.extend_from_slice(BACKEND_INVALID);
                response.extend_from_slice(BACKEND_PLAIN);
                response.extend_from_slice(b"Connection: close\r\n\r\nok\n");
                let _ = stream.write_all(&response);
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

/// A response as raw header lines: the values are bytes.
struct Response {
    status: u16,
    head: Vec<u8>,
}

/// Sends `GET path` with `extra_headers` (raw bytes, each line ending in
/// CRLF) and returns what came back.
fn request(port: u16, path: &str, extra_headers: &[u8]) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut raw_request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n").into_bytes();
    raw_request.extend_from_slice(extra_headers);
    raw_request.extend_from_slice(b"\r\n");
    stream.write_all(&raw_request).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = raw[..split].to_vec();
    let status = String::from_utf8_lossy(&head)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap_or(0);
    Response { status, head }
}

/// Records the headers of every request-headers and response-headers event.
#[derive(Clone, Default)]
struct Recorder {
    requests: Arc<Mutex<Vec<Headers>>>,
    responses: Arc<Mutex<Vec<Headers>>>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::ResponseHeaders)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests.lock().unwrap().push(event.headers);
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        self.responses.lock().unwrap().push(event.headers);
        AgentResponse::default_allow()
    }
}

struct Setup {
    port: u16,
    recorder: Recorder,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("recorder.sock");
    let recorder = Recorder::default();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("recorder", socket.clone(), Box::new(recorder.clone()));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (backend_listener, port) = bind_backend_and_pick_proxy_port(ports);
    let backend = backend_listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    spawn_backend(backend_listener, seen.clone());
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
    agent "recorder" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "response_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "recorder" {{
        type "agent"
        agent "recorder"
        failure-mode "closed"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "recorder"
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
    // Wait until the agent is connected and consulted on the response.
    let deadline = Instant::now() + Duration::from_secs(10);
    while recorder.responses.lock().unwrap().is_empty() {
        let probe = request(port, "/probe", b"");
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted (status {})",
            probe.status
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        recorder,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// The values of `name` in the one recorded event whose `marker` header is
/// `marker_value`.
fn recorded<'a>(events: &'a [Headers], marker_value: &str, name: &str) -> &'a [String] {
    let matching: Vec<&Headers> = events
        .iter()
        .filter(|headers| {
            headers
                .get("x-case")
                .is_some_and(|values| values.iter().any(|value| value == marker_value))
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "events marked {marker_value}: {events:?}"
    );
    values(matching[0], name)
}

/// The values of header `name` in `headers`.
fn values<'a>(headers: &'a Headers, name: &str) -> &'a [String] {
    headers
        .get(name)
        .unwrap_or_else(|| panic!("no {name} in {headers:?}"))
}

/// A request header value that is valid UTF-8 reaches the agent as that
/// text, and one that is not valid UTF-8 reaches it byte by byte as
/// U+0000..U+00FF; neither is an empty string. The upstream still receives
/// the original bytes.
#[test]
fn agent_receives_request_header_values_with_non_ascii_bytes() {
    let setup = setup(19770..19775);
    let resp = request(
        setup.port,
        "/req",
        b"X-Case: req\r\nX-Name: caf\xc3\xa9\r\nX-Invalid: a\xffb\r\nX-Plain: plain\r\n",
    );
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.requests.lock().unwrap().clone();
    assert_eq!(
        recorded(&events, "req", "x-name"),
        ["caf\u{e9}"],
        "{events:?}"
    );
    assert_eq!(
        recorded(&events, "req", "x-invalid"),
        ["a\u{ff}b"],
        "{events:?}"
    );
    assert_eq!(recorded(&events, "req", "x-plain"), ["plain"], "{events:?}");

    // The upstream was sent the original bytes, not the agent's text.
    let seen = setup.seen.lock().unwrap();
    let upstream = seen
        .iter()
        .find(|head| contains_bytes(head, b"/req"))
        .expect("the upstream saw the request");
    assert!(contains_bytes(upstream, b"caf\xc3\xa9"), "{upstream:?}");
    assert!(contains_bytes(upstream, b"a\xffb"), "{upstream:?}");
}

/// The same for the headers of the upstream's response. The client still
/// receives the original bytes.
#[test]
fn agent_receives_response_header_values_with_non_ascii_bytes() {
    let setup = setup(19775..19780);
    // `setup` has already consulted the agent on its probes: only the
    // event recorded after this request belongs to it.
    let before = setup.recorder.responses.lock().unwrap().len();
    let resp = request(setup.port, "/resp", b"");
    assert_eq!(resp.status, 200, "{}", String::from_utf8_lossy(&resp.head));

    let events = setup.recorder.responses.lock().unwrap().clone();
    let [headers] = &events[before..] else {
        panic!(
            "one response event for the request: {:?}",
            &events[before..]
        );
    };
    assert_eq!(
        values(headers, "x-backend-utf8"),
        ["caf\u{e9}"],
        "{headers:?}"
    );
    assert_eq!(
        values(headers, "x-backend-invalid"),
        ["a\u{ff}b"],
        "{headers:?}"
    );
    assert_eq!(values(headers, "x-backend-plain"), ["plain"], "{headers:?}");

    // The client was sent the original bytes.
    assert!(
        contains_bytes(&resp.head, b"caf\xc3\xa9"),
        "{:?}",
        resp.head
    );
    assert!(contains_bytes(&resp.head, b"a\xffb"), "{:?}", resp.head);
}
