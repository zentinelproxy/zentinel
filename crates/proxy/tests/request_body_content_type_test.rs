//! Which request bodies are sent to the agents, by `Content-Type`.
//!
//! Request bodies reach the agents only when the request's `Content-Type`
//! is on `waf { body-inspection { content-types } }`, by default
//! `application/x-www-form-urlencoded`, `multipart/form-data`,
//! `application/json`, `application/xml` and `text/xml`. Two kinds of body
//! were not matched by that list, so the agents were never sent them:
//!
//! - bodies of a structured-syntax media type (RFC 6839), such as
//!   `application/vnd.api+json`, `application/problem+json` or
//!   `application/soap+xml`: an entry was compared as a prefix, and
//!   `application/vnd.api+json` does not start with `application/json`.
//! - bodies of a request without a `Content-Type`, which was compared as
//!   the empty string.
//!
//! Now an entry `type/subtype` also matches `type/<name>+subtype`, with or
//! without parameters, and a request that has a body but no usable
//! `Content-Type` (absent, blank, or not valid text) is inspected whatever
//! the list says, unless `body-inspection { inspect-untyped-bodies #false }`
//! leaves it to the list. A request without a body is matched as before, and
//! a body of another media type (`text/plain`) is still not sent.
//!
//! Runs the real binary against a backend that records the bodies it gets,
//! with an in-test v2 agent that records the body events it is sent.

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

/// What an agent was sent of request bodies: the data of each event.
type Events = Arc<Mutex<Vec<String>>>;

/// What the backend got: the request line and the body.
type Requests = Arc<Mutex<Vec<(String, String)>>>;

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
                // Header lines are read as bytes: a value need not be text.
                let mut raw_line = Vec::new();
                while reader.read_until(b'\n', &mut raw_line).is_ok()
                    && raw_line != b"\r\n"
                    && !raw_line.is_empty()
                {
                    let line = String::from_utf8_lossy(&raw_line).into_owned();
                    if request_line.is_empty() {
                        request_line = line.trim_end().to_string();
                    } else if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse().unwrap_or(0);
                        } else if name.eq_ignore_ascii_case("transfer-encoding") {
                            chunked = value.to_ascii_lowercase().contains("chunked");
                        }
                    }
                    raw_line.clear();
                }
                if request_line.is_empty() {
                    return;
                }
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
                    body = vec![0; length];
                    let mut got = 0;
                    while got < length {
                        match reader.read(&mut body[got..]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got += n,
                        }
                    }
                    body.truncate(got);
                }
                requests
                    .lock()
                    .unwrap()
                    .push((request_line, String::from_utf8_lossy(&body).into_owned()));
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

/// Records the data of each body event it is sent, and refuses a body
/// that contains `refuse-this`.
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
        let data = String::from_utf8_lossy(&data).into_owned();
        let refuse = data.contains("refuse-this");
        self.events.lock().unwrap().push(data);
        if refuse {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
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

/// How a request's body is framed.
#[derive(Clone, Copy)]
enum Framing {
    /// `Content-Length` of the body; none at all for an empty body.
    Length,
    /// `Content-Length: 0`, whatever the body.
    ZeroLength,
    Chunked,
}

/// Send a request and return the status. `content_type` of `None` sends no
/// `Content-Type` header.
fn send(
    port: u16,
    method: &str,
    path: &str,
    content_type: Option<&[u8]>,
    framing: Framing,
    body: &str,
) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
            .into_bytes();
    if let Some(content_type) = content_type {
        request.extend_from_slice(b"Content-Type: ");
        request.extend_from_slice(content_type);
        request.extend_from_slice(b"\r\n");
    }
    let mut tail = String::new();
    match framing {
        Framing::Length if body.is_empty() => tail.push_str("\r\n"),
        Framing::Length => {
            tail.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        }
        Framing::ZeroLength => tail.push_str("Content-Length: 0\r\n\r\n"),
        Framing::Chunked => {
            tail.push_str("Transfer-Encoding: chunked\r\n\r\n");
            // Two chunks, so the body is not in one read.
            let (first, second) = body.split_at(body.len() / 2);
            for chunk in [first, second] {
                tail.push_str(&format!("{:x}\r\n{chunk}\r\n", chunk.len()));
            }
            tail.push_str("0\r\n\r\n");
        }
    }
    request.extend_from_slice(tail.as_bytes());
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
    /// The data of every body event the agent was sent.
    events: Events,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

/// Run the proxy with one agent on every route and `waf` as the `waf`
/// block (empty for none).
fn setup(waf: &str) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let events: Events = Arc::default();
    let socket = dir.path().join("recorder.sock");
    let server = UdsAgentServerV2::new(
        "recorder",
        socket.clone(),
        Box::new(Recorder {
            events: events.clone(),
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
    agent "recorder" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        timeout-ms 2000
    }}
}}
filters {{
    filter "recorder" {{
        type "agent"
        agent "recorder"
        failure-mode "closed"
    }}
}}
{waf}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "recorder"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
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
    // Wait until the agent is connected and consulted: it has been sent the
    // body of a request that every allowlist here covers.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = send(
            port,
            "POST",
            "/warmup",
            Some(b"application/xml"),
            Framing::Length,
            "<warmup/>",
        );
        if status == 200 && !events.lock().unwrap().is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    events.lock().unwrap().clear();
    requests.lock().unwrap().clear();
    Setup {
        port,
        requests,
        events,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

impl Setup {
    /// Whether the agent was sent a body event containing `marker`.
    fn agent_saw(&self, marker: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|data| data.contains(marker))
    }

    /// Whether the backend got a body containing `marker`.
    fn backend_saw(&self, marker: &str) -> bool {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, body)| body.contains(marker))
    }

    /// Send a POST with a `Content-Length` body and `content_type`.
    fn post(&self, content_type: Option<&str>, body: &str) -> u16 {
        self.post_raw(content_type.map(str::as_bytes), body)
    }

    /// Send a POST with a `Content-Length` body and a `Content-Type` of any
    /// bytes.
    fn post_raw(&self, content_type: Option<&[u8]>, body: &str) -> u16 {
        send(
            self.port,
            "POST",
            "/upload",
            content_type,
            Framing::Length,
            body,
        )
    }
}

/// With the default list, a body of a structured-syntax media type is sent
/// to the agent, and what the agent decides is enforced.
#[test]
fn structured_syntax_suffix_bodies_are_sent_to_the_agents_by_default() {
    let setup = setup("waf {\n    mode \"off\"\n}");
    for (index, content_type) in [
        "application/vnd.api+json",
        "application/vnd.api+json; charset=utf-8",
        "application/problem+json",
        "application/merge-patch+json",
        "application/soap+xml; charset=utf-8",
        "application/atom+xml",
        "APPLICATION/VND.API+JSON",
    ]
    .into_iter()
    .enumerate()
    {
        let marker = format!("suffix-body-{index}");
        let body = format!("{{\"data\":\"{marker}\"}}");
        let status = setup.post(Some(content_type), &body);
        assert_eq!(status, 200, "{content_type}");
        assert!(setup.agent_saw(&marker), "{content_type}: the agent got it");
        assert!(
            setup.backend_saw(&marker),
            "{content_type}: upstream got it"
        );
    }

    let status = setup.post(
        Some("application/vnd.api+json"),
        "{\"data\":\"refuse-this\"}",
    );
    assert_eq!(status, 403, "the agent's decision on the body is applied");
    assert!(!setup.backend_saw("refuse-this"));
}

/// A body without a `Content-Type` is sent to the agent, framed by
/// `Content-Length` or chunked.
#[test]
fn a_body_without_content_type_is_sent_to_the_agents_by_default() {
    let setup = setup("waf {\n    mode \"off\"\n}");

    let status = setup.post(None, "length-framed-body");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("length-framed-body"));
    assert!(setup.backend_saw("length-framed-body"));

    let status = send(
        setup.port,
        "PUT",
        "/upload",
        None,
        Framing::Chunked,
        "chunked-framed-body",
    );
    assert_eq!(status, 200);
    assert!(setup.agent_saw("chunked-framed-body"));
    assert!(setup.backend_saw("chunked-framed-body"));

    let status = setup.post(None, "refuse-this-body");
    assert_eq!(status, 403, "the agent's decision on the body is applied");
    assert!(!setup.backend_saw("refuse-this-body"));
}

/// Unchanged: a body of a media type that is not on the list is not sent,
/// nor is a request without a body.
#[test]
fn other_media_types_and_requests_without_a_body_are_not_sent_to_the_agents() {
    let setup = setup("waf {\n    mode \"off\"\n}");

    for (index, content_type) in [
        "text/plain",
        "application/octet-stream",
        "text/vnd.api+json",
        "image/svg+xml",
        "application/x-ndjson",
    ]
    .into_iter()
    .enumerate()
    {
        let marker = format!("other-body-{index}");
        let status = setup.post(Some(content_type), &marker);
        assert_eq!(status, 200, "{content_type}");
        assert!(
            setup.backend_saw(&marker),
            "{content_type}: upstream got it"
        );
        assert!(!setup.agent_saw(&marker), "{content_type}: not inspected");
    }

    let status = send(setup.port, "GET", "/upload", None, Framing::Length, "");
    assert_eq!(status, 200);
    let status = send(setup.port, "POST", "/upload", None, Framing::Length, "");
    assert_eq!(status, 200);
    let status = send(setup.port, "POST", "/upload", None, Framing::ZeroLength, "");
    assert_eq!(status, 200);
    assert!(
        setup.events.lock().unwrap().is_empty(),
        "no body event for requests without a body: {:?}",
        setup.events.lock().unwrap()
    );
}

/// With a list that names one type, the suffix rule follows that entry, and a
/// body without a `Content-Type` is still sent.
#[test]
fn an_explicit_list_covers_suffix_types_of_its_entries_and_bodies_without_content_type() {
    let setup = setup(
        "waf {\n    mode \"off\"\n    body-inspection {\n        content-types \"application/xml\"\n    }\n}",
    );

    let status = setup.post(Some("application/soap+xml"), "<soap-body/>");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("<soap-body/>"), "an xml entry covers +xml");

    let status = setup.post(Some("application/vnd.api+json"), "json-body");
    assert_eq!(status, 200);
    assert!(
        !setup.agent_saw("json-body"),
        "an xml entry does not cover +json"
    );

    let status = setup.post(Some("application/json"), "plain-json-body");
    assert_eq!(status, 200);
    assert!(!setup.agent_saw("plain-json-body"));

    let status = setup.post(None, "no-content-type-body");
    assert_eq!(status, 200);
    assert!(
        setup.agent_saw("no-content-type-body"),
        "a body without a Content-Type is inspected whatever the list says"
    );
}

/// A blank `Content-Type`, and one that is not valid text, tell the proxy no
/// more than none does: the body is inspected.
#[test]
fn a_blank_or_unreadable_content_type_counts_as_none() {
    let setup = setup("waf {\n    mode \"off\"\n}");

    let status = setup.post(Some(""), "blank-content-type-body");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("blank-content-type-body"));

    let status = setup.post_raw(Some(b"\xff\xfe"), "unreadable-content-type-body");
    assert_eq!(status, 200);
    assert!(setup.backend_saw("unreadable-content-type-body"));
    assert!(setup.agent_saw("unreadable-content-type-body"));
}

/// `inspect-untyped-bodies #false` leaves a body with no usable
/// `Content-Type` to the list: it is not sent, and the matching of the
/// listed types is not touched.
#[test]
fn inspect_untyped_bodies_false_leaves_untyped_bodies_to_the_list() {
    let setup = setup(
        "waf {\n    mode \"off\"\n    body-inspection {\n        inspect-untyped-bodies #false\n    }\n}",
    );

    for (what, content_type) in [
        ("none", None),
        ("blank", Some(&b""[..])),
        ("unreadable", Some(&b"\xff\xfe"[..])),
    ] {
        let marker = format!("untyped-{what}-body");
        let status = setup.post_raw(content_type, &marker);
        assert_eq!(status, 200, "{what}");
        assert!(setup.backend_saw(&marker), "{what}: upstream got it");
        assert!(!setup.agent_saw(&marker), "{what}: not inspected");
    }
    let status = send(
        setup.port,
        "PUT",
        "/upload",
        None,
        Framing::Chunked,
        "untyped-chunked-body",
    );
    assert_eq!(status, 200);
    assert!(!setup.agent_saw("untyped-chunked-body"));

    let status = setup.post(Some("application/vnd.api+json"), "typed-suffix-body");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("typed-suffix-body"));
    let status = setup.post(Some("application/json"), "typed-json-body");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("typed-json-body"));
}

/// With `inspect-untyped-bodies #false`, an empty entry in the list still
/// matches a request with no `Content-Type`, as it always did.
#[test]
fn inspect_untyped_bodies_false_still_honours_an_empty_list_entry() {
    let setup = setup(
        "waf {\n    mode \"off\"\n    body-inspection {\n        inspect-untyped-bodies #false\n        content-types \"\" \"application/json\"\n    }\n}",
    );

    let status = setup.post(None, "untyped-body-on-empty-entry");
    assert_eq!(status, 200);
    assert!(setup.agent_saw("untyped-body-on-empty-entry"));
}

/// An untyped body is held to `max-inspection-bytes` like any inspected
/// body: with the agent failing closed, one over the limit is refused with
/// 413. `inspect-untyped-bodies #false` lets it through uninspected.
#[test]
fn an_untyped_body_over_the_limit_is_refused_unless_untyped_bodies_are_not_inspected() {
    let big = format!("big-untyped-body-{}", "x".repeat(2048));
    let waf = |untyped: &str| {
        format!(
            "waf {{\n    mode \"off\"\n    body-inspection {{\n        max-inspection-bytes 1024\n{untyped}    }}\n}}"
        )
    };

    let inspected = setup(&waf(""));
    assert_eq!(inspected.post(None, &big), 413);
    assert!(!inspected.backend_saw("big-untyped-body"));
    assert_eq!(
        inspected.post(Some("text/plain"), &big),
        200,
        "a body of a type that is not listed is not held to the limit"
    );
    assert_eq!(inspected.post(None, "small-untyped-body"), 200);
    assert!(inspected.agent_saw("small-untyped-body"));
    drop(inspected);

    let left_alone = setup(&waf("        inspect-untyped-bodies #false\n"));
    assert_eq!(left_alone.post(None, &big), 200);
    assert!(left_alone.backend_saw("big-untyped-body"));
    assert!(!left_alone.agent_saw("big-untyped-body"));
}
