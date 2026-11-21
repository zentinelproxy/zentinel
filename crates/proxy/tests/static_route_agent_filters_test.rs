//! A route's agent filters on static routes, end to end against the real
//! binary and an in-test v2 agent.
//!
//! A route with `service-type "static"` answers in `request_filter`, and
//! used to do so before the point where the route's agent filters run. An
//! agent listed in the route's `filters` was never called for it: a block, a
//! redirect or a header change did not apply, and a `failure-mode "closed"`
//! filter did not refuse anything.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestCompleteEvent, RequestHeadersEvent,
};

/// The content of the files under `www/gated/`, `www/closed/` and `www/open/`.
const GATED_FILE: &str = "GATED-FILE-CONTENT";
/// The content of `www/page.html`, which no agent filter guards.
const PLAIN_FILE: &str = "PLAIN-FILE-CONTENT";
const DENIED: &str = "DENIED-BY-AGENT";
const TARGET: &str = "https://login.example/start?next=%2F";

/// The proxy process, and the directory holding its config and files (kept alive).
struct Proxy(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port the OS chose for 127.0.0.1, free when this returns.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[derive(Debug, Clone)]
struct Seen {
    route_id: Option<String>,
    method: String,
    uri: String,
    correlation_id: String,
}

/// Decides by the request's URI and records every request headers event and
/// every request-complete notice (by correlation id).
struct Gate {
    seen: Arc<Mutex<Vec<Seen>>>,
    completed: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Gate {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("gate", "Gate", "0.1.0").with_event(EventType::RequestHeaders)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.seen.lock().unwrap().push(Seen {
            route_id: event.metadata.route_id.clone(),
            method: event.method.clone(),
            uri: event.uri.clone(),
            correlation_id: event.metadata.correlation_id.clone(),
        });
        if event.uri.contains("deny") {
            AgentResponse::block(403, Some(DENIED.to_string()))
        } else if event.uri.contains("go-elsewhere") {
            AgentResponse::redirect(TARGET.to_string(), 302)
        } else if event.uri.contains("tag") {
            AgentResponse::default_allow().add_response_header(HeaderOp::Set {
                name: "x-from-agent".to_string(),
                value: "yes".to_string(),
            })
        } else {
            AgentResponse::default_allow()
        }
    }

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        self.completed.lock().unwrap().push(event.correlation_id);
        AgentResponse::default_allow()
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

fn get(port: u16, path: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
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

/// `www/`: four files under each of `gated/`, `closed/` and `open/`, and
/// `page.html` at the top.
fn write_files(root: &Path) {
    for dir in ["gated", "closed", "open"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
        for name in ["page.html", "deny.html", "go-elsewhere.html", "tag.html"] {
            std::fs::write(root.join(dir).join(name), GATED_FILE).unwrap();
        }
    }
    std::fs::write(root.join("page.html"), PLAIN_FILE).unwrap();
}

fn spawn_proxy(dir: tempfile::TempDir, config: &str, port: u16) -> Proxy {
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
        dir,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    proxy
}

struct Setup {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    completed: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
}

impl Setup {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// A proxy with a static route whose filter runs the agent `gate`, and a
/// static route with no filters.
fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("gate.sock");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(Mutex::new(Vec::new()));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new(
        "gate",
        socket.clone(),
        Box::new(Gate {
            seen: seen.clone(),
            completed: completed.clone(),
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

    let root = dir.path().join("www");
    write_files(&root);
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
agents {{
    agent "gate" type="custom" {{
        unix-socket "{socket}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "gate" {{
        type "agent"
        agent "gate"
        failure-mode "closed"
    }}
}}
routes {{
    route "gated-site" {{
        matches {{ path-prefix "/gated/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
        filters "gate"
    }}
    route "plain-site" {{
        matches {{ path-prefix "/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
        root = root.display()
    );
    let proxy = spawn_proxy(dir, &config, port);

    // Wait until the agent is connected: the closed filter answers 503 until
    // then. Serving the file is never right, whether the agent is up or not.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let probe = get(port, "/gated/deny.html");
        if probe.status == 403 && probe.body.contains(DENIED) {
            break;
        }
        assert_ne!(
            probe.status,
            200,
            "the file was served although the route's agent filter denies it: {probe:?}, seen {:?}",
            seen.lock().unwrap()
        );
        assert!(
            Instant::now() < deadline,
            "the agent never answered for a static route: {probe:?}, seen {:?}",
            seen.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        port,
        seen,
        completed,
        _proxy: proxy,
        _rt: rt,
    }
}

#[test]
fn static_route_agent_filter_receives_the_request_and_can_allow_it() {
    let setup = setup();

    let resp = get(setup.port, "/gated/page.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.body, GATED_FILE, "{resp:?}");

    let seen = setup.seen();
    let event = seen
        .iter()
        .find(|s| s.uri == "/gated/page.html")
        .unwrap_or_else(|| panic!("the agent never saw /gated/page.html: {seen:?}"));
    assert_eq!(event.route_id.as_deref(), Some("gated-site"));
    assert_eq!(event.method, "GET");
    assert!(!event.correlation_id.is_empty(), "{event:?}");
}

/// The agent is told once when the request ends, under the correlation id it
/// was given with the request headers.
#[test]
fn static_route_agent_filter_gets_one_correlation_id_for_the_request() {
    let setup = setup();

    let resp = get(setup.port, "/gated/page.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    let id = setup
        .seen()
        .into_iter()
        .find(|s| s.uri == "/gated/page.html")
        .expect("the agent saw /gated/page.html")
        .correlation_id;

    let notices = |id: &str| {
        setup
            .completed
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.as_str() == id)
            .count()
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while notices(&id) == 0 {
        assert!(
            Instant::now() < deadline,
            "no request-complete notice for {id}: {:?}",
            setup.completed.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        notices(&id),
        1,
        "one notice for the request {id}: {:?}",
        setup.completed.lock().unwrap()
    );
}

#[test]
fn static_route_agent_block_replaces_the_file() {
    let setup = setup();

    let resp = get(setup.port, "/gated/deny.html");
    assert_eq!(resp.status, 403, "{resp:?}");
    assert_eq!(resp.body, DENIED, "{resp:?}");
    assert!(!resp.body.contains(GATED_FILE), "{resp:?}");
}

#[test]
fn static_route_agent_redirect_replaces_the_file() {
    let setup = setup();

    let resp = get(setup.port, "/gated/go-elsewhere.html");
    assert_eq!(resp.status, 302, "{resp:?}");
    assert_eq!(resp.header("location"), Some(TARGET), "{resp:?}");
    assert!(!resp.body.contains(GATED_FILE), "{resp:?}");
}

#[test]
fn static_route_agent_response_header_changes_reach_the_file_response() {
    let setup = setup();

    let resp = get(setup.port, "/gated/tag.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.body, GATED_FILE, "{resp:?}");
    assert_eq!(resp.header("x-from-agent"), Some("yes"), "{resp:?}");
}

#[test]
fn static_route_without_agent_filters_serves_without_consulting_agents() {
    let setup = setup();
    let before = setup.seen().len();

    let resp = get(setup.port, "/page.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.body, PLAIN_FILE, "{resp:?}");
    assert_eq!(setup.seen().len(), before, "{:?}", setup.seen());
}

/// The agent is not running. A route's `failure-mode "closed"` filter
/// refuses the request; an `"open"` one lets the file through.
#[test]
fn static_route_agent_filter_failure_mode_applies() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("gone.sock");
    let root = dir.path().join("www");
    write_files(&root);
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
agents {{
    agent "gone" type="custom" {{
        unix-socket "{socket}"
        events "request_headers"
        timeout-ms 500
        failure-mode "closed"
    }}
}}
filters {{
    filter "closed" {{
        type "agent"
        agent "gone"
        failure-mode "closed"
    }}
    filter "open" {{
        type "agent"
        agent "gone"
        failure-mode "open"
    }}
}}
routes {{
    route "closed-site" {{
        matches {{ path-prefix "/closed/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
        filters "closed"
    }}
    route "open-site" {{
        matches {{ path-prefix "/open/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
        filters "open"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
        root = root.display()
    );
    let _proxy = spawn_proxy(dir, &config, port);

    let resp = get(port, "/closed/page.html");
    assert_eq!(resp.status, 503, "{resp:?}");
    assert!(!resp.body.contains(GATED_FILE), "{resp:?}");

    let resp = get(port, "/open/page.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.body, GATED_FILE, "{resp:?}");
}
