//! A route's `filters` on `service-type "builtin"` routes, end to end against
//! the real binary and an in-test v2 agent.
//!
//! A builtin route (`builtin-handler "status"`, `"health"`, ...) was answered
//! in `early_request_filter`, ahead of `request_filter`, where a route's
//! request filters run. The request-side filters written on such a route
//! (rate limit, redirect, agents) were never applied. The response-side
//! `headers` filter already was, through `write_http_response`; its test here
//! checks that this still holds. A builtin route without `filters` is still
//! answered early, and no builtin route is counted against
//! `limits { max-in-flight-requests }`.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, HeaderOp, RequestCompleteEvent, RequestHeadersEvent,
};

const DENIED: &str = "DENIED-BY-AGENT";
/// An in-flight limit no test here comes near.
const ROOMY: &str = "max-in-flight-requests 1000";
const TARGET: &str = "https://login.example/start?next=%2F";

/// The proxy process, and the directory holding its config (kept alive).
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
            AgentResponse::default_allow().add_response_header(HeaderOp::Add {
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

    /// How many headers there are with this name.
    fn header_count(&self, name: &str) -> usize {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .count()
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", self.body))
    }
}

/// The body of a `Transfer-Encoding: chunked` message.
fn dechunk(mut raw: &str) -> String {
    let mut out = String::new();
    while let Some((size, rest)) = raw.split_once("\r\n") {
        let size =
            usize::from_str_radix(size.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if size == 0 || rest.len() < size {
            break;
        }
        out.push_str(&rest[..size]);
        raw = rest[size..].strip_prefix("\r\n").unwrap_or(&rest[size..]);
    }
    out
}

fn get(port: u16, path: &str) -> Response {
    get_with(port, path, "")
}

/// `extra` is header lines, each ending in "\r\n".
fn get_with(port: u16, path: &str, extra: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}\r\n"
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
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    Response {
        status,
        headers,
        body: if chunked {
            dechunk(body)
        } else {
            body.to_string()
        },
    }
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
    /// The upstream of the `held` and `proxied` routes, bound and not yet accepting.
    backend: TcpListener,
    seen: Arc<Mutex<Vec<Seen>>>,
    completed: Arc<Mutex<Vec<String>>>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
}

impl Setup {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Wait until the proxy has the agent connected, through a proxied route
    /// whose filter runs it (its closed filter answers 503 until then).
    fn wait_for_agent(&self) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let probe = get(self.port, "/proxied/deny");
            if probe.status == 403 && probe.body.contains(DENIED) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "the agent never answered: {probe:?}, seen {:?}",
                self.seen()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// A proxy with builtin routes whose filters run the agent `gate`, a rate
/// limit, and a response header; a builtin route with no filters; and two
/// proxied routes. `limits` is the body of the config's `limits` block.
fn setup(limits: &str) -> Setup {
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

    let backend = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = backend.local_addr().unwrap().port();
    let port = free_port();
    let config = format!(
        r#"
system {{ worker-threads 2 }}
limits {{
    {limits}
}}
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
    filter "tight" {{
        type "rate-limit"
        max-rps 1
        burst 1
        key "client-ip"
        on-limit "reject"
        status-code 429
    }}
    filter "mark" {{
        type "headers"
        phase "response"
        set {{
            "X-Filter" "applied"
        }}
    }}
    filter "moved" {{
        type "redirect"
        status-code 301
        scheme "https"
        hostname "login.example"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend_port}"
    }}
}}
routes {{
    route "gated-status" {{
        matches {{ path-prefix "/gated/" }}
        service-type "builtin"
        builtin-handler "status"
        filters "gate"
    }}
    route "limited-health" {{
        matches {{ path-prefix "/limited/" }}
        service-type "builtin"
        builtin-handler "health"
        filters "tight"
    }}
    route "marked-health" {{
        matches {{ path-prefix "/marked/" }}
        service-type "builtin"
        builtin-handler "health"
        filters "mark"
    }}
    route "moved-status" {{
        matches {{ path-prefix "/moved/" }}
        service-type "builtin"
        builtin-handler "status"
        filters "moved"
    }}
    route "plain-health" {{
        matches {{ path "/health" }}
        service-type "builtin"
        builtin-handler "health"
    }}
    route "proxied" {{
        matches {{ path-prefix "/proxied/" }}
        upstream "backend"
        filters "gate"
    }}
    route "held" {{
        matches {{ path-prefix "/held/" }}
        upstream "backend"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
    );
    let proxy = spawn_proxy(dir, &config, port);
    Setup {
        port,
        backend,
        seen,
        completed,
        _proxy: proxy,
        _rt: rt,
    }
}

#[test]
fn builtin_route_agent_filter_receives_the_request_and_can_allow_it() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();

    let resp = get(setup.port, "/gated/page");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "ok", "{resp:?}");

    let seen = setup.seen();
    let event = seen
        .iter()
        .find(|s| s.uri == "/gated/page")
        .unwrap_or_else(|| panic!("the agent never saw /gated/page: {seen:?}"));
    assert_eq!(event.route_id.as_deref(), Some("gated-status"));
    assert_eq!(event.method, "GET");
    // The response carries the id the agent was called under.
    assert!(!event.correlation_id.is_empty(), "{event:?}");
    assert_eq!(
        resp.header("x-request-id"),
        Some(event.correlation_id.as_str()),
        "{resp:?}"
    );
}

/// The agent is told when the request ends, under the correlation id it was
/// given with the request headers. (Not counted: a second notice could arrive
/// after any wait this test makes.)
#[test]
fn builtin_route_agent_filter_gets_the_request_complete_notice_under_the_same_id() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();

    let resp = get(setup.port, "/gated/page");
    assert_eq!(resp.status, 200, "{resp:?}");
    let id = setup
        .seen()
        .into_iter()
        .find(|s| s.uri == "/gated/page")
        .expect("the agent saw /gated/page")
        .correlation_id;

    let deadline = Instant::now() + Duration::from_secs(10);
    while !setup.completed.lock().unwrap().contains(&id) {
        assert!(
            Instant::now() < deadline,
            "no request-complete notice for {id}: {:?}",
            setup.completed.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn builtin_route_agent_block_replaces_the_builtin_response() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();

    let resp = get(setup.port, "/gated/deny");
    assert_eq!(resp.status, 403, "{resp:?}");
    assert_eq!(resp.body, DENIED, "{resp:?}");
}

#[test]
fn builtin_route_agent_redirect_replaces_the_builtin_response() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();

    let resp = get(setup.port, "/gated/go-elsewhere");
    assert_eq!(resp.status, 302, "{resp:?}");
    assert_eq!(resp.header("location"), Some(TARGET), "{resp:?}");
    assert!(!resp.body.contains("\"status\""), "{resp:?}");
}

#[test]
fn builtin_route_agent_response_header_changes_reach_the_builtin_response() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();

    let resp = get(setup.port, "/gated/tag");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "ok", "{resp:?}");
    assert_eq!(resp.header("x-from-agent"), Some("yes"), "{resp:?}");
    assert_eq!(resp.header_count("x-from-agent"), 1, "{resp:?}");
}

#[test]
fn builtin_route_rate_limit_filter_refuses_over_the_limit() {
    let setup = setup(ROOMY);

    // One request fits the burst; the filter's limit is one per second, so
    // a run of requests goes over it.
    let mut statuses = Vec::new();
    for _ in 0..10 {
        let resp = get(setup.port, "/limited/health");
        statuses.push(resp.status);
        if resp.status == 429 {
            assert!(resp.header("x-ratelimit-limit").is_some(), "{resp:?}");
            assert!(!resp.body.contains("healthy"), "{resp:?}");
            assert_eq!(statuses[0], 200, "{statuses:?}");
            return;
        }
    }
    panic!("the route's rate limit never refused a request: {statuses:?}");
}

#[test]
fn builtin_route_redirect_filter_redirects() {
    let setup = setup(ROOMY);

    let resp = get(setup.port, "/moved/page");
    assert_eq!(resp.status, 301, "{resp:?}");
    assert_eq!(
        resp.header("location"),
        Some("https://login.example/moved/page"),
        "{resp:?}"
    );
    assert!(!resp.body.contains("\"status\""), "{resp:?}");
}

/// Already applied before: the response-side filters run where the handler's
/// response is written. This pins that it stays so.
#[test]
fn builtin_route_response_header_filter_applies() {
    let setup = setup(ROOMY);

    let resp = get(setup.port, "/marked/health");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "healthy", "{resp:?}");
    assert_eq!(resp.header("x-filter"), Some("applied"), "{resp:?}");
}

#[test]
fn builtin_route_without_filters_answers_without_consulting_agents() {
    let setup = setup(ROOMY);
    setup.wait_for_agent();
    let before = setup.seen().len();

    let resp = get(setup.port, "/health");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "healthy", "{resp:?}");
    assert_eq!(setup.seen().len(), before, "{:?}", setup.seen());
}

/// While one request holds the only in-flight slot, a proxied route is
/// refused with 503, and builtin routes are still answered, with filters or
/// without: a health check must not fail because the proxy is busy.
#[test]
fn builtin_routes_are_not_refused_over_the_in_flight_limit() {
    let setup = setup("max-in-flight-requests 1");
    setup.wait_for_agent();

    // A backend that takes the request and holds the response until told.
    let (accepted_tx, accepted_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let listener = setup.backend.try_clone().unwrap();
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).unwrap();
            if n == 0 {
                return;
            }
            head.extend_from_slice(&buf[..n]);
        }
        accepted_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(30));
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nheld");
    });
    let port = setup.port;
    let slow = std::thread::spawn(move || get(port, "/held/slow"));
    accepted_rx
        .recv_timeout(Duration::from_secs(15))
        .expect("the held request never reached the backend");

    // The slot is taken: a proxied route is refused ...
    let refused = get(setup.port, "/held/other");
    assert_eq!(refused.status, 503, "{refused:?}");
    // ... and the builtin routes are answered.
    let with_filters = get(setup.port, "/gated/page");
    assert_eq!(with_filters.status, 200, "{with_filters:?}");
    assert_eq!(with_filters.json()["status"], "ok", "{with_filters:?}");
    let without_filters = get(setup.port, "/health");
    assert_eq!(without_filters.status, 200, "{without_filters:?}");
    assert_eq!(
        without_filters.json()["status"],
        "healthy",
        "{without_filters:?}"
    );

    release_tx.send(()).unwrap();
    let held = slow.join().unwrap();
    assert_eq!(held.status, 200, "{held:?}");
    assert_eq!(held.body, "held", "{held:?}");
    backend.join().unwrap();
}

/// The agent is not running. A route's `failure-mode "closed"` filter
/// refuses the request; an `"open"` one lets the builtin response through.
#[test]
fn builtin_route_agent_filter_failure_mode_applies() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("gone.sock");
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
    route "closed-status" {{
        matches {{ path-prefix "/closed/" }}
        service-type "builtin"
        builtin-handler "status"
        filters "closed"
    }}
    route "open-status" {{
        matches {{ path-prefix "/open/" }}
        service-type "builtin"
        builtin-handler "status"
        filters "open"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display(),
    );
    let _proxy = spawn_proxy(dir, &config, port);

    let resp = get(port, "/closed/page");
    assert_eq!(resp.status, 503, "{resp:?}");
    assert!(!resp.body.contains("\"status\": \"ok\""), "{resp:?}");

    let resp = get(port, "/open/page");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "ok", "{resp:?}");
}

/// A builtin route that has `filters` is limited by `rate-limits` like a
/// proxied route; one without filters is answered first and is not.
fn builtin_routes_under_rate_limits(rate_limits: &str) {
    let dir = tempfile::tempdir().unwrap();
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
rate-limits {{
    {rate_limits}
}}
filters {{
    filter "mark" {{
        type "headers"
        phase "response"
        set {{
            "X-Filter" "applied"
        }}
    }}
}}
routes {{
    route "marked-health" {{
        matches {{ path-prefix "/marked/" }}
        service-type "builtin"
        builtin-handler "health"
        filters "mark"
    }}
    route "plain-health" {{
        matches {{ path "/health" }}
        service-type "builtin"
        builtin-handler "health"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    );
    let _proxy = spawn_proxy(dir, &config, port);

    let plain: Vec<u16> = (0..10).map(|_| get(port, "/health").status).collect();
    assert!(plain.iter().all(|s| *s == 200), "{plain:?}");

    let marked: Vec<u16> = (0..10)
        .map(|_| get(port, "/marked/health").status)
        .collect();
    assert_eq!(marked[0], 200, "{marked:?}");
    assert!(marked.contains(&429), "{marked:?}");
}

#[test]
fn builtin_route_with_filters_is_subject_to_the_default_rate_limit() {
    builtin_routes_under_rate_limits("default-rps 1\n    default-burst 1");
}

#[test]
fn builtin_route_with_filters_is_subject_to_the_global_rate_limit() {
    builtin_routes_under_rate_limits("global {\n        max-rps 1\n        burst 1\n    }");
}

/// `max-header-count` and `max-header-size` refuse a request on a static
/// route and on a builtin route with `filters`, as they do on a proxied one.
#[test]
fn static_and_builtin_routes_refuse_headers_over_the_limits() {
    const FILE: &str = "STATIC-FILE-CONTENT";
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("www");
    std::fs::create_dir_all(root.join("static")).unwrap();
    std::fs::write(root.join("static/page.html"), FILE).unwrap();
    let port = free_port();
    let config = format!(
        r#"
system {{ worker-threads 2 }}
limits {{
    max-header-count 8
    max-header-size 400
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
filters {{
    filter "mark" {{
        type "headers"
        phase "response"
        set {{
            "X-Filter" "applied"
        }}
    }}
}}
routes {{
    route "static-site" {{
        matches {{ path-prefix "/static/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
    }}
    route "marked-status" {{
        matches {{ path-prefix "/marked/" }}
        service-type "builtin"
        builtin-handler "status"
        filters "mark"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        root = root.display()
    );
    let _proxy = spawn_proxy(dir, &config, port);

    // Within the limits, both are answered.
    let resp = get(port, "/static/page.html");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.body, FILE, "{resp:?}");
    let resp = get(port, "/marked/page");
    assert_eq!(resp.status, 200, "{resp:?}");
    assert_eq!(resp.json()["status"], "ok", "{resp:?}");

    let many: String = (0..10).map(|i| format!("X-Pad-{i}: a\r\n")).collect();
    let large = format!("X-Pad: {}\r\n", "a".repeat(1000));
    for (what, extra) in [("count", &many), ("size", &large)] {
        let resp = get_with(port, "/static/page.html", extra);
        assert_eq!(resp.status, 500, "static, header {what}: {resp:?}");
        assert!(!resp.body.contains(FILE), "static, header {what}: {resp:?}");

        let resp = get_with(port, "/marked/page", extra);
        assert_eq!(resp.status, 500, "builtin, header {what}: {resp:?}");
        assert!(
            !resp.body.contains("\"status\": \"ok\""),
            "builtin, header {what}: {resp:?}"
        );
    }
}
