//! A route's `error-pages` apply to the errors the proxy raises itself, not
//! only to the ones that reach `fail_to_proxy` (#557).
//!
//! Since #550 a page replaced an upstream error and an error that went
//! through `fail_to_proxy` (a 413 for a body over the limit, a dead upstream),
//! but the refusals written straight from the request filter did not use it:
//! a rate-limit 429 kept its plain-text body and a 503 over
//! `max-in-flight-requests` its JSON one. This runs the real binary against
//! a local backend and checks each refusal's body and headers, with and
//! without a page.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Two free ports from a small fixed range, so the test stays clear of
/// ports other local services are likely to use. Each test has its own
/// range: tests in this file run in parallel.
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

/// A backend answering 200 to everything, after three seconds for `/…/slow`.
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    line.clear();
                }
                if request_line.contains("/slow") {
                    std::thread::sleep(Duration::from_secs(3));
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
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

/// Send a raw HTTP/1.1 request and read the response to the end.
fn request(port: u16, method: &str, path: &str, extra: &str, body: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
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

const PAGES: &str = r#"
        error-pages {
            pages {
                "403" { format "json"; message "Custom 403 page"; }
                "413" { format "json"; message "Custom 413 page"; }
                "429" {
                    format "json"
                    message "Custom 429 page"
                    headers {
                        Retry-After "999"
                        X-Page "429"
                    }
                }
                "503" { format "json"; message "Custom 503 page"; }
            }
        }
"#;

const RATE_LIMIT: &str = r#"
        policies {
            rate-limit {
                requests-per-second 1
                burst 1
                key "client-ip"
            }
        }
"#;

/// Run the proxy with `config` and wait until it listens on `port`.
fn start_proxy(dir: &std::path::Path, port: u16, config: &str) -> Proxy {
    let path = dir.join("zentinel.kdl");
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
    proxy
}

fn limits_config(port: u16, backend: u16) -> String {
    format!(
        r#"
system {{ worker-threads 2 }}
limits {{
    max-body-size 100
    max-in-flight-requests 1
}}
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
routes {{
    route "paged" {{
        matches {{ path-prefix "/paged" }}
        upstream "backend"
        {PAGES}
    }}
    route "limited" {{
        matches {{ path-prefix "/limited" }}
        upstream "backend"
        {RATE_LIMIT}
        {PAGES}
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
    }}
    route "throttled" {{
        matches {{ path-prefix "/throttled" }}
        upstream "backend"
        {RATE_LIMIT}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

fn json(resp: &Response) -> serde_json::Value {
    serde_json::from_str(&resp.body).unwrap_or_else(|e| panic!("not JSON ({e}): {:?}", resp.body))
}

/// The first rate-limited answer from `path`.
fn rate_limited(port: u16, path: &str) -> Response {
    for _ in 0..10 {
        let resp = request(port, "GET", path, "", "");
        if resp.status == 429 {
            return resp;
        }
    }
    panic!("{path} was never rate limited");
}

#[test]
fn a_routes_pages_apply_to_the_proxys_own_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let (port, backend) = free_ports(19550..19555);
    spawn_backend(backend);
    let _proxy = start_proxy(dir.path(), port, &limits_config(port, backend));

    // 503 over max-in-flight-requests, while a slow request holds the slot.
    let slow = std::thread::spawn(move || request(port, "GET", "/paged/slow", "", ""));
    std::thread::sleep(Duration::from_millis(700));
    let paged = request(port, "GET", "/paged", "", "");
    let plain = request(port, "GET", "/open", "", "");
    assert_eq!(slow.join().unwrap().status, 200);

    assert_eq!(paged.status, 503, "{:?}", paged.body);
    assert_eq!(json(&paged)["message"], "Custom 503 page");
    assert_eq!(paged.header("retry-after"), Some("1"));
    assert_eq!(plain.status, 503);
    assert_eq!(plain.header("content-type"), Some("application/json"));
    assert_eq!(json(&plain)["error"], "503 Service Unavailable");
    assert_eq!(plain.header("retry-after"), Some("1"));

    // 429 from the route's rate limit: the page, with the rate-limit
    // headers. The proxy's Retry-After wins over the page's.
    let paged = rate_limited(port, "/limited");
    assert_eq!(
        json(&paged)["message"],
        "Custom 429 page",
        "{:?}",
        paged.body
    );
    assert_eq!(paged.header("x-page"), Some("429"));
    assert_eq!(paged.header("x-ratelimit-limit"), Some("1"));
    assert_eq!(paged.header("x-ratelimit-remaining"), Some("0"));
    assert!(paged.header("x-ratelimit-reset").is_some());
    let retry_after: u64 = paged.header("retry-after").unwrap().parse().unwrap();
    assert!(retry_after <= 2, "Retry-After {retry_after}");

    let plain = rate_limited(port, "/throttled");
    assert_eq!(plain.body, "Rate limit exceeded");
    assert_eq!(
        plain.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert!(plain.header("retry-after").is_some());
    assert_eq!(plain.header("x-ratelimit-limit"), Some("1"));

    // 403 for a WebSocket upgrade on a route without WebSocket.
    let upgrade = "Upgrade: websocket\r\n";
    let paged = request(port, "GET", "/paged", upgrade, "");
    assert_eq!(paged.status, 403);
    assert_eq!(json(&paged)["message"], "Custom 403 page");
    let plain = request(port, "GET", "/open", upgrade, "");
    assert_eq!(plain.status, 403);
    assert_eq!(plain.body, "WebSocket not enabled for this route");

    // 413, which went through `fail_to_proxy` already (#550).
    let big = "x".repeat(200);
    let paged = request(port, "POST", "/paged", "", &big);
    assert_eq!(paged.status, 413);
    assert_eq!(json(&paged)["message"], "Custom 413 page");
    let plain = request(port, "POST", "/open", "", &big);
    assert_eq!(plain.status, 413);
    assert_eq!(json(&plain)["error"], "413 Payload Too Large");
}

// ============================================================================
// Agent blocks
// ============================================================================

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{
    AgentResponse, EventType, RequestBodyChunkEvent, RequestHeadersEvent,
};

/// Blocks by path on request headers and by content on request bodies,
/// with or without a body of its own. Its bodies are text no one else
/// sends, so a response carrying one proves the agent was consulted.
struct BlockingAgent;

#[async_trait::async_trait]
impl AgentHandlerV2 for BlockingAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("blocker", "Blocking Agent", "0.1.0")
            .with_event(EventType::RequestBodyChunk)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if event.uri.contains("/with-body") {
            AgentResponse::block(403, Some("agent header says no".to_string()))
        } else if event.uri.contains("/bare") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        let data = String::from_utf8_lossy(&data);
        if data.contains("evil-with-body") {
            AgentResponse::block(403, Some("agent body says no".to_string()))
        } else if data.contains("evil-bare") {
            AgentResponse::block(403, None)
        } else {
            AgentResponse::default_allow()
        }
    }
}

/// An agent's block with a body of its own sends that body, in either
/// phase; one without a body gets the route's page for the status.
///
/// Before #557 a header-phase block without a body was answered with the
/// text "Blocked by agent" whatever the route's pages, and a body-phase
/// block with a body lost it to the page (or to the generic JSON).
#[test]
fn an_agents_own_body_wins_over_the_page_and_a_bare_block_gets_it() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("blocker.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = UdsAgentServerV2::new("blocker", socket.clone(), Box::new(BlockingAgent));
    rt.spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the agent never listened");
        std::thread::sleep(Duration::from_millis(50));
    }

    let (port, backend) = free_ports(19555..19560);
    spawn_backend(backend);
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
    agent "blocker" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "request_body"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "blocker" {{
        type "agent"
        agent "blocker"
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
    route "paged" {{
        matches {{ path-prefix "/paged" }}
        upstream "backend"
        filters "blocker"
        policies {{ failure-mode "closed"; }}
        {PAGES}
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        filters "blocker"
        policies {{ failure-mode "closed"; }}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        socket = socket.display()
    );
    let _proxy = start_proxy(dir.path(), port, &config);

    // The agent is consulted and lets other requests through.
    let mut allowed = request(port, "GET", "/paged/fine", "", "");
    for _ in 0..50 {
        if allowed.status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        allowed = request(port, "GET", "/paged/fine", "", "");
    }
    assert_eq!(allowed.status, 200, "{:?}", allowed.body);

    for route in ["/paged", "/open"] {
        // Header phase, the agent's own body.
        let resp = request(port, "GET", &format!("{route}/with-body"), "", "");
        assert_eq!(resp.status, 403, "{route}");
        assert_eq!(resp.body, "agent header says no", "{route}");

        // Body phase, the agent's own body.
        let resp = request(
            port,
            "POST",
            &format!("{route}/upload"),
            "Content-Type: application/json\r\n",
            "evil-with-body",
        );
        assert_eq!(resp.status, 403, "{route}");
        assert_eq!(resp.body, "agent body says no", "{route}");
    }

    // Blocks without a body: the page where the route has one.
    let resp = request(port, "GET", "/paged/bare", "", "");
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["message"], "Custom 403 page", "{:?}", resp.body);
    let resp = request(
        port,
        "POST",
        "/paged/upload",
        "Content-Type: application/json\r\n",
        "evil-bare",
    );
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["message"], "Custom 403 page", "{:?}", resp.body);

    // ... and the defaults where it has none, as before.
    let resp = request(port, "GET", "/open/bare", "", "");
    assert_eq!(resp.status, 403);
    assert_eq!(resp.body, "Blocked by agent");
    let resp = request(
        port,
        "POST",
        "/open/upload",
        "Content-Type: application/json\r\n",
        "evil-bare",
    );
    assert_eq!(resp.status, 403);
    assert_eq!(json(&resp)["error"], "403 Forbidden", "{:?}", resp.body);
}
