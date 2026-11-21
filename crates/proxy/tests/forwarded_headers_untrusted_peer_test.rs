//! Headers a client sends to say where its request came from (client address,
//! scheme, port, original URL or host), end to end against the real binary.
//!
//! The proxy rebuilds `X-Forwarded-For`, `-Proto` and `-Host` for a peer that
//! is not in the listener's `trusted-proxies`. The other headers of that kind
//! (`X-Forwarded-Port`, `X-Original-URL`, `True-Client-IP`, ...) used to reach
//! agents and the upstream with the client's values. This checks that both
//! see the same, cleaned request, and that a peer in `trusted-proxies` is
//! passed on unchanged.
//!
//! One proxy, two listeners, routes with an agent that records the request
//! headers it is shown, and a backend that records the head it receives. Every
//! client is `127.0.0.1`; only the second listener lists it as trusted. A
//! header an agent or a route policy writes itself comes after the removal and
//! still reaches the upstream.

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
use zentinel_agent_protocol::{AgentResponse, EventType, HeaderOp, RequestHeadersEvent};

/// Headers the proxy does not pass on from a peer outside `trusted-proxies`.
const FORWARDING_HEADERS: &[&str] = &[
    "Forwarded",
    "X-Real-IP",
    "X-Client-IP",
    "X-Cluster-Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "Client-IP",
    "X-Originating-IP",
    "X-Envoy-External-Address",
    "X-Azure-ClientIP",
    "X-Appengine-User-IP",
    "X-Forwarded-Port",
    "X-Forwarded-Ssl",
    "X-Forwarded-Scheme",
    "X-Forwarded-Protocol",
    "X-Scheme",
    "X-Url-Scheme",
    "Front-End-Https",
    "CF-Visitor",
    "X-Forwarded-Prefix",
    "X-Forwarded-Server",
    "X-Forwarded-Uri",
    "X-Forwarded-Path",
    "X-Original-URL",
    "X-Original-URI",
    "X-Original-Host",
    "X-Rewrite-URL",
];

const VALUE: &str = "198.51.100.7";

/// Headers one request had, by lowercase name.
type Headers = HashMap<String, Vec<String>>;

/// What the backend and the agent each saw, keyed by request path.
#[derive(Default)]
struct Seen {
    backend: Mutex<HashMap<String, Headers>>,
    agent: Mutex<HashMap<String, Headers>>,
}

/// A backend answering 200 to everything and recording each request's headers.
fn spawn_backend(listener: TcpListener, seen: Arc<Seen>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let mut headers = Headers::new();
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        headers
                            .entry(name.trim().to_ascii_lowercase())
                            .or_default()
                            .push(value.trim().to_string());
                    }
                    line.clear();
                }
                seen.backend.lock().unwrap().insert(path, headers);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"
                );
            });
        }
    });
}

/// The value the agent writes for `X-Real-IP` on [`AGENT_PATH`], and the one
/// the route policy writes for `True-Client-IP` on [`POLICY_PATH`].
const AGENT_VALUE: &str = "192.0.2.2";
const POLICY_VALUE: &str = "192.0.2.1";
const AGENT_PATH: &str = "/agent-sets";
const POLICY_PATH: &str = "/policy-sets";

/// Records the request headers it is shown and allows everything. On
/// [`AGENT_PATH`] it also sets `X-Real-IP`.
struct Recorder(Arc<Seen>);

#[async_trait::async_trait]
impl AgentHandlerV2 for Recorder {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("recorder", "Recorder", "0.1.0")
            .with_event(EventType::RequestHeaders)
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0
            .agent
            .lock()
            .unwrap()
            .insert(event.uri.clone(), event.headers.clone());
        let mut response = AgentResponse::default_allow();
        if event.uri == AGENT_PATH {
            response = response.add_request_header(HeaderOp::Set {
                name: "X-Real-IP".to_string(),
                value: AGENT_VALUE.to_string(),
            });
        }
        response
    }
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Setup {
    /// Listener without `trusted-proxies`, and the one that lists `127.0.0.1`.
    untrusted_port: u16,
    trusted_port: u16,
    seen: Arc<Seen>,
    _proxy: Proxy,
    _rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

/// An address the OS had free a moment ago.
fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// GET `path` from `127.0.0.1` with `extra` request headers; returns the status.
fn get(port: u16, path: &str, extra: &[(&str, &str)]) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = format!("GET {path} HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n");
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw)
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("recorder.sock");
    let seen = Arc::new(Seen::default());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server =
        UdsAgentServerV2::new("recorder", socket.clone(), Box::new(Recorder(seen.clone())));
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
    spawn_backend(backend, seen.clone());
    let (untrusted_port, trusted_port) = (free_port(), free_port());
    let config = format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "public" {{
        address "127.0.0.1:{untrusted_port}"
        protocol "http"
    }}
    listener "behind-lb" {{
        address "127.0.0.1:{trusted_port}"
        protocol "http"
        trusted-proxies "127.0.0.1"
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
        events "request_headers"
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
    route "policy" {{
        priority 100
        matches {{ path-prefix "{POLICY_PATH}" }}
        upstream "backend"
        filters "recorder"
        policies {{
            failure-mode "closed"
            request-headers {{
                set {{
                    "True-Client-IP" "{POLICY_VALUE}"
                }}
            }}
        }}
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
    while TcpStream::connect(("127.0.0.1", untrusted_port)).is_err()
        || TcpStream::connect(("127.0.0.1", trusted_port)).is_err()
    {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    // Wait until the agent is connected and consulted.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = get(untrusted_port, "/probe", &[]);
        if status == 200 && seen.agent.lock().unwrap().contains_key("/probe") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the agent was never consulted (status {status})"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    Setup {
        untrusted_port,
        trusted_port,
        seen,
        _proxy: proxy,
        _rt: rt,
        _dir: dir,
    }
}

/// `name` as written, and with `-` written as `_` (some servers read the two
/// the same) when that is a different name.
fn spellings(name: &str) -> Vec<String> {
    let mut spellings = vec![name.to_string()];
    let underscored = name.replace('-', "_");
    if underscored != name {
        spellings.push(underscored);
    }
    spellings
}

/// Request `path` on `port` with every forwarding header set to [`VALUE`], in
/// its usual spelling and with underscores, and an `X-Forwarded-For` of its
/// own; returns what the agent and the backend saw.
fn send_all_forwarding_headers(setup: &Setup, port: u16, path: &str) -> (Headers, Headers) {
    let names: Vec<String> = FORWARDING_HEADERS
        .iter()
        .flat_map(|name| spellings(name))
        .collect();
    let mut extra: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), VALUE)).collect();
    extra.push(("X-Forwarded-For", VALUE));
    extra.push(("X-Request-Id", "req-1"));
    // The three headers Zentinel writes, spelled with underscores.
    extra.push(("X_Forwarded_For", VALUE));
    extra.push(("X_Forwarded_Proto", "https"));
    extra.push(("X_Forwarded_Host", "b.example"));
    assert_eq!(get(port, path, &extra), 200, "{path}");
    let agent = setup.seen.agent.lock().unwrap().get(path).cloned();
    let backend = setup.seen.backend.lock().unwrap().get(path).cloned();
    (
        agent.unwrap_or_else(|| panic!("the agent never saw {path}")),
        backend.unwrap_or_else(|| panic!("the backend never saw {path}")),
    )
}

/// From a peer outside `trusted-proxies`, agents and the upstream both see the
/// request without the client's forwarding headers, and with the proxy's own
/// `X-Forwarded-*`.
#[test]
fn untrusted_peer_forwarding_headers_reach_neither_agent_nor_upstream() {
    let setup = setup();
    let (agent, backend) = send_all_forwarding_headers(&setup, setup.untrusted_port, "/untrusted");

    for (who, headers) in [("agent", &agent), ("upstream", &backend)] {
        for name in FORWARDING_HEADERS {
            for spelled in spellings(name) {
                let lower = spelled.to_ascii_lowercase();
                assert!(
                    !headers.contains_key(&lower),
                    "{who} received {spelled}: {headers:?}"
                );
            }
        }
        for name in ["x_forwarded_for", "x_forwarded_proto", "x_forwarded_host"] {
            assert!(
                !headers.contains_key(name),
                "{who} received {name}: {headers:?}"
            );
        }
        assert_eq!(
            headers.get("x-forwarded-for").map(Vec::as_slice),
            Some(&["127.0.0.1".to_string()][..]),
            "{who}: {headers:?}"
        );
        assert_eq!(
            headers.get("x-forwarded-proto").map(Vec::as_slice),
            Some(&["http".to_string()][..]),
            "{who}: {headers:?}"
        );
        assert_eq!(
            headers.get("x-forwarded-host").map(Vec::as_slice),
            Some(&["a.example".to_string()][..]),
            "{who}: {headers:?}"
        );
        // Headers outside the list are the client's own.
        assert_eq!(
            headers.get("x-request-id").map(Vec::as_slice),
            Some(&["req-1".to_string()][..]),
            "{who}: {headers:?}"
        );
    }
}

/// From a peer in `trusted-proxies`, the same headers are passed on as sent,
/// except the ones the proxy checks and rewrites (`X-Forwarded-*` and
/// `X-Real-IP`): a copy of those spelled with underscores is removed.
#[test]
fn trusted_peer_forwarding_headers_reach_agent_and_upstream() {
    let setup = setup();
    let (agent, backend) = send_all_forwarding_headers(&setup, setup.trusted_port, "/trusted");

    for (who, headers) in [("agent", &agent), ("upstream", &backend)] {
        for name in FORWARDING_HEADERS {
            for spelled in spellings(name) {
                let lower = spelled.to_ascii_lowercase();
                // `VALUE` is also the client IP the proxy chose for `X-Real-IP`.
                let expected = if lower == "x_real_ip" {
                    None
                } else {
                    Some(&[VALUE.to_string()][..])
                };
                assert_eq!(
                    headers.get(&lower).map(Vec::as_slice),
                    expected,
                    "{who}: {spelled}: {headers:?}"
                );
            }
        }
        for name in ["x_forwarded_for", "x_forwarded_proto", "x_forwarded_host"] {
            assert!(
                !headers.contains_key(name),
                "{who} received {name}: {headers:?}"
            );
        }
        assert_eq!(
            headers.get("x-forwarded-for").map(Vec::as_slice),
            Some(&[format!("{VALUE}, 127.0.0.1")][..]),
            "{who}: {headers:?}"
        );
    }
}

/// A header an agent or a route policy writes comes after the removal, so it
/// reaches the upstream, and what the client sent under that name does not.
#[test]
fn headers_written_by_an_agent_or_a_policy_survive_the_removal() {
    let setup = setup();

    let (agent, backend) = send_all_forwarding_headers(&setup, setup.untrusted_port, AGENT_PATH);
    assert!(!agent.contains_key("x-real-ip"), "{agent:?}");
    assert_eq!(
        backend.get("x-real-ip").map(Vec::as_slice),
        Some(&[AGENT_VALUE.to_string()][..]),
        "{backend:?}"
    );

    let (agent, backend) = send_all_forwarding_headers(&setup, setup.untrusted_port, POLICY_PATH);
    // Policies run when the upstream request is built, after the agent.
    assert!(!agent.contains_key("true-client-ip"), "{agent:?}");
    assert_eq!(
        backend.get("true-client-ip").map(Vec::as_slice),
        Some(&[POLICY_VALUE.to_string()][..]),
        "{backend:?}"
    );
}

/// From a peer in `trusted-proxies`, a chain element that is not an address,
/// a scheme other than `http` and `https`, and a value that is not a host are
/// not passed on, and `X-Real-IP` is the client IP the proxy chose. Agents and
/// the upstream see the same request.
#[test]
fn trusted_peer_invalid_forwarding_values_reach_neither_agent_nor_upstream() {
    let setup = setup();
    let path = "/trusted-invalid";
    let extra = [
        ("X-Forwarded-For", "unknown, 198.51.100.7"),
        ("X-Forwarded-Proto", "ftp"),
        ("X-Forwarded-Host", "a.example/path"),
        ("X-Real-IP", "192.0.2.99"),
        ("Forwarded", "for=198.51.100.7;proto=https"),
    ];
    assert_eq!(get(setup.trusted_port, path, &extra), 200);
    let agent = setup.seen.agent.lock().unwrap().get(path).cloned().unwrap();
    let backend = setup
        .seen
        .backend
        .lock()
        .unwrap()
        .get(path)
        .cloned()
        .unwrap();

    for (who, headers) in [("agent", &agent), ("upstream", &backend)] {
        let one = |name: &str| headers.get(name).map(Vec::as_slice);
        assert_eq!(
            one("x-forwarded-for"),
            Some(&["198.51.100.7, 127.0.0.1".to_string()][..]),
            "{who}: {headers:?}"
        );
        assert_eq!(
            one("x-forwarded-proto"),
            Some(&["http".to_string()][..]),
            "{who}: {headers:?}"
        );
        assert_eq!(
            one("x-forwarded-host"),
            Some(&["a.example".to_string()][..]),
            "{who}: {headers:?}"
        );
        assert_eq!(
            one("x-real-ip"),
            Some(&["198.51.100.7".to_string()][..]),
            "{who}: {headers:?}"
        );
        // `Forwarded` is passed on as the peer sent it.
        assert_eq!(
            one("forwarded"),
            Some(&["for=198.51.100.7;proto=https".to_string()][..]),
            "{who}: {headers:?}"
        );
    }
}
