//! A reload that adds an agent or renames one keeps inspecting requests.
//!
//! The agent manager was built once at startup, so after a reload that added
//! an agent, or changed an agent's id, the route's filter named an agent the
//! manager did not have. Nothing was left to run, the request was allowed
//! (whatever the filter's `failure-mode`), and the log said the reload
//! succeeded. This runs the real binary with a small blocking agent on a Unix
//! socket and checks over HTTP, before and after a SIGHUP, that a POST the
//! agent blocks is still blocked.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, RequestHeadersEvent};

/// The proxy's port is released just before it binds it, so the tests run one
/// at a time.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// An agent that blocks every request carrying `x-block`, with a 403.
struct BlockingAgent;

#[async_trait::async_trait]
impl AgentHandlerV2 for BlockingAgent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("blocking-agent", "Blocking Agent", "0.1.0")
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        if event.headers.contains_key("x-block") {
            AgentResponse::block(403, Some("blocked by agent".to_string()))
        } else {
            AgentResponse::default_allow()
        }
    }
}

/// Run the blocking agent on `socket` from its own thread and runtime.
fn spawn_agent(socket: &Path) {
    let socket = socket.to_path_buf();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let _ = UdsAgentServerV2::new("blocking", socket, Box::new(BlockingAgent))
                    .run()
                    .await;
            });
    });
}

/// `n` listeners on ports the OS picked, kept bound.
fn free_ports(n: usize) -> Vec<TcpListener> {
    (0..n)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)).expect("bind"))
        .collect()
}

/// A backend answering 200 `ok` to every request.
fn backend(listener: TcpListener) -> u16 {
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let mut content_length = 0usize;
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                    line.clear();
                }
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
            });
        }
    });
    port
}

/// `POST /submit` with a body on `port`, with `x-block` if `block`: the status.
fn post(port: u16, block: bool) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let body = "field=value";
    let extra = if block { "X-Block: 1\r\n" } else { "" };
    write!(
        stream,
        "POST /submit HTTP/1.1\r\nHost: test\r\n{extra}Content-Type: \
         application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Proxy {
    fn sighup(&self) {
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.0.id() as libc::pid_t, libc::SIGHUP) },
            0
        );
    }
}

/// A config with the agent declared as `agent_id`, or with no agents, filters
/// or route filters at all when `agent_id` is `None`.
fn config(listen: u16, backend: u16, socket: &Path, agent_id: Option<&str>) -> String {
    let (agents, filters, route_filters) = match agent_id {
        Some(id) => (
            format!(
                r#"agents {{
    agent "{id}" {{
        type "custom"
        unix-socket path="{socket}"
        events "request_headers"
        timeout-ms 1000
        failure-mode "closed"
    }}
}}"#,
                socket = socket.display()
            ),
            format!(
                r#"filters {{
    filter "inspect" {{
        type "agent"
        agent "{id}"
        failure-mode "closed"
    }}
}}"#
            ),
            r#"filters "inspect""#.to_string(),
        ),
        None => (String::new(), String::new(), String::new()),
    };
    format!(
        r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{ address "127.0.0.1:{listen}"; protocol "http"; }}
}}
{agents}
{filters}
upstreams {{
    upstream "app" {{ target "127.0.0.1:{backend}"; }}
}}
routes {{
    route "health" {{
        priority "critical"
        matches {{ path "/health"; }}
        builtin-handler "health"
    }}
    route "app" {{
        matches {{ path-prefix "/"; }}
        upstream "app"
        {route_filters}
    }}
}}
observability {{
    metrics {{ enabled #false; }}
}}
"#
    )
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

fn start(path: &Path, listen: u16) -> Proxy {
    let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let proxy = Proxy(child);
    wait_for("the proxy to serve", || {
        TcpStream::connect(("127.0.0.1", listen)).is_ok()
    });
    proxy
}

/// Rewrite the config and SIGHUP, then wait for `ready` to hold.
fn reload(proxy: &Proxy, path: &Path, new_config: &str, ready: impl FnMut() -> bool) {
    std::fs::write(path, new_config).unwrap();
    proxy.sighup();
    wait_for("the reloaded config", ready);
}

#[test]
fn reload_that_adds_an_agent_inspects_requests() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ports = free_ports(2);
    let backend = backend(ports.pop().unwrap());
    let listen = ports.pop().unwrap().local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    spawn_agent(&socket);
    wait_for("the agent socket", || socket.exists());

    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(listen, backend, &socket, None)).unwrap();
    let proxy = start(&path, listen);

    // No agent yet: the request the agent would block goes through.
    assert_eq!(post(listen, true), 200);

    // The reload adds the agent, its filter and the route's `filters`. The
    // POST it blocks must now be blocked; an ordinary POST still goes through.
    reload(
        &proxy,
        &path,
        &config(listen, backend, &socket, Some("inspect-agent")),
        || post(listen, true) == 403,
    );
    assert_eq!(post(listen, false), 200);
}

#[test]
fn reload_that_renames_an_agent_keeps_inspecting_requests() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ports = free_ports(2);
    let backend = backend(ports.pop().unwrap());
    let listen = ports.pop().unwrap().local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    spawn_agent(&socket);
    wait_for("the agent socket", || socket.exists());

    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(listen, backend, &socket, Some("first"))).unwrap();
    let proxy = start(&path, listen);

    wait_for("the agent to answer", || post(listen, true) == 403);

    // The agent, its filter and the route's reference all change id. The
    // route is rebuilt on reload, so it now names an agent the manager had
    // never loaded: it must be loaded, and the POST still blocked, with no
    // request in between let through.
    std::fs::write(&path, config(listen, backend, &socket, Some("second"))).unwrap();
    proxy.sighup();

    // No pause between the requests: the window is the time between the new
    // config becoming current and the agents it names being loaded, which a
    // slow poll steps over.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        assert_eq!(post(listen, true), 403, "a blocked POST was let through");
    }
    assert_eq!(post(listen, false), 200);
}
