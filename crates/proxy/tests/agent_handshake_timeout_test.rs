//! An agent that accepts the connection and never answers the handshake does
//! not hold the proxy's startup (#599).
//!
//! It used to: the UDS client read the handshake response with no timeout,
//! and the gRPC one waited out the request timeout (30 s unless a pool was
//! configured) for each of an agent's four connections in turn, so the
//! listener never opened -- or opened minutes late -- and `failure-mode
//! "open"` never got a chance to apply.
//!
//! This runs the real binary against a local backend with four silent
//! agents: on each transport, one that accepts the connection and sends
//! nothing at all, and one built on the SDK server whose handshake handler
//! never returns (what the TypeScript SDK's gRPC server does). The proxy must
//! serve within a few seconds, each agent's routes must follow their filter's
//! failure mode, a config reload must not wait on them either, and once a
//! working agent takes over the socket, its routes must start using it.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::{AgentHandlerV2, GrpcAgentServerV2};
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::{AgentCapabilities, HandshakeRequest, HandshakeResponse};
use zentinel_agent_protocol::{AgentResponse, EventType, HeaderOp, RequestHeadersEvent};

/// The header a working agent sets, echoed by the backend.
const AGENT_HEADER: &str = "x-agent-said";

/// Free ports from a fixed range, clear of the other integration tests.
fn free_ports<const N: usize>(range: std::ops::Range<u16>) -> [u16; N] {
    let free: Vec<u16> = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok())
        .take(N)
        .collect();
    free.try_into()
        .unwrap_or_else(|_| panic!("{N} free ports in {range:?}"))
}

/// A backend that answers `agent=<value of AGENT_HEADER>`.
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut said = String::from("<none>");
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.trim().eq_ignore_ascii_case(AGENT_HEADER) {
                            said = value.trim().to_string();
                        }
                    }
                    line.clear();
                }
                let body = format!("agent={said}");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
}

/// GET `path`; the status and the body (status 0 if nothing answered).
fn get(port: u16, path: &str) -> (u16, String) {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return (0, String::new());
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    );
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// A handler that never answers the handshake when `silent`, and otherwise
/// accepts everything and says its name in [`AGENT_HEADER`].
struct Handler {
    name: &'static str,
    silent: bool,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Handler {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(self.name, self.name, "0.1.0").with_event(EventType::RequestHeaders)
    }

    async fn on_handshake(&self, _request: HandshakeRequest) -> HandshakeResponse {
        if self.silent {
            std::future::pending::<()>().await;
        }
        HandshakeResponse::success(self.capabilities())
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow().add_request_header(HeaderOp::Set {
            name: AGENT_HEADER.to_string(),
            value: self.name.to_string(),
        })
    }
}

#[derive(Clone)]
enum Transport {
    Uds(PathBuf),
    Grpc(SocketAddr),
}

/// How an agent process behaves.
#[derive(Clone, Copy)]
enum Behaviour {
    /// Accepts connections, reads nothing, writes nothing.
    Mute,
    /// An SDK server whose handshake handler never returns.
    Hanging,
    /// An SDK server that works.
    Working,
}

/// One run of an agent process: its own runtime, so dropping it closes the
/// listener and every connection, as a crash would.
struct AgentProcess {
    rt: Option<tokio::runtime::Runtime>,
}

impl AgentProcess {
    fn start(name: &'static str, transport: &Transport, behaviour: Behaviour) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let handler = |silent| Box::new(Handler { name, silent });
        match (transport, behaviour) {
            (Transport::Uds(path), Behaviour::Mute) => {
                let _ = std::fs::remove_file(path);
                let listener = {
                    let _guard = rt.enter();
                    tokio::net::UnixListener::bind(path).unwrap()
                };
                rt.spawn(async move {
                    let mut held = Vec::new();
                    while let Ok((stream, _)) = listener.accept().await {
                        held.push(stream);
                    }
                });
            }
            (Transport::Grpc(addr), Behaviour::Mute) => {
                let listener = bind_tcp(*addr, name);
                listener.set_nonblocking(true).unwrap();
                let listener = {
                    let _guard = rt.enter();
                    tokio::net::TcpListener::from_std(listener).unwrap()
                };
                rt.spawn(async move {
                    let mut held = Vec::new();
                    while let Ok((stream, _)) = listener.accept().await {
                        held.push(stream);
                    }
                });
            }
            (Transport::Uds(path), behaviour) => {
                let silent = matches!(behaviour, Behaviour::Hanging);
                let server = UdsAgentServerV2::new(name, path.clone(), handler(silent));
                rt.spawn(async move {
                    let _ = server.run().await;
                });
            }
            (Transport::Grpc(addr), behaviour) => {
                let silent = matches!(behaviour, Behaviour::Hanging);
                drop(bind_tcp(*addr, name));
                let server = GrpcAgentServerV2::new(name, handler(silent));
                let addr = *addr;
                rt.spawn(async move {
                    let _ = server.run(addr).await;
                });
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let up = match transport {
                Transport::Uds(path) => UnixStream::connect(path).is_ok(),
                Transport::Grpc(addr) => TcpStream::connect(addr).is_ok(),
            };
            if up {
                break;
            }
            assert!(Instant::now() < deadline, "{name} never listened");
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { rt: Some(rt) }
    }
}

/// Bind `addr`, waiting for a previous run to let go of it.
fn bind_tcp(addr: SocketAddr, name: &str) -> TcpListener {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TcpListener::bind(addr) {
            Ok(listener) => return listener,
            Err(_) => {
                assert!(Instant::now() < deadline, "{name}: port {addr} stays busy");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
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

/// The agents, by name, and their transports.
fn agents(dir: &Path, grpc: [SocketAddr; 2]) -> [(&'static str, Transport, Behaviour); 4] {
    [
        (
            "uds-mute",
            Transport::Uds(dir.join("mute.sock")),
            Behaviour::Mute,
        ),
        (
            "uds-hanging",
            Transport::Uds(dir.join("hanging.sock")),
            Behaviour::Hanging,
        ),
        ("grpc-mute", Transport::Grpc(grpc[0]), Behaviour::Mute),
        ("grpc-hanging", Transport::Grpc(grpc[1]), Behaviour::Hanging),
    ]
}

/// The proxy's configuration. Every agent gets a route per failure mode,
/// `/<agent>/open` and `/<agent>/closed`; `/plain` uses no agent. With
/// `reloaded`, a `/reloaded` route is added.
fn config(
    port: u16,
    backend: u16,
    agents: &[(&'static str, Transport, Behaviour)],
    reloaded: bool,
) -> String {
    let mut agent_blocks = String::new();
    let mut filters = String::new();
    let mut routes = String::new();
    for (name, transport, _) in agents {
        let transport = match transport {
            Transport::Uds(path) => format!("unix-socket \"{}\"", path.display()),
            Transport::Grpc(addr) => format!("grpc \"http://{addr}\""),
        };
        agent_blocks.push_str(&format!(
            r#"
    agent "{name}" type="custom" {{
        {transport}
        events "request_headers"
        timeout-ms 500
        connect-timeout-ms 1000
    }}"#
        ));
        for mode in ["open", "closed"] {
            filters.push_str(&format!(
                r#"
    filter "{name}-{mode}" {{
        type "agent"
        agent "{name}"
        failure-mode "{mode}"
    }}"#
            ));
            routes.push_str(&format!(
                r#"
    route "{name}-{mode}" {{
        matches {{ path-prefix "/{name}/{mode}" }}
        upstream "backend"
        filters "{name}-{mode}"
    }}"#
            ));
        }
    }
    if reloaded {
        routes.push_str(
            r#"
    route "reloaded" {
        matches { path-prefix "/reloaded" }
        upstream "backend"
    }"#,
        );
    }
    format!(
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
agents {{{agent_blocks}
}}
filters {{{filters}
}}
routes {{{routes}
    route "plain" {{
        matches {{ path-prefix "/plain" }}
        upstream "backend"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

/// Every silent agent's routes follow their filter's failure mode, and
/// promptly: a request does not wait for the agent either.
fn assert_failure_modes(port: u16, agents: &[(&'static str, Transport, Behaviour)], when: &str) {
    for (name, _, _) in agents {
        let start = Instant::now();
        let (status, body) = get(port, &format!("/{name}/open"));
        assert_eq!(status, 200, "{when}: {name}, fail-open: {body}");
        assert_eq!(body, "agent=<none>", "{when}: {name}, fail-open");
        let (status, body) = get(port, &format!("/{name}/closed"));
        assert_eq!(status, 503, "{when}: {name}, fail-closed: {body}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{when}: {name}: requests waited {:?} for a silent agent",
            start.elapsed()
        );
    }
}

#[test]
fn a_silent_agent_does_not_hold_startup_and_is_used_once_it_answers() {
    let dir = tempfile::tempdir().unwrap();
    let [port, backend, grpc_mute, grpc_hanging] = free_ports::<4>(19740..19770);
    let agents = agents(
        dir.path(),
        [
            ([127, 0, 0, 1], grpc_mute).into(),
            ([127, 0, 0, 1], grpc_hanging).into(),
        ],
    );
    spawn_backend(backend);
    let silent: Vec<AgentProcess> = agents
        .iter()
        .map(|(name, transport, behaviour)| AgentProcess::start(name, transport, *behaviour))
        .collect();

    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(port, backend, &agents, false)).unwrap();
    let started = Instant::now();
    let proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    // Serving within a few seconds: the connect timeout is one second, and
    // every agent and connection is tried at once. Before, the listener did
    // not open at all.
    loop {
        if get(port, "/plain").0 == 200 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the proxy did not serve within 8 s with silent agents configured"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("served after {:?}", started.elapsed());
    assert_failure_modes(port, &agents, "at startup");

    // A reload does not wait on them either.
    std::fs::write(&path, config(port, backend, &agents, true)).unwrap();
    let reload = Instant::now();
    let status = Command::new("kill")
        .arg("-HUP")
        .arg(proxy.0.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    while get(port, "/reloaded").0 != 200 {
        assert!(
            reload.elapsed() < Duration::from_secs(10),
            "the reload did not take effect within 10 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(get(port, "/plain").0, 200);
    assert_failure_modes(port, &agents, "after a reload");

    // A working agent takes over each socket: the pool's background
    // reconnect finds it, and its routes go through it.
    drop(silent);
    let _working: Vec<AgentProcess> = agents
        .iter()
        .map(|(name, transport, _)| AgentProcess::start(name, transport, Behaviour::Working))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(60);
    for (name, _, _) in &agents {
        let expected = format!("agent={name}");
        loop {
            let (status, body) = get(port, &format!("/{name}/closed"));
            if status == 200 && body == expected {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{name}: never used once it answered (last: {status} {body:?})"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        let (status, body) = get(port, &format!("/{name}/open"));
        assert_eq!((status, body.as_str()), (200, expected.as_str()), "{name}");
    }
}
