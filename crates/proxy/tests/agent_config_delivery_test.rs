//! An agent's `config { }` block reaches the agent (#593).
//!
//! It used to be parsed into `AgentConfig.config` and then dropped: the
//! handshake carried `config: None`, and the `send_configure` after it ignored
//! its argument. Every agent ran on its own defaults whatever the KDL said.
//!
//! This runs the real binary against a local backend and in-test v2 agents on
//! both transports, Unix socket and gRPC. Each agent copies the configuration
//! it was given into a request header, and the backend echoes that header in
//! its body, so the client sees what the agent received. Each agent is then
//! killed and started again with no configuration of its own: what it serves
//! afterwards can only have come from the proxy's reconnect.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::{AgentHandlerV2, GrpcAgentServerV2};
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::{AgentCapabilities, HandshakeRequest, HandshakeResponse};
use zentinel_agent_protocol::{AgentResponse, EventType, HeaderOp, RequestHeadersEvent};

/// The header an agent writes its configuration into.
const CONFIG_HEADER: &str = "x-agent-config";
/// What an agent writes there when it has been given no configuration.
const UNCONFIGURED: &str = "<unconfigured>";

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

/// A backend that answers with the agent's header: `config=<value>`.
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut config = String::from("<no header>");
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.trim().eq_ignore_ascii_case(CONFIG_HEADER) {
                            config = value.trim().to_string();
                        }
                    }
                    line.clear();
                }
                let body = format!("config={config}");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
}

/// GET `path`; the status and the body.
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

/// What one agent process has seen.
#[derive(Default)]
struct Seen {
    /// The configuration of every handshake (`Null` when there was none).
    handshake_configs: Vec<serde_json::Value>,
    /// The configuration of every configure call.
    configures: Vec<serde_json::Value>,
    /// Request-headers events handled.
    requests: usize,
}

/// An agent that reports the configuration it was given in [`CONFIG_HEADER`].
///
/// With `accept: false` it rejects every configuration.
struct ConfigEcho {
    name: &'static str,
    accept: bool,
    seen: Arc<Mutex<Seen>>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for ConfigEcho {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(self.name, "Config Echo", "0.1.0")
            .with_event(EventType::RequestHeaders)
    }

    async fn on_handshake(&self, request: HandshakeRequest) -> HandshakeResponse {
        self.seen
            .lock()
            .unwrap()
            .handshake_configs
            .push(request.config);
        HandshakeResponse::success(self.capabilities())
    }

    async fn on_configure(&self, config: serde_json::Value, _version: Option<String>) -> bool {
        self.seen.lock().unwrap().configures.push(config);
        self.accept
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        let mut seen = self.seen.lock().unwrap();
        seen.requests += 1;
        let value = match seen.configures.last() {
            Some(config) => config.to_string(),
            None => UNCONFIGURED.to_string(),
        };
        AgentResponse::default_allow().add_request_header(HeaderOp::Set {
            name: CONFIG_HEADER.to_string(),
            value,
        })
    }
}

enum Transport {
    Uds(PathBuf),
    Grpc(SocketAddr),
}

/// One run of an agent process: its own runtime, so dropping it kills the
/// listener and every connection, as a crash would.
struct AgentProcess {
    rt: Option<tokio::runtime::Runtime>,
    seen: Arc<Mutex<Seen>>,
}

impl AgentProcess {
    fn start(name: &'static str, transport: &Transport, accept: bool) -> Self {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let handler = ConfigEcho {
            name,
            accept,
            seen: Arc::clone(&seen),
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        match transport {
            Transport::Uds(path) => {
                let server = UdsAgentServerV2::new(name, path.clone(), Box::new(handler));
                rt.spawn(async move {
                    let _ = server.run().await;
                });
                let deadline = Instant::now() + Duration::from_secs(10);
                while UnixStream::connect(path).is_err() {
                    assert!(Instant::now() < deadline, "{name} never listened");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            Transport::Grpc(addr) => {
                let addr = *addr;
                // The port can still be held briefly by the run before.
                let deadline = Instant::now() + Duration::from_secs(10);
                while TcpListener::bind(addr).is_err() {
                    assert!(Instant::now() < deadline, "{name}: port {addr} stays busy");
                    std::thread::sleep(Duration::from_millis(50));
                }
                let server = GrpcAgentServerV2::new(name, Box::new(handler));
                rt.spawn(async move {
                    let _ = server.run(addr).await;
                });
                let deadline = Instant::now() + Duration::from_secs(10);
                while TcpStream::connect(addr).is_err() {
                    assert!(Instant::now() < deadline, "{name} never listened");
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        Self { rt: Some(rt), seen }
    }

    fn kill(mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
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

use std::os::unix::net::UnixStream;

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(port: u16, backend: u16, uds: &Path, grpc: SocketAddr, refuser: &Path) -> String {
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
agents {{
    agent "echo-uds" type="custom" {{
        unix-socket "{uds}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
        config {{
            greeting "hello-over-uds"
            limits {{
                burst 7
            }}
        }}
    }}
    agent "echo-grpc" type="custom" {{
        grpc "http://{grpc}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
        config {{
            greeting "hello-over-grpc"
        }}
    }}
    agent "refuser" type="custom" {{
        unix-socket "{refuser}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
        config {{
            greeting "you-will-say-no"
        }}
    }}
}}
filters {{
    filter "echo-uds" {{
        type "agent"
        agent "echo-uds"
        failure-mode "closed"
    }}
    filter "echo-grpc" {{
        type "agent"
        agent "echo-grpc"
        failure-mode "closed"
    }}
    filter "refuser" {{
        type "agent"
        agent "refuser"
        failure-mode "closed"
    }}
}}
routes {{
    route "uds" {{
        matches {{ path-prefix "/uds" }}
        upstream "backend"
        filters "echo-uds"
    }}
    route "grpc" {{
        matches {{ path-prefix "/grpc" }}
        upstream "backend"
        filters "echo-grpc"
    }}
    route "refused" {{
        matches {{ path-prefix "/refused" }}
        upstream "backend"
        filters "refuser"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        uds = uds.display(),
        refuser = refuser.display(),
    )
}

/// The configuration a response says its agent was given.
fn served_config(body: &str) -> Option<serde_json::Value> {
    serde_json::from_str(body.strip_prefix("config=")?).ok()
}

/// Wait until `path` is served by an agent that has its configuration, and
/// return that configuration.
fn wait_configured(port: u16, path: &str, what: &str) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = get(port, path);
        if status == 200 {
            match served_config(&body) {
                Some(config) => return config,
                // Served by an agent without its configuration: the bug.
                None => panic!("{what}: the agent served without its configuration: {body}"),
            }
        }
        assert!(
            Instant::now() < deadline,
            "{what}: never served (last: {status} {body:?})"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Every connection the proxy made delivered the configuration, in the
/// handshake and in a configure call, and nothing else reached the agent.
fn assert_every_connection_configured(seen: &Mutex<Seen>, greeting: &str, what: &str) {
    let seen = seen.lock().unwrap();
    assert!(!seen.configures.is_empty(), "{what}: never configured");
    for config in &seen.configures {
        assert_eq!(config["greeting"], greeting, "{what}: {config}");
    }
    assert_eq!(
        seen.handshake_configs.len(),
        seen.configures.len(),
        "{what}: a connection was made without a configure call"
    );
    for config in &seen.handshake_configs {
        assert_eq!(config["greeting"], greeting, "{what}: handshake {config}");
    }
}

#[test]
fn agent_config_reaches_the_agent_on_both_transports_and_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let uds = Transport::Uds(dir.path().join("echo.sock"));
    let refuser_path = dir.path().join("refuser.sock");
    let refuser = Transport::Uds(refuser_path.clone());
    let [port, backend, grpc_port] = free_ports::<3>(19700..19720);
    let grpc_addr: SocketAddr = ([127, 0, 0, 1], grpc_port).into();
    let grpc = Transport::Grpc(grpc_addr);

    let uds_agent = AgentProcess::start("echo-uds", &uds, true);
    let grpc_agent = AgentProcess::start("echo-grpc", &grpc, true);
    let refuser_agent = AgentProcess::start("refuser", &refuser, false);
    spawn_backend(backend);

    let Transport::Uds(uds_path) = &uds else {
        unreachable!()
    };
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(
        &path,
        config(port, backend, uds_path, grpc_addr, &refuser_path),
    )
    .unwrap();
    let _proxy = Proxy(
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

    // The configuration reaches the agent, on both transports, nested
    // blocks included.
    let config = wait_configured(port, "/uds/a", "uds");
    assert_eq!(config["greeting"], "hello-over-uds");
    assert_eq!(config["limits"]["burst"], 7, "{config}");
    let config = wait_configured(port, "/grpc/a", "grpc");
    assert_eq!(config["greeting"], "hello-over-grpc");
    assert_every_connection_configured(&uds_agent.seen, "hello-over-uds", "uds");
    assert_every_connection_configured(&grpc_agent.seen, "hello-over-grpc", "grpc");

    // An agent that rejects its configuration is never sent a request: its
    // connections are not used, so its fail-closed filter answers.
    for _ in 0..5 {
        let (status, body) = get(port, "/refused/a");
        assert_eq!(status, 503, "a rejected configuration was served: {body}");
    }
    {
        let seen = refuser_agent.seen.lock().unwrap();
        assert!(!seen.configures.is_empty(), "the refuser was never asked");
        assert_eq!(seen.requests, 0, "a request reached an unconfigured agent");
    }

    // Restart both agents. The new processes know nothing: whatever
    // configuration they serve came from the proxy reconnecting.
    uds_agent.kill();
    grpc_agent.kill();
    let uds_agent = AgentProcess::start("echo-uds", &uds, true);
    let grpc_agent = AgentProcess::start("echo-grpc", &grpc, true);

    let config = wait_configured(port, "/uds/b", "uds after restart");
    assert_eq!(config["greeting"], "hello-over-uds");
    let config = wait_configured(port, "/grpc/b", "grpc after restart");
    assert_eq!(config["greeting"], "hello-over-grpc");
    assert_every_connection_configured(&uds_agent.seen, "hello-over-uds", "uds after restart");
    assert_every_connection_configured(&grpc_agent.seen, "hello-over-grpc", "grpc after restart");

    // And it stays that way: no request is served unconfigured.
    for i in 0..20 {
        for route in ["uds", "grpc"] {
            let (status, body) = get(port, &format!("/{route}/c{i}"));
            assert_eq!(status, 200, "{route}: {body}");
            assert!(served_config(&body).is_some(), "{route}: {body}");
        }
    }
}
