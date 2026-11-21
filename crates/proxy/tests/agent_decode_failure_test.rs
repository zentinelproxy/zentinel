//! An agent that cannot decode an event has failed; it has not allowed it.
//!
//! The agent-side server answered an event it could not decode with an Allow
//! response. The proxy cannot tell that answer from the real thing, so the
//! agent's `failure-mode "closed"` never applied to it and the request went
//! on to the backend.
//!
//! This runs the real binary against a local backend and two in-test agents,
//! one `closed` and one `open`, each built on `UdsAgentServerV2`. A relay
//! stands on the socket the proxy connects to and hands every frame to the
//! agent, except that it replaces the payload of a request-headers event for
//! a path containing `garbled` with one that is not an event. That is what
//! the agent sees when the two sides disagree about the shape of an event.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{UnixListener, UnixStream};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds::{read_message, write_message, MessageType};
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent};

/// What the backend answers with, so a response can be told from the proxy's.
const BACKEND_BODY: &str = "from the backend";

/// A backend that answers every request with [`BACKEND_BODY`] and counts them.
fn spawn_backend(listener: TcpListener, hits: Arc<AtomicUsize>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let hits = Arc::clone(&hits);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    line.clear();
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BACKEND_BODY}",
                    BACKEND_BODY.len()
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

/// An agent that allows everything it can read, and counts the events.
struct Allowing {
    name: &'static str,
    events: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Allowing {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(self.name, "Allowing Agent", "0.1.0")
            .with_event(EventType::RequestHeaders)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        self.events.fetch_add(1, Ordering::SeqCst);
        AgentResponse::default_allow()
    }
}

/// The payload the relay puts in place of a request-headers event it
/// garbles: JSON, with the correlation id and nothing an event needs.
fn garbled(payload: &[u8]) -> Option<Vec<u8>> {
    let event: serde_json::Value = serde_json::from_slice(payload).ok()?;
    if !event["uri"].as_str()?.contains("garbled") {
        return None;
    }
    let correlation_id = event["correlation_id"]
        .as_str()
        .or_else(|| event["metadata"]["correlation_id"].as_str())?;
    Some(serde_json::to_vec(&serde_json::json!({ "correlation_id": correlation_id })).unwrap())
}

/// What the relay forwards to the agent in place of `payload`.
fn rewrite(msg_type: MessageType, payload: Vec<u8>) -> Vec<u8> {
    match msg_type {
        // Offer JSON only, so that the relay can read what it forwards
        // whatever encodings the proxy was built to speak.
        MessageType::HandshakeRequest => {
            let Ok(mut handshake) = serde_json::from_slice::<serde_json::Value>(&payload) else {
                return payload;
            };
            if let Some(object) = handshake.as_object_mut() {
                object.remove("supported_encodings");
            }
            serde_json::to_vec(&handshake).unwrap()
        }
        MessageType::RequestHeaders => garbled(&payload).unwrap_or(payload),
        _ => payload,
    }
}

/// Carry one proxy connection to the agent and back until either side ends.
async fn relay_connection(proxy: UnixStream, agent_socket: PathBuf) {
    let Ok(agent) = UnixStream::connect(&agent_socket).await else {
        return;
    };
    let (mut proxy_read, mut proxy_write) = proxy.into_split();
    let (mut agent_read, mut agent_write) = agent.into_split();

    let to_agent = async {
        while let Ok((msg_type, payload)) = read_message(&mut proxy_read).await {
            let payload = rewrite(msg_type, payload);
            if write_message(&mut agent_write, msg_type, &payload)
                .await
                .is_err()
            {
                break;
            }
        }
    };
    let to_proxy = async {
        let _ = tokio::io::copy(&mut agent_read, &mut proxy_write).await;
    };
    // Whichever side ends first ends the connection, as a direct one would.
    tokio::select! {
        _ = to_agent => {}
        _ = to_proxy => {}
    }
}

/// One agent process: the agent on `<name>.agent.sock`, and the relay the
/// proxy is pointed at on `<name>.sock`. Its own runtime, so that dropping it
/// ends the listeners and every connection.
struct AgentProcess {
    rt: Option<tokio::runtime::Runtime>,
    events: Arc<AtomicUsize>,
    relay_socket: PathBuf,
}

impl AgentProcess {
    fn start(name: &'static str, dir: &Path) -> Self {
        let events = Arc::new(AtomicUsize::new(0));
        let agent_socket = dir.join(format!("{name}.agent.sock"));
        let relay_socket = dir.join(format!("{name}.sock"));

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        let server = UdsAgentServerV2::new(
            name,
            agent_socket.clone(),
            Box::new(Allowing {
                name,
                events: Arc::clone(&events),
            }),
        );
        rt.spawn(async move {
            let _ = server.run().await;
        });
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::os::unix::net::UnixStream::connect(&agent_socket).is_err() {
            assert!(Instant::now() < deadline, "{name} never listened");
            std::thread::sleep(Duration::from_millis(20));
        }

        let listener = {
            let _guard = rt.enter();
            UnixListener::bind(&relay_socket).unwrap()
        };
        let upstream = agent_socket.clone();
        rt.spawn(async move {
            while let Ok((proxy, _)) = listener.accept().await {
                tokio::spawn(relay_connection(proxy, upstream.clone()));
            }
        });

        Self {
            rt: Some(rt),
            events,
            relay_socket,
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

fn config(port: u16, backend: u16, closed: &Path, open: &Path) -> String {
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
    agent "closed-agent" type="custom" {{
        unix-socket "{closed}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
    agent "open-agent" type="custom" {{
        unix-socket "{open}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "open"
    }}
}}
filters {{
    filter "closed-agent" {{
        type "agent"
        agent "closed-agent"
        failure-mode "closed"
    }}
    filter "open-agent" {{
        type "agent"
        agent "open-agent"
        failure-mode "open"
    }}
}}
routes {{
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        filters "closed-agent"
    }}
    route "open" {{
        matches {{ path-prefix "/open" }}
        upstream "backend"
        filters "open-agent"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        closed = closed.display(),
        open = open.display(),
    )
}

/// Request `path` until the backend answers it, and fail if that takes
/// longer than a minute.
fn wait_served(port: u16, path: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (status, body) = get(port, path);
        if status == 200 && body == BACKEND_BODY {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{path}: never served (last: {status} {body:?})"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn an_event_the_agent_cannot_decode_follows_the_failure_mode() {
    let dir = tempfile::tempdir().unwrap();
    let closed = AgentProcess::start("closed-agent", dir.path());
    let open = AgentProcess::start("open-agent", dir.path());

    let backend_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    spawn_backend(backend_listener, Arc::clone(&backend_hits));

    // The proxy binds its own listener, so the port is found and released.
    let port = TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let kdl = dir.path().join("zentinel.kdl");
    std::fs::write(
        &kdl,
        config(port, backend, &closed.relay_socket, &open.relay_socket),
    )
    .unwrap();
    let _proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&kdl)
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

    // Through the relay, events the agents can read are served.
    wait_served(port, "/closed/a");
    wait_served(port, "/open/a");
    assert!(closed.events.load(Ordering::SeqCst) >= 1);
    assert!(open.events.load(Ordering::SeqCst) >= 1);

    // An event the `closed` agent cannot decode is a failure of the agent: the
    // request is stopped, and never reaches the backend.
    let hits_before = backend_hits.load(Ordering::SeqCst);
    let (status, body) = get(port, "/closed/garbled");
    assert_eq!(
        status, 503,
        "a request the agent could not read was not stopped: {body:?}"
    );
    assert_ne!(body, BACKEND_BODY);
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        hits_before,
        "a request the agent could not read reached the backend"
    );

    // The same failure with an `open` agent lets the request through, as any
    // failure of that agent does.
    let (status, body) = get(port, "/open/garbled");
    assert_eq!(
        (status, body.as_str()),
        (200, BACKEND_BODY),
        "an `open` agent's failure stopped the request"
    );

    // The agent is still served: its other connections handle the later
    // requests.
    wait_served(port, "/closed/b");
    wait_served(port, "/open/b");
}
