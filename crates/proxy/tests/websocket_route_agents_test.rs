//! WebSocket frames go to the route's agents, under the route's failure
//! mode (#586).
//!
//! Frames never reached an agent: `AgentV2::call_event` had no case for
//! them and answered every frame "Unsupported event type", a failed call
//! that the agent-level `failure-mode` then decided (open by default, so
//! every frame passed uninspected; closed closed every connection). And the
//! frame dispatch ignored the route: every loaded agent subscribed to
//! frames saw every route's.
//!
//! This runs the real binary against a WebSocket echo backend and in-test
//! v2 agents, and checks what the client gets back.

#![cfg(unix)]

use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::Message;

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent, WebSocketFrameEvent};

fn free_ports(range: std::ops::Range<u16>, n: usize) -> Vec<u16> {
    let ports: Vec<u16> = range
        .clone()
        .filter(|&port| StdTcpListener::bind(("127.0.0.1", port)).is_ok())
        .take(n)
        .collect();
    assert_eq!(ports.len(), n, "{n} free ports in {range:?}");
    ports
}

/// A WebSocket backend that echoes every text frame.
async fn spawn_echo_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    if message.is_text() && ws.send(message).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

/// Drops client frames containing "secret"; counts the frames it sees.
struct Guard {
    frames: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Guard {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("guard", "Guard", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::WebSocketFrame)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        use base64::Engine;
        self.frames.fetch_add(1, Ordering::SeqCst);
        let data = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .unwrap_or_default();
        if event.client_to_server && String::from_utf8_lossy(&data).contains("secret") {
            AgentResponse::websocket_drop()
        } else {
            AgentResponse::websocket_allow()
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

struct Setup {
    port: u16,
    guard_frames: Arc<AtomicUsize>,
    bystander_frames: Arc<AtomicUsize>,
    _proxy: Proxy,
    _dir: tempfile::TempDir,
}

async fn start_agent(dir: &std::path::Path, name: &str, frames: Arc<AtomicUsize>) -> String {
    let socket = dir.join(format!("{name}.sock"));
    let server = UdsAgentServerV2::new(name, socket.clone(), Box::new(Guard { frames }));
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "agent {name} never listened");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    socket.display().to_string()
}

async fn setup(ports: std::ops::Range<u16>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let guard_frames = Arc::new(AtomicUsize::new(0));
    let bystander_frames = Arc::new(AtomicUsize::new(0));
    let guard = start_agent(dir.path(), "guard", guard_frames.clone()).await;
    let bystander = start_agent(dir.path(), "bystander", bystander_frames.clone()).await;
    let down = dir.path().join("down.sock").display().to_string();

    let ports = free_ports(ports, 2);
    let (port, backend) = (ports[0], ports[1]);
    spawn_echo_backend(backend).await;

    // `guard` is on route "/guarded"; `bystander` subscribes to frames but
    // is on no route's filters, and closes nothing -- it only counts. `down`
    // is never reachable: its own failure-mode says open, its filter on
    // "/closed" says closed.
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
    agent "guard" type="custom" {{
        unix-socket "{guard}"
        events "request_headers" "websocket_frame"
        timeout-ms 2000
    }}
    agent "bystander" type="custom" {{
        unix-socket "{bystander}"
        events "websocket_frame"
        timeout-ms 2000
    }}
    agent "down" type="custom" {{
        unix-socket "{down}"
        events "websocket_frame"
        timeout-ms 200
        connect-timeout-ms 200
    }}
}}
filters {{
    filter "guard" {{
        type "agent"
        agent "guard"
        failure-mode "closed"
    }}
    filter "down" {{
        type "agent"
        agent "down"
        failure-mode "closed"
    }}
}}
routes {{
    route "guarded" {{
        matches {{ path-prefix "/guarded" }}
        upstream "backend"
        websocket #true
        websocket-inspection #true
        filters "guard"
    }}
    route "closed" {{
        matches {{ path-prefix "/closed" }}
        upstream "backend"
        websocket #true
        websocket-inspection #true
        filters "down"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
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
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Setup {
        port,
        guard_frames,
        bystander_frames,
        _proxy: proxy,
        _dir: dir,
    }
}

type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect(port: u16, path: &str) -> Client {
    let url = format!("ws://127.0.0.1:{port}{path}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => return ws,
            Err(e) => {
                assert!(Instant::now() < deadline, "could not connect to {url}: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// The next message, or `None` if nothing arrives within `wait`.
async fn next_message(ws: &mut Client, wait: Duration) -> Option<Message> {
    tokio::time::timeout(wait, ws.next())
        .await
        .ok()
        .flatten()
        .and_then(|m| m.ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn frames_go_to_the_routes_agents_under_the_routes_failure_mode() {
    let setup = setup(19860..19960).await;

    // The route's agent inspects frames: it drops the one with "secret",
    // and the others are echoed.
    let mut ws = connect(setup.port, "/guarded").await;
    ws.send(Message::text("hello")).await.unwrap();
    let echoed = next_message(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(echoed, Some(Message::text("hello")));

    ws.send(Message::text("my secret")).await.unwrap();
    ws.send(Message::text("after")).await.unwrap();
    let echoed = next_message(&mut ws, Duration::from_secs(5)).await;
    assert_eq!(
        echoed,
        Some(Message::text("after")),
        "the frame with \"secret\" must be dropped by the route's agent"
    );
    assert!(
        setup.guard_frames.load(Ordering::SeqCst) >= 3,
        "the route's agent saw {} frames",
        setup.guard_frames.load(Ordering::SeqCst)
    );
    assert_eq!(
        setup.bystander_frames.load(Ordering::SeqCst),
        0,
        "an agent on no route's filters must not see the route's frames"
    );
    let _ = ws.close(None).await;

    // A route whose agent cannot be reached follows its filter's
    // failure-mode "closed" -- not the agent's own, which is unset (and
    // was open by default): the first frame ends the connection. The proxy
    // drops it (a 1011 close frame is accepted too); it must neither echo
    // the frame nor keep the connection open.
    let mut ws = connect(setup.port, "/closed").await;
    ws.send(Message::text("hello")).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Err(_) => panic!("the connection stayed open after a fail-closed frame"),
        Ok(None) | Ok(Some(Err(_))) => {}
        Ok(Some(Ok(Message::Close(frame)))) => {
            if let Some(frame) = frame {
                assert_eq!(frame.code, CloseCode::Error, "{frame:?}");
            }
        }
        Ok(Some(Ok(other))) => panic!("expected the connection to end, got {other:?}"),
    }
}
