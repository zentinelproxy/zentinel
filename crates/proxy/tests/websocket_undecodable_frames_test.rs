//! WebSocket frames that cannot be decoded on an inspected route.
//!
//! The proxy parses the frames of a route with `websocket-inspection` so the
//! route's agents can see them. A frame it could not parse -- one larger than
//! the frame size limit, or one with an RSV bit set that no extension
//! accounts for -- used to be logged and forwarded without reaching any
//! agent, and the bytes after it were then read from the middle of a frame.
//! A client that offered `permessage-deflate` got no inspection at all.
//!
//! This runs the real binary between a raw WebSocket client and a scripted
//! backend, and checks what each side receives:
//!
//! - a frame that cannot be decoded is not forwarded, and the connection is
//!   closed with 1009 (too large) or 1002 (RSV bits), from either side;
//! - no extension is negotiated on an inspected route, so compressed frames
//!   never arrive, and the route's agents see the frames;
//! - `websocket-max-frame-size` raises the limit;
//! - a route without inspection is left alone.

#![cfg(unix)]

use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, RequestHeadersEvent, WebSocketFrameEvent};

const MIB: usize = 1024 * 1024;

/// How long to wait for something that should happen.
const WAIT: Duration = Duration::from_secs(5);

/// A port nothing listens on yet.
fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll `condition` until it holds or `WAIT` has passed.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

/// What the backend saw.
#[derive(Default)]
struct Backend {
    /// The head of each upgrade request, lower-cased.
    heads: Mutex<Vec<String>>,
    /// Bytes received after the upgrade, on connections that are not echoes.
    received: AtomicUsize,
    /// Connections whose read side has ended.
    ended: AtomicUsize,
}

impl Backend {
    fn heads(&self) -> Vec<String> {
        self.heads.lock().unwrap().clone()
    }
}

/// The `Sec-WebSocket-Extensions` lines of a request head.
fn extension_lines(head: &str) -> Vec<String> {
    head.lines()
        .filter(|line| line.starts_with("sec-websocket-extensions:"))
        .map(str::to_string)
        .collect()
}

/// Accepts WebSocket upgrades and acts by the last segment of the path:
///
/// - `echo`: echoes text and binary messages;
/// - `silent`: counts what the client sends;
/// - `rsv1`: first sends a text frame with RSV1 set, then counts;
/// - `ok-rsv1`: first sends a valid text frame and a text frame with RSV1
///   set, in one write, then counts;
/// - `rsv1-more`: as `rsv1`, and then keeps sending valid text frames until
///   the proxy closes the connection;
/// - `big`: first sends the header of a frame larger than the default limit
///   and a few bytes of its payload, then counts;
/// - `ready`: answers the first thing the client sends with a pong. It is
///   not recorded, so a test can tell that the proxy upgrades and stays
///   connected before it starts.
fn spawn_backend(listener: StdTcpListener) -> Arc<Backend> {
    let backend = Arc::new(Backend::default());
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    let shared = Arc::clone(&backend);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, Arc::clone(&shared)));
        }
    });
    backend
}

async fn serve(mut stream: TcpStream, backend: Arc<Backend>) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    };
    let original = String::from_utf8_lossy(&request[..head_end]).to_string();
    // The accept key is derived from the key as sent, not lower-cased.
    let key = original
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("sec-websocket-key")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    let head = original.to_lowercase();
    let target = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_string();
    let ready = target.ends_with("/ready");
    if !ready {
        backend.heads.lock().unwrap().push(head);
    }

    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\
         connection: Upgrade\r\nsec-websocket-accept: {}\r\n\r\n",
        derive_accept_key(key.as_bytes())
    );
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }

    match target.rsplit('/').next().unwrap_or("") {
        "ready" => {
            if let Ok(n) = stream.read(&mut chunk).await {
                if n > 0 {
                    let _ = stream.write_all(&[0x8A, 0]).await;
                }
            }
            return;
        }
        "echo" => {
            let mut ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
            while let Some(Ok(message)) = ws.next().await {
                if (message.is_text() || message.is_binary()) && ws.send(message).await.is_err() {
                    break;
                }
            }
            return;
        }
        "rsv1" => {
            let _ = stream
                .write_all(&[0xC1, 5, b'h', b'e', b'l', b'l', b'o'])
                .await;
        }
        "ok-rsv1" => {
            // A valid frame and one with RSV1 set, in one write.
            let _ = stream
                .write_all(&[0x81, 2, b'o', b'k', 0xC1, 5, b'h', b'e', b'l', b'l', b'o'])
                .await;
        }
        "rsv1-more" => {
            let _ = stream
                .write_all(&[0xC1, 5, b'h', b'e', b'l', b'l', b'o'])
                .await;
            // Valid frames, one every few milliseconds, until the proxy
            // ends the connection: the first may reach the proxy in the same
            // read as the frame with RSV1 set, and a later one cannot.
            let deadline = Instant::now() + WAIT;
            while Instant::now() < deadline {
                if stream.write_all(&[0x81, 2, b'o', b'k']).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        "big" => {
            let mut frame = vec![0x82, 127];
            frame.extend_from_slice(&((2 * MIB) as u64).to_be_bytes());
            frame.extend_from_slice(&[0u8; 16]);
            let _ = stream.write_all(&frame).await;
        }
        _ => {}
    }

    // Whatever arrives after the upgrade was sent by the proxy.
    backend
        .received
        .fetch_add(request.len() - head_end, Ordering::SeqCst);
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                backend.received.fetch_add(n, Ordering::SeqCst);
            }
        }
    }
    backend.ended.fetch_add(1, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// The agent
// ---------------------------------------------------------------------------

/// Allows everything, and counts the frames it is shown.
struct Counter {
    frames: Arc<AtomicUsize>,
    largest: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl AgentHandlerV2 for Counter {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("counter", "Counter", "0.1.0")
            .with_event(EventType::RequestHeaders)
            .with_event(EventType::WebSocketFrame)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        use base64::Engine;
        self.frames.fetch_add(1, Ordering::SeqCst);
        let size = base64::engine::general_purpose::STANDARD
            .decode(&event.data)
            .map(|data| data.len())
            .unwrap_or(0);
        self.largest.fetch_max(size, Ordering::SeqCst);
        AgentResponse::websocket_allow()
    }
}

// ---------------------------------------------------------------------------
// The proxy
// ---------------------------------------------------------------------------

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Setup {
    port: u16,
    backend: Arc<Backend>,
    frames: Arc<AtomicUsize>,
    largest: Arc<AtomicUsize>,
    _proxy: Proxy,
    _dir: tempfile::TempDir,
}

/// Routes to one backend: `/inspected`, `/wide` and `/huge` inspect frames
/// (`/wide` and `/huge` with larger frame size limits), `/plain` does not.
/// The agent behind them has `failure-mode "open"`, so nothing closes a
/// connection because a call to an agent failed -- except on `/huge-closed`,
/// which has the same limit as `/huge` and `failure-mode "closed"`.
async fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let frames = Arc::new(AtomicUsize::new(0));
    let largest = Arc::new(AtomicUsize::new(0));
    let socket = dir.path().join("counter.sock");
    let server = UdsAgentServerV2::new(
        "counter",
        socket.clone(),
        Box::new(Counter {
            frames: Arc::clone(&frames),
            largest: Arc::clone(&largest),
        }),
    );
    tokio::spawn(async move {
        let _ = server.run().await;
    });
    eventually("the agent to listen", || socket.exists()).await;

    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = spawn_backend(listener);
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
    agent "counter" type="custom" {{
        unix-socket "{socket}"
        events "request_headers" "websocket_frame"
        timeout-ms 5000
    }}
}}
filters {{
    filter "frames" {{
        type "agent"
        agent "counter"
        failure-mode "open"
    }}
    filter "frames-closed" {{
        type "agent"
        agent "counter"
        failure-mode "closed"
    }}
}}
routes {{
    route "inspected" {{
        matches {{ path-prefix "/inspected" }}
        upstream "backend"
        websocket #true
        websocket-inspection #true
        filters "frames"
    }}
    route "wide" {{
        matches {{ path-prefix "/wide" }}
        upstream "backend"
        websocket #true
        websocket-inspection #true
        websocket-max-frame-size "4MB"
        filters "frames"
    }}
    route "huge" {{
        matches {{ path-prefix "/huge" }}
        upstream "backend"
        websocket #true
        websocket-inspection #true
        websocket-max-frame-size "16MB"
        filters "frames"
    }}
    route "huge-closed" {{
        matches {{ path-prefix "/huge-closed" }}
        priority "high"
        upstream "backend"
        websocket #true
        websocket-inspection #true
        websocket-max-frame-size "16MB"
        filters "frames-closed"
    }}
    route "plain" {{
        matches {{ path-prefix "/plain" }}
        upstream "backend"
        websocket #true
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
    wait_until_upgrades_hold(port).await;
    Setup {
        port,
        backend,
        frames,
        largest,
        _proxy: proxy,
        _dir: dir,
    }
}

/// Wait until the proxy upgrades a connection and keeps it: it has to
/// accept connections, answer an upgrade with 101, and still answer a ping on
/// the upgraded connection. A proxy that is still starting up can accept the
/// connection and still reset it, or end an upgraded connection at once, so
/// listening on the port is not enough.
async fn wait_until_upgrades_hold(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let failure = match RawClient::try_connect(port, "/plain/ready", &[]).await {
            Err(e) => e,
            Ok(mut client) => {
                client.send(&client_frame(0x89, b"")).await;
                match client.read_frame(Duration::from_secs(2)).await {
                    Read::Frame(0x8A, _) => return,
                    other => format!("no pong after the upgrade: {other:?}"),
                }
            }
        };
        assert!(
            Instant::now() < deadline,
            "the proxy never upgraded a connection and kept it: {failure}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// A raw client: it writes exactly the bytes a test names
// ---------------------------------------------------------------------------

struct RawClient {
    stream: TcpStream,
    buffered: Vec<u8>,
}

/// What `RawClient::read_frame` found.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The first byte of a frame (FIN, RSV bits, opcode) and its payload.
    Frame(u8, Vec<u8>),
    /// The proxy closed the connection.
    Eof,
    /// Nothing arrived in time.
    Nothing,
}

const CLOSE: u8 = 0x88;

impl RawClient {
    /// Upgrade `path`, with `extra` request headers, and check for a 101.
    async fn connect(port: u16, path: &str, extra: &[(&str, &str)]) -> RawClient {
        Self::try_connect(port, path, extra)
            .await
            .unwrap_or_else(|e| panic!("could not upgrade {path}: {e}"))
    }

    /// Upgrade `path`, with `extra` request headers: the client, or what went
    /// wrong.
    async fn try_connect(
        port: u16,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Result<RawClient, String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n"
        );
        for (name, value) in extra {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;

        let mut buffered = Vec::new();
        let mut chunk = [0u8; 4096];
        let head_end = loop {
            if let Some(at) = buffered.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let n = tokio::time::timeout(WAIT, stream.read(&mut chunk))
                .await
                .map_err(|_| "no response to the upgrade".to_string())?
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("the connection closed during the upgrade".to_string());
            }
            buffered.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buffered[..head_end]).to_string();
        if !head.starts_with("HTTP/1.1 101") {
            return Err(format!("not upgraded: {head}"));
        }
        buffered.drain(..head_end);
        Ok(RawClient { stream, buffered })
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).await.unwrap();
    }

    /// Like `send`, for bytes the proxy may stop reading: a write that fails
    /// because the proxy closed the connection is not an error.
    async fn send_until_closed(&mut self, bytes: &[u8]) {
        let _ = self.stream.write_all(bytes).await;
    }

    /// The next frame the proxy sends (frames from a server are unmasked).
    async fn read_frame(&mut self, wait: Duration) -> Read {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(frame) = self.take_frame() {
                return frame;
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Read::Nothing;
            };
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(left, self.stream.read(&mut chunk)).await {
                Err(_) => return Read::Nothing,
                Ok(Ok(0)) | Ok(Err(_)) => return Read::Eof,
                Ok(Ok(n)) => self.buffered.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn take_frame(&mut self) -> Option<Read> {
        let buf = &self.buffered;
        if buf.len() < 2 {
            return None;
        }
        let (header, len) = match buf[1] & 0x7F {
            126 if buf.len() >= 4 => (4, u16::from_be_bytes([buf[2], buf[3]]) as usize),
            127 if buf.len() >= 10 => {
                let mut len = [0u8; 8];
                len.copy_from_slice(&buf[2..10]);
                (10, u64::from_be_bytes(len) as usize)
            }
            126 | 127 => return None,
            len => (2, len as usize),
        };
        if buf.len() < header + len {
            return None;
        }
        let frame = Read::Frame(buf[0], buf[header..header + len].to_vec());
        self.buffered.drain(..header + len);
        Some(frame)
    }

    /// The close frame the proxy sends next, as its status code.
    async fn close_code(&mut self) -> u16 {
        match self.read_frame(WAIT).await {
            Read::Frame(CLOSE, payload) if payload.len() >= 2 => {
                u16::from_be_bytes([payload[0], payload[1]])
            }
            other => panic!("expected a close frame with a status code, got {other:?}"),
        }
    }
}

/// A masked client frame with a payload of up to 125 bytes.
fn client_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= 125);
    let mask = [0x11, 0x22, 0x33, 0x44];
    let mut frame = vec![first, 0x80 | payload.len() as u8];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    frame
}

/// A masked client frame that claims `len` payload bytes and carries only
/// `sent` of them.
fn client_frame_prefix(first: u8, len: usize, sent: usize) -> Vec<u8> {
    let mut frame = vec![first, 0x80 | 127];
    frame.extend_from_slice(&(len as u64).to_be_bytes());
    frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    frame.extend(std::iter::repeat_n(0u8, sent));
    frame
}

/// The connection is closed, and the backend received none of it.
async fn assert_closed_and_not_forwarded(client: &mut RawClient, setup: &Setup) {
    assert_eq!(
        client.read_frame(WAIT).await,
        Read::Eof,
        "the proxy keeps the connection open after the close frame"
    );
    eventually("the backend's connection to end", || {
        setup.backend.ended.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(
        setup.backend.received.load(Ordering::SeqCst),
        0,
        "the backend received bytes of a frame the proxy could not decode"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_frame_over_the_limit_closes_with_1009_and_is_not_forwarded() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/inspected/silent", &[]).await;

    // The header of a binary frame of 1 MiB + 1 bytes, and the start of it.
    client.send(&client_frame_prefix(0x82, MIB + 1, 16)).await;

    assert_eq!(client.close_code().await, 1009);
    assert_closed_and_not_forwarded(&mut client, &setup).await;
    assert_eq!(
        setup.frames.load(Ordering::SeqCst),
        0,
        "no agent was shown a frame that could not be decoded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_frame_with_an_rsv_bit_closes_with_1002_and_is_not_forwarded() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/inspected/silent", &[]).await;

    // A text frame with RSV1 set: what a compressed frame looks like.
    client.send(&client_frame(0xC1, b"hello")).await;

    assert_eq!(client.close_code().await, 1002);
    assert_closed_and_not_forwarded(&mut client, &setup).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_frame_with_an_rsv_bit_closes_with_1002_and_is_not_forwarded() {
    let setup = setup().await;
    // The backend sends a text frame with RSV1 set as soon as it upgrades.
    let mut client = RawClient::connect(setup.port, "/inspected/rsv1", &[]).await;

    assert_eq!(client.close_code().await, 1002);

    // The client answers the close, and the proxy ends the upstream side.
    client
        .send(&client_frame(CLOSE, &1002u16.to_be_bytes()))
        .await;
    assert_closed_and_not_forwarded(&mut client, &setup).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_frame_before_an_undecodable_one_in_the_same_read_is_forwarded_first() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/inspected/silent", &[]).await;

    // A valid frame and one with RSV1 set, in one write. The proxy may read
    // them together or one at a time; either way the first goes on.
    let good = client_frame(0x81, b"fine");
    let mut data = good.clone();
    data.extend_from_slice(&client_frame(0xC1, b"hello"));
    client.send(&data).await;

    assert_eq!(client.close_code().await, 1002);
    client
        .send_until_closed(&client_frame(CLOSE, &1002u16.to_be_bytes()))
        .await;
    assert_eq!(client.read_frame(WAIT).await, Read::Eof);
    eventually("the backend's connection to end", || {
        setup.backend.ended.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(
        setup.backend.received.load(Ordering::SeqCst),
        good.len(),
        "the backend should receive the valid frame and nothing else"
    );
    assert_eq!(setup.frames.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_frame_before_an_undecodable_one_in_the_same_read_is_forwarded_first() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/inspected/ok-rsv1", &[]).await;

    assert_eq!(
        client.read_frame(WAIT).await,
        Read::Frame(0x81, b"ok".to_vec()),
        "the valid frame goes to the client first"
    );
    assert_eq!(client.close_code().await, 1002);
    client
        .send_until_closed(&client_frame(CLOSE, &1002u16.to_be_bytes()))
        .await;
    assert_eq!(client.read_frame(WAIT).await, Read::Eof);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_too_large_for_the_agent_transport_follows_the_failure_mode() {
    let setup = setup().await;

    // 13 MiB is under this route's 16MB limit, and over what one message to
    // an agent carries once it is base64-encoded (16 MiB). The call to the
    // agent fails; under `failure-mode "open"` the frame goes on.
    let message = vec![b'x'; 13 * MIB];
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/huge/echo", setup.port))
            .await
            .unwrap();
    ws.send(Message::binary(message.clone())).await.unwrap();
    let echoed = tokio::time::timeout(WAIT, ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::binary(message.clone()));
    assert_eq!(
        setup.frames.load(Ordering::SeqCst),
        0,
        "the agent cannot have been shown a frame that large"
    );
    let _ = ws.close(None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frame_too_large_for_the_agent_transport_closes_under_failure_mode_closed() {
    let setup = setup().await;

    // The same frame under `failure-mode "closed"`: the connection closes
    // instead, and the backend receives none of the frame.
    let mut client = RawClient::connect(setup.port, "/huge-closed/silent", &[]).await;
    client
        .send_until_closed(&client_frame_prefix(0x82, 13 * MIB, 13 * MIB))
        .await;
    // Whatever the client is sent first, the connection ends.
    loop {
        match client.read_frame(WAIT).await {
            Read::Frame(..) => continue,
            Read::Eof => break,
            Read::Nothing => panic!("the connection stayed open"),
        }
    }
    eventually("the backend's connection to end", || {
        setup.backend.ended.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(setup.backend.received.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_ends_when_the_upstream_sends_more_after_the_close_frame() {
    let setup = setup().await;
    // After the frame with RSV1 set, the backend sends a valid frame.
    let mut client = RawClient::connect(setup.port, "/inspected/rsv1-more", &[]).await;

    assert_eq!(client.close_code().await, 1002);

    // The client does not answer. The next data from the backend is not
    // forwarded either; it ends the connection.
    assert_eq!(
        client.read_frame(WAIT).await,
        Read::Eof,
        "data from the upstream after the close frame reached the client or kept the connection open"
    );
    eventually("the backend's connection to end", || {
        setup.backend.ended.load(Ordering::SeqCst) >= 1
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_the_whole_oversized_frame_is_not_forwarded_either() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/inspected/silent", &[]).await;

    // The proxy answers when it has read the header, and the client is still
    // writing: it may see the close frame, or the connection reset.
    client
        .send_until_closed(&client_frame_prefix(0x82, 2 * MIB, 2 * MIB))
        .await;

    match client.read_frame(WAIT).await {
        Read::Frame(CLOSE, payload) => {
            assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), 1009)
        }
        Read::Eof => {}
        other => panic!("expected a close frame or the end of the connection, got {other:?}"),
    }
    eventually("the backend's connection to end", || {
        setup.backend.ended.load(Ordering::SeqCst) >= 1
    })
    .await;
    assert_eq!(setup.backend.received.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upstream_frame_over_the_limit_closes_with_1009() {
    let setup = setup().await;
    // The backend sends the header of a 2 MiB frame as soon as it upgrades.
    let mut client = RawClient::connect(setup.port, "/inspected/big", &[]).await;

    assert_eq!(client.close_code().await, 1009);

    client
        .send(&client_frame(CLOSE, &1009u16.to_be_bytes()))
        .await;
    assert_closed_and_not_forwarded(&mut client, &setup).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inspected_route_negotiates_no_extension_and_still_inspects_frames() {
    let setup = setup().await;

    // Two clients: one offers `permessage-deflate` in a single header line,
    // the other in two lines with other spellings and another extension.
    let offers: [&[&str]; 2] = [
        &["permessage-deflate; client_max_window_bits"],
        &["Permessage-Deflate", "x-webkit-deflate-frame"],
    ];
    for (n, lines) in offers.iter().enumerate() {
        let mut request = format!("ws://127.0.0.1:{}/inspected/echo", setup.port)
            .into_client_request()
            .unwrap();
        for line in *lines {
            request
                .headers_mut()
                .append("Sec-WebSocket-Extensions", line.parse().unwrap());
        }
        let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

        let frames_before = setup.frames.load(Ordering::SeqCst);
        ws.send(Message::text("hello")).await.unwrap();
        let echoed = tokio::time::timeout(WAIT, ws.next())
            .await
            .expect("no echo")
            .unwrap()
            .unwrap();
        assert_eq!(echoed, Message::text("hello"));
        assert!(
            setup.frames.load(Ordering::SeqCst) >= frames_before + 2,
            "client {n}: the route's agent was not shown the frames"
        );
        let _ = ws.close(None).await;
    }

    let heads = setup.backend.heads();
    assert_eq!(heads.len(), 2);
    for head in &heads {
        assert_eq!(
            extension_lines(head),
            Vec::<String>::new(),
            "an extension offer reached the backend:\n{head}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_without_inspection_passes_the_extension_offer_on() {
    let setup = setup().await;
    let mut request = format!("ws://127.0.0.1:{}/plain/echo", setup.port)
        .into_client_request()
        .unwrap();
    request.headers_mut().append(
        "Sec-WebSocket-Extensions",
        "permessage-deflate".parse().unwrap(),
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::text("hello")).await.unwrap();
    let echoed = tokio::time::timeout(WAIT, ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::text("hello"));
    let _ = ws.close(None).await;

    let heads = setup.backend.heads();
    assert_eq!(heads.len(), 1);
    assert_eq!(
        extension_lines(&heads[0]),
        vec!["sec-websocket-extensions: permessage-deflate".to_string()]
    );
    assert_eq!(setup.frames.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_without_inspection_forwards_frames_as_before() {
    let setup = setup().await;
    let mut client = RawClient::connect(setup.port, "/plain/silent", &[]).await;

    let frame = client_frame(0xC1, b"hello");
    client.send(&frame).await;

    eventually("the backend to receive the frame", || {
        setup.backend.received.load(Ordering::SeqCst) >= frame.len()
    })
    .await;
    assert_eq!(
        client.read_frame(Duration::from_millis(500)).await,
        Read::Nothing,
        "a route without inspection closes nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_max_frame_size_raises_the_limit() {
    let setup = setup().await;
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{}/wide/echo", setup.port))
            .await
            .unwrap();

    // 1.5 MiB: over the default limit, under this route's 4MB.
    let message = vec![b'x'; MIB + MIB / 2];
    ws.send(Message::binary(message.clone())).await.unwrap();
    let echoed = tokio::time::timeout(WAIT, ws.next())
        .await
        .expect("no echo")
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::binary(message.clone()));
    assert!(
        setup.largest.load(Ordering::SeqCst) >= message.len(),
        "the route's agent was shown frames of at most {} bytes",
        setup.largest.load(Ordering::SeqCst)
    );
    let _ = ws.close(None).await;
}
