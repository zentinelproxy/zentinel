//! Integration tests for WebSocket frame inspection.
//!
//! These tests verify the full WebSocket inspection flow with an echo server
//! and agent-based frame inspection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tempfile::tempdir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_async, connect_async};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, Decision, EventType, RequestHeadersEvent,
    WebSocketDecision, WebSocketFrameEvent,
};

// ============================================================================
// WebSocket Echo Server
// ============================================================================

/// A simple WebSocket echo server for testing.
struct EchoServer {
    addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl EchoServer {
    /// Start a new WebSocket echo server on a random port.
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind echo server");
        let addr = listener.local_addr().unwrap();

        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        if let Ok((stream, _)) = accept_result {
                            tokio::spawn(handle_connection(stream));
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            addr,
            shutdown: shutdown_tx,
        }
    }

    fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    fn shutdown(self) {
        let _ = self.shutdown.send(true);
    }
}

async fn handle_connection(stream: TcpStream) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => return,
    };

    let (mut write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        match msg_result {
            Ok(msg) => {
                // Echo back non-close messages
                match msg {
                    Message::Text(_) | Message::Binary(_) => {
                        if write.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Message::Ping(data) => {
                        if write.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => {
                        let _ = write.send(Message::Close(None)).await;
                        break;
                    }
                    _ => {}
                }
            }
            Err(_) => break,
        }
    }
}

// ============================================================================
// Test Agent Implementations
// ============================================================================

/// Agent that allows all WebSocket frames.
struct AllowingAgent {
    frames_inspected: AtomicUsize,
}

impl AllowingAgent {
    fn new() -> Self {
        Self {
            frames_inspected: AtomicUsize::new(0),
        }
    }

    fn frames_inspected(&self) -> usize {
        self.frames_inspected.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AgentHandler for AllowingAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, _event: WebSocketFrameEvent) -> AgentResponse {
        self.frames_inspected.fetch_add(1, Ordering::SeqCst);
        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

/// Agent that drops frames containing specific keywords.
struct FilteringAgent {
    blocked_keywords: Vec<String>,
    frames_inspected: AtomicUsize,
    frames_dropped: AtomicUsize,
}

impl FilteringAgent {
    fn new(blocked_keywords: Vec<String>) -> Self {
        Self {
            blocked_keywords,
            frames_inspected: AtomicUsize::new(0),
            frames_dropped: AtomicUsize::new(0),
        }
    }

    fn frames_inspected(&self) -> usize {
        self.frames_inspected.load(Ordering::SeqCst)
    }

    fn frames_dropped(&self) -> usize {
        self.frames_dropped.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AgentHandler for FilteringAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.frames_inspected.fetch_add(1, Ordering::SeqCst);

        // Decode the base64 payload
        let payload =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.data) {
                Ok(data) => data,
                Err(_) => {
                    return AgentResponse::default_allow()
                        .with_websocket_decision(WebSocketDecision::Allow)
                }
            };

        // Check if payload contains blocked keywords
        let payload_str = String::from_utf8_lossy(&payload);
        for keyword in &self.blocked_keywords {
            if payload_str.contains(keyword) {
                self.frames_dropped.fetch_add(1, Ordering::SeqCst);
                return AgentResponse::default_allow()
                    .with_websocket_decision(WebSocketDecision::Drop);
            }
        }

        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

/// Agent that closes connection on specific patterns.
struct ClosingAgent {
    close_patterns: Vec<String>,
    close_code: u16,
    close_reason: String,
    frames_inspected: AtomicUsize,
}

impl ClosingAgent {
    fn new(close_patterns: Vec<String>, close_code: u16, close_reason: String) -> Self {
        Self {
            close_patterns,
            close_code,
            close_reason,
            frames_inspected: AtomicUsize::new(0),
        }
    }

    fn frames_inspected(&self) -> usize {
        self.frames_inspected.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AgentHandler for ClosingAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.frames_inspected.fetch_add(1, Ordering::SeqCst);

        // Decode the base64 payload
        let payload =
            match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.data) {
                Ok(data) => data,
                Err(_) => {
                    return AgentResponse::default_allow()
                        .with_websocket_decision(WebSocketDecision::Allow)
                }
            };

        // Check if payload contains close patterns
        let payload_str = String::from_utf8_lossy(&payload);
        for pattern in &self.close_patterns {
            if payload_str.contains(pattern) {
                return AgentResponse::default_allow().with_websocket_decision(
                    WebSocketDecision::Close {
                        code: self.close_code,
                        reason: self.close_reason.clone(),
                    },
                );
            }
        }

        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

/// Agent that tracks frame direction and counts.
struct DirectionalAgent {
    client_to_server_count: AtomicUsize,
    server_to_client_count: AtomicUsize,
}

impl DirectionalAgent {
    fn new() -> Self {
        Self {
            client_to_server_count: AtomicUsize::new(0),
            server_to_client_count: AtomicUsize::new(0),
        }
    }

    fn client_to_server_frames(&self) -> usize {
        self.client_to_server_count.load(Ordering::SeqCst)
    }

    fn server_to_client_frames(&self) -> usize {
        self.server_to_client_count.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl AgentHandler for DirectionalAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        if event.client_to_server {
            self.client_to_server_count.fetch_add(1, Ordering::SeqCst);
        } else {
            self.server_to_client_count.fetch_add(1, Ordering::SeqCst);
        }

        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

#[tokio::test]
async fn test_echo_server_basic() {
    // Start echo server
    let server = EchoServer::start().await;
    let url = server.url();

    // Connect to echo server
    let (ws_stream, _) = connect_async(&url)
        .await
        .expect("Failed to connect to echo server");

    let (mut write, mut read) = ws_stream.split();

    // Send a message
    write
        .send(Message::Text("Hello, WebSocket!".to_string()))
        .await
        .expect("Failed to send message");

    // Read echoed message
    let response = read.next().await.expect("No response").expect("Read error");
    assert_eq!(response, Message::Text("Hello, WebSocket!".to_string()));

    // Clean up
    write.send(Message::Close(None)).await.ok();
    server.shutdown();
}

#[tokio::test]
async fn test_agent_allows_all_frames() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("allow-agent.sock");

    // Create allowing agent
    let agent = Arc::new(AllowingAgent::new());
    let agent_clone = agent.clone();

    // Start agent server
    let server = AgentServer::new(
        "allow-agent",
        socket_path.clone(),
        Box::new(AllowingAgentWrapper(agent_clone)),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client and send WebSocket frame event
    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    let event = WebSocketFrameEvent {
        correlation_id: "test-123".to_string(),
        opcode: "text".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Hello"),
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    assert_eq!(response.decision, Decision::Allow);
    assert_eq!(response.websocket_decision, Some(WebSocketDecision::Allow));

    // Verify agent was called
    assert_eq!(agent.frames_inspected(), 1);

    client.close().await.unwrap();
    server_handle.abort();
}

// Wrapper to hold Arc<AllowingAgent>
struct AllowingAgentWrapper(Arc<AllowingAgent>);

#[async_trait::async_trait]
impl AgentHandler for AllowingAgentWrapper {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.0.on_websocket_frame(event).await
    }
}

#[tokio::test]
async fn test_agent_drops_blocked_frames() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("filter-agent.sock");

    // Create filtering agent that blocks "secret" keyword
    let agent = Arc::new(FilteringAgent::new(vec![
        "secret".to_string(),
        "password".to_string(),
    ]));
    let agent_clone = agent.clone();

    // Start agent server
    let server = AgentServer::new(
        "filter-agent",
        socket_path.clone(),
        Box::new(FilteringAgentWrapper(agent_clone)),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send allowed frame
    let event = WebSocketFrameEvent {
        correlation_id: "test-1".to_string(),
        opcode: "text".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Hello world"),
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    assert_eq!(response.websocket_decision, Some(WebSocketDecision::Allow));

    // Send blocked frame
    let event = WebSocketFrameEvent {
        correlation_id: "test-2".to_string(),
        opcode: "text".to_string(),
        data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"my secret data",
        ),
        client_to_server: true,
        frame_index: 1,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    assert_eq!(response.websocket_decision, Some(WebSocketDecision::Drop));

    // Verify counts
    assert_eq!(agent.frames_inspected(), 2);
    assert_eq!(agent.frames_dropped(), 1);

    client.close().await.unwrap();
    server_handle.abort();
}

struct FilteringAgentWrapper(Arc<FilteringAgent>);

#[async_trait::async_trait]
impl AgentHandler for FilteringAgentWrapper {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.0.on_websocket_frame(event).await
    }
}

#[tokio::test]
async fn test_agent_closes_connection() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("close-agent.sock");

    // Create closing agent that closes on "malicious" pattern
    let agent = Arc::new(ClosingAgent::new(
        vec!["malicious".to_string(), "attack".to_string()],
        1008, // Policy Violation
        "Malicious content detected".to_string(),
    ));
    let agent_clone = agent.clone();

    let server = AgentServer::new(
        "close-agent",
        socket_path.clone(),
        Box::new(ClosingAgentWrapper(agent_clone)),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send safe frame
    let event = WebSocketFrameEvent {
        correlation_id: "test-1".to_string(),
        opcode: "text".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"Safe message"),
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    assert_eq!(response.websocket_decision, Some(WebSocketDecision::Allow));

    // Send malicious frame
    let event = WebSocketFrameEvent {
        correlation_id: "test-2".to_string(),
        opcode: "text".to_string(),
        data: base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"malicious payload",
        ),
        client_to_server: true,
        frame_index: 1,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    let response = client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    match response.websocket_decision {
        Some(WebSocketDecision::Close { code, reason }) => {
            assert_eq!(code, 1008);
            assert_eq!(reason, "Malicious content detected");
        }
        _ => panic!("Expected Close decision"),
    }

    assert_eq!(agent.frames_inspected(), 2);

    client.close().await.unwrap();
    server_handle.abort();
}

struct ClosingAgentWrapper(Arc<ClosingAgent>);

#[async_trait::async_trait]
impl AgentHandler for ClosingAgentWrapper {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.0.on_websocket_frame(event).await
    }
}

#[tokio::test]
async fn test_bidirectional_frame_inspection() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("direction-agent.sock");

    let agent = Arc::new(DirectionalAgent::new());
    let agent_clone = agent.clone();

    let server = AgentServer::new(
        "direction-agent",
        socket_path.clone(),
        Box::new(DirectionalAgentWrapper(agent_clone)),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send client->server frames
    for i in 0..3 {
        let event = WebSocketFrameEvent {
            correlation_id: format!("c2s-{}", i),
            opcode: "text".to_string(),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("Client message {}", i).as_bytes(),
            ),
            client_to_server: true,
            frame_index: i,
            fin: true,
            route_id: Some("ws-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Should receive response");
    }

    // Send server->client frames
    for i in 0..2 {
        let event = WebSocketFrameEvent {
            correlation_id: format!("s2c-{}", i),
            opcode: "text".to_string(),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("Server message {}", i).as_bytes(),
            ),
            client_to_server: false,
            frame_index: i,
            fin: true,
            route_id: Some("ws-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Should receive response");
    }

    // Verify direction counts
    assert_eq!(agent.client_to_server_frames(), 3);
    assert_eq!(agent.server_to_client_frames(), 2);

    client.close().await.unwrap();
    server_handle.abort();
}

struct DirectionalAgentWrapper(Arc<DirectionalAgent>);

#[async_trait::async_trait]
impl AgentHandler for DirectionalAgentWrapper {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.0.on_request_headers(event).await
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.0.on_websocket_frame(event).await
    }
}

#[tokio::test]
async fn test_frame_index_tracking() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("index-agent.sock");

    // Track received frame indices
    let indices = Arc::new(Mutex::new(Vec::new()));
    let indices_clone = indices.clone();

    let server = AgentServer::new(
        "index-agent",
        socket_path.clone(),
        Box::new(IndexTrackingAgent {
            indices: indices_clone,
        }),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send frames with specific indices
    for i in 0..5 {
        let event = WebSocketFrameEvent {
            correlation_id: format!("frame-{}", i),
            opcode: "text".to_string(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"test"),
            client_to_server: true,
            frame_index: i,
            fin: true,
            route_id: Some("ws-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Should receive response");
    }

    // Verify indices were tracked correctly
    let tracked = indices.lock().await;
    assert_eq!(*tracked, vec![0, 1, 2, 3, 4]);

    client.close().await.unwrap();
    server_handle.abort();
}

struct IndexTrackingAgent {
    indices: Arc<Mutex<Vec<u64>>>,
}

#[async_trait::async_trait]
impl AgentHandler for IndexTrackingAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        let mut indices = self.indices.lock().await;
        indices.push(event.frame_index);
        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

#[tokio::test]
async fn test_binary_frame_inspection() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("binary-agent.sock");

    // Track received binary data
    let received_data = Arc::new(Mutex::new(Vec::new()));
    let received_clone = received_data.clone();

    let server = AgentServer::new(
        "binary-agent",
        socket_path.clone(),
        Box::new(BinaryDataAgent {
            received: received_clone,
        }),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send binary frame with raw bytes
    let binary_data: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let event = WebSocketFrameEvent {
        correlation_id: "binary-1".to_string(),
        opcode: "binary".to_string(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &binary_data),
        client_to_server: true,
        frame_index: 0,
        fin: true,
        route_id: Some("ws-route".to_string()),
        client_ip: "127.0.0.1".to_string(),
    };

    client
        .send_event(EventType::WebSocketFrame, &event)
        .await
        .expect("Should receive response");

    // Verify binary data was received correctly
    let received = received_data.lock().await;
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], binary_data);

    client.close().await.unwrap();
    server_handle.abort();
}

struct BinaryDataAgent {
    received: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait::async_trait]
impl AgentHandler for BinaryDataAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        if let Ok(data) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &event.data)
        {
            let mut received = self.received.lock().await;
            received.push(data);
        }
        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}

#[tokio::test]
async fn test_fragmented_message_handling() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("fragment-agent.sock");

    // Track fin flags
    let fin_flags = Arc::new(Mutex::new(Vec::new()));
    let fin_clone = fin_flags.clone();

    let server = AgentServer::new(
        "fragment-agent",
        socket_path.clone(),
        Box::new(FragmentTrackingAgent { fins: fin_clone }),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    // Send fragmented message (fin=false, then fin=true)
    let events = [
        (false, "First fragment"),
        (false, "Second fragment"),
        (true, "Final fragment"),
    ];

    for (i, (fin, data)) in events.iter().enumerate() {
        let event = WebSocketFrameEvent {
            correlation_id: format!("frag-{}", i),
            opcode: if i == 0 { "text" } else { "continuation" }.to_string(),
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                data.as_bytes(),
            ),
            client_to_server: true,
            frame_index: i as u64,
            fin: *fin,
            route_id: Some("ws-route".to_string()),
            client_ip: "127.0.0.1".to_string(),
        };

        client
            .send_event(EventType::WebSocketFrame, &event)
            .await
            .expect("Should receive response");
    }

    // Verify fin flags were tracked
    let tracked = fin_flags.lock().await;
    assert_eq!(*tracked, vec![false, false, true]);

    client.close().await.unwrap();
    server_handle.abort();
}

struct FragmentTrackingAgent {
    fins: Arc<Mutex<Vec<bool>>>,
}

#[async_trait::async_trait]
impl AgentHandler for FragmentTrackingAgent {
    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        let mut fins = self.fins.lock().await;
        fins.push(event.fin);
        AgentResponse::default_allow().with_websocket_decision(WebSocketDecision::Allow)
    }
}
