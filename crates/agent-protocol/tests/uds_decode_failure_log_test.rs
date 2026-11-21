//! How an agent server logs an event it cannot decode.
//!
//! The failure is logged against the request it belongs to, and what the
//! decoder says about the payload, which can quote a header's value, stays out
//! of every level but `debug`.
//!
//! This is its own test binary because it reads the log through a subscriber
//! set for the thread. Another test that logs through the same call at the
//! same moment on another thread can leave that subscriber without the event,
//! and in the library's own tests, which run side by side, it does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds::{
    read_message, write_message, MessageType, UdsHandshakeRequest,
};
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentProtocolError, EventType};

/// The fields of every event logged on the current thread.
struct LogCapture(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for LogCapture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);

        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={:?}", field.name(), value);
            }
        }

        let mut fields = Fields(event.metadata().level().to_string());
        event.record(&mut fields);
        self.0.lock().expect("log capture lock").push(fields.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

struct Agent;

#[async_trait::async_trait]
impl AgentHandlerV2 for Agent {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("log-test", "Log Test Agent", "1.0.0")
            .with_event(EventType::RequestHeaders)
    }
}

#[tokio::test]
async fn the_failure_is_logged_with_the_correlation_id_and_not_the_payload() {
    let logged = Arc::new(Mutex::new(Vec::new()));
    let _capture = tracing::subscriber::set_default(LogCapture(Arc::clone(&logged)));

    let dir = tempfile::tempdir().expect("temporary directory");
    let socket_path = dir.path().join("agent.sock");
    let server = UdsAgentServerV2::new("log-test", socket_path.clone(), Box::new(Agent));
    let server_task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent never listened"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Connect the way the proxy does, and send one event by hand.
    let (read_half, write_half) = UnixStream::connect(&socket_path)
        .await
        .expect("connect to the agent")
        .into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);
    let handshake = UdsHandshakeRequest {
        supported_versions: vec![2],
        proxy_id: "test-proxy".to_string(),
        proxy_version: "0.0.0".to_string(),
        config: None,
        supported_encodings: vec![],
    };
    write_message(
        &mut writer,
        MessageType::HandshakeRequest,
        &serde_json::to_vec(&handshake).expect("handshake serializes"),
    )
    .await
    .expect("send the handshake");
    let (msg_type, _) = read_message(&mut reader).await.expect("handshake reply");
    assert_eq!(msg_type, MessageType::HandshakeResponse);

    // `headers` maps a name to a list of values; a bare string is not one.
    let undecodable = br#"{
        "correlation_id": "cid-logged",
        "metadata": {"correlation_id": "cid-logged"},
        "method": "GET",
        "uri": "/",
        "headers": {"x-example": "value-for-the-test"}
    }"#;
    write_message(&mut writer, MessageType::RequestHeaders, undecodable)
        .await
        .expect("send the event");

    // The server closes the connection rather than answer.
    let reply = tokio::time::timeout(Duration::from_secs(5), read_message(&mut reader))
        .await
        .expect("the server neither answered nor closed the connection");
    assert!(
        matches!(reply, Err(AgentProtocolError::ConnectionClosed)),
        "expected the connection to be closed, got {:?}",
        reply.map(|(msg_type, _)| msg_type)
    );
    server_task.abort();

    let logged = logged.lock().expect("log capture lock").clone();
    assert!(
        logged
            .iter()
            .any(|line| line.starts_with("ERROR") && line.contains("cid-logged")),
        "no error carried the correlation id: {logged:?}"
    );
    let leaked: Vec<_> = logged
        .iter()
        .filter(|line| !line.starts_with("DEBUG") && line.contains("value-for-the-test"))
        .collect();
    assert!(leaked.is_empty(), "the payload was logged: {leaked:?}");
}
