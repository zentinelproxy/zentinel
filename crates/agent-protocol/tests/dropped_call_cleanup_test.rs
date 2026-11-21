//! A call to an agent that its caller drops must leave nothing behind.
//!
//! The proxy drops agent calls routinely: the 300 ms limit on
//! `RequestComplete`, the per-agent timeout of a filter, a client that
//! disconnects. A dropped call has registered its response channel with the
//! connection and counted itself as in flight; both have to be undone, wherever
//! in the call the drop happens.
//!
//! Each test starts an agent that receives every call and answers none, waits
//! until the agent has the call, and drops it. No timer decides when: the call
//! is dropped at the point it is waiting for its response.
//!
//! What a connection still holds is read through the public API:
//! `in_flight()`, and the number of calls `cancel_all()` finds waiting.

use async_trait::async_trait;
use std::future::Future;
use std::time::Duration;
use tokio::io::{BufReader, BufWriter};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::mpsc;
use tokio_stream::wrappers::TcpListenerStream;
use zentinel_agent_protocol::v2::uds::{
    read_message, write_message, MessageType, UdsCapabilities, UdsEncoding, UdsFeatures,
    UdsHandshakeResponse, UdsLimits,
};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentClientV2, AgentClientV2Uds, AgentHandlerV2, AgentPool, AgentPoolConfig,
    CancelReason, GrpcAgentServerV2, PROTOCOL_VERSION_2,
};
use zentinel_agent_protocol::{
    AgentProtocolError, AgentResponse, BinaryRequestBodyChunkEvent, GuardrailInspectEvent,
    GuardrailInspectionType, RequestCompleteEvent, RequestHeadersEvent, RequestMetadata,
};

/// Long enough that no call below ends by its own timeout.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn request_headers(correlation_id: &str) -> RequestHeadersEvent {
    RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: correlation_id.to_string(),
            request_id: "req-1".to_string(),
            client_ip: "127.0.0.1".to_string(),
            client_port: 40000,
            server_name: Some("a.example".to_string()),
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            traceparent: None,
        },
        method: "GET".to_string(),
        uri: "/".to_string(),
        headers: std::collections::HashMap::new(),
    }
}

fn request_complete(correlation_id: &str) -> RequestCompleteEvent {
    RequestCompleteEvent {
        correlation_id: correlation_id.to_string(),
        status: 200,
        duration_ms: 1,
        request_body_size: 0,
        response_body_size: 0,
        upstream_attempts: 1,
        upstream: None,
        from_cache: false,
        error: None,
    }
}

fn body_chunk(correlation_id: &str) -> BinaryRequestBodyChunkEvent {
    BinaryRequestBodyChunkEvent {
        correlation_id: correlation_id.to_string(),
        data: bytes::Bytes::from_static(b"caf\xc3\xa9"),
        is_last: true,
        total_size: Some(5),
        chunk_index: 0,
        bytes_received: 5,
    }
}

/// An agent on a Unix socket that completes the handshake, reads every event
/// and answers only the calls it is told to.
struct FakeUdsAgent {
    _dir: tempfile::TempDir,
    socket_path: String,
    /// The correlation id of each event the agent has read.
    received: mpsc::UnboundedReceiver<String>,
    /// Correlation ids to send a response for.
    reply: mpsc::UnboundedSender<String>,
}

impl FakeUdsAgent {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let (received_tx, received) = mpsc::unbounded_channel();
        let (reply, mut reply_rx) = mpsc::unbounded_channel::<String>();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);
            let mut writer = BufWriter::new(write_half);

            let (msg_type, _) = read_message(&mut reader).await.unwrap();
            assert_eq!(msg_type, MessageType::HandshakeRequest);
            let handshake = UdsHandshakeResponse {
                protocol_version: PROTOCOL_VERSION_2,
                capabilities: UdsCapabilities {
                    agent_id: "agent-a".to_string(),
                    name: "Fake Agent".to_string(),
                    version: "1.0.0".to_string(),
                    supported_events: vec![1, 2, 5],
                    features: UdsFeatures::default(),
                    limits: UdsLimits::default(),
                },
                success: true,
                error: None,
                encoding: UdsEncoding::Json,
            };
            write_message(
                &mut writer,
                MessageType::HandshakeResponse,
                &serde_json::to_vec(&handshake).unwrap(),
            )
            .await
            .unwrap();

            tokio::spawn(async move {
                while let Some(correlation_id) = reply_rx.recv().await {
                    let mut response = AgentResponse::default_allow();
                    response.audit.custom.insert(
                        "correlation_id".to_string(),
                        serde_json::Value::String(correlation_id),
                    );
                    if write_message(
                        &mut writer,
                        MessageType::AgentResponse,
                        &serde_json::to_vec(&response).unwrap(),
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
            });

            while let Ok((msg_type, payload)) = read_message(&mut reader).await {
                if !(MessageType::RequestHeaders as u8..=MessageType::GuardrailInspect as u8)
                    .contains(&(msg_type as u8))
                {
                    continue;
                }
                let event: serde_json::Value = serde_json::from_slice(&payload).unwrap();
                let correlation_id = event["correlation_id"].as_str().unwrap().to_string();
                if received_tx.send(correlation_id).is_err() {
                    break;
                }
            }
        });

        Self {
            _dir: dir,
            socket_path: socket_path.to_string_lossy().into_owned(),
            received,
            reply,
        }
    }

    async fn client(&self) -> AgentClientV2Uds {
        let client = AgentClientV2Uds::new("agent-a", &self.socket_path, REQUEST_TIMEOUT)
            .await
            .unwrap();
        client.connect().await.unwrap();
        client
    }

    /// Polls `call` until the agent has read an event, then drops it.
    async fn drop_call_once_received<F: Future>(&mut self, call: F) -> String {
        tokio::select! {
            _ = call => panic!("the agent does not answer, so the call cannot finish"),
            correlation_id = self.received.recv() => correlation_id.expect("agent task running"),
        }
    }
}

/// A gRPC agent that receives every request headers event and answers none.
struct SilentGrpcHandler {
    received: mpsc::UnboundedSender<String>,
}

#[async_trait]
impl AgentHandlerV2 for SilentGrpcHandler {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("silent", "Silent Agent", "1.0.0")
    }

    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let _ = self.received.send(event.metadata.correlation_id);
        std::future::pending().await
    }
}

#[tokio::test]
async fn uds_call_dropped_while_waiting_leaves_nothing_registered() {
    let mut agent = FakeUdsAgent::start().await;
    let client = agent.client().await;

    let dropped = agent
        .drop_call_once_received(client.send_request_headers("cid-1", &request_headers("cid-1")))
        .await;

    assert_eq!(dropped, "cid-1");
    assert_eq!(client.in_flight(), 0, "the dropped call is still in flight");
    assert_eq!(
        client.cancel_all(CancelReason::Manual).await.unwrap(),
        0,
        "the dropped call is still registered as waiting for a response"
    );
}

#[tokio::test]
async fn uds_body_chunk_dropped_while_waiting_leaves_nothing_registered() {
    let mut agent = FakeUdsAgent::start().await;
    let client = agent.client().await;

    agent
        .drop_call_once_received(client.send_request_body_chunk_binary(&body_chunk("cid-2")))
        .await;

    assert_eq!(client.in_flight(), 0, "the dropped call is still in flight");
    assert_eq!(
        client.cancel_all(CancelReason::Manual).await.unwrap(),
        0,
        "the dropped call is still registered as waiting for a response"
    );
}

#[tokio::test]
async fn uds_call_that_times_out_is_no_longer_in_flight() {
    let mut agent = FakeUdsAgent::start().await;
    let client = AgentClientV2Uds::new("agent-a", &agent.socket_path, Duration::from_millis(100))
        .await
        .unwrap();
    client.connect().await.unwrap();

    let result = client
        .send_request_headers("cid-3", &request_headers("cid-3"))
        .await;

    assert!(matches!(result, Err(AgentProtocolError::Timeout(_))));
    assert_eq!(agent.received.recv().await.as_deref(), Some("cid-3"));
    assert_eq!(
        client.in_flight(),
        0,
        "the timed-out call is still in flight"
    );
    assert_eq!(client.cancel_all(CancelReason::Manual).await.unwrap(), 0);
}

#[tokio::test]
async fn uds_body_chunk_that_cannot_be_sent_leaves_nothing_registered() {
    let agent = FakeUdsAgent::start().await;
    let client = agent.client().await;
    client.close().await.unwrap();

    let result = client
        .send_request_body_chunk_binary(&body_chunk("cid-4"))
        .await;

    assert!(matches!(result, Err(AgentProtocolError::ConnectionClosed)));
    assert_eq!(client.in_flight(), 0);
    assert_eq!(
        client.cancel_all(CancelReason::Manual).await.unwrap(),
        0,
        "the call that was never sent is still registered as waiting"
    );
}

#[tokio::test]
async fn uds_response_arriving_after_its_call_was_dropped_is_discarded() {
    let mut agent = FakeUdsAgent::start().await;
    let client = agent.client().await;

    let dropped = agent
        .drop_call_once_received(client.send_request_headers("cid-5", &request_headers("cid-5")))
        .await;
    agent.reply.send(dropped).unwrap();

    // The late response is read before the answer to this call, so the call
    // being answered shows that the reader went past it without trouble.
    let complete = request_complete("cid-6");
    let second = client.send_request_complete("cid-6", &complete);
    let answer = async {
        assert_eq!(agent.received.recv().await.as_deref(), Some("cid-6"));
        agent.reply.send("cid-6".to_string()).unwrap();
    };
    let (result, ()) = tokio::join!(second, answer);

    result.expect("the second call is answered");
    assert_eq!(client.in_flight(), 0);
    assert_eq!(client.cancel_all(CancelReason::Manual).await.unwrap(), 0);
}

#[tokio::test]
async fn grpc_call_dropped_while_waiting_leaves_nothing_registered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (received_tx, mut received) = mpsc::unbounded_channel();
    let service = GrpcAgentServerV2::new(
        "silent",
        Box::new(SilentGrpcHandler {
            received: received_tx,
        }),
    )
    .into_service();
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });

    let client = AgentClientV2::new("agent-a", format!("http://{addr}"), REQUEST_TIMEOUT)
        .await
        .unwrap();
    client.connect().await.unwrap();

    let event = request_headers("cid-7");
    tokio::select! {
        _ = client.send_request_headers("cid-7", &event) => {
            panic!("the agent does not answer, so the call cannot finish")
        }
        correlation_id = received.recv() => assert_eq!(correlation_id.as_deref(), Some("cid-7")),
    }

    assert_eq!(
        client.cancel_all(CancelReason::Manual).await.unwrap(),
        0,
        "the dropped call is still registered as waiting for a response"
    );
}

#[tokio::test]
async fn pool_call_dropped_while_waiting_is_no_longer_in_flight() {
    let mut agent = FakeUdsAgent::start().await;
    let pool = AgentPool::with_config(AgentPoolConfig {
        connections_per_agent: 1,
        request_timeout: REQUEST_TIMEOUT,
        ..Default::default()
    });
    pool.add_agent("agent-a", agent.socket_path.clone())
        .await
        .unwrap();

    // `RequestComplete` is the call the proxy gives 300 ms.
    agent
        .drop_call_once_received(pool.send_request_complete(
            "agent-a",
            "cid-8",
            &request_complete("cid-8"),
        ))
        .await;
    assert_eq!(
        pool.agent_stats("agent-a").await.unwrap().total_in_flight,
        0,
        "the pool still counts the dropped call against its connection"
    );

    agent
        .drop_call_once_received(pool.send_request_headers(
            "agent-a",
            "cid-9",
            &request_headers("cid-9"),
        ))
        .await;
    assert_eq!(
        pool.agent_stats("agent-a").await.unwrap().total_in_flight,
        0
    );
    assert_eq!(
        pool.protocol_metrics().snapshot().in_flight_requests,
        0,
        "the in-flight gauge still counts the dropped call"
    );
}

#[tokio::test]
async fn pool_call_that_finds_no_connection_leaves_the_gauge_at_zero() {
    let pool = AgentPool::with_config(AgentPoolConfig {
        connections_per_agent: 1,
        request_timeout: REQUEST_TIMEOUT,
        ..Default::default()
    });
    let headers = request_headers("cid-10");
    let guardrail = GuardrailInspectEvent {
        correlation_id: "cid-12".to_string(),
        inspection_type: GuardrailInspectionType::PiiDetection,
        content: "caf\u{e9}".to_string(),
        model: None,
        categories: Vec::new(),
        route_id: None,
        metadata: std::collections::HashMap::new(),
    };

    // No agent called "unknown" is in the pool, so no connection can be chosen.
    assert!(pool
        .send_request_headers("unknown", "cid-10", &headers)
        .await
        .is_err());
    assert!(pool
        .send_request_headers_with_sticky_session("session-1", "unknown", "cid-11", &headers)
        .await
        .is_err());
    assert!(pool
        .send_guardrail_inspect("unknown", "cid-12", &guardrail)
        .await
        .is_err());

    assert_eq!(
        pool.protocol_metrics().snapshot().in_flight_requests,
        0,
        "the in-flight gauge still counts calls that never reached a connection"
    );
}
