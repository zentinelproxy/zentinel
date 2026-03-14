//! Integration tests for reverse agent connections.
//!
//! Tests the complete reverse connection flow:
//! - Listener binding and cleanup
//! - Agent registration handshake
//! - Validation (protocol version, agent ID, allowed list, auth)
//! - Pool integration after successful registration
//! - Timeout handling for slow handshakes
//! - Connection lifecycle (close, drop)

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use zentinel_agent_protocol::v2::pool::AgentPoolConfig;
use zentinel_agent_protocol::v2::reverse::{
    RegistrationRequest, RegistrationResponse, ReverseConnectionConfig, ReverseConnectionListener,
};
use zentinel_agent_protocol::v2::uds::{MessageType, UdsCapabilities, UdsFeatures, UdsLimits};
use zentinel_agent_protocol::v2::{AgentPool, PROTOCOL_VERSION_2};
use zentinel_agent_protocol::AgentProtocolError;

// =============================================================================
// Helper Functions
// =============================================================================

fn test_capabilities(agent_id: &str) -> UdsCapabilities {
    UdsCapabilities {
        agent_id: agent_id.to_string(),
        name: format!("Test Agent {}", agent_id),
        version: "1.0.0".to_string(),
        supported_events: vec![0x10, 0x11], // RequestHeaders, RequestBodyChunk
        features: UdsFeatures {
            streaming_body: false,
            websocket: false,
            guardrails: false,
            config_push: false,
            metrics_export: false,
            concurrent_requests: 10,
            cancellation: false,
            flow_control: false,
            health_reporting: false,
        },
        limits: UdsLimits {
            max_body_size: 1024 * 1024,
            max_concurrency: 10,
            preferred_chunk_size: 64 * 1024,
        },
    }
}

fn test_registration_request(agent_id: &str) -> RegistrationRequest {
    RegistrationRequest {
        protocol_version: PROTOCOL_VERSION_2,
        agent_id: agent_id.to_string(),
        capabilities: test_capabilities(agent_id),
        auth_token: None,
        metadata: None,
    }
}

/// Write a framed message to a stream (4-byte BE length + 1-byte type + payload).
async fn write_framed_message(stream: &mut UnixStream, msg_type: MessageType, payload: &[u8]) {
    let total_len = (payload.len() + 1) as u32;
    stream.write_all(&total_len.to_be_bytes()).await.unwrap();
    stream.write_all(&[msg_type as u8]).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.flush().await.unwrap();
}

/// Read a framed message from a stream.
async fn read_framed_message(stream: &mut UnixStream) -> (MessageType, Vec<u8>) {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.unwrap();
    let total_len = u32::from_be_bytes(len_bytes) as usize;

    let mut type_byte = [0u8; 1];
    stream.read_exact(&mut type_byte).await.unwrap();
    let msg_type = MessageType::try_from(type_byte[0]).unwrap();

    let payload_len = total_len - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await.unwrap();
    }

    (msg_type, payload)
}

/// Perform a full agent registration handshake on a raw stream.
async fn perform_handshake(
    stream: &mut UnixStream,
    request: &RegistrationRequest,
) -> RegistrationResponse {
    let payload = serde_json::to_vec(request).unwrap();
    write_framed_message(stream, MessageType::HandshakeRequest, &payload).await;

    let (msg_type, response_payload) = read_framed_message(stream).await;
    assert_eq!(msg_type, MessageType::HandshakeResponse);

    serde_json::from_slice(&response_payload).unwrap()
}

fn temp_socket_path(name: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    // Leak the dir so it isn't cleaned up before the test finishes
    let path = dir.path().join(format!("{}.sock", name));
    let path_str = path.to_string_lossy().to_string();
    std::mem::forget(dir);
    path_str
}

// =============================================================================
// Listener Binding Tests
// =============================================================================

#[tokio::test]
async fn listener_binds_to_uds_path() {
    let socket_path = temp_socket_path("bind-test");
    let config = ReverseConnectionConfig::default();

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    assert_eq!(listener.socket_path(), socket_path);
    assert!(std::path::Path::new(&socket_path).exists());
}

#[tokio::test]
async fn listener_removes_existing_socket_on_bind() {
    let socket_path = temp_socket_path("rebind-test");

    // Create a file at the socket path
    std::fs::write(&socket_path, "placeholder").unwrap();
    assert!(std::path::Path::new(&socket_path).exists());

    let config = ReverseConnectionConfig::default();
    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    // Should have replaced the file with a socket
    assert_eq!(listener.socket_path(), socket_path);
}

#[tokio::test]
async fn listener_cleans_up_socket_on_drop() {
    let socket_path = temp_socket_path("drop-test");
    let config = ReverseConnectionConfig::default();

    {
        let _listener = ReverseConnectionListener::bind_uds(&socket_path, config)
            .await
            .unwrap();
        assert!(std::path::Path::new(&socket_path).exists());
    }
    // Listener dropped — socket should be cleaned up
    assert!(!std::path::Path::new(&socket_path).exists());
}

// =============================================================================
// Registration Validation Tests
// =============================================================================

#[tokio::test]
async fn successful_registration_handshake() {
    let socket_path = temp_socket_path("success-handshake");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    // Spawn agent connection
    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let request = test_registration_request("test-agent-1");
        perform_handshake(&mut stream, &request).await
    });

    // Accept on listener side
    let result = listener.accept_one(&pool).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "test-agent-1");

    // Verify agent got success response
    let response = agent_handle.await.unwrap();
    assert!(response.success);
    assert!(response.error.is_none());
    assert_eq!(response.proxy_id, "zentinel-proxy");
    assert!(!response.connection_id.is_empty());
}

#[tokio::test]
async fn rejects_wrong_protocol_version() {
    let socket_path = temp_socket_path("wrong-version");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let mut request = test_registration_request("bad-version-agent");
        request.protocol_version = 99;
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::VersionMismatch { expected, actual } => {
            assert_eq!(expected, PROTOCOL_VERSION_2);
            assert_eq!(actual, 99);
        }
        other => panic!("Expected VersionMismatch, got: {:?}", other),
    }

    let response = agent_handle.await.unwrap();
    assert!(!response.success);
    assert!(response.error.is_some());
}

#[tokio::test]
async fn rejects_empty_agent_id() {
    let socket_path = temp_socket_path("empty-id");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let mut request = test_registration_request("");
        request.agent_id = String::new();
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::InvalidMessage(msg) => {
            assert!(
                msg.contains("empty"),
                "Error should mention empty ID: {}",
                msg
            );
        }
        other => panic!("Expected InvalidMessage, got: {:?}", other),
    }

    let response = agent_handle.await.unwrap();
    assert!(!response.success);
}

#[tokio::test]
async fn rejects_agent_not_in_allowed_list() {
    let socket_path = temp_socket_path("not-allowed");
    let mut allowed = HashSet::new();
    allowed.insert("allowed-agent".to_string());

    let config = ReverseConnectionConfig {
        allowed_agents: allowed,
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let request = test_registration_request("unauthorized-agent");
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::InvalidMessage(msg) => {
            assert!(
                msg.contains("not in the allowed list"),
                "Error should mention allowed list: {}",
                msg
            );
        }
        other => panic!("Expected InvalidMessage, got: {:?}", other),
    }

    let response = agent_handle.await.unwrap();
    assert!(!response.success);
}

#[tokio::test]
async fn accepts_agent_in_allowed_list() {
    let socket_path = temp_socket_path("in-allowed-list");
    let mut allowed = HashSet::new();
    allowed.insert("allowed-agent".to_string());

    let config = ReverseConnectionConfig {
        allowed_agents: allowed,
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let request = test_registration_request("allowed-agent");
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "allowed-agent");

    let response = agent_handle.await.unwrap();
    assert!(response.success);
}

#[tokio::test]
async fn rejects_missing_auth_token_when_required() {
    let socket_path = temp_socket_path("auth-required");
    let config = ReverseConnectionConfig {
        require_auth: true,
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let request = test_registration_request("no-token-agent");
        // auth_token is None by default
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::InvalidMessage(msg) => {
            assert!(
                msg.contains("Authentication required"),
                "Error should mention auth: {}",
                msg
            );
        }
        other => panic!("Expected InvalidMessage, got: {:?}", other),
    }

    let response = agent_handle.await.unwrap();
    assert!(!response.success);
}

#[tokio::test]
async fn accepts_valid_auth_token() {
    let socket_path = temp_socket_path("auth-valid");
    let config = ReverseConnectionConfig {
        require_auth: true,
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    let agent_handle = tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let mut request = test_registration_request("authed-agent");
        request.auth_token = Some("valid-token-123".to_string());
        perform_handshake(&mut stream, &request).await
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_ok());

    let response = agent_handle.await.unwrap();
    assert!(response.success);
}

// =============================================================================
// Handshake Timeout Tests
// =============================================================================

#[tokio::test]
async fn handshake_timeout_on_slow_agent() {
    let socket_path = temp_socket_path("timeout");
    let config = ReverseConnectionConfig {
        handshake_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    // Agent connects but never sends registration
    let _agent_handle = tokio::spawn(async move {
        let _stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        // Hold connection open without sending anything
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::Timeout(duration) => {
            assert_eq!(duration, Duration::from_millis(100));
        }
        other => panic!("Expected Timeout, got: {:?}", other),
    }
}

// =============================================================================
// Protocol Error Tests
// =============================================================================

#[tokio::test]
async fn rejects_wrong_message_type() {
    let socket_path = temp_socket_path("wrong-type");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        // Send an AgentResponse instead of HandshakeRequest
        let payload = b"{}";
        write_framed_message(&mut stream, MessageType::AgentResponse, payload).await;
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::InvalidMessage(msg) => {
            assert!(
                msg.contains("Expected registration request"),
                "Error should mention expected type: {}",
                msg
            );
        }
        other => panic!("Expected InvalidMessage, got: {:?}", other),
    }
}

#[tokio::test]
async fn rejects_malformed_json_payload() {
    let socket_path = temp_socket_path("malformed-json");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        // Send HandshakeRequest with invalid JSON
        write_framed_message(&mut stream, MessageType::HandshakeRequest, b"not-json!!").await;
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        AgentProtocolError::InvalidMessage(_) => {} // Expected
        other => panic!("Expected InvalidMessage, got: {:?}", other),
    }
}

#[tokio::test]
async fn handles_connection_closed_during_handshake() {
    let socket_path = temp_socket_path("conn-closed");
    let config = ReverseConnectionConfig {
        handshake_timeout: Duration::from_secs(2),
        ..Default::default()
    };
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        // Immediately close the connection
        drop(stream);
    });

    let result = listener.accept_one(&pool).await;
    assert!(result.is_err());
}

// =============================================================================
// Accept Loop Tests
// =============================================================================

#[tokio::test]
async fn accept_loop_handles_multiple_agents() {
    let socket_path = temp_socket_path("multi-agent");
    let config = ReverseConnectionConfig::default();
    let pool = Arc::new(AgentPool::with_config(AgentPoolConfig::default()));

    let listener = Arc::new(
        ReverseConnectionListener::bind_uds(&socket_path, config)
            .await
            .unwrap(),
    );

    // Start accept loop in background
    let listener_clone = Arc::clone(&listener);
    let pool_clone = Arc::clone(&pool);
    tokio::spawn(async move {
        listener_clone.accept_loop(pool_clone).await;
    });

    // Give the accept loop time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect 3 agents sequentially
    for i in 0..3 {
        let socket_path_clone = socket_path.clone();
        let agent_id = format!("agent-{}", i);
        let handle = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
            let request = test_registration_request(&agent_id);
            let response = perform_handshake(&mut stream, &request).await;
            assert!(
                response.success,
                "Agent {} registration failed: {:?}",
                agent_id, response.error
            );
            // Keep the stream alive briefly
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        handle.await.unwrap();
    }
}

// =============================================================================
// ReverseConnectionClient Tests
// =============================================================================

#[tokio::test]
async fn reverse_client_reports_connected_after_registration() {
    let socket_path = temp_socket_path("client-connected");
    let config = ReverseConnectionConfig::default();
    let pool = AgentPool::with_config(AgentPoolConfig::default());

    let listener = ReverseConnectionListener::bind_uds(&socket_path, config)
        .await
        .unwrap();

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let mut stream = UnixStream::connect(&socket_path_clone).await.unwrap();
        let request = test_registration_request("connected-agent");
        let response = perform_handshake(&mut stream, &request).await;
        assert!(response.success);
        // Keep connection alive
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let agent_id = listener.accept_one(&pool).await.unwrap();
    assert_eq!(agent_id, "connected-agent");

    // The agent should now be registered in the pool
    let stats = pool.stats().await;
    assert!(
        !stats.is_empty(),
        "Pool should have at least one agent after registration"
    );
    assert_eq!(stats[0].agent_id, "connected-agent");
}

// =============================================================================
// Config Default Tests
// =============================================================================

#[test]
fn config_default_values_are_reasonable() {
    let config = ReverseConnectionConfig::default();

    assert_eq!(config.backlog, 128);
    assert_eq!(config.handshake_timeout, Duration::from_secs(10));
    assert_eq!(config.max_connections_per_agent, 4);
    assert!(config.allowed_agents.is_empty());
    assert!(!config.require_auth);
    assert_eq!(config.request_timeout, Duration::from_secs(30));
}

#[test]
fn registration_request_roundtrip_with_metadata() {
    let mut request = test_registration_request("meta-agent");
    request.metadata = Some(serde_json::json!({
        "region": "us-west-2",
        "version": "2.1.0",
        "tags": ["security", "waf"]
    }));
    request.auth_token = Some("bearer-token-abc".to_string());

    let json = serde_json::to_vec(&request).unwrap();
    let parsed: RegistrationRequest = serde_json::from_slice(&json).unwrap();

    assert_eq!(parsed.agent_id, "meta-agent");
    assert_eq!(parsed.protocol_version, PROTOCOL_VERSION_2);
    assert!(parsed.auth_token.is_some());
    assert!(parsed.metadata.is_some());
    let meta = parsed.metadata.unwrap();
    assert_eq!(meta["region"], "us-west-2");
}

#[test]
fn registration_response_roundtrip_success() {
    let response = RegistrationResponse {
        success: true,
        error: None,
        proxy_id: "zentinel-proxy".to_string(),
        proxy_version: "0.5.12".to_string(),
        connection_id: "agent-1-abc123".to_string(),
    };

    let json = serde_json::to_vec(&response).unwrap();
    let parsed: RegistrationResponse = serde_json::from_slice(&json).unwrap();

    assert!(parsed.success);
    assert!(parsed.error.is_none());
    assert_eq!(parsed.proxy_id, "zentinel-proxy");
    assert_eq!(parsed.connection_id, "agent-1-abc123");
}

#[test]
fn registration_response_roundtrip_failure() {
    let response = RegistrationResponse {
        success: false,
        error: Some("Agent not in allowed list".to_string()),
        proxy_id: "zentinel-proxy".to_string(),
        proxy_version: "0.5.12".to_string(),
        connection_id: String::new(),
    };

    let json = serde_json::to_vec(&response).unwrap();
    let parsed: RegistrationResponse = serde_json::from_slice(&json).unwrap();

    assert!(!parsed.success);
    assert_eq!(parsed.error.unwrap(), "Agent not in allowed list");
}
