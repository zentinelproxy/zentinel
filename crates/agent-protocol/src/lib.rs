// Allow large enum variants in generated protobuf code
#![allow(clippy::large_enum_variant)]

//! Agent protocol for Zentinel proxy
//!
//! This crate defines the protocol for communication between the proxy dataplane
//! and external processing agents (WAF, auth, rate limiting, custom logic).
//!
//! The protocol is inspired by SPOE (Stream Processing Offload Engine) and Envoy's ext_proc,
//! designed for bounded, predictable behavior with strong failure isolation.
//!
//! # Architecture
//!
//! - [`AgentClient`]: Client for sending events to agents from the proxy
//! - [`AgentServer`]: Server for implementing agent handlers
//! - [`AgentHandler`]: Trait for implementing agent logic
//! - [`AgentResponse`]: Response from agent with decision and mutations
//!
//! # Transports
//!
//! Two transport options are supported:
//!
//! ## Unix Domain Sockets (Default)
//! Messages are length-prefixed JSON:
//! - 4-byte big-endian length prefix
//! - JSON payload (max 10MB)
//!
//! ## gRPC
//! Binary protocol using Protocol Buffers over HTTP/2:
//! - Better performance for high-throughput scenarios
//! - Native support for TLS/mTLS
//! - Language-agnostic (agents can be written in any language with gRPC support)
//!
//! # Example: Client Usage (Unix Socket)
//!
//! ```ignore
//! use zentinel_agent_protocol::{AgentClient, EventType, RequestHeadersEvent};
//!
//! let mut client = AgentClient::unix_socket("my-agent", "/tmp/agent.sock", timeout).await?;
//! let response = client.send_event(EventType::RequestHeaders, &event).await?;
//! ```
//!
//! # Example: Client Usage (gRPC)
//!
//! ```ignore
//! use zentinel_agent_protocol::{AgentClient, EventType, RequestHeadersEvent};
//!
//! let mut client = AgentClient::grpc("my-agent", "http://localhost:50051", timeout).await?;
//! let response = client.send_event(EventType::RequestHeaders, &event).await?;
//! ```
//!
//! # Example: Client Usage (gRPC with TLS)
//!
//! ```ignore
//! use zentinel_agent_protocol::{AgentClient, GrpcTlsConfig, EventType, RequestHeadersEvent};
//!
//! // Simple TLS (server verification only)
//! let tls_config = GrpcTlsConfig::new()
//!     .with_ca_cert_file("/etc/zentinel/certs/ca.crt").await?;
//!
//! let mut client = AgentClient::grpc_tls(
//!     "my-agent",
//!     "https://agent.internal:50051",
//!     timeout,
//!     tls_config
//! ).await?;
//!
//! // mTLS (mutual authentication)
//! let tls_config = GrpcTlsConfig::new()
//!     .with_ca_cert_file("/etc/zentinel/certs/ca.crt").await?
//!     .with_client_cert_files(
//!         "/etc/zentinel/certs/client.crt",
//!         "/etc/zentinel/certs/client.key"
//!     ).await?;
//!
//! let mut client = AgentClient::grpc_tls("my-agent", "https://agent.internal:50051", timeout, tls_config).await?;
//! ```
//!
//! # Example: Client Usage (HTTP REST)
//!
//! ```ignore
//! use zentinel_agent_protocol::{AgentClient, HttpTlsConfig, EventType, RequestHeadersEvent};
//!
//! // Plain HTTP
//! let mut client = AgentClient::http("my-agent", "http://localhost:8080/agent", timeout).await?;
//! let response = client.send_event(EventType::RequestHeaders, &event).await?;
//!
//! // HTTPS with TLS
//! let tls_config = HttpTlsConfig::new()
//!     .with_ca_cert_file("/etc/zentinel/certs/ca.crt").await?;
//!
//! let mut client = AgentClient::http_tls(
//!     "my-agent",
//!     "https://agent.internal:8443/agent",
//!     timeout,
//!     tls_config
//! ).await?;
//! ```
//!
//! # Example: Server Implementation
//!
//! ```ignore
//! use zentinel_agent_protocol::{AgentServer, AgentHandler, AgentResponse};
//!
//! struct MyAgent;
//!
//! #[async_trait]
//! impl AgentHandler for MyAgent {
//!     async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
//!         // Implement your logic here
//!         AgentResponse::default_allow()
//!     }
//! }
//!
//! let server = AgentServer::new("my-agent", "/tmp/agent.sock", Box::new(MyAgent));
//! server.run().await?;
//! ```

#![allow(dead_code)]

pub mod binary;
pub mod buffer_pool;
mod client;
mod errors;
pub mod headers;
#[cfg(feature = "mmap-buffers")]
pub mod mmap_buffer;
mod protocol;
mod server;

/// gRPC protocol definitions generated from proto/agent.proto
pub mod grpc {
    tonic::include_proto!("zentinel.agent.v1");
}

/// Protocol v2 types with bidirectional streaming, capabilities, and flow control
pub mod v2;

/// gRPC v2 protocol definitions generated from proto/agent_v2.proto
pub mod grpc_v2 {
    tonic::include_proto!("zentinel.agent.v2");
}

// Re-export error types
pub use errors::AgentProtocolError;

// Re-export protocol types
pub use protocol::{
    AgentRequest, AgentResponse, AuditMetadata, BinaryRequestBodyChunkEvent,
    BinaryResponseBodyChunkEvent, BodyMutation, ConfigureEvent, Decision, DetectionSeverity,
    EventType, GuardrailDetection, GuardrailInspectEvent, GuardrailInspectionType,
    GuardrailResponse, HeaderOp, RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent,
    RequestMetadata, ResponseBodyChunkEvent, ResponseHeadersEvent, TextSpan, WebSocketDecision,
    WebSocketFrameEvent, WebSocketOpcode, MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};

// Re-export client
pub use client::{AgentClient, GrpcTlsConfig, HttpTlsConfig};

// Re-export server and handler
pub use server::{
    AgentHandler, AgentServer, DenylistAgent, EchoAgent, GrpcAgentHandler, GrpcAgentServer,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_agent_protocol_echo() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");

        // Start echo agent server
        let server = AgentServer::new("test-echo", socket_path.clone(), Box::new(EchoAgent));

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client =
            AgentClient::unix_socket("test-client", &socket_path, Duration::from_secs(5))
                .await
                .unwrap();

        // Send request headers event
        let event = RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some("default".to_string()),
                upstream_id: Some("backend".to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/test".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .unwrap();

        // Check response
        assert_eq!(response.decision, Decision::Allow);
        assert_eq!(response.request_headers.len(), 1);

        // Clean up
        client.close().await.unwrap();
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_agent_protocol_denylist() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("denylist.sock");

        // Start denylist agent server
        let agent = DenylistAgent::new(vec!["/admin".to_string()], vec!["10.0.0.1".to_string()]);
        let server = AgentServer::new("test-denylist", socket_path.clone(), Box::new(agent));

        let server_handle = tokio::spawn(async move {
            server.run().await.unwrap();
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client =
            AgentClient::unix_socket("test-client", &socket_path, Duration::from_secs(5))
                .await
                .unwrap();

        // Test blocked path
        let event = RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-123".to_string(),
                request_id: "req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: Some("example.com".to_string()),
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: Some("default".to_string()),
                upstream_id: Some("backend".to_string()),
                timestamp: chrono::Utc::now().to_rfc3339(),
                traceparent: None,
            },
            method: "GET".to_string(),
            uri: "/admin/secret".to_string(),
            headers: HashMap::new(),
        };

        let response = client
            .send_event(EventType::RequestHeaders, &event)
            .await
            .unwrap();

        // Check response is blocked
        match response.decision {
            Decision::Block { status, .. } => assert_eq!(status, 403),
            _ => panic!("Expected block decision"),
        }

        // Clean up
        client.close().await.unwrap();
        server_handle.abort();
    }

    #[test]
    fn test_body_mutation_types() {
        // Test pass-through mutation
        let pass_through = BodyMutation::pass_through(0);
        assert!(pass_through.is_pass_through());
        assert!(!pass_through.is_drop());
        assert_eq!(pass_through.chunk_index, 0);

        // Test drop mutation
        let drop = BodyMutation::drop_chunk(1);
        assert!(!drop.is_pass_through());
        assert!(drop.is_drop());
        assert_eq!(drop.chunk_index, 1);

        // Test replace mutation
        let replace = BodyMutation::replace(2, "modified content".to_string());
        assert!(!replace.is_pass_through());
        assert!(!replace.is_drop());
        assert_eq!(replace.chunk_index, 2);
        assert_eq!(replace.data, Some("modified content".to_string()));
    }

    #[test]
    fn test_agent_response_streaming() {
        // Test needs_more_data response
        let response = AgentResponse::needs_more_data();
        assert!(response.needs_more);
        assert_eq!(response.decision, Decision::Allow);

        // Test response with body mutation
        let mutation = BodyMutation::replace(0, "new content".to_string());
        let response = AgentResponse::default_allow().with_request_body_mutation(mutation.clone());
        assert!(!response.needs_more);
        assert!(response.request_body_mutation.is_some());
        assert_eq!(
            response.request_body_mutation.unwrap().data,
            Some("new content".to_string())
        );

        // Test set_needs_more
        let response = AgentResponse::default_allow().set_needs_more(true);
        assert!(response.needs_more);
    }
}
