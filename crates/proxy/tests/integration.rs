//! Integration tests for Sentinel proxy.
//!
//! These tests verify the end-to-end flow from configuration loading
//! through agent processing to proxy operation.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, Decision, EventType, HeaderOp,
    RequestHeadersEvent, RequestMetadata,
};
use sentinel_common::CorrelationId;
use sentinel_config::Config;
use sentinel_proxy::agents::AgentDecision;

// ============================================================================
// Test Agent Implementation
// ============================================================================

/// Test agent that adds headers and tracks processed requests.
struct TestAgent {
    name: String,
}

impl TestAgent {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[async_trait::async_trait]
impl AgentHandler for TestAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
            .add_request_header(HeaderOp::Set {
                name: format!("X-Agent-{}", self.name),
                value: event.metadata.correlation_id.clone(),
            })
            .with_audit(AuditMetadata {
                tags: vec![format!("agent:{}", self.name)],
                ..Default::default()
            })
    }
}

/// Blocking agent for testing failure modes.
struct BlockingAgent {
    block_paths: Vec<String>,
}

impl BlockingAgent {
    fn new(block_paths: Vec<String>) -> Self {
        Self { block_paths }
    }
}

#[async_trait::async_trait]
impl AgentHandler for BlockingAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        for path in &self.block_paths {
            if event.uri.starts_with(path) {
                return AgentResponse::block(403, Some("Blocked by test agent".to_string()))
                    .with_audit(AuditMetadata {
                        tags: vec!["blocked".to_string()],
                        reason_codes: vec!["TEST_BLOCK".to_string()],
                        ..Default::default()
                    });
            }
        }
        AgentResponse::default_allow()
    }
}

// ============================================================================
// Configuration Integration Tests
// ============================================================================

#[test]
fn test_config_loading_from_kdl() {
    let kdl_config = r#"
        server {
            worker-threads 4
        }

        listeners {
            listener "http" {
                address "0.0.0.0:8080"
                protocol "http"
            }
        }

        upstreams {
            upstream "backend" {
                target "127.0.0.1:3000"
            }
        }

        routes {
            route "api" {
                matches {
                    path-prefix "/api"
                }
                upstream "backend"
            }
        }
    "#;

    let config = Config::from_kdl(kdl_config).expect("Config should parse");

    assert_eq!(config.server.worker_threads, 4);
    assert_eq!(config.listeners.len(), 1);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}

#[test]
fn test_config_with_multiple_upstreams() {
    let kdl_config = r#"
        server {
            worker-threads 2
        }

        listeners {
            listener "http" {
                address "0.0.0.0:8080"
                protocol "http"
            }
        }

        upstreams {
            upstream "backend1" {
                target "127.0.0.1:3000"
            }
            upstream "backend2" {
                target "127.0.0.1:3001"
                target "127.0.0.1:3002" weight=2
            }
        }

        routes {
            route "api" {
                matches {
                    path-prefix "/api"
                }
                upstream "backend1"
            }
        }
    "#;

    let config = Config::from_kdl(kdl_config).expect("Config should parse");

    assert_eq!(config.upstreams.len(), 2);
    assert!(config.upstreams.contains_key("backend1"));
    assert!(config.upstreams.contains_key("backend2"));
    assert_eq!(config.upstreams["backend2"].targets.len(), 2);
}

#[test]
fn test_config_validation_missing_upstream() {
    // Config with missing upstream reference should fail validation
    let kdl_config = r#"
        server {
            worker-threads 2
        }

        listeners {
            listener "http" {
                address "0.0.0.0:8080"
                protocol "http"
            }
        }

        routes {
            route "api" {
                matches {
                    path-prefix "/api"
                }
                upstream "nonexistent"
            }
        }
    "#;

    let result = Config::from_kdl(kdl_config);
    // This should fail validation because "nonexistent" upstream doesn't exist
    assert!(
        result.is_err() || result.unwrap().validate().is_err(),
        "Config with missing upstream should fail"
    );
}

// ============================================================================
// Agent Protocol Integration Tests
// ============================================================================

#[tokio::test]
async fn test_agent_server_client_roundtrip() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("test-agent.sock");

    // Start test agent server
    let server = AgentServer::new(
        "test-agent",
        socket_path.clone(),
        Box::new(TestAgent::new("Test")),
    );

    let server_handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // Wait for server to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client and send request
    let mut client = sentinel_agent_protocol::AgentClient::unix_socket(
        "test-client",
        &socket_path,
        Duration::from_secs(5),
    )
    .await
    .expect("Client should connect");

    let event = RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: "test-corr-123".to_string(),
            request_id: "req-456".to_string(),
            client_ip: "127.0.0.1".to_string(),
            client_port: 12345,
            server_name: Some("example.com".to_string()),
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: Some("api".to_string()),
            upstream_id: Some("backend".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            traceparent: None,
        },
        method: "GET".to_string(),
        uri: "/api/users".to_string(),
        headers: HashMap::new(),
    };

    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Should receive response");

    // Verify response
    assert_eq!(response.decision, Decision::Allow);
    assert!(!response.request_headers.is_empty());
    assert!(response.audit.tags.contains(&"agent:Test".to_string()));

    // Cleanup
    client.close().await.unwrap();
    server_handle.abort();
}

#[tokio::test]
async fn test_blocking_agent_rejects_request() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("block-agent.sock");

    // Start blocking agent server
    let server = AgentServer::new(
        "block-agent",
        socket_path.clone(),
        Box::new(BlockingAgent::new(vec!["/admin".to_string()])),
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

    // Test blocked path
    let event = RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: "test-123".to_string(),
            request_id: "req-456".to_string(),
            client_ip: "127.0.0.1".to_string(),
            client_port: 12345,
            server_name: None,
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
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
        .expect("Should receive response");

    match response.decision {
        Decision::Block { status, .. } => {
            assert_eq!(status, 403);
        }
        _ => panic!("Expected block decision"),
    }

    // Test allowed path
    let event = RequestHeadersEvent {
        metadata: RequestMetadata {
            correlation_id: "test-456".to_string(),
            request_id: "req-789".to_string(),
            client_ip: "127.0.0.1".to_string(),
            client_port: 12345,
            server_name: None,
            protocol: "HTTP/1.1".to_string(),
            tls_version: None,
            tls_cipher: None,
            route_id: None,
            upstream_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            traceparent: None,
        },
        method: "GET".to_string(),
        uri: "/api/users".to_string(),
        headers: HashMap::new(),
    };

    let response = client
        .send_event(EventType::RequestHeaders, &event)
        .await
        .expect("Should receive response");

    assert_eq!(response.decision, Decision::Allow);

    client.close().await.unwrap();
    server_handle.abort();
}

// ============================================================================
// Decision Merging Tests
// ============================================================================

#[test]
fn test_agent_decision_merge_allow() {
    let mut decision1 = AgentDecision::default_allow();
    let decision2 = AgentDecision::default_allow();

    decision1.merge(decision2);
    assert!(decision1.is_allow());
}

#[test]
fn test_agent_decision_merge_block_wins() {
    let mut decision1 = AgentDecision::default_allow();
    let decision2 = AgentDecision::block(403, "Forbidden");

    decision1.merge(decision2);
    assert!(!decision1.is_allow());
}

#[test]
fn test_agent_decision_headers_accumulate() {
    use sentinel_agent_protocol::HeaderOp;

    let mut decision1 = AgentDecision::default_allow();
    decision1.request_headers.push(HeaderOp::Set {
        name: "X-Header-1".to_string(),
        value: "value1".to_string(),
    });

    let mut decision2 = AgentDecision::default_allow();
    decision2.request_headers.push(HeaderOp::Set {
        name: "X-Header-2".to_string(),
        value: "value2".to_string(),
    });

    decision1.merge(decision2);

    assert!(decision1.is_allow());
    assert_eq!(decision1.request_headers.len(), 2);
}

// ============================================================================
// Multi-file Config Tests
// ============================================================================

#[test]
fn test_config_from_file() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("sentinel.kdl");

    // Create config file
    std::fs::write(
        &config_path,
        r#"
        server {
            worker-threads 8
        }

        listeners {
            listener "http" {
                address "0.0.0.0:8080"
                protocol "http"
            }
        }

        upstreams {
            upstream "backend" {
                target "127.0.0.1:3000"
            }
        }

        routes {
            route "api" {
                matches {
                    path-prefix "/api"
                }
                upstream "backend"
            }
        }
    "#,
    )
    .unwrap();

    let config = Config::from_file(&config_path).expect("Should load config from file");

    assert_eq!(config.server.worker_threads, 8);
    assert_eq!(config.upstreams.len(), 1);
    assert_eq!(config.routes.len(), 1);
}

// ============================================================================
// Type Safety Tests
// ============================================================================

#[test]
fn test_correlation_id_type_safety() {
    let corr_id = CorrelationId::new();
    let corr_id_from_string = CorrelationId::from_string("my-correlation-id");

    // These are different types that shouldn't be mixed
    assert_ne!(corr_id.as_str(), corr_id_from_string.as_str());
    assert_eq!(corr_id_from_string.as_str(), "my-correlation-id");
}

#[test]
fn test_route_and_upstream_ids_distinct() {
    use sentinel_common::{RouteId, UpstreamId};

    let route_id = RouteId::new("my-route");
    let upstream_id = UpstreamId::new("my-upstream");

    // These are distinct types - can't accidentally mix them
    assert_eq!(route_id.as_str(), "my-route");
    assert_eq!(upstream_id.as_str(), "my-upstream");
}

// ============================================================================
// Registry Tests
// ============================================================================

#[tokio::test]
async fn test_registry_concurrent_access() {
    use sentinel_common::Registry;

    let registry: Registry<String> = Registry::new();

    // Concurrent insertions
    let mut handles = vec![];
    for i in 0..10 {
        let registry = registry.clone();
        handles.push(tokio::spawn(async move {
            registry
                .insert(format!("key-{}", i), Arc::new(format!("value-{}", i)))
                .await;
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all insertions
    for i in 0..10 {
        let value = registry.get(&format!("key-{}", i)).await;
        assert_eq!(value, Some(Arc::new(format!("value-{}", i))));
    }
}

// ============================================================================
// Error Type Tests
// ============================================================================

#[test]
fn test_sentinel_error_display() {
    use sentinel_common::SentinelError;

    let error = SentinelError::Config {
        message: "Invalid configuration".to_string(),
        source: None,
    };

    let display = format!("{}", error);
    assert!(display.contains("Invalid configuration"));
}

#[test]
fn test_sentinel_error_to_http_status() {
    use sentinel_common::SentinelError;

    let config_error = SentinelError::Config {
        message: "test".to_string(),
        source: None,
    };
    assert_eq!(config_error.to_http_status(), 500);

    let timeout_error = SentinelError::Timeout {
        operation: "test".to_string(),
        duration_ms: 1000,
        correlation_id: None,
    };
    assert_eq!(timeout_error.to_http_status(), 504);
}
