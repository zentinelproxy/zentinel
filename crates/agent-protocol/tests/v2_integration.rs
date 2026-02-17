//! Integration tests for Agent Protocol v2.
//!
//! Tests the complete protocol flow including:
//! - Binary framing
//! - Buffer pooling
//! - Zero-copy headers
//! - Capability negotiation
//! - Streaming protocol types

use bytes::{BufMut, Bytes};
use zentinel_agent_protocol::binary::{
    BinaryAgentResponse, BinaryBodyChunk, BinaryFrame, BinaryRequestHeaders, MessageType,
};
use zentinel_agent_protocol::buffer_pool::{acquire, acquire_default, clear_pool, pool_stats};
use zentinel_agent_protocol::headers::{HeaderIterator, HeadersCow, HeadersRef};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentLimits, HealthConfig, HealthState, HealthStatus,
    LoadMetrics, ResourceMetrics, PROTOCOL_VERSION_2,
};
use zentinel_agent_protocol::{Decision, EventType, HeaderOp};
use std::collections::HashMap;

// =============================================================================
// Binary Protocol Integration Tests
// =============================================================================

#[test]
fn test_binary_request_headers_roundtrip() {
    // Create a request headers message
    let mut headers = HashMap::new();
    headers.insert("host".to_string(), vec!["example.com".to_string()]);
    headers.insert(
        "content-type".to_string(),
        vec!["application/json".to_string()],
    );

    let request = BinaryRequestHeaders {
        correlation_id: "corr-12345".to_string(),
        method: "POST".to_string(),
        uri: "/api/v1/users".to_string(),
        headers: headers.clone(),
        client_ip: "192.168.1.1".to_string(),
        client_port: 54321,
    };

    // Encode to bytes
    let encoded = request.encode();

    // Create a frame
    let frame = BinaryFrame::new(MessageType::RequestHeaders, encoded.clone());
    assert_eq!(frame.msg_type, MessageType::RequestHeaders);
    assert!(!frame.payload.is_empty());

    // Encode frame to wire format
    let wire_data = frame.encode();

    // Verify wire format structure
    assert!(wire_data.len() > 5); // At least length + type + some payload

    // Decode request headers directly
    let decoded_request = BinaryRequestHeaders::decode(encoded).unwrap();
    assert_eq!(decoded_request.correlation_id, "corr-12345");
    assert_eq!(decoded_request.method, "POST");
    assert_eq!(decoded_request.uri, "/api/v1/users");
    assert_eq!(decoded_request.headers.get("host"), headers.get("host"));
}

#[test]
fn test_binary_body_chunk_zero_copy() {
    // Create a body chunk with raw binary data
    let body_data = vec![0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
    let chunk = BinaryBodyChunk {
        correlation_id: "chunk-test".to_string(),
        chunk_index: 0,
        is_last: false,
        data: Bytes::from(body_data.clone()),
    };

    // Encode and decode
    let encoded = chunk.encode();
    let decoded = BinaryBodyChunk::decode(encoded).unwrap();

    // Verify data is identical (zero-copy means no transformation)
    assert_eq!(decoded.data.as_ref(), &body_data);
    assert_eq!(decoded.correlation_id, "chunk-test");
    assert_eq!(decoded.chunk_index, 0);
    assert!(!decoded.is_last);
}

#[test]
fn test_binary_response_with_mutations() {
    let response = BinaryAgentResponse {
        correlation_id: "resp-test".to_string(),
        decision: Decision::Allow,
        request_headers: vec![
            HeaderOp::Set {
                name: "x-processed".to_string(),
                value: "true".to_string(),
            },
            HeaderOp::Remove {
                name: "x-debug".to_string(),
            },
        ],
        response_headers: vec![HeaderOp::Add {
            name: "x-zentinel-version".to_string(),
            value: "2.0".to_string(),
        }],
        needs_more: false,
    };

    let encoded = response.encode();
    let decoded = BinaryAgentResponse::decode(encoded).unwrap();

    assert!(matches!(decoded.decision, Decision::Allow));
    assert_eq!(decoded.request_headers.len(), 2);
    assert_eq!(decoded.response_headers.len(), 1);
    assert!(!decoded.needs_more);
}

#[test]
fn test_binary_response_block_decision() {
    let response = BinaryAgentResponse {
        correlation_id: "block-test".to_string(),
        decision: Decision::Block {
            status: 403,
            body: Some("Access Denied".to_string()),
            headers: Some({
                let mut h = HashMap::new();
                h.insert("X-Reason".to_string(), "Forbidden".to_string());
                h
            }),
        },
        request_headers: vec![],
        response_headers: vec![],
        needs_more: false,
    };

    let encoded = response.encode();
    let decoded = BinaryAgentResponse::decode(encoded).unwrap();

    match decoded.decision {
        Decision::Block {
            status,
            body,
            headers,
        } => {
            assert_eq!(status, 403);
            assert_eq!(body, Some("Access Denied".to_string()));
            assert!(headers.is_some());
        }
        _ => panic!("Expected Block decision"),
    }
}

#[test]
fn test_all_message_types() {
    let types = [
        MessageType::HandshakeRequest,
        MessageType::HandshakeResponse,
        MessageType::RequestHeaders,
        MessageType::RequestBodyChunk,
        MessageType::ResponseHeaders,
        MessageType::ResponseBodyChunk,
        MessageType::AgentResponse,
        MessageType::Ping,
        MessageType::Pong,
        MessageType::Cancel,
        MessageType::Error,
    ];

    for msg_type in types {
        let wire_byte: u8 = msg_type as u8;
        let decoded = MessageType::try_from(wire_byte).unwrap();
        assert_eq!(decoded, msg_type);
    }
}

// =============================================================================
// Buffer Pooling Integration Tests
// =============================================================================

#[test]
fn test_buffer_pool_with_binary_protocol() {
    clear_pool();

    // Simulate typical protocol usage
    for _ in 0..100 {
        let mut buf = acquire(4096);

        // Write binary frame header
        buf.put_u32(1024); // length prefix
        buf.put_u8(MessageType::RequestHeaders as u8);

        // Write some payload
        buf.put_slice(b"test payload data");

        // Buffer returns to pool on drop
    }

    let stats = pool_stats();
    // Most buffers should be reused after first allocation
    assert!(
        stats.reused > 50,
        "Expected high reuse rate, got: {:?}",
        stats
    );
    assert!(
        stats.hit_rate() > 0.5,
        "Expected hit rate > 0.5, got: {}",
        stats.hit_rate()
    );
}

#[test]
fn test_buffer_pool_efficiency() {
    clear_pool();

    // Measure allocation stats
    let initial_stats = pool_stats();
    assert_eq!(initial_stats.allocated, 0);

    // First pass: allocations
    {
        let _bufs: Vec<_> = (0..10).map(|_| acquire_default()).collect();
    }

    let after_first = pool_stats();
    assert_eq!(after_first.allocated, 10);
    assert_eq!(after_first.pooled, 10);

    // Second pass: reuses
    {
        let _bufs: Vec<_> = (0..10).map(|_| acquire_default()).collect();
    }

    let after_second = pool_stats();
    assert_eq!(after_second.allocated, 10); // No new allocations
    assert_eq!(after_second.reused, 10); // All reused
    assert_eq!(after_second.pooled, 10); // Back in pool
}

// =============================================================================
// Zero-Copy Headers Integration Tests
// =============================================================================

#[test]
fn test_headers_cow_no_allocation_on_read() {
    let mut original = HashMap::new();
    original.insert(
        "content-type".to_string(),
        vec!["application/json".to_string()],
    );
    original.insert(
        "accept".to_string(),
        vec!["text/html".to_string(), "application/xml".to_string()],
    );

    // Borrowed headers - no allocation
    let cow = HeadersCow::borrowed(&original);
    assert!(!cow.is_owned());

    // Reading doesn't cause allocation
    assert_eq!(cow.get_first("content-type"), Some("application/json"));
    assert!(!cow.is_owned());

    // Checking existence doesn't cause allocation
    assert!(cow.contains("accept"));
    assert!(!cow.is_owned());

    // Iteration doesn't cause allocation
    let count: usize = cow.iter().count();
    assert_eq!(count, 2);
    assert!(!cow.is_owned());
}

#[test]
fn test_headers_cow_allocation_on_write() {
    let mut original = HashMap::new();
    original.insert("host".to_string(), vec!["example.com".to_string()]);

    let mut cow = HeadersCow::borrowed(&original);
    assert!(!cow.is_owned());

    // Writing causes allocation (copy-on-write)
    cow.set("x-new-header", "new-value");
    assert!(cow.is_owned());

    // Verify new header exists
    assert_eq!(cow.get_first("x-new-header"), Some("new-value"));

    // Original is unchanged
    assert!(!original.contains_key("x-new-header"));
}

#[test]
fn test_headers_iterator_efficiency() {
    let mut headers = HashMap::new();
    headers.insert(
        "accept".to_string(),
        vec![
            "text/html".to_string(),
            "application/json".to_string(),
            "application/xml".to_string(),
        ],
    );
    headers.insert(
        "accept-encoding".to_string(),
        vec!["gzip".to_string(), "deflate".to_string()],
    );

    let iter = HeaderIterator::new(&headers);
    let pairs: Vec<_> = iter.collect();

    // Should have 5 pairs total (3 accept + 2 accept-encoding)
    assert_eq!(pairs.len(), 5);

    // All pairs should be borrowed references
    for (name, value) in &pairs {
        assert!(!name.is_empty());
        assert!(!value.is_empty());
    }
}

#[test]
fn test_headers_ref_operations() {
    let mut raw_headers = HashMap::new();
    raw_headers.insert("host".to_string(), vec!["api.example.com".to_string()]);
    raw_headers.insert(
        "content-type".to_string(),
        vec!["application/json".to_string()],
    );
    raw_headers.insert(
        "authorization".to_string(),
        vec!["Bearer token123".to_string()],
    );

    let headers = HeadersRef::new(&raw_headers);

    // Basic lookups
    assert_eq!(headers.get_first("host"), Some("api.example.com"));
    assert_eq!(headers.get_first("nonexistent"), None);

    // Contains check
    assert!(headers.contains("content-type"));
    assert!(!headers.contains("x-custom"));

    // Length
    assert_eq!(headers.len(), 3);
    assert!(!headers.is_empty());

    // Iteration
    let flat: Vec<_> = headers.iter_flat().collect();
    assert_eq!(flat.len(), 3);
}

// =============================================================================
// Capability Negotiation Integration Tests
// =============================================================================

#[test]
fn test_full_capability_handshake() {
    let capabilities = AgentCapabilities {
        protocol_version: PROTOCOL_VERSION_2,
        agent_id: "test-waf-agent".to_string(),
        name: "WAF Agent".to_string(),
        version: "1.0.0".to_string(),
        supported_events: vec![
            EventType::RequestHeaders,
            EventType::RequestBodyChunk,
            EventType::ResponseHeaders,
        ],
        features: AgentFeatures {
            streaming_body: true,
            websocket: false,
            guardrails: true,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: true,
            health_reporting: true,
        },
        limits: AgentLimits {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024,     // 64KB
            max_memory: Some(512 * 1024 * 1024), // 512MB
            max_processing_time_ms: Some(5000),
        },
        health: HealthConfig {
            report_interval_ms: 5000,
            include_load_metrics: true,
            include_resource_metrics: true,
        },
    };

    // Verify protocol version
    assert_eq!(capabilities.protocol_version, 2);

    // Verify feature flags
    assert!(capabilities.features.streaming_body);
    assert!(capabilities.features.cancellation);
    assert_eq!(capabilities.features.concurrent_requests, 100);

    // Verify limits are reasonable
    assert!(capabilities.limits.max_body_size > 0);
    assert!(capabilities.limits.max_concurrency > 0);
}

// =============================================================================
// Health Reporting Integration Tests
// =============================================================================

#[test]
fn test_health_status_transitions() {
    // Healthy state
    let healthy = HealthStatus::healthy("test-agent");
    assert!(healthy.is_healthy());
    assert!(matches!(healthy.state, HealthState::Healthy));

    // Degraded state
    let degraded = HealthStatus::degraded("test-agent", vec!["body_inspection".to_string()], 1.5);

    match &degraded.state {
        HealthState::Degraded {
            disabled_features,
            timeout_multiplier,
        } => {
            assert_eq!(disabled_features.len(), 1);
            assert_eq!(*timeout_multiplier, 1.5);
        }
        _ => panic!("Expected degraded state"),
    }

    // Unhealthy state
    let unhealthy = HealthStatus::unhealthy("test-agent", "Database connection failed", true);

    match &unhealthy.state {
        HealthState::Unhealthy {
            reason,
            recoverable,
        } => {
            assert!(reason.contains("Database"));
            assert!(*recoverable);
        }
        _ => panic!("Expected unhealthy state"),
    }
}

#[test]
fn test_load_metrics() {
    let load = LoadMetrics {
        in_flight: 50,
        queue_depth: 10,
        avg_latency_ms: 25.5,
        p50_latency_ms: 20.0,
        p95_latency_ms: 45.0,
        p99_latency_ms: 100.0,
        requests_processed: 100_000,
        requests_rejected: 50,
        requests_timed_out: 10,
    };

    assert_eq!(load.in_flight, 50);
    assert_eq!(load.queue_depth, 10);
    assert!(load.avg_latency_ms > 0.0);
}

#[test]
fn test_resource_metrics() {
    let resources = ResourceMetrics {
        cpu_percent: Some(45.0),
        memory_bytes: Some(512 * 1024 * 1024),
        memory_limit: Some(1024 * 1024 * 1024),
        active_threads: Some(16),
        open_fds: Some(256),
        fd_limit: Some(65536),
        connections: Some(100),
    };

    assert_eq!(resources.cpu_percent, Some(45.0));
    assert_eq!(resources.memory_bytes, Some(512 * 1024 * 1024));
}

// =============================================================================
// End-to-End Protocol Flow Tests
// =============================================================================

#[test]
fn test_request_processing_flow() {
    // Simulate a complete request processing flow using v2 types

    // 1. Build request headers with zero-copy
    let mut raw_headers = HashMap::new();
    raw_headers.insert("host".to_string(), vec!["api.example.com".to_string()]);
    raw_headers.insert(
        "content-type".to_string(),
        vec!["application/json".to_string()],
    );
    raw_headers.insert(
        "authorization".to_string(),
        vec!["Bearer token123".to_string()],
    );

    let headers = HeadersRef::new(&raw_headers);
    assert_eq!(headers.get_first("host"), Some("api.example.com"));

    // 2. Create binary request
    let request = BinaryRequestHeaders {
        correlation_id: "flow-test-001".to_string(),
        method: "POST".to_string(),
        uri: "/api/v1/process".to_string(),
        headers: raw_headers.clone(),
        client_ip: "10.0.0.1".to_string(),
        client_port: 50000,
    };

    // 3. Encode to wire format
    let frame = BinaryFrame::new(MessageType::RequestHeaders, request.encode());
    let wire_data = frame.encode();

    // 4. Verify wire format
    assert!(wire_data.len() > 5);
    assert_eq!(wire_data[4], MessageType::RequestHeaders as u8);

    // 5. Agent processes and responds
    let response = BinaryAgentResponse {
        correlation_id: "flow-test-001".to_string(),
        decision: Decision::Allow,
        request_headers: vec![
            HeaderOp::Set {
                name: "x-authenticated".to_string(),
                value: "true".to_string(),
            },
            HeaderOp::Set {
                name: "x-user-id".to_string(),
                value: "user-456".to_string(),
            },
        ],
        response_headers: vec![],
        needs_more: false,
    };

    // 6. Encode and decode response
    let response_encoded = response.encode();
    let decoded_response = BinaryAgentResponse::decode(response_encoded).unwrap();

    assert!(matches!(decoded_response.decision, Decision::Allow));
    assert_eq!(decoded_response.request_headers.len(), 2);
    assert_eq!(decoded_response.correlation_id, "flow-test-001");
}

#[test]
fn test_streaming_body_flow() {
    clear_pool();

    // Simulate streaming body processing with multiple chunks
    let total_size = 256 * 1024; // 256KB body
    let chunk_size = 64 * 1024; // 64KB chunks
    let chunks = total_size / chunk_size;

    for chunk_idx in 0..chunks {
        // Use pooled buffer for chunk
        let mut buf = acquire(chunk_size);

        // Fill with test data
        let test_data = vec![chunk_idx as u8; chunk_size];
        buf.put_slice(&test_data);

        // Create binary chunk
        let chunk = BinaryBodyChunk {
            correlation_id: format!("stream-{}", chunk_idx),
            chunk_index: chunk_idx as u32,
            is_last: chunk_idx == chunks - 1,
            data: Bytes::copy_from_slice(&buf[..]),
        };

        // Encode and verify
        let encoded = chunk.encode();
        let decoded = BinaryBodyChunk::decode(encoded).unwrap();
        assert_eq!(decoded.data.len(), chunk_size);
        assert_eq!(decoded.data[0], chunk_idx as u8);
        assert_eq!(decoded.chunk_index, chunk_idx as u32);
    }

    // Verify buffer reuse
    let stats = pool_stats();
    assert!(stats.reused > 0, "Expected buffer reuse in streaming flow");
}

#[test]
fn test_combined_binary_and_headers() {
    // Test combining binary protocol with zero-copy headers

    // Source headers (would come from HTTP parsing)
    let mut source_headers = HashMap::new();
    source_headers.insert("host".to_string(), vec!["test.example.com".to_string()]);
    source_headers.insert(
        "x-custom".to_string(),
        vec!["value1".to_string(), "value2".to_string()],
    );

    // Use HeadersCow for read operations (no allocation)
    let cow = HeadersCow::borrowed(&source_headers);
    assert!(!cow.is_owned());
    assert_eq!(cow.get_first("host"), Some("test.example.com"));

    // Create binary message using the headers
    let request = BinaryRequestHeaders {
        correlation_id: "combined-test".to_string(),
        method: "GET".to_string(),
        uri: "/test".to_string(),
        headers: cow.into_owned(), // Only allocates when we need owned data
        client_ip: "127.0.0.1".to_string(),
        client_port: 8080,
    };

    // Encode/decode roundtrip
    let decoded = BinaryRequestHeaders::decode(request.encode()).unwrap();
    assert_eq!(decoded.headers.get("x-custom").unwrap().len(), 2);
}
