//! Agent integration module for Zentinel proxy.
//!
//! This module provides integration with external processing agents for WAF,
//! auth, rate limiting, and custom logic. Agents communicate using the v2
//! binary protocol with bidirectional streaming, capabilities, health
//! reporting, metrics export, and flow control.
//!
//! # Architecture
//!
//! - [`AgentManager`]: Coordinates all agents, handles routing to appropriate agents
//! - [`AgentV2`]: Agent with bidirectional streaming and connection pooling
//! - [`AgentDecision`]: Combined result from processing through agents
//! - [`AgentCallContext`]: Request context passed to agents
//!
//! # Queue Isolation
//!
//! Each agent has its own semaphore for queue isolation, preventing a slow agent
//! from affecting other agents (noisy neighbor problem). Configure concurrency
//! limits per-agent via `max_concurrent_calls` in the agent configuration.
//!
//! # Example
//!
//! ```ignore
//! use zentinel_proxy::agents::{AgentManager, AgentCallContext};
//!
//! // Each agent manages its own concurrency limit (default: 100)
//! let manager = AgentManager::new(agent_configs).await?;
//! manager.initialize().await?;
//!
//! let decision = manager.process_request_headers(&ctx, headers, &["waf", "auth"]).await?;
//! if !decision.is_allow() {
//!     // Handle block/redirect/challenge
//! }
//! ```

mod agent_v2;
mod context;
mod decision;
mod manager;
mod metrics;

/// Default maximum body size (in bytes) sent to an agent for inspection.
///
/// Applies when `max-request-body-bytes` / `max-response-body-bytes` are not
/// set on the agent. Bodies larger than the effective limit are handled
/// according to the agent's failure mode: fail-closed blocks the request,
/// fail-open skips that agent's inspection (loudly).
pub const DEFAULT_AGENT_MAX_BODY_BYTES: usize = 1024 * 1024;

pub use agent_v2::AgentV2;
pub use context::AgentCallContext;
pub use decision::{AgentAction, AgentDecision};
pub use manager::AgentManager;
pub use metrics::AgentMetrics;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use zentinel_agent_protocol::HeaderOp;
    use zentinel_common::types::CircuitBreakerConfig;
    use zentinel_common::CircuitBreaker;

    #[tokio::test]
    async fn test_agent_decision_merge() {
        let mut decision1 = AgentDecision::default_allow();
        decision1.request_headers.push(HeaderOp::Set {
            name: "X-Test".to_string(),
            value: "1".to_string(),
        });

        let decision2 = AgentDecision::block(403, "Forbidden");

        decision1.merge(decision2);
        assert!(!decision1.is_allow());
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout_seconds: 1,
            half_open_max_requests: 1,
        };

        let breaker = CircuitBreaker::new(config);
        assert!(breaker.is_closed()); // Lock-free

        // Record failures to open
        for _ in 0..3 {
            breaker.record_failure(); // Lock-free
        }
        assert!(!breaker.is_closed()); // Lock-free

        // Wait for timeout
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(breaker.is_closed()); // Should be half-open now (lock-free)
    }

    #[tokio::test]
    async fn test_per_agent_queue_isolation_config() {
        use std::path::PathBuf;
        use zentinel_config::{AgentConfig, AgentEvent, AgentTransport, AgentType};

        // Verify the max_concurrent_calls field works in AgentConfig
        let config = AgentConfig {
            id: "test-agent".to_string(),
            agent_type: AgentType::Custom("test".to_string()),
            transport: AgentTransport::UnixSocket {
                path: PathBuf::from("/tmp/test.sock"),
            },
            events: vec![AgentEvent::RequestHeaders],
            pool: None,
            timeout_ms: 1000,
            failure_mode: Default::default(),
            circuit_breaker: None,
            max_request_body_bytes: None,
            max_response_body_bytes: None,
            request_body_mode: Default::default(),
            response_body_mode: Default::default(),
            chunk_timeout_ms: 5000,
            config: None,
            max_concurrent_calls: 50, // Custom limit
        };

        assert_eq!(config.max_concurrent_calls, 50);

        // Verify default value
        let default_config = AgentConfig {
            id: "default-agent".to_string(),
            agent_type: AgentType::Custom("test".to_string()),
            transport: AgentTransport::UnixSocket {
                path: PathBuf::from("/tmp/default.sock"),
            },
            events: vec![AgentEvent::RequestHeaders],
            pool: None,
            timeout_ms: 1000,
            failure_mode: Default::default(),
            circuit_breaker: None,
            max_request_body_bytes: None,
            max_response_body_bytes: None,
            request_body_mode: Default::default(),
            response_body_mode: Default::default(),
            chunk_timeout_ms: 5000,
            config: None,
            max_concurrent_calls: 100, // Default value
        };

        assert_eq!(default_config.max_concurrent_calls, 100);
    }

    #[tokio::test]
    async fn test_agent_pool_config() {
        use zentinel_config::{
            AgentConfig, AgentEvent, AgentPoolConfig, AgentTransport, AgentType,
            LoadBalanceStrategy,
        };

        let config = AgentConfig {
            id: "pooled-agent".to_string(),
            agent_type: AgentType::Waf,
            transport: AgentTransport::Grpc {
                address: "localhost:50051".to_string(),
                tls: None,
            },
            events: vec![AgentEvent::RequestHeaders, AgentEvent::RequestBody],
            pool: Some(AgentPoolConfig {
                connections_per_agent: 8,
                load_balance_strategy: LoadBalanceStrategy::LeastConnections,
                connect_timeout_ms: 3000,
                reconnect_interval_ms: 5000,
                max_reconnect_attempts: 5,
                drain_timeout_ms: 60000,
                max_concurrent_per_connection: 200,
                health_check_interval_ms: 5000,
            }),
            timeout_ms: 2000,
            failure_mode: Default::default(),
            circuit_breaker: None,
            max_request_body_bytes: Some(1024 * 1024),
            max_response_body_bytes: None,
            request_body_mode: Default::default(),
            response_body_mode: Default::default(),
            chunk_timeout_ms: 5000,
            config: None,
            max_concurrent_calls: 100,
        };

        assert!(config.pool.is_some());
        let pool = config.pool.unwrap();
        assert_eq!(pool.connections_per_agent, 8);
        assert_eq!(
            pool.load_balance_strategy,
            LoadBalanceStrategy::LeastConnections
        );
    }
}
