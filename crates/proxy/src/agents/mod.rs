//! Agent integration module for Sentinel proxy.
//!
//! This module provides integration with external processing agents for WAF,
//! auth, rate limiting, and custom logic. It implements the SPOE-inspired
//! protocol with bounded behavior and failure isolation.
//!
//! # Architecture
//!
//! - [`AgentManager`]: Coordinates all agents, handles routing to appropriate agents
//! - [`Agent`]: Individual agent with connection, circuit breaker, and metrics
//! - [`AgentConnectionPool`]: Connection pooling for efficient connection reuse
//! - [`AgentDecision`]: Combined result from processing through agents
//! - [`AgentCallContext`]: Request context passed to agents
//!
//! # Example
//!
//! ```ignore
//! use sentinel_proxy::agents::{AgentManager, AgentCallContext};
//!
//! let manager = AgentManager::new(agent_configs, 1000).await?;
//! manager.initialize().await?;
//!
//! let decision = manager.process_request_headers(&ctx, &headers, &["waf", "auth"]).await?;
//! if !decision.is_allow() {
//!     // Handle block/redirect/challenge
//! }
//! ```

mod agent;
mod context;
mod decision;
mod manager;
mod metrics;
mod pool;

pub use agent::Agent;
pub use context::AgentCallContext;
pub use decision::{AgentAction, AgentDecision};
pub use manager::AgentManager;
pub use metrics::AgentMetrics;
pub use pool::AgentConnectionPool;

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_agent_protocol::HeaderOp;
    use sentinel_common::types::CircuitBreakerConfig;
    use sentinel_common::CircuitBreaker;
    use std::time::Duration;

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
        assert!(breaker.is_closed().await);

        // Record failures to open
        for _ in 0..3 {
            breaker.record_failure().await;
        }
        assert!(!breaker.is_closed().await);

        // Wait for timeout
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(breaker.is_closed().await); // Should be half-open now
    }
}
