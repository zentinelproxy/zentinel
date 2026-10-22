//! Protocol v2 types for Agent Protocol 2.0
//!
//! This module provides the v2 protocol types including:
//! - Capability negotiation
//! - Health reporting
//! - Flow control
//! - Metrics export
//! - Bidirectional streaming
//! - v2 server and client implementations

mod capabilities;
pub mod client;
mod control;
mod health;
mod metrics;
pub mod observability;
pub mod pool;
pub mod protocol_metrics;
pub mod reverse;
pub mod server;
mod streaming;
pub mod uds;
pub mod uds_server;

pub use capabilities::*;
pub use client::{AgentClientV2, CancelReason, ConfigUpdateCallback, FlowState, MetricsCallback};
pub use control::*;
pub use health::*;
pub use metrics::*;
pub use observability::{
    AgentConnection, ConfigPusher, ConfigPusherConfig, ConfigUpdateHandler, MetricsCollector,
    MetricsCollectorConfig, MetricsSnapshot, PushResult, PushStatus, UnifiedMetricsAggregator,
};
pub use pool::{AgentPool, AgentPoolConfig, AgentPoolStats, LoadBalanceStrategy, V2Transport};
pub use protocol_metrics::{
    HistogramMetric, HistogramSnapshot, ProtocolMetrics, ProtocolMetricsSnapshot,
};
pub use reverse::{
    RegistrationRequest, RegistrationResponse, ReverseConnectionClient, ReverseConnectionConfig,
    ReverseConnectionListener,
};
pub use server::{
    AgentHandlerV2, DrainReason, GrpcAgentHandlerV2, GrpcAgentServerV2, ShutdownReason,
};
pub use streaming::*;
pub use uds::{
    AgentClientV2Uds, MessageType, UdsCapabilities, UdsEncoding, UdsFeatures, UdsHandshakeRequest,
    UdsHandshakeResponse, UdsLimits, DEFAULT_CONNECT_TIMEOUT, MAX_UDS_MESSAGE_SIZE,
};
pub use uds_server::UdsAgentServerV2;

/// Protocol version 2
pub const PROTOCOL_VERSION_2: u32 = 2;

/// Check if a version is supported by v2.
pub fn supports_version(version: u32) -> bool {
    version <= PROTOCOL_VERSION_2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_support() {
        assert!(supports_version(1));
        assert!(supports_version(2));
        assert!(!supports_version(3));
    }
}
