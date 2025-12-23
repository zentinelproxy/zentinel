// Load balancing algorithm implementations
pub mod adaptive;
pub mod consistent_hash;
pub mod p2c;

// Re-export commonly used types
pub use adaptive::{AdaptiveBalancer, AdaptiveConfig};
pub use consistent_hash::{
    ConsistentHashBalancer, ConsistentHashConfig, HashFunction, HashKeyExtractor,
};
pub use p2c::{LoadMetric, P2cBalancer, P2cConfig};

// Re-export parent module types if needed
pub use super::{
    CircuitBreaker, ConnectionPool, HealthChecker, LoadBalancer, PoolStats, RequestContext,
    TargetSelection, UpstreamPool,
};
