//! Common utilities and shared components for Sentinel proxy
//!
//! This crate provides shared functionality used across all Sentinel components,
//! including observability (metrics, logging, tracing), error types, and common utilities.

pub mod circuit_breaker;
pub mod errors;
pub mod limits;
pub mod observability;
pub mod types;

// Re-export commonly used items at the crate root
pub use observability::{
    init_tracing, AuditLogEntry, ComponentHealth, ComponentHealthTracker, HealthStatus,
    RequestMetrics,
};

// Backwards compatibility alias (deprecated, use ComponentHealthTracker)
#[deprecated(since = "0.2.0", note = "Use ComponentHealthTracker instead")]
pub type HealthChecker = ComponentHealthTracker;

// Re-export error types
pub use errors::{SentinelError, SentinelResult};

// Re-export limit types
pub use limits::{Limits, RateLimiter};

// Re-export common types
pub use types::{CorrelationId, RequestId, TraceIdFormat};

// Re-export circuit breaker
pub use circuit_breaker::CircuitBreaker;
