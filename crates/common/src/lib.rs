//! Common utilities and shared components for Sentinel proxy
//!
//! This crate provides shared functionality used across all Sentinel components,
//! including observability (metrics, logging, tracing), error types, and common utilities.
//!
//! # Module Organization
//!
//! - [`ids`]: Type-safe identifier newtypes (CorrelationId, RequestId, etc.)
//! - [`types`]: Common type definitions (ByteSize, Priority, etc.)
//! - [`errors`]: Error types and result aliases
//! - [`limits`]: Resource limits and rate limiting
//! - [`observability`]: Metrics, logging, and tracing
//! - [`circuit_breaker`]: Circuit breaker state machine
//! - [`registry`]: Generic type-safe registry abstraction

pub mod circuit_breaker;
pub mod errors;
pub mod ids;
pub mod limits;
pub mod observability;
pub mod registry;
pub mod scoped_metrics;
pub mod scoped_registry;
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

// Re-export identifier types
pub use ids::{AgentId, CorrelationId, QualifiedId, RequestId, RouteId, Scope, UpstreamId};

// Re-export common types
pub use types::{CircuitBreakerConfig, TraceIdFormat};

// Re-export circuit breaker
pub use circuit_breaker::CircuitBreaker;

// Re-export registries
pub use registry::Registry;
pub use scoped_registry::ScopedRegistry;

// Re-export scoped metrics
pub use scoped_metrics::{ScopedMetrics, ScopeLabels};
