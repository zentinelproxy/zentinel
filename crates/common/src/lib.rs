//! Common utilities and shared components for Zentinel proxy
//!
//! This crate provides shared functionality used across all Zentinel components,
//! including observability (metrics, logging, tracing), error types, and common utilities.
//!
//! # Module Organization
//!
//! - [`ids`]: Type-safe identifier newtypes (CorrelationId, RequestId, etc.)
//! - [`types`]: Common type definitions (ByteSize, Priority, etc.)
//! - [`errors`]: Error types and result aliases
//! - [`limits`]: Resource limits and rate limiting
//! - [`observability`]: Metrics, logging, and tracing (runtime only)
//! - [`circuit_breaker`]: Circuit breaker state machine (runtime only)
//! - [`registry`]: Generic type-safe registry abstraction (runtime only)

pub mod budget;
#[cfg(feature = "runtime")]
pub mod circuit_breaker;
pub mod errors;
pub mod ids;
pub mod inference;
pub mod limits;
#[cfg(feature = "runtime")]
pub mod observability;
#[cfg(feature = "runtime")]
pub mod registry;
#[cfg(feature = "runtime")]
pub mod scoped_metrics;
#[cfg(feature = "runtime")]
pub mod scoped_registry;
pub mod types;

// Re-export commonly used items at the crate root (runtime only)
#[cfg(feature = "runtime")]
pub use observability::{
    init_tracing, AuditLogEntry, ComponentHealth, ComponentHealthTracker, HealthStatus,
    RequestMetrics,
};

// Backwards compatibility alias (deprecated, use ComponentHealthTracker)
#[cfg(feature = "runtime")]
#[deprecated(since = "0.2.0", note = "Use ComponentHealthTracker instead")]
pub type HealthChecker = ComponentHealthTracker;

// Re-export error types
pub use errors::{ZentinelError, ZentinelResult};

// Re-export limit types
pub use limits::{Limits, RateLimiter};

// Re-export identifier types
pub use ids::{AgentId, CorrelationId, QualifiedId, RequestId, RouteId, Scope, UpstreamId};

// Re-export common types
pub use types::{CircuitBreakerConfig, TraceIdFormat};

// Re-export inference types
pub use inference::{
    ColdModelAction, InferenceProbeConfig, InferenceReadinessConfig, ModelStatusConfig,
    QueueDepthConfig, WarmthDetectionConfig,
};

// Re-export circuit breaker (runtime only)
#[cfg(feature = "runtime")]
pub use circuit_breaker::CircuitBreaker;

// Re-export registries (runtime only)
#[cfg(feature = "runtime")]
pub use registry::Registry;
#[cfg(feature = "runtime")]
pub use scoped_registry::ScopedRegistry;

// Re-export scoped metrics (runtime only)
#[cfg(feature = "runtime")]
pub use scoped_metrics::{ScopeLabels, ScopedMetrics};

// Re-export budget types
pub use budget::{
    BudgetAlert, BudgetCheckResult, BudgetPeriod, CostAttributionConfig, CostResult, ModelPricing,
    TenantBudgetStatus, TokenBudgetConfig,
};
