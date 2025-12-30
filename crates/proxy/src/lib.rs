//! Sentinel Proxy Library
//!
//! A security-first reverse proxy built on Pingora with sleepable ops at the edge.
//!
//! This library provides the core components for building a production-grade
//! reverse proxy with:
//!
//! - **Routing**: Flexible path-based and header-based routing
//! - **Upstream Management**: Load balancing, health checking, circuit breakers
//! - **Static File Serving**: Compression, caching, range requests
//! - **Validation**: JSON Schema validation for API requests/responses
//! - **Error Handling**: Customizable error pages per service type
//! - **Hot Reload**: Configuration changes without restarts
//!
//! # Example
//!
//! ```ignore
//! use sentinel_proxy::{StaticFileServer, ErrorHandler, SchemaValidator};
//! use sentinel_config::{StaticFileConfig, ServiceType};
//!
//! // Create a static file server
//! let config = StaticFileConfig::default();
//! let server = StaticFileServer::new(config);
//!
//! // Create an error handler for API responses
//! let handler = ErrorHandler::new(ServiceType::Api, None);
//! ```


// ============================================================================
// Module Declarations
// ============================================================================

pub mod agents;
pub mod app;
pub mod builtin_handlers;
pub mod cache;
pub mod discovery;
pub mod errors;
pub mod health;
pub mod http_helpers;
pub mod logging;
pub mod memory_cache;
pub mod proxy;
pub mod rate_limit;
pub mod reload;
pub mod routing;
pub mod static_files;
pub mod trace_id;
pub mod upstream;
pub mod validation;

// ============================================================================
// Public API Re-exports
// ============================================================================

// Error handling
pub use errors::ErrorHandler;

// Static file serving
pub use static_files::{CacheStats, CachedFile, FileCache, StaticFileServer};

// Request validation
pub use validation::SchemaValidator;

// Routing
pub use routing::{RouteMatcher, RouteMatch, RequestInfo};

// Upstream management
pub use upstream::{
    LoadBalancer, PoolStats, RequestContext, TargetSelection, UpstreamPool, UpstreamTarget,
};

// Health checking
pub use health::{ActiveHealthChecker, PassiveHealthChecker, TargetHealthInfo};

// Agents
pub use agents::{AgentAction, AgentCallContext, AgentDecision, AgentManager};

// Hot reload
pub use reload::{ConfigManager, ReloadEvent, ReloadTrigger, SignalManager, SignalType};

// Application state
pub use app::AppState;

// Proxy core
pub use proxy::SentinelProxy;

// Built-in handlers
pub use builtin_handlers::{
    execute_handler, BuiltinHandlerState, TargetHealthStatus, TargetStatus, UpstreamHealthSnapshot,
    UpstreamStatus,
};

// HTTP helpers
pub use http_helpers::{
    extract_request_info, get_or_create_trace_id, write_error, write_json_error, write_response,
    write_text_error, OwnedRequestInfo,
};

// Trace ID generation (TinyFlake)
pub use trace_id::{generate_for_format, generate_tinyflake, generate_uuid, TraceIdFormat, TINYFLAKE_LENGTH};

// Logging
pub use logging::{
    AccessLogEntry, AccessLogFormat, AuditLogEntry, ErrorLogEntry, LogManager, SharedLogManager,
};

// Rate limiting
pub use rate_limit::{RateLimitConfig, RateLimitManager, RateLimitResult};

// HTTP caching
pub use cache::{CacheConfig, CacheManager, HttpCacheStats};

// Memory caching
pub use memory_cache::{MemoryCacheConfig, MemoryCacheManager, MemoryCacheStats, RouteMatchEntry, TypedCache};

// Service discovery
pub use discovery::{DiscoveryConfig, DiscoveryManager, DnsDiscovery};

// Re-export common error types for convenience
pub use sentinel_common::errors::{LimitType, SentinelError, SentinelResult};
