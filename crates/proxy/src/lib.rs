// Allow lints for work-in-progress features and code patterns
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::manual_strip)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::type_complexity)]
#![allow(clippy::manual_try_fold)]
#![allow(private_interfaces)]

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
pub mod decompression;
pub mod discovery;
pub mod distributed_rate_limit;
pub mod memcached_rate_limit;
pub mod errors;

// Kubernetes kubeconfig parsing (requires kubernetes feature)
#[cfg(feature = "kubernetes")]
pub mod kubeconfig;
pub mod geo_filter;
pub mod health;
pub mod http_helpers;
pub mod logging;
pub mod memory_cache;
pub mod otel;
pub mod proxy;
pub mod rate_limit;
pub mod reload;
pub mod routing;
pub mod static_files;
pub mod tls;
pub mod trace_id;
pub mod upstream;
pub mod validation;
pub mod websocket;

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
pub use routing::{RequestInfo, RouteMatch, RouteMatcher};

// Upstream management
pub use upstream::{
    LoadBalancer, PoolConfigSnapshot, PoolStats, RequestContext, TargetSelection, UpstreamPool,
    UpstreamTarget,
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
    execute_handler, BuiltinHandlerState, CachePurgeRequest, TargetHealthStatus, TargetStatus,
    UpstreamHealthSnapshot, UpstreamStatus,
};

// HTTP helpers
pub use http_helpers::{
    extract_request_info, get_or_create_trace_id, write_error, write_json_error, write_response,
    write_text_error, OwnedRequestInfo,
};

// Trace ID generation (TinyFlake)
pub use trace_id::{
    generate_for_format, generate_tinyflake, generate_uuid, TraceIdFormat, TINYFLAKE_LENGTH,
};

// OpenTelemetry tracing
pub use otel::{
    create_traceparent, generate_span_id, generate_trace_id, get_tracer, init_tracer,
    shutdown_tracer, OtelError, OtelTracer, RequestSpan, TraceContext, TRACEPARENT_HEADER,
    TRACESTATE_HEADER,
};

// TLS / SNI support
pub use tls::{
    build_server_config, build_upstream_tls_config, load_client_ca, validate_tls_config,
    validate_upstream_tls_config, CertificateReloader, HotReloadableSniResolver, OcspCacheEntry,
    OcspStapler, SniResolver, TlsError,
};

// Logging
pub use logging::{
    AccessLogEntry, AccessLogFormat, AuditEventType, AuditLogEntry, ErrorLogEntry, LogManager,
    SharedLogManager,
};

// Rate limiting
pub use rate_limit::{
    RateLimitConfig, RateLimitManager, RateLimitOutcome, RateLimitResult, RateLimiterPool,
};

// GeoIP filtering
pub use geo_filter::{
    GeoDatabaseWatcher, GeoFilterManager, GeoFilterPool, GeoFilterResult, GeoLookupError,
};

// Body decompression with ratio limits
pub use decompression::{
    decompress_body, decompress_body_with_stats, is_supported_encoding, parse_content_encoding,
    DecompressionConfig, DecompressionError, DecompressionResult, DecompressionStats,
};

// Distributed rate limiting - Redis
#[cfg(feature = "distributed-rate-limit")]
pub use distributed_rate_limit::{
    create_redis_rate_limiter, DistributedRateLimitStats, RedisRateLimiter,
};

// Distributed rate limiting - Memcached
#[cfg(feature = "distributed-rate-limit-memcached")]
pub use memcached_rate_limit::{
    create_memcached_rate_limiter, MemcachedRateLimitStats, MemcachedRateLimiter,
};

// HTTP caching
pub use cache::{
    configure_cache, get_cache_eviction, get_cache_lock, get_cache_storage, is_cache_enabled,
    CacheConfig, CacheManager, HttpCacheStats,
};

// Memory caching
pub use memory_cache::{
    MemoryCacheConfig, MemoryCacheManager, MemoryCacheStats, RouteMatchEntry, TypedCache,
};

// Service discovery
pub use discovery::{
    ConsulDiscovery, DiscoveryConfig, DiscoveryManager, DnsDiscovery, KubernetesDiscovery,
};

// Kubernetes kubeconfig parsing
#[cfg(feature = "kubernetes")]
pub use kubeconfig::{KubeAuth, Kubeconfig, KubeconfigError, ResolvedKubeConfig};

// Re-export common error types for convenience
pub use sentinel_common::errors::{LimitType, SentinelError, SentinelResult};
