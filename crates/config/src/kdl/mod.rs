//! KDL configuration parsing.
//!
//! This module contains all functions for parsing KDL configuration files
//! into Sentinel configuration structures. It is organized into submodules:
//!
//! - `helpers`: Common parsing utility functions
//! - `server`: Server and listener parsing
//! - `routes`: Route and static file parsing
//! - `upstreams`: Upstream target parsing
//! - `filters`: Filter definition parsing

mod filters;
mod helpers;
mod routes;
mod server;
mod upstreams;

use tracing::{debug, trace};

// Re-export commonly used items
pub use helpers::{
    get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry, offset_to_line_col,
};

pub use filters::parse_filter_definitions;
pub use routes::parse_routes;
pub use server::{parse_listeners, parse_server_config};
pub use upstreams::parse_upstreams;

use anyhow::Result;
use std::collections::HashMap;

use sentinel_common::limits::Limits;

use crate::observability::ObservabilityConfig;
use crate::waf::WafConfig;
use crate::{AgentConfig, Config, CURRENT_SCHEMA_VERSION};

// ============================================================================
// Top-Level Document Parser
// ============================================================================

/// Convert a parsed KDL document to Config
pub fn parse_kdl_document(doc: kdl::KdlDocument) -> Result<Config> {
    trace!(node_count = doc.nodes().len(), "Parsing KDL document");

    let mut schema_version = None;
    let mut server = None;
    let mut listeners = Vec::new();
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();
    let mut filters = HashMap::new();
    let mut agents = Vec::new();
    let mut waf = None;
    let mut limits = None;
    let mut observability = None;
    let mut rate_limits = None;
    let mut cache = None;

    for node in doc.nodes() {
        let node_name = node.name().value();
        trace!(node = node_name, "Processing top-level node");

        match node_name {
            "schema-version" | "version" => {
                schema_version = get_first_arg_string(node);
                trace!(version = ?schema_version, "Parsed schema version");
            }
            "server" => {
                server = Some(parse_server_config(node)?);
                trace!("Parsed server configuration");
            }
            "listeners" => {
                listeners = parse_listeners(node)?;
                trace!(count = listeners.len(), "Parsed listeners");
            }
            "routes" => {
                routes = parse_routes(node)?;
                trace!(count = routes.len(), "Parsed routes");
            }
            "upstreams" => {
                upstreams = parse_upstreams(node)?;
                trace!(count = upstreams.len(), "Parsed upstreams");
            }
            "filters" => {
                filters = parse_filter_definitions(node)?;
                trace!(count = filters.len(), "Parsed filters");
            }
            "agents" => {
                agents = parse_agents(node)?;
                trace!(count = agents.len(), "Parsed agents");
            }
            "waf" => {
                waf = Some(parse_waf_config(node)?);
                trace!("Parsed WAF configuration");
            }
            "limits" => {
                limits = Some(parse_limits_config(node)?);
                trace!("Parsed limits configuration");
            }
            "observability" => {
                observability = Some(parse_observability_config(node)?);
                trace!("Parsed observability configuration");
            }
            "rate-limits" => {
                rate_limits = Some(parse_rate_limits_config(node)?);
                trace!("Parsed rate-limits configuration");
            }
            "cache" => {
                cache = Some(parse_cache_config(node)?);
                trace!("Parsed cache configuration");
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown top-level configuration block: '{}'\n\
                     Valid blocks are: schema-version, server, listeners, routes, upstreams, filters, agents, waf, limits, observability, rate-limits, cache",
                    other
                ));
            }
        }
    }

    // Validate required sections
    let server = server.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing required 'server' configuration block\n\
             Example:\n\
             server {{\n\
                 worker-threads 4\n\
                 max-connections 10000\n\
             }}"
        )
    })?;

    if listeners.is_empty() {
        return Err(anyhow::anyhow!(
            "Missing required 'listeners' configuration block\n\
             Example:\n\
             listeners {{\n\
                 listener \"http\" {{\n\
                     address \"0.0.0.0:8080\"\n\
                     protocol \"http\"\n\
                 }}\n\
             }}"
        ));
    }

    debug!(
        listeners = listeners.len(),
        routes = routes.len(),
        upstreams = upstreams.len(),
        filters = filters.len(),
        agents = agents.len(),
        has_waf = waf.is_some(),
        "KDL document parsed successfully"
    );

    Ok(Config {
        schema_version: schema_version.unwrap_or_else(|| CURRENT_SCHEMA_VERSION.to_string()),
        server,
        listeners,
        routes,
        upstreams,
        filters,
        agents,
        waf,
        limits: limits.unwrap_or_default(),
        observability: observability.unwrap_or_default(),
        rate_limits: rate_limits.unwrap_or_default(),
        cache,
        default_upstream: None,
    })
}

// ============================================================================
// Agent Parsing
// ============================================================================

use crate::agents::{AgentEvent, AgentTlsConfig, AgentTransport, AgentType, BodyStreamingMode};
use crate::routes::FailureMode;
use sentinel_common::types::CircuitBreakerConfig;
use std::path::PathBuf;

/// Parse agents configuration block
///
/// Example KDL syntax:
/// ```kdl
/// agents {
///     agent "waf-agent" type="waf" {
///         unix-socket path="/var/run/waf.sock"
///         timeout-ms 200
///         events "request_headers" "request_body"
///         failure-mode "fail_open"
///     }
///     agent "auth-agent" type="auth" {
///         grpc address="http://localhost:50051"
///         timeout-ms 100
///         events "request_headers"
///     }
/// }
/// ```
pub fn parse_agents(node: &kdl::KdlNode) -> Result<Vec<AgentConfig>> {
    let mut agents = Vec::new();

    let children = match node.children() {
        Some(doc) => doc,
        None => return Ok(agents),
    };

    for child in children.nodes() {
        if child.name().value() == "agent" {
            agents.push(parse_single_agent(child)?);
        }
    }

    Ok(agents)
}

/// Convert a KDL config node to JSON value
///
/// Conversion rules:
/// - `key value` -> `{"key": value}`
/// - `key value1 value2` -> `{"key": [value1, value2]}`
/// - `key { ... }` -> `{"key": {...}}` (recursive)
/// - Named entries (`key=value`) become object properties
fn kdl_to_json(node: &kdl::KdlNode) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();

    // Process children nodes
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let name = child.name().value().to_string();

            // Collect arguments (unnamed entries)
            let args: Vec<serde_json::Value> = child
                .entries()
                .iter()
                .filter(|e| e.name().is_none())
                .filter_map(|e| kdl_value_to_json(e.value()))
                .collect();

            // Collect named entries as properties
            let mut child_obj = serde_json::Map::new();
            for entry in child.entries().iter().filter(|e| e.name().is_some()) {
                if let Some(name) = entry.name() {
                    if let Some(value) = kdl_value_to_json(entry.value()) {
                        child_obj.insert(name.value().to_string(), value);
                    }
                }
            }

            // If node has children, recurse
            if child.children().is_some() {
                let nested = kdl_to_json(child)?;
                // Merge nested object with any named entries
                if let serde_json::Value::Object(nested_map) = nested {
                    for (k, v) in nested_map {
                        child_obj.insert(k, v);
                    }
                }
            }

            // Determine final value for this node
            let value = if !child_obj.is_empty() {
                // Has properties or nested children
                serde_json::Value::Object(child_obj)
            } else if args.len() == 1 {
                // Single argument
                args.into_iter().next().unwrap()
            } else if !args.is_empty() {
                // Multiple arguments -> array
                serde_json::Value::Array(args)
            } else {
                // No value - use true (like a flag)
                serde_json::Value::Bool(true)
            };

            obj.insert(name, value);
        }
    }

    Ok(serde_json::Value::Object(obj))
}

/// Convert a single KDL value to JSON
fn kdl_value_to_json(value: &kdl::KdlValue) -> Option<serde_json::Value> {
    if let Some(s) = value.as_string() {
        Some(serde_json::Value::String(s.to_string()))
    } else if let Some(n) = value.as_integer() {
        Some(serde_json::Value::Number((n as i64).into()))
    } else if let Some(f) = value.as_float() {
        serde_json::Number::from_f64(f).map(serde_json::Value::Number)
    } else if let Some(b) = value.as_bool() {
        Some(serde_json::Value::Bool(b))
    } else if value.is_null() {
        Some(serde_json::Value::Null)
    } else {
        None
    }
}

/// Parse a single agent configuration
fn parse_single_agent(node: &kdl::KdlNode) -> Result<AgentConfig> {
    // Get agent ID from first argument
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow::anyhow!("Agent requires an ID as first argument"))?;

    // Get agent type from attribute
    let agent_type = match node
        .get("type")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string())
    {
        Some(t) => match t.as_str() {
            "waf" => AgentType::Waf,
            "auth" => AgentType::Auth,
            "rate_limit" | "rate-limit" => AgentType::RateLimit,
            other => AgentType::Custom(other.to_string()),
        },
        None => AgentType::Custom(id.clone()),
    };

    // Parse transport from children
    let children = node
        .children()
        .ok_or_else(|| anyhow::anyhow!("Agent '{}' requires configuration block", id))?;

    let mut transport = None;
    let mut timeout_ms = 1000u64;
    let mut failure_mode = FailureMode::Open;
    let mut events = Vec::new();
    let mut circuit_breaker = None;
    let mut max_request_body_bytes = None;
    let mut max_response_body_bytes = None;
    let mut request_body_mode = BodyStreamingMode::Buffer;
    let mut response_body_mode = BodyStreamingMode::Buffer;
    let mut chunk_timeout_ms = 5000u64;
    let mut config: Option<serde_json::Value> = None;

    for child in children.nodes() {
        match child.name().value() {
            "unix-socket" => {
                let path = get_string_entry(child, "path")
                    .or_else(|| get_first_arg_string(child))
                    .ok_or_else(|| {
                        anyhow::anyhow!("unix-socket requires 'path' attribute or argument")
                    })?;
                transport = Some(AgentTransport::UnixSocket {
                    path: PathBuf::from(path),
                });
            }
            "grpc" => {
                let address = get_string_entry(child, "address")
                    .or_else(|| get_first_arg_string(child))
                    .ok_or_else(|| {
                        anyhow::anyhow!("grpc requires 'address' attribute or argument")
                    })?;
                let tls = parse_agent_tls(child)?;
                transport = Some(AgentTransport::Grpc { address, tls });
            }
            "http" => {
                let url = get_string_entry(child, "url")
                    .or_else(|| get_first_arg_string(child))
                    .ok_or_else(|| anyhow::anyhow!("http requires 'url' attribute or argument"))?;
                let tls = parse_agent_tls(child)?;
                transport = Some(AgentTransport::Http { url, tls });
            }
            "timeout-ms" => {
                if let Some(entry) = child.entries().first() {
                    if let Some(v) = entry.value().as_integer() {
                        timeout_ms = v as u64;
                    }
                }
            }
            "failure-mode" => {
                if let Some(mode) = get_first_arg_string(child) {
                    failure_mode = match mode.as_str() {
                        "fail_open" | "fail-open" | "open" => FailureMode::Open,
                        "fail_closed" | "fail-closed" | "closed" => FailureMode::Closed,
                        other => {
                            return Err(anyhow::anyhow!(
                                "Unknown failure mode: '{}'. Use 'open' or 'closed'",
                                other
                            ))
                        }
                    };
                }
            }
            "events" => {
                // Parse events from arguments
                for entry in child.entries() {
                    if let Some(event_str) = entry.value().as_string() {
                        let event = match event_str {
                            "request_headers" | "request-headers" => AgentEvent::RequestHeaders,
                            "request_body" | "request-body" => AgentEvent::RequestBody,
                            "response_headers" | "response-headers" => AgentEvent::ResponseHeaders,
                            "response_body" | "response-body" => AgentEvent::ResponseBody,
                            "log" => AgentEvent::Log,
                            other => {
                                return Err(anyhow::anyhow!("Unknown agent event: '{}'", other))
                            }
                        };
                        events.push(event);
                    }
                }
            }
            "circuit-breaker" => {
                circuit_breaker = Some(parse_circuit_breaker(child)?);
            }
            "max-request-body-bytes" => {
                if let Some(entry) = child.entries().first() {
                    if let Some(v) = entry.value().as_integer() {
                        max_request_body_bytes = Some(v as usize);
                    }
                }
            }
            "max-response-body-bytes" => {
                if let Some(entry) = child.entries().first() {
                    if let Some(v) = entry.value().as_integer() {
                        max_response_body_bytes = Some(v as usize);
                    }
                }
            }
            "request-body-mode" => {
                if let Some(mode) = get_first_arg_string(child) {
                    request_body_mode = parse_body_streaming_mode(&mode, &id)?;
                }
            }
            "response-body-mode" => {
                if let Some(mode) = get_first_arg_string(child) {
                    response_body_mode = parse_body_streaming_mode(&mode, &id)?;
                }
            }
            "chunk-timeout-ms" => {
                if let Some(entry) = child.entries().first() {
                    if let Some(v) = entry.value().as_integer() {
                        chunk_timeout_ms = v as u64;
                    }
                }
            }
            "config" => {
                config = Some(kdl_to_json(child)?);
            }
            _ => {}
        }
    }

    let transport = transport.ok_or_else(|| {
        anyhow::anyhow!(
            "Agent '{}' requires a transport (unix-socket, grpc, or http)",
            id
        )
    })?;

    // Default events if none specified
    if events.is_empty() {
        events.push(AgentEvent::RequestHeaders);
    }

    Ok(AgentConfig {
        id,
        agent_type,
        transport,
        events,
        timeout_ms,
        failure_mode,
        circuit_breaker,
        max_request_body_bytes,
        max_response_body_bytes,
        request_body_mode,
        response_body_mode,
        chunk_timeout_ms,
        config,
    })
}

/// Parse body streaming mode from string
fn parse_body_streaming_mode(mode: &str, agent_id: &str) -> Result<BodyStreamingMode> {
    match mode {
        "buffer" => Ok(BodyStreamingMode::Buffer),
        "stream" => Ok(BodyStreamingMode::Stream),
        _ if mode.starts_with("hybrid:") => {
            // Parse "hybrid:1024" format
            let threshold_str = mode.strip_prefix("hybrid:").unwrap();
            let threshold: usize = threshold_str.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Agent '{}': invalid hybrid threshold '{}', expected number",
                    agent_id,
                    threshold_str
                )
            })?;
            Ok(BodyStreamingMode::Hybrid {
                buffer_threshold: threshold,
            })
        }
        "hybrid" => {
            // Default hybrid threshold: 64KB
            Ok(BodyStreamingMode::Hybrid {
                buffer_threshold: 65536,
            })
        }
        other => Err(anyhow::anyhow!(
            "Agent '{}': unknown body streaming mode '{}'. Valid modes: buffer, stream, hybrid, hybrid:<bytes>",
            agent_id,
            other
        )),
    }
}

/// Parse TLS configuration for agent transport
fn parse_agent_tls(node: &kdl::KdlNode) -> Result<Option<AgentTlsConfig>> {
    let children = match node.children() {
        Some(doc) => doc,
        None => return Ok(None),
    };

    let mut has_tls = false;
    let mut insecure_skip_verify = false;
    let mut ca_cert = None;
    let mut client_cert = None;
    let mut client_key = None;

    for child in children.nodes() {
        match child.name().value() {
            "tls" | "tls-insecure" => {
                has_tls = true;
                if child.name().value() == "tls-insecure" {
                    insecure_skip_verify = true;
                }
            }
            "ca-cert" => {
                has_tls = true;
                if let Some(path) = get_first_arg_string(child) {
                    ca_cert = Some(PathBuf::from(path));
                }
            }
            "client-cert" => {
                has_tls = true;
                if let Some(path) = get_first_arg_string(child) {
                    client_cert = Some(PathBuf::from(path));
                }
            }
            "client-key" => {
                has_tls = true;
                if let Some(path) = get_first_arg_string(child) {
                    client_key = Some(PathBuf::from(path));
                }
            }
            _ => {}
        }
    }

    if has_tls {
        Ok(Some(AgentTlsConfig {
            insecure_skip_verify,
            ca_cert,
            client_cert,
            client_key,
        }))
    } else {
        Ok(None)
    }
}

/// Parse circuit breaker configuration
fn parse_circuit_breaker(node: &kdl::KdlNode) -> Result<CircuitBreakerConfig> {
    let mut config = CircuitBreakerConfig::default();

    if let Some(v) = get_int_entry(node, "failure-threshold") {
        config.failure_threshold = v as u32;
    }
    if let Some(v) = get_int_entry(node, "success-threshold") {
        config.success_threshold = v as u32;
    }
    if let Some(v) = get_int_entry(node, "timeout-seconds") {
        config.timeout_seconds = v as u64;
    }
    if let Some(v) = get_int_entry(node, "half-open-max-requests") {
        config.half_open_max_requests = v as u32;
    }

    Ok(config)
}

// ============================================================================
// WAF Parsing
// ============================================================================

/// Parse WAF configuration block
pub fn parse_waf_config(_node: &kdl::KdlNode) -> Result<WafConfig> {
    // TODO: Implement full WAF config parsing
    Err(anyhow::anyhow!(
        "WAF configuration parsing not yet implemented"
    ))
}

// ============================================================================
// Limits Parsing
// ============================================================================

/// Parse limits configuration block
pub fn parse_limits_config(node: &kdl::KdlNode) -> Result<Limits> {
    let mut limits = Limits::default();

    if let Some(v) = get_int_entry(node, "max-header-size") {
        limits.max_header_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-header-count") {
        limits.max_header_count = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-body-size") {
        limits.max_body_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-connections-per-client") {
        limits.max_connections_per_client = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-total-connections") {
        limits.max_total_connections = v as usize;
    }
    if let Some(v) = get_int_entry(node, "max-in-flight-requests") {
        limits.max_in_flight_requests = v as usize;
    }

    Ok(limits)
}

// ============================================================================
// Cache Storage Parsing
// ============================================================================

use crate::routes::{CacheBackend, CacheStorageConfig};

/// Parse cache configuration block
///
/// KDL format:
/// ```kdl
/// cache {
///     enabled true
///     backend "memory"          // "memory", "disk", or "hybrid"
///     max-size 104857600        // 100MB in bytes
///     eviction-limit 104857600  // When to start evicting
///     lock-timeout 10           // Seconds
///     disk-path "/var/cache/sentinel"  // For disk backend
///     disk-shards 16            // Parallelism for disk cache
/// }
/// ```
pub fn parse_cache_config(node: &kdl::KdlNode) -> Result<CacheStorageConfig> {
    let mut config = CacheStorageConfig::default();

    // Parse enabled flag
    if let Some(v) = get_bool_entry(node, "enabled") {
        config.enabled = v;
    }

    // Parse backend type
    if let Some(backend) = get_string_entry(node, "backend") {
        config.backend = match backend.to_lowercase().as_str() {
            "memory" => CacheBackend::Memory,
            "disk" => CacheBackend::Disk,
            "hybrid" => CacheBackend::Hybrid,
            other => {
                return Err(anyhow::anyhow!(
                    "Invalid cache backend '{}'. Valid options: memory, disk, hybrid",
                    other
                ));
            }
        };
    }

    // Parse size limits
    if let Some(v) = get_int_entry(node, "max-size") {
        config.max_size_bytes = v as usize;
    }
    if let Some(v) = get_int_entry(node, "eviction-limit") {
        config.eviction_limit_bytes = Some(v as usize);
    }

    // Parse lock timeout
    if let Some(v) = get_int_entry(node, "lock-timeout") {
        config.lock_timeout_secs = v as u64;
    }

    // Parse disk options
    if let Some(path) = get_string_entry(node, "disk-path") {
        config.disk_path = Some(std::path::PathBuf::from(path));
    }
    if let Some(v) = get_int_entry(node, "disk-shards") {
        config.disk_shards = v as u32;
    }

    // Validate disk backend has a path
    if config.backend == CacheBackend::Disk && config.disk_path.is_none() {
        return Err(anyhow::anyhow!(
            "Disk cache backend requires 'disk-path' to be specified"
        ));
    }

    Ok(config)
}

// ============================================================================
// Rate Limits Parsing
// ============================================================================

use crate::filters::{GlobalLimitConfig, GlobalRateLimitConfig, RateLimitKey};

/// Parse rate-limits configuration block
///
/// KDL format:
/// ```kdl
/// rate-limits {
///     default-rps 100
///     default-burst 20
///     key "client-ip"
///
///     global {
///         max-rps 10000
///         burst 1000
///         key "client-ip"
///     }
/// }
/// ```
pub fn parse_rate_limits_config(node: &kdl::KdlNode) -> Result<GlobalRateLimitConfig> {
    let mut config = GlobalRateLimitConfig::default();

    // Parse direct properties
    if let Some(v) = get_int_entry(node, "default-rps") {
        config.default_rps = Some(v as u32);
    }
    if let Some(v) = get_int_entry(node, "default-burst") {
        config.default_burst = Some(v as u32);
    }
    if let Some(key) = get_string_entry(node, "key") {
        config.key = parse_rate_limit_key(&key)?;
    }

    // Parse global block
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let name = child.name().value();
            if name == "global" {
                config.global = Some(parse_global_limit_config(child)?);
            }
        }
    }

    Ok(config)
}

/// Parse a global limit configuration block
fn parse_global_limit_config(node: &kdl::KdlNode) -> Result<GlobalLimitConfig> {
    let max_rps = get_int_entry(node, "max-rps")
        .ok_or_else(|| anyhow::anyhow!("global rate limit requires 'max-rps'"))?
        as u32;

    let burst = get_int_entry(node, "burst").unwrap_or(10) as u32;

    let key = if let Some(key_str) = get_string_entry(node, "key") {
        parse_rate_limit_key(&key_str)?
    } else {
        RateLimitKey::ClientIp
    };

    Ok(GlobalLimitConfig {
        max_rps,
        burst,
        key,
    })
}

/// Parse a rate limit key string into the enum
fn parse_rate_limit_key(key: &str) -> Result<RateLimitKey> {
    match key.to_lowercase().as_str() {
        "client-ip" | "client_ip" | "ip" => Ok(RateLimitKey::ClientIp),
        "path" => Ok(RateLimitKey::Path),
        "route" => Ok(RateLimitKey::Route),
        "client-ip-and-path" | "client_ip_and_path" => Ok(RateLimitKey::ClientIpAndPath),
        s if s.starts_with("header:") => {
            let header_name = s.strip_prefix("header:").unwrap_or("");
            Ok(RateLimitKey::Header(header_name.to_string()))
        }
        other => Err(anyhow::anyhow!(
            "Unknown rate limit key: '{}'. Valid values: client-ip, path, route, client-ip-and-path, header:<name>",
            other
        )),
    }
}

// ============================================================================
// Observability Parsing
// ============================================================================

/// Parse observability configuration block
///
/// KDL format:
/// ```kdl
/// observability {
///     logging {
///         level "info"
///         format "json"
///         access-log {
///             enabled true
///             file "/var/log/sentinel/access.log"
///             format "json"
///         }
///         error-log {
///             enabled true
///             file "/var/log/sentinel/error.log"
///             level "warn"
///         }
///         audit-log {
///             enabled true
///             file "/var/log/sentinel/audit.log"
///             log-blocked true
///             log-agent-decisions true
///             log-waf-events true
///         }
///     }
/// }
/// ```
pub fn parse_observability_config(node: &kdl::KdlNode) -> Result<ObservabilityConfig> {
    let mut config = ObservabilityConfig::default();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            let name = child.name().value();
            match name {
                "logging" => {
                    config.logging = parse_logging_config(child)?;
                }
                "metrics" => {
                    config.metrics = parse_metrics_config(child)?;
                }
                _ => {
                    trace!(name = %name, "Unknown observability config block, ignoring");
                }
            }
        }
    }

    Ok(config)
}

/// Parse logging configuration block
fn parse_logging_config(node: &kdl::KdlNode) -> Result<crate::observability::LoggingConfig> {
    use crate::observability::LoggingConfig;

    let mut config = LoggingConfig::default();

    // Parse direct properties
    if let Some(level) = get_string_entry(node, "level") {
        config.level = level;
    }
    if let Some(format) = get_string_entry(node, "format") {
        config.format = format;
    }

    // Parse child blocks
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let name = child.name().value();
            match name {
                "access-log" => {
                    config.access_log = Some(parse_access_log_config(child)?);
                }
                "error-log" => {
                    config.error_log = Some(parse_error_log_config(child)?);
                }
                "audit-log" => {
                    config.audit_log = Some(parse_audit_log_config(child)?);
                }
                _ => {
                    trace!(name = %name, "Unknown logging config block, ignoring");
                }
            }
        }
    }

    Ok(config)
}

/// Parse access log configuration
fn parse_access_log_config(node: &kdl::KdlNode) -> Result<crate::observability::AccessLogConfig> {
    use crate::observability::AccessLogConfig;
    use std::path::PathBuf;

    let mut config = AccessLogConfig::default();

    if let Some(enabled) = get_bool_entry(node, "enabled") {
        config.enabled = enabled;
    }
    if let Some(file) = get_string_entry(node, "file") {
        config.file = PathBuf::from(file);
    }
    if let Some(format) = get_string_entry(node, "format") {
        config.format = format;
    }
    if let Some(buffer_size) = get_int_entry(node, "buffer-size") {
        config.buffer_size = buffer_size as usize;
    }

    Ok(config)
}

/// Parse error log configuration
fn parse_error_log_config(node: &kdl::KdlNode) -> Result<crate::observability::ErrorLogConfig> {
    use crate::observability::ErrorLogConfig;
    use std::path::PathBuf;

    let mut config = ErrorLogConfig::default();

    if let Some(enabled) = get_bool_entry(node, "enabled") {
        config.enabled = enabled;
    }
    if let Some(file) = get_string_entry(node, "file") {
        config.file = PathBuf::from(file);
    }
    if let Some(level) = get_string_entry(node, "level") {
        config.level = level;
    }
    if let Some(buffer_size) = get_int_entry(node, "buffer-size") {
        config.buffer_size = buffer_size as usize;
    }

    Ok(config)
}

/// Parse audit log configuration
fn parse_audit_log_config(node: &kdl::KdlNode) -> Result<crate::observability::AuditLogConfig> {
    use crate::observability::AuditLogConfig;
    use std::path::PathBuf;

    let mut config = AuditLogConfig::default();

    if let Some(enabled) = get_bool_entry(node, "enabled") {
        config.enabled = enabled;
    }
    if let Some(file) = get_string_entry(node, "file") {
        config.file = PathBuf::from(file);
    }
    if let Some(buffer_size) = get_int_entry(node, "buffer-size") {
        config.buffer_size = buffer_size as usize;
    }
    if let Some(log_blocked) = get_bool_entry(node, "log-blocked") {
        config.log_blocked = log_blocked;
    }
    if let Some(log_agent) = get_bool_entry(node, "log-agent-decisions") {
        config.log_agent_decisions = log_agent;
    }
    if let Some(log_waf) = get_bool_entry(node, "log-waf-events") {
        config.log_waf_events = log_waf;
    }

    Ok(config)
}

/// Parse metrics configuration block
fn parse_metrics_config(node: &kdl::KdlNode) -> Result<crate::observability::MetricsConfig> {
    use crate::observability::MetricsConfig;

    let mut config = MetricsConfig::default();

    if let Some(enabled) = get_bool_entry(node, "enabled") {
        config.enabled = enabled;
    }
    if let Some(address) = get_string_entry(node, "address") {
        config.address = address;
    }
    if let Some(path) = get_string_entry(node, "path") {
        config.path = path;
    }
    if let Some(high_cardinality) = get_bool_entry(node, "high-cardinality") {
        config.high_cardinality = high_cardinality;
    }

    Ok(config)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::RateLimitKey;

    #[test]
    fn test_parse_rate_limits_config_empty() {
        let kdl = r#"rate-limits {}"#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_rate_limits_config(node).unwrap();
        assert!(config.default_rps.is_none());
        assert!(config.default_burst.is_none());
        assert_eq!(config.key, RateLimitKey::ClientIp);
        assert!(config.global.is_none());
    }

    #[test]
    fn test_parse_rate_limits_config_with_defaults() {
        let kdl = r#"
            rate-limits {
                default-rps 100
                default-burst 20
                key "path"
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_rate_limits_config(node).unwrap();
        assert_eq!(config.default_rps, Some(100));
        assert_eq!(config.default_burst, Some(20));
        assert_eq!(config.key, RateLimitKey::Path);
        assert!(config.global.is_none());
    }

    #[test]
    fn test_parse_rate_limits_config_with_global() {
        let kdl = r#"
            rate-limits {
                default-rps 50
                global {
                    max-rps 10000
                    burst 1000
                    key "client-ip"
                }
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_rate_limits_config(node).unwrap();
        assert_eq!(config.default_rps, Some(50));
        assert!(config.global.is_some());

        let global = config.global.unwrap();
        assert_eq!(global.max_rps, 10000);
        assert_eq!(global.burst, 1000);
        assert_eq!(global.key, RateLimitKey::ClientIp);
    }

    #[test]
    fn test_parse_rate_limit_key_variations() {
        assert_eq!(
            parse_rate_limit_key("client-ip").unwrap(),
            RateLimitKey::ClientIp
        );
        assert_eq!(parse_rate_limit_key("ip").unwrap(), RateLimitKey::ClientIp);
        assert_eq!(parse_rate_limit_key("path").unwrap(), RateLimitKey::Path);
        assert_eq!(parse_rate_limit_key("route").unwrap(), RateLimitKey::Route);
        assert_eq!(
            parse_rate_limit_key("client-ip-and-path").unwrap(),
            RateLimitKey::ClientIpAndPath
        );
    }

    #[test]
    fn test_parse_rate_limit_key_header() {
        let key = parse_rate_limit_key("header:X-Custom-Key").unwrap();
        match key {
            // Header name is lowercased during parsing
            RateLimitKey::Header(name) => assert_eq!(name, "x-custom-key"),
            _ => panic!("Expected Header variant"),
        }
    }

    #[test]
    fn test_parse_rate_limit_key_invalid() {
        let result = parse_rate_limit_key("invalid-key-type");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_full_config_with_rate_limits() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            rate-limits {
                default-rps 100
                default-burst 20
                global {
                    max-rps 5000
                    burst 500
                    key "client-ip"
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        assert_eq!(config.rate_limits.default_rps, Some(100));
        assert_eq!(config.rate_limits.default_burst, Some(20));
        assert!(config.rate_limits.global.is_some());

        let global = config.rate_limits.global.as_ref().unwrap();
        assert_eq!(global.max_rps, 5000);
        assert_eq!(global.burst, 500);
    }

    #[test]
    fn test_parse_rate_limit_filter_with_max_delay() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            filters {
                filter "api-limiter" {
                    type "rate-limit"
                    max-rps 50
                    burst 10
                    key "client-ip"
                    on-limit "delay"
                    max-delay-ms 3000
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        let filter = config.filters.get("api-limiter").unwrap();
        match &filter.filter {
            crate::Filter::RateLimit(rl) => {
                assert_eq!(rl.max_rps, 50);
                assert_eq!(rl.burst, 10);
                assert_eq!(rl.on_limit, crate::RateLimitAction::Delay);
                assert_eq!(rl.max_delay_ms, 3000);
            }
            _ => panic!("Expected RateLimit filter"),
        }
    }

    #[test]
    fn test_parse_geo_filter_block_mode() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            filters {
                filter "block-countries" {
                    type "geo"
                    database-path "/etc/sentinel/GeoLite2-Country.mmdb"
                    action "block"
                    countries "RU,CN,KP,IR"
                    on-failure "closed"
                    status-code 403
                    block-message "Access denied from your region"
                    cache-ttl-secs 7200
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        let filter = config.filters.get("block-countries").unwrap();
        match &filter.filter {
            crate::Filter::Geo(geo) => {
                assert_eq!(geo.database_path, "/etc/sentinel/GeoLite2-Country.mmdb");
                assert_eq!(geo.database_type, Some(crate::GeoDatabaseType::MaxMind));
                assert_eq!(geo.action, crate::GeoFilterAction::Block);
                assert_eq!(geo.countries, vec!["RU", "CN", "KP", "IR"]);
                assert_eq!(geo.on_failure, crate::GeoFailureMode::Closed);
                assert_eq!(geo.status_code, 403);
                assert_eq!(
                    geo.block_message,
                    Some("Access denied from your region".to_string())
                );
                assert_eq!(geo.cache_ttl_secs, 7200);
                // add_country_header defaults to true
                assert!(geo.add_country_header);
            }
            _ => panic!("Expected Geo filter"),
        }
    }

    #[test]
    fn test_parse_geo_filter_allow_mode() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            filters {
                filter "us-only" {
                    type "geo"
                    database-path "/etc/sentinel/GeoLite2-Country.mmdb"
                    action "allow"
                    countries "US,CA"
                    on-failure "open"
                    status-code 451
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        let filter = config.filters.get("us-only").unwrap();
        match &filter.filter {
            crate::Filter::Geo(geo) => {
                assert_eq!(geo.action, crate::GeoFilterAction::Allow);
                assert_eq!(geo.countries, vec!["US", "CA"]);
                assert_eq!(geo.on_failure, crate::GeoFailureMode::Open);
                assert_eq!(geo.status_code, 451);
            }
            _ => panic!("Expected Geo filter"),
        }
    }

    #[test]
    fn test_parse_geo_filter_log_only_mode() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            filters {
                filter "geo-tagging" {
                    type "geo"
                    database-path "/etc/sentinel/IP2LOCATION-LITE-DB1.BIN"
                    database-type "ip2location"
                    action "log-only"
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        let filter = config.filters.get("geo-tagging").unwrap();
        match &filter.filter {
            crate::Filter::Geo(geo) => {
                assert_eq!(geo.database_path, "/etc/sentinel/IP2LOCATION-LITE-DB1.BIN");
                assert_eq!(geo.database_type, Some(crate::GeoDatabaseType::Ip2Location));
                assert_eq!(geo.action, crate::GeoFilterAction::LogOnly);
                assert!(geo.countries.is_empty());
            }
            _ => panic!("Expected Geo filter"),
        }
    }

    #[test]
    fn test_parse_geo_filter_auto_detect_database_type() {
        // MaxMind .mmdb extension
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            filters {
                filter "geo-mmdb" {
                    type "geo"
                    database-path "/path/to/db.mmdb"
                    action "log-only"
                }
                filter "geo-bin" {
                    type "geo"
                    database-path "/path/to/db.bin"
                    action "log-only"
                }
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        // .mmdb should be detected as MaxMind
        let filter = config.filters.get("geo-mmdb").unwrap();
        match &filter.filter {
            crate::Filter::Geo(geo) => {
                assert_eq!(geo.database_type, Some(crate::GeoDatabaseType::MaxMind));
            }
            _ => panic!("Expected Geo filter"),
        }

        // .bin should be detected as IP2Location
        let filter = config.filters.get("geo-bin").unwrap();
        match &filter.filter {
            crate::Filter::Geo(geo) => {
                assert_eq!(geo.database_type, Some(crate::GeoDatabaseType::Ip2Location));
            }
            _ => panic!("Expected Geo filter"),
        }
    }

    // =========================================================================
    // Cache Configuration Tests
    // =========================================================================

    #[test]
    fn test_parse_cache_config_defaults() {
        let kdl = r#"cache {}"#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_cache_config(node).unwrap();
        assert!(config.enabled);
        assert_eq!(config.backend, CacheBackend::Memory);
        assert_eq!(config.max_size_bytes, 100 * 1024 * 1024); // 100MB default
        assert!(config.eviction_limit_bytes.is_none());
        assert_eq!(config.lock_timeout_secs, 10);
        assert!(config.disk_path.is_none());
        assert_eq!(config.disk_shards, 16);
    }

    #[test]
    fn test_parse_cache_config_memory_backend() {
        let kdl = r#"
            cache {
                enabled #true
                backend "memory"
                max-size 209715200
                eviction-limit 104857600
                lock-timeout 5
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_cache_config(node).unwrap();
        assert!(config.enabled);
        assert_eq!(config.backend, CacheBackend::Memory);
        assert_eq!(config.max_size_bytes, 209715200); // 200MB
        assert_eq!(config.eviction_limit_bytes, Some(104857600)); // 100MB
        assert_eq!(config.lock_timeout_secs, 5);
    }

    #[test]
    fn test_parse_cache_config_disk_backend() {
        let kdl = r#"
            cache {
                enabled #true
                backend "disk"
                max-size 1073741824
                disk-path "/var/cache/sentinel"
                disk-shards 32
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_cache_config(node).unwrap();
        assert!(config.enabled);
        assert_eq!(config.backend, CacheBackend::Disk);
        assert_eq!(config.max_size_bytes, 1073741824); // 1GB
        assert_eq!(
            config.disk_path,
            Some(std::path::PathBuf::from("/var/cache/sentinel"))
        );
        assert_eq!(config.disk_shards, 32);
    }

    #[test]
    fn test_parse_cache_config_hybrid_backend() {
        let kdl = r#"
            cache {
                backend "hybrid"
                disk-path "/var/cache/sentinel"
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_cache_config(node).unwrap();
        assert_eq!(config.backend, CacheBackend::Hybrid);
    }

    #[test]
    fn test_parse_cache_config_disabled() {
        let kdl = r#"
            cache {
                enabled #false
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_cache_config(node).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn test_parse_cache_config_invalid_backend() {
        let kdl = r#"
            cache {
                backend "invalid"
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let result = parse_cache_config(node);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid cache backend"));
    }

    #[test]
    fn test_parse_cache_config_disk_without_path() {
        let kdl = r#"
            cache {
                backend "disk"
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let result = parse_cache_config(node);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("disk-path"));
    }

    #[test]
    fn test_parse_full_config_with_cache() {
        let kdl = r#"
            server {
                worker-threads 4
            }

            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }

            cache {
                enabled #true
                backend "memory"
                max-size 209715200
                lock-timeout 15
            }

            routes {
                route "default" {
                    match {
                        path-prefix "/"
                    }
                    builtin "status"
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        assert!(config.cache.is_some());
        let cache = config.cache.unwrap();
        assert!(cache.enabled);
        assert_eq!(cache.backend, CacheBackend::Memory);
        assert_eq!(cache.max_size_bytes, 209715200);
        assert_eq!(cache.lock_timeout_secs, 15);
    }
}
