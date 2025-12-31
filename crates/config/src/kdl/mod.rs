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
use crate::{AgentConfig, Config};

// ============================================================================
// Top-Level Document Parser
// ============================================================================

/// Convert a parsed KDL document to Config
pub fn parse_kdl_document(doc: kdl::KdlDocument) -> Result<Config> {
    trace!(node_count = doc.nodes().len(), "Parsing KDL document");

    let mut server = None;
    let mut listeners = Vec::new();
    let mut routes = Vec::new();
    let mut upstreams = HashMap::new();
    let mut filters = HashMap::new();
    let mut agents = Vec::new();
    let mut waf = None;
    let mut limits = None;
    let mut observability = None;

    for node in doc.nodes() {
        let node_name = node.name().value();
        trace!(node = node_name, "Processing top-level node");

        match node_name {
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
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown top-level configuration block: '{}'\n\
                     Valid blocks are: server, listeners, routes, upstreams, filters, agents, waf, limits, observability",
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
        server,
        listeners,
        routes,
        upstreams,
        filters,
        agents,
        waf,
        limits: limits.unwrap_or_default(),
        observability: observability.unwrap_or_default(),
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
