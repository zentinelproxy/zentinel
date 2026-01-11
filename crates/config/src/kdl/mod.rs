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
//! - `namespace`: Namespace and service parsing

mod filters;
mod helpers;
mod namespace;
mod routes;
mod server;
mod upstreams;

use tracing::{debug, trace, warn};

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
    let mut namespaces = Vec::new();
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
            // Accept both "system" (preferred) and "server" (deprecated)
            "system" => {
                server = Some(parse_server_config(node)?);
                trace!("Parsed system configuration");
            }
            "server" => {
                warn!(
                    "The 'server' block is deprecated. Please use 'system' instead. \
                     This will be removed in a future version."
                );
                server = Some(parse_server_config(node)?);
                trace!("Parsed server configuration (deprecated)");
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
            "namespace" => {
                let ns = namespace::parse_namespace(node)?;
                trace!(namespace = %ns.id, "Parsed namespace");
                namespaces.push(ns);
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
                     Valid blocks are: schema-version, system, listeners, routes, upstreams, \
                     filters, agents, waf, namespace, limits, observability, rate-limits, cache",
                    other
                ));
            }
        }
    }

    // Validate required sections
    let server = server.ok_or_else(|| {
        anyhow::anyhow!(
            "Missing required 'system' configuration block\n\
             Example:\n\
             system {{\n\
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
        namespaces = namespaces.len(),
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
        namespaces,
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
                // Single argument - safe to unwrap since we checked len == 1
                args.into_iter().next().expect("args has exactly one element")
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
    let mut max_concurrent_calls = 100usize; // Per-agent concurrency limit

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
            "max-concurrent-calls" => {
                if let Some(entry) = child.entries().first() {
                    if let Some(v) = entry.value().as_integer() {
                        max_concurrent_calls = v as usize;
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
        config,
        max_concurrent_calls,
    })
}

/// Parse body streaming mode from string
fn parse_body_streaming_mode(mode: &str, agent_id: &str) -> Result<BodyStreamingMode> {
    match mode {
        "buffer" => Ok(BodyStreamingMode::Buffer),
        "stream" => Ok(BodyStreamingMode::Stream),
        _ if mode.starts_with("hybrid:") => {
            // Parse "hybrid:1024" format - safe to unwrap since we checked starts_with
            let threshold_str = mode.strip_prefix("hybrid:")
                .expect("mode starts with 'hybrid:' prefix");
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
///
/// KDL format:
/// ```kdl
/// waf {
///     engine "coraza"           // "mod_security", "coraza", or custom("name")
///     mode "prevention"         // "off", "detection", "prevention"
///     audit-log true
///
///     ruleset {
///         crs-version "3.3.4"
///         custom-rules-dir "/etc/sentinel/waf/rules"
///         paranoia-level 1          // 1-4
///         anomaly-threshold 5
///
///         exclusion {
///             rule-ids "920350" "920370"
///             scope "global"        // "global", path="/api/*", host="example.com"
///         }
///     }
///
///     body-inspection {
///         inspect-request-body true
///         inspect-response-body false
///         max-inspection-bytes 1048576
///         content-types "application/json" "application/xml"
///         decompress false
///         max-decompression-ratio 100.0
///     }
/// }
/// ```
pub fn parse_waf_config(node: &kdl::KdlNode) -> Result<WafConfig> {
    use crate::waf::{BodyInspectionPolicy, WafEngine, WafMode, WafRuleset};

    // Parse engine type
    let engine = if let Some(engine_str) = get_string_entry(node, "engine") {
        match engine_str.to_lowercase().as_str() {
            "mod_security" | "modsecurity" => WafEngine::ModSecurity,
            "coraza" => WafEngine::Coraza,
            custom => WafEngine::Custom(custom.to_string()),
        }
    } else {
        // Default to Coraza if not specified
        WafEngine::Coraza
    };

    // Parse mode
    let mode = if let Some(mode_str) = get_string_entry(node, "mode") {
        match mode_str.to_lowercase().as_str() {
            "off" => WafMode::Off,
            "detection" | "detect" => WafMode::Detection,
            "prevention" | "prevent" | "block" => WafMode::Prevention,
            other => {
                return Err(anyhow::anyhow!(
                    "Invalid WAF mode '{}'. Valid options: off, detection, prevention",
                    other
                ));
            }
        }
    } else {
        WafMode::Prevention
    };

    // Parse audit logging
    let audit_log = get_bool_entry(node, "audit-log").unwrap_or(true);

    // Parse ruleset
    let ruleset = if let Some(children) = node.children() {
        if let Some(ruleset_node) = children.get("ruleset") {
            parse_waf_ruleset(ruleset_node)?
        } else {
            // Default ruleset if none specified
            WafRuleset {
                crs_version: "3.3.4".to_string(),
                custom_rules_dir: None,
                paranoia_level: 1,
                anomaly_threshold: 5,
                exclusions: vec![],
            }
        }
    } else {
        // Default ruleset if no children
        WafRuleset {
            crs_version: "3.3.4".to_string(),
            custom_rules_dir: None,
            paranoia_level: 1,
            anomaly_threshold: 5,
            exclusions: vec![],
        }
    };

    // Parse body inspection
    let body_inspection = if let Some(children) = node.children() {
        if let Some(body_node) = children.get("body-inspection") {
            parse_body_inspection_policy(body_node)?
        } else {
            BodyInspectionPolicy::default()
        }
    } else {
        BodyInspectionPolicy::default()
    };

    Ok(WafConfig {
        engine,
        ruleset,
        mode,
        audit_log,
        body_inspection,
    })
}

/// Parse WAF ruleset configuration
fn parse_waf_ruleset(node: &kdl::KdlNode) -> Result<crate::waf::WafRuleset> {
    use crate::waf::WafRuleset;
    use std::path::PathBuf;

    let crs_version = get_string_entry(node, "crs-version").unwrap_or_else(|| "3.3.4".to_string());

    let custom_rules_dir = get_string_entry(node, "custom-rules-dir").map(PathBuf::from);

    let paranoia_level = get_int_entry(node, "paranoia-level")
        .map(|v| v as u8)
        .unwrap_or(1);

    // Validate paranoia level (1-4)
    if !(1..=4).contains(&paranoia_level) {
        return Err(anyhow::anyhow!(
            "WAF paranoia level must be between 1 and 4, got {}",
            paranoia_level
        ));
    }

    let anomaly_threshold = get_int_entry(node, "anomaly-threshold")
        .map(|v| v as u32)
        .unwrap_or(5);

    // Parse exclusions
    let mut exclusions = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "exclusion" {
                exclusions.push(parse_rule_exclusion(child)?);
            }
        }
    }

    Ok(WafRuleset {
        crs_version,
        custom_rules_dir,
        paranoia_level,
        anomaly_threshold,
        exclusions,
    })
}

/// Parse a rule exclusion
fn parse_rule_exclusion(node: &kdl::KdlNode) -> Result<crate::waf::RuleExclusion> {
    use crate::waf::{ExclusionScope, RuleExclusion};

    // Parse rule IDs - can be arguments or a child node
    let mut rule_ids = Vec::new();

    // Try getting from "rule-ids" child node first
    if let Some(children) = node.children() {
        if let Some(ids_node) = children.get("rule-ids") {
            for entry in ids_node.entries() {
                if let Some(id) = entry.value().as_string() {
                    rule_ids.push(id.to_string());
                }
            }
        }
    }

    // Also try getting from entries on the exclusion node itself
    for entry in node.entries() {
        if let Some(name) = entry.name() {
            if name.value() == "rule-ids" {
                // Skip, handled above
                continue;
            }
        } else if let Some(id) = entry.value().as_string() {
            // Positional argument - this is a rule ID
            rule_ids.push(id.to_string());
        }
    }

    // Parse scope
    let scope = if let Some(scope_str) = get_string_entry(node, "scope") {
        match scope_str.to_lowercase().as_str() {
            "global" => ExclusionScope::Global,
            path if path.starts_with("path=") => {
                ExclusionScope::Path(path.trim_start_matches("path=").to_string())
            }
            host if host.starts_with("host=") => {
                ExclusionScope::Host(host.trim_start_matches("host=").to_string())
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Invalid exclusion scope '{}'. Valid options: global, path=<pattern>, host=<hostname>",
                    other
                ));
            }
        }
    } else {
        ExclusionScope::Global
    };

    if rule_ids.is_empty() {
        return Err(anyhow::anyhow!(
            "WAF rule exclusion requires at least one rule ID"
        ));
    }

    Ok(RuleExclusion { rule_ids, scope })
}

/// Parse body inspection policy
fn parse_body_inspection_policy(node: &kdl::KdlNode) -> Result<crate::waf::BodyInspectionPolicy> {
    use crate::waf::BodyInspectionPolicy;

    let inspect_request_body = get_bool_entry(node, "inspect-request-body").unwrap_or(true);
    let inspect_response_body = get_bool_entry(node, "inspect-response-body").unwrap_or(false);
    let max_inspection_bytes = get_int_entry(node, "max-inspection-bytes")
        .map(|v| v as usize)
        .unwrap_or(1024 * 1024); // 1MB default
    let decompress = get_bool_entry(node, "decompress").unwrap_or(false);
    let max_decompression_ratio = get_int_entry(node, "max-decompression-ratio")
        .map(|v| v as f32)
        .unwrap_or(100.0);

    // Parse content types
    let mut content_types = Vec::new();
    if let Some(children) = node.children() {
        if let Some(ct_node) = children.get("content-types") {
            for entry in ct_node.entries() {
                if let Some(ct) = entry.value().as_string() {
                    content_types.push(ct.to_string());
                }
            }
        }
    }

    // If no content types specified, use defaults
    if content_types.is_empty() {
        content_types = vec![
            "application/x-www-form-urlencoded".to_string(),
            "multipart/form-data".to_string(),
            "application/json".to_string(),
            "application/xml".to_string(),
            "text/xml".to_string(),
        ];
    }

    Ok(BodyInspectionPolicy {
        inspect_request_body,
        inspect_response_body,
        max_inspection_bytes,
        content_types,
        decompress,
        max_decompression_ratio,
    })
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
                "tracing" => {
                    config.tracing = Some(parse_tracing_config(child)?);
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

/// Parse tracing configuration block
///
/// KDL format:
/// ```kdl
/// tracing {
///     backend "otlp" {
///         endpoint "http://localhost:4317"
///     }
///     sampling-rate 0.1
///     service-name "sentinel"
/// }
/// ```
fn parse_tracing_config(node: &kdl::KdlNode) -> Result<crate::observability::TracingConfig> {
    use crate::observability::TracingConfig;
    use helpers::get_float_entry;

    let backend = parse_tracing_backend(node)?;

    let sampling_rate = get_float_entry(node, "sampling-rate").unwrap_or(0.01);
    let service_name =
        get_string_entry(node, "service-name").unwrap_or_else(|| "sentinel".to_string());

    Ok(TracingConfig {
        backend,
        sampling_rate,
        service_name,
    })
}

/// Parse tracing backend configuration
///
/// Supports:
/// - `backend "otlp" { endpoint "..." }`
/// - `backend "jaeger" { endpoint "..." }`
/// - `backend "zipkin" { endpoint "..." }`
fn parse_tracing_backend(node: &kdl::KdlNode) -> Result<crate::observability::TracingBackend> {
    use crate::observability::TracingBackend;

    // Look for a "backend" child node
    let backend_node = node
        .children()
        .and_then(|children| children.get("backend"))
        .ok_or_else(|| anyhow::anyhow!("tracing config requires 'backend' block"))?;

    // Get the backend type from the first argument
    let backend_type = backend_node
        .entries()
        .first()
        .and_then(|e| e.value().as_string())
        .ok_or_else(|| anyhow::anyhow!("backend requires a type (otlp, jaeger, or zipkin)"))?;

    // Get the endpoint from the backend block's children
    let endpoint = get_string_entry(backend_node, "endpoint")
        .ok_or_else(|| anyhow::anyhow!("backend requires 'endpoint' configuration"))?;

    match backend_type.to_lowercase().as_str() {
        "otlp" => Ok(TracingBackend::Otlp { endpoint }),
        "jaeger" => Ok(TracingBackend::Jaeger { endpoint }),
        "zipkin" => Ok(TracingBackend::Zipkin { endpoint }),
        other => Err(anyhow::anyhow!(
            "Unknown tracing backend '{}'. Supported: otlp, jaeger, zipkin",
            other
        )),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::RateLimitKey;

    #[test]
    fn test_parse_tracing_config() {
        let kdl = r#"
            tracing {
                backend "otlp" {
                    endpoint "http://localhost:4317"
                }
                sampling-rate 0.5
                service-name "my-service"
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_tracing_config(node).unwrap();
        assert_eq!(config.sampling_rate, 0.5);
        assert_eq!(config.service_name, "my-service");
        match config.backend {
            crate::observability::TracingBackend::Otlp { endpoint } => {
                assert_eq!(endpoint, "http://localhost:4317");
            }
            _ => panic!("Expected OTLP backend"),
        }
    }

    #[test]
    fn test_parse_tracing_config_defaults() {
        let kdl = r#"
            tracing {
                backend "jaeger" {
                    endpoint "http://jaeger:14268/api/traces"
                }
            }
        "#;
        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let node = doc.nodes().first().unwrap();

        let config = parse_tracing_config(node).unwrap();
        assert_eq!(config.sampling_rate, 0.01); // default
        assert_eq!(config.service_name, "sentinel"); // default
    }

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

    #[test]
    fn test_parse_agent_max_concurrent_calls() {
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

            agents {
                agent "waf" type="custom" {
                    unix-socket path="/tmp/waf.sock"
                    events "request_headers" "request_body"
                    max-concurrent-calls 50
                }
                agent "auth" type="auth" {
                    unix-socket path="/tmp/auth.sock"
                    events "request_headers"
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

        assert_eq!(config.agents.len(), 2);

        // Verify custom max-concurrent-calls
        let waf_agent = config.agents.iter().find(|a| a.id == "waf").unwrap();
        assert_eq!(waf_agent.max_concurrent_calls, 50);

        // Verify default max-concurrent-calls (100)
        let auth_agent = config.agents.iter().find(|a| a.id == "auth").unwrap();
        assert_eq!(auth_agent.max_concurrent_calls, 100);
    }

    #[test]
    fn test_parse_api_schema_with_file() {
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

            upstreams {
                upstream "api-backend" {
                    target "127.0.0.1:3001" weight=1
                    load-balancing "round_robin"
                }
            }

            routes {
                route "api-route" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "api-backend"

                    api-schema {
                        schema-file "/etc/sentinel/schemas/api-v1.yaml"
                        validate-requests #true
                        validate-responses #false
                        strict-mode #true
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.id, "api-route");
        assert_eq!(route.service_type, crate::routes::ServiceType::Api);

        let api_schema = route.api_schema.as_ref().unwrap();
        assert_eq!(
            api_schema.schema_file.as_ref().unwrap().to_str().unwrap(),
            "/etc/sentinel/schemas/api-v1.yaml"
        );
        assert_eq!(api_schema.validate_requests, true);
        assert_eq!(api_schema.validate_responses, false);
        assert_eq!(api_schema.strict_mode, true);
    }

    #[test]
    fn test_parse_api_schema_with_inline_schema() {
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

            upstreams {
                upstream "api-backend" {
                    target "127.0.0.1:3001" weight=1
                    load-balancing "round_robin"
                }
            }

            routes {
                route "user-registration" {
                    matches {
                        path "/api/register"
                    }
                    upstream "api-backend"

                    api-schema {
                        validate-requests #true
                        request-schema {
                            type "object"
                            properties {
                                email {
                                    type "string"
                                    format "email"
                                }
                                password {
                                    type "string"
                                    minLength 8
                                }
                            }
                            required "email" "password"
                        }
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.id, "user-registration");
        assert_eq!(route.service_type, crate::routes::ServiceType::Api);

        let api_schema = route.api_schema.as_ref().unwrap();
        assert_eq!(api_schema.validate_requests, true);
        assert!(api_schema.request_schema.is_some());

        let schema = api_schema.request_schema.as_ref().unwrap();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"].is_object());
        assert_eq!(schema["properties"]["email"]["type"], "string");
        assert_eq!(schema["properties"]["email"]["format"], "email");
        assert_eq!(schema["properties"]["password"]["minLength"], 8);

        // Verify required array
        let required = schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 2);
        assert!(required.contains(&serde_json::Value::String("email".to_string())));
        assert!(required.contains(&serde_json::Value::String("password".to_string())));
    }

    #[test]
    fn test_parse_api_schema_with_inline_openapi() {
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

            upstreams {
                upstream "api-backend" {
                    target "127.0.0.1:3001" weight=1
                    load-balancing "round_robin"
                }
            }

            routes {
                route "api-with-inline-spec" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "api-backend"

                    api-schema {
                        validate-requests #true
                        schema-content "openapi: 3.0.0\ninfo:\n  title: Test API\n  version: 1.0.0\npaths:\n  /users:\n    post:\n      requestBody:\n        content:\n          application/json:\n            schema:\n              type: object\n              required: [email]\n              properties:\n                email:\n                  type: string\n                  format: email"
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).unwrap();

        assert_eq!(config.routes.len(), 1);
        let route = &config.routes[0];
        assert_eq!(route.id, "api-with-inline-spec");
        assert_eq!(route.service_type, crate::routes::ServiceType::Api);

        let api_schema = route.api_schema.as_ref().unwrap();
        assert!(api_schema.schema_file.is_none());
        assert!(api_schema.schema_content.is_some());
        assert_eq!(api_schema.validate_requests, true);

        let content = api_schema.schema_content.as_ref().unwrap();
        assert!(content.starts_with("openapi: 3.0.0"));
        assert!(content.contains("title: Test API"));
        assert!(content.contains("email"));
    }

    #[test]
    fn test_api_schema_file_and_content_mutually_exclusive() {
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

            upstreams {
                upstream "api-backend" {
                    target "127.0.0.1:3001" weight=1
                    load-balancing "round_robin"
                }
            }

            routes {
                route "invalid-api-route" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "api-backend"

                    api-schema {
                        schema-file "/etc/sentinel/api.yaml"
                        schema-content "openapi: 3.0.0"
                        validate-requests #true
                    }
                }
            }
        "#;

        let result = Config::from_kdl(kdl);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        eprintln!("Error message: {}", error_msg);
        assert!(error_msg.contains("mutually exclusive") || error_msg.contains("Upstream"));
    }

    #[test]
    fn test_parse_fallback_config() {
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

            upstreams {
                upstream "openai-primary" {
                    target "api.openai.com:443" weight=1
                    load-balancing "round_robin"
                }
                upstream "anthropic-fallback" {
                    target "api.anthropic.com:443" weight=1
                    load-balancing "round_robin"
                }
                upstream "local-gpu" {
                    target "localhost:8000" weight=1
                    load-balancing "round_robin"
                }
            }

            routes {
                route "inference-api" {
                    matches {
                        path-prefix "/v1/chat/completions"
                    }
                    upstream "openai-primary"
                    service-type "inference"

                    inference {
                        provider "openai"
                    }

                    fallback {
                        max-attempts 2

                        triggers {
                            on-health-failure #true
                            on-budget-exhausted #true
                            on-latency-threshold-ms 5000
                            on-error-codes 429 500 502 503 504
                            on-connection-error #true
                        }

                        fallback-upstream "anthropic-fallback" {
                            provider "anthropic"
                            skip-if-unhealthy #true

                            model-mapping {
                                "gpt-4" "claude-3-opus"
                                "gpt-4o" "claude-3-5-sonnet"
                                "gpt-3.5-turbo" "claude-3-haiku"
                            }
                        }

                        fallback-upstream "local-gpu" {
                            provider "generic"
                            skip-if-unhealthy #true

                            model-mapping {
                                "gpt-4*" "llama-3-70b"
                                "gpt-3.5*" "llama-3-8b"
                            }
                        }
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).expect("Failed to parse KDL with fallback");

        // Find the inference route
        let route = config
            .routes
            .iter()
            .find(|r| r.id == "inference-api")
            .expect("Route not found");

        assert!(route.fallback.is_some());
        let fallback = route.fallback.as_ref().unwrap();

        // Check max_attempts
        assert_eq!(fallback.max_attempts, 2);

        // Check triggers
        assert!(fallback.triggers.on_health_failure);
        assert!(fallback.triggers.on_budget_exhausted);
        assert_eq!(fallback.triggers.on_latency_threshold_ms, Some(5000));
        assert_eq!(fallback.triggers.on_error_codes, vec![429, 500, 502, 503, 504]);
        assert!(fallback.triggers.on_connection_error);

        // Check fallback upstreams
        assert_eq!(fallback.upstreams.len(), 2);

        let anthropic = &fallback.upstreams[0];
        assert_eq!(anthropic.upstream, "anthropic-fallback");
        assert!(matches!(
            anthropic.provider,
            crate::InferenceProvider::Anthropic
        ));
        assert!(anthropic.skip_if_unhealthy);
        assert_eq!(anthropic.model_mapping.get("gpt-4"), Some(&"claude-3-opus".to_string()));
        assert_eq!(anthropic.model_mapping.get("gpt-4o"), Some(&"claude-3-5-sonnet".to_string()));
        assert_eq!(anthropic.model_mapping.get("gpt-3.5-turbo"), Some(&"claude-3-haiku".to_string()));

        let local = &fallback.upstreams[1];
        assert_eq!(local.upstream, "local-gpu");
        assert!(matches!(
            local.provider,
            crate::InferenceProvider::Generic
        ));
        assert!(local.skip_if_unhealthy);
        assert_eq!(local.model_mapping.get("gpt-4*"), Some(&"llama-3-70b".to_string()));
        assert_eq!(local.model_mapping.get("gpt-3.5*"), Some(&"llama-3-8b".to_string()));
    }

    #[test]
    fn test_parse_fallback_config_minimal() {
        // Test minimal fallback configuration with defaults
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

            upstreams {
                upstream "primary" {
                    target "127.0.0.1:8001" weight=1
                }
                upstream "fallback" {
                    target "127.0.0.1:8002" weight=1
                }
            }

            routes {
                route "api" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "primary"

                    fallback {
                        fallback-upstream "fallback" {
                            // Using defaults
                        }
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).expect("Failed to parse minimal fallback KDL");

        let route = config
            .routes
            .iter()
            .find(|r| r.id == "api")
            .expect("Route not found");

        assert!(route.fallback.is_some());
        let fallback = route.fallback.as_ref().unwrap();

        // Check defaults
        assert_eq!(fallback.max_attempts, 3); // default
        assert!(fallback.triggers.on_health_failure); // default true
        assert!(!fallback.triggers.on_budget_exhausted); // default false
        assert!(fallback.triggers.on_connection_error); // default true
        assert!(fallback.triggers.on_error_codes.is_empty()); // default empty

        // Check fallback upstream
        assert_eq!(fallback.upstreams.len(), 1);
        let fb_upstream = &fallback.upstreams[0];
        assert_eq!(fb_upstream.upstream, "fallback");
        assert!(!fb_upstream.skip_if_unhealthy); // default false
        assert!(fb_upstream.model_mapping.is_empty()); // default empty
    }

    #[test]
    fn test_parse_model_routing_config() {
        // Test model-based routing configuration
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

            upstreams {
                upstream "openai-gpt4" {
                    target "api.openai.com:443"
                }
                upstream "openai-primary" {
                    target "api.openai.com:443"
                }
                upstream "anthropic-backend" {
                    target "api.anthropic.com:443"
                }
                upstream "local-gpu" {
                    target "localhost:8000"
                }
            }

            routes {
                route "inference-api" {
                    matches {
                        path-prefix "/v1/chat/completions"
                    }
                    upstream "openai-primary"

                    inference {
                        provider "openai"

                        model-routing {
                            default-upstream "openai-primary"

                            model "gpt-4" upstream="openai-gpt4" provider="openai"
                            model "gpt-4*" upstream="openai-primary" provider="openai"
                            model "claude-*" upstream="anthropic-backend" provider="anthropic"
                            model "llama-*" upstream="local-gpu" provider="generic"
                        }
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).expect("Failed to parse model routing KDL");

        let route = config
            .routes
            .iter()
            .find(|r| r.id == "inference-api")
            .expect("Route not found");

        // Check inference config exists
        let inference = route.inference.as_ref().expect("Inference config not found");
        assert_eq!(inference.provider, crate::InferenceProvider::OpenAi);

        // Check model routing config
        let model_routing = inference
            .model_routing
            .as_ref()
            .expect("Model routing config not found");

        assert_eq!(
            model_routing.default_upstream,
            Some("openai-primary".to_string())
        );
        assert_eq!(model_routing.mappings.len(), 4);

        // Check first mapping (gpt-4 exact)
        let mapping = &model_routing.mappings[0];
        assert_eq!(mapping.model_pattern, "gpt-4");
        assert_eq!(mapping.upstream, "openai-gpt4");
        assert_eq!(mapping.provider, Some(crate::InferenceProvider::OpenAi));

        // Check glob pattern mapping (claude-*)
        let claude_mapping = model_routing
            .mappings
            .iter()
            .find(|m| m.model_pattern == "claude-*")
            .expect("Claude mapping not found");
        assert_eq!(claude_mapping.upstream, "anthropic-backend");
        assert_eq!(
            claude_mapping.provider,
            Some(crate::InferenceProvider::Anthropic)
        );

        // Check local GPU mapping
        let local_mapping = model_routing
            .mappings
            .iter()
            .find(|m| m.model_pattern == "llama-*")
            .expect("Local mapping not found");
        assert_eq!(local_mapping.upstream, "local-gpu");
        assert_eq!(
            local_mapping.provider,
            Some(crate::InferenceProvider::Generic)
        );
    }

    #[test]
    fn test_parse_model_routing_minimal() {
        // Test minimal model routing without provider override
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

            upstreams {
                upstream "default-backend" {
                    target "localhost:8000"
                }
                upstream "fast-backend" {
                    target "localhost:8001"
                }
            }

            routes {
                route "inference" {
                    matches {
                        path-prefix "/inference"
                    }
                    upstream "default-backend"

                    inference {
                        model-routing {
                            model "fast-model" upstream="fast-backend"
                        }
                    }
                }
            }
        "#;

        let config = Config::from_kdl(kdl).expect("Failed to parse minimal model routing KDL");

        let route = config
            .routes
            .iter()
            .find(|r| r.id == "inference")
            .expect("Route not found");

        let inference = route.inference.as_ref().expect("Inference config not found");
        let model_routing = inference
            .model_routing
            .as_ref()
            .expect("Model routing config not found");

        // No default upstream specified
        assert!(model_routing.default_upstream.is_none());

        // Single mapping without provider
        assert_eq!(model_routing.mappings.len(), 1);
        let mapping = &model_routing.mappings[0];
        assert_eq!(mapping.model_pattern, "fast-model");
        assert_eq!(mapping.upstream, "fast-backend");
        assert!(mapping.provider.is_none()); // No provider override
    }

    #[test]
    fn test_parse_waf_config_basic() {
        let kdl = r#"
        waf {
            engine "coraza"
            mode "prevention"
            audit-log #true
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let waf = parse_waf_config(waf_node).unwrap();

        assert!(matches!(waf.engine, crate::waf::WafEngine::Coraza));
        assert!(matches!(waf.mode, crate::waf::WafMode::Prevention));
        assert!(waf.audit_log);
    }

    #[test]
    fn test_parse_waf_config_with_ruleset() {
        let kdl = r#"
        waf {
            engine "mod_security"
            mode "detection"

            ruleset {
                crs-version "3.3.4"
                custom-rules-dir "/etc/sentinel/waf/rules"
                paranoia-level 2
                anomaly-threshold 10
            }
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let waf = parse_waf_config(waf_node).unwrap();

        assert!(matches!(waf.engine, crate::waf::WafEngine::ModSecurity));
        assert!(matches!(waf.mode, crate::waf::WafMode::Detection));
        assert_eq!(waf.ruleset.crs_version, "3.3.4");
        assert_eq!(
            waf.ruleset.custom_rules_dir,
            Some(std::path::PathBuf::from("/etc/sentinel/waf/rules"))
        );
        assert_eq!(waf.ruleset.paranoia_level, 2);
        assert_eq!(waf.ruleset.anomaly_threshold, 10);
    }

    #[test]
    fn test_parse_waf_config_with_body_inspection() {
        let kdl = r#"
        waf {
            engine "coraza"
            mode "prevention"

            body-inspection {
                inspect-request-body #true
                inspect-response-body #true
                max-inspection-bytes 2097152
                decompress #true
                max-decompression-ratio 50
            }
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let waf = parse_waf_config(waf_node).unwrap();

        assert!(waf.body_inspection.inspect_request_body);
        assert!(waf.body_inspection.inspect_response_body);
        assert_eq!(waf.body_inspection.max_inspection_bytes, 2097152);
        assert!(waf.body_inspection.decompress);
        assert_eq!(waf.body_inspection.max_decompression_ratio, 50.0);
    }

    #[test]
    fn test_parse_waf_config_invalid_paranoia_level() {
        let kdl = r#"
        waf {
            engine "coraza"
            ruleset {
                paranoia-level 5
            }
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let result = parse_waf_config(waf_node);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("paranoia level must be between 1 and 4"));
    }

    #[test]
    fn test_parse_waf_config_invalid_mode() {
        let kdl = r#"
        waf {
            engine "coraza"
            mode "invalid"
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let result = parse_waf_config(waf_node);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid WAF mode"));
    }

    #[test]
    fn test_parse_waf_config_custom_engine() {
        let kdl = r#"
        waf {
            engine "my-custom-waf"
            mode "prevention"
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let waf = parse_waf_config(waf_node).unwrap();

        assert!(matches!(waf.engine, crate::waf::WafEngine::Custom(ref name) if name == "my-custom-waf"));
    }

    #[test]
    fn test_parse_waf_config_defaults() {
        // Minimal WAF config using all defaults
        let kdl = r#"
        waf {
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let waf_node = doc.get("waf").unwrap();
        let waf = parse_waf_config(waf_node).unwrap();

        // Check defaults
        assert!(matches!(waf.engine, crate::waf::WafEngine::Coraza));
        assert!(matches!(waf.mode, crate::waf::WafMode::Prevention));
        assert!(waf.audit_log);
        assert_eq!(waf.ruleset.paranoia_level, 1);
        assert_eq!(waf.ruleset.anomaly_threshold, 5);
    }
}
