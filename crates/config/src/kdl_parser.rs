//! KDL configuration parsing
//!
//! This module contains all functions for parsing KDL configuration files
//! into Sentinel configuration structures.

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

use sentinel_common::limits::Limits;
use sentinel_common::types::LoadBalancingAlgorithm;

use crate::filters::*;
use crate::observability::ObservabilityConfig;
use crate::routes::*;
use crate::server::*;
use crate::upstreams::*;
use crate::waf::WafConfig;
use crate::{AgentConfig, Config, FilterConfig};

// ============================================================================
// KDL Parsing Helpers
// ============================================================================

/// Convert a byte offset to line and column numbers (1-indexed)
pub fn offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in content.chars().enumerate() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Helper to get a string entry from a KDL node
pub fn get_string_entry(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Helper to get an integer entry from a KDL node
pub fn get_int_entry(node: &kdl::KdlNode, name: &str) -> Option<i128> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer())
}

/// Helper to get a boolean entry from a KDL node
pub fn get_bool_entry(node: &kdl::KdlNode, name: &str) -> Option<bool> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool())
}

/// Helper to get the first argument of a node as a string
pub fn get_first_arg_string(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

// ============================================================================
// Top-Level Document Parser
// ============================================================================

/// Convert a parsed KDL document to Config
pub fn parse_kdl_document(doc: kdl::KdlDocument) -> Result<Config> {
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
        match node.name().value() {
            "server" => {
                server = Some(parse_server_config(node)?);
            }
            "listeners" => {
                listeners = parse_listeners(node)?;
            }
            "routes" => {
                routes = parse_routes(node)?;
            }
            "upstreams" => {
                upstreams = parse_upstreams(node)?;
            }
            "filters" => {
                filters = parse_filter_definitions(node)?;
            }
            "agents" => {
                agents = parse_agents(node)?;
            }
            "waf" => {
                waf = Some(parse_waf_config(node)?);
            }
            "limits" => {
                limits = Some(parse_limits_config(node)?);
            }
            "observability" => {
                observability = Some(parse_observability_config(node)?);
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
// Server Parsing
// ============================================================================

/// Parse server configuration block
pub fn parse_server_config(node: &kdl::KdlNode) -> Result<ServerConfig> {
    Ok(ServerConfig {
        worker_threads: get_int_entry(node, "worker-threads")
            .map(|v| v as usize)
            .unwrap_or_else(default_worker_threads),
        max_connections: get_int_entry(node, "max-connections")
            .map(|v| v as usize)
            .unwrap_or_else(default_max_connections),
        graceful_shutdown_timeout_secs: get_int_entry(node, "graceful-shutdown-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or_else(default_graceful_shutdown_timeout),
        daemon: get_bool_entry(node, "daemon").unwrap_or(false),
        pid_file: get_string_entry(node, "pid-file").map(PathBuf::from),
        user: get_string_entry(node, "user"),
        group: get_string_entry(node, "group"),
        working_directory: get_string_entry(node, "working-directory").map(PathBuf::from),
    })
}

// ============================================================================
// Listener Parsing
// ============================================================================

/// Parse listeners configuration block
pub fn parse_listeners(node: &kdl::KdlNode) -> Result<Vec<ListenerConfig>> {
    let mut listeners = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "listener" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener requires an ID argument, e.g., listener \"http\" {{ ... }}"
                    )
                })?;

                let address = get_string_entry(child, "address").ok_or_else(|| {
                    anyhow::anyhow!(
                        "Listener '{}' requires an 'address' field, e.g., address \"0.0.0.0:8080\"",
                        id
                    )
                })?;

                let protocol_str =
                    get_string_entry(child, "protocol").unwrap_or_else(|| "http".to_string());
                let protocol = match protocol_str.to_lowercase().as_str() {
                    "http" => ListenerProtocol::Http,
                    "https" => ListenerProtocol::Https,
                    "h2" => ListenerProtocol::Http2,
                    "h3" => ListenerProtocol::Http3,
                    other => {
                        return Err(anyhow::anyhow!(
                            "Invalid protocol '{}' for listener '{}'. Valid protocols: http, https, h2, h3",
                            other,
                            id
                        ));
                    }
                };

                listeners.push(ListenerConfig {
                    id,
                    address,
                    protocol,
                    tls: None, // TODO: Parse TLS config
                    default_route: get_string_entry(child, "default-route"),
                    request_timeout_secs: get_int_entry(child, "request-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_request_timeout),
                    keepalive_timeout_secs: get_int_entry(child, "keepalive-timeout-secs")
                        .map(|v| v as u64)
                        .unwrap_or_else(default_keepalive_timeout),
                    max_concurrent_streams: get_int_entry(child, "max-concurrent-streams")
                        .map(|v| v as u32)
                        .unwrap_or_else(default_max_concurrent_streams),
                });
            }
        }
    }

    Ok(listeners)
}

// ============================================================================
// Route Parsing
// ============================================================================

/// Parse routes configuration block
pub fn parse_routes(node: &kdl::KdlNode) -> Result<Vec<RouteConfig>> {
    let mut routes = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "route" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!("Route requires an ID argument, e.g., route \"api\" {{ ... }}")
                })?;

                // Parse matches
                let matches = parse_match_conditions(child)?;

                // Parse priority
                let priority = parse_priority(child);

                // Parse upstream
                let upstream = parse_upstream_ref(child);

                // Parse static-files
                let static_files = parse_static_file_config_opt(child)?;

                // Parse filters
                let filters = parse_route_filter_refs(child)?;

                // Parse builtin-handler
                let builtin_handler = get_string_entry(child, "builtin-handler").and_then(|s| {
                    match s.as_str() {
                        "status" => Some(BuiltinHandler::Status),
                        "health" => Some(BuiltinHandler::Health),
                        "metrics" => Some(BuiltinHandler::Metrics),
                        "not-found" | "not_found" => Some(BuiltinHandler::NotFound),
                        _ => None,
                    }
                });

                // Determine service type
                let service_type = if static_files.is_some() {
                    ServiceType::Static
                } else if builtin_handler.is_some() {
                    ServiceType::Builtin
                } else {
                    ServiceType::Web
                };

                routes.push(RouteConfig {
                    id,
                    priority,
                    matches,
                    upstream,
                    service_type,
                    policies: RoutePolicies::default(),
                    filters,
                    builtin_handler,
                    waf_enabled: get_bool_entry(child, "waf-enabled").unwrap_or(false),
                    circuit_breaker: None,
                    retry_policy: None,
                    static_files,
                    api_schema: None,
                    error_pages: None,
                });
            }
        }
    }

    Ok(routes)
}

fn parse_match_conditions(node: &kdl::KdlNode) -> Result<Vec<MatchCondition>> {
    let mut matches = Vec::new();

    if let Some(route_children) = node.children() {
        if let Some(matches_node) = route_children.get("matches") {
            if let Some(match_children) = matches_node.children() {
                for match_node in match_children.nodes() {
                    match match_node.name().value() {
                        "path-prefix" => {
                            if let Some(prefix) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::PathPrefix(prefix));
                            }
                        }
                        "path" => {
                            if let Some(path) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::Path(path));
                            }
                        }
                        "host" => {
                            if let Some(host) = get_first_arg_string(match_node) {
                                matches.push(MatchCondition::Host(host));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(matches)
}

fn parse_priority(node: &kdl::KdlNode) -> sentinel_common::types::Priority {
    match get_string_entry(node, "priority").as_deref() {
        Some("high") => sentinel_common::types::Priority::High,
        Some("low") => sentinel_common::types::Priority::Low,
        _ => sentinel_common::types::Priority::Normal,
    }
}

fn parse_upstream_ref(node: &kdl::KdlNode) -> Option<String> {
    if let Some(route_children) = node.children() {
        if let Some(upstream_node) = route_children.get("upstream") {
            let entry = upstream_node.entries().first();
            if let Some(s) = entry.and_then(|e| e.value().as_string()) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn parse_static_file_config_opt(node: &kdl::KdlNode) -> Result<Option<StaticFileConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(static_node) = route_children.get("static-files") {
            return Ok(Some(parse_static_file_config(static_node)?));
        }
    }
    Ok(None)
}

fn parse_route_filter_refs(node: &kdl::KdlNode) -> Result<Vec<String>> {
    let mut filter_ids = Vec::new();

    if let Some(route_children) = node.children() {
        if let Some(filters_node) = route_children.get("filters") {
            for entry in filters_node.entries() {
                if let Some(id) = entry.value().as_string() {
                    filter_ids.push(id.to_string());
                }
            }
        }
    }

    Ok(filter_ids)
}

/// Parse static file configuration block
pub fn parse_static_file_config(node: &kdl::KdlNode) -> Result<StaticFileConfig> {
    let root = get_string_entry(node, "root").ok_or_else(|| {
        anyhow::anyhow!(
            "Static files configuration requires a 'root' directory, e.g., root \"/var/www/html\""
        )
    })?;

    Ok(StaticFileConfig {
        root: PathBuf::from(root),
        index: get_string_entry(node, "index").unwrap_or_else(|| "index.html".to_string()),
        directory_listing: get_bool_entry(node, "directory-listing").unwrap_or(false),
        cache_control: get_string_entry(node, "cache-control")
            .unwrap_or_else(|| "public, max-age=3600".to_string()),
        compress: get_bool_entry(node, "compress").unwrap_or(true),
        mime_types: HashMap::new(),
        fallback: get_string_entry(node, "fallback"),
    })
}

// ============================================================================
// Upstream Parsing
// ============================================================================

/// Parse upstreams configuration block
pub fn parse_upstreams(node: &kdl::KdlNode) -> Result<HashMap<String, UpstreamConfig>> {
    let mut upstreams = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "upstream" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Upstream requires an ID argument, e.g., upstream \"backend\" {{ ... }}"
                    )
                })?;

                // Parse targets
                let mut targets = Vec::new();
                if let Some(upstream_children) = child.children() {
                    for target_node in upstream_children.nodes() {
                        if target_node.name().value() == "target" {
                            if let Some(address) = get_first_arg_string(target_node) {
                                let weight = target_node
                                    .entries()
                                    .iter()
                                    .find(|e| e.name().map(|n| n.value()) == Some("weight"))
                                    .and_then(|e| e.value().as_integer())
                                    .map(|v| v as u32)
                                    .unwrap_or(1);

                                targets.push(UpstreamTarget {
                                    address,
                                    weight,
                                    max_requests: None,
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }

                if targets.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Upstream '{}' requires at least one target, e.g., target \"127.0.0.1:8081\"",
                        id
                    ));
                }

                upstreams.insert(
                    id.clone(),
                    UpstreamConfig {
                        id,
                        targets,
                        load_balancing: LoadBalancingAlgorithm::RoundRobin,
                        health_check: None,
                        connection_pool: ConnectionPoolConfig::default(),
                        timeouts: UpstreamTimeouts::default(),
                        tls: None,
                    },
                );
            }
        }
    }

    Ok(upstreams)
}

// ============================================================================
// Filter Parsing
// ============================================================================

/// Parse top-level filter definitions block
pub fn parse_filter_definitions(node: &kdl::KdlNode) -> Result<HashMap<String, FilterConfig>> {
    let mut filters = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "filter" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Filter requires an ID argument, e.g., filter \"my-rate-limit\" {{ ... }}"
                    )
                })?;

                let filter = parse_single_filter_definition(child)?;
                filters.insert(id.clone(), FilterConfig::new(id, filter));
            }
        }
    }

    Ok(filters)
}

/// Parse a single filter definition
pub fn parse_single_filter_definition(node: &kdl::KdlNode) -> Result<Filter> {
    let filter_type = get_string_entry(node, "type").ok_or_else(|| {
        anyhow::anyhow!(
            "Filter definition requires a 'type' field. Valid types: rate-limit, agent, headers, compress, cors, timeout, log"
        )
    })?;

    match filter_type.as_str() {
        "rate-limit" => parse_rate_limit_filter(node),
        "agent" => parse_agent_filter(node),
        "headers" => parse_headers_filter(node),
        "compress" => parse_compress_filter(node),
        "cors" => Ok(Filter::Cors(CorsFilter::default())),
        "timeout" => parse_timeout_filter(node),
        "log" => parse_log_filter(node),
        other => Err(anyhow::anyhow!(
            "Unknown filter type: '{}'. Valid types: rate-limit, agent, headers, compress, cors, timeout, log",
            other
        )),
    }
}

fn parse_rate_limit_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let max_rps = get_int_entry(node, "max-rps")
        .map(|v| v as u32)
        .unwrap_or(100);
    let burst = get_int_entry(node, "burst").map(|v| v as u32).unwrap_or(10);
    let status_code = get_int_entry(node, "status-code")
        .map(|v| v as u16)
        .unwrap_or(429);

    let key = get_string_entry(node, "key")
        .map(|s| match s.as_str() {
            "client-ip" => RateLimitKey::ClientIp,
            "path" => RateLimitKey::Path,
            "route" => RateLimitKey::Route,
            "client-ip-and-path" => RateLimitKey::ClientIpAndPath,
            header if header.starts_with("header:") => {
                RateLimitKey::Header(header.trim_start_matches("header:").to_string())
            }
            _ => RateLimitKey::ClientIp,
        })
        .unwrap_or(RateLimitKey::ClientIp);

    let on_limit = get_string_entry(node, "on-limit")
        .map(|s| match s.as_str() {
            "reject" => RateLimitAction::Reject,
            "delay" => RateLimitAction::Delay,
            "log-only" => RateLimitAction::LogOnly,
            _ => RateLimitAction::Reject,
        })
        .unwrap_or(RateLimitAction::Reject);

    Ok(Filter::RateLimit(RateLimitFilter {
        max_rps,
        burst,
        key,
        on_limit,
        status_code,
        limit_message: get_string_entry(node, "message"),
    }))
}

fn parse_agent_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let agent = get_string_entry(node, "agent").ok_or_else(|| {
        anyhow::anyhow!("Agent filter requires an 'agent' field referencing an agent definition")
    })?;

    let timeout_ms = get_int_entry(node, "timeout-ms").map(|v| v as u64);
    let failure_mode = get_string_entry(node, "failure-mode").and_then(|s| match s.as_str() {
        "open" => Some(FailureMode::Open),
        "closed" => Some(FailureMode::Closed),
        _ => None,
    });

    let phase = get_string_entry(node, "phase").and_then(|s| match s.as_str() {
        "request" => Some(FilterPhase::Request),
        "response" => Some(FilterPhase::Response),
        "both" => Some(FilterPhase::Both),
        _ => None,
    });

    Ok(Filter::Agent(AgentFilter {
        agent,
        phase,
        timeout_ms,
        failure_mode,
        inspect_body: get_bool_entry(node, "inspect-body").unwrap_or(false),
        max_body_bytes: get_int_entry(node, "max-body-bytes").map(|v| v as usize),
    }))
}

fn parse_headers_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let mut set = HashMap::new();
    let mut add = HashMap::new();
    let mut remove = Vec::new();

    if let Some(node_children) = node.children() {
        if let Some(set_node) = node_children.get("set") {
            if let Some(set_children) = set_node.children() {
                for entry_node in set_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        set.insert(name, value);
                    }
                }
            }
        }
        if let Some(add_node) = node_children.get("add") {
            if let Some(add_children) = add_node.children() {
                for entry_node in add_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        add.insert(name, value);
                    }
                }
            }
        }
        if let Some(remove_node) = node_children.get("remove") {
            for entry in remove_node.entries() {
                if let Some(name) = entry.value().as_string() {
                    remove.push(name.to_string());
                }
            }
        }
    }

    let phase = get_string_entry(node, "phase")
        .and_then(|s| match s.as_str() {
            "request" => Some(FilterPhase::Request),
            "response" => Some(FilterPhase::Response),
            "both" => Some(FilterPhase::Both),
            _ => None,
        })
        .unwrap_or(FilterPhase::Request);

    Ok(Filter::Headers(HeadersFilter {
        phase,
        set,
        add,
        remove,
    }))
}

fn parse_compress_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let algorithms_str =
        get_string_entry(node, "algorithms").unwrap_or_else(|| "gzip,br".to_string());
    let algorithms: Vec<CompressionAlgorithm> = algorithms_str
        .split(',')
        .filter_map(|s| match s.trim() {
            "gzip" => Some(CompressionAlgorithm::Gzip),
            "br" | "brotli" => Some(CompressionAlgorithm::Brotli),
            "deflate" => Some(CompressionAlgorithm::Deflate),
            "zstd" => Some(CompressionAlgorithm::Zstd),
            _ => None,
        })
        .collect();

    let min_size = get_int_entry(node, "min-size")
        .map(|v| v as usize)
        .unwrap_or(1024);

    Ok(Filter::Compress(CompressFilter {
        algorithms,
        min_size,
        content_types: vec![
            "text/html".into(),
            "text/css".into(),
            "application/json".into(),
            "application/javascript".into(),
        ],
        level: get_int_entry(node, "level").map(|v| v as u8).unwrap_or(6),
    }))
}

fn parse_timeout_filter(node: &kdl::KdlNode) -> Result<Filter> {
    Ok(Filter::Timeout(TimeoutFilter {
        request_timeout_secs: get_int_entry(node, "request-timeout-secs").map(|v| v as u64),
        upstream_timeout_secs: get_int_entry(node, "upstream-timeout-secs").map(|v| v as u64),
        connect_timeout_secs: get_int_entry(node, "connect-timeout-secs").map(|v| v as u64),
    }))
}

fn parse_log_filter(node: &kdl::KdlNode) -> Result<Filter> {
    Ok(Filter::Log(LogFilter {
        log_request: get_bool_entry(node, "log-request").unwrap_or(true),
        log_response: get_bool_entry(node, "log-response").unwrap_or(true),
        log_body: get_bool_entry(node, "log-body").unwrap_or(false),
        max_body_log_size: get_int_entry(node, "max-body-log-size")
            .map(|v| v as usize)
            .unwrap_or(4096),
        fields: vec![],
        level: get_string_entry(node, "level").unwrap_or_else(|| "info".to_string()),
    }))
}

// ============================================================================
// Agent Parsing
// ============================================================================

/// Parse agents configuration block
pub fn parse_agents(_node: &kdl::KdlNode) -> Result<Vec<AgentConfig>> {
    // TODO: Implement full agent parsing
    Ok(vec![])
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
pub fn parse_observability_config(_node: &kdl::KdlNode) -> Result<ObservabilityConfig> {
    // TODO: Implement full observability config parsing
    Ok(ObservabilityConfig::default())
}
