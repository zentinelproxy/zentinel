//! Filter KDL parsing.

use anyhow::Result;
use std::collections::HashMap;

use crate::filters::*;
use crate::routes::FailureMode;
use crate::FilterConfig;

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

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
