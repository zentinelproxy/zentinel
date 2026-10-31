//! Filter KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use tracing::{trace, warn};

use crate::filters::*;
use crate::routes::FailureMode;
use crate::FilterConfig;

use super::helpers::{get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry};

/// Parse top-level filter definitions block
pub fn parse_filter_definitions(node: &kdl::KdlNode) -> Result<HashMap<String, FilterConfig>> {
    trace!("Parsing filter definitions block");
    let mut filters = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "filter" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Filter requires an ID argument, e.g., filter \"my-rate-limit\" {{ ... }}"
                    )
                })?;

                trace!(filter_id = %id, "Parsing filter definition");

                let filter = parse_single_filter_definition(child)?;
                filters.insert(id.clone(), FilterConfig::new(id, filter));
            }
        }
    }

    trace!(
        filter_count = filters.len(),
        "Finished parsing filter definitions"
    );
    Ok(filters)
}

/// Parse a single filter definition
pub fn parse_single_filter_definition(node: &kdl::KdlNode) -> Result<Filter> {
    let filter_type = get_string_entry(node, "type").ok_or_else(|| {
        anyhow::anyhow!(
            "Filter definition requires a 'type' field. Valid types: rate-limit, agent, headers, compress, cors, timeout, log, geo"
        )
    })?;

    trace!(filter_type = %filter_type, "Parsing filter of type");

    match filter_type.as_str() {
        "rate-limit" => parse_rate_limit_filter(node),
        "agent" => parse_agent_filter(node),
        "headers" => parse_headers_filter(node),
        "compress" => parse_compress_filter(node),
        "cors" => Ok(Filter::Cors(CorsFilter::default())),
        "timeout" => parse_timeout_filter(node),
        "log" => parse_log_filter(node),
        "geo" => parse_geo_filter(node),
        "redirect" => parse_redirect_filter(node),
        "url-rewrite" => parse_url_rewrite_filter(node),
        other => Err(anyhow::anyhow!(
            "Unknown filter type: '{}'. Valid types: rate-limit, agent, headers, compress, cors, timeout, log, geo, redirect, url-rewrite",
            other
        )),
    }
}

/// Every setting a `filter` with `type "rate-limit"` reads.
///
/// Includes the backend settings, which `parse_rate_limit_backend` reads from
/// the same node rather than from a nested block. Both spellings of the two
/// aliased settings are listed, because both are accepted.
pub(crate) const RECOGNIZED_RATE_LIMIT_FILTER_KEYS: &[&str] = &[
    "type",
    "max-rps",
    "burst",
    "key",
    "on-limit",
    "status-code",
    "message",
    "max-delay-ms",
    "max-keys",
    // Backend selection and its settings.
    "backend",
    "redis-url",
    "redis-prefix",
    "redis-pool-size",
    "redis-timeout-ms",
    "redis-fallback",
    "redis-fallback-local",
    "memcached-url",
    "memcached-prefix",
    "memcached-pool-size",
    "memcached-timeout-ms",
    "memcached-ttl",
    "memcached-ttl-secs",
    "memcached-fallback",
    "memcached-fallback-local",
];

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
            "mcp-tool" => RateLimitKey::McpTool,
            "client-ip-and-mcp-tool" => RateLimitKey::ClientIpAndMcpTool,
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

    // Parse backend configuration
    let backend = parse_rate_limit_backend(node)?;

    Ok(Filter::RateLimit(RateLimitFilter {
        max_rps,
        burst,
        key,
        on_limit,
        status_code,
        limit_message: get_string_entry(node, "message"),
        backend,
        max_delay_ms: get_int_entry(node, "max-delay-ms")
            .map(|v| v as u64)
            .unwrap_or(5000),
        max_keys: get_int_entry(node, "max-keys")
            .map(|v| v as usize)
            .unwrap_or_else(crate::filters::default_max_keys),
    }))
}

/// Parse rate limit backend configuration
fn parse_rate_limit_backend(node: &kdl::KdlNode) -> Result<RateLimitBackend> {
    let backend_type = get_string_entry(node, "backend").unwrap_or_else(|| "local".to_string());

    match backend_type.as_str() {
        "local" => Ok(RateLimitBackend::Local),
        "redis" => {
            // Look for redis configuration node
            let redis_url = get_string_entry(node, "redis-url")
                .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
            let key_prefix = get_string_entry(node, "redis-prefix")
                .unwrap_or_else(|| "zentinel:ratelimit:".to_string());
            let pool_size = get_int_entry(node, "redis-pool-size")
                .map(|v| v as u32)
                .unwrap_or(10);
            let timeout_ms = get_int_entry(node, "redis-timeout-ms")
                .map(|v| v as u64)
                .unwrap_or(50);
            // Every config writes `redis-fallback-local`; this read only
            // `redis-fallback`. It looked correct because the default is also
            // true, so the discarded setting matched intent by coincidence —
            // until someone wrote `#false`, which was silently ignored.
            let fallback_local = get_bool_entry(node, "redis-fallback-local")
                .or_else(|| get_bool_entry(node, "redis-fallback"))
                .unwrap_or(true);

            Ok(RateLimitBackend::Redis(RedisBackendConfig {
                url: redis_url,
                key_prefix,
                pool_size,
                timeout_ms,
                fallback_local,
            }))
        }
        "memcached" | "memcache" => {
            // Look for memcached configuration
            let memcached_url = get_string_entry(node, "memcached-url")
                .unwrap_or_else(|| "memcache://127.0.0.1:11211".to_string());
            let key_prefix = get_string_entry(node, "memcached-prefix")
                .unwrap_or_else(|| "zentinel:ratelimit:".to_string());
            let pool_size = get_int_entry(node, "memcached-pool-size")
                .map(|v| v as u32)
                .unwrap_or(10);
            let timeout_ms = get_int_entry(node, "memcached-timeout-ms")
                .map(|v| v as u64)
                .unwrap_or(50);
            // Same mismatch as the Redis branch above, plus the TTL: configs
            // write `memcached-ttl-secs`, this read `memcached-ttl`, and the
            // default of 2 matched what the examples asked for.
            let fallback_local = get_bool_entry(node, "memcached-fallback-local")
                .or_else(|| get_bool_entry(node, "memcached-fallback"))
                .unwrap_or(true);
            let ttl_secs = get_int_entry(node, "memcached-ttl-secs")
                .or_else(|| get_int_entry(node, "memcached-ttl"))
                .map(|v| v as u32)
                .unwrap_or(2);

            Ok(RateLimitBackend::Memcached(MemcachedBackendConfig {
                url: memcached_url,
                key_prefix,
                pool_size,
                timeout_ms,
                fallback_local,
                ttl_secs,
            }))
        }
        other => Err(anyhow::anyhow!(
            "Unknown rate limit backend: '{}'. Valid backends: local, redis, memcached",
            other
        )),
    }
}

/// Read an agent filter's `failure-mode`, and whether its value was ignored.
///
/// Only `open` and `closed` are failure modes here. Anything else — including
/// `fail-open`, which the agent block accepts — has always been read as unset,
/// which hands the decision to the route's `policies { failure-mode }` and,
/// when that is unset too, to closed. Honouring such a value now could turn a
/// setup that has been failing closed into one that fails open, so the
/// fallback stays; the value is logged at load and reported by `zentinel lint`
/// through `validate::unknown_keys`.
pub(crate) fn resolve_agent_filter_failure_mode(
    node: &kdl::KdlNode,
    filter_id: &str,
) -> (Option<FailureMode>, Option<String>) {
    match get_string_entry(node, "failure-mode").as_deref() {
        None => (None, None),
        Some("open") => (Some(FailureMode::Open), None),
        Some("closed") => (Some(FailureMode::Closed), None),
        Some(other) => (
            None,
            Some(format!(
                "'failure-mode \"{}\"' on filter '{}' is not a failure mode (open, closed) and \
                 is being ignored; the route's policies failure-mode applies instead, and that \
                 defaults to closed.",
                other, filter_id
            )),
        ),
    }
}

/// Read an agent filter's `timeout-ms`, and whether its value was ignored.
///
/// The filter's timeout applies to the request-headers call, the same call
/// its `failure-mode` decides, and can only shorten the agent's own
/// `timeout-ms`: that value is also the agent connection pool's request
/// timeout, so a longer wait would be cut off underneath anyway. A value
/// that is not a positive number of milliseconds used to be read as a
/// timeout too (zero failed every call, a negative one wrapped to years);
/// it is now ignored and reported.
pub(crate) fn resolve_agent_filter_timeout(
    node: &kdl::KdlNode,
    filter_id: &str,
) -> (Option<u64>, Option<String>) {
    let Some(entry) = node
        .children()
        .and_then(|c| c.get("timeout-ms"))
        .and_then(|n| n.entries().first())
    else {
        return (None, None);
    };
    match entry.value().as_integer() {
        Some(v) if v > 0 => (Some(v.min(u64::MAX as i128) as u64), None),
        _ => (
            None,
            Some(format!(
                "'timeout-ms {}' on filter '{}' is not a positive number of milliseconds and is \
                 being ignored; the agent's own timeout-ms applies.",
                entry.value(),
                filter_id
            )),
        ),
    }
}

/// Read an agent filter's `inspect-body`, and whether its value was ignored.
///
/// `inspect-body #false` keeps request bodies from the filter's agent on the
/// routes using the filter. `#true` cannot make an agent receive bodies its
/// `events` do not ask for; that case is reported by `zentinel lint`, which
/// knows the agent. A value that is not a boolean used to be read as `false`
/// and nothing read it either way, so it is ignored and reported.
pub(crate) fn resolve_agent_filter_inspect_body(
    node: &kdl::KdlNode,
    filter_id: &str,
) -> (Option<bool>, Option<String>) {
    let Some(entry) = node
        .children()
        .and_then(|c| c.get("inspect-body"))
        .and_then(|n| n.entries().first())
    else {
        return (None, None);
    };
    match entry.value().as_bool() {
        Some(v) => (Some(v), None),
        None => (
            None,
            Some(format!(
                "'inspect-body {}' on filter '{}' is not #true or #false and is being ignored; \
                 the agent's own events decide whether it receives request bodies.",
                entry.value(),
                filter_id
            )),
        ),
    }
}

/// Read an agent filter's `max-body-bytes`, and whether its value was ignored.
///
/// The value narrows the agent's own `max-request-body-bytes` for the routes
/// using the filter: a larger request body is handled as for the agent's own
/// limit (skipped when the agent fails open, refused with 413 when it fails
/// closed). It cannot widen the agent's limit; `zentinel lint` reports a
/// larger value. A value that is not a positive number of bytes is ignored
/// and reported: `inspect-body #false` is the way to send no body at all.
pub(crate) fn resolve_agent_filter_max_body_bytes(
    node: &kdl::KdlNode,
    filter_id: &str,
) -> (Option<usize>, Option<String>) {
    let Some(entry) = node
        .children()
        .and_then(|c| c.get("max-body-bytes"))
        .and_then(|n| n.entries().first())
    else {
        return (None, None);
    };
    match entry.value().as_integer() {
        Some(v) if v > 0 => (Some(v.min(usize::MAX as i128) as usize), None),
        _ => (
            None,
            Some(format!(
                "'max-body-bytes {}' on filter '{}' is not a positive number of bytes and is \
                 being ignored; the agent's own max-request-body-bytes applies. Use \
                 'inspect-body #false' to send the agent no request body.",
                entry.value(),
                filter_id
            )),
        ),
    }
}

/// Whether an agent filter's `phase` is set, which nothing reads.
///
/// Which events an agent receives is decided by its own `events` list, and
/// every agent filter on a route calls its agent for each of those events.
/// Honouring `phase` would take events away from agents that asked for them:
/// `phase "response"` on a security agent would stop it seeing request
/// headers, so it would stop blocking requests without any other sign. The
/// value is kept in the model and reported instead.
pub(crate) fn agent_filter_phase_problem(node: &kdl::KdlNode, filter_id: &str) -> Option<String> {
    let value = node.children()?.get("phase")?.entries().first()?.value();
    let phase = match value.as_string() {
        Some(s) => format!("\"{s}\""),
        None => value.to_string(),
    };
    Some(format!(
        "'phase {}' on filter '{}' is being ignored: the events an agent receives are set by \
         the agent block's 'events' (request-headers, request-body, response-headers, \
         response-body, ...), not by the filter.",
        phase, filter_id
    ))
}

fn parse_agent_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let agent = get_string_entry(node, "agent").ok_or_else(|| {
        anyhow::anyhow!("Agent filter requires an 'agent' field referencing an agent definition")
    })?;

    let filter_id = get_first_arg_string(node).unwrap_or_default();
    let (timeout_ms, problem) = resolve_agent_filter_timeout(node, &filter_id);
    if let Some(problem) = problem {
        warn!("{}", problem);
    }
    if let Some(problem) = agent_filter_phase_problem(node, &filter_id) {
        warn!("{}", problem);
    }
    let (failure_mode, problem) = resolve_agent_filter_failure_mode(node, &filter_id);
    if let Some(problem) = problem {
        warn!("{}", problem);
    }
    let (inspect_body, problem) = resolve_agent_filter_inspect_body(node, &filter_id);
    if let Some(problem) = problem {
        warn!("{}", problem);
    }
    let (max_body_bytes, problem) = resolve_agent_filter_max_body_bytes(node, &filter_id);
    if let Some(problem) = problem {
        warn!("{}", problem);
    }

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
        inspect_body,
        max_body_bytes,
    }))
}

fn parse_headers_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let mut rename = HashMap::new();
    let mut set = HashMap::new();
    let mut add = HashMap::new();
    let mut remove = Vec::new();

    if let Some(node_children) = node.children() {
        if let Some(rename_node) = node_children.get("rename") {
            if let Some(rename_children) = rename_node.children() {
                for entry_node in rename_children.nodes() {
                    let old_name = entry_node.name().value().to_string();
                    if let Some(new_name) = get_first_arg_string(entry_node) {
                        rename.insert(old_name, new_name);
                    }
                }
            }
        }
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
        rename,
        set,
        add,
        remove,
    }))
}

/// Settings a `compress` filter reads; anything else is reported by `lint`.
pub(crate) const RECOGNIZED_COMPRESS_FILTER_KEYS: &[&str] =
    &["type", "algorithms", "min-size", "level", "content-types"];

/// Every string argument of the child `name`, each also split on commas.
///
/// Both `algorithms "gzip" "br"` (the documented form) and the older
/// `algorithms "gzip,br"` are accepted. Only the first argument used to be
/// read, so the documented form silently dropped all but one entry.
fn get_string_list(node: &kdl::KdlNode, name: &str) -> Option<Vec<String>> {
    let child = node.children()?.get(name)?;
    Some(
        child
            .entries()
            .iter()
            .filter(|e| e.name().is_none())
            .filter_map(|e| e.value().as_string())
            .flat_map(|s| s.split(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    )
}

fn parse_compression_algorithm(name: &str) -> Result<CompressionAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "gzip" => Ok(CompressionAlgorithm::Gzip),
        "br" | "brotli" => Ok(CompressionAlgorithm::Brotli),
        "zstd" => Ok(CompressionAlgorithm::Zstd),
        // Rejected by `CompressFilter::validate` with an explanation.
        "deflate" => Ok(CompressionAlgorithm::Deflate),
        other => Err(anyhow::anyhow!(
            "compress filter: unknown algorithm '{}'. Valid algorithms: gzip, br (or brotli), zstd",
            other
        )),
    }
}

fn parse_compress_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let algorithms = match get_string_list(node, "algorithms") {
        None => vec![CompressionAlgorithm::Gzip],
        Some(names) => {
            let mut algorithms = Vec::new();
            for name in names {
                let algorithm = parse_compression_algorithm(&name)?;
                if !algorithms.contains(&algorithm) {
                    algorithms.push(algorithm);
                }
            }
            algorithms
        }
    };

    let min_size = get_int_entry(node, "min-size")
        .map(|v| v as usize)
        .unwrap_or(1024);

    let content_types = get_string_list(node, "content-types").unwrap_or_else(|| {
        vec![
            "text/html".into(),
            "text/css".into(),
            "application/json".into(),
            "application/javascript".into(),
        ]
    });

    let level = match get_int_entry(node, "level") {
        None => 6,
        // Out-of-range values are kept out of range so that validation
        // reports them instead of a wrapped `u8`.
        Some(v) => u8::try_from(v).unwrap_or(u8::MAX),
    };

    Ok(Filter::Compress(CompressFilter {
        algorithms,
        min_size,
        content_types,
        level,
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

fn parse_geo_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let database_path = get_string_entry(node, "database-path").ok_or_else(|| {
        anyhow::anyhow!("Geo filter requires 'database-path' pointing to a GeoIP database file")
    })?;

    // Auto-detect database type from file extension if not specified
    let database_type = get_string_entry(node, "database-type")
        .and_then(|s| match s.as_str() {
            "maxmind" => Some(GeoDatabaseType::MaxMind),
            "ip2location" => Some(GeoDatabaseType::Ip2Location),
            _ => None,
        })
        .or_else(|| {
            if database_path.ends_with(".mmdb") {
                Some(GeoDatabaseType::MaxMind)
            } else if database_path.ends_with(".bin") || database_path.ends_with(".BIN") {
                Some(GeoDatabaseType::Ip2Location)
            } else {
                None
            }
        });

    let action = get_string_entry(node, "action")
        .map(|s| match s.as_str() {
            "block" => GeoFilterAction::Block,
            "allow" => GeoFilterAction::Allow,
            "log-only" => GeoFilterAction::LogOnly,
            _ => GeoFilterAction::Block,
        })
        .unwrap_or_default();

    // Parse countries - comma-separated list of ISO 3166-1 alpha-2 codes
    let countries = get_string_entry(node, "countries")
        .map(|s| {
            s.split(',')
                .map(|c| c.trim().to_uppercase())
                .filter(|c| !c.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let on_failure = get_string_entry(node, "on-failure")
        .map(|s| match s.as_str() {
            "open" => GeoFailureMode::Open,
            "closed" => GeoFailureMode::Closed,
            _ => GeoFailureMode::Open,
        })
        .unwrap_or_default();

    let status_code = get_int_entry(node, "status-code")
        .map(|v| v as u16)
        .unwrap_or(403);

    let block_message = get_string_entry(node, "block-message");

    let cache_ttl_secs = get_int_entry(node, "cache-ttl-secs")
        .map(|v| v as u64)
        .unwrap_or(3600);

    let add_country_header = get_bool_entry(node, "add-country-header").unwrap_or(true);

    Ok(Filter::Geo(GeoFilter {
        database_path,
        database_type,
        action,
        countries,
        on_failure,
        status_code,
        block_message,
        cache_ttl_secs,
        add_country_header,
    }))
}

fn parse_redirect_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let status_code = get_int_entry(node, "status-code")
        .map(|v| v as u16)
        .unwrap_or(302);
    let hostname = get_string_entry(node, "hostname");
    let scheme = get_string_entry(node, "scheme");
    let port = get_int_entry(node, "port").map(|v| v as u16);
    let path = parse_path_modifier(node);

    Ok(Filter::Redirect(RedirectFilter {
        hostname,
        status_code,
        scheme,
        port,
        path,
    }))
}

fn parse_url_rewrite_filter(node: &kdl::KdlNode) -> Result<Filter> {
    let hostname = get_string_entry(node, "hostname");
    let path = parse_path_modifier(node);

    Ok(Filter::UrlRewrite(UrlRewriteFilter { hostname, path }))
}

fn parse_path_modifier(node: &kdl::KdlNode) -> Option<PathModifier> {
    if let Some(full) = get_string_entry(node, "replace-full-path") {
        Some(PathModifier::ReplaceFullPath { value: full })
    } else {
        get_string_entry(node, "replace-prefix-match")
            .map(|prefix| PathModifier::ReplacePrefixMatch { value: prefix })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distributed backends read `redis-fallback` / `memcached-fallback` /
    /// `memcached-ttl`, while every config writes the longer names. Because the
    /// defaults matched what the examples asked for, the mismatch was invisible
    /// until someone set a value that differed.
    mod backend_key_names {
        use super::*;

        fn backend(body: &str) -> RateLimitBackend {
            let kdl =
                format!("filter \"rl\" {{\n  type \"rate-limit\"\n  max-rps 100\n{body}\n}}\n");
            let doc: kdl::KdlDocument = kdl.parse().expect("kdl parses");
            match parse_single_filter_definition(doc.nodes().first().expect("filter node"))
                .expect("parses")
            {
                Filter::RateLimit(f) => f.backend,
                other => panic!("expected a rate limit filter, got {other:?}"),
            }
        }

        fn redis(extra: &str) -> RedisBackendConfig {
            match backend(&format!(
                "  backend \"redis\"\n  redis-url \"redis://localhost:6379\"\n  {extra}"
            )) {
                RateLimitBackend::Redis(c) => c,
                other => panic!("expected redis backend, got {other:?}"),
            }
        }

        fn memcached(extra: &str) -> MemcachedBackendConfig {
            match backend(&format!(
                "  backend \"memcached\"\n  memcached-url \"memcache://localhost:11211\"\n  {extra}"
            )) {
                RateLimitBackend::Memcached(c) => c,
                other => panic!("expected memcached backend, got {other:?}"),
            }
        }

        /// The name every config uses. `#false` is the value that mattered:
        /// with it discarded, a Redis outage silently fell back to local
        /// counting, so each instance limited independently.
        #[test]
        fn redis_fallback_local_is_read() {
            assert!(!redis("redis-fallback-local #false").fallback_local);
            assert!(redis("redis-fallback-local #true").fallback_local);
        }

        #[test]
        fn redis_fallback_alias_still_works() {
            assert!(!redis("redis-fallback #false").fallback_local);
        }

        #[test]
        fn redis_fallback_defaults_to_true() {
            assert!(redis("redis-prefix \"x:\"").fallback_local);
        }

        #[test]
        fn memcached_fallback_local_is_read() {
            assert!(!memcached("memcached-fallback-local #false").fallback_local);
        }

        #[test]
        fn memcached_fallback_alias_still_works() {
            assert!(!memcached("memcached-fallback #false").fallback_local);
        }

        #[test]
        fn memcached_ttl_secs_is_read() {
            assert_eq!(memcached("memcached-ttl-secs 99").ttl_secs, 99);
        }

        #[test]
        fn memcached_ttl_alias_still_works() {
            assert_eq!(memcached("memcached-ttl 99").ttl_secs, 99);
        }

        #[test]
        fn the_documented_name_wins_when_both_are_present() {
            assert!(!redis("redis-fallback-local #false\n  redis-fallback #true").fallback_local);
            assert_eq!(
                memcached("memcached-ttl-secs 99\n  memcached-ttl 5").ttl_secs,
                99
            );
        }
    }

    fn parse_filter(kdl: &str) -> Filter {
        let doc: kdl::KdlDocument = kdl.parse().expect("kdl parses");
        let node = doc.nodes().first().expect("one node");
        parse_single_filter_definition(node).expect("filter parses")
    }

    /// An unrecognised failure mode keeps meaning "unset", which defers to
    /// the route and then to closed; honouring `fail-open` would turn a setup
    /// that has been failing closed into one that fails open (#529).
    #[test]
    fn an_unknown_agent_filter_failure_mode_stays_unset() {
        for (value, expected) in [
            ("open", Some(FailureMode::Open)),
            ("closed", Some(FailureMode::Closed)),
            ("fail-open", None),
        ] {
            let filter = parse_filter(&format!(
                "filter \"f\" {{\n type \"agent\"\n agent \"a\"\n failure-mode \"{value}\"\n}}"
            ));
            let Filter::Agent(agent) = filter else {
                panic!("expected an agent filter");
            };
            assert_eq!(agent.failure_mode, expected, "{value}");
        }
    }

    #[test]
    fn rate_limit_filter_parses_max_keys() {
        let filter = parse_filter(
            r#"filter "rl" {
    type "rate-limit"
    max-rps 50
    max-keys 5000
}"#,
        );
        match filter {
            Filter::RateLimit(rl) => {
                assert_eq!(rl.max_rps, 50);
                assert_eq!(rl.max_keys, 5000);
            }
            other => panic!("expected rate-limit filter, got {other:?}"),
        }
    }

    #[test]
    fn rate_limit_filter_defaults_max_keys() {
        let filter = parse_filter(
            r#"filter "rl" {
    type "rate-limit"
    max-rps 50
}"#,
        );
        match filter {
            Filter::RateLimit(rl) => {
                assert_eq!(rl.max_keys, crate::filters::default_max_keys());
            }
            other => panic!("expected rate-limit filter, got {other:?}"),
        }
    }

    /// #591: the compress filter's settings are read back as written.
    mod compress {
        use super::*;

        fn compress(body: &str) -> Result<CompressFilter> {
            let kdl = format!("filter \"c\" {{\n  type \"compress\"\n{body}\n}}\n");
            let doc: kdl::KdlDocument = kdl.parse().expect("kdl parses");
            match parse_single_filter_definition(doc.nodes().first().expect("filter node"))? {
                Filter::Compress(c) => Ok(c),
                other => panic!("expected a compress filter, got {other:?}"),
            }
        }

        fn config_with(body: &str) -> crate::Config {
            let kdl = format!(
                r#"
                schema-version "1.0"
                system {{ worker-threads 0 }}
                listeners {{ listener "http" {{ address "127.0.0.1:8080" }} }}
                filters {{
                    filter "c" {{
                        type "compress"
                        {body}
                    }}
                }}
                routes {{
                    route "r" {{
                        matches {{ path-prefix "/" }}
                        upstream "backend"
                        filters "c"
                    }}
                }}
                upstreams {{ upstream "backend" {{ target "127.0.0.1:3000" }} }}
                "#
            );
            crate::Config::from_kdl(&kdl).expect("config parses")
        }

        use CompressionAlgorithm::{Brotli, Gzip, Zstd};

        #[test]
        fn documented_multi_argument_form_keeps_every_algorithm() {
            // Only the first argument used to be read: this came back as [Brotli].
            let c = compress(r#"algorithms "brotli" "gzip" "zstd""#).unwrap();
            assert_eq!(c.algorithms, vec![Brotli, Gzip, Zstd]);
        }

        #[test]
        fn comma_separated_form_still_works() {
            let c = compress(r#"algorithms "zstd,br""#).unwrap();
            assert_eq!(c.algorithms, vec![Zstd, Brotli]);
        }

        #[test]
        fn default_is_gzip() {
            let c = compress("").unwrap();
            assert_eq!(c.algorithms, vec![Gzip]);
            assert_eq!(c.algorithms, CompressFilter::default().algorithms);
            assert_eq!(c.level, 6);
            assert_eq!(c.min_size, 1024);
        }

        #[test]
        fn unknown_algorithm_is_an_error() {
            // Used to be dropped silently.
            let err = compress(r#"algorithms "gzip" "lzma""#).unwrap_err();
            assert!(err.to_string().contains("lzma"), "{err}");
        }

        #[test]
        fn content_types_and_level_are_read() {
            // content-types used to be replaced by a fixed list.
            let c = compress(
                r#"content-types "text/plain" "application/xml"
                   level 3
                   min-size 10"#,
            )
            .unwrap();
            assert_eq!(c.content_types, vec!["text/plain", "application/xml"]);
            assert_eq!(c.level, 3);
            assert_eq!(c.min_size, 10);
        }

        #[test]
        fn deflate_is_rejected_at_load() {
            let config = config_with(r#"algorithms "gzip" "deflate""#);
            let err = config.validate().expect_err("deflate must not load");
            assert!(err.to_string().contains("deflate"), "{err}");
        }

        #[test]
        fn out_of_range_level_is_rejected_at_load() {
            for level in ["0", "10", "300"] {
                let config = config_with(&format!("level {level}"));
                assert!(config.validate().is_err(), "level {level} must not load");
            }
        }

        #[test]
        fn supported_algorithms_load() {
            let config = config_with(r#"algorithms "zstd" "br" "gzip""#);
            config.validate().expect("supported algorithms load");
        }
    }
}
