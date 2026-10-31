//! Upstream KDL parsing.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{trace, warn};

use zentinel_common::types::{HealthCheckType, LoadBalancingAlgorithm};

use crate::{kdl::circuitbreaker_helper::parse_circuit_breaker_faildefault, upstreams::*};

use super::helpers::{
    get_bool_entry, get_first_arg_string, get_int_entry, get_string_entry, parse_upstream_targets,
};

//Parse a single upstream block
/// Every child node `parse_upstream` reads.
///
/// `address` is the easy one to miss: it is the single-target shorthand
/// (`upstream "x" { address "127.0.0.1:8081" }`), handled inside
/// `parse_upstream_targets` rather than here, so it does not appear anywhere in
/// this function's body.
///
/// Kept beside the parser for the same reason as the other recognised-key
/// lists: the unknown-key lint reads it, and under-listing produces false
/// warnings on valid configs.
pub(crate) const RECOGNIZED_UPSTREAM_KEYS: &[&str] = &[
    "target",
    "targets",
    // Single-target shorthand; see `parse_upstream_targets`.
    "address",
    "load-balancing",
    "health-check",
    "http-version",
    "h2c",
    "connection-pool",
    "timeouts",
    "tls",
    "circuit-breaker",
    "discovery",
];

/// Settings accepted inside `discovery "<kind>" { ... }`.
///
/// This is the union across every discovery backend rather than a per-kind
/// list, because the lint matches on the block name and not on its argument.
/// A key that belongs to a different backend than the one named is caught by
/// `parse_discovery`, which rejects it with the kind in the message.
pub(crate) const RECOGNIZED_DISCOVERY_KEYS: &[&str] = &[
    "backends",
    "hostname",
    "port",
    "service",
    "refresh-interval",
    "address",
    "datacenter",
    "only-passing",
    "tag",
    "namespace",
    "port-name",
    "kubeconfig",
    "path",
    "watch-interval",
];

/// Every child node `parse_health_check` reads directly.
///
/// The type-specific settings are *not* here: they are children of the `type`
/// node itself (`type "http" { path "/health" }`), so this list is fixed rather
/// than varying with the check type.
pub(crate) const RECOGNIZED_HEALTH_CHECK_KEYS: &[&str] = &[
    "type",
    "interval-secs",
    "timeout-secs",
    "healthy-threshold",
    "unhealthy-threshold",
];

/// Settings accepted inside `type "http" { ... }`.
pub(crate) const RECOGNIZED_HTTP_CHECK_KEYS: &[&str] = &["path", "expected-status", "host"];

/// Settings accepted inside `type "grpc" { ... }`.
pub(crate) const RECOGNIZED_GRPC_CHECK_KEYS: &[&str] = &["service"];

/// Settings accepted inside `type "inference" { ... }`.
pub(crate) const RECOGNIZED_INFERENCE_CHECK_KEYS: &[&str] =
    &["endpoint", "expected-models", "readiness"];

/// `type "tcp"` takes no settings; the parser reads none and treats every
/// unrecognised type as TCP.
pub(crate) const RECOGNIZED_TCP_CHECK_KEYS: &[&str] = &[];

/// Settings accepted inside `type "mcp" { ... }`.
pub(crate) const RECOGNIZED_MCP_CHECK_KEYS: &[&str] = &["path", "expected-tools"];

/// Sub-blocks accepted inside a `readiness` block.
///
/// `readiness` holds nothing but these four; it has no settings of its own.
pub(crate) const RECOGNIZED_READINESS_KEYS: &[&str] = &[
    "inference-probe",
    "model-status",
    "queue-depth",
    "warmth-detection",
];

/// Settings accepted inside `readiness > inference-probe`.
pub(crate) const RECOGNIZED_INFERENCE_PROBE_KEYS: &[&str] = &[
    "endpoint",
    "model",
    "prompt",
    "max-tokens",
    "timeout-secs",
    "max-latency-ms",
];

/// Settings accepted inside `readiness > model-status`.
///
/// Note `expected-status` and `status-field` are *settings*; their defaults are
/// the strings `"ready"` and `"status"`. Reading those defaults as key names is
/// the mistake a mechanical scan of this function makes.
pub(crate) const RECOGNIZED_MODEL_STATUS_KEYS: &[&str] = &[
    "endpoint-pattern",
    "models",
    "expected-status",
    "status-field",
    "timeout-secs",
];

/// Settings accepted inside `readiness > queue-depth`.
pub(crate) const RECOGNIZED_QUEUE_DEPTH_KEYS: &[&str] = &[
    "header",
    "body-field",
    "endpoint",
    "degraded-threshold",
    "unhealthy-threshold",
    "timeout-secs",
];

/// Settings accepted inside `readiness > warmth-detection`.
///
/// `cold-action` takes one of `log-only`, `mark-degraded` or `mark-unhealthy`
/// (underscored spellings also accepted). Those are *values*, not settings, and
/// do not belong in this list.
pub(crate) const RECOGNIZED_WARMTH_DETECTION_KEYS: &[&str] = &[
    "cold-action",
    "sample-size",
    "cold-threshold-multiplier",
    "idle-cold-timeout-secs",
];

/// Every child node `parse_upstream_tls` reads.
///
/// Distinct from a listener's `tls` block, which shares the name and no keys.
pub(crate) const RECOGNIZED_UPSTREAM_TLS_KEYS: &[&str] = &[
    "sni",
    "insecure-skip-verify",
    "client-cert",
    "client-key",
    "ca-cert",
];

/// Every child node a `target` block reads.
///
/// Both are also accepted as properties (`target address="..." weight=2`),
/// which the lint ignores; only child nodes are checked.
pub(crate) const RECOGNIZED_TARGET_KEYS: &[&str] = &["address", "weight"];

pub fn parse_upstream(child: &kdl::KdlNode) -> Result<UpstreamConfig> {
    if child.name().value() == "upstream" {
        let id = get_first_arg_string(child).ok_or_else(|| {
            anyhow::anyhow!(
                "Upstream requires an ID argument, e.g., upstream \"backend\" {{ ... }}"
            )
        })?;

        trace!(upstream_id = %id, "Parsing upstream");

        // Parse targets (accepts every supported syntax; see
        // `parse_upstream_targets`).
        let targets = parse_upstream_targets(child);

        // Service discovery, which may supply the targets instead of (or in
        // addition to) statically configured ones.
        let discovery = child
            .children()
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "discovery"))
            .map(|n| parse_discovery(n, &id))
            .transpose()?;

        if targets.is_empty() && discovery.is_none() {
            return Err(anyhow::anyhow!(
                "Upstream '{}' requires at least one target, e.g., target \"127.0.0.1:8081\", \
                 or a discovery block, e.g., discovery \"dns\" {{ hostname \"api.internal\"; port 8080 }}",
                id
            ));
        }

        // Parse load balancing algorithm and sticky session config
        let load_balancing_node = child.children().and_then(|c| {
            c.nodes()
                .iter()
                .find(|n| n.name().value() == "load-balancing")
        });

        let (load_balancing, problem) = resolve_load_balancing(child, &id);
        if let Some(problem) = problem {
            warn!("{}", problem);
        }

        // Parse sticky session config (if load-balancing is "sticky" with children)
        let sticky_session = if load_balancing == LoadBalancingAlgorithm::Sticky {
            load_balancing_node
                .and_then(|n| n.children())
                .map(|children| {
                    let (config, problems) = resolve_sticky_session_config(children, &id);
                    for problem in problems {
                        warn!("{}", problem);
                    }
                    config
                })
        } else {
            None
        };

        if sticky_session.is_some() {
            trace!(
                upstream_id = %id,
                cookie_name = ?sticky_session.as_ref().map(|s| &s.cookie_name),
                "Parsed sticky session configuration"
            );
        }

        // Parse health check configuration
        let health_check = child
            .children()
            .and_then(|c| {
                c.nodes()
                    .iter()
                    .find(|n| n.name().value() == "health-check")
            })
            .and_then(|n| {
                if let Some(problem) = health_check_type_problem(n, &id) {
                    warn!("{}", problem);
                }
                parse_health_check(n).ok()
            });

        if health_check.is_some() {
            trace!(
                upstream_id = %id,
                "Parsed health check configuration"
            );
        }

        // Parse HTTP version configuration
        let http_version_node = child.children().and_then(|c| {
            c.nodes()
                .iter()
                .find(|n| n.name().value() == "http-version")
        });
        let http_version = http_version_node
            .map(parse_http_version)
            .unwrap_or_default();

        let mut http_version = http_version;
        http_version.h2c = parse_h2c(child, &id)?;

        if http_version.max_version >= 2 {
            trace!(
                upstream_id = %id,
                max_version = http_version.max_version,
                h2c = http_version.h2c,
                "HTTP/2 enabled for upstream"
            );
        }

        // Parse connection pool configuration
        let connection_pool = child
            .children()
            .and_then(|c| {
                c.nodes()
                    .iter()
                    .find(|n| n.name().value() == "connection-pool")
            })
            .map(parse_connection_pool)
            .unwrap_or_default();

        // Parse timeouts configuration
        let timeouts = child
            .children()
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "timeouts"))
            .map(parse_upstream_timeouts)
            .unwrap_or_default();

        // Parse TLS configuration
        let tls = child
            .children()
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "tls"))
            .map(parse_upstream_tls);

        if tls.is_some() {
            trace!(
                upstream_id = %id,
                "Parsed TLS configuration"
            );
        }

        check_http_version_transport(&id, &http_version, tls.is_some(), http_version_node)?;

        let circuit_breaker = child
            .children()
            .and_then(|c| {
                c.nodes()
                    .iter()
                    .find(|n| n.name().value() == "circuit-breaker")
            })
            .map(parse_circuit_breaker_faildefault)
            .transpose()?;

        trace!(
            upstream_id = %id,
            target_count = targets.len(),
            load_balancing = ?load_balancing,
            has_health_check = health_check.is_some(),
            has_tls = tls.is_some(),
            http_version = http_version.max_version,
            max_connections = connection_pool.max_connections,
            connect_timeout = timeouts.connect_secs,
            "Parsed upstream"
        );

        Ok(UpstreamConfig {
            id,
            targets,
            load_balancing,
            sticky_session,
            health_check,
            circuit_breaker,
            connection_pool,
            timeouts,
            tls,
            http_version,
            discovery,
        })
    } else {
        Err(anyhow!("Child is not upstream stanza"))
    }
}

/// Parse upstreams configuration block
pub fn parse_upstreams(node: &kdl::KdlNode) -> Result<HashMap<String, UpstreamConfig>> {
    trace!("Parsing upstreams configuration block");
    let mut upstreams = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "upstream" {
                let config = parse_upstream(child)?;
                upstreams.insert(config.id.clone(), config);
            }
        }
    }

    trace!(
        upstream_count = upstreams.len(),
        "Finished parsing upstreams"
    );
    Ok(upstreams)
}

/// The canonical name of every load-balancing algorithm, for messages.
const LOAD_BALANCING_NAMES: &[&str] = &[
    "round_robin",
    "least_connections",
    "weighted",
    "ip_hash",
    "random",
    "consistent_hash",
    "power_of_two_choices",
    "adaptive",
    "least_tokens_queued",
    "maglev",
    "locality_aware",
    "peak_ewma",
    "deterministic_subset",
    "weighted_least_connections",
    "sticky",
];

/// Parse a load balancing algorithm name, or `None` if it names none.
///
/// Case-insensitive, and hyphens are read as underscores, so
/// `least-connections` is `least_connections`. Only the underscore spelling
/// used to be accepted here while route-level strategies took both, and the
/// hyphenated one silently became round robin.
fn parse_load_balancing(s: &str) -> Option<LoadBalancingAlgorithm> {
    let algorithm = match s.to_lowercase().replace('-', "_").as_str() {
        "round_robin" | "roundrobin" => LoadBalancingAlgorithm::RoundRobin,
        "least_connections" | "leastconnections" => LoadBalancingAlgorithm::LeastConnections,
        "weighted" | "weighted_round_robin" => LoadBalancingAlgorithm::Weighted,
        "ip_hash" | "iphash" => LoadBalancingAlgorithm::IpHash,
        "random" => LoadBalancingAlgorithm::Random,
        "consistent_hash" | "consistenthash" => LoadBalancingAlgorithm::ConsistentHash,
        "power_of_two_choices" | "p2c" => LoadBalancingAlgorithm::PowerOfTwoChoices,
        "adaptive" => LoadBalancingAlgorithm::Adaptive,
        "least_tokens_queued" | "leasttokensqueued" | "least_tokens" => {
            LoadBalancingAlgorithm::LeastTokensQueued
        }
        "maglev" => LoadBalancingAlgorithm::Maglev,
        "locality_aware" | "localityaware" | "locality" => LoadBalancingAlgorithm::LocalityAware,
        "peak_ewma" | "peakewma" | "ewma" => LoadBalancingAlgorithm::PeakEwma,
        "deterministic_subset" | "subset" | "subsetting" => {
            LoadBalancingAlgorithm::DeterministicSubset
        }
        "weighted_least_connections" | "weighted_least_conn" | "wlc" => {
            LoadBalancingAlgorithm::WeightedLeastConnections
        }
        "sticky" | "sticky_session" | "stickysession" => LoadBalancingAlgorithm::Sticky,
        _ => return None,
    };
    Some(algorithm)
}

/// Work out an upstream's load-balancing algorithm, and whether its
/// `load-balancing` value was ignored.
///
/// An unknown name keeps round robin, as it always has — configs carrying one
/// have been loading and must keep doing so — but it comes back as a problem
/// for `zentinel lint` (through `validate::unknown_keys`) rather than silently.
pub(crate) fn resolve_load_balancing(
    upstream: &kdl::KdlNode,
    upstream_id: &str,
) -> (LoadBalancingAlgorithm, Option<String>) {
    let Some(name) = upstream
        .children()
        .and_then(|c| c.get("load-balancing"))
        .and_then(get_first_arg_string)
    else {
        return (LoadBalancingAlgorithm::RoundRobin, None);
    };
    if let Some(algorithm) = parse_load_balancing(&name) {
        return (algorithm, None);
    }
    let suggestion = super::helpers::did_you_mean(&name, LOAD_BALANCING_NAMES)
        .map(|s| format!(" Did you mean '{}'?", s))
        .unwrap_or_default();
    (
        LoadBalancingAlgorithm::RoundRobin,
        Some(format!(
            "'load-balancing \"{}\"' on upstream '{}' is not a load-balancing algorithm and \
             is being ignored; the upstream uses round_robin.{} Valid algorithms: {}.",
            name,
            upstream_id,
            suggestion,
            LOAD_BALANCING_NAMES.join(", ")
        )),
    )
}

/// Parse sticky session configuration
///
/// Example KDL:
/// ```kdl
/// load-balancing "sticky" {
///     cookie-name "SERVERID"
///     cookie-ttl 3600
///     cookie-path "/"
///     cookie-secure #true
///     cookie-same-site "lax"
///     fallback "round-robin"
/// }
/// ```
///
/// Unknown `fallback` and `cookie-same-site` values keep their old defaults
/// (round robin and lax) -- configs carrying them have been loading -- and
/// come back as problems, logged at load and reported by `zentinel lint`
/// through `validate::unknown_keys`, rather than silently.
pub(crate) fn resolve_sticky_session_config(
    children: &kdl::KdlDocument,
    upstream_id: &str,
) -> (StickySessionConfig, Vec<String>) {
    let nodes = children.nodes();
    let mut problems = Vec::new();

    let cookie_name =
        find_string_entry(nodes, "cookie-name").unwrap_or_else(|| "SERVERID".to_string());

    // Parse cookie TTL - support both integer seconds and duration strings
    let cookie_ttl_secs = find_int_entry(nodes, "cookie-ttl")
        .map(|v| v as u64)
        .or_else(|| find_string_entry(nodes, "cookie-ttl").and_then(|s| parse_duration_string(&s)))
        .unwrap_or(3600); // Default 1 hour

    let cookie_path = find_string_entry(nodes, "cookie-path").unwrap_or_else(|| "/".to_string());

    let cookie_secure = nodes
        .iter()
        .find(|n| n.name().value() == "cookie-secure")
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool())
        .unwrap_or(true); // Default to secure

    let cookie_same_site = match find_string_entry(nodes, "cookie-same-site") {
        None => SameSitePolicy::default(),
        Some(value) => match value.to_lowercase().as_str() {
            "strict" => SameSitePolicy::Strict,
            "none" => SameSitePolicy::None,
            "lax" => SameSitePolicy::Lax,
            _ => {
                problems.push(format!(
                    "'cookie-same-site \"{}\"' on upstream '{}' is not a SameSite policy \
                     (strict, lax, none) and is being ignored; the cookie uses lax.",
                    value, upstream_id
                ));
                SameSitePolicy::Lax
            }
        },
    };

    let fallback = match find_string_entry(nodes, "fallback") {
        None => LoadBalancingAlgorithm::RoundRobin,
        Some(name) => parse_load_balancing(&name).unwrap_or_else(|| {
            let suggestion = super::helpers::did_you_mean(&name, LOAD_BALANCING_NAMES)
                .map(|s| format!(" Did you mean '{}'?", s))
                .unwrap_or_default();
            problems.push(format!(
                "'fallback \"{}\"' in the sticky load-balancing of upstream '{}' is not a \
                 load-balancing algorithm and is being ignored; requests without a valid \
                 affinity cookie use round_robin.{} Valid algorithms: {}.",
                name,
                upstream_id,
                suggestion,
                LOAD_BALANCING_NAMES
                    .iter()
                    .filter(|n| **n != "sticky")
                    .copied()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            LoadBalancingAlgorithm::RoundRobin
        }),
    };

    (
        StickySessionConfig {
            cookie_name,
            cookie_ttl_secs,
            cookie_path,
            cookie_secure,
            cookie_same_site,
            fallback,
        },
        problems,
    )
}

/// Parse duration string like "1h", "30m", "1d" to seconds
pub(crate) fn parse_duration_string(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // Try to find where the number ends and the unit begins
    let (num_part, unit_part) = s
        .chars()
        .position(|c| c.is_alphabetic())
        .map(|i| s.split_at(i))?;

    let value: f64 = num_part.trim().parse().ok()?;

    let multiplier = match unit_part.to_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3600,
        "d" | "day" | "days" => 86400,
        _ => return None,
    };

    Some((value * multiplier as f64) as u64)
}

/// Parse HTTP version configuration
///
/// Example KDL:
/// ```kdl
/// http-version {
///     min-version 1
///     max-version 2
///     h2-ping-interval 30
///     max-h2-streams 100
/// }
/// ```
fn parse_http_version(node: &kdl::KdlNode) -> HttpVersionConfig {
    // Helper to get integer value from a child node's first argument
    let get_child_int = |name: &str| -> Option<i128> {
        node.children()
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == name))
            .and_then(|n| n.entries().first())
            .and_then(|e| e.value().as_integer())
    };

    let min_version = get_child_int("min-version").map(|v| v as u8).unwrap_or(1);

    let max_version = get_child_int("max-version").map(|v| v as u8).unwrap_or(2); // Default to HTTP/2 support

    let h2_ping_interval_secs = get_child_int("h2-ping-interval")
        .map(|v| v as u64)
        .unwrap_or(0);

    let max_h2_streams = get_child_int("max-h2-streams")
        .map(|v| v as usize)
        .unwrap_or(100);

    HttpVersionConfig {
        min_version,
        max_version,
        h2_ping_interval_secs,
        max_h2_streams,
        // Set by `parse_upstream` from the upstream's own `h2c` node.
        h2c: false,
    }
}

/// Read an upstream's `h2c` setting: absent is `false`, anything but a
/// boolean is an error rather than a silent `false`.
fn parse_h2c(upstream: &kdl::KdlNode, id: &str) -> Result<bool> {
    let Some(node) = upstream
        .children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "h2c"))
    else {
        return Ok(false);
    };
    node.entries()
        .first()
        .and_then(|e| e.value().as_bool())
        .ok_or_else(|| anyhow!("Upstream '{id}': 'h2c' takes #true or #false, e.g. 'h2c #true'"))
}

/// Reject HTTP version settings the connection could not honour.
///
/// Without `tls` there is no ALPN, so HTTP/2 to a plain upstream is only
/// possible with prior knowledge, which `h2c #true` asks for. An HTTP/2-only
/// `http-version` on a plain upstream used to be served over HTTP/1.1 without
/// a word, and `h2c` with `tls` or with an HTTP/1-only range cannot mean what
/// it says, so each of these fails to load.
fn check_http_version_transport(
    id: &str,
    http_version: &HttpVersionConfig,
    tls: bool,
    http_version_node: Option<&kdl::KdlNode>,
) -> Result<()> {
    if http_version.h2c {
        if tls {
            return Err(anyhow!(
                "Upstream '{id}': 'h2c #true' is HTTP/2 over cleartext TCP and cannot be \
                 combined with a 'tls' block. Over TLS, HTTP/2 is negotiated with ALPN: \
                 remove 'h2c' and set 'http-version {{ min-version 2 }}' instead."
            ));
        }
        if http_version.max_version < 2 {
            return Err(anyhow!(
                "Upstream '{id}': 'h2c #true' speaks HTTP/2 only, but 'http-version' \
                 allows at most HTTP/{}. Remove 'max-version' or 'h2c'.",
                http_version.max_version
            ));
        }
        // min-version defaults to 1; only a value written down conflicts.
        let explicit_min = http_version_node
            .and_then(|n| n.children())
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "min-version"))
            .and_then(|n| n.entries().first())
            .and_then(|e| e.value().as_integer());
        if explicit_min == Some(1) {
            return Err(anyhow!(
                "Upstream '{id}': 'h2c #true' never falls back to HTTP/1.1, but \
                 'http-version' sets 'min-version 1'. Remove 'min-version' or 'h2c'."
            ));
        }
    } else if !tls && http_version.min_version >= 2 {
        return Err(anyhow!(
            "Upstream '{id}': 'http-version' requires HTTP/2 ('min-version {}'), but \
             the upstream has no 'tls' block, so there is no ALPN to negotiate it and \
             the connection would use HTTP/1.1. Add 'h2c #true' for HTTP/2 over \
             cleartext, or a 'tls' block.",
            http_version.min_version
        ));
    }
    Ok(())
}

/// Parse connection pool configuration
///
/// Example KDL:
/// ```kdl
/// connection-pool {
///     max-connections 100
///     max-idle 20
///     idle-timeout-secs 60
///     max-lifetime-secs 3600
/// }
/// ```
///
/// `idle-timeout` and `max-lifetime` are accepted as aliases for the two
/// `-secs` names.
fn parse_connection_pool(node: &kdl::KdlNode) -> ConnectionPoolConfig {
    let max_connections = get_int_entry(node, "max-connections")
        .map(|v| v as usize)
        .unwrap_or(100);

    let max_idle = get_int_entry(node, "max-idle")
        .map(|v| v as usize)
        .unwrap_or(20);

    // `-secs` is the documented spelling and the one every shipped config and
    // example uses; the bare form appears only in this function's own doc
    // comment. Reading only the bare form meant `max-lifetime-secs 300` in
    // config/zentinel.kdl was discarded and pools ran with no lifetime cap at
    // all. Both are accepted so anyone who followed the old rustdoc keeps
    // working, with the documented name taking precedence.
    let idle_timeout_secs = get_int_entry(node, "idle-timeout-secs")
        .or_else(|| get_int_entry(node, "idle-timeout"))
        .map(|v| v as u64)
        .unwrap_or(60);

    let max_lifetime_secs = get_int_entry(node, "max-lifetime-secs")
        .or_else(|| get_int_entry(node, "max-lifetime"))
        .map(|v| v as u64);

    ConnectionPoolConfig {
        max_connections,
        max_idle,
        idle_timeout_secs,
        max_lifetime_secs,
    }
}

/// Parse upstream timeouts configuration
///
/// Example KDL:
/// ```kdl
/// timeouts {
///     connect-secs 10
///     request-secs 60
///     read-secs 30
///     write-secs 30
/// }
/// ```
///
/// The unsuffixed names (`connect`, `request`, `read`, `write`) are accepted as
/// aliases.
fn parse_upstream_timeouts(node: &kdl::KdlNode) -> UpstreamTimeouts {
    // As with the connection pool above, the `-secs` spellings are what every
    // config and the documentation use, and the unsuffixed ones are what this
    // parser used to read. Reading only the latter meant every timeout in
    // every shipped config was discarded in favour of the default — an
    // upstream asking for `request-secs 300` was cut off at 60.
    let timeout = |suffixed: &str, bare: &str, default: u64| {
        get_int_entry(node, suffixed)
            .or_else(|| get_int_entry(node, bare))
            .map(|v| v as u64)
            .unwrap_or(default)
    };

    let connect_secs = timeout("connect-secs", "connect", 10);
    let request_secs = timeout("request-secs", "request", 60);
    let read_secs = timeout("read-secs", "read", 30);
    let write_secs = timeout("write-secs", "write", 30);

    UpstreamTimeouts {
        connect_secs,
        request_secs,
        read_secs,
        write_secs,
    }
}

/// Parse upstream TLS configuration
///
/// Example KDL:
/// ```kdl
/// tls {
///     sni "backend.example.com"
///     insecure-skip-verify false
///     client-cert "/path/to/client.crt"
///     client-key "/path/to/client.key"
///     ca-cert "/path/to/ca.crt"
/// }
/// ```
fn parse_upstream_tls(node: &kdl::KdlNode) -> UpstreamTlsConfig {
    let sni = find_string_entry_from_node(node, "sni");

    let insecure_skip_verify =
        find_bool_entry_from_node(node, "insecure-skip-verify").unwrap_or(false);

    let client_cert = find_string_entry_from_node(node, "client-cert").map(PathBuf::from);

    let client_key = find_string_entry_from_node(node, "client-key").map(PathBuf::from);

    let ca_cert = find_string_entry_from_node(node, "ca-cert").map(PathBuf::from);

    UpstreamTlsConfig {
        sni,
        insecure_skip_verify,
        client_cert,
        client_key,
        ca_cert,
    }
}

/// Find a string entry in a node's children by name
fn find_string_entry_from_node(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string().map(|s| s.to_string()))
}

/// Find a boolean entry in a node's children by name
fn find_bool_entry_from_node(node: &kdl::KdlNode, name: &str) -> Option<bool> {
    node.children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool())
}

/// Keys each discovery backend accepts, used to reject settings that belong to
/// a different backend than the one named.
const STATIC_DISCOVERY_KEYS: &[&str] = &["backends"];
const DNS_DISCOVERY_KEYS: &[&str] = &["hostname", "port", "refresh-interval"];
const DNS_SRV_DISCOVERY_KEYS: &[&str] = &["service", "refresh-interval"];
const CONSUL_DISCOVERY_KEYS: &[&str] = &[
    "address",
    "service",
    "datacenter",
    "only-passing",
    "refresh-interval",
    "tag",
];
const KUBERNETES_DISCOVERY_KEYS: &[&str] = &[
    "namespace",
    "service",
    "port-name",
    "refresh-interval",
    "kubeconfig",
];
const FILE_DISCOVERY_KEYS: &[&str] = &["path", "watch-interval"];

/// Reject any child of a `discovery` block that the named backend does not use.
///
/// The unknown-key lint only knows the union of all backends' keys, so without
/// this a `hostname` under `discovery "consul"` would parse, validate clean, and
/// be silently dropped — the failure shape this whole feature exists to avoid.
fn reject_foreign_discovery_keys(
    node: &kdl::KdlNode,
    kind: &str,
    allowed: &[&str],
    upstream_id: &str,
) -> Result<()> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value();
        if !allowed.contains(&name) {
            return Err(anyhow!(
                "Upstream '{}': '{}' is not a setting of discovery \"{}\" (accepted: {})",
                upstream_id,
                name,
                kind,
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

/// Read a required string child node, naming the block in the error.
fn required_string(
    node: &kdl::KdlNode,
    key: &str,
    kind: &str,
    upstream_id: &str,
) -> Result<String> {
    get_string_entry(node, key).ok_or_else(|| {
        anyhow!(
            "Upstream '{}': discovery \"{}\" requires '{}'",
            upstream_id,
            kind,
            key
        )
    })
}

/// Read a refresh interval in seconds, rejecting zero.
///
/// Zero would busy-loop the refresh task, so it is an error rather than a
/// value that silently becomes the default.
fn refresh_secs(node: &kdl::KdlNode, key: &str, default: u64, upstream_id: &str) -> Result<u64> {
    match get_int_entry(node, key) {
        None => Ok(default),
        Some(v) if v <= 0 => Err(anyhow!(
            "Upstream '{}': '{}' must be greater than zero (got {})",
            upstream_id,
            key,
            v
        )),
        Some(v) => Ok(v as u64),
    }
}

/// Parse a `discovery "<kind>" { ... }` block.
///
/// The backend is named by the block's first argument; its settings are child
/// nodes. Anything that does not belong to that backend is an error rather than
/// a silently ignored key.
pub(crate) fn parse_discovery(node: &kdl::KdlNode, upstream_id: &str) -> Result<UpstreamDiscovery> {
    let kind = get_first_arg_string(node).ok_or_else(|| {
        anyhow!(
            "Upstream '{}': discovery requires a type argument, e.g., discovery \"dns\" {{ ... }}",
            upstream_id
        )
    })?;

    match kind.as_str() {
        "static" => {
            reject_foreign_discovery_keys(node, &kind, STATIC_DISCOVERY_KEYS, upstream_id)?;
            let backends = node
                .children()
                .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "backends"))
                .map(|n| {
                    n.entries()
                        .iter()
                        .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if backends.is_empty() {
                return Err(anyhow!(
                    "Upstream '{}': discovery \"static\" requires a non-empty 'backends' list",
                    upstream_id
                ));
            }
            Ok(UpstreamDiscovery::Static { backends })
        }
        "dns" => {
            reject_foreign_discovery_keys(node, &kind, DNS_DISCOVERY_KEYS, upstream_id)?;
            let hostname = required_string(node, "hostname", &kind, upstream_id)?;
            let port = get_int_entry(node, "port").ok_or_else(|| {
                anyhow!(
                    "Upstream '{}': discovery \"dns\" requires 'port'",
                    upstream_id
                )
            })?;
            let port = u16::try_from(port).map_err(|_| {
                anyhow!(
                    "Upstream '{}': discovery port {} is out of range",
                    upstream_id,
                    port
                )
            })?;
            Ok(UpstreamDiscovery::Dns {
                hostname,
                port,
                refresh_interval_secs: refresh_secs(node, "refresh-interval", 30, upstream_id)?,
            })
        }
        "dns-srv" => {
            reject_foreign_discovery_keys(node, &kind, DNS_SRV_DISCOVERY_KEYS, upstream_id)?;
            Ok(UpstreamDiscovery::DnsSrv {
                service: required_string(node, "service", &kind, upstream_id)?,
                refresh_interval_secs: refresh_secs(node, "refresh-interval", 30, upstream_id)?,
            })
        }
        "consul" => {
            reject_foreign_discovery_keys(node, &kind, CONSUL_DISCOVERY_KEYS, upstream_id)?;
            Ok(UpstreamDiscovery::Consul {
                address: required_string(node, "address", &kind, upstream_id)?,
                service: required_string(node, "service", &kind, upstream_id)?,
                datacenter: get_string_entry(node, "datacenter"),
                only_passing: get_bool_entry(node, "only-passing").unwrap_or(true),
                refresh_interval_secs: refresh_secs(node, "refresh-interval", 30, upstream_id)?,
                tag: get_string_entry(node, "tag"),
            })
        }
        "kubernetes" => {
            reject_foreign_discovery_keys(node, &kind, KUBERNETES_DISCOVERY_KEYS, upstream_id)?;
            Ok(UpstreamDiscovery::Kubernetes {
                namespace: required_string(node, "namespace", &kind, upstream_id)?,
                service: required_string(node, "service", &kind, upstream_id)?,
                port_name: get_string_entry(node, "port-name"),
                refresh_interval_secs: refresh_secs(node, "refresh-interval", 30, upstream_id)?,
                kubeconfig: get_string_entry(node, "kubeconfig"),
            })
        }
        "file" => {
            reject_foreign_discovery_keys(node, &kind, FILE_DISCOVERY_KEYS, upstream_id)?;
            Ok(UpstreamDiscovery::File {
                path: required_string(node, "path", &kind, upstream_id)?,
                watch_interval_secs: refresh_secs(node, "watch-interval", 5, upstream_id)?,
            })
        }
        other => Err(anyhow!(
            "Upstream '{}': unknown discovery type '{}' (accepted: static, dns, dns-srv, consul, kubernetes, file)",
            upstream_id,
            other
        )),
    }
}

/// Every health-check type `parse_health_check` reads settings for.
const HEALTH_CHECK_TYPES: &[&str] = &["tcp", "http", "grpc", "inference", "mcp"];

/// Whether a health check's `type` value is ignored, as a message.
///
/// A name that is not a type (`type "htttp"`) is probed as TCP, and the settings
/// written for the intended type go with it. That fallback is kept, because
/// configs carrying such a value have been loading, and reported here for
/// `zentinel lint` (through `validate::unknown_keys`).
pub(crate) fn health_check_type_problem(
    health_check: &kdl::KdlNode,
    upstream_id: &str,
) -> Option<String> {
    let name = health_check
        .children()?
        .get("type")
        .and_then(get_first_arg_string)?;
    if HEALTH_CHECK_TYPES.contains(&name.to_lowercase().as_str()) {
        return None;
    }
    let suggestion = super::helpers::did_you_mean(&name.to_lowercase(), HEALTH_CHECK_TYPES)
        .map(|s| format!(" Did you mean '{}'?", s))
        .unwrap_or_default();
    Some(format!(
        "health-check 'type \"{}\"' on upstream '{}' is not a health-check type ({}) and is \
         being ignored; the upstream is checked over TCP.{}",
        name,
        upstream_id,
        HEALTH_CHECK_TYPES.join(", "),
        suggestion
    ))
}

/// Parse health check configuration
fn parse_health_check(node: &kdl::KdlNode) -> Result<HealthCheck> {
    // Parse health check type
    let check_type = node
        .children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "type"))
        .map(|type_node| {
            let type_name = get_first_arg_string(type_node).unwrap_or_else(|| "tcp".to_string());
            match type_name.to_lowercase().as_str() {
                "http" => {
                    // Parse HTTP health check options
                    let path = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "path"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "/health".to_string());

                    let expected_status = type_node
                        .children()
                        .and_then(|c| {
                            c.nodes()
                                .iter()
                                .find(|n| n.name().value() == "expected-status")
                        })
                        .and_then(get_first_arg_string)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(200);

                    let host = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "host"))
                        .and_then(get_first_arg_string);

                    HealthCheckType::Http {
                        path,
                        expected_status,
                        host,
                    }
                }
                "grpc" => {
                    let service = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "service"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "grpc.health.v1.Health".to_string());
                    HealthCheckType::Grpc { service }
                }
                "inference" => {
                    // Parse inference health check options
                    let endpoint = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "endpoint"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "/v1/models".to_string());

                    let expected_models = type_node
                        .children()
                        .and_then(|c| {
                            c.nodes()
                                .iter()
                                .find(|n| n.name().value() == "expected-models")
                        })
                        .map(|n| {
                            n.entries()
                                .iter()
                                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    // Parse optional readiness config
                    let readiness = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "readiness"))
                        .map(|n| Box::new(parse_inference_readiness(n)));

                    HealthCheckType::Inference {
                        endpoint,
                        expected_models,
                        readiness,
                    }
                }
                "mcp" => {
                    let path = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "path"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "/".to_string());

                    let expected_tools = type_node
                        .children()
                        .and_then(|c| {
                            c.nodes()
                                .iter()
                                .find(|n| n.name().value() == "expected-tools")
                        })
                        .map(|n| {
                            n.entries()
                                .iter()
                                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();

                    HealthCheckType::Mcp {
                        path,
                        expected_tools,
                    }
                }
                _ => HealthCheckType::Tcp,
            }
        })
        .unwrap_or(HealthCheckType::Tcp);

    // Parse other health check settings
    let interval_secs = get_int_entry(node, "interval-secs").unwrap_or(10) as u64;
    let timeout_secs = get_int_entry(node, "timeout-secs").unwrap_or(5) as u64;
    let healthy_threshold = get_int_entry(node, "healthy-threshold").unwrap_or(2) as u32;
    let unhealthy_threshold = get_int_entry(node, "unhealthy-threshold").unwrap_or(3) as u32;

    Ok(HealthCheck {
        check_type,
        interval_secs,
        timeout_secs,
        healthy_threshold,
        unhealthy_threshold,
    })
}

/// Parse inference readiness configuration
fn parse_inference_readiness(node: &kdl::KdlNode) -> zentinel_common::InferenceReadinessConfig {
    use zentinel_common::{
        ColdModelAction, InferenceProbeConfig, InferenceReadinessConfig, ModelStatusConfig,
        QueueDepthConfig, WarmthDetectionConfig,
    };

    let children = match node.children() {
        Some(c) => c,
        None => return InferenceReadinessConfig::default(),
    };

    // Parse inference-probe
    let inference_probe = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == "inference-probe")
        .and_then(|n| n.children())
        .map(|c| {
            let nodes = c.nodes();
            InferenceProbeConfig {
                endpoint: find_string_entry(nodes, "endpoint")
                    .unwrap_or_else(|| "/v1/completions".to_string()),
                model: find_string_entry(nodes, "model").unwrap_or_default(),
                prompt: find_string_entry(nodes, "prompt").unwrap_or_else(|| ".".to_string()),
                max_tokens: find_int_entry(nodes, "max-tokens").unwrap_or(1) as u32,
                timeout_secs: find_int_entry(nodes, "timeout-secs").unwrap_or(30) as u64,
                max_latency_ms: find_int_entry(nodes, "max-latency-ms").map(|v| v as u64),
            }
        });

    // Parse model-status
    let model_status = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == "model-status")
        .and_then(|n| n.children())
        .map(|c| {
            let nodes = c.nodes();
            let models = nodes
                .iter()
                .find(|n| n.name().value() == "models")
                .map(|n| {
                    n.entries()
                        .iter()
                        .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            ModelStatusConfig {
                endpoint_pattern: find_string_entry(nodes, "endpoint-pattern")
                    .unwrap_or_else(|| "/v1/models/{model}/status".to_string()),
                models,
                expected_status: find_string_entry(nodes, "expected-status")
                    .unwrap_or_else(|| "ready".to_string()),
                status_field: find_string_entry(nodes, "status-field")
                    .unwrap_or_else(|| "status".to_string()),
                timeout_secs: find_int_entry(nodes, "timeout-secs").unwrap_or(5) as u64,
            }
        });

    // Parse queue-depth
    let queue_depth = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == "queue-depth")
        .and_then(|n| n.children())
        .map(|c| {
            let nodes = c.nodes();
            QueueDepthConfig {
                header: find_string_entry(nodes, "header"),
                body_field: find_string_entry(nodes, "body-field"),
                endpoint: find_string_entry(nodes, "endpoint"),
                degraded_threshold: find_int_entry(nodes, "degraded-threshold").unwrap_or(50)
                    as u64,
                unhealthy_threshold: find_int_entry(nodes, "unhealthy-threshold").unwrap_or(200)
                    as u64,
                timeout_secs: find_int_entry(nodes, "timeout-secs").unwrap_or(5) as u64,
            }
        });

    // Parse warmth-detection
    let warmth_detection = children
        .nodes()
        .iter()
        .find(|n| n.name().value() == "warmth-detection")
        .and_then(|n| n.children())
        .map(|c| {
            let nodes = c.nodes();
            let cold_action = find_string_entry(nodes, "cold-action")
                .map(|s| match s.as_str() {
                    "log-only" | "log_only" => ColdModelAction::LogOnly,
                    "mark-degraded" | "mark_degraded" => ColdModelAction::MarkDegraded,
                    "mark-unhealthy" | "mark_unhealthy" => ColdModelAction::MarkUnhealthy,
                    _ => ColdModelAction::LogOnly,
                })
                .unwrap_or_default();

            WarmthDetectionConfig {
                sample_size: find_int_entry(nodes, "sample-size").unwrap_or(10) as u32,
                cold_threshold_multiplier: find_float_entry(nodes, "cold-threshold-multiplier")
                    .unwrap_or(3.0),
                idle_cold_timeout_secs: find_int_entry(nodes, "idle-cold-timeout-secs")
                    .unwrap_or(300) as u64,
                cold_action,
            }
        });

    InferenceReadinessConfig {
        inference_probe,
        model_status,
        queue_depth,
        warmth_detection,
    }
}

/// Find a string entry in nodes by name
fn find_string_entry(nodes: &[kdl::KdlNode], name: &str) -> Option<String> {
    nodes
        .iter()
        .find(|n| n.name().value() == name)
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string().map(|s| s.to_string()))
}

/// Find an integer entry in nodes by name
fn find_int_entry(nodes: &[kdl::KdlNode], name: &str) -> Option<i64> {
    nodes
        .iter()
        .find(|n| n.name().value() == name)
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer().map(|v| v as i64))
}

/// Find a float entry in nodes by name
fn find_float_entry(nodes: &[kdl::KdlNode], name: &str) -> Option<f64> {
    nodes
        .iter()
        .find(|n| n.name().value() == name)
        .and_then(|n| n.entries().first())
        .and_then(|e| {
            e.value()
                .as_float()
                .or_else(|| e.value().as_integer().map(|i| i as f64))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_kdl_upstreams(input: &str) -> Result<HashMap<String, UpstreamConfig>> {
        let doc: kdl::KdlDocument = input.parse().unwrap();
        let node = doc.nodes().first().unwrap();
        parse_upstreams(node)
    }

    fn targets_of(kdl: &str, id: &str) -> Vec<UpstreamTarget> {
        parse_kdl_upstreams(kdl)
            .unwrap()
            .get(id)
            .unwrap()
            .targets
            .clone()
    }

    /// Read the struct back rather than trusting that the block parsed. An
    /// unrecognised `type` falls back to TCP here, so a check that "parsed"
    /// can silently be probing something else entirely.
    mod mcp_health_check {
        use super::*;

        fn check_of(body: &str) -> HealthCheck {
            parse_kdl_upstreams(&format!(
                r#"upstreams {{
                    upstream "backend" {{
                        target "127.0.0.1:9000"
                        health-check {{ {body} }}
                    }}
                }}"#
            ))
            .unwrap()
            .get("backend")
            .unwrap()
            .health_check
            .clone()
            .expect("health check parsed")
        }

        #[test]
        fn path_and_expected_tools_are_read() {
            let hc = check_of(
                "type \"mcp\" {\n  path \"/mcp\"\n  expected-tools \"search_docs\" \"get_weather\"\n}",
            );
            match hc.check_type {
                HealthCheckType::Mcp {
                    path,
                    expected_tools,
                } => {
                    assert_eq!(path, "/mcp");
                    assert_eq!(expected_tools, ["search_docs", "get_weather"]);
                }
                other => panic!("expected an MCP check, got {other:?}"),
            }
        }

        /// Omitting the tool list is the liveness-only case, not an empty
        /// allowlist -- the check stops after `initialize`.
        #[test]
        fn expected_tools_defaults_to_empty_and_path_to_root() {
            match check_of("type \"mcp\"").check_type {
                HealthCheckType::Mcp {
                    path,
                    expected_tools,
                } => {
                    assert_eq!(path, "/");
                    assert!(expected_tools.is_empty());
                }
                other => panic!("expected an MCP check, got {other:?}"),
            }
        }

        /// Thresholds and intervals are siblings of `type`, not children, so
        /// they must survive a type-specific block being present.
        #[test]
        fn sibling_settings_still_apply() {
            let hc = check_of(
                r#"type "mcp" { path "/mcp" }
                   interval-secs 30
                   timeout-secs 7
                   unhealthy-threshold 5"#,
            );
            assert_eq!(hc.interval_secs, 30);
            assert_eq!(hc.timeout_secs, 7);
            assert_eq!(hc.unhealthy_threshold, 5);
        }
    }

    /// The documented spellings carry a unit suffix. Reading only the bare
    /// names meant every config written against the documentation — including
    /// the ones shipped in this repo — had its pool lifetime silently dropped.
    mod connection_pool_key_names {
        use super::*;

        fn pool_of(kdl: &str) -> ConnectionPoolConfig {
            parse_kdl_upstreams(kdl)
                .unwrap()
                .get("backend")
                .unwrap()
                .connection_pool
                .clone()
        }

        fn with_pool(body: &str) -> String {
            format!(
                r#"upstreams {{
                    upstream "backend" {{
                        target "127.0.0.1:9000"
                        connection-pool {{ {body} }}
                    }}
                }}"#
            )
        }

        #[test]
        fn documented_secs_names_are_read() {
            let pool = pool_of(&with_pool("idle-timeout-secs 45\nmax-lifetime-secs 300"));
            assert_eq!(pool.idle_timeout_secs, 45);
            assert_eq!(pool.max_lifetime_secs, Some(300));
        }

        /// The bare names were what the parser used to read, and they appeared
        /// in its own rustdoc, so anyone who copied from there keeps working.
        #[test]
        fn bare_names_still_work_as_aliases() {
            let pool = pool_of(&with_pool("idle-timeout 45\nmax-lifetime 300"));
            assert_eq!(pool.idle_timeout_secs, 45);
            assert_eq!(pool.max_lifetime_secs, Some(300));
        }

        #[test]
        fn documented_name_wins_when_both_are_present() {
            let pool = pool_of(&with_pool(
                "idle-timeout-secs 45\nidle-timeout 99\nmax-lifetime-secs 300\nmax-lifetime 999",
            ));
            assert_eq!(pool.idle_timeout_secs, 45);
            assert_eq!(pool.max_lifetime_secs, Some(300));
        }

        #[test]
        fn absent_lifetime_stays_unbounded() {
            let pool = pool_of(&with_pool("max-connections 10"));
            assert_eq!(pool.idle_timeout_secs, 60);
            assert_eq!(pool.max_lifetime_secs, None);
        }

        /// Pins the regression to the file it actually broke: the shipped
        /// default config asks for a 300s lifetime cap and used to get none.
        #[test]
        fn shipped_default_config_gets_the_lifetime_it_asks_for() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/zentinel.kdl");
            let text = std::fs::read_to_string(path).expect("shipped config should be readable");
            let config = crate::Config::from_kdl(&text).expect("shipped config should parse");

            // Only `api-backend` declares a connection-pool in the shipped
            // config; the rest take pool defaults, where an absent lifetime
            // legitimately means unbounded.
            let api = config
                .upstreams
                .get("api-backend")
                .expect("shipped config should define the api-backend upstream");

            assert_eq!(
                api.connection_pool.max_lifetime_secs,
                Some(300),
                "api-backend asks for max-lifetime-secs 300 and must get it"
            );
            assert_eq!(api.connection_pool.idle_timeout_secs, 60);
        }
    }

    /// Same defect as the connection-pool names above, with a sharper edge:
    /// every timeout in every shipped config was being replaced by a default.
    mod upstream_timeout_key_names {
        use super::*;

        fn timeouts_of(body: &str) -> UpstreamTimeouts {
            let kdl = format!(
                r#"upstreams {{
                    upstream "backend" {{
                        target "127.0.0.1:9000"
                        timeouts {{ {body} }}
                    }}
                }}"#
            );
            parse_kdl_upstreams(&kdl)
                .unwrap()
                .get("backend")
                .unwrap()
                .timeouts
                .clone()
        }

        #[test]
        fn documented_secs_names_are_read() {
            let t = timeouts_of("connect-secs 2\nrequest-secs 300\nread-secs 120\nwrite-secs 15");
            assert_eq!(t.connect_secs, 2);
            assert_eq!(t.request_secs, 300);
            assert_eq!(t.read_secs, 120);
            assert_eq!(t.write_secs, 15);
        }

        #[test]
        fn bare_names_still_work_as_aliases() {
            let t = timeouts_of("connect 2\nrequest 300\nread 120\nwrite 15");
            assert_eq!(t.connect_secs, 2);
            assert_eq!(t.request_secs, 300);
            assert_eq!(t.read_secs, 120);
            assert_eq!(t.write_secs, 15);
        }

        #[test]
        fn documented_name_wins_when_both_are_present() {
            let t = timeouts_of("connect-secs 2\nconnect 99\nrequest-secs 300\nrequest 999");
            assert_eq!(t.connect_secs, 2);
            assert_eq!(t.request_secs, 300);
        }

        #[test]
        fn defaults_apply_when_absent() {
            let t = timeouts_of("connect-secs 5");
            assert_eq!(t.connect_secs, 5);
            assert_eq!(t.request_secs, 60);
            assert_eq!(t.read_secs, 30);
            assert_eq!(t.write_secs, 30);
        }

        /// The case that made this expensive: an inference upstream asking for
        /// a 300s request timeout was silently cut off at the 60s default.
        #[test]
        fn a_long_request_timeout_is_not_replaced_by_the_default() {
            let t = timeouts_of("request-secs 300");
            assert_eq!(
                t.request_secs, 300,
                "a configured 300s request timeout must not fall back to 60s"
            );
        }

        /// Pins it to the shipped config, which asks for a 30s request timeout
        /// and used to run with 60.
        #[test]
        fn shipped_default_config_gets_the_timeouts_it_asks_for() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/zentinel.kdl");
            let text = std::fs::read_to_string(path).expect("shipped config should be readable");
            let config = crate::Config::from_kdl(&text).expect("shipped config should parse");

            let api = config
                .upstreams
                .get("api-backend")
                .expect("shipped config should define the api-backend upstream");

            assert_eq!(api.timeouts.connect_secs, 10);
            assert_eq!(
                api.timeouts.request_secs, 30,
                "api-backend asks for request-secs 30 and must get it, not the 60s default"
            );
            assert_eq!(api.timeouts.read_secs, 30);
            assert_eq!(api.timeouts.write_secs, 30);
        }
    }

    #[test]
    fn test_target_shorthand_first_arg() {
        let t = targets_of(
            r#"upstreams { upstream "b" { target "127.0.0.1:8081" weight=2 } }"#,
            "b",
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "127.0.0.1:8081");
        assert_eq!(t[0].weight, 2);
    }

    #[test]
    fn test_target_block_form_inside_targets() {
        // The form the quickstart docs showed — previously rejected by the
        // single-file parser (zentinelproxy/zentinel#254).
        let t = targets_of(
            r#"
            upstreams {
                upstream "b" {
                    targets {
                        target { address "127.0.0.1:3000"; weight 3 }
                        target { address "127.0.0.1:3001" }
                    }
                }
            }
            "#,
            "b",
        );
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].address, "127.0.0.1:3000");
        assert_eq!(t[0].weight, 3);
        assert_eq!(t[1].address, "127.0.0.1:3001");
        assert_eq!(t[1].weight, 1);
    }

    #[test]
    fn test_target_block_form_without_wrapper() {
        let t = targets_of(
            r#"upstreams { upstream "b" { target { address "10.0.0.1:80" } } }"#,
            "b",
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "10.0.0.1:80");
    }

    #[test]
    fn test_target_address_property_form() {
        let t = targets_of(
            r#"upstreams { upstream "b" { target address="10.0.0.1:80" weight=5 } }"#,
            "b",
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "10.0.0.1:80");
        assert_eq!(t[0].weight, 5);
    }

    #[test]
    fn test_upstream_address_shorthand() {
        let t = targets_of(
            r#"upstreams { upstream "b" { address "10.0.0.1:80" } }"#,
            "b",
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].address, "10.0.0.1:80");
    }

    #[test]
    fn test_upstream_no_target_errors() {
        let err = parse_kdl_upstreams(r#"upstreams { upstream "b" { } }"#).unwrap_err();
        assert!(err.to_string().contains("at least one target"));
    }

    #[test]
    fn test_parse_upstream_tls_full() {
        let kdl = r#"
        upstreams {
            upstream "secure-backend" {
                target "10.0.0.1:8443"
                tls {
                    sni "backend.example.com"
                    insecure-skip-verify #false
                    client-cert "/path/to/client.crt"
                    client-key "/path/to/client.key"
                    ca-cert "/path/to/ca.crt"
                }
            }
        }
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("secure-backend").unwrap();

        assert!(upstream.tls.is_some());
        let tls = upstream.tls.as_ref().unwrap();

        assert_eq!(tls.sni, Some("backend.example.com".to_string()));
        assert!(!tls.insecure_skip_verify);
        assert_eq!(tls.client_cert, Some(PathBuf::from("/path/to/client.crt")));
        assert_eq!(tls.client_key, Some(PathBuf::from("/path/to/client.key")));
        assert_eq!(tls.ca_cert, Some(PathBuf::from("/path/to/ca.crt")));
    }

    #[test]
    fn test_parse_upstream_tls_minimal() {
        let kdl = r#"
        upstreams {
            upstream "simple-tls" {
                target "10.0.0.1:443"
                tls {
                    sni "api.example.com"
                }
            }
        }
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("simple-tls").unwrap();

        assert!(upstream.tls.is_some());
        let tls = upstream.tls.as_ref().unwrap();

        assert_eq!(tls.sni, Some("api.example.com".to_string()));
        assert!(!tls.insecure_skip_verify); // default
        assert!(tls.client_cert.is_none());
        assert!(tls.client_key.is_none());
        assert!(tls.ca_cert.is_none());
    }

    #[test]
    fn test_parse_upstream_tls_insecure() {
        let kdl = r#"
        upstreams {
            upstream "dev-backend" {
                target "localhost:8443"
                tls {
                    insecure-skip-verify #true
                }
            }
        }
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("dev-backend").unwrap();

        assert!(upstream.tls.is_some());
        let tls = upstream.tls.as_ref().unwrap();

        assert!(tls.insecure_skip_verify);
        assert!(tls.sni.is_none());
    }

    #[test]
    fn test_parse_upstream_no_tls() {
        let kdl = r#"
        upstreams {
            upstream "plain-http" {
                target "10.0.0.1:8080"
            }
        }
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("plain-http").unwrap();

        assert!(upstream.tls.is_none());
    }

    #[test]
    fn test_parse_upstream_tls_mtls_only() {
        let kdl = r#"
        upstreams {
            upstream "mtls-backend" {
                target "10.0.0.1:443"
                tls {
                    client-cert "/certs/client.pem"
                    client-key "/certs/client-key.pem"
                }
            }
        }
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("mtls-backend").unwrap();

        assert!(upstream.tls.is_some());
        let tls = upstream.tls.as_ref().unwrap();

        assert_eq!(tls.client_cert, Some(PathBuf::from("/certs/client.pem")));
        assert_eq!(tls.client_key, Some(PathBuf::from("/certs/client-key.pem")));
        assert!(tls.sni.is_none());
        assert!(tls.ca_cert.is_none());
    }

    /// circuit-breaker stanza present, all values normally set, use those values
    /// Retain this test here to ensure block parser works
    #[test]
    fn test_parse_circuit_breaker_normal() {
        let kdl = r#"
        upstreams {
            upstream "test-cb" {
                target "10.0.0.1:80"
                circuit-breaker {
                    failure-threshold 1
                    success-threshold 2
                    timeout-seconds 4
                    half-open-max-requests 8
                }
            }
        } 
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("test-cb").unwrap();

        let cbconfig = upstream.circuit_breaker.unwrap();

        assert_eq!(cbconfig.failure_threshold, 1);
        assert_eq!(cbconfig.success_threshold, 2);
        assert_eq!(cbconfig.timeout_seconds, 4);
        assert_eq!(cbconfig.half_open_max_requests, 8);
    }

    /// circuit-breaker stanza missing, Option<CircuitBreakerConfig> will be None, upstream to set defaults
    #[test]
    fn test_parse_circuit_breaker_stanza_missing() {
        let kdl = r#"
        upstreams {
            upstream "test-cb" {
                target "10.0.0.1:80"
            }
        } 
        "#;

        let upstreams = parse_kdl_upstreams(kdl).unwrap();
        let upstream = upstreams.get("test-cb").unwrap();

        let cbconfig = upstream.circuit_breaker;

        assert!(cbconfig.is_none());
    }

    /// Helper: parse one upstream carrying the given discovery block.
    fn discovery_of(block: &str) -> Result<Option<UpstreamDiscovery>> {
        let kdl = format!("upstreams {{\n    upstream \"u\" {{\n{block}\n    }}\n}}");
        Ok(parse_kdl_upstreams(&kdl)?
            .get("u")
            .expect("upstream parsed")
            .discovery
            .clone())
    }

    #[test]
    fn discovery_defaults_are_applied_when_intervals_are_omitted() {
        let discovery = discovery_of("        discovery \"dns\" {\n            hostname \"api.internal\"\n            port 8080\n        }")
            .expect("parses")
            .expect("discovery present");
        assert_eq!(
            discovery,
            UpstreamDiscovery::Dns {
                hostname: "api.internal".to_string(),
                port: 8080,
                refresh_interval_secs: 30,
            }
        );
        assert_eq!(discovery.refresh_interval_secs(), 30);
        assert_eq!(discovery.kind(), "dns");
    }

    #[test]
    fn file_discovery_defaults_to_a_five_second_watch() {
        let discovery = discovery_of("        discovery \"file\" {\n            path \"/etc/zentinel/backends.txt\"\n        }")
            .expect("parses")
            .expect("discovery present");
        assert_eq!(discovery.refresh_interval_secs(), 5);
    }

    #[test]
    fn static_discovery_reports_no_refresh_interval() {
        let discovery = discovery_of("        discovery \"static\" {\n            backends \"10.0.0.1:80\" \"10.0.0.2:80\"\n        }")
            .expect("parses")
            .expect("discovery present");
        assert_eq!(
            discovery,
            UpstreamDiscovery::Static {
                backends: vec!["10.0.0.1:80".to_string(), "10.0.0.2:80".to_string()],
            }
        );
        assert_eq!(discovery.refresh_interval_secs(), 0);
    }

    #[test]
    fn zero_refresh_interval_is_rejected() {
        let message = discovery_of("        discovery \"dns\" {\n            hostname \"api.internal\"\n            port 8080\n            refresh-interval 0\n        }")
            .expect_err("zero would busy-loop the refresh task")
            .to_string();
        assert!(
            message.contains("refresh-interval"),
            "error should name the key, got: {message}"
        );
    }

    #[test]
    fn missing_required_setting_is_rejected() {
        let message = discovery_of("        discovery \"dns\" {\n            port 8080\n        }")
            .expect_err("dns discovery needs a hostname")
            .to_string();
        assert!(
            message.contains("hostname"),
            "error should name the missing key, got: {message}"
        );
    }

    #[test]
    fn unknown_discovery_type_is_rejected() {
        let message =
            discovery_of("        discovery \"etcd\" {\n            address \"x\"\n        }")
                .expect_err("etcd is not a discovery backend")
                .to_string();
        assert!(
            message.contains("etcd"),
            "error should name the unknown type, got: {message}"
        );
    }

    #[test]
    fn discovery_without_a_type_argument_is_rejected() {
        let message = discovery_of("        discovery {\n            hostname \"api\"\n        }")
            .expect_err("the backend has to be named")
            .to_string();
        assert!(
            message.contains("discovery"),
            "error should mention discovery, got: {message}"
        );
    }

    #[test]
    fn consul_optional_settings_round_trip() {
        let discovery = discovery_of(
            "        discovery \"consul\" {\n            address \"http://consul:8500\"\n            service \"api\"\n            datacenter \"dc2\"\n            only-passing #false\n            refresh-interval 15\n            tag \"canary\"\n        }",
        )
        .expect("parses")
        .expect("discovery present");
        assert_eq!(
            discovery,
            UpstreamDiscovery::Consul {
                address: "http://consul:8500".to_string(),
                service: "api".to_string(),
                datacenter: Some("dc2".to_string()),
                // Deliberately non-default: a value that silently reverted to
                // `true` here would be invisible in any test that used the
                // default.
                only_passing: false,
                refresh_interval_secs: 15,
                tag: Some("canary".to_string()),
            }
        );
    }

    #[test]
    fn an_upstream_may_have_discovery_instead_of_targets() {
        let upstreams = parse_kdl_upstreams(
            "upstreams {\n    upstream \"u\" {\n        discovery \"file\" {\n            path \"/tmp/b.txt\"\n        }\n    }\n}",
        )
        .expect("an upstream backed by discovery needs no static targets");
        assert!(upstreams["u"].targets.is_empty());
        assert!(upstreams["u"].discovery.is_some());
    }

    #[test]
    fn an_upstream_with_neither_targets_nor_discovery_is_rejected() {
        let message = parse_kdl_upstreams(
            "upstreams {\n    upstream \"u\" {\n        load-balancing \"round-robin\"\n    }\n}",
        )
        .expect_err("nothing to route to")
        .to_string();
        assert!(
            message.contains("target") && message.contains("discovery"),
            "error should offer both ways out, got: {message}"
        );
    }

    /// Unknown values keep today's fallback and are reported (#521).
    mod ignored_values {
        use super::*;

        fn upstream(body: &str) -> UpstreamConfig {
            let kdl =
                format!("upstreams {{ upstream \"b\" {{ target \"127.0.0.1:1\"\n{body} }} }}");
            parse_kdl_upstreams(&kdl).unwrap().remove("b").unwrap()
        }

        fn upstream_node(body: &str) -> kdl::KdlDocument {
            format!("upstream \"b\" {{ target \"127.0.0.1:1\"\n{body} }}")
                .parse()
                .unwrap()
        }

        /// Route-level strategies accept both spellings; this one silently
        /// turned the hyphenated name into round robin.
        #[test]
        fn hyphenated_algorithm_names_are_accepted() {
            for (name, expected) in [
                (
                    "least-connections",
                    LoadBalancingAlgorithm::LeastConnections,
                ),
                ("ip-hash", LoadBalancingAlgorithm::IpHash),
                ("consistent-hash", LoadBalancingAlgorithm::ConsistentHash),
                (
                    "power-of-two-choices",
                    LoadBalancingAlgorithm::PowerOfTwoChoices,
                ),
                ("peak-ewma", LoadBalancingAlgorithm::PeakEwma),
                (
                    "weighted-least-connections",
                    LoadBalancingAlgorithm::WeightedLeastConnections,
                ),
                ("weighted-round-robin", LoadBalancingAlgorithm::Weighted),
                (
                    "Least_Connections",
                    LoadBalancingAlgorithm::LeastConnections,
                ),
            ] {
                let config = upstream(&format!("load-balancing \"{name}\""));
                assert_eq!(config.load_balancing, expected, "{name}");
            }
        }

        #[test]
        fn every_listed_algorithm_name_parses() {
            for name in LOAD_BALANCING_NAMES {
                assert!(parse_load_balancing(name).is_some(), "{name}");
            }
        }

        #[test]
        fn an_unknown_algorithm_keeps_round_robin_and_is_reported() {
            let config = upstream(r#"load-balancing "totally_bogus""#);
            assert_eq!(config.load_balancing, LoadBalancingAlgorithm::RoundRobin);

            let doc = upstream_node(r#"load-balancing "least-conections""#);
            let problem = resolve_load_balancing(doc.nodes().first().unwrap(), "b")
                .1
                .expect("an unknown algorithm should be reported");
            assert!(problem.contains("is being ignored"), "{problem}");
            assert!(
                problem.contains("Did you mean 'least_connections'?"),
                "{problem}"
            );
        }

        #[test]
        fn known_and_absent_algorithms_are_not_reported() {
            for body in [
                "load-balancing \"p2c\"",
                "load-balancing \"least-connections\"",
                "",
            ] {
                let doc = upstream_node(body);
                assert_eq!(
                    resolve_load_balancing(doc.nodes().first().unwrap(), "b").1,
                    None
                );
            }
        }

        #[test]
        fn an_unknown_health_check_type_keeps_tcp_and_is_reported() {
            let body = r#"health-check { type "htttp" { path "/healthz" } }"#;
            let config = upstream(body);
            assert!(matches!(
                config.health_check.unwrap().check_type,
                HealthCheckType::Tcp
            ));

            let doc = upstream_node(body);
            let check = doc.nodes()[0]
                .children()
                .unwrap()
                .get("health-check")
                .unwrap();
            let problem = health_check_type_problem(check, "b").expect("should be reported");
            assert!(problem.contains("is being ignored"), "{problem}");
            assert!(problem.contains("Did you mean 'http'?"), "{problem}");
        }

        #[test]
        fn known_health_check_types_are_not_reported() {
            for name in ["tcp", "http", "HTTP", "grpc", "inference", "mcp"] {
                let doc = upstream_node(&format!("health-check {{ type \"{name}\" }}"));
                let check = doc.nodes()[0]
                    .children()
                    .unwrap()
                    .get("health-check")
                    .unwrap();
                assert_eq!(health_check_type_problem(check, "b"), None, "{name}");
            }
        }
    }

    /// #614: `h2c #true` and the HTTP version settings it must agree with.
    /// Read the struct back for the accepted cases; the rejected ones must
    /// fail to load rather than be served over HTTP/1.1.
    mod h2c {
        use super::*;

        fn parse(body: &str) -> Result<HttpVersionConfig> {
            parse_kdl_upstreams(&format!(
                r#"upstreams {{
                    upstream "b" {{
                        target "127.0.0.1:9000"
                        {body}
                    }}
                }}"#
            ))
            .map(|u| u.get("b").unwrap().http_version.clone())
        }

        fn error_of(body: &str) -> String {
            format!("{:#}", parse(body).expect_err("should be rejected"))
        }

        #[test]
        fn h2c_is_read_and_off_by_default() {
            assert!(parse("h2c #true").unwrap().h2c);
            assert!(!parse("h2c #false").unwrap().h2c);
            assert!(!parse("").unwrap().h2c);
            let v = parse("h2c #true\nhttp-version { min-version 2; max-h2-streams 50; }").unwrap();
            assert!(v.h2c);
            assert_eq!(v.max_h2_streams, 50);
        }

        #[test]
        fn h2c_that_is_not_a_boolean_is_rejected() {
            for value in [r#""yes""#, "1", ""] {
                let e = error_of(&format!("h2c {value}"));
                assert!(e.contains("'h2c' takes #true or #false"), "{value}: {e}");
            }
        }

        #[test]
        fn h2c_with_tls_is_rejected() {
            let e = error_of("h2c #true\ntls { sni \"b\" }");
            assert!(e.contains("cannot be combined with a 'tls' block"), "{e}");
        }

        #[test]
        fn h2c_with_an_http1_range_is_rejected() {
            let e = error_of("h2c #true\nhttp-version { max-version 1; }");
            assert!(e.contains("allows at most HTTP/1"), "{e}");
            let e = error_of("h2c #true\nhttp-version { min-version 1; }");
            assert!(e.contains("never falls back to HTTP/1.1"), "{e}");
        }

        /// Used to be accepted and served over HTTP/1.1.
        #[test]
        fn an_http2_only_range_on_a_plain_upstream_needs_h2c() {
            let e = error_of("http-version { min-version 2; }");
            assert!(e.contains("Add 'h2c #true'"), "{e}");
            // With TLS it is negotiated by ALPN, as before.
            assert!(parse("tls { sni \"b\" }\nhttp-version { min-version 2; }").is_ok());
            // The default range on a plain upstream stays HTTP/1.1.
            assert!(parse("http-version { max-version 2; }").is_ok());
        }
    }
}
