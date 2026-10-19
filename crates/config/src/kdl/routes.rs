//! Route KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{trace, warn};

use zentinel_common::budget::{
    BudgetPeriod, CostAttributionConfig, ModelPricing, TokenBudgetConfig,
};

use crate::agentic::{A2aConfig, McpConfig, McpUpstream, UninspectableBody, UnknownMethods};
use crate::filters::RateLimitKey;
use crate::{kdl::retrypolicy_helper::parse_retry_policy, routes::*};
use zentinel_common::types::ByteSize;

use super::helpers::{
    get_bool_entry, get_first_arg_string, get_float_entry, get_int_entry, get_string_entry,
};

/// Recognized child node names inside a `route` block.
/// Any child node not in this set will produce a warning during parsing.
pub(crate) const RECOGNIZED_ROUTE_CHILDREN: &[&str] = &[
    "matches",
    "priority",
    "upstream",
    "static-files",
    "api-schema",
    "inference",
    "filters",
    "builtin-handler",
    "cache",
    "shadow",
    "waf-enabled",
    "websocket",
    "websocket-inspection",
    "fallback",
    "policies",
    "service-type",
    "retry-policy",
    "mcp",
    "a2a",
];

/// Parse routes configuration block
pub fn parse_routes(node: &kdl::KdlNode) -> Result<Vec<RouteConfig>> {
    trace!("Parsing routes configuration block");
    let mut routes = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "route" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!("Route requires an ID argument, e.g., route \"api\" {{ ... }}")
                })?;

                trace!(route_id = %id, "Parsing route");

                // Parse matches
                let matches = parse_match_conditions(child)?;

                // Parse priority
                let (priority, problem) = resolve_priority(child, &id);
                if let Some(problem) = problem {
                    warn!("{}", problem);
                }

                // Parse upstream
                let upstream = parse_upstream_ref(child);

                // Parse static-files
                let static_files = parse_static_file_config_opt(child)?;

                // Parse api-schema
                let api_schema = parse_api_schema_config_opt(child)?;

                // Parse inference config
                let inference = parse_inference_config_opt(child)?;

                // Parse filters
                let filters = parse_route_filter_refs(child)?;

                let retry_policy = child
                    .children()
                    .and_then(|c| {
                        c.nodes()
                            .iter()
                            .find(|n| n.name().value() == "retry-policy")
                    })
                    .map(parse_retry_policy)
                    .transpose()?;

                // Parse builtin-handler
                let (builtin_handler, problem) = resolve_builtin_handler(child, &id);
                if let Some(problem) = problem {
                    warn!("{}", problem);
                }

                // Parse cache configuration
                let cache_config = parse_cache_config_opt(child)?;

                // Parse shadow (traffic mirroring) configuration
                let shadow = parse_shadow_config_opt(child)?;

                // Determine service type
                let (service_type, problem) = resolve_service_type(child, &id);
                if let Some(problem) = problem {
                    warn!("{}", problem);
                }

                trace!(
                    route_id = %id,
                    service_type = ?service_type,
                    match_count = matches.len(),
                    filter_count = filters.len(),
                    has_upstream = upstream.is_some(),
                    "Parsed route"
                );

                // Parse policies block (request-headers, response-headers, etc.)
                let (request_headers, response_headers) = parse_route_header_policies(child)?;

                // Warn about unrecognized child nodes
                if let Some(route_children) = child.children() {
                    for child_node in route_children.nodes() {
                        let name = child_node.name().value();
                        if !RECOGNIZED_ROUTE_CHILDREN.contains(&name) {
                            warn!(
                                route_id = %id,
                                directive = %name,
                                "Unrecognized directive in route block (will be ignored). \
                                 Agents must be configured in a top-level \"agents\" block \
                                 and referenced via filters."
                            );
                        }
                    }
                }

                // Every field is spelled out. This used to end in
                // `..RoutePolicies::default()`, which quietly left six of the
                // nine fields at their defaults no matter what the config
                // said — `failure-mode "open"` ran fail-closed, per-route
                // timeouts and rate limits never applied. Adding a field to
                // RoutePolicies should break this line, not slip through it.
                let settings = parse_route_policy_settings(child)?;
                let policies = RoutePolicies {
                    request_headers,
                    response_headers,
                    cache: cache_config,
                    timeout_secs: settings.timeout_secs,
                    max_body_size: settings.max_body_size,
                    rate_limit: settings.rate_limit,
                    failure_mode: settings.failure_mode,
                };

                routes.push(RouteConfig {
                    id,
                    priority,
                    matches,
                    upstream,
                    service_type,
                    policies,
                    filters,
                    builtin_handler,
                    waf_enabled: get_bool_entry(child, "waf-enabled").unwrap_or(false),
                    retry_policy,
                    static_files,
                    api_schema,
                    inference,
                    mcp: parse_optional_block(child, "mcp", parse_mcp_config)?,
                    a2a: parse_optional_block(child, "a2a", parse_a2a_config)?,
                    error_pages: None,
                    websocket: get_bool_entry(child, "websocket").unwrap_or(false),
                    websocket_inspection: get_bool_entry(child, "websocket-inspection")
                        .unwrap_or(false),
                    shadow,
                    fallback: parse_fallback_config_opt(child)?,
                });
            }
        }
    }

    trace!(route_count = routes.len(), "Finished parsing routes");
    Ok(routes)
}

/// Match condition node names recognized inside a `matches` block, paired
/// with a usage example for error messages.
const VALID_MATCH_CONDITIONS: &[(&str, &str)] = &[
    ("path", "path \"/api/v1/users\""),
    ("path-prefix", "path-prefix \"/api\""),
    ("path-regex", "path-regex \"^/api/v[0-9]+/\""),
    ("host", "host \"example.com\" (or \"*.example.com\")"),
    (
        "header",
        "header \"x-version\" (or header \"x-version\" \"2\")",
    ),
    ("method", "method \"GET\" (or method \"GET\" \"POST\")"),
    (
        "query-param",
        "query-param \"debug\" (or query-param \"debug\" \"true\")",
    ),
];

/// Whether `name` is a condition a `matches` block accepts.
pub(crate) fn is_match_condition(name: &str) -> bool {
    VALID_MATCH_CONDITIONS.iter().any(|(n, _)| *n == name)
}

/// How many leading arguments of a match condition are its own values, before
/// anything after them can only be a mistake.
///
/// `header` and `query-param` take a name and an optional value, so their
/// second argument may legitimately be any string, including one spelled like
/// a condition (`header "x-kind" "path"`). `method` takes a list, but no HTTP
/// method is spelled like a condition, so only its first argument is exempt.
/// The lint uses this to find run-together lines such as
/// `path-prefix "/api" host "a.com"`, where `host` is read as a second argument
/// and dropped.
pub(crate) fn match_condition_own_args(name: &str) -> usize {
    match name {
        "header" | "query-param" => 2,
        _ => 1,
    }
}

/// Build the error for a match condition whose first argument is missing or
/// not a string (e.g. `path-prefix` with no value, or `method 42`).
fn match_condition_value_error(route_id: &str, match_node: &kdl::KdlNode) -> anyhow::Error {
    let name = match_node.name().value();
    let example = VALID_MATCH_CONDITIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, ex)| *ex)
        .unwrap_or("path-prefix \"/api\"");
    match match_node.entries().first() {
        Some(entry) => anyhow::anyhow!(
            "Route '{}': match condition '{}' has a non-string value {}.\n\
             Expected a quoted string, e.g., {}",
            route_id,
            name,
            entry.value(),
            example
        ),
        None => anyhow::anyhow!(
            "Route '{}': match condition '{}' is missing its value.\n\
             Expected a quoted string, e.g., {}",
            route_id,
            name,
            example
        ),
    }
}

fn parse_match_conditions(node: &kdl::KdlNode) -> Result<Vec<MatchCondition>> {
    let mut matches = Vec::new();
    // Route ID for error context; parse_routes has already required it.
    let route_id = get_first_arg_string(node).unwrap_or_else(|| "<unnamed>".to_string());

    if let Some(route_children) = node.children() {
        if let Some(matches_node) = route_children.get("matches") {
            if let Some(match_children) = matches_node.children() {
                for match_node in match_children.nodes() {
                    let name = match_node.name().value();
                    match name {
                        "path-prefix" => {
                            let prefix = get_first_arg_string(match_node).ok_or_else(|| {
                                match_condition_value_error(&route_id, match_node)
                            })?;
                            matches.push(MatchCondition::PathPrefix(prefix));
                        }
                        "path" => {
                            let path = get_first_arg_string(match_node).ok_or_else(|| {
                                match_condition_value_error(&route_id, match_node)
                            })?;
                            matches.push(MatchCondition::Path(path));
                        }
                        "path-regex" => {
                            let regex = get_first_arg_string(match_node).ok_or_else(|| {
                                match_condition_value_error(&route_id, match_node)
                            })?;
                            matches.push(MatchCondition::PathRegex(regex));
                        }
                        "host" => {
                            let host = get_first_arg_string(match_node).ok_or_else(|| {
                                match_condition_value_error(&route_id, match_node)
                            })?;
                            matches.push(MatchCondition::Host(host));
                        }
                        "header" => {
                            let entries: Vec<_> = match_node.entries().iter().collect();
                            let name = entries
                                .first()
                                .and_then(|e| e.value().as_string())
                                .ok_or_else(|| {
                                    match_condition_value_error(&route_id, match_node)
                                })?;
                            let value = entries
                                .get(1)
                                .and_then(|e| e.value().as_string())
                                .map(|s| s.to_string());
                            matches.push(MatchCondition::Header {
                                name: name.to_string(),
                                value,
                            });
                        }
                        "method" => {
                            // `method "GET" "POST"` means either. Only the first
                            // argument used to be read, so the route silently
                            // stopped matching POST; every argument is now kept,
                            // and the matchers already accept any of a list.
                            get_first_arg_string(match_node).ok_or_else(|| {
                                match_condition_value_error(&route_id, match_node)
                            })?;
                            let methods: Vec<String> = match_node
                                .entries()
                                .iter()
                                .filter(|e| e.name().is_none())
                                .filter_map(|e| e.value().as_string().map(str::to_string))
                                .collect();
                            matches.push(MatchCondition::Method(methods));
                        }
                        "query-param" => {
                            let entries: Vec<_> = match_node.entries().iter().collect();
                            let name = entries
                                .first()
                                .and_then(|e| e.value().as_string())
                                .ok_or_else(|| {
                                    match_condition_value_error(&route_id, match_node)
                                })?;
                            let value = entries
                                .get(1)
                                .and_then(|e| e.value().as_string())
                                .map(|s| s.to_string());
                            matches.push(MatchCondition::QueryParam {
                                name: name.to_string(),
                                value,
                            });
                        }
                        other => {
                            // A silently dropped match condition would make the
                            // route match MORE requests than intended, so a typo
                            // here must be a hard error, not a warning.
                            let valid_names: Vec<&str> =
                                VALID_MATCH_CONDITIONS.iter().map(|(n, _)| *n).collect();
                            let suggestion = super::helpers::did_you_mean(other, &valid_names)
                                .map(|s| format!(" Did you mean '{}'?", s))
                                .unwrap_or_default();
                            return Err(anyhow::anyhow!(
                                "Route '{}': unknown match condition '{}'.{}\n\
                                 Valid match conditions are: {}",
                                route_id,
                                other,
                                suggestion,
                                valid_names.join(", ")
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(matches)
}

/// Work out a route's priority, and whether its `priority` value was ignored.
///
/// Accepts an integer (`priority 100`) or a named alias, case-insensitively:
/// `"low"`, `"normal"`, `"high"`, `"critical"`. No value means normal.
///
/// Anything that is neither an integer nor one of the aliases — `"urgent"`,
/// `1.5` — falls back to normal. That is kept, because configs carrying such a
/// value have been loading and must keep doing so, but the value comes back as
/// a problem for `zentinel lint` (through `validate::unknown_keys`) instead of
/// vanishing: a route meant to win over its neighbours silently did not.
pub(crate) fn resolve_priority(
    node: &kdl::KdlNode,
    route_id: &str,
) -> (zentinel_common::types::Priority, Option<String>) {
    use zentinel_common::types::Priority;

    let Some(value) = node
        .children()
        .and_then(|c| c.get("priority"))
        .and_then(|n| n.entries().first())
        .map(|e| e.value())
    else {
        return (Priority::NORMAL, None);
    };

    // Integer form: `priority 100`
    if let Some(n) = value.as_integer() {
        return (Priority(n as i32), None);
    }

    // Named string alias: `priority "high"`
    let alias = value.as_string().map(str::to_ascii_lowercase);
    // Quoted, as it would be written; KDL's own display drops the quotes.
    let written = match value.as_string() {
        Some(s) => format!("\"{s}\""),
        None => value.to_string(),
    };
    match alias.as_deref() {
        Some("critical") => (Priority::CRITICAL, None),
        Some("high") => (Priority::HIGH, None),
        Some("low") => (Priority::LOW, None),
        Some("normal") => (Priority::NORMAL, None),
        _ => (
            Priority::NORMAL,
            Some(format!(
                "'priority {}' on route '{}' is not a priority (low, normal, high, critical, \
                 or an integer) and is being ignored; the route has normal priority.",
                written, route_id
            )),
        ),
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

/// Every name `parse_builtin_handler` accepts, for messages and suggestions.
const BUILTIN_HANDLER_NAMES: &[&str] = &[
    "status",
    "health",
    "metrics",
    "not-found",
    "config",
    "upstreams",
    "cache-purge",
    "cache-stats",
];

/// Work out a route's builtin handler, and whether its `builtin-handler` value
/// was ignored.
///
/// A name that is not a handler leaves the route without one, so it is served
/// as a plain web route — usually with no upstream, so every request fails.
/// Loading such a config keeps working, as it always has; the problem goes to
/// `zentinel lint` through `validate::unknown_keys`.
pub(crate) fn resolve_builtin_handler(
    node: &kdl::KdlNode,
    route_id: &str,
) -> (Option<BuiltinHandler>, Option<String>) {
    let Some(name) = get_string_entry(node, "builtin-handler") else {
        return (None, None);
    };
    if let Some(handler) = parse_builtin_handler(&name) {
        return (Some(handler), None);
    }
    let suggestion = super::helpers::did_you_mean(&name, BUILTIN_HANDLER_NAMES)
        .map(|s| format!(" Did you mean '{}'?", s))
        .unwrap_or_default();
    (
        None,
        Some(format!(
            "'builtin-handler \"{}\"' on route '{}' is not a builtin handler ({}) and is \
             being ignored.{}",
            name,
            route_id,
            BUILTIN_HANDLER_NAMES.join(", "),
            suggestion
        )),
    )
}

fn parse_builtin_handler(name: &str) -> Option<BuiltinHandler> {
    match name {
        "status" => Some(BuiltinHandler::Status),
        "health" => Some(BuiltinHandler::Health),
        "metrics" => Some(BuiltinHandler::Metrics),
        "not-found" | "not_found" => Some(BuiltinHandler::NotFound),
        "config" => Some(BuiltinHandler::Config),
        "upstreams" => Some(BuiltinHandler::Upstreams),
        "cache-purge" | "cache_purge" => Some(BuiltinHandler::CachePurge),
        "cache-stats" | "cache_stats" => Some(BuiltinHandler::CacheStats),
        _ => None,
    }
}

/// Work out a route's service type, and whether its `service-type` was ignored.
///
/// The type is implied by the route's blocks: `static-files`, a recognised
/// `builtin-handler`, `api-schema` or `inference`, and `web` otherwise. For a
/// long time that was all, and `service-type` was accepted and never read: a
/// route documented as `service-type "api"` served HTML error pages.
///
/// An explicit value now applies where the blocks allow it. `api` needs no
/// block, since it only changes how the route responds. A value that is not a
/// type, or that the blocks contradict, keeps the implied type and comes back
/// as a problem: logged at load, and reported by `zentinel lint` through
/// `validate::unknown_keys`. It is not an error, because configs that carried
/// such a value have been loading fine and must keep doing so.
pub(crate) fn resolve_service_type(
    node: &kdl::KdlNode,
    route_id: &str,
) -> (ServiceType, Option<String>) {
    let has = |name: &str| node.children().and_then(|c| c.get(name)).is_some();
    let implied = if has("static-files") {
        ServiceType::Static
    } else if get_string_entry(node, "builtin-handler")
        .and_then(|s| parse_builtin_handler(&s))
        .is_some()
    {
        ServiceType::Builtin
    } else if has("api-schema") {
        ServiceType::Api
    } else if has("inference") {
        ServiceType::Inference
    } else {
        ServiceType::Web
    };

    let Some(value) = get_string_entry(node, "service-type") else {
        return (implied, None);
    };

    let explicit = match value.as_str() {
        "web" => ServiceType::Web,
        "api" => ServiceType::Api,
        "static" => ServiceType::Static,
        "builtin" => ServiceType::Builtin,
        "inference" => ServiceType::Inference,
        _ => {
            return (
                implied,
                Some(format!(
                    "'service-type \"{}\"' on route '{}' is not a service type (web, api, \
                     static, builtin, inference) and is being ignored.",
                    value, route_id
                )),
            )
        }
    };

    if explicit == implied || (explicit == ServiceType::Api && implied == ServiceType::Web) {
        return (explicit, None);
    }

    let requirement = match explicit {
        ServiceType::Static => "needs a static-files block",
        ServiceType::Builtin => "needs a builtin-handler",
        ServiceType::Inference => "needs an inference block",
        ServiceType::Web | ServiceType::Api => {
            "cannot apply to a route with static-files, a builtin-handler or inference"
        }
    };
    let problem = format!(
        "'service-type \"{}\"' on route '{}' {}; the route is served as '{}' and the \
         setting is being ignored.",
        value,
        route_id,
        requirement,
        format!("{:?}", implied).to_lowercase()
    );
    (implied, Some(problem))
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

/// Parse route-level header policies from the `policies` block.
///
/// Example KDL:
/// ```kdl
/// policies {
///     request-headers {
///         rename {
///             X-Old-Name "X-New-Name"
///         }
///         set {
///             X-Custom "value"
///         }
///         add {
///             X-Extra "extra"
///         }
///         remove "X-Internal"
///     }
///     response-headers {
///         set {
///             X-Powered-By "Zentinel"
///         }
///     }
/// }
/// ```
/// The settings a `policies` block can carry beyond header rewriting and
/// caching, which are parsed separately.
struct RoutePolicySettings {
    timeout_secs: Option<u64>,
    max_body_size: Option<ByteSize>,
    rate_limit: Option<RateLimitPolicy>,
    failure_mode: FailureMode,
}

/// Parse the `policies` block of a route.
///
/// Absent `policies`, or a `policies` block that sets none of these, yields
/// defaults — notably `failure_mode: Closed`, which is the safe direction: a
/// route only becomes fail-open when its config asks for it in as many words.
/// Parse an optional named child block through a parser function.
fn parse_optional_block<T>(
    node: &kdl::KdlNode,
    name: &str,
    parse: impl Fn(&kdl::KdlNode) -> Result<T>,
) -> Result<Option<T>> {
    node.children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == name))
        .map(parse)
        .transpose()
}

/// A node's `name=value` property, as a string.
///
/// The shared helpers read *child nodes*; this reads a property on the node
/// itself, which is the shape `upstream "docs" prefix="docs"` uses.
fn get_string_prop(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some(name))
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Parse the `upstreams` block inside `mcp`.
///
/// ```kdl
/// upstreams {
///     upstream "docs" prefix="docs"
///     upstream "warehouse" prefix="warehouse" path="/mcp"
/// }
/// ```
fn parse_mcp_upstreams(node: &kdl::KdlNode) -> Result<Vec<McpUpstream>> {
    let mut out: Vec<McpUpstream> = Vec::new();

    let Some(children) = node.children() else {
        return Ok(out);
    };

    for child in children.nodes() {
        if child.name().value() != "upstream" {
            return Err(anyhow::anyhow!(
                "Unknown node '{}' in mcp upstreams block. Expected 'upstream'",
                child.name().value()
            ));
        }

        let upstream = get_first_arg_string(child).ok_or_else(|| {
            anyhow::anyhow!("mcp upstream needs a name: upstream \"docs\" prefix=\"docs\"")
        })?;

        // Required, never derived from the upstream name. A tool's name is what
        // a model reasons about; deriving it would rename every tool when an
        // upstream is renamed.
        let prefix = get_string_prop(child, "prefix").ok_or_else(|| {
            anyhow::anyhow!(
                "mcp upstream '{upstream}' needs a prefix: upstream \"{upstream}\" prefix=\"...\""
            )
        })?;

        if prefix.contains('.') {
            return Err(anyhow::anyhow!(
                "mcp upstream '{upstream}' prefix '{prefix}' contains '.', which separates a \
                 prefix from a tool name and would make routing ambiguous"
            ));
        }
        if prefix.is_empty() {
            return Err(anyhow::anyhow!(
                "mcp upstream '{upstream}' has an empty prefix"
            ));
        }
        if let Some(clash) = out.iter().find(|u| u.prefix == prefix) {
            return Err(anyhow::anyhow!(
                "mcp upstreams '{}' and '{upstream}' share the prefix '{prefix}'; every tool \
                 from one would be indistinguishable from the other's",
                clash.upstream
            ));
        }

        out.push(McpUpstream {
            path: get_string_prop(child, "path").unwrap_or_else(|| "/".to_string()),
            upstream,
            prefix,
        });
    }

    Ok(out)
}

/// Parse a route's `mcp` block.
///
/// ```kdl
/// mcp {
///     require-validated-version #true
///     filter-tool-list #true
///     on-uninspectable-body "deny"
///     methods {
///         allow "tools/call" "tools/list"
///         deny "resources/read"
///     }
///     tools {
///         allow "get_weather" "search_docs"
///         deny "execute_sql"
///     }
/// }
/// ```
fn parse_mcp_config(node: &kdl::KdlNode) -> Result<McpConfig> {
    let mut config = McpConfig::default();

    if let Some(value) = get_bool_entry(node, "require-validated-version") {
        config.require_validated_version = value;
    }

    if let Some(value) = get_bool_entry(node, "validate-param-headers") {
        config.validate_param_headers = value;
    }

    if let Some(value) = get_bool_entry(node, "filter-tool-list") {
        config.filter_tool_list = value;
    }

    config.session_key = get_string_entry(node, "session-key");

    config.on_uninspectable_body = match get_string_entry(node, "on-uninspectable-body").as_deref()
    {
        None => UninspectableBody::default(),
        Some("deny") => UninspectableBody::Deny,
        Some("allow") => UninspectableBody::Allow,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown on-uninspectable-body '{other}'. Valid values: deny, allow"
            ))
        }
    };

    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "methods" => {
                    let (allow, deny) = parse_allow_deny(child)?;
                    config.allowed_methods = allow;
                    config.denied_methods = deny;
                }
                "tools" => {
                    let (allow, deny) = parse_allow_deny(child)?;
                    config.allowed_tools = allow;
                    config.denied_tools = deny;
                }
                "upstreams" => {
                    config.upstreams = parse_mcp_upstreams(child)?;
                }
                // Scalars already read above; anything else is a mistake worth
                // naming, since a silently ignored key in a security policy is
                // how a policy stops applying without anyone noticing.
                "require-validated-version"
                | "validate-param-headers"
                | "filter-tool-list"
                | "session-key"
                | "on-uninspectable-body" => {}
                other => {
                    return Err(anyhow::anyhow!(
                        "Unknown setting '{other}' in mcp block. Valid settings: \
                         require-validated-version, validate-param-headers, filter-tool-list, \
                         session-key, on-uninspectable-body, methods, tools, upstreams"
                    ))
                }
            }
        }
    }

    Ok(config)
}

/// Parse a route's `a2a` block.
///
/// ```kdl
/// a2a {
///     unknown-methods "allow"
///     deny-uninspectable-body #true
///     methods {
///         allow "GetTask" "ListTasks"
///         deny "CancelTask"
///     }
/// }
/// ```
fn parse_a2a_config(node: &kdl::KdlNode) -> Result<A2aConfig> {
    let mut config = A2aConfig::default();

    if let Some(value) = get_bool_entry(node, "deny-uninspectable-body") {
        config.deny_uninspectable_body = value;
    }

    config.unknown_methods = match get_string_entry(node, "unknown-methods").as_deref() {
        None => UnknownMethods::default(),
        Some("allow") => UnknownMethods::Allow,
        Some("deny") => UnknownMethods::Deny,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown unknown-methods '{other}'. Valid values: allow, deny"
            ))
        }
    };

    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "methods" => {
                    let (allow, deny) = parse_allow_deny(child)?;
                    config.allowed_methods = allow;
                    config.denied_methods = deny;
                }
                "unknown-methods" | "deny-uninspectable-body" => {}
                other => {
                    return Err(anyhow::anyhow!(
                        "Unknown setting '{other}' in a2a block. Valid settings: \
                         unknown-methods, deny-uninspectable-body, methods"
                    ))
                }
            }
        }
    }

    Ok(config)
}

/// Read `allow` and `deny` lists from a block.
///
/// Both take any number of string arguments. An `allow` with no entries is an
/// error rather than an empty allowlist: an empty allowlist means "unrestricted"
/// everywhere else in this config, so writing `allow` and getting the opposite
/// of a restriction is precisely the surprise worth refusing.
fn parse_allow_deny(node: &kdl::KdlNode) -> Result<(Vec<String>, Vec<String>)> {
    let mut allow = Vec::new();
    let mut deny = Vec::new();

    let Some(children) = node.children() else {
        return Ok((allow, deny));
    };

    for child in children.nodes() {
        let values: Vec<String> = child
            .entries()
            .iter()
            .filter(|entry| entry.name().is_none())
            .filter_map(|entry| entry.value().as_string().map(str::to_string))
            .collect();

        match child.name().value() {
            "allow" => {
                if values.is_empty() {
                    return Err(anyhow::anyhow!(
                        "'allow' with no entries would be read as no allowlist at all, \
                         permitting everything. Remove the line, or list what is permitted."
                    ));
                }
                allow.extend(values);
            }
            "deny" => {
                if values.is_empty() {
                    return Err(anyhow::anyhow!("'deny' needs at least one entry"));
                }
                deny.extend(values);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "Unknown entry '{other}'; expected 'allow' or 'deny'"
                ))
            }
        }
    }

    Ok((allow, deny))
}

fn parse_route_policy_settings(route: &kdl::KdlNode) -> Result<RoutePolicySettings> {
    let Some(policies) = route
        .children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "policies"))
    else {
        return Ok(RoutePolicySettings {
            timeout_secs: None,
            max_body_size: None,
            rate_limit: None,
            failure_mode: FailureMode::default(),
        });
    };

    let timeout_secs = get_int_entry(policies, "timeout-secs").map(|v| v as u64);

    // Accepts both `max-body-size "10MB"` and a plain byte count.
    let max_body_size = match get_string_entry(policies, "max-body-size") {
        Some(s) => Some(
            s.parse::<ByteSize>()
                .map_err(|e| anyhow::anyhow!("Invalid max-body-size '{s}': {e}"))?,
        ),
        None => get_int_entry(policies, "max-body-size").map(|v| ByteSize(v as usize)),
    };

    let failure_mode = match get_string_entry(policies, "failure-mode").as_deref() {
        Some("open") => FailureMode::Open,
        Some("closed") => FailureMode::Closed,
        None => FailureMode::default(),
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown failure-mode '{other}'. Valid modes: open, closed"
            ))
        }
    };

    let rate_limit = policies
        .children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "rate-limit"))
        .map(parse_route_rate_limit)
        .transpose()?;

    Ok(RoutePolicySettings {
        timeout_secs,
        max_body_size,
        rate_limit,
        failure_mode,
    })
}

/// Parse a route-level `rate-limit` block.
fn parse_route_rate_limit(node: &kdl::KdlNode) -> Result<RateLimitPolicy> {
    let requests_per_second = get_int_entry(node, "requests-per-second")
        .map(|v| v as u32)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Route rate-limit requires 'requests-per-second', e.g. requests-per-second 100"
            )
        })?;

    // A burst below the sustained rate would throttle below the configured
    // rate, which is never what an operator means by "burst".
    let burst = get_int_entry(node, "burst")
        .map(|v| v as u32)
        .unwrap_or(requests_per_second);

    let key = match get_string_entry(node, "key").as_deref() {
        None => RateLimitKey::default(),
        // Both separators are accepted: the shipped config writes
        // `key "client_ip"` while the filter-level parser documents
        // `client-ip`, and silently resolving a mismatch to the default is
        // how these settings go missing in the first place.
        Some("client-ip") | Some("client_ip") => RateLimitKey::ClientIp,
        Some("path") => RateLimitKey::Path,
        Some("route") => RateLimitKey::Route,
        Some("client-ip-and-path") | Some("client_ip_and_path") => RateLimitKey::ClientIpAndPath,
        Some(header) if header.starts_with("header:") => {
            let name = header.trim_start_matches("header:").trim();
            if name.is_empty() {
                return Err(anyhow::anyhow!(
                    "Rate limit key 'header:' needs a header name, e.g. key \"header:X-API-Key\""
                ));
            }
            RateLimitKey::Header(name.to_string())
        }
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown rate limit key '{other}'. Valid keys: client-ip, path, route, \
                 client-ip-and-path, or header:<name>"
            ))
        }
    };

    Ok(RateLimitPolicy {
        requests_per_second,
        burst,
        key,
    })
}

fn parse_route_header_policies(
    node: &kdl::KdlNode,
) -> Result<(HeaderModifications, HeaderModifications)> {
    let mut request_headers = HeaderModifications::default();
    let mut response_headers = HeaderModifications::default();

    if let Some(route_children) = node.children() {
        if let Some(policies_node) = route_children.get("policies") {
            if let Some(policy_children) = policies_node.children() {
                if let Some(req_node) = policy_children.get("request-headers") {
                    request_headers = parse_header_modifications(req_node)?;
                }
                if let Some(resp_node) = policy_children.get("response-headers") {
                    response_headers = parse_header_modifications(resp_node)?;
                }
            }
        }
    }

    Ok((request_headers, response_headers))
}

/// Parse a header modifications block (rename, set, add, remove).
fn parse_header_modifications(node: &kdl::KdlNode) -> Result<HeaderModifications> {
    let mut rename = HashMap::new();
    let mut set = HashMap::new();
    let mut add = HashMap::new();
    let mut remove = Vec::new();

    if let Some(children) = node.children() {
        if let Some(rename_node) = children.get("rename") {
            if let Some(rename_children) = rename_node.children() {
                for entry_node in rename_children.nodes() {
                    let old_name = entry_node.name().value().to_string();
                    if let Some(new_name) = get_first_arg_string(entry_node) {
                        rename.insert(old_name, new_name);
                    }
                }
            }
        }
        if let Some(set_node) = children.get("set") {
            if let Some(set_children) = set_node.children() {
                for entry_node in set_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        set.insert(name, value);
                    }
                }
            }
        }
        if let Some(add_node) = children.get("add") {
            if let Some(add_children) = add_node.children() {
                for entry_node in add_children.nodes() {
                    let name = entry_node.name().value().to_string();
                    if let Some(value) = get_first_arg_string(entry_node) {
                        add.insert(name, value);
                    }
                }
            }
        }
        if let Some(remove_node) = children.get("remove") {
            for entry in remove_node.entries() {
                if let Some(name) = entry.value().as_string() {
                    remove.push(name.to_string());
                }
            }
        }
    }

    Ok(HeaderModifications {
        rename,
        set,
        add,
        remove,
    })
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

/// Parse optional cache configuration from a route
fn parse_cache_config_opt(node: &kdl::KdlNode) -> Result<Option<RouteCacheConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(cache_node) = route_children.get("cache") {
            return Ok(Some(parse_cache_config(cache_node)?));
        }
    }
    Ok(None)
}

/// Parse cache configuration block
///
/// Example KDL:
/// ```kdl
/// cache {
///     enabled true
///     default-ttl-secs 3600
///     max-size-bytes 10485760
///     cache-private false
///     stale-while-revalidate-secs 60
///     stale-if-error-secs 300
///     cacheable-methods "GET" "HEAD"
///     cacheable-status-codes 200 203 204 206 300 301 308 404 410
///     vary-headers "Accept" "Accept-Encoding"
///     ignore-query-params "utm_source" "utm_medium"
/// }
/// ```
fn parse_cache_config(node: &kdl::KdlNode) -> Result<RouteCacheConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);
    let default_ttl_secs = get_int_entry(node, "default-ttl-secs").unwrap_or(3600) as u64;
    let max_size_bytes = get_int_entry(node, "max-size-bytes").unwrap_or(10 * 1024 * 1024) as usize;
    let cache_private = get_bool_entry(node, "cache-private").unwrap_or(false);
    let stale_while_revalidate_secs =
        get_int_entry(node, "stale-while-revalidate-secs").unwrap_or(60) as u64;
    let stale_if_error_secs = get_int_entry(node, "stale-if-error-secs").unwrap_or(300) as u64;

    // Parse cacheable methods (string arguments)
    let cacheable_methods = if let Some(children) = node.children() {
        if let Some(methods_node) = children.get("cacheable-methods") {
            methods_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            vec!["GET".to_string(), "HEAD".to_string()]
        }
    } else {
        vec!["GET".to_string(), "HEAD".to_string()]
    };

    // Parse cacheable status codes (integer arguments)
    let cacheable_status_codes = if let Some(children) = node.children() {
        if let Some(codes_node) = children.get("cacheable-status-codes") {
            codes_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                .collect()
        } else {
            vec![200, 203, 204, 206, 300, 301, 308, 404, 410]
        }
    } else {
        vec![200, 203, 204, 206, 300, 301, 308, 404, 410]
    };

    // Parse vary headers
    let vary_headers = if let Some(children) = node.children() {
        if let Some(vary_node) = children.get("vary-headers") {
            vary_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Parse ignore query params
    let ignore_query_params = if let Some(children) = node.children() {
        if let Some(ignore_node) = children.get("ignore-query-params") {
            ignore_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Parse exclude extensions (file extensions to skip caching)
    let exclude_extensions = if let Some(children) = node.children() {
        if let Some(ext_node) = children.get("exclude-extensions") {
            ext_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // Parse exclude paths (glob patterns to skip caching)
    let exclude_paths = if let Some(children) = node.children() {
        if let Some(paths_node) = children.get("exclude-paths") {
            paths_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    trace!(
        enabled = enabled,
        default_ttl = default_ttl_secs,
        max_size = max_size_bytes,
        "Parsed cache configuration"
    );

    Ok(RouteCacheConfig {
        enabled,
        default_ttl_secs,
        max_size_bytes,
        cache_private,
        stale_while_revalidate_secs,
        stale_if_error_secs,
        cacheable_methods,
        cacheable_status_codes,
        vary_headers,
        ignore_query_params,
        exclude_extensions,
        exclude_paths,
    })
}

/// Parse optional API schema configuration from a route
fn parse_api_schema_config_opt(node: &kdl::KdlNode) -> Result<Option<ApiSchemaConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(api_schema_node) = route_children.get("api-schema") {
            return Ok(Some(parse_api_schema_config(api_schema_node)?));
        }
    }
    Ok(None)
}

/// Parse API schema configuration block
///
/// Example KDL with external file:
/// ```kdl
/// api-schema {
///     schema-file "/etc/zentinel/schemas/api-v1.yaml"
///     validate-requests #true
///     validate-responses #false
///     strict-mode #false
/// }
/// ```
///
/// Example KDL with inline OpenAPI spec:
/// ```kdl
/// api-schema {
///     validate-requests #true
///     schema-content r#"
/// openapi: 3.0.0
/// info:
///   title: User API
///   version: 1.0.0
/// paths:
///   /api/users:
///     post:
///       requestBody:
///         content:
///           application/json:
///             schema:
///               type: object
///               required: [email, password]
///               properties:
///                 email: { type: string, format: email }
///                 password: { type: string, minLength: 8 }
///     "#
/// }
/// ```
///
/// Example KDL with inline JSON schema:
/// ```kdl
/// api-schema {
///     validate-requests #true
///     request-schema {
///         type "object"
///         properties {
///             email {
///                 type "string"
///             }
///             password {
///                 type "string"
///                 minLength 8
///             }
///         }
///         required "email" "password"
///     }
/// }
/// ```
/// Convert an inline KDL schema to JSON Schema.
///
/// `kdl_to_json` turns a node with one argument into a scalar, so
/// `required "email"` became `"required": "email"`, which JSON Schema rejects:
/// `required` and `enum` must be arrays however many entries they have. The
/// schema then failed to compile and the route ran unvalidated (#524).
fn schema_from_kdl(node: &kdl::KdlNode) -> Result<serde_json::Value> {
    let mut schema = super::kdl_to_json(node)?;
    normalize_schema_arrays(&mut schema);
    Ok(schema)
}

/// Wrap a scalar `required`, `enum` or `examples` in an array, recursively.
///
/// Recursion goes through subschemas only. Under `properties`,
/// `patternProperties`, `definitions` and `$defs` the keys are names, not
/// keywords, so a property called `required` is left alone and only its schema
/// is visited.
fn normalize_schema_arrays(schema: &mut serde_json::Value) {
    let serde_json::Value::Object(map) = schema else {
        return;
    };
    for (key, value) in map.iter_mut() {
        match key.as_str() {
            "required" | "enum" | "examples" if !value.is_array() && !value.is_object() => {
                *value = serde_json::Value::Array(vec![value.take()]);
            }
            "properties" | "patternProperties" | "definitions" | "$defs" => {
                if let serde_json::Value::Object(named) = value {
                    named.values_mut().for_each(normalize_schema_arrays);
                }
            }
            _ => match value {
                serde_json::Value::Array(items) => {
                    items.iter_mut().for_each(normalize_schema_arrays)
                }
                serde_json::Value::Object(_) => normalize_schema_arrays(value),
                _ => {}
            },
        }
    }
}

fn parse_api_schema_config(node: &kdl::KdlNode) -> Result<ApiSchemaConfig> {
    let schema_file = get_string_entry(node, "schema-file").map(PathBuf::from);
    let schema_content = get_string_entry(node, "schema-content");
    let validate_requests = get_bool_entry(node, "validate-requests").unwrap_or(true);
    let validate_responses = get_bool_entry(node, "validate-responses").unwrap_or(false);
    let strict_mode = get_bool_entry(node, "strict-mode").unwrap_or(false);

    // Validate mutually exclusive options
    if schema_file.is_some() && schema_content.is_some() {
        return Err(anyhow::anyhow!(
            "schema-file and schema-content are mutually exclusive. Use one or the other."
        ));
    }

    // Parse inline request schema if present
    let request_schema = if let Some(children) = node.children() {
        if let Some(schema_node) = children.get("request-schema") {
            Some(schema_from_kdl(schema_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse inline response schema if present
    let response_schema = if let Some(children) = node.children() {
        if let Some(schema_node) = children.get("response-schema") {
            Some(schema_from_kdl(schema_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        has_schema_file = schema_file.is_some(),
        has_schema_content = schema_content.is_some(),
        has_request_schema = request_schema.is_some(),
        has_response_schema = response_schema.is_some(),
        validate_requests = validate_requests,
        validate_responses = validate_responses,
        strict_mode = strict_mode,
        "Parsed API schema configuration"
    );

    Ok(ApiSchemaConfig {
        schema_file,
        schema_content,
        request_schema,
        response_schema,
        validate_requests,
        validate_responses,
        strict_mode,
    })
}

/// Parse optional shadow (traffic mirroring) configuration from a route
fn parse_shadow_config_opt(node: &kdl::KdlNode) -> Result<Option<ShadowConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(shadow_node) = route_children.get("shadow") {
            return Ok(Some(parse_shadow_config(shadow_node)?));
        }
    }
    Ok(None)
}

/// Parse shadow (traffic mirroring) configuration block
///
/// Example KDL:
/// ```kdl
/// shadow {
///     upstream "canary"
///     percentage 10.0
///     sample-header "X-Debug-Shadow" "true"
///     timeout-ms 5000
///     buffer-body #true
///     max-body-bytes 1048576
/// }
/// ```
fn parse_shadow_config(node: &kdl::KdlNode) -> Result<ShadowConfig> {
    // Upstream is required
    let upstream = get_string_entry(node, "upstream").ok_or_else(|| {
        anyhow::anyhow!(
            "Shadow configuration requires an 'upstream' field, e.g., upstream \"canary\""
        )
    })?;

    // Percentage: accepts a number (`percentage 50` / `percentage 12.5`) or a
    // numeric string (`percentage "50"`). Invalid values are hard errors —
    // silently falling back to the 100% default would mirror far more traffic
    // than intended.
    let percentage = if let Some(pct_str) = get_string_entry(node, "percentage") {
        pct_str.parse::<f64>().map_err(|_| {
            anyhow::anyhow!(
                "Shadow 'percentage' has invalid value \"{}\". \
                 Expected a number between 0 and 100, e.g., percentage 50",
                pct_str
            )
        })?
    } else {
        get_float_entry(node, "percentage").unwrap_or(100.0)
    };
    if !(0.0..=100.0).contains(&percentage) {
        return Err(anyhow::anyhow!(
            "Shadow 'percentage' is {} but must be between 0 and 100.",
            percentage
        ));
    }

    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(5000) as u64;
    let buffer_body = get_bool_entry(node, "buffer-body").unwrap_or(false);
    let max_body_bytes = get_int_entry(node, "max-body-bytes").unwrap_or(1048576) as usize;

    // Parse sample-header if present (tuple of name, value)
    let sample_header = if let Some(children) = node.children() {
        if let Some(header_node) = children.get("sample-header") {
            let entries: Vec<_> = header_node.entries().iter().collect();
            if entries.len() >= 2 {
                let name = entries[0]
                    .value()
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("sample-header name must be a string"))?;
                let value = entries[1]
                    .value()
                    .as_string()
                    .ok_or_else(|| anyhow::anyhow!("sample-header value must be a string"))?;
                Some((name.to_string(), value.to_string()))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        upstream = %upstream,
        percentage = percentage,
        timeout_ms = timeout_ms,
        buffer_body = buffer_body,
        max_body_bytes = max_body_bytes,
        has_sample_header = sample_header.is_some(),
        "Parsed shadow configuration"
    );

    Ok(ShadowConfig {
        upstream,
        percentage,
        sample_header,
        timeout_ms,
        buffer_body,
        max_body_bytes,
    })
}

/// Parse optional fallback configuration from a route
fn parse_fallback_config_opt(node: &kdl::KdlNode) -> Result<Option<FallbackConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(fallback_node) = route_children.get("fallback") {
            return Ok(Some(parse_fallback_config(fallback_node)?));
        }
    }
    Ok(None)
}

/// Parse fallback configuration block
///
/// Example KDL:
/// ```kdl
/// fallback {
///     max-attempts 2
///
///     triggers {
///         on-health-failure true
///         on-budget-exhausted true
///         on-latency-threshold-ms 5000
///         on-error-codes 429 500 502 503 504
///         on-connection-error true
///     }
///
///     fallback-upstream "anthropic-fallback" {
///         provider "anthropic"
///         skip-if-unhealthy true
///
///         model-mapping {
///             "gpt-4" "claude-3-opus"
///             "gpt-4o" "claude-3-5-sonnet"
///         }
///     }
/// }
/// ```
fn parse_fallback_config(node: &kdl::KdlNode) -> Result<FallbackConfig> {
    let max_attempts = get_int_entry(node, "max-attempts").unwrap_or(3) as u32;

    // Parse triggers
    let triggers = if let Some(children) = node.children() {
        if let Some(triggers_node) = children.get("triggers") {
            parse_fallback_triggers(triggers_node)?
        } else {
            FallbackTriggers::default()
        }
    } else {
        FallbackTriggers::default()
    };

    // Parse fallback upstreams
    let upstreams = parse_fallback_upstreams(node)?;

    trace!(
        max_attempts = max_attempts,
        upstream_count = upstreams.len(),
        on_health_failure = triggers.on_health_failure,
        on_connection_error = triggers.on_connection_error,
        "Parsed fallback configuration"
    );

    Ok(FallbackConfig {
        upstreams,
        triggers,
        max_attempts,
    })
}

/// Parse fallback triggers block
fn parse_fallback_triggers(node: &kdl::KdlNode) -> Result<FallbackTriggers> {
    let on_health_failure = get_bool_entry(node, "on-health-failure").unwrap_or(true);
    let on_budget_exhausted = get_bool_entry(node, "on-budget-exhausted").unwrap_or(false);
    let on_latency_threshold_ms = get_int_entry(node, "on-latency-threshold-ms").map(|v| v as u64);
    let on_connection_error = get_bool_entry(node, "on-connection-error").unwrap_or(true);

    // Parse error codes (integer arguments)
    let on_error_codes = if let Some(children) = node.children() {
        if let Some(codes_node) = children.get("on-error-codes") {
            codes_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        // Also check for inline arguments
        node.children()
            .and_then(|c| c.get("on-error-codes"))
            .map(|n| {
                n.entries()
                    .iter()
                    .filter_map(|e| e.value().as_integer().map(|v| v as u16))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(FallbackTriggers {
        on_health_failure,
        on_budget_exhausted,
        on_latency_threshold_ms,
        on_error_codes,
        on_connection_error,
    })
}

/// Parse fallback upstreams from fallback block
fn parse_fallback_upstreams(node: &kdl::KdlNode) -> Result<Vec<FallbackUpstream>> {
    let mut upstreams = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "fallback-upstream" {
                let upstream_id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "fallback-upstream requires an upstream ID, e.g., fallback-upstream \"anthropic\" {{ ... }}"
                    )
                })?;

                let provider = parse_inference_provider(child);
                let skip_if_unhealthy = get_bool_entry(child, "skip-if-unhealthy").unwrap_or(false);
                let model_mapping = parse_model_mapping(child)?;

                trace!(
                    upstream = %upstream_id,
                    provider = ?provider,
                    skip_if_unhealthy = skip_if_unhealthy,
                    model_mapping_count = model_mapping.len(),
                    "Parsed fallback upstream"
                );

                upstreams.push(FallbackUpstream {
                    upstream: upstream_id,
                    provider,
                    model_mapping,
                    skip_if_unhealthy,
                });
            }
        }
    }

    Ok(upstreams)
}

/// Parse model mapping block
///
/// Example KDL:
/// ```kdl
/// model-mapping {
///     "gpt-4" "claude-3-opus"
///     "gpt-4o" "claude-3-5-sonnet"
/// }
/// ```
fn parse_model_mapping(node: &kdl::KdlNode) -> Result<HashMap<String, String>> {
    let mut mapping = HashMap::new();

    if let Some(children) = node.children() {
        if let Some(mapping_node) = children.get("model-mapping") {
            if let Some(mapping_children) = mapping_node.children() {
                for entry_node in mapping_children.nodes() {
                    // Each node is like: "gpt-4" "claude-3-opus"
                    let entries: Vec<_> = entry_node
                        .entries()
                        .iter()
                        .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                        .collect();

                    // The node name is the source model, first entry is target
                    let source = entry_node.name().value().to_string();
                    if let Some(target) = entries.first() {
                        mapping.insert(source, target.clone());
                    }
                }
            }

            // Also handle inline format: model-mapping { "gpt-4" "claude-3-opus" }
            // where entries are pairs
            let entries: Vec<_> = mapping_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect();

            // Process pairs
            for chunk in entries.chunks(2) {
                if chunk.len() == 2 {
                    mapping.insert(chunk[0].clone(), chunk[1].clone());
                }
            }
        }
    }

    Ok(mapping)
}

/// Parse inference provider from node
fn parse_inference_provider(node: &kdl::KdlNode) -> InferenceProvider {
    match get_string_entry(node, "provider").as_deref() {
        Some("openai") => InferenceProvider::OpenAi,
        Some("anthropic") => InferenceProvider::Anthropic,
        _ => InferenceProvider::Generic,
    }
}

/// Parse optional model routing configuration from an inference block.
///
/// Example KDL:
/// ```kdl
/// model-routing {
///     model "gpt-4" upstream="openai-primary"
///     model "gpt-4*" upstream="openai-primary"
///     model "claude-*" upstream="anthropic-backend" provider="anthropic"
///     default-upstream "openai-primary"
/// }
/// ```
fn parse_model_routing_config_opt(node: &kdl::KdlNode) -> Result<Option<ModelRoutingConfig>> {
    if let Some(children) = node.children() {
        if let Some(routing_node) = children.get("model-routing") {
            return Ok(Some(parse_model_routing_config(routing_node)?));
        }
    }
    Ok(None)
}

/// Parse model routing configuration block.
fn parse_model_routing_config(node: &kdl::KdlNode) -> Result<ModelRoutingConfig> {
    let mut mappings = Vec::new();
    let mut default_upstream = None;

    // Get default-upstream if present (as entry or child)
    if let Some(def) = get_string_entry(node, "default-upstream") {
        default_upstream = Some(def);
    }

    // Parse children
    if let Some(children) = node.children() {
        // Check for default-upstream as a child node
        if let Some(def_node) = children.get("default-upstream") {
            if let Some(first_entry) = def_node.entries().first() {
                if let Some(val) = first_entry.value().as_string() {
                    default_upstream = Some(val.to_string());
                }
            }
        }

        // Parse model entries
        for model_node in children.nodes() {
            if model_node.name().value() == "model" {
                if let Some(mapping) = parse_model_upstream_mapping(model_node)? {
                    mappings.push(mapping);
                }
            }
        }
    }

    tracing::trace!(
        mappings_count = mappings.len(),
        default_upstream = ?default_upstream,
        "Parsed model routing configuration"
    );

    Ok(ModelRoutingConfig {
        mappings,
        default_upstream,
    })
}

/// Parse a single model-to-upstream mapping entry.
///
/// Example KDL:
/// ```kdl
/// model "gpt-4" upstream="openai-primary"
/// model "claude-*" upstream="anthropic-backend" provider="anthropic"
/// ```
fn parse_model_upstream_mapping(node: &kdl::KdlNode) -> Result<Option<ModelUpstreamMapping>> {
    // Get the model pattern from the first positional entry (no name)
    let model_pattern = node
        .entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string());

    let model_pattern = match model_pattern {
        Some(p) => p,
        None => return Ok(None), // No model pattern specified
    };

    // Get upstream from inline entry (e.g., upstream="openai-primary")
    let upstream = node
        .entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some("upstream"))
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("Model mapping requires 'upstream' attribute"))?;

    // Get optional provider override from inline entry
    let provider_str = node
        .entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some("provider"))
        .and_then(|e| e.value().as_string());

    let provider = match provider_str {
        Some("openai") => Some(InferenceProvider::OpenAi),
        Some("anthropic") => Some(InferenceProvider::Anthropic),
        Some("generic") => Some(InferenceProvider::Generic),
        Some(_) | None => None,
    };

    tracing::trace!(
        model_pattern = %model_pattern,
        upstream = %upstream,
        provider = ?provider,
        "Parsed model upstream mapping"
    );

    Ok(Some(ModelUpstreamMapping {
        model_pattern,
        upstream,
        provider,
    }))
}

/// Parse optional inference configuration from a route
fn parse_inference_config_opt(node: &kdl::KdlNode) -> Result<Option<InferenceConfig>> {
    if let Some(route_children) = node.children() {
        if let Some(inference_node) = route_children.get("inference") {
            return Ok(Some(parse_inference_config(inference_node)?));
        }
    }
    Ok(None)
}

/// Parse inference configuration block
///
/// Example KDL:
/// ```kdl
/// inference {
///     provider "openai"
///     model-header "x-model"
///
///     rate-limit {
///         tokens-per-minute 100000
///         requests-per-minute 500
///         burst-tokens 10000
///         estimation-method "chars"
///     }
///
///     routing {
///         strategy "least-tokens-queued"
///         queue-depth-header "x-queue-depth"
///     }
/// }
/// ```
fn parse_inference_config(node: &kdl::KdlNode) -> Result<InferenceConfig> {
    // Parse provider
    let provider = match get_string_entry(node, "provider").as_deref() {
        Some("openai") | Some("open-ai") | Some("open_ai") => InferenceProvider::OpenAi,
        Some("anthropic") => InferenceProvider::Anthropic,
        Some("generic") | None => InferenceProvider::Generic,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown inference provider '{}'. Valid providers: openai, anthropic, generic",
                other
            ));
        }
    };

    let model_header = get_string_entry(node, "model-header");

    // Parse rate-limit sub-block
    let rate_limit = if let Some(children) = node.children() {
        if let Some(rl_node) = children.get("rate-limit") {
            Some(parse_token_rate_limit(rl_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse routing sub-block
    let routing = if let Some(children) = node.children() {
        if let Some(routing_node) = children.get("routing") {
            Some(parse_inference_routing(routing_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse budget sub-block
    let budget = if let Some(children) = node.children() {
        if let Some(budget_node) = children.get("budget") {
            Some(parse_token_budget(budget_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse cost-attribution sub-block
    let cost_attribution = if let Some(children) = node.children() {
        if let Some(cost_node) = children.get("cost-attribution") {
            Some(parse_cost_attribution(cost_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        provider = ?provider,
        has_rate_limit = rate_limit.is_some(),
        has_routing = routing.is_some(),
        has_budget = budget.is_some(),
        has_cost = cost_attribution.is_some(),
        "Parsed inference configuration"
    );

    // Parse model-routing block if present
    let model_routing = parse_model_routing_config_opt(node)?;

    // Parse guardrails block if present
    let guardrails = parse_guardrails_config_opt(node)?;

    Ok(InferenceConfig {
        provider,
        model_header,
        rate_limit,
        budget,
        cost_attribution,
        routing,
        model_routing,
        guardrails,
    })
}

/// Parse token rate limit configuration
fn parse_token_rate_limit(node: &kdl::KdlNode) -> Result<TokenRateLimit> {
    let tokens_per_minute = get_int_entry(node, "tokens-per-minute")
        .ok_or_else(|| anyhow::anyhow!("Token rate limit requires 'tokens-per-minute'"))?
        as u64;

    let requests_per_minute = get_int_entry(node, "requests-per-minute").map(|v| v as u64);

    let burst_tokens = get_int_entry(node, "burst-tokens").unwrap_or(10000) as u64;

    let estimation_method = match get_string_entry(node, "estimation-method").as_deref() {
        Some("chars") | Some("characters") | None => TokenEstimation::Chars,
        Some("words") => TokenEstimation::Words,
        Some("tiktoken") => TokenEstimation::Tiktoken,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown token estimation method '{}'. Valid methods: chars, words, tiktoken",
                other
            ));
        }
    };

    Ok(TokenRateLimit {
        tokens_per_minute,
        requests_per_minute,
        burst_tokens,
        estimation_method,
    })
}

/// Parse inference routing configuration
fn parse_inference_routing(node: &kdl::KdlNode) -> Result<InferenceRouting> {
    let strategy = match get_string_entry(node, "strategy").as_deref() {
        Some("least-tokens-queued") | Some("least_tokens_queued") | None => {
            InferenceRoutingStrategy::LeastTokensQueued
        }
        Some("round-robin") | Some("round_robin") => InferenceRoutingStrategy::RoundRobin,
        Some("least-latency") | Some("least_latency") => InferenceRoutingStrategy::LeastLatency,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown inference routing strategy '{}'. Valid strategies: least-tokens-queued, round-robin, least-latency",
                other
            ));
        }
    };

    let queue_depth_header = get_string_entry(node, "queue-depth-header");

    Ok(InferenceRouting {
        strategy,
        queue_depth_header,
    })
}

/// Parse token budget configuration
///
/// KDL format:
/// ```kdl
/// budget {
///     period "daily"
///     limit 1000000
///     alert-thresholds 0.80 0.90 0.95
///     enforce true
///     rollover false
///     burst-allowance 0.10
/// }
/// ```
fn parse_token_budget(node: &kdl::KdlNode) -> Result<TokenBudgetConfig> {
    let period = match get_string_entry(node, "period").as_deref() {
        Some("hourly") => BudgetPeriod::Hourly,
        Some("daily") | None => BudgetPeriod::Daily,
        Some("monthly") => BudgetPeriod::Monthly,
        Some(other) => {
            // Try to parse as custom seconds
            if let Ok(seconds) = other.parse::<u64>() {
                BudgetPeriod::Custom { seconds }
            } else {
                return Err(anyhow::anyhow!(
                    "Unknown budget period '{}'. Valid periods: hourly, daily, monthly, or a number of seconds",
                    other
                ));
            }
        }
    };

    let limit = get_int_entry(node, "limit")
        .ok_or_else(|| anyhow::anyhow!("Token budget requires 'limit'"))? as u64;

    // Parse alert-thresholds as a list of floats from arguments
    let alert_thresholds = if let Some(children) = node.children() {
        if let Some(threshold_node) = children.get("alert-thresholds") {
            threshold_node
                .entries()
                .iter()
                .filter_map(|e| {
                    e.value()
                        .as_float()
                        .or_else(|| e.value().as_integer().map(|i| i as f64))
                })
                .collect()
        } else {
            vec![0.80, 0.90, 0.95]
        }
    } else {
        vec![0.80, 0.90, 0.95]
    };

    let enforce = get_bool_entry(node, "enforce").unwrap_or(true);
    let rollover = get_bool_entry(node, "rollover").unwrap_or(false);
    let burst_allowance = get_float_entry(node, "burst-allowance");
    let max_tenants = get_int_entry(node, "max-tenants")
        .map(|v| v as usize)
        .unwrap_or_else(zentinel_common::budget::default_max_tenants);

    trace!(
        period = ?period,
        limit = limit,
        alert_thresholds = ?alert_thresholds,
        enforce = enforce,
        rollover = rollover,
        burst_allowance = ?burst_allowance,
        max_tenants = max_tenants,
        "Parsed token budget configuration"
    );

    Ok(TokenBudgetConfig {
        period,
        limit,
        alert_thresholds,
        enforce,
        rollover,
        burst_allowance,
        max_tenants,
    })
}

/// Parse cost attribution configuration
///
/// KDL format:
/// ```kdl
/// cost-attribution {
///     enabled true
///     default-input-cost 1.0
///     default-output-cost 2.0
///     currency "USD"
///
///     pricing {
///         model "gpt-4*" {
///             input-cost-per-million 30.0
///             output-cost-per-million 60.0
///         }
///         model "gpt-3.5*" {
///             input-cost-per-million 0.5
///             output-cost-per-million 1.5
///         }
///     }
/// }
/// ```
fn parse_cost_attribution(node: &kdl::KdlNode) -> Result<CostAttributionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(true);
    let default_input_cost = get_float_entry(node, "default-input-cost").unwrap_or(1.0);
    let default_output_cost = get_float_entry(node, "default-output-cost").unwrap_or(2.0);
    let currency = get_string_entry(node, "currency").unwrap_or_else(|| "USD".to_string());

    // Parse pricing sub-block
    let pricing = if let Some(children) = node.children() {
        if let Some(pricing_node) = children.get("pricing") {
            parse_model_pricing_list(pricing_node)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    trace!(
        enabled = enabled,
        default_input_cost = default_input_cost,
        default_output_cost = default_output_cost,
        currency = %currency,
        pricing_rules = pricing.len(),
        "Parsed cost attribution configuration"
    );

    Ok(CostAttributionConfig {
        enabled,
        pricing,
        default_input_cost,
        default_output_cost,
        currency,
    })
}

/// Parse model pricing list
fn parse_model_pricing_list(node: &kdl::KdlNode) -> Result<Vec<ModelPricing>> {
    let mut pricing = Vec::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "model" {
                let pattern = get_first_arg_string(child)
                    .ok_or_else(|| anyhow::anyhow!("Model pricing requires a pattern argument"))?;

                let input_cost =
                    get_float_entry(child, "input-cost-per-million").ok_or_else(|| {
                        anyhow::anyhow!("Model pricing requires 'input-cost-per-million'")
                    })?;

                let output_cost =
                    get_float_entry(child, "output-cost-per-million").ok_or_else(|| {
                        anyhow::anyhow!("Model pricing requires 'output-cost-per-million'")
                    })?;

                let currency = get_string_entry(child, "currency");

                pricing.push(ModelPricing {
                    model_pattern: pattern,
                    input_cost_per_million: input_cost,
                    output_cost_per_million: output_cost,
                    currency,
                });
            }
        }
    }

    Ok(pricing)
}

// ============================================================================
// Guardrails Configuration Parsing
// ============================================================================

/// Parse optional guardrails configuration from an inference block.
///
/// Example KDL:
/// ```kdl
/// guardrails {
///     prompt-injection {
///         enabled true
///         agent "prompt-guard"
///         action "block"
///         block-status 400
///         block-message "Request blocked: potential prompt injection detected"
///         timeout-ms 500
///         failure-mode "open"
///     }
///
///     pii-detection {
///         enabled true
///         agent "pii-scanner"
///         action "log"
///         categories "ssn" "credit-card" "email" "phone"
///         timeout-ms 1000
///         failure-mode "open"
///     }
/// }
/// ```
fn parse_guardrails_config_opt(node: &kdl::KdlNode) -> Result<Option<GuardrailsConfig>> {
    if let Some(children) = node.children() {
        if let Some(guardrails_node) = children.get("guardrails") {
            return Ok(Some(parse_guardrails_config(guardrails_node)?));
        }
    }
    Ok(None)
}

/// Parse guardrails configuration block.
fn parse_guardrails_config(node: &kdl::KdlNode) -> Result<GuardrailsConfig> {
    // Parse prompt-injection sub-block
    let prompt_injection = if let Some(children) = node.children() {
        if let Some(pi_node) = children.get("prompt-injection") {
            Some(parse_prompt_injection_config(pi_node)?)
        } else {
            None
        }
    } else {
        None
    };

    // Parse pii-detection sub-block
    let pii_detection = if let Some(children) = node.children() {
        if let Some(pii_node) = children.get("pii-detection") {
            Some(parse_pii_detection_config(pii_node)?)
        } else {
            None
        }
    } else {
        None
    };

    trace!(
        has_prompt_injection = prompt_injection.is_some(),
        has_pii_detection = pii_detection.is_some(),
        "Parsed guardrails configuration"
    );

    Ok(GuardrailsConfig {
        prompt_injection,
        pii_detection,
    })
}

/// Parse prompt injection detection configuration.
fn parse_prompt_injection_config(node: &kdl::KdlNode) -> Result<PromptInjectionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);

    let agent = get_string_entry(node, "agent")
        .ok_or_else(|| anyhow::anyhow!("Prompt injection config requires 'agent' field"))?;

    let action = match get_string_entry(node, "action").as_deref() {
        Some("block") => GuardrailAction::Block,
        Some("log") | None => GuardrailAction::Log,
        Some("warn") => GuardrailAction::Warn,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown guardrail action '{}'. Valid actions: block, log, warn",
                other
            ));
        }
    };

    let block_status = get_int_entry(node, "block-status").unwrap_or(400) as u16;
    let block_message = get_string_entry(node, "block-message");
    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(500) as u64;

    let failure_mode = match get_string_entry(node, "failure-mode").as_deref() {
        Some("open") | None => GuardrailFailureMode::Open,
        Some("closed") => GuardrailFailureMode::Closed,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown failure mode '{}'. Valid modes: open, closed",
                other
            ));
        }
    };

    trace!(
        enabled = enabled,
        agent = %agent,
        action = ?action,
        block_status = block_status,
        timeout_ms = timeout_ms,
        failure_mode = ?failure_mode,
        "Parsed prompt injection configuration"
    );

    Ok(PromptInjectionConfig {
        enabled,
        agent,
        action,
        block_status,
        block_message,
        timeout_ms,
        failure_mode,
    })
}

/// Parse PII detection configuration.
fn parse_pii_detection_config(node: &kdl::KdlNode) -> Result<PiiDetectionConfig> {
    let enabled = get_bool_entry(node, "enabled").unwrap_or(false);

    let agent = get_string_entry(node, "agent")
        .ok_or_else(|| anyhow::anyhow!("PII detection config requires 'agent' field"))?;

    let action = match get_string_entry(node, "action").as_deref() {
        Some("log") | None => PiiAction::Log,
        Some("redact") => PiiAction::Redact,
        Some("block") => PiiAction::Block,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown PII action '{}'. Valid actions: log, redact, block",
                other
            ));
        }
    };

    // Parse categories as string arguments
    let categories = if let Some(children) = node.children() {
        if let Some(cat_node) = children.get("categories") {
            cat_node
                .entries()
                .iter()
                .filter_map(|e| e.value().as_string().map(|s| s.to_string()))
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let timeout_ms = get_int_entry(node, "timeout-ms").unwrap_or(1000) as u64;

    let failure_mode = match get_string_entry(node, "failure-mode").as_deref() {
        Some("open") | None => GuardrailFailureMode::Open,
        Some("closed") => GuardrailFailureMode::Closed,
        Some(other) => {
            return Err(anyhow::anyhow!(
                "Unknown failure mode '{}'. Valid modes: open, closed",
                other
            ));
        }
    };

    trace!(
        enabled = enabled,
        agent = %agent,
        action = ?action,
        categories = ?categories,
        timeout_ms = timeout_ms,
        failure_mode = ?failure_mode,
        "Parsed PII detection configuration"
    );

    Ok(PiiDetectionConfig {
        enabled,
        agent,
        action,
        categories,
        timeout_ms,
        failure_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Six of these nine fields used to sit behind `..RoutePolicies::default()`
    /// and hold their defaults no matter what the config said. Each test below
    /// uses a value that differs from the default, so a field falling back to
    /// its default fails the test rather than passing by coincidence.
    /// The WebSocket example exists to demonstrate WebSocket proxying, and for
    /// some time demonstrated none: it wrote `websocket { enabled #true … }`
    /// as a block while the parser reads `websocket` as a scalar bool, so every
    /// route in it parsed to `websocket = false` (#369).
    #[test]
    fn the_websocket_example_actually_enables_websocket() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../config/examples/websocket.kdl"
        );
        let text = std::fs::read_to_string(path).expect("example should be readable");
        let config = crate::Config::from_kdl(&text).expect("example should parse");

        let ws_routes: Vec<&crate::RouteConfig> =
            config.routes.iter().filter(|r| r.websocket).collect();

        assert!(
            ws_routes.len() >= 3,
            "the WebSocket example should enable websocket on its websocket routes, \
             found {} of {}",
            ws_routes.len(),
            config.routes.len()
        );

        assert!(
            config.routes.iter().any(|r| r.websocket_inspection),
            "the example advertises frame inspection and should enable it on at least one route"
        );
    }

    /// The whole point of this week: a config block that parses but never
    /// reaches the struct is worse than no config block. Every setting below is
    /// asserted against a value that differs from its default, so a field that
    /// silently falls back fails the test rather than passing by coincidence.
    mod agentic_blocks_are_parsed {
        use super::*;
        use crate::agentic::{UninspectableBody, UnknownMethods};

        fn route_with(body: &str) -> crate::RouteConfig {
            let kdl = format!(
                "routes {{\n  route \"agentic\" {{\n    matches {{\n      path-prefix \"/mcp\"\n    }}\n\
                 \x20   upstream \"backend\"\n{body}\n  }}\n}}\n"
            );
            let doc: kdl::KdlDocument = kdl.parse().expect("kdl should parse");
            parse_routes(doc.nodes().first().expect("routes node"))
                .expect("routes should parse")
                .remove(0)
        }

        /// Like `route_with`, but hands back the error instead of unwrapping —
        /// for the cases where refusing the config *is* the behaviour.
        fn route_result(body: &str) -> Result<Vec<crate::RouteConfig>> {
            let kdl = format!(
                "routes {{\n  route \"agentic\" {{\n    matches {{\n      path-prefix \"/mcp\"\n    }}\n\
                 \x20   upstream \"backend\"\n{body}\n  }}\n}}\n"
            );
            let doc: kdl::KdlDocument = kdl.parse().expect("kdl should parse");
            parse_routes(doc.nodes().first().expect("routes node"))
        }

        #[test]
        fn a_route_without_an_mcp_block_has_no_mcp_policy() {
            assert!(route_with("").mcp.is_none());
            assert!(route_with("").a2a.is_none());
        }

        #[test]
        fn mcp_tool_lists_are_read() {
            let route = route_with(
                "    mcp {\n      tools {\n        allow \"get_weather\" \"search_docs\"\n\
                 \x20       deny \"execute_sql\"\n      }\n    }",
            );
            let mcp = route.mcp.expect("mcp block should be parsed");
            assert_eq!(mcp.allowed_tools, ["get_weather", "search_docs"]);
            assert_eq!(mcp.denied_tools, ["execute_sql"]);
        }

        /// Read the struct back rather than trusting that the key parsed:
        /// a setting KDL accepts and nothing stores is how a policy stops
        /// applying without anyone noticing.
        #[test]
        fn filter_tool_list_can_be_turned_off() {
            let route = route_with("    mcp {\n      filter-tool-list #false\n    }");
            assert!(!route.mcp.expect("parsed").filter_tool_list);
        }

        #[test]
        fn filter_tool_list_defaults_on() {
            let route = route_with("    mcp {\n      tools {\n        deny \"x\"\n      }\n    }");
            assert!(route.mcp.expect("parsed").filter_tool_list);
        }

        mod multiplexing {
            use super::*;

            #[test]
            fn upstreams_and_prefixes_are_read() {
                let route = route_with(
                    "    mcp {\n      upstreams {\n        upstream \"docs\" prefix=\"docs\"\n        upstream \"wh\" prefix=\"warehouse\" path=\"/mcp\"\n      }\n    }",
                );
                let ups = route.mcp.expect("parsed").upstreams;
                assert_eq!(ups.len(), 2);
                assert_eq!(ups[0].upstream, "docs");
                assert_eq!(ups[0].prefix, "docs");
                assert_eq!(ups[0].path, "/", "path defaults to root");
                assert_eq!(ups[1].upstream, "wh");
                assert_eq!(ups[1].prefix, "warehouse");
                assert_eq!(ups[1].path, "/mcp");
            }

            #[test]
            fn the_session_key_is_read() {
                let route = route_with("    mcp {\n      session-key \"abc123\"\n    }");
                assert_eq!(
                    route.mcp.expect("parsed").session_key.as_deref(),
                    Some("abc123")
                );
            }

            /// The ordinary route is untouched: no upstreams, no key, and none
            /// of the multiplexing machinery applies.
            #[test]
            fn a_route_without_the_block_multiplexes_nothing() {
                let route =
                    route_with("    mcp {\n      tools {\n        deny \"x\"\n      }\n    }");
                let mcp = route.mcp.expect("parsed");
                assert!(mcp.upstreams.is_empty());
                assert!(mcp.session_key.is_none());
            }

            /// Deriving the prefix from the upstream name was rejected, so a
            /// missing one is an error rather than a default.
            #[test]
            fn a_missing_prefix_is_refused() {
                let err = route_result(
                    "    mcp {\n      upstreams {\n        upstream \"docs\"\n      }\n    }",
                )
                .expect_err("should refuse");
                assert!(err.to_string().contains("needs a prefix"), "{err}");
            }

            /// Two upstreams sharing a prefix would make every tool from one
            /// indistinguishable from the other's.
            #[test]
            fn duplicate_prefixes_are_refused() {
                let err = route_result(
                    "    mcp {\n      upstreams {\n        upstream \"a\" prefix=\"p\"\n        upstream \"b\" prefix=\"p\"\n      }\n    }",
                )
                .expect_err("should refuse");
                assert!(err.to_string().contains("share the prefix"), "{err}");
            }

            /// The separator in a prefix would make routing ambiguous.
            #[test]
            fn a_prefix_containing_the_separator_is_refused() {
                let err = route_result(
                    "    mcp {\n      upstreams {\n        upstream \"a\" prefix=\"a.b\"\n      }\n    }",
                )
                .expect_err("should refuse");
                assert!(
                    err.to_string().contains("would make routing ambiguous"),
                    "{err}"
                );
            }

            #[test]
            fn an_unknown_node_in_the_block_is_refused() {
                let err = route_result(
                    "    mcp {\n      upstreams {\n        server \"a\" prefix=\"p\"\n      }\n    }",
                )
                .expect_err("should refuse");
                assert!(err.to_string().contains("Expected 'upstream'"), "{err}");
            }
        }

        #[test]
        fn mcp_method_lists_are_read() {
            let route = route_with(
                "    mcp {\n      methods {\n        allow \"tools/call\"\n        deny \"resources/read\"\n      }\n    }",
            );
            let mcp = route.mcp.expect("parsed");
            assert_eq!(mcp.allowed_methods, ["tools/call"]);
            assert_eq!(mcp.denied_methods, ["resources/read"]);
        }

        /// Defaults to true, so the test uses false to prove it is read.
        #[test]
        fn require_validated_version_is_read() {
            let route = route_with("    mcp {\n      require-validated-version #false\n    }");
            assert!(!route.mcp.expect("parsed").require_validated_version);
        }

        #[test]
        fn require_validated_version_defaults_to_true() {
            let route = route_with("    mcp {\n      tools {\n        deny \"x\"\n      }\n    }");
            assert!(
                route.mcp.expect("parsed").require_validated_version,
                "a route that does not say otherwise must require a validated protocol version"
            );
        }

        /// Defaults to Deny, so the test uses allow.
        /// Defaults to true, so the test uses false to prove it is read.
        #[test]
        fn validate_param_headers_is_read() {
            let route = route_with("    mcp {\n      validate-param-headers #false\n    }");
            assert!(!route.mcp.expect("parsed").validate_param_headers);
        }

        #[test]
        fn validate_param_headers_defaults_to_true() {
            let route = route_with("    mcp {\n      tools {\n        deny \"x\"\n      }\n    }");
            assert!(route.mcp.expect("parsed").validate_param_headers);
        }

        #[test]
        fn on_uninspectable_body_is_read() {
            let route = route_with("    mcp {\n      on-uninspectable-body \"allow\"\n    }");
            assert_eq!(
                route.mcp.expect("parsed").on_uninspectable_body,
                UninspectableBody::Allow
            );
        }

        #[test]
        fn on_uninspectable_body_defaults_to_deny() {
            let route = route_with("    mcp {\n      tools {\n        deny \"x\"\n      }\n    }");
            assert_eq!(
                route.mcp.expect("parsed").on_uninspectable_body,
                UninspectableBody::Deny
            );
        }

        #[test]
        fn a2a_method_lists_are_read() {
            let route = route_with(
                "    a2a {\n      methods {\n        allow \"GetTask\" \"ListTasks\"\n\
                 \x20       deny \"CancelTask\"\n      }\n    }",
            );
            let a2a = route.a2a.expect("a2a block should be parsed");
            assert_eq!(a2a.allowed_methods, ["GetTask", "ListTasks"]);
            assert_eq!(a2a.denied_methods, ["CancelTask"]);
        }

        /// Defaults to Allow, so the test uses deny.
        #[test]
        fn a2a_unknown_methods_is_read() {
            let route = route_with("    a2a {\n      unknown-methods \"deny\"\n    }");
            assert_eq!(
                route.a2a.expect("parsed").unknown_methods,
                UnknownMethods::Deny
            );
        }

        #[test]
        fn a2a_deny_uninspectable_body_is_read() {
            let route = route_with("    a2a {\n      deny-uninspectable-body #false\n    }");
            assert!(!route.a2a.expect("parsed").deny_uninspectable_body);
        }

        #[test]
        fn both_blocks_can_coexist_on_one_route() {
            let route = route_with(
                "    mcp {\n      tools {\n        deny \"execute_sql\"\n      }\n    }\n\
                 \x20   a2a {\n      methods {\n        deny \"CancelTask\"\n      }\n    }",
            );
            assert_eq!(route.mcp.expect("mcp").denied_tools, ["execute_sql"]);
            assert_eq!(route.a2a.expect("a2a").denied_methods, ["CancelTask"]);
        }

        /// A misspelled key inside a security policy must not be discarded —
        /// that is the failure mode this whole codebase spent the week on.
        #[test]
        fn an_unknown_setting_in_the_mcp_block_is_rejected() {
            let kdl = "routes {\n  route \"r\" {\n    matches {\n      path-prefix \"/\"\n    }\n\
                       \x20   upstream \"b\"\n    mcp {\n      allowed_tools \"x\"\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap())
                .expect_err("a misspelled mcp setting must not be silently ignored");
            assert!(err.to_string().contains("allowed_tools"), "got: {err}");
        }

        #[test]
        fn an_unknown_value_for_on_uninspectable_body_is_rejected() {
            let kdl = "routes {\n  route \"r\" {\n    matches {\n      path-prefix \"/\"\n    }\n\
                       \x20   upstream \"b\"\n    mcp {\n      on-uninspectable-body \"maybe\"\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap()).expect_err("rejected");
            assert!(err.to_string().contains("maybe"), "got: {err}");
        }

        /// `allow` with nothing after it reads as "no allowlist", which permits
        /// everything — the opposite of what the word says.
        #[test]
        fn an_empty_allow_list_is_rejected_rather_than_read_as_unrestricted() {
            let kdl = "routes {\n  route \"r\" {\n    matches {\n      path-prefix \"/\"\n    }\n\
                       \x20   upstream \"b\"\n    mcp {\n      tools {\n        allow\n      }\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap()).expect_err("rejected");
            assert!(
                err.to_string().contains("permitting everything"),
                "the error should explain the trap, got: {err}"
            );
        }
    }

    mod route_policies_are_parsed {
        use super::*;

        fn policies_of(body: &str) -> RoutePolicies {
            let kdl = format!(
                "routes {{\n  route \"api\" {{\n    matches {{ path-prefix \"/api\" }}\n    upstream \"backend\"\n    policies {{\n      {body}\n    }}\n  }}\n}}\n"
            );
            let doc: kdl::KdlDocument = kdl.parse().expect("kdl should parse");
            let node = doc.nodes().first().expect("routes node");
            parse_routes(node)
                .expect("routes should parse")
                .remove(0)
                .policies
        }

        #[test]
        fn timeout_secs_is_read() {
            assert_eq!(policies_of("timeout-secs 7").timeout_secs, Some(7));
        }

        #[test]
        fn max_body_size_accepts_a_suffixed_string() {
            let p = policies_of("max-body-size \"5MB\"");
            assert_eq!(p.max_body_size.map(|b| b.0), Some(5 * 1024 * 1024));
        }

        #[test]
        fn max_body_size_accepts_a_plain_byte_count() {
            assert_eq!(
                policies_of("max-body-size 4096").max_body_size.map(|b| b.0),
                Some(4096)
            );
        }

        /// The one that mattered: the proxy consumes this to decide whether to
        /// block a request when an agent fails, and it was pinned to Closed.
        #[test]
        fn failure_mode_open_is_honoured() {
            assert_eq!(
                policies_of("failure-mode \"open\"").failure_mode,
                FailureMode::Open
            );
        }

        #[test]
        fn failure_mode_closed_is_honoured() {
            assert_eq!(
                policies_of("failure-mode \"closed\"").failure_mode,
                FailureMode::Closed
            );
        }

        /// Absent configuration stays fail-closed: a route becomes fail-open
        /// only by asking for it.
        #[test]
        fn failure_mode_defaults_to_closed() {
            assert_eq!(
                policies_of("timeout-secs 1").failure_mode,
                FailureMode::Closed
            );
        }

        #[test]
        fn an_unknown_failure_mode_is_rejected() {
            let kdl = "routes {\n  route \"api\" {\n    matches { path-prefix \"/api\" }\n    upstream \"backend\"\n    policies {\n      failure-mode \"fail-open\"\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap())
                .expect_err("an unknown failure-mode should not be silently ignored");
            assert!(err.to_string().contains("Unknown failure-mode"));
        }

        #[test]
        fn rate_limit_is_read() {
            let p = policies_of(
                "rate-limit {\n        requests-per-second 100\n        burst 200\n        key \"client-ip\"\n      }",
            );
            let rl = p.rate_limit.expect("rate limit should be parsed");
            assert_eq!(rl.requests_per_second, 100);
            assert_eq!(rl.burst, 200);
            assert_eq!(rl.key, RateLimitKey::ClientIp);
        }

        /// The shipped config writes the underscore form.
        #[test]
        fn rate_limit_key_accepts_either_separator() {
            for spelling in ["client_ip", "client-ip"] {
                let body = format!(
                    "rate-limit {{\n        requests-per-second 10\n        key \"{spelling}\"\n      }}"
                );
                let rl = policies_of(&body).rate_limit.expect("parsed");
                assert_eq!(rl.key, RateLimitKey::ClientIp, "for {spelling}");
            }
        }

        #[test]
        fn rate_limit_key_supports_headers() {
            let rl = policies_of(
                "rate-limit {\n        requests-per-second 10\n        key \"header:X-API-Key\"\n      }",
            )
            .rate_limit
            .expect("parsed");
            assert_eq!(rl.key, RateLimitKey::Header("X-API-Key".to_string()));
        }

        /// A burst below the sustained rate would throttle below the rate the
        /// operator configured, so it defaults to the rate rather than to a
        /// smaller constant.
        #[test]
        fn burst_defaults_to_the_configured_rate() {
            let rl = policies_of("rate-limit {\n        requests-per-second 42\n      }")
                .rate_limit
                .expect("parsed");
            assert_eq!(rl.burst, 42);
        }

        #[test]
        fn a_rate_limit_without_a_rate_is_rejected() {
            let kdl = "routes {\n  route \"api\" {\n    matches { path-prefix \"/api\" }\n    upstream \"backend\"\n    policies {\n      rate-limit {\n        burst 10\n      }\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap())
                .expect_err("a rate-limit with no rate should be rejected");
            assert!(err.to_string().contains("requests-per-second"));
        }

        #[test]
        fn an_unknown_rate_limit_key_is_rejected() {
            let kdl = "routes {\n  route \"api\" {\n    matches { path-prefix \"/api\" }\n    upstream \"backend\"\n    policies {\n      rate-limit {\n        requests-per-second 10\n        key \"whatever\"\n      }\n    }\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let err = parse_routes(doc.nodes().first().unwrap())
                .expect_err("an unknown rate limit key should not resolve to the default");
            assert!(err.to_string().contains("Unknown rate limit key"));
        }

        #[test]
        fn a_route_without_a_policies_block_gets_defaults() {
            let kdl = "routes {\n  route \"api\" {\n    matches { path-prefix \"/api\" }\n    upstream \"backend\"\n  }\n}\n";
            let doc: kdl::KdlDocument = kdl.parse().unwrap();
            let p = parse_routes(doc.nodes().first().unwrap())
                .expect("should parse")
                .remove(0)
                .policies;
            assert_eq!(p.timeout_secs, None);
            assert_eq!(p.max_body_size, None);
            assert!(p.rate_limit.is_none());
            assert_eq!(p.failure_mode, FailureMode::Closed);
        }

        /// Pins the regression to the shipped config, whose api-v1 route
        /// declares four policies and used to get none of them.
        #[test]
        fn shipped_config_route_policies_take_effect() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/zentinel.kdl");
            let text = std::fs::read_to_string(path).expect("shipped config readable");
            let config = crate::Config::from_kdl(&text).expect("shipped config parses");

            let api = config
                .routes
                .iter()
                .find(|r| r.id == "api-v1")
                .expect("api-v1 route");

            assert_eq!(api.policies.timeout_secs, Some(30));
            assert_eq!(
                api.policies.max_body_size.map(|b| b.0),
                Some(10 * 1024 * 1024)
            );
            assert_eq!(api.policies.failure_mode, FailureMode::Closed);

            let rl = api
                .policies
                .rate_limit
                .as_ref()
                .expect("api-v1 declares a rate limit and should get one");
            assert_eq!(rl.requests_per_second, 100);
            assert_eq!(rl.burst, 200);
            assert_eq!(rl.key, RateLimitKey::ClientIp);
        }
    }

    use zentinel_common::types::Priority;

    /// Parse a KDL fragment like `route "test" { priority ... }` and return
    /// the resulting `Priority`. The parser expects a `route` parent node, so
    /// we wrap the priority directive in a minimal route block.
    fn parse_priority_from(kdl: &str) -> Priority {
        let doc: ::kdl::KdlDocument = kdl.parse().expect("KDL parses");
        let route_node = doc.get("route").expect("route node present");
        resolve_priority(route_node, "r").0
    }

    #[test]
    fn priority_accepts_integer() {
        assert_eq!(
            parse_priority_from(r#"route "r" { priority 100 }"#),
            Priority(100)
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority 1000 }"#),
            Priority::CRITICAL
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority 1 }"#),
            Priority(1)
        );
    }

    #[test]
    fn priority_accepts_large_and_negative_integers() {
        assert_eq!(
            parse_priority_from(r#"route "r" { priority 999999 }"#),
            Priority(999_999)
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority -50 }"#),
            Priority(-50)
        );
    }

    #[test]
    fn priority_accepts_all_string_aliases() {
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "critical" }"#),
            Priority::CRITICAL
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "high" }"#),
            Priority::HIGH
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "normal" }"#),
            Priority::NORMAL
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "low" }"#),
            Priority::LOW
        );
    }

    #[test]
    fn priority_string_aliases_are_case_insensitive() {
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "HIGH" }"#),
            Priority::HIGH
        );
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "Critical" }"#),
            Priority::CRITICAL
        );
    }

    #[test]
    fn priority_unknown_string_falls_back_to_normal() {
        assert_eq!(
            parse_priority_from(r#"route "r" { priority "medium" }"#),
            Priority::NORMAL
        );
    }

    #[test]
    fn priority_missing_is_normal() {
        assert_eq!(
            parse_priority_from(r#"route "r" { upstream "backend" }"#),
            Priority::NORMAL
        );
    }

    #[test]
    fn numeric_priorities_sort_before_named_aliases() {
        // Regression: documentation-style gap-based priorities must preserve
        // the numeric ordering the docs advertise (e.g. 500 > HIGH > 50).
        assert!(Priority(500) > Priority::HIGH);
        assert!(Priority::HIGH > Priority(75));
        assert!(Priority(75) > Priority::NORMAL);
        assert!(Priority::NORMAL > Priority(25));
        assert!(Priority(25) > Priority::LOW);
    }

    /// retry-policy stanza present, all values normally set, use those values
    /// Retain this test here to ensure block parser works
    #[test]
    fn test_parse_retry_policy_normal() {
        let kdl = r#"
        routes {
            route "test-rp" {
                upstream "backend";
                retry-policy {
                    max-attempts 10
                }
            }
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let routes_node = doc.get("routes").unwrap();

        let routes = parse_routes(routes_node).unwrap();

        let rp = routes.first().unwrap().retry_policy.as_ref().unwrap();

        assert_eq!(rp.max_attempts, 10);
    }

    /// retry-policy stanza missing, Option<RetryPolicy> will be None
    #[test]
    fn test_parse_retry_policy_stanza_missing() {
        let kdl = r#"
        routes {
            route "test-rp" {
                upstream "backend";
            }
        }
        "#;

        let doc: kdl::KdlDocument = kdl.parse().unwrap();
        let routes_node = doc.get("routes").unwrap();
        let routes = parse_routes(routes_node).unwrap();

        let rp = routes.first().unwrap().retry_policy.as_ref();

        assert!(rp.is_none());
    }

    /// Parse a `routes { ... }` KDL fragment through `parse_routes`.
    fn parse_routes_from(kdl: &str) -> Result<Vec<RouteConfig>> {
        let doc: kdl::KdlDocument = kdl.parse().expect("KDL parses");
        let routes_node = doc.get("routes").expect("routes node present");
        parse_routes(routes_node)
    }

    #[test]
    fn match_condition_unknown_name_is_an_error_with_suggestion() {
        // `path_prefix` (underscore) is the classic typo for `path-prefix`.
        // Silently dropping it would make the route match everything.
        let err = parse_routes_from(
            r#"
            routes {
                route "assets" {
                    matches { path_prefix "/assets" }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("Route 'assets'"), "missing route id: {err}");
        assert!(
            err.contains("unknown match condition 'path_prefix'"),
            "missing offending name: {err}"
        );
        assert!(
            err.contains("Did you mean 'path-prefix'?"),
            "missing suggestion: {err}"
        );
        assert!(
            err.contains("path, path-prefix, path-regex, host, header, method, query-param"),
            "missing valid condition list: {err}"
        );
    }

    #[test]
    fn match_condition_unknown_name_without_close_candidate_lists_valid_names() {
        let err = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { banana "/api" }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("unknown match condition 'banana'"), "{err}");
        assert!(!err.contains("Did you mean"), "{err}");
        assert!(err.contains("Valid match conditions are:"), "{err}");
    }

    #[test]
    fn match_condition_missing_value_is_an_error() {
        let err = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { path-prefix }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("Route 'api'"), "{err}");
        assert!(
            err.contains("match condition 'path-prefix' is missing its value"),
            "{err}"
        );
        assert!(
            err.contains("path-prefix \"/api\""),
            "missing example: {err}"
        );
    }

    #[test]
    fn match_condition_non_string_value_is_an_error() {
        let err = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { method 42 }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("match condition 'method' has a non-string value 42"),
            "{err}"
        );
        assert!(err.contains("method \"GET\""), "missing example: {err}");
    }

    #[test]
    fn match_condition_valid_forms_still_parse() {
        let routes = parse_routes_from(
            r#"
            routes {
                route "kitchen-sink" {
                    matches {
                        path "/exact"
                        path-prefix "/api"
                        path-regex "^/v[0-9]+/"
                        host "*.example.com"
                        header "x-version" "2"
                        header "x-flag"
                        method "GET"
                        query-param "debug" "true"
                        query-param "trace"
                    }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap();

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].matches.len(), 9);
        assert!(matches!(
            routes[0].matches[4],
            MatchCondition::Header { ref name, ref value } if name == "x-version" && value.as_deref() == Some("2")
        ));
        assert!(matches!(
            routes[0].matches[5],
            MatchCondition::Header { ref name, ref value } if name == "x-flag" && value.is_none()
        ));
        assert!(matches!(
            routes[0].matches[8],
            MatchCondition::QueryParam { ref name, ref value } if name == "trace" && value.is_none()
        ));
    }

    #[test]
    fn shadow_percentage_rejects_non_numeric_string() {
        // Previously `percentage "lots"` silently became 100% mirroring.
        let err = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                    shadow {
                        upstream "canary"
                        percentage "lots"
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("Shadow 'percentage' has invalid value \"lots\""),
            "{err}"
        );
        assert!(err.contains("between 0 and 100"), "{err}");
    }

    #[test]
    fn shadow_percentage_rejects_out_of_range_values() {
        let err = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { path-prefix "/" }
                    upstream "backend"
                    shadow {
                        upstream "canary"
                        percentage 150
                    }
                }
            }
            "#,
        )
        .unwrap_err()
        .to_string();

        assert!(
            err.contains("Shadow 'percentage' is 150 but must be between 0 and 100"),
            "{err}"
        );
    }

    #[test]
    fn shadow_percentage_accepts_numeric_forms() {
        let routes = parse_routes_from(
            r#"
            routes {
                route "int-pct" {
                    matches { path-prefix "/" }
                    upstream "backend"
                    shadow { upstream "canary"; percentage 50 }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].shadow.as_ref().unwrap().percentage, 50.0);

        // Float form was previously (silently) ignored and became 100.0.
        let routes = parse_routes_from(
            r#"
            routes {
                route "float-pct" {
                    matches { path-prefix "/" }
                    upstream "backend"
                    shadow { upstream "canary"; percentage 12.5 }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].shadow.as_ref().unwrap().percentage, 12.5);

        let routes = parse_routes_from(
            r#"
            routes {
                route "string-pct" {
                    matches { path-prefix "/" }
                    upstream "backend"
                    shadow { upstream "canary"; percentage "75" }
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].shadow.as_ref().unwrap().percentage, 75.0);
    }

    /// `service-type` was accepted and never read, so `service-type "api"`
    /// left the route as `web` and it served HTML errors instead of JSON.
    #[test]
    fn explicit_service_type_is_applied() {
        let routes = parse_routes_from(
            r#"
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    upstream "backend"
                    service-type "api"
                }
                route "web" {
                    matches { path-prefix "/" }
                    upstream "backend"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].service_type, ServiceType::Api);
        assert_eq!(routes[1].service_type, ServiceType::Web);
    }

    #[test]
    fn service_type_matching_its_block_is_accepted() {
        let routes = parse_routes_from(
            r#"
            routes {
                route "health" {
                    matches { path "/health" }
                    service-type "builtin"
                    builtin-handler "health"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].service_type, ServiceType::Builtin);
    }

    /// A value the route's blocks contradict, or one that is not a type, has
    /// been loading fine for as long as `service-type` was ignored. It keeps
    /// loading, with the implied type, and is reported instead.
    #[test]
    fn contradicting_or_unknown_service_type_keeps_the_implied_type() {
        let routes = parse_routes_from(
            r#"
            routes {
                route "assets" {
                    matches { path-prefix "/static" }
                    upstream "backend"
                    service-type "static"
                }
                route "grpc" {
                    matches { path-prefix "/grpc" }
                    upstream "backend"
                    service-type "grpc"
                }
            }
            "#,
        )
        .unwrap();
        assert_eq!(routes[0].service_type, ServiceType::Web);
        assert_eq!(routes[1].service_type, ServiceType::Web);
    }

    #[test]
    fn service_type_problems_are_described() {
        let doc: kdl::KdlDocument = r#"
            route "assets" {
                upstream "backend"
                service-type "static"
            }
            route "grpc" {
                upstream "backend"
                service-type "grpc"
            }
            route "api" {
                upstream "backend"
                service-type "api"
            }
        "#
        .parse()
        .unwrap();
        let problems: Vec<_> = doc
            .nodes()
            .iter()
            .map(|n| resolve_service_type(n, &get_first_arg_string(n).unwrap()).1)
            .collect();
        let assets = problems[0].as_deref().unwrap();
        assert!(assets.contains("needs a static-files block"), "{assets}");
        assert!(assets.contains("is being ignored"), "{assets}");
        let grpc = problems[1].as_deref().unwrap();
        assert!(grpc.contains("is not a service type"), "{grpc}");
        assert!(problems[2].is_none());
    }

    fn api_route_schema(schema_body: &str) -> serde_json::Value {
        let routes = parse_routes_from(&format!(
            r#"
            routes {{
                route "api" {{
                    matches {{ path-prefix "/api" }}
                    upstream "backend"
                    api-schema {{
                        request-schema {{
{schema_body}
                        }}
                    }}
                }}
            }}
            "#
        ))
        .unwrap();
        routes[0]
            .api_schema
            .as_ref()
            .unwrap()
            .request_schema
            .clone()
            .unwrap()
    }

    /// #524: one name made `required` a string, the schema failed to compile,
    /// and the route ran without validation.
    #[test]
    fn single_required_entry_becomes_an_array() {
        let schema = api_route_schema(
            r#"
            type "object"
            properties {
                email { type "string" }
                address {
                    type "object"
                    properties {
                        city { type "string" }
                    }
                    required "city"
                }
            }
            required "email"
            "#,
        );
        assert_eq!(schema["required"], serde_json::json!(["email"]));
        assert_eq!(
            schema["properties"]["address"]["required"],
            serde_json::json!(["city"])
        );
        assert!(jsonschema::draft7::new(&schema).is_ok());
    }

    #[test]
    fn a_property_named_required_is_not_rewritten() {
        let schema = api_route_schema(
            r#"
            type "object"
            properties {
                required { type "boolean" }
            }
            required "required" "other"
            "#,
        );
        assert_eq!(
            schema["properties"]["required"],
            serde_json::json!({"type": "boolean"})
        );
        assert_eq!(schema["required"], serde_json::json!(["required", "other"]));
    }

    /// A schema that still does not compile is a configuration error, not a
    /// route that silently runs unvalidated.
    #[test]
    fn an_uncompilable_schema_fails_validation() {
        let kdl = r#"
            system { worker-threads 1 }
            listeners {
                listener "http" {
                    address "127.0.0.1:8080"
                    protocol "http"
                }
            }
            routes {
                route "api" {
                    matches { path-prefix "/api" }
                    upstream "backend"
                    api-schema {
                        request-schema {
                            type "object"
                            minProperties "two"
                        }
                    }
                }
            }
            upstreams {
                upstream "backend" { target "127.0.0.1:3000"; }
            }
        "#;
        let config = crate::Config::from_kdl(kdl).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("request-schema is not a valid JSON Schema"),
            "{err}"
        );
    }

    /// Values that name nothing the parser knows keep today's fallback, and
    /// are reported instead of vanishing (#521).
    mod ignored_values {
        use super::*;

        fn route_node(body: &str) -> kdl::KdlDocument {
            format!("route \"r\" {{\n{body}\n}}")
                .parse()
                .expect("kdl should parse")
        }

        fn methods_of(matches: &str) -> Vec<String> {
            let doc: kdl::KdlDocument =
                format!("routes {{ route \"r\" {{ matches {{ {matches} }}\n upstream \"b\" }} }}")
                    .parse()
                    .expect("kdl should parse");
            let route = parse_routes(doc.nodes().first().unwrap())
                .expect("routes should parse")
                .remove(0);
            match &route.matches[..] {
                [MatchCondition::Method(methods)] => methods.clone(),
                other => panic!("expected one method condition, got {other:?}"),
            }
        }

        /// Every argument used to be dropped after the first, so the route
        /// below matched GET and never POST.
        #[test]
        fn every_method_argument_is_kept() {
            assert_eq!(methods_of(r#"method "GET" "POST""#), ["GET", "POST"]);
            assert_eq!(methods_of(r#"method "PUT""#), ["PUT"]);
        }

        #[test]
        fn a_non_string_method_is_still_rejected() {
            let doc: kdl::KdlDocument = "routes { route \"r\" { matches { method 42 } } }"
                .parse()
                .unwrap();
            assert!(parse_routes(doc.nodes().first().unwrap()).is_err());
        }

        #[test]
        fn an_unknown_priority_keeps_normal_and_is_reported() {
            let doc = route_node(r#"priority "urgent""#);
            let (priority, problem) = resolve_priority(doc.nodes().first().unwrap(), "r");
            assert_eq!(priority, Priority::NORMAL);
            let problem = problem.expect("an unknown priority should be reported");
            assert!(problem.contains("\"urgent\""), "{problem}");
            assert!(problem.contains("is being ignored"), "{problem}");
        }

        #[test]
        fn known_priorities_are_not_reported() {
            for value in ["100", "\"high\"", "\"LOW\"", "-5"] {
                let doc = route_node(&format!("priority {value}"));
                assert_eq!(resolve_priority(doc.nodes().first().unwrap(), "r").1, None);
            }
            let doc = route_node("upstream \"b\"");
            assert_eq!(resolve_priority(doc.nodes().first().unwrap(), "r").1, None);
        }

        #[test]
        fn an_unknown_builtin_handler_is_reported_with_a_suggestion() {
            let doc = route_node(r#"builtin-handler "helth""#);
            let (handler, problem) = resolve_builtin_handler(doc.nodes().first().unwrap(), "r");
            assert_eq!(handler, None);
            let problem = problem.expect("an unknown handler should be reported");
            assert!(problem.contains("is being ignored"), "{problem}");
            assert!(problem.contains("Did you mean 'health'?"), "{problem}");
        }

        #[test]
        fn every_listed_builtin_handler_is_one() {
            for name in BUILTIN_HANDLER_NAMES {
                assert!(parse_builtin_handler(name).is_some(), "{name}");
            }
        }

        #[test]
        fn known_builtin_handlers_are_not_reported() {
            let doc = route_node(r#"builtin-handler "cache_purge""#);
            let (handler, problem) = resolve_builtin_handler(doc.nodes().first().unwrap(), "r");
            assert_eq!(handler, Some(BuiltinHandler::CachePurge));
            assert_eq!(problem, None);
        }
    }
}
