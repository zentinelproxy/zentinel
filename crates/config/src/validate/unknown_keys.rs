//! Reports configuration keys that no parser reads.
//!
//! KDL blocks accept any key. A name the parser does not recognise is dropped
//! without complaint, so a misspelling produces no error, no warning, and no
//! effect — the proxy runs on the default while the config file says otherwise.
//! That has cost real behaviour more than once: `max-lifetime-secs` left
//! connection pools with no lifetime cap, and the whole `timeouts` block was
//! discarded in favour of defaults, because in each case the parser read a
//! slightly different name than every config wrote.
//!
//! This check works from the KDL document rather than the parsed `Config`,
//! because by the time a `Config` exists the unknown keys are already gone.
//!
//! # Only closed blocks are checked
//!
//! Some blocks legitimately hold arbitrary keys — a JSON schema's properties,
//! a header map, agent configuration forwarded verbatim. Warning about those
//! would be noise, and noise in a linter is worse than silence because it
//! teaches people to skip the output.
//!
//! So this checks an explicit list of blocks whose key set is known and fixed
//! (`CLOSED_BLOCKS`). Anything not on that list is not inspected. Adding a
//! block to the list is deliberately a decision, and `shipped_configs_use_only_known_keys`
//! guards it: if a real config uses a key the list does not know about, that
//! test fails rather than operators getting a false warning.
//!
//! Part of zentinelproxy/zentinel#365.

use super::{ValidationResult, ValidationWarning};

/// Where a block has to appear for its key list to apply.
///
/// Block names are not unique. `cache` at the top level configures the storage
/// backend (`backend`, `disk-path`, `max-size`); `cache` inside a `route`
/// configures that route's policy (`default-ttl-secs`, `stale-if-error-secs`).
/// The two share no keys at all, so matching on the node name alone would force
/// this check to accept the union — and accepting the union is precisely how
/// #90 went unreported, where `backend "disk"` and `disk-path` were written into
/// a route's `cache` block and silently did nothing.
#[derive(PartialEq, Eq)]
enum Nesting {
    /// Matches wherever the name appears. Correct when the name is unique.
    Anywhere,
    /// Matches only as a top-level block.
    Root,
    /// Matches only as a direct child of the named block.
    In(&'static str),
    /// Matches a node inside `parent` carrying a child node `child` whose value
    /// is `value`.
    ///
    /// For blocks discriminated by a setting rather than by their own argument:
    /// a `filter` block's valid settings depend on its `type` child, while its
    /// own argument is just the filter's id.
    InWithChild {
        parent: &'static str,
        child: &'static str,
        value: &'static str,
    },
    /// Matches a node inside `parent` whose own first argument is `arg`.
    ///
    /// For blocks whose valid keys depend on the value they carry:
    /// `type "http" { path "/health" }` and `type "grpc" { service "..." }` are
    /// both `type` blocks inside `health-check`, and neither accepts the
    /// other's settings.
    InWithArg {
        parent: &'static str,
        arg: &'static str,
    },
}

/// A block whose full set of valid keys is known.
struct ClosedBlock {
    /// The block's node name in KDL.
    name: &'static str,
    /// Where this key list applies.
    nesting: Nesting,
    /// Every key the parser reads inside it, including nested block names.
    keys: &'static [&'static str],
}

impl ClosedBlock {
    /// Whether this entry describes `node`, sitting directly inside `parent`.
    fn matches(&self, node: &kdl::KdlNode, parent: Option<&str>) -> bool {
        if self.name != node.name().value() {
            return false;
        }
        match self.nesting {
            Nesting::Anywhere => true,
            Nesting::Root => parent.is_none(),
            Nesting::In(required) => parent == Some(required),
            Nesting::InWithArg {
                parent: required,
                arg,
            } => parent == Some(required) && first_arg(node) == Some(arg),
            Nesting::InWithChild {
                parent: required,
                child,
                value,
            } => parent == Some(required) && child_value(node, child) == Some(value),
        }
    }

    /// How narrowly this entry applies. Higher wins when several match.
    fn specificity(&self) -> u8 {
        match self.nesting {
            Nesting::Anywhere => 0,
            Nesting::Root | Nesting::In(_) => 1,
            Nesting::InWithArg { .. } | Nesting::InWithChild { .. } => 2,
        }
    }
}

/// The value of a node's named child, if it has one.
fn child_value<'a>(node: &'a kdl::KdlNode, child: &str) -> Option<&'a str> {
    node.children()?
        .nodes()
        .iter()
        .find(|n| n.name().value() == child)
        .and_then(first_arg)
}

/// A node's first argument as a string, if it has one.
fn first_arg(node: &kdl::KdlNode) -> Option<&str> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
}

/// The entry describing this node, preferring the most narrowly scoped match.
///
/// `type "http"` inside `health-check` matches both the value-qualified entry
/// and any broader one; the value-qualified entry is the accurate description,
/// so it wins.
fn block_for<'a>(node: &kdl::KdlNode, parent: Option<&str>) -> Option<&'a ClosedBlock> {
    CLOSED_BLOCKS
        .iter()
        .filter(|b| b.matches(node, parent))
        .max_by_key(|b| b.specificity())
}

/// Blocks this check inspects.
///
/// Each entry must list *every* key the corresponding parser reads, aliases
/// included. Under-listing produces false warnings on valid configs, which is
/// the failure mode to avoid.
const CLOSED_BLOCKS: &[ClosedBlock] = &[
    ClosedBlock {
        name: "connection-pool",
        nesting: Nesting::Anywhere,
        keys: &[
            "max-connections",
            "max-idle",
            "idle-timeout-secs",
            "max-lifetime-secs",
            // Accepted aliases; see parse_connection_pool.
            "idle-timeout",
            "max-lifetime",
        ],
    },
    ClosedBlock {
        name: "timeouts",
        nesting: Nesting::Anywhere,
        keys: &[
            "connect-secs",
            "request-secs",
            "read-secs",
            "write-secs",
            // Accepted aliases; see parse_upstream_timeouts.
            "connect",
            "request",
            "read",
            "write",
        ],
    },
    ClosedBlock {
        name: "ruleset",
        nesting: Nesting::Anywhere,
        keys: &[
            "crs-version",
            "custom-rules-dir",
            "paranoia-level",
            "anomaly-threshold",
            // Exclusions are accepted grouped in a wrapper or listed directly.
            "exclusions",
            "exclusion",
        ],
    },
    // `route` and `system` both keep their key list beside their parser, so
    // that adding a setting and forgetting the list is visible at the point of
    // the change rather than here.
    ClosedBlock {
        name: "route",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::routes::RECOGNIZED_ROUTE_CHILDREN,
    },
    // `limits` appears at the top level and inside a namespace or service,
    // all read by `parse_limits_config`. Listed by position rather than as
    // `Anywhere` so a `limits` node inside free-form agent configuration is
    // left alone.
    ClosedBlock {
        name: "limits",
        nesting: Nesting::Root,
        keys: crate::kdl::RECOGNIZED_LIMITS_KEYS,
    },
    ClosedBlock {
        name: "limits",
        nesting: Nesting::In("namespace"),
        keys: crate::kdl::RECOGNIZED_LIMITS_KEYS,
    },
    ClosedBlock {
        name: "limits",
        nesting: Nesting::In("service"),
        keys: crate::kdl::RECOGNIZED_LIMITS_KEYS,
    },
    ClosedBlock {
        name: "system",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::server::RECOGNIZED_SYSTEM_KEYS,
    },
    ClosedBlock {
        // Deprecated spelling of `system`, parsed by the same function.
        name: "server",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::server::RECOGNIZED_SYSTEM_KEYS,
    },
    ClosedBlock {
        name: "listener",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::server::RECOGNIZED_LISTENER_KEYS,
    },
    // A service's single `listener` block is read by its own parser, which
    // also takes its id from an `id` key (#548: it reported `id` as ignored).
    ClosedBlock {
        name: "listener",
        nesting: Nesting::In("service"),
        keys: crate::kdl::namespace::RECOGNIZED_SERVICE_LISTENER_KEYS,
    },
    ClosedBlock {
        // Storage backend. Distinct from the per-route `cache` policy below:
        // they share a name and not one key.
        name: "cache",
        nesting: Nesting::Root,
        keys: &[
            "enabled",
            "backend",
            "max-size",
            "eviction-limit",
            "lock-timeout",
            // Accepted aliases; see CACHE_KEY_ALIASES.
            "max-size-bytes",
            "lock-timeout-secs",
            "disk-path",
            "disk-shards",
            "disk-max-size",
            "status-header",
            "status-header-name",
        ],
    },
    ClosedBlock {
        // Per-route cache policy. `backend`, `disk-path` and the other storage
        // settings belong in the top-level block and do nothing here -- #90.
        name: "cache",
        nesting: Nesting::In("route"),
        keys: &[
            "enabled",
            "default-ttl-secs",
            "max-size-bytes",
            "cache-private",
            "stale-while-revalidate-secs",
            "stale-if-error-secs",
            "cacheable-methods",
            "cacheable-status-codes",
            "exclude-extensions",
            "exclude-paths",
            "ignore-query-params",
            "vary-headers",
        ],
    },
    ClosedBlock {
        // The listener TLS parser rejects unknown nodes here outright
        // (`reject_unknown_nodes`), so this mainly covers the same ground a
        // second time -- but it shares the parser's list rather than copying
        // it, so the two cannot drift apart.
        name: "sni",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::server::KNOWN_SNI_NODES,
    },
    ClosedBlock {
        name: "sni-certs",
        nesting: Nesting::Anywhere,
        keys: &["cert-folder", "reload-mode", "reload-interval"],
    },
    ClosedBlock {
        name: "acme",
        nesting: Nesting::Anywhere,
        keys: &[
            "email",
            "domains",
            "storage",
            "staging",
            "server-url",
            "challenge-type",
            "dns-provider",
            "key-type",
            "renew-before-days",
            "eab",
        ],
    },
    ClosedBlock {
        // External Account Binding, nested inside `acme`.
        name: "eab",
        nesting: Nesting::Anywhere,
        keys: &["kid", "hmac-key"],
    },
    ClosedBlock {
        name: "upstream",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::upstreams::RECOGNIZED_UPSTREAM_KEYS,
    },
    ClosedBlock {
        // An upstream's `tls` block. A listener's `tls` block shares the name
        // and not one key, hence the qualification.
        //
        // The listener side is deliberately absent: `parse_tls_config` already
        // rejects unknown nodes with a hard error and a targeted hint, so a
        // lint warning there would arrive after the config had already failed
        // to load. Upstream TLS has no such check, which is why this one earns
        // its place.
        name: "tls",
        nesting: Nesting::In("upstream"),
        keys: crate::kdl::upstreams::RECOGNIZED_UPSTREAM_TLS_KEYS,
    },
    ClosedBlock {
        // The union of every discovery backend's settings. Keys belonging to a
        // backend other than the one named are rejected by `parse_discovery`
        // with a hard error, so this list only has to catch outright typos.
        name: "discovery",
        nesting: Nesting::In("upstream"),
        keys: crate::kdl::upstreams::RECOGNIZED_DISCOVERY_KEYS,
    },
    ClosedBlock {
        name: "target",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::upstreams::RECOGNIZED_TARGET_KEYS,
    },
    ClosedBlock {
        name: "health-check",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::upstreams::RECOGNIZED_HEALTH_CHECK_KEYS,
    },
    // The `type` block's settings depend on the type it names, so each value
    // gets its own entry. `type "http" { service "..." }` is a gRPC setting on
    // an HTTP check and is reported as such.
    ClosedBlock {
        name: "type",
        nesting: Nesting::InWithArg {
            parent: "health-check",
            arg: "http",
        },
        keys: crate::kdl::upstreams::RECOGNIZED_HTTP_CHECK_KEYS,
    },
    ClosedBlock {
        name: "type",
        nesting: Nesting::InWithArg {
            parent: "health-check",
            arg: "grpc",
        },
        keys: crate::kdl::upstreams::RECOGNIZED_GRPC_CHECK_KEYS,
    },
    ClosedBlock {
        name: "type",
        nesting: Nesting::InWithArg {
            parent: "health-check",
            arg: "inference",
        },
        keys: crate::kdl::upstreams::RECOGNIZED_INFERENCE_CHECK_KEYS,
    },
    ClosedBlock {
        name: "type",
        nesting: Nesting::InWithArg {
            parent: "health-check",
            arg: "tcp",
        },
        keys: crate::kdl::upstreams::RECOGNIZED_TCP_CHECK_KEYS,
    },
    ClosedBlock {
        name: "type",
        nesting: Nesting::InWithArg {
            parent: "health-check",
            arg: "mcp",
        },
        keys: crate::kdl::upstreams::RECOGNIZED_MCP_CHECK_KEYS,
    },
    ClosedBlock {
        name: "readiness",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::upstreams::RECOGNIZED_READINESS_KEYS,
    },
    ClosedBlock {
        name: "inference-probe",
        nesting: Nesting::In("readiness"),
        keys: crate::kdl::upstreams::RECOGNIZED_INFERENCE_PROBE_KEYS,
    },
    ClosedBlock {
        name: "model-status",
        nesting: Nesting::In("readiness"),
        keys: crate::kdl::upstreams::RECOGNIZED_MODEL_STATUS_KEYS,
    },
    ClosedBlock {
        name: "queue-depth",
        nesting: Nesting::In("readiness"),
        keys: crate::kdl::upstreams::RECOGNIZED_QUEUE_DEPTH_KEYS,
    },
    ClosedBlock {
        name: "warmth-detection",
        nesting: Nesting::In("readiness"),
        keys: crate::kdl::upstreams::RECOGNIZED_WARMTH_DETECTION_KEYS,
    },
    ClosedBlock {
        name: "agent",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_AGENT_KEYS,
    },
    // An agent's transport blocks. Each also accepts its address as a bare
    // argument (`grpc "http://..."`), which needs no key at all.
    ClosedBlock {
        name: "unix-socket",
        nesting: Nesting::In("agent"),
        keys: &["path"],
    },
    ClosedBlock {
        name: "grpc",
        nesting: Nesting::In("agent"),
        keys: &["address", "tls"],
    },
    ClosedBlock {
        name: "http",
        nesting: Nesting::In("agent"),
        keys: &["url", "tls"],
    },
    // An agent transport's `tls` block -- a third meaning of the name, after
    // the listener's and the upstream's.
    ClosedBlock {
        name: "tls",
        nesting: Nesting::In("grpc"),
        keys: crate::kdl::RECOGNIZED_AGENT_TLS_KEYS,
    },
    ClosedBlock {
        name: "tls",
        nesting: Nesting::In("http"),
        keys: crate::kdl::RECOGNIZED_AGENT_TLS_KEYS,
    },
    ClosedBlock {
        name: "rate-limits",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_RATE_LIMITS_KEYS,
    },
    ClosedBlock {
        name: "global",
        nesting: Nesting::In("rate-limits"),
        keys: crate::kdl::RECOGNIZED_GLOBAL_LIMIT_KEYS,
    },
    // A filter's settings depend on its `type` child, not on its own argument,
    // which is just the filter's id. Only rate-limit filters are described
    // here; a filter of any other type matches nothing and is left unchecked.
    ClosedBlock {
        name: "filter",
        nesting: Nesting::InWithChild {
            parent: "filters",
            child: "type",
            value: "rate-limit",
        },
        keys: crate::kdl::filters::RECOGNIZED_RATE_LIMIT_FILTER_KEYS,
    },
    ClosedBlock {
        name: "observability",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_OBSERVABILITY_KEYS,
    },
    ClosedBlock {
        name: "logging",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_LOGGING_KEYS,
    },
    ClosedBlock {
        name: "access-log",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_ACCESS_LOG_KEYS,
    },
    ClosedBlock {
        // Takes `level` where the access log takes `format`; the two look alike
        // and accept different settings.
        name: "error-log",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_ERROR_LOG_KEYS,
    },
    ClosedBlock {
        name: "audit-log",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_AUDIT_LOG_KEYS,
    },
    ClosedBlock {
        name: "metrics",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_METRICS_KEYS,
    },
    ClosedBlock {
        name: "tracing",
        nesting: Nesting::Anywhere,
        keys: crate::kdl::RECOGNIZED_TRACING_KEYS,
    },
    ClosedBlock {
        // Qualified: a rate-limit filter also has a `backend`, but that one is
        // a scalar setting rather than a block.
        name: "backend",
        nesting: Nesting::In("tracing"),
        keys: crate::kdl::RECOGNIZED_TRACING_BACKEND_KEYS,
    },
    ClosedBlock {
        name: "error-pages",
        nesting: Nesting::In("route"),
        keys: crate::kdl::error_pages::RECOGNIZED_ERROR_PAGES_KEYS,
    },
    ClosedBlock {
        name: "policies",
        nesting: Nesting::Anywhere,
        keys: &[
            "request-headers",
            "response-headers",
            "cache",
            "timeout-secs",
            "max-body-size",
            "failure-mode",
            "rate-limit",
            // "buffer-requests" / "buffer-responses" were listed here to keep
            // this check quiet about a known gap. #366 removed the fields, so
            // they are now reported like any other key nothing reads.
        ],
    },
];

/// Warn about keys inside closed blocks that no parser reads.
pub fn check_unknown_keys(kdl_source: &str, result: &mut ValidationResult) {
    let Ok(document) = kdl_source.parse::<kdl::KdlDocument>() else {
        // A document that does not parse is not this check's problem; the
        // parser will have produced a better error already.
        return;
    };

    let context = Context::of([&document]);
    for node in document.nodes() {
        walk(node, None, &context, result);
    }
}

/// [`check_unknown_keys`] for a configuration read from several files.
///
/// Each file is checked on its own text, so a run-together line is found where
/// it was written, and each warning names its file. What a check needs to know
/// about the rest of the configuration (which filters use an agent) comes from
/// all of them, since that can sit in another file. Checking only the entry
/// file, as `test --strict` once did, passed any typo in an included file.
pub fn check_unknown_keys_in_files(
    sources: &[(std::path::PathBuf, String)],
    result: &mut ValidationResult,
) {
    let documents: Vec<_> = sources
        .iter()
        .filter_map(|(path, text)| Some((path, text.parse::<kdl::KdlDocument>().ok()?)))
        .collect();

    let context = Context::of(documents.iter().map(|(_, document)| document));
    for (path, document) in &documents {
        let mut found = ValidationResult::new();
        for node in document.nodes() {
            walk(node, None, &context, &mut found);
        }
        for warning in found.warnings {
            result.add_warning(ValidationWarning::new(format!(
                "{}: {}",
                path.display(),
                warning.message
            )));
        }
    }
}

/// What a check needs to know about the rest of the document.
struct Context {
    /// For each agent id, the agent filters that use it and set no failure
    /// mode of their own (or one that is ignored).
    filters_without_failure_mode: std::collections::HashMap<String, Vec<String>>,
    /// Each agent block's `timeout-ms`, or the default when it sets none.
    agent_timeouts: std::collections::HashMap<String, u64>,
    /// For each agent block, whether its `events` include request bodies,
    /// and its `max-request-body-bytes` (or the default).
    agent_request_bodies: std::collections::HashMap<String, (bool, usize)>,
}

impl Context {
    fn of<'a>(documents: impl IntoIterator<Item = &'a kdl::KdlDocument>) -> Self {
        let mut context = Context {
            filters_without_failure_mode: Default::default(),
            agent_timeouts: Default::default(),
            agent_request_bodies: Default::default(),
        };
        for document in documents {
            for node in document.nodes() {
                context.collect(node);
            }
        }
        context
    }

    fn collect(&mut self, node: &kdl::KdlNode) {
        // An agent definition, as opposed to a filter's `agent "id"` line,
        // which has no block.
        if node.name().value() == "agent" && node.children().is_some() {
            if let Some(agent_id) = first_arg(node) {
                let timeout = node
                    .children()
                    .and_then(|c| c.get("timeout-ms"))
                    .and_then(|n| n.entries().first())
                    .and_then(|e| e.value().as_integer())
                    .map(|v| v as u64)
                    .unwrap_or(crate::kdl::DEFAULT_AGENT_TIMEOUT_MS);
                self.agent_timeouts.insert(agent_id.to_string(), timeout);
                let receives_bodies =
                    node.children()
                        .and_then(|c| c.get("events"))
                        .is_some_and(|events| {
                            events.entries().iter().any(|e| {
                                matches!(
                                    e.value().as_string(),
                                    Some("request-body" | "request_body")
                                )
                            })
                        });
                let limit = node
                    .children()
                    .and_then(|c| c.get("max-request-body-bytes"))
                    .and_then(|n| n.entries().first())
                    .and_then(|e| e.value().as_integer())
                    .map(|v| v as usize)
                    .unwrap_or(crate::agents::DEFAULT_AGENT_MAX_BODY_BYTES);
                self.agent_request_bodies
                    .insert(agent_id.to_string(), (receives_bodies, limit));
            }
        }
        if node.name().value() == "filter" && child_value(node, "type") == Some("agent") {
            if let (Some(filter_id), Some(agent_id)) = (first_arg(node), child_value(node, "agent"))
            {
                let (mode, _) =
                    crate::kdl::filters::resolve_agent_filter_failure_mode(node, filter_id);
                if mode.is_none() {
                    self.filters_without_failure_mode
                        .entry(agent_id.to_string())
                        .or_default()
                        .push(filter_id.to_string());
                }
            }
        }
        if let Some(children) = node.children() {
            for child in children.nodes() {
                self.collect(child);
            }
        }
    }
}

/// Depth-first walk, checking any node that names a closed block.
///
/// `parent` is the name of the block this node sits directly inside, or `None`
/// at the top level. It is what lets two blocks share a name and keep separate
/// key lists -- see [`Nesting`].
fn walk(
    node: &kdl::KdlNode,
    parent: Option<&str>,
    context: &Context,
    result: &mut ValidationResult,
) {
    let name = node.name().value();

    check_values(node, parent, context, result);

    if let Some(block) = block_for(node, parent) {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                let key = child.name().value();
                if !block.keys.contains(&key) {
                    result.add_warning(ValidationWarning::new(unknown_key_message(block, key)));
                }
                check_run_together(block, child, result);
            }
        }
    }

    if let Some(children) = node.children() {
        for child in children.nodes() {
            walk(child, Some(name), context, result);
        }
    }
}

/// Report known keys whose *value* is ignored.
///
/// The keys below pass the check for unknown keys, but each parser falls back
/// to a default when the value names nothing it knows: `load-balancing
/// "least-conections"` is round robin, `priority "urgent"` is normal. Those
/// fallbacks are kept, since configs carrying such values have been loading
/// and must keep doing so; what changes is that they are reported. Whether a
/// value is known is decided by the parser's own function in each case, so
/// this check and the parser cannot disagree.
fn check_values(
    node: &kdl::KdlNode,
    parent: Option<&str>,
    context: &Context,
    result: &mut ValidationResult,
) {
    let id = first_arg(node);
    let mut report = |problem: Option<String>| {
        if let Some(problem) = problem {
            result.add_warning(ValidationWarning::new(problem));
        }
    };

    match (node.name().value(), id) {
        ("route", Some(route_id)) => {
            // `service-type` is applied or not depending on the route's
            // other blocks.
            report(crate::kdl::routes::resolve_service_type(node, route_id).1);
            report(crate::kdl::routes::resolve_priority(node, route_id).1);
            report(crate::kdl::routes::resolve_builtin_handler(node, route_id).1);
            let service_type = crate::kdl::routes::resolve_service_type(node, route_id).0;
            let (_, problems) =
                crate::kdl::error_pages::resolve_error_pages(node, route_id, &service_type);
            for problem in problems {
                report(Some(problem));
            }
        }
        ("pages", _) if parent == Some("error-pages") => check_error_page_keys(node, result),
        ("upstream", Some(upstream_id)) => {
            let (algorithm, problem) =
                crate::kdl::upstreams::resolve_load_balancing(node, upstream_id);
            report(problem);
            // The sticky settings are read only when the algorithm is sticky.
            if algorithm == crate::LoadBalancingAlgorithm::Sticky {
                if let Some(sticky) = node
                    .children()
                    .and_then(|c| c.get("load-balancing"))
                    .and_then(|n| n.children())
                {
                    let (_, problems) =
                        crate::kdl::upstreams::resolve_sticky_session_config(sticky, upstream_id);
                    for problem in problems {
                        report(Some(problem));
                    }
                }
            }
            if let Some(check) = node.children().and_then(|c| c.get("health-check")) {
                report(crate::kdl::upstreams::health_check_type_problem(
                    check,
                    upstream_id,
                ));
            }
        }
        ("filter", Some(filter_id)) if child_value(node, "type") == Some("agent") => {
            report(crate::kdl::filters::resolve_agent_filter_failure_mode(node, filter_id).1);
            report(crate::kdl::filters::agent_filter_phase_problem(
                node, filter_id,
            ));
            report(agent_filter_timeout_problem(node, filter_id, context));
            for problem in agent_filter_body_problems(node, filter_id, context) {
                report(Some(problem));
            }
        }
        ("agent", Some(agent_id)) if parent == Some("agents") => {
            report(agent_failure_mode_problem(node, agent_id, context));
        }
        ("system" | "server", _) if parent.is_none() => {
            for problem in crate::kdl::server::unapplied_system_settings(node, node.name().value())
            {
                report(Some(problem));
            }
        }
        // The same positions the closed-block check lists for `limits`, so a
        // `limits` node inside free-form agent configuration is left alone. A
        // scoped block is checked from its namespace or service, which is
        // where its id is.
        ("limits", _) if parent.is_none() => {
            for problem in crate::kdl::unapplied_limits_settings(node) {
                report(Some(problem));
            }
        }
        ("namespace" | "service", Some(_)) => {
            for limits in node
                .children()
                .into_iter()
                .flat_map(|c| c.nodes())
                .filter(|n| n.name().value() == "limits")
            {
                for problem in crate::kdl::unapplied_limits_settings(limits) {
                    report(Some(problem));
                }
            }
        }
        ("cache", _) if parent.is_none() => {
            for problem in crate::kdl::cache_alias_problems(node) {
                report(Some(problem));
            }
        }
        ("matches", _) if parent == Some("route") => check_run_together_matches(node, result),
        _ => {}
    }
}

/// The keys of each page in an `error-pages` block's `pages`.
///
/// Pages are named by their status (`"503" { ... }`), so no fixed block name
/// describes them and they cannot sit in `CLOSED_BLOCKS`; this applies the
/// same check to every child of `pages` instead.
fn check_error_page_keys(pages: &kdl::KdlNode, result: &mut ValidationResult) {
    const ERROR_PAGE: ClosedBlock = ClosedBlock {
        name: "error page",
        nesting: Nesting::In("pages"),
        keys: crate::kdl::error_pages::RECOGNIZED_ERROR_PAGE_KEYS,
    };
    for page in pages.children().map(|c| c.nodes()).unwrap_or_default() {
        for key in page.children().map(|c| c.nodes()).unwrap_or_default() {
            let name = key.name().value();
            if !ERROR_PAGE.keys.contains(&name) {
                result.add_warning(ValidationWarning::new(unknown_key_message(
                    &ERROR_PAGE,
                    name,
                )));
            }
            check_run_together(&ERROR_PAGE, key, result);
        }
    }
}

/// Whether an agent filter's `timeout-ms` is unusable, or longer than its
/// agent's.
///
/// The filter's value can only shorten the agent's `timeout-ms` (see
/// `resolve_agent_filter_timeout`), so a longer one does nothing past the
/// agent's.
fn agent_filter_timeout_problem(
    filter: &kdl::KdlNode,
    filter_id: &str,
    context: &Context,
) -> Option<String> {
    let (timeout, problem) = crate::kdl::filters::resolve_agent_filter_timeout(filter, filter_id);
    if problem.is_some() {
        return problem;
    }
    let timeout = timeout?;
    let agent_id = child_value(filter, "agent")?;
    let agent_timeout = *context.agent_timeouts.get(agent_id)?;
    (timeout > agent_timeout).then(|| {
        format!(
            "'timeout-ms {timeout}' on filter '{filter_id}' is longer than agent \
             '{agent_id}''s timeout-ms {agent_timeout} and is being ignored beyond it: a filter \
             can shorten its agent's timeout, not extend it. Raise timeout-ms on the agent \
             instead."
        )
    })
}

/// Whether an agent filter's `inspect-body` or `max-body-bytes` does nothing.
///
/// Both only narrow what the agent's own settings send it (see
/// `resolve_agent_filter_inspect_body` and
/// `resolve_agent_filter_max_body_bytes`): neither can make an agent receive
/// request bodies its `events` do not include, and `max-body-bytes` cannot
/// exceed the agent's `max-request-body-bytes`.
fn agent_filter_body_problems(
    filter: &kdl::KdlNode,
    filter_id: &str,
    context: &Context,
) -> Vec<String> {
    let mut problems = Vec::new();
    let (inspect_body, problem) =
        crate::kdl::filters::resolve_agent_filter_inspect_body(filter, filter_id);
    problems.extend(problem);
    let (max_body_bytes, problem) =
        crate::kdl::filters::resolve_agent_filter_max_body_bytes(filter, filter_id);
    problems.extend(problem);

    let Some(agent_id) = child_value(filter, "agent") else {
        return problems;
    };
    let Some(&(receives_bodies, agent_limit)) = context.agent_request_bodies.get(agent_id) else {
        return problems;
    };

    if !receives_bodies {
        if inspect_body == Some(true) {
            problems.push(format!(
                "'inspect-body #true' on filter '{filter_id}' is being ignored: agent \
                 '{agent_id}' does not receive request bodies. Add \"request-body\" to the \
                 agent's events."
            ));
        }
        if let Some(limit) = max_body_bytes {
            problems.push(format!(
                "'max-body-bytes {limit}' on filter '{filter_id}' is being ignored: agent \
                 '{agent_id}' does not receive request bodies."
            ));
        }
    } else if let Some(limit) = max_body_bytes {
        if inspect_body == Some(false) {
            problems.push(format!(
                "'max-body-bytes {limit}' on filter '{filter_id}' is being ignored: the \
                 filter's 'inspect-body #false' sends agent '{agent_id}' no request body."
            ));
        } else if limit > agent_limit {
            problems.push(format!(
                "'max-body-bytes {limit}' on filter '{filter_id}' is larger than agent \
                 '{agent_id}''s max-request-body-bytes {agent_limit} and is being ignored \
                 beyond it: a filter can lower its agent's body limit, not raise it. Raise \
                 max-request-body-bytes on the agent instead."
            ));
        }
    }
    problems
}

/// Whether an agent block's `failure-mode` is being relied on where it does
/// not apply.
///
/// What a failed call to an agent means on a route -- on request headers,
/// request bodies, response headers and bodies, and for a body over the
/// agent's inspection limit -- is decided by the agent filter's
/// `failure-mode`, then the route's `policies { failure-mode }`, then closed
/// (`FilterAgent::failure_mode` in the proxy, #584). The agent's own
/// `failure-mode` applies only to WebSocket frames, which are not inspected
/// per route. An agent written with `failure-mode "open"` and a filter
/// without one therefore blocks requests when the agent is down.
///
/// Honouring the agent's value would turn setups that have been failing
/// closed into ones that fail open, so the behaviour stays and this reports
/// it instead -- only when some filter using the agent leaves the
/// decision open, since a filter with its own value states the intent.
fn agent_failure_mode_problem(
    agent: &kdl::KdlNode,
    agent_id: &str,
    context: &Context,
) -> Option<String> {
    let value = child_value(agent, "failure-mode")?;
    let filters = context.filters_without_failure_mode.get(agent_id)?;
    let filters = filters
        .iter()
        .map(|f| format!("'{f}'"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "'failure-mode \"{value}\"' on agent '{agent_id}' is being ignored for requests \
         and responses: that is decided by the agent filter's failure-mode, then the route's \
         policies failure-mode, and is closed when neither is set. Set failure-mode on \
         filter {filters} as well. The agent's own setting applies only to WebSocket frames."
    ))
}

/// The run-together check for a route's `matches` block.
///
/// `matches` is not a closed block — an unknown condition is already a hard
/// error at load — but a condition written on the same line as another one,
///
/// ```kdl
/// matches { path-prefix "/api" host "a.com" }
/// ```
///
/// is read as `path-prefix` with three arguments, and `host` is dropped. The
/// route then matches every host, which is the direction a silent match
/// failure must never go. Unlike [`check_run_together`], each condition's own
/// value arguments are exempt, since `header "x-kind" "path"` is a header
/// value and not a swallowed condition.
fn check_run_together_matches(matches: &kdl::KdlNode, result: &mut ValidationResult) {
    let Some(children) = matches.children() else {
        return;
    };
    for condition in children.nodes() {
        let key = condition.name().value();
        let own = crate::kdl::routes::match_condition_own_args(key);
        for entry in condition
            .entries()
            .iter()
            .filter(|e| e.name().is_none())
            .skip(own)
        {
            if let Some(value) = entry.value().as_string() {
                if crate::kdl::routes::is_match_condition(value) {
                    result.add_warning(ValidationWarning::new(run_together_message(
                        "matches", key, value,
                    )));
                }
            }
        }
    }
}

/// Warn when a node's surplus arguments name a sibling key.
///
/// KDL separates nodes by newline or `;`. Written on one line without either,
///
/// ```kdl
/// listener "public" { address "0.0.0.0:8080" namespace "iso" }
/// ```
///
/// is not two settings — it is a single `address` node carrying three
/// arguments, and the entry helpers read only the first. `namespace` is
/// dropped before any parser sees it, so the unknown-key check above cannot
/// see it either: there is no `namespace` child node to be unknown. The config
/// loads, validates and starts, and the setting simply does not exist. That is
/// how a listener's namespace isolation came to be silently absent in #396.
///
/// The signature is specific: an argument *after the first* whose value is the
/// name of a key in this same block. A node legitimately taking a list —
/// `hostnames "a.com" "b.com"` — never matches, because hostnames are not
/// listener keys. Only the first argument is exempt, since that is the node's
/// own value.
fn check_run_together(block: &ClosedBlock, child: &kdl::KdlNode, result: &mut ValidationResult) {
    let key = child.name().value();

    for entry in child.entries().iter().skip(1) {
        // Property syntax (`name=value`) is not a run-together line.
        if entry.name().is_some() {
            continue;
        }
        let Some(value) = entry.value().as_string() else {
            continue;
        };
        if block.keys.contains(&value) {
            result.add_warning(ValidationWarning::new(run_together_message(
                block.name, key, value,
            )));
        }
    }
}

/// Build the run-together warning.
///
/// Every finding of this module says "is being ignored": `zentinel test`
/// prints them under that heading, and docs CI and the playground filter on
/// the phrase.
fn run_together_message(block: &str, key: &str, swallowed: &str) -> String {
    format!(
        "'{swallowed}' is read as an argument to '{key}' rather than as a setting, \
         and is being ignored. In the '{block}' block, put each setting on its own line \
         (or separate them with ';')."
    )
}

/// How to refer to a block in a message, given where it has to appear.
fn describe(block: &ClosedBlock) -> String {
    match block.nesting {
        Nesting::Root => format!("the top-level '{}' block", block.name),
        Nesting::In(parent) => format!("a '{parent}' block's '{}' block", block.name),
        Nesting::InWithArg { parent, arg } => {
            format!("a '{parent}' block's '{} \"{arg}\"' block", block.name)
        }
        Nesting::InWithChild { child, value, .. } => {
            format!("a '{}' block with {child} \"{value}\"", block.name)
        }
        Nesting::Anywhere => format!("the '{}' block", block.name),
    }
}

/// Build the warning, with a suggestion when one key is clearly meant.
fn unknown_key_message(block: &ClosedBlock, key: &str) -> String {
    // A key that is valid in a *same-named* block elsewhere is not a typo, it
    // is in the wrong place -- `disk-path` in a route's `cache` rather than the
    // top-level one. Saying where it belongs is far more use than an
    // edit-distance guess, which would otherwise suggest the key back to itself.
    if let Some(other) = sibling_block_defining(block, key) {
        return format!(
            "'{key}' is a setting of {}, not of {}, and is being ignored here.",
            describe(other),
            describe(block)
        );
    }

    // The directory-config spelling of a limit. The edit distance from
    // `max-body-size-bytes` to `max-body-size` is within the suggestion budget
    // anyway, but the reason it is ignored is not a typo, and saying so stops
    // the next person from "fixing" the parser instead.
    if block.name == "limits" {
        if let Some(single_file) = key
            .strip_suffix("-bytes")
            .filter(|stem| block.keys.contains(stem))
        {
            return format!(
                "'{key}' is the directory-config name for this limit and is ignored in a \
                 single-file config. Did you mean '{single_file}'?"
            );
        }
    }

    match closest_key(block, key) {
        Some(suggestion) => format!(
            "'{key}' is not a setting in the '{}' block and is being ignored. \
             Did you mean '{suggestion}'?",
            block.name
        ),
        None => format!(
            "'{key}' is not a setting in the '{}' block and is being ignored.",
            block.name
        ),
    }
}

/// A block of the same name, in a different position, that does define `key`.
fn sibling_block_defining<'a>(block: &ClosedBlock, key: &str) -> Option<&'a ClosedBlock> {
    CLOSED_BLOCKS
        .iter()
        .find(|b| b.name == block.name && b.nesting != block.nesting && b.keys.contains(&key))
}

/// The nearest known key, when it is near enough to be worth naming.
///
/// Scoped to this block's own key list, so a block sharing a name with another
/// cannot borrow its keys as suggestions.
fn closest_key(block: &ClosedBlock, key: &str) -> Option<&'static str> {
    let candidates = block.keys;

    // A third of the length, so short keys need a close match and long ones
    // tolerate a suffix like `-secs`. Beyond that a suggestion is a guess, and
    // a wrong suggestion is worse than none.
    let budget = (key.len() / 3).max(2);

    candidates
        .iter()
        .map(|candidate| (*candidate, edit_distance(key, candidate)))
        .filter(|(_, distance)| *distance <= budget)
        .min_by_key(|(_, distance)| *distance)
        .map(|(candidate, _)| candidate)
}

/// Levenshtein distance, iterative with a single row.
fn edit_distance(a: &str, b: &str) -> usize {
    let b_chars: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b_chars.len()).collect();
    let mut current = vec![0; b_chars.len() + 1];

    for (i, a_char) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b_chars.iter().enumerate() {
            let substitution = previous[j] + usize::from(a_char != *b_char);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b_chars.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warnings_for(kdl: &str) -> Vec<String> {
        let mut result = ValidationResult::new();
        check_unknown_keys(kdl, &mut result);
        result.warnings.into_iter().map(|w| w.message).collect()
    }

    #[test]
    fn a_valid_block_produces_no_warnings() {
        let kdl = r#"
            upstreams {
                upstream "backend" {
                    connection-pool {
                        max-connections 100
                        max-idle 20
                        idle-timeout-secs 60
                        max-lifetime-secs 300
                    }
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty());
    }

    /// The bug this check exists for: a name one hyphen away from the real one.
    #[test]
    fn an_underscore_instead_of_a_hyphen_is_reported_with_a_suggestion() {
        let kdl = r#"
            routes {
                route "api" {
                    policies {
                        failure_mode "closed"
                    }
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("failure_mode"));
        assert!(warnings[0].contains("is being ignored"));
        assert!(
            warnings[0].contains("Did you mean 'failure-mode'?"),
            "expected a suggestion, got: {}",
            warnings[0]
        );
    }

    #[test]
    fn a_missing_hyphen_is_reported_with_a_suggestion() {
        let warnings = warnings_for(r#"routes { route "api" { policies { ratelimit { } } } }"#);
        assert_eq!(warnings.len(), 1);
        assert!(
            warnings[0].contains("Did you mean 'rate-limit'?"),
            "got: {}",
            warnings[0]
        );
    }

    /// The real-world case from #367: the config carried the unit suffix and
    /// the parser did not.
    #[test]
    fn a_unit_suffix_mismatch_is_reported() {
        let warnings =
            warnings_for(r#"upstreams { upstream "b" { timeouts { connect-seconds 5 } } }"#);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("connect-seconds"));
        assert!(warnings[0].contains("Did you mean 'connect-secs'?"));
    }

    #[test]
    fn a_key_resembling_nothing_is_reported_without_a_suggestion() {
        let warnings =
            warnings_for(r#"upstreams { upstream "b" { connection-pool { zzzzzzzzzzzz 1 } } }"#);
        assert_eq!(warnings.len(), 1);
        assert!(
            !warnings[0].contains("Did you mean"),
            "got: {}",
            warnings[0]
        );
    }

    /// Blocks that legitimately carry arbitrary keys must stay silent.
    #[test]
    fn blocks_outside_the_list_are_not_inspected() {
        let kdl = r#"
            routes {
                route "api" {
                    api-schema {
                        properties {
                            avatar_url "string"
                            created_at "string"
                        }
                    }
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty());
    }

    #[test]
    fn closed_blocks_are_found_at_any_depth() {
        let kdl = r#"
            namespace "team-a" {
                upstreams {
                    upstream "backend" {
                        timeouts { bogus-key 1 }
                    }
                }
            }
        "#;
        assert_eq!(warnings_for(kdl).len(), 1);
    }

    /// Guards the registry against under-listing. If a shipped config uses a
    /// key this check does not know, operators would get a warning about
    /// perfectly valid configuration — so that failure belongs here, loudly,
    /// rather than in someone's terminal.
    /// `workers` shipped in two configs and was read by nothing, so both ran on
    /// the default worker count while the file said 4 and 1.
    ///
    /// No suggestion is offered here, and that is worth recording rather than
    /// asserting away: `workers` is not a typo of `worker-threads`, it is a
    /// different, shorter name for the same idea, and it is too far away for
    /// the edit-distance heuristic to reach. The warning still names the key
    /// and says it is ignored, which is the part that matters.
    #[test]
    fn the_workers_key_that_shipped_in_two_configs_is_reported() {
        let kdl = r#"
            system {
                workers 4
                daemon #false
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(warnings[0].contains("workers"));
        assert!(warnings[0].contains("is being ignored"));
    }

    /// `max-connections` is a known key and absent here: it is reported for
    /// not being applied (#527), see `system_max_connections_is_reported`.
    #[test]
    fn a_valid_system_block_produces_no_warnings() {
        let kdl = r#"
            system {
                worker-threads 4
                graceful-shutdown-timeout-secs 30
                daemon #false
                pid-file "/var/run/zentinel.pid"
                user "zentinel"
                group "zentinel"
                working-directory "/var/lib/zentinel"
                trace-id-format "uuid"
                auto-reload #false
                route-cache-size 1024
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// `server` is the deprecated spelling and is parsed by the same function,
    /// so it has to be checked against the same keys.
    #[test]
    fn the_deprecated_server_block_is_checked_too() {
        let kdl = r#"
            server {
                worker_threads 4
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(warnings[0].contains("worker_threads"));
    }

    #[test]
    fn an_unknown_directive_in_a_route_is_reported() {
        let kdl = r#"
            routes {
                route "api" {
                    path_prefix "/api"
                    upstream "backend"
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(warnings[0].contains("path_prefix"));
    }

    #[test]
    fn a_valid_route_produces_no_warnings() {
        let kdl = r#"
            routes {
                route "api" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "backend"
                    priority 10
                    waf-enabled #true
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// The same trap in an MCP health check: written on one line,
    /// `expected-tools` is swallowed as an argument to `path` and the check
    /// silently probes liveness only. Caught while writing the tests for it.
    #[test]
    fn a_run_together_mcp_health_check_line_is_reported() {
        let kdl = r#"
            upstreams {
                upstream "mcp" {
                    target "mcp:8090"
                    health-check {
                        type "mcp" { path "/mcp" expected-tools "search_docs" }
                    }
                }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);

        let warnings = warning_texts(&result);
        assert!(
            warnings.iter().any(|w| w.contains("expected-tools")),
            "expected a run-together warning, got {warnings:?}"
        );
    }

    /// Written properly, it is silent.
    #[test]
    fn a_well_formed_mcp_health_check_is_not_reported() {
        let kdl = "
            upstreams {
                upstream \"mcp\" {
                    target \"mcp:8090\"
                    health-check {
                        type \"mcp\" {
                            path \"/mcp\"
                            expected-tools \"search_docs\" \"get_weather\"
                        }
                    }
                }
            }
        ";
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);
        assert!(
            warning_texts(&result).is_empty(),
            "{:?}",
            warning_texts(&result)
        );
    }

    /// The #396 case: `namespace` swallowed as an argument to `address`.
    #[test]
    fn a_run_together_listener_line_is_reported() {
        let kdl = r#"
            listeners {
                listener "public" { address "0.0.0.0:8080" namespace "iso" }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);

        let warnings = warning_texts(&result);
        assert_eq!(
            warnings.len(),
            1,
            "expected exactly one warning, got: {warnings:?}"
        );
        assert!(
            warnings[0].contains("'namespace'") && warnings[0].contains("'address'"),
            "warning should name both the swallowed setting and its host: {}",
            warnings[0]
        );
    }

    /// The same config written correctly must be silent.
    #[test]
    fn separated_listener_settings_are_not_reported() {
        for separator in ["\n", ";"] {
            let kdl = format!(
                r#"
                listeners {{
                    listener "public" {{ address "0.0.0.0:8080"{separator}namespace "iso" }}
                }}
                "#
            );
            let mut result = ValidationResult::default();
            check_unknown_keys(&kdl, &mut result);
            assert!(
                result.warnings.is_empty(),
                "separator {separator:?} should parse as two settings, got: {:?}",
                warning_texts(&result)
            );
        }
    }

    /// A node that legitimately takes a list must not be flagged. This is the
    /// false positive that would make the check unusable.
    #[test]
    fn a_node_taking_a_list_of_values_is_not_reported() {
        let kdl = r#"
            route "r" {
                policies {
                    cache {
                        cacheable-methods "GET" "HEAD"
                    }
                }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);
        assert!(
            result.warnings.is_empty(),
            "a value list is not a run-together line: {:?}",
            warning_texts(&result)
        );
    }

    /// Only arguments *after* the first are candidates: the first is the
    /// node's own value, and may legitimately equal a key name.
    #[test]
    fn a_value_equal_to_a_key_name_is_allowed_in_first_position() {
        let kdl = r#"
            listeners {
                listener "public" { address "0.0.0.0:8080" }
                listener "odd" { default-route "namespace" }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);
        assert!(
            result.warnings.is_empty(),
            "a first-position value is the node's own: {:?}",
            warning_texts(&result)
        );
    }

    /// Several settings can be swallowed by one line, and each is worth naming.
    #[test]
    fn every_swallowed_setting_on_a_line_is_reported() {
        let kdl = r#"
            listeners {
                listener "public" {
                    address "0.0.0.0:8080" namespace "iso" protocol "https"
                }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);

        let warnings = warning_texts(&result);
        assert_eq!(warnings.len(), 2, "got: {warnings:?}");
        assert!(warnings.iter().any(|w| w.contains("'namespace'")));
        assert!(warnings.iter().any(|w| w.contains("'protocol'")));
    }

    /// Property syntax is a different construct and not this check's business.
    #[test]
    fn property_syntax_is_not_a_run_together_line() {
        let kdl = r#"
            listeners {
                listener "public" { address "0.0.0.0:8080" namespace="iso" }
            }
        "#;
        let mut result = ValidationResult::default();
        check_unknown_keys(kdl, &mut result);
        assert!(
            result.warnings.is_empty(),
            "named entries are properties, not swallowed nodes: {:?}",
            warning_texts(&result)
        );
    }

    /// The #90 case: storage settings written into a route's cache policy,
    /// where they parse and do nothing. Reporting these is the whole reason the
    /// two `cache` blocks need separate key lists.
    #[test]
    fn storage_settings_in_a_route_cache_block_are_reported() {
        let kdl = r#"
            route "app" {
                cache {
                    enabled #true
                    backend "disk"
                    disk-path "/etc/zentinel/cache"
                    disk-shards 16
                }
            }
        "#;
        let warnings = warnings_for(kdl);

        for key in ["backend", "disk-path", "disk-shards"] {
            assert!(
                warnings.iter().any(|w| w.contains(&format!("'{key}'"))),
                "{key} belongs to the top-level cache block, not a route's: {warnings:?}"
            );
        }
        assert!(
            !warnings.iter().any(|w| w.contains("'enabled'")),
            "enabled is valid in both: {warnings:?}"
        );
    }

    /// Each `cache` block accepts its own keys and only its own.
    #[test]
    fn the_two_cache_blocks_keep_separate_key_lists() {
        let top_level = r#"
            cache {
                enabled #true
                backend "disk"
                disk-path "/var/cache/zentinel"
                max-size 1073741824
                status-header #true
            }
        "#;
        assert!(
            warnings_for(top_level).is_empty(),
            "{:?}",
            warnings_for(top_level)
        );

        let per_route = r#"
            route "app" {
                cache {
                    enabled #true
                    default-ttl-secs 86400
                    stale-if-error-secs 300
                    vary-headers "Accept"
                }
            }
        "#;
        assert!(
            warnings_for(per_route).is_empty(),
            "{:?}",
            warnings_for(per_route)
        );
    }

    /// Route policy settings in the top-level block are equally wrong, in the
    /// other direction.
    #[test]
    fn policy_settings_in_the_top_level_cache_block_are_reported() {
        let kdl = r#"
            cache {
                backend "memory"
                default-ttl-secs 3600
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'default-ttl-secs'")),
            "{warnings:?}"
        );
    }

    #[test]
    fn tls_certificate_blocks_are_checked() {
        let valid = r#"
            tls {
                sni {
                    hostnames "example.com"
                    cert-file "/c.crt"
                    key-file "/c.key"
                }
                sni-certs {
                    cert-folder "/etc/certs/dynamic/"
                    reload-mode "watch"
                    reload-interval "30s"
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        // `hostname` is the singular typo of a real key; `cert-dir` is not a key.
        let typos = r#"
            tls {
                sni { hostname "example.com" }
                sni-certs { cert-dir "/etc/certs/" }
            }
        "#;
        let warnings = warnings_for(typos);
        assert!(
            warnings.iter().any(|w| w.contains("'hostname'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("'cert-dir'")),
            "{warnings:?}"
        );
    }

    #[test]
    fn acme_and_its_eab_block_keep_separate_keys() {
        let valid = r#"
            acme {
                email "admin@example.com"
                domains "example.com"
                storage "/var/lib/zentinel/acme"
                challenge-type "http-01"
                eab {
                    kid "abc"
                    hmac-key "def"
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        // `kid` is an eab key, not an acme one.
        let misplaced = r#"
            acme {
                email "admin@example.com"
                kid "abc"
            }
        "#;
        assert!(
            warnings_for(misplaced).iter().any(|w| w.contains("'kid'")),
            "{:?}",
            warnings_for(misplaced)
        );
    }

    /// A run-together line inside one of the newly closed blocks is caught by
    /// the same check, since it reads the block's key list.
    #[test]
    fn run_together_lines_are_caught_in_the_new_blocks() {
        let kdl = r#"
            tls {
                sni-certs { cert-folder "/etc/certs/" reload-mode "watch" }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'reload-mode'") && w.contains("'cert-folder'")),
            "{warnings:?}"
        );
    }

    /// A misplaced key must be told where it belongs, not offered an
    /// edit-distance guess. Looking up suggestions by block *name* alone found
    /// the sibling list and produced "'backend' ... Did you mean 'backend'?",
    /// which reads as a linter malfunction.
    #[test]
    fn a_misplaced_key_names_the_block_it_belongs_to() {
        let kdl = r#"
            route "app" {
                cache { disk-path "/var/cache" }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "{warnings:?}");

        let warning = &warnings[0];
        assert!(
            warning.contains("top-level 'cache'"),
            "should say where it belongs: {warning}"
        );
        assert!(
            !warning.contains("Did you mean"),
            "a misplaced key is not a typo: {warning}"
        );
    }

    /// Suggestions must come from the block actually being checked, never from
    /// a same-named block elsewhere.
    #[test]
    fn suggestions_do_not_leak_between_same_named_blocks() {
        // `disk-pathh` is a typo of a *top-level* key, inside a route's cache.
        // It is not a key of either list, so the only honest suggestion comes
        // from the route cache's own keys -- or none at all.
        let kdl = r#"
            route "app" {
                cache { disk-pathh "/var/cache" }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            !warnings[0].contains("'disk-path'"),
            "suggestion leaked from the top-level block: {}",
            warnings[0]
        );
    }

    /// The single-target shorthand. `address` is read inside
    /// `parse_upstream_targets`, not in `parse_upstream`, so it appears nowhere
    /// in the upstream parser's body -- omitting it from the key list would
    /// warn about a perfectly valid config.
    #[test]
    fn the_upstream_address_shorthand_is_not_reported() {
        let kdl = r#"
            upstream "backend" {
                address "127.0.0.1:8081"
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    #[test]
    fn a_valid_upstream_produces_no_warnings() {
        let kdl = r#"
            upstream "backend" {
                target "127.0.0.1:8081" weight=2
                targets {
                    target { address "127.0.0.1:8082"; weight 3 }
                }
                load-balancing "round_robin"
                health-check { type "http" { path "/healthz" } }
                http-version { max-version 2 }
                connection-pool { max-connections 100 }
                timeouts { connect-secs 5 }
                tls { sni "backend.internal" }
                circuit-breaker { failure-threshold 5 }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    #[test]
    fn an_unknown_upstream_key_is_reported() {
        let kdl = r#"
            upstream "backend" {
                target "127.0.0.1:8081"
                retries 3
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'retries'")),
            "{warnings:?}"
        );
    }

    /// The two `tls` blocks share a name and no keys, exactly like the two
    /// `cache` blocks.
    #[test]
    fn upstream_tls_keys_are_distinct_from_listener_tls_keys() {
        let valid = r#"
            upstream "backend" {
                target "127.0.0.1:8081"
                tls {
                    sni "backend.internal"
                    insecure-skip-verify #false
                    client-cert "/c.crt"
                    client-key "/c.key"
                    ca-cert "/ca.crt"
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        // `cert-file` is a *listener* TLS key and does nothing on an upstream.
        let wrong = r#"
            upstream "backend" {
                target "127.0.0.1:8081"
                tls { cert-file "/c.crt" }
            }
        "#;
        assert!(
            warnings_for(wrong)
                .iter()
                .any(|w| w.contains("'cert-file'")),
            "{:?}",
            warnings_for(wrong)
        );
    }

    /// The dead key this check found in `config/examples/inference-routing.kdl`
    /// on its first run: certificate verification is controlled by
    /// `insecure-skip-verify`, and `verify` is read by nothing.
    #[test]
    fn the_verify_key_that_shipped_in_an_example_is_reported() {
        let kdl = r#"
            upstream "openai" {
                target "api.openai.com:443"
                tls {
                    sni "api.openai.com"
                    verify #true
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'verify'")),
            "{warnings:?}"
        );
    }

    #[test]
    fn target_block_keys_are_checked() {
        let kdl = r#"
            upstream "backend" {
                target { address "127.0.0.1:8081"; wieght 2 }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'wieght'")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_valid_health_check_produces_no_warnings() {
        // The form the documentation shows.
        let kdl = r#"
            upstream "backend" {
                target "127.0.0.1:8081"
                health-check {
                    type "http" {
                        path "/health"
                        expected-status 200
                        host "backend.internal"
                    }
                    interval-secs 10
                    timeout-secs 5
                    healthy-threshold 2
                    unhealthy-threshold 3
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// `path` is read only inside `type "http"`. Directly under `health-check`
    /// it is read by nothing -- a mistake easy to make, and one I made in this
    /// file's own fixtures before the check existed.
    #[test]
    fn a_type_specific_setting_outside_its_type_block_is_reported() {
        let kdl = r#"
            health-check {
                path "/health"
                interval-secs 10
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("'path'"), "{}", warnings[0]);
    }

    /// The point of the value-qualified entries: each check type accepts only
    /// its own settings.
    #[test]
    fn each_health_check_type_accepts_only_its_own_settings() {
        // `service` is a gRPC setting, on an HTTP check.
        let http_with_grpc_key = r#"
            health-check {
                type "http" { service "grpc.health.v1.Health" }
            }
        "#;
        let warnings = warnings_for(http_with_grpc_key);
        assert!(
            warnings.iter().any(|w| w.contains("'service'")),
            "{warnings:?}"
        );

        // ...and the same key is fine on a gRPC check.
        let grpc = r#"
            health-check {
                type "grpc" { service "grpc.health.v1.Health" }
            }
        "#;
        assert!(warnings_for(grpc).is_empty(), "{:?}", warnings_for(grpc));

        // `path` is fine on HTTP but not on inference.
        let inference_with_http_key = r#"
            health-check {
                type "inference" { path "/health" }
            }
        "#;
        assert!(
            warnings_for(inference_with_http_key)
                .iter()
                .any(|w| w.contains("'path'")),
            "{:?}",
            warnings_for(inference_with_http_key)
        );
    }

    #[test]
    fn a_valid_inference_health_check_produces_no_warnings() {
        let kdl = r#"
            health-check {
                type "inference" {
                    endpoint "/v1/models"
                    expected-models "gpt-4" "claude-3"
                }
                interval-secs 30
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// `type "tcp"` takes no settings at all.
    #[test]
    fn a_tcp_check_accepts_no_settings() {
        let bare = r#"
            health-check {
                type "tcp"
                interval-secs 5
            }
        "#;
        assert!(warnings_for(bare).is_empty(), "{:?}", warnings_for(bare));

        let with_settings = r#"
            health-check {
                type "tcp" { path "/health" }
            }
        "#;
        assert!(
            warnings_for(with_settings)
                .iter()
                .any(|w| w.contains("'path'")),
            "{:?}",
            warnings_for(with_settings)
        );
    }

    #[test]
    fn a_fully_populated_readiness_block_produces_no_warnings() {
        let kdl = r#"
            health-check {
                type "inference" {
                    endpoint "/v1/models"
                    readiness {
                        inference-probe {
                            endpoint "/v1/completions"
                            model "gpt-4"
                            prompt "."
                            max-tokens 1
                            timeout-secs 30
                            max-latency-ms 5000
                        }
                        model-status {
                            endpoint-pattern "/v1/models/{model}/status"
                            models "gpt-4" "claude-3"
                            expected-status "ready"
                            status-field "status"
                            timeout-secs 5
                        }
                        queue-depth {
                            header "X-Queue-Depth"
                            body-field "queue"
                            endpoint "/metrics"
                            degraded-threshold 50
                            unhealthy-threshold 200
                            timeout-secs 5
                        }
                        warmth-detection {
                            sample-size 10
                            cold-threshold-multiplier 3.0
                            idle-cold-timeout-secs 300
                            cold-action "mark-degraded"
                        }
                    }
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// The reason this block was left until last: a mechanical scan of
    /// `parse_inference_readiness` reports its match-arm values and string
    /// defaults as if they were settings. They are not, and a config using them
    /// as settings must be reported.
    #[test]
    fn values_of_settings_are_not_themselves_settings() {
        // `log-only`/`mark-degraded`/`mark-unhealthy` are values of `cold-action`.
        let kdl = r#"
            readiness {
                warmth-detection {
                    log-only #true
                    mark-degraded #true
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'log-only'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("'mark-degraded'")),
            "{warnings:?}"
        );

        // `ready` and `status` are the *defaults* of `expected-status` and
        // `status-field`, not settings in their own right.
        let defaults_as_keys = r#"
            readiness {
                model-status {
                    ready "yes"
                    status "up"
                }
            }
        "#;
        let warnings = warnings_for(defaults_as_keys);
        assert!(
            warnings.iter().any(|w| w.contains("'ready'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("'status'")),
            "{warnings:?}"
        );
    }

    /// `readiness` holds sub-blocks and nothing else.
    #[test]
    fn a_setting_directly_inside_readiness_is_reported() {
        let kdl = r#"
            readiness {
                timeout-secs 30
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("'timeout-secs'"), "{}", warnings[0]);
    }

    /// `endpoint` and `timeout-secs` are valid in several readiness sub-blocks
    /// and mean different things in each; none of them may borrow another's
    /// settings.
    #[test]
    fn readiness_sub_blocks_do_not_share_settings() {
        let kdl = r#"
            readiness {
                inference-probe { degraded-threshold 50 }
                queue-depth { prompt "." }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'degraded-threshold'")),
            "a queue-depth setting on an inference probe: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("'prompt'")),
            "an inference-probe setting on queue-depth: {warnings:?}"
        );
    }

    #[test]
    fn a_valid_agent_produces_no_warnings() {
        let kdl = r#"
            agents {
                agent "waf-agent" type="waf" {
                    unix-socket "/var/run/zentinel/waf.sock"
                    events "request_headers" "request_body"
                    timeout-ms 200
                    connect-timeout-ms 750
                    failure-mode "closed"
                    max-concurrent-calls 100
                    circuit-breaker {
                        failure-threshold 5
                    }
                    config {
                        anything-goes-here #true
                    }
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    #[test]
    fn an_unknown_agent_key_is_reported() {
        let kdl = r#"
            agents {
                agent "a" {
                    timeout-msec 200
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'timeout-msec'")),
            "{warnings:?}"
        );
    }

    /// An agent transport's `tls` is the third distinct meaning of that block
    /// name, after the listener's and the upstream's.
    #[test]
    fn agent_transport_tls_has_its_own_keys() {
        let valid = r#"
            agents {
                agent "a" {
                    grpc {
                        address "http://localhost:50051"
                        tls {
                            ca-cert "/ca.crt"
                            client-cert "/c.crt"
                            client-key "/c.key"
                            tls-insecure #false
                        }
                    }
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        // `cert-file` is a listener TLS key; `sni` is an upstream one.
        let wrong = r#"
            agents {
                agent "a" {
                    grpc {
                        address "http://localhost:50051"
                        tls {
                            cert-file "/c.crt"
                            sni "x"
                        }
                    }
                }
            }
        "#;
        let warnings = warnings_for(wrong);
        assert!(
            warnings.iter().any(|w| w.contains("'cert-file'")),
            "{warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("'sni'")), "{warnings:?}");
    }

    #[test]
    fn the_global_rate_limits_block_is_checked() {
        let valid = r#"
            rate-limits {
                default-rps 100
                default-burst 10
                key "client-ip"
                global {
                    max-rps 50000
                    burst 1000
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        // The shipped configs' spelling for the global limit is
        // `max-requests-per-second-global`, which this block does not read.
        let wrong = r#"
            rate-limits {
                max-requests-per-second-global 50000
            }
        "#;
        assert!(
            warnings_for(wrong)
                .iter()
                .any(|w| w.contains("'max-requests-per-second-global'")),
            "{:?}",
            warnings_for(wrong)
        );
    }

    /// A filter's settings depend on its `type` child, not on its own argument
    /// -- the argument is the filter's id.
    #[test]
    fn a_rate_limit_filter_is_checked_by_its_type_child() {
        let valid = r#"
            filters {
                filter "my-limiter" {
                    type "rate-limit"
                    max-rps 100
                    burst 10
                    key "client-ip"
                    on-limit "reject"
                    status-code 429
                    backend "redis"
                    redis-url "redis://localhost"
                    redis-fallback-local #true
                }
            }
        "#;
        assert!(warnings_for(valid).is_empty(), "{:?}", warnings_for(valid));

        let typo = r#"
            filters {
                filter "my-limiter" {
                    type "rate-limit"
                    max-rp 100
                }
            }
        "#;
        let warnings = warnings_for(typo);
        assert!(
            warnings.iter().any(|w| w.contains("'max-rp'")),
            "{warnings:?}"
        );
    }

    /// Filters of a type this check does not describe are left alone rather
    /// than measured against the wrong list.
    #[test]
    fn a_filter_of_another_type_is_not_checked() {
        let kdl = r#"
            filters {
                filter "c" {
                    type "cors"
                    allow-origins "*"
                    allow-methods "GET"
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    #[test]
    fn a_valid_observability_block_produces_no_warnings() {
        let kdl = r#"
            observability {
                logging {
                    level "info"
                    format "json"
                    access-log {
                        enabled #true
                        file "/var/log/zentinel/access.log"
                        format "json"
                        buffer-size 8192
                    }
                    error-log {
                        enabled #true
                        file "/var/log/zentinel/error.log"
                        level "warn"
                        buffer-size 4096
                    }
                    audit-log {
                        enabled #true
                        file "/var/log/zentinel/audit.log"
                        buffer-size 4096
                        log-blocked #true
                        log-agent-decisions #true
                        log-waf-events #true
                    }
                }
                metrics {
                    enabled #true
                    address "0.0.0.0:9090"
                    path "/metrics"
                    high-cardinality #false
                }
                tracing {
                    backend "otlp" {
                        endpoint "http://localhost:4317"
                    }
                    sampling-rate 0.1
                    service-name "zentinel"
                }
            }
        "#;
        assert!(warnings_for(kdl).is_empty(), "{:?}", warnings_for(kdl));
    }

    /// The access log takes `format`, the error log takes `level`. The two
    /// blocks look alike, so each borrowing the other's setting must be caught.
    #[test]
    fn the_two_log_blocks_do_not_share_settings() {
        let kdl = r#"
            logging {
                access-log { level "warn" }
                error-log { format "json" }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert!(
            warnings.iter().any(|w| w.contains("'level'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("'format'")),
            "{warnings:?}"
        );
    }

    /// All three settings from #415 are now read, so none should be reported.
    ///
    /// `timestamps` was the last one: it needed the log subscriber to be built
    /// after the configuration is read. The diagnostics emitted while finding
    /// that configuration are buffered and replayed once logging is up, so
    /// nothing is lost by the reordering.
    #[test]
    fn the_observability_settings_from_415_are_all_read() {
        let kdl = r#"
            observability {
                logging {
                    timestamps #true
                    access-log {
                        include-trace-id #true
                    }
                }
                tracing {
                    enabled #true
                    backend "otlp" {
                        endpoint "http://localhost:4317"
                    }
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        for key in ["timestamps", "include-trace-id", "enabled"] {
            assert!(
                !warnings.iter().any(|w| w.contains(&format!("'{key}'"))),
                "{key} is parsed now and must not be reported: {warnings:?}"
            );
        }
    }

    #[test]
    fn an_unknown_observability_block_is_reported() {
        let kdl = r#"
            observability {
                profiling { enabled #true }
            }
        "#;
        assert!(
            warnings_for(kdl).iter().any(|w| w.contains("'profiling'")),
            "{:?}",
            warnings_for(kdl)
        );
    }

    /// #517: in a single-file config the `-bytes` names belong to the
    /// directory-config parser and were dropped without a word, so a 1 KB
    /// body limit written that way let a 5 KB body through.
    #[test]
    fn directory_config_limit_names_are_reported_in_a_single_file_config() {
        let warnings = warnings_for(
            r#"
            limits {
                max-body-size-bytes 1024
                max-header-size-bytes 4096
                max-header-count 50
            }
            "#,
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings[0].contains("'max-body-size-bytes'"));
        assert!(warnings[0].contains("Did you mean 'max-body-size'?"));
        assert!(warnings[1].contains("Did you mean 'max-header-size'?"));
    }

    #[test]
    fn a_limit_with_no_single_file_name_is_reported_without_a_bogus_suggestion() {
        let warnings = warnings_for("limits {\n  max-header-name-bytes 256\n}\n");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("'max-header-name-bytes'"));
        assert!(!warnings[0].contains("directory-config"));
    }

    #[test]
    fn namespace_and_service_limits_are_checked_too() {
        let warnings = warnings_for(
            r#"
            namespace "ns" {
                limits { max-body-size-bytes 1 }
                service "svc" {
                    limits { max-body-size-bytes 1 }
                }
            }
            "#,
        );
        let unknown = warnings
            .iter()
            .filter(|w| w.contains("'max-body-size-bytes'"))
            .count();
        assert_eq!(unknown, 2, "{warnings:?}");
    }

    #[test]
    fn a_valid_limits_block_produces_no_warnings() {
        let warnings = warnings_for(
            r#"
            limits {
                max-header-size 8192
                max-header-count 100
                max-body-size 1048576
                max-connections-per-client 100
                max-total-connections 10000
                max-in-flight-requests 10000
            }
            "#,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// #542: a `0` connection or in-flight limit loaded and limited nothing
    /// while these keys were never applied. Now that they are, `0` stays "no
    /// limit" rather than refusing everything, and says so.
    #[test]
    fn a_zero_concurrency_limit_is_reported_as_ignored() {
        let warnings = warnings_for(
            r#"
            limits {
                max-in-flight-requests 0
                max-total-connections 0
                max-connections-per-client 5
            }
            "#,
        );
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(warnings
            .iter()
            .all(|w| w.contains("is being ignored") && w.contains(" 0'")));
    }

    /// #542 applied namespace limits; a service's were reported as ignored,
    /// since no listener served a service's routes. #548 serves them, and
    /// applies their limits, so neither block is reported.
    #[test]
    fn namespace_and_service_limits_are_not_reported() {
        let warnings = warnings_for(
            r#"
            namespace "ns" {
                limits {
                    max-body-size 1000
                    max-in-flight-requests 5
                    max-connections-per-client 5
                }
                service "svc" {
                    limits { max-body-size 10 }
                }
            }
            "#,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// #548: a service's `listener` block takes its id from an `id` key,
    /// which its parser reads; it was reported as ignored.
    #[test]
    fn a_service_listener_id_is_not_reported() {
        let warnings = warnings_for(
            r#"
            namespace "ns" {
                service "svc" {
                    listener {
                        id "svc-http"
                        address "127.0.0.1:19480"
                        protocol "http"
                    }
                }
            }
            "#,
        );
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// A `0` concurrency limit is reported wherever the block sits.
    #[test]
    fn a_zero_limit_in_a_service_is_reported() {
        let warnings = warnings_for(
            r#"
            namespace "ns" {
                service "svc" {
                    limits { max-in-flight-requests 0 }
                }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("is being ignored"), "{warnings:?}");
    }

    /// The values from #521 that each fell back to a default without a word.
    #[test]
    fn ignored_values_are_reported() {
        let kdl = r#"
            routes {
                route "a" {
                    priority "urgent"
                    builtin-handler "helth"
                }
            }
            upstreams {
                upstream "b" {
                    target "127.0.0.1:1"
                    load-balancing "totally_bogus"
                    health-check { type "htttp" }
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 4, "{warnings:#?}");
        for fragment in [
            "'priority \"urgent\"'",
            "'builtin-handler \"helth\"'",
            "'load-balancing \"totally_bogus\"'",
            "'type \"htttp\"'",
        ] {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.contains(fragment) && w.contains("is being ignored")),
                "expected {fragment} to be reported, got {warnings:#?}"
            );
        }
    }

    #[test]
    fn accepted_values_are_not_reported() {
        let kdl = r#"
            routes {
                route "a" {
                    priority "HIGH"
                    builtin-handler "not_found"
                    matches {
                        method "GET" "POST"
                        header "x-kind" "path"
                        query-param "host" "method"
                    }
                }
            }
            upstreams {
                upstream "b" {
                    target "127.0.0.1:1"
                    load-balancing "least-connections"
                    health-check { type "grpc" }
                }
            }
        "#;
        assert_eq!(warnings_for(kdl), Vec::<String>::new());
    }

    /// The run-together check from #365 did not cover `matches`, where a
    /// dropped condition makes the route match more than intended.
    #[test]
    fn a_run_together_match_condition_is_reported() {
        let warnings = warnings_for(
            r#"routes { route "a" { matches { path-prefix "/api" host "a.com"; } } }"#,
        );
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'host' is read as an argument to 'path-prefix'"));
        assert!(warnings[0].contains("'matches' block"));
    }

    #[test]
    fn a_condition_run_into_a_header_match_is_reported_after_its_value() {
        let warnings =
            warnings_for(r#"routes { route "a" { matches { header "x-a" "1" method "GET"; } } }"#);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'method' is read as an argument to 'header'"));
    }

    fn agent_config(agent_mode: &str, filter_mode: &str) -> String {
        format!(
            r#"
            agents {{
                agent "waf" {{
                    unix-socket "/tmp/waf.sock"
                    {agent_mode}
                }}
            }}
            filters {{
                filter "waf-filter" {{
                    type "agent"
                    agent "waf"
                    {filter_mode}
                }}
            }}
        "#
        )
    }

    /// #529: the agent block's failure-mode does not decide the
    /// request-headers call, which is where it is usually meant to.
    #[test]
    fn an_agent_failure_mode_without_a_filter_one_is_reported() {
        let warnings = warnings_for(&agent_config(r#"failure-mode "open""#, ""));
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("on agent 'waf' is being ignored for requests and responses"));
        assert!(
            warnings[0].contains("filter 'waf-filter'"),
            "{}",
            warnings[0]
        );
    }

    #[test]
    fn an_agent_failure_mode_is_not_reported_when_the_filter_sets_one() {
        let kdl = agent_config(r#"failure-mode "open""#, r#"failure-mode "open""#);
        assert_eq!(warnings_for(&kdl), Vec::<String>::new());
        // Neither is an agent without a failure-mode of its own.
        assert_eq!(warnings_for(&agent_config("", "")), Vec::<String>::new());
    }

    /// #541: a configuration split over files is checked file by file, each
    /// warning naming its file, with what one check needs to know about the
    /// rest (the filters using an agent) taken from every file.
    #[test]
    fn several_files_are_each_checked_and_named() {
        let sources = vec![
            (
                std::path::PathBuf::from("conf/agents.kdl"),
                "agents {\n    agent \"waf\" {\n        unix-socket \"/tmp/waf.sock\"\n        failure-mode \"open\"\n    }\n}\n".to_string(),
            ),
            (
                std::path::PathBuf::from("conf/filters.kdl"),
                "filters {\n    filter \"waf-filter\" {\n        type \"agent\"\n        agent \"waf\"\n    }\n}\n".to_string(),
            ),
            (
                std::path::PathBuf::from("conf/limits.kdl"),
                "limits {\n    max-body-size-bytes 1024\n}\n".to_string(),
            ),
        ];
        let mut result = ValidationResult::new();
        check_unknown_keys_in_files(&sources, &mut result);
        let warnings: Vec<_> = result.warnings.into_iter().map(|w| w.message).collect();

        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(
            warnings[0].starts_with("conf/agents.kdl: ")
                && warnings[0].contains("filter 'waf-filter'"),
            "{}",
            warnings[0]
        );
        assert!(
            warnings[1].starts_with("conf/limits.kdl: ")
                && warnings[1].contains("max-body-size-bytes"),
            "{}",
            warnings[1]
        );
    }

    /// `fail-open` is accepted on the agent block, not on the filter, where
    /// it has always meant "unset" and so, by default, closed.
    #[test]
    fn an_unknown_filter_failure_mode_is_reported() {
        let warnings = warnings_for(&agent_config("", r#"failure-mode "fail-open""#));
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'failure-mode \"fail-open\"' on filter 'waf-filter'"));
        assert!(warnings[0].contains("is being ignored"));
    }

    /// An ignored filter value leaves the decision open, so the agent's
    /// value is reported as well.
    #[test]
    fn an_ignored_filter_value_counts_as_unset() {
        let warnings = warnings_for(&agent_config(
            r#"failure-mode "open""#,
            r#"failure-mode "fail-open""#,
        ));
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
    }

    /// Docs CI and the playground pick findings out by this phrase, so a
    /// finding worded differently is a finding they never see.
    #[test]
    fn every_kind_of_finding_says_it_is_being_ignored() {
        let kdl = r#"
            listeners { listener "l" { adress "x"; address "y" namespace "n"; } }
            routes {
                route "a" {
                    priority "urgent"
                    matches { path-prefix "/api" host "a.com"; }
                    cache { backend "disk"; }
                }
            }
        "#;
        let warnings = warnings_for(kdl);
        assert_eq!(warnings.len(), 5, "{warnings:#?}");
        for warning in &warnings {
            assert!(warning.contains("is being ignored"), "{warning}");
        }
    }

    /// #527: known, parsed, and never applied.
    #[test]
    fn system_max_connections_is_reported() {
        let warnings = warnings_for("system { max-connections 10000; daemon #false; }");
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'max-connections' in the 'system' block"));
        assert!(warnings[0].contains("is being ignored"));

        // The upstream connection pool's setting of the same name is applied.
        let pool = r#"upstreams { upstream "b" { connection-pool { max-connections 5; } } }"#;
        assert_eq!(warnings_for(pool), Vec::<String>::new());
    }

    fn warning_texts(result: &ValidationResult) -> Vec<String> {
        result.warnings.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn shipped_configs_use_only_known_keys() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let mut checked = 0;
        let mut complaints = Vec::new();

        for dir in ["config", "config/examples"] {
            let path = std::path::Path::new(root).join(dir);
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                let file = entry.path();
                if file.extension().and_then(|e| e.to_str()) != Some("kdl") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&file) else {
                    continue;
                };
                checked += 1;
                for warning in warnings_for(&text) {
                    complaints.push(format!("{}: {warning}", file.display()));
                }
            }
        }

        assert!(checked > 0, "should have found shipped configs to check");
        assert!(
            complaints.is_empty(),
            "shipped configs contain keys this check does not know about. Either the \
             config is wrong or CLOSED_BLOCKS is under-listed:\n{}",
            complaints.join("\n")
        );
    }

    /// #542: `error-pages` is read now, so a correct block is quiet, and the
    /// parts of it the parser cannot use are reported.
    #[test]
    fn error_pages_are_checked_not_reported_wholesale() {
        let clean = warnings_for(
            r#"routes {
                route "r" {
                    error-pages {
                        default-format "json"
                        pages {
                            "404" {
                                format "json"
                                message "nope"
                                headers { Cache-Control "no-store" }
                            }
                        }
                    }
                }
            }"#,
        );
        assert!(clean.is_empty(), "{clean:?}");

        let warnings = warnings_for(
            r#"routes {
                route "r" {
                    error-pages {
                        include-stack-trace #true
                        pages {
                            "503" {
                                format "yaml"
                                mesage "typo"
                            }
                            "oops" { message "x" }
                        }
                    }
                }
            }"#,
        );
        assert_eq!(warnings.len(), 4, "{warnings:#?}");
        assert!(warnings.iter().all(|w| w.contains("is being ignored")));
        assert!(warnings.iter().any(|w| w.contains("'include-stack-trace'")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("'mesage'") && w.contains("Did you mean 'message'?")));
        assert!(warnings.iter().any(|w| w.contains("'format \"yaml\"'")));
        assert!(warnings.iter().any(|w| w.contains("'oops'")));
    }

    /// #542: an agent filter's `phase` is parsed and never applied, and its
    /// `timeout-ms` can only shorten the agent's. Both are reported.
    #[test]
    fn agent_filter_phase_and_overlong_timeout_are_reported() {
        let config = |filter_timeout: &str, phase: &str| {
            format!(
                r#"agents {{
                    agent "waf" type="waf" {{
                        unix-socket "/tmp/waf.sock"
                        timeout-ms 200
                    }}
                }}
                filters {{
                    filter "f" {{
                        type "agent"
                        agent "waf"
                        failure-mode "closed"
                        {filter_timeout}
                        {phase}
                    }}
                }}"#
            )
        };

        assert!(warnings_for(&config("timeout-ms 50", "")).is_empty());

        let warnings = warnings_for(&config("timeout-ms 500", r#"phase "response""#));
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings.iter().all(|w| w.contains("is being ignored")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("'timeout-ms 500'") && w.contains("timeout-ms 200")));
        assert!(warnings.iter().any(|w| w.contains("'phase \"response\"'")));

        let warnings = warnings_for(&config("timeout-ms 0", ""));
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("not a positive number"));
    }

    /// An agent without `timeout-ms` has the parser's default, and a filter
    /// asking for longer than that is reported against the default.
    #[test]
    fn agent_filter_timeout_is_compared_with_the_default_agent_timeout() {
        let warnings = warnings_for(
            r#"agents {
                agent "a" type="custom" { unix-socket "/tmp/a.sock" }
            }
            filters {
                filter "f" {
                    type "agent"
                    agent "a"
                    failure-mode "open"
                    timeout-ms 5000
                }
            }"#,
        );
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("timeout-ms 1000"));
    }

    /// #542: an unknown sticky `fallback` silently became round robin, and an
    /// unknown `cookie-same-site` lax. Both behaviours stay, and are reported
    /// like the other #521 values.
    #[test]
    fn unknown_sticky_fallback_and_same_site_are_reported() {
        let config = |fallback: &str, same_site: &str| {
            format!(
                r#"upstreams {{
                    upstream "u" {{
                        target "127.0.0.1:9000"
                        load-balancing "sticky" {{
                            cookie-name "S"
                            cookie-same-site "{same_site}"
                            fallback "{fallback}"
                        }}
                    }}
                }}"#
            )
        };

        assert!(warnings_for(&config("least-connections", "strict")).is_empty());

        let warnings = warnings_for(&config("least-conections", "strct"));
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings.iter().all(|w| w.contains("is being ignored")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("'fallback \"least-conections\"'")
                && w.contains("Did you mean 'least_connections'?")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("'cookie-same-site \"strct\"'")));

        // The fallback the parser applies is still round robin.
        let config = crate::Config::from_kdl(&format!(
            "system {{ worker-threads 1 }}\n\
             listeners {{ listener \"l\" {{ address \"127.0.0.1:8080\"; protocol \"http\" }} }}\n\
             {}",
            config("least-conections", "strct")
        ))
        .expect("loads");
        let sticky = config.upstreams["u"].sticky_session.as_ref().unwrap();
        assert_eq!(sticky.fallback, crate::LoadBalancingAlgorithm::RoundRobin);
    }

    /// #553: an agent filter's `inspect-body` and `max-body-bytes` narrow
    /// what the agent's own settings send it. Values that cannot narrow
    /// anything are reported.
    #[test]
    fn agent_filter_body_settings_that_do_nothing_are_reported() {
        let config = |events: &str, filter: &str| {
            format!(
                r#"agents {{
                    agent "waf" type="waf" {{
                        unix-socket "/tmp/waf.sock"
                        {events}
                        max-request-body-bytes 4096
                    }}
                }}
                filters {{
                    filter "f" {{
                        type "agent"
                        agent "waf"
                        failure-mode "closed"
                        {filter}
                    }}
                }}"#
            )
        };
        let bodies = r#"events "request-headers" "request-body""#;

        // Narrowing: nothing to report.
        assert!(warnings_for(&config(bodies, "inspect-body #false")).is_empty());
        assert!(
            warnings_for(&config(bodies, "inspect-body #true\nmax-body-bytes 1024")).is_empty()
        );

        // Wider than the agent's own limit.
        let warnings = warnings_for(&config(bodies, "max-body-bytes 8192"));
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'max-body-bytes 8192'"));
        assert!(warnings[0].contains("max-request-body-bytes 4096"));
        assert!(warnings[0].contains("is being ignored"));

        // A limit on a body the filter does not send.
        let warnings = warnings_for(&config(bodies, "inspect-body #false\nmax-body-bytes 10"));
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("'inspect-body #false'"));

        // An agent that receives no bodies at all (request headers only, the
        // default).
        let warnings = warnings_for(&config("", "inspect-body #true\nmax-body-bytes 10"));
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings
            .iter()
            .all(|w| w.contains("does not receive request bodies")));

        // Unusable values.
        let warnings = warnings_for(&config(bodies, "inspect-body \"no\"\nmax-body-bytes 0"));
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings.iter().all(|w| w.contains("is being ignored")));
    }

    /// The agent's default body limit is what an overlong filter value is
    /// compared with when the agent sets none.
    #[test]
    fn agent_filter_body_limit_is_compared_with_the_default_agent_limit() {
        let warnings = warnings_for(
            r#"agents {
                agent "waf" type="waf" {
                    unix-socket "/tmp/waf.sock"
                    events "request-body"
                }
            }
            filters {
                filter "f" {
                    type "agent"
                    agent "waf"
                    failure-mode "open"
                    max-body-bytes 2097152
                }
            }"#,
        );
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("max-request-body-bytes 1048576"));
    }

    /// #553: the documented `max-size-bytes` and `lock-timeout-secs` are
    /// accepted in the top-level `cache` block; written together with the
    /// original names, the alias is reported as ignored.
    #[test]
    fn top_level_cache_aliases_are_known_and_conflicts_reported() {
        assert!(warnings_for("cache {\n max-size-bytes 1024\n lock-timeout-secs 3\n}").is_empty());
        assert!(warnings_for("cache {\n max-size 1024\n lock-timeout 3\n}").is_empty());

        let warnings = warnings_for(
            "cache {\n max-size 1024\n max-size-bytes 2048\n lock-timeout 3\n lock-timeout-secs 4\n}",
        );
        assert_eq!(warnings.len(), 2, "{warnings:#?}");
        assert!(warnings
            .iter()
            .any(|w| w.contains("'max-size-bytes 2048'") && w.contains("'max-size 1024'")));
        assert!(warnings
            .iter()
            .any(|w| w.contains("'lock-timeout-secs 4'") && w.contains("is being ignored")));

        // A route's cache block keeps its own key list.
        let warnings = warnings_for(r#"routes { route "r" { cache { lock-timeout-secs 3 } } }"#);
        assert_eq!(warnings.len(), 1, "{warnings:#?}");
        assert!(warnings[0].contains("top-level 'cache'"), "{warnings:#?}");
    }
}
