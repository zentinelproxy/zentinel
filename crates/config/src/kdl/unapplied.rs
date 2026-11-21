//! Settings the parsers read and the proxy never applies, and keys in the
//! blocks of an inference route (`inference` and what it holds, `fallback`)
//! that the parsers do not read.
//!
//! A key can pass every other check -- the parser reads it, the unknown-key
//! check lists it -- and still change nothing at runtime, because nothing in
//! the proxy looks at the value it was parsed into. `waf-enabled #true` reads
//! as a route with a WAF and is stored as a flag that no request handling reads. These
//! functions name such settings, so that an operator is told instead of finding
//! out from behaviour.
//!
//! Each function takes the node of the block that holds the settings and
//! returns one message per setting written there, in the order written. The
//! parsers log them when the configuration is loaded, and
//! `validate::unknown_keys` reports the same messages for `zentinel lint` and
//! `zentinel test --strict`. That check works from the source text, which is
//! why a setting is reported whatever its value: a value equal to the default
//! is as unapplied as any other, and a parsed `Config` cannot tell the two
//! apart.
//!
//! Loading still succeeds. Configurations carrying these lines have always
//! loaded, so refusing them would turn a reload into an outage; `--strict` is
//! where an operator asks for them to be refused.
//!
//! Applying one of these settings makes its message false. The tests in
//! `unapplied_tests` and `validate::unknown_keys` name each setting, and the
//! change that applies it removes its entry here, its documentation note in
//! `docs/schema.md`, and those tests. See also `unapplied_system_settings` in
//! `server` and `unapplied_limits_settings` in the parent module, which do the
//! same for `system` and `limits`.

use std::fmt::Write;

use super::routes::{
    RECOGNIZED_COST_ATTRIBUTION_KEYS, RECOGNIZED_FALLBACK_KEYS, RECOGNIZED_FALLBACK_TRIGGER_KEYS,
    RECOGNIZED_FALLBACK_UPSTREAM_KEYS, RECOGNIZED_GUARDRAILS_KEYS, RECOGNIZED_INFERENCE_KEYS,
    RECOGNIZED_INFERENCE_ROUTING_KEYS, RECOGNIZED_MODEL_PRICING_KEYS,
    RECOGNIZED_MODEL_ROUTING_KEYS, RECOGNIZED_MODEL_RULE_PROPERTIES, RECOGNIZED_PII_DETECTION_KEYS,
    RECOGNIZED_PROMPT_INJECTION_KEYS, RECOGNIZED_TOKEN_BUDGET_KEYS,
    RECOGNIZED_TOKEN_RATE_LIMIT_KEYS,
};

/// The child nodes of `node`, in the order written.
fn children(node: &kdl::KdlNode) -> impl Iterator<Item = &kdl::KdlNode> {
    node.children().into_iter().flat_map(|c| c.nodes())
}

/// The first child of `node` called `name`.
fn child<'a>(node: &'a kdl::KdlNode, name: &str) -> Option<&'a kdl::KdlNode> {
    children(node).find(|n| n.name().value() == name)
}

/// One finding: `setting`, written inside `block` of `place` (either may be
/// empty), is not applied, for `reason`.
fn finding(place: &str, block: &str, setting: &str, reason: &str) -> String {
    let mut text = String::new();
    if !place.is_empty() {
        let _ = write!(text, "{place}: ");
    }
    let _ = write!(text, "'{setting}'");
    if !block.is_empty() {
        let _ = write!(text, " in '{block}'");
    }
    let _ = write!(text, " is not applied and is being ignored: {reason}");
    text
}

/// One finding about a key the parser does not read: `setting`, written inside
/// `block` of `place`, is ignored, for `reason`.
fn unread(place: &str, block: &str, setting: &str, reason: &str) -> String {
    format!("{place}: '{setting}' in '{block}' is not read and is being ignored: {reason}")
}

/// A block whose settings the parser reads from a fixed set of child nodes,
/// and for a few nodes from properties.
///
/// Every key and property written in it that the lists do not have is
/// reported, whatever it is called: the parser drops it.
struct Shape {
    name: &'static str,
    /// The child nodes the parser reads.
    keys: &'static [&'static str],
    /// The properties the parser reads from the node itself.
    properties: &'static [&'static str],
    /// The shapes of those child nodes that are blocks of their own.
    nested: &'static [Shape],
}

const TRIGGERS: Shape = Shape {
    name: "triggers",
    keys: RECOGNIZED_FALLBACK_TRIGGER_KEYS,
    properties: &[],
    nested: &[],
};

const FALLBACK_UPSTREAM: Shape = Shape {
    name: "fallback-upstream",
    keys: RECOGNIZED_FALLBACK_UPSTREAM_KEYS,
    properties: &[],
    nested: &[],
};

/// A route's `fallback` block.
const FALLBACK: Shape = Shape {
    name: "fallback",
    keys: RECOGNIZED_FALLBACK_KEYS,
    properties: &[],
    nested: &[TRIGGERS, FALLBACK_UPSTREAM],
};

const TOKEN_RATE_LIMIT: Shape = Shape {
    name: "rate-limit",
    keys: RECOGNIZED_TOKEN_RATE_LIMIT_KEYS,
    properties: &[],
    nested: &[],
};

const INFERENCE_ROUTING: Shape = Shape {
    name: "routing",
    keys: RECOGNIZED_INFERENCE_ROUTING_KEYS,
    properties: &[],
    nested: &[],
};

const TOKEN_BUDGET: Shape = Shape {
    name: "budget",
    keys: RECOGNIZED_TOKEN_BUDGET_KEYS,
    properties: &[],
    nested: &[],
};

const MODEL_PRICING: Shape = Shape {
    name: "model",
    keys: RECOGNIZED_MODEL_PRICING_KEYS,
    properties: &[],
    nested: &[],
};

const PRICING: Shape = Shape {
    name: "pricing",
    keys: &["model"],
    properties: &[],
    nested: &[MODEL_PRICING],
};

const COST_ATTRIBUTION: Shape = Shape {
    name: "cost-attribution",
    keys: RECOGNIZED_COST_ATTRIBUTION_KEYS,
    properties: &[],
    nested: &[PRICING],
};

/// One `model "<pattern>" upstream="<id>"` rule: no child nodes, two
/// properties.
const MODEL_RULE: Shape = Shape {
    name: "model",
    keys: &[],
    properties: RECOGNIZED_MODEL_RULE_PROPERTIES,
    nested: &[],
};

const MODEL_ROUTING: Shape = Shape {
    name: "model-routing",
    keys: RECOGNIZED_MODEL_ROUTING_KEYS,
    properties: &[],
    nested: &[MODEL_RULE],
};

const PROMPT_INJECTION: Shape = Shape {
    name: "prompt-injection",
    keys: RECOGNIZED_PROMPT_INJECTION_KEYS,
    properties: &[],
    nested: &[],
};

const PII_DETECTION: Shape = Shape {
    name: "pii-detection",
    keys: RECOGNIZED_PII_DETECTION_KEYS,
    properties: &[],
    nested: &[],
};

const GUARDRAILS: Shape = Shape {
    name: "guardrails",
    keys: RECOGNIZED_GUARDRAILS_KEYS,
    properties: &[],
    nested: &[PROMPT_INJECTION, PII_DETECTION],
};

/// A route's `inference` block and everything it holds.
const INFERENCE: Shape = Shape {
    name: "inference",
    keys: RECOGNIZED_INFERENCE_KEYS,
    properties: &[],
    nested: &[
        TOKEN_RATE_LIMIT,
        INFERENCE_ROUTING,
        TOKEN_BUDGET,
        COST_ATTRIBUTION,
        MODEL_ROUTING,
        GUARDRAILS,
    ],
};

/// What a key or property that has a known right place should be.
fn hint(block: &str, key: &str) -> Option<&'static str> {
    Some(match (block, key) {
        ("fallback", "upstream") => {
            "a fallback upstream is written as fallback-upstream \"<id>\" { ... }, so the \
             route has none."
        }
        ("fallback", "model-mapping") => {
            "it is read inside a 'fallback-upstream' block, not directly in 'fallback'."
        }
        ("inference", "fallback") => {
            "a route's fallback is a 'fallback' block of the route itself, beside \
             'inference', not inside it."
        }
        ("inference", "token-estimation") => {
            "the estimation method is the 'estimation-method' setting of 'rate-limit'."
        }
        ("model-routing", "mappings" | "mapping") => {
            "none of its rules are read. A rule is written as model \"<pattern>\" \
             upstream=\"<id>\" directly in 'model-routing', and the catch-all as \
             default-upstream \"<id>\"."
        }
        ("model-routing", "model-header") => {
            "it is not read here. Model routing reads the model name only from the 'x-model' or \
             'x-model-id' request header."
        }
        ("cost-attribution", "models") => {
            "per-model prices are written in a 'pricing' block, as model \"<pattern>\" { \
             input-cost-per-million ...; output-cost-per-million ... }."
        }
        ("model", "input-cost-per-1k" | "output-cost-per-1k") => {
            "prices are per million tokens: input-cost-per-million and output-cost-per-million."
        }
        ("budget", "daily-limit" | "monthly-limit") => {
            "a budget is one 'limit' over a 'period' (hourly, daily, monthly or a number of \
             seconds)."
        }
        ("budget", "alert-threshold") => "the setting is 'alert-thresholds', a list of fractions.",
        ("pii-detection", "detect-types" | "types") => {
            "the kinds of personal data to look for are the 'categories' setting."
        }
        _ => return None,
    })
}

/// What `shape` reads, for a message about something it does not.
fn reads(shape: &Shape) -> String {
    if shape.keys.is_empty() {
        format!(
            "'{}' has no child nodes; its settings are the properties {}.",
            shape.name,
            shape.properties.join(", ")
        )
    } else {
        format!(
            "the settings of '{}' are {}.",
            shape.name,
            shape.keys.join(", ")
        )
    }
}

/// Reports what `node` holds that `shape` does not read, and in the blocks
/// inside it.
fn check_shape(node: &kdl::KdlNode, shape: &Shape, place: &str, found: &mut Vec<String>) {
    // `fallback-upstream "anthropic"` and `model "gpt-4*"` name which one.
    let label = match node
        .entries()
        .iter()
        .find(|e| e.name().is_none())
        .and_then(|e| e.value().as_string())
    {
        Some(argument) => format!("{} \"{argument}\"", shape.name),
        None => shape.name.to_string(),
    };

    for entry in node.entries().iter().filter(|e| e.name().is_some()) {
        let Some(name) = entry.name().map(|n| n.value()) else {
            continue;
        };
        if shape.properties.contains(&name) {
            continue;
        }
        let reason = if shape.keys.contains(&name) {
            format!(
                "'{}' reads its settings from child nodes, not properties: write {name} \
                 \"<value>\" on a line of its own inside the block.",
                shape.name
            )
        } else {
            hint(shape.name, name).map_or_else(|| reads(shape), str::to_string)
        };
        found.push(unread(place, &label, name, &reason));
    }

    for key in children(node) {
        let name = key.name().value();
        if shape.keys.contains(&name) {
            if let Some(inner) = shape.nested.iter().find(|s| s.name == name) {
                check_shape(key, inner, place, found);
            }
            continue;
        }
        let reason = hint(shape.name, name).map_or_else(|| reads(shape), str::to_string);
        found.push(unread(place, &label, name, &reason));
    }
}

/// Settings of a `route` block that are read and not applied.
///
/// - `policies { cache { ... } }`: a route's cache is read from a `cache`
///   block beside `policies`, never from inside it. Moving it turns the cache
///   on, so the advice says the cache key has no request headers in it.
/// - `waf-enabled`: stored on the route, and no request handling reads it.
/// - `cache { vary-headers ... }` and `cache { ignore-query-params ... }`: the
///   cache key is built from the request URI.
/// - `inference { model-header ... }`: model routing reads the model name only
///   from the `x-model` or `x-model-id` request header, and token counting also
///   reads `model` from the request body.
/// - `inference { routing { ... } }`: no upstream is chosen by it.
///
/// And every key or property in `fallback` and `inference`, and the blocks
/// inside them, that the parser does not read.
pub(crate) fn route_settings(route: &kdl::KdlNode, route_id: &str) -> Vec<String> {
    let place = format!("route '{route_id}'");
    let mut found = Vec::new();

    for setting in children(route) {
        match setting.name().value() {
            "waf-enabled" => found.push(finding(
                &place,
                "",
                "waf-enabled",
                "it does not change how the route's requests are handled. What inspects a \
                 route's traffic is the agents its 'filters' list; remove the line.",
            )),
            "fallback" => check_shape(setting, &FALLBACK, &place, &mut found),
            "inference" => {
                check_shape(setting, &INFERENCE, &place, &mut found);
                for key in children(setting) {
                    match key.name().value() {
                        "model-header" => found.push(finding(
                            &place,
                            "inference",
                            "model-header",
                            "it names no header that is read. Model routing reads the model name \
                             only from the 'x-model' or 'x-model-id' request header, and token \
                             counting also reads 'model' from the request body. Remove the line.",
                        )),
                        "routing" => found.push(finding(
                            &place,
                            "inference",
                            "routing",
                            "none of its settings take effect: the proxy does not choose an \
                             upstream by this strategy or by the queue depth. An upstream's \
                             strategy is its 'load-balancing' setting. Remove the block.",
                        )),
                        _ => {}
                    }
                }
            }
            "policies" => {
                if child(setting, "cache").is_some() {
                    found.push(finding(
                        &place,
                        "policies",
                        "cache",
                        "none of its settings take effect, so the route is not cached by it. A \
                         route's cache is a 'cache' block written in the route itself, beside \
                         'policies'. Moving the block there turns the cache on, and the cache \
                         key does not include request headers: do not cache a route whose \
                         response varies by a request header.",
                    ));
                }
            }
            "cache" => {
                for key in children(setting) {
                    match key.name().value() {
                        "vary-headers" => found.push(finding(
                            &place,
                            "cache",
                            "vary-headers",
                            "request header values are not part of the cache key, so responses \
                             are not kept apart by them. Do not cache a route whose response \
                             varies by a request header. Remove the line.",
                        )),
                        "ignore-query-params" => found.push(finding(
                            &place,
                            "cache",
                            "ignore-query-params",
                            "the query string is part of the cache key as written, whatever \
                             this lists. Remove the line.",
                        )),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// Settings of an `upstream` block that are read and not applied.
///
/// - `tls { ca-cert ... }`: the file is not read, and the upstream's
///   certificate is verified against the platform's trusted root certificates.
/// - `connection-pool`: only `idle-timeout-secs` reaches the connection
///   pool. The pool's size is a fixed value for the whole proxy (256), not a
///   setting of an upstream.
pub(crate) fn upstream_settings(upstream: &kdl::KdlNode, upstream_id: &str) -> Vec<String> {
    let place = format!("upstream '{upstream_id}'");
    let mut found = Vec::new();

    for setting in children(upstream) {
        match setting.name().value() {
            "tls" => {
                if child(setting, "ca-cert").is_some() {
                    found.push(finding(
                        &place,
                        "tls",
                        "ca-cert",
                        "the file is not read, and the upstream's certificate is verified \
                         against the platform's trusted root certificates. Remove the line.",
                    ));
                }
            }
            "connection-pool" => {
                for key in children(setting) {
                    let name = key.name().value();
                    let reason = match name {
                        "max-connections" => "connections to a target are not capped by it",
                        "max-idle" => {
                            "the number of idle connections kept is a fixed value for the whole proxy \
                             (256), not set per upstream"
                        }
                        "max-lifetime-secs" | "max-lifetime" => {
                            "connections are not closed because of their age"
                        }
                        _ => continue,
                    };
                    found.push(finding(
                        &place,
                        "connection-pool",
                        name,
                        &format!(
                            "{reason}. 'idle-timeout-secs' is the setting of this block that is \
                             applied. Remove the line."
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    found
}

/// Settings of a `listener` block that are read and not applied.
///
/// - `max-concurrent-streams`: the HTTP/2 stream limit of a listener is not
///   set from it.
pub(crate) fn listener_settings(listener: &kdl::KdlNode, listener_id: &str) -> Vec<String> {
    let place = format!("listener '{listener_id}'");
    children(listener)
        .filter(|setting| setting.name().value() == "max-concurrent-streams")
        .map(|_| {
            finding(
                &place,
                "",
                "max-concurrent-streams",
                "the HTTP/2 stream limit of a listener is not set from it. Remove the line.",
            )
        })
        .collect()
}

/// Settings of the `logging` block that are read and not applied.
///
/// - `level` and `format`: the proxy's own log takes its level from the
///   `RUST_LOG` environment variable and is written as text. They are not the
///   `level` of `error-log` or the `format` of `access-log`, which are applied.
pub(crate) fn logging_settings(logging: &kdl::KdlNode) -> Vec<String> {
    let mut found = Vec::new();
    for setting in children(logging) {
        match setting.name().value() {
            "level" => found.push(finding(
                "",
                "logging",
                "level",
                "the level of the proxy's own log comes from the RUST_LOG environment variable \
                 (info, or debug with --verbose). 'error-log' has a 'level' of its own, which \
                 is applied.",
            )),
            "format" => found.push(finding(
                "",
                "logging",
                "format",
                "the proxy's own log is written as text. 'access-log' has a 'format' of its \
                 own, which is applied.",
            )),
            _ => {}
        }
    }
    found
}

/// Settings of a `waf { body-inspection { ... } }` block that are read and not
/// applied.
///
/// - `inspect-response-body`: a response body goes to the agents that
///   subscribe to the `response-body` event, whatever this says.
pub(crate) fn body_inspection_settings(body_inspection: &kdl::KdlNode) -> Vec<String> {
    children(body_inspection)
        .filter(|setting| setting.name().value() == "inspect-response-body")
        .map(|_| {
            finding(
                "",
                "body-inspection",
                "inspect-response-body",
                "a response body goes to the agents that subscribe to the 'response-body' \
                 event, whatever this says. Remove the line.",
            )
        })
        .collect()
}
