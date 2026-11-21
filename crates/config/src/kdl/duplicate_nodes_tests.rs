//! A node that is read once must not be written twice.
//!
//! Each case builds a document in which one block holds the same node two
//! times. A control document, with a single copy, must load; the document with
//! two must not, and the error must name the node.

use crate::Config;

/// Where in the document a case places its node.
#[derive(Clone, Copy, Debug)]
enum Ctx {
    /// Directly inside `route "r" { ... }`.
    Route,
    /// Inside `route "r" { policies { ... } }`.
    Policies,
    /// Inside `route "r" { policies { request-headers { ... } } }`.
    RequestHeaders,
    /// Inside `route "r" { cache { ... } }`.
    RouteCache,
    /// Inside `route "r" { inference { ... } }`.
    Inference,
    /// Inside `route "r" { fallback { ... } }`.
    Fallback,
    /// Directly inside `upstream "u" { target "127.0.0.1:9000" ... }`.
    Upstream,
    /// Inside `upstream "u" { health-check { ... } }`.
    HealthCheck,
    /// Inside `upstream "u" { load-balancing "sticky" { ... } }`.
    Sticky,
    /// Directly inside `listener "l" { address "127.0.0.1:8443" protocol "https" ... }`.
    Listener,
    /// Inside the listener's `tls { cert-file ... key-file ... }`.
    ListenerTls,
    /// Inside `filter "f" { ... }`.
    Filter,
    /// Directly inside `agent "a" { unix-socket path="/tmp/a.sock" ... }`.
    Agent,
    /// Directly inside `system { ... }`.
    System,
    /// Directly inside `waf { ... }`.
    Waf,
    /// Directly inside `namespace "ns" { ... }`.
    Namespace,
    /// Directly inside `observability { ... }`.
    Observability,
}

/// The whole document, with `inner` placed in `ctx`.
///
/// Every block is written one node per line, so `inner` may hold several nodes.
fn document(ctx: Ctx, inner: &str) -> String {
    let mut system = "system {\n worker-threads 1\n}".to_string();
    let mut listener = "listener \"l\" {\n address \"127.0.0.1:8080\"\n}".to_string();
    let mut upstream = "upstream \"u\" {\n target \"127.0.0.1:9000\"\n}".to_string();
    let mut filter = "filter \"f\" {\n type \"cors\"\n}".to_string();
    let mut agent = "agent \"a\" {\n unix-socket path=\"/tmp/a.sock\"\n}".to_string();
    let mut route = "route \"r\" {\n matches {\n path \"/\"\n }\n}".to_string();
    let mut waf = String::new();
    let mut namespace = String::new();
    let mut observability = String::new();

    let in_route = |body: String| format!("route \"r\" {{\n{body}\n}}");
    let in_upstream =
        |body: String| format!("upstream \"u\" {{\n target \"127.0.0.1:9000\"\n{body}\n}}");
    let https_listener = |tls_body: &str, listener_body: &str| {
        format!(
            "listener \"l\" {{\n address \"127.0.0.1:8443\"\n protocol \"https\"\n \
             tls {{\n cert-file \"/c.pem\"\n key-file \"/k.pem\"\n{tls_body}\n}}\n{listener_body}\n}}"
        )
    };

    match ctx {
        Ctx::Route => route = in_route(inner.to_string()),
        Ctx::Policies => route = in_route(format!("policies {{\n{inner}\n}}")),
        Ctx::RequestHeaders => {
            route = in_route(format!("policies {{\nrequest-headers {{\n{inner}\n}}\n}}"))
        }
        Ctx::RouteCache => route = in_route(format!("cache {{\n{inner}\n}}")),
        Ctx::Inference => route = in_route(format!("inference {{\n{inner}\n}}")),
        Ctx::Fallback => route = in_route(format!("fallback {{\n{inner}\n}}")),
        Ctx::Upstream => upstream = in_upstream(inner.to_string()),
        Ctx::HealthCheck => upstream = in_upstream(format!("health-check {{\n{inner}\n}}")),
        Ctx::Sticky => upstream = in_upstream(format!("load-balancing \"sticky\" {{\n{inner}\n}}")),
        Ctx::Listener => listener = https_listener("", inner),
        Ctx::ListenerTls => listener = https_listener(inner, ""),
        Ctx::Filter => filter = format!("filter \"f\" {{\n{inner}\n}}"),
        Ctx::Agent => {
            agent = format!("agent \"a\" {{\n unix-socket path=\"/tmp/a.sock\"\n{inner}\n}}")
        }
        Ctx::System => system = format!("system {{\n{inner}\n}}"),
        Ctx::Waf => waf = format!("waf {{\n{inner}\n}}"),
        Ctx::Namespace => namespace = format!("namespace \"ns\" {{\n{inner}\n}}"),
        Ctx::Observability => observability = format!("observability {{\n{inner}\n}}"),
    }

    format!(
        "{system}\nlisteners {{\n{listener}\n}}\nupstreams {{\n{upstream}\n}}\n\
         filters {{\n{filter}\n}}\nagents {{\n{agent}\n}}\nroutes {{\n{route}\n}}\n\
         {waf}\n{namespace}\n{observability}\n"
    )
}

/// Load a document, with the error text on failure.
fn load(kdl: &str) -> Result<Config, String> {
    Config::from_kdl(kdl).map_err(|e| format!("{e:#}"))
}

/// `first` alone must load; `first` followed by `second` must not, and the
/// error must name `node`.
#[track_caller]
fn assert_duplicate(ctx: Ctx, first: &str, second: &str, node: &str) {
    let single = document(ctx, first);
    if let Err(e) = load(&single) {
        panic!("{ctx:?}: control with a single `{node}` should load, got: {e}\n{single}");
    }

    let doubled = document(ctx, &format!("{first}\n{second}"));
    match load(&doubled) {
        Ok(_) => panic!("{ctx:?}: `{node}` written twice was accepted\n{doubled}"),
        Err(e) => {
            assert!(
                e.contains(&format!("'{node}'")),
                "{ctx:?}: the error should name '{node}', got: {e}"
            );
            assert!(
                e.contains("Duplicate"),
                "{ctx:?}: the error should say what is wrong, got: {e}"
            );
        }
    }
}

/// `without` must load; `with`, which writes one of its nodes twice inside the
/// block, must not, and the error must name `node`.
#[track_caller]
fn assert_duplicate_within(ctx: Ctx, with: &str, without: &str, node: &str) {
    let control = document(ctx, without);
    if let Err(e) = load(&control) {
        panic!("{ctx:?}: control without the repeat should load, got: {e}\n{control}");
    }
    let doubled = document(ctx, with);
    match load(&doubled) {
        Ok(_) => panic!("{ctx:?}: `{node}` written twice was accepted\n{doubled}"),
        Err(e) => {
            assert!(
                e.starts_with(&format!("Duplicate node '{node}'")),
                "{ctx:?}: the error should name '{node}', got: {e}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[test]
fn a_route_with_two_filters_nodes_is_an_error() {
    assert_duplicate(Ctx::Route, r#"filters "a""#, r#"filters "b""#, "filters");
}

#[test]
fn a_route_with_two_matches_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"matches { path "/a" }"#,
        r#"matches { path "/b" }"#,
        "matches",
    );
}

#[test]
fn a_route_with_two_policies_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "policies { timeout-secs 5 }",
        "policies { timeout-secs 6 }",
        "policies",
    );
}

#[test]
fn a_route_with_two_upstream_nodes_is_an_error() {
    assert_duplicate(Ctx::Route, r#"upstream "a""#, r#"upstream "b""#, "upstream");
}

#[test]
fn a_route_with_two_priority_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"priority "high""#,
        r#"priority "low""#,
        "priority",
    );
}

#[test]
fn a_route_with_two_service_type_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"service-type "web""#,
        r#"service-type "api""#,
        "service-type",
    );
}

#[test]
fn a_route_with_two_websocket_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "websocket #true",
        "websocket #false",
        "websocket",
    );
}

#[test]
fn a_route_with_two_waf_enabled_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "waf-enabled #true",
        "waf-enabled #false",
        "waf-enabled",
    );
}

#[test]
fn a_route_with_two_retry_policy_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "retry-policy { max-attempts 2 }",
        "retry-policy { max-attempts 3 }",
        "retry-policy",
    );
}

#[test]
fn a_route_with_two_static_files_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"static-files { root "/www" }"#,
        r#"static-files { root "/other" }"#,
        "static-files",
    );
}

#[test]
fn a_route_with_two_shadow_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"shadow { upstream "s" }"#,
        r#"shadow { upstream "t" }"#,
        "shadow",
    );
}

#[test]
fn a_route_with_two_inference_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"inference { provider "openai" }"#,
        r#"inference { provider "anthropic" }"#,
        "inference",
    );
}

#[test]
fn a_route_with_two_error_pages_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        r#"error-pages { pages { "503" { message "a" } } }"#,
        r#"error-pages { pages { "503" { message "b" } } }"#,
        "error-pages",
    );
}

#[test]
fn a_policies_block_with_two_request_headers_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Policies,
        r#"request-headers { set { X-A "1" } }"#,
        r#"request-headers { set { X-B "2" } }"#,
        "request-headers",
    );
}

#[test]
fn a_policies_block_with_two_response_headers_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Policies,
        r#"response-headers { set { X-A "1" } }"#,
        r#"response-headers { set { X-B "2" } }"#,
        "response-headers",
    );
}

#[test]
fn a_policies_block_with_two_timeout_secs_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Policies,
        "timeout-secs 5",
        "timeout-secs 6",
        "timeout-secs",
    );
}

#[test]
fn a_policies_block_with_two_failure_mode_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Policies,
        r#"failure-mode "open""#,
        r#"failure-mode "closed""#,
        "failure-mode",
    );
}

#[test]
fn a_route_with_two_cache_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "cache { enabled #true }",
        "cache { enabled #false }",
        "cache",
    );
}

#[test]
fn a_cache_policy_with_two_ttl_nodes_is_an_error() {
    assert_duplicate(
        Ctx::RouteCache,
        "default-ttl-secs 60",
        "default-ttl-secs 120",
        "default-ttl-secs",
    );
}

#[test]
fn a_header_block_with_two_remove_nodes_is_an_error() {
    assert_duplicate(
        Ctx::RequestHeaders,
        r#"remove "X-A""#,
        r#"remove "X-B""#,
        "remove",
    );
}

#[test]
fn a_header_block_with_two_set_nodes_is_an_error() {
    assert_duplicate(
        Ctx::RequestHeaders,
        r#"set { X-A "1" }"#,
        r#"set { X-B "2" }"#,
        "set",
    );
}

#[test]
fn a_header_block_with_two_add_nodes_is_an_error() {
    assert_duplicate(
        Ctx::RequestHeaders,
        r#"add { X-A "1" }"#,
        r#"add { X-B "2" }"#,
        "add",
    );
}

#[test]
fn a_header_block_with_two_rename_nodes_is_an_error() {
    assert_duplicate(
        Ctx::RequestHeaders,
        r#"rename { X-A "X-B" }"#,
        r#"rename { X-C "X-D" }"#,
        "rename",
    );
}

#[test]
fn a_header_block_setting_the_same_header_twice_is_an_error() {
    let kdl = document(
        Ctx::RequestHeaders,
        r#"set { X-A "1"
 X-A "2" }"#,
    );
    let e = load(&kdl).expect_err("the same header set twice was accepted");
    assert!(e.contains("'X-A'") && e.contains("Duplicate"), "{e}");
}

#[test]
fn an_inference_block_with_two_model_routing_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Inference,
        r#"model-routing { default-upstream "a" }"#,
        r#"model-routing { default-upstream "b" }"#,
        "model-routing",
    );
}

#[test]
fn an_inference_block_with_two_rate_limit_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Inference,
        "rate-limit { tokens-per-minute 100 }",
        "rate-limit { tokens-per-minute 200 }",
        "rate-limit",
    );
}

#[test]
fn a_fallback_block_with_two_triggers_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Fallback,
        "triggers { on-health-failure #true }",
        "triggers { on-health-failure #false }",
        "triggers",
    );
}

#[test]
fn a_fallback_block_with_two_max_attempts_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Fallback,
        "max-attempts 2",
        "max-attempts 3",
        "max-attempts",
    );
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

#[test]
fn an_upstream_with_two_health_check_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        r#"health-check { type "tcp" }"#,
        r#"health-check { type "http" }"#,
        "health-check",
    );
}

#[test]
fn an_upstream_with_two_timeouts_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        "timeouts { connect-secs 5 }",
        "timeouts { connect-secs 6 }",
        "timeouts",
    );
}

#[test]
fn an_upstream_with_two_connection_pool_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        "connection-pool { max-connections 10 }",
        "connection-pool { max-connections 20 }",
        "connection-pool",
    );
}

#[test]
fn an_upstream_with_two_tls_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        r#"tls { sni "a.example" }"#,
        r#"tls { sni "b.example" }"#,
        "tls",
    );
}

#[test]
fn an_upstream_with_two_load_balancing_nodes_is_an_error() {
    // The upstream in `document` has no `load-balancing` of its own here.
    assert_duplicate(
        Ctx::Upstream,
        r#"load-balancing "round_robin""#,
        r#"load-balancing "random""#,
        "load-balancing",
    );
}

#[test]
fn an_upstream_with_two_circuit_breaker_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        "circuit-breaker { failure-threshold 3 }",
        "circuit-breaker { failure-threshold 5 }",
        "circuit-breaker",
    );
}

#[test]
fn an_upstream_with_two_http_version_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Upstream,
        "http-version { max-version 1 }",
        "http-version { max-version 2 }",
        "http-version",
    );
}

#[test]
fn a_health_check_with_two_interval_nodes_is_an_error() {
    assert_duplicate(
        Ctx::HealthCheck,
        "interval-secs 10",
        "interval-secs 20",
        "interval-secs",
    );
}

#[test]
fn a_health_check_with_two_type_nodes_is_an_error() {
    assert_duplicate(Ctx::HealthCheck, r#"type "tcp""#, r#"type "http""#, "type");
}

#[test]
fn a_sticky_block_with_two_cookie_name_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Sticky,
        r#"cookie-name "A""#,
        r#"cookie-name "B""#,
        "cookie-name",
    );
}

#[test]
fn an_upstream_defined_twice_in_one_block_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
upstreams {
    upstream "u" { target "127.0.0.1:9000" }
    upstream "u" { target "127.0.0.1:9001" }
}
"#;
    let e = load(kdl).expect_err("an upstream id defined twice was accepted");
    assert!(e.contains("Duplicate upstream ID 'u'"), "{e}");
}

#[test]
fn an_upstream_defined_in_two_upstreams_blocks_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
upstreams { upstream "u" { target "127.0.0.1:9000" } }
upstreams { upstream "u" { target "127.0.0.1:9001" } }
"#;
    let e = load(kdl).expect_err("an upstream id defined twice was accepted");
    assert!(e.contains("Duplicate upstream ID 'u'"), "{e}");
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

#[test]
fn a_filter_defined_twice_in_one_block_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
filters {
    filter "f" { type "cors" }
    filter "f" { type "compress" }
}
"#;
    let e = load(kdl).expect_err("a filter id defined twice was accepted");
    assert!(e.contains("Duplicate filter ID 'f'"), "{e}");
}

#[test]
fn a_filter_with_two_type_nodes_is_an_error() {
    assert_duplicate(Ctx::Filter, r#"type "cors""#, r#"type "compress""#, "type");
}

#[test]
fn a_rate_limit_filter_with_two_max_rps_nodes_is_an_error() {
    let single = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
filters { filter "f" { type "rate-limit"; max-rps 10; burst 20 } }
"#;
    load(single).expect("control loads");
    let doubled = single.replace("max-rps 10;", "max-rps 10; max-rps 20;");
    let e = load(&doubled).expect_err("max-rps written twice was accepted");
    assert!(e.contains("'max-rps'") && e.contains("Duplicate"), "{e}");
}

// ---------------------------------------------------------------------------
// Listeners, agents, system, other top-level blocks
// ---------------------------------------------------------------------------

#[test]
fn a_listener_with_two_tls_blocks_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners {
    listener "l" {
        address "127.0.0.1:8443"
        protocol "https"
        tls { cert-file "/a.pem"; key-file "/a.key" }
        tls { cert-file "/b.pem"; key-file "/b.key" }
    }
}
"#;
    let e = load(kdl).expect_err("two tls blocks were accepted");
    assert!(e.contains("'tls'") && e.contains("Duplicate"), "{e}");
}

#[test]
fn a_listener_with_two_address_nodes_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners {
    listener "l" {
        address "127.0.0.1:8080"
        address "127.0.0.1:8081"
    }
}
"#;
    let e = load(kdl).expect_err("two address nodes were accepted");
    assert!(e.contains("'address'") && e.contains("Duplicate"), "{e}");
}

#[test]
fn a_listener_with_two_request_timeout_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Listener,
        "request-timeout-secs 30",
        "request-timeout-secs 60",
        "request-timeout-secs",
    );
}

#[test]
fn a_tls_block_with_two_min_version_nodes_is_an_error() {
    assert_duplicate(
        Ctx::ListenerTls,
        r#"min-version "1.2""#,
        r#"min-version "1.3""#,
        "min-version",
    );
}

#[test]
fn an_agent_with_two_timeout_nodes_is_an_error() {
    assert_duplicate(Ctx::Agent, "timeout-ms 100", "timeout-ms 200", "timeout-ms");
}

#[test]
fn an_agent_with_two_failure_mode_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Agent,
        r#"failure-mode "open""#,
        r#"failure-mode "closed""#,
        "failure-mode",
    );
}

#[test]
fn an_agent_with_two_circuit_breaker_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Agent,
        "circuit-breaker { failure-threshold 3 }",
        "circuit-breaker { failure-threshold 5 }",
        "circuit-breaker",
    );
}

#[test]
fn a_system_block_with_two_worker_threads_nodes_is_an_error() {
    assert_duplicate(
        Ctx::System,
        "worker-threads 1",
        "worker-threads 2",
        "worker-threads",
    );
}

#[test]
fn a_system_block_with_two_max_connections_nodes_is_an_error() {
    assert_duplicate(
        Ctx::System,
        "max-connections 100",
        "max-connections 200",
        "max-connections",
    );
}

#[test]
fn a_waf_ruleset_written_twice_is_an_error() {
    assert_duplicate(
        Ctx::Waf,
        "ruleset { paranoia-level 1 }",
        "ruleset { paranoia-level 2 }",
        "ruleset",
    );
}

#[test]
fn an_observability_block_with_two_logging_blocks_is_an_error() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
observability {
    logging { level "info" }
    logging { level "debug" }
}
"#;
    let e = load(kdl).expect_err("two logging blocks were accepted");
    assert!(e.contains("'logging'") && e.contains("Duplicate"), "{e}");
}

#[test]
fn a_namespace_with_two_routes_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Namespace,
        r#"routes { route "a" { matches { path "/a" } } }"#,
        r#"routes { route "b" { matches { path "/b" } } }"#,
        "routes",
    );
}

#[test]
fn a_namespace_with_two_upstreams_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Namespace,
        r#"upstreams { upstream "a" { target "127.0.0.1:9000" } }"#,
        r#"upstreams { upstream "b" { target "127.0.0.1:9001" } }"#,
        "upstreams",
    );
}

// ---------------------------------------------------------------------------
// What stays legal
// ---------------------------------------------------------------------------

/// Nodes whose repetition is how a list is written must keep loading.
#[test]
fn nodes_that_are_meant_to_repeat_still_load() {
    let kdl = r#"
system { worker-threads 1 }
listeners {
    listener "a" {
        address "127.0.0.1:8080"
        trusted-proxies "10.0.0.0/8"
        trusted-proxies "192.0.2.0/24"
    }
    listener "b" { address "127.0.0.1:8081" }
}
listeners {
    listener "c" { address "127.0.0.1:8082" }
}
upstreams {
    upstream "u" {
        target "127.0.0.1:9000"
        target "127.0.0.1:9001" weight=2
    }
}
upstreams {
    upstream "v" { target "127.0.0.1:9002" }
}
agents {
    agent "a" {
        unix-socket path="/tmp/a.sock"
        events "request_headers"
        events "response_headers"
    }
}
routes {
    route "r" {
        matches {
            path-prefix "/api"
            header "x-a" "1"
            header "x-b" "2"
            method "GET"
        }
        upstream "u"
    }
    route "s" {
        matches { path "/s" }
        upstream "v"
    }
}
routes {
    route "t" {
        matches { path "/t" }
        upstream "u"
    }
}
"#;
    let config = load(kdl).expect("repeated list-like nodes load");
    assert_eq!(config.listeners.len(), 3);
    assert_eq!(config.upstreams.len(), 2);
    assert_eq!(config.routes.len(), 3);
    assert_eq!(config.upstreams["u"].targets.len(), 2);
    assert_eq!(config.agents[0].events.len(), 2);
    assert_eq!(config.listeners[0].trusted_proxies.len(), 2);
}

/// The same name in different blocks is not a repeat.
#[test]
fn the_same_node_name_in_different_blocks_is_not_a_duplicate() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
upstreams {
    upstream "u" {
        target "127.0.0.1:9000"
        timeouts { request-secs 30 }
        health-check { type "tcp"; timeout-secs 5 }
    }
    upstream "v" {
        target "127.0.0.1:9001"
        timeouts { request-secs 60 }
        health-check { type "tcp"; timeout-secs 5 }
    }
}
routes {
    route "r" { matches { path "/r" }; policies { timeout-secs 5 } }
    route "s" { matches { path "/s" }; policies { timeout-secs 5 } }
}
"#;
    load(kdl).expect("a node name shared between sibling blocks loads");
}

/// A top-level block written again, in another file or after an environment
/// override, replaces the earlier one. Directory loading relies on it.
#[test]
fn a_top_level_block_written_again_still_replaces_the_earlier_one() {
    let kdl = r#"
system { worker-threads 1 }
listeners { listener "l" { address "127.0.0.1:8080" } }
limits { max-header-count 100 }
limits { max-header-count 50 }
"#;
    let config = load(kdl).expect("a repeated top-level block loads");
    assert_eq!(config.limits.max_header_count, 50);
}

// ---------------------------------------------------------------------------
// The error says where the node is
// ---------------------------------------------------------------------------

#[track_caller]
fn assert_error_starts_with(ctx: Ctx, first: &str, second: &str, expected: &str) {
    let e = load(&document(ctx, &format!("{first}\n{second}"))).expect_err("accepted");
    assert!(e.starts_with(expected), "expected `{expected}`, got: {e}");
}

#[test]
fn the_error_names_the_route_that_holds_the_repeat() {
    assert_error_starts_with(
        Ctx::Route,
        r#"filters "a""#,
        r#"filters "b""#,
        r#"Duplicate node 'filters' in routes > route "r": "#,
    );
}

#[test]
fn the_error_names_every_block_on_the_way_down() {
    assert_error_starts_with(
        Ctx::RequestHeaders,
        r#"remove "X-A""#,
        r#"remove "X-B""#,
        r#"Duplicate node 'remove' in routes > route "r" > policies > request-headers: "#,
    );
}

#[test]
fn the_error_counts_the_copies() {
    let kdl = document(
        Ctx::System,
        "worker-threads 1\nworker-threads 2\nworker-threads 3",
    );
    let e = load(&kdl).expect_err("accepted");
    assert!(
        e.starts_with("Duplicate node 'worker-threads' in system: it is written 3 times"),
        "{e}"
    );
}

#[test]
fn the_error_tells_the_operator_what_to_do() {
    let kdl = document(Ctx::Route, "filters \"a\"\nfilters \"b\"");
    let e = load(&kdl).expect_err("accepted");
    assert!(
        e.contains("Combine them into a single 'filters' node"),
        "{e}"
    );
}

// ---------------------------------------------------------------------------
// Blocks read by walking their children, and keyed entries
// ---------------------------------------------------------------------------

#[test]
fn an_agent_circuit_breaker_with_a_setting_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "circuit-breaker {\nfailure-threshold 3\nfailure-threshold 5\n}",
        "circuit-breaker {\nfailure-threshold 3\n}",
        "failure-threshold",
    );
}

#[test]
fn a_retry_policy_with_a_setting_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "retry-policy {\nmax-attempts 2\nmax-attempts 3\n}",
        "retry-policy {\nmax-attempts 2\n}",
        "max-attempts",
    );
}

#[test]
fn an_agent_config_with_a_key_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "config {\ngreeting \"a\"\ngreeting \"b\"\n}",
        "config {\ngreeting \"a\"\n}",
        "greeting",
    );
}

#[test]
fn an_error_page_for_the_same_status_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "error-pages {\npages {\n\"503\" {\nmessage \"a\"\n}\n\"503\" {\nmessage \"b\"\n}\n}\n}",
        "error-pages {\npages {\n\"503\" {\nmessage \"a\"\n}\n}\n}",
        "503",
    );
}

#[test]
fn a_model_mapped_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Fallback,
        "fallback-upstream \"b\" {\nmodel-mapping {\n\"gpt-4\" \"x\"\n\"gpt-4\" \"y\"\n}\n}",
        "fallback-upstream \"b\" {\nmodel-mapping {\n\"gpt-4\" \"x\"\n}\n}",
        "gpt-4",
    );
}

#[test]
fn a_logging_block_with_two_access_logs_is_an_error() {
    assert_duplicate_within(
        Ctx::Observability,
        "logging {\naccess-log {\nenabled #true\n}\naccess-log {\nenabled #false\n}\n}",
        "logging {\naccess-log {\nenabled #true\n}\n}",
        "access-log",
    );
}

#[test]
fn a_service_with_two_listeners_is_an_error() {
    assert_duplicate_within(
        Ctx::Namespace,
        "service \"s\" {\nlistener {\naddress \"127.0.0.1:9100\"\n}\nlistener {\naddress \"127.0.0.1:9101\"\n}\n}",
        "service \"s\" {\nlistener {\naddress \"127.0.0.1:9100\"\n}\n}",
        "listener",
    );
}

#[test]
fn a_namespace_with_two_exports_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Namespace,
        "exports {\nupstreams \"a\"\n}",
        "exports {\nupstreams \"b\"\n}",
        "exports",
    );
}

#[test]
fn an_exports_block_with_two_upstreams_nodes_is_an_error() {
    assert_duplicate_within(
        Ctx::Namespace,
        "exports {\nupstreams \"a\"\nupstreams \"b\"\n}",
        "exports {\nupstreams \"a\"\n}",
        "upstreams",
    );
}

#[test]
fn a_target_with_two_weight_nodes_is_an_error() {
    assert_duplicate_within(
        Ctx::Upstream,
        "target {\naddress \"127.0.0.1:9001\"\nweight 1\nweight 2\n}",
        "target {\naddress \"127.0.0.1:9001\"\nweight 1\n}",
        "weight",
    );
}

#[test]
fn an_mcp_block_with_two_methods_blocks_is_an_error() {
    assert_duplicate(
        Ctx::Route,
        "mcp {\nmethods {\nallow \"tools/call\"\n}\n}",
        "mcp {\nmethods {\ndeny \"tools/list\"\n}\n}",
        "mcp",
    );
    assert_duplicate_within(
        Ctx::Route,
        "mcp {\nmethods {\nallow \"tools/call\"\n}\nmethods {\ndeny \"tools/list\"\n}\n}",
        "mcp {\nmethods {\nallow \"tools/call\"\n}\n}",
        "methods",
    );
}

#[test]
fn an_a2a_block_with_two_methods_blocks_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "a2a {\nmethods {\nallow \"message/send\"\n}\nmethods {\ndeny \"tasks/get\"\n}\n}",
        "a2a {\nmethods {\nallow \"message/send\"\n}\n}",
        "methods",
    );
}

#[test]
fn a_headers_filter_naming_a_header_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Filter,
        "type \"headers\"\nset {\nX-A \"1\"\nX-A \"2\"\n}",
        "type \"headers\"\nset {\nX-A \"1\"\n}",
        "X-A",
    );
}

#[test]
fn a_headers_filter_with_two_remove_nodes_is_an_error() {
    assert_duplicate(
        Ctx::Filter,
        "type \"headers\"\nremove \"X-A\"",
        "remove \"X-B\"",
        "remove",
    );
}

#[test]
fn a_response_header_added_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Policies,
        "response-headers {\nadd {\nX-A \"1\"\nX-A \"2\"\n}\n}",
        "response-headers {\nadd {\nX-A \"1\"\n}\n}",
        "X-A",
    );
}

#[test]
fn an_api_schema_with_a_setting_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "api-schema {\nschema-file \"/s.yaml\"\nvalidate-requests #true\nvalidate-requests #false\n}",
        "api-schema {\nschema-file \"/s.yaml\"\nvalidate-requests #true\n}",
        "validate-requests",
    );
}

#[test]
fn an_inline_schema_with_a_key_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "api-schema {\nrequest-schema {\ntype \"object\"\ntype \"array\"\n}\n}",
        "api-schema {\nrequest-schema {\ntype \"object\"\n}\n}",
        "type",
    );
}

// ---------------------------------------------------------------------------
// Agent TLS, header names, and what stays legal
// ---------------------------------------------------------------------------

#[test]
fn an_agent_transport_with_a_tls_setting_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "grpc \"http://127.0.0.1:50051\" {\nca-cert \"/a.pem\"\nca-cert \"/b.pem\"\n}",
        "grpc \"http://127.0.0.1:50051\" {\nca-cert \"/a.pem\"\n}",
        "ca-cert",
    );
}

#[test]
fn an_agent_transport_with_two_tls_blocks_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "grpc \"http://127.0.0.1:50051\" {\ntls {\nca-cert \"/a.pem\"\n}\ntls {\nclient-cert \"/c.pem\"\n}\n}",
        "grpc \"http://127.0.0.1:50051\" {\ntls {\nca-cert \"/a.pem\"\n}\n}",
        "tls",
    );
}

#[test]
fn an_agent_tls_block_with_a_setting_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "http \"https://127.0.0.1:8443\" {\ntls {\nclient-key \"/a.key\"\nclient-key \"/b.key\"\n}\n}",
        "http \"https://127.0.0.1:8443\" {\ntls {\nclient-key \"/a.key\"\n}\n}",
        "client-key",
    );
}

#[test]
fn an_agent_tls_verification_setting_written_twice_is_an_error() {
    assert_duplicate_within(
        Ctx::Agent,
        "grpc \"http://127.0.0.1:50051\" {\ntls-insecure #true\ntls-insecure #false\n}",
        "grpc \"http://127.0.0.1:50051\" {\ntls-insecure #true\n}",
        "tls-insecure",
    );
}

#[test]
fn a_header_named_in_two_cases_is_one_header() {
    assert_duplicate_within(
        Ctx::RequestHeaders,
        "set {\nX-A \"1\"\nx-a \"2\"\n}",
        "set {\nX-A \"1\"\n}",
        "X-A",
    );
    assert_duplicate_within(
        Ctx::RequestHeaders,
        "add {\nX-A \"1\"\nX-a \"2\"\n}",
        "add {\nX-A \"1\"\n}",
        "X-A",
    );
    assert_duplicate_within(
        Ctx::RequestHeaders,
        "rename {\nX-Old \"X-New\"\nx-old \"X-Newer\"\n}",
        "rename {\nX-Old \"X-New\"\n}",
        "X-Old",
    );
}

#[test]
fn a_headers_filter_naming_a_header_in_two_cases_is_an_error() {
    assert_duplicate_within(
        Ctx::Filter,
        "type \"headers\"\nset {\nX-A \"1\"\nx-a \"2\"\n}",
        "type \"headers\"\nset {\nX-A \"1\"\n}",
        "X-A",
    );
}

#[test]
fn an_error_page_header_in_two_cases_is_an_error() {
    assert_duplicate_within(
        Ctx::Route,
        "error-pages {\npages {\n\"503\" {\nheaders {\nRetry-After \"5\"\nretry-after \"6\"\n}\n}\n}\n}",
        "error-pages {\npages {\n\"503\" {\nheaders {\nRetry-After \"5\"\n}\n}\n}\n}",
        "Retry-After",
    );
}

/// The check compares names, so different headers in one block are fine and
/// both are read.
#[test]
fn different_header_names_in_one_block_are_both_read() {
    let kdl = document(
        Ctx::RequestHeaders,
        "set {\nX-A \"1\"\nX-B \"2\"\n}\nremove \"X-C\"",
    );
    let config = load(&kdl).expect("different header names load");
    let headers = &config.routes[0].policies.request_headers;
    assert_eq!(headers.set.get("X-A").map(String::as_str), Some("1"));
    assert_eq!(headers.set.get("X-B").map(String::as_str), Some("2"));
    assert_eq!(headers.remove, vec!["X-C".to_string()]);
}

/// `protocol-version` is read only to warn that it is ignored, so writing it
/// twice has no effect to refuse.
#[test]
fn the_deprecated_protocol_version_may_be_written_twice() {
    let kdl = document(Ctx::Agent, "protocol-version 2\nprotocol-version 2");
    load(&kdl).expect("a repeated protocol-version loads");
}

/// `system` repeated is read with a warning, the later block replacing the
/// earlier, as the other top-level blocks are.
#[test]
fn a_system_block_written_again_replaces_the_earlier_one() {
    let kdl = r#"
system { worker-threads 1 }
system { worker-threads 3 }
listeners { listener "l" { address "127.0.0.1:8080" } }
"#;
    let config = load(kdl).expect("a repeated system block loads");
    assert_eq!(config.server.worker_threads, 3);
}
