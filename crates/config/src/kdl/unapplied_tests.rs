//! A setting the parser reads and the proxy never applies is said so when the
//! configuration is loaded.
//!
//! Each case loads a document that writes one such setting and checks that
//! exactly one warning names it and where it was written. The control beside
//! it writes the settings of the same blocks that are applied, and must load
//! without a warning of that kind. The same messages reach `zentinel lint` and
//! `zentinel test --strict`; those are tested in `validate::unknown_keys`.

use crate::test_log::warnings_logged_by;
use crate::Config;

/// What every message of this kind says, so a control can check for it.
const NOT_APPLIED: &str = "is not applied and is being ignored";

/// What the message for a key the parser does not read says.
const NOT_READ: &str = "is not read and is being ignored";

/// A whole document with `body` added to the block it is about.
struct Doc {
    listener: String,
    upstream: String,
    route: String,
    extra: String,
}

impl Doc {
    fn empty() -> Self {
        Doc {
            listener: String::new(),
            upstream: String::new(),
            route: String::new(),
            extra: String::new(),
        }
    }

    fn listener(body: &str) -> Self {
        Doc {
            listener: body.to_string(),
            ..Doc::empty()
        }
    }

    fn upstream(body: &str) -> Self {
        Doc {
            upstream: body.to_string(),
            ..Doc::empty()
        }
    }

    fn route(body: &str) -> Self {
        Doc {
            route: body.to_string(),
            ..Doc::empty()
        }
    }

    fn top_level(body: &str) -> Self {
        Doc {
            extra: body.to_string(),
            ..Doc::empty()
        }
    }

    /// The warnings logged while the document is loaded.
    fn warnings(&self) -> Vec<String> {
        let kdl = format!(
            "system {{\n worker-threads 1\n}}\n\
             listeners {{\n listener \"l\" {{\n address \"127.0.0.1:8080\"\n{}\n }}\n}}\n\
             upstreams {{\n upstream \"u\" {{\n target \"127.0.0.1:9000\"\n{}\n }}\n}}\n\
             routes {{\n route \"r\" {{\n matches {{\n path \"/\"\n }}\n upstream \"u\"\n{}\n }}\n}}\n\
             {}\n",
            self.listener, self.upstream, self.route, self.extra
        );
        let (loaded, warnings) = warnings_logged_by(|| Config::from_kdl(&kdl));
        if let Err(e) = loaded {
            panic!("the document should load: {e:#}\n{kdl}");
        }
        warnings
            .into_iter()
            .filter(|w| w.contains(NOT_APPLIED) || w.contains(NOT_READ))
            .collect()
    }
}

/// Exactly one warning, and it names `setting` and `place`.
#[track_caller]
fn assert_reported(doc: &Doc, setting: &str, place: &str) {
    let warnings = doc.warnings();
    assert_eq!(
        warnings.len(),
        1,
        "expected one warning for `{setting}`, got: {warnings:#?}"
    );
    assert!(
        warnings[0].contains(&format!("'{setting}'")),
        "the warning should name `{setting}`: {}",
        warnings[0]
    );
    assert!(
        warnings[0].contains(place),
        "the warning should say where it was written (`{place}`): {}",
        warnings[0]
    );
}

#[track_caller]
fn assert_quiet(doc: &Doc) {
    let warnings = doc.warnings();
    assert!(
        warnings.is_empty(),
        "settings that are applied were reported: {warnings:#?}"
    );
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[test]
fn a_cache_block_inside_policies_is_reported_and_one_beside_it_is_not() {
    assert_reported(
        &Doc::route("policies {\n cache {\n enabled #true\n }\n}"),
        "cache",
        "route 'r'",
    );
    assert_quiet(&Doc::route(
        "policies {\n timeout-secs 5\n}\ncache {\n enabled #true\n default-ttl-secs 60\n}",
    ));
}

/// Writing the block where it is read makes the route cached, and the cache key
/// has no request headers in it: the advice must say so.
#[test]
fn the_advice_on_a_cache_block_says_what_moving_it_does() {
    let moved = Doc::route("policies {\n cache {\n enabled #true\n }\n}").warnings();
    assert_eq!(moved.len(), 1, "{moved:#?}");
    assert!(moved[0].contains("turns the cache on"), "{}", moved[0]);
    assert!(
        moved[0].contains("varies by a request header"),
        "{}",
        moved[0]
    );

    let varied = Doc::route("cache {\n enabled #true\n vary-headers \"Accept\"\n}").warnings();
    assert_eq!(varied.len(), 1, "{varied:#?}");
    assert!(
        varied[0].contains("varies by a request header"),
        "{}",
        varied[0]
    );
}

#[test]
fn model_header_advice_says_where_the_model_name_is_read_from() {
    let warnings = Doc::route("inference {\n model-header \"X-Model\"\n}").warnings();
    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(warnings[0].contains("'x-model'"), "{}", warnings[0]);
    assert!(warnings[0].contains("request body"), "{}", warnings[0]);
}

#[test]
fn waf_enabled_is_reported_whatever_its_value() {
    assert_reported(&Doc::route("waf-enabled #true"), "waf-enabled", "route 'r'");
    assert_reported(
        &Doc::route("waf-enabled #false"),
        "waf-enabled",
        "route 'r'",
    );
    assert_quiet(&Doc::route("websocket #true"));
}

#[test]
fn the_cache_settings_that_do_not_reach_the_cache_key_are_reported() {
    assert_reported(
        &Doc::route("cache {\n enabled #true\n vary-headers \"Accept\"\n}"),
        "vary-headers",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("cache {\n enabled #true\n ignore-query-params \"a\" \"b\"\n}"),
        "ignore-query-params",
        "route 'r'",
    );
    assert_quiet(&Doc::route(
        "cache {\n enabled #true\n default-ttl-secs 60\n exclude-paths \"/a/**\"\n \
         exclude-extensions \"php\"\n cacheable-methods \"GET\"\n}",
    ));
}

#[test]
fn a_fallback_upstream_written_as_upstream_is_reported() {
    assert_reported(
        &Doc::route("fallback {\n upstream \"u\"\n}"),
        "upstream",
        "route 'r'",
    );
    assert_quiet(&Doc::route(
        "fallback {\n max-attempts 2\n triggers {\n on-health-failure #true\n \
         on-budget-exhausted #false\n on-latency-threshold-ms 5000\n on-error-codes 502 503\n \
         on-connection-error #true\n }\n fallback-upstream \"u\" {\n provider \"openai\"\n \
         skip-if-unhealthy #true\n model-mapping {\n \"a\" \"b\"\n }\n }\n}",
    ));
}

#[test]
fn a_model_mapping_beside_the_fallback_upstream_is_reported() {
    assert_reported(
        &Doc::route("fallback {\n fallback-upstream \"u\"\n model-mapping {\n \"a\" \"b\"\n }\n}"),
        "model-mapping",
        "route 'r'",
    );
}

#[test]
fn keys_the_fallback_blocks_do_not_read_are_reported() {
    assert_reported(
        &Doc::route("fallback {\n triggers {\n on-timeout 5\n }\n}"),
        "on-timeout",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("fallback {\n fallback-upstream \"u\" {\n weight 2\n }\n}"),
        "weight",
        "route 'r'",
    );
}

#[test]
fn model_routing_rules_written_as_mappings_are_reported() {
    assert_reported(
        &Doc::route(
            "inference {\n model-routing {\n mappings {\n mapping \"gpt-4*\" {\n \
             upstream \"u\"\n }\n }\n }\n}",
        ),
        "mappings",
        "route 'r'",
    );
    assert_quiet(&Doc::route(
        "inference {\n model-routing {\n model \"gpt-4*\" upstream=\"u\"\n \
         model \"claude-*\" upstream=\"u\" provider=\"anthropic\"\n default-upstream \"u\"\n }\n}",
    ));
}

#[test]
fn a_fallback_written_inside_inference_and_token_estimation_are_reported() {
    assert_reported(
        &Doc::route("inference {\n fallback {\n fallback-upstream \"u\"\n }\n}"),
        "fallback",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n token-estimation \"chars\"\n}"),
        "token-estimation",
        "route 'r'",
    );
    assert_quiet(&Doc::route(
        "inference {\n provider \"openai\"\n rate-limit {\n tokens-per-minute 1000\n \
         estimation-method \"words\"\n }\n}\nfallback {\n fallback-upstream \"u\"\n}",
    ));
}

#[test]
fn keys_the_token_limit_and_budget_blocks_do_not_read_are_reported() {
    assert_reported(
        &Doc::route("inference {\n rate-limit {\n tokens-per-minute 100\n key \"x\"\n }\n}"),
        "key",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n budget {\n limit 10\n key \"x\"\n }\n}"),
        "key",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n budget {\n limit 10\n daily-limit 5\n }\n}"),
        "daily-limit",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n budget {\n limit 10\n alert-threshold 0.8\n }\n}"),
        "alert-threshold",
        "route 'r'",
    );
}

#[test]
fn per_model_prices_are_read_from_pricing_and_nowhere_else() {
    assert_reported(
        &Doc::route(
            "inference {\n cost-attribution {\n models {\n model \"m\" {\n \
             input-cost-per-1k 1\n }\n }\n }\n}",
        ),
        "models",
        "route 'r'",
    );
    assert_reported(
        &Doc::route(
            "inference {\n cost-attribution {\n pricing {\n model \"m\" {\n \
             input-cost-per-million 1\n output-cost-per-million 2\n \
             input-cost-per-1k 3\n }\n }\n }\n}",
        ),
        "input-cost-per-1k",
        "route 'r'",
    );
}

#[test]
fn a_property_a_block_does_not_read_is_reported() {
    assert_reported(
        &Doc::route(
            "fallback {\n fallback-upstream \"u\" provider=\"anthropic\" {\n \
             skip-if-unhealthy #true\n }\n}",
        ),
        "provider",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n model-routing {\n model \"m*\" upstream=\"u\" weight=2\n }\n}"),
        "weight",
        "route 'r'",
    );
}

#[test]
fn keys_the_guardrail_blocks_do_not_read_are_reported() {
    assert_reported(
        &Doc::route(
            "inference {\n guardrails {\n prompt-injection {\n agent \"g\"\n \
             severity \"high\"\n }\n }\n}",
        ),
        "severity",
        "route 'r'",
    );
}

#[test]
fn inference_routing_is_reported_as_not_applied() {
    assert_reported(
        &Doc::route("inference {\n routing {\n strategy \"least_latency\"\n }\n}"),
        "routing",
        "route 'r'",
    );
}

#[test]
fn every_inference_setting_the_parser_reads_and_the_proxy_applies_is_quiet() {
    assert_quiet(&Doc::route(
        "inference {\n provider \"openai\"\n rate-limit {\n tokens-per-minute 1000\n \
         requests-per-minute 10\n burst-tokens 100\n estimation-method \"words\"\n }\n \
         budget {\n period \"daily\"\n limit 100000\n alert-thresholds 0.8 0.9\n \
         enforce #true\n rollover #false\n burst-allowance 0.1\n max-tenants 100\n }\n \
         cost-attribution {\n enabled #true\n default-input-cost 1.0\n \
         default-output-cost 2.0\n currency \"USD\"\n pricing {\n model \"gpt-4*\" {\n \
         input-cost-per-million 30.0\n output-cost-per-million 60.0\n currency \"USD\"\n }\n \
         }\n }\n guardrails {\n prompt-injection {\n enabled #true\n agent \"g\"\n \
         action \"block\"\n block-status 400\n block-message \"no\"\n timeout-ms 500\n \
         failure-mode \"open\"\n }\n pii-detection {\n enabled #true\n agent \"p\"\n \
         action \"log\"\n categories \"ssn\" \"email\"\n timeout-ms 500\n \
         failure-mode \"closed\"\n }\n }\n}",
    ));
}

#[test]
fn model_header_is_reported_inside_model_routing_and_in_inference() {
    assert_reported(
        &Doc::route(
            "inference {\n model-routing {\n model-header \"X-Model\"\n default-upstream \"u\"\n }\n}",
        ),
        "model-header",
        "route 'r'",
    );
    assert_reported(
        &Doc::route("inference {\n model-header \"X-Model\"\n}"),
        "model-header",
        "route 'r'",
    );
}

// ---------------------------------------------------------------------------
// Upstreams
// ---------------------------------------------------------------------------

#[test]
fn an_upstream_ca_cert_is_reported_and_the_other_tls_settings_are_not() {
    assert_reported(
        &Doc::upstream("tls {\n sni \"a.example\"\n ca-cert \"/etc/ca.pem\"\n}"),
        "ca-cert",
        "upstream 'u'",
    );
    assert_quiet(&Doc::upstream(
        "tls {\n sni \"a.example\"\n insecure-skip-verify #false\n}",
    ));
}

#[test]
fn the_connection_pool_settings_nothing_reads_are_reported() {
    for (line, setting) in [
        ("max-connections 5", "max-connections"),
        ("max-idle 5", "max-idle"),
        ("max-lifetime-secs 300", "max-lifetime-secs"),
        ("max-lifetime 300", "max-lifetime"),
    ] {
        let body = format!("connection-pool {{\n {line}\n}}");
        assert_reported(&Doc::upstream(&body), setting, "upstream 'u'");
    }
}

#[test]
fn the_connection_pool_idle_timeout_is_applied_and_not_reported() {
    assert_quiet(&Doc::upstream(
        "connection-pool {\n idle-timeout-secs 30\n}",
    ));
    assert_quiet(&Doc::upstream("connection-pool {\n idle-timeout 30\n}"));
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

#[test]
fn a_listener_max_concurrent_streams_is_reported_even_at_its_default() {
    assert_reported(
        &Doc::listener("max-concurrent-streams 50"),
        "max-concurrent-streams",
        "listener 'l'",
    );
    assert_reported(
        &Doc::listener("max-concurrent-streams 100"),
        "max-concurrent-streams",
        "listener 'l'",
    );
    assert_quiet(&Doc::listener(
        "request-timeout-secs 30\nkeepalive-timeout-secs 60",
    ));
}

// ---------------------------------------------------------------------------
// Logging and the WAF block
// ---------------------------------------------------------------------------

#[test]
fn the_logging_level_and_format_are_reported() {
    assert_reported(
        &Doc::top_level("observability {\n logging {\n level \"debug\"\n }\n}"),
        "level",
        "'logging'",
    );
    assert_reported(
        &Doc::top_level("observability {\n logging {\n format \"pretty\"\n }\n}"),
        "format",
        "'logging'",
    );
}

#[test]
fn the_log_settings_that_are_applied_are_not_reported() {
    // `format` of the access log and `level` of the error log are their own
    // settings and are applied.
    assert_quiet(&Doc::top_level(
        "observability {\n logging {\n timestamps #false\n \
         access-log {\n enabled #false\n format \"combined\"\n }\n \
         error-log {\n enabled #false\n level \"error\"\n }\n }\n}",
    ));
}

#[test]
fn inspect_response_body_is_reported_and_the_request_side_is_not() {
    assert_reported(
        &Doc::top_level(
            "waf {\n mode \"off\"\n body-inspection {\n inspect-response-body #true\n }\n}",
        ),
        "inspect-response-body",
        "'body-inspection'",
    );
    assert_quiet(&Doc::top_level(
        "waf {\n mode \"off\"\n body-inspection {\n inspect-request-body #true\n \
         max-inspection-bytes 4096\n }\n}",
    ));
}
