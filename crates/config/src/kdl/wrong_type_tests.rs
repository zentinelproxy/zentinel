//! A value of the wrong type is an error, not the setting's default.
//!
//! Each case writes a setting with a value of a type it does not take, such as
//! `max-connections-per-client "100"`, and the same document with the right
//! type. The control must load; the other must not, and the error must name the
//! setting, what it takes, what was written, and where. A `tls` block on a
//! listener that does not serve TLS is refused too.

use crate::{Config, ListenerProtocol};
use zentinel_common::types::TlsVersion;

/// A whole document, one block at a time, so that a case can change the block it
/// is about and keep the rest valid.
struct Doc {
    listener: String,
    upstream: String,
    route: String,
    extra: String,
}

impl Doc {
    fn new() -> Self {
        Doc {
            listener: String::new(),
            upstream: String::new(),
            route: String::new(),
            extra: String::new(),
        }
    }

    /// Lines placed inside `listener "l" { address "127.0.0.1:8080" ... }`.
    fn listener(mut self, body: &str) -> Self {
        self.listener = body.to_string();
        self
    }

    /// Lines placed inside `upstream "u" { target "127.0.0.1:9000" ... }`.
    fn upstream(mut self, body: &str) -> Self {
        self.upstream = body.to_string();
        self
    }

    /// Lines placed inside `route "r" { matches { path "/" } upstream "u" ... }`.
    fn route(mut self, body: &str) -> Self {
        self.route = body.to_string();
        self
    }

    /// Blocks placed after the others, at the top level.
    fn extra(mut self, body: &str) -> Self {
        self.extra = body.to_string();
        self
    }

    fn render(&self) -> String {
        format!(
            "system {{\n worker-threads 1\n}}\n\
             listeners {{\n listener \"l\" {{\n address \"127.0.0.1:8080\"\n{}\n }}\n}}\n\
             upstreams {{\n upstream \"u\" {{\n target \"127.0.0.1:9000\"\n{}\n }}\n}}\n\
             routes {{\n route \"r\" {{\n matches {{\n path \"/\"\n }}\n upstream \"u\"\n{}\n }}\n}}\n\
             {}\n",
            self.listener, self.upstream, self.route, self.extra
        )
    }

    fn load(&self) -> Result<Config, String> {
        Config::from_kdl(&self.render()).map_err(|e| format!("{e:#}"))
    }
}

const TLS_FILES: &str = "cert-file \"/c.pem\"\n key-file \"/k.pem\"";

/// A listener body that serves TLS, with `tls_body` added to its `tls` block.
fn https_listener(tls_body: &str) -> String {
    format!("protocol \"https\"\n tls {{\n {TLS_FILES}\n{tls_body}\n }}")
}

/// `good` must load; `bad` must not, and the error must say that `node` was
/// written with a value of the wrong type, what it takes, and what was written.
/// `location` is the part of the error that says where, or empty.
#[track_caller]
fn assert_wrong_type(good: &Doc, bad: &Doc, node: &str, expected: &str, found: &str, at: &str) {
    if let Err(e) = good.load() {
        panic!(
            "the control with the right type should load, got: {e}\n{}",
            good.render()
        );
    }
    let error = match bad.load() {
        Ok(_) => panic!("`{node}` with a wrong type was accepted\n{}", bad.render()),
        Err(e) => e,
    };
    let want = format!("Wrong value type for '{node}'");
    assert!(error.contains(&want), "expected `{want}` in: {error}");
    assert!(
        error.contains(&format!("expected {expected}, found {found}.")),
        "expected `expected {expected}, found {found}.` in: {error}"
    );
    assert!(error.contains(at), "expected `{at}` in: {error}");
}

const INTEGER: &str = "an integer (without quotes)";
const STRING: &str = "a string (in quotes)";
const BOOL: &str = "#true or #false (without quotes)";

// ---------------------------------------------------------------------------
// The cases the change is about
// ---------------------------------------------------------------------------

#[test]
fn a_connection_limit_written_as_a_string_is_an_error() {
    let good = Doc::new().extra("limits {\n max-connections-per-client 100\n}");
    let bad = Doc::new().extra("limits {\n max-connections-per-client \"100\"\n}");
    assert_wrong_type(
        &good,
        &bad,
        "max-connections-per-client",
        INTEGER,
        "a string",
        "in limits",
    );
}

#[test]
fn client_auth_written_as_a_string_is_an_error() {
    let good = Doc::new().listener(&https_listener("client-auth #true\n ca-file \"/ca.pem\""));
    let bad = Doc::new().listener(&https_listener(
        "client-auth \"true\"\n ca-file \"/ca.pem\"",
    ));
    assert_wrong_type(
        &good,
        &bad,
        "client-auth",
        BOOL,
        "a string",
        "in listeners > listener \"l\" > tls",
    );
}

#[test]
fn a_tls_version_written_as_a_number_is_an_error() {
    let good = Doc::new().listener(&https_listener("min-version \"1.3\""));
    let bad = Doc::new().listener(&https_listener("min-version 1.3"));
    assert_wrong_type(
        &good,
        &bad,
        "min-version",
        STRING,
        "a number",
        "in listeners > listener \"l\" > tls",
    );

    let config = good.load().unwrap();
    let tls = config.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.min_version, TlsVersion::Tls13);
}

#[test]
fn a_route_timeout_written_as_a_string_is_an_error() {
    let good = Doc::new().route("policies {\n timeout-secs 30\n}");
    let bad = Doc::new().route("policies {\n timeout-secs \"30\"\n}");
    assert_wrong_type(
        &good,
        &bad,
        "timeout-secs",
        INTEGER,
        "a string",
        "in routes > route \"r\" > policies",
    );
    assert_eq!(
        good.load().unwrap().routes[0].policies.timeout_secs,
        Some(30)
    );
}

#[test]
fn a_string_setting_written_as_a_number_is_an_error() {
    let good = Doc::new().listener("protocol \"http\"");
    let bad = Doc::new().listener("protocol 1");
    assert_wrong_type(
        &good,
        &bad,
        "protocol",
        STRING,
        "an integer",
        "in listeners > listener \"l\"",
    );
}

#[test]
fn a_boolean_written_as_a_string_is_an_error() {
    let good = Doc::new().extra("system {\n daemon #false\n}");
    let bad = Doc::new().extra("system {\n daemon \"false\"\n}");
    // A second `system` block replaces the first, so the case is checked on the
    // block that wins.
    assert_wrong_type(&good, &bad, "daemon", BOOL, "a string", "in system");
}

#[test]
fn a_setting_written_with_no_value_is_an_error() {
    let good = Doc::new().extra("limits {\n max-connections-per-client 100\n}");
    let bad = Doc::new().extra("limits {\n max-connections-per-client\n}");
    assert_wrong_type(
        &good,
        &bad,
        "max-connections-per-client",
        INTEGER,
        "no value",
        "in limits",
    );
}

#[test]
fn a_top_level_setting_is_located_at_the_top_level() {
    let bad = format!("{}\nschema-version 1\n", Doc::new().render());
    let error = Config::from_kdl(&bad).map(|_| ()).unwrap_err().to_string();
    assert!(
        error.contains("Wrong value type for 'schema-version' at the top level"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_property_of_the_wrong_type_is_an_error() {
    let good = Doc::new().upstream("target \"127.0.0.1:9001\" weight=2");
    let bad = Doc::new().upstream("target \"127.0.0.1:9001\" weight=\"2\"");
    assert_wrong_type(
        &good,
        &bad,
        "weight",
        INTEGER,
        "a string",
        "in upstreams > upstream \"u\"",
    );
}

#[test]
fn a_header_value_that_is_not_a_string_is_an_error() {
    let good =
        Doc::new().route("policies {\n response-headers {\n set {\n X-Retries \"3\"\n }\n }\n}");
    let bad = Doc::new().route("policies {\n response-headers {\n set {\n X-Retries 3\n }\n }\n}");
    assert_wrong_type(
        &good,
        &bad,
        "X-Retries",
        STRING,
        "an integer",
        "routes > route \"r\" > policies > response-headers > set",
    );
}

#[test]
fn a_list_with_a_value_of_the_wrong_type_is_an_error() {
    let good = Doc::new().route("cache {\n cacheable-methods \"GET\" \"HEAD\"\n}");
    let bad = Doc::new().route("cache {\n cacheable-methods \"GET\" 5\n}");
    assert_wrong_type(
        &good,
        &bad,
        "cacheable-methods",
        STRING,
        "an integer",
        "in routes > route \"r\" > cache",
    );

    let good = Doc::new().route("cache {\n cacheable-status-codes 200 404\n}");
    let bad = Doc::new().route("cache {\n cacheable-status-codes 200 \"404\"\n}");
    assert_wrong_type(
        &good,
        &bad,
        "cacheable-status-codes",
        INTEGER,
        "a string",
        "in routes > route \"r\" > cache",
    );

    let good = Doc::new().route("filters \"f\"");
    let bad = Doc::new().route("filters \"f\" 7");
    assert_wrong_type(
        &good,
        &bad,
        "filters",
        STRING,
        "an integer",
        "in routes > route \"r\"",
    );
}

#[test]
fn an_agent_setting_of_the_wrong_type_is_an_error() {
    let agent = |body: &str| {
        Doc::new().extra(&format!(
            "agents {{\n agent \"a\" {{\n unix-socket path=\"/tmp/a.sock\"\n{body}\n }}\n}}"
        ))
    };
    assert_wrong_type(
        &agent("timeout-ms 500"),
        &agent("timeout-ms \"500\""),
        "timeout-ms",
        INTEGER,
        "a string",
        "in agents > agent \"a\"",
    );
    // `tls-insecure` alone means #true; with an argument that is not a boolean
    // it used to mean #true too.
    let grpc = |body: &str| {
        Doc::new().extra(&format!(
            "agents {{\n agent \"a\" {{\n grpc \"localhost:50051\" {{\n{body}\n }}\n }}\n}}"
        ))
    };
    assert_wrong_type(
        &grpc("tls-insecure #false"),
        &grpc("tls-insecure \"false\""),
        "tls-insecure",
        BOOL,
        "a string",
        "in agents > agent \"a\" > grpc",
    );
    assert_wrong_type(
        &agent("events \"request_headers\""),
        &agent("events 1"),
        "events",
        STRING,
        "an integer",
        "in agents > agent \"a\"",
    );
}

#[test]
fn an_upstream_setting_of_the_wrong_type_is_an_error() {
    assert_wrong_type(
        &Doc::new().upstream("load-balancing \"round_robin\""),
        &Doc::new().upstream("load-balancing 2"),
        "load-balancing",
        STRING,
        "an integer",
        "in upstreams > upstream \"u\"",
    );
    assert_wrong_type(
        &Doc::new().upstream("health-check {\n interval-secs 5\n}"),
        &Doc::new().upstream("health-check {\n interval-secs \"5\"\n}"),
        "interval-secs",
        INTEGER,
        "a string",
        "in upstreams > upstream \"u\" > health-check",
    );
}

#[test]
fn the_error_does_not_repeat_the_value() {
    let bad = Doc::new().extra("limits {\n max-connections-per-client \"hunter2\"\n}");
    let error = bad.load().map(|_| ()).unwrap_err();
    assert!(
        error.contains("found a string."),
        "unexpected error: {error}"
    );
    assert!(!error.contains("hunter2"), "the value is in: {error}");
}

#[test]
fn an_argument_that_is_missing_or_written_as_a_property_is_an_error() {
    let agent = |body: &str| {
        Doc::new().extra(&format!(
            "agents {{\n agent \"a\" {{\n unix-socket path=\"/tmp/a.sock\"\n{body}\n }}\n}}"
        ))
    };
    let at = "in agents > agent \"a\"";
    assert_wrong_type(
        &agent("failure-mode \"closed\""),
        &agent("failure-mode"),
        "failure-mode",
        STRING,
        "no value",
        at,
    );
    assert_wrong_type(
        &agent("failure-mode \"closed\""),
        &agent("failure-mode mode=\"closed\""),
        "failure-mode",
        STRING,
        "a property written as name=value",
        at,
    );
    assert_wrong_type(
        &agent("request-body-mode \"stream\""),
        &agent("request-body-mode"),
        "request-body-mode",
        STRING,
        "no value",
        at,
    );

    assert_wrong_type(
        &Doc::new().upstream("load-balancing \"round_robin\""),
        &Doc::new().upstream("load-balancing"),
        "load-balancing",
        STRING,
        "no value",
        "in upstreams > upstream \"u\"",
    );
    assert_wrong_type(
        &Doc::new().listener(&https_listener("cipher-suite \"TLS_AES_128_GCM_SHA256\"")),
        &Doc::new().listener(&https_listener("cipher-suite")),
        "cipher-suite",
        STRING,
        "no value",
        "in listeners > listener \"l\" > tls",
    );
    assert_wrong_type(
        &Doc::new().route("policies {\n request-headers {\n set {\n X-A \"1\"\n }\n }\n}"),
        &Doc::new().route("policies {\n request-headers {\n set {\n X-A\n }\n }\n}"),
        "X-A",
        STRING,
        "no value",
        "in routes > route \"r\" > policies > request-headers > set",
    );
}

#[test]
fn a_list_entry_written_as_a_property_is_an_error() {
    let good = Doc::new().route("cache {\n cacheable-methods \"GET\" \"HEAD\"\n}");
    let bad = Doc::new().route("cache {\n cacheable-methods \"GET\" method=\"HEAD\"\n}");
    assert_wrong_type(
        &good,
        &bad,
        "cacheable-methods",
        STRING,
        "a property written as name=value",
        "in routes > route \"r\" > cache",
    );
}

#[test]
fn an_allow_list_with_a_value_of_the_wrong_type_is_an_error() {
    let route = |tools: &str| Doc::new().route(&format!("mcp {{\n tools {{\n{tools}\n }}\n}}"));
    assert_wrong_type(
        &route("allow \"search\""),
        &route("allow \"search\" 5"),
        "allow",
        STRING,
        "an integer",
        "in routes > route \"r\" > mcp > tools",
    );

    // An entry that is neither `allow` nor `deny` keeps its own message, whatever
    // it holds.
    let error = route("frob 5").load().map(|_| ()).unwrap_err();
    assert!(
        error.contains("Unknown entry 'frob'"),
        "unexpected error: {error}"
    );
}

#[test]
fn a_null_is_read_as_no_value() {
    let doc = Doc::new()
        .listener(&https_listener("min-version #null\n client-auth #null"))
        .route("policies {\n timeout-secs #null\n}")
        .extra(
            "limits {\n max-connections-per-client #null\n}\n\
             agents {\n agent \"a\" {\n unix-socket path=\"/tmp/a.sock\"\n \
             timeout-ms #null\n failure-mode #null\n }\n}",
        );
    let config = doc.load().unwrap();

    let tls = config.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.min_version, TlsVersion::Tls12);
    assert!(!tls.client_auth);
    assert_eq!(config.routes[0].policies.timeout_secs, None);
    assert_eq!(config.limits.max_connections_per_client, None);
    let defaults = Doc::new()
        .extra("agents {\n agent \"a\" {\n unix-socket path=\"/tmp/a.sock\"\n }\n}")
        .load()
        .unwrap();
    assert_eq!(config.agents[0].timeout_ms, defaults.agents[0].timeout_ms);
}

#[test]
fn tls_insecure_alone_means_true_and_an_argument_is_read() {
    use crate::AgentTransport;

    let insecure = |line: &str| {
        let doc = Doc::new().extra(&format!(
            "agents {{\n agent \"a\" {{\n grpc \"localhost:50051\" {{\n{line}\n }}\n }}\n}}"
        ));
        let config = doc.load()?;
        match &config.agents[0].transport {
            AgentTransport::Grpc { tls, .. } => Ok::<bool, String>(
                tls.as_ref()
                    .expect("a tls setting makes a tls config")
                    .insecure_skip_verify,
            ),
            other => panic!("not a gRPC transport: {other:?}"),
        }
    };

    assert_eq!(insecure("tls-insecure"), Ok(true));
    assert_eq!(insecure("tls-insecure #true"), Ok(true));
    assert_eq!(insecure("tls-insecure #false"), Ok(false));
    assert!(insecure("tls-insecure \"false\"")
        .unwrap_err()
        .contains("Wrong value type for 'tls-insecure'"));
}

// ---------------------------------------------------------------------------
// Settings that take more than one type keep taking each of them
// ---------------------------------------------------------------------------

#[test]
fn a_health_check_status_is_read_as_a_number_or_as_a_string() {
    use zentinel_common::types::HealthCheckType;

    let status = |value: &str| {
        let doc = Doc::new().upstream(&format!(
            "health-check {{\n type \"http\" {{\n path \"/h\"\n expected-status {value}\n }}\n}}"
        ));
        let config = doc.load().map_err(|e| e.to_string())?;
        match &config.upstreams["u"]
            .health_check
            .as_ref()
            .unwrap()
            .check_type
        {
            HealthCheckType::Http {
                expected_status, ..
            } => Ok::<u16, String>(*expected_status),
            other => panic!("not an HTTP check: {other:?}"),
        }
    };

    assert_eq!(status("204"), Ok(204));
    assert_eq!(status("\"204\""), Ok(204));
    assert!(status("#true")
        .unwrap_err()
        .contains("Wrong value type for 'expected-status'"));
    assert!(status("\"fine\"")
        .unwrap_err()
        .contains("Wrong value type for 'expected-status'"));
}

#[test]
fn a_sticky_cookie_ttl_is_read_as_seconds_or_as_a_duration() {
    let ttl = |value: &str| {
        let doc = Doc::new().upstream(&format!(
            "load-balancing \"sticky\" {{\n cookie-ttl {value}\n}}"
        ));
        let config = doc.load()?;
        Ok::<u64, String>(
            config.upstreams["u"]
                .sticky_session
                .as_ref()
                .unwrap()
                .cookie_ttl_secs,
        )
    };

    assert_eq!(ttl("90"), Ok(90));
    assert_eq!(ttl("\"1h\""), Ok(3600));
    assert_eq!(ttl("\"30m\""), Ok(1800));
    assert_eq!(ttl("\"120\""), Ok(120));
    assert!(ttl("#true")
        .unwrap_err()
        .contains("Wrong value type for 'cookie-ttl'"));
    assert!(ttl("\"forever\"")
        .unwrap_err()
        .contains("Wrong value type for 'cookie-ttl'"));
}

#[test]
fn a_body_size_is_read_as_bytes_or_as_a_size() {
    let size = |value: &str| {
        let doc = Doc::new().route(&format!("policies {{\n max-body-size {value}\n}}"));
        let config = doc.load()?;
        Ok::<usize, String>(config.routes[0].policies.max_body_size.unwrap().0)
    };

    assert_eq!(size("2048"), Ok(2048));
    assert_eq!(size("\"2KB\""), Ok(2048));
    assert!(size("#true")
        .unwrap_err()
        .contains("Wrong value type for 'max-body-size'"));
    assert!(size("\"lots\"")
        .unwrap_err()
        .contains("Invalid max-body-size"));
}

#[test]
fn a_shadow_percentage_is_read_as_a_number_or_as_a_string() {
    let percentage = |value: &str| {
        let doc = Doc::new().route(&format!(
            "shadow {{\n upstream \"u\"\n percentage {value}\n}}"
        ));
        let config = doc.load()?;
        Ok::<f64, String>(config.routes[0].shadow.as_ref().unwrap().percentage)
    };

    assert_eq!(percentage("50"), Ok(50.0));
    assert_eq!(percentage("12.5"), Ok(12.5));
    assert_eq!(percentage("\"25\""), Ok(25.0));
    assert!(percentage("#true")
        .unwrap_err()
        .contains("Wrong value type for 'percentage'"));
    assert!(percentage("\"half\"")
        .unwrap_err()
        .contains("invalid value"));
}

#[test]
fn a_ratio_is_read_as_an_integer_or_as_a_fraction() {
    let ratio = |value: &str| {
        let doc = Doc::new().extra(&format!(
            "waf {{\n body-inspection {{\n max-decompression-ratio {value}\n }}\n}}"
        ));
        let config = doc.load()?;
        Ok::<f32, String>(config.waf.unwrap().body_inspection.max_decompression_ratio)
    };

    assert_eq!(ratio("50"), Ok(50.0));
    assert_eq!(ratio("2.5"), Ok(2.5));
    assert!(ratio("\"50\"")
        .unwrap_err()
        .contains("Wrong value type for 'max-decompression-ratio'"));
}

#[test]
fn a_route_priority_keeps_taking_a_number_or_a_name() {
    let priority = |value: &str| {
        let doc = Doc::new().route(&format!("priority {value}"));
        doc.load().map(|c| c.routes[0].priority.0)
    };

    assert_eq!(priority("7"), Ok(7));
    assert_eq!(
        priority("\"high\""),
        Ok(zentinel_common::types::Priority::HIGH.0)
    );
    // Not a priority: ignored with a message for `zentinel lint`, as before.
    assert_eq!(
        priority("1.5"),
        Ok(zentinel_common::types::Priority::NORMAL.0)
    );
}

// ---------------------------------------------------------------------------
// Values of the right type, and nodes that are not there, are read as before
// ---------------------------------------------------------------------------

#[test]
fn values_of_the_right_type_are_read() {
    let config = Doc::new()
        .listener(&https_listener(
            "min-version \"1.3\"\n client-auth #true\n ca-file \"/ca.pem\"",
        ))
        .route("policies {\n timeout-secs 30\n}")
        .extra("limits {\n max-connections-per-client 100\n}")
        .load()
        .unwrap();

    let tls = config.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.min_version, TlsVersion::Tls13);
    assert!(tls.client_auth);
    assert_eq!(config.routes[0].policies.timeout_secs, Some(30));
    assert_eq!(config.limits.max_connections_per_client, Some(100));
}

#[test]
fn settings_that_are_not_written_keep_their_defaults() {
    let config = Doc::new().listener(&https_listener("")).load().unwrap();

    let tls = config.listeners[0].tls.as_ref().unwrap();
    assert_eq!(tls.min_version, TlsVersion::Tls12);
    assert!(!tls.client_auth);
    assert_eq!(config.routes[0].policies.timeout_secs, None);
    assert_eq!(config.limits.max_connections_per_client, None);
}

// ---------------------------------------------------------------------------
// A `tls` block on a listener that does not serve TLS
// ---------------------------------------------------------------------------

#[test]
fn a_tls_block_on_a_listener_without_a_protocol_is_an_error() {
    let error = Doc::new()
        .listener(&format!("tls {{\n {TLS_FILES}\n}}"))
        .load()
        .map(|_| ())
        .unwrap_err();
    assert!(error.contains("Listener 'l'"), "unexpected error: {error}");
    assert!(
        error.contains("'tls' block") && error.contains("protocol \"http\""),
        "unexpected error: {error}"
    );
    assert!(
        error.contains("protocol \"https\""),
        "unexpected error: {error}"
    );
}

#[test]
fn a_tls_block_on_an_http_listener_is_an_error() {
    let error = Doc::new()
        .listener(&format!("protocol \"http\"\n tls {{\n {TLS_FILES}\n}}"))
        .load()
        .map(|_| ())
        .unwrap_err();
    assert!(error.contains("Listener 'l'"), "unexpected error: {error}");
    assert!(error.contains("'tls' block"), "unexpected error: {error}");
}

#[test]
fn a_tls_block_on_an_h2_listener_is_read() {
    let config = Doc::new()
        .listener(&format!("protocol \"h2\"\n tls {{\n {TLS_FILES}\n}}"))
        .load()
        .unwrap();
    assert_eq!(config.listeners[0].protocol, ListenerProtocol::Http2);
    assert!(config.listeners[0].tls.is_some());
}

#[test]
fn a_tls_block_on_an_https_listener_is_read() {
    let config = Doc::new().listener(&https_listener("")).load().unwrap();
    assert_eq!(config.listeners[0].protocol, ListenerProtocol::Https);
    assert!(config.listeners[0].tls.is_some());
}

#[test]
fn an_https_listener_without_a_tls_block_is_an_error() {
    let error = Doc::new()
        .listener("protocol \"https\"")
        .load()
        .map(|_| ())
        .unwrap_err();
    assert!(
        error.contains("needs a 'tls' block"),
        "unexpected error: {error}"
    );
}

#[test]
fn an_http_listener_without_a_tls_block_is_read() {
    let config = Doc::new().load().unwrap();
    assert_eq!(config.listeners[0].protocol, ListenerProtocol::Http);
    assert!(config.listeners[0].tls.is_none());
}

#[test]
fn a_service_listener_follows_the_same_rule() {
    let service = |listener_body: &str| {
        format!(
            "namespace \"ns\" {{\n service \"svc\" {{\n listener {{\n address \"127.0.0.1:8443\"\n\
             {listener_body}\n }}\n }}\n}}\n"
        )
    };
    let tls = format!("tls {{\n {TLS_FILES}\n}}");

    let good = Doc::new().extra(&service(&format!("protocol \"https\"\n{tls}")));
    good.load().unwrap();

    let bad = Doc::new().extra(&service(&tls));
    let error = bad.load().map(|_| ()).unwrap_err();
    assert!(error.contains("'tls' block"), "unexpected error: {error}");
}
