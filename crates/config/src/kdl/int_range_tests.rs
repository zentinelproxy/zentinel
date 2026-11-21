//! An integer outside the range a setting takes is an error, not a wrapped value.
//!
//! A count, a duration or a port is read as a KDL integer and stored in a
//! narrower type. `default-ttl-secs -1` used to be stored as `u64::MAX`, and
//! `port 70000` as `4464`. Each case writes a setting with a value just outside
//! the range of its type, and the same document with a value inside it. The
//! control must load; the other must not, and the error must name the setting,
//! the value, the range, and where.

use crate::Config;

/// Where in the document a case places its line.
#[derive(Clone, Copy, Debug)]
enum Ctx {
    /// Directly inside `system { ... }`.
    System,
    /// Directly inside `listener "l" { address "127.0.0.1:8080" ... }`.
    Listener,
    /// Directly inside `upstream "u" { target "127.0.0.1:9000" ... }`.
    Upstream,
    /// Inside `upstream "u" { connection-pool { ... } }`.
    ConnectionPool,
    /// Inside `upstream "u" { timeouts { ... } }`.
    UpstreamTimeouts,
    /// Inside `upstream "u" { http-version { ... } }`.
    HttpVersion,
    /// Inside `upstream "u" { health-check { ... } }`.
    HealthCheck,
    /// Inside `upstream "u" { health-check { type "http" { ... } } }`.
    HttpHealthCheck,
    /// Directly inside `route "r" { matches { path "/" } upstream "u" ... }`.
    Route,
    /// Inside `route "r" { policies { ... } }`.
    Policies,
    /// Inside `route "r" { cache { ... } }`.
    RouteCache,
    /// Inside `route "r" { fallback { upstream "u" ... } }`.
    Fallback,
    /// Inside `route "r" { fallback { triggers { ... } } }`.
    FallbackTriggers,
    /// Inside `route "r" { inference { ... } }`.
    Inference,
    /// Inside the first guardrail of `route "r" { inference { guardrails { ... } } }`.
    Guardrail,
    /// Inside `filter "f" { type "rate-limit" ... }`.
    RateLimitFilter,
    /// Inside `filter "f" { type "redirect" hostname "a.example" ... }`.
    RedirectFilter,
    /// Inside `filter "f" { type "geo" database-path "/g.mmdb" ... }`.
    GeoFilter,
    /// Inside `filter "f" { type "agent" agent "a" ... }`.
    AgentFilter,
    /// Inside `filter "f" { type "timeout" ... }`.
    TimeoutFilter,
    /// Inside `filter "f" { type "compress" ... }`.
    CompressFilter,
    /// Inside `filter "f" { type "log" ... }`.
    LogFilter,
    /// Directly inside `agent "a" { unix-socket path="/tmp/a.sock" ... }`.
    Agent,
    /// Directly inside the top-level `limits { ... }`.
    Limits,
    /// Directly inside the top-level `cache { ... }`.
    TopCache,
    /// Directly inside the top-level `rate-limits { ... }`.
    RateLimits,
    /// Inside the top-level `waf { ruleset { ... } }`.
    WafRuleset,
    /// Inside `service "s" { listener "sl" { address "127.0.0.1:8081" ... } }`.
    ServiceListener,
    /// Inside the `acme` block of an HTTPS listener's `tls` block.
    Acme,
    /// Inside the `dns-provider` block of an `acme` block.
    DnsProvider,
    /// Inside the `propagation` block of a `dns-provider` block.
    Propagation,
    /// Inside the `sni-certs` block of an HTTPS listener's `tls` block.
    SniCerts,
    /// Inside `observability { logging { access-log { ... } } }`.
    AccessLog,
    /// Inside `observability { logging { error-log { ... } } }`.
    ErrorLog,
    /// Inside `observability { logging { audit-log { ... } } }`.
    AuditLog,
    /// Inside `waf { body-inspection { ... } }`.
    WafBodyInspection,
    /// Inside `route "r" { shadow { upstream "u" ... } }`.
    Shadow,
    /// Inside the inference probe of an inference health check's readiness settings.
    InferenceProbe,
    /// Inside the model status of an inference health check's readiness settings.
    ModelStatus,
    /// Inside the queue depth of an inference health check's readiness settings.
    QueueDepth,
    /// Inside the warmth detection of an inference health check's readiness settings.
    WarmthDetection,
    /// Inside `upstream "u" { discovery "dns" { ... } }`.
    DiscoveryDns,
    /// Inside `upstream "u" { discovery "file" { ... } }`.
    DiscoveryFile,
    /// Inside the free-form `config` block of an agent.
    AgentConfig,
}

/// The settings an `acme` block needs, apart from the one a case writes.
const ACME: &str = " email \"a@example.com\"\n domains \"a.example\"";

/// The whole document, with `inner` placed in `ctx`.
fn document(ctx: Ctx, inner: &str) -> String {
    let mut system = "worker-threads 1".to_string();
    let mut listener = String::new();
    let mut upstream = String::new();
    let mut route = String::new();
    let mut filter = "filter \"f\" {\n type \"cors\"\n}".to_string();
    let mut agent = "agent \"a\" {\n unix-socket path=\"/tmp/a.sock\"\n}".to_string();
    let mut extra = String::new();

    let https_listener = |tls_body: &str| {
        format!(
            "protocol \"https\"\n tls {{\n cert-file \"/c.pem\"\n key-file \"/k.pem\"\n{tls_body}\n}}"
        )
    };
    let logging = |log: &str| format!("observability {{\n logging {{\n{log}\n}}\n}}");
    let readiness = |probe: &str| {
        format!("health-check {{\n type \"inference\" {{\n readiness {{\n{probe}\n}}\n}}\n}}")
    };

    match ctx {
        Ctx::System => system = inner.to_string(),
        Ctx::Listener => listener = inner.to_string(),
        Ctx::Upstream => upstream = inner.to_string(),
        Ctx::ConnectionPool => upstream = format!("connection-pool {{\n{inner}\n}}"),
        Ctx::UpstreamTimeouts => upstream = format!("timeouts {{\n{inner}\n}}"),
        Ctx::HttpVersion => upstream = format!("http-version {{\n{inner}\n}}"),
        Ctx::HealthCheck => upstream = format!("health-check {{\n{inner}\n}}"),
        Ctx::HttpHealthCheck => {
            upstream = format!("health-check {{\n type \"http\" {{\n{inner}\n}}\n}}")
        }
        Ctx::Route => route = inner.to_string(),
        Ctx::Policies => route = format!("policies {{\n{inner}\n}}"),
        Ctx::RouteCache => route = format!("cache {{\n{inner}\n}}"),
        Ctx::Fallback => route = format!("fallback {{\n upstream \"u\"\n{inner}\n}}"),
        Ctx::FallbackTriggers => {
            route = format!("fallback {{\n upstream \"u\"\n triggers {{\n{inner}\n}}\n}}")
        }
        Ctx::Inference => route = format!("inference {{\n{inner}\n}}"),
        Ctx::Guardrail => {
            route = format!(
            "inference {{\n guardrails {{\n prompt-injection {{\n agent \"a\"\n{inner}\n}}\n}}\n}}"
        )
        }
        Ctx::RateLimitFilter => {
            filter = format!("filter \"f\" {{\n type \"rate-limit\"\n{inner}\n}}")
        }
        Ctx::RedirectFilter => {
            filter =
                format!("filter \"f\" {{\n type \"redirect\"\n hostname \"a.example\"\n{inner}\n}}")
        }
        Ctx::GeoFilter => {
            filter =
                format!("filter \"f\" {{\n type \"geo\"\n database-path \"/g.mmdb\"\n{inner}\n}}")
        }
        Ctx::AgentFilter => {
            filter = format!("filter \"f\" {{\n type \"agent\"\n agent \"a\"\n{inner}\n}}")
        }
        Ctx::TimeoutFilter => filter = format!("filter \"f\" {{\n type \"timeout\"\n{inner}\n}}"),
        Ctx::CompressFilter => filter = format!("filter \"f\" {{\n type \"compress\"\n{inner}\n}}"),
        Ctx::LogFilter => filter = format!("filter \"f\" {{\n type \"log\"\n{inner}\n}}"),
        Ctx::Agent => {
            agent = format!("agent \"a\" {{\n unix-socket path=\"/tmp/a.sock\"\n{inner}\n}}")
        }
        Ctx::Limits => extra = format!("limits {{\n{inner}\n}}"),
        Ctx::TopCache => extra = format!("cache {{\n{inner}\n}}"),
        Ctx::RateLimits => extra = format!("rate-limits {{\n{inner}\n}}"),
        Ctx::WafRuleset => extra = format!("waf {{\n ruleset {{\n{inner}\n}}\n}}"),
        Ctx::Acme => listener = https_listener(&format!("acme {{\n{ACME}\n{inner}\n}}")),
        Ctx::DnsProvider => {
            listener = https_listener(&format!(
                "acme {{\n{ACME}\n challenge-type \"dns-01\"\n dns-provider {{\n type \"cloudflare\"\n credentials-env \"T\"\n{inner}\n}}\n}}"
            ))
        }
        Ctx::Propagation => {
            listener = https_listener(&format!(
                "acme {{\n{ACME}\n challenge-type \"dns-01\"\n dns-provider {{\n type \"cloudflare\"\n credentials-env \"T\"\n \
                 propagation {{\n{inner}\n}}\n}}\n}}"
            ))
        }
        Ctx::SniCerts => {
            listener = https_listener(&format!(
                "sni-certs {{\n cert-folder \"/certs\"\n reload-mode \"interval\"\n{inner}\n}}"
            ))
        }
        Ctx::AccessLog => extra = logging(&format!("access-log {{\n{inner}\n}}")),
        Ctx::ErrorLog => extra = logging(&format!("error-log {{\n{inner}\n}}")),
        Ctx::AuditLog => extra = logging(&format!("audit-log {{\n{inner}\n}}")),
        Ctx::WafBodyInspection => extra = format!("waf {{\n body-inspection {{\n{inner}\n}}\n}}"),
        Ctx::Shadow => route = format!("shadow {{\n upstream \"u\"\n{inner}\n}}"),
        Ctx::InferenceProbe => upstream = readiness(&format!("inference-probe {{\n{inner}\n}}")),
        Ctx::ModelStatus => upstream = readiness(&format!("model-status {{\n{inner}\n}}")),
        Ctx::QueueDepth => upstream = readiness(&format!("queue-depth {{\n{inner}\n}}")),
        Ctx::WarmthDetection => {
            upstream = readiness(&format!("warmth-detection {{\n{inner}\n}}"))
        }
        Ctx::DiscoveryDns => {
            upstream = format!("discovery \"dns\" {{\n hostname \"a.example\"\n port 8080\n{inner}\n}}")
        }
        Ctx::DiscoveryFile => {
            upstream = format!("discovery \"file\" {{\n path \"/u.txt\"\n{inner}\n}}")
        }
        Ctx::AgentConfig => {
            agent = format!("agent \"a\" {{\n unix-socket path=\"/tmp/a.sock\"\n config {{\n{inner}\n}}\n}}")
        }
        Ctx::ServiceListener => {
            extra = format!(
                "namespace \"ns\" {{\n service \"s\" {{\n listener \"sl\" {{\n \
                 address \"127.0.0.1:8081\"\n{inner}\n}}\n}}\n}}"
            )
        }
    }

    format!(
        "system {{\n{system}\n}}\n\
         listeners {{\n listener \"l\" {{\n address \"127.0.0.1:8080\"\n{listener}\n }}\n}}\n\
         upstreams {{\n upstream \"u\" {{\n target \"127.0.0.1:9000\"\n{upstream}\n }}\n}}\n\
         filters {{\n{filter}\n}}\nagents {{\n{agent}\n}}\n\
         routes {{\n route \"r\" {{\n matches {{\n path \"/\"\n }}\n upstream \"u\"\n{route}\n }}\n}}\n\
         {extra}\n"
    )
}

/// Load a document, with the error text on failure.
fn load(kdl: &str) -> Result<Config, String> {
    Config::from_kdl(kdl).map_err(|e| format!("{e:#}"))
}

/// `line` with the value filled in.
fn with_value(line: &str, value: impl std::fmt::Display) -> String {
    line.replace("{}", &value.to_string())
}

/// The setting that `line` writes the value of, as the error names it: the
/// property when the value is written as `name={}`, else the node on the last
/// line that holds the value.
fn setting_of(line: &str) -> &str {
    let last = line
        .lines()
        .rfind(|l| l.contains("{}"))
        .unwrap_or(line)
        .trim();
    let before = last.split("{}").next().unwrap_or(last);
    match before.strip_suffix('=') {
        Some(property) => property.rsplit(' ').next().unwrap_or(property),
        None => last.split_whitespace().next().unwrap_or(last),
    }
}

/// `line` with `control` as its value must load; with `value` it must not, and
/// the error must say that the setting was written with `value`, outside `min`
/// to `max`. Returns the error.
#[track_caller]
fn assert_out_of_range(
    ctx: Ctx,
    line: &str,
    control: &str,
    value: i128,
    min: i128,
    max: i128,
) -> String {
    let good = document(ctx, &with_value(line, control));
    if let Err(e) = load(&good) {
        panic!("{ctx:?}: the control `{line}` with {control} should load, got: {e}\n{good}");
    }
    let bad = document(ctx, &with_value(line, value));
    let error = match load(&bad) {
        Ok(_) => panic!("{ctx:?}: `{line}` with {value} was accepted\n{bad}"),
        Err(e) => e,
    };
    let want = format!("Value out of range for '{}'", setting_of(line));
    assert!(
        error.contains(&want),
        "{ctx:?}: expected `{want}` in: {error}"
    );
    let range = format!("{value} is not between {min} and {max}.");
    assert!(
        error.contains(&range),
        "{ctx:?}: expected `{range}` in: {error}"
    );
    error
}

/// A setting that is stored in an unsigned type, whose range is `0..=max`.
struct Unsigned {
    ctx: Ctx,
    /// The setting as written, with `{}` where its value goes.
    line: &'static str,
    /// A value that the setting takes and its document is valid with.
    control: &'static str,
    max: i128,
}

const U64: i128 = u64::MAX as i128;
const U32: i128 = u32::MAX as i128;
const U16: i128 = u16::MAX as i128;
const U8: i128 = u8::MAX as i128;
/// The tests run where `usize` is 64 bits wide; the range follows its width.
const USIZE: i128 = usize::MAX as i128;

const fn unsigned(ctx: Ctx, line: &'static str, control: &'static str, max: i128) -> Unsigned {
    Unsigned {
        ctx,
        line,
        control,
        max,
    }
}

/// Settings read as an unsigned integer, one or more from every parser that
/// narrows one.
fn unsigned_settings() -> Vec<Unsigned> {
    vec![
        // u64
        unsigned(Ctx::System, "graceful-shutdown-timeout-secs {}", "30", U64),
        unsigned(Ctx::Listener, "request-timeout-secs {}", "30", U64),
        unsigned(Ctx::Listener, "keepalive-timeout-secs {}", "30", U64),
        unsigned(Ctx::ServiceListener, "request-timeout-secs {}", "30", U64),
        unsigned(Ctx::ServiceListener, "keepalive-timeout-secs {}", "30", U64),
        unsigned(Ctx::ConnectionPool, "idle-timeout-secs {}", "30", U64),
        unsigned(Ctx::ConnectionPool, "idle-timeout {}", "30", U64),
        unsigned(Ctx::ConnectionPool, "max-lifetime-secs {}", "30", U64),
        unsigned(Ctx::UpstreamTimeouts, "connect-secs {}", "5", U64),
        unsigned(Ctx::UpstreamTimeouts, "request {}", "5", U64),
        unsigned(Ctx::HttpVersion, "h2-ping-interval {}", "30", U64),
        unsigned(Ctx::HealthCheck, "interval-secs {}", "10", U64),
        unsigned(Ctx::HealthCheck, "timeout-secs {}", "5", U64),
        unsigned(Ctx::Policies, "timeout-secs {}", "30", U64),
        unsigned(Ctx::RouteCache, "default-ttl-secs {}", "60", U64),
        unsigned(Ctx::Agent, "timeout-ms {}", "1000", U64),
        unsigned(Ctx::Agent, "connect-timeout-ms {}", "1000", U64),
        unsigned(Ctx::Agent, "chunk-timeout-ms {}", "1000", U64),
        unsigned(
            Ctx::FallbackTriggers,
            "on-latency-threshold-ms {}",
            "500",
            U64,
        ),
        unsigned(
            Ctx::Inference,
            "rate-limit {\n tokens-per-minute {}\n}",
            "1000",
            U64,
        ),
        unsigned(
            Ctx::Inference,
            "budget {\n period \"daily\"\n limit {}\n}",
            "1000",
            U64,
        ),
        unsigned(Ctx::Guardrail, "timeout-ms {}", "500", U64),
        unsigned(Ctx::RateLimitFilter, "max-delay-ms {}", "100", U64),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"redis\"\n redis-timeout-ms {}",
            "50",
            U64,
        ),
        unsigned(Ctx::TimeoutFilter, "request-timeout-secs {}", "30", U64),
        unsigned(Ctx::TimeoutFilter, "connect-timeout-secs {}", "30", U64),
        unsigned(Ctx::GeoFilter, "cache-ttl-secs {}", "60", U64),
        unsigned(Ctx::TopCache, "lock-timeout {}", "10", U64),
        unsigned(Ctx::TopCache, "lock-timeout-secs {}", "10", U64),
        unsigned(Ctx::DnsProvider, "api-timeout-secs {}", "30", U64),
        unsigned(Ctx::Propagation, "initial-delay-secs {}", "10", U64),
        unsigned(Ctx::Propagation, "check-interval-secs {}", "5", U64),
        unsigned(Ctx::Propagation, "timeout-secs {}", "120", U64),
        unsigned(Ctx::InferenceProbe, "timeout-secs {}", "30", U64),
        unsigned(Ctx::InferenceProbe, "max-latency-ms {}", "1000", U64),
        unsigned(Ctx::ModelStatus, "timeout-secs {}", "5", U64),
        unsigned(Ctx::QueueDepth, "degraded-threshold {}", "50", U64),
        unsigned(Ctx::QueueDepth, "unhealthy-threshold {}", "200", U64),
        unsigned(Ctx::QueueDepth, "timeout-secs {}", "5", U64),
        unsigned(
            Ctx::WarmthDetection,
            "idle-cold-timeout-secs {}",
            "300",
            U64,
        ),
        unsigned(Ctx::Shadow, "timeout-ms {}", "5000", U64),
        unsigned(
            Ctx::Inference,
            "rate-limit {\n tokens-per-minute 1000\n requests-per-minute {}\n}",
            "500",
            U64,
        ),
        unsigned(
            Ctx::Inference,
            "rate-limit {\n tokens-per-minute 1000\n burst-tokens {}\n}",
            "500",
            U64,
        ),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"memcached\"\n memcached-timeout-ms {}",
            "50",
            U64,
        ),
        unsigned(Ctx::TimeoutFilter, "upstream-timeout-secs {}", "30", U64),
        // u32
        unsigned(Ctx::Acme, "renew-before-days {}", "30", U32),
        unsigned(Ctx::InferenceProbe, "max-tokens {}", "1", U32),
        unsigned(Ctx::WarmthDetection, "sample-size {}", "10", U32),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"memcached\"\n memcached-pool-size {}",
            "10",
            U32,
        ),
        unsigned(Ctx::Listener, "max-concurrent-streams {}", "100", U32),
        unsigned(Ctx::Listener, "keepalive-max-requests {}", "100", U32),
        unsigned(
            Ctx::ServiceListener,
            "max-concurrent-streams {}",
            "100",
            U32,
        ),
        unsigned(
            Ctx::ServiceListener,
            "keepalive-max-requests {}",
            "100",
            U32,
        ),
        unsigned(
            Ctx::Upstream,
            "target \"127.0.0.1:9001\" weight={}",
            "2",
            U32,
        ),
        unsigned(
            Ctx::Upstream,
            "target \"127.0.0.1:9001\" {\n weight {}\n}",
            "2",
            U32,
        ),
        unsigned(Ctx::HealthCheck, "healthy-threshold {}", "2", U32),
        unsigned(Ctx::HealthCheck, "unhealthy-threshold {}", "3", U32),
        unsigned(
            Ctx::Policies,
            "rate-limit {\n requests-per-second {}\n}",
            "10",
            U32,
        ),
        unsigned(Ctx::RouteCache, "stale-while-revalidate-secs {}", "60", U32),
        unsigned(Ctx::RouteCache, "stale-if-error-secs {}", "300", U32),
        unsigned(Ctx::Fallback, "max-attempts {}", "3", U32),
        unsigned(Ctx::RateLimitFilter, "max-rps {}", "100", U32),
        unsigned(Ctx::RateLimitFilter, "burst {}", "10", U32),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"redis\"\n redis-pool-size {}",
            "10",
            U32,
        ),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"memcached\"\n memcached-ttl-secs {}",
            "2",
            U32,
        ),
        unsigned(
            Ctx::RateLimitFilter,
            "backend \"memcached\"\n memcached-ttl {}",
            "2",
            U32,
        ),
        unsigned(Ctx::RateLimits, "default-rps {}", "100", U32),
        unsigned(Ctx::RateLimits, "default-burst {}", "10", U32),
        unsigned(Ctx::RateLimits, "global {\n max-rps {}\n}", "100", U32),
        unsigned(Ctx::TopCache, "disk-shards {}", "16", U32),
        unsigned(Ctx::WafRuleset, "anomaly-threshold {}", "5", U32),
        // u16
        unsigned(Ctx::RedirectFilter, "port {}", "8443", U16),
        // u8
        unsigned(Ctx::HttpVersion, "min-version {}", "1", U8),
        unsigned(Ctx::HttpVersion, "max-version {}", "2", U8),
        unsigned(Ctx::WafRuleset, "paranoia-level {}", "2", U8),
        // usize
        unsigned(Ctx::AccessLog, "buffer-size {}", "8192", USIZE),
        unsigned(Ctx::ErrorLog, "buffer-size {}", "8192", USIZE),
        unsigned(Ctx::AuditLog, "buffer-size {}", "8192", USIZE),
        unsigned(
            Ctx::WafBodyInspection,
            "max-inspection-bytes {}",
            "1048576",
            USIZE,
        ),
        unsigned(Ctx::Shadow, "max-body-bytes {}", "1048576", USIZE),
        unsigned(
            Ctx::Inference,
            "budget {\n period \"daily\"\n limit 1000\n max-tenants {}\n}",
            "100",
            USIZE,
        ),
        unsigned(Ctx::System, "worker-threads {}", "1", USIZE),
        unsigned(Ctx::System, "max-connections {}", "100", USIZE),
        unsigned(Ctx::System, "route-cache-size {}", "100", USIZE),
        unsigned(Ctx::Limits, "max-header-size {}", "8192", USIZE),
        unsigned(Ctx::Limits, "max-header-count {}", "100", USIZE),
        unsigned(Ctx::Limits, "max-connections-per-client {}", "100", USIZE),
        unsigned(Ctx::Limits, "max-total-connections {}", "100", USIZE),
        unsigned(Ctx::Limits, "max-in-flight-requests {}", "100", USIZE),
        unsigned(Ctx::ConnectionPool, "max-connections {}", "100", USIZE),
        unsigned(Ctx::ConnectionPool, "max-idle {}", "20", USIZE),
        unsigned(Ctx::HttpVersion, "max-h2-streams {}", "100", USIZE),
        unsigned(Ctx::TopCache, "max-size {}", "1048576", USIZE),
        unsigned(Ctx::TopCache, "max-size-bytes {}", "1048576", USIZE),
        unsigned(Ctx::TopCache, "eviction-limit {}", "1048576", USIZE),
        unsigned(Ctx::TopCache, "disk-max-size {}", "1048576", USIZE),
        unsigned(Ctx::RouteCache, "max-size-bytes {}", "1048576", USIZE),
        unsigned(Ctx::Agent, "max-request-body-bytes {}", "1048576", USIZE),
        unsigned(Ctx::Agent, "max-response-body-bytes {}", "1048576", USIZE),
        unsigned(Ctx::Agent, "max-concurrent-calls {}", "10", USIZE),
        unsigned(Ctx::Policies, "max-body-size {}", "1048576", USIZE),
        unsigned(Ctx::CompressFilter, "min-size {}", "1024", USIZE),
        unsigned(Ctx::LogFilter, "max-body-log-size {}", "4096", USIZE),
        unsigned(Ctx::RateLimitFilter, "max-keys {}", "1000", USIZE),
    ]
}

#[test]
fn the_documents_of_the_cases_load_with_a_value_inside_the_range() {
    for case in unsigned_settings() {
        let kdl = document(case.ctx, &with_value(case.line, case.control));
        load(&kdl).unwrap_or_else(|e| {
            panic!(
                "{:?}: `{}` with {} should load, got: {e}\n{kdl}",
                case.ctx, case.line, case.control
            )
        });
    }
    for (ctx, line, control) in status_settings() {
        let kdl = document(ctx, &with_value(line, control));
        load(&kdl).unwrap_or_else(|e| {
            panic!("{ctx:?}: `{line}` with {control} should load, got: {e}\n{kdl}")
        });
    }
}

#[test]
fn a_negative_value_for_an_unsigned_setting_is_an_error() {
    for case in unsigned_settings() {
        assert_out_of_range(case.ctx, case.line, case.control, -1, 0, case.max);
    }
}

#[test]
fn a_value_one_above_the_range_of_the_type_is_an_error() {
    for case in unsigned_settings() {
        assert_out_of_range(case.ctx, case.line, case.control, case.max + 1, 0, case.max);
    }
}

#[test]
fn a_very_large_integer_is_an_error_not_a_truncated_value() {
    // 2^100: its low 64 bits are zero, so a truncating cast reads it as 0.
    let huge: i128 = 1 << 100;
    for case in unsigned_settings() {
        assert_out_of_range(case.ctx, case.line, case.control, huge, 0, case.max);
    }
}

#[test]
fn the_largest_value_of_the_type_loads_unchanged() {
    let cache = |line: &str, value: i128| {
        let kdl = document(Ctx::RouteCache, &with_value(line, value));
        load(&kdl).unwrap_or_else(|e| panic!("{line} {value} should load, got: {e}\n{kdl}"))
    };

    let config = cache("default-ttl-secs {}", U64);
    assert_eq!(
        config.routes[0]
            .policies
            .cache
            .as_ref()
            .map(|c| c.default_ttl_secs),
        Some(u64::MAX)
    );

    let config = cache("stale-while-revalidate-secs {}", U32);
    assert_eq!(
        config.routes[0]
            .policies
            .cache
            .as_ref()
            .map(|c| c.stale_while_revalidate_secs),
        Some(u64::from(u32::MAX))
    );

    let config = cache("stale-if-error-secs {}", U32);
    assert_eq!(
        config.routes[0]
            .policies
            .cache
            .as_ref()
            .map(|c| c.stale_if_error_secs),
        Some(u64::from(u32::MAX))
    );

    let kdl = document(Ctx::RedirectFilter, "port 65535");
    let config = load(&kdl).expect("port 65535 loads");
    let redirect = config
        .filters
        .values()
        .find_map(|f| match &f.filter {
            crate::Filter::Redirect(redirect) => Some(redirect.port),
            _ => None,
        })
        .expect("the redirect filter is in the document");
    assert_eq!(redirect, Some(65535));
}

#[test]
fn a_zero_for_a_setting_that_took_it_still_loads() {
    // Ranges are the type's own: a zero that loaded before still does, and its
    // meaning is left to the setting's own checks.
    for line in [
        "default-ttl-secs {}",
        "stale-while-revalidate-secs {}",
        "stale-if-error-secs {}",
    ] {
        let kdl = document(Ctx::RouteCache, &with_value(line, 0));
        load(&kdl).unwrap_or_else(|e| panic!("`{line}` with 0 should load, got: {e}\n{kdl}"));
    }
}

// ---------------------------------------------------------------------------
// HTTP status codes
// ---------------------------------------------------------------------------

/// A setting that holds one HTTP status code, written as `line`.
fn status_settings() -> Vec<(Ctx, &'static str, &'static str)> {
    vec![
        (Ctx::RateLimitFilter, "status-code {}", "429"),
        (Ctx::GeoFilter, "status-code {}", "403"),
        (Ctx::RedirectFilter, "status-code {}", "301"),
        (Ctx::Guardrail, "block-status {}", "400"),
        (Ctx::RouteCache, "cacheable-status-codes 200 {}", "404"),
        (Ctx::FallbackTriggers, "on-error-codes 502 {}", "503"),
        (Ctx::HttpHealthCheck, "expected-status {}", "200"),
        (Ctx::HttpHealthCheck, "expected-status \"{}\"", "200"),
    ]
}

#[test]
fn a_status_code_outside_100_to_599_is_an_error() {
    for (ctx, line, control) in status_settings() {
        for value in [-1, 0, 99, 600, 700, 999, 1000, 65535, 65536, 70000] {
            let error = assert_out_of_range(ctx, line, control, value, 100, 599);
            assert!(
                error.contains(&value.to_string()),
                "{ctx:?}: the error should show the value {value}, got: {error}"
            );
        }
    }
}

#[test]
fn the_ends_of_the_status_code_range_load() {
    for (ctx, line, _) in status_settings() {
        for value in [100, 599] {
            let kdl = document(ctx, &with_value(line, value));
            load(&kdl).unwrap_or_else(|e| {
                panic!("{ctx:?}: `{line}` with {value} should load, got: {e}\n{kdl}")
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Signed settings, and the ones that are not a plain integer node
// ---------------------------------------------------------------------------

#[test]
fn a_priority_outside_the_range_of_i32_is_an_error() {
    for value in [i128::from(i32::MIN) - 1, i128::from(i32::MAX) + 1, 1 << 100] {
        assert_out_of_range(
            Ctx::Route,
            "priority {}",
            "100",
            value,
            i128::from(i32::MIN),
            i128::from(i32::MAX),
        );
    }
    for value in [i32::MIN, -1, 0, i32::MAX] {
        let kdl = document(Ctx::Route, &format!("priority {value}"));
        load(&kdl).unwrap_or_else(|e| panic!("priority {value} should load, got: {e}"));
    }
}

#[test]
fn a_sticky_cookie_ttl_that_is_negative_or_too_large_is_an_error() {
    let sticky = |ttl: &str| {
        document(
            Ctx::Upstream,
            &format!("load-balancing \"sticky\" {{\n cookie-ttl {ttl}\n}}"),
        )
    };
    load(&sticky("3600")).expect("a TTL in seconds loads");
    load(&sticky("\"1h\"")).expect("a TTL as a duration loads");
    for ttl in [
        "-1",
        "18446744073709551616",
        "\"-1h\"",
        "\"99999999999999999999999d\"",
    ] {
        let error = load(&sticky(ttl)).expect_err(&format!("cookie-ttl {ttl} was accepted"));
        assert!(
            error.contains("cookie-ttl"),
            "expected the setting in: {error}"
        );
    }
}

#[test]
fn a_max_body_size_that_is_negative_is_an_error() {
    let route = |value: &str| document(Ctx::Policies, &format!("max-body-size {value}"));
    load(&route("1024")).expect("a byte count loads");
    load(&route("\"10MB\"")).expect("a size string loads");
    let error = load(&route("-1")).expect_err("a negative size was accepted");
    assert!(error.contains("max-body-size"), "{error}");
}

#[test]
fn a_negative_agent_connect_timeout_is_an_error_not_zero() {
    let error = load(&document(Ctx::Agent, "connect-timeout-ms -5"))
        .expect_err("a negative connect timeout was accepted");
    assert!(error.contains("connect-timeout-ms"), "{error}");
    assert!(error.contains("-5 is not between 0 and"), "{error}");
}

#[test]
fn an_agent_filter_limit_too_large_for_its_type_is_an_error() {
    assert_out_of_range(Ctx::AgentFilter, "timeout-ms {}", "500", U64 + 1, 0, U64);
    assert_out_of_range(
        Ctx::AgentFilter,
        "max-body-bytes {}",
        "1024",
        USIZE + 1,
        0,
        USIZE,
    );
}

#[test]
fn an_agent_filter_limit_that_is_not_positive_is_still_ignored() {
    // Zero and negative values are reported and left out, as before: the
    // agent's own limits apply.
    for line in ["timeout-ms {}", "max-body-bytes {}"] {
        for value in [0, -1] {
            let kdl = document(Ctx::AgentFilter, &with_value(line, value));
            load(&kdl)
                .unwrap_or_else(|e| panic!("`{line}` with {value} should load, got: {e}\n{kdl}"));
        }
    }
}

// ---------------------------------------------------------------------------
// The message
// ---------------------------------------------------------------------------

#[test]
fn the_error_says_where_the_setting_is() {
    let error = load(&document(Ctx::RouteCache, "default-ttl-secs -1"))
        .expect_err("a negative TTL was accepted");
    assert!(
        error.contains(
            "Value out of range for 'default-ttl-secs' in routes > route \"r\" > cache: \
             -1 is not between 0 and 18446744073709551615."
        ),
        "{error}"
    );
}

#[test]
fn a_node_with_a_wrong_type_is_still_reported_as_a_wrong_type() {
    let error = load(&document(Ctx::RouteCache, "default-ttl-secs \"60\""))
        .expect_err("a string was accepted");
    assert!(
        error.contains("Wrong value type for 'default-ttl-secs'"),
        "{error}"
    );
}

#[test]
fn integers_inside_their_range_are_read_as_written() {
    let kdl = document(
        Ctx::Listener,
        "request-timeout-secs 45\n max-concurrent-streams 250\n keepalive-max-requests 1000",
    );
    let config = load(&kdl).expect("loads");
    let listener = &config.listeners[0];
    assert_eq!(listener.request_timeout_secs, 45);
    assert_eq!(listener.max_concurrent_streams, 250);
    assert_eq!(listener.keepalive_max_requests, Some(1000));
}

#[test]
fn a_stale_period_longer_than_u32_is_an_error_whatever_u64_would_hold() {
    for line in ["stale-while-revalidate-secs {}", "stale-if-error-secs {}"] {
        for value in [U32 + 1, 1 << 40, U64] {
            assert_out_of_range(Ctx::RouteCache, line, "60", value, 0, U32);
        }
    }
}

// ---------------------------------------------------------------------------
// Integers in an agent's free-form `config` block
// ---------------------------------------------------------------------------

/// The `config` block of the agent in a document that loads.
fn agent_config(inner: &str) -> serde_json::Value {
    let kdl = document(Ctx::AgentConfig, inner);
    let config = load(&kdl).unwrap_or_else(|e| panic!("should load, got: {e}\n{kdl}"));
    config.agents[0]
        .config
        .clone()
        .expect("the agent has a config block")
}

#[test]
fn an_integer_in_an_agent_config_takes_i64_min_to_u64_max() {
    let config = agent_config(
        "largest 18446744073709551615\n smallest -9223372036854775808\n small 5\n \
         negative -5\n listed 1 -2 18446744073709551615",
    );
    assert_eq!(config["largest"].as_u64(), Some(u64::MAX));
    assert_eq!(config["smallest"].as_i64(), Some(i64::MIN));
    assert_eq!(config["small"].as_i64(), Some(5));
    assert_eq!(config["negative"].as_i64(), Some(-5));
    assert_eq!(config["listed"][1].as_i64(), Some(-2));
    assert_eq!(config["listed"][2].as_u64(), Some(u64::MAX));
    // The largest value is a positive number; it was one already, which is why
    // it must not turn negative.
    assert!(config["largest"].as_i64().is_none());
}

#[test]
fn an_integer_in_an_agent_config_outside_that_range_is_an_error() {
    let (min, max) = (i128::from(i64::MIN), i128::from(u64::MAX));
    for (written, setting) in [
        ("limit 18446744073709551616", "limit"),
        ("limit -9223372036854775809", "limit"),
        ("limit 1 18446744073709551616", "limit"),
        ("entry max=18446744073709551616", "max"),
        ("entry min=-9223372036854775809", "min"),
    ] {
        let kdl = document(Ctx::AgentConfig, written);
        let error = load(&kdl).expect_err(&format!("`{written}` was accepted"));
        assert!(
            error.contains(&format!("Value out of range for '{setting}'")),
            "`{written}`: {error}"
        );
        assert!(
            error.contains(&format!("is not between {min} and {max}.")),
            "`{written}`: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// Durations written as strings
// ---------------------------------------------------------------------------

use super::upstreams::parse_duration_string;

#[test]
fn a_duration_string_reads_as_before() {
    for (text, secs) in [
        ("30s", 30),
        ("30sec", 30),
        ("5m", 300),
        ("2 hours", 7200),
        ("1.5h", 5400),
        ("1d", 86400),
        ("0s", 0),
        ("0.5s", 0),
        (" 10m ", 600),
        // A negative zero is not below zero.
        ("-0s", 0),
        ("4294967296s", 4_294_967_296),
    ] {
        assert_eq!(parse_duration_string(text), Some(secs), "{text:?}");
    }
}

#[test]
fn a_duration_string_that_is_not_one_is_none_as_before() {
    for text in ["", "30", "5x", "s", "abc", "1e3s", "NaNs", "infs"] {
        assert_eq!(parse_duration_string(text), None, "{text:?}");
    }
}

#[test]
fn a_negative_or_uncountable_duration_string_is_none() {
    for text in [
        "-1s",
        "-1h",
        "-0.5m",
        "-1d",
        // A `u64` of seconds counts up to 18446744073709551615.
        "18446744073709551616s",
        "99999999999999999999999d",
        "9999999999999999999999999999999999999999h",
    ] {
        assert_eq!(parse_duration_string(text), None, "{text:?}");
    }
}

#[test]
fn a_certificate_folder_reload_interval_that_is_not_a_duration_is_an_error() {
    let load_with = |text: &str| {
        load(&document(
            Ctx::SniCerts,
            &format!("reload-interval \"{text}\""),
        ))
    };
    for text in ["30s", "5m", "1.5h"] {
        load_with(text).unwrap_or_else(|e| panic!("{text}: should load, got: {e}"));
    }
    for text in ["-1h", "-1s", "99999999999999999999999d", "soon"] {
        let error = load_with(text).expect_err(&format!("{text} was accepted"));
        assert!(
            error.contains(&format!("invalid reload-interval '{text}'")),
            "{text}: {error}"
        );
    }
}

#[test]
fn a_retry_policy_duration_that_is_negative_or_too_long_is_an_error() {
    for (key, good) in [
        ("backoff", "50ms"),
        ("max-backoff", "10s"),
        ("per-attempt-timeout", "10s"),
    ] {
        let with = |text: &str| {
            load(&document(
                Ctx::Route,
                &format!("retry-policy {{\n {key} \"{text}\"\n}}"),
            ))
        };
        with(good).unwrap_or_else(|e| panic!("{key} {good}: should load, got: {e}"));
        for text in ["-1s", "99999999999999999999999m"] {
            let error = with(text).expect_err(&format!("{key} {text} was accepted"));
            assert!(
                error.contains(&format!("{key} has an invalid duration")),
                "{key} {text}: {error}"
            );
        }
    }
}

#[test]
fn a_sticky_cookie_ttl_string_that_is_negative_is_reported_as_the_wrong_value() {
    let kdl = document(
        Ctx::Upstream,
        "load-balancing \"sticky\" {\n cookie-ttl \"-1h\"\n}",
    );
    let error = load(&kdl).expect_err("a negative duration was accepted");
    assert!(
        error.contains("Wrong value type for 'cookie-ttl'")
            && error.contains("a duration string such as \"1h\", found a string."),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// Discovery intervals
// ---------------------------------------------------------------------------

#[test]
fn a_discovery_interval_keeps_its_zero_check_and_takes_a_u64() {
    for (ctx, key) in [
        (Ctx::DiscoveryDns, "refresh-interval"),
        (Ctx::DiscoveryFile, "watch-interval"),
    ] {
        let with = |value: &str| load(&document(ctx, &format!("{key} {value}")));
        with("30").unwrap_or_else(|e| panic!("{key} 30: should load, got: {e}"));
        with("18446744073709551615")
            .unwrap_or_else(|e| panic!("{key} u64::MAX: should load, got: {e}"));
        for value in ["0", "-1"] {
            let error = with(value).expect_err(&format!("{key} {value} was accepted"));
            assert!(
                error.contains(&format!("'{key}' must be greater than zero (got {value})")),
                "{key} {value}: {error}"
            );
        }
        let error = with("18446744073709551616").expect_err("a value above u64 was accepted");
        assert!(
            error.contains(&format!("Value out of range for '{key}'")),
            "{key}: {error}"
        );
    }
}
