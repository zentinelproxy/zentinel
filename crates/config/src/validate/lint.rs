//! Configuration linting for best practices
//!
//! Checks configuration for missing best practices and potential issues.

use super::{ValidationResult, ValidationWarning};
use crate::filters::{Filter, HeadersFilter};
use crate::Config;

/// Lint configuration for best practices
pub fn lint_config(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Check routes for missing best practices
    for route in &config.routes {
        // Check for missing retry policy
        if route.retry_policy.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no retry policy (recommended for production)",
                route.id
            )));
        }

        // Check for missing timeout
        if route.policies.timeout_secs.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no timeout (recommended for production)",
                route.id
            )));
        }

        // Check for missing upstream (skip for static and builtin service types)
        use crate::routes::ServiceType;
        if route.upstream.is_none()
            && !matches!(
                route.service_type,
                ServiceType::Static | ServiceType::Builtin
            )
        {
            result.add_warning(ValidationWarning::new(format!(
                "Route '{}' has no upstream configured",
                route.id
            )));
        }
    }

    // Check upstreams for missing health checks
    for (name, upstream) in &config.upstreams {
        if upstream.health_check.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{}' has no health check (recommended for production)",
                name
            )));
        }

        // Check for single target without health check
        if upstream.targets.len() == 1 && upstream.health_check.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{}' has only one target and no health check (no failover possible)",
                name
            )));
        }
    }

    // Check listeners for security best practices
    let has_tls_listener = config.listeners.iter().any(|l| l.tls.is_some());

    for listener in &config.listeners {
        // Check for HTTP listener on standard port without redirect to HTTPS
        if listener.address.ends_with(":80") && listener.tls.is_none() {
            result.add_warning(ValidationWarning::new(format!(
                "Listener '{}' serves HTTP on port 80 without TLS (consider HTTPS redirect)",
                listener.address
            )));
        }
    }

    // Check for HSTS header when TLS is enabled
    if has_tls_listener {
        check_hsts_headers(config, &mut result);
    }

    // Check observability configuration
    if !config.observability.metrics.enabled {
        result.add_warning(ValidationWarning::new(
            "Metrics are disabled (recommended for production monitoring)".to_string(),
        ));
    }

    // Check for access logs
    if let Some(ref access_log) = config.observability.logging.access_log {
        if !access_log.enabled {
            result.add_warning(ValidationWarning::new(
                "Access logs are disabled (recommended for debugging and compliance)".to_string(),
            ));
        }
    }

    check_resource_bounds(config, &mut result);

    result
}

/// Bounds above which a limit is more likely a typo than a decision.
///
/// These are not enforcement thresholds. A lint asks a question; it does not
/// refuse the config. They sit far enough above realistic values that crossing
/// one usually means a unit was misread or a zero slipped in.
mod bound_thresholds {
    /// Roughly a file descriptor per connection, well past a default ulimit.
    pub const GENEROUS_MAX_CONNECTIONS: usize = 100_000;
    /// Per upstream target, not in total.
    pub const GENEROUS_UPSTREAM_CONNECTIONS: usize = 10_000;
    /// Each entry is a route ID keyed by method, host, path, and any matched
    /// headers and query parameters.
    pub const GENEROUS_ROUTE_CACHE: usize = 1_000_000;
    /// A buffered body is held in memory for the life of the request.
    pub const GENEROUS_BODY_SIZE: usize = 128 * 1024 * 1024;
    /// In-flight calls to a single agent.
    pub const GENEROUS_AGENT_CONCURRENCY: usize = 10_000;
}

/// Warn about resource limits that are missing, disabled, or generous enough
/// to be indistinguishable from unbounded.
///
/// The proxy should refuse traffic under load rather than grow until it is
/// killed. Most of that is enforced at runtime, and most of it already is;
/// what runtime enforcement cannot help with is a configuration that removes
/// the bound in the first place.
fn check_resource_bounds(config: &Config, result: &mut ValidationResult) {
    use bound_thresholds::*;

    if config.server.max_connections == 0 {
        result.add_warning(ValidationWarning::new(
            "server.max-connections is 0, which accepts connections without limit. \
             Set a value the host can actually serve, so the proxy refuses traffic \
             under load rather than growing until it is killed."
                .to_string(),
        ));
    } else if config.server.max_connections > GENEROUS_MAX_CONNECTIONS {
        result.add_warning(ValidationWarning::new(format!(
            "server.max-connections is {}, high enough that the file descriptor \
             limit will be reached first. Check `ulimit -n`.",
            config.server.max_connections
        )));
    }

    if config.server.route_cache_size > GENEROUS_ROUTE_CACHE {
        result.add_warning(ValidationWarning::new(format!(
            "server.route-cache-size is {}. Each entry is keyed by method, host, \
             path and any matched headers or query parameters, so a large cache on \
             varied traffic holds a lot of memory for little hit rate.",
            config.server.route_cache_size
        )));
    }

    for (name, upstream) in &config.upstreams {
        let pool = &upstream.connection_pool;

        if pool.max_connections == 0 {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{name}' has connection-pool max-connections 0, so the pool \
                 is unbounded. A slow upstream will accumulate connections until the \
                 process runs out of them."
            )));
        } else if pool.max_connections > GENEROUS_UPSTREAM_CONNECTIONS {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{name}' allows {} connections per target, more than most \
                 origins accept. The effective limit will be the origin's, and it \
                 will surface as errors rather than as backpressure.",
                pool.max_connections
            )));
        }

        if pool.max_connections > 0 && pool.max_idle > pool.max_connections {
            result.add_warning(ValidationWarning::new(format!(
                "Upstream '{name}' has max-idle ({}) greater than max-connections \
                 ({}), so the idle bound can never be reached.",
                pool.max_idle, pool.max_connections
            )));
        }
    }

    for route in &config.routes {
        let policies = &route.policies;

        // A rule for "buffers bodies but sets no max-body-size" used to live
        // here, keyed on `buffer_requests` / `buffer_responses`. It could never
        // fire — those fields had no KDL key and were read by nothing, so they
        // were always false for any config a person could write, and the rule's
        // tests passed only because they set the fields directly. #366 removed
        // the fields; if body buffering is ever implemented as real
        // configuration, this rule is worth restoring with it.
        if let Some(max_body) = policies.max_body_size {
            if max_body.0 > GENEROUS_BODY_SIZE {
                result.add_warning(ValidationWarning::new(format!(
                    "Route '{}' allows a {} byte body. With buffering enabled that is \
                     held in memory for each concurrent request.",
                    route.id, max_body.0
                )));
            }
        }
    }

    for agent in &config.agents {
        if agent.max_concurrent_calls == 0 {
            result.add_warning(ValidationWarning::new(format!(
                "Agent '{}' has max-concurrent-calls 0, so calls to it are unbounded. \
                 A slow agent will hold every in-flight request.",
                agent.id
            )));
        } else if agent.max_concurrent_calls > GENEROUS_AGENT_CONCURRENCY {
            result.add_warning(ValidationWarning::new(format!(
                "Agent '{}' allows {} concurrent calls, which is unlikely to be a \
                 limit the agent itself can honour.",
                agent.id, agent.max_concurrent_calls
            )));
        }
    }
}

/// HSTS header name (case-insensitive comparison should be used)
const HSTS_HEADER: &str = "Strict-Transport-Security";

/// Check for HSTS headers in route configurations and header filters
fn check_hsts_headers(config: &Config, result: &mut ValidationResult) {
    // Check if any route has HSTS in its response_headers
    let has_hsts_in_route_policies = config
        .routes
        .iter()
        .any(|route| route_has_hsts_header(&route.policies.response_headers));

    // Check if any headers filter sets HSTS
    let has_hsts_in_filter = config.filters.values().any(|filter_config| {
        if let Filter::Headers(headers_filter) = &filter_config.filter {
            headers_filter_has_hsts(headers_filter)
        } else {
            false
        }
    });

    // If TLS is enabled but no HSTS found, warn
    if !has_hsts_in_route_policies && !has_hsts_in_filter {
        result.add_warning(ValidationWarning::new(
            "TLS is enabled but no HSTS (Strict-Transport-Security) header is configured. \
             Consider adding HSTS to protect against protocol downgrade attacks and cookie hijacking. \
             Recommended value: 'max-age=31536000; includeSubDomains'".to_string(),
        ));
    }
}

/// Check if route header modifications contain HSTS
fn route_has_hsts_header(headers: &crate::HeaderModifications) -> bool {
    // Check 'set' headers (case-insensitive)
    let has_in_set = headers
        .set
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    // Check 'add' headers (case-insensitive)
    let has_in_add = headers
        .add
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    has_in_set || has_in_add
}

/// Check if a headers filter sets HSTS
fn headers_filter_has_hsts(filter: &HeadersFilter) -> bool {
    // Check 'set' headers (case-insensitive)
    let has_in_set = filter
        .set
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    // Check 'add' headers (case-insensitive)
    let has_in_add = filter
        .add
        .keys()
        .any(|k| k.eq_ignore_ascii_case(HSTS_HEADER));

    has_in_set || has_in_add
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::FilterConfig;
    use crate::{
        ConnectionPoolConfig, HttpVersionConfig, ListenerConfig, MatchCondition, RouteConfig,
        RoutePolicies, ServiceType, TlsConfig, UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use zentinel_common::types::{LoadBalancingAlgorithm, Priority, TlsVersion};

    fn test_route_config() -> RouteConfig {
        RouteConfig {
            id: "test".to_string(),
            priority: Priority::NORMAL,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: None,
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
            mcp: None,
            a2a: None,
            shadow: None,
            fallback: None,
        }
    }

    fn test_upstream_config() -> UpstreamConfig {
        UpstreamConfig {
            id: "test".to_string(),
            targets: vec![UpstreamTarget {
                address: "127.0.0.1:8080".to_string(),
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            }],
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            sticky_session: None,
            health_check: None,
            circuit_breaker: None,
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
            discovery: None,
        }
    }

    fn test_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: None,
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            trusted_proxies: Vec::new(),
        }
    }

    fn test_tls_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "tls-test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: Some(TlsConfig {
                cert_folders: Vec::new(),
                allow_sni_overlaps: false,
                cert_file: Some(PathBuf::from("/path/to/cert.pem")),
                key_file: Some(PathBuf::from("/path/to/key.pem")),
                additional_certs: vec![],
                ca_file: None,
                min_version: TlsVersion::Tls12,
                max_version: None,
                cipher_suites: vec![],
                client_auth: false,
                ocsp_stapling: true,
                session_resumption: true,
                acme: None,
            }),
            default_route: None,
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            trusted_proxies: Vec::new(),
        }
    }

    #[test]
    fn test_lint_missing_retry_policy() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_config()];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no retry policy")));
    }

    #[test]
    fn test_lint_missing_health_check() {
        let mut config = Config::default_for_testing();
        config
            .upstreams
            .insert("test".to_string(), test_upstream_config());

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("no health check")));
    }

    #[test]
    fn test_lint_http_on_port_80() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_listener_config("0.0.0.0:80")];

        let result = lint_config(&config);

        assert!(result
            .warnings
            .iter()
            .any(|w| w.message.contains("without TLS")));
    }

    #[test]
    fn test_lint_tls_without_hsts() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        let result = lint_config(&config);

        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.message.contains("HSTS")
                    && w.message.contains("Strict-Transport-Security"))
        );
    }

    #[test]
    fn test_lint_tls_with_hsts_in_route_policies() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add route with HSTS header in response_headers
        let mut route = test_route_config();
        route.policies.response_headers.set.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        );
        config.routes = vec![route];

        let result = lint_config(&config);

        // Should NOT warn about HSTS since it's configured
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when it's configured in route policies"
        );
    }

    #[test]
    fn test_lint_tls_with_hsts_in_filter() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add headers filter with HSTS
        let mut headers_filter = HeadersFilter::default();
        headers_filter.set.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        config.filters.insert(
            "hsts-filter".to_string(),
            FilterConfig::new("hsts-filter", Filter::Headers(headers_filter)),
        );

        let result = lint_config(&config);

        // Should NOT warn about HSTS since it's configured in filter
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when it's configured in headers filter"
        );
    }

    #[test]
    fn test_lint_hsts_case_insensitive() {
        let mut config = Config::default_for_testing();
        config.listeners = vec![test_tls_listener_config("0.0.0.0:443")];

        // Add route with lowercase HSTS header
        let mut route = test_route_config();
        route.policies.response_headers.set.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        config.routes = vec![route];

        let result = lint_config(&config);

        // Should NOT warn about HSTS (case-insensitive match)
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should detect HSTS header with case-insensitive matching"
        );
    }

    #[test]
    fn test_lint_no_hsts_warning_without_tls() {
        let mut config = Config::default_for_testing();
        // Only HTTP listener, no TLS
        config.listeners = vec![test_listener_config("0.0.0.0:8080")];

        let result = lint_config(&config);

        // Should NOT warn about HSTS when there's no TLS listener
        assert!(
            !result.warnings.iter().any(|w| w.message.contains("HSTS")),
            "Should not warn about HSTS when there's no TLS listener"
        );
    }
}

#[cfg(test)]
mod resource_bound_tests {
    use super::*;
    use crate::Config;
    use zentinel_common::types::ByteSize;

    fn warnings(config: &Config) -> Vec<String> {
        lint_config(config)
            .warnings
            .iter()
            .map(|w| w.message.clone())
            .collect()
    }

    fn mentions(config: &Config, needle: &str) -> bool {
        warnings(config).iter().any(|w| w.contains(needle))
    }

    /// A limit of zero reads as "no limit", which is the one value that turns a
    /// bound into its opposite.
    #[test]
    fn a_zero_connection_limit_is_reported() {
        let mut config = Config::default_for_testing();
        config.server.max_connections = 0;
        assert!(mentions(&config, "server.max-connections is 0"));
    }

    #[test]
    fn an_implausibly_large_connection_limit_is_reported() {
        let mut config = Config::default_for_testing();
        config.server.max_connections = 5_000_000;
        assert!(mentions(&config, "file descriptor"));
    }

    /// The defaults must be quiet. A lint that fires on a stock config gets
    /// switched off, and then it protects nothing.
    #[test]
    fn a_default_config_produces_no_resource_bound_warnings() {
        let config = Config::default_for_testing();
        let bound_warnings: Vec<_> = warnings(&config)
            .into_iter()
            .filter(|w| {
                w.contains("max-connections")
                    || w.contains("route-cache-size")
                    || w.contains("max-body-size")
                    || w.contains("max-concurrent-calls")
                    || w.contains("max-idle")
            })
            .collect();
        assert!(
            bound_warnings.is_empty(),
            "defaults should not trip the bounds lint: {bound_warnings:?}"
        );
    }

    #[test]
    fn an_unbounded_upstream_pool_is_reported() {
        let mut config = Config::default_for_testing();
        for upstream in config.upstreams.values_mut() {
            upstream.connection_pool.max_connections = 0;
        }
        assert!(mentions(&config, "connection-pool max-connections 0"));
    }

    /// An idle bound above the total is unreachable, so it reads as configured
    /// while doing nothing.
    #[test]
    fn an_unreachable_idle_bound_is_reported() {
        let mut config = Config::default_for_testing();
        for upstream in config.upstreams.values_mut() {
            upstream.connection_pool.max_connections = 10;
            upstream.connection_pool.max_idle = 100;
        }
        assert!(mentions(&config, "can never be reached"));
    }

    /// #366 removed `buffer_requests` / `buffer_responses`, so the guard test
    /// that asserted they stayed unreachable no longer has fields to assert on.
    /// What replaces it is the unknown-key check: with the keys gone from
    /// `CLOSED_BLOCKS`, writing one in a `policies` block is now reported
    /// rather than silently accepted.
    #[test]
    fn buffering_keys_are_reported_rather_than_silently_accepted() {
        let mut result = ValidationResult::new();
        crate::validate::unknown_keys::check_unknown_keys(
            "routes {\n  route \"r\" {\n    policies {\n      buffer-requests #true\n    }\n  }\n}\n",
            &mut result,
        );

        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.message.contains("buffer-requests")),
            "expected 'buffer-requests' to be reported as an unknown key, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn a_very_large_body_limit_is_reported() {
        let mut config = Config::default_for_testing();
        for route in &mut config.routes {
            route.policies.max_body_size = Some(ByteSize::from_mb(512));
        }
        assert!(mentions(&config, "held in memory"));
    }

    #[test]
    fn an_oversized_route_cache_is_reported() {
        let mut config = Config::default_for_testing();
        config.server.route_cache_size = 50_000_000;
        assert!(mentions(&config, "route-cache-size"));
    }
}
