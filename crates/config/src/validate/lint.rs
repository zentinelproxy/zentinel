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

    result
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
            priority: Priority::Normal,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: None,
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            circuit_breaker: None,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            inference: None,
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
            connection_pool: ConnectionPoolConfig::default(),
            timeouts: UpstreamTimeouts::default(),
            tls: None,
            http_version: HttpVersionConfig::default(),
        }
    }

    fn test_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: None,
            default_route: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
        }
    }

    fn test_tls_listener_config(address: &str) -> ListenerConfig {
        ListenerConfig {
            id: "tls-test".to_string(),
            address: address.to_string(),
            protocol: crate::ListenerProtocol::Http,
            tls: Some(TlsConfig {
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
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
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
