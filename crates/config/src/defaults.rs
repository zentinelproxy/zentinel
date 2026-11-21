//! Default embedded configuration for Zentinel proxy
//!
//! This module provides the minimal default configuration that ships with
//! the binary. It is used when no configuration file is provided.
//!
//! The default configuration:
//! - Listens on `0.0.0.0:8080` (HTTP) for the main service, which answers
//!   every path with a JSON status page
//! - Listens on `127.0.0.1:9090` for the admin endpoints: `/metrics`, and the
//!   `/health`, `/healthz` and `/ready` probes
//!
//! Routes are not tied to a listener: a route written at the top level is
//! served on every listener that has no namespace of its own. The admin
//! routes are therefore declared in the `admin` namespace, whose listener
//! serves only that namespace's routes, and no other listener serves them.

/// Embedded default configuration in KDL format
pub const DEFAULT_CONFIG_KDL: &str = r#"
// Zentinel Default Configuration
// This minimal config is used when no configuration file is provided.
// For production use, create a configuration file with your routes and upstreams.

// Configuration schema version - used for compatibility checking
schema-version "1.0"

system {
    worker-threads 0  // Auto-detect CPU cores
    graceful-shutdown-timeout-secs 30
}

listeners {
    // Main HTTP listener
    listener "default-http" {
        address "0.0.0.0:8080"
        protocol "http"
        request-timeout-secs 60
        keepalive-timeout-secs 75
        default-route "status"
    }
}

// Routes written here are served on every listener that has no namespace of
// its own, which is the main listener only. The admin routes are in the
// "admin" namespace below.
routes {
    // JSON status page - catch-all for main listener
    route "status" {
        priority "low"
        matches {
            path-prefix "/"
        }
        service-type "builtin"
        builtin-handler "status"
    }
}

// Admin surface. A namespace with a listener of its own is served only on that
// listener, and that listener serves only the namespace's routes, so neither
// route below answers on the main listener. To reach them from another host,
// change the address.
namespace "admin" {
    listeners {
        listener "http" {
            address "127.0.0.1:9090"
            protocol "http"
            request-timeout-secs 5
            keepalive-timeout-secs 30
        }
    }

    routes {
        // Health probes. The conditions of a route must all hold, so the three
        // paths are one regex rather than three `path` lines.
        route "health" {
            priority "high"
            matches {
                path-regex "^/(health|healthz|ready)$"
            }
            service-type "builtin"
            builtin-handler "health"
        }

        // Metrics endpoint
        route "metrics" {
            priority "high"
            matches {
                path "/metrics"
            }
            service-type "builtin"
            builtin-handler "metrics"
        }
    }
}

limits {
    max-header-size 8192
    max-header-count 100
    max-body-size 10485760  // 10MB default
}

// Observability uses defaults:
// - Metrics enabled at /metrics
// - JSON logging at info level to stdout/stderr
//
// File logging is left disabled in the embedded default so `zentinel` with no
// config file starts cleanly for any user — writing to /var/log/zentinel
// requires a writable directory the process may not own. Enable the error/
// access/audit logs explicitly (and ensure the directory is writable) to get
// on-disk logs; the systemd unit provisions /var/log/zentinel via LogsDirectory.
observability {
    logging {
        error-log {
            enabled #false
        }
    }

    // The standalone metrics server is off here because this configuration
    // already serves /metrics from the admin listener above, via the builtin
    // "metrics" route. Both use 127.0.0.1:9090 (the metrics server's default
    // address), so turning it on makes the admin listener be ignored (`zentinel
    // test` reports it) and its routes answer nowhere.
    //
    // Turn it on when you want the scrape endpoint on a listener of its own,
    // separate from anything serving client traffic, and give it a port that no
    // listener uses.
    metrics {
        enabled #false
    }
}
"#;

use crate::{
    BuiltinHandler, Config, GlobalRateLimitConfig, ListenerConfig, ListenerProtocol,
    MatchCondition, NamespaceConfig, ObservabilityConfig, RouteConfig, RoutePolicies, ServerConfig,
    ServiceType,
};
use std::collections::HashMap;
use zentinel_common::{limits::Limits, types::Priority};

/// A builtin route with no upstream, filters or policies.
fn builtin_route(
    id: &str,
    priority: Priority,
    matches: Vec<MatchCondition>,
    handler: BuiltinHandler,
) -> RouteConfig {
    RouteConfig {
        id: id.to_string(),
        priority,
        matches,
        upstream: None,
        service_type: ServiceType::Builtin,
        policies: RoutePolicies::default(),
        filters: vec![],
        builtin_handler: Some(handler),
        waf_enabled: false,
        retry_policy: None,
        static_files: None,
        api_schema: None,
        inference: None,
        mcp: None,
        a2a: None,
        error_pages: None,
        websocket: false,
        websocket_inspection: false,
        shadow: None,
        fallback: None,
    }
}

/// Create the default embedded configuration programmatically.
/// This serves as a fallback if KDL parsing fails for any reason.
///
/// It describes the same listeners and routes as [`DEFAULT_CONFIG_KDL`]: the
/// admin routes belong to the `admin` namespace, whose listener is bound to
/// loopback and serves only them.
pub fn create_default_config() -> Config {
    // The standalone metrics server is off, as in the KDL: it would bind the
    // port of the admin listener, which serves `/metrics` itself.
    let mut observability = ObservabilityConfig::default();
    observability.metrics.enabled = false;

    let mut admin = NamespaceConfig::new("admin");
    admin.listeners = vec![ListenerConfig {
        service: None,
        id: "http".to_string(),
        address: "127.0.0.1:9090".to_string(),
        protocol: ListenerProtocol::Http,
        tls: None,
        default_route: None,
        namespace: None,
        request_timeout_secs: 5,
        keepalive_timeout_secs: 30,
        max_concurrent_streams: 100,
        keepalive_max_requests: None,
        trusted_proxies: Vec::new(),
    }];
    admin.routes = vec![
        builtin_route(
            "health",
            Priority::HIGH,
            vec![MatchCondition::PathRegex(
                "^/(health|healthz|ready)$".to_string(),
            )],
            BuiltinHandler::Health,
        ),
        builtin_route(
            "metrics",
            Priority::HIGH,
            vec![MatchCondition::Path("/metrics".to_string())],
            BuiltinHandler::Metrics,
        ),
    ];

    Config {
        scope_index: Default::default(),
        schema_version: crate::CURRENT_SCHEMA_VERSION.to_string(),
        server: ServerConfig {
            worker_threads: 0, // Auto-detect
            max_connections: 10000,
            graceful_shutdown_timeout_secs: 30,
            daemon: false,
            pid_file: None,
            user: None,
            group: None,
            working_directory: None,
            trace_id_format: Default::default(),
            auto_reload: false,
            route_cache_size: 1000,
        },
        listeners: vec![ListenerConfig {
            service: None,
            id: "default-http".to_string(),
            address: "0.0.0.0:8080".to_string(),
            protocol: ListenerProtocol::Http,
            tls: None,
            default_route: Some("status".to_string()),
            namespace: None,
            request_timeout_secs: 60,
            keepalive_timeout_secs: 75,
            max_concurrent_streams: 100,
            keepalive_max_requests: None,
            trusted_proxies: Vec::new(),
        }],
        routes: vec![builtin_route(
            "status",
            Priority::LOW,
            vec![MatchCondition::PathPrefix("/".to_string())],
            BuiltinHandler::Status,
        )],
        upstreams: HashMap::new(),
        filters: HashMap::new(),
        agents: vec![],
        waf: None,
        namespaces: vec![admin],
        limits: Limits::default(),
        observability,
        rate_limits: GlobalRateLimitConfig::default(),
        cache: None,
        default_upstream: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    #[test]
    fn test_default_config_kdl_parses() {
        let config = Config::from_kdl(DEFAULT_CONFIG_KDL);
        assert!(
            config.is_ok(),
            "Default KDL config should parse: {:?}",
            config.err()
        );
    }

    #[test]
    fn test_create_default_config() {
        let config = create_default_config();
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.routes.len(), 1);
        assert!(config.routes.iter().any(|r| r.id == "status"));

        assert_eq!(config.namespaces.len(), 1);
        let admin = &config.namespaces[0];
        assert_eq!(admin.id, "admin");
        assert_eq!(admin.listeners.len(), 1);
        assert_eq!(admin.routes.len(), 2);
        assert!(admin.routes.iter().any(|r| r.id == "health"));
        assert!(admin.routes.iter().any(|r| r.id == "metrics"));
    }

    /// Builtin handlers that report or change the state of the whole proxy,
    /// as opposed to answering a probe.
    const ADMIN_HANDLERS: [BuiltinHandler; 5] = [
        BuiltinHandler::Config,
        BuiltinHandler::Upstreams,
        BuiltinHandler::CacheStats,
        BuiltinHandler::CachePurge,
        BuiltinHandler::Metrics,
    ];

    fn is_loopback(address: &str) -> bool {
        address
            .parse::<std::net::SocketAddr>()
            .is_ok_and(|addr| addr.ip().is_loopback())
    }

    /// Each listener of `config`, lowered the way the proxy runs it, with the
    /// routes it serves.
    fn served(config: &Config) -> Vec<(ListenerConfig, Vec<RouteConfig>)> {
        let (lowered, problems) = config.lower_scopes_reporting();
        assert!(problems.is_empty(), "{problems:#?}");
        lowered
            .listeners
            .iter()
            .map(|listener| {
                (
                    listener.clone(),
                    lowered.routes_served_on(&listener.scope()),
                )
            })
            .collect()
    }

    fn defaults() -> [(&'static str, Config); 2] {
        [
            (
                "embedded KDL",
                Config::from_kdl(DEFAULT_CONFIG_KDL).expect("embedded default parses"),
            ),
            ("programmatic fallback", create_default_config()),
        ]
    }

    #[test]
    fn default_serves_admin_handlers_only_on_loopback() {
        for (name, config) in defaults() {
            let mut metrics_listeners = Vec::new();
            for (listener, routes) in served(&config) {
                let handlers = routes
                    .iter()
                    .filter_map(|route| route.builtin_handler)
                    .filter(|handler| ADMIN_HANDLERS.contains(handler));
                for handler in handlers {
                    assert!(
                        is_loopback(&listener.address),
                        "{name}: listener '{}' on {} serves the {handler:?} handler",
                        listener.id,
                        listener.address
                    );
                    if handler == BuiltinHandler::Metrics {
                        metrics_listeners.push(listener.address.clone());
                    }
                }
            }
            assert_eq!(metrics_listeners, ["127.0.0.1:9090"], "{name}");
        }
    }

    #[test]
    fn default_main_listener_serves_the_status_page_only() {
        for (name, config) in defaults() {
            let (main, routes) = served(&config)
                .into_iter()
                .find(|(listener, _)| listener.id == "default-http")
                .expect("the main listener is declared");
            assert_eq!(main.address, "0.0.0.0:8080", "{name}");
            let ids: Vec<&str> = routes.iter().map(|route| route.id.as_str()).collect();
            assert_eq!(ids, ["status"], "{name}");
        }
    }

    #[test]
    fn default_admin_listener_serves_metrics_and_health() {
        for (name, config) in defaults() {
            let (admin, routes) = served(&config)
                .into_iter()
                .find(|(listener, _)| listener.id == "admin:http")
                .expect("the admin listener is declared");
            assert_eq!(admin.address, "127.0.0.1:9090", "{name}");
            let mut ids: Vec<&str> = routes.iter().map(|route| route.id.as_str()).collect();
            ids.sort_unstable();
            assert_eq!(ids, ["admin:health", "admin:metrics"], "{name}");
        }
    }

    /// `matches` conditions other than `host` must all hold, so a route that
    /// lists two `path` conditions answers nothing. Every route of the
    /// defaults must be able to match.
    #[test]
    fn default_routes_have_at_most_one_path_condition() {
        for (name, config) in defaults() {
            let lowered = config.lower_scopes();
            for route in &lowered.routes {
                let paths = route
                    .matches
                    .iter()
                    .filter(|condition| {
                        matches!(
                            condition,
                            MatchCondition::Path(_)
                                | MatchCondition::PathPrefix(_)
                                | MatchCondition::PathRegex(_)
                        )
                    })
                    .count();
                assert!(
                    paths <= 1,
                    "{name}: route '{}' lists {paths} path conditions",
                    route.id
                );
            }
        }
    }

    #[test]
    fn programmatic_default_matches_embedded_default() {
        let summary = |config: &Config| {
            let mut listeners: Vec<String> = served(config)
                .into_iter()
                .map(|(listener, routes)| {
                    let mut routes: Vec<String> = routes
                        .into_iter()
                        .map(|route| format!("{} {:?}", route.id, route.matches))
                        .collect();
                    routes.sort();
                    format!("{} {} {routes:?}", listener.id, listener.address)
                })
                .collect();
            listeners.sort();
            listeners
        };
        let embedded = Config::from_kdl(DEFAULT_CONFIG_KDL).expect("embedded default parses");
        let fallback = create_default_config();
        assert_eq!(summary(&embedded), summary(&fallback));

        let (embedded, fallback) = (
            &embedded.observability.metrics,
            &fallback.observability.metrics,
        );
        assert_eq!(embedded.enabled, fallback.enabled);
        assert_eq!(embedded.address, fallback.address);
    }

    /// Guard the starter config dropped by the installer at
    /// /etc/zentinel/zentinel.kdl. Breaking its syntax breaks first-run UX
    /// for `curl | sh` users, so we parse and validate it in tests.
    #[test]
    fn test_starter_config_parses_and_validates() {
        const STARTER: &str = include_str!("../../../deploy/zentinel.starter.kdl");
        let config = Config::from_kdl(STARTER).expect("starter config must parse as valid KDL");
        config
            .validate()
            .expect("starter config must pass schema validation");
    }
}
