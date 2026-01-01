//! Default embedded configuration for Sentinel proxy
//!
//! This module provides the minimal default configuration that ships with
//! the binary. It is used when no configuration file is provided.
//!
//! The default configuration:
//! - Listens on port 8080 (HTTP) for the main service
//! - Listens on port 9090 for admin/health endpoints
//! - Returns JSON status at the root path
//! - Provides /health and /metrics endpoints

/// Embedded default configuration in KDL format
pub const DEFAULT_CONFIG_KDL: &str = r#"
// Sentinel Default Configuration
// This minimal config is used when no configuration file is provided.
// For production use, create a configuration file with your routes and upstreams.

server {
    worker-threads 0  // Auto-detect CPU cores
    max-connections 10000
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

    // Admin/health listener on separate port
    listener "admin" {
        address "0.0.0.0:9090"
        protocol "http"
        request-timeout-secs 5
        keepalive-timeout-secs 30
        default-route "health"
    }
}

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

    // Health check endpoint on admin port
    route "health" {
        priority "high"
        matches {
            path "/health"
            path "/healthz"
            path "/ready"
        }
        service-type "builtin"
        builtin-handler "health"
    }

    // Metrics endpoint on admin port
    route "metrics" {
        priority "high"
        matches {
            path "/metrics"
        }
        service-type "builtin"
        builtin-handler "metrics"
    }

    // Config dump endpoint on admin port
    route "config" {
        priority "high"
        matches {
            path "/admin/config"
            path "/config"
        }
        service-type "builtin"
        builtin-handler "config"
    }

    // Upstream health status endpoint on admin port
    route "upstreams" {
        priority "high"
        matches {
            path "/admin/upstreams"
            path "/upstreams"
        }
        service-type "builtin"
        builtin-handler "upstreams"
    }

    // Cache statistics endpoint on admin port
    route "cache-stats" {
        priority "high"
        matches {
            path "/admin/cache/stats"
            path "/cache/stats"
        }
        service-type "builtin"
        builtin-handler "cache-stats"
    }

    // Cache purge endpoint on admin port (PURGE method or POST)
    route "cache-purge" {
        priority "high"
        matches {
            path-prefix "/admin/cache/purge"
            path-prefix "/cache/purge"
        }
        service-type "builtin"
        builtin-handler "cache-purge"
    }
}

limits {
    max-header-size-bytes 8192
    max-header-count 100
    max-body-size-bytes 1048576  // 1MB default
    max-connections-per-client 100
}

// Observability uses defaults:
// - Metrics enabled at /metrics
// - JSON logging at info level
"#;

use crate::{
    BuiltinHandler, Config, GlobalRateLimitConfig, ListenerConfig, ListenerProtocol,
    MatchCondition, ObservabilityConfig, RouteConfig, RoutePolicies, ServerConfig, ServiceType,
};
use sentinel_common::{limits::Limits, types::Priority};
use std::collections::HashMap;

/// Create the default embedded configuration programmatically.
/// This serves as a fallback if KDL parsing fails for any reason.
pub fn create_default_config() -> Config {
    Config {
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
        },
        listeners: vec![
            ListenerConfig {
                id: "default-http".to_string(),
                address: "0.0.0.0:8080".to_string(),
                protocol: ListenerProtocol::Http,
                tls: None,
                default_route: Some("status".to_string()),
                request_timeout_secs: 60,
                keepalive_timeout_secs: 75,
                max_concurrent_streams: 100,
            },
            ListenerConfig {
                id: "admin".to_string(),
                address: "0.0.0.0:9090".to_string(),
                protocol: ListenerProtocol::Http,
                tls: None,
                default_route: Some("health".to_string()),
                request_timeout_secs: 5,
                keepalive_timeout_secs: 30,
                max_concurrent_streams: 100,
            },
        ],
        routes: vec![
            RouteConfig {
                id: "status".to_string(),
                priority: Priority::Low,
                matches: vec![MatchCondition::PathPrefix("/".to_string())],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::Status),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "health".to_string(),
                priority: Priority::High,
                matches: vec![
                    MatchCondition::Path("/health".to_string()),
                    MatchCondition::Path("/healthz".to_string()),
                    MatchCondition::Path("/ready".to_string()),
                ],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::Health),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "metrics".to_string(),
                priority: Priority::High,
                matches: vec![MatchCondition::Path("/metrics".to_string())],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::Metrics),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "config".to_string(),
                priority: Priority::High,
                matches: vec![
                    MatchCondition::Path("/admin/config".to_string()),
                    MatchCondition::Path("/config".to_string()),
                ],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::Config),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "upstreams".to_string(),
                priority: Priority::High,
                matches: vec![
                    MatchCondition::Path("/admin/upstreams".to_string()),
                    MatchCondition::Path("/upstreams".to_string()),
                ],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::Upstreams),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "cache-stats".to_string(),
                priority: Priority::High,
                matches: vec![
                    MatchCondition::Path("/admin/cache/stats".to_string()),
                    MatchCondition::Path("/cache/stats".to_string()),
                ],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::CacheStats),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
            RouteConfig {
                id: "cache-purge".to_string(),
                priority: Priority::High,
                matches: vec![
                    MatchCondition::PathPrefix("/admin/cache/purge".to_string()),
                    MatchCondition::PathPrefix("/cache/purge".to_string()),
                ],
                upstream: None,
                service_type: ServiceType::Builtin,
                policies: RoutePolicies::default(),
                filters: vec![],
                builtin_handler: Some(BuiltinHandler::CachePurge),
                waf_enabled: false,
                circuit_breaker: None,
                retry_policy: None,
                static_files: None,
                api_schema: None,
                error_pages: None,
                websocket: false,
                websocket_inspection: false,
            },
        ],
        upstreams: HashMap::new(),
        filters: HashMap::new(),
        agents: vec![],
        waf: None,
        limits: Limits::default(),
        observability: ObservabilityConfig::default(),
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
        assert_eq!(config.listeners.len(), 2);
        assert_eq!(config.routes.len(), 7);
        assert!(config.routes.iter().any(|r| r.id == "status"));
        assert!(config.routes.iter().any(|r| r.id == "health"));
        assert!(config.routes.iter().any(|r| r.id == "config"));
        assert!(config.routes.iter().any(|r| r.id == "upstreams"));
        assert!(config.routes.iter().any(|r| r.id == "cache-stats"));
        assert!(config.routes.iter().any(|r| r.id == "cache-purge"));
    }
}
