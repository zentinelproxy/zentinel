//! Agent connectivity validation
//!
//! Validates that agent sockets are reachable and agent configurations are valid.

use std::path::Path;

use super::{ErrorCategory, ValidationError, ValidationResult, ValidationWarning};
use crate::agents::AgentTransport;
use crate::filters::Filter;
use crate::Config;

/// Validate agent connectivity
pub async fn validate_agents(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    // Collect unique filter names from all routes
    let mut filter_names = std::collections::HashSet::new();
    for route in &config.routes {
        for filter_name in &route.filters {
            filter_names.insert(filter_name.clone());
        }
    }

    // Check if each filter exists in config
    for filter_name in &filter_names {
        let Some(filter_config) = config.filters.get(filter_name) else {
            result.add_error(ValidationError::new(
                ErrorCategory::Agent,
                format!(
                    "Filter '{}' referenced in route but not defined",
                    filter_name
                ),
            ));
            continue;
        };

        // For agent filters, validate the referenced agent and check connectivity
        if let Filter::Agent(agent_filter) = &filter_config.filter {
            let agent_id = &agent_filter.agent;

            // Find the agent configuration
            let Some(agent_config) = config.agents.iter().find(|a| &a.id == agent_id) else {
                result.add_error(ValidationError::new(
                    ErrorCategory::Agent,
                    format!(
                        "Filter '{}' references agent '{}' which is not defined",
                        filter_name, agent_id
                    ),
                ));
                continue;
            };

            // Validate transport connectivity based on transport type
            match &agent_config.transport {
                AgentTransport::UnixSocket { path } => {
                    validate_unix_socket(&mut result, agent_id, path);
                }
                AgentTransport::Grpc { address, .. } => {
                    validate_grpc_address(&mut result, agent_id, address);
                }
                AgentTransport::Http { url, .. } => {
                    validate_http_url(&mut result, agent_id, url);
                }
            }
        }
    }

    // Also validate all agents directly (even if not referenced by filters)
    for agent_config in &config.agents {
        match &agent_config.transport {
            AgentTransport::UnixSocket { path } => {
                // Only warn for unreferenced agents with missing sockets
                if !path.exists() {
                    let is_referenced = config.filters.values().any(|f| {
                        if let Filter::Agent(af) = &f.filter {
                            af.agent == agent_config.id
                        } else {
                            false
                        }
                    });
                    if !is_referenced {
                        result.add_warning(ValidationWarning::new(format!(
                            "Agent '{}' socket path '{}' does not exist (agent not referenced by any filter)",
                            agent_config.id,
                            path.display()
                        )));
                    }
                }
            }
            AgentTransport::Grpc { address, .. } => {
                // Validate address format even for unreferenced agents
                if !is_valid_grpc_address(address) {
                    result.add_warning(ValidationWarning::new(format!(
                        "Agent '{}' has invalid gRPC address format: '{}'",
                        agent_config.id, address
                    )));
                }
            }
            AgentTransport::Http { url, .. } => {
                // Validate URL format even for unreferenced agents
                if !is_valid_http_url(url) {
                    result.add_warning(ValidationWarning::new(format!(
                        "Agent '{}' has invalid HTTP URL format: '{}'",
                        agent_config.id, url
                    )));
                }
            }
        }
    }

    result
}

/// Validate Unix socket connectivity
fn validate_unix_socket(result: &mut ValidationResult, agent_id: &str, path: &Path) {
    if !path.exists() {
        result.add_error(ValidationError::new(
            ErrorCategory::Agent,
            format!(
                "Agent '{}' socket path '{}' does not exist",
                agent_id,
                path.display()
            ),
        ));
    } else if !is_socket_file(path) {
        result.add_error(ValidationError::new(
            ErrorCategory::Agent,
            format!(
                "Agent '{}' path '{}' exists but is not a socket",
                agent_id,
                path.display()
            ),
        ));
    }
}

/// Check if a path is a Unix socket
fn is_socket_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        path.metadata()
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // On non-Unix platforms, we can't check if it's a socket
        // Just assume it's valid if the path exists
        let _ = path;
        true
    }
}

/// Validate gRPC address format
fn validate_grpc_address(result: &mut ValidationResult, agent_id: &str, address: &str) {
    if !is_valid_grpc_address(address) {
        result.add_error(ValidationError::new(
            ErrorCategory::Agent,
            format!(
                "Agent '{}' has invalid gRPC address: '{}'. Expected format: 'http://host:port' or 'https://host:port'",
                agent_id, address
            ),
        ));
    }
}

/// Check if a gRPC address is valid
fn is_valid_grpc_address(address: &str) -> bool {
    // gRPC addresses should be valid HTTP(S) URLs
    if let Ok(url) = url::Url::parse(address) {
        matches!(url.scheme(), "http" | "https") && url.host().is_some()
    } else {
        false
    }
}

/// Validate HTTP URL format
fn validate_http_url(result: &mut ValidationResult, agent_id: &str, url_str: &str) {
    if !is_valid_http_url(url_str) {
        result.add_error(ValidationError::new(
            ErrorCategory::Agent,
            format!(
                "Agent '{}' has invalid HTTP URL: '{}'. Expected format: 'http://host:port/path' or 'https://host:port/path'",
                agent_id, url_str
            ),
        ));
    }
}

/// Check if an HTTP URL is valid
fn is_valid_http_url(url_str: &str) -> bool {
    if let Ok(url) = url::Url::parse(url_str) {
        matches!(url.scheme(), "http" | "https") && url.host().is_some()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{AgentConfig, AgentEvent, AgentType};
    use crate::filters::{AgentFilter, FilterConfig};
    use crate::{MatchCondition, RouteConfig, RoutePolicies, ServiceType};
    use std::path::PathBuf;
    use zentinel_common::types::Priority;

    fn test_route_with_filter(filter: &str) -> RouteConfig {
        RouteConfig {
            id: "test".to_string(),
            priority: Priority::Normal,
            matches: vec![MatchCondition::PathPrefix("/".to_string())],
            upstream: None,
            service_type: ServiceType::Web,
            policies: RoutePolicies::default(),
            filters: vec![filter.to_string()],
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

    fn test_agent_config(id: &str, transport: AgentTransport) -> AgentConfig {
        AgentConfig {
            id: id.to_string(),
            agent_type: AgentType::Custom("test".to_string()),
            transport,
            events: vec![AgentEvent::RequestHeaders],
            protocol_version: Default::default(),
            pool: None,
            timeout_ms: 1000,
            failure_mode: crate::FailureMode::default(),
            circuit_breaker: None,
            max_request_body_bytes: None,
            max_response_body_bytes: None,
            request_body_mode: Default::default(),
            response_body_mode: Default::default(),
            chunk_timeout_ms: 5000,
            config: None,
            max_concurrent_calls: 100,
        }
    }

    #[tokio::test]
    async fn test_validate_missing_filter() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("nonexistent-filter")];

        let result = validate_agents(&config).await;

        // Should have an error about undefined filter
        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("not defined")));
    }

    #[tokio::test]
    async fn test_validate_agent_filter_missing_agent() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("auth-filter")];
        config.filters.insert(
            "auth-filter".to_string(),
            FilterConfig::new(
                "auth-filter",
                Filter::Agent(AgentFilter::new("nonexistent-agent")),
            ),
        );

        let result = validate_agents(&config).await;

        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("nonexistent-agent") && e.message.contains("not defined")));
    }

    #[tokio::test]
    async fn test_validate_unix_socket_missing() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("auth-filter")];
        config.filters.insert(
            "auth-filter".to_string(),
            FilterConfig::new("auth-filter", Filter::Agent(AgentFilter::new("auth-agent"))),
        );
        config.agents.push(test_agent_config(
            "auth-agent",
            AgentTransport::UnixSocket {
                path: PathBuf::from("/nonexistent/path/to/socket.sock"),
            },
        ));

        let result = validate_agents(&config).await;

        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("does not exist")));
    }

    #[tokio::test]
    async fn test_validate_grpc_invalid_address() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("grpc-filter")];
        config.filters.insert(
            "grpc-filter".to_string(),
            FilterConfig::new("grpc-filter", Filter::Agent(AgentFilter::new("grpc-agent"))),
        );
        config.agents.push(test_agent_config(
            "grpc-agent",
            AgentTransport::Grpc {
                address: "invalid-address".to_string(),
                tls: None,
            },
        ));

        let result = validate_agents(&config).await;

        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("invalid gRPC address")));
    }

    #[tokio::test]
    async fn test_validate_grpc_valid_address() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("grpc-filter")];
        config.filters.insert(
            "grpc-filter".to_string(),
            FilterConfig::new("grpc-filter", Filter::Agent(AgentFilter::new("grpc-agent"))),
        );
        config.agents.push(test_agent_config(
            "grpc-agent",
            AgentTransport::Grpc {
                address: "http://localhost:50051".to_string(),
                tls: None,
            },
        ));

        let result = validate_agents(&config).await;

        // Should have no errors (address format is valid)
        assert!(
            result.errors.is_empty(),
            "Expected no errors but got: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_validate_http_invalid_url() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("http-filter")];
        config.filters.insert(
            "http-filter".to_string(),
            FilterConfig::new("http-filter", Filter::Agent(AgentFilter::new("http-agent"))),
        );
        config.agents.push(test_agent_config(
            "http-agent",
            AgentTransport::Http {
                url: "not-a-valid-url".to_string(),
                tls: None,
            },
        ));

        let result = validate_agents(&config).await;

        assert!(!result.errors.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.message.contains("invalid HTTP URL")));
    }

    #[tokio::test]
    async fn test_validate_http_valid_url() {
        let mut config = Config::default_for_testing();
        config.routes = vec![test_route_with_filter("http-filter")];
        config.filters.insert(
            "http-filter".to_string(),
            FilterConfig::new("http-filter", Filter::Agent(AgentFilter::new("http-agent"))),
        );
        config.agents.push(test_agent_config(
            "http-agent",
            AgentTransport::Http {
                url: "http://localhost:8080/agent".to_string(),
                tls: None,
            },
        ));

        let result = validate_agents(&config).await;

        // Should have no errors (URL format is valid)
        assert!(
            result.errors.is_empty(),
            "Expected no errors but got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_is_valid_grpc_address() {
        // Valid addresses
        assert!(is_valid_grpc_address("http://localhost:50051"));
        assert!(is_valid_grpc_address("https://agent.example.com:443"));
        assert!(is_valid_grpc_address("http://192.168.1.100:50051"));

        // Invalid addresses
        assert!(!is_valid_grpc_address("localhost:50051")); // Missing scheme
        assert!(!is_valid_grpc_address("invalid"));
        assert!(!is_valid_grpc_address("ftp://localhost:21")); // Wrong scheme
    }

    #[test]
    fn test_is_valid_http_url() {
        // Valid URLs
        assert!(is_valid_http_url("http://localhost:8080/agent"));
        assert!(is_valid_http_url(
            "https://agent.example.com/api/v1/process"
        ));
        assert!(is_valid_http_url("http://192.168.1.100:8080"));

        // Invalid URLs
        assert!(!is_valid_http_url("localhost:8080/agent")); // Missing scheme
        assert!(!is_valid_http_url("not-a-url"));
        assert!(!is_valid_http_url("ftp://files.example.com")); // Wrong scheme
    }
}
