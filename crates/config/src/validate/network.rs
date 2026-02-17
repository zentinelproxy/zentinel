//! Network connectivity validation
//!
//! Validates that upstream targets are reachable.

use super::{ErrorCategory, ValidationError, ValidationResult, ValidationWarning};
use crate::Config;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Validate upstream connectivity
pub async fn validate_upstreams(config: &Config) -> ValidationResult {
    let mut result = ValidationResult::new();

    for (name, upstream) in &config.upstreams {
        for target in &upstream.targets {
            // Try to connect to upstream with timeout
            match timeout(Duration::from_secs(5), TcpStream::connect(&target.address)).await {
                Ok(Ok(_)) => {
                    // Connection successful
                }
                Ok(Err(e)) => {
                    result.add_error(ValidationError::new(
                        ErrorCategory::Network,
                        format!(
                            "Upstream '{}' target '{}' unreachable: {}",
                            name, target.address, e
                        ),
                    ));
                }
                Err(_) => {
                    result.add_warning(ValidationWarning::new(format!(
                        "Upstream '{}' target '{}' connection timeout (5s)",
                        name, target.address
                    )));
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ConnectionPoolConfig, HttpVersionConfig, UpstreamConfig, UpstreamTarget, UpstreamTimeouts,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_validate_upstreams_unreachable() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "test".to_string(),
            UpstreamConfig {
                id: "test".to_string(),
                targets: vec![UpstreamTarget {
                    address: "192.0.2.1:9999".to_string(), // TEST-NET-1 (unreachable)
                    weight: 1,
                    max_requests: None,
                    metadata: std::collections::HashMap::new(),
                }],
                load_balancing: zentinel_common::types::LoadBalancingAlgorithm::RoundRobin,
                sticky_session: None,
                health_check: None,
                connection_pool: ConnectionPoolConfig::default(),
                timeouts: UpstreamTimeouts::default(),
                tls: None,
                http_version: HttpVersionConfig::default(),
            },
        );

        let mut config = Config::default_for_testing();
        config.upstreams = upstreams;

        let result = validate_upstreams(&config).await;

        // Should have either an error or warning (depending on timeout)
        assert!(!result.errors.is_empty() || !result.warnings.is_empty());
    }
}
