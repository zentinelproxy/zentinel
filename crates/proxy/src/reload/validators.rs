//! Configuration validators for hot reload.
//!
//! These validators perform runtime-specific validation that complements
//! the schema-level validation in sentinel-config.

use sentinel_common::errors::{SentinelError, SentinelResult};
use sentinel_config::Config;

use super::ConfigValidator;

/// Route configuration validator
///
/// Performs runtime-specific route validation that complements the schema-level
/// validation in sentinel-config. This validator focuses on aspects that may
/// change during hot reload.
pub struct RouteValidator;

#[async_trait::async_trait]
impl ConfigValidator for RouteValidator {
    async fn validate(&self, config: &Config) -> SentinelResult<()> {
        // Most validation is now handled by Config's validate_config_semantics
        // This validator handles runtime-specific checks

        // Check for routes with both upstream and static-files (ambiguous config)
        for route in &config.routes {
            if route.upstream.is_some() && route.static_files.is_some() {
                return Err(SentinelError::Config {
                    message: format!(
                        "Route '{}' has both 'upstream' and 'static-files' configured.\n\
                         A route can only be one type. Choose either:\n\
                         - Remove 'upstream' to serve static files\n\
                         - Remove 'static-files' to proxy to upstream",
                        route.id
                    ),
                    source: None,
                });
            }
        }

        // Check for static routes with non-existent root directories
        for route in &config.routes {
            if let Some(ref static_config) = route.static_files {
                if !static_config.root.exists() {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' static files root directory '{}' does not exist.\n\
                             Hint: Create the directory or update the path:\n\
                             \n\
                             mkdir -p {}\n\
                             \n\
                             Or change the configuration:\n\
                             static-files {{\n\
                                 root \"/path/to/existing/directory\"\n\
                             }}",
                            route.id,
                            static_config.root.display(),
                            static_config.root.display()
                        ),
                        source: None,
                    });
                }

                if !static_config.root.is_dir() {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' static files root '{}' is not a directory.\n\
                             The 'root' must be a directory path, not a file.",
                            route.id,
                            static_config.root.display()
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "RouteValidator"
    }
}

/// Upstream configuration validator
///
/// Performs runtime-specific upstream validation. The schema-level validation
/// in sentinel-config handles most checks; this focuses on network reachability
/// and runtime concerns.
pub struct UpstreamValidator;

#[async_trait::async_trait]
impl ConfigValidator for UpstreamValidator {
    async fn validate(&self, config: &Config) -> SentinelResult<()> {
        // Most validation is now handled by Config's validate_config_semantics
        // This validator handles runtime-specific checks

        for (name, upstream) in &config.upstreams {
            // Validate target addresses can be parsed (supports hostnames)
            for (i, target) in upstream.targets.iter().enumerate() {
                // Try as socket address first
                if target.address.parse::<std::net::SocketAddr>().is_ok() {
                    continue;
                }

                // Try as host:port format
                let parts: Vec<&str> = target.address.rsplitn(2, ':').collect();
                if parts.len() == 2 {
                    if let Ok(port) = parts[0].parse::<u16>() {
                        if port > 0 {
                            continue; // Valid host:port format
                        }
                    }
                }

                return Err(SentinelError::Config {
                    message: format!(
                        "Upstream '{}' target #{} has invalid address '{}'.\n\
                         \n\
                         Expected format: HOST:PORT\n\
                         \n\
                         Valid examples:\n\
                         - 127.0.0.1:8080 (IPv4)\n\
                         - [::1]:8080 (IPv6)\n\
                         - backend.local:8080 (hostname)\n\
                         - api-server:3000 (service name)",
                        name,
                        i + 1,
                        target.address
                    ),
                    source: None,
                });
            }

            // Warn about upstreams with only one target (no redundancy)
            if upstream.targets.len() == 1 {
                tracing::warn!(
                    upstream = %name,
                    "Upstream '{}' has only one target. Consider adding more targets for redundancy.",
                    name
                );
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "UpstreamValidator"
    }
}
