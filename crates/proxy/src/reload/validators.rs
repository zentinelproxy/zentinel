//! Configuration validators for hot reload.
//!
//! These validators perform runtime-specific validation that complements
//! the schema-level validation in zentinel-config.

use tracing::{debug, trace, warn};
use zentinel_common::errors::{ZentinelError, ZentinelResult};
use zentinel_config::Config;

use super::ConfigValidator;

/// Route configuration validator
///
/// Performs runtime-specific route validation that complements the schema-level
/// validation in zentinel-config. This validator focuses on aspects that may
/// change during hot reload.
pub struct RouteValidator;

#[async_trait::async_trait]
impl ConfigValidator for RouteValidator {
    async fn validate(&self, config: &Config) -> ZentinelResult<()> {
        trace!(route_count = config.routes.len(), "Running route validator");

        // Most validation is now handled by Config's validate_config_semantics
        // This validator handles runtime-specific checks

        // Check for routes with both upstream and static-files (ambiguous config)
        for route in &config.routes {
            trace!(route_id = %route.id, "Validating route");

            if route.upstream.is_some() && route.static_files.is_some() {
                warn!(
                    route_id = %route.id,
                    "Route has both upstream and static-files configured"
                );
                return Err(ZentinelError::Config {
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
                trace!(
                    route_id = %route.id,
                    root = %static_config.root.display(),
                    "Checking static files root directory"
                );

                if !static_config.root.exists() {
                    warn!(
                        route_id = %route.id,
                        root = %static_config.root.display(),
                        "Static files root directory does not exist"
                    );
                    return Err(ZentinelError::Config {
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
                    warn!(
                        route_id = %route.id,
                        root = %static_config.root.display(),
                        "Static files root is not a directory"
                    );
                    return Err(ZentinelError::Config {
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

        debug!("Route validation passed");
        Ok(())
    }

    fn name(&self) -> &str {
        "RouteValidator"
    }
}

/// Upstream configuration validator
///
/// Performs runtime-specific upstream validation. The schema-level validation
/// in zentinel-config handles most checks; this focuses on network reachability
/// and runtime concerns.
pub struct UpstreamValidator;

#[async_trait::async_trait]
impl ConfigValidator for UpstreamValidator {
    async fn validate(&self, config: &Config) -> ZentinelResult<()> {
        trace!(
            upstream_count = config.upstreams.len(),
            "Running upstream validator"
        );

        // Most validation is now handled by Config's validate_config_semantics
        // This validator handles runtime-specific checks

        for (name, upstream) in &config.upstreams {
            trace!(
                upstream_id = %name,
                target_count = upstream.targets.len(),
                "Validating upstream"
            );

            // Validate target addresses can be parsed (supports hostnames)
            for (i, target) in upstream.targets.iter().enumerate() {
                trace!(
                    upstream_id = %name,
                    target_index = i,
                    address = %target.address,
                    "Validating target address"
                );

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

                warn!(
                    upstream_id = %name,
                    target_index = i,
                    address = %target.address,
                    "Invalid target address format"
                );

                return Err(ZentinelError::Config {
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
                warn!(
                    upstream_id = %name,
                    "Upstream has only one target - consider adding more for redundancy"
                );
            }
        }

        debug!("Upstream validation passed");
        Ok(())
    }

    fn name(&self) -> &str {
        "UpstreamValidator"
    }
}
