//! Configuration module for Sentinel proxy
//!
//! This module provides configuration parsing, validation, and hot-reload support
//! with a focus on safety, security-first defaults, and operational clarity.
//!
//! # Module Organization
//!
//! - [`server`]: Server and listener configuration
//! - [`routes`]: Route configuration and match conditions
//! - [`upstreams`]: Upstream backend configuration
//! - [`agents`]: External processing agent configuration
//! - [`waf`]: WAF (Web Application Firewall) configuration
//! - [`observability`]: Metrics, logging, and tracing configuration
//! - [`filters`]: Filter types for request/response processing
//! - [`validation`]: Configuration validation functions
//! - [`kdl`]: KDL format parsing
//! - [`defaults`]: Default embedded configuration
//! - [`multi_file`]: Multi-file configuration loading

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info, trace, warn};
use validator::Validate;

use sentinel_common::{
    errors::{SentinelError, SentinelResult},
    limits::Limits,
    types::Priority,
};

// ============================================================================
// Module Declarations
// ============================================================================

pub mod agents;
mod defaults;
pub mod filters;
mod kdl;
pub mod multi_file;
pub mod observability;
pub mod routes;
pub mod server;
pub mod upstreams;
pub mod validation;
pub mod waf;

// ============================================================================
// Re-exports
// ============================================================================

// Agents
pub use agents::{
    AgentConfig, AgentEvent, AgentTlsConfig, AgentTransport, AgentType, BodyStreamingMode,
};

// Defaults
pub use defaults::{create_default_config, DEFAULT_CONFIG_KDL};

// Filters
pub use filters::*;

// Multi-file
pub use multi_file::{ConfigDirectory, MultiFileLoader};

// Observability
pub use observability::{
    AccessLogConfig, AuditLogConfig, ErrorLogConfig, LoggingConfig, MetricsConfig,
    ObservabilityConfig, TracingBackend, TracingConfig,
};

// Routes
pub use routes::{
    ApiSchemaConfig, BuiltinHandler, CacheBackend, CacheStorageConfig, ErrorFormat, ErrorPage,
    ErrorPageConfig, FailureMode, HeaderModifications, MatchCondition, RateLimitPolicy,
    RouteCacheConfig, RouteConfig, RoutePolicies, ServiceType, StaticFileConfig,
};

// Server
pub use server::{ListenerConfig, ListenerProtocol, ServerConfig, SniCertificate, TlsConfig};

// Re-export TraceIdFormat from common for convenience
pub use sentinel_common::TraceIdFormat;

// Upstreams
pub use upstreams::{
    ConnectionPoolConfig, HealthCheck, HttpVersionConfig, UpstreamConfig, UpstreamPeer,
    UpstreamTarget, UpstreamTimeouts, UpstreamTlsConfig,
};

// WAF
pub use waf::{
    BodyInspectionPolicy, ExclusionScope, RuleExclusion, WafConfig, WafEngine, WafMode, WafRuleset,
};

// Common types re-exported for convenience
pub use sentinel_common::types::LoadBalancingAlgorithm;

// ============================================================================
// Main Configuration Structure
// ============================================================================

/// Current schema version supported by this build
pub const CURRENT_SCHEMA_VERSION: &str = "1.0";

/// Minimum schema version supported by this build
pub const MIN_SCHEMA_VERSION: &str = "1.0";

/// Main configuration structure for Sentinel proxy
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validation::validate_config_semantics"))]
pub struct Config {
    /// Configuration schema version for compatibility checking
    /// If not specified, defaults to current version
    #[serde(default = "default_schema_version")]
    pub schema_version: String,

    /// Global server configuration
    pub server: ServerConfig,

    /// Listener configurations
    #[validate(length(min = 1, message = "At least one listener is required"))]
    pub listeners: Vec<ListenerConfig>,

    /// Route configurations
    pub routes: Vec<RouteConfig>,

    /// Upstream pool configurations (can be empty if all routes are static)
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,

    /// Named filter configurations (referenced by routes)
    #[serde(default)]
    pub filters: HashMap<String, FilterConfig>,

    /// Agent configurations
    #[serde(default)]
    pub agents: Vec<AgentConfig>,

    /// WAF configuration
    #[serde(default)]
    pub waf: Option<WafConfig>,

    /// Global limits configuration
    #[serde(default)]
    pub limits: Limits,

    /// Observability configuration
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Global rate limit configuration
    #[serde(default)]
    pub rate_limits: GlobalRateLimitConfig,

    /// Global cache storage configuration
    #[serde(default)]
    pub cache: Option<CacheStorageConfig>,

    /// Default upstream for Phase 0 testing
    #[serde(skip)]
    pub default_upstream: Option<UpstreamPeer>,
}

/// Default schema version (current version)
fn default_schema_version() -> String {
    CURRENT_SCHEMA_VERSION.to_string()
}

/// Schema version compatibility result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaCompatibility {
    /// Version matches exactly
    Exact,
    /// Version is compatible (within supported range)
    Compatible,
    /// Version is newer than supported - may have unsupported features
    Newer { config_version: String, max_supported: String },
    /// Version is older than minimum supported
    Older { config_version: String, min_supported: String },
    /// Version format is invalid
    Invalid { config_version: String, reason: String },
}

impl SchemaCompatibility {
    /// Returns true if the config can be loaded (Exact, Compatible, or Newer with warning)
    pub fn is_loadable(&self) -> bool {
        matches!(self, Self::Exact | Self::Compatible | Self::Newer { .. })
    }

    /// Returns a warning message if applicable
    pub fn warning(&self) -> Option<String> {
        match self {
            Self::Newer { config_version, max_supported } => Some(format!(
                "Config schema version {} is newer than supported version {}. Some features may not work.",
                config_version, max_supported
            )),
            _ => None,
        }
    }

    /// Returns an error message if not loadable
    pub fn error(&self) -> Option<String> {
        match self {
            Self::Older { config_version, min_supported } => Some(format!(
                "Config schema version {} is older than minimum supported version {}. Please update your configuration.",
                config_version, min_supported
            )),
            Self::Invalid { config_version, reason } => Some(format!(
                "Invalid schema version '{}': {}",
                config_version, reason
            )),
            _ => None,
        }
    }
}

/// Parse a version string into (major, minor) tuple
fn parse_version(version: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = version.trim().split('.').collect();
    if parts.len() != 2 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    Some((major, minor))
}

/// Check schema version compatibility
pub fn check_schema_compatibility(config_version: &str) -> SchemaCompatibility {
    let config_ver = match parse_version(config_version) {
        Some(v) => v,
        None => return SchemaCompatibility::Invalid {
            config_version: config_version.to_string(),
            reason: "Expected format: major.minor (e.g., '1.0')".to_string(),
        },
    };

    let current_ver = parse_version(CURRENT_SCHEMA_VERSION).unwrap();
    let min_ver = parse_version(MIN_SCHEMA_VERSION).unwrap();

    // Check if older than minimum
    if config_ver < min_ver {
        return SchemaCompatibility::Older {
            config_version: config_version.to_string(),
            min_supported: MIN_SCHEMA_VERSION.to_string(),
        };
    }

    // Check if newer than current
    if config_ver > current_ver {
        return SchemaCompatibility::Newer {
            config_version: config_version.to_string(),
            max_supported: CURRENT_SCHEMA_VERSION.to_string(),
        };
    }

    // Check if exact match
    if config_ver == current_ver {
        return SchemaCompatibility::Exact;
    }

    // Within range
    SchemaCompatibility::Compatible
}

// ============================================================================
// Config Implementation
// ============================================================================

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        trace!(
            path = %path.display(),
            "Loading configuration from file"
        );

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("kdl");

        debug!(
            path = %path.display(),
            format = extension,
            content_length = content.len(),
            "Read configuration file"
        );

        let config = match extension {
            "kdl" => Self::from_kdl(&content),
            "json" => Self::from_json(&content),
            "toml" => Self::from_toml(&content),
            _ => Err(anyhow::anyhow!("Unsupported config format: {}", extension)),
        }?;

        info!(
            path = %path.display(),
            routes = config.routes.len(),
            upstreams = config.upstreams.len(),
            agents = config.agents.len(),
            listeners = config.listeners.len(),
            "Configuration loaded successfully"
        );

        Ok(config)
    }

    /// Load the default embedded configuration.
    ///
    /// This is used when no configuration file is provided. It parses the
    /// embedded KDL configuration, falling back to the programmatic default
    /// if KDL parsing fails for any reason.
    pub fn default_embedded() -> Result<Self> {
        trace!("Loading embedded default configuration");

        Self::from_kdl(DEFAULT_CONFIG_KDL).or_else(|e| {
            warn!(
                error = %e,
                "Failed to parse embedded KDL config, using programmatic default"
            );
            Ok(create_default_config())
        })
    }

    /// Parse configuration from KDL format
    pub fn from_kdl(content: &str) -> Result<Self> {
        trace!(content_length = content.len(), "Parsing KDL configuration");
        let doc: ::kdl::KdlDocument = content.parse().map_err(|e: ::kdl::KdlError| {
            use miette::Diagnostic;

            let mut error_msg = String::new();
            error_msg.push_str("KDL configuration parse error:\n\n");

            let mut found_details = false;
            if let Some(related) = e.related() {
                for diagnostic in related {
                    let diag_str = format!("{}", diagnostic);
                    error_msg.push_str(&format!("  {}\n", diag_str));
                    found_details = true;

                    if let Some(labels) = diagnostic.labels() {
                        for label in labels {
                            let offset = label.offset();
                            let (line, col) = kdl::offset_to_line_col(content, offset);
                            error_msg
                                .push_str(&format!("\n  --> at line {}, column {}\n", line, col));

                            let lines: Vec<&str> = content.lines().collect();

                            if line > 1 {
                                if let Some(lc) = lines.get(line.saturating_sub(2)) {
                                    error_msg.push_str(&format!("{:>4} | {}\n", line - 1, lc));
                                }
                            }

                            if let Some(line_content) = lines.get(line.saturating_sub(1)) {
                                error_msg.push_str(&format!("{:>4} | {}\n", line, line_content));
                                error_msg.push_str(&format!(
                                    "     | {}^",
                                    " ".repeat(col.saturating_sub(1))
                                ));
                                if let Some(label_msg) = label.label() {
                                    error_msg.push_str(&format!(" {}", label_msg));
                                }
                                error_msg.push('\n');
                            }

                            if let Some(lc) = lines.get(line) {
                                error_msg.push_str(&format!("{:>4} | {}\n", line + 1, lc));
                            }
                        }
                    }

                    if let Some(help) = diagnostic.help() {
                        error_msg.push_str(&format!("\n  Help: {}\n", help));
                    }
                }
            }

            if !found_details {
                error_msg.push_str(&format!("  {}\n", e));
                error_msg.push_str("\n  Note: Check your KDL syntax. Common issues:\n");
                error_msg.push_str("    - Unclosed strings (missing closing quote)\n");
                error_msg.push_str("    - Unclosed blocks (missing closing brace)\n");
                error_msg.push_str("    - Invalid node names or values\n");
            }

            if let Some(help) = e.help() {
                error_msg.push_str(&format!("\n  Help: {}\n", help));
            }

            anyhow::anyhow!("{}", error_msg)
        })?;

        kdl::parse_kdl_document(doc)
    }

    /// Parse configuration from JSON format
    pub fn from_json(content: &str) -> Result<Self> {
        trace!(content_length = content.len(), "Parsing JSON configuration");
        serde_json::from_str(content).context("Failed to parse JSON configuration")
    }

    /// Parse configuration from TOML format
    pub fn from_toml(content: &str) -> Result<Self> {
        trace!(content_length = content.len(), "Parsing TOML configuration");
        toml::from_str(content).context("Failed to parse TOML configuration")
    }

    /// Check schema version compatibility
    pub fn check_schema_version(&self) -> SchemaCompatibility {
        check_schema_compatibility(&self.schema_version)
    }

    /// Validate the configuration
    pub fn validate(&self) -> SentinelResult<()> {
        trace!(
            routes = self.routes.len(),
            upstreams = self.upstreams.len(),
            agents = self.agents.len(),
            schema_version = %self.schema_version,
            "Starting configuration validation"
        );

        // Check schema version compatibility
        let compat = self.check_schema_version();
        if let Some(warning) = compat.warning() {
            warn!("{}", warning);
        }
        if !compat.is_loadable() {
            return Err(SentinelError::Config {
                message: compat.error().unwrap_or_else(|| "Unknown schema version error".to_string()),
                source: None,
            });
        }
        trace!(
            schema_version = %self.schema_version,
            compatibility = ?compat,
            "Schema version check passed"
        );

        Validate::validate(self).map_err(|e| SentinelError::Config {
            message: format!("Configuration validation failed: {}", e),
            source: None,
        })?;

        trace!("Schema validation passed");

        self.validate_routes()?;
        trace!("Route validation passed");

        self.validate_upstreams()?;
        trace!("Upstream validation passed");

        self.validate_agents()?;
        trace!("Agent validation passed");

        self.limits.validate()?;
        trace!("Limits validation passed");

        debug!(
            routes = self.routes.len(),
            upstreams = self.upstreams.len(),
            agents = self.agents.len(),
            "Configuration validation successful"
        );

        Ok(())
    }

    fn validate_routes(&self) -> SentinelResult<()> {
        for route in &self.routes {
            if let Some(upstream) = &route.upstream {
                if !self.upstreams.contains_key(upstream) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' references non-existent upstream '{}'",
                            route.id, upstream
                        ),
                        source: None,
                    });
                }
            }

            for filter_id in &route.filters {
                if !self.filters.contains_key(filter_id) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Route '{}' references non-existent filter '{}'",
                            route.id, filter_id
                        ),
                        source: None,
                    });
                }
            }
        }

        for (filter_id, filter_config) in &self.filters {
            if let Filter::Agent(agent_filter) = &filter_config.filter {
                if !self.agents.iter().any(|a| a.id == agent_filter.agent) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Filter '{}' references non-existent agent '{}'",
                            filter_id, agent_filter.agent
                        ),
                        source: None,
                    });
                }
            }
        }

        Ok(())
    }

    fn validate_upstreams(&self) -> SentinelResult<()> {
        for (id, upstream) in &self.upstreams {
            if upstream.targets.is_empty() {
                return Err(SentinelError::Config {
                    message: format!("Upstream '{}' has no targets", id),
                    source: None,
                });
            }
        }
        Ok(())
    }

    fn validate_agents(&self) -> SentinelResult<()> {
        for agent in &self.agents {
            if agent.timeout_ms == 0 {
                return Err(SentinelError::Config {
                    message: format!("Agent '{}' has invalid timeout", agent.id),
                    source: None,
                });
            }

            if let AgentTransport::UnixSocket { path } = &agent.transport {
                if !path.exists() && !path.parent().is_some_and(|p| p.exists()) {
                    return Err(SentinelError::Config {
                        message: format!(
                            "Agent '{}' unix socket path parent directory doesn't exist: {:?}",
                            agent.id, path
                        ),
                        source: None,
                    });
                }
            }
        }
        Ok(())
    }

    /// Create a default configuration for testing
    pub fn default_for_testing() -> Self {
        use sentinel_common::types::LoadBalancingAlgorithm;

        let mut upstreams = HashMap::new();
        upstreams.insert(
            "default".to_string(),
            UpstreamConfig {
                id: "default".to_string(),
                targets: vec![UpstreamTarget {
                    address: "127.0.0.1:8081".to_string(),
                    weight: 1,
                    max_requests: None,
                    metadata: HashMap::new(),
                }],
                load_balancing: LoadBalancingAlgorithm::RoundRobin,
                health_check: None,
                connection_pool: ConnectionPoolConfig::default(),
                timeouts: UpstreamTimeouts::default(),
                tls: None,
                http_version: HttpVersionConfig::default(),
            },
        );

        Self {
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            server: ServerConfig {
                worker_threads: 4,
                max_connections: 1000,
                graceful_shutdown_timeout_secs: 30,
                daemon: false,
                pid_file: None,
                user: None,
                group: None,
                working_directory: None,
                trace_id_format: Default::default(),
                auto_reload: false,
            },
            listeners: vec![ListenerConfig {
                id: "http".to_string(),
                address: "0.0.0.0:8080".to_string(),
                protocol: ListenerProtocol::Http,
                tls: None,
                default_route: Some("default".to_string()),
                request_timeout_secs: 60,
                keepalive_timeout_secs: 75,
                max_concurrent_streams: 100,
            }],
            routes: vec![RouteConfig {
                id: "default".to_string(),
                priority: Priority::Normal,
                matches: vec![MatchCondition::PathPrefix("/".to_string())],
                upstream: Some("default".to_string()),
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
            }],
            upstreams,
            filters: HashMap::new(),
            agents: vec![],
            waf: None,
            limits: Limits::for_testing(),
            observability: ObservabilityConfig::default(),
            rate_limits: GlobalRateLimitConfig::default(),
            cache: None,
            default_upstream: Some(UpstreamPeer {
                address: "127.0.0.1:8081".to_string(),
                tls: false,
                host: "localhost".to_string(),
                connect_timeout_secs: 10,
                read_timeout_secs: 30,
                write_timeout_secs: 30,
            }),
        }
    }

    /// Reload configuration from the same file path
    pub fn reload(&mut self, path: impl AsRef<Path>) -> SentinelResult<()> {
        let path = path.as_ref();
        debug!(
            path = %path.display(),
            "Reloading configuration"
        );

        let new_config = Self::from_file(path).map_err(|e| SentinelError::Config {
            message: format!("Failed to reload configuration: {}", e),
            source: None,
        })?;

        new_config.validate()?;

        info!(
            path = %path.display(),
            routes = new_config.routes.len(),
            upstreams = new_config.upstreams.len(),
            "Configuration reloaded successfully"
        );

        *self = new_config;
        Ok(())
    }

    /// Get a route by ID
    pub fn get_route(&self, id: &str) -> Option<&RouteConfig> {
        self.routes.iter().find(|r| r.id == id)
    }

    /// Get an upstream by ID
    pub fn get_upstream(&self, id: &str) -> Option<&UpstreamConfig> {
        self.upstreams.get(id)
    }

    /// Get an agent by ID
    pub fn get_agent(&self, id: &str) -> Option<&AgentConfig> {
        self.agents.iter().find(|a| a.id == id)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.0"), Some((1, 0)));
        assert_eq!(parse_version("2.5"), Some((2, 5)));
        assert_eq!(parse_version("10.20"), Some((10, 20)));
        assert_eq!(parse_version("1"), None);
        assert_eq!(parse_version("1.0.0"), None);
        assert_eq!(parse_version("abc"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_schema_compatibility_exact() {
        let compat = check_schema_compatibility(CURRENT_SCHEMA_VERSION);
        assert_eq!(compat, SchemaCompatibility::Exact);
        assert!(compat.is_loadable());
        assert!(compat.warning().is_none());
        assert!(compat.error().is_none());
    }

    #[test]
    fn test_schema_compatibility_newer() {
        let compat = check_schema_compatibility("99.0");
        assert!(matches!(compat, SchemaCompatibility::Newer { .. }));
        assert!(compat.is_loadable()); // Newer versions are loadable with warning
        assert!(compat.warning().is_some());
        assert!(compat.error().is_none());
    }

    #[test]
    fn test_schema_compatibility_older() {
        // This test assumes MIN_SCHEMA_VERSION is "1.0"
        let compat = check_schema_compatibility("0.5");
        assert!(matches!(compat, SchemaCompatibility::Older { .. }));
        assert!(!compat.is_loadable());
        assert!(compat.warning().is_none());
        assert!(compat.error().is_some());
    }

    #[test]
    fn test_schema_compatibility_invalid() {
        let compat = check_schema_compatibility("not-a-version");
        assert!(matches!(compat, SchemaCompatibility::Invalid { .. }));
        assert!(!compat.is_loadable());
        assert!(compat.error().is_some());

        let compat = check_schema_compatibility("1.0.0");
        assert!(matches!(compat, SchemaCompatibility::Invalid { .. }));
    }

    #[test]
    fn test_default_schema_version() {
        let config = Config::default_for_testing();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn test_kdl_with_schema_version() {
        let kdl = r#"
            schema-version "1.0"
            server {
                worker-threads 4
            }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }
        "#;
        let config = Config::from_kdl(kdl).unwrap();
        assert_eq!(config.schema_version, "1.0");
    }

    #[test]
    fn test_kdl_without_schema_version_uses_default() {
        let kdl = r#"
            server {
                worker-threads 4
            }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                    protocol "http"
                }
            }
        "#;
        let config = Config::from_kdl(kdl).unwrap();
        assert_eq!(config.schema_version, CURRENT_SCHEMA_VERSION);
    }
}
