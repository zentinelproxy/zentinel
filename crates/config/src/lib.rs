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
pub use agents::{AgentConfig, AgentEvent, AgentTlsConfig, AgentTransport, AgentType};

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
    ApiSchemaConfig, BuiltinHandler, ErrorFormat, ErrorPage, ErrorPageConfig, FailureMode,
    HeaderModifications, MatchCondition, RateLimitPolicy, RouteConfig, RoutePolicies, ServiceType,
    StaticFileConfig,
};

// Server
pub use server::{ListenerConfig, ListenerProtocol, ServerConfig, TlsConfig};

// Re-export TraceIdFormat from common for convenience
pub use sentinel_common::TraceIdFormat;

// Upstreams
pub use upstreams::{
    ConnectionPoolConfig, HealthCheck, UpstreamConfig, UpstreamPeer, UpstreamTarget,
    UpstreamTimeouts, UpstreamTlsConfig,
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

/// Main configuration structure for Sentinel proxy
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validation::validate_config_semantics"))]
pub struct Config {
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

    /// Default upstream for Phase 0 testing
    #[serde(skip)]
    pub default_upstream: Option<UpstreamPeer>,
}

// ============================================================================
// Config Implementation
// ============================================================================

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("kdl");

        match extension {
            "kdl" => Self::from_kdl(&content),
            "json" => Self::from_json(&content),
            "toml" => Self::from_toml(&content),
            _ => Err(anyhow::anyhow!("Unsupported config format: {}", extension)),
        }
    }

    /// Load the default embedded configuration.
    ///
    /// This is used when no configuration file is provided. It parses the
    /// embedded KDL configuration, falling back to the programmatic default
    /// if KDL parsing fails for any reason.
    pub fn default_embedded() -> Result<Self> {
        Self::from_kdl(DEFAULT_CONFIG_KDL).or_else(|e| {
            tracing::warn!(
                "Failed to parse embedded KDL config, using programmatic default: {}",
                e
            );
            Ok(create_default_config())
        })
    }

    /// Parse configuration from KDL format
    pub fn from_kdl(content: &str) -> Result<Self> {
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
        serde_json::from_str(content).context("Failed to parse JSON configuration")
    }

    /// Parse configuration from TOML format
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).context("Failed to parse TOML configuration")
    }

    /// Validate the configuration
    pub fn validate(&self) -> SentinelResult<()> {
        Validate::validate(self).map_err(|e| SentinelError::Config {
            message: format!("Configuration validation failed: {}", e),
            source: None,
        })?;

        self.validate_routes()?;
        self.validate_upstreams()?;
        self.validate_agents()?;
        self.limits.validate()?;

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
                if !path.exists() && !path.parent().map_or(false, |p| p.exists()) {
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
            },
        );

        Self {
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
            }],
            upstreams,
            filters: HashMap::new(),
            agents: vec![],
            waf: None,
            limits: Limits::for_testing(),
            observability: ObservabilityConfig::default(),
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
        let new_config = Self::from_file(path).map_err(|e| SentinelError::Config {
            message: format!("Failed to reload configuration: {}", e),
            source: None,
        })?;

        new_config.validate()?;
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
