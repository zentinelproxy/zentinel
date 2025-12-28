//! Multi-file configuration support for Sentinel
//!
//! This module provides the ability to load and merge configurations from
//! multiple KDL files, supporting modular configuration management.

use anyhow::{anyhow, Context, Result};
use glob::glob;
use kdl::{KdlDocument, KdlNode};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::{
    AgentConfig, Config, Limits, ListenerConfig, ObservabilityConfig, RouteConfig, ServerConfig,
    UpstreamConfig, WafConfig,
};

/// Multi-file configuration loader
pub struct MultiFileLoader {
    /// Base directory for configuration files
    base_dir: PathBuf,
    /// File patterns to include
    include_patterns: Vec<String>,
    /// File patterns to exclude
    exclude_patterns: Vec<String>,
    /// Enable recursive directory scanning
    recursive: bool,
    /// Allow duplicate definitions (last wins)
    allow_duplicates: bool,
    /// Strict mode - fail on warnings
    strict: bool,
    /// Loaded files tracking
    loaded_files: HashSet<PathBuf>,
}

impl MultiFileLoader {
    /// Create a new multi-file loader
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            include_patterns: vec!["*.kdl".to_string()],
            exclude_patterns: vec![],
            recursive: true,
            allow_duplicates: false,
            strict: false,
            loaded_files: HashSet::new(),
        }
    }

    /// Add include pattern
    pub fn with_include(mut self, pattern: impl Into<String>) -> Self {
        self.include_patterns.push(pattern.into());
        self
    }

    /// Add exclude pattern
    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Set recursive scanning
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Allow duplicate definitions
    pub fn allow_duplicates(mut self, allow: bool) -> Self {
        self.allow_duplicates = allow;
        self
    }

    /// Enable strict mode
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Load configuration from multiple files
    pub fn load(&mut self) -> Result<Config> {
        info!("Loading configuration from directory: {:?}", self.base_dir);

        // Find all configuration files
        let files = self.find_config_files()?;

        if files.is_empty() {
            return Err(anyhow!(
                "No configuration files found in {:?}",
                self.base_dir
            ));
        }

        info!("Found {} configuration files", files.len());

        // Load and merge configurations
        let mut merged = ConfigBuilder::new();

        for file in files {
            debug!("Loading configuration from: {:?}", file);
            let config = self.load_file(&file)?;
            merged.merge(config)?;
            self.loaded_files.insert(file);
        }

        // Build final configuration
        let config = merged.build()?;

        // Validate if in strict mode
        if self.strict {
            config
                .validate()
                .map_err(|e| anyhow!("Validation failed: {}", e))?;
        }

        Ok(config)
    }

    /// Find all configuration files matching patterns
    fn find_config_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut seen = HashSet::new();

        for pattern in &self.include_patterns {
            let full_pattern = if self.recursive {
                self.base_dir.join("**").join(pattern)
            } else {
                self.base_dir.join(pattern)
            };

            let pattern_str = full_pattern
                .to_str()
                .ok_or_else(|| anyhow!("Invalid path pattern"))?;

            for entry in glob(pattern_str).context("Failed to read glob pattern")? {
                match entry {
                    Ok(path) => {
                        if path.is_file() {
                            // Check exclusions
                            if self.should_exclude(&path) {
                                debug!("Excluding file: {:?}", path);
                                continue;
                            }

                            if seen.insert(path.clone()) {
                                files.push(path);
                            }
                        }
                        // Skip directories
                    }
                    Err(e) => {
                        warn!("Error accessing path: {}", e);
                    }
                }
            }
        }

        // Sort files for consistent loading order
        files.sort();

        Ok(files)
    }

    /// Check if a file should be excluded
    fn should_exclude(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in &self.exclude_patterns {
            if path_str.contains(pattern) {
                return true;
            }
        }

        // Common exclusions
        if path_str.contains(".example.") || path_str.contains(".bak") || path_str.ends_with("~") {
            return true;
        }

        false
    }

    /// Load a single configuration file
    fn load_file(&self, path: &Path) -> Result<PartialConfig> {
        let content =
            fs::read_to_string(path).with_context(|| format!("Failed to read file: {:?}", path))?;

        let doc: KdlDocument = content
            .parse()
            .with_context(|| format!("Failed to parse KDL file: {:?}", path))?;

        PartialConfig::from_kdl(doc, path)
    }
}

/// Partial configuration from a single file
#[derive(Debug, Default)]
struct PartialConfig {
    source_file: PathBuf,
    server: Option<ServerConfig>,
    listeners: Vec<ListenerConfig>,
    routes: Vec<RouteConfig>,
    upstreams: HashMap<String, UpstreamConfig>,
    agents: Vec<AgentConfig>,
    waf: Option<WafConfig>,
    limits: Option<Limits>,
    observability: Option<ObservabilityConfig>,
}

impl PartialConfig {
    /// Parse partial configuration from KDL document
    fn from_kdl(doc: KdlDocument, source: &Path) -> Result<Self> {
        let mut config = Self {
            source_file: source.to_path_buf(),
            ..Default::default()
        };

        for node in doc.nodes() {
            match node.name().value() {
                "include" => {
                    // Handle include directives - currently ignored
                    // TODO: Implement include processing
                }
                "server" if config.server.is_none() => {
                    config.server = Some(parse_server(node)?);
                }
                "listener" => {
                    config.listeners.push(parse_listener(node)?);
                }
                "route" => {
                    config.routes.push(parse_route(node)?);
                }
                "upstream" => {
                    let (name, upstream) = parse_upstream(node)?;
                    config.upstreams.insert(name, upstream);
                }
                "agent" => {
                    config.agents.push(parse_agent(node)?);
                }
                "waf" if config.waf.is_none() => {
                    config.waf = Some(parse_waf(node)?);
                }
                "limits" if config.limits.is_none() => {
                    config.limits = Some(parse_limits(node)?);
                }
                "observability" if config.observability.is_none() => {
                    config.observability = Some(parse_observability(node)?);
                }
                "metadata" => {
                    // Skip metadata for now - not part of the main config structure
                }
                _ => {
                    debug!(
                        "Ignoring unknown configuration node: {}",
                        node.name().value()
                    );
                }
            }
        }

        Ok(config)
    }
}

/// Configuration builder for merging multiple partial configs
struct ConfigBuilder {
    server: Option<ServerConfig>,
    listeners: Vec<ListenerConfig>,
    routes: Vec<RouteConfig>,
    upstreams: HashMap<String, UpstreamConfig>,
    filters: HashMap<String, crate::FilterConfig>,
    agents: Vec<AgentConfig>,
    waf: Option<WafConfig>,
    limits: Option<Limits>,
    observability: Option<ObservabilityConfig>,

    // Tracking for duplicates
    listener_ids: HashSet<String>,
    route_ids: HashSet<String>,
    filter_ids: HashSet<String>,
    agent_ids: HashSet<String>,
}

impl ConfigBuilder {
    fn new() -> Self {
        Self {
            server: None,
            listeners: Vec::new(),
            routes: Vec::new(),
            upstreams: HashMap::new(),
            filters: HashMap::new(),
            agents: Vec::new(),
            waf: None,
            limits: None,
            observability: None,
            listener_ids: HashSet::new(),
            route_ids: HashSet::new(),
            filter_ids: HashSet::new(),
            agent_ids: HashSet::new(),
        }
    }

    /// Merge a partial configuration
    fn merge(&mut self, partial: PartialConfig) -> Result<()> {
        // Merge listeners
        for listener in partial.listeners {
            if !self.listener_ids.insert(listener.id.clone()) {
                return Err(anyhow!(
                    "Duplicate listener '{}' in {:?}",
                    listener.id,
                    partial.source_file
                ));
            }
            self.listeners.push(listener);
        }

        // Merge routes
        for route in partial.routes {
            if !self.route_ids.insert(route.id.clone()) {
                return Err(anyhow!(
                    "Duplicate route '{}' in {:?}",
                    route.id,
                    partial.source_file
                ));
            }
            self.routes.push(route);
        }

        // Merge upstreams (last wins for duplicates)
        for (name, upstream) in partial.upstreams {
            if self.upstreams.contains_key(&name) {
                warn!(
                    "Overriding upstream '{}' from {:?}",
                    name, partial.source_file
                );
            }
            self.upstreams.insert(name, upstream);
        }

        // Merge agents
        for agent in partial.agents {
            if !self.agent_ids.insert(agent.id.clone()) {
                return Err(anyhow!(
                    "Duplicate agent '{}' in {:?}",
                    agent.id,
                    partial.source_file
                ));
            }
            self.agents.push(agent);
        }

        // Merge singleton configs (last wins)
        // Merge server (warn on override)
        if partial.server.is_some() {
            if self.server.is_some() {
                warn!("Overriding server config from {:?}", partial.source_file);
            }
            self.server = partial.server;
        }

        // Merge WAF (warn on override)
        if partial.waf.is_some() {
            if self.waf.is_some() {
                warn!("Overriding WAF config from {:?}", partial.source_file);
            }
            self.waf = partial.waf;
        }

        // Merge limits (warn on override)
        if partial.limits.is_some() {
            if self.limits.is_some() {
                warn!("Overriding limits config from {:?}", partial.source_file);
            }
            self.limits = partial.limits;
        }

        // Merge observability (warn on override)
        if partial.observability.is_some() {
            if self.observability.is_some() {
                warn!(
                    "Overriding observability config from {:?}",
                    partial.source_file
                );
            }
            self.observability = partial.observability;
        }

        Ok(())
    }

    /// Build the final configuration
    fn build(self) -> Result<Config> {
        Ok(Config {
            server: self
                .server
                .ok_or_else(|| anyhow!("Server configuration is required"))?,
            listeners: self.listeners,
            routes: self.routes,
            upstreams: self.upstreams,
            filters: self.filters,
            agents: self.agents,
            waf: self.waf,
            limits: self.limits.unwrap_or_default(),
            observability: self.observability.unwrap_or_default(),
            default_upstream: None,
        })
    }
}

// =============================================================================
// Parsing helper functions for multi-file config format
// =============================================================================

/// Get string value from a node entry by name
fn get_string_entry(node: &KdlNode, name: &str) -> Option<String> {
    for entry in node.entries() {
        if let Some(entry_name) = entry.name() {
            if entry_name.value() == name {
                return entry.value().as_string().map(|s| s.to_string());
            }
        }
    }
    // Also check children for nested values
    if let Some(children) = node.children() {
        if let Some(child) = children.get(name) {
            if let Some(first_entry) = child.entries().first() {
                return first_entry.value().as_string().map(|s| s.to_string());
            }
        }
    }
    None
}

/// Get integer value from a node entry by name
fn get_int_entry(node: &KdlNode, name: &str) -> Option<i64> {
    for entry in node.entries() {
        if let Some(entry_name) = entry.name() {
            if entry_name.value() == name {
                if let Some(i) = entry.value().as_integer() {
                    return Some(i as i64);
                }
            }
        }
    }
    if let Some(children) = node.children() {
        if let Some(child) = children.get(name) {
            if let Some(first_entry) = child.entries().first() {
                if let Some(i) = first_entry.value().as_integer() {
                    return Some(i as i64);
                }
            }
        }
    }
    None
}

/// Get boolean value from a node entry by name
fn get_bool_entry(node: &KdlNode, name: &str) -> Option<bool> {
    for entry in node.entries() {
        if let Some(entry_name) = entry.name() {
            if entry_name.value() == name {
                return entry.value().as_bool();
            }
        }
    }
    if let Some(children) = node.children() {
        if let Some(child) = children.get(name) {
            if let Some(first_entry) = child.entries().first() {
                return first_entry.value().as_bool();
            }
        }
    }
    None
}

/// Get first string argument from a node
fn get_first_arg_string(node: &KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

fn parse_server(node: &KdlNode) -> Result<ServerConfig> {
    Ok(ServerConfig {
        worker_threads: get_int_entry(node, "worker-threads")
            .map(|v| v as usize)
            .unwrap_or(0),
        max_connections: get_int_entry(node, "max-connections")
            .map(|v| v as usize)
            .unwrap_or(10000),
        graceful_shutdown_timeout_secs: get_int_entry(node, "graceful-shutdown-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or(30),
        daemon: get_bool_entry(node, "daemon").unwrap_or(false),
        pid_file: get_string_entry(node, "pid-file").map(PathBuf::from),
        user: get_string_entry(node, "user"),
        group: get_string_entry(node, "group"),
        working_directory: get_string_entry(node, "working-directory").map(PathBuf::from),
    })
}

fn parse_listener(node: &KdlNode) -> Result<ListenerConfig> {
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow!("Listener requires an ID"))?;

    Ok(ListenerConfig {
        id,
        address: get_string_entry(node, "address")
            .unwrap_or_else(|| "0.0.0.0:8080".to_string()),
        protocol: match get_string_entry(node, "protocol").as_deref() {
            Some("https") => crate::ListenerProtocol::Https,
            _ => crate::ListenerProtocol::Http,
        },
        tls: None, // TLS config would need more complex parsing
        default_route: get_string_entry(node, "default-route"),
        request_timeout_secs: get_int_entry(node, "request-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or(60),
        keepalive_timeout_secs: get_int_entry(node, "keepalive-timeout-secs")
            .map(|v| v as u64)
            .unwrap_or(75),
        max_concurrent_streams: get_int_entry(node, "max-concurrent-streams")
            .map(|v| v as u32)
            .unwrap_or(100),
    })
}

fn parse_route(node: &KdlNode) -> Result<RouteConfig> {
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow!("Route requires an ID"))?;

    // Parse match conditions
    let mut matches = Vec::new();
    if let Some(path) = get_string_entry(node, "path") {
        matches.push(crate::MatchCondition::PathPrefix(path));
    }
    if let Some(path_prefix) = get_string_entry(node, "path-prefix") {
        matches.push(crate::MatchCondition::PathPrefix(path_prefix));
    }
    if matches.is_empty() {
        matches.push(crate::MatchCondition::PathPrefix("/".to_string()));
    }

    Ok(RouteConfig {
        id,
        priority: crate::Priority::Normal,
        matches,
        upstream: get_string_entry(node, "upstream"),
        service_type: crate::ServiceType::Web,
        policies: crate::RoutePolicies::default(),
        filters: Vec::new(),
        builtin_handler: None,
        waf_enabled: get_bool_entry(node, "waf-enabled").unwrap_or(false),
        circuit_breaker: None,
        retry_policy: None,
        static_files: None,
        api_schema: None,
        error_pages: None,
    })
}

fn parse_upstream(node: &KdlNode) -> Result<(String, UpstreamConfig)> {
    let name = get_first_arg_string(node)
        .ok_or_else(|| anyhow!("Upstream requires a name"))?;

    let mut targets = Vec::new();

    // Parse targets from children
    if let Some(children) = node.children() {
        if let Some(targets_node) = children.get("targets") {
            if let Some(target_children) = targets_node.children() {
                for target_node in target_children.nodes() {
                    if target_node.name().value() == "target" {
                        let address = get_string_entry(target_node, "address")
                            .unwrap_or_else(|| "127.0.0.1:8080".to_string());
                        let weight = get_int_entry(target_node, "weight")
                            .map(|v| v as u32)
                            .unwrap_or(1);
                        targets.push(crate::UpstreamTarget {
                            address,
                            weight,
                            max_requests: None,
                            metadata: HashMap::new(),
                        });
                    }
                }
            }
        }
    }

    // If no targets defined, use address from node directly
    if targets.is_empty() {
        if let Some(address) = get_string_entry(node, "address") {
            targets.push(crate::UpstreamTarget {
                address,
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            });
        }
    }

    Ok((name.clone(), UpstreamConfig {
        id: name,
        targets,
        load_balancing: get_string_entry(node, "load-balancing")
            .map(|s| match s.as_str() {
                "round_robin" => crate::LoadBalancingAlgorithm::RoundRobin,
                "least_connections" => crate::LoadBalancingAlgorithm::LeastConnections,
                "ip_hash" => crate::LoadBalancingAlgorithm::IpHash,
                "random" => crate::LoadBalancingAlgorithm::Random,
                _ => crate::LoadBalancingAlgorithm::RoundRobin,
            })
            .unwrap_or(crate::LoadBalancingAlgorithm::RoundRobin),
        health_check: None,
        connection_pool: crate::ConnectionPoolConfig::default(),
        timeouts: crate::UpstreamTimeouts::default(),
        tls: None,
    }))
}

fn parse_agent(node: &KdlNode) -> Result<AgentConfig> {
    let id = get_first_arg_string(node)
        .ok_or_else(|| anyhow!("Agent requires an ID"))?;

    let type_str = get_string_entry(node, "type").unwrap_or_else(|| "custom".to_string());
    let agent_type = match type_str.as_str() {
        "auth" => crate::AgentType::Auth,
        "rate_limit" => crate::AgentType::RateLimit,
        "waf" => crate::AgentType::Waf,
        other => crate::AgentType::Custom(other.to_string()),
    };

    // Parse transport - default to unix socket
    let socket_path = get_string_entry(node, "socket-path")
        .unwrap_or_else(|| format!("/var/run/sentinel/{}.sock", id));
    let transport = crate::AgentTransport::UnixSocket {
        path: PathBuf::from(socket_path),
    };

    Ok(AgentConfig {
        id,
        agent_type,
        transport,
        events: vec![crate::AgentEvent::RequestHeaders],
        timeout_ms: get_int_entry(node, "timeout-ms")
            .map(|v| v as u64)
            .unwrap_or(100),
        failure_mode: match get_string_entry(node, "failure-mode").as_deref() {
            Some("closed") => crate::FailureMode::Closed,
            _ => crate::FailureMode::Open,
        },
        max_request_body_bytes: get_int_entry(node, "max-request-body-bytes")
            .map(|v| v as usize),
        max_response_body_bytes: None,
        circuit_breaker: None,
    })
}

fn parse_waf(node: &KdlNode) -> Result<WafConfig> {
    let engine = match get_string_entry(node, "engine").as_deref() {
        Some("modsecurity") | None => crate::WafEngine::ModSecurity,
        Some("coraza") => crate::WafEngine::Coraza,
        Some(other) => crate::WafEngine::Custom(other.to_string()),
    };

    Ok(WafConfig {
        engine,
        ruleset: crate::WafRuleset {
            crs_version: get_string_entry(node, "crs-version").unwrap_or_default(),
            paranoia_level: get_int_entry(node, "paranoia-level").map(|v| v as u8).unwrap_or(1),
            anomaly_threshold: get_int_entry(node, "anomaly-threshold").map(|v| v as u32).unwrap_or(5),
            custom_rules_dir: get_string_entry(node, "custom-rules-dir").map(PathBuf::from),
            exclusions: Vec::new(),
        },
        mode: match get_string_entry(node, "mode").as_deref() {
            Some("detection") => crate::WafMode::Detection,
            _ => crate::WafMode::Prevention,
        },
        audit_log: get_bool_entry(node, "audit-log").unwrap_or(true),
        body_inspection: crate::BodyInspectionPolicy::default(),
    })
}

fn parse_limits(node: &KdlNode) -> Result<Limits> {
    // Start with defaults and override what's specified
    let defaults = Limits::default();

    Ok(Limits {
        max_header_size_bytes: get_int_entry(node, "max-header-size-bytes")
            .or_else(|| get_int_entry(node, "max-header-size"))
            .map(|v| v as usize)
            .unwrap_or(defaults.max_header_size_bytes),
        max_header_count: get_int_entry(node, "max-header-count")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_header_count),
        max_header_name_bytes: get_int_entry(node, "max-header-name-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_header_name_bytes),
        max_header_value_bytes: get_int_entry(node, "max-header-value-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_header_value_bytes),
        max_body_size_bytes: get_int_entry(node, "max-body-size-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_body_size_bytes),
        max_body_buffer_bytes: get_int_entry(node, "max-body-buffer-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_body_buffer_bytes),
        max_body_inspection_bytes: get_int_entry(node, "max-body-inspection-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_body_inspection_bytes),
        max_decompression_ratio: defaults.max_decompression_ratio,
        max_decompressed_size_bytes: get_int_entry(node, "max-decompressed-size-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_decompressed_size_bytes),
        max_connections_per_client: get_int_entry(node, "max-connections-per-client")
            .or_else(|| get_int_entry(node, "max-connections"))
            .map(|v| v as usize)
            .unwrap_or(defaults.max_connections_per_client),
        max_connections_per_route: get_int_entry(node, "max-connections-per-route")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_connections_per_route),
        max_total_connections: get_int_entry(node, "max-total-connections")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_total_connections),
        max_idle_connections_per_upstream: get_int_entry(node, "max-idle-connections-per-upstream")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_idle_connections_per_upstream),
        max_in_flight_requests: get_int_entry(node, "max-in-flight-requests")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_in_flight_requests),
        max_in_flight_requests_per_worker: get_int_entry(node, "max-in-flight-requests-per-worker")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_in_flight_requests_per_worker),
        max_queued_requests: get_int_entry(node, "max-queued-requests")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_queued_requests),
        max_agent_queue_depth: get_int_entry(node, "max-agent-queue-depth")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_agent_queue_depth),
        max_agent_body_bytes: get_int_entry(node, "max-agent-body-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_agent_body_bytes),
        max_agent_response_bytes: get_int_entry(node, "max-agent-response-bytes")
            .map(|v| v as usize)
            .unwrap_or(defaults.max_agent_response_bytes),
        max_requests_per_second_global: get_int_entry(node, "max-requests-per-second-global")
            .map(|v| v as u32),
        max_requests_per_second_per_client: get_int_entry(node, "max-requests-per-second-per-client")
            .map(|v| v as u32),
        max_requests_per_second_per_route: get_int_entry(node, "max-requests-per-second-per-route")
            .map(|v| v as u32),
        max_memory_bytes: get_int_entry(node, "max-memory-bytes")
            .map(|v| v as usize),
        max_memory_percent: None,
    })
}

fn parse_observability(node: &KdlNode) -> Result<ObservabilityConfig> {
    let mut config = ObservabilityConfig::default();

    if let Some(children) = node.children() {
        if let Some(metrics_node) = children.get("metrics") {
            config.metrics.enabled = get_bool_entry(metrics_node, "enabled").unwrap_or(true);
            if let Some(addr) = get_string_entry(metrics_node, "address") {
                config.metrics.address = addr;
            }
            if let Some(path) = get_string_entry(metrics_node, "path") {
                config.metrics.path = path;
            }
        }

        if let Some(logging_node) = children.get("logging") {
            if let Some(level) = get_string_entry(logging_node, "level") {
                config.logging.level = level;
            }
            if let Some(format) = get_string_entry(logging_node, "format") {
                config.logging.format = format;
            }
        }
    }

    Ok(config)
}

/// Configuration directory structure support
pub struct ConfigDirectory {
    root: PathBuf,
}

impl ConfigDirectory {
    /// Create a new config directory handler
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Load configuration using convention-based structure
    ///
    /// Expected structure:
    /// ```text
    /// config/
    ///   ├── sentinel.kdl         # Main config
    ///   ├── listeners/           # Listener definitions
    ///   │   ├── http.kdl
    ///   │   └── https.kdl
    ///   ├── routes/              # Route definitions
    ///   │   ├── api.kdl
    ///   │   └── static.kdl
    ///   ├── upstreams/           # Upstream definitions
    ///   │   ├── backend.kdl
    ///   │   └── cache.kdl
    ///   ├── agents/              # Agent configurations
    ///   │   ├── waf.kdl
    ///   │   └── auth.kdl
    ///   └── environments/        # Environment overrides
    ///       ├── development.kdl
    ///       ├── staging.kdl
    ///       └── production.kdl
    /// ```
    pub fn load(&self, environment: Option<&str>) -> Result<Config> {
        let mut loader = MultiFileLoader::new(&self.root);

        // Load main configuration
        if self.root.join("sentinel.kdl").exists() {
            loader = loader.with_include("sentinel.kdl");
        }

        // Load from subdirectories
        let subdirs = ["listeners", "routes", "upstreams", "agents"];
        for subdir in subdirs {
            let dir = self.root.join(subdir);
            if dir.exists() {
                loader = loader.with_include(format!("{}/*.kdl", subdir));
            }
        }

        // Load environment-specific overrides
        if let Some(env) = environment {
            let env_file = format!("environments/{}.kdl", env);
            let env_path = self.root.join(&env_file);
            if env_path.exists() {
                loader = loader.with_include(env_file);
            }
        }

        // Exclude example and backup files
        loader = loader
            .with_exclude("*.example.kdl")
            .with_exclude("*.bak")
            .with_exclude("*~");

        loader.load()
    }
}

/// Extension trait for Config to support multi-file operations
impl Config {
    /// Load configuration from a directory
    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self> {
        let mut loader = MultiFileLoader::new(path);
        loader.load()
    }

    /// Load configuration with environment-specific overrides
    pub fn from_directory_with_env(path: impl AsRef<Path>, environment: &str) -> Result<Self> {
        let dir = ConfigDirectory::new(path);
        dir.load(Some(environment))
    }

    /// Merge another configuration into this one
    pub fn merge(&mut self, other: Config) -> Result<()> {
        // Merge listeners
        for listener in other.listeners {
            if !self.listeners.iter().any(|l| l.id == listener.id) {
                self.listeners.push(listener);
            } else {
                return Err(anyhow!("Duplicate listener ID: {}", listener.id));
            }
        }

        // Merge routes
        for route in other.routes {
            if !self.routes.iter().any(|r| r.id == route.id) {
                self.routes.push(route);
            } else {
                return Err(anyhow!("Duplicate route ID: {}", route.id));
            }
        }

        // Merge upstreams
        self.upstreams.extend(other.upstreams);

        // Merge agents
        for agent in other.agents {
            if !self.agents.iter().any(|a| a.id == agent.id) {
                self.agents.push(agent);
            } else {
                return Err(anyhow!("Duplicate agent ID: {}", agent.id));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_multi_file_loading() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        // Create test configuration files with required server block
        fs::write(
            config_dir.join("main.kdl"),
            r#"
            server {
                worker-threads 2
                max-connections 1000
            }
            limits {
                max-header-size 8192
            }
            "#,
        )
        .unwrap();

        fs::create_dir(config_dir.join("routes")).unwrap();
        fs::write(
            config_dir.join("routes/api.kdl"),
            r#"
            route "api" {
                path "/api/*"
                upstream "backend"
            }
            "#,
        )
        .unwrap();

        // Load configuration
        let mut loader = MultiFileLoader::new(config_dir);
        let config = loader.load();

        assert!(config.is_ok(), "Config load failed: {:?}", config.err());
    }

    #[test]
    fn test_duplicate_detection() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        // Create files with duplicate routes
        fs::write(
            config_dir.join("routes1.kdl"),
            r#"
            route "api" {
                path "/api/*"
            }
            "#,
        )
        .unwrap();

        fs::write(
            config_dir.join("routes2.kdl"),
            r#"
            route "api" {
                path "/api/v2/*"
            }
            "#,
        )
        .unwrap();

        let mut loader = MultiFileLoader::new(config_dir);
        let result = loader.load();

        // Should fail due to duplicate route ID
        assert!(result.is_err());
    }

    #[test]
    fn test_environment_overrides() {
        let temp_dir = TempDir::new().unwrap();
        let config_dir = temp_dir.path();

        // Create main config with required server block
        fs::write(
            config_dir.join("sentinel.kdl"),
            r#"
            server {
                worker-threads 2
                max-connections 1000
            }
            limits {
                max-connections 1000
            }
            "#,
        )
        .unwrap();

        // Create environment override
        fs::create_dir(config_dir.join("environments")).unwrap();
        fs::write(
            config_dir.join("environments/production.kdl"),
            r#"
            limits {
                max-connections 10000
            }
            "#,
        )
        .unwrap();

        // Load with production environment
        let config_dir = ConfigDirectory::new(config_dir);
        let config = config_dir.load(Some("production"));

        assert!(config.is_ok(), "Config load failed: {:?}", config.err());
        // In a real implementation, we'd verify the override was applied
    }
}
