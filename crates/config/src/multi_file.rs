//! Multi-file configuration support for Sentinel
//!
//! This module provides the ability to load and merge configurations from
//! multiple KDL files, supporting modular configuration management.

use anyhow::{anyhow, Context, Result};
use glob::glob;
use kdl::{KdlDocument, KdlEntry, KdlNode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::{
    AgentConfig, Config, LimitsConfig, ListenerConfig, LoggingConfig, MetricsConfig, RouteConfig,
    TlsConfig, UpstreamConfig,
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
                    Ok(path) if path.is_file() => {
                        // Check exclusions
                        if self.should_exclude(&path) {
                            debug!("Excluding file: {:?}", path);
                            continue;
                        }

                        if seen.insert(path.clone()) {
                            files.push(path);
                        }
                    }
                    Ok(_) => {} // Skip directories
                    Err(e) => warn!("Error scanning files: {}", e),
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
    listeners: Vec<ListenerConfig>,
    routes: Vec<RouteConfig>,
    upstreams: HashMap<String, UpstreamConfig>,
    agents: Vec<AgentConfig>,
    tls: Option<TlsConfig>,
    limits: Option<LimitsConfig>,
    logging: Option<LoggingConfig>,
    metrics: Option<MetricsConfig>,
    includes: Vec<String>,
    metadata: HashMap<String, String>,
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
                    // Handle include directives
                    if let Some(path) = node.entries().first().and_then(|e| e.value().as_string()) {
                        config.includes.push(path.to_string());
                    }
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
                "tls" if config.tls.is_none() => {
                    config.tls = Some(parse_tls(node)?);
                }
                "limits" if config.limits.is_none() => {
                    config.limits = Some(parse_limits(node)?);
                }
                "logging" if config.logging.is_none() => {
                    config.logging = Some(parse_logging(node)?);
                }
                "metrics" if config.metrics.is_none() => {
                    config.metrics = Some(parse_metrics(node)?);
                }
                "metadata" => {
                    // Store metadata for debugging
                    for entry in node.entries() {
                        if let (Some(name), value) = (entry.name(), entry.value().as_string()) {
                            config
                                .metadata
                                .insert(name.value().to_string(), value.to_string());
                        }
                    }
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
    listeners: Vec<ListenerConfig>,
    routes: Vec<RouteConfig>,
    upstreams: HashMap<String, UpstreamConfig>,
    agents: Vec<AgentConfig>,
    tls: Option<TlsConfig>,
    limits: Option<LimitsConfig>,
    logging: Option<LoggingConfig>,
    metrics: Option<MetricsConfig>,

    // Tracking for duplicates
    listener_ids: HashSet<String>,
    route_ids: HashSet<String>,
    agent_ids: HashSet<String>,
}

impl ConfigBuilder {
    fn new() -> Self {
        Self {
            listeners: Vec::new(),
            routes: Vec::new(),
            upstreams: HashMap::new(),
            agents: Vec::new(),
            tls: None,
            limits: None,
            logging: None,
            metrics: None,
            listener_ids: HashSet::new(),
            route_ids: HashSet::new(),
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
        if partial.tls.is_some() {
            if self.tls.is_some() {
                warn!("Overriding TLS config from {:?}", partial.source_file);
            }
            self.tls = partial.tls;
        }

        if partial.limits.is_some() {
            if self.limits.is_some() {
                warn!("Overriding limits config from {:?}", partial.source_file);
            }
            self.limits = partial.limits;
        }

        if partial.logging.is_some() {
            if self.logging.is_some() {
                warn!("Overriding logging config from {:?}", partial.source_file);
            }
            self.logging = partial.logging;
        }

        if partial.metrics.is_some() {
            if self.metrics.is_some() {
                warn!("Overriding metrics config from {:?}", partial.source_file);
            }
            self.metrics = partial.metrics;
        }

        Ok(())
    }

    /// Build the final configuration
    fn build(self) -> Result<Config> {
        Ok(Config {
            listeners: self.listeners,
            routes: self.routes,
            upstreams: self.upstreams,
            agents: self.agents,
            tls: self.tls.unwrap_or_default(),
            limits: self.limits.unwrap_or_default(),
            logging: self.logging.unwrap_or_default(),
            metrics: self.metrics.unwrap_or_default(),
        })
    }
}

// Parsing helper functions (stubs - would be implemented based on actual schema)
fn parse_listener(_node: &KdlNode) -> Result<ListenerConfig> {
    todo!("Implement listener parsing")
}

fn parse_route(_node: &KdlNode) -> Result<RouteConfig> {
    todo!("Implement route parsing")
}

fn parse_upstream(_node: &KdlNode) -> Result<(String, UpstreamConfig)> {
    todo!("Implement upstream parsing")
}

fn parse_agent(_node: &KdlNode) -> Result<AgentConfig> {
    todo!("Implement agent parsing")
}

fn parse_tls(_node: &KdlNode) -> Result<TlsConfig> {
    todo!("Implement TLS parsing")
}

fn parse_limits(_node: &KdlNode) -> Result<LimitsConfig> {
    todo!("Implement limits parsing")
}

fn parse_logging(_node: &KdlNode) -> Result<LoggingConfig> {
    todo!("Implement logging parsing")
}

fn parse_metrics(_node: &KdlNode) -> Result<MetricsConfig> {
    todo!("Implement metrics parsing")
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
    /// ```
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

        // Create test configuration files
        fs::write(
            config_dir.join("main.kdl"),
            r#"
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

        assert!(config.is_ok());
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

        // Create main config
        fs::write(
            config_dir.join("sentinel.kdl"),
            r#"
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

        assert!(config.is_ok());
        // In a real implementation, we'd verify the override was applied
    }
}
