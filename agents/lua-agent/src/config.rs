//! Configuration for the Lua agent
//!
//! This module defines the configuration structures and loading logic
//! for the Lua scripting agent.

use anyhow::{Context, Result};
use kdl::{KdlDocument, KdlNode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tracing::{debug, info};

use crate::sandbox::ResourceLimits;

/// Main configuration for the Lua agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaAgentConfig {
    /// Path to Unix domain socket for agent communication
    pub socket_path: PathBuf,

    /// Directory containing Lua scripts
    pub script_directory: PathBuf,

    /// Enable hot reload of scripts
    pub hot_reload: bool,

    /// Script file watch interval (seconds)
    pub watch_interval: u64,

    /// VM pool configuration
    pub vm_pool_size: usize,

    /// Maximum VM age before recreation
    pub vm_max_age_seconds: u64,

    /// Maximum executions per VM before recreation
    pub vm_max_executions: usize,

    /// Script execution timeout (milliseconds)
    pub script_timeout: Duration,

    /// Script cache size
    pub script_cache_size: u64,

    /// Script cache TTL (seconds)
    pub script_cache_ttl: u64,

    /// Resource limits for Lua VMs
    pub resource_limits: ResourceLimits,

    /// Fail open on script errors
    pub fail_open: bool,

    /// Enable script debugging
    pub debug_scripts: bool,

    /// Maximum concurrent script executions
    pub max_concurrent_executions: usize,

    /// Script priorities (script name -> priority)
    pub script_priorities: HashMap<String, i32>,

    /// Disabled scripts
    pub disabled_scripts: HashSet<String>,

    /// Global script timeout override (milliseconds)
    pub global_timeout_ms: Option<u64>,

    /// Enable performance metrics
    pub enable_metrics: bool,

    /// Metrics export interval (seconds)
    pub metrics_interval: u64,

    /// Server configuration
    pub server: ServerConfig,
}

impl Default for LuaAgentConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/var/run/sentinel/lua-agent.sock"),
            script_directory: PathBuf::from("/etc/sentinel/scripts"),
            hot_reload: true,
            watch_interval: 5,
            vm_pool_size: 10,
            vm_max_age_seconds: 300,
            vm_max_executions: 1000,
            script_timeout: Duration::from_millis(50),
            script_cache_size: 100,
            script_cache_ttl: 60,
            resource_limits: ResourceLimits::default(),
            fail_open: false,
            debug_scripts: false,
            max_concurrent_executions: 100,
            script_priorities: HashMap::new(),
            disabled_scripts: HashSet::new(),
            global_timeout_ms: None,
            enable_metrics: true,
            metrics_interval: 60,
            server: ServerConfig::default(),
        }
    }
}

impl LuaAgentConfig {
    /// Load configuration from KDL file
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        info!("Loading Lua agent configuration from {:?}", path);

        let content = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read config file: {:?}", path))?;

        let doc: KdlDocument = content
            .parse()
            .with_context(|| format!("Failed to parse KDL config: {:?}", path))?;

        let config = Self::from_kdl(&doc)?;

        // Validate configuration
        config.validate()?;

        info!("Loaded configuration: {:?}", config);
        Ok(config)
    }

    /// Parse configuration from KDL document
    fn from_kdl(doc: &KdlDocument) -> Result<Self> {
        let mut config = Self::default();

        for node in doc.nodes() {
            match node.name().value() {
                "socket-path" => {
                    if let Some(path) = node.entries().first().and_then(|e| e.value().as_string()) {
                        config.socket_path = PathBuf::from(path);
                    }
                }
                "scripts" => {
                    Self::parse_scripts_config(node, &mut config)?;
                }
                "vm-pool" => {
                    Self::parse_vm_pool_config(node, &mut config)?;
                }
                "resource-limits" => {
                    config.resource_limits = Self::parse_resource_limits(node)?;
                }
                "safety" => {
                    Self::parse_safety_config(node, &mut config)?;
                }
                "metrics" => {
                    Self::parse_metrics_config(node, &mut config)?;
                }
                "server" => {
                    config.server = Self::parse_server_config(node)?;
                }
                _ => {
                    debug!("Ignoring unknown config node: {}", node.name().value());
                }
            }
        }

        Ok(config)
    }

    /// Parse scripts configuration
    fn parse_scripts_config(node: &KdlNode, config: &mut Self) -> Result<()> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "directory" => {
                        if let Some(path) = child.entries().first().and_then(|e| e.value().as_string()) {
                            config.script_directory = PathBuf::from(path);
                        }
                    }
                    "hot-reload" => {
                        if let Some(enabled) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            config.hot_reload = enabled;
                        }
                    }
                    "watch-interval" => {
                        if let Some(interval) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.watch_interval = interval as u64;
                        }
                    }
                    "cache-size" => {
                        if let Some(size) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.script_cache_size = size as u64;
                        }
                    }
                    "cache-ttl" => {
                        if let Some(ttl) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.script_cache_ttl = ttl as u64;
                        }
                    }
                    "timeout" => {
                        if let Some(timeout) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.script_timeout = Duration::from_millis(timeout as u64);
                        }
                    }
                    "priority" => {
                        if let (Some(name), Some(priority)) = (
                            child.entries().get(0).and_then(|e| e.value().as_string()),
                            child.entries().get(1).and_then(|e| e.value().as_i64()),
                        ) {
                            config.script_priorities.insert(name.to_string(), priority as i32);
                        }
                    }
                    "disable" => {
                        if let Some(name) = child.entries().first().and_then(|e| e.value().as_string()) {
                            config.disabled_scripts.insert(name.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Parse VM pool configuration
    fn parse_vm_pool_config(node: &KdlNode, config: &mut Self) -> Result<()> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "size" => {
                        if let Some(size) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.vm_pool_size = size as usize;
                        }
                    }
                    "max-age" => {
                        if let Some(age) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.vm_max_age_seconds = age as u64;
                        }
                    }
                    "max-executions" => {
                        if let Some(execs) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.vm_max_executions = execs as usize;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Parse resource limits
    fn parse_resource_limits(node: &KdlNode) -> Result<ResourceLimits> {
        let mut limits = ResourceLimits::default();

        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "max-memory" => {
                        if let Some(mem) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_memory = mem as usize;
                        }
                    }
                    "max-instructions" => {
                        if let Some(instr) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_instructions = instr as usize;
                        }
                    }
                    "max-execution-time" => {
                        if let Some(time) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_execution_time = Duration::from_millis(time as u64);
                        }
                    }
                    "max-recursion-depth" => {
                        if let Some(depth) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_recursion_depth = depth as usize;
                        }
                    }
                    "max-string-length" => {
                        if let Some(len) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_string_length = len as usize;
                        }
                    }
                    "max-table-size" => {
                        if let Some(size) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            limits.max_table_size = size as usize;
                        }
                    }
                    "allow-filesystem" => {
                        if let Some(allow) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            limits.allow_filesystem = allow;
                        }
                    }
                    "allow-network" => {
                        if let Some(allow) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            limits.allow_network = allow;
                        }
                    }
                    "allowed-library" => {
                        if let Some(lib) = child.entries().first().and_then(|e| e.value().as_string()) {
                            limits.allowed_libraries.insert(lib.to_string());
                        }
                    }
                    "blocked-function" => {
                        if let Some(func) = child.entries().first().and_then(|e| e.value().as_string()) {
                            limits.blocked_functions.insert(func.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(limits)
    }

    /// Parse safety configuration
    fn parse_safety_config(node: &KdlNode, config: &mut Self) -> Result<()> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "fail-open" => {
                        if let Some(enabled) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            config.fail_open = enabled;
                        }
                    }
                    "debug-scripts" => {
                        if let Some(enabled) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            config.debug_scripts = enabled;
                        }
                    }
                    "max-concurrent" => {
                        if let Some(max) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.max_concurrent_executions = max as usize;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Parse metrics configuration
    fn parse_metrics_config(node: &KdlNode, config: &mut Self) -> Result<()> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "enabled" => {
                        if let Some(enabled) = child.entries().first().and_then(|e| e.value().as_bool()) {
                            config.enable_metrics = enabled;
                        }
                    }
                    "interval" => {
                        if let Some(interval) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.metrics_interval = interval as u64;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Parse server configuration
    fn parse_server_config(node: &KdlNode) -> Result<ServerConfig> {
        let mut config = ServerConfig::default();

        if let Some(children) = node.children() {
            for child in children.nodes() {
                match child.name().value() {
                    "listen-address" => {
                        if let Some(addr) = child.entries().first().and_then(|e| e.value().as_string()) {
                            config.listen_address = addr.to_string();
                        }
                    }
                    "max-connections" => {
                        if let Some(max) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.max_connections = max as usize;
                        }
                    }
                    "connection-timeout" => {
                        if let Some(timeout) = child.entries().first().and_then(|e| e.value().as_i64()) {
                            config.connection_timeout = Duration::from_secs(timeout as u64);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Check script directory exists
        if !self.script_directory.exists() {
            return Err(anyhow::anyhow!(
                "Script directory does not exist: {:?}",
                self.script_directory
            ));
        }

        // Check VM pool size is reasonable
        if self.vm_pool_size == 0 || self.vm_pool_size > 1000 {
            return Err(anyhow::anyhow!(
                "VM pool size must be between 1 and 1000, got {}",
                self.vm_pool_size
            ));
        }

        // Check resource limits are reasonable
        if self.resource_limits.max_memory < 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "Max memory must be at least 1MB, got {}",
                self.resource_limits.max_memory
            ));
        }

        Ok(())
    }
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Listen address for HTTP API
    pub listen_address: String,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Connection timeout
    pub connection_timeout: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:9092".to_string(),
            max_connections: 1000,
            connection_timeout: Duration::from_secs(60),
        }
    }
}

/// Authentication method for scripts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    None,
    Jwt,
    ApiKey,
    Basic,
    Session,
    Certificate,
}

/// Policy engine type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEngine {
    None,
    Builtin,
    OPA,
    Oso,
    Custom,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LuaAgentConfig::default();
        assert_eq!(config.vm_pool_size, 10);
        assert_eq!(config.script_timeout, Duration::from_millis(50));
        assert!(!config.fail_open);
        assert!(config.hot_reload);
    }

    #[tokio::test]
    async fn test_parse_kdl_config() {
        let kdl = r#"
            socket-path "/var/run/lua-agent.sock"

            scripts {
                directory "/etc/sentinel/scripts"
                hot-reload true
                timeout 100
                cache-size 200
            }

            vm-pool {
                size 20
                max-age 600
                max-executions 5000
            }

            resource-limits {
                max-memory 104857600
                max-instructions 50000000
                max-execution-time 200
                allow-filesystem false
                allow-network false
            }

            safety {
                fail-open true
                debug-scripts false
                max-concurrent 200
            }
        "#;

        let doc: KdlDocument = kdl.parse().unwrap();
        let config = LuaAgentConfig::from_kdl(&doc).unwrap();

        assert_eq!(config.socket_path, PathBuf::from("/var/run/lua-agent.sock"));
        assert_eq!(config.vm_pool_size, 20);
        assert_eq!(config.script_timeout, Duration::from_millis(100));
        assert!(config.fail_open);
        assert_eq!(config.resource_limits.max_memory, 104857600);
    }
}
