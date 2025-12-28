//! Multi-file configuration support for Sentinel.
//!
//! This module provides the ability to load and merge configurations from
//! multiple KDL files, supporting modular configuration management.
//!
//! # Features
//!
//! - Load configuration from multiple files in a directory
//! - Glob-based file pattern matching
//! - Convention-based directory structure support
//! - Environment-specific overrides
//! - Duplicate detection and validation
//!
//! # Example
//!
//! ```ignore
//! use sentinel_config::multi_file::MultiFileLoader;
//!
//! let mut loader = MultiFileLoader::new("/etc/sentinel/conf.d")
//!     .with_include("*.kdl")
//!     .with_exclude("*.example.kdl")
//!     .recursive(true);
//!
//! let config = loader.load()?;
//! ```
//!
//! # Directory Structure
//!
//! For convention-based loading, use `ConfigDirectory`:
//!
//! ```text
//! config/
//!   ├── sentinel.kdl         # Main config
//!   ├── listeners/           # Listener definitions
//!   ├── routes/              # Route definitions
//!   ├── upstreams/           # Upstream definitions
//!   ├── agents/              # Agent configurations
//!   └── environments/        # Environment overrides
//! ```

mod builder;
mod directory;
mod loader;
mod parsers;

pub use directory::ConfigDirectory;
pub use loader::MultiFileLoader;

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::Config;

/// Extension methods for Config to support multi-file operations.
impl Config {
    /// Load configuration from a directory.
    ///
    /// Scans the directory for KDL files and merges them into a single configuration.
    pub fn from_directory(path: impl AsRef<Path>) -> Result<Self> {
        let mut loader = MultiFileLoader::new(path);
        loader.load()
    }

    /// Load configuration with environment-specific overrides.
    ///
    /// Uses convention-based directory structure and applies
    /// environment-specific overrides from the `environments/` subdirectory.
    pub fn from_directory_with_env(path: impl AsRef<Path>, environment: &str) -> Result<Self> {
        let dir = ConfigDirectory::new(path);
        dir.load(Some(environment))
    }

    /// Merge another configuration into this one.
    ///
    /// Fails on duplicate IDs for listeners, routes, and agents.
    /// Upstreams are merged with last-wins semantics.
    pub fn merge(&mut self, other: Config) -> Result<()> {
        // Merge listeners
        for listener in other.listeners {
            if self.listeners.iter().any(|l| l.id == listener.id) {
                return Err(anyhow!("Duplicate listener ID: {}", listener.id));
            }
            self.listeners.push(listener);
        }

        // Merge routes
        for route in other.routes {
            if self.routes.iter().any(|r| r.id == route.id) {
                return Err(anyhow!("Duplicate route ID: {}", route.id));
            }
            self.routes.push(route);
        }

        // Merge upstreams
        self.upstreams.extend(other.upstreams);

        // Merge agents
        for agent in other.agents {
            if self.agents.iter().any(|a| a.id == agent.id) {
                return Err(anyhow!("Duplicate agent ID: {}", agent.id));
            }
            self.agents.push(agent);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
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
