//! Convention-based configuration directory support.
//!
//! This module provides `ConfigDirectory` for loading configuration
//! from a structured directory layout.

use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::Config;

use super::loader::MultiFileLoader;

/// Configuration directory structure support.
///
/// Provides convention-based loading from a standard directory layout:
///
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
pub struct ConfigDirectory {
    root: PathBuf,
}

impl ConfigDirectory {
    /// Create a new config directory handler.
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    /// Load configuration using convention-based structure.
    ///
    /// Optionally applies environment-specific overrides.
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
