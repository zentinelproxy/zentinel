//! Convention-based configuration directory support.
//!
//! This module provides `ConfigDirectory` for loading configuration
//! from a structured directory layout.

use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::Config;

use super::loader::MultiFileLoader;

/// Configuration directory structure support.
///
/// Provides convention-based loading from a standard directory layout:
///
/// ```text
/// config/
///   ├── zentinel.kdl         # Main config
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
    /// Every file of the directory is read, as by [`MultiFileLoader`]; the
    /// layout above is a convention, not a filter. `environments/` is the
    /// exception: only the chosen environment's file is read, and last, so
    /// that its `system`, `limits` and other single blocks replace the base
    /// ones.
    pub fn load(&self, environment: Option<&str>) -> Result<Config> {
        let mut loader = MultiFileLoader::new(&self.root);

        if let Some(env) = environment {
            let env_path = self.root.join("environments").join(format!("{env}.kdl"));
            if !env_path.is_file() {
                // Asking for an environment that has no file used to load the
                // base configuration as if nothing had been asked.
                return Err(anyhow!(
                    "No overrides for environment '{env}': {:?} does not exist",
                    env_path
                ));
            }
            loader = loader.with_overlay(env_path);
        }

        loader.load()
    }
}
