//! Multi-file configuration loader.
//!
//! This module provides `MultiFileLoader` for loading and merging
//! configurations from multiple KDL files.

use anyhow::{anyhow, Context, Result};
use glob::glob;
use kdl::KdlDocument;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::Config;

use super::builder::{ConfigBuilder, PartialConfig};

/// Multi-file configuration loader.
///
/// Provides a builder-style API for configuring how configuration files
/// are discovered and loaded from a directory.
///
/// # Example
///
/// ```ignore
/// let mut loader = MultiFileLoader::new("/etc/sentinel/conf.d")
///     .with_include("*.kdl")
///     .with_exclude("*.example.kdl")
///     .recursive(true);
///
/// let config = loader.load()?;
/// ```
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
    #[allow(dead_code)]
    allow_duplicates: bool,
    /// Strict mode - fail on warnings
    strict: bool,
    /// Loaded files tracking
    loaded_files: HashSet<PathBuf>,
}

impl MultiFileLoader {
    /// Create a new multi-file loader.
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

    /// Add include pattern.
    pub fn with_include(mut self, pattern: impl Into<String>) -> Self {
        self.include_patterns.push(pattern.into());
        self
    }

    /// Add exclude pattern.
    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.exclude_patterns.push(pattern.into());
        self
    }

    /// Set recursive scanning.
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Allow duplicate definitions.
    pub fn allow_duplicates(mut self, allow: bool) -> Self {
        self.allow_duplicates = allow;
        self
    }

    /// Enable strict mode.
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Load configuration from multiple files.
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
            self.load_file_recursive(&file, &mut merged)?;
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

    /// Load a file and recursively process its includes.
    fn load_file_recursive(&mut self, path: &Path, merged: &mut ConfigBuilder) -> Result<()> {
        // Canonicalize path to detect circular includes
        let canonical = path
            .canonicalize()
            .with_context(|| format!("Failed to resolve path: {:?}", path))?;

        // Check for circular includes
        if self.loaded_files.contains(&canonical) {
            debug!("Skipping already loaded file: {:?}", canonical);
            return Ok(());
        }

        debug!("Loading configuration from: {:?}", path);

        // Mark as loaded before processing to prevent circular includes
        self.loaded_files.insert(canonical.clone());

        // Load and parse the file
        let config = self.load_file(path)?;

        // Process includes first (depth-first)
        for include_path in &config.includes {
            let resolved = self.resolve_include_path(path, include_path)?;

            if !resolved.exists() {
                warn!(
                    "Include file not found: {:?} (referenced from {:?})",
                    resolved, path
                );
                continue;
            }

            self.load_file_recursive(&resolved, merged)?;
        }

        // Merge this file's config
        merged.merge(config)?;

        Ok(())
    }

    /// Resolve an include path relative to the including file.
    fn resolve_include_path(&self, from_file: &Path, include: &Path) -> Result<PathBuf> {
        if include.is_absolute() {
            Ok(include.to_path_buf())
        } else {
            // Relative to the directory containing the including file
            let base_dir = from_file
                .parent()
                .ok_or_else(|| anyhow!("Cannot determine parent directory of {:?}", from_file))?;
            Ok(base_dir.join(include))
        }
    }

    /// Find all configuration files matching patterns.
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

    /// Check if a file should be excluded.
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

    /// Load a single configuration file.
    fn load_file(&self, path: &Path) -> Result<PartialConfig> {
        let content =
            fs::read_to_string(path).with_context(|| format!("Failed to read file: {:?}", path))?;

        let doc: KdlDocument = content
            .parse()
            .with_context(|| format!("Failed to parse KDL file: {:?}", path))?;

        PartialConfig::from_kdl(doc, path)
    }
}
