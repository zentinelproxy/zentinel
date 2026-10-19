//! Multi-file configuration loader.
//!
//! This module provides `MultiFileLoader` for loading a configuration that is
//! split across the KDL files of a directory.
//!
//! Every file is written in the ordinary configuration format -- `system { }`,
//! `listeners { }`, `routes { }` and so on -- and the files are read as one
//! document by the same parser that reads a single file. This loader used to
//! have a parser of its own for a different dialect (bare top-level `route`,
//! `listener`, `server` nodes) that read a fraction of the settings: listener
//! TLS, route policies, filters, matches other than a path were all dropped
//! without a word, and the blocks the documentation and the shipped example
//! use (`routes { }`, `system { }`) were skipped as unknown. Sharing the
//! single-file parser means a directory reads exactly what the same text in
//! one file would, and rejects what it would reject.

use anyhow::{anyhow, Context, Result};
use glob::glob;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::Config;

/// Directory holding per-environment overrides.
///
/// Its files are alternatives to one another (`staging.kdl`,
/// `production.kdl`), so loading all of them would apply every environment at
/// once, the last one silently winning. They are only read when one is chosen,
/// through [`super::ConfigDirectory`].
const ENVIRONMENTS_DIR: &str = "environments";

/// Multi-file configuration loader.
///
/// Provides a builder-style API for configuring how configuration files
/// are discovered and loaded from a directory.
///
/// Files are found recursively and read in path order. A file that another
/// file in the directory pulls in with `include` is read once, through that
/// `include`, rather than a second time on its own -- so a directory with a
/// `zentinel.kdl` that includes `routes/*.kdl` (the documented layout) and a
/// directory of standalone fragments (`conf.d` style) both load.
///
/// # Example
///
/// ```ignore
/// let mut loader = MultiFileLoader::new("/etc/zentinel/conf.d")
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
    /// File patterns to exclude, matched against the file name and against
    /// the path relative to `base_dir`
    exclude_patterns: Vec<String>,
    /// Enable recursive directory scanning
    recursive: bool,
    /// Strict mode - fail on warnings
    strict: bool,
    /// Files read after everything else, in order (environment overrides)
    overlays: Vec<PathBuf>,
}

/// The files of a directory, read as one document.
pub(crate) struct DirectorySources {
    /// KDL text of every file, includes expanded, in load order
    pub kdl: String,
    /// Every file read, in load order
    pub files: Vec<PathBuf>,
}

impl MultiFileLoader {
    /// Create a new multi-file loader.
    pub fn new(base_dir: impl AsRef<Path>) -> Self {
        Self {
            base_dir: base_dir.as_ref().to_path_buf(),
            include_patterns: vec!["*.kdl".to_string()],
            exclude_patterns: vec![],
            recursive: true,
            strict: false,
            overlays: vec![],
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

    /// Enable strict mode.
    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Read `file` after every other file, so its singleton blocks
    /// (`system`, `limits`, ...) replace the ones before it.
    pub(crate) fn with_overlay(mut self, file: impl Into<PathBuf>) -> Self {
        self.overlays.push(file.into());
        self
    }

    /// Load configuration from multiple files.
    pub fn load(&mut self) -> Result<Config> {
        info!("Loading configuration from directory: {:?}", self.base_dir);

        let sources = self.read()?;
        let config = Config::from_kdl(&sources.kdl).with_context(|| {
            format!(
                "Failed to load configuration directory {:?} ({} files)",
                self.base_dir,
                sources.files.len()
            )
        })?;

        info!(
            path = %self.base_dir.display(),
            files = sources.files.len(),
            routes = config.routes.len(),
            upstreams = config.upstreams.len(),
            agents = config.agents.len(),
            listeners = config.listeners.len(),
            "Configuration loaded successfully"
        );

        // Validate if in strict mode
        if self.strict {
            config
                .validate()
                .map_err(|e| anyhow!("Validation failed: {}", e))?;
        }

        Ok(config)
    }

    /// Read every file of the directory into one KDL document.
    pub(crate) fn read(&self) -> Result<DirectorySources> {
        let candidates = self.find_config_files()?;

        if candidates.is_empty() {
            return Err(anyhow!(
                "No configuration files found in {:?}",
                self.base_dir
            ));
        }

        // A file included by another file of the directory is not loaded on
        // its own as well: that would define its routes twice (a duplicate ID
        // error) or, for blocks such as `limits`, apply it twice in an order
        // nobody chose.
        let mut included = HashSet::new();
        for file in &candidates {
            let (_, files) = expand(file)?;
            for reached in files.iter().skip(1) {
                included.insert(canonical(reached)?);
            }
        }

        let mut roots = Vec::new();
        for file in candidates {
            if included.contains(&canonical(&file)?) {
                debug!(file = %file.display(), "Read through an include, not on its own");
            } else {
                roots.push(file);
            }
        }
        roots.extend(self.overlays.iter().cloned());

        debug!(entry_files = roots.len(), "Reading configuration directory");

        let mut kdl = String::new();
        let mut files = Vec::new();
        // Which root reached each file: two roots including the same file
        // would read it twice.
        let mut read_by: HashMap<PathBuf, PathBuf> = HashMap::new();
        for root in roots {
            let (text, reached) = expand(&root)?;
            for file in &reached {
                if let Some(other) = read_by.insert(canonical(file)?, root.clone()) {
                    return Err(anyhow!(
                        "{:?} is included by both {:?} and {:?}; each file of a \
                         configuration directory may be read only once",
                        file,
                        other,
                        root
                    ));
                }
            }
            kdl.push_str(&text);
            kdl.push('\n');
            files.extend(reached);
        }

        Ok(DirectorySources { kdl, files })
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
        // Only the part below the base directory counts: the base directory
        // itself may well sit under a hidden one (`~/.config/zentinel`).
        let relative = path
            .strip_prefix(&self.base_dir)
            .ok()
            .or_else(|| path.file_name().map(Path::new))
            .unwrap_or(path);

        // Hidden files and directories: editor lock files (`.#zentinel.kdl`),
        // `.git`, and the `..data` symlink farm of a Kubernetes ConfigMap
        // mount, whose files would otherwise be read twice.
        if relative.components().any(|c| {
            matches!(c, std::path::Component::Normal(name)
                if name.to_string_lossy().starts_with('.'))
        }) {
            return true;
        }

        if relative
            .components()
            .next()
            .is_some_and(|c| c.as_os_str() == ENVIRONMENTS_DIR)
        {
            return true;
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        // Patterns are globs ("*.example.kdl"). They were once compared as
        // plain substrings, which no glob pattern ever matched.
        for pattern in &self.exclude_patterns {
            let matches = glob::Pattern::new(pattern)
                .map(|p| p.matches(&file_name) || p.matches_path(relative))
                .unwrap_or(false);
            if matches || file_name == *pattern {
                return true;
            }
        }

        // Common exclusions
        file_name.contains(".example.") || file_name.contains(".bak") || file_name.ends_with('~')
    }
}

/// Read a file with its includes expanded, and every file that took.
fn expand(path: &Path) -> Result<(String, Vec<PathBuf>)> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {:?}", path))?;
    let mut visited = HashSet::new();
    let mut files = Vec::new();
    let text = Config::expand_includes_recursive(&content, path, &mut visited, &mut files)?;
    Ok((text, files))
}

fn canonical(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("Failed to resolve path: {:?}", path))
}
