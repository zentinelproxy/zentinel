//! Multi-file configuration support for Zentinel.
//!
//! This module loads one configuration from the KDL files of a directory. It
//! is what `zentinel -c <dir>` uses: [`Config::from_file`] hands directories
//! here.
//!
//! # Features
//!
//! - Load configuration from every `*.kdl` file in a directory, recursively
//! - Files use the ordinary configuration format and are read by the same
//!   parser as a single file, so a file can be moved into a directory as is
//! - `include` directives inside the files work as in a single file; a file
//!   that is included is not read a second time on its own
//! - Environment-specific overrides
//! - Duplicate detection and validation
//!
//! # Example
//!
//! ```ignore
//! use zentinel_config::multi_file::MultiFileLoader;
//!
//! let mut loader = MultiFileLoader::new("/etc/zentinel/conf.d")
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
//!   ├── zentinel.kdl         # Main config
//!   ├── listeners/           # Listener definitions
//!   ├── routes/              # Route definitions
//!   ├── upstreams/           # Upstream definitions
//!   ├── agents/              # Agent configurations
//!   └── environments/        # Environment overrides (read only when chosen)
//! ```

mod directory;
mod loader;

pub use directory::ConfigDirectory;
pub use loader::MultiFileLoader;

use anyhow::{anyhow, Result};
use std::path::Path;

use crate::Config;

/// Extension methods for Config to support multi-file operations.
impl Config {
    /// Load configuration from a directory.
    ///
    /// Reads every KDL file of the directory as one configuration.
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

    const SYSTEM: &str = "system {\n    worker-threads 2\n}\n";
    const LISTENERS: &str =
        "listeners {\n    listener \"http\" {\n        address \"127.0.0.1:8080\"\n        protocol \"http\"\n    }\n}\n";
    const UPSTREAMS: &str =
        "upstreams {\n    upstream \"backend\" {\n        target \"127.0.0.1:9000\"\n    }\n}\n";

    fn write(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn route(id: &str, prefix: &str) -> String {
        format!(
            "routes {{\n    route \"{id}\" {{\n        matches {{\n            path-prefix \"{prefix}\"\n        }}\n        upstream \"backend\"\n    }}\n}}\n"
        )
    }

    /// The layout the documentation and `config/example-multi-file` use: an
    /// entry file that includes the rest. Each file must be read once, through
    /// its include, and not again on its own.
    #[test]
    fn entry_file_with_includes_reads_each_file_once() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(
            dir,
            "zentinel.kdl",
            &format!("{SYSTEM}include \"listeners/*.kdl\"\ninclude \"upstreams/*.kdl\"\ninclude \"routes/*.kdl\"\n"),
        );
        write(dir, "listeners/http.kdl", LISTENERS);
        write(dir, "upstreams/backends.kdl", UPSTREAMS);
        write(dir, "routes/api.kdl", &route("api", "/api"));
        write(dir, "routes/web.kdl", &route("web", "/"));

        let config = Config::from_directory(dir).expect("directory should load");
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.upstreams.len(), 1);
        let mut ids: Vec<_> = config.routes.iter().map(|r| r.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, ["api", "web"]);
    }

    /// A `conf.d` directory: fragments that know nothing of each other.
    #[test]
    fn standalone_fragments_are_merged() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "00-system.kdl", SYSTEM);
        write(dir, "10-listeners.kdl", LISTENERS);
        write(dir, "20-upstreams.kdl", UPSTREAMS);
        write(dir, "routes/api.kdl", &route("api", "/api"));

        let config = Config::from_directory(dir).expect("directory should load");
        assert_eq!(config.routes.len(), 1);
        assert_eq!(config.routes[0].upstream.as_deref(), Some("backend"));
    }

    /// The loader used to parse with a reduced parser of its own, which
    /// dropped listener TLS, route policies and filters without a word. The
    /// same text must read the same from a directory as from one file.
    #[test]
    fn a_directory_reads_what_a_single_file_reads() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        let text = format!(
            "{SYSTEM}{UPSTREAMS}\
             listeners {{\n    listener \"https\" {{\n        address \"127.0.0.1:8443\"\n        protocol \"https\"\n        tls {{\n            cert-file \"/tmp/c.crt\"\n            key-file \"/tmp/c.key\"\n        }}\n    }}\n}}\n\
             routes {{\n    route \"api\" {{\n        matches {{\n            path-prefix \"/api\"\n            method \"GET\"\n        }}\n        upstream \"backend\"\n        policies {{\n            timeout-secs 7\n        }}\n    }}\n}}\n"
        );
        write(dir, "zentinel.kdl", &text);

        let from_dir = Config::from_directory(dir).unwrap();
        let from_text = Config::from_kdl(&text).unwrap();

        assert!(
            from_dir.listeners[0].tls.is_some(),
            "listener TLS was dropped"
        );
        assert_eq!(from_dir.routes[0].policies.timeout_secs, Some(7));
        assert_eq!(
            format!("{:?}", from_dir.routes[0].matches),
            format!("{:?}", from_text.routes[0].matches)
        );
        assert_eq!(from_dir.routes[0].matches.len(), 2);
    }

    /// The old loader's dialect -- bare `route` and `server` nodes at the top
    /// level -- is rejected loudly, as it would be in a single file, rather
    /// than half read.
    #[test]
    fn bare_top_level_nodes_are_rejected() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}"));
        write(
            dir,
            "routes.kdl",
            "route \"api\" {\n    path \"/api/*\"\n}\n",
        );

        let error = format!("{:#}", Config::from_directory(dir).unwrap_err());
        assert!(error.contains("'route'"), "{error}");
        assert!(error.contains("Did you mean 'routes'"), "{error}");
    }

    #[test]
    fn duplicate_route_across_files_is_rejected() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}{UPSTREAMS}"));
        write(dir, "routes1.kdl", &route("api", "/api"));
        write(dir, "routes2.kdl", &route("api", "/api/v2"));

        let error = format!("{:#}", Config::from_directory(dir).unwrap_err());
        assert!(error.contains("Duplicate route ID 'api'"), "{error}");
    }

    #[test]
    fn a_file_included_twice_is_rejected() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(
            dir,
            "a.kdl",
            &format!("{SYSTEM}{LISTENERS}include \"shared/*.kdl\"\n"),
        );
        write(dir, "b.kdl", "include \"shared/*.kdl\"\n");
        write(dir, "shared/upstreams.kdl", UPSTREAMS);

        let error = format!("{:#}", Config::from_directory(dir).unwrap_err());
        assert!(error.contains("is included by both"), "{error}");
    }

    /// Circular includes are an error, as they are for a single file. The
    /// loader used to skip them silently.
    #[test]
    fn circular_includes_are_rejected() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "a.kdl", &format!("include \"b.kdl\"\n{SYSTEM}"));
        write(dir, "b.kdl", &format!("include \"a.kdl\"\n{LISTENERS}"));

        let error = format!("{:#}", Config::from_directory(dir).unwrap_err());
        assert!(error.contains("Circular include"), "{error}");
    }

    #[test]
    fn hidden_backup_and_example_files_are_skipped() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}{UPSTREAMS}"));
        write(dir, "routes.kdl", &route("api", "/api"));
        // Each of these would be a duplicate route if it were read.
        write(dir, ".#routes.kdl", &route("api", "/api"));
        write(dir, "..data/routes.kdl", &route("api", "/api"));
        write(dir, "routes.example.kdl", &route("api", "/api"));
        write(dir, "routes.kdl.bak", &route("api", "/api"));

        let config = Config::from_directory(dir).expect("only main and routes are read");
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn exclude_patterns_are_globs() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}{UPSTREAMS}"));
        write(dir, "routes.kdl", &route("api", "/api"));
        write(dir, "routes.draft.kdl", &route("api", "/api"));

        let config = MultiFileLoader::new(dir)
            .with_exclude("*.draft.kdl")
            .load()
            .expect("the draft is excluded");
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn environment_overrides_apply_only_when_chosen() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(
            dir,
            "zentinel.kdl",
            &format!("{SYSTEM}{LISTENERS}limits {{\n    max-header-count 100\n}}\n"),
        );
        write(
            dir,
            "environments/production.kdl",
            "limits {\n    max-header-count 50\n}\n",
        );
        write(
            dir,
            "environments/staging.kdl",
            "limits {\n    max-header-count 75\n}\n",
        );

        // Without an environment, none of them is read.
        let base = Config::from_directory(dir).unwrap();
        assert_eq!(base.limits.max_header_count, 100);

        let production = Config::from_directory_with_env(dir, "production").unwrap();
        assert_eq!(production.limits.max_header_count, 50);

        let error = Config::from_directory_with_env(dir, "qa").unwrap_err();
        assert!(error.to_string().contains("'qa'"), "{error}");
    }

    #[test]
    fn namespaces_load_from_a_directory() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}"));
        write(
            dir,
            "namespaces/api.kdl",
            "namespace \"api\" {\n    upstreams {\n        upstream \"backend\" {\n            target \"127.0.0.1:8080\"\n        }\n    }\n}\n",
        );

        let config = Config::from_directory(dir).unwrap();
        assert_eq!(config.namespaces.len(), 1);
        assert_eq!(config.namespaces[0].id, "api");
        assert_eq!(config.namespaces[0].upstreams.len(), 1);
    }

    /// `Config::from_file` is what the CLI, the proxy and reload call; a
    /// directory used to fail there with "Is a directory" (#541).
    #[test]
    fn from_file_accepts_a_directory() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(dir, "main.kdl", &format!("{SYSTEM}{LISTENERS}{UPSTREAMS}"));
        write(dir, "routes/api.kdl", &route("api", "/api"));

        let config = Config::from_file(dir).expect("a directory should load");
        assert_eq!(config.routes.len(), 1);
    }

    #[test]
    fn source_files_lists_every_file_read() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path();
        write(
            dir,
            "zentinel.kdl",
            &format!("{SYSTEM}{LISTENERS}include \"upstreams.kdl\"\n"),
        );
        write(dir, "upstreams.kdl", UPSTREAMS);
        write(dir, "routes/api.kdl", &route("api", "/api"));

        // Included files are reached through the canonical path (on macOS the
        // temporary directory is a symlink), so compare canonical paths.
        let root = dir.canonicalize().unwrap();
        let names = |files: Vec<std::path::PathBuf>| -> Vec<String> {
            files
                .iter()
                .map(|f| {
                    let f = f.canonicalize().unwrap();
                    f.strip_prefix(&root).unwrap().display().to_string()
                })
                .collect()
        };

        assert_eq!(
            names(Config::source_files(dir).unwrap()),
            ["routes/api.kdl", "zentinel.kdl", "upstreams.kdl"]
        );
        // A single file with includes lists them too.
        assert_eq!(
            names(Config::source_files(dir.join("zentinel.kdl")).unwrap()),
            ["zentinel.kdl", "upstreams.kdl"]
        );
    }
}
