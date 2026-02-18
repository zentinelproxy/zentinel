//! Bundle lock file parsing
//!
//! Parses the `bundle-versions.lock` TOML file that defines which agent
//! versions are included in the bundle.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Errors that can occur when parsing the lock file
#[derive(Debug, Error)]
pub enum LockError {
    #[error("Failed to read lock file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to parse lock file: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("Lock file not found at: {0}")]
    NotFound(String),

    #[error("Failed to fetch lock file from remote: {0}")]
    Fetch(String),
}

/// Bundle lock file structure
#[derive(Debug, Clone, Deserialize)]
pub struct BundleLock {
    /// Bundle metadata
    pub bundle: BundleInfo,

    /// Agent versions (agent name -> version)
    pub agents: HashMap<String, String>,

    /// Agent repositories (agent name -> "owner/repo")
    pub repositories: HashMap<String, String>,

    /// Optional checksums for verification
    #[serde(default)]
    pub checksums: HashMap<String, String>,
}

/// Bundle metadata
#[derive(Debug, Clone, Deserialize)]
pub struct BundleInfo {
    /// Bundle version (CalVer: YY.MM_PATCH)
    pub version: String,
}

/// Information about a bundled agent
#[derive(Debug, Clone)]
pub struct AgentInfo {
    /// Agent name (e.g., "waf", "ratelimit")
    pub name: String,

    /// Version string (e.g., "0.2.0")
    pub version: String,

    /// GitHub repository (e.g., "zentinelproxy/zentinel-agent-waf")
    pub repository: String,

    /// Binary name (e.g., "zentinel-waf-agent")
    pub binary_name: String,
}

impl BundleLock {
    /// Load the embedded lock file (compiled into the binary)
    pub fn embedded() -> Result<Self, LockError> {
        let content = include_str!(concat!(env!("OUT_DIR"), "/bundle-versions.lock"));
        Self::from_str(content)
    }

    /// Load lock file from a path
    pub fn from_file(path: &Path) -> Result<Self, LockError> {
        if !path.exists() {
            return Err(LockError::NotFound(path.display().to_string()));
        }
        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Parse lock file from string content
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(content: &str) -> Result<Self, LockError> {
        let lock: BundleLock = toml::from_str(content)?;
        Ok(lock)
    }

    /// Fetch the latest lock file from the repository
    pub async fn fetch_latest() -> Result<Self, LockError> {
        let url =
            "https://raw.githubusercontent.com/zentinelproxy/zentinel/main/bundle-versions.lock";

        let client = reqwest::Client::new();
        let response = client
            .get(url)
            .header("User-Agent", "zentinel-bundle")
            .send()
            .await
            .map_err(|e| LockError::Fetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(LockError::Fetch(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        let content = response
            .text()
            .await
            .map_err(|e| LockError::Fetch(e.to_string()))?;

        Self::from_str(&content)
    }

    /// Get information about all bundled agents
    pub fn agents(&self) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter_map(|(name, version)| {
                let repository = self.repositories.get(name)?;
                Some(AgentInfo {
                    name: name.clone(),
                    version: version.clone(),
                    repository: repository.clone(),
                    binary_name: format!("zentinel-{}-agent", name),
                })
            })
            .collect()
    }

    /// Get information about a specific agent
    pub fn agent(&self, name: &str) -> Option<AgentInfo> {
        let version = self.agents.get(name)?;
        let repository = self.repositories.get(name)?;
        Some(AgentInfo {
            name: name.to_string(),
            version: version.clone(),
            repository: repository.clone(),
            binary_name: format!("zentinel-{}-agent", name),
        })
    }

    /// Get the list of agent names
    pub fn agent_names(&self) -> Vec<&str> {
        self.agents.keys().map(|s| s.as_str()).collect()
    }
}

impl AgentInfo {
    /// Get the download URL for this agent
    ///
    /// # Arguments
    /// * `os` - Operating system (e.g., "linux", "darwin")
    /// * `arch` - Architecture (e.g., "amd64", "arm64")
    pub fn download_url(&self, os: &str, arch: &str) -> String {
        // Map our arch names to release artifact naming conventions
        let release_arch = match arch {
            "amd64" => "x86_64",
            "arm64" => "aarch64",
            _ => arch,
        };

        format!(
            "https://github.com/{}/releases/download/v{}/{}-{}-{}-{}.tar.gz",
            self.repository, self.version, self.binary_name, self.version, os, release_arch
        )
    }

    /// Get the checksum URL for this agent
    pub fn checksum_url(&self, os: &str, arch: &str) -> String {
        format!("{}.sha256", self.download_url(os, arch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_lock_file() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"
ratelimit = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
ratelimit = "zentinelproxy/zentinel-agent-ratelimit"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        assert_eq!(lock.bundle.version, "26.01_1");
        assert_eq!(lock.agents.get("waf"), Some(&"0.2.0".to_string()));
        assert_eq!(lock.agents.get("ratelimit"), Some(&"0.2.0".to_string()));
    }

    #[test]
    fn test_parse_lock_file_with_checksums() {
        let content = r#"
[bundle]
version = "26.01_2"

[agents]
waf = "0.3.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"

[checksums]
waf = "abc123def456"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        assert_eq!(lock.checksums.get("waf"), Some(&"abc123def456".to_string()));
    }

    #[test]
    fn test_parse_lock_file_empty_checksums() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        assert!(lock.checksums.is_empty());
    }

    #[test]
    fn test_parse_invalid_toml() {
        let content = "this is not valid toml {{{";
        let result = BundleLock::from_str(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_bundle_section() {
        let content = r#"
[agents]
waf = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;
        let result = BundleLock::from_str(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_agent_info() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        let agent = lock.agent("waf").unwrap();

        assert_eq!(agent.name, "waf");
        assert_eq!(agent.version, "0.2.0");
        assert_eq!(agent.binary_name, "zentinel-waf-agent");

        let url = agent.download_url("linux", "amd64");
        assert!(url.contains("zentinel-waf-agent"));
        assert!(url.contains("v0.2.0"));
        assert!(url.contains("x86_64"));
    }

    #[test]
    fn test_agent_not_found() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        assert!(lock.agent("nonexistent").is_none());
    }

    #[test]
    fn test_agent_without_repository() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"
orphan = "1.0.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        // orphan has no repository entry, so agent() should return None
        assert!(lock.agent("orphan").is_none());
        // agents() should skip orphan
        let agents = lock.agents();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "waf");
    }

    #[test]
    fn test_agent_names() {
        let content = r#"
[bundle]
version = "26.01_1"

[agents]
waf = "0.2.0"
ratelimit = "0.2.0"
denylist = "0.2.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
ratelimit = "zentinelproxy/zentinel-agent-ratelimit"
denylist = "zentinelproxy/zentinel-agent-denylist"
"#;

        let lock = BundleLock::from_str(content).unwrap();
        let names = lock.agent_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"waf"));
        assert!(names.contains(&"ratelimit"));
        assert!(names.contains(&"denylist"));
    }

    #[test]
    fn test_download_url_linux_amd64() {
        let agent = AgentInfo {
            name: "waf".to_string(),
            version: "0.2.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-waf".to_string(),
            binary_name: "zentinel-waf-agent".to_string(),
        };

        let url = agent.download_url("linux", "amd64");
        assert_eq!(
            url,
            "https://github.com/zentinelproxy/zentinel-agent-waf/releases/download/v0.2.0/zentinel-waf-agent-0.2.0-linux-x86_64.tar.gz"
        );
    }

    #[test]
    fn test_download_url_linux_arm64() {
        let agent = AgentInfo {
            name: "ratelimit".to_string(),
            version: "1.0.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-ratelimit".to_string(),
            binary_name: "zentinel-ratelimit-agent".to_string(),
        };

        let url = agent.download_url("linux", "arm64");
        assert_eq!(
            url,
            "https://github.com/zentinelproxy/zentinel-agent-ratelimit/releases/download/v1.0.0/zentinel-ratelimit-agent-1.0.0-linux-aarch64.tar.gz"
        );
    }

    #[test]
    fn test_download_url_darwin() {
        let agent = AgentInfo {
            name: "denylist".to_string(),
            version: "0.5.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-denylist".to_string(),
            binary_name: "zentinel-denylist-agent".to_string(),
        };

        let url = agent.download_url("darwin", "arm64");
        assert!(url.contains("darwin"));
        assert!(url.contains("aarch64"));
    }

    #[test]
    fn test_checksum_url() {
        let agent = AgentInfo {
            name: "waf".to_string(),
            version: "0.2.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-waf".to_string(),
            binary_name: "zentinel-waf-agent".to_string(),
        };

        let url = agent.checksum_url("linux", "amd64");
        assert!(url.ends_with(".sha256"));
        assert!(url.contains("zentinel-waf-agent"));
    }

    #[test]
    fn test_embedded_lock() {
        // This test verifies the embedded lock file can be parsed
        let lock = BundleLock::embedded().unwrap();
        assert!(!lock.bundle.version.is_empty());
        assert!(!lock.agents.is_empty());
    }

    #[test]
    fn test_embedded_lock_has_required_agents() {
        let lock = BundleLock::embedded().unwrap();

        // Core agents
        assert!(lock.agent("waf").is_some(), "waf agent should be in bundle");
        assert!(
            lock.agent("ratelimit").is_some(),
            "ratelimit agent should be in bundle"
        );
        assert!(
            lock.agent("denylist").is_some(),
            "denylist agent should be in bundle"
        );

        // Security agents
        assert!(
            lock.agent("zentinelsec").is_some(),
            "zentinelsec agent should be in bundle"
        );
        assert!(
            lock.agent("ip-reputation").is_some(),
            "ip-reputation agent should be in bundle"
        );

        // Scripting agents
        assert!(lock.agent("lua").is_some(), "lua agent should be in bundle");
        assert!(lock.agent("js").is_some(), "js agent should be in bundle");
        assert!(
            lock.agent("wasm").is_some(),
            "wasm agent should be in bundle"
        );

        // Should have many agents total
        assert!(
            lock.agents.len() >= 20,
            "bundle should have at least 20 agents"
        );
    }

    #[test]
    fn test_from_file_not_found() {
        let result = BundleLock::from_file(Path::new("/nonexistent/path/lock.toml"));
        assert!(matches!(result, Err(LockError::NotFound(_))));
    }
}
