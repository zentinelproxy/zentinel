//! Bundle lock file parsing
//!
//! Parses the `bundle-versions.lock` TOML file that defines which agent
//! versions are included in the bundle. Also supports fetching bundle
//! metadata from the Zentinel API (`api.zentinelproxy.io`).

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// API endpoint for the Zentinel bundle registry.
/// Trailing slash avoids a 308 redirect from Cloudflare Pages.
const API_BUNDLE_URL: &str = "https://api.zentinelproxy.io/v1/bundle/";

/// Legacy lock file URL (backward compatibility)
const LEGACY_LOCK_URL: &str =
    "https://raw.githubusercontent.com/zentinelproxy/zentinel/main/bundle-versions.lock";

/// Maximum schema version this CLI understands
const MAX_SCHEMA_VERSION: u32 = 1;

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

    #[error(
        "Unsupported API schema version {version} (max supported: {max}). Please update zentinel."
    )]
    UnsupportedSchema { version: u32, max: u32 },
}

// ---------------------------------------------------------------------------
// API JSON response types
// ---------------------------------------------------------------------------

/// JSON response from `GET /v1/bundle/`
#[derive(Debug, Deserialize)]
pub struct ApiBundleResponse {
    pub schema_version: u32,
    pub bundle: ApiBundleMeta,
    pub agents: HashMap<String, ApiBundleAgent>,
}

/// Bundle-level metadata from the API
#[derive(Debug, Deserialize)]
pub struct ApiBundleMeta {
    pub version: String,
    #[allow(dead_code)]
    pub generated_at: String,
}

/// Per-agent data from the API bundle endpoint
#[derive(Debug, Deserialize)]
pub struct ApiBundleAgent {
    pub version: String,
    pub repository: String,
    pub binary_name: String,
    #[serde(default)]
    pub download_urls: HashMap<String, String>,
    #[serde(default)]
    pub checksums: HashMap<String, String>,
}

impl From<ApiBundleResponse> for BundleLock {
    fn from(api: ApiBundleResponse) -> Self {
        let mut agents = HashMap::new();
        let mut repositories = HashMap::new();
        let mut binary_names = HashMap::new();
        let mut download_urls = HashMap::new();
        let mut platforms = HashMap::new();

        for (name, agent) in &api.agents {
            agents.insert(name.clone(), agent.version.clone());
            repositories.insert(name.clone(), agent.repository.clone());
            binary_names.insert(name.clone(), agent.binary_name.clone());
            let mut published: Vec<String> = agent.download_urls.keys().cloned().collect();
            published.sort();
            platforms.insert(name.clone(), published);

            // Store precomputed download URLs keyed as "agent-os-arch"
            for (platform, url) in &agent.download_urls {
                download_urls.insert(format!("{}-{}", name, platform), url.clone());
            }
        }

        BundleLock {
            bundle: BundleInfo {
                version: api.bundle.version,
                platforms: Vec::new(),
            },
            agents,
            repositories,
            binary_names,
            platforms,
            checksums: HashMap::new(),
            precomputed_urls: download_urls,
        }
    }
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

    /// Optional binary name overrides (agent name -> asset prefix)
    /// When present, used instead of the default "zentinel-{name}-agent" pattern.
    #[serde(default)]
    pub binary_names: HashMap<String, String>,

    /// Per-agent platform lists (agent name -> ["linux-x86_64", ...]),
    /// overriding `[bundle] platforms` for agents released on fewer or more.
    #[serde(default)]
    pub platforms: HashMap<String, Vec<String>>,

    /// Optional checksums for verification
    #[serde(default)]
    pub checksums: HashMap<String, String>,

    /// Precomputed download URLs from the API (not in TOML, populated by API fetch).
    /// Keys are "agent-platform" (e.g., "waf-linux-x86_64"), values are full URLs.
    #[serde(skip)]
    pub precomputed_urls: HashMap<String, String>,
}

/// Bundle metadata
#[derive(Debug, Clone, Deserialize)]
pub struct BundleInfo {
    /// Bundle version (CalVer: YY.MM_PATCH)
    pub version: String,

    /// Platforms every agent is released for ("linux-x86_64", ...), unless
    /// `[platforms]` says otherwise for that agent. Empty in lock files that
    /// predate this field, which means "unknown": the installer then tries
    /// the download and reports what the server says.
    #[serde(default)]
    pub platforms: Vec<String>,
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

    /// Precomputed download URLs from the API, keyed by platform (e.g., "linux-x86_64")
    pub precomputed_urls: HashMap<String, String>,

    /// Platforms this release is published for; empty means unknown.
    pub platforms: Vec<String>,
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

    /// Fetch the latest bundle metadata, trying the API first with legacy fallback.
    ///
    /// Order:
    /// 1. `ZENTINEL_API_URL` env var (if set) — for self-hosted registries
    /// 2. `api.zentinelproxy.io/v1/bundle/` — primary API
    /// 3. `raw.githubusercontent.com/.../bundle-versions.lock` — legacy fallback
    pub async fn fetch_latest() -> Result<Self, LockError> {
        let client = reqwest::Client::builder()
            .user_agent("zentinel-bundle")
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| LockError::Fetch(e.to_string()))?;

        // Determine API URL (env override or default)
        let api_url =
            std::env::var("ZENTINEL_API_URL").unwrap_or_else(|_| API_BUNDLE_URL.to_string());

        // Try API endpoint first
        match Self::fetch_from_api(&client, &api_url).await {
            Ok(lock) => return Ok(lock),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    url = %api_url,
                    "API fetch failed, falling back to legacy lock file"
                );
            }
        }

        // Fall back to legacy raw GitHub URL
        Self::fetch_from_legacy(&client).await
    }

    /// Fetch bundle metadata from the JSON API
    async fn fetch_from_api(client: &reqwest::Client, url: &str) -> Result<Self, LockError> {
        let response = client
            .get(url)
            .header("Accept", "application/json")
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

        let body = response
            .text()
            .await
            .map_err(|e| LockError::Fetch(e.to_string()))?;

        let api_response: ApiBundleResponse = serde_json::from_str(&body)
            .map_err(|e| LockError::Fetch(format!("Invalid API response: {}", e)))?;

        // Reject unknown schema versions
        if api_response.schema_version > MAX_SCHEMA_VERSION {
            return Err(LockError::UnsupportedSchema {
                version: api_response.schema_version,
                max: MAX_SCHEMA_VERSION,
            });
        }

        Ok(BundleLock::from(api_response))
    }

    /// Fetch the legacy TOML lock file from raw.githubusercontent.com
    async fn fetch_from_legacy(client: &reqwest::Client) -> Result<Self, LockError> {
        let response = client
            .get(LEGACY_LOCK_URL)
            .send()
            .await
            .map_err(|e| LockError::Fetch(e.to_string()))?;

        if !response.status().is_success() {
            return Err(LockError::Fetch(format!(
                "HTTP {} from {}",
                response.status(),
                LEGACY_LOCK_URL
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
                let binary_name = self
                    .binary_names
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("zentinel-{}-agent", name));
                let precomputed_urls = self.precomputed_urls_for(name);
                Some(AgentInfo {
                    name: name.clone(),
                    version: version.clone(),
                    repository: repository.clone(),
                    binary_name,
                    precomputed_urls,
                    platforms: self.platforms_for(name),
                })
            })
            .collect()
    }

    /// Get information about a specific agent
    pub fn agent(&self, name: &str) -> Option<AgentInfo> {
        let version = self.agents.get(name)?;
        let repository = self.repositories.get(name)?;
        let binary_name = self
            .binary_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| format!("zentinel-{}-agent", name));
        let precomputed_urls = self.precomputed_urls_for(name);
        Some(AgentInfo {
            name: name.to_string(),
            version: version.clone(),
            repository: repository.clone(),
            binary_name,
            precomputed_urls,
            platforms: self.platforms_for(name),
        })
    }

    /// Platforms an agent is published for: its `[platforms]` entry, or the
    /// bundle-wide list.
    fn platforms_for(&self, agent_name: &str) -> Vec<String> {
        self.platforms
            .get(agent_name)
            .cloned()
            .unwrap_or_else(|| self.bundle.platforms.clone())
    }

    /// Extract precomputed URLs for a specific agent from the flat map
    fn precomputed_urls_for(&self, agent_name: &str) -> HashMap<String, String> {
        let prefix = format!("{}-", agent_name);
        self.precomputed_urls
            .iter()
            .filter_map(|(key, url)| {
                key.strip_prefix(&prefix)
                    .map(|platform| (platform.to_string(), url.clone()))
            })
            .collect()
    }

    /// Get the list of agent names
    pub fn agent_names(&self) -> Vec<&str> {
        self.agents.keys().map(|s| s.as_str()).collect()
    }
}

impl AgentInfo {
    /// The release platform name for an OS and proxy-style arch
    /// ("linux", "amd64" -> "linux-x86_64").
    pub fn platform_key(os: &str, arch: &str) -> String {
        let release_arch = match arch {
            "amd64" => "x86_64",
            "arm64" => "aarch64",
            _ => arch,
        };
        format!("{}-{}", os, release_arch)
    }

    /// Whether this release is published for the platform. An agent with no
    /// platform list (an older lock file) is assumed to be.
    pub fn supports(&self, os: &str, arch: &str) -> bool {
        self.platforms.is_empty() || self.platforms.contains(&Self::platform_key(os, arch))
    }
    /// Get the download URL for this agent.
    ///
    /// Uses a precomputed URL from the API when available, otherwise constructs
    /// the URL from the repository, version, and binary name.
    ///
    /// # Arguments
    /// * `os` - Operating system (e.g., "linux", "darwin")
    /// * `arch` - Architecture (e.g., "amd64", "arm64")
    pub fn download_url(&self, os: &str, arch: &str) -> String {
        // Check for precomputed URL from API
        let platform_key = Self::platform_key(os, arch);
        if let Some(url) = self.precomputed_urls.get(&platform_key) {
            return url.clone();
        }

        // Fall back to constructed URL
        format!(
            "https://github.com/{}/releases/download/v{}/{}-{}-{}.tar.gz",
            self.repository, self.version, self.binary_name, self.version, platform_key
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
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
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
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
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
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
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
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
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
    fn test_platforms_default_and_override() {
        let content = r#"
[bundle]
version = "26.10_01"
platforms = ["linux-x86_64", "linux-aarch64", "darwin-aarch64"]

[agents]
waf = "0.4.0"
odd = "0.1.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
odd = "zentinelproxy/zentinel-agent-odd"

[platforms]
odd = ["linux-x86_64"]
"#;
        let lock = BundleLock::from_str(content).unwrap();
        let waf = lock.agent("waf").unwrap();
        assert!(waf.supports("linux", "amd64"));
        assert!(waf.supports("darwin", "arm64"));
        assert!(!waf.supports("darwin", "amd64"));
        let odd = lock.agent("odd").unwrap();
        assert!(odd.supports("linux", "amd64"));
        assert!(!odd.supports("linux", "arm64"));
    }

    #[test]
    fn test_lock_without_platforms_supports_everything() {
        let content = r#"
[bundle]
version = "26.03_01"

[agents]
waf = "0.3.0"

[repositories]
waf = "zentinelproxy/zentinel-agent-waf"
"#;
        let lock = BundleLock::from_str(content).unwrap();
        assert!(lock.agent("waf").unwrap().supports("darwin", "amd64"));
    }

    #[test]
    fn test_embedded_lock_lists_platforms() {
        // Every entry must say which platforms its release was built for, so
        // `scripts/check-bundle-lock.py` can prove each asset exists and the
        // installer can refuse unpublished platforms.
        let lock = BundleLock::embedded().unwrap();
        for agent in lock.agents() {
            assert!(
                !agent.platforms.is_empty(),
                "{} has no platform list",
                agent.name
            );
        }
    }

    #[test]
    fn test_from_file_not_found() {
        let result = BundleLock::from_file(Path::new("/nonexistent/path/lock.toml"));
        assert!(matches!(result, Err(LockError::NotFound(_))));
    }

    #[test]
    fn test_api_bundle_response_conversion() {
        let mut agents = HashMap::new();
        let mut download_urls = HashMap::new();
        download_urls.insert(
            "linux-x86_64".to_string(),
            "https://example.com/waf-linux-x86_64.tar.gz".to_string(),
        );
        download_urls.insert(
            "darwin-aarch64".to_string(),
            "https://example.com/waf-darwin-aarch64.tar.gz".to_string(),
        );

        agents.insert(
            "waf".to_string(),
            ApiBundleAgent {
                version: "0.3.0".to_string(),
                repository: "zentinelproxy/zentinel-agent-waf".to_string(),
                binary_name: "zentinel-waf-agent".to_string(),
                download_urls,
                checksums: HashMap::new(),
            },
        );

        let api = ApiBundleResponse {
            schema_version: 1,
            bundle: ApiBundleMeta {
                version: "26.02_13".to_string(),
                generated_at: "2026-02-23T00:00:00Z".to_string(),
            },
            agents,
        };

        let lock = BundleLock::from(api);
        assert_eq!(lock.bundle.version, "26.02_13");
        assert_eq!(lock.agents.get("waf"), Some(&"0.3.0".to_string()));
        assert_eq!(
            lock.binary_names.get("waf"),
            Some(&"zentinel-waf-agent".to_string())
        );

        // Precomputed URLs should be populated
        let agent = lock.agent("waf").unwrap();
        let url = agent.download_url("linux", "amd64");
        assert_eq!(url, "https://example.com/waf-linux-x86_64.tar.gz");

        let url = agent.download_url("darwin", "arm64");
        assert_eq!(url, "https://example.com/waf-darwin-aarch64.tar.gz");
    }

    #[test]
    fn test_precomputed_url_fallback() {
        // When no precomputed URL exists, should fall back to constructed URL
        let agent = AgentInfo {
            name: "waf".to_string(),
            version: "0.3.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-waf".to_string(),
            binary_name: "zentinel-waf-agent".to_string(),
            precomputed_urls: HashMap::new(),
            platforms: Vec::new(),
        };

        let url = agent.download_url("linux", "amd64");
        assert_eq!(
            url,
            "https://github.com/zentinelproxy/zentinel-agent-waf/releases/download/v0.3.0/zentinel-waf-agent-0.3.0-linux-x86_64.tar.gz"
        );
    }

    #[test]
    fn test_precomputed_url_used_when_available() {
        let mut precomputed = HashMap::new();
        precomputed.insert(
            "linux-x86_64".to_string(),
            "https://api.example.com/waf-custom.tar.gz".to_string(),
        );

        let agent = AgentInfo {
            name: "waf".to_string(),
            version: "0.3.0".to_string(),
            repository: "zentinelproxy/zentinel-agent-waf".to_string(),
            binary_name: "zentinel-waf-agent".to_string(),
            precomputed_urls: precomputed,
            platforms: Vec::new(),
        };

        // Should use precomputed URL
        let url = agent.download_url("linux", "amd64");
        assert_eq!(url, "https://api.example.com/waf-custom.tar.gz");

        // Should fall back for missing platform
        let url = agent.download_url("darwin", "arm64");
        assert!(url.contains("github.com"));
    }

    #[test]
    fn test_unsupported_schema_version_error() {
        let err = LockError::UnsupportedSchema {
            version: 99,
            max: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("99"));
        assert!(msg.contains("update zentinel"));
    }
}
