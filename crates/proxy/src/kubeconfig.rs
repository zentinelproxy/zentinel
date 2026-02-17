//! Kubeconfig file parsing for Kubernetes service discovery
//!
//! This module parses kubeconfig files (~/.kube/config) to extract:
//! - Cluster API server URL
//! - Authentication credentials (token, client certificate, or exec)
//! - CA certificate for TLS verification
//!
//! # Supported Authentication Methods
//!
//! - **Token**: Bearer token authentication
//! - **Client Certificate**: mTLS with client cert/key
//! - **Exec**: External command to get credentials (e.g., aws eks get-token)
//!
//! # Example
//!
//! ```ignore
//! use zentinel_proxy::kubeconfig::Kubeconfig;
//!
//! let config = Kubeconfig::from_file("~/.kube/config")?;
//! let context = config.current_context()?;
//! let (cluster, user) = config.get_context_config(&context)?;
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{debug, trace, warn};

/// Kubeconfig file structure
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Kubeconfig {
    /// API version (usually "v1")
    #[serde(default)]
    pub api_version: String,
    /// Kind (usually "Config")
    #[serde(default)]
    pub kind: String,
    /// Current context name
    pub current_context: Option<String>,
    /// List of clusters
    #[serde(default)]
    pub clusters: Vec<NamedCluster>,
    /// List of contexts
    #[serde(default)]
    pub contexts: Vec<NamedContext>,
    /// List of users
    #[serde(default)]
    pub users: Vec<NamedUser>,
}

/// Named cluster entry
#[derive(Debug, Clone, Deserialize)]
pub struct NamedCluster {
    /// Cluster name
    pub name: String,
    /// Cluster configuration
    pub cluster: ClusterConfig,
}

/// Cluster configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClusterConfig {
    /// API server URL
    pub server: String,
    /// CA certificate data (base64 encoded)
    pub certificate_authority_data: Option<String>,
    /// Path to CA certificate file
    pub certificate_authority: Option<String>,
    /// Skip TLS verification (not recommended)
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
}

/// Named context entry
#[derive(Debug, Clone, Deserialize)]
pub struct NamedContext {
    /// Context name
    pub name: String,
    /// Context configuration
    pub context: ContextConfig,
}

/// Context configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ContextConfig {
    /// Cluster name reference
    pub cluster: String,
    /// User name reference
    pub user: String,
    /// Default namespace (optional)
    pub namespace: Option<String>,
}

/// Named user entry
#[derive(Debug, Clone, Deserialize)]
pub struct NamedUser {
    /// User name
    pub name: String,
    /// User configuration
    pub user: UserConfig,
}

/// User authentication configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UserConfig {
    /// Bearer token
    pub token: Option<String>,
    /// Path to token file
    pub token_file: Option<String>,
    /// Client certificate data (base64 encoded)
    pub client_certificate_data: Option<String>,
    /// Path to client certificate file
    pub client_certificate: Option<String>,
    /// Client key data (base64 encoded)
    pub client_key_data: Option<String>,
    /// Path to client key file
    pub client_key: Option<String>,
    /// Username for basic auth
    pub username: Option<String>,
    /// Password for basic auth
    pub password: Option<String>,
    /// Exec-based authentication
    pub exec: Option<ExecConfig>,
}

/// Exec-based authentication configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecConfig {
    /// API version for exec credentials
    pub api_version: Option<String>,
    /// Command to execute
    pub command: String,
    /// Arguments for the command
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables
    #[serde(default)]
    pub env: Vec<ExecEnv>,
    /// Whether to provide cluster info
    #[serde(default)]
    pub provide_cluster_info: bool,
}

/// Environment variable for exec
#[derive(Debug, Clone, Deserialize)]
pub struct ExecEnv {
    /// Variable name
    pub name: String,
    /// Variable value
    pub value: String,
}

/// Exec credential response
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecCredential {
    /// API version
    pub api_version: Option<String>,
    /// Kind (ExecCredential)
    pub kind: Option<String>,
    /// Status with credentials
    pub status: Option<ExecCredentialStatus>,
}

/// Exec credential status
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecCredentialStatus {
    /// Expiration timestamp
    pub expiration_timestamp: Option<String>,
    /// Bearer token
    pub token: Option<String>,
    /// Client certificate data
    pub client_certificate_data: Option<String>,
    /// Client key data
    pub client_key_data: Option<String>,
}

/// Resolved authentication for a Kubernetes cluster
#[derive(Debug, Clone)]
pub enum KubeAuth {
    /// Bearer token authentication
    Token(String),
    /// Client certificate authentication (cert, key in PEM format)
    ClientCert { cert: Vec<u8>, key: Vec<u8> },
    /// No authentication
    None,
}

/// Resolved Kubernetes cluster configuration
#[derive(Debug, Clone)]
pub struct ResolvedKubeConfig {
    /// API server URL
    pub server: String,
    /// CA certificate (PEM format)
    pub ca_cert: Option<Vec<u8>>,
    /// Authentication method
    pub auth: KubeAuth,
    /// Default namespace
    pub namespace: Option<String>,
    /// Skip TLS verification
    pub insecure_skip_tls_verify: bool,
}

/// Kubeconfig parsing errors
#[derive(Debug, thiserror::Error)]
pub enum KubeconfigError {
    #[error("Failed to read kubeconfig file: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("Failed to parse kubeconfig YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),
    #[error("No current context set in kubeconfig")]
    NoCurrentContext,
    #[error("Context '{0}' not found")]
    ContextNotFound(String),
    #[error("Cluster '{0}' not found")]
    ClusterNotFound(String),
    #[error("User '{0}' not found")]
    UserNotFound(String),
    #[error("Failed to decode base64: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("Exec command failed: {0}")]
    ExecError(String),
    #[error("Failed to parse exec credential: {0}")]
    ExecParseError(String),
}

impl Kubeconfig {
    /// Load kubeconfig from a file path
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KubeconfigError> {
        let path = path.as_ref();
        debug!(path = %path.display(), "Loading kubeconfig");

        let content = std::fs::read_to_string(path)?;
        Self::from_str(&content)
    }

    /// Load kubeconfig from the default location (~/.kube/config)
    pub fn from_default_location() -> Result<Self, KubeconfigError> {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let path = PathBuf::from(home).join(".kube").join("config");
        Self::from_file(path)
    }

    /// Parse kubeconfig from a YAML string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(content: &str) -> Result<Self, KubeconfigError> {
        let config: Kubeconfig = serde_yaml::from_str(content)?;
        trace!(
            clusters = config.clusters.len(),
            contexts = config.contexts.len(),
            users = config.users.len(),
            "Parsed kubeconfig"
        );
        Ok(config)
    }

    /// Get the current context name
    pub fn current_context(&self) -> Result<String, KubeconfigError> {
        self.current_context
            .clone()
            .ok_or(KubeconfigError::NoCurrentContext)
    }

    /// Get a context by name
    pub fn get_context(&self, name: &str) -> Result<&ContextConfig, KubeconfigError> {
        self.contexts
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.context)
            .ok_or_else(|| KubeconfigError::ContextNotFound(name.to_string()))
    }

    /// Get a cluster by name
    pub fn get_cluster(&self, name: &str) -> Result<&ClusterConfig, KubeconfigError> {
        self.clusters
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.cluster)
            .ok_or_else(|| KubeconfigError::ClusterNotFound(name.to_string()))
    }

    /// Get a user by name
    pub fn get_user(&self, name: &str) -> Result<&UserConfig, KubeconfigError> {
        self.users
            .iter()
            .find(|u| u.name == name)
            .map(|u| &u.user)
            .ok_or_else(|| KubeconfigError::UserNotFound(name.to_string()))
    }

    /// Resolve the current context to a complete configuration
    pub fn resolve_current(&self) -> Result<ResolvedKubeConfig, KubeconfigError> {
        let context_name = self.current_context()?;
        self.resolve_context(&context_name)
    }

    /// Resolve a specific context to a complete configuration
    pub fn resolve_context(
        &self,
        context_name: &str,
    ) -> Result<ResolvedKubeConfig, KubeconfigError> {
        let context = self.get_context(context_name)?;
        let cluster = self.get_cluster(&context.cluster)?;
        let user = self.get_user(&context.user)?;

        debug!(
            context = context_name,
            cluster = &context.cluster,
            user = &context.user,
            server = &cluster.server,
            "Resolving kubeconfig context"
        );

        // Resolve CA certificate
        let ca_cert = self.resolve_ca_cert(cluster)?;

        // Resolve authentication
        let auth = self.resolve_auth(user)?;

        Ok(ResolvedKubeConfig {
            server: cluster.server.clone(),
            ca_cert,
            auth,
            namespace: context.namespace.clone(),
            insecure_skip_tls_verify: cluster.insecure_skip_tls_verify,
        })
    }

    /// Resolve CA certificate from config
    fn resolve_ca_cert(&self, cluster: &ClusterConfig) -> Result<Option<Vec<u8>>, KubeconfigError> {
        if let Some(data) = &cluster.certificate_authority_data {
            let decoded = BASE64.decode(data)?;
            return Ok(Some(decoded));
        }

        if let Some(path) = &cluster.certificate_authority {
            let expanded = expand_path(path);
            let content = std::fs::read(&expanded)?;
            return Ok(Some(content));
        }

        Ok(None)
    }

    /// Resolve authentication from user config
    fn resolve_auth(&self, user: &UserConfig) -> Result<KubeAuth, KubeconfigError> {
        // Check for exec-based auth first (most flexible)
        if let Some(exec) = &user.exec {
            return self.resolve_exec_auth(exec);
        }

        // Check for token
        if let Some(token) = &user.token {
            return Ok(KubeAuth::Token(token.clone()));
        }

        // Check for token file
        if let Some(token_file) = &user.token_file {
            let expanded = expand_path(token_file);
            let token = std::fs::read_to_string(&expanded)?.trim().to_string();
            return Ok(KubeAuth::Token(token));
        }

        // Check for client certificate
        let cert = self.resolve_client_cert(user)?;
        let key = self.resolve_client_key(user)?;

        if let (Some(cert), Some(key)) = (cert, key) {
            return Ok(KubeAuth::ClientCert { cert, key });
        }

        warn!("No authentication method found in kubeconfig user");
        Ok(KubeAuth::None)
    }

    /// Resolve client certificate from user config
    fn resolve_client_cert(&self, user: &UserConfig) -> Result<Option<Vec<u8>>, KubeconfigError> {
        if let Some(data) = &user.client_certificate_data {
            let decoded = BASE64.decode(data)?;
            return Ok(Some(decoded));
        }

        if let Some(path) = &user.client_certificate {
            let expanded = expand_path(path);
            let content = std::fs::read(&expanded)?;
            return Ok(Some(content));
        }

        Ok(None)
    }

    /// Resolve client key from user config
    fn resolve_client_key(&self, user: &UserConfig) -> Result<Option<Vec<u8>>, KubeconfigError> {
        if let Some(data) = &user.client_key_data {
            let decoded = BASE64.decode(data)?;
            return Ok(Some(decoded));
        }

        if let Some(path) = &user.client_key {
            let expanded = expand_path(path);
            let content = std::fs::read(&expanded)?;
            return Ok(Some(content));
        }

        Ok(None)
    }

    /// Execute external command to get credentials
    fn resolve_exec_auth(&self, exec: &ExecConfig) -> Result<KubeAuth, KubeconfigError> {
        debug!(command = &exec.command, "Executing credential command");

        let mut cmd = Command::new(&exec.command);
        cmd.args(&exec.args);

        // Set environment variables
        for env_var in &exec.env {
            cmd.env(&env_var.name, &env_var.value);
        }

        let output = cmd.output().map_err(|e| {
            KubeconfigError::ExecError(format!("Failed to execute {}: {}", exec.command, e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KubeconfigError::ExecError(format!(
                "Command {} failed: {}",
                exec.command, stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let cred: ExecCredential = serde_json::from_str(&stdout).map_err(|e| {
            KubeconfigError::ExecParseError(format!("Failed to parse exec output: {}", e))
        })?;

        if let Some(status) = cred.status {
            if let Some(token) = status.token {
                return Ok(KubeAuth::Token(token));
            }

            if let (Some(cert_data), Some(key_data)) =
                (status.client_certificate_data, status.client_key_data)
            {
                let cert = BASE64.decode(&cert_data)?;
                let key = BASE64.decode(&key_data)?;
                return Ok(KubeAuth::ClientCert { cert, key });
            }
        }

        Err(KubeconfigError::ExecParseError(
            "Exec credential response missing token or certificate".to_string(),
        ))
    }
}

/// Expand ~ to home directory in paths
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        PathBuf::from(home).join(&path[2..])
    } else {
        PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: docker-desktop
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lSQU5oV1hCWTBNREMKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==
    server: https://kubernetes.docker.internal:6443
  name: docker-desktop
contexts:
- context:
    cluster: docker-desktop
    user: docker-desktop
    namespace: default
  name: docker-desktop
users:
- name: docker-desktop
  user:
    client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lSQU5oV1hCWTBNREMKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==
    client-key-data: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBejZ3ZWlPZkp6NW8KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0=
"#;

    const TOKEN_KUBECONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: my-cluster
clusters:
- cluster:
    server: https://api.my-cluster.example.com:6443
    insecure-skip-tls-verify: true
  name: my-cluster
contexts:
- context:
    cluster: my-cluster
    user: my-user
  name: my-cluster
users:
- name: my-user
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test-token
"#;

    #[test]
    fn test_parse_kubeconfig() {
        let config = Kubeconfig::from_str(SAMPLE_KUBECONFIG).unwrap();

        assert_eq!(config.current_context, Some("docker-desktop".to_string()));
        assert_eq!(config.clusters.len(), 1);
        assert_eq!(config.contexts.len(), 1);
        assert_eq!(config.users.len(), 1);
    }

    #[test]
    fn test_get_context() {
        let config = Kubeconfig::from_str(SAMPLE_KUBECONFIG).unwrap();

        let context = config.get_context("docker-desktop").unwrap();
        assert_eq!(context.cluster, "docker-desktop");
        assert_eq!(context.user, "docker-desktop");
        assert_eq!(context.namespace, Some("default".to_string()));
    }

    #[test]
    fn test_get_cluster() {
        let config = Kubeconfig::from_str(SAMPLE_KUBECONFIG).unwrap();

        let cluster = config.get_cluster("docker-desktop").unwrap();
        assert_eq!(cluster.server, "https://kubernetes.docker.internal:6443");
        assert!(cluster.certificate_authority_data.is_some());
    }

    #[test]
    fn test_context_not_found() {
        let config = Kubeconfig::from_str(SAMPLE_KUBECONFIG).unwrap();

        let result = config.get_context("nonexistent");
        assert!(matches!(result, Err(KubeconfigError::ContextNotFound(_))));
    }

    #[test]
    fn test_resolve_current_context() {
        let config = Kubeconfig::from_str(SAMPLE_KUBECONFIG).unwrap();

        let resolved = config.resolve_current().unwrap();
        assert_eq!(resolved.server, "https://kubernetes.docker.internal:6443");
        assert!(resolved.ca_cert.is_some());
        assert!(matches!(resolved.auth, KubeAuth::ClientCert { .. }));
        assert_eq!(resolved.namespace, Some("default".to_string()));
    }

    #[test]
    fn test_token_auth() {
        let config = Kubeconfig::from_str(TOKEN_KUBECONFIG).unwrap();

        let resolved = config.resolve_current().unwrap();
        assert_eq!(resolved.server, "https://api.my-cluster.example.com:6443");
        assert!(resolved.insecure_skip_tls_verify);

        match resolved.auth {
            KubeAuth::Token(token) => {
                assert!(token.starts_with("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
            }
            _ => panic!("Expected token auth"),
        }
    }

    #[test]
    fn test_expand_path() {
        std::env::set_var("HOME", "/home/test");

        assert_eq!(
            expand_path("~/.kube/config"),
            PathBuf::from("/home/test/.kube/config")
        );
        assert_eq!(
            expand_path("/etc/kubernetes/config"),
            PathBuf::from("/etc/kubernetes/config")
        );
    }

    #[test]
    fn test_no_current_context() {
        let config_str = r#"
apiVersion: v1
kind: Config
clusters: []
contexts: []
users: []
"#;
        let config = Kubeconfig::from_str(config_str).unwrap();

        let result = config.current_context();
        assert!(matches!(result, Err(KubeconfigError::NoCurrentContext)));
    }
}
