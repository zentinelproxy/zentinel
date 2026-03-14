//! TLS certificate management from Kubernetes Secrets.
//!
//! Watches Kubernetes Secrets referenced by Gateway TLS configurations
//! and writes certificate/key pairs to temporary files for Pingora's
//! TLS stack. Certificates are refreshed when Secrets change.

use k8s_openapi::api::core::v1::Secret;
use kube::api::Api;
use kube::Client;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::error::GatewayError;

/// Reference to a Kubernetes Secret containing TLS certificates.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SecretRef {
    pub namespace: String,
    pub name: String,
}

/// A resolved TLS certificate pair on disk.
#[derive(Debug, Clone)]
pub struct ResolvedCertificate {
    /// Path to the certificate file (PEM).
    pub cert_path: PathBuf,
    /// Path to the private key file (PEM).
    pub key_path: PathBuf,
    /// Hostnames this certificate covers (from Gateway listener).
    pub hostnames: Vec<String>,
}

/// Manages TLS certificates extracted from Kubernetes Secrets.
///
/// Certificates are written to a managed directory and their paths
/// are returned for use in `TlsConfig`. When Secrets change, the
/// files are updated in place and the proxy's certificate reloader
/// picks up the changes.
pub struct SecretCertificateManager {
    client: Client,
    cert_dir: PathBuf,
    /// Cache of resolved certificates by Secret ref.
    resolved: Arc<parking_lot::RwLock<HashMap<SecretRef, ResolvedCertificate>>>,
}

impl SecretCertificateManager {
    /// Create a new certificate manager.
    ///
    /// `cert_dir` is the directory where certificate files will be written.
    /// It must exist and be writable.
    pub fn new(client: Client, cert_dir: PathBuf) -> Self {
        Self {
            client,
            cert_dir,
            resolved: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    /// Resolve a Secret reference into certificate file paths.
    ///
    /// Fetches the Secret from the Kubernetes API, extracts `tls.crt` and
    /// `tls.key`, writes them to disk, and returns the paths.
    ///
    /// Results are cached — subsequent calls for the same Secret return
    /// the cached paths without re-fetching.
    pub async fn resolve(
        &self,
        secret_ref: &SecretRef,
        hostnames: Vec<String>,
    ) -> Result<ResolvedCertificate, GatewayError> {
        // Check cache
        if let Some(cached) = self.resolved.read().get(secret_ref) {
            debug!(
                secret = %secret_ref.name,
                namespace = %secret_ref.namespace,
                "Using cached certificate"
            );
            return Ok(cached.clone());
        }

        // Fetch Secret
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &secret_ref.namespace);
        let secret = api.get(&secret_ref.name).await.map_err(|e| {
            GatewayError::InvalidResource {
                name: format!("{}/{}", secret_ref.namespace, secret_ref.name),
                reason: format!("Failed to fetch TLS Secret: {e}"),
            }
        })?;

        // Extract tls.crt and tls.key from Secret data
        let data = secret.data.ok_or_else(|| GatewayError::InvalidResource {
            name: format!("{}/{}", secret_ref.namespace, secret_ref.name),
            reason: "Secret has no data field".to_string(),
        })?;

        let cert_data = data.get("tls.crt").ok_or_else(|| GatewayError::InvalidResource {
            name: format!("{}/{}", secret_ref.namespace, secret_ref.name),
            reason: "Secret missing 'tls.crt' key".to_string(),
        })?;

        let key_data = data.get("tls.key").ok_or_else(|| GatewayError::InvalidResource {
            name: format!("{}/{}", secret_ref.namespace, secret_ref.name),
            reason: "Secret missing 'tls.key' key".to_string(),
        })?;

        // Write to disk
        let safe_name = format!("{}-{}", secret_ref.namespace, secret_ref.name);
        let cert_path = self.cert_dir.join(format!("{safe_name}.crt"));
        let key_path = self.cert_dir.join(format!("{safe_name}.key"));

        std::fs::write(&cert_path, &cert_data.0).map_err(|e| {
            GatewayError::Translation(format!(
                "Failed to write certificate to {}: {e}",
                cert_path.display()
            ))
        })?;

        std::fs::write(&key_path, &key_data.0).map_err(|e| {
            GatewayError::Translation(format!(
                "Failed to write key to {}: {e}",
                key_path.display()
            ))
        })?;

        // Set restrictive permissions on key file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }

        info!(
            secret = %secret_ref.name,
            namespace = %secret_ref.namespace,
            cert_path = %cert_path.display(),
            "TLS certificate resolved from Kubernetes Secret"
        );

        let resolved = ResolvedCertificate {
            cert_path,
            key_path,
            hostnames,
        };

        // Cache
        self.resolved
            .write()
            .insert(secret_ref.clone(), resolved.clone());

        Ok(resolved)
    }

    /// Refresh all cached certificates by re-fetching from Kubernetes.
    ///
    /// Called when Secret watch events fire. Updates the files in place
    /// so the proxy's certificate reloader picks up changes.
    pub async fn refresh_all(&self) -> Vec<GatewayError> {
        let refs: Vec<(SecretRef, Vec<String>)> = self
            .resolved
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), v.hostnames.clone()))
            .collect();

        let mut errors = Vec::new();
        for (secret_ref, hostnames) in refs {
            // Clear cache entry to force re-fetch
            self.resolved.write().remove(&secret_ref);

            if let Err(e) = self.resolve(&secret_ref, hostnames).await {
                error!(
                    secret = %secret_ref.name,
                    namespace = %secret_ref.namespace,
                    error = %e,
                    "Failed to refresh certificate"
                );
                errors.push(e);
            }
        }

        if errors.is_empty() {
            info!("All TLS certificates refreshed successfully");
        }

        errors
    }

    /// Get all currently resolved certificates.
    pub fn resolved_certificates(&self) -> Vec<ResolvedCertificate> {
        self.resolved.read().values().cloned().collect()
    }

    /// Clear all cached certificates.
    pub fn clear(&self) {
        self.resolved.write().clear();
    }
}
