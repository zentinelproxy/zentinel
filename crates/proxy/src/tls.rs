//! TLS Configuration and SNI Support
//!
//! This module provides TLS configuration with Server Name Indication (SNI) support
//! for serving multiple certificates based on the requested hostname.
//!
//! # Features
//!
//! - SNI-based certificate selection
//! - Wildcard certificate matching (e.g., `*.example.com`)
//! - Default certificate fallback
//! - Certificate validation at startup
//! - mTLS client certificate verification
//!
//! # Example KDL Configuration
//!
//! ```kdl
//! listener "https" {
//!     address "0.0.0.0:443"
//!     protocol "https"
//!     tls {
//!         cert-file "/etc/certs/default.crt"
//!         key-file "/etc/certs/default.key"
//!
//!         // SNI certificates
//!         sni {
//!             hostnames "example.com" "www.example.com"
//!             cert-file "/etc/certs/example.crt"
//!             key-file "/etc/certs/example.key"
//!         }
//!         sni {
//!             hostnames "*.api.example.com"
//!             cert-file "/etc/certs/api-wildcard.crt"
//!             key-file "/etc/certs/api-wildcard.key"
//!         }
//!
//!         // mTLS configuration
//!         ca-file "/etc/certs/ca.crt"
//!         client-auth true
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{RootCertStore, ServerConfig};
use tracing::{debug, error, info, warn};

use sentinel_config::{SniCertificate, TlsConfig};

/// Error type for TLS operations
#[derive(Debug)]
pub enum TlsError {
    /// Failed to load certificate file
    CertificateLoad(String),
    /// Failed to load private key file
    KeyLoad(String),
    /// Failed to build TLS configuration
    ConfigBuild(String),
    /// Certificate/key mismatch
    CertKeyMismatch(String),
    /// Invalid certificate
    InvalidCertificate(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertificateLoad(e) => write!(f, "Failed to load certificate: {}", e),
            TlsError::KeyLoad(e) => write!(f, "Failed to load private key: {}", e),
            TlsError::ConfigBuild(e) => write!(f, "Failed to build TLS config: {}", e),
            TlsError::CertKeyMismatch(e) => write!(f, "Certificate/key mismatch: {}", e),
            TlsError::InvalidCertificate(e) => write!(f, "Invalid certificate: {}", e),
        }
    }
}

impl std::error::Error for TlsError {}

/// SNI-aware certificate resolver
///
/// Resolves certificates based on the Server Name Indication (SNI) extension
/// in the TLS handshake. Supports:
/// - Exact hostname matches
/// - Wildcard certificates (e.g., `*.example.com`)
/// - Default certificate fallback
#[derive(Debug)]
pub struct SniResolver {
    /// Default certificate (used when no SNI match)
    default_cert: Arc<CertifiedKey>,
    /// SNI hostname to certificate mapping
    /// Key is lowercase hostname, value is the certified key
    sni_certs: HashMap<String, Arc<CertifiedKey>>,
    /// Wildcard certificates (e.g., "*.example.com" -> cert)
    wildcard_certs: HashMap<String, Arc<CertifiedKey>>,
}

impl SniResolver {
    /// Create a new SNI resolver from TLS configuration
    pub fn from_config(config: &TlsConfig) -> Result<Self, TlsError> {
        // Load default certificate
        let default_cert = load_certified_key(&config.cert_file, &config.key_file)?;

        info!(
            cert_file = %config.cert_file.display(),
            "Loaded default TLS certificate"
        );

        let mut sni_certs = HashMap::new();
        let mut wildcard_certs = HashMap::new();

        // Load SNI certificates
        for sni_config in &config.additional_certs {
            let cert = load_certified_key(&sni_config.cert_file, &sni_config.key_file)?;
            let cert = Arc::new(cert);

            for hostname in &sni_config.hostnames {
                let hostname_lower = hostname.to_lowercase();

                if hostname_lower.starts_with("*.") {
                    // Wildcard certificate
                    let domain = hostname_lower.strip_prefix("*.").unwrap().to_string();
                    wildcard_certs.insert(domain.clone(), cert.clone());
                    debug!(
                        pattern = %hostname,
                        domain = %domain,
                        cert_file = %sni_config.cert_file.display(),
                        "Registered wildcard SNI certificate"
                    );
                } else {
                    // Exact hostname match
                    sni_certs.insert(hostname_lower.clone(), cert.clone());
                    debug!(
                        hostname = %hostname_lower,
                        cert_file = %sni_config.cert_file.display(),
                        "Registered SNI certificate"
                    );
                }
            }
        }

        info!(
            exact_certs = sni_certs.len(),
            wildcard_certs = wildcard_certs.len(),
            "SNI resolver initialized"
        );

        Ok(Self {
            default_cert: Arc::new(default_cert),
            sni_certs,
            wildcard_certs,
        })
    }

    /// Resolve certificate for a given server name
    fn resolve(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        let Some(name) = server_name else {
            debug!("No SNI provided, using default certificate");
            return self.default_cert.clone();
        };

        let name_lower = name.to_lowercase();

        // Try exact match first
        if let Some(cert) = self.sni_certs.get(&name_lower) {
            debug!(hostname = %name_lower, "SNI exact match found");
            return cert.clone();
        }

        // Try wildcard match
        // For "foo.bar.example.com", try "bar.example.com", then "example.com"
        let parts: Vec<&str> = name_lower.split('.').collect();
        for i in 1..parts.len() {
            let domain = parts[i..].join(".");
            if let Some(cert) = self.wildcard_certs.get(&domain) {
                debug!(
                    hostname = %name_lower,
                    wildcard_domain = %domain,
                    "SNI wildcard match found"
                );
                return cert.clone();
            }
        }

        debug!(
            hostname = %name_lower,
            "No SNI match found, using default certificate"
        );
        self.default_cert.clone()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.resolve(client_hello.server_name()))
    }
}

/// Load a certificate chain and private key from files
fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, TlsError> {
    // Load certificate chain
    let cert_file = File::open(cert_path).map_err(|e| {
        TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e))
    })?;
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?;

    if certs.is_empty() {
        return Err(TlsError::CertificateLoad(format!(
            "{}: No certificates found in file",
            cert_path.display()
        )));
    }

    // Load private key
    let key_file = File::open(key_path).map_err(|e| {
        TlsError::KeyLoad(format!("{}: {}", key_path.display(), e))
    })?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?
        .ok_or_else(|| {
            TlsError::KeyLoad(format!("{}: No private key found in file", key_path.display()))
        })?;

    // Create signing key using the default crypto provider
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));

    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| TlsError::CertKeyMismatch(format!("Failed to load private key: {:?}", e)))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Load CA certificates for client verification (mTLS)
pub fn load_client_ca(ca_path: &Path) -> Result<RootCertStore, TlsError> {
    let ca_file = File::open(ca_path).map_err(|e| {
        TlsError::CertificateLoad(format!("{}: {}", ca_path.display(), e))
    })?;
    let mut ca_reader = BufReader::new(ca_file);

    let mut root_store = RootCertStore::empty();

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", ca_path.display(), e)))?;

    for cert in certs {
        root_store.add(cert).map_err(|e| {
            TlsError::InvalidCertificate(format!("Failed to add CA certificate: {}", e))
        })?;
    }

    if root_store.is_empty() {
        return Err(TlsError::CertificateLoad(format!(
            "{}: No CA certificates found",
            ca_path.display()
        )));
    }

    info!(
        ca_file = %ca_path.display(),
        cert_count = root_store.len(),
        "Loaded client CA certificates"
    );

    Ok(root_store)
}

/// Build a TLS ServerConfig from our configuration
pub fn build_server_config(config: &TlsConfig) -> Result<ServerConfig, TlsError> {
    let resolver = SniResolver::from_config(config)?;

    let mut builder = ServerConfig::builder();

    // Configure client authentication (mTLS)
    let server_config = if config.client_auth {
        if let Some(ca_path) = &config.ca_file {
            let root_store = load_client_ca(ca_path)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| TlsError::ConfigBuild(format!("Failed to build client verifier: {}", e)))?;

            info!("mTLS enabled: client certificates required");

            builder
                .with_client_cert_verifier(verifier)
                .with_cert_resolver(Arc::new(resolver))
        } else {
            warn!("client_auth enabled but no ca_file specified, disabling client auth");
            builder
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(resolver))
        }
    } else {
        builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver))
    };

    // Configure ALPN for HTTP/2 support
    let mut config = server_config;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    debug!("TLS configuration built successfully");

    Ok(config)
}

/// Validate TLS configuration files exist and are readable
pub fn validate_tls_config(config: &TlsConfig) -> Result<(), TlsError> {
    // Check default certificate
    if !config.cert_file.exists() {
        return Err(TlsError::CertificateLoad(format!(
            "Certificate file not found: {}",
            config.cert_file.display()
        )));
    }
    if !config.key_file.exists() {
        return Err(TlsError::KeyLoad(format!(
            "Key file not found: {}",
            config.key_file.display()
        )));
    }

    // Check SNI certificates
    for sni in &config.additional_certs {
        if !sni.cert_file.exists() {
            return Err(TlsError::CertificateLoad(format!(
                "SNI certificate file not found: {}",
                sni.cert_file.display()
            )));
        }
        if !sni.key_file.exists() {
            return Err(TlsError::KeyLoad(format!(
                "SNI key file not found: {}",
                sni.key_file.display()
            )));
        }
    }

    // Check CA file if mTLS enabled
    if config.client_auth {
        if let Some(ca_path) = &config.ca_file {
            if !ca_path.exists() {
                return Err(TlsError::CertificateLoad(format!(
                    "CA certificate file not found: {}",
                    ca_path.display()
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        // Create a mock resolver without actual certs
        // Just test the matching logic
        let name = "foo.bar.example.com";
        let parts: Vec<&str> = name.split('.').collect();

        assert_eq!(parts.len(), 4);

        // Check domain extraction for wildcard matching
        let domain1 = parts[1..].join(".");
        assert_eq!(domain1, "bar.example.com");

        let domain2 = parts[2..].join(".");
        assert_eq!(domain2, "example.com");
    }

    #[test]
    fn test_hostname_normalization() {
        let hostname = "Example.COM";
        let normalized = hostname.to_lowercase();
        assert_eq!(normalized, "example.com");
    }
}
