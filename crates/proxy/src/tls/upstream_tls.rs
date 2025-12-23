//! mTLS support for upstream connections
//!
//! This module provides mutual TLS authentication for upstream connections,
//! including certificate management, rotation, and validation.

use anyhow::{anyhow, Context, Result};
use pingora::tls::ssl::{SslConnector, SslMethod, SslVerifyMode};
use rustls::{Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerName};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use webpki::TrustAnchor;

use crate::types::{SentinelError, SentinelResult};

/// TLS version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    /// Convert to rustls protocol version
    pub fn to_protocol_version(&self) -> &'static rustls::SupportedProtocolVersion {
        match self {
            TlsVersion::Tls10 | TlsVersion::Tls11 => {
                panic!("TLS 1.0 and 1.1 are not supported by rustls")
            }
            TlsVersion::Tls12 => &rustls::version::TLS12,
            TlsVersion::Tls13 => &rustls::version::TLS13,
        }
    }
}

/// Cipher suite configuration
#[derive(Debug, Clone)]
pub struct CipherSuite {
    pub name: String,
    pub suite: rustls::SupportedCipherSuite,
}

/// mTLS configuration for an upstream
#[derive(Debug, Clone)]
pub struct UpstreamTlsConfig {
    /// Enable TLS for this upstream
    pub enabled: bool,
    /// Client certificate path
    pub client_cert: Option<PathBuf>,
    /// Client private key path
    pub client_key: Option<PathBuf>,
    /// CA certificate path(s)
    pub ca_certs: Vec<PathBuf>,
    /// Verify hostname
    pub verify_hostname: bool,
    /// Allow invalid certificates (DANGEROUS - only for testing)
    pub allow_invalid_certs: bool,
    /// Minimum TLS version
    pub min_version: TlsVersion,
    /// Maximum TLS version
    pub max_version: Option<TlsVersion>,
    /// Allowed cipher suites
    pub cipher_suites: Option<Vec<String>>,
    /// SNI hostname override
    pub sni_hostname: Option<String>,
    /// Enable session resumption
    pub session_resumption: bool,
    /// Session cache size
    pub session_cache_size: usize,
    /// Certificate reload interval
    pub reload_interval: Duration,
    /// OCSP stapling
    pub ocsp_stapling: bool,
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            client_cert: None,
            client_key: None,
            ca_certs: Vec::new(),
            verify_hostname: true,
            allow_invalid_certs: false,
            min_version: TlsVersion::Tls12,
            max_version: None,
            cipher_suites: None,
            sni_hostname: None,
            session_resumption: true,
            session_cache_size: 1024,
            reload_interval: Duration::from_secs(3600), // 1 hour
            ocsp_stapling: false,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        }
    }
}

/// Certificate with metadata
#[derive(Debug, Clone)]
struct CertificateData {
    /// The certificate chain
    pub cert_chain: Vec<Certificate>,
    /// The private key
    pub private_key: PrivateKey,
    /// When the certificate was loaded
    pub loaded_at: Instant,
    /// Certificate expiry time
    pub expires_at: Option<SystemTime>,
    /// Certificate subject
    pub subject: String,
    /// Certificate serial number
    pub serial: String,
}

impl CertificateData {
    /// Load certificate data from files
    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        // Load certificate chain
        let cert_file = File::open(cert_path)
            .with_context(|| format!("Failed to open certificate file: {:?}", cert_path))?;
        let mut cert_reader = BufReader::new(cert_file);
        let cert_chain = certs(&mut cert_reader)
            .with_context(|| format!("Failed to parse certificate: {:?}", cert_path))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        if cert_chain.is_empty() {
            return Err(anyhow!("No certificates found in file: {:?}", cert_path));
        }

        // Load private key
        let key_file = File::open(key_path)
            .with_context(|| format!("Failed to open key file: {:?}", key_path))?;
        let mut key_reader = BufReader::new(key_file);

        // Try PKCS8 first
        let keys = pkcs8_private_keys(&mut key_reader)
            .with_context(|| format!("Failed to parse PKCS8 key: {:?}", key_path))?;

        let private_key = if !keys.is_empty() {
            PrivateKey(keys[0].clone())
        } else {
            // Try RSA format
            let key_file = File::open(key_path)?;
            let mut key_reader = BufReader::new(key_file);
            let keys = rsa_private_keys(&mut key_reader)
                .with_context(|| format!("Failed to parse RSA key: {:?}", key_path))?;

            if keys.is_empty() {
                return Err(anyhow!("No private keys found in file: {:?}", key_path));
            }
            PrivateKey(keys[0].clone())
        };

        // Parse certificate for metadata
        let (subject, serial, expires_at) = Self::parse_certificate_metadata(&cert_chain[0])?;

        Ok(Self {
            cert_chain,
            private_key,
            loaded_at: Instant::now(),
            expires_at,
            subject,
            serial,
        })
    }

    /// Parse certificate metadata
    fn parse_certificate_metadata(
        cert: &Certificate,
    ) -> Result<(String, String, Option<SystemTime>)> {
        use x509_parser::prelude::*;

        let parsed = parse_x509_certificate(&cert.0)
            .map_err(|e| anyhow!("Failed to parse certificate: {:?}", e))?
            .1;

        let subject = parsed.subject().to_string();
        let serial = format!("{:X}", parsed.serial);

        let expires_at = SystemTime::UNIX_EPOCH
            + Duration::from_secs(parsed.validity().not_after.timestamp() as u64);

        Ok((subject, serial, Some(expires_at)))
    }

    /// Check if certificate needs reload
    pub fn needs_reload(&self, reload_interval: Duration) -> bool {
        self.loaded_at.elapsed() > reload_interval
    }

    /// Check if certificate is expired or expiring soon
    pub fn is_expiring_soon(&self, warning_days: u64) -> bool {
        if let Some(expires_at) = self.expires_at {
            let warning_duration = Duration::from_secs(warning_days * 24 * 3600);
            match expires_at.duration_since(SystemTime::now()) {
                Ok(remaining) => remaining < warning_duration,
                Err(_) => true, // Already expired
            }
        } else {
            false
        }
    }
}

/// TLS context manager for upstream connections
pub struct UpstreamTlsManager {
    /// Configurations per upstream
    configs: Arc<RwLock<HashMap<String, UpstreamTlsConfig>>>,
    /// Loaded certificates per upstream
    certificates: Arc<RwLock<HashMap<String, CertificateData>>>,
    /// TLS client configurations per upstream
    client_configs: Arc<RwLock<HashMap<String, Arc<ClientConfig>>>>,
    /// Last reload check time
    last_reload_check: Arc<RwLock<Instant>>,
    /// Metrics
    metrics: Arc<TlsMetrics>,
}

impl UpstreamTlsManager {
    /// Create a new TLS manager
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            certificates: Arc::new(RwLock::new(HashMap::new())),
            client_configs: Arc::new(RwLock::new(HashMap::new())),
            last_reload_check: Arc::new(RwLock::new(Instant::now())),
            metrics: Arc::new(TlsMetrics::default()),
        }
    }

    /// Configure TLS for an upstream
    pub async fn configure_upstream(
        &self,
        upstream_id: String,
        config: UpstreamTlsConfig,
    ) -> Result<()> {
        if !config.enabled {
            // Remove any existing configuration
            self.configs.write().await.remove(&upstream_id);
            self.certificates.write().await.remove(&upstream_id);
            self.client_configs.write().await.remove(&upstream_id);
            return Ok(());
        }

        // Load certificates if configured
        let cert_data =
            if let (Some(cert_path), Some(key_path)) = (&config.client_cert, &config.client_key) {
                Some(CertificateData::from_files(cert_path, key_path)?)
            } else {
                None
            };

        // Build rustls client configuration
        let client_config = self
            .build_client_config(&config, cert_data.as_ref())
            .await?;

        // Store everything
        self.configs
            .write()
            .await
            .insert(upstream_id.clone(), config);
        if let Some(data) = cert_data {
            self.certificates
                .write()
                .await
                .insert(upstream_id.clone(), data);
        }
        self.client_configs
            .write()
            .await
            .insert(upstream_id.clone(), Arc::new(client_config));

        info!("Configured TLS for upstream: {}", upstream_id);
        Ok(())
    }

    /// Build rustls client configuration
    async fn build_client_config(
        &self,
        config: &UpstreamTlsConfig,
        cert_data: Option<&CertificateData>,
    ) -> Result<ClientConfig> {
        // Create root certificate store
        let mut root_store = RootCertStore::empty();

        // Add CA certificates
        for ca_path in &config.ca_certs {
            let ca_file = File::open(ca_path)
                .with_context(|| format!("Failed to open CA certificate: {:?}", ca_path))?;
            let mut ca_reader = BufReader::new(ca_file);
            let ca_certs = certs(&mut ca_reader)?;

            for cert in ca_certs {
                root_store
                    .add(&Certificate(cert))
                    .with_context(|| format!("Failed to add CA certificate from: {:?}", ca_path))?;
            }
        }

        // If no CA certs specified, use system roots
        if config.ca_certs.is_empty() {
            let native_roots = rustls_native_certs::load_native_certs()
                .context("Failed to load native root certificates")?;
            for cert in native_roots {
                root_store.add(&Certificate(cert.0))?;
            }
        }

        // Create client config builder
        let builder = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);

        // Add client certificate if provided
        let mut client_config = if let Some(cert_data) = cert_data {
            builder
                .with_single_cert(cert_data.cert_chain.clone(), cert_data.private_key.clone())
                .context("Failed to configure client certificate")?
        } else {
            builder.with_no_client_auth()
        };

        // Configure ALPN
        if !config.alpn_protocols.is_empty() {
            client_config.alpn_protocols = config
                .alpn_protocols
                .iter()
                .map(|p| p.as_bytes().to_vec())
                .collect();
        }

        // Configure session resumption
        if config.session_resumption {
            client_config.session_storage =
                rustls::client::ClientSessionMemoryCache::new(config.session_cache_size);
        }

        // Configure verification
        if config.allow_invalid_certs {
            warn!("Certificate verification disabled for upstream - DANGEROUS!");
            struct DangerousVerifier;
            impl rustls::client::ServerCertVerifier for DangerousVerifier {
                fn verify_server_cert(
                    &self,
                    _end_entity: &Certificate,
                    _intermediates: &[Certificate],
                    _server_name: &ServerName,
                    _scts: &mut dyn Iterator<Item = &[u8]>,
                    _ocsp_response: &[u8],
                    _now: std::time::SystemTime,
                ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                    Ok(rustls::client::ServerCertVerified::assertion())
                }
            }
            client_config
                .dangerous()
                .set_certificate_verifier(Arc::new(DangerousVerifier));
        }

        Ok(client_config)
    }

    /// Get TLS client configuration for an upstream
    pub async fn get_client_config(&self, upstream_id: &str) -> Option<Arc<ClientConfig>> {
        // Check if certificates need reload
        self.check_reload(upstream_id).await;

        self.client_configs.read().await.get(upstream_id).cloned()
    }

    /// Check and reload certificates if necessary
    async fn check_reload(&self, upstream_id: &str) {
        let mut last_check = self.last_reload_check.write().await;
        if last_check.elapsed() < Duration::from_secs(60) {
            return; // Check at most once per minute
        }
        *last_check = Instant::now();
        drop(last_check);

        let configs = self.configs.read().await;
        let config = match configs.get(upstream_id) {
            Some(c) => c.clone(),
            None => return,
        };
        drop(configs);

        let certificates = self.certificates.read().await;
        let needs_reload = certificates
            .get(upstream_id)
            .map(|cert| cert.needs_reload(config.reload_interval))
            .unwrap_or(false);
        drop(certificates);

        if needs_reload {
            info!("Reloading certificate for upstream: {}", upstream_id);
            if let Err(e) = self.reload_certificate(upstream_id, &config).await {
                error!("Failed to reload certificate for {}: {}", upstream_id, e);
                self.metrics
                    .reload_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                self.metrics
                    .reloads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Check for expiring certificates
        let certificates = self.certificates.read().await;
        if let Some(cert_data) = certificates.get(upstream_id) {
            if cert_data.is_expiring_soon(7) {
                warn!(
                    "Certificate for upstream {} expires at {:?}",
                    upstream_id, cert_data.expires_at
                );
                self.metrics
                    .expiring_certs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Reload certificate for an upstream
    async fn reload_certificate(
        &self,
        upstream_id: &str,
        config: &UpstreamTlsConfig,
    ) -> Result<()> {
        if let (Some(cert_path), Some(key_path)) = (&config.client_cert, &config.client_key) {
            let cert_data = CertificateData::from_files(cert_path, key_path)?;
            let client_config = self.build_client_config(config, Some(&cert_data)).await?;

            self.certificates
                .write()
                .await
                .insert(upstream_id.to_string(), cert_data);
            self.client_configs
                .write()
                .await
                .insert(upstream_id.to_string(), Arc::new(client_config));

            info!("Reloaded certificate for upstream: {}", upstream_id);
        }
        Ok(())
    }

    /// Get certificate expiry information
    pub async fn get_certificate_info(&self, upstream_id: &str) -> Option<CertificateInfo> {
        let certificates = self.certificates.read().await;
        certificates.get(upstream_id).map(|cert| CertificateInfo {
            subject: cert.subject.clone(),
            serial: cert.serial.clone(),
            loaded_at: cert.loaded_at,
            expires_at: cert.expires_at,
            is_expiring: cert.is_expiring_soon(7),
        })
    }

    /// Get metrics
    pub fn metrics(&self) -> &TlsMetrics {
        &self.metrics
    }
}

/// Certificate information
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub serial: String,
    pub loaded_at: Instant,
    pub expires_at: Option<SystemTime>,
    pub is_expiring: bool,
}

/// TLS metrics
#[derive(Debug, Default)]
pub struct TlsMetrics {
    /// Total handshakes
    pub handshakes: std::sync::atomic::AtomicU64,
    /// Failed handshakes
    pub handshake_errors: std::sync::atomic::AtomicU64,
    /// Total handshake time in microseconds
    pub handshake_time_us: std::sync::atomic::AtomicU64,
    /// Certificate reloads
    pub reloads: std::sync::atomic::AtomicU64,
    /// Reload errors
    pub reload_errors: std::sync::atomic::AtomicU64,
    /// Expiring certificates
    pub expiring_certs: std::sync::atomic::AtomicU64,
    /// Session resumptions
    pub session_resumptions: std::sync::atomic::AtomicU64,
}

impl TlsMetrics {
    /// Record a handshake
    pub fn record_handshake(&self, duration: Duration, success: bool) {
        self.handshakes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !success {
            self.handshake_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.handshake_time_us.fetch_add(
            duration.as_micros() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_cert_and_key() -> (NamedTempFile, NamedTempFile) {
        let cert = r#"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIG...
-----END CERTIFICATE-----"#;

        let key = r#"-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgk...
-----END PRIVATE KEY-----"#;

        let mut cert_file = NamedTempFile::new().unwrap();
        cert_file.write_all(cert.as_bytes()).unwrap();

        let mut key_file = NamedTempFile::new().unwrap();
        key_file.write_all(key.as_bytes()).unwrap();

        (cert_file, key_file)
    }

    #[tokio::test]
    async fn test_tls_configuration() {
        let manager = UpstreamTlsManager::new();

        let config = UpstreamTlsConfig {
            enabled: true,
            verify_hostname: true,
            ..Default::default()
        };

        let result = manager
            .configure_upstream("test-upstream".to_string(), config)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_certificate_expiry_check() {
        let cert_data = CertificateData {
            cert_chain: vec![],
            private_key: PrivateKey(vec![]),
            loaded_at: Instant::now(),
            expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
            subject: "test".to_string(),
            serial: "123".to_string(),
        };

        assert!(!cert_data.is_expiring_soon(1)); // Not expiring in 1 day
        assert!(cert_data.is_expiring_soon(3650)); // Would be expiring in 10 years
    }

    #[tokio::test]
    async fn test_reload_check() {
        let cert_data = CertificateData {
            cert_chain: vec![],
            private_key: PrivateKey(vec![]),
            loaded_at: Instant::now() - Duration::from_secs(7200),
            expires_at: None,
            subject: "test".to_string(),
            serial: "123".to_string(),
        };

        assert!(cert_data.needs_reload(Duration::from_secs(3600)));
        assert!(!cert_data.needs_reload(Duration::from_secs(10000)));
    }
}
