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
//! - Certificate hot-reload on SIGHUP
//! - OCSP stapling support
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
//!
//!         // OCSP stapling
//!         ocsp-stapling true
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustls::client::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use tracing::{debug, error, info, trace, warn};

use zentinel_config::{TlsConfig, UpstreamTlsConfig};

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
    /// OCSP fetch error
    OcspFetch(String),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::CertificateLoad(e) => write!(f, "Failed to load certificate: {}", e),
            TlsError::KeyLoad(e) => write!(f, "Failed to load private key: {}", e),
            TlsError::ConfigBuild(e) => write!(f, "Failed to build TLS config: {}", e),
            TlsError::CertKeyMismatch(e) => write!(f, "Certificate/key mismatch: {}", e),
            TlsError::InvalidCertificate(e) => write!(f, "Invalid certificate: {}", e),
            TlsError::OcspFetch(e) => write!(f, "Failed to fetch OCSP response: {}", e),
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
        // Get cert_file and key_file - manual certs or ACME-managed paths
        let (cert_path_buf, key_path_buf);
        let (cert_file, key_file) = match (&config.cert_file, &config.key_file) {
            (Some(cert), Some(key)) => (cert.as_path(), key.as_path()),
            _ if config.acme.is_some() => {
                let acme = config.acme.as_ref().unwrap();
                let primary = acme.domains.first().ok_or_else(|| {
                    TlsError::ConfigBuild(
                        "ACME configuration has no domains for cert path resolution".to_string(),
                    )
                })?;
                cert_path_buf = acme.storage.join("domains").join(primary).join("cert.pem");
                key_path_buf = acme.storage.join("domains").join(primary).join("key.pem");
                (cert_path_buf.as_path(), key_path_buf.as_path())
            }
            _ => {
                return Err(TlsError::ConfigBuild(
                    "TLS configuration requires cert_file and key_file (or ACME block)".to_string(),
                ));
            }
        };

        // Load default certificate
        let default_cert = load_certified_key(cert_file, key_file)?;

        info!(
            cert_file = %cert_file.display(),
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
    ///
    /// This is the core resolution logic. For the rustls trait implementation,
    /// see `ResolvesServerCert`.
    pub fn resolve(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
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

// ============================================================================
// Hot-Reloadable Certificate Support
// ============================================================================

/// Hot-reloadable SNI certificate resolver
///
/// Wraps an SniResolver behind an RwLock to allow certificate hot-reload
/// without restarting the server. On SIGHUP, the inner resolver is replaced
/// with a newly loaded one.
pub struct HotReloadableSniResolver {
    /// Inner resolver (protected by RwLock for hot-reload)
    inner: RwLock<Arc<SniResolver>>,
    /// Original config for reloading
    config: RwLock<TlsConfig>,
    /// Last reload time
    last_reload: RwLock<Instant>,
}

impl std::fmt::Debug for HotReloadableSniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotReloadableSniResolver")
            .field("last_reload", &*self.last_reload.read())
            .finish()
    }
}

impl HotReloadableSniResolver {
    /// Create a new hot-reloadable resolver from TLS configuration
    pub fn from_config(config: TlsConfig) -> Result<Self, TlsError> {
        let resolver = SniResolver::from_config(&config)?;

        Ok(Self {
            inner: RwLock::new(Arc::new(resolver)),
            config: RwLock::new(config),
            last_reload: RwLock::new(Instant::now()),
        })
    }

    /// Reload certificates from disk
    ///
    /// This is called on SIGHUP to pick up new certificates without restart.
    /// If the reload fails, the old certificates continue to be used.
    pub fn reload(&self) -> Result<(), TlsError> {
        let config = self.config.read();

        let cert_file_display = config
            .cert_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(acme-managed)".to_string());

        info!(
            cert_file = %cert_file_display,
            sni_count = config.additional_certs.len(),
            "Reloading TLS certificates"
        );

        // Try to load new certificates
        let new_resolver = SniResolver::from_config(&config)?;

        // Swap in the new resolver atomically
        *self.inner.write() = Arc::new(new_resolver);
        *self.last_reload.write() = Instant::now();

        info!("TLS certificates reloaded successfully");
        Ok(())
    }

    /// Update configuration and reload
    pub fn update_config(&self, new_config: TlsConfig) -> Result<(), TlsError> {
        // Load with new config first
        let new_resolver = SniResolver::from_config(&new_config)?;

        // Update both config and resolver
        *self.config.write() = new_config;
        *self.inner.write() = Arc::new(new_resolver);
        *self.last_reload.write() = Instant::now();

        info!("TLS configuration updated and certificates reloaded");
        Ok(())
    }

    /// Get time since last reload
    pub fn last_reload_age(&self) -> Duration {
        self.last_reload.read().elapsed()
    }

    /// Resolve certificate for a given server name
    ///
    /// This is the core resolution logic exposed for testing.
    pub fn resolve(&self, server_name: Option<&str>) -> Arc<CertifiedKey> {
        self.inner.read().resolve(server_name)
    }
}

impl ResolvesServerCert for HotReloadableSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.inner.read().resolve(client_hello.server_name()))
    }
}

/// Certificate reload manager
///
/// Tracks all TLS listeners and provides a unified reload interface.
pub struct CertificateReloader {
    /// Map of listener ID to hot-reloadable resolver
    resolvers: RwLock<HashMap<String, Arc<HotReloadableSniResolver>>>,
}

impl CertificateReloader {
    /// Create a new certificate reloader
    pub fn new() -> Self {
        Self {
            resolvers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a resolver for a listener
    pub fn register(&self, listener_id: &str, resolver: Arc<HotReloadableSniResolver>) {
        debug!(listener_id = %listener_id, "Registering TLS resolver for hot-reload");
        self.resolvers
            .write()
            .insert(listener_id.to_string(), resolver);
    }

    /// Reload all registered certificates
    ///
    /// Returns the number of successfully reloaded listeners and any errors.
    pub fn reload_all(&self) -> (usize, Vec<(String, TlsError)>) {
        let resolvers = self.resolvers.read();
        let mut success_count = 0;
        let mut errors = Vec::new();

        info!(
            listener_count = resolvers.len(),
            "Reloading certificates for all TLS listeners"
        );

        for (listener_id, resolver) in resolvers.iter() {
            match resolver.reload() {
                Ok(()) => {
                    success_count += 1;
                    debug!(listener_id = %listener_id, "Certificate reload successful");
                }
                Err(e) => {
                    error!(listener_id = %listener_id, error = %e, "Certificate reload failed");
                    errors.push((listener_id.clone(), e));
                }
            }
        }

        if errors.is_empty() {
            info!(
                success_count = success_count,
                "All certificates reloaded successfully"
            );
        } else {
            warn!(
                success_count = success_count,
                error_count = errors.len(),
                "Certificate reload completed with errors"
            );
        }

        (success_count, errors)
    }

    /// Get reload status for all listeners
    pub fn status(&self) -> HashMap<String, Duration> {
        self.resolvers
            .read()
            .iter()
            .map(|(id, resolver)| (id.clone(), resolver.last_reload_age()))
            .collect()
    }
}

impl Default for CertificateReloader {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OCSP Stapling Support
// ============================================================================

/// OCSP response cache entry
#[derive(Debug, Clone)]
pub struct OcspCacheEntry {
    /// DER-encoded OCSP response
    pub response: Vec<u8>,
    /// When this response was fetched
    pub fetched_at: Instant,
    /// When this response expires (from nextUpdate field)
    pub expires_at: Option<Instant>,
}

/// OCSP stapling manager
///
/// Fetches and caches OCSP responses for certificates.
pub struct OcspStapler {
    /// Cache of OCSP responses by certificate fingerprint
    cache: RwLock<HashMap<String, OcspCacheEntry>>,
    /// Refresh interval for OCSP responses (default 1 hour)
    refresh_interval: Duration,
}

impl OcspStapler {
    /// Create a new OCSP stapler
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            refresh_interval: Duration::from_secs(3600), // 1 hour default
        }
    }

    /// Create with custom refresh interval
    pub fn with_refresh_interval(interval: Duration) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            refresh_interval: interval,
        }
    }

    /// Get cached OCSP response for a certificate
    pub fn get_response(&self, cert_fingerprint: &str) -> Option<Vec<u8>> {
        let cache = self.cache.read();
        if let Some(entry) = cache.get(cert_fingerprint) {
            // Check if response is still valid
            if entry.fetched_at.elapsed() < self.refresh_interval {
                trace!(fingerprint = %cert_fingerprint, "OCSP cache hit");
                return Some(entry.response.clone());
            }
            trace!(fingerprint = %cert_fingerprint, "OCSP cache expired");
        }
        None
    }

    /// Fetch OCSP response for a certificate
    ///
    /// This performs an HTTP request to the OCSP responder specified in the
    /// certificate's Authority Information Access extension.
    pub fn fetch_ocsp_response(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        use x509_parser::prelude::*;

        // Parse the end-entity certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| TlsError::OcspFetch(format!("Failed to parse certificate: {}", e)))?;

        // Parse the issuer certificate
        let (_, issuer) = X509Certificate::from_der(issuer_der).map_err(|e| {
            TlsError::OcspFetch(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Extract OCSP responder URL from AIA extension
        let ocsp_url = extract_ocsp_responder_url(&cert)?;
        debug!(url = %ocsp_url, "Found OCSP responder URL");

        // Build OCSP request
        let ocsp_request = build_ocsp_request(&cert, &issuer)?;

        // Send request synchronously (blocking context)
        // Note: In production, this should be async with proper timeout handling
        let response = send_ocsp_request_sync(&ocsp_url, &ocsp_request)?;

        // Calculate fingerprint for caching
        let fingerprint = calculate_cert_fingerprint(cert_der);

        // Cache the response
        let entry = OcspCacheEntry {
            response: response.clone(),
            fetched_at: Instant::now(),
            expires_at: None, // Could parse nextUpdate from response
        };
        self.cache.write().insert(fingerprint, entry);

        info!("Successfully fetched and cached OCSP response");
        Ok(response)
    }

    /// Async version of fetch_ocsp_response
    pub async fn fetch_ocsp_response_async(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        use x509_parser::prelude::*;

        // Parse the end-entity certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| TlsError::OcspFetch(format!("Failed to parse certificate: {}", e)))?;

        // Parse the issuer certificate
        let (_, issuer) = X509Certificate::from_der(issuer_der).map_err(|e| {
            TlsError::OcspFetch(format!("Failed to parse issuer certificate: {}", e))
        })?;

        // Extract OCSP responder URL from AIA extension
        let ocsp_url = extract_ocsp_responder_url(&cert)?;
        debug!(url = %ocsp_url, "Found OCSP responder URL");

        // Build OCSP request
        let ocsp_request = build_ocsp_request(&cert, &issuer)?;

        // Send request asynchronously
        let response = send_ocsp_request_async(&ocsp_url, &ocsp_request).await?;

        // Calculate fingerprint for caching
        let fingerprint = calculate_cert_fingerprint(cert_der);

        // Cache the response
        let entry = OcspCacheEntry {
            response: response.clone(),
            fetched_at: Instant::now(),
            expires_at: None,
        };
        self.cache.write().insert(fingerprint, entry);

        info!("Successfully fetched and cached OCSP response (async)");
        Ok(response)
    }

    /// Prefetch OCSP responses for all certificates in a config
    pub fn prefetch_for_config(&self, config: &TlsConfig) -> Vec<String> {
        let mut warnings = Vec::new();

        if !config.ocsp_stapling {
            trace!("OCSP stapling disabled in config");
            return warnings;
        }

        info!("Prefetching OCSP responses for certificates");

        // For now, just log that we would prefetch
        // Full implementation would iterate certificates and fetch OCSP responses
        warnings.push("OCSP stapling prefetch not yet fully implemented".to_string());

        warnings
    }

    /// Clear the OCSP cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
        info!("OCSP cache cleared");
    }
}

impl Default for OcspStapler {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OCSP Helper Functions
// ============================================================================

/// Extract OCSP responder URL from certificate's Authority Information Access extension
fn extract_ocsp_responder_url(
    cert: &x509_parser::certificate::X509Certificate,
) -> Result<String, TlsError> {
    use x509_parser::prelude::*;

    // Find the AIA extension
    let aia = cert
        .extensions()
        .iter()
        .find(|ext| ext.oid == oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS)
        .ok_or_else(|| {
            TlsError::OcspFetch(
                "Certificate does not have Authority Information Access extension".to_string(),
            )
        })?;

    // Parse AIA extension
    let aia_value = match aia.parsed_extension() {
        ParsedExtension::AuthorityInfoAccess(aia) => aia,
        _ => {
            return Err(TlsError::OcspFetch(
                "Failed to parse Authority Information Access extension".to_string(),
            ))
        }
    };

    // Find OCSP access method
    for access in &aia_value.accessdescs {
        if access.access_method == oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
            match &access.access_location {
                GeneralName::URI(url) => {
                    return Ok(url.to_string());
                }
                _ => continue,
            }
        }
    }

    Err(TlsError::OcspFetch(
        "Certificate AIA does not contain OCSP responder URL".to_string(),
    ))
}

/// Build an OCSP request for the given certificate
///
/// This builds a minimal OCSP request with SHA-256 hashes
fn build_ocsp_request(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &x509_parser::certificate::X509Certificate,
) -> Result<Vec<u8>, TlsError> {
    use sha2::{Digest, Sha256};

    // Per RFC 6960, an OCSP request contains:
    // - Hash of issuer name
    // - Hash of issuer public key
    // - Certificate serial number

    // Hash issuer name (Distinguished Name)
    let issuer_name_hash = {
        let mut hasher = Sha256::new();
        hasher.update(issuer.subject().as_raw());
        hasher.finalize()
    };

    // Hash issuer public key (the BIT STRING content, not including tag/length)
    let issuer_key_hash = {
        let mut hasher = Sha256::new();
        hasher.update(issuer.public_key().subject_public_key.data.as_ref());
        hasher.finalize()
    };

    // Get certificate serial number
    let serial = cert.serial.to_bytes_be();

    // Build ASN.1 DER encoded OCSP request
    // This is a minimal implementation of the OCSP request structure
    let request = build_ocsp_request_der(&issuer_name_hash, &issuer_key_hash, &serial);

    Ok(request)
}

/// Build DER-encoded OCSP request
fn build_ocsp_request_der(
    issuer_name_hash: &[u8],
    issuer_key_hash: &[u8],
    serial_number: &[u8],
) -> Vec<u8> {
    // OID for SHA-256
    let sha256_oid: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    // Build CertID structure
    let hash_algorithm = der_sequence(&[&der_oid(sha256_oid), &der_null()]);

    let cert_id = der_sequence(&[
        &hash_algorithm,
        &der_octet_string(issuer_name_hash),
        &der_octet_string(issuer_key_hash),
        &der_integer(serial_number),
    ]);

    // Build Request structure
    let request = der_sequence(&[&cert_id]);

    // Build requestList (SEQUENCE OF Request)
    let request_list = der_sequence(&[&request]);

    // Build TBSRequest
    let tbs_request = der_sequence(&[&request_list]);

    // Build OCSPRequest
    der_sequence(&[&tbs_request])
}

// DER encoding helpers
fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for item in items {
        content.extend_from_slice(item);
    }
    let mut result = vec![0x30]; // SEQUENCE tag
    result.extend(der_length(content.len()));
    result.extend(content);
    result
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    let mut result = vec![0x06]; // OID tag
    result.extend(der_length(oid.len()));
    result.extend_from_slice(oid);
    result
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00] // NULL
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x04]; // OCTET STRING tag
    result.extend(der_length(data.len()));
    result.extend_from_slice(data);
    result
}

fn der_integer(data: &[u8]) -> Vec<u8> {
    let mut result = vec![0x02]; // INTEGER tag
                                 // Remove leading zeros but ensure at least one byte
    let data = match data.iter().position(|&b| b != 0) {
        Some(pos) => &data[pos..],
        None => &[0],
    };
    // Add leading zero if high bit is set (to ensure positive)
    if !data.is_empty() && data[0] & 0x80 != 0 {
        result.extend(der_length(data.len() + 1));
        result.push(0x00);
    } else {
        result.extend(der_length(data.len()));
    }
    result.extend_from_slice(data);
    result
}

fn der_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Send OCSP request synchronously (blocking)
fn send_ocsp_request_sync(url: &str, request: &[u8]) -> Result<Vec<u8>, TlsError> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    // Parse URL to get host, port, and path
    let url = url::Url::parse(url)
        .map_err(|e| TlsError::OcspFetch(format!("Invalid OCSP URL: {}", e)))?;

    let host = url
        .host_str()
        .ok_or_else(|| TlsError::OcspFetch("OCSP URL has no host".to_string()))?;
    let port = url.port().unwrap_or(80);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };

    // Connect to server
    let addr = format!("{}:{}", host, port);
    let mut stream = TcpStream::connect(&addr)
        .map_err(|e| TlsError::OcspFetch(format!("Failed to connect to OCSP responder: {}", e)))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| TlsError::OcspFetch(format!("Failed to set timeout: {}", e)))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| TlsError::OcspFetch(format!("Failed to set timeout: {}", e)))?;

    // Build HTTP POST request
    let http_request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/ocsp-request\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        path,
        host,
        request.len()
    );

    // Send request
    stream
        .write_all(http_request.as_bytes())
        .map_err(|e| TlsError::OcspFetch(format!("Failed to send OCSP request: {}", e)))?;
    stream
        .write_all(request)
        .map_err(|e| TlsError::OcspFetch(format!("Failed to send OCSP request body: {}", e)))?;

    // Read response
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| TlsError::OcspFetch(format!("Failed to read OCSP response: {}", e)))?;

    // Parse HTTP response - find body after headers
    let headers_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| TlsError::OcspFetch("Invalid HTTP response: no headers end".to_string()))?;

    let body = &response[headers_end + 4..];
    if body.is_empty() {
        return Err(TlsError::OcspFetch("Empty OCSP response body".to_string()));
    }

    Ok(body.to_vec())
}

/// Send OCSP request asynchronously
async fn send_ocsp_request_async(url: &str, request: &[u8]) -> Result<Vec<u8>, TlsError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| TlsError::OcspFetch(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .post(url)
        .header("Content-Type", "application/ocsp-request")
        .body(request.to_vec())
        .send()
        .await
        .map_err(|e| TlsError::OcspFetch(format!("OCSP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(TlsError::OcspFetch(format!(
            "OCSP responder returned status: {}",
            response.status()
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| TlsError::OcspFetch(format!("Failed to read OCSP response: {}", e)))?;

    Ok(body.to_vec())
}

/// Calculate certificate fingerprint for cache key
fn calculate_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    hex::encode(result)
}

// ============================================================================
// Upstream mTLS Support (Client Certificates)
// ============================================================================

/// Load client certificate and key for mTLS to upstreams
///
/// This function loads PEM-encoded certificates and private key and converts
/// them to Pingora's CertKey format for use with `HttpPeer.client_cert_key`.
///
/// # Arguments
///
/// * `cert_path` - Path to PEM-encoded certificate (may include chain)
/// * `key_path` - Path to PEM-encoded private key
///
/// # Returns
///
/// An `Arc<CertKey>` that can be set on `peer.client_cert_key` for mTLS
pub fn load_client_cert_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<Arc<pingora_core::utils::tls::CertKey>, TlsError> {
    // Read certificate chain (PEM format, may contain intermediates)
    let cert_file = File::open(cert_path)
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?;
    let mut cert_reader = BufReader::new(cert_file);

    // Parse certificates from PEM to DER
    let cert_ders: Vec<Vec<u8>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?
        .into_iter()
        .map(|c| c.to_vec())
        .collect();

    if cert_ders.is_empty() {
        return Err(TlsError::CertificateLoad(format!(
            "{}: No certificates found in PEM file",
            cert_path.display()
        )));
    }

    // Read private key (PEM format)
    let key_file = File::open(key_path)
        .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?;
    let mut key_reader = BufReader::new(key_file);

    // Parse private key from PEM to DER
    let key_der = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?
        .ok_or_else(|| {
            TlsError::KeyLoad(format!(
                "{}: No private key found in PEM file",
                key_path.display()
            ))
        })?
        .secret_der()
        .to_vec();

    // Create Pingora's CertKey (certificates: Vec<Vec<u8>>, key: Vec<u8>)
    let cert_key = pingora_core::utils::tls::CertKey::new(cert_ders, key_der);

    debug!(
        cert_path = %cert_path.display(),
        key_path = %key_path.display(),
        "Loaded mTLS client certificate for upstream connections"
    );

    Ok(Arc::new(cert_key))
}

/// Build a TLS client configuration for upstream connections with mTLS
///
/// This creates a rustls ClientConfig that can be used when Zentinel
/// connects to backends that require client certificate authentication.
pub fn build_upstream_tls_config(config: &UpstreamTlsConfig) -> Result<ClientConfig, TlsError> {
    let mut root_store = RootCertStore::empty();

    // Load CA certificates for server verification
    if let Some(ca_path) = &config.ca_cert {
        let ca_file = File::open(ca_path)
            .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", ca_path.display(), e)))?;
        let mut ca_reader = BufReader::new(ca_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", ca_path.display(), e)))?;

        for cert in certs {
            root_store.add(cert).map_err(|e| {
                TlsError::InvalidCertificate(format!("Failed to add CA certificate: {}", e))
            })?;
        }

        debug!(
            ca_file = %ca_path.display(),
            cert_count = root_store.len(),
            "Loaded upstream CA certificates"
        );
    } else if !config.insecure_skip_verify {
        // Use webpki roots for standard TLS
        root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        trace!("Using webpki-roots for upstream TLS verification");
    }

    // Build the client config
    let builder = ClientConfig::builder().with_root_certificates(root_store);

    let client_config = if let (Some(cert_path), Some(key_path)) =
        (&config.client_cert, &config.client_key)
    {
        // Load client certificate for mTLS
        let cert_file = File::open(cert_path)
            .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?;
        let mut cert_reader = BufReader::new(cert_file);

        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?;

        if certs.is_empty() {
            return Err(TlsError::CertificateLoad(format!(
                "{}: No certificates found",
                cert_path.display()
            )));
        }

        // Load client private key
        let key_file = File::open(key_path)
            .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?;
        let mut key_reader = BufReader::new(key_file);

        let key = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?
            .ok_or_else(|| {
                TlsError::KeyLoad(format!("{}: No private key found", key_path.display()))
            })?;

        info!(
            cert_file = %cert_path.display(),
            "Configured mTLS client certificate for upstream connections"
        );

        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| TlsError::CertKeyMismatch(format!("Failed to set client auth: {}", e)))?
    } else {
        // No client certificate
        builder.with_no_client_auth()
    };

    debug!("Upstream TLS configuration built successfully");
    Ok(client_config)
}

/// Validate upstream TLS configuration
pub fn validate_upstream_tls_config(config: &UpstreamTlsConfig) -> Result<(), TlsError> {
    // Validate CA certificate if specified
    if let Some(ca_path) = &config.ca_cert {
        if !ca_path.exists() {
            return Err(TlsError::CertificateLoad(format!(
                "Upstream CA certificate not found: {}",
                ca_path.display()
            )));
        }
    }

    // Validate client certificate pair if mTLS is configured
    if let Some(cert_path) = &config.client_cert {
        if !cert_path.exists() {
            return Err(TlsError::CertificateLoad(format!(
                "Upstream client certificate not found: {}",
                cert_path.display()
            )));
        }

        // If cert is specified, key must also be specified
        match &config.client_key {
            Some(key_path) if !key_path.exists() => {
                return Err(TlsError::KeyLoad(format!(
                    "Upstream client key not found: {}",
                    key_path.display()
                )));
            }
            None => {
                return Err(TlsError::ConfigBuild(
                    "client_cert specified without client_key".to_string(),
                ));
            }
            _ => {}
        }
    }

    if config.client_key.is_some() && config.client_cert.is_none() {
        return Err(TlsError::ConfigBuild(
            "client_key specified without client_cert".to_string(),
        ));
    }

    Ok(())
}

// ============================================================================
// Certificate Loading Functions
// ============================================================================

/// Load a certificate chain and private key from files
fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, TlsError> {
    // Load certificate chain
    let cert_file = File::open(cert_path)
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", cert_path.display(), e)))?;
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
    let key_file = File::open(key_path)
        .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?;
    let mut key_reader = BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::KeyLoad(format!("{}: {}", key_path.display(), e)))?
        .ok_or_else(|| {
            TlsError::KeyLoad(format!(
                "{}: No private key found in file",
                key_path.display()
            ))
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
    let ca_file = File::open(ca_path)
        .map_err(|e| TlsError::CertificateLoad(format!("{}: {}", ca_path.display(), e)))?;
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

/// Resolve TLS protocol versions from config into rustls version references.
fn resolve_protocol_versions(config: &TlsConfig) -> Vec<&'static rustls::SupportedProtocolVersion> {
    use zentinel_common::types::TlsVersion;

    let min = &config.min_version;
    let max = config.max_version.as_ref().unwrap_or(&TlsVersion::Tls13);

    let mut versions = Vec::new();

    // Include TLS 1.2 if within the min..=max range
    if matches!(min, TlsVersion::Tls12) {
        versions.push(&rustls::version::TLS12);
    }

    // Include TLS 1.3 if within the min..=max range
    if matches!(max, TlsVersion::Tls13) {
        versions.push(&rustls::version::TLS13);
    }

    if versions.is_empty() {
        // Shouldn't happen with valid config, but be safe
        warn!("No valid TLS versions resolved from config, falling back to TLS 1.2 + 1.3");
        versions.push(&rustls::version::TLS12);
        versions.push(&rustls::version::TLS13);
    }

    versions
}

/// Resolve cipher suite names from config to rustls `SupportedCipherSuite` values.
///
/// Uses the aws-lc-rs crypto provider's available cipher suites.
fn resolve_cipher_suites(names: &[String]) -> Result<Vec<rustls::SupportedCipherSuite>, TlsError> {
    use rustls::crypto::aws_lc_rs::cipher_suite;

    // Map of canonical IANA names to rustls cipher suite values
    let known: &[(&str, rustls::SupportedCipherSuite)] = &[
        // TLS 1.3
        (
            "TLS_AES_256_GCM_SHA384",
            cipher_suite::TLS13_AES_256_GCM_SHA384,
        ),
        (
            "TLS_AES_128_GCM_SHA256",
            cipher_suite::TLS13_AES_128_GCM_SHA256,
        ),
        (
            "TLS_CHACHA20_POLY1305_SHA256",
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ),
        // TLS 1.2
        (
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
        (
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ),
        (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ),
        (
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ),
    ];

    let mut suites = Vec::with_capacity(names.len());
    for name in names {
        let normalized = name.to_uppercase().replace('-', "_");
        match known.iter().find(|(n, _)| *n == normalized) {
            Some((_, suite)) => suites.push(*suite),
            None => {
                let available: Vec<&str> = known.iter().map(|(n, _)| *n).collect();
                return Err(TlsError::ConfigBuild(format!(
                    "Unknown cipher suite '{}'. Available: {}",
                    name,
                    available.join(", ")
                )));
            }
        }
    }

    Ok(suites)
}

/// Build a TLS ServerConfig from our configuration.
///
/// Applies protocol versions, cipher suites, session resumption, mTLS,
/// and SNI certificate resolution from the Zentinel TLS config.
///
/// # Note
///
/// This ServerConfig is fully configured but currently not used by
/// Pingora's listener infrastructure. Pingora's rustls `TlsSettings`
/// builds its own `ServerConfig` internally with hardcoded defaults.
/// A future update to the Pingora fork should accept a pre-built
/// `ServerConfig` via `TlsSettings`, at which point this function's
/// output will be wired into the listener setup.
pub fn build_server_config(config: &TlsConfig) -> Result<ServerConfig, TlsError> {
    let resolver = SniResolver::from_config(config)?;

    // Resolve protocol versions from config
    let versions = resolve_protocol_versions(config);
    info!(
        versions = ?versions.iter().map(|v| format!("{:?}", v.version)).collect::<Vec<_>>(),
        "TLS protocol versions configured"
    );

    // Build the ServerConfig builder, with custom cipher suites if specified
    let builder = if !config.cipher_suites.is_empty() {
        let suites = resolve_cipher_suites(&config.cipher_suites)?;
        info!(
            cipher_suites = ?config.cipher_suites,
            count = suites.len(),
            "Custom TLS cipher suites configured"
        );
        let provider = rustls::crypto::CryptoProvider {
            cipher_suites: suites,
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&versions)
            .map_err(|e| {
                TlsError::ConfigBuild(format!("Invalid TLS protocol/cipher configuration: {}", e))
            })?
    } else {
        ServerConfig::builder_with_protocol_versions(&versions)
    };

    // Configure client authentication (mTLS)
    let server_config = if config.client_auth {
        if let Some(ca_path) = &config.ca_file {
            let root_store = load_client_ca(ca_path)?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
                .build()
                .map_err(|e| {
                    TlsError::ConfigBuild(format!("Failed to build client verifier: {}", e))
                })?;

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
    let mut server_config = server_config;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Disable session resumption if configured
    if !config.session_resumption {
        server_config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        info!("TLS session resumption disabled");
    }

    debug!("TLS configuration built successfully");

    Ok(server_config)
}

/// Validate TLS configuration files exist and are readable
pub fn validate_tls_config(config: &TlsConfig) -> Result<(), TlsError> {
    // If ACME is configured, skip manual cert file validation
    if config.acme.is_some() {
        // ACME-managed certificates don't need cert_file/key_file to exist
        trace!("Skipping manual cert validation for ACME-managed TLS");
    } else {
        // Check default certificate (required for non-ACME configs)
        match (&config.cert_file, &config.key_file) {
            (Some(cert_file), Some(key_file)) => {
                if !cert_file.exists() {
                    return Err(TlsError::CertificateLoad(format!(
                        "Certificate file not found: {}",
                        cert_file.display()
                    )));
                }
                if !key_file.exists() {
                    return Err(TlsError::KeyLoad(format!(
                        "Key file not found: {}",
                        key_file.display()
                    )));
                }
            }
            _ => {
                return Err(TlsError::ConfigBuild(
                    "TLS configuration requires cert_file and key_file (or ACME block)".to_string(),
                ));
            }
        }
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
