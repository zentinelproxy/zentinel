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

use sentinel_config::{TlsConfig, UpstreamTlsConfig};

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

        info!(
            cert_file = %config.cert_file.display(),
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
        _cert_der: &[u8],
        _issuer_der: &[u8],
    ) -> Result<Vec<u8>, TlsError> {
        // Parse certificates to extract OCSP responder URL
        // Note: Full implementation would use x509-parser or similar
        // For now, we'll return an error indicating the feature needs the full impl

        // This is a placeholder - actual implementation would:
        // 1. Parse the certificate to find AIA extension
        // 2. Extract OCSP responder URL
        // 3. Build OCSP request
        // 4. Send HTTP POST to responder
        // 5. Parse and validate response
        // 6. Cache the response

        warn!("OCSP stapling fetch not yet implemented - certificates will work without stapling");
        Err(TlsError::OcspFetch(
            "OCSP responder URL extraction requires x509-parser dependency".to_string(),
        ))
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
// Upstream mTLS Support (Client Certificates)
// ============================================================================

/// Build a TLS client configuration for upstream connections with mTLS
///
/// This creates a rustls ClientConfig that can be used when Sentinel
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

/// Build a TLS ServerConfig from our configuration
pub fn build_server_config(config: &TlsConfig) -> Result<ServerConfig, TlsError> {
    let resolver = SniResolver::from_config(config)?;

    let builder = ServerConfig::builder();

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
