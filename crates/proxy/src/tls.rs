//! TLS Configuration and SNI Support
//!
//! This module provides TLS configuration with Server Name Indication (SNI) support
//! for serving multiple certificates based on the requested hostname.
//!
//! # Features
//!
//! - SNI-based certificate selection
//! - Wildcard certificate matching (e.g., `*.example.com`)
//! - Automatic CN/SAN extraction when hostnames are omitted
//! - Default certificate fallback
//! - Certificate validation at startup
//! - mTLS client certificate verification
//! - Certificate hot-reload on SIGHUP
//! - OCSP stapling (fetched from the certificate's responder, refreshed in
//!   the background, never fatal to a handshake; see `tls/ocsp.rs`)
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
//!         // SNI certificates with explicit hostnames
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
//!         // SNI certificate with auto-extracted hostnames from CN/SAN
//!         sni {
//!             cert-file "/etc/certs/premium.crt"
//!             key-file "/etc/certs/premium.key"
//!         }
//!
//!         // SNI certificate with priority tie-breaking (auto-extracts all SANs,
//!         // but this cert wins for "shared.example.com" if contested)
//!         sni {
//!             priority-hostnames "shared.example.com"
//!             cert-file "/etc/certs/shared.crt"
//!             key-file "/etc/certs/shared.key"
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rustls::client::ClientConfig;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, ServerConfig};
use tracing::{debug, error, info, trace, warn};

use zentinel_config::{SniCertFolder, SniCertificate, TlsConfig, UpstreamTlsConfig};

mod ocsp;

pub use ocsp::{
    run_ocsp_refresher, OcspCacheEntry, OcspRefreshSummary, OcspStapler, OCSP_REFRESH_TICK,
};

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

/// The name used for the default certificate in reload diffs.
///
/// It has no SNI hostname of its own but is what an unmatched name is served,
/// so a silent rotation of it would be exactly as invisible as any other.
const DEFAULT_CERT_LABEL: &str = "<default>";

/// SHA-256 of a leaf certificate's DER encoding, as lowercase hex.
///
/// This is the same digest `openssl x509 -fingerprint -sha256 -noout` prints, so
/// a fingerprint in the log can be matched against a file on disk without
/// guesswork. Truncated to 16 hex characters: enough to distinguish the
/// certificates on one listener, short enough to stay readable in a log line.
fn cert_fingerprint(cert: &CertifiedKey) -> String {
    use sha2::{Digest, Sha256};

    let Some(leaf) = cert.cert.first() else {
        return "unknown".to_string();
    };
    let digest = Sha256::digest(leaf.as_ref());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// What a reload actually changed, in terms an operator can act on.
///
/// Counts alone cannot answer "did anything change?": the common case is a
/// renewal, where a certificate is replaced by one covering the same names and
/// every count stays identical. `replaced` is what makes that visible.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct CertDiff {
    /// Hostnames served now that were not served before.
    pub added: Vec<String>,
    /// Hostnames no longer served.
    pub removed: Vec<String>,
    /// Hostnames still served, but by a different certificate — i.e. a renewal.
    pub replaced: Vec<String>,
}

impl CertDiff {
    /// Whether the reload was a no-op as far as served certificates go.
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.replaced.is_empty()
    }

    /// Compute the diff between two snapshots of `hostname -> fingerprint`.
    fn between(before: &BTreeMap<String, String>, after: &BTreeMap<String, String>) -> Self {
        let mut diff = Self::default();

        for (hostname, new_fp) in after {
            match before.get(hostname) {
                None => diff.added.push(hostname.clone()),
                Some(old_fp) if old_fp != new_fp => {
                    diff.replaced
                        .push(format!("{hostname} ({old_fp}->{new_fp})"));
                }
                Some(_) => {}
            }
        }
        for hostname in before.keys() {
            if !after.contains_key(hostname) {
                diff.removed.push(hostname.clone());
            }
        }

        diff
    }

    /// Render one field of the diff for logging, or `-` when it is empty.
    fn render(names: &[String]) -> String {
        if names.is_empty() {
            "-".to_string()
        } else {
            names.join(", ")
        }
    }
}

impl SniResolver {
    /// Every hostname this resolver serves, mapped to its certificate
    /// fingerprint.
    ///
    /// Built on demand at reload time only, so the hot path pays nothing for it.
    pub fn served_certs(&self) -> BTreeMap<String, String> {
        let mut served = BTreeMap::new();
        served.insert(
            DEFAULT_CERT_LABEL.to_string(),
            cert_fingerprint(&self.default_cert),
        );
        for (hostname, cert) in self.sni_certs.iter().chain(self.wildcard_certs.iter()) {
            served.insert(hostname.clone(), cert_fingerprint(cert));
        }
        served
    }

    /// Every distinct certificate this resolver can serve.
    pub(crate) fn unique_certs(&self) -> Vec<Arc<CertifiedKey>> {
        let mut seen = HashSet::new();
        std::iter::once(&self.default_cert)
            .chain(self.sni_certs.values())
            .chain(self.wildcard_certs.values())
            .filter(|cert| seen.insert(Arc::as_ptr(cert)))
            .cloned()
            .collect()
    }

    /// A copy of this resolver whose certificates carry the OCSP responses
    /// `staple` returns for them.
    ///
    /// A certificate shared by several hostnames stays one shared object, so
    /// this costs one clone per distinct certificate that is actually stapled.
    pub(crate) fn with_staples(
        &self,
        staple: impl Fn(&CertifiedKey) -> Option<Vec<u8>>,
    ) -> SniResolver {
        let mut memo: HashMap<*const CertifiedKey, Arc<CertifiedKey>> = HashMap::new();
        let mut apply = |cert: &Arc<CertifiedKey>| -> Arc<CertifiedKey> {
            memo.entry(Arc::as_ptr(cert))
                .or_insert_with(|| {
                    let ocsp = staple(cert);
                    if ocsp == cert.ocsp {
                        cert.clone()
                    } else {
                        let mut stapled = CertifiedKey::clone(cert);
                        stapled.ocsp = ocsp;
                        Arc::new(stapled)
                    }
                })
                .clone()
        };
        SniResolver {
            default_cert: apply(&self.default_cert),
            sni_certs: self
                .sni_certs
                .iter()
                .map(|(name, cert)| (name.clone(), apply(cert)))
                .collect(),
            wildcard_certs: self
                .wildcard_certs
                .iter()
                .map(|(name, cert)| (name.clone(), apply(cert)))
                .collect(),
        }
    }

    /// Create a new SNI resolver from TLS configuration
    pub fn from_config(config: &TlsConfig, listener_id: Option<&str>) -> Result<Self, TlsError> {
        let listener_id_str = listener_id.unwrap_or("unknown");

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
            listener_id = %listener_id_str,
            cert_file = %cert_file.display(),
            "Loaded default TLS certificate"
        );

        let mut sni_certs = HashMap::new();
        let mut wildcard_certs = HashMap::new();

        // Track which hostnames were registered with priority, so we can resolve
        // conflicts during build. These sets are not stored in the final resolver
        // because priority is a build-time concept only.
        let mut priority_exact: HashSet<String> = HashSet::new();
        let mut priority_wildcard: HashSet<String> = HashSet::new();

        // Certificates found by scanning configured folders are registered
        // exactly like explicit `sni` blocks with no `hostnames`: their names
        // come from the certificate's CN and SANs. Feeding them through the
        // same loop keeps one implementation of hostname extraction, priority
        // handling and overlap detection.
        let scanned = scan_cert_folders(&config.cert_folders, listener_id_str);
        let all_sni_certs: Vec<&SniCertificate> = config
            .additional_certs
            .iter()
            .chain(scanned.iter())
            .collect();

        // Load SNI certificates
        for (i, sni_config) in all_sni_certs.into_iter().enumerate() {
            // Resolve paths for this SNI cert
            let (sni_cert_path_buf, sni_key_path_buf);
            let (sni_cert_path, sni_key_path) = match (&sni_config.cert_file, &sni_config.key_file)
            {
                (Some(cert), Some(key)) => (cert.as_path(), key.as_path()),
                _ if sni_config.acme.is_some() => {
                    let acme = sni_config.acme.as_ref().unwrap();
                    let primary = acme.domains.first().ok_or_else(|| {
                        TlsError::ConfigBuild("SNI ACME configuration has no domains".to_string())
                    })?;
                    sni_cert_path_buf = acme.storage.join("domains").join(primary).join("cert.pem");
                    sni_key_path_buf = acme.storage.join("domains").join(primary).join("key.pem");
                    (sni_cert_path_buf.as_path(), sni_key_path_buf.as_path())
                }
                _ => unreachable!("Config validation ensures certs or acme"),
            };

            let cert = match load_certified_key(sni_cert_path, sni_key_path) {
                Ok(cert) => Arc::new(cert),
                Err(e) => {
                    // If ACME is configured, the certificate might not exist yet.
                    // We log a warning and skip this certificate for now.
                    // It will be loaded later via hot-reload once issued.
                    if let Some(acme) = &sni_config.acme {
                        let primary = acme
                            .domains
                            .first()
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        warn!(
                            listener_id = %listener_id_str,
                            sni_index = i,
                            primary_domain = %primary,
                            error = %e,
                            "ACME SNI certificate not yet available, skipping initial load"
                        );

                        // Record metric for observability
                        if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
                            metrics.record_sni_cert_skip(listener_id_str, primary);
                        }

                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };

            // Build priority set for this cert (lowercased for consistent matching)
            let priority_set: HashSet<String> = sni_config
                .priority_hostnames
                .iter()
                .map(|h| h.to_lowercase())
                .collect();
            let has_priority = !priority_set.is_empty();

            // Determine hostnames: use explicit config, acme domains, or auto-extract from certificate.
            let hostnames = if !sni_config.hostnames.is_empty() {
                sni_config.hostnames.clone()
            } else if !priority_set.is_empty() {
                // When priority_hostnames is set, we always auto-extract.
                extract_hostnames_from_cert(cert.cert.first().unwrap())?
            } else if let Some(ref acme) = sni_config.acme {
                // If ACME is present and no explicit hostnames, use ACME domains.
                acme.domains.clone()
            } else {
                // Fallback to auto-extraction
                extract_hostnames_from_cert(cert.cert.first().unwrap())?
            };

            if has_priority {
                info!(
                    cert_file = %sni_cert_path.display(),
                    hostnames = ?hostnames,
                    priority_hostnames = ?sni_config.priority_hostnames,
                    "Loaded SNI certificate with priority tie-breaking"
                );
            } else if sni_config.hostnames.is_empty() && sni_config.acme.is_none() {
                info!(
                    cert_file = %sni_cert_path.display(),
                    hostnames = ?hostnames,
                    "Loaded SNI certificate (auto-extracted hostnames)"
                );
            } else {
                info!(
                    cert_file = %sni_cert_path.display(),
                    hostnames = ?hostnames,
                    "Loaded SNI certificate"
                );
            }

            for hostname in &hostnames {
                let hostname_lower = hostname.to_lowercase();
                let is_priority = priority_set.contains(&hostname_lower);

                if hostname_lower.starts_with("*.") {
                    // Wildcard certificate
                    let domain = hostname_lower.strip_prefix("*.").unwrap().to_string();

                    if let Some(existing) = wildcard_certs.get(&domain) {
                        if !Arc::ptr_eq(existing, &cert) {
                            let existing_has_priority = priority_wildcard.contains(&domain);

                            if is_priority && existing_has_priority {
                                // Both certs claim priority for the same wildcard
                                return Err(TlsError::ConfigBuild(format!(
                                    "Conflicting priority-hostnames: wildcard '*.{}' is claimed as priority by multiple certificates (including {:?}).",
                                    domain,
                                    sni_cert_path
                                )));
                            } else if is_priority {
                                // New cert has priority, overwrite the existing one
                                debug!(
                                    pattern = %hostname,
                                    domain = %domain,
                                    cert_file = %sni_cert_path.display(),
                                    "Priority wildcard SNI certificate overwrites previous registration"
                                );
                            } else if existing_has_priority {
                                // Existing cert has priority, skip the new one
                                debug!(
                                    pattern = %hostname,
                                    domain = %domain,
                                    cert_file = %sni_cert_path.display(),
                                    "Skipping wildcard SNI registration, existing cert has priority"
                                );
                                continue;
                            } else if config.allow_sni_overlaps {
                                // Overlaps accepted: the first registration
                                // wins. Certificates are registered in sorted
                                // path order, so the winner is the same on
                                // every machine and across reloads rather
                                // than whatever the filesystem listed first.
                                warn!(
                                    listener_id = %listener_id_str,
                                    pattern = %hostname,
                                    cert_file = %sni_cert_path.display(),
                                    "Overlapping wildcard SNI certificate ignored; \
                                     an earlier certificate already claims this name"
                                );
                                continue;
                            } else {
                                // Neither has priority, ambiguity error
                                return Err(TlsError::ConfigBuild(format!(
                                    "Ambiguous SNI configuration: wildcard '*.{}' matches multiple certificates (including {:?}). \
                                     Use explicit 'hostnames' or 'priority-hostnames' to resolve the conflict, \
                                     or set 'allow-sni-overlaps true' to accept the first match in path order.",
                                    domain,
                                    sni_cert_path
                                )));
                            }
                        }
                    }

                    wildcard_certs.insert(domain.clone(), cert.clone());
                    if is_priority {
                        priority_wildcard.insert(domain.clone());
                    }
                    debug!(
                        pattern = %hostname,
                        domain = %domain,
                        priority = is_priority,
                        cert_file = %sni_cert_path.display(),
                        "Registered wildcard SNI certificate"
                    );
                } else {
                    // Exact hostname match
                    if let Some(existing) = sni_certs.get(&hostname_lower) {
                        if !Arc::ptr_eq(existing, &cert) {
                            let existing_has_priority = priority_exact.contains(&hostname_lower);

                            if is_priority && existing_has_priority {
                                // Both certs claim priority for the same hostname
                                return Err(TlsError::ConfigBuild(format!(
                                    "Conflicting priority-hostnames: hostname '{}' is claimed as priority by multiple certificates (including {:?}).",
                                    hostname_lower,
                                    sni_cert_path
                                )));
                            } else if is_priority {
                                // New cert has priority, overwrite
                                debug!(
                                    hostname = %hostname_lower,
                                    cert_file = %sni_cert_path.display(),
                                    "Priority SNI certificate overwrites previous registration"
                                );
                            } else if existing_has_priority {
                                // Existing cert has priority, skip
                                debug!(
                                    hostname = %hostname_lower,
                                    cert_file = %sni_cert_path.display(),
                                    "Skipping SNI registration, existing cert has priority"
                                );
                                continue;
                            } else if config.allow_sni_overlaps {
                                warn!(
                                    listener_id = %listener_id_str,
                                    hostname = %hostname_lower,
                                    cert_file = %sni_cert_path.display(),
                                    "Overlapping SNI certificate ignored; \
                                     an earlier certificate already claims this name"
                                );
                                continue;
                            } else {
                                // Neither has priority, ambiguity error
                                return Err(TlsError::ConfigBuild(format!(
                                    "Ambiguous SNI configuration: hostname '{}' matches multiple certificates (including {:?}). \
                                     Use explicit 'hostnames' or 'priority-hostnames' to resolve the conflict, \
                                     or set 'allow-sni-overlaps true' to accept the first match in path order.",
                                    hostname_lower,
                                    sni_cert_path
                                )));
                            }
                        }
                    }

                    sni_certs.insert(hostname_lower.clone(), cert.clone());
                    if is_priority {
                        priority_exact.insert(hostname_lower.clone());
                    }
                    debug!(
                        hostname = %hostname_lower,
                        priority = is_priority,
                        cert_file = %sni_cert_path.display(),
                        "Registered SNI certificate"
                    );
                }
            }
        }

        info!(
            listener_id = %listener_id_str,
            exact_certs = sni_certs.len(),
            wildcard_certs = wildcard_certs.len(),
            "SNI resolver initialized"
        );

        if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
            // The default certificate counts too: it is what an unmatched
            // name is served.
            metrics.set_certificates_loaded(
                listener_id_str,
                1 + sni_certs.len() + wildcard_certs.len(),
            );
        }

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
    /// The resolver handshakes consult: `loaded` with any current OCSP
    /// staples attached.
    inner: RwLock<Arc<SniResolver>>,
    /// Certificates exactly as loaded from disk, without staples. Staples are
    /// re-applied to this whenever they change, so an expired staple is
    /// dropped rather than lingering on a certificate object.
    loaded: RwLock<Arc<SniResolver>>,
    /// Serialises updates of `loaded` and `inner`, so a staple refresh that
    /// read the old `loaded` cannot overwrite a reload that just happened.
    publish_lock: parking_lot::Mutex<()>,
    /// OCSP responses for this listener's certificates.
    ocsp: OcspStapler,
    /// Original config for reloading
    config: RwLock<TlsConfig>,
    /// Listener ID for observability
    listener_id: String,
    /// Last reload time
    last_reload: RwLock<Instant>,
}

impl std::fmt::Debug for HotReloadableSniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotReloadableSniResolver")
            .field("last_reload", &*self.last_reload.read())
            .field("listener_id", &self.listener_id)
            .finish()
    }
}

impl HotReloadableSniResolver {
    /// Create a new hot-reloadable resolver from TLS configuration
    pub fn from_config(
        config: TlsConfig,
        listener_id: impl Into<String>,
    ) -> Result<Self, TlsError> {
        let listener_id = listener_id.into();
        let resolver = Arc::new(SniResolver::from_config(&config, Some(&listener_id))?);

        Ok(Self {
            inner: RwLock::new(resolver.clone()),
            loaded: RwLock::new(resolver),
            publish_lock: parking_lot::Mutex::new(()),
            ocsp: OcspStapler::new(),
            config: RwLock::new(config),
            listener_id,
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
            listener_id = %self.listener_id,
            cert_file = %cert_file_display,
            sni_count = config.additional_certs.len(),
            "Reloading TLS certificates"
        );

        // Try to load new certificates. A failure leaves the previous ones in
        // place, which is invisible in traffic -- hence the counter.
        let new_resolver = match SniResolver::from_config(&config, Some(&self.listener_id)) {
            Ok(resolver) => resolver,
            Err(e) => {
                if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
                    metrics.record_reload(&self.listener_id, false);
                }
                return Err(e);
            }
        };

        // Snapshot both sides before the swap. With `reload-mode "watch"` the
        // reload is unattended by design, so this log line is the only record an
        // operator has of what a rescan actually did.
        let before = self.inner.read().served_certs();
        let after = new_resolver.served_certs();
        let diff = CertDiff::between(&before, &after);

        // Swap in the new resolver atomically. Certificates that did not
        // change keep their OCSP staple; new ones get one on the next refresh.
        self.publish(Arc::new(new_resolver), config.ocsp_stapling);
        *self.last_reload.write() = Instant::now();

        if diff.is_empty() {
            info!(
                listener_id = %self.listener_id,
                hostnames = after.len(),
                "TLS certificates reloaded successfully; no change to served certificates"
            );
        } else {
            info!(
                listener_id = %self.listener_id,
                hostnames = after.len(),
                added = %CertDiff::render(&diff.added),
                removed = %CertDiff::render(&diff.removed),
                replaced = %CertDiff::render(&diff.replaced),
                "TLS certificates reloaded successfully"
            );
        }
        if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
            metrics.record_reload(&self.listener_id, true);
        }
        Ok(())
    }

    /// Update configuration and reload
    pub fn update_config(&self, new_config: TlsConfig) -> Result<(), TlsError> {
        // Load with new config first
        let new_resolver = SniResolver::from_config(&new_config, Some(&self.listener_id))?;

        // Update both config and resolver
        let ocsp_stapling = new_config.ocsp_stapling;
        *self.config.write() = new_config;
        self.publish(Arc::new(new_resolver), ocsp_stapling);
        *self.last_reload.write() = Instant::now();

        info!(
            listener_id = %self.listener_id,
            "TLS configuration updated and certificates reloaded"
        );
        Ok(())
    }

    /// Install freshly loaded certificates, with current staples attached.
    fn publish(&self, loaded: Arc<SniResolver>, ocsp_stapling: bool) {
        let _guard = self.publish_lock.lock();
        let served = if ocsp_stapling {
            Arc::new(loaded.with_staples(|cert| self.ocsp.staple_for(cert)))
        } else {
            loaded.clone()
        };
        *self.loaded.write() = loaded;
        *self.inner.write() = served;
    }

    /// Re-attach staples to the currently loaded certificates.
    fn restaple(&self, ocsp_stapling: bool) {
        let _guard = self.publish_lock.lock();
        let loaded = self.loaded.read().clone();
        let served = if ocsp_stapling {
            Arc::new(loaded.with_staples(|cert| self.ocsp.staple_for(cert)))
        } else {
            loaded
        };
        *self.inner.write() = served;
    }

    /// Whether this listener is configured to staple OCSP responses.
    pub fn ocsp_stapling_enabled(&self) -> bool {
        self.config.read().ocsp_stapling
    }

    /// Fetch or refresh OCSP responses that are due, and staple them.
    ///
    /// Called periodically by [`run_ocsp_refresher`]. Does nothing when
    /// stapling is disabled. Never fails: a responder problem leaves the
    /// certificate unstapled and is logged and counted.
    pub async fn refresh_ocsp(&self) -> OcspRefreshSummary {
        self.refresh_ocsp_inner(false).await
    }

    /// Like [`Self::refresh_ocsp`], but refetches every response now,
    /// regardless of when it is due.
    pub async fn force_refresh_ocsp(&self) -> OcspRefreshSummary {
        self.refresh_ocsp_inner(true).await
    }

    async fn refresh_ocsp_inner(&self, force: bool) -> OcspRefreshSummary {
        if !self.ocsp_stapling_enabled() {
            return OcspRefreshSummary::default();
        }
        let certs = self.loaded.read().unique_certs();
        let summary = self.ocsp.refresh(&self.listener_id, &certs, force).await;
        if summary.changed {
            self.restaple(self.ocsp_stapling_enabled());
        }
        summary
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

/// Extensions treated as certificates, paired with a key of the same stem.
const CERT_EXTENSIONS: &[&str] = &["crt", "pem", "cert"];

/// Extensions treated as private keys.
const KEY_EXTENSIONS: &[&str] = &["key"];

/// Scan configured folders for certificate/key pairs.
///
/// A pair is a certificate file and a key file sharing a stem — `a.crt` with
/// `a.key`. Entries are returned sorted by path so that registration order,
/// and therefore any tie-break between overlapping certificates, does not
/// depend on the order the filesystem happens to return.
///
/// Problems with individual files are skipped and warned about rather than
/// failing the scan. A folder is a moving target — certificates are written
/// there by other processes, sometimes non-atomically — so one half-written
/// file must not take down every other certificate on the listener. The
/// warning is what keeps that from being silent.
fn scan_cert_folders(folders: &[SniCertFolder], listener_id: &str) -> Vec<SniCertificate> {
    let mut found = Vec::new();

    for folder in folders {
        let dir = &folder.cert_folder;
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!(
                    listener_id = %listener_id,
                    cert_folder = %dir.display(),
                    error = %e,
                    "Certificate folder could not be read; no certificates loaded from it"
                );
                continue;
            }
        };

        // Collect and sort first: read_dir order is unspecified, and a
        // tie-break that depends on it would resolve differently between
        // machines or after a reload.
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        paths.sort();

        let mut pairs = 0usize;
        for cert_path in &paths {
            let Some(extension) = cert_path.extension().and_then(|e| e.to_str()) else {
                continue;
            };
            if !CERT_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str()) {
                continue;
            }

            let Some(key_path) = matching_key_path(cert_path) else {
                warn!(
                    listener_id = %listener_id,
                    cert_file = %cert_path.display(),
                    "Certificate in scanned folder has no matching key file; skipping"
                );
                if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
                    metrics.record_folder_entry_skipped(listener_id, "no_key");
                }
                continue;
            };

            // Load it here purely to reject unusable pairs with a precise
            // message. The pair is loaded again by the caller, which is cheap
            // next to serving traffic with a certificate that turns out to be
            // unreadable.
            if let Err(e) = load_certified_key(cert_path, &key_path) {
                warn!(
                    listener_id = %listener_id,
                    cert_file = %cert_path.display(),
                    key_file = %key_path.display(),
                    error = %e,
                    "Certificate pair in scanned folder could not be loaded; skipping"
                );
                if let Some(metrics) = crate::tls_metrics::get_tls_metrics() {
                    metrics.record_folder_entry_skipped(listener_id, "unreadable");
                }
                continue;
            }

            found.push(SniCertificate {
                hostnames: Vec::new(),
                priority_hostnames: Vec::new(),
                cert_file: Some(cert_path.clone()),
                key_file: Some(key_path),
                acme: None,
            });
            pairs += 1;
        }

        info!(
            listener_id = %listener_id,
            cert_folder = %dir.display(),
            certificates = pairs,
            reload_mode = %folder.reload_mode,
            "Scanned certificate folder"
        );
    }

    found
}

/// Find the key file belonging to a certificate, by stem.
///
/// `server.crt` pairs with `server.key`. A `.pem` certificate also accepts a
/// `.pem` key only when they are separate files, since a combined PEM holding
/// both is loaded from the one path.
fn matching_key_path(cert_path: &Path) -> Option<PathBuf> {
    for extension in KEY_EXTENSIONS {
        let candidate = cert_path.with_extension(extension);
        if candidate != cert_path && candidate.is_file() {
            return Some(candidate);
        }
    }
    // A PEM bundle may carry the key alongside the certificate.
    if cert_path
        .extension()
        .and_then(|e| e.to_str())?
        .eq_ignore_ascii_case("pem")
        && load_certified_key(cert_path, cert_path).is_ok()
    {
        return Some(cert_path.to_path_buf());
    }
    None
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

/// Extract DNS hostnames from a certificate's CN and Subject Alternative Names.
///
/// Returns a list of DNS names (e.g., "example.com", "*.example.com") found in:
/// 1. Subject Alternative Name (SAN) DNS entries (preferred)
/// 2. Common Name (CN) as fallback if no SAN DNS entries exist
///
/// IP addresses in SANs are ignored since SNI operates on hostnames only.
fn extract_hostnames_from_cert(cert_der: &CertificateDer<'_>) -> Result<Vec<String>, TlsError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        TlsError::InvalidCertificate(format!("Failed to parse X.509 certificate: {}", e))
    })?;

    let mut hostnames = Vec::new();

    // Try SAN extension first (RFC 6125: SAN takes precedence over CN)
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                hostnames.push(dns.to_lowercase());
            }
        }
    }

    // Fall back to CN only if no SAN DNS names were found
    if hostnames.is_empty() {
        for attr in cert.subject().iter_common_name() {
            if let Ok(cn) = attr.as_str() {
                hostnames.push(cn.to_lowercase());
            }
        }
    }

    if hostnames.is_empty() {
        return Err(TlsError::InvalidCertificate(
            "Certificate has no DNS names in SAN or CN".to_string(),
        ));
    }

    Ok(hostnames)
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
/// The certificate resolver is built fresh from `config` and never changes
/// afterwards. Use [`build_server_config_with_resolver`] to supply a
/// [`HotReloadableSniResolver`] instead, so that certificates reloaded from
/// disk are picked up by connections already being served.
pub fn build_server_config(
    config: &TlsConfig,
    listener_id: &str,
) -> Result<ServerConfig, TlsError> {
    let resolver = SniResolver::from_config(config, Some(listener_id))?;
    build_server_config_with_resolver(config, Arc::new(resolver))
}

/// Build a TLS ServerConfig around a caller-supplied certificate resolver.
///
/// Everything except certificate selection still comes from `config`:
/// protocol versions, cipher suites, client authentication and session
/// resumption. Separating the resolver lets the caller keep a handle on it,
/// which is what makes certificate hot-reload possible — the resolver
/// installed in the [`ServerConfig`] and the one being reloaded have to be
/// the same object, or reloads update something no connection consults.
pub fn build_server_config_with_resolver(
    config: &TlsConfig,
    resolver: Arc<dyn ResolvesServerCert>,
) -> Result<ServerConfig, TlsError> {
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
                .with_cert_resolver(resolver.clone())
        } else {
            // Config validation rejects this combination, so reaching here
            // means a Config was built in code rather than parsed. Failing is
            // still the right answer: quietly serving without client
            // authentication is the outcome an operator asking for mTLS would
            // least expect, and a warning in the startup log is not a
            // proportionate signal for it.
            return Err(TlsError::ConfigBuild(
                "client_auth is enabled but no ca_file is configured. Client certificates \
                 cannot be verified without a CA, and serving without client authentication \
                 would contradict the configuration."
                    .to_string(),
            ));
        }
    } else {
        builder
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone())
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
        // If ACME is configured for this SNI cert, skip existence check
        if sni.acme.is_some() {
            trace!("Skipping manual cert validation for ACME-managed SNI certificate");
            continue;
        }

        // Standard certificate validation
        match (&sni.cert_file, &sni.key_file) {
            (Some(cert_file), Some(key_file)) => {
                if !cert_file.exists() {
                    return Err(TlsError::CertificateLoad(format!(
                        "SNI certificate file not found: {}",
                        cert_file.display()
                    )));
                }
                if !key_file.exists() {
                    return Err(TlsError::KeyLoad(format!(
                        "SNI key file not found: {}",
                        key_file.display()
                    )));
                }
            }
            _ => {
                return Err(TlsError::ConfigBuild(
                    "SNI certificate requires cert_file and key_file (or ACME block)".to_string(),
                ));
            }
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

#[cfg(test)]
mod cert_diff_tests {
    use super::*;

    fn snapshot(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(h, f)| (h.to_string(), f.to_string()))
            .collect()
    }

    #[test]
    fn an_unchanged_folder_reports_no_change() {
        let before = snapshot(&[("<default>", "aa"), ("a.test", "bb")]);
        let diff = CertDiff::between(&before, &before);
        assert!(diff.is_empty());
    }

    #[test]
    fn a_new_certificate_is_reported_as_added() {
        let before = snapshot(&[("a.test", "aa")]);
        let after = snapshot(&[("a.test", "aa"), ("b.test", "bb")]);
        let diff = CertDiff::between(&before, &after);
        assert_eq!(diff.added, vec!["b.test".to_string()]);
        assert!(diff.removed.is_empty());
        assert!(diff.replaced.is_empty());
    }

    #[test]
    fn a_deleted_certificate_is_reported_as_removed() {
        let before = snapshot(&[("a.test", "aa"), ("b.test", "bb")]);
        let after = snapshot(&[("a.test", "aa")]);
        let diff = CertDiff::between(&before, &after);
        assert_eq!(diff.removed, vec!["b.test".to_string()]);
        assert!(diff.added.is_empty());
        assert!(diff.replaced.is_empty());
    }

    /// The case the counts cannot see, and the reason this diff exists: a
    /// renewal swaps the certificate while every hostname and every count stays
    /// exactly the same.
    #[test]
    fn a_renewal_for_the_same_hostname_is_reported_as_replaced() {
        let before = snapshot(&[("a.test", "old00000")]);
        let after = snapshot(&[("a.test", "new11111")]);
        let diff = CertDiff::between(&before, &after);

        assert!(diff.added.is_empty(), "hostname set is unchanged");
        assert!(diff.removed.is_empty(), "hostname set is unchanged");
        assert_eq!(
            diff.replaced,
            vec!["a.test (old00000->new11111)".to_string()]
        );
        assert!(!diff.is_empty(), "a renewal is a change and must be logged");
    }

    /// A 1-for-1 rotation: one name retired, its replacement added, counts equal
    /// on both sides.
    #[test]
    fn a_one_for_one_rotation_shows_both_sides() {
        let before = snapshot(&[("<default>", "dd"), ("old.test", "aa")]);
        let after = snapshot(&[("<default>", "dd"), ("new.test", "bb")]);
        let diff = CertDiff::between(&before, &after);

        assert_eq!(before.len(), after.len(), "counts alone show nothing");
        assert_eq!(diff.added, vec!["new.test".to_string()]);
        assert_eq!(diff.removed, vec!["old.test".to_string()]);
    }

    #[test]
    fn rotating_the_default_certificate_is_visible() {
        let before = snapshot(&[(DEFAULT_CERT_LABEL, "old00000")]);
        let after = snapshot(&[(DEFAULT_CERT_LABEL, "new11111")]);
        assert!(!CertDiff::between(&before, &after).is_empty());
    }

    #[test]
    fn empty_diff_fields_render_as_a_dash() {
        assert_eq!(CertDiff::render(&[]), "-");
        assert_eq!(
            CertDiff::render(&["a.test".to_string(), "b.test".to_string()]),
            "a.test, b.test"
        );
    }
}
