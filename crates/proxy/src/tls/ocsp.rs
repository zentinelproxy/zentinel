//! OCSP stapling.
//!
//! For every certificate a listener serves, the stapler fetches an OCSP
//! response from the responder named in the certificate's Authority
//! Information Access extension, checks it, caches it, and refreshes it well
//! before it expires. [`super::HotReloadableSniResolver`] attaches the cached
//! response to the certificate it hands rustls, which sends it to every client
//! that asks for certificate status.
//!
//! Stapling is best-effort by design: a responder that is down, slow or
//! returns garbage must never fail a handshake. The certificate is then served
//! without a staple, exactly as if stapling were off, and the failure is made
//! visible instead through a warning and `zentinel_tls_ocsp_fetch_total`.
//!
//! What is checked before a response is stapled: the responder reported
//! success, the response is a basic OCSP response, it contains a status for
//! this certificate's serial number, that status is `good`, and the current
//! time lies between `thisUpdate` and `nextUpdate`. The responder's signature
//! is *not* verified here; clients verify it themselves, and a response that
//! fails their check is no worse than no staple. An expired staple is dropped
//! rather than served, because a client that enforces must-staple rejects an
//! expired response.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use rustls::sign::CertifiedKey;
use tracing::{debug, error, info, warn};

use super::TlsError;

/// How often the background task checks whether a response is due.
///
/// A check is cheap -- nothing is fetched unless a response is due -- and this
/// bounds how long a newly loaded certificate goes without a staple.
pub const OCSP_REFRESH_TICK: Duration = Duration::from_secs(30);

/// Upper bound on the time between fetches for one certificate.
///
/// Responses are refreshed at the midpoint of their validity window, but at
/// least this often, so that a revocation is noticed within the hour.
const DEFAULT_MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);

/// Wait before retrying a failed fetch.
const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_secs(300);

/// Never refetch more often than this, even for very short-lived responses.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for one request to an OCSP responder.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Responses are a few kilobytes. Anything far larger is not one.
const MAX_OCSP_RESPONSE_BYTES: usize = 64 * 1024;

/// Responders sometimes date `thisUpdate` slightly ahead of our clock.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::from_secs(300);

/// A checked OCSP response for one certificate.
#[derive(Debug, Clone)]
pub struct OcspCacheEntry {
    /// DER-encoded OCSPResponse, exactly as the responder sent it.
    pub response: Vec<u8>,
    /// When this response was fetched.
    pub fetched_at: Instant,
    /// The response's `thisUpdate`.
    pub this_update: SystemTime,
    /// The response's `nextUpdate`, if it has one.
    pub next_update: Option<SystemTime>,
}

impl OcspCacheEntry {
    /// Whether the response may be stapled at `now`.
    pub fn is_current(&self, now: SystemTime) -> bool {
        let started = self.this_update <= now + CLOCK_SKEW_ALLOWANCE;
        let not_expired = self.next_update.is_none_or(|next| now < next);
        started && not_expired
    }
}

/// What the stapler knows about one certificate, keyed by leaf fingerprint.
#[derive(Debug)]
enum CertState {
    /// Stapling is impossible for this certificate: it names no OCSP
    /// responder, or the chain has no issuer to build a request with. A
    /// certificate never changes, so neither does this; a new certificate on
    /// reload has a new fingerprint and is looked at afresh.
    NotApplicable,
    Tracked {
        staple: Option<OcspCacheEntry>,
        next_attempt: Instant,
        /// Whether the last attempt failed. Used to warn on the transition
        /// into failure rather than on every retry.
        failing: bool,
    },
}

/// Counts from one refresh pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OcspRefreshSummary {
    /// Certificates with a valid staple after the pass.
    pub stapled: usize,
    /// Fetches attempted in this pass.
    pub fetched: usize,
    /// Fetches in this pass that did not produce a usable response.
    pub failed: usize,
    /// Certificates for which stapling is impossible.
    pub not_applicable: usize,
    /// Whether any certificate's staple was added, replaced or removed.
    pub changed: bool,
}

/// Fetches, checks, caches and refreshes OCSP responses.
///
/// One stapler belongs to one listener's resolver, so the set of certificates
/// it tracks is exactly the set that listener serves.
pub struct OcspStapler {
    certs: RwLock<HashMap<String, CertState>>,
    max_refresh_interval: Duration,
    retry_interval: Duration,
}

impl std::fmt::Debug for OcspStapler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspStapler")
            .field("tracked", &self.certs.read().len())
            .finish()
    }
}

impl Default for OcspStapler {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a fetch did not produce a staple. Maps to a bounded metric label.
#[derive(Debug)]
enum FetchError {
    /// Could not reach the responder, or it answered with an HTTP error.
    Transport(String),
    /// The response could not be used (malformed, unsuccessful, stale, or for
    /// another certificate).
    Invalid(String),
    /// The responder says the certificate is revoked or unknown.
    NotGood(&'static str),
}

impl FetchError {
    fn metric_label(&self) -> &'static str {
        match self {
            FetchError::Transport(_) => "failure",
            FetchError::Invalid(_) => "invalid",
            FetchError::NotGood(_) => "revoked",
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Transport(e) => write!(f, "{e}"),
            FetchError::Invalid(e) => write!(f, "unusable OCSP response: {e}"),
            FetchError::NotGood(status) => write!(f, "OCSP responder reports status '{status}'"),
        }
    }
}

impl OcspStapler {
    /// Create a stapler with the default refresh and retry intervals.
    pub fn new() -> Self {
        Self::with_intervals(DEFAULT_MAX_REFRESH_INTERVAL, DEFAULT_RETRY_INTERVAL)
    }

    /// Create a stapler with custom intervals.
    pub fn with_intervals(max_refresh_interval: Duration, retry_interval: Duration) -> Self {
        Self {
            certs: RwLock::new(HashMap::new()),
            max_refresh_interval,
            retry_interval,
        }
    }

    /// The response to staple to `cert`, if there is a current one.
    pub fn staple_for(&self, cert: &CertifiedKey) -> Option<Vec<u8>> {
        let leaf = cert.cert.first()?;
        let fingerprint = calculate_cert_fingerprint(leaf.as_ref());
        match self.certs.read().get(&fingerprint) {
            Some(CertState::Tracked {
                staple: Some(entry),
                ..
            }) if entry.is_current(SystemTime::now()) => Some(entry.response.clone()),
            _ => None,
        }
    }

    /// Forget every cached response.
    pub fn clear_cache(&self) {
        self.certs.write().clear();
        info!("OCSP cache cleared");
    }

    /// Bring every certificate's response up to date.
    ///
    /// Fetches only what is due unless `force` is set. Certificates no longer
    /// in `certs` are forgotten, so a reload that removes a certificate also
    /// removes its staple. Never fails: problems are logged, counted, and
    /// leave the certificate unstapled.
    pub async fn refresh(
        &self,
        listener_id: &str,
        certs: &[Arc<CertifiedKey>],
        force: bool,
    ) -> OcspRefreshSummary {
        let metrics = crate::tls_metrics::get_tls_metrics();
        let mut summary = OcspRefreshSummary::default();
        let now = Instant::now();
        let wall_now = SystemTime::now();

        let mut seen = HashSet::new();
        let mut due = Vec::new();

        for cert in certs {
            let Some(leaf) = cert.cert.first() else {
                continue;
            };
            let fingerprint = calculate_cert_fingerprint(leaf.as_ref());
            if !seen.insert(fingerprint.clone()) {
                continue;
            }

            let mut states = self.certs.write();
            let state = states.entry(fingerprint.clone()).or_insert_with(|| {
                Self::classify(listener_id, &fingerprint, cert, metrics.as_deref(), now)
            });

            match state {
                CertState::NotApplicable => summary.not_applicable += 1,
                CertState::Tracked {
                    staple,
                    next_attempt,
                    ..
                } => {
                    // Drop a staple that has run out before anything else: it
                    // must not be served even if the refetch below fails.
                    if staple.as_ref().is_some_and(|s| !s.is_current(wall_now)) {
                        warn!(
                            listener_id = %listener_id,
                            cert_fingerprint = %short(&fingerprint),
                            "OCSP staple expired before it could be refreshed; serving the certificate without one"
                        );
                        *staple = None;
                        summary.changed = true;
                    }
                    if force || now >= *next_attempt {
                        due.push((fingerprint, cert.clone()));
                    }
                }
            }
        }

        // Forget certificates this listener no longer serves.
        {
            let mut states = self.certs.write();
            let before = states.len();
            states.retain(|fp, _| seen.contains(fp));
            if states.len() != before {
                summary.changed = true;
            }
        }

        if !due.is_empty() {
            let client = match reqwest::Client::builder().timeout(FETCH_TIMEOUT).build() {
                Ok(c) => Some(c),
                Err(e) => {
                    warn!(error = %e, "Could not create HTTP client for OCSP fetches");
                    None
                }
            };

            for (fingerprint, cert) in due {
                summary.fetched += 1;
                let result = match &client {
                    Some(client) => fetch_and_check(client, &cert).await,
                    None => Err(FetchError::Transport("no HTTP client".to_string())),
                };
                if result.is_err() {
                    summary.failed += 1;
                }
                if self.record(listener_id, &fingerprint, result, metrics.as_deref()) {
                    summary.changed = true;
                }
            }
        }

        summary.stapled = self
            .certs
            .read()
            .values()
            .filter(|s| {
                matches!(s, CertState::Tracked { staple: Some(e), .. } if e.is_current(wall_now))
            })
            .count();
        if let Some(m) = &metrics {
            m.set_ocsp_stapled(listener_id, summary.stapled);
        }
        summary
    }

    /// Decide, once per certificate, whether stapling is possible at all.
    fn classify(
        listener_id: &str,
        fingerprint: &str,
        cert: &CertifiedKey,
        metrics: Option<&crate::tls_metrics::TlsMetrics>,
        now: Instant,
    ) -> CertState {
        let Some(leaf) = cert.cert.first() else {
            return CertState::NotApplicable;
        };
        match responder_url(leaf.as_ref()) {
            Ok(None) => {
                // Common and harmless: many CAs no longer run OCSP.
                debug!(
                    listener_id = %listener_id,
                    cert_fingerprint = %short(fingerprint),
                    "Certificate names no OCSP responder; nothing to staple"
                );
                CertState::NotApplicable
            }
            Err(e) => {
                warn!(
                    listener_id = %listener_id,
                    cert_fingerprint = %short(fingerprint),
                    error = %e,
                    "Could not read the certificate's OCSP responder; it will be served without a staple"
                );
                CertState::NotApplicable
            }
            Ok(Some(url)) if cert.cert.len() < 2 => {
                warn!(
                    listener_id = %listener_id,
                    cert_fingerprint = %short(fingerprint),
                    ocsp_url = %url,
                    "Certificate names an OCSP responder but its file has no issuer certificate; \
                     include the intermediate in cert-file to enable OCSP stapling"
                );
                if let Some(m) = metrics {
                    m.record_ocsp_fetch(listener_id, "no_issuer");
                }
                CertState::NotApplicable
            }
            Ok(Some(_)) => CertState::Tracked {
                staple: None,
                next_attempt: now,
                failing: false,
            },
        }
    }

    /// Store a fetch result. Returns whether the served staple changed.
    fn record(
        &self,
        listener_id: &str,
        fingerprint: &str,
        result: Result<OcspCacheEntry, FetchError>,
        metrics: Option<&crate::tls_metrics::TlsMetrics>,
    ) -> bool {
        let mut states = self.certs.write();
        let Some(CertState::Tracked {
            staple,
            next_attempt,
            failing,
        }) = states.get_mut(fingerprint)
        else {
            return false;
        };

        match result {
            Ok(entry) => {
                if let Some(m) = metrics {
                    m.record_ocsp_fetch(listener_id, "success");
                }
                let refresh_in = self.refresh_delay(&entry);
                if *failing || staple.is_none() {
                    info!(
                        listener_id = %listener_id,
                        cert_fingerprint = %short(fingerprint),
                        next_update = ?entry.next_update.map(humantime_utc),
                        refresh_in_secs = refresh_in.as_secs(),
                        "OCSP response fetched; certificate is now stapled"
                    );
                } else {
                    debug!(
                        listener_id = %listener_id,
                        cert_fingerprint = %short(fingerprint),
                        refresh_in_secs = refresh_in.as_secs(),
                        "OCSP response refreshed"
                    );
                }
                *staple = Some(entry);
                *next_attempt = Instant::now() + refresh_in;
                *failing = false;
                true
            }
            Err(e) => {
                if let Some(m) = metrics {
                    m.record_ocsp_fetch(listener_id, e.metric_label());
                }
                *next_attempt = Instant::now() + self.retry_interval;
                let mut changed = false;
                if let FetchError::NotGood(status) = e {
                    // Stapling a revoked status would make every client that
                    // checks reject the certificate, and keeping an older
                    // `good` response would hide the revocation.
                    error!(
                        listener_id = %listener_id,
                        cert_fingerprint = %short(fingerprint),
                        status = status,
                        "OCSP responder does not report this certificate as good; serving it without a staple"
                    );
                    changed = staple.take().is_some();
                } else if !*failing {
                    warn!(
                        listener_id = %listener_id,
                        cert_fingerprint = %short(fingerprint),
                        error = %e,
                        keeping_previous_staple = staple.is_some(),
                        retry_in_secs = self.retry_interval.as_secs(),
                        "OCSP fetch failed; the certificate is served without a fresh staple"
                    );
                } else {
                    debug!(
                        listener_id = %listener_id,
                        cert_fingerprint = %short(fingerprint),
                        error = %e,
                        "OCSP fetch still failing"
                    );
                }
                *failing = true;
                changed
            }
        }
    }

    /// When to refetch: the midpoint of the validity window, capped.
    fn refresh_delay(&self, entry: &OcspCacheEntry) -> Duration {
        let midpoint = entry.next_update.and_then(|next| {
            next.duration_since(entry.this_update)
                .ok()
                .map(|window| window / 2)
                .and_then(|half| {
                    (entry.this_update + half)
                        .duration_since(SystemTime::now())
                        .ok()
                })
        });
        midpoint
            .unwrap_or(self.max_refresh_interval)
            .min(self.max_refresh_interval)
            .max(MIN_REFRESH_INTERVAL.min(self.max_refresh_interval))
    }
}

/// Fetch a response for `cert` (leaf plus issuer in the chain) and check it.
async fn fetch_and_check(
    client: &reqwest::Client,
    cert: &CertifiedKey,
) -> Result<OcspCacheEntry, FetchError> {
    use x509_parser::prelude::*;

    let leaf_der = cert.cert.first().map(|c| c.as_ref()).unwrap_or_default();
    let issuer_der = cert.cert.get(1).map(|c| c.as_ref()).unwrap_or_default();

    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| FetchError::Invalid(format!("parsing certificate: {e}")))?;
    let (_, issuer) = X509Certificate::from_der(issuer_der)
        .map_err(|e| FetchError::Invalid(format!("parsing issuer certificate: {e}")))?;

    let url = responder_url(leaf_der)
        .map_err(|e| FetchError::Invalid(e.to_string()))?
        .ok_or_else(|| FetchError::Invalid("no OCSP responder URL".to_string()))?;
    let request = build_ocsp_request(&leaf, &issuer);
    let serial = leaf.serial.to_bytes_be();

    let response = client
        .post(&url)
        .header("Content-Type", "application/ocsp-request")
        .body(request)
        .send()
        .await
        .map_err(|e| {
            FetchError::Transport(format!("OCSP request to {url} failed: {}", error_chain(&e)))
        })?;
    if !response.status().is_success() {
        return Err(FetchError::Transport(format!(
            "OCSP responder {url} returned HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|len| len as usize > MAX_OCSP_RESPONSE_BYTES)
    {
        return Err(FetchError::Invalid("response too large".to_string()));
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| FetchError::Transport(format!("reading OCSP response from {url}: {e}")))?;
    if body.len() > MAX_OCSP_RESPONSE_BYTES {
        return Err(FetchError::Invalid("response too large".to_string()));
    }

    let parsed = parse_ocsp_response(&body, &serial).map_err(FetchError::Invalid)?;
    match parsed.status {
        CertStatus::Good => {}
        CertStatus::Revoked => return Err(FetchError::NotGood("revoked")),
        CertStatus::Unknown => return Err(FetchError::NotGood("unknown")),
    }
    let entry = OcspCacheEntry {
        response: body.to_vec(),
        fetched_at: Instant::now(),
        this_update: parsed.this_update,
        next_update: parsed.next_update,
    };
    if !entry.is_current(SystemTime::now()) {
        return Err(FetchError::Invalid(
            "response is outside its validity window (check the system clock)".to_string(),
        ));
    }
    Ok(entry)
}

/// Run the refresh loop for one listener's resolver until the process exits.
pub async fn run_ocsp_refresher(resolver: Arc<super::HotReloadableSniResolver>, tick: Duration) {
    loop {
        resolver.refresh_ocsp().await;
        tokio::time::sleep(tick).await;
    }
}

// ============================================================================
// Request building
// ============================================================================

/// The OCSP responder URL in a certificate's Authority Information Access
/// extension, or `None` if it names none.
pub(crate) fn responder_url(cert_der: &[u8]) -> Result<Option<String>, TlsError> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| TlsError::OcspFetch(format!("Failed to parse certificate: {e}")))?;

    for ext in cert.extensions() {
        if ext.oid != oid_registry::OID_PKIX_AUTHORITY_INFO_ACCESS {
            continue;
        }
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            return Err(TlsError::OcspFetch(
                "Failed to parse Authority Information Access extension".to_string(),
            ));
        };
        for access in &aia.accessdescs {
            if access.access_method == oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
                if let GeneralName::URI(url) = &access.access_location {
                    return Ok(Some(url.to_string()));
                }
            }
        }
    }
    Ok(None)
}

/// Build a DER OCSPRequest (RFC 6960) for one certificate, using SHA-256
/// CertID hashes.
fn build_ocsp_request(
    cert: &x509_parser::certificate::X509Certificate,
    issuer: &x509_parser::certificate::X509Certificate,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    // Hash of the issuer's DER-encoded subject Name.
    let issuer_name_hash = Sha256::digest(issuer.subject().as_raw());
    // Hash of the issuer's public key BIT STRING contents.
    let issuer_key_hash = Sha256::digest(issuer.public_key().subject_public_key.data.as_ref());
    let serial = cert.serial.to_bytes_be();

    // id-sha256
    let sha256_oid: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let hash_algorithm = der_sequence(&[&der_oid(sha256_oid), &der_null()]);
    let cert_id = der_sequence(&[
        &hash_algorithm,
        &der_octet_string(&issuer_name_hash),
        &der_octet_string(&issuer_key_hash),
        &der_integer(&serial),
    ]);
    let request = der_sequence(&[&cert_id]);
    let request_list = der_sequence(&[&request]);
    let tbs_request = der_sequence(&[&request_list]);
    der_sequence(&[&tbs_request])
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn der_sequence(items: &[&[u8]]) -> Vec<u8> {
    der_tlv(0x30, &items.concat())
}

fn der_oid(oid: &[u8]) -> Vec<u8> {
    der_tlv(0x06, oid)
}

fn der_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    der_tlv(0x04, data)
}

fn der_integer(data: &[u8]) -> Vec<u8> {
    let trimmed = match data.iter().position(|&b| b != 0) {
        Some(pos) => &data[pos..],
        None => &[0][..],
    };
    if trimmed[0] & 0x80 != 0 {
        let mut padded = vec![0];
        padded.extend_from_slice(trimmed);
        der_tlv(0x02, &padded)
    } else {
        der_tlv(0x02, trimmed)
    }
}

// ============================================================================
// Response parsing
// ============================================================================

/// The status a responder gave one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CertStatus {
    Good,
    Revoked,
    Unknown,
}

/// The parts of an OCSP response that decide whether it can be stapled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedOcspResponse {
    pub status: CertStatus,
    pub this_update: SystemTime,
    pub next_update: Option<SystemTime>,
}

/// Read one DER TLV: returns (tag, contents, rest).
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), String> {
    let (&tag, rest) = input.split_first().ok_or("truncated DER: no tag")?;
    if tag & 0x1f == 0x1f {
        return Err("multi-byte DER tags are not expected in OCSP".to_string());
    }
    let (&first, mut rest) = rest.split_first().ok_or("truncated DER: no length")?;
    let len = if first < 0x80 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err("unsupported DER length encoding".to_string());
        }
        if rest.len() < n {
            return Err("truncated DER length".to_string());
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | b as usize);
        rest = &rest[n..];
        len
    };
    if rest.len() < len {
        return Err("truncated DER contents".to_string());
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn expect_tlv<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<(&'a [u8], &'a [u8]), String> {
    let (got, content, rest) = read_tlv(input)?;
    if got != tag {
        return Err(format!(
            "expected {what} (tag 0x{tag:02x}), found tag 0x{got:02x}"
        ));
    }
    Ok((content, rest))
}

/// Strip leading zero bytes so serials compare by value.
fn integer_value(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[start..]
}

/// Parse an OCSPResponse and pick out the status for `serial`.
pub(crate) fn parse_ocsp_response(der: &[u8], serial: &[u8]) -> Result<ParsedOcspResponse, String> {
    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, responseBytes [0] EXPLICIT ... }
    let (ocsp_response, _) = expect_tlv(der, 0x30, "OCSPResponse")?;
    let (status, rest) = expect_tlv(ocsp_response, 0x0a, "responseStatus")?;
    match status {
        [0] => {}
        [code] => {
            let name = match code {
                1 => "malformedRequest",
                2 => "internalError",
                3 => "tryLater",
                5 => "sigRequired",
                6 => "unauthorized",
                _ => "unrecognised",
            };
            return Err(format!("responder returned status {name} ({code})"));
        }
        _ => return Err("malformed responseStatus".to_string()),
    }

    let (response_bytes_explicit, _) = expect_tlv(rest, 0xa0, "responseBytes")?;
    let (response_bytes, _) = expect_tlv(response_bytes_explicit, 0x30, "ResponseBytes")?;
    let (response_type, rest) = expect_tlv(response_bytes, 0x06, "responseType")?;
    // id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
    const ID_PKIX_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
    if response_type != ID_PKIX_OCSP_BASIC {
        return Err("not a basic OCSP response".to_string());
    }
    let (basic_der, _) = expect_tlv(rest, 0x04, "response")?;

    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, ... }
    let (basic, _) = expect_tlv(basic_der, 0x30, "BasicOCSPResponse")?;
    let (tbs, _) = expect_tlv(basic, 0x30, "ResponseData")?;

    // ResponseData ::= SEQUENCE { version [0] EXPLICIT OPTIONAL, responderID,
    //                             producedAt, responses, responseExtensions [1] OPTIONAL }
    let mut rest = tbs;
    let (tag, _, after) = read_tlv(rest)?;
    if tag == 0xa0 {
        rest = after;
    }
    let (tag, _, after) = read_tlv(rest)?; // responderID: [1] byName or [2] byKey
    if tag != 0xa1 && tag != 0xa2 {
        return Err(format!("unexpected responderID tag 0x{tag:02x}"));
    }
    let (_, after) = expect_tlv(after, 0x18, "producedAt")?;
    let (mut responses, _) = expect_tlv(after, 0x30, "responses")?;

    let wanted = integer_value(serial);
    while !responses.is_empty() {
        let (single, next) = expect_tlv(responses, 0x30, "SingleResponse")?;
        responses = next;

        // SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate,
        //                               nextUpdate [0] EXPLICIT OPTIONAL, ... }
        let (cert_id, rest) = expect_tlv(single, 0x30, "CertID")?;
        let (_, cid) = expect_tlv(cert_id, 0x30, "hashAlgorithm")?;
        let (_, cid) = expect_tlv(cid, 0x04, "issuerNameHash")?;
        let (_, cid) = expect_tlv(cid, 0x04, "issuerKeyHash")?;
        let (serial_number, _) = expect_tlv(cid, 0x02, "serialNumber")?;
        if integer_value(serial_number) != wanted {
            continue;
        }

        let (status_tag, _, rest) = read_tlv(rest)?;
        let status = match status_tag {
            0x80 => CertStatus::Good,
            0xa1 => CertStatus::Revoked,
            0x82 => CertStatus::Unknown,
            other => return Err(format!("unexpected certStatus tag 0x{other:02x}")),
        };
        let (this_update, rest) = expect_tlv(rest, 0x18, "thisUpdate")?;
        let this_update = parse_generalized_time(this_update)?;
        let next_update = match read_tlv(rest) {
            Ok((0xa0, explicit, _)) => {
                let (time, _) = expect_tlv(explicit, 0x18, "nextUpdate")?;
                Some(parse_generalized_time(time)?)
            }
            _ => None,
        };
        return Ok(ParsedOcspResponse {
            status,
            this_update,
            next_update,
        });
    }
    Err("response contains no status for this certificate".to_string())
}

/// Parse a DER GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`).
fn parse_generalized_time(bytes: &[u8]) -> Result<SystemTime, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "GeneralizedTime is not ASCII")?;
    let bad = || format!("invalid GeneralizedTime '{s}'");
    let s_trim = s.strip_suffix('Z').ok_or_else(bad)?;
    let (main, _fraction) = s_trim.split_once('.').unwrap_or((s_trim, ""));
    if main.len() != 14 || !main.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let num = |r: std::ops::Range<usize>| main[r].parse::<i64>().map_err(|_| bad());
    let (year, month, day) = (num(0..4)?, num(4..6)?, num(6..8)?);
    let (hour, minute, second) = (num(8..10)?, num(10..12)?, num(12..14)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(bad());
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    if secs < 0 {
        return Err(bad());
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn humantime_utc(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An error and its sources, so "error sending request" says why.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(inner) = source {
        out.push_str(": ");
        out.push_str(&inner.to_string());
        source = inner.source();
    }
    out
}

/// Full SHA-256 of a certificate's DER encoding, as lowercase hex.
fn calculate_cert_fingerprint(cert_der: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(cert_der))
}

/// The first 16 hex characters, matching the fingerprints in reload logs.
fn short(fingerprint: &str) -> &str {
    &fingerprint[..fingerprint.len().min(16)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_parses_to_unix_seconds() {
        let t = parse_generalized_time(b"20261031120000Z").unwrap();
        assert_eq!(humantime_utc(t), 1_793_448_000);
        let t = parse_generalized_time(b"19700101000000Z").unwrap();
        assert_eq!(humantime_utc(t), 0);
        // Fractional seconds are allowed and ignored.
        let t = parse_generalized_time(b"20000229235959.123Z").unwrap();
        assert_eq!(humantime_utc(t), 951_868_799);
    }

    #[test]
    fn generalized_time_rejects_garbage() {
        assert!(parse_generalized_time(b"20261031120000").is_err());
        assert!(parse_generalized_time(b"2026103112000Z").is_err());
        assert!(parse_generalized_time(b"20261331120000Z").is_err());
    }

    #[test]
    fn der_integer_is_minimal_and_positive() {
        assert_eq!(der_integer(&[0x00, 0x01]), vec![0x02, 0x01, 0x01]);
        assert_eq!(der_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der_integer(&[0x00]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn der_long_lengths_round_trip_through_the_reader() {
        let content = vec![0xab; 300];
        let encoded = der_tlv(0x04, &content);
        let (tag, got, rest) = read_tlv(&encoded).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(got, &content[..]);
        assert!(rest.is_empty());
    }

    #[test]
    fn unsuccessful_responder_status_is_reported_by_name() {
        // OCSPResponse { responseStatus tryLater }
        let der = [0x30, 0x03, 0x0a, 0x01, 0x03];
        let err = parse_ocsp_response(&der, &[1]).unwrap_err();
        assert!(err.contains("tryLater"), "{err}");
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        for len in 0..5 {
            let der = [0x30, 0x82, 0x01, 0x00, 0x0a];
            let _ = parse_ocsp_response(&der[..len], &[1]);
        }
    }

    #[test]
    fn entry_validity_window() {
        let now = SystemTime::now();
        let entry = |this: SystemTime, next: Option<SystemTime>| OcspCacheEntry {
            response: vec![],
            fetched_at: Instant::now(),
            this_update: this,
            next_update: next,
        };
        let hour = Duration::from_secs(3600);
        assert!(entry(now - hour, Some(now + hour)).is_current(now));
        assert!(!entry(now - 2 * hour, Some(now - hour)).is_current(now));
        assert!(!entry(now + hour, Some(now + 2 * hour)).is_current(now));
        assert!(entry(now - hour, None).is_current(now));
    }
}
