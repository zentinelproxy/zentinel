//! ACME Renewal Information (ARI) support (RFC 9773)
//!
//! Provides support for the ACME Renewal Information (ARI) extension, enabling
//! CAs to suggest renewal windows and client order replacement (`replaces`).
//!
//! # Specification Reference
//!
//! - RFC 9773: Automated Certificate Management Environment (ACME) Renewal Information (ARI)
//!   <https://www.rfc-editor.org/rfc/rfc9773.html>

use std::time::Duration;

use chrono::{DateTime, Utc};
use instant_acme::{CertificateIdentifier, SuggestedWindow};
use rand::RngExt;
use rustls::pki_types::CertificateDer;
use tracing::{debug, warn};

use super::error::AcmeError;

/// Minimum refresh interval for ARI polling (1 minute, RFC 9773 §4.3.2).
pub const ARI_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum refresh interval for ARI polling (24 hours, RFC 9773 §4.3.2).
pub const ARI_MAX_REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Default retry interval for long-term errors (6 hours, RFC 9773 §4.3.3).
pub const ARI_LONG_TERM_RETRY_INTERVAL: Duration = Duration::from_secs(6 * 3600);

/// Maximum number of consecutive temporary failure retries before transitioning to long-term retry.
pub const ARI_MAX_TEMP_RETRIES: u32 = 3;

/// Base backoff for temporary failures (1 minute).
pub const ARI_BASE_TEMP_BACKOFF: Duration = Duration::from_secs(60);

/// CA ARI capability status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AriCapability {
    /// ARI request succeeded; CA is confirmed to support RFC 9773.
    Supported,
    /// CA explicitly reported that ARI is unsupported (directory metadata omits renewalInfo or Error::Unsupported).
    ///
    /// Note: Non-5xx HTTP errors (such as 404 Not Found) are long-term errors, NOT evidence of unsupported capability.
    Unsupported,
    /// ARI support is not yet known or inconclusive (initial state or transient/long-term error).
    Unknown,
}

/// Classification of ARI request errors per RFC 9773 §4.3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AriErrorClassification {
    /// CA explicitly reports that ARI is unsupported (e.g. Error::Unsupported when Directory omits renewalInfo).
    Unsupported,
    /// Temporary/transient failure eligible for bounded exponential backoff (e.g. connection/request timeout, 5xx server response).
    Temporary,
    /// Long-term failure requiring ~6 hour retry (e.g. non-5xx HTTP responses like 404 Not Found, missing/invalid Retry-After, invalid renewal response, DNS resolution failure, connection refusal).
    LongTerm,
}

/// Errors specific to ARI operations.
#[derive(Debug, thiserror::Error)]
pub enum AriError {
    /// ACME protocol or transport error from instant-acme
    #[error("ACME protocol error: {0}")]
    Protocol(#[from] instant_acme::Error),

    /// Invalid renewal window suggested by CA
    #[error("Invalid renewal window: end ({end}) <= start ({start})")]
    InvalidWindow {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },

    /// Failed to parse certificate or extract ARI identifier
    #[error("Certificate parse error: {0}")]
    CertificateParse(String),

    /// ACME account not initialized
    #[error("ACME account not initialized")]
    NoAccount,

    /// Error ensuring ACME account
    #[error("Failed to ensure ACME account: {0}")]
    Account(String),
}

impl AriError {
    /// Classify the error into Unsupported, Temporary, or LongTerm.
    pub fn classification(&self) -> AriErrorClassification {
        match self {
            AriError::Protocol(err) => classify_instant_acme_error(err),
            AriError::InvalidWindow { .. } => AriErrorClassification::LongTerm,
            AriError::CertificateParse(_) => AriErrorClassification::LongTerm,
            AriError::NoAccount => AriErrorClassification::Temporary,
            AriError::Account(_) => AriErrorClassification::Temporary,
        }
    }

    /// Whether this error indicates ARI is explicitly unsupported.
    pub fn is_unsupported(&self) -> bool {
        self.classification() == AriErrorClassification::Unsupported
    }

    /// Whether this error is transient and eligible for bounded exponential backoff.
    pub fn is_temporary(&self) -> bool {
        self.classification() == AriErrorClassification::Temporary
    }

    /// Whether this error is a long-term failure requiring ~6 hour retry.
    pub fn is_long_term(&self) -> bool {
        self.classification() == AriErrorClassification::LongTerm
    }
}

/// Classify an `instant_acme::Error` into an `AriErrorClassification` (RFC 9773 §4.3.3).
pub fn classify_instant_acme_error(err: &instant_acme::Error) -> AriErrorClassification {
    match err {
        instant_acme::Error::Unsupported(_) => AriErrorClassification::Unsupported,
        instant_acme::Error::Api(problem) => match problem.status {
            Some(status) if (500..=599).contains(&status) => AriErrorClassification::Temporary,
            // RFC 9773 §4.3.3 / Dependency boundary note:
            // instant-acme 0.8.5 parses Problem JSON (RFC 7807/RFC 8555) and exposes the
            // optional `problem.status: Option<u16>` as deserialized from the response body.
            // The actual transport-level HTTP status code header is not retained by the
            // library when Problem `status` is absent, or if the response fails to parse
            // as Problem JSON (which yields `Error::Json` or `Error::Str("missing Retry-After header")`).
            //
            // When `problem.status` is present and in 500..=599, it is classified as Temporary.
            // When `problem.status` is non-5xx (including 404), RFC 9773 classifies it as LongTerm.
            // When `problem.status` is missing (`None`), we cannot confirm a 5xx status, so we
            // fall back conservatively to LongTerm. Crucially, missing or non-5xx problem details
            // are NEVER treated as proof that ARI is Unsupported.
            _ => AriErrorClassification::LongTerm,
        },
        instant_acme::Error::Timeout(_) => AriErrorClassification::Temporary,
        instant_acme::Error::Http(_) => {
            // Client-side HTTP creation error (e.g. invalid header) is long-term.
            AriErrorClassification::LongTerm
        }
        instant_acme::Error::Hyper(hyper_err) => {
            if hyper_err.is_timeout() {
                return AriErrorClassification::Temporary;
            }

            // Inspect the error source chain for structured std::io::Error
            let mut curr: Option<&(dyn std::error::Error + 'static)> = Some(hyper_err);
            while let Some(e) = curr {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    match io_err.kind() {
                        std::io::ErrorKind::ConnectionRefused => {
                            // RFC 9773 §4.3.3: Connection refusal is an example of long-term error.
                            return AriErrorClassification::LongTerm;
                        }
                        std::io::ErrorKind::TimedOut => {
                            return AriErrorClassification::Temporary;
                        }
                        std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof => {
                            return AriErrorClassification::Temporary;
                        }
                        _ => {}
                    }
                }
                curr = e.source();
            }

            let msg = hyper_err.to_string().to_lowercase();
            if msg.contains("connection refused")
                || msg.contains("dns")
                || msg.contains("resolve")
                || msg.contains("name resolution")
                || msg.contains("failed to lookup address")
                || msg.contains("name or service not known")
                || msg.contains("not found")
            {
                AriErrorClassification::LongTerm
            } else if msg.contains("timeout")
                || msg.contains("timed out")
                || msg.contains("reset")
                || msg.contains("closed")
                || msg.contains("aborted")
                || msg.contains("eof")
            {
                AriErrorClassification::Temporary
            } else {
                AriErrorClassification::LongTerm
            }
        }
        instant_acme::Error::Str("missing Retry-After header") => AriErrorClassification::LongTerm,
        instant_acme::Error::Json(_) => {
            // Invalid renewal information JSON response (RFC 9773 §4.3.3)
            AriErrorClassification::LongTerm
        }
        instant_acme::Error::InvalidUri(_) => AriErrorClassification::LongTerm,
        instant_acme::Error::Crypto | instant_acme::Error::KeyRejected => {
            AriErrorClassification::LongTerm
        }
        instant_acme::Error::Other(ref err) => {
            let mut curr: Option<&(dyn std::error::Error + 'static)> = Some(err.as_ref());
            while let Some(e) = curr {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    match io_err.kind() {
                        std::io::ErrorKind::ConnectionRefused => {
                            return AriErrorClassification::LongTerm;
                        }
                        std::io::ErrorKind::TimedOut => {
                            return AriErrorClassification::Temporary;
                        }
                        std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::UnexpectedEof => {
                            return AriErrorClassification::Temporary;
                        }
                        _ => {}
                    }
                }
                curr = e.source();
            }

            let msg = err.to_string().to_lowercase();
            if msg.contains("connection refused")
                || msg.contains("dns")
                || msg.contains("resolve")
                || msg.contains("name resolution")
                || msg.contains("failed to lookup address")
                || msg.contains("name or service not known")
                || msg.contains("not found")
            {
                AriErrorClassification::LongTerm
            } else if msg.contains("timeout")
                || msg.contains("timed out")
                || msg.contains("reset")
                || msg.contains("closed")
                || msg.contains("aborted")
                || msg.contains("eof")
            {
                AriErrorClassification::Temporary
            } else {
                AriErrorClassification::LongTerm
            }
        }
        _ => AriErrorClassification::LongTerm,
    }
}

/// Validated suggested renewal window from the ACME server (RFC 9773 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalWindow {
    /// Start of suggested renewal window.
    pub start: DateTime<Utc>,
    /// End of suggested renewal window.
    pub end: DateTime<Utc>,
}

impl RenewalWindow {
    /// Create and validate a renewal window.
    ///
    /// # Errors
    /// Returns `AriError::InvalidWindow` if `end <= start`.
    pub fn new(start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Self, AriError> {
        if end <= start {
            return Err(AriError::InvalidWindow { start, end });
        }
        Ok(Self { start, end })
    }

    /// Construct from `instant_acme::SuggestedWindow`.
    ///
    /// # Errors
    /// Returns `AriError::InvalidWindow` if `end <= start`.
    pub fn from_instant_acme(window: &SuggestedWindow) -> Result<Self, AriError> {
        let start = offset_date_time_to_chrono(window.start);
        let end = offset_date_time_to_chrono(window.end);
        Self::new(start, end)
    }

    /// Calculate the intersection with another window, if non-empty.
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }
}

/// Convert `time::OffsetDateTime` to `chrono::DateTime<Utc>`.
pub fn offset_date_time_to_chrono(odt: time::OffsetDateTime) -> DateTime<Utc> {
    DateTime::from_timestamp(odt.unix_timestamp(), odt.nanosecond()).unwrap_or_else(|| {
        if odt.unix_timestamp() < 0 {
            DateTime::<Utc>::MIN_UTC
        } else {
            DateTime::<Utc>::MAX_UTC
        }
    })
}

/// Convert `chrono::DateTime<Utc>` to `time::OffsetDateTime`.
pub fn chrono_to_offset_date_time(dt: DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp_nanos(dt.timestamp_nanos_opt().unwrap_or(0) as i128)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

/// Clamp the refresh interval according to RFC 9773 §4.3.2 bounds.
pub fn clamp_refresh_interval(interval: Duration) -> Duration {
    interval.clamp(ARI_MIN_REFRESH_INTERVAL, ARI_MAX_REFRESH_INTERVAL)
}

/// Calculate retry delay and whether the retry transitioned to long-term (RFC 9773 §4.3.3).
///
/// `temp_failure_count` represents the 1-based number of consecutive temporary failures:
/// - 1st failure (count <= 1): base backoff (1 minute)
/// - 2nd failure (count == 2): 2 minutes
/// - 3rd failure (count == 3): 4 minutes
/// - Failure count > `ARI_MAX_TEMP_RETRIES` (3 attempts) transitions to long-term (6 hours).
pub fn calculate_retry_delay(
    classification: AriErrorClassification,
    temp_failure_count: u32,
) -> (Duration, bool) {
    match classification {
        AriErrorClassification::Unsupported => (ARI_LONG_TERM_RETRY_INTERVAL, false),
        AriErrorClassification::LongTerm => (ARI_LONG_TERM_RETRY_INTERVAL, false),
        AriErrorClassification::Temporary => {
            if temp_failure_count > ARI_MAX_TEMP_RETRIES {
                (ARI_LONG_TERM_RETRY_INTERVAL, true)
            } else {
                let exponent = temp_failure_count.saturating_sub(1);
                let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
                let delay = ARI_BASE_TEMP_BACKOFF.saturating_mul(multiplier as u32);
                (delay.min(ARI_LONG_TERM_RETRY_INTERVAL), false)
            }
        }
    }
}

/// Select a renewal time uniformly at random within the valid window (RFC 9773 §4.3.1).
pub fn select_renewal_time(
    window: &RenewalWindow,
    previous_window: Option<&RenewalWindow>,
    previous_renewal_time: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    let mut rng = rand::rng();
    select_renewal_time_with_rng(
        window,
        previous_window,
        previous_renewal_time,
        now,
        &mut rng,
    )
}

/// Select a renewal time with a specific RNG (RFC 9773 §4.3.1).
pub fn select_renewal_time_with_rng<R: rand::RngExt>(
    window: &RenewalWindow,
    previous_window: Option<&RenewalWindow>,
    previous_renewal_time: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    rng: &mut R,
) -> DateTime<Utc> {
    // If the window has not changed and a previous time exists, keep it stable.
    if let (Some(prev_win), Some(prev_time)) = (previous_window, previous_renewal_time) {
        if prev_win == window {
            if prev_time <= now {
                return now;
            }
            return prev_time;
        }
    }

    // RFC 9773 §4.3.1: If the window starts in the past (e.g. revoked), attempt renewal immediately.
    if window.start <= now {
        return now;
    }

    // Determine target selection window: intersection if non-empty, else new window.
    let target = if let Some(prev) = previous_window {
        window.intersection(prev).unwrap_or_else(|| window.clone())
    } else {
        window.clone()
    };

    let span_secs = (target.end - target.start).num_seconds();
    if span_secs <= 0 {
        return now;
    }

    let offset_secs = rng.random_range(0..=span_secs);
    let selected = target.start + chrono::Duration::seconds(offset_secs);

    if selected <= now {
        now
    } else {
        selected
    }
}

/// Deterministically selects a renewal time at fraction `ratio` in [0.0, 1.0] of the target window.
pub fn select_renewal_time_at_ratio(
    window: &RenewalWindow,
    previous_window: Option<&RenewalWindow>,
    previous_renewal_time: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    ratio: f64,
) -> DateTime<Utc> {
    if let (Some(prev_win), Some(prev_time)) = (previous_window, previous_renewal_time) {
        if prev_win == window {
            if prev_time <= now {
                return now;
            }
            return prev_time;
        }
    }

    if window.start <= now {
        return now;
    }

    let target = if let Some(prev) = previous_window {
        window.intersection(prev).unwrap_or_else(|| window.clone())
    } else {
        window.clone()
    };

    let span_secs = (target.end - target.start).num_seconds();
    if span_secs <= 0 {
        return now;
    }

    let clamped_ratio = ratio.clamp(0.0, 1.0);
    let offset_secs = (span_secs as f64 * clamped_ratio).round() as i64;
    let selected = target.start + chrono::Duration::seconds(offset_secs);

    if selected <= now {
        now
    } else {
        selected
    }
}

/// Computes the next instant the scheduler loop should awaken.
pub fn next_wakeup(
    now_utc: DateTime<Utc>,
    now_instant: tokio::time::Instant,
    renewal_deadline: Option<DateTime<Utc>>,
    next_refresh: Option<tokio::time::Instant>,
    fallback_interval: Duration,
) -> tokio::time::Instant {
    let fallback_wake = now_instant + fallback_interval;
    let mut earliest = fallback_wake;

    if let Some(refresh_time) = next_refresh {
        if refresh_time < earliest {
            earliest = refresh_time;
        }
    }

    if let Some(renew_dt) = renewal_deadline {
        let renew_instant = if renew_dt <= now_utc {
            now_instant
        } else {
            let dur = (renew_dt - now_utc).to_std().unwrap_or(Duration::ZERO);
            now_instant + dur
        };
        if renew_instant < earliest {
            earliest = renew_instant;
        }
    }

    earliest
}

/// Extract the leaf certificate DER from a PEM-encoded certificate chain.
pub fn extract_leaf_certificate_der(cert_pem: &str) -> Result<CertificateDer<'static>, AcmeError> {
    let mut reader = cert_pem.as_bytes();
    if let Some(item) = rustls_pemfile::certs(&mut reader).next() {
        let cert = item.map_err(|e| {
            AcmeError::CertificateParse(format!("Failed to parse certificate PEM: {e}"))
        })?;
        return Ok(cert);
    }
    Err(AcmeError::CertificateParse(
        "No certificates found in PEM data".to_string(),
    ))
}

/// Extract the RFC 9773 CertificateIdentifier from a PEM-encoded certificate or chain.
pub fn extract_certificate_identifier(
    cert_pem: &str,
) -> Result<CertificateIdentifier<'static>, AcmeError> {
    let leaf_der = extract_leaf_certificate_der(cert_pem)?;
    CertificateIdentifier::try_from(&leaf_der)
        .map(|id| id.into_owned())
        .map_err(|e| {
            AcmeError::CertificateParse(format!(
                "Failed to extract ARI certificate identifier: {e}"
            ))
        })
}

/// In-memory ARI tracking state for a certificate.
#[derive(Debug, Clone)]
pub struct AriSchedulerState {
    /// In-memory ARI capability for this CA: Supported, Unsupported, or Unknown.
    pub capability: AriCapability,
    /// Active leaf certificate identifier, if known.
    pub certificate_id: Option<CertificateIdentifier<'static>>,
    /// Last valid renewal window provided by the CA.
    pub last_window: Option<RenewalWindow>,
    /// Selected renewal deadline within the suggested window.
    pub renewal_deadline: Option<DateTime<Utc>>,
    /// Next deadline to refresh renewal information from the CA.
    pub next_refresh: Option<tokio::time::Instant>,
    /// Consecutive temporary failure count for backoff calculation.
    pub temp_failure_count: u32,
    /// Explanation URL provided by the CA, if any.
    pub explanation_url: Option<String>,
}

impl Default for AriSchedulerState {
    fn default() -> Self {
        Self {
            capability: AriCapability::Unknown,
            certificate_id: None,
            last_window: None,
            renewal_deadline: None,
            next_refresh: None,
            temp_failure_count: 0,
            explanation_url: None,
        }
    }
}

impl AriSchedulerState {
    /// Reset in-memory retry and window state when the active certificate changes.
    pub fn reset_for_new_certificate(
        &mut self,
        new_cert_id: Option<CertificateIdentifier<'static>>,
    ) {
        self.certificate_id = new_cert_id;
        self.last_window = None;
        self.renewal_deadline = None;
        self.next_refresh = None;
        self.temp_failure_count = 0;
        self.explanation_url = None;
    }

    /// Clear scheduling state when certificate is missing or expired.
    pub fn clear_expired_or_missing(&mut self) {
        self.last_window = None;
        self.renewal_deadline = None;
        self.next_refresh = None;
        self.temp_failure_count = 0;
        self.explanation_url = None;
    }

    /// Check whether ARI renewal deadline indicates renewal is due.
    ///
    /// Returns:
    /// - `None` if ARI is explicitly unsupported or no ARI deadline is set (signaling that fallback policy should decide).
    /// - `Some(true)` if ARI is active and the renewal deadline has passed.
    /// - `Some(false)` if ARI is active and the renewal deadline is in the future.
    pub fn is_ari_renewal_due(&self, now: DateTime<Utc>) -> Option<bool> {
        if self.capability == AriCapability::Unsupported {
            return None;
        }
        self.renewal_deadline.map(|deadline| deadline <= now)
    }

    /// Record a successful ARI refresh.
    pub fn record_success(
        &mut self,
        window: RenewalWindow,
        renewal_deadline: DateTime<Utc>,
        next_refresh: tokio::time::Instant,
        explanation_url: Option<String>,
    ) {
        self.capability = AriCapability::Supported;
        self.last_window = Some(window);
        self.renewal_deadline = Some(renewal_deadline);
        self.next_refresh = Some(next_refresh);
        self.temp_failure_count = 0;
        self.explanation_url = explanation_url;
    }

    /// Record that ARI is explicitly unsupported.
    ///
    /// Clears any cached ARI window and renewal deadline, stops using ARI for renewal,
    /// and schedules a delayed capability recheck.
    pub fn record_unsupported(&mut self, next_recheck: tokio::time::Instant) {
        self.capability = AriCapability::Unsupported;
        self.last_window = None;
        self.renewal_deadline = None;
        self.next_refresh = Some(next_recheck);
        self.temp_failure_count = 0;
    }

    /// Record a temporary failure and update next_refresh deadline.
    ///
    /// Retains previously valid window and renewal deadline for the active certificate.
    pub fn record_temporary_failure(&mut self, delay: Duration) {
        self.temp_failure_count = self.temp_failure_count.saturating_add(1);
        self.next_refresh = Some(tokio::time::Instant::now() + delay);
    }

    /// Record a long-term failure and update next_refresh deadline.
    ///
    /// Retains previously valid window and renewal deadline for the active certificate.
    pub fn record_long_term_failure(&mut self, delay: Duration) {
        self.next_refresh = Some(tokio::time::Instant::now() + delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_renewal_window_validation() {
        let now = Utc::now();
        let valid = RenewalWindow::new(now, now + chrono::Duration::hours(2));
        assert!(valid.is_ok());

        // end == start must fail
        let equal = RenewalWindow::new(now, now);
        assert!(equal.is_err());
        assert!(matches!(equal.unwrap_err(), AriError::InvalidWindow { .. }));

        // end < start must fail
        let reversed = RenewalWindow::new(now + chrono::Duration::hours(2), now);
        assert!(reversed.is_err());
        assert!(matches!(
            reversed.unwrap_err(),
            AriError::InvalidWindow { .. }
        ));
    }

    #[test]
    fn test_renewal_window_intersection() {
        let t0 = Utc::now();
        let t1 = t0 + chrono::Duration::hours(1);
        let t2 = t0 + chrono::Duration::hours(2);
        let t3 = t0 + chrono::Duration::hours(3);

        let w1 = RenewalWindow::new(t0, t2).unwrap();
        let w2 = RenewalWindow::new(t1, t3).unwrap();

        let inter = w1.intersection(&w2).unwrap();
        assert_eq!(inter.start, t1);
        assert_eq!(inter.end, t2);

        // Disjoint windows
        let w3 = RenewalWindow::new(t0, t1).unwrap();
        let w4 = RenewalWindow::new(t2, t3).unwrap();
        assert!(w3.intersection(&w4).is_none());
    }

    #[test]
    fn test_select_renewal_time_in_future_window() {
        let now = Utc::now();
        let start = now + chrono::Duration::days(1);
        let end = now + chrono::Duration::days(5);
        let window = RenewalWindow::new(start, end).unwrap();

        let selected = select_renewal_time_at_ratio(&window, None, None, now, 0.5);
        assert!(selected >= start && selected <= end);
        assert_eq!(selected, start + chrono::Duration::days(2));
    }

    #[test]
    fn test_select_renewal_time_window_starting_in_past_is_immediate() {
        let now = Utc::now();
        let start = now - chrono::Duration::hours(1);
        let end = now + chrono::Duration::hours(5);
        let window = RenewalWindow::new(start, end).unwrap();

        let selected = select_renewal_time_at_ratio(&window, None, None, now, 0.5);
        assert_eq!(selected, now);
    }

    #[test]
    fn test_select_renewal_time_unchanged_window_stability() {
        let now = Utc::now();
        let start = now + chrono::Duration::days(1);
        let end = now + chrono::Duration::days(5);
        let window = RenewalWindow::new(start, end).unwrap();

        let first_choice = start + chrono::Duration::days(2);
        let second_choice = select_renewal_time_at_ratio(
            &window,
            Some(&window),
            Some(first_choice),
            now,
            0.8, // even if ratio is different, unchanged window keeps first_choice
        );

        assert_eq!(second_choice, first_choice);
    }

    #[test]
    fn test_select_renewal_time_changed_window_uses_intersection() {
        let now = Utc::now();
        let w1 = RenewalWindow::new(
            now + chrono::Duration::days(2),
            now + chrono::Duration::days(6),
        )
        .unwrap();
        let w2 = RenewalWindow::new(
            now + chrono::Duration::days(4),
            now + chrono::Duration::days(8),
        )
        .unwrap();

        // Intersection is days 4..6
        let selected = select_renewal_time_at_ratio(&w2, Some(&w1), None, now, 0.5);
        assert_eq!(selected, now + chrono::Duration::days(5));
    }

    #[test]
    fn test_clamp_refresh_interval() {
        assert_eq!(
            clamp_refresh_interval(Duration::from_secs(10)),
            ARI_MIN_REFRESH_INTERVAL
        );
        assert_eq!(
            clamp_refresh_interval(Duration::from_secs(3600)),
            Duration::from_secs(3600)
        );
        assert_eq!(
            clamp_refresh_interval(Duration::from_secs(100_000)),
            ARI_MAX_REFRESH_INTERVAL
        );
    }

    #[test]
    fn test_retry_delay_temporary_backoff_and_exhaustion() {
        // 1st temporary failure: base backoff (1 min)
        let (d1, trans1) = calculate_retry_delay(AriErrorClassification::Temporary, 1);
        assert_eq!(d1, Duration::from_secs(60));
        assert!(!trans1);

        // 2nd temporary failure: 2 mins
        let (d2, trans2) = calculate_retry_delay(AriErrorClassification::Temporary, 2);
        assert_eq!(d2, Duration::from_secs(120));
        assert!(!trans2);

        // 3rd temporary failure: 4 mins
        let (d3, trans3) = calculate_retry_delay(AriErrorClassification::Temporary, 3);
        assert_eq!(d3, Duration::from_secs(240));
        assert!(!trans3);

        // 4th temporary failure (> ARI_MAX_TEMP_RETRIES): exhausted, transitions to long-term (6 hours)
        let (d4, trans4) = calculate_retry_delay(AriErrorClassification::Temporary, 4);
        assert_eq!(d4, ARI_LONG_TERM_RETRY_INTERVAL);
        assert!(trans4);
    }

    #[test]
    fn test_retry_delay_long_term_and_unsupported() {
        let (d_lt, trans_lt) = calculate_retry_delay(AriErrorClassification::LongTerm, 0);
        assert_eq!(d_lt, ARI_LONG_TERM_RETRY_INTERVAL);
        assert!(!trans_lt);

        let (d_unsup, trans_unsup) = calculate_retry_delay(AriErrorClassification::Unsupported, 0);
        assert_eq!(d_unsup, ARI_LONG_TERM_RETRY_INTERVAL);
        assert!(!trans_unsup);
    }

    #[test]
    fn test_next_wakeup_renewal_precedence() {
        let now_utc = Utc::now();
        let now_inst = tokio::time::Instant::now();

        let renewal_deadline = now_utc + chrono::Duration::minutes(10);
        let next_refresh = now_inst + Duration::from_secs(3600); // 1 hour
        let fallback = Duration::from_secs(12 * 3600); // 12 hours

        let wake = next_wakeup(
            now_utc,
            now_inst,
            Some(renewal_deadline),
            Some(next_refresh),
            fallback,
        );
        // Should wake at renewal deadline (~10 minutes), not refresh (1 hour)
        let diff = wake.duration_since(now_inst);
        assert!(diff <= Duration::from_secs(601) && diff >= Duration::from_secs(599));
    }

    #[test]
    fn test_next_wakeup_refresh_precedence() {
        let now_utc = Utc::now();
        let now_inst = tokio::time::Instant::now();

        let renewal_deadline = now_utc + chrono::Duration::hours(24);
        let next_refresh = now_inst + Duration::from_secs(1800); // 30 mins
        let fallback = Duration::from_secs(12 * 3600);

        let wake = next_wakeup(
            now_utc,
            now_inst,
            Some(renewal_deadline),
            Some(next_refresh),
            fallback,
        );
        let diff = wake.duration_since(now_inst);
        assert_eq!(diff, Duration::from_secs(1800));
    }

    #[test]
    fn test_classify_instant_acme_error_unsupported() {
        let err = instant_acme::Error::Unsupported("ACME renewal information (ARI)");
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::Unsupported
        );
    }

    #[test]
    fn test_classify_instant_acme_error_api_404_is_long_term() {
        let problem = instant_acme::Problem {
            r#type: None,
            detail: None,
            status: Some(404),
            subproblems: Vec::new(),
        };
        let err = instant_acme::Error::Api(problem);
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_classify_instant_acme_error_api_500_is_temporary() {
        let problem = instant_acme::Problem {
            r#type: None,
            detail: None,
            status: Some(500),
            subproblems: Vec::new(),
        };
        let err = instant_acme::Error::Api(problem);
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::Temporary
        );
    }

    #[test]
    fn test_classify_instant_acme_error_missing_retry_after_is_long_term() {
        let err = instant_acme::Error::Str("missing Retry-After header");
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_classify_instant_acme_error_api_missing_status_is_long_term() {
        // Dependency limitation test: Problem without an explicit status field falls back conservatively to LongTerm
        let problem = instant_acme::Problem {
            r#type: Some("urn:ietf:params:acme:error:serverInternal".to_string()),
            detail: Some("server failure".to_string()),
            status: None,
            subproblems: Vec::new(),
        };
        let err = instant_acme::Error::Api(problem);
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_classify_instant_acme_error_timeout_is_temporary() {
        // Direct instant_acme::Error::Timeout
        let err = instant_acme::Error::Timeout(None);
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::Temporary
        );
    }

    #[test]
    fn test_classify_instant_acme_error_io_timeout_is_temporary() {
        // Structured std::io::ErrorKind::TimedOut wrapped in Error::Other
        let io_err = std::io::Error::from(std::io::ErrorKind::TimedOut);
        let err = instant_acme::Error::Other(Box::new(io_err));
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::Temporary
        );
    }

    #[test]
    fn test_classify_instant_acme_error_string_timeout_is_temporary() {
        // String pattern timeout match in Error::Other
        let custom_err = std::io::Error::other("connection timed out during request");
        let err = instant_acme::Error::Other(Box::new(custom_err));
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::Temporary
        );
    }

    #[test]
    fn test_classify_instant_acme_error_connection_refused_is_long_term() {
        // Structured std::io::ErrorKind::ConnectionRefused wrapped in Error::Other
        let io_err = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
        let err = instant_acme::Error::Other(Box::new(io_err));
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_classify_instant_acme_error_dns_failure_is_long_term() {
        // Standard libc/platform getaddrinfo failure string explicitly recognized
        let custom_err = std::io::Error::other(
            "failed to lookup address information: Name or service not known",
        );
        let err = instant_acme::Error::Other(Box::new(custom_err));
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );

        // Explicit "dns" keyword recognition
        let dns_err =
            std::io::Error::other("dns resolution failed for acme-v02.api.letsencrypt.org");
        let err_dns = instant_acme::Error::Other(Box::new(dns_err));
        assert_eq!(
            classify_instant_acme_error(&err_dns),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_classify_instant_acme_error_json_parse_is_long_term() {
        let json_err: serde_json::Error = serde_json::from_str::<String>("not json").unwrap_err();
        let err = instant_acme::Error::Json(json_err);
        assert_eq!(
            classify_instant_acme_error(&err),
            AriErrorClassification::LongTerm
        );
    }

    #[test]
    fn test_extract_certificate_identifier_invalid_pem() {
        let invalid = "not a valid pem";
        let res = extract_certificate_identifier(invalid);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AcmeError::CertificateParse(_)));
    }
}
