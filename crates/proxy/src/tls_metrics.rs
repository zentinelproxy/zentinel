//! TLS-related Prometheus metrics.
//!
//! Provides metrics for tracking certificate status, resolution,
//! and SNI cold-start events.

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{register_int_counter_vec, register_int_gauge_vec, IntCounterVec, IntGaugeVec};
use std::sync::Arc;

/// Global TLS metrics instance.
static TLS_METRICS: OnceCell<Arc<TlsMetrics>> = OnceCell::new();

/// Get or initialize the global TLS metrics.
pub fn get_tls_metrics() -> Option<Arc<TlsMetrics>> {
    TLS_METRICS.get().cloned()
}

/// Initialize the global TLS metrics.
pub fn init_tls_metrics() -> Result<Arc<TlsMetrics>> {
    if let Some(metrics) = TLS_METRICS.get() {
        return Ok(metrics.clone());
    }

    let metrics = Arc::new(TlsMetrics::new()?);
    let _ = TLS_METRICS.set(metrics.clone());
    Ok(metrics)
}

/// TLS metrics collector.
pub struct TlsMetrics {
    /// Number of SNI certificates skipped at startup due to missing files (ACME)
    /// Labels: listener, primary_domain
    sni_certs_skipped_total: IntCounterVec,

    /// Certificates currently loaded per listener.
    ///
    /// A gauge rather than a counter: what matters operationally is how many
    /// are in service right now, which falls when a certificate is removed
    /// from a scanned folder.
    /// Labels: listener
    certificates_loaded: IntGaugeVec,

    /// Certificate reload attempts, by outcome.
    ///
    /// A failed reload leaves the previous certificates in use, so failures
    /// are invisible in traffic. This is how they become visible.
    /// Labels: listener, result
    reload_total: IntCounterVec,

    /// Files in a scanned folder that could not be used as a certificate.
    /// Labels: listener, reason
    folder_entries_skipped_total: IntCounterVec,

    /// OCSP fetch attempts for stapling, by outcome.
    ///
    /// A failed fetch never fails a handshake -- the certificate is served
    /// without a staple -- so this is the only place it shows.
    /// Labels: listener, result (`success`, `failure`, `invalid`, `revoked`,
    /// `no_issuer`)
    ocsp_fetch_total: IntCounterVec,

    /// Certificates on a listener currently served with a valid OCSP staple.
    /// Labels: listener
    ocsp_stapled_certificates: IntGaugeVec,
}

impl TlsMetrics {
    /// Create new TLS metrics and register with Prometheus.
    pub fn new() -> Result<Self> {
        let sni_certs_skipped_total = register_int_counter_vec!(
            "zentinel_tls_sni_certs_skipped_total",
            "Total number of SNI certificates skipped during initialization (usually pending ACME issuance)",
            &["listener", "primary_domain"]
        )
        .context("Failed to register zentinel_tls_sni_certs_skipped_total metric")?;

        let certificates_loaded = register_int_gauge_vec!(
            "zentinel_tls_certificates_loaded",
            "Number of TLS certificates currently loaded for a listener",
            &["listener"]
        )
        .context("Failed to register zentinel_tls_certificates_loaded metric")?;

        let reload_total = register_int_counter_vec!(
            "zentinel_tls_reload_total",
            "Total TLS certificate reload attempts by outcome",
            &["listener", "result"]
        )
        .context("Failed to register zentinel_tls_reload_total metric")?;

        let folder_entries_skipped_total = register_int_counter_vec!(
            "zentinel_tls_folder_entries_skipped_total",
            "Files in a scanned certificate folder that could not be loaded",
            &["listener", "reason"]
        )
        .context("Failed to register zentinel_tls_folder_entries_skipped_total metric")?;

        let ocsp_fetch_total = register_int_counter_vec!(
            "zentinel_tls_ocsp_fetch_total",
            "OCSP response fetches for stapling, by outcome",
            &["listener", "result"]
        )
        .context("Failed to register zentinel_tls_ocsp_fetch_total metric")?;

        let ocsp_stapled_certificates = register_int_gauge_vec!(
            "zentinel_tls_ocsp_stapled_certificates",
            "Number of certificates on a listener currently served with a valid OCSP staple",
            &["listener"]
        )
        .context("Failed to register zentinel_tls_ocsp_stapled_certificates metric")?;

        Ok(Self {
            sni_certs_skipped_total,
            certificates_loaded,
            reload_total,
            folder_entries_skipped_total,
            ocsp_fetch_total,
            ocsp_stapled_certificates,
        })
    }

    /// Record how many certificates a listener currently has loaded.
    pub fn set_certificates_loaded(&self, listener_id: &str, count: usize) {
        self.certificates_loaded
            .with_label_values(&[listener_id])
            .set(count as i64);
    }

    /// Record the outcome of a reload attempt.
    pub fn record_reload(&self, listener_id: &str, succeeded: bool) {
        let result = if succeeded { "success" } else { "failure" };
        self.reload_total
            .with_label_values(&[listener_id, result])
            .inc();
    }

    /// Record a file skipped during a folder scan.
    ///
    /// `reason` is a small fixed set (`no_key`, `unreadable`) rather than the
    /// error text, so it cannot become an unbounded label.
    pub fn record_folder_entry_skipped(&self, listener_id: &str, reason: &str) {
        self.folder_entries_skipped_total
            .with_label_values(&[listener_id, reason])
            .inc();
    }

    /// Record an SNI certificate skip event.
    pub fn record_sni_cert_skip(&self, listener_id: &str, primary_domain: &str) {
        self.sni_certs_skipped_total
            .with_label_values(&[listener_id, primary_domain])
            .inc();
    }

    /// Record the outcome of an OCSP fetch.
    ///
    /// `result` is a small fixed set, never error text, so the label stays
    /// bounded.
    pub fn record_ocsp_fetch(&self, listener_id: &str, result: &str) {
        self.ocsp_fetch_total
            .with_label_values(&[listener_id, result])
            .inc();
    }

    /// Record how many certificates currently carry a valid OCSP staple.
    pub fn set_ocsp_stapled(&self, listener_id: &str, count: usize) {
        self.ocsp_stapled_certificates
            .with_label_values(&[listener_id])
            .set(count as i64);
    }
}
