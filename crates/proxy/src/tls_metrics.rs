//! TLS-related Prometheus metrics.
//!
//! Provides metrics for tracking certificate status, resolution,
//! and SNI cold-start events.

use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use prometheus::{register_int_counter_vec, IntCounterVec};
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

        Ok(Self {
            sni_certs_skipped_total,
        })
    }

    /// Record an SNI certificate skip event.
    pub fn record_sni_cert_skip(&self, listener_id: &str, primary_domain: &str) {
        self.sni_certs_skipped_total
            .with_label_values(&[listener_id, primary_domain])
            .inc();
    }
}
