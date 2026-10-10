//! ACME error types

use std::io;
use std::time::Duration;
use thiserror::Error;

use super::dns::DnsProviderError;

/// Maximum retries for transient ACME transport failures.
///
/// Shared by `AcmeClient::retry_acme` to avoid drift between
/// `error` and `client` modules.
pub const ACME_RETRY_MAX: usize = 3;
/// Base backoff for the first transient retry (doubles each attempt).
pub const ACME_RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// Errors that can occur during ACME operations
#[derive(Debug, Error)]
pub enum AcmeError {
    /// No ACME account has been initialized
    #[error("ACME account not initialized - call init_account() first")]
    NoAccount,

    /// Failed to create or load ACME account
    #[error("Failed to create ACME account: {0}")]
    AccountCreation(String),

    /// Failed to create certificate order
    #[error("Failed to create certificate order: {0}")]
    OrderCreation(String),

    /// Challenge validation failed
    #[error("Challenge validation failed for domain '{domain}': {message}")]
    ChallengeValidation { domain: String, message: String },

    /// Certificate finalization failed
    #[error("Failed to finalize certificate: {0}")]
    Finalization(String),

    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    /// ACME protocol error from instant-acme
    #[error("ACME protocol error: {0}")]
    Protocol(String),

    /// Operation timed out
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// No HTTP-01 challenge available for domain
    #[error("No HTTP-01 challenge available for domain '{0}'")]
    NoHttp01Challenge(String),

    /// No DNS-01 challenge available for domain
    #[error("No DNS-01 challenge available for domain '{0}'")]
    NoDns01Challenge(String),

    /// DNS provider not configured
    #[error("DNS-01 challenge requires a DNS provider configuration")]
    NoDnsProvider,

    /// DNS provider operation failed
    #[error("DNS provider error: {0}")]
    DnsProvider(#[from] DnsProviderError),

    /// DNS propagation timeout
    #[error("DNS propagation timeout for record '{record}' after {elapsed:?}")]
    PropagationTimeout { record: String, elapsed: Duration },

    /// Wildcard domain requires DNS-01 challenge
    #[error("Wildcard domain '{domain}' requires DNS-01 challenge type")]
    WildcardRequiresDns01 { domain: String },

    /// Certificate parsing error
    #[error("Failed to parse certificate: {0}")]
    CertificateParse(String),

    /// ACME Renewal Information (ARI) error
    #[error("ARI error: {0}")]
    Ari(#[from] super::ari::AriError),

    /// ACME feature unsupported (e.g. replaces or renewalInfo)
    #[error("ACME feature unsupported: {0}")]
    Unsupported(&'static str),
}

/// Errors specific to certificate storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// IO error during file operations
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// Failed to serialize/deserialize data
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Storage directory not writable
    #[error("Storage directory not writable: {path}")]
    NotWritable { path: String },

    /// Certificate not found
    #[error("Certificate not found for domain: {domain}")]
    CertificateNotFound { domain: String },

    /// Invalid storage structure
    #[error("Invalid storage structure: {0}")]
    InvalidStructure(String),
}

impl From<serde_json::Error> for StorageError {
    fn from(e: serde_json::Error) -> Self {
        StorageError::Serialization(e.to_string())
    }
}

impl From<instant_acme::Error> for AcmeError {
    fn from(e: instant_acme::Error) -> Self {
        match e {
            instant_acme::Error::Unsupported(feature) => AcmeError::Unsupported(feature),
            other => AcmeError::Protocol(other.to_string()),
        }
    }
}

/// Whether an ACME error is transient and worth retrying.
///
/// Covers the field-observed proxy cold-start pattern
/// (`curl` first `35 unexpected eof` then `301`, ACME
/// `client error (Connect)` / `TLS connect error`) and generic
/// transport failures. Non-transient errors like auth/rate-limit
/// or DNS propagation timeouts must fail fast.
pub fn is_retryable_acme_error(e: &AcmeError) -> bool {
    if let AcmeError::Ari(ari_err) = e {
        return ari_err.is_temporary();
    }
    // Never retry deterministic errors: storage/config, missing
    // challenges, unsupported features, or polling timeouts.
    if matches!(
        e,
        AcmeError::Storage(_)
            | AcmeError::NoAccount
            | AcmeError::NoHttp01Challenge(_)
            | AcmeError::NoDns01Challenge(_)
            | AcmeError::NoDnsProvider
            | AcmeError::WildcardRequiresDns01 { .. }
            | AcmeError::CertificateParse(_)
            | AcmeError::Timeout(_)
            | AcmeError::PropagationTimeout { .. }
            | AcmeError::Unsupported(_)
    ) {
        return false;
    }
    // DNS provider errors: match variants explicitly instead of via
    // string matching. `DnsProviderError::Timeout` is the real
    // propagation timeout (`PropagationTimeout` is never constructed
    // in practice) and must not be retried; the same string
    // ("timed out") would otherwise incorrectly mark it retryable.
    if matches!(
        e,
        AcmeError::DnsProvider(
            DnsProviderError::Timeout { .. }
                | DnsProviderError::RateLimited { .. }
                | DnsProviderError::Authentication(_)
                | DnsProviderError::ZoneNotFound { .. }
                | DnsProviderError::Configuration(_)
                | DnsProviderError::Credentials(_)
                | DnsProviderError::UnsupportedDomain { .. }
        )
    ) {
        return false;
    }
    let msg = e.to_string().to_lowercase();
    // Narrow allowlist: only transport-layer transient failures.
    // Avoid bare "hyper"/"transport"/"timeout" which also match
    // application-level timeouts or incidental substrings.
    msg.contains("client error (connect)")
        || msg.contains("unexpected eof")
        || msg.contains("connection reset")
        || msg.contains("connection closed")
        || msg.contains("connection aborted")
        || msg.contains("tls connect error")
        || msg.contains("timed out")
        || msg.contains("transport error")
        || msg.contains("hyper::")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_retryable_connect_and_eof() {
        let e = AcmeError::AccountCreation("client error (Connect)".to_string());
        assert!(is_retryable_acme_error(&e));
        let e = AcmeError::Protocol("unexpected eof while reading".to_string());
        assert!(is_retryable_acme_error(&e));
        let e = AcmeError::AccountCreation("TLS connect error".to_string());
        assert!(is_retryable_acme_error(&e));
    }

    #[test]
    fn test_retryable_transport_variants() {
        let e = AcmeError::OrderCreation("connection reset by peer".to_string());
        assert!(is_retryable_acme_error(&e));
        let e = AcmeError::OrderCreation("transport error: closed".to_string());
        assert!(is_retryable_acme_error(&e));
        let e = AcmeError::Finalization("hyper::Error(ChannelClosed)".to_string());
        assert!(is_retryable_acme_error(&e));
    }

    #[test]
    fn test_non_retryable_timeouts_and_storage() {
        let e = AcmeError::Timeout("timed out waiting for order".to_string());
        assert!(!is_retryable_acme_error(&e));
        let e = AcmeError::PropagationTimeout {
            record: "_acme-challenge.example.com".to_string(),
            elapsed: Duration::from_secs(120),
        };
        assert!(!is_retryable_acme_error(&e));
        let e = AcmeError::Storage(StorageError::InvalidStructure("x".to_string()));
        assert!(!is_retryable_acme_error(&e));
        let e = AcmeError::AccountCreation("401 Unauthorized".to_string());
        assert!(!is_retryable_acme_error(&e));
    }

    #[test]
    fn test_non_retryable_dns_provider_variants() {
        let e = AcmeError::DnsProvider(DnsProviderError::Timeout { elapsed_secs: 120 });
        assert!(!is_retryable_acme_error(&e));
        // DnsProvider Timeout contains "timed out" but must not be retryable
        assert!(e.to_string().to_lowercase().contains("timed out"));
        let e = AcmeError::DnsProvider(DnsProviderError::Authentication("bad token".to_string()));
        assert!(!is_retryable_acme_error(&e));
        let e = AcmeError::DnsProvider(DnsProviderError::ZoneNotFound {
            domain: "example.com".to_string(),
        });
        assert!(!is_retryable_acme_error(&e));
        let e = AcmeError::DnsProvider(DnsProviderError::RateLimited {
            retry_after_secs: 60,
        });
        assert!(!is_retryable_acme_error(&e));
    }
}
