//! ACME error types

use std::io;
use std::time::Duration;
use thiserror::Error;

use super::dns::DnsProviderError;

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
        AcmeError::Protocol(e.to_string())
    }
}
