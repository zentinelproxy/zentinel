//! DNS provider trait for DNS-01 challenges
//!
//! Defines the interface that all DNS providers must implement.

use async_trait::async_trait;
use std::fmt::Debug;
use thiserror::Error;

/// Result type for DNS operations
pub type DnsResult<T> = Result<T, DnsProviderError>;

/// Errors that can occur during DNS provider operations
#[derive(Debug, Error)]
pub enum DnsProviderError {
    /// Authentication failed with the DNS provider
    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Zone not found for the domain
    #[error("Zone not found for domain '{domain}'")]
    ZoneNotFound { domain: String },

    /// Record creation failed
    #[error("Failed to create TXT record for '{record_name}': {message}")]
    RecordCreation { record_name: String, message: String },

    /// Record deletion failed
    #[error("Failed to delete TXT record '{record_id}': {message}")]
    RecordDeletion { record_id: String, message: String },

    /// API request failed
    #[error("API request failed: {0}")]
    ApiRequest(String),

    /// Rate limited by provider
    #[error("Rate limited by DNS provider, retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    /// Request timeout
    #[error("Request timed out after {elapsed_secs}s")]
    Timeout { elapsed_secs: u64 },

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    Configuration(String),

    /// Credential loading failed
    #[error("Failed to load credentials: {0}")]
    Credentials(String),

    /// Domain not supported by this provider
    #[error("Domain '{domain}' is not supported by this provider")]
    UnsupportedDomain { domain: String },
}

/// Trait for DNS providers that support DNS-01 challenges
///
/// Implementations must be thread-safe and support concurrent operations.
#[async_trait]
pub trait DnsProvider: Send + Sync + Debug {
    /// Returns the provider name (e.g., "hetzner", "cloudflare")
    fn name(&self) -> &'static str;

    /// Create a TXT record for DNS-01 challenge
    ///
    /// # Arguments
    ///
    /// * `domain` - The full domain name (e.g., "example.com" or "sub.example.com")
    /// * `record_name` - The challenge record name (typically "_acme-challenge")
    /// * `record_value` - The challenge value (base64url-encoded digest)
    ///
    /// # Returns
    ///
    /// The record ID for later cleanup, or an error
    ///
    /// # Implementation Notes
    ///
    /// - The full record name should be `{record_name}.{domain}`
    /// - Use a short TTL (60s recommended) for challenge records
    /// - If a record already exists, either update it or create a new one
    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> DnsResult<String>;

    /// Delete a TXT record after challenge validation
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain the record belongs to
    /// * `record_id` - The record ID returned from `create_txt_record`
    ///
    /// # Implementation Notes
    ///
    /// - Should not error if the record doesn't exist (idempotent)
    /// - Called during cleanup, even if validation failed
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> DnsResult<()>;

    /// Check if the provider supports/manages the given domain
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to check
    ///
    /// # Returns
    ///
    /// `true` if the provider can manage DNS for this domain
    ///
    /// # Implementation Notes
    ///
    /// - Should check if a zone exists for this domain or its parent
    /// - May cache zone information to reduce API calls
    async fn supports_domain(&self, domain: &str) -> DnsResult<bool>;
}

/// ACME challenge record name prefix
pub const ACME_CHALLENGE_RECORD: &str = "_acme-challenge";

/// Recommended TTL for challenge records (60 seconds)
pub const CHALLENGE_TTL: u32 = 60;

/// Extract the parent domain from a domain name
///
/// For wildcard domains (*.example.com), returns the base domain.
/// For subdomains (sub.example.com), returns the same domain.
///
/// The actual zone lookup is done by the provider.
pub fn normalize_domain(domain: &str) -> &str {
    domain.strip_prefix("*.").unwrap_or(domain)
}

/// Build the full ACME challenge record name
///
/// For `example.com`, returns `_acme-challenge.example.com`
/// For `*.example.com`, returns `_acme-challenge.example.com`
pub fn challenge_record_fqdn(domain: &str) -> String {
    let normalized = normalize_domain(domain);
    format!("{}.{}", ACME_CHALLENGE_RECORD, normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use parking_lot::Mutex;

    #[test]
    fn test_normalize_domain() {
        assert_eq!(normalize_domain("example.com"), "example.com");
        assert_eq!(normalize_domain("*.example.com"), "example.com");
        assert_eq!(normalize_domain("sub.example.com"), "sub.example.com");
        assert_eq!(normalize_domain("*.sub.example.com"), "sub.example.com");
    }

    #[test]
    fn test_challenge_record_fqdn() {
        assert_eq!(
            challenge_record_fqdn("example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            challenge_record_fqdn("*.example.com"),
            "_acme-challenge.example.com"
        );
        assert_eq!(
            challenge_record_fqdn("sub.example.com"),
            "_acme-challenge.sub.example.com"
        );
    }

    #[test]
    fn test_dns_provider_error_display() {
        let err = DnsProviderError::Authentication("bad token".to_string());
        assert!(err.to_string().contains("Authentication failed"));

        let err = DnsProviderError::ZoneNotFound { domain: "test.com".to_string() };
        assert!(err.to_string().contains("test.com"));

        let err = DnsProviderError::RecordCreation {
            record_name: "_acme-challenge".to_string(),
            message: "API error".to_string(),
        };
        assert!(err.to_string().contains("_acme-challenge"));

        let err = DnsProviderError::RateLimited { retry_after_secs: 60 };
        assert!(err.to_string().contains("60"));

        let err = DnsProviderError::Timeout { elapsed_secs: 30 };
        assert!(err.to_string().contains("30"));
    }

    /// Mock DNS provider for testing
    #[derive(Debug)]
    pub struct MockDnsProvider {
        /// Records created: (domain, record_name) -> (record_id, value)
        pub records: Mutex<HashMap<(String, String), (String, String)>>,
        /// Supported domains
        pub supported_domains: Vec<String>,
        /// Counter for generating record IDs
        pub record_counter: AtomicU64,
        /// Whether to fail on create
        pub fail_on_create: bool,
        /// Whether to fail on delete
        pub fail_on_delete: bool,
    }

    impl MockDnsProvider {
        pub fn new(supported_domains: Vec<String>) -> Self {
            Self {
                records: Mutex::new(HashMap::new()),
                supported_domains,
                record_counter: AtomicU64::new(1),
                fail_on_create: false,
                fail_on_delete: false,
            }
        }

        pub fn with_failure_on_create(mut self) -> Self {
            self.fail_on_create = true;
            self
        }

        pub fn with_failure_on_delete(mut self) -> Self {
            self.fail_on_delete = true;
            self
        }

        pub fn get_record(&self, domain: &str, record_name: &str) -> Option<(String, String)> {
            self.records.lock().get(&(domain.to_string(), record_name.to_string())).cloned()
        }

        pub fn record_count(&self) -> usize {
            self.records.lock().len()
        }
    }

    #[async_trait]
    impl DnsProvider for MockDnsProvider {
        fn name(&self) -> &'static str {
            "mock"
        }

        async fn create_txt_record(
            &self,
            domain: &str,
            record_name: &str,
            record_value: &str,
        ) -> DnsResult<String> {
            if self.fail_on_create {
                return Err(DnsProviderError::RecordCreation {
                    record_name: record_name.to_string(),
                    message: "Mock failure".to_string(),
                });
            }

            let record_id = format!("record-{}", self.record_counter.fetch_add(1, Ordering::SeqCst));
            self.records.lock().insert(
                (domain.to_string(), record_name.to_string()),
                (record_id.clone(), record_value.to_string()),
            );
            Ok(record_id)
        }

        async fn delete_txt_record(&self, domain: &str, record_id: &str) -> DnsResult<()> {
            if self.fail_on_delete {
                return Err(DnsProviderError::RecordDeletion {
                    record_id: record_id.to_string(),
                    message: "Mock failure".to_string(),
                });
            }

            // Find and remove the record by ID
            let mut records = self.records.lock();
            records.retain(|_, (id, _)| id != record_id);
            Ok(())
        }

        async fn supports_domain(&self, domain: &str) -> DnsResult<bool> {
            let normalized = normalize_domain(domain);
            Ok(self.supported_domains.iter().any(|d| {
                normalized == *d || normalized.ends_with(&format!(".{}", d))
            }))
        }
    }

    #[tokio::test]
    async fn test_mock_provider_create_record() {
        let provider = MockDnsProvider::new(vec!["example.com".to_string()]);

        let record_id = provider
            .create_txt_record("example.com", "_acme-challenge", "test-value")
            .await
            .unwrap();

        assert!(record_id.starts_with("record-"));
        assert_eq!(provider.record_count(), 1);

        let (stored_id, stored_value) = provider
            .get_record("example.com", "_acme-challenge")
            .unwrap();
        assert_eq!(stored_id, record_id);
        assert_eq!(stored_value, "test-value");
    }

    #[tokio::test]
    async fn test_mock_provider_delete_record() {
        let provider = MockDnsProvider::new(vec!["example.com".to_string()]);

        let record_id = provider
            .create_txt_record("example.com", "_acme-challenge", "test-value")
            .await
            .unwrap();
        assert_eq!(provider.record_count(), 1);

        provider
            .delete_txt_record("example.com", &record_id)
            .await
            .unwrap();
        assert_eq!(provider.record_count(), 0);
    }

    #[tokio::test]
    async fn test_mock_provider_supports_domain() {
        let provider = MockDnsProvider::new(vec!["example.com".to_string()]);

        assert!(provider.supports_domain("example.com").await.unwrap());
        assert!(provider.supports_domain("sub.example.com").await.unwrap());
        assert!(provider.supports_domain("*.example.com").await.unwrap());
        assert!(!provider.supports_domain("other.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_provider_failure_on_create() {
        let provider = MockDnsProvider::new(vec!["example.com".to_string()])
            .with_failure_on_create();

        let result = provider
            .create_txt_record("example.com", "_acme-challenge", "test-value")
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DnsProviderError::RecordCreation { .. }));
    }

    #[tokio::test]
    async fn test_mock_provider_failure_on_delete() {
        let provider = MockDnsProvider::new(vec!["example.com".to_string()])
            .with_failure_on_delete();

        let result = provider.delete_txt_record("example.com", "record-1").await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DnsProviderError::RecordDeletion { .. }));
    }
}
