//! DNS-01 challenge management
//!
//! Orchestrates the DNS-01 challenge flow:
//! 1. Create TXT records via DNS provider
//! 2. Wait for propagation
//! 3. Cleanup records after validation

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};

use super::propagation::{PropagationChecker, PropagationConfig};
use super::provider::{challenge_record_fqdn, normalize_domain, DnsProvider, DnsProviderError, DnsResult, ACME_CHALLENGE_RECORD};

/// Information about a pending DNS-01 challenge
#[derive(Debug, Clone)]
pub struct Dns01ChallengeInfo {
    /// Domain this challenge is for
    pub domain: String,
    /// The full record name (e.g., "_acme-challenge.example.com")
    pub record_name: String,
    /// The challenge value to set in the TXT record
    pub record_value: String,
    /// Challenge URL for validation notification
    pub url: String,
    /// Record ID after creation (for cleanup)
    pub record_id: Option<String>,
}

/// DNS-01 challenge manager
///
/// Coordinates DNS record creation, propagation checking, and cleanup.
#[derive(Debug)]
pub struct Dns01ChallengeManager {
    provider: Arc<dyn DnsProvider>,
    propagation_checker: PropagationChecker,
}

impl Dns01ChallengeManager {
    /// Create a new DNS-01 challenge manager
    pub fn new(
        provider: Arc<dyn DnsProvider>,
        propagation_config: PropagationConfig,
    ) -> DnsResult<Self> {
        let propagation_checker = PropagationChecker::with_config(propagation_config)?;

        Ok(Self {
            provider,
            propagation_checker,
        })
    }

    /// Create a new manager with default propagation settings
    pub fn with_defaults(provider: Arc<dyn DnsProvider>) -> DnsResult<Self> {
        Self::new(provider, PropagationConfig::default())
    }

    /// Compute the DNS-01 challenge value from key authorization
    ///
    /// The DNS-01 challenge value is the base64url-encoded SHA256 digest
    /// of the key authorization.
    pub fn compute_challenge_value(key_authorization: &str) -> String {
        let digest = Sha256::digest(key_authorization.as_bytes());
        URL_SAFE_NO_PAD.encode(digest)
    }

    /// Create a challenge record and wait for propagation
    ///
    /// # Arguments
    ///
    /// * `challenge` - Challenge information (will be updated with record_id)
    ///
    /// # Returns
    ///
    /// The record ID for cleanup
    pub async fn create_and_wait(&self, challenge: &mut Dns01ChallengeInfo) -> DnsResult<()> {
        let normalized_domain = normalize_domain(&challenge.domain);

        info!(
            domain = %challenge.domain,
            record = %challenge.record_name,
            provider = %self.provider.name(),
            "Creating DNS-01 challenge record"
        );

        // Create the TXT record
        let record_id = self
            .provider
            .create_txt_record(
                normalized_domain,
                ACME_CHALLENGE_RECORD,
                &challenge.record_value,
            )
            .await?;

        challenge.record_id = Some(record_id.clone());

        debug!(
            domain = %challenge.domain,
            record_id = %record_id,
            "DNS record created, waiting for propagation"
        );

        // Wait for propagation
        self.propagation_checker
            .wait_for_propagation(&challenge.domain, &challenge.record_value)
            .await?;

        info!(
            domain = %challenge.domain,
            "DNS-01 challenge record propagated"
        );

        Ok(())
    }

    /// Cleanup a challenge record
    ///
    /// Should be called after validation completes (success or failure).
    pub async fn cleanup(&self, challenge: &Dns01ChallengeInfo) -> DnsResult<()> {
        let record_id = match &challenge.record_id {
            Some(id) => id,
            None => {
                debug!(domain = %challenge.domain, "No record ID to cleanup");
                return Ok(());
            }
        };

        let normalized_domain = normalize_domain(&challenge.domain);

        debug!(
            domain = %challenge.domain,
            record_id = %record_id,
            "Cleaning up DNS-01 challenge record"
        );

        match self.provider.delete_txt_record(normalized_domain, record_id).await {
            Ok(()) => {
                info!(domain = %challenge.domain, "DNS-01 challenge record cleaned up");
                Ok(())
            }
            Err(e) => {
                // Log but don't fail - cleanup errors are non-fatal
                warn!(
                    domain = %challenge.domain,
                    record_id = %record_id,
                    error = %e,
                    "Failed to cleanup DNS-01 challenge record"
                );
                Err(e)
            }
        }
    }

    /// Cleanup multiple challenge records
    ///
    /// Attempts to cleanup all records, logging failures but not stopping.
    pub async fn cleanup_all(&self, challenges: &[Dns01ChallengeInfo]) {
        for challenge in challenges {
            if let Err(e) = self.cleanup(challenge).await {
                error!(
                    domain = %challenge.domain,
                    error = %e,
                    "Failed to cleanup challenge record"
                );
            }
        }
    }

    /// Check if the provider supports a domain
    pub async fn supports_domain(&self, domain: &str) -> DnsResult<bool> {
        self.provider.supports_domain(domain).await
    }

    /// Get the DNS provider name
    pub fn provider_name(&self) -> &'static str {
        self.provider.name()
    }
}

/// Create DNS-01 challenge info from ACME authorization
pub fn create_challenge_info(
    domain: &str,
    key_authorization: &str,
    challenge_url: &str,
) -> Dns01ChallengeInfo {
    let record_name = challenge_record_fqdn(domain);
    let record_value = Dns01ChallengeManager::compute_challenge_value(key_authorization);

    Dns01ChallengeInfo {
        domain: domain.to_string(),
        record_name,
        record_value,
        url: challenge_url.to_string(),
        record_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_challenge_value() {
        // Test vector from RFC 8555
        // The key authorization "token.thumbprint" should produce a specific digest
        let key_auth = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA.QxKhYaH6VWOWyLVV9dVRqY8hZVp-ZxCfmYkf8BwqF0c";
        let value = Dns01ChallengeManager::compute_challenge_value(key_auth);

        // Should be base64url-encoded SHA256
        assert!(!value.is_empty());
        assert!(!value.contains('+'));
        assert!(!value.contains('/'));
        assert!(!value.contains('='));
    }

    #[test]
    fn test_create_challenge_info() {
        let info = create_challenge_info(
            "example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/123",
        );

        assert_eq!(info.domain, "example.com");
        assert_eq!(info.record_name, "_acme-challenge.example.com");
        assert_eq!(info.url, "https://acme.example.com/challenge/123");
        assert!(info.record_id.is_none());
        assert!(!info.record_value.is_empty());
    }

    #[test]
    fn test_wildcard_challenge_info() {
        let info = create_challenge_info(
            "*.example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/456",
        );

        // Wildcard should use base domain for record
        assert_eq!(info.domain, "*.example.com");
        assert_eq!(info.record_name, "_acme-challenge.example.com");
    }
}
