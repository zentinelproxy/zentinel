//! ACME client wrapper around instant-acme
//!
//! Provides a high-level interface for ACME protocol operations including:
//! - Account creation and management
//! - Certificate ordering
//! - Challenge handling (HTTP-01 and DNS-01)
//! - Certificate finalization

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AccountBuilder, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier,
    LetsEncrypt, NewAccount, NewOrder, Order, OrderStatus, RenewalInfo, RetryPolicy,
};
use tokio::sync::RwLock;
use tracing::{debug, error, info, trace, warn};

use zentinel_config::server::AcmeConfig;

use super::ari::{self, AriError};
use super::dns::challenge::{create_challenge_info, Dns01ChallengeInfo};
use super::error::{is_retryable_acme_error, AcmeError, ACME_RETRY_BACKOFF, ACME_RETRY_MAX};
use super::storage::{CertificateStorage, StoredAccountCredentials};

/// Let's Encrypt production directory URL
const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory URL
const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Default timeout for ACME operations
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Timeout for challenge validation
const CHALLENGE_TIMEOUT: Duration = Duration::from_secs(120);

/// Retry transient ACME transport failures with exponential backoff.
///
/// Note on `create_order` retries: a retry creates a new ACME Order;
/// the previous `pending` order is left to expire by the CA. This is
/// harmless (CA auto-expires pending orders) and `429 rateLimited` is
/// explicitly non-retryable, so quota is not burned.
async fn retry_acme<F, Fut, T>(mut op: F) -> Result<T, AcmeError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, AcmeError>>,
{
    let mut backoff = ACME_RETRY_BACKOFF;
    for attempt in 0..ACME_RETRY_MAX {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if is_retryable_acme_error(&e) && attempt + 1 < ACME_RETRY_MAX => {
                tracing::info!(
                    attempt = attempt + 1,
                    max_retries = ACME_RETRY_MAX,
                    backoff_secs = backoff.as_secs(),
                    error = %e,
                    "ACME transient failure, retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("retry loop always returns")
}

/// ACME client for automatic certificate management
///
/// Wraps the `instant-acme` library and provides Zentinel-specific functionality
/// for certificate ordering, challenge handling, and persistence.
pub struct AcmeClient {
    /// ACME account (lazy initialized)
    account: Arc<RwLock<Option<Account>>>,
    /// Configuration
    config: AcmeConfig,
    /// Certificate storage
    storage: Arc<CertificateStorage>,
    /// Optional custom HTTP client factory for testing with mock servers.
    custom_http: Option<Arc<dyn Fn() -> Box<dyn instant_acme::HttpClient> + Send + Sync>>,
}

impl AcmeClient {
    /// Create a new ACME client
    ///
    /// # Arguments
    ///
    /// * `config` - ACME configuration from the listener
    /// * `storage` - Certificate storage instance
    pub fn new(config: AcmeConfig, storage: Arc<CertificateStorage>) -> Self {
        Self {
            account: Arc::new(RwLock::new(None)),
            config,
            storage,
            custom_http: None,
        }
    }

    /// Set a custom HTTP client factory for testing with mock ACME servers.
    pub fn with_custom_http<F>(mut self, factory: F) -> Self
    where
        F: Fn() -> Box<dyn instant_acme::HttpClient> + Send + Sync + 'static,
    {
        self.custom_http = Some(Arc::new(factory));
        self
    }

    /// Get the ACME configuration
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }

    /// Get the certificate storage
    pub fn storage(&self) -> &CertificateStorage {
        &self.storage
    }

    /// Get the ACME directory URL based on configuration
    fn directory_url(&self) -> &str {
        if let Some(ref url) = self.config.server_url {
            url
        } else if self.config.staging {
            LETSENCRYPT_STAGING
        } else {
            LETSENCRYPT_PRODUCTION
        }
    }

    /// Initialize or load the ACME account
    ///
    /// If account credentials exist in storage, loads them. Otherwise,
    /// creates a new account with Let's Encrypt.
    ///
    /// # Errors
    ///
    /// Returns an error if account creation or loading fails.
    pub async fn init_account(&self) -> Result<(), AcmeError> {
        retry_acme(|| async { self.init_account_once().await }).await
    }

    /// Ensure ACME account is initialized, initializing if needed.
    ///
    /// Used by `RenewalScheduler` to lazily recover after a transient
    /// `init_account` failure that was deferred to background during
    /// startup. If the account is already present the call is a no-op.
    pub async fn ensure_account(&self) -> Result<(), AcmeError> {
        if self.account.read().await.is_some() {
            return Ok(());
        }
        self.init_account().await
    }

    fn account_builder(&self) -> Result<AccountBuilder, AcmeError> {
        if let Some(ref factory) = self.custom_http {
            Ok(Account::builder_with_http(factory()))
        } else {
            Account::builder().map_err(|e| AcmeError::AccountCreation(e.to_string()))
        }
    }

    async fn init_account_once(&self) -> Result<(), AcmeError> {
        // Check for existing account credentials (stored as JSON)
        if let Some(creds_json) = self.storage.load_credentials_json()? {
            info!("Loading existing ACME account from storage");

            // Deserialize credentials
            let credentials: instant_acme::AccountCredentials = serde_json::from_str(&creds_json)
                .map_err(|e| {
                AcmeError::AccountCreation(format!("Failed to deserialize credentials: {}", e))
            })?;

            // Reconstruct account from stored credentials
            let account = self
                .account_builder()?
                .from_credentials(credentials)
                .await
                .map_err(|e| AcmeError::AccountCreation(e.to_string()))?;

            *self.account.write().await = Some(account);
            info!("ACME account loaded successfully");
            return Ok(());
        }

        // Create new account
        info!(
            email = %self.config.email,
            server_url = %self.directory_url(),
            key_type = ?self.config.key_type,
            "Creating new ACME account"
        );

        let eab = if let Some(ref eab_config) = self.config.eab {
            let hmac_key = URL_SAFE_NO_PAD.decode(&eab_config.hmac_key).map_err(|e| {
                AcmeError::AccountCreation(format!("Invalid EAB HMAC key (base64url): {}", e))
            })?;
            Some(instant_acme::ExternalAccountKey::new(
                eab_config.kid.clone(),
                &hmac_key,
            ))
        } else {
            None
        };

        let (account, credentials) = self
            .account_builder()?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", self.config.email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url().to_owned(),
                eab.as_ref(),
            )
            .await
            .map_err(|e| AcmeError::AccountCreation(e.to_string()))?;

        // Store credentials as JSON (AccountCredentials is serializable)
        let creds_json = serde_json::to_string_pretty(&credentials).map_err(|e| {
            AcmeError::AccountCreation(format!("Failed to serialize credentials: {}", e))
        })?;
        self.storage.save_credentials_json(&creds_json)?;

        *self.account.write().await = Some(account);
        info!("ACME account created successfully");

        Ok(())
    }

    /// Order a certificate for the configured domains
    ///
    /// Creates a new certificate order and returns it along with the
    /// authorization challenges that need to be completed.
    ///
    /// # Arguments
    ///
    /// * `replaces` - Optional RFC 9773 predecessor certificate identifier
    ///
    /// # Returns
    ///
    /// A tuple of (Order, Vec<`ChallengeInfo`>) containing the order and
    /// HTTP-01 challenge information for each domain.
    pub async fn create_order(
        &self,
        replaces: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(Order, Vec<ChallengeInfo>), AcmeError> {
        let replaces_owned = replaces.cloned();
        retry_acme(|| {
            let r = replaces_owned.clone();
            async move { self.create_order_once(r.as_ref()).await }
        })
        .await
    }

    async fn create_order_once(
        &self,
        replaces: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(Order, Vec<ChallengeInfo>), AcmeError> {
        let account_guard = self.account.read().await;
        let account = account_guard.as_ref().ok_or(AcmeError::NoAccount)?;

        // Create identifiers for all domains
        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d: &String| Identifier::Dns(d.clone()))
            .collect();

        info!(
            domains = ?self.config.domains,
            replaces = ?replaces.map(|r| r.to_string()),
            "Creating certificate order"
        );

        // Create the order
        let mut new_order = NewOrder::new(&identifiers);
        if let Some(replaces_id) = replaces {
            new_order = new_order.replaces(replaces_id.clone());
        }

        let mut order = account.new_order(&new_order).await.map_err(|e| match e {
            instant_acme::Error::Unsupported(feature) => AcmeError::Unsupported(feature),
            other => AcmeError::OrderCreation(other.to_string()),
        })?;

        // Get authorizations and extract HTTP-01 challenges
        let mut authorizations = order.authorizations();
        let mut challenges = Vec::new();

        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| {
                AcmeError::Authorization(format!("Failed to get authorization: {}", e))
            })?;

            let identifier = authz.identifier();
            let domain = match &identifier.identifier {
                Identifier::Dns(domain) => domain.clone(),
                _ => continue,
            };

            debug!(domain = %domain, status = ?authz.status, "Processing authorization");

            // Skip if already valid
            if authz.status == AuthorizationStatus::Valid {
                debug!(domain = %domain, "Authorization already valid");
                continue;
            }

            // Find HTTP-01 challenge
            let http01_challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| AcmeError::NoHttp01Challenge(domain.clone()))?;

            let key_authorization = http01_challenge.key_authorization();

            challenges.push(ChallengeInfo {
                domain,
                token: http01_challenge.token.clone(),
                key_authorization: key_authorization.as_str().to_string(),
                url: http01_challenge.url.clone(),
            });
        }

        Ok((order, challenges))
    }

    /// Order a certificate using DNS-01 challenges
    ///
    /// Creates a new certificate order and returns it along with the
    /// DNS-01 challenge information for each domain.
    ///
    /// # Arguments
    ///
    /// * `replaces` - Optional RFC 9773 predecessor certificate identifier
    ///
    /// # Returns
    ///
    /// A tuple of (Order, Vec<`Dns01ChallengeInfo`>) containing the order and
    /// DNS-01 challenge information for each domain.
    pub async fn create_order_dns01(
        &self,
        replaces: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(Order, Vec<Dns01ChallengeInfo>), AcmeError> {
        let replaces_owned = replaces.cloned();
        retry_acme(|| {
            let r = replaces_owned.clone();
            async move { self.create_order_dns01_once(r.as_ref()).await }
        })
        .await
    }

    async fn create_order_dns01_once(
        &self,
        replaces: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(Order, Vec<Dns01ChallengeInfo>), AcmeError> {
        let account_guard = self.account.read().await;
        let account = account_guard.as_ref().ok_or(AcmeError::NoAccount)?;

        // Create identifiers for all domains
        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d: &String| Identifier::Dns(d.clone()))
            .collect();

        info!(
            domains = ?self.config.domains,
            replaces = ?replaces.map(|r| r.to_string()),
            "Creating certificate order with DNS-01 challenges"
        );

        // Create the order
        let mut new_order = NewOrder::new(&identifiers);
        if let Some(replaces_id) = replaces {
            new_order = new_order.replaces(replaces_id.clone());
        }

        let mut order = account.new_order(&new_order).await.map_err(|e| match e {
            instant_acme::Error::Unsupported(feature) => AcmeError::Unsupported(feature),
            other => AcmeError::OrderCreation(other.to_string()),
        })?;

        // Get authorizations and extract DNS-01 challenges
        let mut authorizations = order.authorizations();
        let mut challenges = Vec::new();

        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| {
                AcmeError::Authorization(format!("Failed to get authorization: {}", e))
            })?;

            let identifier = authz.identifier();
            let domain = match &identifier.identifier {
                Identifier::Dns(domain) => domain.clone(),
                _ => continue,
            };

            debug!(domain = %domain, status = ?authz.status, "Processing DNS-01 authorization");

            // Skip if already valid
            if authz.status == AuthorizationStatus::Valid {
                debug!(domain = %domain, "Authorization already valid");
                continue;
            }

            // Find DNS-01 challenge
            let dns01_challenge = authz
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| AcmeError::NoDns01Challenge(domain.clone()))?;

            let key_authorization = dns01_challenge.key_authorization();

            // Create DNS-01 challenge info with computed value
            let challenge_info =
                create_challenge_info(&domain, key_authorization.as_str(), &dns01_challenge.url);

            challenges.push(challenge_info);
        }

        Ok((order, challenges))
    }

    /// Extract RFC 9773 certificate identifier from a PEM certificate chain
    pub fn extract_certificate_identifier(
        &self,
        cert_pem: &str,
    ) -> Result<CertificateIdentifier<'static>, AcmeError> {
        super::ari::extract_certificate_identifier(cert_pem)
    }

    /// Request ARI renewal information for an identified certificate (RFC 9773 §4.2)
    pub async fn renewal_info(
        &self,
        certificate_id: &CertificateIdentifier<'_>,
    ) -> Result<(RenewalInfo, Duration), AriError> {
        let account_guard = self.account.read().await;
        let account = account_guard.as_ref().ok_or(AriError::NoAccount)?;
        account
            .renewal_info(certificate_id)
            .await
            .map_err(AriError::Protocol)
    }

    /// Notify the ACME server that a challenge is ready for validation
    ///
    /// Iterates through the order's authorizations to find the challenge
    /// matching the given URL and marks it as ready.
    ///
    /// # Arguments
    ///
    /// * `order` - The certificate order
    /// * `challenge_url` - The URL of the challenge to validate
    pub async fn validate_challenge(
        &self,
        order: &mut Order,
        challenge_url: &str,
    ) -> Result<(), AcmeError> {
        debug!(challenge_url = %challenge_url, "Setting challenge ready");

        // Iterate authorizations to find the matching challenge by URL
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| AcmeError::ChallengeValidation {
                domain: "unknown".to_string(),
                message: format!("Failed to get authorization: {}", e),
            })?;

            // Determine which challenge type matches the URL
            let matching_type = authz
                .challenges
                .iter()
                .find(|c| c.url == challenge_url)
                .map(|c| c.r#type.clone());

            if let Some(challenge_type) = matching_type {
                if let Some(mut challenge) = authz.challenge(challenge_type) {
                    challenge
                        .set_ready()
                        .await
                        .map_err(|e| AcmeError::ChallengeValidation {
                            domain: "unknown".to_string(),
                            message: e.to_string(),
                        })?;
                    return Ok(());
                }
            }
        }

        Err(AcmeError::ChallengeValidation {
            domain: "unknown".to_string(),
            message: format!("Challenge not found for URL: {}", challenge_url),
        })
    }

    /// Wait for the order to become ready (all challenges validated)
    ///
    /// Polls the order status until it becomes ready or times out.
    pub async fn wait_for_order_ready(&self, order: &mut Order) -> Result<(), AcmeError> {
        let deadline = tokio::time::Instant::now() + CHALLENGE_TIMEOUT;

        loop {
            let state = order
                .refresh()
                .await
                .map_err(|e| AcmeError::OrderCreation(format!("Failed to refresh order: {}", e)))?;

            match state.status {
                OrderStatus::Ready => {
                    info!("Order is ready for finalization");
                    return Ok(());
                }
                OrderStatus::Invalid => {
                    error!("Order became invalid");
                    return Err(AcmeError::OrderCreation("Order became invalid".to_string()));
                }
                OrderStatus::Valid => {
                    info!("Order is already valid (certificate issued)");
                    return Ok(());
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    if tokio::time::Instant::now() > deadline {
                        return Err(AcmeError::Timeout(
                            "Timed out waiting for order to become ready".to_string(),
                        ));
                    }
                    trace!(status = ?state.status, "Order not ready yet, waiting...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    /// Finalize the order and retrieve the certificate
    ///
    /// Generates a CSR, submits it to the ACME server, and retrieves
    /// the issued certificate.
    ///
    /// # Returns
    ///
    /// A tuple of (certificate_pem, private_key_pem, expiry_date)
    pub async fn finalize_order(
        &self,
        order: &mut Order,
    ) -> Result<(String, String, DateTime<Utc>), AcmeError> {
        // retry_acme cannot hold &mut Order across the FnMut boundary
        // (E0658: async block escapes with borrowed &mut). Keep the
        // retry loop inline for this &mut case — same policy as
        // retry_acme (ACME_RETRY_MAX / BACKOFF + is_retryable).
        let mut backoff = ACME_RETRY_BACKOFF;
        for attempt in 0..ACME_RETRY_MAX {
            match self.finalize_order_once(order).await {
                Ok(v) => return Ok(v),
                Err(e) if is_retryable_acme_error(&e) && attempt + 1 < ACME_RETRY_MAX => {
                    tracing::info!(
                        attempt = attempt + 1,
                        max_retries = ACME_RETRY_MAX,
                        backoff_secs = backoff.as_secs(),
                        error = %e,
                        "ACME transient failure, retrying"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = backoff.saturating_mul(2);
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!("retry loop always returns")
    }

    async fn finalize_order_once(
        &self,
        order: &mut Order,
    ) -> Result<(String, String, DateTime<Utc>), AcmeError> {
        info!("Finalizing certificate order");

        // Map config key type to rcgen signature algorithm
        use zentinel_config::server::AcmeKeyType;
        let algo = match self.config.key_type {
            AcmeKeyType::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
            AcmeKeyType::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        };

        // Generate a new private key for the certificate
        let cert_key = rcgen::KeyPair::generate_for(algo)
            .map_err(|e| AcmeError::Finalization(format!("Failed to generate key: {}", e)))?;

        // Create CSR with all domains
        let mut params = rcgen::CertificateParams::new(self.config.domains.clone())
            .map_err(|e| AcmeError::Finalization(format!("Failed to create CSR params: {}", e)))?;

        // Set the Common Name to the first domain — rcgen defaults to "rcgen self signed cert"
        // which ACME CAs reject as an invalid domain name
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, self.config.domains[0].clone());
        params.distinguished_name = dn;

        // Serialize CSR with the key pair (rcgen 0.14 API)
        let csr_request = params
            .serialize_request(&cert_key)
            .map_err(|e| AcmeError::Finalization(format!("Failed to serialize CSR: {}", e)))?;
        let csr = csr_request.der().to_vec();

        // Submit CSR and finalize
        order
            .finalize_csr(&csr)
            .await
            .map_err(|e| AcmeError::Finalization(format!("Failed to finalize order: {}", e)))?;

        // Wait for certificate to be issued
        let deadline = tokio::time::Instant::now() + DEFAULT_TIMEOUT;
        let cert_chain = loop {
            let state = order
                .refresh()
                .await
                .map_err(|e| AcmeError::Finalization(format!("Failed to refresh order: {}", e)))?;

            match state.status {
                OrderStatus::Valid => {
                    let cert_chain = order.certificate().await.map_err(|e| {
                        AcmeError::Finalization(format!("Failed to get certificate: {}", e))
                    })?;
                    break cert_chain.ok_or_else(|| {
                        AcmeError::Finalization("No certificate in response".to_string())
                    })?;
                }
                OrderStatus::Invalid => {
                    return Err(AcmeError::Finalization("Order became invalid".to_string()));
                }
                _ => {
                    if tokio::time::Instant::now() > deadline {
                        return Err(AcmeError::Timeout(
                            "Timed out waiting for certificate".to_string(),
                        ));
                    }
                    tokio::time::sleep(ACME_RETRY_BACKOFF).await;
                }
            }
        };

        // Get the private key PEM
        let key_pem = cert_key.serialize_pem();

        // Parse certificate to get expiry date
        let expiry = parse_certificate_expiry(&cert_chain)?;

        info!(
            domains = ?self.config.domains,
            expires = %expiry,
            "Certificate issued successfully"
        );

        Ok((cert_chain, key_pem, expiry))
    }

    /// Check if a certificate exists and needs renewal
    pub fn needs_renewal(&self, domain: &str) -> Result<bool, AcmeError> {
        Ok(self
            .storage
            .needs_renewal(domain, self.config.renew_before_days)?)
    }
}

/// Information about an HTTP-01 challenge
#[derive(Debug, Clone)]
pub struct ChallengeInfo {
    /// Domain this challenge is for
    pub domain: String,
    /// Challenge token (appears in URL path)
    pub token: String,
    /// Key authorization (the response content)
    pub key_authorization: String,
    /// Challenge URL for validation notification
    pub url: String,
}

/// Parse certificate PEM to extract expiry date
fn parse_certificate_expiry(cert_pem: &str) -> Result<DateTime<Utc>, AcmeError> {
    use x509_parser::prelude::*;

    // Parse PEM
    let (_, pem) = pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|e| AcmeError::CertificateParse(format!("Failed to parse PEM: {}", e)))?;

    // Parse X.509 certificate
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| AcmeError::CertificateParse(format!("Failed to parse certificate: {}", e)))?;

    // Get expiry time
    let not_after = cert.validity().not_after;
    let timestamp = not_after.timestamp();

    DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| AcmeError::CertificateParse("Invalid expiry timestamp".to_string()))
}

impl std::fmt::Debug for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeClient")
            .field("config", &self.config)
            .field(
                "has_account",
                &self
                    .account
                    .try_read()
                    .map(|a| a.is_some())
                    .unwrap_or(false),
            )
            .field("has_custom_http", &self.custom_http.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::server::{AcmeChallengeType, AcmeKeyType};

    #[tokio::test]
    async fn test_default_client_rejects_plaintext_http_url() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(CertificateStorage::new(temp_dir.path()).unwrap());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            server_url: Some("http://127.0.0.1:9999/directory".to_string()),
            staging: false,
            eab: None,
            storage: temp_dir.path().to_path_buf(),
            renew_before_days: 30,
            challenge_type: AcmeChallengeType::Http01,
            key_type: AcmeKeyType::EcdsaP256,
            dns_provider: None,
        };

        let client = AcmeClient::new(config, storage);
        assert!(client.custom_http.is_none());

        // Default construction must NOT use a plaintext client; instant-acme's default HTTPS-only
        // client will fail or reject http:// directory URLs.
        let result = client.init_account().await;
        assert!(result.is_err());
    }
}
