//! Background certificate renewal scheduler
//!
//! Periodically checks certificates and triggers renewal when needed.
//! Supports both HTTP-01 and DNS-01 challenge types.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, Instant};
use tracing::{debug, error, info, warn};

use zentinel_config::server::AcmeChallengeType;

use super::challenge::ChallengeManager;
use super::client::AcmeClient;
use super::dns::Dns01ChallengeManager;
use super::error::AcmeError;
use crate::tls::HotReloadableSniResolver;

/// Default check interval (12 hours)
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);

/// Minimum check interval (1 hour)
const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(3600);

/// Background certificate renewal scheduler
///
/// Runs as a background task and periodically checks if any certificates
/// need renewal. When renewal is needed, it orchestrates the ACME challenge
/// flow (HTTP-01 or DNS-01) and triggers TLS hot-reload after successful
/// certificate issuance.
pub struct RenewalScheduler {
    /// ACME client for certificate operations
    client: Arc<AcmeClient>,
    /// Challenge manager for HTTP-01 handling
    challenge_manager: Arc<ChallengeManager>,
    /// DNS-01 challenge manager (optional, for DNS-01 challenges)
    dns_challenge_manager: Option<Arc<Dns01ChallengeManager>>,
    /// SNI resolver for hot-reload after renewal
    sni_resolver: Option<Arc<HotReloadableSniResolver>>,
    /// Check interval
    check_interval: Duration,
}

impl RenewalScheduler {
    /// Create a new renewal scheduler
    ///
    /// # Arguments
    ///
    /// * `client` - ACME client instance
    /// * `challenge_manager` - Challenge manager for HTTP-01 challenges
    /// * `sni_resolver` - Optional SNI resolver for triggering hot-reload
    pub fn new(
        client: Arc<AcmeClient>,
        challenge_manager: Arc<ChallengeManager>,
        sni_resolver: Option<Arc<HotReloadableSniResolver>>,
    ) -> Self {
        Self {
            client,
            challenge_manager,
            dns_challenge_manager: None,
            sni_resolver,
            check_interval: DEFAULT_CHECK_INTERVAL,
        }
    }

    /// Set the DNS-01 challenge manager
    ///
    /// Required when using DNS-01 challenge type.
    pub fn with_dns_manager(mut self, dns_manager: Arc<Dns01ChallengeManager>) -> Self {
        self.dns_challenge_manager = Some(dns_manager);
        self
    }

    /// Set the check interval
    ///
    /// The interval is clamped to a minimum of 1 hour to avoid
    /// excessive polling.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval.max(MIN_CHECK_INTERVAL);
        self
    }

    /// Get the configured challenge type
    fn challenge_type(&self) -> AcmeChallengeType {
        self.client.config().challenge_type
    }

    /// Run the renewal scheduler loop
    ///
    /// This runs indefinitely, checking certificates at the configured
    /// interval and renewing as needed.
    pub async fn run(self) {
        info!(
            check_interval_hours = self.check_interval.as_secs() / 3600,
            "Starting certificate renewal scheduler"
        );

        // Initial check after a short delay
        tokio::time::sleep(Duration::from_secs(10)).await;

        if let Err(e) = self.check_renewals().await {
            error!(error = %e, "Initial certificate renewal check failed");
        }

        // Periodic checks
        let mut interval = interval(self.check_interval);

        loop {
            interval.tick().await;

            debug!("Running scheduled certificate renewal check");

            if let Err(e) = self.check_renewals().await {
                error!(error = %e, "Certificate renewal check failed");
            }
        }
    }

    /// Check all configured domains and renew certificates as needed
    async fn check_renewals(&self) -> Result<(), AcmeError> {
        let domains = self.client.config().domains.clone();

        info!(
            domain_count = domains.len(),
            "Checking certificates for renewal"
        );

        for domain in &domains {
            match self.client.needs_renewal(domain) {
                Ok(true) => {
                    info!(domain = %domain, "Certificate needs renewal");

                    match self.renew_certificate().await {
                        Ok(()) => {
                            info!(domain = %domain, "Certificate renewed successfully");

                            // Trigger TLS hot-reload
                            if let Some(ref resolver) = self.sni_resolver {
                                if let Err(e) = resolver.reload() {
                                    error!(
                                        domain = %domain,
                                        error = %e,
                                        "Failed to reload TLS configuration"
                                    );
                                } else {
                                    info!("TLS configuration reloaded with new certificate");
                                }
                            }
                        }
                        Err(e) => {
                            error!(
                                domain = %domain,
                                error = %e,
                                "Certificate renewal failed"
                            );
                            // Continue with other domains
                        }
                    }

                    // Only renew once per check - all domains are in the same cert
                    break;
                }
                Ok(false) => {
                    debug!(domain = %domain, "Certificate is still valid");
                }
                Err(e) => {
                    warn!(
                        domain = %domain,
                        error = %e,
                        "Failed to check certificate renewal status"
                    );
                }
            }
        }

        Ok(())
    }

    /// Renew the certificate for all configured domains
    ///
    /// Automatically selects the appropriate challenge type based on configuration.
    async fn renew_certificate(&self) -> Result<(), AcmeError> {
        match self.challenge_type() {
            AcmeChallengeType::Http01 => self.renew_certificate_http01().await,
            AcmeChallengeType::Dns01 => self.renew_certificate_dns01().await,
        }
    }

    /// Renew certificate using HTTP-01 challenge
    async fn renew_certificate_http01(&self) -> Result<(), AcmeError> {
        let start = Instant::now();

        info!("Starting certificate renewal with HTTP-01 challenge");

        // Create order and get challenges
        let (mut order, challenges) = self.client.create_order().await?;

        // Register all challenges
        for challenge in &challenges {
            self.challenge_manager
                .add_challenge(&challenge.token, &challenge.key_authorization);
        }

        // Notify ACME server that challenges are ready
        for challenge in &challenges {
            self.client
                .validate_challenge(&mut order, &challenge.url)
                .await?;
        }

        // Wait for validation
        self.client.wait_for_order_ready(&mut order).await?;

        // Cleanup challenges
        for challenge in &challenges {
            self.challenge_manager.remove_challenge(&challenge.token);
        }

        // Finalize and get certificate
        let (cert_pem, key_pem, expires) = self.client.finalize_order(&mut order).await?;

        // Save certificate
        self.save_certificate(&cert_pem, &key_pem, expires)?;

        let elapsed = start.elapsed();
        info!(
            elapsed_secs = elapsed.as_secs(),
            expires = %expires,
            "Certificate renewal completed (HTTP-01)"
        );

        Ok(())
    }

    /// Renew certificate using DNS-01 challenge
    async fn renew_certificate_dns01(&self) -> Result<(), AcmeError> {
        let dns_manager = self
            .dns_challenge_manager
            .as_ref()
            .ok_or(AcmeError::NoDnsProvider)?;

        let start = Instant::now();

        info!(
            provider = %dns_manager.provider_name(),
            "Starting certificate renewal with DNS-01 challenge"
        );

        // Create order and get DNS-01 challenges
        let (mut order, mut challenges) = self.client.create_order_dns01().await?;

        // Create DNS records and wait for propagation
        // We need to do this sequentially to ensure all records are created before validation
        for challenge in &mut challenges {
            if let Err(e) = dns_manager.create_and_wait(challenge).await {
                // Cleanup any records we created before failing
                warn!(
                    domain = %challenge.domain,
                    error = %e,
                    "Failed to create DNS record, cleaning up"
                );
                dns_manager.cleanup_all(&challenges).await;
                return Err(e.into());
            }
        }

        // Notify ACME server that challenges are ready
        for challenge in &challenges {
            if let Err(e) = self
                .client
                .validate_challenge(&mut order, &challenge.url)
                .await
            {
                // Cleanup DNS records even on validation error
                dns_manager.cleanup_all(&challenges).await;
                return Err(e);
            }
        }

        // Wait for validation
        let validation_result = self.client.wait_for_order_ready(&mut order).await;

        // Always cleanup DNS records, regardless of validation result
        dns_manager.cleanup_all(&challenges).await;

        // Now check validation result
        validation_result?;

        // Finalize and get certificate
        let (cert_pem, key_pem, expires) = self.client.finalize_order(&mut order).await?;

        // Save certificate
        self.save_certificate(&cert_pem, &key_pem, expires)?;

        let elapsed = start.elapsed();
        info!(
            elapsed_secs = elapsed.as_secs(),
            expires = %expires,
            "Certificate renewal completed (DNS-01)"
        );

        Ok(())
    }

    /// Save certificate to storage
    fn save_certificate(
        &self,
        cert_pem: &str,
        key_pem: &str,
        expires: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AcmeError> {
        let primary_domain = self
            .client
            .config()
            .domains
            .first()
            .ok_or_else(|| AcmeError::OrderCreation("No domains configured".to_string()))?;

        self.client.storage().save_certificate(
            primary_domain,
            cert_pem,
            key_pem,
            expires,
            &self.client.config().domains,
        )?;

        Ok(())
    }

    /// Perform initial certificate issuance if needed
    ///
    /// Call this during startup to ensure certificates exist before
    /// starting the server.
    pub async fn ensure_certificates(&self) -> Result<(), AcmeError> {
        let domains = self.client.config().domains.clone();

        if domains.is_empty() {
            return Err(AcmeError::OrderCreation(
                "No domains configured".to_string(),
            ));
        }

        let primary_domain = &domains[0];

        if self.client.needs_renewal(primary_domain)? {
            info!(
                domain = %primary_domain,
                "Initial certificate issuance required"
            );
            self.renew_certificate().await?;
        } else {
            info!(
                domain = %primary_domain,
                "Certificate already exists and is valid"
            );
        }

        Ok(())
    }
}

impl std::fmt::Debug for RenewalScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenewalScheduler")
            .field("check_interval", &self.check_interval)
            .field("has_sni_resolver", &self.sni_resolver.is_some())
            .finish()
    }
}
