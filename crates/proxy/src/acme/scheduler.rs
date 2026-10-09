//! Background certificate renewal scheduler
//!
//! Periodically checks certificates and triggers renewal when needed.
//! Supports both HTTP-01 and DNS-01 challenge types, and RFC 9773
//! ACME Renewal Information (ARI) with fallback to `renew-before-days`.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use instant_acme::CertificateIdentifier;
use parking_lot::Mutex;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use zentinel_config::server::AcmeChallengeType;

use super::ari::{
    calculate_retry_delay, clamp_refresh_interval, next_wakeup, select_renewal_time, AriCapability,
    AriError, AriErrorClassification, AriSchedulerState, RenewalWindow,
    ARI_LONG_TERM_RETRY_INTERVAL,
};
use super::challenge::ChallengeManager;
use super::client::AcmeClient;
use super::dns::Dns01ChallengeManager;
use super::error::{is_retryable_acme_error, AcmeError};
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
///
/// Uses RFC 9773 (ARI) renewal windows when supported by the CA, with
/// automatic fallback to `renew-before-days`.
pub struct RenewalScheduler {
    /// ACME client for certificate operations
    client: Arc<AcmeClient>,
    /// Challenge manager for HTTP-01 handling
    challenge_manager: Arc<ChallengeManager>,
    /// DNS-01 challenge manager (optional, for DNS-01 challenges)
    dns_challenge_manager: Option<Arc<Dns01ChallengeManager>>,
    /// SNI resolver for hot-reload after renewal
    sni_resolver: Option<Arc<HotReloadableSniResolver>>,
    /// Check interval for fallback polling
    check_interval: Duration,
    /// In-memory ARI tracking state
    ari_state: Mutex<AriSchedulerState>,
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
            ari_state: Mutex::new(AriSchedulerState::default()),
        }
    }

    /// Get the ACME client
    pub fn client(&self) -> &Arc<AcmeClient> {
        &self.client
    }

    /// Get a clone of the current in-memory ARI state
    pub fn ari_state(&self) -> AriSchedulerState {
        self.ari_state.lock().clone()
    }

    /// Get the current ARI capability status
    pub fn ari_capability(&self) -> AriCapability {
        self.ari_state.lock().capability
    }

    /// Set the in-memory ARI capability directly (useful for testing)
    pub fn set_ari_capability(&self, capability: AriCapability) {
        self.ari_state.lock().capability = capability;
    }

    /// Update in-memory ARI state with a closure (useful for testing)
    pub fn update_ari_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut AriSchedulerState) -> R,
    {
        f(&mut self.ari_state.lock())
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
    /// Runs an event-driven, deadline-based loop responding to both
    /// ARI refresh deadlines and selected renewal times.
    pub async fn run(self) {
        info!(
            check_interval_hours = self.check_interval.as_secs() / 3600,
            "Starting certificate renewal scheduler with RFC 9773 ARI support"
        );

        // Initial check after a short delay
        tokio::time::sleep(Duration::from_secs(2)).await;

        let primary_domain = match self.client.config().domains.first() {
            Some(d) => d.clone(),
            None => {
                warn!("No domains configured for ACME renewal scheduler");
                return;
            }
        };

        // Lazily ensure ACME account exists
        if let Err(e) = self.client.ensure_account().await {
            error!(
                domain = %primary_domain,
                error = %e,
                "Failed to ensure ACME account on startup"
            );
        }

        // On startup with an existing certificate, request its current ARI info
        // before relying solely on the legacy renewal threshold.
        let has_existing_cert = self
            .client
            .storage()
            .load_certificate(&primary_domain)
            .ok()
            .flatten()
            .is_some();

        if has_existing_cert {
            // Check if we already have a valid ARI schedule or pending retry:
            // Do not perform duplicate requests if ensure_certificates() or previous setup
            // already established a future refresh deadline.
            let should_initial_refresh = {
                let state = self.ari_state.lock();
                state.next_refresh.is_none_or(|r| r <= Instant::now())
            };

            if should_initial_refresh {
                info!(
                    domain = %primary_domain,
                    "Requesting initial ARI renewal information for existing certificate"
                );
                if let Err(e) = self.refresh_ari().await {
                    warn!(
                        domain = %primary_domain,
                        error = %e,
                        "Initial ARI refresh failed; continuing with standard checks"
                    );
                }
            } else {
                debug!(
                    domain = %primary_domain,
                    "ARI refresh already scheduled in future; skipping duplicate startup request"
                );
            }
        }

        // Perform initial check
        if let Err(e) = self.check_renewals().await {
            error!(domain = %primary_domain, error = %e, "Initial certificate renewal check failed");
        }

        // Deadline-based event loop
        loop {
            let (renewal_deadline, next_refresh) = {
                let state = self.ari_state.lock();
                (state.renewal_deadline, state.next_refresh)
            };

            let now_utc = Utc::now();
            let now_instant = Instant::now();
            let next_wake = next_wakeup(
                now_utc,
                now_instant,
                renewal_deadline,
                next_refresh,
                self.check_interval,
            );

            tokio::time::sleep_until(next_wake).await;

            debug!(domain = %primary_domain, "Renewal scheduler awakened for deadline check");

            // 1. Renewal check: If renewal is due, renewal takes precedence over refresh.
            // RFC 9773: "an upcoming refresh must not delay an already-due renewal"
            let renewal_is_due = self.is_renewal_due(&primary_domain).unwrap_or(false);

            if renewal_is_due {
                info!(domain = %primary_domain, "Certificate renewal is due");
                if let Err(e) = self.check_renewals().await {
                    error!(domain = %primary_domain, error = %e, "Certificate renewal failed");
                    // Avoid tight loop on renewal failure: sleep minimum interval before next attempt
                    tokio::time::sleep(MIN_CHECK_INTERVAL).await;
                }
                continue;
            }

            // 2. Refresh check: If an ARI refresh is due, execute it.
            let refresh_is_due = {
                let state = self.ari_state.lock();
                state.next_refresh.is_some_and(|r| r <= Instant::now())
            };

            if refresh_is_due {
                debug!(domain = %primary_domain, "ARI refresh is due; refreshing ARI info");
                if let Err(e) = self.refresh_ari().await {
                    warn!(domain = %primary_domain, error = %e, "Scheduled ARI refresh failed");
                }
            }

            // 3. Fallback renewal check (periodic fallback when no ARI or ARI unsupported)
            if let Err(e) = self.check_renewals().await {
                error!(domain = %primary_domain, error = %e, "Certificate renewal check failed");
            }
        }
    }

    /// Check whether renewal is needed according to ARI or fallback policy
    pub fn is_renewal_due(&self, domain: &str) -> Result<bool, AcmeError> {
        let now = Utc::now();
        let ari_due = {
            let state = self.ari_state.lock();
            state.is_ari_renewal_due(now)
        };

        match ari_due {
            Some(due) => Ok(due),
            None => self.client.needs_renewal(domain),
        }
    }

    /// Refresh ARI information for the active certificate.
    ///
    /// Leaves the scheduler in a safe, forward-progressing state whether it succeeds or fails.
    /// On success, schedules the next refresh according to the CA's `Retry-After` hint.
    /// On failure, schedules an appropriate backoff retry or clears obsolete deadlines.
    pub async fn refresh_ari(&self) -> Result<(), AcmeError> {
        let primary_domain = match self.client.config().domains.first() {
            Some(d) => d.clone(),
            None => return Ok(()),
        };

        match self.refresh_ari_step(&primary_domain).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.handle_refresh_failure(&primary_domain, &err);
                Err(err)
            }
        }
    }

    async fn refresh_ari_step(&self, primary_domain: &str) -> Result<(), AcmeError> {
        // 1. Ensure account is ready
        self.client.ensure_account().await?;

        // 2. Load stored certificate and check validity
        let stored_cert = match self.client.storage().load_certificate(primary_domain)? {
            Some(cert) => cert,
            None => {
                debug!(domain = %primary_domain, "No stored certificate found; clearing obsolete ARI state");
                self.ari_state.lock().clear_expired_or_missing();
                return Ok(());
            }
        };

        // RFC 9773 §4.3.2: Do not request renewal info for expired certificate
        if stored_cert.meta.expires <= Utc::now() {
            debug!(
                domain = %primary_domain,
                expires = %stored_cert.meta.expires,
                "Certificate has expired; clearing obsolete ARI state"
            );
            self.ari_state.lock().clear_expired_or_missing();
            return Ok(());
        }

        // 3. Extract leaf certificate identifier
        let cert_id = self
            .client
            .extract_certificate_identifier(&stored_cert.cert_pem)?;

        // Update active certificate_id in state
        {
            let mut state = self.ari_state.lock();
            if state.certificate_id.as_ref() != Some(&cert_id) {
                state.reset_for_new_certificate(Some(cert_id.clone()));
            }
        }

        // 4. Request renewal info from CA
        let (renewal_info, retry_after) = self
            .client
            .renewal_info(&cert_id)
            .await
            .map_err(AcmeError::Ari)?;

        // 5. Validate suggested window: if end <= start, invalid response
        let window = RenewalWindow::from_instant_acme(&renewal_info.suggested_window)
            .map_err(AcmeError::Ari)?;

        let clamped_refresh = clamp_refresh_interval(retry_after);
        let now_utc = Utc::now();
        let now_instant = Instant::now();

        let mut state = self.ari_state.lock();
        let renewal_time = select_renewal_time(
            &window,
            state.last_window.as_ref(),
            state.renewal_deadline,
            now_utc,
        );

        info!(
            domain = %primary_domain,
            window_start = %window.start,
            window_end = %window.end,
            renewal_deadline = %renewal_time,
            refresh_in_secs = clamped_refresh.as_secs(),
            "ARI renewal info updated successfully"
        );

        state.record_success(
            window,
            renewal_time,
            now_instant + clamped_refresh,
            renewal_info.explanation_url,
        );

        Ok(())
    }

    fn handle_refresh_failure(&self, primary_domain: &str, err: &AcmeError) {
        let classification = match err {
            AcmeError::Ari(ari_err) => ari_err.classification(),
            AcmeError::Unsupported(_) => AriErrorClassification::Unsupported,
            AcmeError::NoAccount | AcmeError::AccountCreation(_) => {
                if is_retryable_acme_error(err) {
                    AriErrorClassification::Temporary
                } else {
                    AriErrorClassification::LongTerm
                }
            }
            AcmeError::Storage(_) | AcmeError::CertificateParse(_) => {
                AriErrorClassification::LongTerm
            }
            AcmeError::Timeout(_) => AriErrorClassification::Temporary,
            AcmeError::Protocol(_) => {
                if is_retryable_acme_error(err) {
                    AriErrorClassification::Temporary
                } else {
                    AriErrorClassification::LongTerm
                }
            }
            _ => {
                if is_retryable_acme_error(err) {
                    AriErrorClassification::Temporary
                } else {
                    AriErrorClassification::LongTerm
                }
            }
        };

        let mut state = self.ari_state.lock();
        match classification {
            AriErrorClassification::Unsupported => {
                info!(
                    domain = %primary_domain,
                    "ACME CA does not support ARI; activating renew-before-days fallback policy"
                );
                state.record_unsupported(Instant::now() + ARI_LONG_TERM_RETRY_INTERVAL);
            }
            AriErrorClassification::Temporary => {
                let failure_count = state.temp_failure_count.saturating_add(1);
                let (delay, transitioned) =
                    calculate_retry_delay(AriErrorClassification::Temporary, failure_count);
                if transitioned {
                    warn!(
                        domain = %primary_domain,
                        failures = failure_count,
                        error = %err,
                        "Exhausted temporary retries for ARI; transitioning to long-term retry schedule (6 hours)"
                    );
                } else {
                    warn!(
                        domain = %primary_domain,
                        attempt = failure_count,
                        delay_secs = delay.as_secs(),
                        error = %err,
                        "Temporary failure requesting ARI; scheduling retry with backoff"
                    );
                }
                state.record_temporary_failure(delay);
            }
            AriErrorClassification::LongTerm => {
                let (delay, _) = calculate_retry_delay(
                    AriErrorClassification::LongTerm,
                    state.temp_failure_count,
                );
                warn!(
                    domain = %primary_domain,
                    delay_secs = delay.as_secs(),
                    error = %err,
                    "Long-term error requesting ARI; scheduling retry in 6 hours"
                );
                state.record_long_term_failure(delay);
            }
        }
    }

    /// Check all configured domains and renew certificates as needed
    async fn check_renewals(&self) -> Result<(), AcmeError> {
        let domains = self.client.config().domains.clone();

        if domains.is_empty() {
            return Ok(());
        }

        // We only check the primary domain for renewal as all domains in this
        // config block are part of the same certificate and stored under the primary domain.
        let domain = &domains[0];

        // Lazily ensure the ACME account exists.
        if let Err(e) = self.client.ensure_account().await {
            error!(
                domain = %domain,
                error = %e,
                "Failed to ensure ACME account before renewal check"
            );
            return Err(e);
        }

        // Check if renewal is needed according to ARI or fallback
        let needs_renewal = self.is_renewal_due(domain)?;

        if needs_renewal {
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
                    return Err(e);
                }
            }
        } else {
            debug!(domain = %domain, "Certificate is still valid");
        }

        Ok(())
    }

    /// Extract predecessor certificate identifier if valid, existing, and ARI is supported.
    fn get_predecessor_id_for_renewal(
        &self,
        primary_domain: &str,
    ) -> Option<CertificateIdentifier<'static>> {
        if self.ari_capability() != AriCapability::Supported {
            return None;
        }

        let cert = match self.client.storage().load_certificate(primary_domain) {
            Ok(Some(cert)) => cert,
            _ => return None,
        };

        match self.client.extract_certificate_identifier(&cert.cert_pem) {
            Ok(id) => Some(id),
            Err(e) => {
                warn!(
                    domain = %primary_domain,
                    error = %e,
                    "Failed to extract predecessor ARI identifier; renewing without replaces"
                );
                None
            }
        }
    }

    /// Renew the certificate for all configured domains
    ///
    /// Automatically selects the appropriate challenge type based on configuration.
    async fn renew_certificate(&self) -> Result<(), AcmeError> {
        let primary_domain = self
            .client
            .config()
            .domains
            .first()
            .cloned()
            .ok_or_else(|| AcmeError::OrderCreation("No domains configured".to_string()))?;

        // Extract predecessor identity before renewing/overwriting
        let predecessor_id = self.get_predecessor_id_for_renewal(&primary_domain);

        match self.challenge_type() {
            AcmeChallengeType::Http01 => {
                self.renew_certificate_http01(predecessor_id.as_ref()).await
            }
            AcmeChallengeType::Dns01 => self.renew_certificate_dns01(predecessor_id.as_ref()).await,
        }
    }

    /// Renew certificate using HTTP-01 challenge
    async fn renew_certificate_http01(
        &self,
        predecessor_id: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(), AcmeError> {
        let start = Instant::now();

        info!(
            replaces = ?predecessor_id.map(|p| p.to_string()),
            "Starting certificate renewal with HTTP-01 challenge"
        );

        // Create order and get challenges (with replaces if supported)
        let order_res = self.client.create_order(predecessor_id).await;
        let (mut order, challenges) = match order_res {
            Ok(res) => res,
            Err(e) if predecessor_id.is_some() && e.is_replaces_unsupported() => {
                warn!("CA does not support order with replaces; marking ARI unsupported and retrying without replaces");
                self.ari_state
                    .lock()
                    .record_unsupported(Instant::now() + ARI_LONG_TERM_RETRY_INTERVAL);
                self.client.create_order(None).await?
            }
            Err(e) => return Err(e),
        };

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

        // Update active certificate identity and reset ARI state for new certificate
        let new_cert_id = self.client.extract_certificate_identifier(&cert_pem).ok();
        self.ari_state.lock().reset_for_new_certificate(new_cert_id);

        // Promptly request ARI renewal information for the new certificate
        if let Err(e) = self.refresh_ari().await {
            debug!(error = %e, "Initial ARI refresh for renewed certificate failed (non-fatal)");
        }

        let elapsed = start.elapsed();
        info!(
            elapsed_secs = elapsed.as_secs(),
            expires = %expires,
            "Certificate renewal completed (HTTP-01)"
        );

        Ok(())
    }

    /// Renew certificate using DNS-01 challenge
    async fn renew_certificate_dns01(
        &self,
        predecessor_id: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(), AcmeError> {
        let dns_manager = self
            .dns_challenge_manager
            .as_ref()
            .ok_or(AcmeError::NoDnsProvider)?;

        let start = Instant::now();

        info!(
            provider = %dns_manager.provider_name(),
            replaces = ?predecessor_id.map(|p| p.to_string()),
            "Starting certificate renewal with DNS-01 challenge"
        );

        // Create order and get DNS-01 challenges (with replaces if supported)
        let order_res = self.client.create_order_dns01(predecessor_id).await;
        let (mut order, mut challenges) = match order_res {
            Ok(res) => res,
            Err(e) if predecessor_id.is_some() && e.is_replaces_unsupported() => {
                warn!("CA does not support order with replaces; marking ARI unsupported and retrying without replaces");
                self.ari_state
                    .lock()
                    .record_unsupported(Instant::now() + ARI_LONG_TERM_RETRY_INTERVAL);
                self.client.create_order_dns01(None).await?
            }
            Err(e) => return Err(e),
        };

        // Create DNS records and wait for propagation
        for challenge in &mut challenges {
            if let Err(e) = dns_manager.create_and_wait(challenge).await {
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
                dns_manager.cleanup_all(&challenges).await;
                return Err(e);
            }
        }

        // Wait for validation
        let validation_result = self.client.wait_for_order_ready(&mut order).await;

        // Always cleanup DNS records, regardless of validation result
        dns_manager.cleanup_all(&challenges).await;

        validation_result?;

        // Finalize and get certificate
        let (cert_pem, key_pem, expires) = self.client.finalize_order(&mut order).await?;

        // Save certificate
        self.save_certificate(&cert_pem, &key_pem, expires)?;

        // Update active certificate identity and reset ARI state for new certificate
        let new_cert_id = self.client.extract_certificate_identifier(&cert_pem).ok();
        self.ari_state.lock().reset_for_new_certificate(new_cert_id);

        // Promptly request ARI renewal information for the new certificate
        if let Err(e) = self.refresh_ari().await {
            debug!(error = %e, "Initial ARI refresh for renewed certificate failed (non-fatal)");
        }

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

        // Ensure ACME account exists
        self.client.ensure_account().await?;

        // If certificate already exists, attempt ARI refresh
        if let Ok(Some(cert)) = self.client.storage().load_certificate(primary_domain) {
            if let Ok(id) = self.client.extract_certificate_identifier(&cert.cert_pem) {
                self.ari_state.lock().certificate_id = Some(id);
                let _ = self.refresh_ari().await;
            }
        }

        let needs_renewal = self.is_renewal_due(primary_domain)?;

        if needs_renewal {
            info!(
                domain = %primary_domain,
                "Initial certificate issuance or renewal required"
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
            .field("ari_state", &self.ari_state.lock())
            .finish()
    }
}
