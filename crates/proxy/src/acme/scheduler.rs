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
    ARI_LONG_TERM_RETRY_INTERVAL, ARI_MIN_CERTIFICATE_AGE,
};
use super::challenge::ChallengeManager;
use super::client::AcmeClient;
use super::dns::Dns01ChallengeManager;
use super::error::{is_retryable_acme_error, AcmeError};
use crate::tls::HotReloadableSniResolver;

/// Startup delay before initial check (10 seconds)
const STARTUP_DELAY: Duration = Duration::from_secs(10);

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

        // Initial check after startup delay
        tokio::time::sleep(STARTUP_DELAY).await;

        let primary_domain = match self.client.config().domains.first() {
            Some(d) => d.clone(),
            None => {
                warn!("No domains configured for ACME renewal scheduler; exiting background loop");
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
            let renewal_deadline = self.effective_renewal_deadline(&primary_domain);
            let next_refresh = self.ari_state.lock().next_refresh;

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

    /// Calculate the effective renewal deadline taking certificate cooldown into account.
    ///
    /// If an ARI renewal deadline is set, it cannot trigger renewal until the certificate has
    /// reached `ARI_MIN_CERTIFICATE_AGE`. Returning the clamped deadline ensures that `next_wakeup`
    /// does not wake up in a tight loop while an ARI renewal is deferred.
    fn effective_renewal_deadline(&self, primary_domain: &str) -> Option<chrono::DateTime<Utc>> {
        let deadline = self.ari_state.lock().renewal_deadline?;
        let min_renewal_time = self
            .client
            .storage()
            .load_certificate(primary_domain)
            .ok()
            .flatten()
            .and_then(|cert| {
                chrono::Duration::from_std(ARI_MIN_CERTIFICATE_AGE)
                    .ok()
                    .map(|min_age| cert.meta.issued + min_age)
            });

        match min_renewal_time {
            Some(min_time) => Some(deadline.max(min_time)),
            None => Some(deadline),
        }
    }

    /// Check whether renewal is needed according to ARI or fallback policy.
    ///
    /// Expiry-based renewal (`renew-before-days`) is independent of ARI: ARI can cause
    /// renewal earlier, but cannot suppress or delay expiry-based renewal.
    /// Additionally, an ARI-triggered renewal enforces `ARI_MIN_CERTIFICATE_AGE` cooldown
    /// to prevent immediate repeated renewals on pathological CA windows.
    pub fn is_renewal_due(&self, domain: &str) -> Result<bool, AcmeError> {
        // 1. Expiry protection is independent of ARI:
        // ARI can cause renewal earlier, but can never suppress existing expiry-based renewal.
        if self.client.needs_renewal(domain)? {
            return Ok(true);
        }

        let now = Utc::now();
        let ari_due = {
            let state = self.ari_state.lock();
            state.is_ari_renewal_due(now).unwrap_or(false)
        };

        if !ari_due {
            return Ok(false);
        }

        // 2. Cooldown guard for ARI-triggered renewals:
        // Ensure the certificate has reached ARI_MIN_CERTIFICATE_AGE before renewing via ARI.
        if let Some(cert) = self.client.storage().load_certificate(domain)? {
            if let Ok(min_age) = chrono::Duration::from_std(ARI_MIN_CERTIFICATE_AGE) {
                if now.signed_duration_since(cert.meta.issued) < min_age {
                    debug!(
                        domain = %domain,
                        issued = %cert.meta.issued,
                        cooldown_secs = ARI_MIN_CERTIFICATE_AGE.as_secs(),
                        "ARI renewal deadline reached but certificate is within minimum age cooldown; deferring renewal"
                    );
                    return Ok(false);
                }
            }
        }

        Ok(true)
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
        let window_changed = state.last_window.as_ref() != Some(&window);
        let renewal_time = select_renewal_time(
            &window,
            state.last_window.as_ref(),
            state.renewal_deadline,
            now_utc,
        );

        if window_changed {
            if let Some(ref explanation_url) = renewal_info.explanation_url {
                info!(
                    domain = %primary_domain,
                    window_start = %window.start,
                    window_end = %window.end,
                    renewal_deadline = %renewal_time,
                    refresh_in_secs = clamped_refresh.as_secs(),
                    explanation_url = %explanation_url,
                    "ARI renewal info updated with explanation URL"
                );
            } else {
                info!(
                    domain = %primary_domain,
                    window_start = %window.start,
                    window_end = %window.end,
                    renewal_deadline = %renewal_time,
                    refresh_in_secs = clamped_refresh.as_secs(),
                    "ARI renewal info updated successfully"
                );
            }
        } else {
            debug!(
                domain = %primary_domain,
                window_start = %window.start,
                window_end = %window.end,
                renewal_deadline = %renewal_time,
                refresh_in_secs = clamped_refresh.as_secs(),
                "ARI renewal info unchanged"
            );
        }

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
    pub async fn check_renewals(&self) -> Result<(), AcmeError> {
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
    pub async fn renew_certificate_http01(
        &self,
        predecessor_id: Option<&CertificateIdentifier<'_>>,
    ) -> Result<(), AcmeError> {
        let start = Instant::now();

        info!(
            replaces = ?predecessor_id.map(|p| p.to_string()),
            "Starting certificate renewal with HTTP-01 challenge"
        );

        // Create order and get challenges (with replaces if predecessor_id is present)
        let (mut order, challenges) = match self.client.create_order(predecessor_id).await {
            Ok(res) => res,
            Err(initial_err) if predecessor_id.is_some() => {
                warn!(
                    error = %initial_err,
                    predecessor_id = ?predecessor_id.map(|p| p.to_string()),
                    "Order creation with 'replaces' failed; falling back to renewal order without replaces"
                );
                match self.client.create_order(None).await {
                    Ok(fallback_res) => {
                        info!("Fallback order without 'replaces' succeeded");
                        fallback_res
                    }
                    Err(fallback_err) => {
                        error!(
                            initial_error = %initial_err,
                            fallback_error = %fallback_err,
                            "Fallback order creation without 'replaces' also failed"
                        );
                        return Err(fallback_err);
                    }
                }
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
    pub async fn renew_certificate_dns01(
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

        // Create order and get DNS-01 challenges (with replaces if predecessor_id is present)
        let (mut order, mut challenges) = match self.client.create_order_dns01(predecessor_id).await
        {
            Ok(res) => res,
            Err(initial_err) if predecessor_id.is_some() => {
                warn!(
                    error = %initial_err,
                    predecessor_id = ?predecessor_id.map(|p| p.to_string()),
                    "DNS-01 order creation with 'replaces' failed; falling back to renewal order without replaces"
                );
                match self.client.create_order_dns01(None).await {
                    Ok(fallback_res) => {
                        info!("Fallback DNS-01 order without 'replaces' succeeded");
                        fallback_res
                    }
                    Err(fallback_err) => {
                        error!(
                            initial_error = %initial_err,
                            fallback_error = %fallback_err,
                            "Fallback DNS-01 order creation without 'replaces' also failed"
                        );
                        return Err(fallback_err);
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use zentinel_config::server::{AcmeChallengeType, AcmeConfig, AcmeKeyType};

    fn test_fixtures_path() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests/fixtures/tls")
    }

    fn create_test_scheduler(
        storage_dir: PathBuf,
    ) -> (
        Arc<AcmeClient>,
        Arc<super::super::storage::CertificateStorage>,
        RenewalScheduler,
    ) {
        let storage =
            Arc::new(super::super::storage::CertificateStorage::new(&storage_dir).unwrap());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            server_url: None,
            staging: true,
            eab: None,
            storage: storage_dir,
            renew_before_days: 30,
            challenge_type: AcmeChallengeType::Http01,
            key_type: AcmeKeyType::EcdsaP256,
            dns_provider: None,
        };
        let client = Arc::new(AcmeClient::new(config, Arc::clone(&storage)));
        let challenge_mgr = Arc::new(ChallengeManager::new());
        let scheduler = RenewalScheduler::new(Arc::clone(&client), challenge_mgr, None);
        (client, storage, scheduler)
    }

    #[test]
    fn test_predecessor_id_only_used_when_supported() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (_client, storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());
        let fixtures = test_fixtures_path();
        let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
        let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

        storage
            .save_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                Utc::now() + chrono::Duration::days(90),
                &["example.com".to_string()],
            )
            .unwrap();

        // 1. Unknown
        scheduler.ari_state.lock().capability = AriCapability::Unknown;
        assert!(scheduler
            .get_predecessor_id_for_renewal("example.com")
            .is_none());

        // 2. Unsupported
        scheduler.ari_state.lock().capability = AriCapability::Unsupported;
        assert!(scheduler
            .get_predecessor_id_for_renewal("example.com")
            .is_none());

        // 3. Supported
        scheduler.ari_state.lock().capability = AriCapability::Supported;
        let id = scheduler.get_predecessor_id_for_renewal("example.com");
        assert!(id.is_some());
    }

    #[test]
    fn test_expiry_protection_independent_of_ari() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (_client, storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());
        let fixtures = test_fixtures_path();
        let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
        let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

        // Certificate expiring in 10 days (< renew_before_days of 30)
        let expires = Utc::now() + chrono::Duration::days(10);
        storage
            .save_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                expires,
                &["example.com".to_string()],
            )
            .unwrap();

        // CA returns an excessively late renewal deadline far in future (60 days)
        scheduler.ari_state.lock().capability = AriCapability::Supported;
        scheduler.ari_state.lock().renewal_deadline = Some(Utc::now() + chrono::Duration::days(60));

        // Even though ARI renewal_deadline is in the future, expiry protection MUST trigger renewal!
        assert!(scheduler.is_renewal_due("example.com").unwrap());
    }

    #[test]
    fn test_ari_cooldown_prevents_immediate_repeated_renewal() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (_client, storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());
        let fixtures = test_fixtures_path();
        let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
        let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

        // Certificate issued now, expiring in 90 days (not due for expiry renewal)
        let expires = Utc::now() + chrono::Duration::days(90);
        storage
            .save_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                expires,
                &["example.com".to_string()],
            )
            .unwrap();

        // CA returns a window in the past (e.g. renewal_deadline is now)
        scheduler.ari_state.lock().capability = AriCapability::Supported;
        scheduler.ari_state.lock().renewal_deadline =
            Some(Utc::now() - chrono::Duration::minutes(5));

        // Certificate was just issued (< ARI_MIN_CERTIFICATE_AGE), so ARI renewal is deferred!
        assert!(!scheduler.is_renewal_due("example.com").unwrap());

        // And effective_renewal_deadline defers next wake until cooldown expires
        let effective = scheduler.effective_renewal_deadline("example.com").unwrap();
        assert!(effective > Utc::now());
    }

    #[test]
    fn test_ari_cooldown_survives_process_restart() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fixtures = test_fixtures_path();
        let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
        let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

        // Save certificate
        let storage =
            Arc::new(super::super::storage::CertificateStorage::new(temp_dir.path()).unwrap());
        storage
            .save_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                Utc::now() + chrono::Duration::days(90),
                &["example.com".to_string()],
            )
            .unwrap();

        // Simulate process restart: create a brand new scheduler instance on the existing storage
        let (_client2, _storage2, scheduler2) =
            create_test_scheduler(temp_dir.path().to_path_buf());
        scheduler2.ari_state.lock().capability = AriCapability::Supported;
        scheduler2.ari_state.lock().renewal_deadline =
            Some(Utc::now() - chrono::Duration::minutes(5));

        // Stored issuance metadata is read and cooldown is enforced!
        assert!(!scheduler2.is_renewal_due("example.com").unwrap());
    }
}
