//! DNS propagation checking for DNS-01 challenges
//!
//! Verifies that TXT records have propagated to authoritative nameservers
//! before notifying the ACME server.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::{Resolver, TokioResolver};
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use super::provider::{challenge_record_fqdn, DnsProviderError};

/// Configuration for propagation checking
#[derive(Debug, Clone)]
pub struct PropagationConfig {
    /// Delay before first check (allows DNS to start propagating)
    pub initial_delay: Duration,
    /// Interval between checks
    pub check_interval: Duration,
    /// Maximum time to wait for propagation
    pub timeout: Duration,
    /// Nameservers to query (empty = use defaults)
    pub nameservers: Vec<IpAddr>,
}

impl Default for PropagationConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_secs(10),
            check_interval: Duration::from_secs(5),
            timeout: Duration::from_secs(120),
            nameservers: vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),       // Google DNS
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),       // Cloudflare DNS
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),       // Quad9
            ],
        }
    }
}

/// DNS propagation checker
///
/// Verifies that DNS TXT records have propagated before ACME validation.
#[derive(Debug)]
pub struct PropagationChecker {
    config: PropagationConfig,
    resolver: TokioResolver,
}

impl PropagationChecker {
    /// Create a new propagation checker with default configuration
    pub fn new() -> Result<Self, DnsProviderError> {
        Self::with_config(PropagationConfig::default())
    }

    /// Create a propagation checker with custom configuration
    pub fn with_config(config: PropagationConfig) -> Result<Self, DnsProviderError> {
        let resolver = Self::create_resolver(&config)?;

        Ok(Self { config, resolver })
    }

    /// Create a DNS resolver with the configured nameservers
    fn create_resolver(config: &PropagationConfig) -> Result<TokioResolver, DnsProviderError> {
        let resolver_config = if config.nameservers.is_empty() {
            ResolverConfig::default()
        } else {
            let mut resolver_config = ResolverConfig::new();
            for ip in &config.nameservers {
                resolver_config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(*ip, 53),
                    Protocol::Udp,
                ));
            }
            resolver_config
        };

        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 3;
        opts.cache_size = 0; // Disable caching for propagation checks

        // hickory-resolver 0.25 uses builder pattern
        let resolver = Resolver::builder_with_config(resolver_config, TokioConnectionProvider::default())
            .with_options(opts)
            .build();
        Ok(resolver)
    }

    /// Wait for a TXT record to propagate
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain for the challenge
    /// * `expected_value` - The expected TXT record value
    ///
    /// # Returns
    ///
    /// `Ok(())` when the record is found with the expected value,
    /// or an error if the timeout is reached.
    pub async fn wait_for_propagation(
        &self,
        domain: &str,
        expected_value: &str,
    ) -> Result<(), DnsProviderError> {
        let record_name = challenge_record_fqdn(domain);
        let start = Instant::now();
        let deadline = start + self.config.timeout;

        debug!(
            record = %record_name,
            timeout_secs = self.config.timeout.as_secs(),
            "Waiting for DNS propagation"
        );

        // Initial delay
        tokio::time::sleep(self.config.initial_delay).await;

        loop {
            match self.check_record(&record_name, expected_value).await {
                Ok(true) => {
                    let elapsed = start.elapsed();
                    debug!(
                        record = %record_name,
                        elapsed_secs = elapsed.as_secs(),
                        "DNS propagation confirmed"
                    );
                    return Ok(());
                }
                Ok(false) => {
                    trace!(record = %record_name, "Record not yet propagated");
                }
                Err(e) => {
                    warn!(record = %record_name, error = %e, "DNS lookup error");
                }
            }

            if Instant::now() > deadline {
                return Err(DnsProviderError::Timeout {
                    elapsed_secs: self.config.timeout.as_secs(),
                });
            }

            tokio::time::sleep(self.config.check_interval).await;
        }
    }

    /// Check if a TXT record exists with the expected value
    async fn check_record(&self, record_name: &str, expected_value: &str) -> Result<bool, DnsProviderError> {
        let lookup = self.resolver.txt_lookup(record_name).await;

        match lookup {
            Ok(records) => {
                for record in records.iter() {
                    // TXT records can have multiple strings, join them
                    let value: String = record.txt_data().iter()
                        .map(|data| String::from_utf8_lossy(data))
                        .collect();

                    trace!(
                        record = %record_name,
                        found_value = %value,
                        expected_value = %expected_value,
                        "Checking TXT record"
                    );

                    if value == expected_value {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Err(e) => {
                // NXDOMAIN, NOERROR with no records, or SERVFAIL is expected during propagation
                // Check if the error message indicates a common transient condition
                let err_str = e.to_string().to_lowercase();
                if err_str.contains("no records found")
                    || err_str.contains("nxdomain")
                    || err_str.contains("no connections available")
                    || err_str.contains("record not found")
                {
                    Ok(false)
                } else {
                    Err(DnsProviderError::ApiRequest(format!(
                        "DNS lookup failed for '{}': {}",
                        record_name, e
                    )))
                }
            }
        }
    }

    /// Verify a record exists immediately (no waiting)
    ///
    /// Useful for testing or verifying cleanup.
    pub async fn verify_record_exists(
        &self,
        domain: &str,
        expected_value: &str,
    ) -> Result<bool, DnsProviderError> {
        let record_name = challenge_record_fqdn(domain);
        self.check_record(&record_name, expected_value).await
    }

    /// Get the configuration
    pub fn config(&self) -> &PropagationConfig {
        &self.config
    }
}

impl Default for PropagationChecker {
    fn default() -> Self {
        Self::new().expect("Failed to create default PropagationChecker")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PropagationConfig::default();
        assert_eq!(config.initial_delay, Duration::from_secs(10));
        assert_eq!(config.check_interval, Duration::from_secs(5));
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert!(!config.nameservers.is_empty());
    }

    #[tokio::test]
    async fn test_propagation_checker_creation() {
        let checker = PropagationChecker::new();
        assert!(checker.is_ok());
    }

    #[tokio::test]
    async fn test_custom_config() {
        let config = PropagationConfig {
            initial_delay: Duration::from_secs(5),
            check_interval: Duration::from_secs(2),
            timeout: Duration::from_secs(60),
            nameservers: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        };

        let checker = PropagationChecker::with_config(config.clone());
        assert!(checker.is_ok());

        let checker = checker.unwrap();
        assert_eq!(checker.config().initial_delay, Duration::from_secs(5));
    }
}
