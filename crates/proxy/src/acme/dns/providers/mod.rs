//! DNS provider implementations
//!
//! Available providers:
//! - [`HetznerProvider`] - Hetzner DNS API
//! - [`WebhookProvider`] - Generic webhook for custom providers

mod hetzner;
mod webhook;

pub use hetzner::HetznerProvider;
pub use webhook::WebhookProvider;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use zentinel_config::server::{DnsProviderConfig, DnsProviderType};

use super::credentials::{CredentialLoader, Credentials};
use super::provider::{DnsProvider, DnsProviderError, DnsResult};

/// Create a DNS provider from configuration
pub fn create_provider(config: &DnsProviderConfig) -> DnsResult<Arc<dyn DnsProvider>> {
    // Load credentials
    let credentials = load_credentials(config)?;
    let timeout = Duration::from_secs(config.api_timeout_secs);

    match &config.provider {
        DnsProviderType::Hetzner => {
            let token = credentials.token().ok_or_else(|| {
                DnsProviderError::Credentials(
                    "Hetzner provider requires a token credential".to_string(),
                )
            })?;
            let provider = HetznerProvider::new(token, timeout)?;
            Ok(Arc::new(provider))
        }
        DnsProviderType::Webhook { url, auth_header } => {
            let provider =
                WebhookProvider::new(url.clone(), auth_header.clone(), Some(credentials), timeout)?;
            Ok(Arc::new(provider))
        }
    }
}

/// Load credentials from file or environment variable
fn load_credentials(config: &DnsProviderConfig) -> DnsResult<Credentials> {
    if let Some(ref path) = config.credentials_file {
        return CredentialLoader::load_from_file(Path::new(path));
    }

    if let Some(ref env_var) = config.credentials_env {
        return CredentialLoader::load_from_env(env_var);
    }

    Err(DnsProviderError::Credentials(
        "No credentials configured. Specify either 'credentials-file' or 'credentials-env'"
            .to_string(),
    ))
}
