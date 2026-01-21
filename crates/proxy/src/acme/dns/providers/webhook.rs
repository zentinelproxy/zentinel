//! Generic webhook DNS provider
//!
//! Allows integration with custom DNS management systems via HTTP webhooks.
//!
//! # Webhook API
//!
//! ## Create Record
//! ```text
//! POST {url}/records
//! Content-Type: application/json
//!
//! {
//!   "domain": "example.com",
//!   "record_name": "_acme-challenge",
//!   "record_type": "TXT",
//!   "record_value": "challenge-value",
//!   "ttl": 60
//! }
//!
//! Response:
//! {
//!   "record_id": "unique-id"
//! }
//! ```
//!
//! ## Delete Record
//! ```text
//! DELETE {url}/records/{record_id}?domain={domain}
//!
//! Response: 200 OK or 204 No Content
//! ```
//!
//! ## Check Domain Support
//! ```text
//! GET {url}/domains/{domain}/supported
//!
//! Response:
//! {
//!   "supported": true
//! }
//! ```

use std::time::Duration;

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::acme::dns::credentials::Credentials;
use crate::acme::dns::provider::{DnsProvider, DnsProviderError, DnsResult, CHALLENGE_TTL};

/// Webhook DNS provider for custom integrations
#[derive(Debug)]
pub struct WebhookProvider {
    client: Client,
    base_url: String,
    auth_header: Option<String>,
    credentials: Option<Credentials>,
}

impl WebhookProvider {
    /// Create a new webhook DNS provider
    ///
    /// # Arguments
    ///
    /// * `base_url` - Base URL for the webhook API
    /// * `auth_header` - Optional custom auth header name (e.g., "X-API-Key")
    /// * `credentials` - Optional credentials for authentication
    /// * `timeout` - Request timeout
    pub fn new(
        base_url: String,
        auth_header: Option<String>,
        credentials: Option<Credentials>,
        timeout: Duration,
    ) -> DnsResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| {
                DnsProviderError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        // Remove trailing slash from base URL
        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
            auth_header,
            credentials,
        })
    }

    /// Add authentication to a request
    fn add_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (&self.auth_header, &self.credentials) {
            (Some(header), Some(creds)) => {
                request.header(header.as_str(), creds.as_bearer_token())
            }
            (None, Some(creds)) => {
                request.bearer_auth(creds.as_bearer_token())
            }
            _ => request,
        }
    }
}

#[async_trait]
impl DnsProvider for WebhookProvider {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> DnsResult<String> {
        debug!(
            domain = %domain,
            record_name = %record_name,
            url = %self.base_url,
            "Creating TXT record via webhook"
        );

        let request = CreateRecordRequest {
            domain: domain.to_string(),
            record_name: record_name.to_string(),
            record_type: "TXT".to_string(),
            record_value: record_value.to_string(),
            ttl: CHALLENGE_TTL,
        };

        let request_builder = self
            .client
            .post(format!("{}/records", self.base_url))
            .json(&request);

        let response = self
            .add_auth(request_builder)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Webhook request failed: {}", e))
                }
            })?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Err(DnsProviderError::Authentication(
                "Webhook authentication failed".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::RecordCreation {
                record_name: record_name.to_string(),
                message: format!("Webhook returned HTTP {} - {}", status, body),
            });
        }

        let record_response: CreateRecordResponse = response.json().await.map_err(|e| {
            DnsProviderError::RecordCreation {
                record_name: record_name.to_string(),
                message: format!("Failed to parse webhook response: {}", e),
            }
        })?;

        debug!(record_id = %record_response.record_id, "TXT record created via webhook");
        Ok(record_response.record_id)
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> DnsResult<()> {
        debug!(
            domain = %domain,
            record_id = %record_id,
            "Deleting TXT record via webhook"
        );

        let request_builder = self
            .client
            .delete(format!("{}/records/{}", self.base_url, record_id))
            .query(&[("domain", domain)]);

        let response = self
            .add_auth(request_builder)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Webhook request failed: {}", e))
                }
            })?;

        // 404 is acceptable - record might already be deleted
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!(record_id = %record_id, "Record already deleted");
            return Ok(());
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::RecordDeletion {
                record_id: record_id.to_string(),
                message: format!("Webhook returned HTTP {} - {}", status, body),
            });
        }

        debug!(record_id = %record_id, "TXT record deleted via webhook");
        Ok(())
    }

    async fn supports_domain(&self, domain: &str) -> DnsResult<bool> {
        let request_builder = self
            .client
            .get(format!("{}/domains/{}/supported", self.base_url, domain));

        let response = self
            .add_auth(request_builder)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Webhook request failed: {}", e))
                }
            })?;

        // 404 means domain not supported
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(false);
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::ApiRequest(format!(
                "Webhook returned HTTP {} - {}",
                status, body
            )));
        }

        let support_response: DomainSupportResponse = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse webhook response: {}", e))
        })?;

        Ok(support_response.supported)
    }
}

// Webhook API types

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    domain: String,
    record_name: String,
    record_type: String,
    record_value: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct CreateRecordResponse {
    record_id: String,
}

#[derive(Debug, Deserialize)]
struct DomainSupportResponse {
    supported: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_url_normalization() {
        let provider = WebhookProvider::new(
            "https://example.com/api/".to_string(),
            None,
            None,
            Duration::from_secs(30),
        )
        .unwrap();

        assert_eq!(provider.base_url, "https://example.com/api");
    }

    #[test]
    fn test_without_trailing_slash() {
        let provider = WebhookProvider::new(
            "https://example.com/api".to_string(),
            None,
            None,
            Duration::from_secs(30),
        )
        .unwrap();

        assert_eq!(provider.base_url, "https://example.com/api");
    }
}
