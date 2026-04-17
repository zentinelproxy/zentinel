//! Cloudflare DNS provider implementation
//!
//! Uses the Cloudflare API v4 to manage TXT records for DNS-01 challenges.
//! API documentation: <https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record>

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::acme::dns::provider::{
    challenge_record_fqdn, normalize_domain, DnsProvider, DnsProviderError, DnsResult,
    CHALLENGE_TTL,
};

/// Cloudflare API base URL
const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare DNS provider
#[derive(Debug)]
pub struct CloudflareProvider {
    client: Client,
    token: String,
    base_url: String,
    /// Cache of domain -> zone_id mappings
    zone_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl CloudflareProvider {
    /// Create a new Cloudflare DNS provider
    ///
    /// # Arguments
    ///
    /// * `token` - Cloudflare API Token (Bearer auth)
    /// * `timeout` - Request timeout
    pub fn new(token: &str, timeout: Duration) -> DnsResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            DnsProviderError::Configuration(format!("Failed to create HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            token: token.to_string(),
            base_url: CLOUDFLARE_API_BASE.to_string(),
            zone_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new Cloudflare DNS provider with a custom base URL (for testing)
    #[doc(hidden)]
    pub fn new_test(token: &str, base_url: String, timeout: Duration) -> DnsResult<Self> {
        let mut provider = Self::new(token, timeout)?;
        provider.base_url = base_url;
        Ok(provider)
    }

    /// Get the zone ID for a domain
    async fn get_zone_id(&self, domain: &str) -> DnsResult<String> {
        let normalized = normalize_domain(domain);

        // Check cache first
        {
            let cache = self.zone_cache.read();
            if let Some(zone_id) = cache.get(normalized) {
                trace!(domain = %domain, zone_id = %zone_id, "Zone ID found in cache");
                return Ok(zone_id.clone());
            }
        }

        // Fetch zones from API
        // We filter by name to get the specific zone
        let response = self
            .client
            .get(format!("{}/zones", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .query(&[("name", normalized)])
            .send()
            .await
            .map_err(|e| DnsProviderError::ApiRequest(format!("Failed to list zones: {}", e)))?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DnsProviderError::Authentication(
                "Invalid Cloudflare API token".to_string(),
            ));
        }

        let zones_resp: CloudflareResponse<Vec<Zone>> = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse zone response: {}", e))
        })?;

        if !zones_resp.success {
            return Err(DnsProviderError::ApiRequest(format!(
                "Cloudflare API error: {:?}",
                zones_resp.errors
            )));
        }

        // Find the matching zone
        let zone = zones_resp
            .result
            .and_then(|zones| zones.into_iter().next())
            .ok_or_else(|| DnsProviderError::ZoneNotFound {
                domain: normalized.to_string(),
            })?;

        // Cache the result
        {
            let mut cache = self.zone_cache.write();
            cache.insert(normalized.to_string(), zone.id.clone());
        }

        debug!(domain = %domain, zone_id = %zone.id, "Found zone for domain");
        Ok(zone.id)
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "cloudflare"
    }

    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> DnsResult<String> {
        let zone_id = self.get_zone_id(domain).await?;
        let full_name = format!("{}.{}", record_name, normalize_domain(domain));

        let payload = CreateRecordRequest {
            type_name: "TXT".to_string(),
            name: full_name.clone(),
            content: record_value.to_string(),
            ttl: CHALLENGE_TTL,
        };

        let response = self
            .client
            .post(format!("{}/zones/{}/dns_records", self.base_url, zone_id))
            .header("Authorization", format!("Bearer {}", self.token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to create TXT record: {}", e))
            })?;

        let record_resp: CloudflareResponse<Record> = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse record response: {}", e))
        })?;

        if !record_resp.success {
            return Err(DnsProviderError::RecordCreation {
                record_name: full_name,
                message: format!("{:?}", record_resp.errors),
            });
        }

        let record = record_resp
            .result
            .ok_or_else(|| DnsProviderError::RecordCreation {
                record_name: full_name,
                message: "Cloudflare API returned success but missing record in result".to_string(),
            })?;

        debug!(
            domain = %domain,
            record_id = %record.id,
            "Created TXT record"
        );
        Ok(record.id)
    }

    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> DnsResult<()> {
        let zone_id = self.get_zone_id(domain).await?;

        let response = self
            .client
            .delete(format!(
                "{}/zones/{}/dns_records/{}",
                self.base_url, zone_id, record_id
            ))
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to delete TXT record: {}", e))
            })?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(()); // Already deleted
        }

        let delete_resp: CloudflareResponse<serde_json::Value> =
            response.json().await.map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to parse delete response: {}", e))
            })?;

        if !delete_resp.success {
            return Err(DnsProviderError::RecordDeletion {
                record_id: record_id.to_string(),
                message: format!("{:?}", delete_resp.errors),
            });
        }

        debug!(domain = %domain, record_id = %record_id, "Deleted TXT record");
        Ok(())
    }

    async fn supports_domain(&self, domain: &str) -> DnsResult<bool> {
        match self.get_zone_id(domain).await {
            Ok(_) => Ok(true),
            Err(DnsProviderError::ZoneNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Generic Cloudflare API response
#[derive(Debug, Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: i32,
    message: String,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    #[serde(rename = "type")]
    type_name: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
}
