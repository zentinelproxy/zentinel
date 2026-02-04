//! Hetzner DNS provider implementation
//!
//! Uses the Hetzner DNS API to manage TXT records for DNS-01 challenges.
//! API documentation: <https://dns.hetzner.com/api-docs>

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

/// Hetzner DNS API base URL
const HETZNER_API_BASE: &str = "https://dns.hetzner.com/api/v1";

/// Hetzner DNS provider
#[derive(Debug)]
pub struct HetznerProvider {
    client: Client,
    token: String,
    /// Cache of domain -> zone_id mappings
    zone_cache: Arc<RwLock<HashMap<String, String>>>,
}

impl HetznerProvider {
    /// Create a new Hetzner DNS provider
    ///
    /// # Arguments
    ///
    /// * `token` - Hetzner DNS API token
    /// * `timeout` - Request timeout
    pub fn new(token: &str, timeout: Duration) -> DnsResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            DnsProviderError::Configuration(format!("Failed to create HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            token: token.to_string(),
            zone_cache: Arc::new(RwLock::new(HashMap::new())),
        })
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
        let zones = self.list_zones().await?;

        // Find the matching zone (try exact match first, then parent domains)
        let zone = self.find_matching_zone(normalized, &zones)?;

        // Cache the result
        {
            let mut cache = self.zone_cache.write();
            cache.insert(normalized.to_string(), zone.id.clone());
        }

        debug!(domain = %domain, zone_id = %zone.id, zone_name = %zone.name, "Found zone for domain");
        Ok(zone.id.clone())
    }

    /// List all zones from Hetzner API
    async fn list_zones(&self) -> DnsResult<Vec<Zone>> {
        let response = self
            .client
            .get(format!("{}/zones", HETZNER_API_BASE))
            .header("Auth-API-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Failed to list zones: {}", e))
                }
            })?;

        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(DnsProviderError::Authentication(
                "Invalid Hetzner API token".to_string(),
            ));
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::ApiRequest(format!(
                "Failed to list zones: HTTP {} - {}",
                status, body
            )));
        }

        let zones_response: ZonesResponse = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse zones response: {}", e))
        })?;

        Ok(zones_response.zones)
    }

    /// Find the matching zone for a domain
    fn find_matching_zone<'a>(&self, domain: &str, zones: &'a [Zone]) -> DnsResult<&'a Zone> {
        // Try exact match first
        if let Some(zone) = zones.iter().find(|z| z.name == domain) {
            return Ok(zone);
        }

        // Try parent domains
        let mut current = domain;
        while let Some(pos) = current.find('.') {
            current = &current[pos + 1..];
            if let Some(zone) = zones.iter().find(|z| z.name == current) {
                return Ok(zone);
            }
        }

        Err(DnsProviderError::ZoneNotFound {
            domain: domain.to_string(),
        })
    }

    /// Extract record name relative to zone
    fn record_name_for_zone(&self, fqdn: &str, zone_name: &str) -> String {
        if fqdn == zone_name {
            "@".to_string()
        } else if let Some(stripped) = fqdn.strip_suffix(&format!(".{}", zone_name)) {
            stripped.to_string()
        } else {
            fqdn.to_string()
        }
    }

    /// Get zone name by ID
    async fn get_zone_name(&self, zone_id: &str) -> DnsResult<String> {
        let response = self
            .client
            .get(format!("{}/zones/{}", HETZNER_API_BASE, zone_id))
            .header("Auth-API-Token", &self.token)
            .send()
            .await
            .map_err(|e| DnsProviderError::ApiRequest(format!("Failed to get zone: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::ApiRequest(format!(
                "Failed to get zone: HTTP {} - {}",
                status, body
            )));
        }

        let zone_response: ZoneResponse = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse zone response: {}", e))
        })?;

        Ok(zone_response.zone.name)
    }
}

#[async_trait]
impl DnsProvider for HetznerProvider {
    fn name(&self) -> &'static str {
        "hetzner"
    }

    async fn create_txt_record(
        &self,
        domain: &str,
        record_name: &str,
        record_value: &str,
    ) -> DnsResult<String> {
        let zone_id = self.get_zone_id(domain).await?;
        let zone_name = self.get_zone_name(&zone_id).await?;

        // Build the full record name and then make it relative to zone
        let fqdn = format!("{}.{}", record_name, normalize_domain(domain));
        let relative_name = self.record_name_for_zone(&fqdn, &zone_name);

        debug!(
            domain = %domain,
            zone_id = %zone_id,
            record_name = %relative_name,
            "Creating TXT record"
        );

        let request = CreateRecordRequest {
            zone_id: zone_id.clone(),
            name: relative_name.clone(),
            r#type: "TXT".to_string(),
            value: record_value.to_string(),
            ttl: Some(CHALLENGE_TTL),
        };

        let response = self
            .client
            .post(format!("{}/records", HETZNER_API_BASE))
            .header("Auth-API-Token", &self.token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Failed to create record: {}", e))
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::RecordCreation {
                record_name: relative_name,
                message: format!("HTTP {} - {}", status, body),
            });
        }

        let record_response: RecordResponse =
            response
                .json()
                .await
                .map_err(|e| DnsProviderError::RecordCreation {
                    record_name: relative_name.clone(),
                    message: format!("Failed to parse response: {}", e),
                })?;

        debug!(
            record_id = %record_response.record.id,
            "TXT record created successfully"
        );

        Ok(record_response.record.id)
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> DnsResult<()> {
        debug!(record_id = %record_id, "Deleting TXT record");

        let response = self
            .client
            .delete(format!("{}/records/{}", HETZNER_API_BASE, record_id))
            .header("Auth-API-Token", &self.token)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsProviderError::Timeout { elapsed_secs: 30 }
                } else {
                    DnsProviderError::ApiRequest(format!("Failed to delete record: {}", e))
                }
            })?;

        // 404 is fine - record might already be deleted
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!(record_id = %record_id, "Record already deleted");
            return Ok(());
        }

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(DnsProviderError::RecordDeletion {
                record_id: record_id.to_string(),
                message: format!("HTTP {} - {}", status, body),
            });
        }

        debug!(record_id = %record_id, "TXT record deleted successfully");
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

// Hetzner API types

#[derive(Debug, Deserialize)]
struct ZonesResponse {
    zones: Vec<Zone>,
}

#[derive(Debug, Deserialize)]
struct ZoneResponse {
    zone: Zone,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    zone_id: String,
    name: String,
    r#type: String,
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct RecordResponse {
    record: Record,
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_name_for_zone() {
        let provider = HetznerProvider {
            client: Client::new(),
            token: "test".to_string(),
            zone_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        // Direct zone
        assert_eq!(
            provider.record_name_for_zone("example.com", "example.com"),
            "@"
        );

        // Subdomain
        assert_eq!(
            provider.record_name_for_zone("_acme-challenge.example.com", "example.com"),
            "_acme-challenge"
        );

        // Nested subdomain
        assert_eq!(
            provider.record_name_for_zone("_acme-challenge.sub.example.com", "example.com"),
            "_acme-challenge.sub"
        );
    }
}
