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
use tracing::{debug, info, trace, warn};

use crate::acme::dns::provider::{
    challenge_record_fqdn, normalize_domain, DnsProvider, DnsProviderError, DnsResult,
    CHALLENGE_TTL,
};

/// Cloudflare API base URL
const CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare error code for "An identical record already exists."
const CF_ERR_DUPLICATE: i32 = 81058;

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

    /// Query Cloudflare for a zone with the exact specified name.
    async fn query_zone(&self, name: &str) -> DnsResult<Option<Zone>> {
        let response = self
            .client
            .get(format!("{}/zones", self.base_url))
            .header("Authorization", format!("Bearer {}", self.token))
            .query(&[("name", name)])
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

        Ok(zones_resp.result.and_then(|zones| zones.into_iter().next()))
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

        // Try exact domain first, then progressively strip leftmost labels to try parent domains
        let mut candidate = normalized;
        while !candidate.is_empty() {
            if let Some(zone) = self.query_zone(candidate).await? {
                // Cache the result
                {
                    let mut cache = self.zone_cache.write();
                    cache.insert(normalized.to_string(), zone.id.clone());
                }

                debug!(
                    domain = %domain,
                    candidate = %candidate,
                    zone_id = %zone.id,
                    "Found zone for domain"
                );
                return Ok(zone.id);
            }

            if let Some(pos) = candidate.find('.') {
                candidate = &candidate[pos + 1..];
            } else {
                break;
            }
        }

        Err(DnsProviderError::ZoneNotFound {
            domain: normalized.to_string(),
        })
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
            // Cover both the stable error code (81058) and the human
            // message, matching acme.sh's grep for
            // "An identical record already exists." / "already exists" /
            // '"code":81058'. This guards against code drift.
            let is_duplicate = record_resp.errors.iter().any(|e| {
                e.code == CF_ERR_DUPLICATE || e.message.to_lowercase().contains("already exists")
            });
            if is_duplicate {
                warn!(
                    domain = %domain,
                    record_name = %full_name,
                    "Cloudflare reports identical TXT already exists, reusing existing record"
                );
                if let Some(existing_id) = self
                    .find_existing_record_id(&zone_id, &full_name, record_value)
                    .await?
                {
                    info!(
                        domain = %domain,
                        record_id = %existing_id,
                        "Reusing existing Cloudflare TXT record for DNS-01"
                    );
                    return Ok(existing_id);
                }
            }
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

impl CloudflareProvider {
    async fn find_existing_record_id(
        &self,
        zone_id: &str,
        full_name: &str,
        expected_content: &str,
    ) -> DnsResult<Option<String>> {
        // Pagination not needed for ACME: only a few TXT records exist
        // under _acme-challenge, so a single page is sufficient.
        let resp = self
            .client
            .get(format!("{}/zones/{}/dns_records", self.base_url, zone_id))
            .header("Authorization", format!("Bearer {}", self.token))
            .query(&[
                ("type", "TXT"),
                ("name", full_name),
                ("content", expected_content),
            ])
            .send()
            .await
            .map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to list TXT records: {}", e))
            })?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let list_resp: CloudflareResponse<Vec<Record>> = resp.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse TXT list response: {}", e))
        })?;
        if !list_resp.success {
            return Ok(None);
        }
        let Some(records) = list_resp.result else {
            return Ok(None);
        };
        for r in records {
            if r.content.as_deref() == Some(expected_content) {
                return Ok(Some(r.id));
            }
        }
        Ok(None)
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
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default, rename = "type")]
    #[allow(dead_code)]
    type_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_get_zone_id_no_matching_zone_returns_original_domain() {
        let mock_server = MockServer::start().await;

        // All zone queries return empty results
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let err = provider
            .get_zone_id("deep.unknown.example.com")
            .await
            .unwrap_err();
        match err {
            DnsProviderError::ZoneNotFound { domain } => {
                assert_eq!(domain, "deep.unknown.example.com");
            }
            other => panic!("expected ZoneNotFound, got {:?}", other),
        }

        // Wildcard should normalize and report normalized domain on error
        let err_wildcard = provider
            .get_zone_id("*.deep.unknown.example.com")
            .await
            .unwrap_err();
        match err_wildcard {
            DnsProviderError::ZoneNotFound { domain } => {
                assert_eq!(domain, "deep.unknown.example.com");
            }
            other => panic!("expected ZoneNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_zone_id_label_boundaries_not_substring() {
        let mock_server = MockServer::start().await;

        // Querying sub.notexample.com should check:
        // 1. sub.notexample.com
        // 2. notexample.com
        // 3. com
        // It must NOT match or query example.com!
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "sub.notexample.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "notexample.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "wrong-zone", "name": "example.com" }]
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let err = provider
            .get_zone_id("sub.notexample.com")
            .await
            .unwrap_err();
        match err {
            DnsProviderError::ZoneNotFound { domain } => {
                assert_eq!(domain, "sub.notexample.com");
            }
            other => panic!("expected ZoneNotFound, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_get_zone_id_cache_internals() {
        let mock_server = MockServer::start().await;
        let parent_zone_id = "zone-parent-789";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": parent_zone_id, "name": "example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        // Verify cache is empty before lookup
        {
            let cache = provider.zone_cache.read();
            assert_eq!(cache.get("sub.example.com"), None);
        }

        // First call populates cache
        let id1 = provider.get_zone_id("sub.example.com").await.unwrap();
        assert_eq!(id1, parent_zone_id);

        // Verify cache is populated under the normalized requested domain
        {
            let cache = provider.zone_cache.read();
            assert_eq!(
                cache.get("sub.example.com"),
                Some(&parent_zone_id.to_string())
            );
        }

        // Second call with same domain uses cache (no API calls, expect(1) would fail if called)
        let id2 = provider.get_zone_id("sub.example.com").await.unwrap();
        assert_eq!(id2, parent_zone_id);

        // Third call with wildcard normalizes to sub.example.com and hits cache
        let id3 = provider.get_zone_id("*.sub.example.com").await.unwrap();
        assert_eq!(id3, parent_zone_id);
    }
}
