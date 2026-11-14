//! Hetzner DNS provider implementation
//!
//! Manages DNS-01 challenge TXT records through the DNS endpoints of the
//! Hetzner Cloud API (`https://api.hetzner.cloud/v1`, zones and RRSets).
//! API documentation: <https://docs.hetzner.cloud/reference/cloud#zones>
//!
//! The old Hetzner DNS API (`dns.hetzner.com`) was shut down on 2026-05-27.
//! Tokens created in the old DNS Console do not work against the Cloud API;
//! operators need a Hetzner Cloud API token with read & write permission,
//! created in the project that holds the zone.
//!
//! # How records are managed
//!
//! The Cloud API works on RRSets (all records sharing one name and type), not
//! on individual records. A wildcard plus apex certificate needs two TXT
//! values on the same `_acme-challenge` name at the same time, so this
//! provider never replaces an RRSet: it adds its value with the
//! `add_records` action and removes only its own value with
//! `remove_records`. Both actions may complete asynchronously; the provider
//! waits for the returned Action to finish.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use crate::acme::dns::provider::{
    normalize_domain, DnsProvider, DnsProviderError, DnsResult, CHALLENGE_TTL,
};

/// Hetzner Cloud API base URL
const HETZNER_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// Interval between polls of a running Action
const ACTION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How often an RRSet action is retried when the RRSet is busy
/// (`409 conflict` / `423 locked`, e.g. the wildcard and apex challenges
/// writing the same `_acme-challenge` RRSet at once)
const BUSY_RETRIES: u32 = 5;

/// Comment attached to the records this provider creates
const RECORD_COMMENT: &str = "zentinel acme dns-01 challenge";

/// Message for a token the Cloud API does not accept
const TOKEN_HINT: &str = "the Hetzner provider uses the Hetzner Cloud API \
    (api.hetzner.cloud) since the old DNS Console API (dns.hetzner.com) was shut down \
    on 2026-05-27. Tokens from the old DNS Console do not work: create an API token \
    with Read & Write permission in the Hetzner Console, in the project that holds \
    the DNS zone (Security -> API Tokens)";

/// A zone, as cached by the provider
#[derive(Debug, Clone)]
struct ZoneInfo {
    id: u64,
    name: String,
}

/// Hetzner DNS provider (Hetzner Cloud API)
#[derive(Debug)]
pub struct HetznerProvider {
    client: Client,
    token: String,
    base_url: String,
    timeout: Duration,
    poll_interval: Duration,
    /// Cache of domain -> zone mappings
    zone_cache: Arc<RwLock<HashMap<String, ZoneInfo>>>,
}

impl HetznerProvider {
    /// Create a new Hetzner DNS provider
    ///
    /// # Arguments
    ///
    /// * `token` - Hetzner Cloud API token (read & write)
    /// * `timeout` - Request timeout, also the limit for waiting on an Action
    pub fn new(token: &str, timeout: Duration) -> DnsResult<Self> {
        let client = Client::builder().timeout(timeout).build().map_err(|e| {
            DnsProviderError::Configuration(format!("Failed to create HTTP client: {}", e))
        })?;

        Ok(Self {
            client,
            token: token.trim().to_string(),
            base_url: HETZNER_API_BASE.to_string(),
            timeout,
            poll_interval: ACTION_POLL_INTERVAL,
            zone_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a new Hetzner DNS provider with a custom base URL (for testing)
    ///
    /// Actions are polled every 10 ms instead of every second.
    #[doc(hidden)]
    pub fn new_test(token: &str, base_url: String, timeout: Duration) -> DnsResult<Self> {
        let mut provider = Self::new(token, timeout)?;
        provider.base_url = base_url;
        provider.poll_interval = Duration::from_millis(10);
        Ok(provider)
    }

    fn auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.bearer_auth(&self.token)
    }

    fn map_send_error(&self, what: &str, e: reqwest::Error) -> DnsProviderError {
        if e.is_timeout() {
            DnsProviderError::Timeout {
                elapsed_secs: self.timeout.as_secs(),
            }
        } else {
            DnsProviderError::ApiRequest(format!("Failed to {}: {}", what, e))
        }
    }

    /// Find the zone for a domain, trying the domain itself and then each
    /// parent domain (`a.b.example.com`, `b.example.com`, `example.com`).
    async fn get_zone(&self, domain: &str) -> DnsResult<ZoneInfo> {
        let normalized = normalize_domain(domain)
            .trim_end_matches('.')
            .to_lowercase();

        if let Some(zone) = self.zone_cache.read().get(&normalized) {
            trace!(domain = %domain, zone_id = zone.id, "Zone found in cache");
            return Ok(zone.clone());
        }

        let mut candidate = normalized.as_str();
        loop {
            if let Some(zone) = self.query_zone(candidate).await? {
                if zone.mode.as_deref().is_some_and(|m| m != "primary") {
                    return Err(DnsProviderError::Configuration(format!(
                        "Hetzner zone '{}' is in '{}' mode; DNS-01 records can only be \
                         managed in zones in primary mode",
                        zone.name,
                        zone.mode.unwrap_or_default()
                    )));
                }
                let info = ZoneInfo {
                    id: zone.id,
                    name: zone.name,
                };
                debug!(
                    domain = %domain,
                    zone_id = info.id,
                    zone_name = %info.name,
                    "Found Hetzner zone for domain"
                );
                self.zone_cache
                    .write()
                    .insert(normalized.clone(), info.clone());
                return Ok(info);
            }

            match candidate.find('.') {
                Some(pos) => candidate = &candidate[pos + 1..],
                None => break,
            }
        }

        warn!(
            domain = %normalized,
            "No Hetzner zone found for domain; the zone must be in the Hetzner Cloud project \
             the API token belongs to"
        );
        Err(DnsProviderError::ZoneNotFound { domain: normalized })
    }

    /// Look up a zone by its exact name
    async fn query_zone(&self, name: &str) -> DnsResult<Option<Zone>> {
        let response = self
            .auth(self.client.get(format!("{}/zones", self.base_url)))
            .query(&[("name", name)])
            .send()
            .await
            .map_err(|e| self.map_send_error("list zones", e))?;

        let response = check_status(response, "list zones").await?;
        let zones: ZonesResponse = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse zones response: {}", e))
        })?;

        Ok(zones.zones.into_iter().find(|z| z.name == name))
    }

    /// Fetch an RRSet; `None` if it does not exist
    async fn get_rrset(&self, zone_id: u64, name: &str) -> DnsResult<Option<RRSet>> {
        let response = self
            .auth(self.client.get(format!(
                "{}/zones/{}/rrsets/{}/TXT",
                self.base_url, zone_id, name
            )))
            .send()
            .await
            .map_err(|e| self.map_send_error("get RRSet", e))?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let response = check_status(response, "get RRSet").await?;
        let rrset: RRSetResponse = response.json().await.map_err(|e| {
            DnsProviderError::ApiRequest(format!("Failed to parse RRSet response: {}", e))
        })?;
        Ok(Some(rrset.rrset))
    }

    /// Run an RRSet action (`add_records` / `remove_records`) and wait for
    /// it to finish. Retries while the RRSet is busy.
    ///
    /// Returns `Ok(None)` if the RRSet does not exist (404).
    async fn rrset_action<T: Serialize>(
        &self,
        zone_id: u64,
        name: &str,
        action: &str,
        body: &T,
    ) -> DnsResult<Option<()>> {
        let url = format!(
            "{}/zones/{}/rrsets/{}/TXT/actions/{}",
            self.base_url, zone_id, name, action
        );

        let mut attempt = 0;
        loop {
            attempt += 1;
            let response = self
                .auth(self.client.post(&url))
                .json(body)
                .send()
                .await
                .map_err(|e| self.map_send_error(action, e))?;

            let status = response.status();
            if status == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if matches!(status.as_u16(), 409 | 423) && attempt <= BUSY_RETRIES {
                debug!(
                    rrset = %name,
                    action = %action,
                    status = %status,
                    attempt,
                    "Hetzner RRSet busy, retrying"
                );
                tokio::time::sleep(self.poll_interval * attempt).await;
                continue;
            }

            let response = check_status(response, action).await?;
            let action_response: ActionResponse = response.json().await.map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to parse {} response: {}", action, e))
            })?;
            self.wait_for_action(action_response.action).await?;
            return Ok(Some(()));
        }
    }

    /// Wait until an Action reaches `success` or `error`
    async fn wait_for_action(&self, mut action: Action) -> DnsResult<()> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        loop {
            match action.status.as_str() {
                "success" => return Ok(()),
                "error" => {
                    let (code, message) = action
                        .error
                        .map(|e| (e.code, e.message))
                        .unwrap_or_else(|| ("unknown".into(), "no details".into()));
                    return Err(DnsProviderError::ApiRequest(format!(
                        "Hetzner action {} ({}) failed: {} - {}",
                        action.id, action.command, code, message
                    )));
                }
                _ => {}
            }

            if tokio::time::Instant::now() >= deadline {
                return Err(DnsProviderError::Timeout {
                    elapsed_secs: self.timeout.as_secs(),
                });
            }
            tokio::time::sleep(self.poll_interval).await;

            trace!(action_id = action.id, "Polling Hetzner action");
            let response = self
                .auth(
                    self.client
                        .get(format!("{}/zones/actions/{}", self.base_url, action.id)),
                )
                .send()
                .await
                .map_err(|e| self.map_send_error("get action", e))?;
            let response = check_status(response, "get action").await?;
            let polled: ActionResponse = response.json().await.map_err(|e| {
                DnsProviderError::ApiRequest(format!("Failed to parse action response: {}", e))
            })?;
            action = polled.action;
        }
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
        let zone = self.get_zone(domain).await?;
        let fqdn = format!(
            "{}.{}",
            record_name,
            normalize_domain(domain)
                .trim_end_matches('.')
                .to_lowercase()
        );
        let name = record_name_for_zone(&fqdn, &zone.name);
        let record_id = encode_record_id(zone.id, &name, record_value);

        debug!(
            domain = %domain,
            zone_id = zone.id,
            record_name = %name,
            "Creating TXT record"
        );

        // Ensure semantics: if our value is already there (leftover from an
        // earlier attempt), reuse it. The existing RRSet's TTL is kept, because
        // add_records rejects a TTL that differs from the RRSet's.
        let existing = self.get_rrset(zone.id, &name).await?;
        let ttl = match &existing {
            Some(rrset) if rrset.contains(record_value) => {
                info!(
                    domain = %domain,
                    record_name = %name,
                    "Reusing existing Hetzner TXT record for DNS-01"
                );
                return Ok(record_id);
            }
            Some(rrset) => rrset.ttl,
            None => Some(CHALLENGE_TTL),
        };

        let request = RecordsRequest {
            ttl,
            records: vec![RecordValue {
                value: quote_txt_value(record_value),
                comment: Some(RECORD_COMMENT.to_string()),
            }],
        };

        let result = self
            .rrset_action(zone.id, &name, "add_records", &request)
            .await;

        match result {
            Ok(Some(())) => {
                debug!(record_id = %record_id, "TXT record created successfully");
                Ok(record_id)
            }
            Ok(None) => Err(DnsProviderError::RecordCreation {
                record_name: name,
                message: format!("Hetzner zone {} not found", zone.id),
            }),
            Err(e) => {
                // A concurrent attempt may have added the same value meanwhile.
                if let Ok(Some(rrset)) = self.get_rrset(zone.id, &name).await {
                    if rrset.contains(record_value) {
                        warn!(
                            domain = %domain,
                            record_name = %name,
                            error = %e,
                            "add_records failed but the value is present; reusing it"
                        );
                        return Ok(record_id);
                    }
                }
                match e {
                    DnsProviderError::Authentication(_)
                    | DnsProviderError::RateLimited { .. }
                    | DnsProviderError::Timeout { .. } => Err(e),
                    other => Err(DnsProviderError::RecordCreation {
                        record_name: name,
                        message: other.to_string(),
                    }),
                }
            }
        }
    }

    async fn delete_txt_record(&self, _domain: &str, record_id: &str) -> DnsResult<()> {
        let (zone_id, name, value) =
            decode_record_id(record_id).ok_or_else(|| DnsProviderError::RecordDeletion {
                record_id: record_id.to_string(),
                message: "not a Hetzner Cloud record ID".to_string(),
            })?;

        debug!(record_id = %record_id, "Deleting TXT record");

        // remove_records identifies records by their exact stored value, so
        // send the value as Hetzner stores it, and only ours: other TXT values
        // on the same name (a concurrent challenge) stay.
        let stored = match self.get_rrset(zone_id, &name).await? {
            Some(rrset) => rrset
                .records
                .into_iter()
                .find(|r| txt_value_eq(&r.value, &value))
                .map(|r| r.value),
            None => None,
        };
        let Some(stored) = stored else {
            debug!(record_id = %record_id, "Record already deleted");
            return Ok(());
        };

        let request = RecordsRequest {
            ttl: None,
            records: vec![RecordValue {
                value: stored,
                comment: None,
            }],
        };

        match self
            .rrset_action(zone_id, &name, "remove_records", &request)
            .await
        {
            Ok(_) => {
                debug!(record_id = %record_id, "TXT record deleted successfully");
                Ok(())
            }
            Err(e @ DnsProviderError::Authentication(_)) => Err(e),
            Err(e) => Err(DnsProviderError::RecordDeletion {
                record_id: record_id.to_string(),
                message: e.to_string(),
            }),
        }
    }

    async fn supports_domain(&self, domain: &str) -> DnsResult<bool> {
        match self.get_zone(domain).await {
            Ok(_) => Ok(true),
            Err(DnsProviderError::ZoneNotFound { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Turn a non-success response into an error; pass a success through.
async fn check_status(response: Response, what: &str) -> DnsResult<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let retry_after = response
        .headers()
        .get("RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .map(|reset| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            reset.saturating_sub(now).max(1)
        });

    let body = response.text().await.unwrap_or_default();
    let (code, detail) = match serde_json::from_str::<ErrorResponse>(&body) {
        Ok(err) => {
            let detail = format!("{} - {}", err.error.code, err.error.message);
            (Some(err.error.code), detail)
        }
        Err(_) => (None, body),
    };

    match status {
        StatusCode::UNAUTHORIZED => Err(DnsProviderError::Authentication(format!(
            "Hetzner Cloud API rejected the token ({}): {}",
            detail, TOKEN_HINT
        ))),
        // 403 also covers `maintenance` and `resource_limit_exceeded`
        StatusCode::FORBIDDEN if code.as_deref().is_none_or(|c| c == "forbidden") => {
            Err(DnsProviderError::Authentication(format!(
                "Hetzner Cloud API refused to {} ({}); the token needs Read & Write \
             permission",
                what, detail
            )))
        }
        StatusCode::TOO_MANY_REQUESTS => Err(DnsProviderError::RateLimited {
            retry_after_secs: retry_after.unwrap_or(60),
        }),
        _ => Err(DnsProviderError::ApiRequest(format!(
            "Failed to {}: HTTP {} - {}",
            what, status, detail
        ))),
    }
}

/// Record name relative to the zone (`@` for the apex)
fn record_name_for_zone(fqdn: &str, zone_name: &str) -> String {
    if fqdn == zone_name {
        "@".to_string()
    } else if let Some(stripped) = fqdn.strip_suffix(&format!(".{}", zone_name)) {
        stripped.to_string()
    } else {
        fqdn.to_string()
    }
}

/// Hetzner requires TXT values in quotes (`"value"`), each quoted string at
/// most 255 characters. ACME challenge values are 43 characters of
/// base64url, but split longer values anyway so the function is total.
fn quote_txt_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    chars
        .chunks(255)
        .map(|chunk| {
            let s: String = chunk.iter().collect();
            format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode a stored TXT value (`"a" "b"` or unquoted `ab`) to its text
fn unquote_txt_value(stored: &str) -> String {
    let trimmed = stored.trim();
    if !trimmed.starts_with('"') {
        return trimmed.to_string();
    }

    let mut out = String::new();
    let mut in_quotes = false;
    let mut chars = trimmed.chars();
    while let Some(c) = chars.next() {
        match (c, in_quotes) {
            ('"', _) => in_quotes = !in_quotes,
            ('\\', true) => {
                if let Some(next) = chars.next() {
                    out.push(next);
                }
            }
            (c, true) => out.push(c),
            (_, false) => {} // whitespace between quoted strings
        }
    }
    out
}

/// Whether a stored TXT value holds the given text
fn txt_value_eq(stored: &str, value: &str) -> bool {
    unquote_txt_value(stored) == value
}

/// Record IDs carry what cleanup needs: `<zone id>/<rrset name>/<value>`.
/// RRSet names never contain `/`, so the value is everything after the
/// second slash.
fn encode_record_id(zone_id: u64, name: &str, value: &str) -> String {
    format!("{}/{}/{}", zone_id, name, value)
}

fn decode_record_id(record_id: &str) -> Option<(u64, String, String)> {
    let mut parts = record_id.splitn(3, '/');
    let zone_id = parts.next()?.parse().ok()?;
    let name = parts.next()?;
    let value = parts.next()?;
    if name.is_empty() || value.is_empty() {
        return None;
    }
    Some((zone_id, name.to_string(), value.to_string()))
}

// Hetzner Cloud API types

#[derive(Debug, Deserialize)]
struct ZonesResponse {
    zones: Vec<Zone>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: u64,
    name: String,
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RRSetResponse {
    rrset: RRSet,
}

#[derive(Debug, Deserialize)]
struct RRSet {
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    records: Vec<StoredRecord>,
}

impl RRSet {
    fn contains(&self, value: &str) -> bool {
        self.records.iter().any(|r| txt_value_eq(&r.value, value))
    }
}

#[derive(Debug, Deserialize)]
struct StoredRecord {
    value: String,
}

#[derive(Debug, Serialize)]
struct RecordsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    records: Vec<RecordValue>,
}

#[derive(Debug, Serialize)]
struct RecordValue {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActionResponse {
    action: Action,
}

#[derive(Debug, Deserialize)]
struct Action {
    id: u64,
    #[serde(default)]
    command: String,
    status: String,
    #[serde(default)]
    error: Option<ActionError>,
}

#[derive(Debug, Deserialize)]
struct ActionError {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: ApiError,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_name_for_zone() {
        assert_eq!(record_name_for_zone("example.com", "example.com"), "@");
        assert_eq!(
            record_name_for_zone("_acme-challenge.example.com", "example.com"),
            "_acme-challenge"
        );
        assert_eq!(
            record_name_for_zone("_acme-challenge.sub.example.com", "example.com"),
            "_acme-challenge.sub"
        );
    }

    #[test]
    fn test_quote_txt_value() {
        assert_eq!(quote_txt_value("abc-DEF_123"), "\"abc-DEF_123\"");
        assert_eq!(quote_txt_value("a\"b\\c"), "\"a\\\"b\\\\c\"");

        let long = "x".repeat(300);
        let quoted = quote_txt_value(&long);
        assert_eq!(
            quoted,
            format!("\"{}\" \"{}\"", "x".repeat(255), "x".repeat(45))
        );
        assert_eq!(unquote_txt_value(&quoted), long);
    }

    #[test]
    fn test_unquote_txt_value() {
        assert_eq!(unquote_txt_value("\"abc\""), "abc");
        assert_eq!(unquote_txt_value("abc"), "abc");
        assert_eq!(unquote_txt_value("\"hello \" \"world\""), "hello world");
        assert_eq!(unquote_txt_value("\"a\\\"b\""), "a\"b");
        assert!(txt_value_eq("\"abc\"", "abc"));
        assert!(!txt_value_eq("\"abcd\"", "abc"));
    }

    #[test]
    fn test_record_id_roundtrip() {
        let id = encode_record_id(42, "_acme-challenge.sub", "val-ue_1");
        assert_eq!(id, "42/_acme-challenge.sub/val-ue_1");
        assert_eq!(
            decode_record_id(&id),
            Some((42, "_acme-challenge.sub".into(), "val-ue_1".into()))
        );
        // Old dns.hetzner.com record IDs are not accepted
        assert_eq!(decode_record_id("abc123"), None);
        assert_eq!(decode_record_id("1//v"), None);
    }

    #[test]
    fn test_token_is_trimmed() {
        let provider = HetznerProvider::new("  token\n", Duration::from_secs(30)).unwrap();
        assert_eq!(provider.token, "token");
    }
}
