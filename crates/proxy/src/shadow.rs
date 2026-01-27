//! Traffic mirroring / shadowing for safe canary testing
//!
//! This module implements fire-and-forget request duplication to shadow upstreams,
//! enabling safe canary deployments and testing with production traffic.
//!
//! # Features
//!
//! - Sampling-based mirroring (percentage control)
//! - Header-based sampling (selective mirroring)
//! - Optional request body buffering
//! - Fire-and-forget async execution (no blocking)
//! - Comprehensive metrics

use bytes::Bytes;
use pingora::http::RequestHeader;
use pingora::proxy::Session;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use sentinel_common::errors::{SentinelError, SentinelResult};
use sentinel_common::observability::RequestMetrics;
use sentinel_config::routes::ShadowConfig;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{debug, error, trace, warn};

use crate::{RequestContext, UpstreamPool};

/// Manager for traffic shadowing/mirroring
///
/// Handles request duplication to shadow upstreams with sampling control,
/// optional body buffering, and fire-and-forget execution.
#[derive(Clone)]
pub struct ShadowManager {
    /// Reference to upstream pools for shadow target selection
    upstream_pools: Arc<HashMap<String, Arc<UpstreamPool>>>,

    /// Shadow configuration
    config: ShadowConfig,

    /// Metrics collector for recording shadow metrics
    metrics: Option<Arc<RequestMetrics>>,

    /// Route ID for metrics labeling
    route_id: String,

    /// Shared HTTP client for shadow requests
    client: reqwest::Client,
}

impl ShadowManager {
    /// Create a new shadow manager
    pub fn new(
        upstream_pools: Arc<HashMap<String, Arc<UpstreamPool>>>,
        config: ShadowConfig,
        metrics: Option<Arc<RequestMetrics>>,
        route_id: String,
    ) -> Self {
        // Build a reusable HTTP client with reasonable defaults for shadow traffic
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            // Accept invalid certs for shadow targets (they're often internal)
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            upstream_pools,
            config,
            metrics,
            route_id,
            client,
        }
    }

    /// Decide whether to shadow this request based on sampling rules
    pub fn should_shadow(&self, headers: &RequestHeader) -> bool {
        // Check sample_header if configured
        if let Some((header_name, header_value)) = &self.config.sample_header {
            if let Some(actual_value) = headers.headers.get(header_name) {
                if actual_value.to_str().ok() != Some(header_value.as_str()) {
                    trace!("Shadow skipped: sample-header mismatch");
                    return false;
                }
            } else {
                trace!("Shadow skipped: sample-header not present");
                return false;
            }
        }

        // Sample based on percentage
        if self.config.percentage < 100.0 {
            let mut rng = rand::rng();
            let roll: f64 = rng.random_range(0.0..100.0);
            if roll > self.config.percentage {
                trace!(
                    roll = roll,
                    threshold = self.config.percentage,
                    "Shadow skipped: sampling"
                );
                return false;
            }
        }

        true
    }

    /// Shadow a request asynchronously (fire-and-forget)
    ///
    /// This method spawns a tokio task to mirror the request to the shadow upstream.
    /// The task does not block the main request path and failures do not affect
    /// the primary response.
    ///
    /// # Arguments
    ///
    /// * `original_headers` - Original request headers to clone
    /// * `body` - Optional buffered request body (if buffer_body=true)
    /// * `ctx` - Request context for correlation
    pub fn shadow_request(
        &self,
        original_headers: RequestHeader,
        body: Option<Vec<u8>>,
        ctx: RequestContext,
    ) {
        // Check if upstream exists
        if !self.upstream_pools.contains_key(&self.config.upstream) {
            warn!(
                upstream = %self.config.upstream,
                "Shadow upstream not found in pools"
            );
            // Record error metric
            if let Some(ref metrics) = self.metrics {
                metrics.record_shadow_error(&self.route_id, &self.config.upstream, "upstream_not_found");
            }
            return;
        }

        let config = self.config.clone();
        let upstream_id = self.config.upstream.clone();
        let upstream_pools = Arc::clone(&self.upstream_pools);
        let metrics = self.metrics.clone();
        let route_id = self.route_id.clone();
        let client = self.client.clone();

        // Spawn fire-and-forget task
        tokio::spawn(async move {
            let start = Instant::now();

            // Get upstream pool inside the async task
            let upstream_pool = match upstream_pools.get(&upstream_id) {
                Some(pool) => pool,
                None => {
                    // This shouldn't happen since we checked above, but handle gracefully
                    warn!(upstream = %upstream_id, "Shadow upstream disappeared");
                    return;
                }
            };

            // Execute shadow request with timeout
            let result = tokio::time::timeout(
                Duration::from_millis(config.timeout_ms),
                Self::execute_shadow_request(
                    &client,
                    upstream_pool,
                    original_headers,
                    body,
                    ctx.clone(),
                ),
            )
            .await;

            let latency = start.elapsed();

            match result {
                Ok(Ok(())) => {
                    debug!(
                        upstream = %upstream_id,
                        latency_ms = latency.as_millis(),
                        path = %ctx.path,
                        method = %ctx.method,
                        "Shadow request completed successfully"
                    );
                    // Record success metrics
                    if let Some(ref metrics) = metrics {
                        metrics.record_shadow_success(&route_id, &upstream_id, latency);
                    }
                }
                Ok(Err(e)) => {
                    error!(
                        upstream = %upstream_id,
                        error = %e,
                        latency_ms = latency.as_millis(),
                        path = %ctx.path,
                        method = %ctx.method,
                        "Shadow request failed"
                    );
                    // Record error metrics
                    if let Some(ref metrics) = metrics {
                        metrics.record_shadow_error(&route_id, &upstream_id, "request_failed");
                    }
                }
                Err(_) => {
                    warn!(
                        upstream = %upstream_id,
                        timeout_ms = config.timeout_ms,
                        path = %ctx.path,
                        method = %ctx.method,
                        "Shadow request timed out"
                    );
                    // Record timeout metrics
                    if let Some(ref metrics) = metrics {
                        metrics.record_shadow_timeout(&route_id, &upstream_id, latency);
                    }
                }
            }
        });
    }

    /// Execute the actual shadow request
    ///
    /// This is the internal implementation that sends the mirrored request
    /// to the shadow upstream using reqwest.
    async fn execute_shadow_request(
        client: &reqwest::Client,
        upstream_pool: &UpstreamPool,
        headers: RequestHeader,
        body: Option<Vec<u8>>,
        ctx: RequestContext,
    ) -> SentinelResult<()> {
        // Select shadow target from upstream pool
        let target = upstream_pool.select_shadow_target(Some(&ctx)).await?;

        // Build the full URL
        let url = target.build_url(&ctx.path);

        trace!(
            url = %url,
            method = %ctx.method,
            body_size = body.as_ref().map(|b| b.len()).unwrap_or(0),
            "Executing shadow request"
        );

        // Convert Pingora headers to reqwest headers
        let mut reqwest_headers = HeaderMap::new();
        for (name, value) in headers.headers.iter() {
            // Skip hop-by-hop headers that shouldn't be forwarded
            let name_str = name.as_str().to_lowercase();
            if matches!(
                name_str.as_str(),
                "connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
                    | "transfer-encoding"
                    | "upgrade"
            ) {
                continue;
            }

            if let (Ok(header_name), Ok(header_value)) = (
                HeaderName::from_str(name.as_str()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                reqwest_headers.insert(header_name, header_value);
            }
        }

        // Add shadow-specific header to identify mirrored traffic
        reqwest_headers.insert("x-shadow-request", HeaderValue::from_static("true"));

        // Update Host header to match shadow target
        if let Ok(host_value) = HeaderValue::from_str(&target.host) {
            reqwest_headers.insert("host", host_value);
        }

        // Build the request based on method
        let method = reqwest::Method::from_bytes(ctx.method.as_bytes())
            .unwrap_or(reqwest::Method::GET);

        let mut request_builder = client.request(method, &url).headers(reqwest_headers);

        // Add body if present
        if let Some(body_bytes) = body {
            request_builder = request_builder.body(body_bytes);
        }

        // Send the request and discard response
        let response = request_builder.send().await.map_err(|e| {
            SentinelError::upstream(
                upstream_pool.id().to_string(),
                format!("Shadow request failed: {}", e),
            )
        })?;

        let status = response.status();
        trace!(
            url = %url,
            status = %status,
            "Shadow request completed"
        );

        // We don't care about the response body, just that it was sent
        // Drop the response to release the connection back to the pool
        drop(response);

        Ok(())
    }
}

/// Helper to determine if HTTP method should have body buffered
pub fn should_buffer_method(method: &str) -> bool {
    matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
}

/// Buffer request body from session with size limits
///
/// Reads the request body from a Pingora session and buffers it up to
/// the configured maximum size. Returns an error if the body exceeds
/// the limit.
///
/// # Arguments
///
/// * `session` - Pingora session to read body from
/// * `max_bytes` - Maximum bytes to buffer
pub async fn buffer_request_body(
    session: &mut Session,
    max_bytes: usize,
) -> SentinelResult<Vec<u8>> {
    if max_bytes == 0 {
        return Err(SentinelError::LimitExceeded {
            limit_type: sentinel_common::errors::LimitType::BodySize,
            message: "max_body_bytes must be > 0".to_string(),
            current_value: 0,
            limit: 0,
        });
    }

    let mut buffer = Vec::with_capacity(max_bytes.min(65536)); // Start with reasonable capacity
    let mut total_read = 0;

    loop {
        // Read next chunk from the session
        let chunk = session.read_request_body().await.map_err(|e| {
            SentinelError::Internal {
                message: format!("Failed to read request body for shadow: {}", e),
                correlation_id: None,
                source: None,
            }
        })?;

        match chunk {
            Some(data) => {
                let chunk_len: usize = data.len();

                // Check if this chunk would exceed the limit
                if total_read + chunk_len > max_bytes {
                    return Err(SentinelError::LimitExceeded {
                        limit_type: sentinel_common::errors::LimitType::BodySize,
                        message: format!(
                            "Request body exceeds maximum shadow buffer size of {} bytes",
                            max_bytes
                        ),
                        current_value: total_read + chunk_len,
                        limit: max_bytes,
                    });
                }

                buffer.extend_from_slice(&data);
                total_read += chunk_len;

                trace!(
                    chunk_size = chunk_len,
                    total_buffered = total_read,
                    max_bytes = max_bytes,
                    "Buffered request body chunk for shadow"
                );
            }
            None => {
                // End of body
                break;
            }
        }
    }

    debug!(
        total_bytes = total_read,
        "Finished buffering request body for shadow"
    );

    Ok(buffer)
}

/// Clone request body bytes for shadow traffic
///
/// This is a simpler version that takes already-buffered body bytes
/// (from request_body_filter) and returns a clone for shadow use.
pub fn clone_body_for_shadow(body: &Option<Bytes>) -> Option<Vec<u8>> {
    body.as_ref().map(|b| b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora::http::RequestHeader as PingoraRequestHeader;

    #[test]
    fn test_should_buffer_method() {
        assert!(should_buffer_method("POST"));
        assert!(should_buffer_method("PUT"));
        assert!(should_buffer_method("PATCH"));
        assert!(should_buffer_method("post")); // Case insensitive
        assert!(!should_buffer_method("GET"));
        assert!(!should_buffer_method("HEAD"));
        assert!(!should_buffer_method("DELETE"));
    }

    #[test]
    fn test_shadow_sampling_percentage() {
        let pools = Arc::new(HashMap::new());
        let config = ShadowConfig {
            upstream: "shadow".to_string(),
            percentage: 0.0, // 0% should never shadow
            sample_header: None,
            timeout_ms: 5000,
            buffer_body: false,
            max_body_bytes: 1048576,
        };

        let manager = ShadowManager::new(pools, config, None, "test-route".to_string());
        let headers = PingoraRequestHeader::build("GET", b"/", None).unwrap();

        // With 0% sampling, should never shadow
        for _ in 0..100 {
            assert!(!manager.should_shadow(&headers));
        }
    }

    #[test]
    fn test_shadow_sampling_always() {
        let pools = Arc::new(HashMap::new());
        let config = ShadowConfig {
            upstream: "shadow".to_string(),
            percentage: 100.0, // 100% should always shadow
            sample_header: None,
            timeout_ms: 5000,
            buffer_body: false,
            max_body_bytes: 1048576,
        };

        let manager = ShadowManager::new(pools, config, None, "test-route".to_string());
        let headers = PingoraRequestHeader::build("GET", b"/", None).unwrap();

        // With 100% sampling, should always shadow
        for _ in 0..100 {
            assert!(manager.should_shadow(&headers));
        }
    }

    #[test]
    fn test_shadow_sample_header_match() {
        let pools = Arc::new(HashMap::new());
        let config = ShadowConfig {
            upstream: "shadow".to_string(),
            percentage: 100.0,
            sample_header: Some(("X-Shadow".to_string(), "true".to_string())),
            timeout_ms: 5000,
            buffer_body: false,
            max_body_bytes: 1048576,
        };

        let manager = ShadowManager::new(pools, config, None, "test-route".to_string());

        // Request with matching header
        let mut headers = PingoraRequestHeader::build("GET", b"/", None).unwrap();
        headers.insert_header("X-Shadow", "true").unwrap();
        assert!(manager.should_shadow(&headers));

        // Request without header
        let headers_no_match = PingoraRequestHeader::build("GET", b"/", None).unwrap();
        assert!(!manager.should_shadow(&headers_no_match));

        // Request with wrong header value
        let mut headers_wrong = PingoraRequestHeader::build("GET", b"/", None).unwrap();
        headers_wrong.insert_header("X-Shadow", "false").unwrap();
        assert!(!manager.should_shadow(&headers_wrong));
    }

    #[test]
    fn test_clone_body_for_shadow() {
        // Test with Some body
        let body = Some(Bytes::from("test body content"));
        let cloned = clone_body_for_shadow(&body);
        assert!(cloned.is_some());
        assert_eq!(cloned.unwrap(), b"test body content");

        // Test with None body
        let no_body: Option<Bytes> = None;
        let cloned_none = clone_body_for_shadow(&no_body);
        assert!(cloned_none.is_none());
    }
}
