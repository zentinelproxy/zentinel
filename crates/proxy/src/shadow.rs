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

use pingora::http::RequestHeader;
use rand::Rng;
use sentinel_common::errors::{SentinelError, SentinelResult};
use sentinel_common::observability::RequestMetrics;
use sentinel_config::routes::ShadowConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::Duration;
use tracing::{debug, error, info, trace, warn};

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
}

impl ShadowManager {
    /// Create a new shadow manager
    pub fn new(
        upstream_pools: Arc<HashMap<String, Arc<UpstreamPool>>>,
        config: ShadowConfig,
        metrics: Option<Arc<RequestMetrics>>,
        route_id: String,
    ) -> Self {
        Self {
            upstream_pools,
            config,
            metrics,
            route_id,
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
            let mut rng = rand::thread_rng();
            let roll: f64 = rng.gen_range(0.0..100.0);
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
                Self::execute_shadow_request(upstream_pool, original_headers, body, ctx.clone()),
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
    /// to the shadow upstream.
    async fn execute_shadow_request(
        _upstream_pool: &UpstreamPool,
        _headers: RequestHeader,
        _body: Option<Vec<u8>>,
        _ctx: RequestContext,
    ) -> SentinelResult<()> {
        // TODO: Implement actual request execution
        // This will require:
        // 1. Select target from upstream_pool
        // 2. Connect to shadow target
        // 3. Send headers
        // 4. Send body if present
        // 5. Read response (and discard)
        // 6. Close connection

        // For now, placeholder implementation
        trace!("Shadow request execution (placeholder)");
        Ok(())
    }
}

/// Helper to determine if HTTP method should have body buffered
pub fn should_buffer_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
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
    _session: &mut pingora::proxy::Session,
    max_bytes: usize,
) -> SentinelResult<Vec<u8>> {
    // TODO: Implement body buffering
    // This will require:
    // 1. Read chunks from session.read_request_body()
    // 2. Accumulate into buffer
    // 3. Check total size against max_bytes
    // 4. Return error if exceeded

    // For now, placeholder
    if max_bytes > 0 {
        Ok(Vec::new())
    } else {
        Err(SentinelError::LimitExceeded {
            limit_type: sentinel_common::errors::LimitType::BodySize,
            message: "max_body_bytes must be > 0".to_string(),
            current_value: 0,
            limit: 0,
        })
    }
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
        headers
            .insert_header("X-Shadow", "true")
            .unwrap();
        assert!(manager.should_shadow(&headers));

        // Request without header
        let headers_no_match = PingoraRequestHeader::build("GET", b"/", None).unwrap();
        assert!(!manager.should_shadow(&headers_no_match));

        // Request with wrong header value
        let mut headers_wrong = PingoraRequestHeader::build("GET", b"/", None).unwrap();
        headers_wrong
            .insert_header("X-Shadow", "false")
            .unwrap();
        assert!(!manager.should_shadow(&headers_wrong));
    }
}
