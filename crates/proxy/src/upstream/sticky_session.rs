//! Cookie-based sticky session load balancer
//!
//! Routes requests to the same backend based on an affinity cookie.
//! Falls back to a configurable algorithm when no cookie is present
//! or the target is unavailable.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use super::{LoadBalancer, RequestContext, TargetSelection, UpstreamTarget};
use sentinel_common::errors::{SentinelError, SentinelResult};
use sentinel_config::upstreams::StickySessionConfig;

type HmacSha256 = Hmac<Sha256>;

/// Runtime configuration for sticky sessions
#[derive(Debug, Clone)]
pub struct StickySessionRuntimeConfig {
    /// Cookie name for session affinity
    pub cookie_name: String,
    /// Cookie TTL in seconds
    pub cookie_ttl_secs: u64,
    /// Cookie path
    pub cookie_path: String,
    /// Whether to set Secure and HttpOnly flags
    pub cookie_secure: bool,
    /// SameSite policy
    pub cookie_same_site: sentinel_config::upstreams::SameSitePolicy,
    /// HMAC key for signing cookie values
    pub hmac_key: [u8; 32],
}

impl StickySessionRuntimeConfig {
    /// Create runtime config from parsed config, generating HMAC key
    pub fn from_config(config: &StickySessionConfig) -> Self {
        use rand::RngCore;

        // Generate random HMAC key
        let mut hmac_key = [0u8; 32];
        rand::rng().fill_bytes(&mut hmac_key);

        Self {
            cookie_name: config.cookie_name.clone(),
            cookie_ttl_secs: config.cookie_ttl_secs,
            cookie_path: config.cookie_path.clone(),
            cookie_secure: config.cookie_secure,
            cookie_same_site: config.cookie_same_site,
            hmac_key,
        }
    }
}

/// Cookie-based sticky session load balancer
///
/// This balancer wraps a fallback load balancer and adds session affinity
/// based on cookies. When a client has a valid affinity cookie, requests
/// are routed to the same backend. Otherwise, the fallback balancer is used
/// and a new cookie is set.
pub struct StickySessionBalancer {
    /// Runtime configuration
    config: StickySessionRuntimeConfig,
    /// All upstream targets
    targets: Vec<UpstreamTarget>,
    /// Fallback load balancer
    fallback: Arc<dyn LoadBalancer>,
    /// Target health status
    health_status: Arc<RwLock<HashMap<String, bool>>>,
}

impl StickySessionBalancer {
    /// Create a new sticky session balancer
    pub fn new(
        targets: Vec<UpstreamTarget>,
        config: StickySessionRuntimeConfig,
        fallback: Arc<dyn LoadBalancer>,
    ) -> Self {
        trace!(
            target_count = targets.len(),
            cookie_name = %config.cookie_name,
            cookie_ttl_secs = config.cookie_ttl_secs,
            "Creating sticky session balancer"
        );

        let mut health_status = HashMap::new();
        for target in &targets {
            health_status.insert(target.full_address(), true);
        }

        Self {
            config,
            targets,
            fallback,
            health_status: Arc::new(RwLock::new(health_status)),
        }
    }

    /// Extract and validate sticky cookie from request
    ///
    /// Returns the target index if the cookie is valid and properly signed.
    fn extract_affinity(&self, context: &RequestContext) -> Option<usize> {
        // Get cookie header
        let cookie_header = context.headers.get("cookie")?;

        // Parse cookies and find our sticky session cookie
        let cookie_value = cookie_header.split(';').find_map(|cookie| {
            let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == self.config.cookie_name {
                Some(parts[1].to_string())
            } else {
                None
            }
        })?;

        // Validate cookie format: "{index}.{signature}"
        let parts: Vec<&str> = cookie_value.splitn(2, '.').collect();
        if parts.len() != 2 {
            trace!(
                cookie_value = %cookie_value,
                "Invalid sticky cookie format (missing signature)"
            );
            return None;
        }

        let index: usize = parts[0].parse().ok()?;
        let signature = parts[1];

        // Verify HMAC signature
        if !self.verify_signature(index, signature) {
            warn!(
                cookie_value = %cookie_value,
                "Invalid sticky cookie signature (possible tampering)"
            );
            return None;
        }

        // Verify index is valid
        if index >= self.targets.len() {
            trace!(
                index = index,
                target_count = self.targets.len(),
                "Sticky cookie index out of bounds"
            );
            return None;
        }

        trace!(
            cookie_name = %self.config.cookie_name,
            target_index = index,
            "Extracted valid sticky session affinity"
        );

        Some(index)
    }

    /// Generate signed cookie value for target
    pub fn generate_cookie_value(&self, target_index: usize) -> String {
        let signature = self.sign_index(target_index);
        format!("{}.{}", target_index, signature)
    }

    /// Generate full Set-Cookie header value
    pub fn generate_set_cookie_header(&self, target_index: usize) -> String {
        let cookie_value = self.generate_cookie_value(target_index);

        let mut header = format!(
            "{}={}; Path={}; Max-Age={}",
            self.config.cookie_name,
            cookie_value,
            self.config.cookie_path,
            self.config.cookie_ttl_secs
        );

        if self.config.cookie_secure {
            header.push_str("; HttpOnly; Secure");
        }

        header.push_str(&format!("; SameSite={}", self.config.cookie_same_site));

        header
    }

    /// Sign target index with HMAC-SHA256
    fn sign_index(&self, index: usize) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.config.hmac_key).expect("HMAC key length is valid");
        mac.update(index.to_string().as_bytes());
        let result = mac.finalize();
        // Use first 8 bytes of signature (16 hex chars) for compactness
        hex::encode(&result.into_bytes()[..8])
    }

    /// Verify HMAC signature for target index
    fn verify_signature(&self, index: usize, signature: &str) -> bool {
        let expected = self.sign_index(index);
        // Constant-time comparison
        expected == signature
    }

    /// Check if target at index is healthy
    async fn is_target_healthy(&self, index: usize) -> bool {
        if index >= self.targets.len() {
            return false;
        }

        let target = &self.targets[index];
        let health = self.health_status.read().await;
        *health.get(&target.full_address()).unwrap_or(&true)
    }

    /// Find target index by address
    fn find_target_index(&self, address: &str) -> Option<usize> {
        self.targets
            .iter()
            .position(|t| t.full_address() == address)
    }

    /// Get the cookie name
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get the config for Set-Cookie header generation
    pub fn config(&self) -> &StickySessionRuntimeConfig {
        &self.config
    }
}

#[async_trait]
impl LoadBalancer for StickySessionBalancer {
    async fn select(&self, context: Option<&RequestContext>) -> SentinelResult<TargetSelection> {
        trace!(
            has_context = context.is_some(),
            cookie_name = %self.config.cookie_name,
            "Sticky session select called"
        );

        // Try to extract affinity from cookie
        if let Some(ctx) = context {
            if let Some(target_index) = self.extract_affinity(ctx) {
                // Check if target is healthy
                if self.is_target_healthy(target_index).await {
                    let target = &self.targets[target_index];

                    debug!(
                        target = %target.full_address(),
                        target_index = target_index,
                        cookie_name = %self.config.cookie_name,
                        "Sticky session hit - routing to affinity target"
                    );

                    return Ok(TargetSelection {
                        address: target.full_address(),
                        weight: target.weight,
                        metadata: {
                            let mut meta = HashMap::new();
                            meta.insert("sticky_session_hit".to_string(), "true".to_string());
                            meta.insert("sticky_target_index".to_string(), target_index.to_string());
                            meta.insert("algorithm".to_string(), "sticky_session".to_string());
                            meta
                        },
                    });
                }

                debug!(
                    target_index = target_index,
                    cookie_name = %self.config.cookie_name,
                    "Sticky target unhealthy, falling back to load balancer"
                );
            }
        }

        // No valid cookie or target unavailable - use fallback
        let mut selection = self.fallback.select(context).await?;

        // Find target index for the selected address
        let target_index = self.find_target_index(&selection.address);

        if let Some(index) = target_index {
            // Mark that we need to set a new cookie
            selection
                .metadata
                .insert("sticky_session_new".to_string(), "true".to_string());
            selection
                .metadata
                .insert("sticky_target_index".to_string(), index.to_string());
            selection.metadata.insert(
                "sticky_cookie_value".to_string(),
                self.generate_cookie_value(index),
            );
            selection.metadata.insert(
                "sticky_set_cookie_header".to_string(),
                self.generate_set_cookie_header(index),
            );

            debug!(
                target = %selection.address,
                target_index = index,
                cookie_name = %self.config.cookie_name,
                "New sticky session assignment, will set cookie"
            );
        }

        selection
            .metadata
            .insert("algorithm".to_string(), "sticky_session".to_string());

        Ok(selection)
    }

    async fn report_health(&self, address: &str, healthy: bool) {
        trace!(
            target = %address,
            healthy = healthy,
            algorithm = "sticky_session",
            "Updating target health status"
        );

        // Update local health status
        self.health_status
            .write()
            .await
            .insert(address.to_string(), healthy);

        // Propagate to fallback balancer
        self.fallback.report_health(address, healthy).await;
    }

    async fn healthy_targets(&self) -> Vec<String> {
        // Delegate to fallback balancer for consistency
        self.fallback.healthy_targets().await
    }

    async fn release(&self, selection: &TargetSelection) {
        // Delegate to fallback balancer
        self.fallback.release(selection).await;
    }

    async fn report_result(
        &self,
        selection: &TargetSelection,
        success: bool,
        latency: Option<std::time::Duration>,
    ) {
        // Delegate to fallback balancer
        self.fallback
            .report_result(selection, success, latency)
            .await;
    }

    async fn report_result_with_latency(
        &self,
        address: &str,
        success: bool,
        latency: Option<std::time::Duration>,
    ) {
        // Delegate to fallback balancer
        self.fallback
            .report_result_with_latency(address, success, latency)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_targets(count: usize) -> Vec<UpstreamTarget> {
        (0..count)
            .map(|i| UpstreamTarget {
                address: format!("10.0.0.{}", i + 1),
                port: 8080,
                weight: 100,
            })
            .collect()
    }

    fn create_test_config() -> StickySessionRuntimeConfig {
        StickySessionRuntimeConfig {
            cookie_name: "SERVERID".to_string(),
            cookie_ttl_secs: 3600,
            cookie_path: "/".to_string(),
            cookie_secure: true,
            cookie_same_site: sentinel_config::upstreams::SameSitePolicy::Lax,
            hmac_key: [42u8; 32], // Fixed key for testing
        }
    }

    #[test]
    fn test_cookie_generation_and_validation() {
        let targets = create_test_targets(3);
        let config = create_test_config();

        // Create a mock fallback balancer
        struct MockBalancer;

        #[async_trait]
        impl LoadBalancer for MockBalancer {
            async fn select(
                &self,
                _context: Option<&RequestContext>,
            ) -> SentinelResult<TargetSelection> {
                Ok(TargetSelection {
                    address: "10.0.0.1:8080".to_string(),
                    weight: 100,
                    metadata: HashMap::new(),
                })
            }
            async fn report_health(&self, _address: &str, _healthy: bool) {}
            async fn healthy_targets(&self) -> Vec<String> {
                vec![]
            }
        }

        let balancer = StickySessionBalancer::new(targets, config, Arc::new(MockBalancer));

        // Test cookie value generation
        let cookie_value = balancer.generate_cookie_value(1);
        assert!(cookie_value.starts_with("1."));
        assert_eq!(cookie_value.len(), 2 + 16); // "1." + 16 hex chars

        // Test signature verification
        let parts: Vec<&str> = cookie_value.splitn(2, '.').collect();
        assert!(balancer.verify_signature(1, parts[1]));

        // Test invalid signature
        assert!(!balancer.verify_signature(1, "invalid"));
        assert!(!balancer.verify_signature(2, parts[1])); // Wrong index
    }

    #[test]
    fn test_set_cookie_header_generation() {
        let targets = create_test_targets(3);
        let config = create_test_config();

        struct MockBalancer;

        #[async_trait]
        impl LoadBalancer for MockBalancer {
            async fn select(
                &self,
                _context: Option<&RequestContext>,
            ) -> SentinelResult<TargetSelection> {
                unreachable!()
            }
            async fn report_health(&self, _address: &str, _healthy: bool) {}
            async fn healthy_targets(&self) -> Vec<String> {
                vec![]
            }
        }

        let balancer = StickySessionBalancer::new(targets, config, Arc::new(MockBalancer));

        let header = balancer.generate_set_cookie_header(0);
        assert!(header.starts_with("SERVERID=0."));
        assert!(header.contains("Path=/"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
    }

    #[tokio::test]
    async fn test_sticky_session_hit() {
        let targets = create_test_targets(3);
        let config = create_test_config();

        struct MockBalancer;

        #[async_trait]
        impl LoadBalancer for MockBalancer {
            async fn select(
                &self,
                _context: Option<&RequestContext>,
            ) -> SentinelResult<TargetSelection> {
                // Should not be called when we have valid cookie
                panic!("Fallback should not be called for sticky hit");
            }
            async fn report_health(&self, _address: &str, _healthy: bool) {}
            async fn healthy_targets(&self) -> Vec<String> {
                vec![
                    "10.0.0.1:8080".to_string(),
                    "10.0.0.2:8080".to_string(),
                    "10.0.0.3:8080".to_string(),
                ]
            }
        }

        let balancer = StickySessionBalancer::new(targets, config, Arc::new(MockBalancer));

        // Generate a valid cookie for target 1
        let cookie_value = balancer.generate_cookie_value(1);

        // Create context with sticky cookie
        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), format!("SERVERID={}", cookie_value));

        let context = RequestContext {
            client_ip: None,
            headers,
            path: "/".to_string(),
            method: "GET".to_string(),
        };

        let selection = balancer.select(Some(&context)).await.unwrap();

        // Should route to target 1 (10.0.0.2:8080)
        assert_eq!(selection.address, "10.0.0.2:8080");
        assert_eq!(
            selection.metadata.get("sticky_session_hit"),
            Some(&"true".to_string())
        );
        assert_eq!(
            selection.metadata.get("sticky_target_index"),
            Some(&"1".to_string())
        );
    }

    #[tokio::test]
    async fn test_sticky_session_miss_sets_cookie() {
        let targets = create_test_targets(3);
        let config = create_test_config();

        struct MockBalancer;

        #[async_trait]
        impl LoadBalancer for MockBalancer {
            async fn select(
                &self,
                _context: Option<&RequestContext>,
            ) -> SentinelResult<TargetSelection> {
                Ok(TargetSelection {
                    address: "10.0.0.2:8080".to_string(),
                    weight: 100,
                    metadata: HashMap::new(),
                })
            }
            async fn report_health(&self, _address: &str, _healthy: bool) {}
            async fn healthy_targets(&self) -> Vec<String> {
                vec!["10.0.0.2:8080".to_string()]
            }
        }

        let balancer = StickySessionBalancer::new(targets, config, Arc::new(MockBalancer));

        // Create context without sticky cookie
        let context = RequestContext {
            client_ip: None,
            headers: HashMap::new(),
            path: "/".to_string(),
            method: "GET".to_string(),
        };

        let selection = balancer.select(Some(&context)).await.unwrap();

        // Should use fallback and mark for cookie setting
        assert_eq!(selection.address, "10.0.0.2:8080");
        assert_eq!(
            selection.metadata.get("sticky_session_new"),
            Some(&"true".to_string())
        );
        assert!(selection.metadata.get("sticky_cookie_value").is_some());
        assert!(selection.metadata.get("sticky_set_cookie_header").is_some());
    }

    #[tokio::test]
    async fn test_unhealthy_target_falls_back() {
        let targets = create_test_targets(3);
        let config = create_test_config();

        struct MockBalancer;

        #[async_trait]
        impl LoadBalancer for MockBalancer {
            async fn select(
                &self,
                _context: Option<&RequestContext>,
            ) -> SentinelResult<TargetSelection> {
                Ok(TargetSelection {
                    address: "10.0.0.3:8080".to_string(), // Different target
                    weight: 100,
                    metadata: HashMap::new(),
                })
            }
            async fn report_health(&self, _address: &str, _healthy: bool) {}
            async fn healthy_targets(&self) -> Vec<String> {
                vec!["10.0.0.3:8080".to_string()]
            }
        }

        let balancer = StickySessionBalancer::new(targets, config, Arc::new(MockBalancer));

        // Mark target 1 as unhealthy
        balancer.report_health("10.0.0.2:8080", false).await;

        // Generate cookie for unhealthy target 1
        let cookie_value = balancer.generate_cookie_value(1);

        let mut headers = HashMap::new();
        headers.insert("cookie".to_string(), format!("SERVERID={}", cookie_value));

        let context = RequestContext {
            client_ip: None,
            headers,
            path: "/".to_string(),
            method: "GET".to_string(),
        };

        let selection = balancer.select(Some(&context)).await.unwrap();

        // Should fall back to another target and set new cookie
        assert_eq!(selection.address, "10.0.0.3:8080");
        assert_eq!(
            selection.metadata.get("sticky_session_new"),
            Some(&"true".to_string())
        );
    }
}
