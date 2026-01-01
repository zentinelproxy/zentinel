//! gRPC Health Checking Protocol implementation
//!
//! Implements the standard gRPC Health Checking Protocol (grpc.health.v1.Health)
//! for health checking gRPC backends.
//!
//! # Protocol
//!
//! The gRPC health check protocol uses:
//! - Service: `grpc.health.v1.Health`
//! - Method: `Check(HealthCheckRequest) returns (HealthCheckResponse)`
//! - Request: `{ service: string }` - empty string for server health
//! - Response: `{ status: ServingStatus }`
//!   - `SERVING` = healthy
//!   - `NOT_SERVING`, `UNKNOWN`, `SERVICE_UNKNOWN` = unhealthy
//!
//! # Example
//!
//! ```ignore
//! use sentinel_proxy::grpc_health::GrpcHealthCheck;
//! use std::time::Duration;
//!
//! let hc = GrpcHealthCheck::new("my.service.Name".to_string(), Duration::from_secs(5));
//! // Use with Pingora's health check infrastructure
//! ```

use async_trait::async_trait;
use pingora_core::{Error, ErrorType::CustomCode, Result};
use pingora_load_balancing::health_check::HealthCheck;
use pingora_load_balancing::Backend;
use std::time::Duration;
use tonic::transport::Endpoint;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use tonic_health::pb::HealthCheckRequest;
use tracing::{debug, trace, warn};

/// gRPC health check implementing Pingora's HealthCheck trait
///
/// This health check connects to a gRPC server and calls the standard
/// `grpc.health.v1.Health/Check` method to verify the server is healthy.
pub struct GrpcHealthCheck {
    /// Service name to check (empty string = overall server health)
    service: String,

    /// Number of consecutive successes required to flip from unhealthy to healthy
    pub consecutive_success: usize,

    /// Number of consecutive failures required to flip from healthy to unhealthy
    pub consecutive_failure: usize,

    /// Health check timeout
    timeout: Duration,
}

impl GrpcHealthCheck {
    /// Create a new gRPC health check
    ///
    /// # Arguments
    ///
    /// * `service` - The service name to check. Empty string checks overall server health.
    /// * `timeout` - Timeout for the health check RPC call
    pub fn new(service: String, timeout: Duration) -> Self {
        Self {
            service,
            consecutive_success: 1,
            consecutive_failure: 1,
            timeout,
        }
    }

    /// Perform the gRPC health check against a specific address
    async fn check_grpc(&self, addr: &str) -> Result<()> {
        // Build the endpoint URL
        // The address from Backend is in format "host:port"
        let url = format!("http://{}", addr);

        trace!(
            address = %addr,
            service = %self.service,
            timeout_ms = self.timeout.as_millis(),
            "Performing gRPC health check"
        );

        // Create endpoint with timeout
        let endpoint = match Endpoint::from_shared(url.clone()) {
            Ok(ep) => ep.timeout(self.timeout).connect_timeout(self.timeout),
            Err(e) => {
                warn!(address = %addr, error = %e, "Invalid gRPC endpoint URL");
                return Err(Error::explain(
                    CustomCode("gRPC health check", 1),
                    format!("Invalid endpoint: {}", e),
                ));
            }
        };

        // Connect to the server
        let channel = match endpoint.connect().await {
            Ok(ch) => ch,
            Err(e) => {
                debug!(
                    address = %addr,
                    error = %e,
                    "Failed to connect for gRPC health check"
                );
                return Err(Error::explain(
                    CustomCode("gRPC health check", 2),
                    format!("Connection failed: {}", e),
                ));
            }
        };

        // Create health client and perform check
        let mut client = HealthClient::new(channel);

        let request = tonic::Request::new(HealthCheckRequest {
            service: self.service.clone(),
        });

        let response = match client.check(request).await {
            Ok(resp) => resp,
            Err(e) => {
                debug!(
                    address = %addr,
                    service = %self.service,
                    error = %e,
                    "gRPC health check RPC failed"
                );
                return Err(Error::explain(
                    CustomCode("gRPC health check", 3),
                    format!("Health check RPC failed: {}", e),
                ));
            }
        };

        let status = response.into_inner().status();

        match status {
            ServingStatus::Serving => {
                trace!(
                    address = %addr,
                    service = %self.service,
                    "gRPC health check passed: SERVING"
                );
                Ok(())
            }
            ServingStatus::NotServing => {
                debug!(
                    address = %addr,
                    service = %self.service,
                    "gRPC health check failed: NOT_SERVING"
                );
                Err(Error::explain(
                    CustomCode("gRPC health check", 4),
                    "Service status: NOT_SERVING",
                ))
            }
            ServingStatus::Unknown => {
                debug!(
                    address = %addr,
                    service = %self.service,
                    "gRPC health check failed: UNKNOWN"
                );
                Err(Error::explain(
                    CustomCode("gRPC health check", 5),
                    "Service status: UNKNOWN",
                ))
            }
            ServingStatus::ServiceUnknown => {
                debug!(
                    address = %addr,
                    service = %self.service,
                    "gRPC health check failed: SERVICE_UNKNOWN"
                );
                Err(Error::explain(
                    CustomCode("gRPC health check", 6),
                    "Service status: SERVICE_UNKNOWN",
                ))
            }
        }
    }
}

#[async_trait]
impl HealthCheck for GrpcHealthCheck {
    /// Check if the backend is healthy using gRPC health protocol
    async fn check(&self, target: &Backend) -> Result<()> {
        let addr = target.addr.to_string();
        self.check_grpc(&addr).await
    }

    /// Return the health threshold for flipping health status
    ///
    /// * `success: true` - returns consecutive_success (unhealthy -> healthy)
    /// * `success: false` - returns consecutive_failure (healthy -> unhealthy)
    fn health_threshold(&self, success: bool) -> usize {
        if success {
            self.consecutive_success
        } else {
            self.consecutive_failure
        }
    }
}

impl Default for GrpcHealthCheck {
    fn default() -> Self {
        Self::new(String::new(), Duration::from_secs(5))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_health_check_new() {
        let hc = GrpcHealthCheck::new("my.service".to_string(), Duration::from_secs(10));
        assert_eq!(hc.service, "my.service");
        assert_eq!(hc.timeout, Duration::from_secs(10));
        assert_eq!(hc.consecutive_success, 1);
        assert_eq!(hc.consecutive_failure, 1);
    }

    #[test]
    fn test_grpc_health_check_default() {
        let hc = GrpcHealthCheck::default();
        assert_eq!(hc.service, "");
        assert_eq!(hc.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_health_threshold() {
        let mut hc = GrpcHealthCheck::new("".to_string(), Duration::from_secs(5));
        hc.consecutive_success = 3;
        hc.consecutive_failure = 5;

        assert_eq!(hc.health_threshold(true), 3);
        assert_eq!(hc.health_threshold(false), 5);
    }

    #[tokio::test]
    async fn test_grpc_health_check_connection_refused() {
        let hc = GrpcHealthCheck::new("".to_string(), Duration::from_secs(1));

        // Try to connect to a non-existent server
        let result = hc.check_grpc("127.0.0.1:59999").await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        // Should fail with connection error
        assert!(err.to_string().contains("Connection failed") || err.to_string().contains("gRPC"));
    }
}
