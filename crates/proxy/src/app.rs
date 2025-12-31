//! Application module for Sentinel proxy
//!
//! This module contains application-level logic and utilities for the proxy.

use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{error, info, warn};

/// Application state for the proxy
pub struct AppState {
    /// Application version
    pub version: String,
    /// Instance ID
    pub instance_id: String,
    /// Startup time
    pub start_time: std::time::Instant,
    /// Is the proxy healthy?
    pub is_healthy: Arc<RwLock<bool>>,
    /// Is the proxy ready to serve traffic?
    pub is_ready: Arc<RwLock<bool>>,
}

impl AppState {
    /// Create new application state
    pub fn new(instance_id: String) -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            instance_id,
            start_time: std::time::Instant::now(),
            is_healthy: Arc::new(RwLock::new(true)),
            is_ready: Arc::new(RwLock::new(false)),
        }
    }

    /// Mark the application as ready
    pub fn set_ready(&self, ready: bool) {
        *self.is_ready.write() = ready;
        if ready {
            info!("Application marked as ready");
        } else {
            warn!("Application marked as not ready");
        }
    }

    /// Mark the application as healthy/unhealthy
    pub fn set_healthy(&self, healthy: bool) {
        *self.is_healthy.write() = healthy;
        if healthy {
            info!("Application marked as healthy");
        } else {
            error!("Application marked as unhealthy");
        }
    }

    /// Check if the application is healthy
    pub fn is_healthy(&self) -> bool {
        *self.is_healthy.read()
    }

    /// Check if the application is ready
    pub fn is_ready(&self) -> bool {
        *self.is_ready.read()
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get application info as JSON
    pub fn info(&self) -> serde_json::Value {
        serde_json::json!({
            "version": self.version,
            "instance_id": self.instance_id,
            "uptime_seconds": self.uptime_seconds(),
            "is_healthy": self.is_healthy(),
            "is_ready": self.is_ready(),
        })
    }
}

/// Health check status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is degraded but operational
    Degraded,
    /// Service is unhealthy
    Unhealthy,
}

impl HealthStatus {
    /// Convert to HTTP status code
    pub fn to_http_status(&self) -> u16 {
        match self {
            Self::Healthy => 200,
            Self::Degraded => 200, // Still return 200 for degraded
            Self::Unhealthy => 503,
        }
    }

    /// Check if the status is considered "ok" for serving traffic
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheck {
    /// Overall status
    pub status: HealthStatus,
    /// Individual component checks
    pub components: Vec<ComponentHealth>,
    /// Timestamp of the check
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Component health status
#[derive(Debug, Clone)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Component status
    pub status: HealthStatus,
    /// Optional error message
    pub message: Option<String>,
    /// Last successful check time
    pub last_success: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthCheck {
    /// Create a new health check result
    pub fn new() -> Self {
        Self {
            status: HealthStatus::Healthy,
            components: Vec::new(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Add a component health status
    pub fn add_component(&mut self, component: ComponentHealth) {
        // Update overall status based on component
        match component.status {
            HealthStatus::Unhealthy => self.status = HealthStatus::Unhealthy,
            HealthStatus::Degraded if self.status == HealthStatus::Healthy => {
                self.status = HealthStatus::Degraded;
            }
            _ => {}
        }
        self.components.push(component);
    }

    /// Convert to JSON response
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": match self.status {
                HealthStatus::Healthy => "healthy",
                HealthStatus::Degraded => "degraded",
                HealthStatus::Unhealthy => "unhealthy",
            },
            "timestamp": self.timestamp.to_rfc3339(),
            "components": self.components.iter().map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "status": match c.status {
                        HealthStatus::Healthy => "healthy",
                        HealthStatus::Degraded => "degraded",
                        HealthStatus::Unhealthy => "unhealthy",
                    },
                    "message": c.message,
                    "last_success": c.last_success.map(|t| t.to_rfc3339()),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

/// Readiness check result
#[derive(Debug, Clone)]
pub struct ReadinessCheck {
    /// Is the service ready?
    pub ready: bool,
    /// Reason if not ready
    pub reason: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ReadinessCheck {
    /// Create a ready result
    pub fn ready() -> Self {
        Self {
            ready: true,
            reason: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a not ready result
    pub fn not_ready(reason: String) -> Self {
        Self {
            ready: false,
            reason: Some(reason),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Convert to JSON response
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ready": self.ready,
            "reason": self.reason,
            "timestamp": self.timestamp.to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state() {
        let state = AppState::new("test-123".to_string());

        assert!(!state.is_ready());
        assert!(state.is_healthy());

        state.set_ready(true);
        assert!(state.is_ready());

        state.set_healthy(false);
        assert!(!state.is_healthy());
    }

    #[test]
    fn test_health_check() {
        let mut check = HealthCheck::new();
        assert_eq!(check.status, HealthStatus::Healthy);

        check.add_component(ComponentHealth {
            name: "upstream".to_string(),
            status: HealthStatus::Healthy,
            message: None,
            last_success: Some(chrono::Utc::now()),
        });
        assert_eq!(check.status, HealthStatus::Healthy);

        check.add_component(ComponentHealth {
            name: "cache".to_string(),
            status: HealthStatus::Degraded,
            message: Some("High latency".to_string()),
            last_success: Some(chrono::Utc::now()),
        });
        assert_eq!(check.status, HealthStatus::Degraded);

        check.add_component(ComponentHealth {
            name: "database".to_string(),
            status: HealthStatus::Unhealthy,
            message: Some("Connection failed".to_string()),
            last_success: None,
        });
        assert_eq!(check.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_health_status_http_codes() {
        assert_eq!(HealthStatus::Healthy.to_http_status(), 200);
        assert_eq!(HealthStatus::Degraded.to_http_status(), 200);
        assert_eq!(HealthStatus::Unhealthy.to_http_status(), 503);

        assert!(HealthStatus::Healthy.is_ok());
        assert!(HealthStatus::Degraded.is_ok());
        assert!(!HealthStatus::Unhealthy.is_ok());
    }
}
