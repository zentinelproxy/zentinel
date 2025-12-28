//! Built-in handlers for Sentinel proxy
//!
//! These handlers provide default responses for common endpoints like
//! status pages, health checks, and metrics. They are used when routes
//! are configured with `service-type: builtin`.

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use serde::Serialize;
use std::time::{Duration, Instant};

use sentinel_config::BuiltinHandler;

/// Application state for builtin handlers
pub struct BuiltinHandlerState {
    /// Application start time
    start_time: Instant,
    /// Application version
    version: String,
    /// Instance ID
    instance_id: String,
}

impl BuiltinHandlerState {
    /// Create new handler state
    pub fn new(version: String, instance_id: String) -> Self {
        Self {
            start_time: Instant::now(),
            version,
            instance_id,
        }
    }

    /// Get uptime as a Duration
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Format uptime as human-readable string
    pub fn uptime_string(&self) -> String {
        let uptime = self.uptime();
        let secs = uptime.as_secs();
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        let secs = secs % 60;

        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, mins, secs)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, mins, secs)
        } else if mins > 0 {
            format!("{}m {}s", mins, secs)
        } else {
            format!("{}s", secs)
        }
    }
}

/// Status response payload
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    /// Service status
    pub status: &'static str,
    /// Service version
    pub version: String,
    /// Service uptime
    pub uptime: String,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Instance identifier
    pub instance_id: String,
    /// Timestamp
    pub timestamp: String,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Health status
    pub status: &'static str,
    /// Timestamp
    pub timestamp: String,
}

/// Execute a builtin handler
pub fn execute_handler(
    handler: BuiltinHandler,
    state: &BuiltinHandlerState,
    request_id: &str,
) -> Response<Full<Bytes>> {
    match handler {
        BuiltinHandler::Status => status_handler(state, request_id),
        BuiltinHandler::Health => health_handler(request_id),
        BuiltinHandler::Metrics => metrics_handler(request_id),
        BuiltinHandler::NotFound => not_found_handler(request_id),
    }
}

/// JSON status page handler
fn status_handler(state: &BuiltinHandlerState, request_id: &str) -> Response<Full<Bytes>> {
    let response = StatusResponse {
        status: "ok",
        version: state.version.clone(),
        uptime: state.uptime_string(),
        uptime_secs: state.uptime().as_secs(),
        instance_id: state.instance_id.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let body = serde_json::to_vec_pretty(&response).unwrap_or_else(|_| {
        b"{\"status\":\"ok\"}".to_vec()
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Request-Id", request_id)
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Health check handler
fn health_handler(request_id: &str) -> Response<Full<Bytes>> {
    let response = HealthResponse {
        status: "healthy",
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let body = serde_json::to_vec(&response).unwrap_or_else(|_| {
        b"{\"status\":\"healthy\"}".to_vec()
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Request-Id", request_id)
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Prometheus metrics handler
fn metrics_handler(request_id: &str) -> Response<Full<Bytes>> {
    // Get metrics from the global registry
    // For now, return basic metrics format
    let metrics = format!(
        "# HELP sentinel_up Sentinel proxy is up and running\n\
         # TYPE sentinel_up gauge\n\
         sentinel_up 1\n\
         # HELP sentinel_build_info Build information\n\
         # TYPE sentinel_build_info gauge\n\
         sentinel_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .header("X-Request-Id", request_id)
        .body(Full::new(Bytes::from(metrics)))
        .unwrap()
}

/// 404 Not Found handler
fn not_found_handler(request_id: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": "Not Found",
        "status": 404,
        "message": "The requested resource could not be found.",
        "request_id": request_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    let body_bytes = serde_json::to_vec_pretty(&body).unwrap_or_else(|_| {
        b"{\"error\":\"Not Found\",\"status\":404}".to_vec()
    });

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Request-Id", request_id)
        .body(Full::new(Bytes::from(body_bytes)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_handler() {
        let state = BuiltinHandlerState::new(
            "0.1.0".to_string(),
            "test-instance".to_string(),
        );

        let response = status_handler(&state, "test-request-id");
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("Content-Type").unwrap();
        assert_eq!(content_type, "application/json; charset=utf-8");
    }

    #[test]
    fn test_health_handler() {
        let response = health_handler("test-request-id");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_metrics_handler() {
        let response = metrics_handler("test-request-id");
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("Content-Type").unwrap();
        assert!(content_type.to_str().unwrap().contains("text/plain"));
    }

    #[test]
    fn test_not_found_handler() {
        let response = not_found_handler("test-request-id");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_uptime_formatting() {
        let state = BuiltinHandlerState::new(
            "0.1.0".to_string(),
            "test".to_string(),
        );

        // Just verify it doesn't panic and returns a string
        let uptime = state.uptime_string();
        assert!(!uptime.is_empty());
    }
}
