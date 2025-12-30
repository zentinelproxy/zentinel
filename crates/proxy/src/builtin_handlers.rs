//! Built-in handlers for Sentinel proxy
//!
//! These handlers provide default responses for common endpoints like
//! status pages, health checks, and metrics. They are used when routes
//! are configured with `service-type: builtin`.

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::Full;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use sentinel_config::{BuiltinHandler, Config};

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

/// Upstream health snapshot for the upstreams handler
#[derive(Debug, Clone, Default)]
pub struct UpstreamHealthSnapshot {
    /// Health status per upstream, keyed by upstream ID
    pub upstreams: HashMap<String, UpstreamStatus>,
}

/// Status of a single upstream
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatus {
    /// Upstream ID
    pub id: String,
    /// Load balancing algorithm
    pub load_balancing: String,
    /// Target statuses
    pub targets: Vec<TargetStatus>,
}

/// Status of a single target within an upstream
#[derive(Debug, Clone, Serialize)]
pub struct TargetStatus {
    /// Target address
    pub address: String,
    /// Weight
    pub weight: u32,
    /// Health status
    pub status: TargetHealthStatus,
    /// Failure rate (0.0 - 1.0)
    pub failure_rate: Option<f64>,
    /// Last error message if unhealthy
    pub last_error: Option<String>,
}

/// Health status of a target
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TargetHealthStatus {
    /// Target is healthy
    Healthy,
    /// Target is unhealthy
    Unhealthy,
    /// Health status unknown (no checks yet)
    Unknown,
}

/// Execute a builtin handler
pub fn execute_handler(
    handler: BuiltinHandler,
    state: &BuiltinHandlerState,
    request_id: &str,
    config: Option<Arc<Config>>,
    upstreams: Option<UpstreamHealthSnapshot>,
) -> Response<Full<Bytes>> {
    trace!(
        handler = ?handler,
        request_id = %request_id,
        "Executing builtin handler"
    );

    let response = match handler {
        BuiltinHandler::Status => status_handler(state, request_id),
        BuiltinHandler::Health => health_handler(request_id),
        BuiltinHandler::Metrics => metrics_handler(request_id),
        BuiltinHandler::NotFound => not_found_handler(request_id),
        BuiltinHandler::Config => config_handler(config, request_id),
        BuiltinHandler::Upstreams => upstreams_handler(upstreams, request_id),
    };

    debug!(
        handler = ?handler,
        request_id = %request_id,
        status = response.status().as_u16(),
        "Builtin handler completed"
    );

    response
}

/// JSON status page handler
fn status_handler(state: &BuiltinHandlerState, request_id: &str) -> Response<Full<Bytes>> {
    trace!(
        request_id = %request_id,
        uptime_secs = state.uptime().as_secs(),
        "Generating status response"
    );

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
        .expect("static response builder with valid headers cannot fail")
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
        .expect("static response builder with valid headers cannot fail")
}

/// Prometheus metrics handler
fn metrics_handler(request_id: &str) -> Response<Full<Bytes>> {
    use prometheus::{Encoder, TextEncoder};

    // Create encoder for Prometheus text format
    let encoder = TextEncoder::new();

    // Gather all metrics from the default registry
    let metric_families = prometheus::gather();

    // Encode metrics to text format
    let mut buffer = Vec::new();
    match encoder.encode(&metric_families, &mut buffer) {
        Ok(()) => {
            // Add sentinel_up and build_info metrics
            let extra_metrics = format!(
                "# HELP sentinel_up Sentinel proxy is up and running\n\
                 # TYPE sentinel_up gauge\n\
                 sentinel_up 1\n\
                 # HELP sentinel_build_info Build information\n\
                 # TYPE sentinel_build_info gauge\n\
                 sentinel_build_info{{version=\"{}\"}} 1\n",
                env!("CARGO_PKG_VERSION")
            );
            buffer.extend_from_slice(extra_metrics.as_bytes());

            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .header("X-Request-Id", request_id)
                .body(Full::new(Bytes::from(buffer)))
                .expect("static response builder with valid headers cannot fail")
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to encode Prometheus metrics");
            let error_body = format!("# ERROR: Failed to encode metrics: {}\n", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("X-Request-Id", request_id)
                .body(Full::new(Bytes::from(error_body)))
                .expect("static response builder with valid headers cannot fail")
        }
    }
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
        .expect("static response builder with valid headers cannot fail")
}

/// Configuration dump handler
///
/// Returns the current running configuration as JSON. Sensitive fields like
/// TLS private keys are redacted for security.
fn config_handler(config: Option<Arc<Config>>, request_id: &str) -> Response<Full<Bytes>> {
    let body = match &config {
        Some(cfg) => {
            // Build a response with configuration details
            // The Config struct derives Serialize, so we can serialize directly
            // Note: sensitive fields should be redacted in production
            let response = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "request_id": request_id,
                "config": {
                    "server": &cfg.server,
                    "listeners": cfg.listeners.iter().map(|l| {
                        serde_json::json!({
                            "id": l.id,
                            "address": l.address,
                            "protocol": l.protocol,
                            "default_route": l.default_route,
                            "request_timeout_secs": l.request_timeout_secs,
                            "keepalive_timeout_secs": l.keepalive_timeout_secs,
                            // TLS config is redacted - only show if enabled
                            "tls_enabled": l.tls.is_some(),
                        })
                    }).collect::<Vec<_>>(),
                    "routes": cfg.routes.iter().map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "priority": r.priority,
                            "matches": r.matches,
                            "upstream": r.upstream,
                            "service_type": r.service_type,
                            "builtin_handler": r.builtin_handler,
                            "filters": r.filters,
                            "waf_enabled": r.waf_enabled,
                        })
                    }).collect::<Vec<_>>(),
                    "upstreams": cfg.upstreams.iter().map(|(id, u)| {
                        serde_json::json!({
                            "id": id,
                            "targets": u.targets.iter().map(|t| {
                                serde_json::json!({
                                    "address": t.address,
                                    "weight": t.weight,
                                })
                            }).collect::<Vec<_>>(),
                            "load_balancing": u.load_balancing,
                            "health_check": u.health_check.as_ref().map(|h| {
                                serde_json::json!({
                                    "interval_secs": h.interval_secs,
                                    "timeout_secs": h.timeout_secs,
                                    "healthy_threshold": h.healthy_threshold,
                                    "unhealthy_threshold": h.unhealthy_threshold,
                                })
                            }),
                            // TLS config redacted
                            "tls_enabled": u.tls.is_some(),
                        })
                    }).collect::<Vec<_>>(),
                    "agents": cfg.agents.iter().map(|a| {
                        serde_json::json!({
                            "id": a.id,
                            "agent_type": a.agent_type,
                            "timeout_ms": a.timeout_ms,
                        })
                    }).collect::<Vec<_>>(),
                    "filters": cfg.filters.keys().collect::<Vec<_>>(),
                    "waf": cfg.waf.as_ref().map(|w| {
                        serde_json::json!({
                            "mode": w.mode,
                            "engine": w.engine,
                            "audit_log": w.audit_log,
                        })
                    }),
                    "limits": &cfg.limits,
                }
            });

            serde_json::to_vec_pretty(&response).unwrap_or_else(|e| {
                serde_json::to_vec(&serde_json::json!({
                    "error": "Failed to serialize config",
                    "message": e.to_string(),
                })).unwrap_or_default()
            })
        }
        None => {
            serde_json::to_vec_pretty(&serde_json::json!({
                "error": "Configuration unavailable",
                "status": 503,
                "message": "Config manager not available",
                "request_id": request_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            })).unwrap_or_default()
        }
    };

    let status = if config.is_some() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Request-Id", request_id)
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builder with valid headers cannot fail")
}

/// Upstream health status handler
///
/// Returns the health status of all configured upstreams and their targets.
fn upstreams_handler(
    snapshot: Option<UpstreamHealthSnapshot>,
    request_id: &str,
) -> Response<Full<Bytes>> {
    let body = match snapshot {
        Some(data) => {
            // Count healthy/unhealthy/unknown targets
            let mut total_healthy = 0;
            let mut total_unhealthy = 0;
            let mut total_unknown = 0;

            for upstream in data.upstreams.values() {
                for target in &upstream.targets {
                    match target.status {
                        TargetHealthStatus::Healthy => total_healthy += 1,
                        TargetHealthStatus::Unhealthy => total_unhealthy += 1,
                        TargetHealthStatus::Unknown => total_unknown += 1,
                    }
                }
            }

            let response = serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "request_id": request_id,
                "summary": {
                    "total_upstreams": data.upstreams.len(),
                    "total_targets": total_healthy + total_unhealthy + total_unknown,
                    "healthy": total_healthy,
                    "unhealthy": total_unhealthy,
                    "unknown": total_unknown,
                },
                "upstreams": data.upstreams.values().collect::<Vec<_>>(),
            });

            serde_json::to_vec_pretty(&response).unwrap_or_else(|e| {
                serde_json::to_vec(&serde_json::json!({
                    "error": "Failed to serialize upstreams",
                    "message": e.to_string(),
                })).unwrap_or_default()
            })
        }
        None => {
            // No upstreams configured or data unavailable
            serde_json::to_vec_pretty(&serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "request_id": request_id,
                "summary": {
                    "total_upstreams": 0,
                    "total_targets": 0,
                    "healthy": 0,
                    "unhealthy": 0,
                    "unknown": 0,
                },
                "upstreams": [],
                "message": "No upstreams configured",
            })).unwrap_or_default()
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("X-Request-Id", request_id)
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builder with valid headers cannot fail")
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
    fn test_config_handler_with_config() {
        let config = Arc::new(Config::default_for_testing());
        let response = config_handler(Some(config), "test-request-id");
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("Content-Type").unwrap();
        assert_eq!(content_type, "application/json; charset=utf-8");
    }

    #[test]
    fn test_config_handler_without_config() {
        let response = config_handler(None, "test-request-id");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn test_upstreams_handler_with_data() {
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "backend".to_string(),
            UpstreamStatus {
                id: "backend".to_string(),
                load_balancing: "round_robin".to_string(),
                targets: vec![
                    TargetStatus {
                        address: "10.0.0.1:8080".to_string(),
                        weight: 1,
                        status: TargetHealthStatus::Healthy,
                        failure_rate: Some(0.0),
                        last_error: None,
                    },
                    TargetStatus {
                        address: "10.0.0.2:8080".to_string(),
                        weight: 1,
                        status: TargetHealthStatus::Unhealthy,
                        failure_rate: Some(0.8),
                        last_error: Some("connection refused".to_string()),
                    },
                ],
            },
        );

        let snapshot = UpstreamHealthSnapshot { upstreams };
        let response = upstreams_handler(Some(snapshot), "test-request-id");
        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("Content-Type").unwrap();
        assert_eq!(content_type, "application/json; charset=utf-8");
    }

    #[test]
    fn test_upstreams_handler_no_upstreams() {
        let response = upstreams_handler(None, "test-request-id");
        assert_eq!(response.status(), StatusCode::OK);
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
