//! Error types for Sentinel proxy
//!
//! This module defines common error types used throughout the Sentinel platform,
//! with a focus on clear failure modes and operational visibility.

use std::fmt;
use thiserror::Error;

/// Main error type for Sentinel operations
#[derive(Error, Debug)]
pub enum SentinelError {
    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Upstream connection errors
    #[error("Upstream error: {upstream} - {message}")]
    Upstream {
        upstream: String,
        message: String,
        retryable: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Agent communication errors
    #[error("Agent error: {agent} - {message}")]
    Agent {
        agent: String,
        message: String,
        event: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Request validation errors
    #[error("Request validation failed: {reason}")]
    RequestValidation {
        reason: String,
        correlation_id: Option<String>,
    },

    /// Response validation errors
    #[error("Response validation failed: {reason}")]
    ResponseValidation {
        reason: String,
        correlation_id: Option<String>,
    },

    /// Limit exceeded errors
    #[error("Limit exceeded: {limit_type} - {message}")]
    LimitExceeded {
        limit_type: LimitType,
        message: String,
        current_value: usize,
        limit: usize,
    },

    /// Timeout errors
    #[error("Timeout: {operation} after {duration_ms}ms")]
    Timeout {
        operation: String,
        duration_ms: u64,
        correlation_id: Option<String>,
    },

    /// Circuit breaker errors
    #[error("Circuit breaker open: {component}")]
    CircuitBreakerOpen {
        component: String,
        consecutive_failures: u32,
        last_error: String,
    },

    /// WAF block errors
    #[error("WAF blocked request: {reason}")]
    WafBlocked {
        reason: String,
        rule_ids: Vec<String>,
        confidence: f32,
        correlation_id: String,
    },

    /// Authentication/Authorization errors
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed {
        reason: String,
        correlation_id: Option<String>,
    },

    #[error("Authorization failed: {reason}")]
    AuthorizationFailed {
        reason: String,
        correlation_id: Option<String>,
        required_permissions: Vec<String>,
    },

    /// TLS/Certificate errors
    #[error("TLS error: {message}")]
    Tls {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Internal errors
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        correlation_id: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// IO errors
    #[error("IO error: {message}")]
    Io {
        message: String,
        path: Option<String>,
        #[source]
        source: std::io::Error,
    },

    /// Parsing errors
    #[error("Parse error: {message}")]
    Parse {
        message: String,
        input: Option<String>,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Service unavailable (for graceful degradation)
    #[error("Service unavailable: {service}")]
    ServiceUnavailable {
        service: String,
        retry_after_seconds: Option<u32>,
    },

    /// Rate limit errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit {
        message: String,
        limit: u32,
        window_seconds: u32,
        retry_after_seconds: Option<u32>,
    },

    /// No healthy upstream available
    #[error("No healthy upstream available")]
    NoHealthyUpstream,
}

/// Types of limits that can be exceeded
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    HeaderSize,
    HeaderCount,
    BodySize,
    RequestRate,
    ConnectionCount,
    InFlightRequests,
    DecompressionSize,
    BufferSize,
    QueueDepth,
}

impl fmt::Display for LimitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderSize => write!(f, "header_size"),
            Self::HeaderCount => write!(f, "header_count"),
            Self::BodySize => write!(f, "body_size"),
            Self::RequestRate => write!(f, "request_rate"),
            Self::ConnectionCount => write!(f, "connection_count"),
            Self::InFlightRequests => write!(f, "in_flight_requests"),
            Self::DecompressionSize => write!(f, "decompression_size"),
            Self::BufferSize => write!(f, "buffer_size"),
            Self::QueueDepth => write!(f, "queue_depth"),
        }
    }
}

/// Result type alias for Sentinel operations
pub type SentinelResult<T> = Result<T, SentinelError>;

impl SentinelError {
    /// Determine if this error should trigger a circuit breaker
    pub fn is_circuit_breaker_eligible(&self) -> bool {
        matches!(
            self,
            Self::Upstream { .. }
                | Self::Timeout { .. }
                | Self::ServiceUnavailable { .. }
                | Self::Agent { .. }
        )
    }

    /// Determine if this error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Upstream { retryable, .. } => *retryable,
            Self::Timeout { .. } => true,
            Self::ServiceUnavailable { .. } => true,
            Self::Io { .. } => true,
            _ => false,
        }
    }

    /// Get the HTTP status code for this error
    pub fn to_http_status(&self) -> u16 {
        match self {
            Self::Config { .. } => 500,
            Self::Upstream { .. } => 502,
            Self::Agent { .. } => 500,
            Self::RequestValidation { .. } => 400,
            Self::ResponseValidation { .. } => 502,
            Self::LimitExceeded { .. } => 429,
            Self::Timeout { .. } => 504,
            Self::CircuitBreakerOpen { .. } => 503,
            Self::WafBlocked { .. } => 403,
            Self::AuthenticationFailed { .. } => 401,
            Self::AuthorizationFailed { .. } => 403,
            Self::Tls { .. } => 495, // SSL Certificate Error
            Self::Internal { .. } => 500,
            Self::Io { .. } => 500,
            Self::Parse { .. } => 400,
            Self::ServiceUnavailable { .. } => 503,
            Self::RateLimit { .. } => 429,
            Self::NoHealthyUpstream => 503,
        }
    }

    /// Get a client-safe error message (without internal details)
    pub fn client_message(&self) -> String {
        match self {
            Self::Config { .. } => "Internal server error".to_string(),
            Self::Upstream { .. } => "Bad gateway".to_string(),
            Self::Agent { .. } => "Internal server error".to_string(),
            Self::RequestValidation { reason, .. } => format!("Bad request: {}", reason),
            Self::ResponseValidation { .. } => "Bad gateway".to_string(),
            Self::LimitExceeded { limit_type, .. } => {
                format!("Request limit exceeded: {}", limit_type)
            }
            Self::Timeout { .. } => "Gateway timeout".to_string(),
            Self::CircuitBreakerOpen { .. } => "Service temporarily unavailable".to_string(),
            Self::WafBlocked { reason, .. } => format!("Request blocked: {}", reason),
            Self::AuthenticationFailed { .. } => "Authentication required".to_string(),
            Self::AuthorizationFailed { .. } => "Access denied".to_string(),
            Self::Tls { .. } => "TLS handshake failed".to_string(),
            Self::Internal { .. } => "Internal server error".to_string(),
            Self::Io { .. } => "Internal server error".to_string(),
            Self::Parse { .. } => "Bad request".to_string(),
            Self::ServiceUnavailable { service, .. } => {
                format!("Service '{}' temporarily unavailable", service)
            }
            Self::RateLimit { .. } => "Rate limit exceeded".to_string(),
            Self::NoHealthyUpstream => "No healthy upstream available".to_string(),
        }
    }

    /// Create an upstream error
    pub fn upstream(upstream: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Upstream {
            upstream: upstream.into(),
            message: message.into(),
            retryable: false,
            source: None,
        }
    }

    /// Create a retryable upstream error
    pub fn upstream_retryable(upstream: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Upstream {
            upstream: upstream.into(),
            message: message.into(),
            retryable: true,
            source: None,
        }
    }

    /// Create a timeout error
    pub fn timeout(operation: impl Into<String>, duration_ms: u64) -> Self {
        Self::Timeout {
            operation: operation.into(),
            duration_ms,
            correlation_id: None,
        }
    }

    /// Create a limit exceeded error
    pub fn limit_exceeded(
        limit_type: LimitType,
        current_value: usize,
        limit: usize,
    ) -> Self {
        Self::LimitExceeded {
            limit_type,
            message: format!("Current value {} exceeds limit {}", current_value, limit),
            current_value,
            limit,
        }
    }

    /// Add correlation ID to the error
    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        match &mut self {
            Self::RequestValidation { correlation_id: cid, .. }
            | Self::ResponseValidation { correlation_id: cid, .. }
            | Self::Timeout { correlation_id: cid, .. }
            | Self::AuthenticationFailed { correlation_id: cid, .. }
            | Self::AuthorizationFailed { correlation_id: cid, .. }
            | Self::Internal { correlation_id: cid, .. } => {
                *cid = Some(correlation_id.into());
            }
            _ => {}
        }
        self
    }
}

/// Helper for converting IO errors
impl From<std::io::Error> for SentinelError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            message: err.to_string(),
            path: None,
            source: err,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_http_status() {
        assert_eq!(SentinelError::upstream("backend", "connection refused").to_http_status(), 502);
        assert_eq!(SentinelError::timeout("upstream", 5000).to_http_status(), 504);
        assert_eq!(
            SentinelError::limit_exceeded(LimitType::HeaderSize, 2048, 1024).to_http_status(),
            429
        );
    }

    #[test]
    fn test_error_retryable() {
        assert!(!SentinelError::upstream("backend", "error").is_retryable());
        assert!(SentinelError::upstream_retryable("backend", "error").is_retryable());
        assert!(SentinelError::timeout("operation", 1000).is_retryable());
    }

    #[test]
    fn test_error_circuit_breaker() {
        assert!(SentinelError::upstream("backend", "error").is_circuit_breaker_eligible());
        assert!(SentinelError::timeout("operation", 1000).is_circuit_breaker_eligible());
        assert!(!SentinelError::RequestValidation {
            reason: "invalid".to_string(),
            correlation_id: None
        }
        .is_circuit_breaker_eligible());
    }

    #[test]
    fn test_client_message() {
        let err = SentinelError::Internal {
            message: "Database connection failed".to_string(),
            correlation_id: Some("123".to_string()),
            source: None,
        };
        assert_eq!(err.client_message(), "Internal server error");

        let err = SentinelError::WafBlocked {
            reason: "SQL injection detected".to_string(),
            rule_ids: vec!["942100".to_string()],
            confidence: 0.95,
            correlation_id: "456".to_string(),
        };
        assert_eq!(err.client_message(), "Request blocked: SQL injection detected");
    }
}
