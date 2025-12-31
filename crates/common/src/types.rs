//! Common type definitions for Sentinel proxy.
//!
//! This module provides shared type definitions used throughout the platform,
//! with a focus on type safety and operational clarity.
//!
//! For identifier types (CorrelationId, RequestId, etc.), see the `ids` module.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// HTTP method wrapper with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    HEAD,
    OPTIONS,
    PATCH,
    CONNECT,
    TRACE,
    #[serde(untagged)]
    Custom(String),
}

impl FromStr for HttpMethod {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_uppercase().as_str() {
            "GET" => Self::GET,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "DELETE" => Self::DELETE,
            "HEAD" => Self::HEAD,
            "OPTIONS" => Self::OPTIONS,
            "PATCH" => Self::PATCH,
            "CONNECT" => Self::CONNECT,
            "TRACE" => Self::TRACE,
            other => Self::Custom(other.to_string()),
        })
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GET => write!(f, "GET"),
            Self::POST => write!(f, "POST"),
            Self::PUT => write!(f, "PUT"),
            Self::DELETE => write!(f, "DELETE"),
            Self::HEAD => write!(f, "HEAD"),
            Self::OPTIONS => write!(f, "OPTIONS"),
            Self::PATCH => write!(f, "PATCH"),
            Self::CONNECT => write!(f, "CONNECT"),
            Self::TRACE => write!(f, "TRACE"),
            Self::Custom(method) => write!(f, "{}", method),
        }
    }
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "TLS1.2")]
    Tls12,
    #[serde(rename = "TLS1.3")]
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls12 => write!(f, "TLS1.2"),
            Self::Tls13 => write!(f, "TLS1.3"),
        }
    }
}

/// Trace ID format selection.
///
/// Controls how trace IDs are generated for request tracing.
///
/// # Formats
///
/// - **TinyFlake** (default): 11-character Base58 encoded ID with time prefix.
///   Operator-friendly format designed for easy copying and log correlation.
///   Example: `k7BxR3nVp2Ym`
///
/// - **UUID**: Standard 36-character UUID v4 format with dashes.
///   Guaranteed unique, widely compatible.
///   Example: `550e8400-e29b-41d4-a716-446655440000`
///
/// # Configuration
///
/// ```kdl
/// server {
///     trace-id-format "tinyflake"  // or "uuid"
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceIdFormat {
    /// TinyFlake format: 11-char Base58, time-prefixed (default)
    #[default]
    TinyFlake,

    /// UUID v4 format: 36-char with dashes
    Uuid,
}

impl TraceIdFormat {
    /// Parse format from string (case-insensitive)
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "uuid" | "uuid4" | "uuidv4" => TraceIdFormat::Uuid,
            _ => TraceIdFormat::TinyFlake, // Default to TinyFlake
        }
    }
}

impl fmt::Display for TraceIdFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceIdFormat::TinyFlake => write!(f, "tinyflake"),
            TraceIdFormat::Uuid => write!(f, "uuid"),
        }
    }
}

/// Load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    RoundRobin,
    LeastConnections,
    Random,
    IpHash,
    Weighted,
    ConsistentHash,
    PowerOfTwoChoices,
    Adaptive,
}

/// Health check type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckType {
    Http {
        path: String,
        expected_status: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
    Tcp,
    Grpc {
        service: String,
    },
}

/// Retry policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub timeout_ms: u64,
    pub backoff_base_ms: u64,
    pub backoff_max_ms: u64,
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            timeout_ms: 30000,
            backoff_base_ms: 100,
            backoff_max_ms: 10000,
            retryable_status_codes: vec![502, 503, 504],
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout_seconds: u64,
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            timeout_seconds: 30,
            half_open_max_requests: 1,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Request priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low = 0,
    #[default]
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// Time window for rate limiting and metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    pub seconds: u64,
}

impl TimeWindow {
    pub fn new(seconds: u64) -> Self {
        Self { seconds }
    }

    pub fn as_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.seconds)
    }
}

/// Byte size with human-readable serialization
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub usize);

impl ByteSize {
    pub const KB: usize = 1024;
    pub const MB: usize = 1024 * 1024;
    pub const GB: usize = 1024 * 1024 * 1024;

    pub fn from_kb(kb: usize) -> Self {
        Self(kb * Self::KB)
    }

    pub fn from_mb(mb: usize) -> Self {
        Self(mb * Self::MB)
    }

    pub fn from_gb(gb: usize) -> Self {
        Self(gb * Self::GB)
    }

    pub fn as_bytes(&self) -> usize {
        self.0
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 >= Self::GB {
            write!(f, "{:.2}GB", self.0 as f64 / Self::GB as f64)
        } else if self.0 >= Self::MB {
            write!(f, "{:.2}MB", self.0 as f64 / Self::MB as f64)
        } else if self.0 >= Self::KB {
            write!(f, "{:.2}KB", self.0 as f64 / Self::KB as f64)
        } else {
            write!(f, "{}B", self.0)
        }
    }
}

impl Serialize for ByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err("Empty byte size string".to_string());
        }

        // Try to parse as plain number (bytes)
        if let Ok(bytes) = s.parse::<usize>() {
            return Ok(Self(bytes));
        }

        // Parse with unit suffix
        let (num_part, unit_part) = s
            .chars()
            .position(|c| c.is_alphabetic())
            .map(|i| s.split_at(i))
            .ok_or_else(|| format!("Invalid byte size format: {}", s))?;

        let value: f64 = num_part
            .trim()
            .parse()
            .map_err(|_| format!("Invalid number: {}", num_part))?;

        let multiplier = match unit_part.to_uppercase().as_str() {
            "B" => 1,
            "KB" | "K" => Self::KB,
            "MB" | "M" => Self::MB,
            "GB" | "G" => Self::GB,
            _ => return Err(format!("Invalid unit: {}", unit_part)),
        };

        Ok(Self((value * multiplier as f64) as usize))
    }
}

/// IP address wrapper with additional metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientIp {
    pub address: std::net::IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarded_for: Option<Vec<std::net::IpAddr>>,
}

impl fmt::Display for ClientIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_method_parsing() {
        assert_eq!(HttpMethod::from_str("GET").unwrap(), HttpMethod::GET);
        assert_eq!(HttpMethod::from_str("post").unwrap(), HttpMethod::POST);
        assert_eq!(
            HttpMethod::from_str("PROPFIND").unwrap(),
            HttpMethod::Custom("PROPFIND".to_string())
        );
    }

    #[test]
    fn test_byte_size_parsing() {
        assert_eq!(ByteSize::from_str("1024").unwrap().0, 1024);
        assert_eq!(ByteSize::from_str("10KB").unwrap().0, 10 * 1024);
        assert_eq!(
            ByteSize::from_str("5.5MB").unwrap().0,
            (5.5 * 1024.0 * 1024.0) as usize
        );
        assert_eq!(ByteSize::from_str("2GB").unwrap().0, 2 * 1024 * 1024 * 1024);
        assert_eq!(ByteSize::from_str("100 B").unwrap().0, 100);
    }

    #[test]
    fn test_byte_size_display() {
        assert_eq!(ByteSize(512).to_string(), "512B");
        assert_eq!(ByteSize(2048).to_string(), "2.00KB");
        assert_eq!(ByteSize(1024 * 1024).to_string(), "1.00MB");
        assert_eq!(ByteSize(1024 * 1024 * 1024).to_string(), "1.00GB");
    }

    #[test]
    fn test_trace_id_format() {
        assert_eq!(TraceIdFormat::from_str_loose("uuid"), TraceIdFormat::Uuid);
        assert_eq!(
            TraceIdFormat::from_str_loose("tinyflake"),
            TraceIdFormat::TinyFlake
        );
        assert_eq!(
            TraceIdFormat::from_str_loose("unknown"),
            TraceIdFormat::TinyFlake
        );
    }
}
