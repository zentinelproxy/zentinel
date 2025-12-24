//! Internal type definitions for the proxy crate
//!
//! Re-exports common types and defines proxy-specific types.

// Re-export common error types
pub use sentinel_common::errors::{SentinelError, SentinelResult};

/// Internal upstream target representation for load balancers
///
/// This is a simplified representation used internally by load balancers,
/// separate from the user-facing config UpstreamTarget.
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    /// Target IP address or hostname
    pub address: String,
    /// Target port
    pub port: u16,
    /// Weight for weighted load balancing
    pub weight: u32,
}

impl UpstreamTarget {
    /// Create a new upstream target
    pub fn new(address: impl Into<String>, port: u16, weight: u32) -> Self {
        Self {
            address: address.into(),
            port,
            weight,
        }
    }

    /// Create from a "host:port" string with default weight
    pub fn from_address(addr: &str) -> Option<Self> {
        let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            let port = parts[0].parse().ok()?;
            let address = parts[1].to_string();
            Some(Self {
                address,
                port,
                weight: 100,
            })
        } else {
            None
        }
    }

    /// Convert from config UpstreamTarget
    pub fn from_config(config: &sentinel_config::UpstreamTarget) -> Option<Self> {
        Self::from_address(&config.address).map(|mut t| {
            t.weight = config.weight;
            t
        })
    }

    /// Get the full address string
    pub fn full_address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}
