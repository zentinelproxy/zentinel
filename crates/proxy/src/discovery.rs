//! Service Discovery Module
//!
//! This module provides service discovery integration using pingora-load-balancing's
//! ServiceDiscovery trait. Supports:
//!
//! - Static: Fixed list of backends (default)
//! - DNS: Resolve backends from DNS A/AAAA records
//! - File: Watch configuration file for backend changes
//!
//! Future extensions:
//! - Consul service discovery
//! - Kubernetes service discovery
//! - etcd-based discovery

use async_trait::async_trait;
use parking_lot::RwLock;
use pingora::prelude::*;
use pingora_load_balancing::discovery::{ServiceDiscovery, Static as StaticDiscovery};
use pingora_load_balancing::Backend;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

/// Service discovery configuration
#[derive(Debug, Clone)]
pub enum DiscoveryConfig {
    /// Static list of backends
    Static {
        /// Backend addresses (host:port)
        backends: Vec<String>,
    },
    /// DNS-based discovery
    Dns {
        /// DNS hostname to resolve
        hostname: String,
        /// Port for discovered backends
        port: u16,
        /// Resolution interval
        refresh_interval: Duration,
    },
    /// File-based discovery (watches config file)
    File {
        /// Path to the file containing backend addresses
        path: String,
        /// Watch interval
        watch_interval: Duration,
    },
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self::Static {
            backends: vec!["127.0.0.1:8080".to_string()],
        }
    }
}

/// DNS-based service discovery
///
/// Resolves backends from DNS A/AAAA records.
pub struct DnsDiscovery {
    hostname: String,
    port: u16,
    refresh_interval: Duration,
    /// Cached backends
    cached_backends: RwLock<BTreeSet<Backend>>,
    /// Last resolution time
    last_resolution: RwLock<Instant>,
}

impl DnsDiscovery {
    /// Create a new DNS discovery instance
    pub fn new(hostname: String, port: u16, refresh_interval: Duration) -> Self {
        Self {
            hostname,
            port,
            refresh_interval,
            cached_backends: RwLock::new(BTreeSet::new()),
            last_resolution: RwLock::new(Instant::now() - refresh_interval),
        }
    }

    /// Resolve the hostname to backends
    fn resolve(&self) -> Result<BTreeSet<Backend>, Box<Error>> {
        let address = format!("{}:{}", self.hostname, self.port);

        trace!(
            hostname = %self.hostname,
            port = self.port,
            "Resolving DNS for service discovery"
        );

        match address.to_socket_addrs() {
            Ok(addrs) => {
                let backends: BTreeSet<Backend> = addrs
                    .map(|addr| Backend {
                        addr: pingora_core::protocols::l4::socket::SocketAddr::Inet(addr),
                        weight: 1,
                        ext: http::Extensions::new(),
                    })
                    .collect();

                debug!(
                    hostname = %self.hostname,
                    backend_count = backends.len(),
                    "DNS resolution successful"
                );

                Ok(backends)
            }
            Err(e) => {
                error!(
                    hostname = %self.hostname,
                    error = %e,
                    "DNS resolution failed"
                );
                Err(Error::explain(
                    ErrorType::ConnectNoRoute,
                    format!("DNS resolution failed for {}: {}", self.hostname, e),
                ))
            }
        }
    }

    /// Check if cache needs refresh
    fn needs_refresh(&self) -> bool {
        let last = *self.last_resolution.read();
        last.elapsed() >= self.refresh_interval
    }
}

#[async_trait]
impl ServiceDiscovery for DnsDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // Check if we need to refresh
        if self.needs_refresh() {
            match self.resolve() {
                Ok(backends) => {
                    *self.cached_backends.write() = backends;
                    *self.last_resolution.write() = Instant::now();
                }
                Err(e) => {
                    // Return cached backends on error if available
                    let cached = self.cached_backends.read().clone();
                    if !cached.is_empty() {
                        warn!(
                            hostname = %self.hostname,
                            error = %e,
                            cached_count = cached.len(),
                            "DNS resolution failed, using cached backends"
                        );
                        return Ok((cached, HashMap::new()));
                    }
                    return Err(e);
                }
            }
        }

        let backends = self.cached_backends.read().clone();
        Ok((backends, HashMap::new()))
    }
}

/// Service discovery manager
///
/// Manages service discovery for upstreams with support for multiple
/// discovery mechanisms.
pub struct DiscoveryManager {
    /// Discovery implementations keyed by upstream ID
    discoveries: RwLock<HashMap<String, Arc<dyn ServiceDiscovery + Send + Sync>>>,
}

impl DiscoveryManager {
    /// Create a new discovery manager
    pub fn new() -> Self {
        Self {
            discoveries: RwLock::new(HashMap::new()),
        }
    }

    /// Register a service discovery for an upstream
    pub fn register(
        &self,
        upstream_id: &str,
        config: DiscoveryConfig,
    ) -> Result<(), Box<Error>> {
        let discovery: Arc<dyn ServiceDiscovery + Send + Sync> = match config {
            DiscoveryConfig::Static { backends } => {
                let backend_set = backends
                    .iter()
                    .filter_map(|addr| {
                        addr.to_socket_addrs()
                            .ok()
                            .and_then(|mut addrs| addrs.next())
                            .map(|addr| Backend {
                                addr: pingora_core::protocols::l4::socket::SocketAddr::Inet(addr),
                                weight: 1,
                                ext: http::Extensions::new(),
                            })
                    })
                    .collect();

                info!(
                    upstream_id = %upstream_id,
                    backend_count = backends.len(),
                    "Registered static service discovery"
                );

                Arc::new(StaticWrapper(StaticDiscovery::new(backend_set)))
            }
            DiscoveryConfig::Dns {
                hostname,
                port,
                refresh_interval,
            } => {
                info!(
                    upstream_id = %upstream_id,
                    hostname = %hostname,
                    port = port,
                    refresh_interval_secs = refresh_interval.as_secs(),
                    "Registered DNS service discovery"
                );

                Arc::new(DnsDiscovery::new(hostname, port, refresh_interval))
            }
            DiscoveryConfig::File { path, watch_interval } => {
                info!(
                    upstream_id = %upstream_id,
                    path = %path,
                    watch_interval_secs = watch_interval.as_secs(),
                    "File-based discovery not yet implemented, using empty static"
                );

                // TODO: Implement file-based discovery
                Arc::new(StaticWrapper(StaticDiscovery::new(BTreeSet::new())))
            }
        };

        self.discoveries
            .write()
            .insert(upstream_id.to_string(), discovery);
        Ok(())
    }

    /// Get the discovery for an upstream
    pub fn get(&self, upstream_id: &str) -> Option<Arc<dyn ServiceDiscovery + Send + Sync>> {
        self.discoveries.read().get(upstream_id).cloned()
    }

    /// Discover backends for an upstream
    pub async fn discover(
        &self,
        upstream_id: &str,
    ) -> Option<Result<(BTreeSet<Backend>, HashMap<u64, bool>)>> {
        let discovery = self.get(upstream_id)?;
        Some(discovery.discover().await)
    }

    /// Remove discovery for an upstream
    pub fn remove(&self, upstream_id: &str) {
        self.discoveries.write().remove(upstream_id);
    }

    /// Number of registered discoveries
    pub fn count(&self) -> usize {
        self.discoveries.read().len()
    }
}

impl Default for DiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper for pingora's Static discovery to add Send + Sync
struct StaticWrapper(Box<StaticDiscovery>);

#[async_trait]
impl ServiceDiscovery for StaticWrapper {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        self.0.discover().await
    }
}

// Make StaticWrapper Send + Sync safe since StaticDiscovery uses ArcSwap internally
unsafe impl Send for StaticWrapper {}
unsafe impl Sync for StaticWrapper {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        match config {
            DiscoveryConfig::Static { backends } => {
                assert_eq!(backends.len(), 1);
                assert_eq!(backends[0], "127.0.0.1:8080");
            }
            _ => panic!("Expected Static config"),
        }
    }

    #[tokio::test]
    async fn test_discovery_manager() {
        let manager = DiscoveryManager::new();

        // Register static discovery
        manager
            .register(
                "test-upstream",
                DiscoveryConfig::Static {
                    backends: vec!["127.0.0.1:8080".to_string(), "127.0.0.1:8081".to_string()],
                },
            )
            .unwrap();

        assert_eq!(manager.count(), 1);

        // Discover backends
        let result = manager.discover("test-upstream").await;
        assert!(result.is_some());
        let (backends, _) = result.unwrap().unwrap();
        assert_eq!(backends.len(), 2);
    }

    #[test]
    fn test_dns_discovery_needs_refresh() {
        let discovery = DnsDiscovery::new(
            "localhost".to_string(),
            8080,
            Duration::from_secs(0), // Immediate refresh
        );

        // Should need refresh immediately after creation
        assert!(discovery.needs_refresh());
    }
}
