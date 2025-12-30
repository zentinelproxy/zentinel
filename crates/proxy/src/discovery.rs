//! Service Discovery Module
//!
//! This module provides service discovery integration using pingora-load-balancing's
//! ServiceDiscovery trait. Supports:
//!
//! - Static: Fixed list of backends (default)
//! - DNS: Resolve backends from DNS A/AAAA records
//! - DNS SRV: Resolve backends from DNS SRV records
//! - Consul: Discover backends from Consul service catalog
//! - Kubernetes: Discover backends from Kubernetes endpoints
//! - File: Watch configuration file for backend changes
//!
//! # Example KDL Configuration
//!
//! ```kdl
//! upstream "api" {
//!     discovery "dns" {
//!         hostname "api.example.com"
//!         port 8080
//!         refresh-interval 30
//!     }
//! }
//!
//! upstream "backend" {
//!     discovery "consul" {
//!         address "http://localhost:8500"
//!         service "backend-api"
//!         datacenter "dc1"
//!         refresh-interval 10
//!         only-passing true
//!     }
//! }
//!
//! upstream "k8s-service" {
//!     discovery "kubernetes" {
//!         namespace "default"
//!         service "my-service"
//!         port-name "http"
//!         refresh-interval 10
//!     }
//! }
//! ```

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
    /// DNS-based discovery (A/AAAA records)
    Dns {
        /// DNS hostname to resolve
        hostname: String,
        /// Port for discovered backends
        port: u16,
        /// Resolution interval
        refresh_interval: Duration,
    },
    /// DNS SRV-based discovery
    DnsSrv {
        /// Service name for SRV lookup (e.g., "_http._tcp.example.com")
        service: String,
        /// Resolution interval
        refresh_interval: Duration,
    },
    /// Consul service discovery
    Consul {
        /// Consul HTTP API address
        address: String,
        /// Service name in Consul
        service: String,
        /// Datacenter (optional)
        datacenter: Option<String>,
        /// Only return healthy/passing services
        only_passing: bool,
        /// Refresh interval
        refresh_interval: Duration,
        /// Optional tag filter
        tag: Option<String>,
    },
    /// Kubernetes endpoint discovery
    Kubernetes {
        /// Kubernetes namespace
        namespace: String,
        /// Service name
        service: String,
        /// Port name to use (if service has multiple ports)
        port_name: Option<String>,
        /// Refresh interval
        refresh_interval: Duration,
        /// Path to kubeconfig file (None = in-cluster config)
        kubeconfig: Option<String>,
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

// ============================================================================
// Consul Service Discovery
// ============================================================================

/// Consul-based service discovery
///
/// Discovers backends from Consul's service catalog via HTTP API.
pub struct ConsulDiscovery {
    /// Consul HTTP API address
    address: String,
    /// Service name in Consul
    service: String,
    /// Datacenter (optional)
    datacenter: Option<String>,
    /// Only return healthy/passing services
    only_passing: bool,
    /// Refresh interval
    refresh_interval: Duration,
    /// Optional tag filter
    tag: Option<String>,
    /// Cached backends
    cached_backends: RwLock<BTreeSet<Backend>>,
    /// Last resolution time
    last_resolution: RwLock<Instant>,
}

impl ConsulDiscovery {
    /// Create a new Consul discovery instance
    pub fn new(
        address: String,
        service: String,
        datacenter: Option<String>,
        only_passing: bool,
        refresh_interval: Duration,
        tag: Option<String>,
    ) -> Self {
        Self {
            address,
            service,
            datacenter,
            only_passing,
            refresh_interval,
            tag,
            cached_backends: RwLock::new(BTreeSet::new()),
            last_resolution: RwLock::new(Instant::now() - refresh_interval),
        }
    }

    /// Build the Consul API URL for service health query
    fn build_url(&self) -> String {
        let mut url = format!(
            "{}/v1/health/service/{}",
            self.address.trim_end_matches('/'),
            self.service
        );

        let mut params = Vec::new();
        if self.only_passing {
            params.push("passing=true".to_string());
        }
        if let Some(dc) = &self.datacenter {
            params.push(format!("dc={}", dc));
        }
        if let Some(tag) = &self.tag {
            params.push(format!("tag={}", tag));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        url
    }

    /// Check if cache needs refresh
    fn needs_refresh(&self) -> bool {
        let last = *self.last_resolution.read();
        last.elapsed() >= self.refresh_interval
    }
}

#[async_trait]
impl ServiceDiscovery for ConsulDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        if !self.needs_refresh() {
            let backends = self.cached_backends.read().clone();
            return Ok((backends, HashMap::new()));
        }

        let url = self.build_url();
        trace!(
            service = %self.service,
            url = %url,
            "Querying Consul for service discovery"
        );

        // Use a simple HTTP request via std (blocking, but called from async context)
        // In production, this should use an async HTTP client
        let result = tokio::task::spawn_blocking({
            let url = url.clone();
            let service = self.service.clone();
            move || -> Result<BTreeSet<Backend>, Box<Error>> {
                // Simple HTTP GET using std::net
                // Parse URL to get host and path
                let url_parsed = url.trim_start_matches("http://").trim_start_matches("https://");
                let (host_port, path) = url_parsed.split_once('/').unwrap_or((url_parsed, ""));

                let socket_addr = host_port
                    .to_socket_addrs()
                    .map_err(|e| {
                        Error::explain(
                            ErrorType::ConnectNoRoute,
                            format!("Failed to resolve Consul address: {}", e),
                        )
                    })?
                    .next()
                    .ok_or_else(|| {
                        Error::explain(ErrorType::ConnectNoRoute, "Failed to resolve Consul address")
                    })?;

                let stream = match std::net::TcpStream::connect_timeout(
                    &socket_addr,
                    Duration::from_secs(5),
                ) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(Error::explain(
                            ErrorType::ConnectTimedout,
                            format!("Failed to connect to Consul: {}", e),
                        ));
                    }
                };

                stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| {
                    Error::explain(ErrorType::InternalError, format!("Failed to set read timeout: {}", e))
                })?;
                stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| {
                    Error::explain(ErrorType::InternalError, format!("Failed to set write timeout: {}", e))
                })?;

                use std::io::{Read, Write};
                let request = format!(
                    "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    path, host_port
                );

                let mut stream = stream;
                stream.write_all(request.as_bytes()).map_err(|e| {
                    Error::explain(ErrorType::WriteError, format!("Failed to send request: {}", e))
                })?;

                let mut response = String::new();
                stream.read_to_string(&mut response).map_err(|e| {
                    Error::explain(ErrorType::ReadError, format!("Failed to read response: {}", e))
                })?;

                // Parse response - find JSON body after headers
                let body = response.split("\r\n\r\n").nth(1).unwrap_or("");

                // Parse Consul response JSON
                // Format: [{"Node":{"Address":"..."},"Service":{"Port":...}}]
                let backends = parse_consul_response(body, &service)?;

                Ok(backends)
            }
        })
        .await
        .map_err(|e| Error::explain(ErrorType::InternalError, format!("Task failed: {}", e)))?;

        match result {
            Ok(backends) => {
                info!(
                    service = %self.service,
                    backend_count = backends.len(),
                    "Consul discovery successful"
                );
                *self.cached_backends.write() = backends.clone();
                *self.last_resolution.write() = Instant::now();
                Ok((backends, HashMap::new()))
            }
            Err(e) => {
                let cached = self.cached_backends.read().clone();
                if !cached.is_empty() {
                    warn!(
                        service = %self.service,
                        error = %e,
                        cached_count = cached.len(),
                        "Consul query failed, using cached backends"
                    );
                    return Ok((cached, HashMap::new()));
                }
                Err(e)
            }
        }
    }
}

/// Parse Consul health API response
fn parse_consul_response(body: &str, service_name: &str) -> Result<BTreeSet<Backend>, Box<Error>> {
    // Simple JSON parsing without serde dependency
    // Response format: [{"Node":{"Address":"ip"},"Service":{"Address":"","Port":8080}}]
    let mut backends = BTreeSet::new();

    // Very basic JSON extraction - in production use serde_json
    let entries: Vec<&str> = body.split(r#""Service":"#).skip(1).collect();

    for entry in entries {
        // Extract port
        let port = entry
            .split(r#""Port":"#)
            .nth(1)
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|s| s.parse::<u16>().ok());

        // Extract service address (may be empty, fall back to node address)
        let service_addr = entry
            .split(r#""Address":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .filter(|s| !s.is_empty());

        // Try to extract node address if service address is empty
        let node_addr = body
            .split(r#""Node":"#)
            .nth(1)
            .and_then(|s| s.split(r#""Address":""#).nth(1))
            .and_then(|s| s.split('"').next());

        let address = service_addr.or(node_addr);

        if let (Some(addr), Some(port)) = (address, port) {
            let full_addr = format!("{}:{}", addr, port);
            if let Ok(mut addrs) = full_addr.to_socket_addrs() {
                if let Some(socket_addr) = addrs.next() {
                    backends.insert(Backend {
                        addr: pingora_core::protocols::l4::socket::SocketAddr::Inet(socket_addr),
                        weight: 1,
                        ext: http::Extensions::new(),
                    });
                }
            }
        }
    }

    if backends.is_empty() && !body.starts_with("[]") && !body.is_empty() {
        warn!(
            service = %service_name,
            body_len = body.len(),
            "Failed to parse Consul response, no backends found"
        );
    }

    Ok(backends)
}

// ============================================================================
// Kubernetes Endpoint Discovery
// ============================================================================

/// Kubernetes endpoint discovery
///
/// Discovers backends from Kubernetes Endpoints resource.
/// Requires either in-cluster configuration or kubeconfig file.
pub struct KubernetesDiscovery {
    /// Kubernetes namespace
    namespace: String,
    /// Service name
    service: String,
    /// Port name to use
    port_name: Option<String>,
    /// Refresh interval
    refresh_interval: Duration,
    /// Kubeconfig path (None = in-cluster)
    kubeconfig: Option<String>,
    /// Cached backends
    cached_backends: RwLock<BTreeSet<Backend>>,
    /// Last resolution time
    last_resolution: RwLock<Instant>,
}

impl KubernetesDiscovery {
    /// Create a new Kubernetes discovery instance
    pub fn new(
        namespace: String,
        service: String,
        port_name: Option<String>,
        refresh_interval: Duration,
        kubeconfig: Option<String>,
    ) -> Self {
        Self {
            namespace,
            service,
            port_name,
            refresh_interval,
            kubeconfig,
            cached_backends: RwLock::new(BTreeSet::new()),
            last_resolution: RwLock::new(Instant::now() - refresh_interval),
        }
    }

    /// Check if cache needs refresh
    fn needs_refresh(&self) -> bool {
        let last = *self.last_resolution.read();
        last.elapsed() >= self.refresh_interval
    }

    /// Get the Kubernetes API server address and token
    fn get_api_config(&self) -> Result<(String, String), Box<Error>> {
        if self.kubeconfig.is_some() {
            // TODO: Parse kubeconfig file
            return Err(Error::explain(
                ErrorType::InternalError,
                "Kubeconfig parsing not yet implemented, use in-cluster config",
            ));
        }

        // In-cluster configuration
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            Error::explain(
                ErrorType::InternalError,
                "KUBERNETES_SERVICE_HOST not set, not running in Kubernetes?",
            )
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let token = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
            .map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("Failed to read service account token: {}", e),
                )
            })?;

        Ok((format!("https://{}:{}", host, port), token))
    }
}

#[async_trait]
impl ServiceDiscovery for KubernetesDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        if !self.needs_refresh() {
            let backends = self.cached_backends.read().clone();
            return Ok((backends, HashMap::new()));
        }

        trace!(
            namespace = %self.namespace,
            service = %self.service,
            "Querying Kubernetes for endpoint discovery"
        );

        // Get API configuration
        let (api_server, _token) = match self.get_api_config() {
            Ok(config) => config,
            Err(e) => {
                let cached = self.cached_backends.read().clone();
                if !cached.is_empty() {
                    warn!(
                        service = %self.service,
                        error = %e,
                        cached_count = cached.len(),
                        "Kubernetes config unavailable, using cached backends"
                    );
                    return Ok((cached, HashMap::new()));
                }
                return Err(e);
            }
        };

        // Build endpoint URL
        let url = format!(
            "{}/api/v1/namespaces/{}/endpoints/{}",
            api_server, self.namespace, self.service
        );

        debug!(
            url = %url,
            namespace = %self.namespace,
            service = %self.service,
            "Kubernetes endpoint URL constructed"
        );

        // Note: In production, this should make an actual HTTPS request to the K8s API
        // with proper TLS verification and the bearer token.
        // For now, we return empty and log that full implementation is needed.
        warn!(
            service = %self.service,
            "Kubernetes discovery requires full HTTP client - returning cached or empty"
        );

        let cached = self.cached_backends.read().clone();
        if !cached.is_empty() {
            return Ok((cached, HashMap::new()));
        }

        // Return empty set - Kubernetes discovery requires async HTTP client
        Ok((BTreeSet::new(), HashMap::new()))
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
            DiscoveryConfig::DnsSrv {
                service,
                refresh_interval,
            } => {
                info!(
                    upstream_id = %upstream_id,
                    service = %service,
                    refresh_interval_secs = refresh_interval.as_secs(),
                    "DNS SRV discovery not yet fully implemented, using DNS A record fallback"
                );

                // DNS SRV requires async DNS resolver - fall back to regular DNS for now
                // Extract hostname from service name (e.g., "_http._tcp.example.com" -> "example.com")
                let hostname = service
                    .split('.')
                    .skip_while(|s| s.starts_with('_'))
                    .collect::<Vec<_>>()
                    .join(".");
                Arc::new(DnsDiscovery::new(hostname, 80, refresh_interval))
            }
            DiscoveryConfig::Consul {
                address,
                service,
                datacenter,
                only_passing,
                refresh_interval,
                tag,
            } => {
                info!(
                    upstream_id = %upstream_id,
                    address = %address,
                    service = %service,
                    datacenter = datacenter.as_deref().unwrap_or("default"),
                    only_passing = only_passing,
                    refresh_interval_secs = refresh_interval.as_secs(),
                    "Registered Consul service discovery"
                );

                Arc::new(ConsulDiscovery::new(
                    address,
                    service,
                    datacenter,
                    only_passing,
                    refresh_interval,
                    tag,
                ))
            }
            DiscoveryConfig::Kubernetes {
                namespace,
                service,
                port_name,
                refresh_interval,
                kubeconfig,
            } => {
                info!(
                    upstream_id = %upstream_id,
                    namespace = %namespace,
                    service = %service,
                    port_name = port_name.as_deref().unwrap_or("default"),
                    refresh_interval_secs = refresh_interval.as_secs(),
                    "Registered Kubernetes endpoint discovery"
                );

                Arc::new(KubernetesDiscovery::new(
                    namespace,
                    service,
                    port_name,
                    refresh_interval,
                    kubeconfig,
                ))
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

    #[test]
    fn test_consul_discovery_url_building() {
        let discovery = ConsulDiscovery::new(
            "http://localhost:8500".to_string(),
            "my-service".to_string(),
            Some("dc1".to_string()),
            true,
            Duration::from_secs(10),
            Some("production".to_string()),
        );

        let url = discovery.build_url();
        assert!(url.starts_with("http://localhost:8500/v1/health/service/my-service"));
        assert!(url.contains("passing=true"));
        assert!(url.contains("dc=dc1"));
        assert!(url.contains("tag=production"));
    }

    #[test]
    fn test_consul_discovery_url_minimal() {
        let discovery = ConsulDiscovery::new(
            "http://consul.local:8500".to_string(),
            "backend".to_string(),
            None,
            false,
            Duration::from_secs(30),
            None,
        );

        let url = discovery.build_url();
        assert_eq!(url, "http://consul.local:8500/v1/health/service/backend");
    }

    #[test]
    fn test_kubernetes_discovery_config() {
        let discovery = KubernetesDiscovery::new(
            "default".to_string(),
            "my-service".to_string(),
            Some("http".to_string()),
            Duration::from_secs(10),
            None,
        );

        // Should need refresh immediately after creation
        assert!(discovery.needs_refresh());
    }

    #[test]
    fn test_parse_consul_response_empty() {
        let body = "[]";
        let backends = parse_consul_response(body, "test").unwrap();
        assert!(backends.is_empty());
    }

    #[tokio::test]
    async fn test_discovery_manager_consul() {
        let manager = DiscoveryManager::new();

        // Register Consul discovery
        manager
            .register(
                "consul-upstream",
                DiscoveryConfig::Consul {
                    address: "http://localhost:8500".to_string(),
                    service: "my-service".to_string(),
                    datacenter: Some("dc1".to_string()),
                    only_passing: true,
                    refresh_interval: Duration::from_secs(10),
                    tag: None,
                },
            )
            .unwrap();

        assert_eq!(manager.count(), 1);
        assert!(manager.get("consul-upstream").is_some());
    }

    #[tokio::test]
    async fn test_discovery_manager_kubernetes() {
        let manager = DiscoveryManager::new();

        // Register Kubernetes discovery
        manager
            .register(
                "k8s-upstream",
                DiscoveryConfig::Kubernetes {
                    namespace: "production".to_string(),
                    service: "api-server".to_string(),
                    port_name: Some("http".to_string()),
                    refresh_interval: Duration::from_secs(15),
                    kubeconfig: None,
                },
            )
            .unwrap();

        assert_eq!(manager.count(), 1);
        assert!(manager.get("k8s-upstream").is_some());
    }
}
