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
                let url_parsed = url
                    .trim_start_matches("http://")
                    .trim_start_matches("https://");
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
                        Error::explain(
                            ErrorType::ConnectNoRoute,
                            "Failed to resolve Consul address",
                        )
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

                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .map_err(|e| {
                        Error::explain(
                            ErrorType::InternalError,
                            format!("Failed to set read timeout: {}", e),
                        )
                    })?;
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .map_err(|e| {
                        Error::explain(
                            ErrorType::InternalError,
                            format!("Failed to set write timeout: {}", e),
                        )
                    })?;

                use std::io::{Read, Write};
                let request = format!(
                    "GET /{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                    path, host_port
                );

                let mut stream = stream;
                stream.write_all(request.as_bytes()).map_err(|e| {
                    Error::explain(
                        ErrorType::WriteError,
                        format!("Failed to send request: {}", e),
                    )
                })?;

                let mut response = String::new();
                stream.read_to_string(&mut response).map_err(|e| {
                    Error::explain(
                        ErrorType::ReadError,
                        format!("Failed to read response: {}", e),
                    )
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

#[cfg(feature = "kubernetes")]
use crate::kubeconfig::{KubeAuth, Kubeconfig, ResolvedKubeConfig};

/// Kubernetes endpoint discovery
///
/// Discovers backends from Kubernetes Endpoints resource.
/// Requires either in-cluster configuration or kubeconfig file.
///
/// # Authentication Methods
///
/// - **In-cluster**: Uses service account token from `/var/run/secrets/kubernetes.io/serviceaccount/token`
/// - **Kubeconfig**: Parses `~/.kube/config` or specified kubeconfig file for credentials
///
/// # Example KDL Configuration
///
/// ```kdl
/// upstream "k8s-service" {
///     discovery "kubernetes" {
///         namespace "default"
///         service "my-service"
///         port-name "http"
///         refresh-interval 10
///         kubeconfig "~/.kube/config"  // Optional, uses in-cluster if omitted
///     }
/// }
/// ```
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
    /// Cached resolved config (for kubeconfig mode)
    #[cfg(feature = "kubernetes")]
    resolved_config: RwLock<Option<ResolvedKubeConfig>>,
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
            #[cfg(feature = "kubernetes")]
            resolved_config: RwLock::new(None),
        }
    }

    /// Check if cache needs refresh
    fn needs_refresh(&self) -> bool {
        let last = *self.last_resolution.read();
        last.elapsed() >= self.refresh_interval
    }

    /// Get in-cluster configuration (service account token)
    fn get_in_cluster_config(&self) -> Result<(String, String), Box<Error>> {
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

        Ok((
            format!("https://{}:{}", host, port),
            token.trim().to_string(),
        ))
    }

    /// Load and cache kubeconfig
    #[cfg(feature = "kubernetes")]
    fn load_kubeconfig(&self) -> Result<ResolvedKubeConfig, Box<Error>> {
        // Check if we have a cached config
        if let Some(config) = self.resolved_config.read().as_ref() {
            return Ok(config.clone());
        }

        let kubeconfig = if let Some(path) = &self.kubeconfig {
            Kubeconfig::from_file(path).map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("Failed to load kubeconfig from {}: {}", path, e),
                )
            })?
        } else {
            Kubeconfig::from_default_location().map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("Failed to load kubeconfig from default location: {}", e),
                )
            })?
        };

        let resolved = kubeconfig.resolve_current().map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("Failed to resolve kubeconfig context: {}", e),
            )
        })?;

        // Cache the resolved config
        *self.resolved_config.write() = Some(resolved.clone());

        Ok(resolved)
    }
}

/// Kubernetes Endpoints API response structures
#[cfg(feature = "kubernetes")]
mod k8s_types {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct Endpoints {
        pub subsets: Option<Vec<EndpointSubset>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct EndpointSubset {
        pub addresses: Option<Vec<EndpointAddress>>,
        pub ports: Option<Vec<EndpointPort>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct EndpointAddress {
        pub ip: String,
        pub hostname: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct EndpointPort {
        pub name: Option<String>,
        pub port: u16,
        pub protocol: Option<String>,
    }
}

#[cfg(feature = "kubernetes")]
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

        // Determine if we're using kubeconfig or in-cluster config
        let (api_server, auth, ca_cert, skip_verify) = if self.kubeconfig.is_some() {
            let config = self.load_kubeconfig()?;
            (
                config.server,
                config.auth,
                config.ca_cert,
                config.insecure_skip_tls_verify,
            )
        } else {
            // Try in-cluster first
            match self.get_in_cluster_config() {
                Ok((server, token)) => {
                    // In-cluster uses the service account CA
                    let ca =
                        std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt").ok();
                    (server, KubeAuth::Token(token), ca, false)
                }
                Err(e) => {
                    // Fall back to default kubeconfig location
                    debug!(
                        error = %e,
                        "In-cluster config not available, trying default kubeconfig"
                    );
                    let config = self.load_kubeconfig()?;
                    (
                        config.server,
                        config.auth,
                        config.ca_cert,
                        config.insecure_skip_tls_verify,
                    )
                }
            }
        };

        // Build endpoint URL
        let url = format!(
            "{}/api/v1/namespaces/{}/endpoints/{}",
            api_server.trim_end_matches('/'),
            self.namespace,
            self.service
        );

        debug!(
            url = %url,
            namespace = %self.namespace,
            service = %self.service,
            "Fetching Kubernetes endpoints"
        );

        // Build HTTP client with proper TLS configuration
        let client_builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(skip_verify);

        // Add CA certificate if available
        let client_builder = if let Some(ca_data) = ca_cert {
            let cert = reqwest::Certificate::from_pem(&ca_data).map_err(|e| {
                Error::explain(
                    ErrorType::InternalError,
                    format!("Failed to parse CA certificate: {}", e),
                )
            })?;
            client_builder.add_root_certificate(cert)
        } else {
            client_builder
        };

        // Add client certificate auth if needed
        let client_builder = match &auth {
            KubeAuth::ClientCert { cert, key } => {
                // Combine cert and key into identity
                let mut identity_pem = cert.clone();
                identity_pem.extend_from_slice(key);
                let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|e| {
                    Error::explain(
                        ErrorType::InternalError,
                        format!("Failed to create client identity: {}", e),
                    )
                })?;
                client_builder.identity(identity)
            }
            _ => client_builder,
        };

        let client = client_builder.build().map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("Failed to create HTTP client: {}", e),
            )
        })?;

        // Build request with authentication
        let mut request = client.get(&url);
        if let KubeAuth::Token(token) = &auth {
            request = request.bearer_auth(token);
        }

        // Make the request
        let response = request.send().await.map_err(|e| {
            Error::explain(
                ErrorType::ConnectError,
                format!("Failed to connect to Kubernetes API: {}", e),
            )
        })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::explain(
                ErrorType::HTTPStatus(status.as_u16()),
                format!("Kubernetes API returned {}: {}", status, body),
            ));
        }

        // Parse the response
        let endpoints: k8s_types::Endpoints = response.json().await.map_err(|e| {
            Error::explain(
                ErrorType::InternalError,
                format!("Failed to parse Kubernetes endpoints: {}", e),
            )
        })?;

        // Extract backends from endpoints
        let mut backends = BTreeSet::new();
        if let Some(subsets) = endpoints.subsets {
            for subset in subsets {
                // Find the target port
                let target_port = subset.ports.as_ref().and_then(|ports| {
                    if let Some(port_name) = &self.port_name {
                        // Find port by name
                        ports
                            .iter()
                            .find(|p| p.name.as_ref() == Some(port_name))
                            .map(|p| p.port)
                    } else {
                        // Use first port
                        ports.first().map(|p| p.port)
                    }
                });

                if let (Some(addresses), Some(port)) = (subset.addresses, target_port) {
                    for addr in addresses {
                        let socket_addr = format!("{}:{}", addr.ip, port);
                        if let Ok(mut addrs) = socket_addr.to_socket_addrs() {
                            if let Some(socket_addr) = addrs.next() {
                                backends.insert(Backend {
                                    addr: pingora_core::protocols::l4::socket::SocketAddr::Inet(
                                        socket_addr,
                                    ),
                                    weight: 1,
                                    ext: http::Extensions::new(),
                                });
                            }
                        }
                    }
                }
            }
        }

        info!(
            service = %self.service,
            namespace = %self.namespace,
            backend_count = backends.len(),
            "Kubernetes endpoint discovery successful"
        );

        // Update cache
        *self.cached_backends.write() = backends.clone();
        *self.last_resolution.write() = Instant::now();

        Ok((backends, HashMap::new()))
    }
}

// Fallback implementation when kubernetes feature is not enabled
#[cfg(not(feature = "kubernetes"))]
#[async_trait]
impl ServiceDiscovery for KubernetesDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        if !self.needs_refresh() {
            let backends = self.cached_backends.read().clone();
            return Ok((backends, HashMap::new()));
        }

        // Try in-cluster config
        if self.kubeconfig.is_none() {
            if let Ok((_, _)) = self.get_in_cluster_config() {
                warn!(
                    service = %self.service,
                    "Kubernetes discovery requires 'kubernetes' feature flag for full support"
                );
            }
        } else {
            warn!(
                service = %self.service,
                kubeconfig = ?self.kubeconfig,
                "Kubeconfig support requires 'kubernetes' feature flag"
            );
        }

        let cached = self.cached_backends.read().clone();
        Ok((cached, HashMap::new()))
    }
}

// ============================================================================
// File-based Service Discovery
// ============================================================================

/// File-based service discovery
///
/// Discovers backends by reading a configuration file. The file is watched
/// for changes and backends are reloaded automatically.
///
/// # File Format
///
/// One backend per line:
/// ```text
/// # Comment lines start with #
/// 10.0.0.1:8080
/// 10.0.0.2:8080 weight=2
/// 10.0.0.3:8080 weight=3
///
/// # Empty lines are ignored
/// backend.example.com:8080
/// ```
///
/// # Example KDL Configuration
///
/// ```kdl
/// upstream "dynamic-backend" {
///     discovery "file" {
///         path "/etc/zentinel/backends/api-servers.txt"
///         watch-interval 5
///     }
/// }
/// ```
pub struct FileDiscovery {
    /// Path to the backends file
    path: String,
    /// Watch/refresh interval
    watch_interval: Duration,
    /// Cached backends
    cached_backends: RwLock<BTreeSet<Backend>>,
    /// Last check time
    last_check: RwLock<Instant>,
    /// Last known file modification time
    last_modified: RwLock<Option<std::time::SystemTime>>,
}

impl FileDiscovery {
    /// Create a new file-based discovery instance
    pub fn new(path: String, watch_interval: Duration) -> Self {
        Self {
            path,
            watch_interval,
            cached_backends: RwLock::new(BTreeSet::new()),
            last_check: RwLock::new(Instant::now() - watch_interval),
            last_modified: RwLock::new(None),
        }
    }

    /// Check if we should re-check the file
    fn needs_check(&self) -> bool {
        let last = *self.last_check.read();
        last.elapsed() >= self.watch_interval
    }

    /// Check if file has been modified since last read
    fn file_modified(&self) -> bool {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return true, // If we can't read metadata, try to read the file
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(_) => return true,
        };

        let last_known = *self.last_modified.read();
        match last_known {
            Some(last) => modified > last,
            None => true, // First check
        }
    }

    /// Read and parse backends from the file
    fn read_backends(&self) -> Result<BTreeSet<Backend>, Box<Error>> {
        trace!(path = %self.path, "Reading backends from file");

        let content = std::fs::read_to_string(&self.path).map_err(|e| {
            Error::explain(
                ErrorType::ReadError,
                format!("Failed to read backends file '{}': {}", self.path, e),
            )
        })?;

        // Update last modified time
        if let Ok(metadata) = std::fs::metadata(&self.path) {
            if let Ok(modified) = metadata.modified() {
                *self.last_modified.write() = Some(modified);
            }
        }

        let mut backends = BTreeSet::new();
        let mut line_num = 0;

        for line in content.lines() {
            line_num += 1;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line: "host:port" or "host:port weight=N"
            let (address, weight) = Self::parse_backend_line(line, line_num)?;

            // Resolve address
            match address.to_socket_addrs() {
                Ok(mut addrs) => {
                    if let Some(socket_addr) = addrs.next() {
                        backends.insert(Backend {
                            addr: pingora_core::protocols::l4::socket::SocketAddr::Inet(
                                socket_addr,
                            ),
                            weight,
                            ext: http::Extensions::new(),
                        });
                        trace!(
                            address = %address,
                            weight = weight,
                            "Added backend from file"
                        );
                    } else {
                        warn!(
                            path = %self.path,
                            line = line_num,
                            address = %address,
                            "Address resolved but no socket address found"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        path = %self.path,
                        line = line_num,
                        address = %address,
                        error = %e,
                        "Failed to resolve backend address, skipping"
                    );
                }
            }
        }

        debug!(
            path = %self.path,
            backend_count = backends.len(),
            "Loaded backends from file"
        );

        Ok(backends)
    }

    /// Parse a single backend line
    ///
    /// Format: `host:port [weight=N]`
    fn parse_backend_line(line: &str, line_num: usize) -> Result<(String, usize), Box<Error>> {
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.is_empty() {
            return Err(Error::explain(
                ErrorType::InternalError,
                format!("Empty backend line at line {}", line_num),
            ));
        }

        let address = parts[0].to_string();
        let mut weight = 1usize;

        // Parse optional weight parameter
        for part in parts.iter().skip(1) {
            if let Some(weight_str) = part.strip_prefix("weight=") {
                weight = weight_str.parse().unwrap_or_else(|_| {
                    warn!(
                        line = line_num,
                        weight = weight_str,
                        "Invalid weight value, using default 1"
                    );
                    1
                });
            }
        }

        Ok((address, weight))
    }
}

#[async_trait]
impl ServiceDiscovery for FileDiscovery {
    async fn discover(&self) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        // Check if we need to refresh
        if self.needs_check() {
            *self.last_check.write() = Instant::now();

            // Check if file has been modified
            if self.file_modified() {
                match self.read_backends() {
                    Ok(backends) => {
                        info!(
                            path = %self.path,
                            backend_count = backends.len(),
                            "File-based discovery updated backends"
                        );
                        *self.cached_backends.write() = backends;
                    }
                    Err(e) => {
                        // Return cached backends on error if available
                        let cached = self.cached_backends.read().clone();
                        if !cached.is_empty() {
                            warn!(
                                path = %self.path,
                                error = %e,
                                cached_count = cached.len(),
                                "File read failed, using cached backends"
                            );
                            return Ok((cached, HashMap::new()));
                        }
                        return Err(e);
                    }
                }
            }
        }

        let backends = self.cached_backends.read().clone();
        Ok((backends, HashMap::new()))
    }
}

// ============================================================================
// Service Discovery Manager
// ============================================================================

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
    pub fn register(&self, upstream_id: &str, config: DiscoveryConfig) -> Result<(), Box<Error>> {
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
            DiscoveryConfig::File {
                path,
                watch_interval,
            } => {
                info!(
                    upstream_id = %upstream_id,
                    path = %path,
                    watch_interval_secs = watch_interval.as_secs(),
                    "Registered file-based service discovery"
                );

                Arc::new(FileDiscovery::new(path, watch_interval))
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

    // ========================================================================
    // File-based Discovery Tests
    // ========================================================================

    #[test]
    fn test_file_discovery_parse_backend_line_simple() {
        let (address, weight) = FileDiscovery::parse_backend_line("127.0.0.1:8080", 1).unwrap();
        assert_eq!(address, "127.0.0.1:8080");
        assert_eq!(weight, 1);
    }

    #[test]
    fn test_file_discovery_parse_backend_line_with_weight() {
        let (address, weight) =
            FileDiscovery::parse_backend_line("10.0.0.1:8080 weight=5", 1).unwrap();
        assert_eq!(address, "10.0.0.1:8080");
        assert_eq!(weight, 5);
    }

    #[test]
    fn test_file_discovery_parse_backend_line_hostname() {
        let (address, weight) =
            FileDiscovery::parse_backend_line("backend.example.com:443 weight=2", 1).unwrap();
        assert_eq!(address, "backend.example.com:443");
        assert_eq!(weight, 2);
    }

    #[test]
    fn test_file_discovery_needs_check() {
        let discovery = FileDiscovery::new(
            "/nonexistent/path.txt".to_string(),
            Duration::from_secs(0), // Immediate refresh
        );

        // Should need check immediately after creation
        assert!(discovery.needs_check());
    }

    #[tokio::test]
    async fn test_file_discovery_with_temp_file() {
        use std::io::Write;

        // Create temp file with backend addresses
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("backends.txt");

        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "# Backend servers").unwrap();
            writeln!(file, "127.0.0.1:8080").unwrap();
            writeln!(file, "127.0.0.1:8081 weight=2").unwrap();
            writeln!(file).unwrap(); // Empty line
            writeln!(file, "127.0.0.1:8082 weight=3").unwrap();
        }

        let discovery = FileDiscovery::new(
            file_path.to_string_lossy().to_string(),
            Duration::from_secs(1),
        );

        // Discover backends
        let (backends, _) = discovery.discover().await.unwrap();

        assert_eq!(backends.len(), 3);

        // Verify weights are preserved
        let weights: Vec<usize> = backends.iter().map(|b| b.weight).collect();
        assert!(weights.contains(&1)); // Default weight
        assert!(weights.contains(&2));
        assert!(weights.contains(&3));
    }

    #[tokio::test]
    async fn test_file_discovery_missing_file_uses_cache() {
        use std::io::Write;

        // Create temp file first
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("backends.txt");

        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "127.0.0.1:8080").unwrap();
        }

        let discovery = FileDiscovery::new(
            file_path.to_string_lossy().to_string(),
            Duration::from_secs(0), // Immediate refresh
        );

        // Initial discovery
        let (backends, _) = discovery.discover().await.unwrap();
        assert_eq!(backends.len(), 1);

        // Delete the file
        std::fs::remove_file(&file_path).unwrap();

        // Wait a bit to ensure needs_check returns true
        std::thread::sleep(Duration::from_millis(10));

        // Discovery should use cached backends
        let (backends, _) = discovery.discover().await.unwrap();
        assert_eq!(backends.len(), 1);
    }

    #[tokio::test]
    async fn test_file_discovery_hot_reload() {
        use std::io::Write;

        // Create temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("backends.txt");

        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "127.0.0.1:8080").unwrap();
        }

        let discovery = FileDiscovery::new(
            file_path.to_string_lossy().to_string(),
            Duration::from_millis(10), // Short interval for test
        );

        // Initial discovery
        let (backends, _) = discovery.discover().await.unwrap();
        assert_eq!(backends.len(), 1);

        // Wait for watch interval
        std::thread::sleep(Duration::from_millis(50));

        // Update the file
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "127.0.0.1:8080").unwrap();
            writeln!(file, "127.0.0.1:8081").unwrap();
            writeln!(file, "127.0.0.1:8082").unwrap();
        }

        // Discover again - should pick up changes
        let (backends, _) = discovery.discover().await.unwrap();
        assert_eq!(backends.len(), 3);
    }

    #[tokio::test]
    async fn test_discovery_manager_file() {
        use std::io::Write;

        // Create temp file
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("backends.txt");

        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            writeln!(file, "127.0.0.1:8080").unwrap();
            writeln!(file, "127.0.0.1:8081").unwrap();
        }

        let manager = DiscoveryManager::new();

        // Register file-based discovery
        manager
            .register(
                "file-upstream",
                DiscoveryConfig::File {
                    path: file_path.to_string_lossy().to_string(),
                    watch_interval: Duration::from_secs(5),
                },
            )
            .unwrap();

        assert_eq!(manager.count(), 1);
        assert!(manager.get("file-upstream").is_some());

        // Discover backends
        let result = manager.discover("file-upstream").await;
        assert!(result.is_some());
        let (backends, _) = result.unwrap().unwrap();
        assert_eq!(backends.len(), 2);
    }
}
