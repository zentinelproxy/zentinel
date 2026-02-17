//! Agent client for communicating with external agents.
//!
//! Supports three transport mechanisms:
//! - Unix domain sockets (length-prefixed JSON)
//! - gRPC (Protocol Buffers over HTTP/2, with optional TLS)
//! - HTTP REST (JSON over HTTP/1.1 or HTTP/2, with optional TLS)

use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tracing::{debug, error, trace, warn};

use crate::errors::AgentProtocolError;
use crate::grpc::{self, agent_processor_client::AgentProcessorClient};
use crate::protocol::{
    AgentRequest, AgentResponse, AuditMetadata, BodyMutation, Decision, EventType, HeaderOp,
    RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent, RequestMetadata,
    ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketDecision, WebSocketFrameEvent,
    MAX_MESSAGE_SIZE, PROTOCOL_VERSION,
};

/// TLS configuration for gRPC agent connections
#[derive(Debug, Clone, Default)]
pub struct GrpcTlsConfig {
    /// Skip certificate verification (DANGEROUS - only for testing)
    pub insecure_skip_verify: bool,
    /// CA certificate PEM data for verifying the server
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client certificate PEM data for mTLS
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client key PEM data for mTLS
    pub client_key_pem: Option<Vec<u8>>,
    /// Domain name to use for TLS SNI and certificate validation
    pub domain_name: Option<String>,
}

impl GrpcTlsConfig {
    /// Create a new TLS config builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Load CA certificate from a file
    pub async fn with_ca_cert_file(
        mut self,
        path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        self.ca_cert_pem = Some(tokio::fs::read(path).await?);
        Ok(self)
    }

    /// Set CA certificate from PEM data
    pub fn with_ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Load client certificate and key from files (for mTLS)
    pub async fn with_client_cert_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        self.client_cert_pem = Some(tokio::fs::read(cert_path).await?);
        self.client_key_pem = Some(tokio::fs::read(key_path).await?);
        Ok(self)
    }

    /// Set client certificate and key from PEM data (for mTLS)
    pub fn with_client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_cert_pem = Some(cert_pem.into());
        self.client_key_pem = Some(key_pem.into());
        self
    }

    /// Set the domain name for TLS SNI and certificate validation
    pub fn with_domain_name(mut self, domain: impl Into<String>) -> Self {
        self.domain_name = Some(domain.into());
        self
    }

    /// Skip certificate verification (DANGEROUS - only for testing)
    pub fn with_insecure_skip_verify(mut self) -> Self {
        self.insecure_skip_verify = true;
        self
    }
}

/// TLS configuration for HTTP agent connections
#[derive(Debug, Clone, Default)]
pub struct HttpTlsConfig {
    /// Skip certificate verification (DANGEROUS - only for testing)
    pub insecure_skip_verify: bool,
    /// CA certificate PEM data for verifying the server
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Client certificate PEM data for mTLS
    pub client_cert_pem: Option<Vec<u8>>,
    /// Client key PEM data for mTLS
    pub client_key_pem: Option<Vec<u8>>,
}

impl HttpTlsConfig {
    /// Create a new TLS config builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Load CA certificate from a file
    pub async fn with_ca_cert_file(
        mut self,
        path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        self.ca_cert_pem = Some(tokio::fs::read(path).await?);
        Ok(self)
    }

    /// Set CA certificate from PEM data
    pub fn with_ca_cert_pem(mut self, pem: impl Into<Vec<u8>>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    /// Load client certificate and key from files (for mTLS)
    pub async fn with_client_cert_files(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, std::io::Error> {
        self.client_cert_pem = Some(tokio::fs::read(cert_path).await?);
        self.client_key_pem = Some(tokio::fs::read(key_path).await?);
        Ok(self)
    }

    /// Set client certificate and key from PEM data (for mTLS)
    pub fn with_client_identity(
        mut self,
        cert_pem: impl Into<Vec<u8>>,
        key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        self.client_cert_pem = Some(cert_pem.into());
        self.client_key_pem = Some(key_pem.into());
        self
    }

    /// Skip certificate verification (DANGEROUS - only for testing)
    pub fn with_insecure_skip_verify(mut self) -> Self {
        self.insecure_skip_verify = true;
        self
    }
}

/// HTTP connection details
struct HttpConnection {
    /// HTTP client
    client: reqwest::Client,
    /// Base URL for the agent endpoint
    url: String,
}

/// Agent client for communicating with external agents
pub struct AgentClient {
    /// Agent ID
    id: String,
    /// Connection to agent
    connection: AgentConnection,
    /// Timeout for agent calls
    timeout: Duration,
    /// Maximum retries
    #[allow(dead_code)]
    max_retries: u32,
}

/// Agent connection type
enum AgentConnection {
    UnixSocket(UnixStream),
    Grpc(AgentProcessorClient<Channel>),
    Http(Arc<HttpConnection>),
}

impl AgentClient {
    /// Create a new Unix socket agent client
    pub async fn unix_socket(
        id: impl Into<String>,
        path: impl AsRef<std::path::Path>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let path = path.as_ref();

        trace!(
            agent_id = %id,
            socket_path = %path.display(),
            timeout_ms = timeout.as_millis() as u64,
            "Connecting to agent via Unix socket"
        );

        let stream = UnixStream::connect(path).await.map_err(|e| {
            error!(
                agent_id = %id,
                socket_path = %path.display(),
                error = %e,
                "Failed to connect to agent via Unix socket"
            );
            AgentProtocolError::ConnectionFailed(e.to_string())
        })?;

        debug!(
            agent_id = %id,
            socket_path = %path.display(),
            "Connected to agent via Unix socket"
        );

        Ok(Self {
            id,
            connection: AgentConnection::UnixSocket(stream),
            timeout,
            max_retries: 3,
        })
    }

    /// Create a new gRPC agent client
    ///
    /// # Arguments
    /// * `id` - Agent identifier
    /// * `address` - gRPC server address (e.g., "http://localhost:50051")
    /// * `timeout` - Timeout for agent calls
    pub async fn grpc(
        id: impl Into<String>,
        address: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let address = address.into();

        trace!(
            agent_id = %id,
            address = %address,
            timeout_ms = timeout.as_millis() as u64,
            "Connecting to agent via gRPC"
        );

        let channel = Channel::from_shared(address.clone())
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    address = %address,
                    error = %e,
                    "Invalid gRPC URI"
                );
                AgentProtocolError::ConnectionFailed(format!("Invalid URI: {}", e))
            })?
            .timeout(timeout)
            .connect()
            .await
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    address = %address,
                    error = %e,
                    "Failed to connect to agent via gRPC"
                );
                AgentProtocolError::ConnectionFailed(format!("gRPC connect failed: {}", e))
            })?;

        let client = AgentProcessorClient::new(channel);

        debug!(
            agent_id = %id,
            address = %address,
            "Connected to agent via gRPC"
        );

        Ok(Self {
            id,
            connection: AgentConnection::Grpc(client),
            timeout,
            max_retries: 3,
        })
    }

    /// Create a new gRPC agent client with TLS
    ///
    /// # Arguments
    /// * `id` - Agent identifier
    /// * `address` - gRPC server address (e.g., "https://localhost:50051")
    /// * `timeout` - Timeout for agent calls
    /// * `tls_config` - TLS configuration
    pub async fn grpc_tls(
        id: impl Into<String>,
        address: impl Into<String>,
        timeout: Duration,
        tls_config: GrpcTlsConfig,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let address = address.into();

        trace!(
            agent_id = %id,
            address = %address,
            timeout_ms = timeout.as_millis() as u64,
            has_ca_cert = tls_config.ca_cert_pem.is_some(),
            has_client_cert = tls_config.client_cert_pem.is_some(),
            insecure = tls_config.insecure_skip_verify,
            "Connecting to agent via gRPC with TLS"
        );

        // Build TLS config
        let mut client_tls_config = ClientTlsConfig::new();

        // Set domain name for SNI if provided, otherwise extract from address
        if let Some(domain) = &tls_config.domain_name {
            client_tls_config = client_tls_config.domain_name(domain.clone());
        } else {
            // Try to extract domain from address URL
            if let Some(domain) = Self::extract_domain(&address) {
                client_tls_config = client_tls_config.domain_name(domain);
            }
        }

        // Add CA certificate if provided
        if let Some(ca_pem) = &tls_config.ca_cert_pem {
            let ca_cert = Certificate::from_pem(ca_pem);
            client_tls_config = client_tls_config.ca_certificate(ca_cert);
            debug!(
                agent_id = %id,
                "Using custom CA certificate for gRPC TLS"
            );
        }

        // Add client identity for mTLS if provided
        if let (Some(cert_pem), Some(key_pem)) =
            (&tls_config.client_cert_pem, &tls_config.client_key_pem)
        {
            let identity = Identity::from_pem(cert_pem, key_pem);
            client_tls_config = client_tls_config.identity(identity);
            debug!(
                agent_id = %id,
                "Using client certificate for mTLS to gRPC agent"
            );
        }

        // Build channel: use custom connector for insecure_skip_verify,
        // otherwise use tonic's built-in TLS configuration
        let channel = if tls_config.insecure_skip_verify {
            warn!(
                agent_id = %id,
                address = %address,
                "SECURITY WARNING: TLS certificate verification disabled for gRPC agent connection"
            );

            let connector = Self::build_insecure_connector()?;
            Channel::from_shared(address.clone())
                .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Invalid URI: {}", e)))?
                .timeout(timeout)
                .connect_with_connector(connector)
                .await
                .map_err(|e| {
                    error!(
                        agent_id = %id,
                        address = %address,
                        error = %e,
                        "Failed to connect via insecure gRPC TLS"
                    );
                    AgentProtocolError::ConnectionFailed(format!(
                        "gRPC insecure TLS connect failed: {}",
                        e
                    ))
                })?
        } else {
            Channel::from_shared(address.clone())
                .map_err(|e| AgentProtocolError::ConnectionFailed(format!("Invalid URI: {}", e)))?
                .tls_config(client_tls_config)
                .map_err(|e| {
                    error!(
                        agent_id = %id,
                        address = %address,
                        error = %e,
                        "Invalid TLS configuration"
                    );
                    AgentProtocolError::ConnectionFailed(format!("TLS config error: {}", e))
                })?
                .timeout(timeout)
                .connect()
                .await
                .map_err(|e| {
                    error!(
                        agent_id = %id,
                        address = %address,
                        error = %e,
                        "Failed to connect to agent via gRPC with TLS"
                    );
                    AgentProtocolError::ConnectionFailed(format!("gRPC TLS connect failed: {}", e))
                })?
        };

        let client = AgentProcessorClient::new(channel);

        debug!(
            agent_id = %id,
            address = %address,
            "Connected to agent via gRPC with TLS"
        );

        Ok(Self {
            id,
            connection: AgentConnection::Grpc(client),
            timeout,
            max_retries: 3,
        })
    }

    /// Extract domain name from a URL for TLS SNI
    fn extract_domain(address: &str) -> Option<String> {
        // Try to parse as URL and extract host
        let address = address.trim();

        // Handle URLs like "https://example.com:443" or "http://example.com:8080"
        if let Some(rest) = address
            .strip_prefix("https://")
            .or_else(|| address.strip_prefix("http://"))
        {
            // Split off port and path
            let host = rest.split(':').next()?.split('/').next()?;
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }

        None
    }

    /// Build an HTTPS connector that skips certificate verification.
    ///
    /// **DANGEROUS:** Only use this for testing with self-signed certificates.
    fn build_insecure_connector() -> Result<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        AgentProtocolError,
    > {
        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::DigitallySignedStruct;

        /// Certificate verifier that accepts all certificates without validation.
        #[derive(Debug)]
        struct NoVerifier;

        impl ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            }
        }

        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();

        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http2()
            .build();

        Ok(connector)
    }

    /// Create a new HTTP agent client
    ///
    /// # Arguments
    /// * `id` - Agent identifier
    /// * `url` - HTTP endpoint URL (e.g., "http://localhost:8080/agent")
    /// * `timeout` - Timeout for agent calls
    pub async fn http(
        id: impl Into<String>,
        url: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let url = url.into();

        trace!(
            agent_id = %id,
            url = %url,
            timeout_ms = timeout.as_millis() as u64,
            "Creating HTTP agent client"
        );

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| {
                error!(
                    agent_id = %id,
                    url = %url,
                    error = %e,
                    "Failed to create HTTP client"
                );
                AgentProtocolError::ConnectionFailed(format!("HTTP client error: {}", e))
            })?;

        debug!(
            agent_id = %id,
            url = %url,
            "HTTP agent client created"
        );

        Ok(Self {
            id,
            connection: AgentConnection::Http(Arc::new(HttpConnection { client, url })),
            timeout,
            max_retries: 3,
        })
    }

    /// Create a new HTTP agent client with TLS
    ///
    /// # Arguments
    /// * `id` - Agent identifier
    /// * `url` - HTTPS endpoint URL (e.g., `https://agent.internal:8443/agent`)
    /// * `timeout` - Timeout for agent calls
    /// * `tls_config` - TLS configuration
    pub async fn http_tls(
        id: impl Into<String>,
        url: impl Into<String>,
        timeout: Duration,
        tls_config: HttpTlsConfig,
    ) -> Result<Self, AgentProtocolError> {
        let id = id.into();
        let url = url.into();

        trace!(
            agent_id = %id,
            url = %url,
            timeout_ms = timeout.as_millis() as u64,
            has_ca_cert = tls_config.ca_cert_pem.is_some(),
            has_client_cert = tls_config.client_cert_pem.is_some(),
            insecure = tls_config.insecure_skip_verify,
            "Creating HTTP agent client with TLS"
        );

        let mut client_builder = reqwest::Client::builder().timeout(timeout).use_rustls_tls();

        // Add CA certificate if provided
        if let Some(ca_pem) = &tls_config.ca_cert_pem {
            let ca_cert = reqwest::Certificate::from_pem(ca_pem).map_err(|e| {
                error!(
                    agent_id = %id,
                    error = %e,
                    "Failed to parse CA certificate"
                );
                AgentProtocolError::ConnectionFailed(format!("Invalid CA certificate: {}", e))
            })?;
            client_builder = client_builder.add_root_certificate(ca_cert);
            debug!(
                agent_id = %id,
                "Using custom CA certificate for HTTP TLS"
            );
        }

        // Add client identity for mTLS if provided
        if let (Some(cert_pem), Some(key_pem)) =
            (&tls_config.client_cert_pem, &tls_config.client_key_pem)
        {
            // Combine cert and key into identity PEM
            let mut identity_pem = cert_pem.clone();
            identity_pem.extend_from_slice(b"\n");
            identity_pem.extend_from_slice(key_pem);

            let identity = reqwest::Identity::from_pem(&identity_pem).map_err(|e| {
                error!(
                    agent_id = %id,
                    error = %e,
                    "Failed to parse client certificate/key"
                );
                AgentProtocolError::ConnectionFailed(format!("Invalid client certificate: {}", e))
            })?;
            client_builder = client_builder.identity(identity);
            debug!(
                agent_id = %id,
                "Using client certificate for mTLS to HTTP agent"
            );
        }

        // Handle insecure skip verify (dangerous - only for testing)
        if tls_config.insecure_skip_verify {
            warn!(
                agent_id = %id,
                url = %url,
                "SECURITY WARNING: TLS certificate verification disabled for HTTP agent connection"
            );
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        let client = client_builder.build().map_err(|e| {
            error!(
                agent_id = %id,
                url = %url,
                error = %e,
                "Failed to create HTTP TLS client"
            );
            AgentProtocolError::ConnectionFailed(format!("HTTP TLS client error: {}", e))
        })?;

        debug!(
            agent_id = %id,
            url = %url,
            "HTTP agent client created with TLS"
        );

        Ok(Self {
            id,
            connection: AgentConnection::Http(Arc::new(HttpConnection { client, url })),
            timeout,
            max_retries: 3,
        })
    }

    /// Get the agent ID
    #[allow(dead_code)]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Send an event to the agent and get a response
    pub async fn send_event(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        // Clone HTTP connection Arc before match to avoid borrow issues
        let http_conn = if let AgentConnection::Http(conn) = &self.connection {
            Some(Arc::clone(conn))
        } else {
            None
        };

        match &mut self.connection {
            AgentConnection::UnixSocket(_) => {
                self.send_event_unix_socket(event_type, payload).await
            }
            AgentConnection::Grpc(_) => self.send_event_grpc(event_type, payload).await,
            AgentConnection::Http(_) => {
                // Use the cloned Arc
                self.send_event_http(http_conn.unwrap(), event_type, payload)
                    .await
            }
        }
    }

    /// Send event via Unix socket (length-prefixed JSON)
    async fn send_event_unix_socket(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let request = AgentRequest {
            version: PROTOCOL_VERSION,
            event_type,
            payload: serde_json::to_value(payload)
                .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?,
        };

        // Serialize request
        let request_bytes = serde_json::to_vec(&request)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        // Check message size
        if request_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(AgentProtocolError::MessageTooLarge {
                size: request_bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Send with timeout
        let response = tokio::time::timeout(self.timeout, async {
            self.send_raw_unix(&request_bytes).await?;
            self.receive_raw_unix().await
        })
        .await
        .map_err(|_| AgentProtocolError::Timeout(self.timeout))??;

        // Parse response
        let agent_response: AgentResponse = serde_json::from_slice(&response)
            .map_err(|e| AgentProtocolError::InvalidMessage(e.to_string()))?;

        // Verify protocol version
        if agent_response.version != PROTOCOL_VERSION {
            return Err(AgentProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: agent_response.version,
            });
        }

        Ok(agent_response)
    }

    /// Send event via gRPC
    async fn send_event_grpc(
        &mut self,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        // Build request first (doesn't need mutable borrow)
        let grpc_request = Self::build_grpc_request(event_type, payload)?;

        let AgentConnection::Grpc(client) = &mut self.connection else {
            return Err(AgentProtocolError::WrongConnectionType(
                "Expected gRPC connection but found Unix socket".to_string(),
            ));
        };

        // Send with timeout
        let response = tokio::time::timeout(self.timeout, client.process_event(grpc_request))
            .await
            .map_err(|_| AgentProtocolError::Timeout(self.timeout))?
            .map_err(|e| {
                AgentProtocolError::ConnectionFailed(format!("gRPC call failed: {}", e))
            })?;

        // Convert gRPC response to internal format
        Self::convert_grpc_response(response.into_inner())
    }

    /// Send event via HTTP POST (JSON)
    async fn send_event_http(
        &self,
        conn: Arc<HttpConnection>,
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let request = AgentRequest {
            version: PROTOCOL_VERSION,
            event_type,
            payload: serde_json::to_value(payload)
                .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?,
        };

        // Serialize request
        let request_json = serde_json::to_string(&request)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        // Check message size
        if request_json.len() > MAX_MESSAGE_SIZE {
            return Err(AgentProtocolError::MessageTooLarge {
                size: request_json.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        trace!(
            agent_id = %self.id,
            url = %conn.url,
            event_type = ?event_type,
            request_size = request_json.len(),
            "Sending HTTP request to agent"
        );

        // Send HTTP POST request
        let response = conn
            .client
            .post(&conn.url)
            .header("Content-Type", "application/json")
            .header("X-Zentinel-Protocol-Version", PROTOCOL_VERSION.to_string())
            .body(request_json)
            .send()
            .await
            .map_err(|e| {
                error!(
                    agent_id = %self.id,
                    url = %conn.url,
                    error = %e,
                    "HTTP request to agent failed"
                );
                if e.is_timeout() {
                    AgentProtocolError::Timeout(self.timeout)
                } else if e.is_connect() {
                    AgentProtocolError::ConnectionFailed(format!("HTTP connect failed: {}", e))
                } else {
                    AgentProtocolError::ConnectionFailed(format!("HTTP request failed: {}", e))
                }
            })?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!(
                agent_id = %self.id,
                url = %conn.url,
                status = %status,
                body = %body,
                "Agent returned HTTP error"
            );
            return Err(AgentProtocolError::ConnectionFailed(format!(
                "HTTP {} from agent: {}",
                status, body
            )));
        }

        // Parse response
        let response_bytes = response.bytes().await.map_err(|e| {
            AgentProtocolError::ConnectionFailed(format!("Failed to read response body: {}", e))
        })?;

        // Check response size
        if response_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(AgentProtocolError::MessageTooLarge {
                size: response_bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }

        let agent_response: AgentResponse =
            serde_json::from_slice(&response_bytes).map_err(|e| {
                AgentProtocolError::InvalidMessage(format!("Invalid JSON response: {}", e))
            })?;

        // Verify protocol version
        if agent_response.version != PROTOCOL_VERSION {
            return Err(AgentProtocolError::VersionMismatch {
                expected: PROTOCOL_VERSION,
                actual: agent_response.version,
            });
        }

        trace!(
            agent_id = %self.id,
            decision = ?agent_response.decision,
            "Received HTTP response from agent"
        );

        Ok(agent_response)
    }

    /// Build a gRPC request from internal types
    fn build_grpc_request(
        event_type: EventType,
        payload: impl Serialize,
    ) -> Result<grpc::AgentRequest, AgentProtocolError> {
        let payload_json = serde_json::to_value(&payload)
            .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;

        let grpc_event_type = match event_type {
            EventType::Configure => {
                return Err(AgentProtocolError::Serialization(
                    "Configure events are not supported via gRPC".to_string(),
                ))
            }
            EventType::RequestHeaders => grpc::EventType::RequestHeaders,
            EventType::RequestBodyChunk => grpc::EventType::RequestBodyChunk,
            EventType::ResponseHeaders => grpc::EventType::ResponseHeaders,
            EventType::ResponseBodyChunk => grpc::EventType::ResponseBodyChunk,
            EventType::RequestComplete => grpc::EventType::RequestComplete,
            EventType::WebSocketFrame => grpc::EventType::WebsocketFrame,
            EventType::GuardrailInspect => {
                return Err(AgentProtocolError::Serialization(
                    "GuardrailInspect events are not yet supported via gRPC".to_string(),
                ))
            }
        };

        let event = match event_type {
            EventType::Configure => {
                return Err(AgentProtocolError::InvalidMessage(
                    "Configure event should be handled separately".to_string(),
                ));
            }
            EventType::RequestHeaders => {
                let event: RequestHeadersEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestHeaders(grpc::RequestHeadersEvent {
                    metadata: Some(Self::convert_metadata_to_grpc(&event.metadata)),
                    method: event.method,
                    uri: event.uri,
                    headers: event
                        .headers
                        .into_iter()
                        .map(|(k, v)| (k, grpc::HeaderValues { values: v }))
                        .collect(),
                })
            }
            EventType::RequestBodyChunk => {
                let event: RequestBodyChunkEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestBodyChunk(grpc::RequestBodyChunkEvent {
                    correlation_id: event.correlation_id,
                    data: event.data.into_bytes(),
                    is_last: event.is_last,
                    total_size: event.total_size.map(|s| s as u64),
                    chunk_index: event.chunk_index,
                    bytes_received: event.bytes_received as u64,
                })
            }
            EventType::ResponseHeaders => {
                let event: ResponseHeadersEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::ResponseHeaders(grpc::ResponseHeadersEvent {
                    correlation_id: event.correlation_id,
                    status: event.status as u32,
                    headers: event
                        .headers
                        .into_iter()
                        .map(|(k, v)| (k, grpc::HeaderValues { values: v }))
                        .collect(),
                })
            }
            EventType::ResponseBodyChunk => {
                let event: ResponseBodyChunkEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::ResponseBodyChunk(grpc::ResponseBodyChunkEvent {
                    correlation_id: event.correlation_id,
                    data: event.data.into_bytes(),
                    is_last: event.is_last,
                    total_size: event.total_size.map(|s| s as u64),
                    chunk_index: event.chunk_index,
                    bytes_sent: event.bytes_sent as u64,
                })
            }
            EventType::RequestComplete => {
                let event: RequestCompleteEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::RequestComplete(grpc::RequestCompleteEvent {
                    correlation_id: event.correlation_id,
                    status: event.status as u32,
                    duration_ms: event.duration_ms,
                    request_body_size: event.request_body_size as u64,
                    response_body_size: event.response_body_size as u64,
                    upstream_attempts: event.upstream_attempts,
                    error: event.error,
                })
            }
            EventType::WebSocketFrame => {
                use base64::{engine::general_purpose::STANDARD, Engine as _};
                let event: WebSocketFrameEvent = serde_json::from_value(payload_json)
                    .map_err(|e| AgentProtocolError::Serialization(e.to_string()))?;
                grpc::agent_request::Event::WebsocketFrame(grpc::WebSocketFrameEvent {
                    correlation_id: event.correlation_id,
                    opcode: event.opcode,
                    data: STANDARD.decode(&event.data).unwrap_or_default(),
                    client_to_server: event.client_to_server,
                    frame_index: event.frame_index,
                    fin: event.fin,
                    route_id: event.route_id,
                    client_ip: event.client_ip,
                })
            }
            EventType::GuardrailInspect => {
                return Err(AgentProtocolError::InvalidMessage(
                    "GuardrailInspect events are not yet supported via gRPC".to_string(),
                ));
            }
        };

        Ok(grpc::AgentRequest {
            version: PROTOCOL_VERSION,
            event_type: grpc_event_type as i32,
            event: Some(event),
        })
    }

    /// Convert internal metadata to gRPC format
    fn convert_metadata_to_grpc(metadata: &RequestMetadata) -> grpc::RequestMetadata {
        grpc::RequestMetadata {
            correlation_id: metadata.correlation_id.clone(),
            request_id: metadata.request_id.clone(),
            client_ip: metadata.client_ip.clone(),
            client_port: metadata.client_port as u32,
            server_name: metadata.server_name.clone(),
            protocol: metadata.protocol.clone(),
            tls_version: metadata.tls_version.clone(),
            tls_cipher: metadata.tls_cipher.clone(),
            route_id: metadata.route_id.clone(),
            upstream_id: metadata.upstream_id.clone(),
            timestamp: metadata.timestamp.clone(),
            traceparent: metadata.traceparent.clone(),
        }
    }

    /// Convert gRPC response to internal format
    fn convert_grpc_response(
        response: grpc::AgentResponse,
    ) -> Result<AgentResponse, AgentProtocolError> {
        let decision = match response.decision {
            Some(grpc::agent_response::Decision::Allow(_)) => Decision::Allow,
            Some(grpc::agent_response::Decision::Block(b)) => Decision::Block {
                status: b.status as u16,
                body: b.body,
                headers: if b.headers.is_empty() {
                    None
                } else {
                    Some(b.headers)
                },
            },
            Some(grpc::agent_response::Decision::Redirect(r)) => Decision::Redirect {
                url: r.url,
                status: r.status as u16,
            },
            Some(grpc::agent_response::Decision::Challenge(c)) => Decision::Challenge {
                challenge_type: c.challenge_type,
                params: c.params,
            },
            None => Decision::Allow, // Default to allow if no decision
        };

        let request_headers: Vec<HeaderOp> = response
            .request_headers
            .into_iter()
            .filter_map(Self::convert_header_op_from_grpc)
            .collect();

        let response_headers: Vec<HeaderOp> = response
            .response_headers
            .into_iter()
            .filter_map(Self::convert_header_op_from_grpc)
            .collect();

        let audit = response.audit.map(|a| AuditMetadata {
            tags: a.tags,
            rule_ids: a.rule_ids,
            confidence: a.confidence,
            reason_codes: a.reason_codes,
            custom: a
                .custom
                .into_iter()
                .map(|(k, v)| (k, serde_json::Value::String(v)))
                .collect(),
        });

        // Convert body mutations
        let request_body_mutation = response.request_body_mutation.map(|m| BodyMutation {
            data: m.data.map(|d| String::from_utf8_lossy(&d).to_string()),
            chunk_index: m.chunk_index,
        });

        let response_body_mutation = response.response_body_mutation.map(|m| BodyMutation {
            data: m.data.map(|d| String::from_utf8_lossy(&d).to_string()),
            chunk_index: m.chunk_index,
        });

        // Convert WebSocket decision
        let websocket_decision = response
            .websocket_decision
            .map(|ws_decision| match ws_decision {
                grpc::agent_response::WebsocketDecision::WebsocketAllow(_) => {
                    WebSocketDecision::Allow
                }
                grpc::agent_response::WebsocketDecision::WebsocketDrop(_) => {
                    WebSocketDecision::Drop
                }
                grpc::agent_response::WebsocketDecision::WebsocketClose(c) => {
                    WebSocketDecision::Close {
                        code: c.code as u16,
                        reason: c.reason,
                    }
                }
            });

        Ok(AgentResponse {
            version: response.version,
            decision,
            request_headers,
            response_headers,
            routing_metadata: response.routing_metadata,
            audit: audit.unwrap_or_default(),
            needs_more: response.needs_more,
            request_body_mutation,
            response_body_mutation,
            websocket_decision,
        })
    }

    /// Convert gRPC header operation to internal format
    fn convert_header_op_from_grpc(op: grpc::HeaderOp) -> Option<HeaderOp> {
        match op.operation? {
            grpc::header_op::Operation::Set(s) => Some(HeaderOp::Set {
                name: s.name,
                value: s.value,
            }),
            grpc::header_op::Operation::Add(a) => Some(HeaderOp::Add {
                name: a.name,
                value: a.value,
            }),
            grpc::header_op::Operation::Remove(r) => Some(HeaderOp::Remove { name: r.name }),
        }
    }

    /// Send raw bytes to agent (Unix socket only)
    async fn send_raw_unix(&mut self, data: &[u8]) -> Result<(), AgentProtocolError> {
        let AgentConnection::UnixSocket(stream) = &mut self.connection else {
            return Err(AgentProtocolError::WrongConnectionType(
                "Expected Unix socket connection but found gRPC".to_string(),
            ));
        };
        // Write message length (4 bytes, big-endian)
        let len_bytes = (data.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        // Write message data
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(())
    }

    /// Receive raw bytes from agent (Unix socket only)
    async fn receive_raw_unix(&mut self) -> Result<Vec<u8>, AgentProtocolError> {
        let AgentConnection::UnixSocket(stream) = &mut self.connection else {
            return Err(AgentProtocolError::WrongConnectionType(
                "Expected Unix socket connection but found gRPC".to_string(),
            ));
        };
        // Read message length (4 bytes, big-endian)
        let mut len_bytes = [0u8; 4];
        stream.read_exact(&mut len_bytes).await?;
        let message_len = u32::from_be_bytes(len_bytes) as usize;

        // Check message size
        if message_len > MAX_MESSAGE_SIZE {
            return Err(AgentProtocolError::MessageTooLarge {
                size: message_len,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read message data
        let mut buffer = vec![0u8; message_len];
        stream.read_exact(&mut buffer).await?;
        Ok(buffer)
    }

    /// Close the agent connection
    pub async fn close(self) -> Result<(), AgentProtocolError> {
        match self.connection {
            AgentConnection::UnixSocket(mut stream) => {
                stream.shutdown().await?;
                Ok(())
            }
            AgentConnection::Grpc(_) => Ok(()), // gRPC channels close automatically
            AgentConnection::Http(_) => Ok(()), // HTTP clients are stateless, no cleanup needed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_https() {
        assert_eq!(
            AgentClient::extract_domain("https://example.com:443"),
            Some("example.com".to_string())
        );
        assert_eq!(
            AgentClient::extract_domain("https://agent.internal:50051"),
            Some("agent.internal".to_string())
        );
        assert_eq!(
            AgentClient::extract_domain("https://localhost:8080/path"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_domain_http() {
        assert_eq!(
            AgentClient::extract_domain("http://example.com:8080"),
            Some("example.com".to_string())
        );
        assert_eq!(
            AgentClient::extract_domain("http://localhost:50051"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_extract_domain_invalid() {
        assert_eq!(AgentClient::extract_domain("example.com:443"), None);
        assert_eq!(AgentClient::extract_domain("tcp://example.com:443"), None);
        assert_eq!(AgentClient::extract_domain(""), None);
    }

    #[test]
    fn test_grpc_tls_config_builder() {
        let config = GrpcTlsConfig::new()
            .with_ca_cert_pem(b"test-ca-cert".to_vec())
            .with_client_identity(b"test-cert".to_vec(), b"test-key".to_vec())
            .with_domain_name("example.com");

        assert!(config.ca_cert_pem.is_some());
        assert!(config.client_cert_pem.is_some());
        assert!(config.client_key_pem.is_some());
        assert_eq!(config.domain_name, Some("example.com".to_string()));
        assert!(!config.insecure_skip_verify);
    }

    #[test]
    fn test_grpc_tls_config_insecure() {
        let config = GrpcTlsConfig::new().with_insecure_skip_verify();

        assert!(config.insecure_skip_verify);
        assert!(config.ca_cert_pem.is_none());
    }

    #[test]
    fn test_http_tls_config_builder() {
        let config = HttpTlsConfig::new()
            .with_ca_cert_pem(b"test-ca-cert".to_vec())
            .with_client_identity(b"test-cert".to_vec(), b"test-key".to_vec());

        assert!(config.ca_cert_pem.is_some());
        assert!(config.client_cert_pem.is_some());
        assert!(config.client_key_pem.is_some());
        assert!(!config.insecure_skip_verify);
    }

    #[test]
    fn test_http_tls_config_insecure() {
        let config = HttpTlsConfig::new().with_insecure_skip_verify();

        assert!(config.insecure_skip_verify);
        assert!(config.ca_cert_pem.is_none());
    }

    #[tokio::test]
    async fn test_http_client_creation() {
        // Test that we can create an HTTP client (doesn't actually connect)
        let result = AgentClient::http(
            "test-agent",
            "http://localhost:9999/agent",
            Duration::from_secs(5),
        )
        .await;

        // Client should be created successfully (connection happens on first request)
        assert!(result.is_ok());
    }
}
