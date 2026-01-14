//! mTLS Upstream Integration Tests
//!
//! These tests verify end-to-end mTLS functionality by starting a TLS server
//! that requires client certificates and testing connections to it.
//!
//! Unlike the unit tests in tls_mtls_test.rs which test config building,
//! these tests verify actual TLS handshakes with client authentication.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Once};
use std::thread;
use std::time::Duration;

use rcgen::{CertificateParams, CertifiedIssuer, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::TlsConnector;

use sentinel_proxy::tls::load_client_cert_key;

static CRYPTO_PROVIDER_INIT: Once = Once::new();

fn ensure_crypto_provider() {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Get the path to the test fixtures directory
fn fixtures_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/tls")
}

// ============================================================================
// Certificate Generation Utilities
// ============================================================================

/// Generate a CA certificate and key pair for testing
fn generate_ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test CA");
    dn.push(DnType::OrganizationName, "Sentinel Test");
    params.distinguished_name = dn;

    let key_pair = KeyPair::generate().unwrap();
    CertifiedIssuer::self_signed(params, key_pair).unwrap()
}

/// Generate a server certificate signed by the CA
fn generate_server_cert(
    ca: &CertifiedIssuer<'static, KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;

    // Add SAN for localhost
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("localhost".try_into().unwrap()),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, ca).unwrap();
    (cert, key_pair)
}

/// Generate a client certificate signed by the CA
fn generate_client_cert(
    ca: &CertifiedIssuer<'static, KeyPair>,
) -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::default();

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Test Client");
    params.distinguished_name = dn;

    // Add client auth extended key usage
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, ca).unwrap();
    (cert, key_pair)
}

// ============================================================================
// mTLS Test Server
// ============================================================================

/// A simple TLS server that requires client certificates
struct MtlsServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    connection_count: Arc<AtomicUsize>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MtlsServer {
    /// Start a new mTLS server with the given certificates
    fn start(
        ca_cert_der: Vec<u8>,
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
    ) -> std::io::Result<Self> {
        ensure_crypto_provider();

        // Build client verifier that requires client certs signed by our CA
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert_der))
            .expect("Failed to add CA cert");

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("Failed to build client verifier");

        // Build server config
        let server_cert = CertificateDer::from(server_cert_der);
        let server_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![server_cert], server_key)
            .expect("Failed to build server config");

        let config = Arc::new(config);

        // Bind to a random port
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let connection_count = Arc::new(AtomicUsize::new(0));

        let shutdown_clone = shutdown.clone();
        let connection_count_clone = connection_count.clone();

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _peer_addr)) => {
                        stream.set_nonblocking(false).ok();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .ok();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .ok();

                        // Perform TLS handshake
                        let mut conn =
                            match rustls::ServerConnection::new(config.clone()) {
                                Ok(c) => c,
                                Err(_) => continue,
                            };

                        // Complete handshake
                        let mut tls_stream =
                            rustls::Stream::new(&mut conn, &mut stream);

                        // Try to read something to complete handshake
                        let mut buf = [0u8; 1024];
                        match tls_stream.read(&mut buf) {
                            Ok(n) if n > 0 => {
                                connection_count_clone.fetch_add(1, Ordering::SeqCst);
                                // Echo back with prefix
                                let response = format!("mTLS OK: {}", String::from_utf8_lossy(&buf[..n]));
                                let _ = tls_stream.write_all(response.as_bytes());
                            }
                            Ok(_) => {}
                            Err(_) => {
                                // Handshake failed (no client cert, etc.)
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            connection_count,
            handle: Some(handle),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn connection_count(&self) -> usize {
        self.connection_count.load(Ordering::SeqCst)
    }
}

impl Drop for MtlsServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod integration {
    use super::*;

    /// Test that mTLS connection succeeds with valid client certificate
    #[test]
    fn test_mtls_connection_with_valid_client_cert() {
        ensure_crypto_provider();

        // Generate certificates
        let ca = generate_ca();
        let (server_cert, server_key) = generate_server_cert(&ca);
        let (client_cert, client_key) = generate_client_cert(&ca);
        let ca_cert = ca.as_ref();

        // Start mTLS server
        let server = MtlsServer::start(
            ca_cert.der().to_vec(),
            server_cert.der().to_vec(),
            server_key.serialize_der(),
        )
        .expect("Failed to start mTLS server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Build client config with our client certificate
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();

        let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
        let client_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![client_cert_der], client_key_der)
            .expect("Failed to build client config");

        let client_config = Arc::new(client_config);

        // Connect to server
        let mut stream = TcpStream::connect(server.addr()).expect("Failed to connect");
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let server_name = "localhost".try_into().unwrap();
        let mut conn =
            rustls::ClientConnection::new(client_config, server_name).expect("Failed to create client connection");

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

        // Send test message
        tls_stream
            .write_all(b"Hello mTLS")
            .expect("Failed to write");
        tls_stream.flush().expect("Failed to flush");

        // Read response
        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).expect("Failed to read response");
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(
            response.contains("mTLS OK"),
            "Expected mTLS OK response, got: {}",
            response
        );

        // Verify connection was counted
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            server.connection_count(),
            1,
            "Expected 1 successful connection"
        );
    }

    /// Test that mTLS connection fails without client certificate
    #[test]
    fn test_mtls_connection_fails_without_client_cert() {
        ensure_crypto_provider();

        // Generate certificates
        let ca = generate_ca();
        let (server_cert, server_key) = generate_server_cert(&ca);
        let ca_cert = ca.as_ref();

        // Start mTLS server
        let server = MtlsServer::start(
            ca_cert.der().to_vec(),
            server_cert.der().to_vec(),
            server_key.serialize_der(),
        )
        .expect("Failed to start mTLS server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Build client config WITHOUT client certificate
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(); // No client cert!

        let client_config = Arc::new(client_config);

        // Connect to server
        let mut stream = TcpStream::connect(server.addr()).expect("Failed to connect");
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

        let server_name = "localhost".try_into().unwrap();
        let mut conn =
            rustls::ClientConnection::new(client_config, server_name).expect("Failed to create client connection");

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

        // Try to complete the handshake and communicate
        // The error may surface on write, flush, or read depending on timing
        let write_result = tls_stream.write_all(b"Hello");
        let flush_result = tls_stream.flush();

        // Try to read response (this forces handshake completion)
        let mut buf = [0u8; 1024];
        let read_result = tls_stream.read(&mut buf);

        // At least one of these operations should fail
        let all_succeeded =
            write_result.is_ok() && flush_result.is_ok() && read_result.is_ok();

        // Wait for server to process
        thread::sleep(Duration::from_millis(100));

        // Either the operations failed OR the server didn't count a successful connection
        let server_rejected = server.connection_count() == 0;

        assert!(
            !all_succeeded || server_rejected,
            "Expected connection to fail without client cert. \
             write: {:?}, flush: {:?}, read: {:?}, server_count: {}",
            write_result,
            flush_result,
            read_result,
            server.connection_count()
        );
    }

    /// Test that mTLS connection fails with untrusted client certificate
    #[test]
    fn test_mtls_connection_fails_with_untrusted_client_cert() {
        ensure_crypto_provider();

        // Generate server CA and certs
        let ca = generate_ca();
        let (server_cert, server_key) = generate_server_cert(&ca);
        let ca_cert = ca.as_ref();

        // Generate a DIFFERENT CA for client cert (untrusted)
        let untrusted_ca = generate_ca();
        let (client_cert, client_key) = generate_client_cert(&untrusted_ca);

        // Start mTLS server (only trusts the first CA)
        let server = MtlsServer::start(
            ca_cert.der().to_vec(),
            server_cert.der().to_vec(),
            server_key.serialize_der(),
        )
        .expect("Failed to start mTLS server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Build client config with untrusted client certificate
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();

        let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
        let client_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![client_cert_der], client_key_der)
            .expect("Failed to build client config");

        let client_config = Arc::new(client_config);

        // Connect to server
        let mut stream = TcpStream::connect(server.addr()).expect("Failed to connect");
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(2))).ok();

        let server_name = "localhost".try_into().unwrap();
        let mut conn =
            rustls::ClientConnection::new(client_config, server_name).expect("Failed to create client connection");

        let mut tls_stream = rustls::Stream::new(&mut conn, &mut stream);

        // Try to complete the handshake and communicate
        let write_result = tls_stream.write_all(b"Hello");
        let flush_result = tls_stream.flush();

        // Try to read response
        let mut buf = [0u8; 1024];
        let read_result = tls_stream.read(&mut buf);

        // At least one of these should fail
        let all_succeeded =
            write_result.is_ok() && flush_result.is_ok() && read_result.is_ok();

        // Wait for server to process
        thread::sleep(Duration::from_millis(100));

        // Either the operations failed OR the server didn't count a successful connection
        let server_rejected = server.connection_count() == 0;

        assert!(
            !all_succeeded || server_rejected,
            "Expected connection to fail with untrusted client cert. \
             write: {:?}, flush: {:?}, read: {:?}, server_count: {}",
            write_result,
            flush_result,
            read_result,
            server.connection_count()
        );
    }
}

// ============================================================================
// load_client_cert_key Function Tests (with real files)
// ============================================================================

mod load_client_cert_key_tests {
    use super::*;

    /// Test loading client cert/key from fixture files
    #[test]
    fn test_load_from_fixture_files() {
        ensure_crypto_provider();

        let fixtures = fixtures_path();
        let cert_path = fixtures.join("client.crt");
        let key_path = fixtures.join("client.key");

        // Skip if fixtures don't exist
        if !cert_path.exists() || !key_path.exists() {
            eprintln!("Skipping test: fixture files not found");
            return;
        }

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(
            result.is_ok(),
            "Failed to load client cert/key: {:?}",
            result.err()
        );
    }

    /// Test loading from combined PEM file (cert and key in same file)
    #[test]
    fn test_load_from_combined_pem() {
        ensure_crypto_provider();

        let fixtures = fixtures_path();
        let pem_path = fixtures.join("client.pem");

        // Skip if fixture doesn't exist
        if !pem_path.exists() {
            eprintln!("Skipping test: client.pem not found");
            return;
        }

        // Use same file for both cert and key
        let result = load_client_cert_key(&pem_path, &pem_path);
        assert!(
            result.is_ok(),
            "Failed to load from combined PEM: {:?}",
            result.err()
        );
    }

    /// Test that loading from non-existent file fails
    #[test]
    fn test_load_nonexistent_cert_fails() {
        ensure_crypto_provider();

        let fixtures = fixtures_path();
        let cert_path = fixtures.join("nonexistent.crt");
        let key_path = fixtures.join("client.key");

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(result.is_err(), "Expected error for nonexistent cert");
    }

    /// Test that loading from non-existent key file fails
    #[test]
    fn test_load_nonexistent_key_fails() {
        ensure_crypto_provider();

        let fixtures = fixtures_path();
        let cert_path = fixtures.join("client.crt");
        let key_path = fixtures.join("nonexistent.key");

        // Skip if cert fixture doesn't exist
        if !cert_path.exists() {
            eprintln!("Skipping test: fixture files not found");
            return;
        }

        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(result.is_err(), "Expected error for nonexistent key");
    }

    /// Test loading with dynamically generated certificates
    #[test]
    fn test_load_generated_certs() {
        ensure_crypto_provider();

        // Generate CA and client cert
        let ca = generate_ca();
        let (client_cert, client_key) = generate_client_cert(&ca);

        // Write to temp files
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("client.crt");
        let key_path = temp_dir.path().join("client.key");

        std::fs::write(&cert_path, client_cert.pem()).unwrap();
        std::fs::write(&key_path, client_key.serialize_pem()).unwrap();

        // Load using our function
        let result = load_client_cert_key(&cert_path, &key_path);
        assert!(
            result.is_ok(),
            "Failed to load generated certs: {:?}",
            result.err()
        );
    }
}

// ============================================================================
// Async Integration Tests (for completeness with tokio runtime)
// ============================================================================

mod async_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as TokioTcpStream;

    /// Test mTLS connection using async tokio-rustls
    #[tokio::test]
    async fn test_async_mtls_connection() {
        ensure_crypto_provider();

        // Generate certificates
        let ca = generate_ca();
        let (server_cert, server_key) = generate_server_cert(&ca);
        let (client_cert, client_key) = generate_client_cert(&ca);
        let ca_cert = ca.as_ref();

        // Start mTLS server (runs in a thread)
        let server = MtlsServer::start(
            ca_cert.der().to_vec(),
            server_cert.der().to_vec(),
            server_key.serialize_der(),
        )
        .expect("Failed to start mTLS server");

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Build async client config
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();

        let client_cert_der = CertificateDer::from(client_cert.der().to_vec());
        let client_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der()));

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(vec![client_cert_der], client_key_der)
            .expect("Failed to build client config");

        let connector = TlsConnector::from(Arc::new(client_config));

        // Connect using tokio
        let stream = TokioTcpStream::connect(server.addr())
            .await
            .expect("Failed to connect");

        let server_name = "localhost".try_into().unwrap();
        let mut tls_stream = connector
            .connect(server_name, stream)
            .await
            .expect("TLS handshake failed");

        // Send and receive
        tls_stream
            .write_all(b"Async Hello")
            .await
            .expect("Write failed");
        tls_stream.flush().await.expect("Flush failed");

        let mut buf = [0u8; 1024];
        let n = tls_stream.read(&mut buf).await.expect("Read failed");
        let response = String::from_utf8_lossy(&buf[..n]);

        assert!(
            response.contains("mTLS OK"),
            "Expected mTLS OK, got: {}",
            response
        );
    }

    /// Test that async connection fails without client cert
    #[tokio::test]
    async fn test_async_mtls_fails_without_cert() {
        ensure_crypto_provider();

        // Generate certificates
        let ca = generate_ca();
        let (server_cert, server_key) = generate_server_cert(&ca);
        let ca_cert = ca.as_ref();

        // Start mTLS server
        let server = MtlsServer::start(
            ca_cert.der().to_vec(),
            server_cert.der().to_vec(),
            server_key.serialize_der(),
        )
        .expect("Failed to start mTLS server");

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Build client config WITHOUT client cert
        let mut root_store = RootCertStore::empty();
        root_store
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();

        let client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = TlsConnector::from(Arc::new(client_config));

        // Connect
        let stream = TokioTcpStream::connect(server.addr())
            .await
            .expect("TCP connect failed");

        let server_name = "localhost".try_into().unwrap();

        // TLS handshake may succeed but communication should fail
        let connect_result = connector.connect(server_name, stream).await;

        let communication_failed = match connect_result {
            Err(_) => true, // Handshake failed
            Ok(mut tls_stream) => {
                // Try to communicate - this should fail
                let write_result = tls_stream.write_all(b"Hello").await;
                let flush_result = tls_stream.flush().await;
                let mut buf = [0u8; 1024];
                let read_result = tls_stream.read(&mut buf).await;

                // Check if any operation failed
                write_result.is_err() || flush_result.is_err() || read_result.is_err()
            }
        };

        // Wait for server to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Either communication failed OR server didn't count a successful connection
        let server_rejected = server.connection_count() == 0;

        assert!(
            communication_failed || server_rejected,
            "Expected connection to fail without client cert. Server count: {}",
            server.connection_count()
        );
    }
}
