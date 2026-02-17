//! ACME Startup Integration Tests
//!
//! Tests for ACME challenge server, certificate storage integration,
//! and SniResolver ACME path resolution during startup.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use zentinel_config::server::{AcmeChallengeType, AcmeConfig};
use zentinel_config::TlsConfig;
use zentinel_proxy::acme::{CertificateStorage, ChallengeManager};

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

/// Build an AcmeConfig pointing at the given storage directory
fn acme_config(storage: PathBuf) -> AcmeConfig {
    AcmeConfig {
        email: "test@example.com".to_string(),
        domains: vec!["example.com".to_string()],
        staging: true,
        storage,
        renew_before_days: 30,
        challenge_type: AcmeChallengeType::Http01,
        dns_provider: None,
    }
}

// ============================================================================
// Certificate Storage + SniResolver Integration
// ============================================================================

mod storage_resolver_integration {
    use super::*;
    use chrono::Utc;
    use zentinel_proxy::tls::SniResolver;

    #[test]
    fn test_storage_saves_then_resolver_loads() {
        // Verify the full flow: storage saves cert files, SniResolver loads them
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = CertificateStorage::new(temp_dir.path()).unwrap();

        // Copy real cert/key from fixtures into storage
        let fixtures = fixtures_path();
        let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
        let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

        let expires = Utc::now() + chrono::Duration::days(90);
        storage
            .save_certificate(
                "example.com",
                &cert_pem,
                &key_pem,
                expires,
                &["example.com".to_string()],
            )
            .unwrap();

        // Build TlsConfig with ACME pointing at the storage
        let config = TlsConfig {
            cert_file: None,
            key_file: None,
            additional_certs: vec![],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: true,
            acme: Some(acme_config(temp_dir.path().to_path_buf())),
        };

        // SniResolver should load the cert files that storage wrote
        let resolver = SniResolver::from_config(&config);
        assert!(
            resolver.is_ok(),
            "SniResolver should load storage-managed certs: {:?}",
            resolver.err()
        );
    }

    #[test]
    fn test_storage_needs_renewal_returns_false_for_fresh_cert() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = CertificateStorage::new(temp_dir.path()).unwrap();

        // Save a cert that expires in 90 days
        let expires = Utc::now() + chrono::Duration::days(90);
        storage
            .save_certificate(
                "example.com",
                "cert",
                "key",
                expires,
                &["example.com".to_string()],
            )
            .unwrap();

        // With 30-day renewal window, should NOT need renewal
        assert!(!storage.needs_renewal("example.com", 30).unwrap());
    }

    #[test]
    fn test_storage_certificate_paths_returns_paths_when_files_exist() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = CertificateStorage::new(temp_dir.path()).unwrap();

        // No cert yet
        assert!(storage.certificate_paths("example.com").is_none());

        // Save a cert
        let expires = Utc::now() + chrono::Duration::days(90);
        storage
            .save_certificate(
                "example.com",
                "cert",
                "key",
                expires,
                &["example.com".to_string()],
            )
            .unwrap();

        let paths = storage.certificate_paths("example.com");
        assert!(paths.is_some());
        let (cert_path, key_path) = paths.unwrap();
        assert!(cert_path.ends_with("cert.pem"));
        assert!(key_path.ends_with("key.pem"));
    }
}

// ============================================================================
// Challenge Server Integration Tests
// ============================================================================

mod challenge_server {
    use super::*;
    use zentinel_proxy::acme::challenge_server::run_challenge_server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    /// Helper to start a challenge server on a random port and return the address
    async fn start_server(
        cm: Arc<ChallengeManager>,
    ) -> (String, watch::Sender<bool>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let addr_clone = addr.clone();
        let handle = tokio::spawn(async move {
            let _ = run_challenge_server(&addr_clone, cm, shutdown_rx).await;
        });

        // Give server time to bind
        tokio::time::sleep(Duration::from_millis(50)).await;

        (addr, shutdown_tx, handle)
    }

    #[tokio::test]
    async fn test_challenge_server_concurrent_requests() {
        let cm = Arc::new(ChallengeManager::new());

        // Register multiple tokens
        for i in 0..10 {
            cm.add_challenge(&format!("token-{}", i), &format!("auth-value-{}", i));
        }

        let (addr, shutdown_tx, server_handle) = start_server(Arc::clone(&cm)).await;

        // Send concurrent requests
        let mut handles = Vec::new();
        for i in 0..10 {
            let addr = addr.clone();
            handles.push(tokio::spawn(async move {
                let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
                let request = format!(
                    "GET /.well-known/acme-challenge/token-{} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                    i
                );
                stream.write_all(request.as_bytes()).await.unwrap();

                let mut response = vec![0u8; 4096];
                let n = stream.read(&mut response).await.unwrap();
                let response_str = String::from_utf8_lossy(&response[..n]).to_string();

                (i, response_str)
            }));
        }

        // Verify all responses
        for handle in handles {
            let (i, response_str) = handle.await.unwrap();
            assert!(
                response_str.starts_with("HTTP/1.1 200 OK"),
                "Request {} should get 200, got: {}",
                i,
                response_str.lines().next().unwrap_or("")
            );
            assert!(
                response_str.contains(&format!("auth-value-{}", i)),
                "Request {} should contain auth-value-{}, got: {}",
                i,
                i,
                response_str
            );
        }

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }

    #[tokio::test]
    async fn test_challenge_server_shutdown_is_clean() {
        let cm = Arc::new(ChallengeManager::new());
        let (_, shutdown_tx, server_handle) = start_server(cm).await;

        // Shut down immediately
        shutdown_tx.send(true).unwrap();

        // Server should exit cleanly within a reasonable time
        let result = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
        assert!(result.is_ok(), "Server should shut down within 2 seconds");

        // The JoinHandle result should be Ok (no panic)
        let inner = result.unwrap();
        assert!(inner.is_ok(), "Server task should not panic on shutdown");
    }

    #[tokio::test]
    async fn test_challenge_server_mixed_valid_and_invalid_requests() {
        let cm = Arc::new(ChallengeManager::new());
        cm.add_challenge("valid-token", "valid-auth");

        let (addr, shutdown_tx, server_handle) = start_server(Arc::clone(&cm)).await;

        // Valid challenge request
        {
            let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
            let request =
                "GET /.well-known/acme-challenge/valid-token HTTP/1.1\r\nHost: localhost\r\n\r\n";
            stream.write_all(request.as_bytes()).await.unwrap();

            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await.unwrap();
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.starts_with("HTTP/1.1 200 OK"));
            assert!(response_str.contains("valid-auth"));
        }

        // Non-challenge path
        {
            let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
            let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
            stream.write_all(request.as_bytes()).await.unwrap();

            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await.unwrap();
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.starts_with("HTTP/1.1 404 Not Found"));
        }

        // Unknown token
        {
            let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
            let request =
                "GET /.well-known/acme-challenge/unknown HTTP/1.1\r\nHost: localhost\r\n\r\n";
            stream.write_all(request.as_bytes()).await.unwrap();

            let mut response = vec![0u8; 4096];
            let n = stream.read(&mut response).await.unwrap();
            let response_str = String::from_utf8_lossy(&response[..n]);
            assert!(response_str.starts_with("HTTP/1.1 404 Not Found"));
        }

        shutdown_tx.send(true).unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;
    }
}

// ============================================================================
// Validate TLS Config with ACME
// ============================================================================

mod validate_acme_config {
    use super::*;
    use zentinel_proxy::tls::{validate_tls_config, TlsError};

    #[test]
    fn test_validate_skips_cert_check_for_acme_config() {
        // ACME-managed config without cert_file/key_file should pass validation
        let temp_dir = tempfile::tempdir().unwrap();
        let config = TlsConfig {
            cert_file: None,
            key_file: None,
            additional_certs: vec![],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: true,
            acme: Some(acme_config(temp_dir.path().to_path_buf())),
        };

        let result = validate_tls_config(&config);
        assert!(
            result.is_ok(),
            "ACME config should skip manual cert validation: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_validate_requires_cert_or_acme() {
        // No cert_file, no key_file, no ACME → should fail
        let config = TlsConfig {
            cert_file: None,
            key_file: None,
            additional_certs: vec![],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: true,
            acme: None,
        };

        let result = validate_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::ConfigBuild(msg) => {
                assert!(msg.contains("cert_file") || msg.contains("ACME"));
            }
            e => panic!("Expected ConfigBuild error, got {:?}", e),
        }
    }
}
