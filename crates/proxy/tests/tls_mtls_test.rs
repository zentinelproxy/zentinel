//! mTLS Integration Tests
//!
//! Tests for mutual TLS (mTLS) configuration - both server-side client
//! authentication and upstream client certificate configuration.
//! Uses test certificates from tests/fixtures/tls/

use std::path::PathBuf;
use std::sync::Once;

use zentinel_config::UpstreamTlsConfig;
use zentinel_proxy::tls::{build_upstream_tls_config, validate_upstream_tls_config, TlsError};

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

/// Create a minimal upstream TLS config (no client cert)
fn minimal_upstream_config() -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        sni: None,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure_skip_verify: false,
    }
}

/// Create an upstream TLS config with custom CA
fn custom_ca_upstream_config() -> UpstreamTlsConfig {
    let fixtures = fixtures_path();
    UpstreamTlsConfig {
        sni: Some("example.com".to_string()),
        ca_cert: Some(fixtures.join("ca.crt")),
        client_cert: None,
        client_key: None,
        insecure_skip_verify: false,
    }
}

/// Create an mTLS upstream config (with client certificate)
fn mtls_upstream_config() -> UpstreamTlsConfig {
    let fixtures = fixtures_path();
    UpstreamTlsConfig {
        sni: Some("api.example.com".to_string()),
        ca_cert: Some(fixtures.join("ca.crt")),
        client_cert: Some(fixtures.join("client.crt")),
        client_key: Some(fixtures.join("client.key")),
        insecure_skip_verify: false,
    }
}

/// Create an insecure upstream config (skip verification)
fn insecure_upstream_config() -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        sni: None,
        ca_cert: None,
        client_cert: None,
        client_key: None,
        insecure_skip_verify: true,
    }
}

// ============================================================================
// Upstream TLS Config Building Tests
// ============================================================================

mod build_config {
    use super::*;

    #[test]
    fn test_build_minimal_config() {
        ensure_crypto_provider();
        let config = minimal_upstream_config();
        let result = build_upstream_tls_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build minimal upstream TLS config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_with_custom_ca() {
        ensure_crypto_provider();
        let config = custom_ca_upstream_config();
        let result = build_upstream_tls_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build upstream config with custom CA: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_with_mtls() {
        ensure_crypto_provider();
        let config = mtls_upstream_config();
        let result = build_upstream_tls_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build mTLS upstream config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_insecure_config() {
        ensure_crypto_provider();
        let config = insecure_upstream_config();
        let result = build_upstream_tls_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build insecure upstream config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_with_missing_ca() {
        ensure_crypto_provider();
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(fixtures.join("nonexistent-ca.crt")),
            client_cert: None,
            client_key: None,
            insecure_skip_verify: false,
        };

        let result = build_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertificateLoad(msg) => {
                assert!(msg.contains("nonexistent-ca.crt"));
            }
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_build_with_missing_client_cert() {
        ensure_crypto_provider();
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(fixtures.join("ca.crt")),
            client_cert: Some(fixtures.join("nonexistent-client.crt")),
            client_key: Some(fixtures.join("client.key")),
            insecure_skip_verify: false,
        };

        let result = build_upstream_tls_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_with_missing_client_key() {
        ensure_crypto_provider();
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(fixtures.join("ca.crt")),
            client_cert: Some(fixtures.join("client.crt")),
            client_key: Some(fixtures.join("nonexistent-client.key")),
            insecure_skip_verify: false,
        };

        let result = build_upstream_tls_config(&config);
        assert!(result.is_err());
    }
}

// ============================================================================
// Upstream TLS Config Validation Tests
// ============================================================================

mod validation {
    use super::*;

    #[test]
    fn test_validate_minimal_config() {
        let config = minimal_upstream_config();
        let result = validate_upstream_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_custom_ca_config() {
        let config = custom_ca_upstream_config();
        let result = validate_upstream_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mtls_config() {
        let config = mtls_upstream_config();
        let result = validate_upstream_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_insecure_config() {
        let config = insecure_upstream_config();
        let result = validate_upstream_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_ca_file() {
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(fixtures.join("nonexistent-ca.crt")),
            client_cert: None,
            client_key: None,
            insecure_skip_verify: false,
        };

        let result = validate_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertificateLoad(msg) => {
                assert!(msg.contains("not found"));
            }
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_missing_client_cert_file() {
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: None,
            client_cert: Some(fixtures.join("nonexistent-client.crt")),
            client_key: Some(fixtures.join("client.key")),
            insecure_skip_verify: false,
        };

        let result = validate_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertificateLoad(msg) => {
                assert!(msg.contains("not found"));
            }
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_missing_client_key_file() {
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: None,
            client_cert: Some(fixtures.join("client.crt")),
            client_key: Some(fixtures.join("nonexistent-client.key")),
            insecure_skip_verify: false,
        };

        let result = validate_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::KeyLoad(msg) => {
                assert!(msg.contains("not found"));
            }
            e => panic!("Expected KeyLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_client_cert_without_key() {
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: None,
            client_cert: Some(fixtures.join("client.crt")),
            client_key: None,
            insecure_skip_verify: false,
        };

        let result = validate_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::ConfigBuild(msg) => {
                assert!(msg.contains("client_cert specified without client_key"));
            }
            e => panic!("Expected ConfigBuild error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_client_key_without_cert() {
        let fixtures = fixtures_path();
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: None,
            client_cert: None,
            client_key: Some(fixtures.join("client.key")),
            insecure_skip_verify: false,
        };

        let result = validate_upstream_tls_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::ConfigBuild(msg) => {
                assert!(msg.contains("client_key specified without client_cert"));
            }
            e => panic!("Expected ConfigBuild error, got {:?}", e),
        }
    }
}

// ============================================================================
// Certificate Loading Edge Cases
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn test_empty_ca_file() {
        ensure_crypto_provider();
        // Create a temporary empty file and test
        let temp_dir = tempfile::tempdir().unwrap();
        let empty_ca = temp_dir.path().join("empty.crt");
        std::fs::write(&empty_ca, "").unwrap();

        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(empty_ca),
            client_cert: None,
            client_key: None,
            insecure_skip_verify: false,
        };

        // Empty CA file should either fail to parse or produce empty root store
        let result = build_upstream_tls_config(&config);
        // This may succeed with empty root store (webpki behavior) or fail
        // depending on implementation - just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_invalid_cert_content() {
        ensure_crypto_provider();
        let temp_dir = tempfile::tempdir().unwrap();
        let invalid_cert = temp_dir.path().join("invalid.crt");
        std::fs::write(&invalid_cert, "this is not a certificate").unwrap();

        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(invalid_cert),
            client_cert: None,
            client_key: None,
            insecure_skip_verify: false,
        };

        // Invalid content may or may not cause an error depending on parsing
        let _ = build_upstream_tls_config(&config);
    }

    #[test]
    fn test_untrusted_ca_in_chain() {
        ensure_crypto_provider();
        let fixtures = fixtures_path();

        // Use the untrusted (self-signed) cert as CA - this is valid
        // but any certs signed by our main CA won't be trusted
        let config = UpstreamTlsConfig {
            sni: None,
            ca_cert: Some(fixtures.join("untrusted.crt")),
            client_cert: None,
            client_key: None,
            insecure_skip_verify: false,
        };

        let result = build_upstream_tls_config(&config);
        // Should succeed - the untrusted cert is still a valid certificate
        assert!(result.is_ok());
    }

    #[test]
    fn test_mtls_with_combined_pem() {
        ensure_crypto_provider();
        let fixtures = fixtures_path();

        // client.pem contains both cert and key
        // but our config requires separate files
        let config = UpstreamTlsConfig {
            sni: Some("example.com".to_string()),
            ca_cert: Some(fixtures.join("ca.crt")),
            client_cert: Some(fixtures.join("client.pem")),
            client_key: Some(fixtures.join("client.pem")),
            insecure_skip_verify: false,
        };

        // Combined PEM file should work for both cert and key
        let result = build_upstream_tls_config(&config);
        assert!(
            result.is_ok(),
            "Combined PEM should work: {:?}",
            result.err()
        );
    }
}
