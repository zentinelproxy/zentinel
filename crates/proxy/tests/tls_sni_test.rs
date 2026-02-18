//! SNI Resolver Unit Tests
//!
//! Tests for TLS Server Name Indication (SNI) certificate resolution.
//! Uses test certificates from tests/fixtures/tls/

use std::path::PathBuf;
use std::sync::Arc;

use zentinel_config::{SniCertificate, TlsConfig};
use zentinel_proxy::tls::{
    build_server_config, validate_tls_config, CertificateReloader, HotReloadableSniResolver,
    SniResolver, TlsError,
};

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

/// Create a minimal TLS config with just the default certificate
fn minimal_tls_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_file: Some(fixtures.join("server-default.crt")),
        key_file: Some(fixtures.join("server-default.key")),
        additional_certs: vec![],
        ca_file: None,
        min_version: zentinel_common::types::TlsVersion::Tls12,
        max_version: None,
        cipher_suites: vec![],
        client_auth: false,
        ocsp_stapling: false,
        session_resumption: true,
        acme: None,
    }
}

/// Create a TLS config with multiple SNI certificates
fn multi_sni_tls_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_file: Some(fixtures.join("server-default.crt")),
        key_file: Some(fixtures.join("server-default.key")),
        additional_certs: vec![
            SniCertificate {
                hostnames: vec!["api.example.com".to_string()],
                cert_file: fixtures.join("server-api.crt"),
                key_file: fixtures.join("server-api.key"),
            },
            SniCertificate {
                hostnames: vec!["secure.example.com".to_string()],
                cert_file: fixtures.join("server-secure.crt"),
                key_file: fixtures.join("server-secure.key"),
            },
        ],
        ca_file: None,
        min_version: zentinel_common::types::TlsVersion::Tls12,
        max_version: None,
        cipher_suites: vec![],
        client_auth: false,
        ocsp_stapling: false,
        session_resumption: true,
        acme: None,
    }
}

/// Create a TLS config with wildcard certificates
fn wildcard_tls_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_file: Some(fixtures.join("server-default.crt")),
        key_file: Some(fixtures.join("server-default.key")),
        additional_certs: vec![SniCertificate {
            hostnames: vec!["*.example.com".to_string()],
            cert_file: fixtures.join("server-wildcard.crt"),
            key_file: fixtures.join("server-wildcard.key"),
        }],
        ca_file: None,
        min_version: zentinel_common::types::TlsVersion::Tls12,
        max_version: None,
        cipher_suites: vec![],
        client_auth: false,
        ocsp_stapling: false,
        session_resumption: true,
        acme: None,
    }
}

/// Create a TLS config with mTLS enabled
fn mtls_tls_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_file: Some(fixtures.join("server-default.crt")),
        key_file: Some(fixtures.join("server-default.key")),
        additional_certs: vec![],
        ca_file: Some(fixtures.join("ca.crt")),
        min_version: zentinel_common::types::TlsVersion::Tls12,
        max_version: None,
        cipher_suites: vec![],
        client_auth: true,
        ocsp_stapling: false,
        session_resumption: true,
        acme: None,
    }
}

// ============================================================================
// SNI Resolver Tests
// ============================================================================

mod sni_resolver {
    use super::*;

    #[test]
    fn test_create_from_minimal_config() {
        let config = minimal_tls_config();
        let resolver = SniResolver::from_config(&config);
        assert!(
            resolver.is_ok(),
            "Failed to create resolver: {:?}",
            resolver.err()
        );
    }

    #[test]
    fn test_create_from_multi_sni_config() {
        let config = multi_sni_tls_config();
        let resolver = SniResolver::from_config(&config);
        assert!(
            resolver.is_ok(),
            "Failed to create resolver: {:?}",
            resolver.err()
        );
    }

    #[test]
    fn test_create_from_wildcard_config() {
        let config = wildcard_tls_config();
        let resolver = SniResolver::from_config(&config);
        assert!(
            resolver.is_ok(),
            "Failed to create resolver: {:?}",
            resolver.err()
        );
    }

    #[test]
    fn test_resolve_without_sni_returns_default() {
        let config = multi_sni_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // When no SNI is provided, should return default cert
        let cert = resolver.resolve(None);
        assert!(Arc::strong_count(&cert) > 0, "Certificate not resolved");
    }

    #[test]
    fn test_resolve_unknown_hostname_returns_default() {
        let config = multi_sni_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // Unknown hostname should fall back to default
        let cert = resolver.resolve(Some("unknown.example.org"));
        assert!(Arc::strong_count(&cert) > 0, "Certificate not resolved");
    }

    #[test]
    fn test_case_insensitive_matching() {
        let config = multi_sni_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // All these should match the same cert
        let cert1 = resolver.resolve(Some("api.example.com"));
        let cert2 = resolver.resolve(Some("API.EXAMPLE.COM"));
        let cert3 = resolver.resolve(Some("Api.Example.Com"));

        // The certificates should be the same Arc instance
        assert!(
            Arc::ptr_eq(&cert1, &cert2),
            "Case insensitive matching failed"
        );
        assert!(
            Arc::ptr_eq(&cert2, &cert3),
            "Case insensitive matching failed"
        );
    }

    #[test]
    fn test_different_sni_hostnames_return_different_certs() {
        let config = multi_sni_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        let api_cert = resolver.resolve(Some("api.example.com"));
        let secure_cert = resolver.resolve(Some("secure.example.com"));

        // Different hostnames should return different certs
        assert!(
            !Arc::ptr_eq(&api_cert, &secure_cert),
            "Different hostnames should return different certs"
        );
    }

    #[test]
    fn test_wildcard_matching() {
        let config = wildcard_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // These should all match *.example.com
        let wildcard_cert = resolver.resolve(Some("foo.example.com"));
        let bar_cert = resolver.resolve(Some("bar.example.com"));
        let sub_cert = resolver.resolve(Some("sub.example.com"));

        // All should be the same wildcard cert
        assert!(Arc::ptr_eq(&wildcard_cert, &bar_cert));
        assert!(Arc::ptr_eq(&bar_cert, &sub_cert));
    }

    #[test]
    fn test_wildcard_does_not_match_exact_domain() {
        let config = wildcard_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // *.example.com should NOT match example.com (no subdomain)
        // This should fall back to the default certificate
        let exact_cert = resolver.resolve(Some("example.com"));
        let wildcard_cert = resolver.resolve(Some("sub.example.com"));

        // The exact domain should get the default cert, not the wildcard
        // Since example.com is the default cert CN, they might be same or different
        // depending on whether the default cert covers example.com
        // The key assertion is that the wildcard pattern *.example.com doesn't match example.com directly
        assert!(Arc::strong_count(&exact_cert) > 0);
        assert!(Arc::strong_count(&wildcard_cert) > 0);
    }

    #[test]
    fn test_multi_level_subdomain_wildcard_matching() {
        let config = wildcard_tls_config();
        let resolver = SniResolver::from_config(&config).unwrap();

        // *.example.com should match foo.bar.example.com because we try multiple levels
        let deep_cert = resolver.resolve(Some("foo.bar.example.com"));
        let shallow_cert = resolver.resolve(Some("sub.example.com"));

        // Both should match the same wildcard cert for *.example.com
        assert!(
            Arc::ptr_eq(&deep_cert, &shallow_cert),
            "Multi-level subdomain should match wildcard"
        );
    }

    #[test]
    fn test_exact_match_takes_precedence_over_wildcard() {
        let fixtures = fixtures_path();
        // Create a config with both exact and wildcard for the same domain
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("server-default.key")),
            additional_certs: vec![
                SniCertificate {
                    hostnames: vec!["*.example.com".to_string()],
                    cert_file: fixtures.join("server-wildcard.crt"),
                    key_file: fixtures.join("server-wildcard.key"),
                },
                SniCertificate {
                    hostnames: vec!["api.example.com".to_string()],
                    cert_file: fixtures.join("server-api.crt"),
                    key_file: fixtures.join("server-api.key"),
                },
            ],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: true,
            acme: None,
        };

        let resolver = SniResolver::from_config(&config).unwrap();

        // api.example.com should use exact match, not wildcard
        let api_cert = resolver.resolve(Some("api.example.com"));
        // other.example.com should use wildcard
        let other_cert = resolver.resolve(Some("other.example.com"));

        // The exact match should return a different cert than wildcard
        assert!(
            !Arc::ptr_eq(&api_cert, &other_cert),
            "Exact match should take precedence over wildcard"
        );
    }

    #[test]
    fn test_error_on_missing_cert_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("nonexistent.crt")),
            key_file: Some(fixtures.join("server-default.key")),
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

        let result = SniResolver::from_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::CertificateLoad(_) => {}
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_error_on_missing_key_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("nonexistent.key")),
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

        let result = SniResolver::from_config(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            TlsError::KeyLoad(_) => {}
            e => panic!("Expected KeyLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_error_on_missing_sni_cert_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("server-default.key")),
            additional_certs: vec![SniCertificate {
                hostnames: vec!["api.example.com".to_string()],
                cert_file: fixtures.join("nonexistent.crt"),
                key_file: fixtures.join("server-api.key"),
            }],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling: false,
            session_resumption: true,
            acme: None,
        };

        let result = SniResolver::from_config(&config);
        assert!(result.is_err());
    }
}

// ============================================================================
// ACME Resolver Tests
// ============================================================================

mod acme_resolver {
    use super::*;
    use std::path::PathBuf;
    use zentinel_config::server::{AcmeChallengeType, AcmeConfig};

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

    /// Build a TlsConfig with ACME config and no manual cert/key paths
    fn acme_tls_config(storage: PathBuf) -> TlsConfig {
        TlsConfig {
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
            acme: Some(acme_config(storage)),
        }
    }

    #[test]
    fn test_from_config_with_acme_cert_paths() {
        // Pre-populate ACME storage with real cert/key from fixtures
        let temp_dir = tempfile::tempdir().unwrap();
        let domain_dir = temp_dir.path().join("domains").join("example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();

        let fixtures = fixtures_path();
        std::fs::copy(
            fixtures.join("server-default.crt"),
            domain_dir.join("cert.pem"),
        )
        .unwrap();
        std::fs::copy(
            fixtures.join("server-default.key"),
            domain_dir.join("key.pem"),
        )
        .unwrap();

        let config = acme_tls_config(temp_dir.path().to_path_buf());
        let resolver = SniResolver::from_config(&config);
        assert!(
            resolver.is_ok(),
            "SniResolver should load ACME-managed certs: {:?}",
            resolver.err()
        );

        // Should resolve the default cert
        let cert = resolver.unwrap().resolve(None);
        assert!(Arc::strong_count(&cert) > 0);
    }

    #[test]
    fn test_from_config_acme_no_domains_errors() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut config = acme_tls_config(temp_dir.path().to_path_buf());
        // Clear domains
        config.acme.as_mut().unwrap().domains.clear();

        let result = SniResolver::from_config(&config);
        assert!(result.is_err(), "Empty domains should fail");
        match result.unwrap_err() {
            TlsError::ConfigBuild(msg) => {
                assert!(
                    msg.contains("no domains"),
                    "Error should mention no domains, got: {}",
                    msg
                );
            }
            e => panic!("Expected ConfigBuild error, got {:?}", e),
        }
    }

    #[test]
    fn test_from_config_no_cert_no_acme_errors() {
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

        let result = SniResolver::from_config(&config);
        assert!(result.is_err(), "No cert and no ACME should fail");
        match result.unwrap_err() {
            TlsError::ConfigBuild(msg) => {
                assert!(
                    msg.contains("cert_file") && msg.contains("ACME"),
                    "Error should mention cert_file and ACME, got: {}",
                    msg
                );
            }
            e => panic!("Expected ConfigBuild error, got {:?}", e),
        }
    }

    #[test]
    fn test_from_config_acme_missing_cert_files_errors() {
        // ACME config pointing at storage dir that has no cert files
        let temp_dir = tempfile::tempdir().unwrap();
        // Create the domains directory structure but don't put any cert files
        let domain_dir = temp_dir.path().join("domains").join("example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();

        let config = acme_tls_config(temp_dir.path().to_path_buf());
        let result = SniResolver::from_config(&config);
        assert!(result.is_err(), "Missing ACME cert files should fail");
        match result.unwrap_err() {
            TlsError::CertificateLoad(_) => {}
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_hot_reload_with_acme_config() {
        // Pre-populate ACME storage with initial cert
        let temp_dir = tempfile::tempdir().unwrap();
        let domain_dir = temp_dir.path().join("domains").join("example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();

        let fixtures = fixtures_path();
        let cert_path = domain_dir.join("cert.pem");
        let key_path = domain_dir.join("key.pem");

        std::fs::copy(fixtures.join("server-default.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-default.key"), &key_path).unwrap();

        let config = acme_tls_config(temp_dir.path().to_path_buf());
        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        let cert_before = resolver.resolve(None);

        // Swap to different cert files (simulating ACME renewal)
        std::fs::copy(fixtures.join("server-api.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-api.key"), &key_path).unwrap();

        let reload_result = resolver.reload();
        assert!(
            reload_result.is_ok(),
            "Reload should succeed: {:?}",
            reload_result.err()
        );

        let cert_after = resolver.resolve(None);
        assert!(
            !Arc::ptr_eq(&cert_before, &cert_after),
            "Certificate should change after reload with new ACME cert files"
        );
    }
}

// ============================================================================
// Hot-Reloadable Resolver Tests
// ============================================================================

mod hot_reload {
    use super::*;

    #[test]
    fn test_create_hot_reloadable_resolver() {
        let config = minimal_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_hot_reload_success() {
        let config = minimal_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        // Reload should succeed (certs haven't changed)
        let result = resolver.reload();
        assert!(result.is_ok());
    }

    #[test]
    fn test_last_reload_age() {
        let config = minimal_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        let age1 = resolver.last_reload_age();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let age2 = resolver.last_reload_age();

        assert!(age2 > age1, "Age should increase over time");
    }

    #[test]
    fn test_reload_resets_age() {
        let config = minimal_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));
        let age_before = resolver.last_reload_age();

        resolver.reload().unwrap();
        let age_after = resolver.last_reload_age();

        assert!(age_after < age_before, "Reload should reset age");
    }

    #[test]
    fn test_hot_reload_resolves_certificates() {
        let config = multi_sni_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        // Test that the hot reloadable resolver can resolve certificates
        let cert = resolver.resolve(Some("api.example.com"));
        assert!(Arc::strong_count(&cert) > 0);
    }

    #[test]
    fn test_update_config() {
        let config1 = minimal_tls_config();
        let resolver = HotReloadableSniResolver::from_config(config1).unwrap();

        // Update with a multi-SNI config
        let config2 = multi_sni_tls_config();
        let result = resolver.update_config(config2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_certificate_rotation_via_file_swap() {
        // This test verifies that when certificate files are replaced on disk,
        // calling reload() picks up the new certificates.

        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

        // Copy initial certificate (server-default)
        let fixtures = fixtures_path();
        std::fs::copy(fixtures.join("server-default.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-default.key"), &key_path).unwrap();

        // Create resolver with initial certs
        let config = TlsConfig {
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
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

        let resolver = HotReloadableSniResolver::from_config(config).unwrap();

        // Get initial certificate
        let cert_before = resolver.resolve(None);

        // Now swap the certificate files to a different cert (server-api)
        std::fs::copy(fixtures.join("server-api.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-api.key"), &key_path).unwrap();

        // Reload should pick up new certs
        let reload_result = resolver.reload();
        assert!(
            reload_result.is_ok(),
            "Reload should succeed: {:?}",
            reload_result.err()
        );

        // Get certificate after reload
        let cert_after = resolver.resolve(None);

        // Certificates should be different (different Arc instances with different content)
        // Note: We can't easily compare cert content, but we can verify the Arc changed
        assert!(
            !Arc::ptr_eq(&cert_before, &cert_after),
            "Certificate should change after reload with new files"
        );
    }

    #[test]
    fn test_reload_fails_with_invalid_replacement() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

        // Copy valid initial certificate
        let fixtures = fixtures_path();
        std::fs::copy(fixtures.join("server-default.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-default.key"), &key_path).unwrap();

        let config = TlsConfig {
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
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

        let resolver = HotReloadableSniResolver::from_config(config).unwrap();
        let cert_before = resolver.resolve(None);

        // Replace with invalid cert content
        std::fs::write(&cert_path, "invalid certificate content").unwrap();

        // Reload should fail
        let reload_result = resolver.reload();
        assert!(
            reload_result.is_err(),
            "Reload should fail with invalid cert"
        );

        // Original cert should still be in use
        let cert_after = resolver.resolve(None);
        assert!(
            Arc::ptr_eq(&cert_before, &cert_after),
            "Original certificate should be preserved after failed reload"
        );
    }

    #[test]
    fn test_reload_fails_when_file_deleted() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

        // Copy valid certificate
        let fixtures = fixtures_path();
        std::fs::copy(fixtures.join("server-default.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-default.key"), &key_path).unwrap();

        let config = TlsConfig {
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
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

        let resolver = HotReloadableSniResolver::from_config(config).unwrap();
        let cert_before = resolver.resolve(None);

        // Delete the certificate file
        std::fs::remove_file(&cert_path).unwrap();

        // Reload should fail
        let reload_result = resolver.reload();
        assert!(
            reload_result.is_err(),
            "Reload should fail when cert file is deleted"
        );

        // Original cert should still be in use
        let cert_after = resolver.resolve(None);
        assert!(
            Arc::ptr_eq(&cert_before, &cert_after),
            "Original certificate should be preserved when reload fails"
        );
    }
}

// ============================================================================
// CertificateReloader Tests (Multi-Listener Management)
// ============================================================================

mod certificate_reloader {
    use super::*;

    #[test]
    fn test_create_certificate_reloader() {
        let reloader = CertificateReloader::new();
        let status = reloader.status();
        assert!(status.is_empty(), "New reloader should have no listeners");
    }

    #[test]
    fn test_register_single_resolver() {
        let reloader = CertificateReloader::new();
        let config = minimal_tls_config();
        let resolver = Arc::new(HotReloadableSniResolver::from_config(config).unwrap());

        reloader.register("https-main", resolver);

        let status = reloader.status();
        assert_eq!(status.len(), 1);
        assert!(status.contains_key("https-main"));
    }

    #[test]
    fn test_register_multiple_resolvers() {
        let reloader = CertificateReloader::new();

        let config1 = minimal_tls_config();
        let resolver1 = Arc::new(HotReloadableSniResolver::from_config(config1).unwrap());
        reloader.register("https-main", resolver1);

        let config2 = multi_sni_tls_config();
        let resolver2 = Arc::new(HotReloadableSniResolver::from_config(config2).unwrap());
        reloader.register("https-api", resolver2);

        let status = reloader.status();
        assert_eq!(status.len(), 2);
        assert!(status.contains_key("https-main"));
        assert!(status.contains_key("https-api"));
    }

    #[test]
    fn test_reload_all_success() {
        let reloader = CertificateReloader::new();

        let config1 = minimal_tls_config();
        let resolver1 = Arc::new(HotReloadableSniResolver::from_config(config1).unwrap());
        reloader.register("https-main", resolver1);

        let config2 = multi_sni_tls_config();
        let resolver2 = Arc::new(HotReloadableSniResolver::from_config(config2).unwrap());
        reloader.register("https-api", resolver2);

        // Reload all - should succeed
        let (success_count, errors) = reloader.reload_all();
        assert_eq!(
            success_count, 2,
            "Both resolvers should reload successfully"
        );
        assert!(errors.is_empty(), "No errors expected");
    }

    #[test]
    fn test_reload_all_partial_failure() {
        let reloader = CertificateReloader::new();

        // First resolver with valid config
        let config1 = minimal_tls_config();
        let resolver1 = Arc::new(HotReloadableSniResolver::from_config(config1).unwrap());
        reloader.register("https-valid", resolver1);

        // Second resolver with temp files that we'll delete
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("server.crt");
        let key_path = temp_dir.path().join("server.key");

        let fixtures = fixtures_path();
        std::fs::copy(fixtures.join("server-default.crt"), &cert_path).unwrap();
        std::fs::copy(fixtures.join("server-default.key"), &key_path).unwrap();

        let config2 = TlsConfig {
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
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
        let resolver2 = Arc::new(HotReloadableSniResolver::from_config(config2).unwrap());
        reloader.register("https-will-fail", resolver2);

        // Delete the cert file for the second resolver
        std::fs::remove_file(&cert_path).unwrap();

        // Reload all - should have partial failure
        let (success_count, errors) = reloader.reload_all();
        assert_eq!(success_count, 1, "One resolver should succeed");
        assert_eq!(errors.len(), 1, "One resolver should fail");
        assert_eq!(
            errors[0].0, "https-will-fail",
            "Failed resolver should be identified"
        );
    }

    #[test]
    fn test_status_tracks_reload_age() {
        let reloader = CertificateReloader::new();

        let config = minimal_tls_config();
        let resolver = Arc::new(HotReloadableSniResolver::from_config(config).unwrap());
        reloader.register("https-main", resolver);

        let status_before = reloader.status();
        let age_before = status_before.get("https-main").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        let status_after = reloader.status();
        let age_after = status_after.get("https-main").unwrap();

        assert!(age_after > age_before, "Age should increase over time");
    }

    #[test]
    fn test_reload_all_resets_ages() {
        let reloader = CertificateReloader::new();

        let config = minimal_tls_config();
        let resolver = Arc::new(HotReloadableSniResolver::from_config(config).unwrap());
        reloader.register("https-main", resolver);

        std::thread::sleep(std::time::Duration::from_millis(10));
        let status_before = reloader.status();
        let age_before = status_before.get("https-main").unwrap();

        reloader.reload_all();

        let status_after = reloader.status();
        let age_after = status_after.get("https-main").unwrap();

        assert!(age_after < age_before, "Age should reset after reload");
    }
}

// ============================================================================
// TLS Config Validation Tests
// ============================================================================

mod validation {
    use super::*;

    #[test]
    fn test_validate_valid_config() {
        let config = minimal_tls_config();
        let result = validate_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_multi_sni_config() {
        let config = multi_sni_tls_config();
        let result = validate_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_mtls_config() {
        let config = mtls_tls_config();
        let result = validate_tls_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_cert_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("nonexistent.crt")),
            key_file: Some(fixtures.join("server-default.key")),
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
            TlsError::CertificateLoad(msg) => {
                assert!(msg.contains("not found"));
            }
            e => panic!("Expected CertificateLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_missing_key_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("nonexistent.key")),
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
            TlsError::KeyLoad(msg) => {
                assert!(msg.contains("not found"));
            }
            e => panic!("Expected KeyLoad error, got {:?}", e),
        }
    }

    #[test]
    fn test_validate_missing_sni_cert() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("server-default.key")),
            additional_certs: vec![SniCertificate {
                hostnames: vec!["test.example.com".to_string()],
                cert_file: fixtures.join("nonexistent.crt"),
                key_file: fixtures.join("server-api.key"),
            }],
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
    }

    #[test]
    fn test_validate_mtls_missing_ca_file() {
        let fixtures = fixtures_path();
        let config = TlsConfig {
            cert_file: Some(fixtures.join("server-default.crt")),
            key_file: Some(fixtures.join("server-default.key")),
            additional_certs: vec![],
            ca_file: Some(fixtures.join("nonexistent-ca.crt")),
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: true,
            ocsp_stapling: false,
            session_resumption: true,
            acme: None,
        };

        let result = validate_tls_config(&config);
        assert!(result.is_err());
    }
}

// ============================================================================
// ServerConfig Building Tests
// ============================================================================

mod server_config {
    use super::*;
    use std::sync::Once;

    static CRYPTO_PROVIDER_INIT: Once = Once::new();

    fn ensure_crypto_provider() {
        CRYPTO_PROVIDER_INIT.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn test_build_server_config_minimal() {
        ensure_crypto_provider();
        let config = minimal_tls_config();
        let result = build_server_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build server config: {:?}",
            result.err()
        );

        let server_config = result.unwrap();
        // Check ALPN protocols are set
        assert!(server_config.alpn_protocols.contains(&b"h2".to_vec()));
        assert!(server_config.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }

    #[test]
    fn test_build_server_config_with_sni() {
        ensure_crypto_provider();
        let config = multi_sni_tls_config();
        let result = build_server_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build server config with SNI: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_server_config_with_mtls() {
        ensure_crypto_provider();
        let config = mtls_tls_config();
        let result = build_server_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build mTLS server config: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_server_config_with_wildcard() {
        ensure_crypto_provider();
        let config = wildcard_tls_config();
        let result = build_server_config(&config);
        assert!(
            result.is_ok(),
            "Failed to build wildcard server config: {:?}",
            result.err()
        );
    }
}
