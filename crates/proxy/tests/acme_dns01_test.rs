//! Integration tests for DNS-01 ACME challenge support
//!
//! Tests the DNS provider implementations using wiremock to mock API responses.

use std::time::Duration;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use sentinel_proxy::acme::dns::{
    create_challenge_info, Dns01ChallengeManager, DnsProvider, DnsProviderError, WebhookProvider,
};

// ============================================================================
// Webhook Provider Tests
// ============================================================================

mod webhook_provider {
    use super::*;

    #[tokio::test]
    async fn test_create_record_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "record_id": "webhook-record-123"
                })),
            )
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let record_id = provider
            .create_txt_record("example.com", "_acme-challenge", "challenge-value")
            .await
            .unwrap();

        assert_eq!(record_id, "webhook-record-123");
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path_regex(r"/records/record-\d+"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let result = provider
            .delete_txt_record("example.com", "record-123")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_delete_record_not_found_is_ok() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path_regex(r"/records/.*"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        // 404 should be treated as success (idempotent)
        let result = provider
            .delete_txt_record("example.com", "nonexistent")
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_supports_domain() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/domains/example.com/supported"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "supported": true
                })),
            )
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains/other.com/supported"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "supported": false
                })),
            )
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        assert!(provider.supports_domain("example.com").await.unwrap());
        assert!(!provider.supports_domain("other.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_supports_domain_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path_regex(r"/domains/.*/supported"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        // 404 means not supported
        assert!(!provider.supports_domain("unknown.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let result = provider
            .create_txt_record("example.com", "_acme-challenge", "value")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DnsProviderError::Authentication(_)
        ));
    }

    #[tokio::test]
    async fn test_server_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let result = provider
            .create_txt_record("example.com", "_acme-challenge", "value")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DnsProviderError::RecordCreation { .. }
        ));
    }

    #[tokio::test]
    async fn test_forbidden_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let result = provider
            .create_txt_record("example.com", "_acme-challenge", "value")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DnsProviderError::Authentication(_)
        ));
    }

    #[tokio::test]
    async fn test_multiple_records() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "record_id": "record-1"
                })),
            )
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "record_id": "record-2"
                })),
            )
            .mount(&mock_server)
            .await;

        let provider =
            WebhookProvider::new(mock_server.uri(), None, None, Duration::from_secs(30)).unwrap();

        let id1 = provider
            .create_txt_record("example.com", "_acme-challenge", "value1")
            .await
            .unwrap();
        let id2 = provider
            .create_txt_record("other.com", "_acme-challenge", "value2")
            .await
            .unwrap();

        assert_eq!(id1, "record-1");
        assert_eq!(id2, "record-2");
    }
}

// ============================================================================
// Challenge Info Tests
// ============================================================================

mod challenge_info {
    use super::*;

    #[test]
    fn test_challenge_info_creation() {
        let info = create_challenge_info(
            "example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/123",
        );

        assert_eq!(info.domain, "example.com");
        assert_eq!(info.record_name, "_acme-challenge.example.com");
        assert!(!info.record_value.is_empty());
        assert_eq!(info.url, "https://acme.example.com/challenge/123");
        assert!(info.record_id.is_none());
    }

    #[test]
    fn test_wildcard_challenge_info() {
        let info = create_challenge_info(
            "*.example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/456",
        );

        // Wildcard should use base domain for the record
        assert_eq!(info.domain, "*.example.com");
        assert_eq!(info.record_name, "_acme-challenge.example.com");
    }

    #[test]
    fn test_subdomain_challenge_info() {
        let info = create_challenge_info(
            "sub.example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/789",
        );

        assert_eq!(info.domain, "sub.example.com");
        assert_eq!(info.record_name, "_acme-challenge.sub.example.com");
    }

    #[test]
    fn test_deep_subdomain_challenge_info() {
        let info = create_challenge_info(
            "deep.sub.example.com",
            "token.thumbprint",
            "https://acme.example.com/challenge/abc",
        );

        assert_eq!(info.domain, "deep.sub.example.com");
        assert_eq!(info.record_name, "_acme-challenge.deep.sub.example.com");
    }

    #[test]
    fn test_challenge_value_computation() {
        // The challenge value should be base64url-encoded SHA256 of key authorization
        let value1 = Dns01ChallengeManager::compute_challenge_value("token1.thumbprint1");
        let value2 = Dns01ChallengeManager::compute_challenge_value("token2.thumbprint2");

        // Different inputs should produce different values
        assert_ne!(value1, value2);

        // Same input should produce same value
        let value1_again = Dns01ChallengeManager::compute_challenge_value("token1.thumbprint1");
        assert_eq!(value1, value1_again);

        // Should be base64url (no +, /, or =)
        assert!(!value1.contains('+'));
        assert!(!value1.contains('/'));
        assert!(!value1.contains('='));
    }

    #[test]
    fn test_challenge_value_length() {
        // SHA256 produces 32 bytes, base64url encodes that to ~43 characters
        let value = Dns01ChallengeManager::compute_challenge_value("test.key");
        assert_eq!(value.len(), 43); // base64url of 32 bytes without padding
    }
}

// ============================================================================
// KDL Config Parsing Tests
// ============================================================================

mod config_parsing {
    use sentinel_config::server::{
        AcmeChallengeType, DnsProviderType, PropagationCheckConfig,
    };

    #[test]
    fn test_acme_challenge_type_default() {
        let challenge_type = AcmeChallengeType::default();
        assert!(challenge_type.is_http01());
        assert!(!challenge_type.is_dns01());
    }

    #[test]
    fn test_acme_challenge_type_dns01() {
        let challenge_type = AcmeChallengeType::Dns01;
        assert!(!challenge_type.is_http01());
        assert!(challenge_type.is_dns01());
    }

    #[test]
    fn test_propagation_config_default() {
        let config = PropagationCheckConfig::default();
        assert_eq!(config.initial_delay_secs, 10);
        assert_eq!(config.check_interval_secs, 5);
        assert_eq!(config.timeout_secs, 120);
        assert!(config.nameservers.is_empty());
    }

    #[test]
    fn test_dns_provider_type_hetzner() {
        let provider_type = DnsProviderType::Hetzner;
        assert!(matches!(provider_type, DnsProviderType::Hetzner));
    }

    #[test]
    fn test_dns_provider_type_webhook() {
        let provider_type = DnsProviderType::Webhook {
            url: "https://dns.example.com/api".to_string(),
            auth_header: Some("X-API-Key".to_string()),
        };

        if let DnsProviderType::Webhook { url, auth_header } = provider_type {
            assert_eq!(url, "https://dns.example.com/api");
            assert_eq!(auth_header, Some("X-API-Key".to_string()));
        } else {
            panic!("Expected Webhook variant");
        }
    }

    #[test]
    fn test_dns_provider_type_webhook_without_auth() {
        let provider_type = DnsProviderType::Webhook {
            url: "https://dns.example.com/api".to_string(),
            auth_header: None,
        };

        if let DnsProviderType::Webhook { url, auth_header } = provider_type {
            assert_eq!(url, "https://dns.example.com/api");
            assert!(auth_header.is_none());
        } else {
            panic!("Expected Webhook variant");
        }
    }
}

// ============================================================================
// Provider Error Tests
// ============================================================================

mod provider_errors {
    use super::*;

    #[test]
    fn test_authentication_error_display() {
        let err = DnsProviderError::Authentication("bad token".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Authentication"));
        assert!(msg.contains("bad token"));
    }

    #[test]
    fn test_zone_not_found_error_display() {
        let err = DnsProviderError::ZoneNotFound {
            domain: "test.com".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("test.com"));
    }

    #[test]
    fn test_record_creation_error_display() {
        let err = DnsProviderError::RecordCreation {
            record_name: "_acme-challenge".to_string(),
            message: "API error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("_acme-challenge"));
        assert!(msg.contains("API error"));
    }

    #[test]
    fn test_record_deletion_error_display() {
        let err = DnsProviderError::RecordDeletion {
            record_id: "record-123".to_string(),
            message: "Not found".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("record-123"));
        assert!(msg.contains("Not found"));
    }

    #[test]
    fn test_rate_limited_error_display() {
        let err = DnsProviderError::RateLimited { retry_after_secs: 60 };
        let msg = err.to_string();
        assert!(msg.contains("60"));
        assert!(msg.contains("Rate limited"));
    }

    #[test]
    fn test_timeout_error_display() {
        let err = DnsProviderError::Timeout { elapsed_secs: 30 };
        let msg = err.to_string();
        assert!(msg.contains("30"));
        assert!(msg.contains("timed out"));
    }

    #[test]
    fn test_configuration_error_display() {
        let err = DnsProviderError::Configuration("invalid config".to_string());
        let msg = err.to_string();
        assert!(msg.contains("Invalid configuration"));
        assert!(msg.contains("invalid config"));
    }

    #[test]
    fn test_credentials_error_display() {
        let err = DnsProviderError::Credentials("file not found".to_string());
        let msg = err.to_string();
        assert!(msg.contains("credentials"));
        assert!(msg.contains("file not found"));
    }

    #[test]
    fn test_unsupported_domain_error_display() {
        let err = DnsProviderError::UnsupportedDomain {
            domain: "other.com".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("other.com"));
        assert!(msg.contains("not supported"));
    }
}
