//! Integration tests for DNS-01 ACME challenge support
//!
//! Tests the DNS provider implementations using wiremock to mock API responses.

use std::time::Duration;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use zentinel_proxy::acme::dns::{
    create_challenge_info, Dns01ChallengeManager, DnsProvider, DnsProviderError, HetznerProvider,
    WebhookProvider,
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "record_id": "webhook-record-123"
            })))
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "supported": true
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/domains/other.com/supported"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "supported": false
            })))
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "record_id": "record-1"
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/records"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "record_id": "record-2"
            })))
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
    use zentinel_config::server::{AcmeChallengeType, DnsProviderType, PropagationCheckConfig};

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
        let err = DnsProviderError::RateLimited {
            retry_after_secs: 60,
        };
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

// ============================================================================
// Cloudflare Provider Tests
// ============================================================================

mod cloudflare_provider {
    use super::*;
    use zentinel_proxy::acme::dns::CloudflareProvider;

    #[tokio::test]
    async fn test_create_record_success() {
        let mock_server = MockServer::start().await;
        let token = "test-token";
        let zone_id = "zone-123";
        let record_id = "record-456";

        // Mock zone lookup
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        // Mock record creation
        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": { "id": record_id }
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test(token, mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let id = provider
            .create_txt_record("example.com", "_acme-challenge", "value")
            .await
            .unwrap();

        assert_eq!(id, record_id);
    }

    #[tokio::test]
    async fn test_zone_caching() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-123";

        // Mock zone lookup - only allow ONE call
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        // First call triggers API
        let id1 = provider.supports_domain("example.com").await.unwrap();
        assert!(id1);

        // Second call should use cache (no API call, otherwise expect(1) fails)
        let id2 = provider.supports_domain("example.com").await.unwrap();
        assert!(id2);
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("bad-token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let result = provider.create_txt_record("example.com", "re", "val").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DnsProviderError::Authentication(_)
        ));
    }

    #[tokio::test]
    async fn test_delete_record_success() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-123";
        let record_id = "record-456";

        // Mock zone lookup (cached from previous if we were careful, but here new provider)
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        // Mock record deletion
        Mock::given(method("DELETE"))
            .and(path(format!(
                "/zones/{}/dns_records/{}",
                zone_id, record_id
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": {}
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let result = provider.delete_txt_record("example.com", record_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_zone_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let result = provider.supports_domain("unknown.com").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_create_record_duplicate_reuses_existing_cloudflare() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-123";
        let existing_id = "existing-456";
        let expected_content = "sqGBWGO-ubD0sYsInrp3Zo8s3GT7T6ZArO5Jcz9bNbI";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 81058, "message": "An identical record already exists." }],
                "result": null
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .and(wiremock::matchers::query_param("type", "TXT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": existing_id, "name": "_acme-challenge.example.com", "content": expected_content, "type": "TXT" }]
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let id = provider
            .create_txt_record("example.com", "_acme-challenge", expected_content)
            .await
            .unwrap();

        assert_eq!(id, existing_id);
    }

    #[tokio::test]
    async fn test_create_record_non_duplicate_still_fails() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-123";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 9000, "message": "some other error" }],
                "result": null
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let err = provider
            .create_txt_record("example.com", "_acme-challenge", "value")
            .await
            .unwrap_err();

        assert!(matches!(err, DnsProviderError::RecordCreation { .. }));
    }

    #[tokio::test]
    async fn test_cloudflare_duplicate_without_matching_value_still_fails() {
        // Duplicate error but list returns a different value — reuse must
        // not happen (apex+wildcard share _acme-challenge with different
        // contents). Provider should fall through to RecordCreation error.
        let mock_server = MockServer::start().await;
        let zone_id = "zone-123";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 81058, "message": "An identical record already exists." }],
                "result": null
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/zones/{}/dns_records", zone_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "other-id", "name": "_acme-challenge.example.com", "content": "other-value", "type": "TXT" }]
            })))
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let err = provider
            .create_txt_record("example.com", "_acme-challenge", "expected-value")
            .await
            .unwrap_err();

        assert!(matches!(err, DnsProviderError::RecordCreation { .. }));
    }

    #[tokio::test]
    async fn test_exact_zone_match() {
        let mock_server = MockServer::start().await;
        let zone_id = "zone-exact-123";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": zone_id, "name": "example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let supported = provider.supports_domain("example.com").await.unwrap();
        assert!(supported);
    }

    #[tokio::test]
    async fn test_parent_zone_fallback() {
        let mock_server = MockServer::start().await;
        let parent_zone_id = "zone-parent-456";

        // Subdomain has no direct zone
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Parent domain has a zone
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": parent_zone_id, "name": "example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let supported = provider.supports_domain("sub.example.com").await.unwrap();
        assert!(supported);
    }

    #[tokio::test]
    async fn test_most_specific_zone_selection() {
        let mock_server = MockServer::start().await;
        let sub_zone_id = "zone-sub-specific";
        let record_id = "rec-sub-specific-1";

        // Exact deep subdomain has no zone
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "a.b.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // More specific parent b.example.com has a zone (wins)
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "b.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": sub_zone_id, "name": "b.example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Less specific root parent example.com must never be queried
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "zone-root", "name": "example.com" }]
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        // TXT record is created under the more-specific zone sub_zone_id
        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", sub_zone_id)))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "type": "TXT",
                "name": "_acme-challenge.a.b.example.com",
                "content": "challenge-val",
                "ttl": 60
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let id = provider
            .create_txt_record("a.b.example.com", "_acme-challenge", "challenge-val")
            .await
            .unwrap();
        assert_eq!(id, record_id);
    }

    #[tokio::test]
    async fn test_api_failure_propagates_without_fallback() {
        let mock_server = MockServer::start().await;

        // Direct lookup fails with 500 error
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 1000, "message": "Internal error" }],
                "result": null
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        // Parent domain must never be queried when an API error occurs
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": "parent-id", "name": "example.com" }]
            })))
            .expect(0)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let err = provider
            .supports_domain("sub.example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, DnsProviderError::ApiRequest(_)));
    }

    #[tokio::test]
    async fn test_zone_caching_subdomain_parent() {
        let mock_server = MockServer::start().await;
        let parent_zone_id = "zone-parent-789";

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": parent_zone_id, "name": "example.com" }]
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        // First call populates cache
        let supported1 = provider.supports_domain("sub.example.com").await.unwrap();
        assert!(supported1);

        // Second call with same domain uses cache (no API calls, expect(1) would fail if called)
        let supported2 = provider.supports_domain("sub.example.com").await.unwrap();
        assert!(supported2);

        // Third call with wildcard normalizes to sub.example.com and hits cache
        let supported3 = provider.supports_domain("*.sub.example.com").await.unwrap();
        assert!(supported3);
    }

    #[tokio::test]
    async fn test_create_txt_record_subdomain_uses_parent_zone() {
        let mock_server = MockServer::start().await;
        let parent_zone_id = "zone-parent-999";
        let record_id = "rec-subdomain-123";

        // Subdomain has no exact zone
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "sub.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": []
            })))
            .mount(&mock_server)
            .await;

        // Parent domain has zone
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(wiremock::matchers::query_param("name", "example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": [{ "id": parent_zone_id, "name": "example.com" }]
            })))
            .mount(&mock_server)
            .await;

        // TXT record is created under the parent zone ID with full subdomain name
        Mock::given(method("POST"))
            .and(path(format!("/zones/{}/dns_records", parent_zone_id)))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "type": "TXT",
                "name": "_acme-challenge.sub.example.com",
                "content": "challenge-digest-value",
                "ttl": 60
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": { "id": record_id }
            })))
            .expect(1)
            .mount(&mock_server)
            .await;

        let provider =
            CloudflareProvider::new_test("token", mock_server.uri(), Duration::from_secs(30))
                .unwrap();

        let created_id = provider
            .create_txt_record(
                "sub.example.com",
                "_acme-challenge",
                "challenge-digest-value",
            )
            .await
            .unwrap();

        assert_eq!(created_id, record_id);
    }
}

/// Hetzner Cloud DNS API (api.hetzner.cloud/v1, zones + RRSets)
mod hetzner_provider {
    use super::*;
    use wiremock::matchers::{body_json, header, query_param};

    const ZONE_ID: u64 = 4711;
    const RRSET_PATH: &str = "/zones/4711/rrsets/_acme-challenge/TXT";

    fn provider(server: &MockServer) -> HetznerProvider {
        HetznerProvider::new_test("cloud-token", server.uri(), Duration::from_secs(5)).unwrap()
    }

    fn action(id: u64, command: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "action": {
                "id": id,
                "command": command,
                "status": status,
                "progress": if status == "running" { 0 } else { 100 },
                "started": "2026-11-14T10:00:00Z",
                "finished": null,
                "resources": [{ "id": ZONE_ID, "type": "zone" }],
                "error": if status == "error" {
                    serde_json::json!({ "code": "action_failed", "message": "boom" })
                } else {
                    serde_json::Value::Null
                }
            }
        })
    }

    fn rrset(ttl: Option<u32>, values: &[&str]) -> serde_json::Value {
        let records: Vec<_> = values
            .iter()
            .map(|v| serde_json::json!({ "value": v, "comment": "" }))
            .collect();
        serde_json::json!({
            "rrset": {
                "id": "_acme-challenge/TXT",
                "name": "_acme-challenge",
                "type": "TXT",
                "ttl": ttl,
                "labels": {},
                "protection": { "change": false },
                "records": records,
                "zone": ZONE_ID
            }
        })
    }

    /// Zone `example.com` exists; any other name filter returns no zones.
    async fn mount_zone(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/zones"))
            .and(query_param("name", "example.com"))
            .and(header("authorization", "Bearer cloud-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "zones": [{ "id": ZONE_ID, "name": "example.com", "mode": "primary" }],
                "meta": { "pagination": { "page": 1, "per_page": 25, "total_entries": 1 } }
            })))
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "zones": [],
                "meta": { "pagination": { "page": 1, "per_page": 25, "total_entries": 0 } }
            })))
            .with_priority(10)
            .mount(server)
            .await;
    }

    async fn mount_rrset_missing(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": { "code": "not_found", "message": "rrset not found" }
            })))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn create_adds_quoted_value_with_bearer_token() {
        let server = MockServer::start().await;
        mount_zone(&server).await;
        mount_rrset_missing(&server).await;

        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .and(header("authorization", "Bearer cloud-token"))
            .and(body_json(serde_json::json!({
                "ttl": 60,
                "records": [{ "value": "\"challenge-value\"", "comment": "zentinel acme dns-01 challenge" }]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(1, "add_records", "success")))
            .expect(1)
            .mount(&server)
            .await;

        let id = provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "challenge-value")
            .await
            .unwrap();
        assert_eq!(id, "4711/_acme-challenge/challenge-value");
    }

    #[tokio::test]
    async fn create_walks_up_to_parent_zone() {
        let server = MockServer::start().await;
        mount_zone(&server).await;

        Mock::given(method("GET"))
            .and(path("/zones/4711/rrsets/_acme-challenge.a.b/TXT"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/zones/4711/rrsets/_acme-challenge.a.b/TXT/actions/add_records",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                2,
                "add_records",
                "success",
            )))
            .expect(1)
            .mount(&server)
            .await;

        let id = provider(&server)
            .create_txt_record("a.b.example.com", "_acme-challenge", "v1")
            .await
            .unwrap();
        assert_eq!(id, "4711/_acme-challenge.a.b/v1");

        // a.b.example.com, b.example.com, example.com
        let zone_lookups = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/zones")
            .count();
        assert_eq!(zone_lookups, 3);
    }

    /// Wildcard + apex: the second challenge value is added next to the
    /// first, keeping the RRSet's TTL; the existing value is not resent.
    #[tokio::test]
    async fn create_appends_to_existing_rrset_without_clobbering() {
        let server = MockServer::start().await;
        mount_zone(&server).await;

        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(rrset(Some(300), &["\"apex-value\""])),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .and(body_json(serde_json::json!({
                "ttl": 300,
                "records": [{ "value": "\"wildcard-value\"", "comment": "zentinel acme dns-01 challenge" }]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(3, "add_records", "success")))
            .expect(1)
            .mount(&server)
            .await;
        // set_records would replace the RRSet; it must never be used.
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/set_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "wildcard-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_reuses_value_already_present() {
        let server = MockServer::start().await;
        mount_zone(&server).await;

        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(rrset(Some(60), &["\"leftover\""])),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let id = provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "leftover")
            .await
            .unwrap();
        assert_eq!(id, "4711/_acme-challenge/leftover");
    }

    #[tokio::test]
    async fn create_waits_for_running_action() {
        let server = MockServer::start().await;
        mount_zone(&server).await;
        mount_rrset_missing(&server).await;

        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                42,
                "add_records",
                "running",
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones/actions/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(action(
                42,
                "add_records",
                "running",
            )))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/zones/actions/42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(action(
                42,
                "add_records",
                "success",
            )))
            .with_priority(2)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "v")
            .await
            .unwrap();

        let polls = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/zones/actions/42")
            .count();
        assert_eq!(polls, 3);
    }

    #[tokio::test]
    async fn create_fails_when_action_fails() {
        let server = MockServer::start().await;
        mount_zone(&server).await;
        mount_rrset_missing(&server).await;

        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                5,
                "add_records",
                "error",
            )))
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "v")
            .await
            .unwrap_err();
        assert!(
            matches!(err, DnsProviderError::RecordCreation { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("boom"), "{err}");
    }

    #[tokio::test]
    async fn create_retries_while_rrset_locked() {
        let server = MockServer::start().await;
        mount_zone(&server).await;
        mount_rrset_missing(&server).await;

        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(423).set_body_json(serde_json::json!({
                "error": { "code": "locked", "message": "there is already an action running" }
            })))
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                6,
                "add_records",
                "success",
            )))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "v")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn old_dns_console_token_gets_a_clear_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": { "code": "unauthorized", "message": "unable to authenticate" }
            })))
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, DnsProviderError::Authentication(_)), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("unauthorized"), "{msg}");
        assert!(msg.contains("dns.hetzner.com"), "{msg}");
        assert!(msg.contains("Hetzner Console"), "{msg}");
    }

    #[tokio::test]
    async fn zone_not_found() {
        let server = MockServer::start().await;
        mount_zone(&server).await;

        let p = provider(&server);
        let err = p
            .create_txt_record("example.org", "_acme-challenge", "v")
            .await
            .unwrap_err();
        assert!(
            matches!(err, DnsProviderError::ZoneNotFound { .. }),
            "{err}"
        );
        assert!(!p.supports_domain("example.org").await.unwrap());
        assert!(p.supports_domain("*.example.com").await.unwrap());
    }

    #[tokio::test]
    async fn secondary_zone_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/zones"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "zones": [{ "id": ZONE_ID, "name": "example.com", "mode": "secondary" }]
            })))
            .mount(&server)
            .await;

        let err = provider(&server)
            .create_txt_record("example.com", "_acme-challenge", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, DnsProviderError::Configuration(_)), "{err}");
    }

    /// Cleanup sends only our value, exactly as Hetzner stores it.
    #[tokio::test]
    async fn delete_removes_only_our_value() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(rrset(Some(60), &["\"other-value\"", "\"our-value\""])),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/remove_records", RRSET_PATH)))
            .and(header("authorization", "Bearer cloud-token"))
            .and(body_json(serde_json::json!({
                "records": [{ "value": "\"our-value\"" }]
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                7,
                "remove_records",
                "success",
            )))
            .expect(1)
            .mount(&server)
            .await;

        provider(&server)
            .delete_txt_record("example.com", "4711/_acme-challenge/our-value")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        // RRSet gone
        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        // RRSet present, but without our value
        Mock::given(method("GET"))
            .and(path("/zones/4711/rrsets/_acme-challenge.sub/TXT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(rrset(Some(60), &["\"other\""])))
            .mount(&server)
            .await;

        let p = provider(&server);
        p.delete_txt_record("example.com", "4711/_acme-challenge/v")
            .await
            .unwrap();
        p.delete_txt_record("sub.example.com", "4711/_acme-challenge.sub/v")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_then_delete_roundtrip() {
        let server = MockServer::start().await;
        mount_zone(&server).await;
        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(ResponseTemplate::new(404))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(RRSET_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(rrset(Some(60), &["\"x\""])))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/add_records", RRSET_PATH)))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                8,
                "add_records",
                "success",
            )))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{}/actions/remove_records", RRSET_PATH)))
            .and(body_json(
                serde_json::json!({ "records": [{ "value": "\"x\"" }] }),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(action(
                9,
                "remove_records",
                "success",
            )))
            .expect(1)
            .mount(&server)
            .await;

        // Wildcard names resolve to the same record as the apex.
        let p = provider(&server);
        let id = p
            .create_txt_record("*.example.com", "_acme-challenge", "x")
            .await
            .unwrap();
        p.delete_txt_record("example.com", &id).await.unwrap();
    }
}
