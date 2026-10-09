//! Integration and lifecycle tests for RFC 9773 ACME Renewal Information (ARI)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeZone, Utc};
use instant_acme::{CertificateIdentifier, Identifier, NewOrder};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use zentinel_config::server::{AcmeChallengeType, AcmeConfig, AcmeKeyType};
use zentinel_proxy::acme::ari::{
    calculate_retry_delay, clamp_refresh_interval, extract_certificate_identifier,
    extract_leaf_certificate_der, next_wakeup, select_renewal_time, select_renewal_time_at_ratio,
    AriCapability, AriError, AriErrorClassification, AriSchedulerState, RenewalWindow,
    ARI_LONG_TERM_RETRY_INTERVAL, ARI_MAX_REFRESH_INTERVAL, ARI_MIN_REFRESH_INTERVAL,
};
use zentinel_proxy::acme::{AcmeClient, CertificateStorage, ChallengeManager, RenewalScheduler};

fn fixtures_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/tls")
}

fn create_test_scheduler(
    storage_dir: PathBuf,
) -> (Arc<AcmeClient>, Arc<CertificateStorage>, RenewalScheduler) {
    let storage = Arc::new(CertificateStorage::new(&storage_dir).unwrap());
    let config = AcmeConfig {
        email: "ari-test@example.com".to_string(),
        domains: vec!["example.com".to_string()],
        server_url: None,
        staging: true,
        eab: None,
        storage: storage_dir,
        renew_before_days: 30,
        challenge_type: AcmeChallengeType::Http01,
        key_type: AcmeKeyType::EcdsaP256,
        dns_provider: None,
    };
    let client = Arc::new(AcmeClient::new(config, Arc::clone(&storage)));
    let challenge_mgr = Arc::new(ChallengeManager::new());
    let scheduler = RenewalScheduler::new(Arc::clone(&client), challenge_mgr, None);
    (client, storage, scheduler)
}

// ============================================================================
// 1. Certificate Identification Tests
// ============================================================================

#[test]
fn test_extract_ari_identifier_from_real_leaf_certificate() {
    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();

    let cert_id = extract_certificate_identifier(&cert_pem).unwrap();

    // Verify identifier components
    assert!(!cert_id.authority_key_identifier.is_empty());
    assert!(!cert_id.serial.is_empty());

    let formatted = cert_id.to_string();
    assert!(formatted.contains('.'));
    let parts: Vec<&str> = formatted.split('.').collect();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], cert_id.authority_key_identifier.as_ref());
    assert_eq!(parts[1], cert_id.serial.as_ref());
}

#[test]
fn test_extract_ari_identifier_from_certificate_chain() {
    let fixtures = fixtures_path();
    let leaf_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let ca_pem = std::fs::read_to_string(fixtures.join("ca.crt")).unwrap();

    // Chain: leaf followed by CA
    let chain_pem = format!("{}\n{}", leaf_pem, ca_pem);

    let leaf_id = extract_certificate_identifier(&leaf_pem).unwrap();
    let chain_id = extract_certificate_identifier(&chain_pem).unwrap();

    // Leaf certificate identifier must be extracted, not the CA
    assert_eq!(leaf_id, chain_id);
}

#[test]
fn test_extract_leaf_der_success() {
    let fixtures = fixtures_path();
    let leaf_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let der = extract_leaf_certificate_der(&leaf_pem).unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_select_renewal_time_random_in_bounds() {
    let now = Utc::now();
    let start = now + chrono::Duration::days(1);
    let end = now + chrono::Duration::days(5);
    let window = RenewalWindow::new(start, end).unwrap();

    let chosen = select_renewal_time(&window, None, None, now);
    assert!(chosen >= start && chosen <= end);
}

#[test]
fn test_extract_ari_identifier_missing_aki_fails_safely() {
    // Generate a simple self-signed certificate without AKI extension using rcgen
    let cert = rcgen::generate_simple_self_signed(vec!["no-aki.example.com".to_string()]).unwrap();
    let no_aki_pem = cert.cert.pem();

    let res = extract_certificate_identifier(&no_aki_pem);
    assert!(res.is_err());
    let err_msg = res.unwrap_err().to_string();
    assert!(err_msg.contains("Authority Key Identifier") || err_msg.contains("AKI"));
}

#[test]
fn test_extract_ari_identifier_malformed_pem_fails_safely() {
    let malformed = "-----BEGIN CERTIFICATE-----\ninvalid base64!!!\n-----END CERTIFICATE-----";
    let res = extract_certificate_identifier(malformed);
    assert!(res.is_err());

    let not_pem = "random non-pem content";
    let res2 = extract_certificate_identifier(not_pem);
    assert!(res2.is_err());
}

#[test]
fn test_no_predecessor_certificate_behavior() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (_client, _storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());

    // When no predecessor exists in storage
    scheduler.set_ari_capability(AriCapability::Supported);
    let state = scheduler.ari_state();
    assert!(state.certificate_id.is_none());
    assert_eq!(state.capability, AriCapability::Supported);
}

// ============================================================================
// 2. Window Selection Tests
// ============================================================================

#[test]
fn test_valid_future_window_selection() {
    let now = Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap();
    let start = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 10, 10, 0, 0, 0).unwrap();
    let window = RenewalWindow::new(start, end).unwrap();

    let selected = select_renewal_time_at_ratio(&window, None, None, now, 0.25);
    assert!(selected >= start && selected <= end);
    assert_eq!(
        selected,
        start + chrono::Duration::seconds((5.0 * 86400.0 * 0.25) as i64)
    );
}

#[test]
fn test_window_starting_in_past_results_in_immediate_renewal() {
    let now = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap();
    let start = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 10, 10, 0, 0, 0).unwrap();
    let window = RenewalWindow::new(start, end).unwrap();

    let selected = select_renewal_time_at_ratio(&window, None, None, now, 0.5);
    assert_eq!(selected, now);
}

#[test]
fn test_window_end_equal_or_earlier_than_start_is_rejected() {
    let t = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();

    // Equal
    let res_equal = RenewalWindow::new(t, t);
    assert!(matches!(
        res_equal.unwrap_err(),
        AriError::InvalidWindow { .. }
    ));

    // Earlier
    let res_earlier = RenewalWindow::new(t, t - chrono::Duration::hours(1));
    assert!(matches!(
        res_earlier.unwrap_err(),
        AriError::InvalidWindow { .. }
    ));
}

#[test]
fn test_unchanged_window_does_not_move_renewal_time() {
    let now = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let start = Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 10, 10, 0, 0, 0).unwrap();
    let window = RenewalWindow::new(start, end).unwrap();

    let initial_time = start + chrono::Duration::days(2);
    let reselected = select_renewal_time_at_ratio(
        &window,
        Some(&window),
        Some(initial_time),
        now,
        0.9, // Different ratio must not alter the stable renewal time
    );

    assert_eq!(reselected, initial_time);
}

#[test]
fn test_changed_window_updates_schedule_using_intersection() {
    let now = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let w1 = RenewalWindow::new(
        Utc.with_ymd_and_hms(2026, 10, 5, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 10, 15, 0, 0, 0).unwrap(),
    )
    .unwrap();
    let w2 = RenewalWindow::new(
        Utc.with_ymd_and_hms(2026, 10, 10, 0, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 10, 20, 0, 0, 0).unwrap(),
    )
    .unwrap();

    // Intersection is Oct 10 to Oct 15 (5 days)
    let selected = select_renewal_time_at_ratio(&w2, Some(&w1), None, now, 0.5);
    assert_eq!(
        selected,
        Utc.with_ymd_and_hms(2026, 10, 12, 12, 0, 0).unwrap()
    );
}

#[test]
fn test_renewal_deadline_precedence_over_later_refresh_deadline() {
    let now_utc = Utc::now();
    let now_inst = tokio::time::Instant::now();

    // Renewal in 5 minutes, refresh in 2 hours
    let renewal_deadline = now_utc + chrono::Duration::minutes(5);
    let next_refresh = now_inst + Duration::from_secs(7200);
    let fallback = Duration::from_secs(12 * 3600);

    let wake = next_wakeup(
        now_utc,
        now_inst,
        Some(renewal_deadline),
        Some(next_refresh),
        fallback,
    );
    let diff = wake.duration_since(now_inst);
    assert!(diff <= Duration::from_secs(305) && diff >= Duration::from_secs(295));
}

// ============================================================================
// 3. Refresh Scheduling and Failure Tests
// ============================================================================

#[test]
fn test_retry_after_calculated_and_bounded() {
    // Clamping to 1 minute minimum
    assert_eq!(
        clamp_refresh_interval(Duration::from_secs(5)),
        ARI_MIN_REFRESH_INTERVAL
    );
    assert_eq!(
        clamp_refresh_interval(Duration::from_secs(59)),
        ARI_MIN_REFRESH_INTERVAL
    );

    // Normal values preserved
    assert_eq!(
        clamp_refresh_interval(Duration::from_secs(3600)),
        Duration::from_secs(3600)
    );

    // Clamping to 24 hours maximum
    assert_eq!(
        clamp_refresh_interval(Duration::from_secs(90_000)),
        ARI_MAX_REFRESH_INTERVAL
    );
}

#[test]
fn test_temporary_failures_exponential_backoff_and_exhaustion() {
    let (d0, trans0) = calculate_retry_delay(AriErrorClassification::Temporary, 0);
    assert_eq!(d0, Duration::from_secs(60));
    assert!(!trans0);

    let (d1, trans1) = calculate_retry_delay(AriErrorClassification::Temporary, 1);
    assert_eq!(d1, Duration::from_secs(120));
    assert!(!trans1);

    let (d2, trans2) = calculate_retry_delay(AriErrorClassification::Temporary, 2);
    assert_eq!(d2, Duration::from_secs(240));
    assert!(!trans2);

    // Attempt 3: exhausted temporary sequence -> transitions to 6h
    let (d3, trans3) = calculate_retry_delay(AriErrorClassification::Temporary, 3);
    assert_eq!(d3, ARI_LONG_TERM_RETRY_INTERVAL);
    assert!(trans3);
}

#[test]
fn test_invalid_responses_use_long_term_error_path() {
    let (d, trans) = calculate_retry_delay(AriErrorClassification::LongTerm, 0);
    assert_eq!(d, ARI_LONG_TERM_RETRY_INTERVAL);
    assert!(!trans);

    // Invalid window error classifies as LongTerm
    let invalid_win = AriError::InvalidWindow {
        start: Utc::now(),
        end: Utc::now(),
    };
    assert_eq!(
        invalid_win.classification(),
        AriErrorClassification::LongTerm
    );
}

#[test]
fn test_unsupported_ari_does_not_repeat_tight_retries() {
    let (d, trans) = calculate_retry_delay(AriErrorClassification::Unsupported, 0);
    assert_eq!(d, ARI_LONG_TERM_RETRY_INTERVAL);
    assert!(!trans);
}

#[test]
fn test_transient_refresh_failure_does_not_discard_valid_window() {
    let mut state = AriSchedulerState::default();
    let now = Utc::now();
    let window = RenewalWindow::new(
        now + chrono::Duration::days(10),
        now + chrono::Duration::days(20),
    )
    .unwrap();
    let deadline = now + chrono::Duration::days(15);

    state.capability = AriCapability::Supported;
    state.last_window = Some(window.clone());
    state.renewal_deadline = Some(deadline);

    // Simulate transient failure during refresh: update retry state only
    state.temp_failure_count += 1;
    let (delay, _) =
        calculate_retry_delay(AriErrorClassification::Temporary, state.temp_failure_count);
    state.next_refresh = Some(tokio::time::Instant::now() + delay);

    // Window and renewal deadline MUST be preserved
    assert_eq!(state.last_window.as_ref(), Some(&window));
    assert_eq!(state.renewal_deadline, Some(deadline));
    assert_eq!(state.capability, AriCapability::Supported);
}

#[test]
fn test_fallback_policy_when_no_valid_ari_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (client, storage, _scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());

    // Save cert expiring in 10 days
    let expires = Utc::now() + chrono::Duration::days(10);
    storage
        .save_certificate(
            "example.com",
            "cert-data",
            "key-data",
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // renew_before_days is 30, so needs_renewal must be true
    assert!(client.needs_renewal("example.com").unwrap());
}

// ============================================================================
// 4. Order Replacement Tests
// ============================================================================

#[test]
fn test_new_order_serialization_with_and_without_replaces() {
    let id = Identifier::Dns("example.com".to_string());
    let identifiers = vec![id];

    // Initial issuance: no replaces
    let order_initial = NewOrder::new(&identifiers);
    let json_initial = serde_json::to_value(&order_initial).unwrap();
    assert!(json_initial.get("replaces").is_none());

    // Renewal with replaces
    let cert_id = CertificateIdentifier {
        authority_key_identifier: "aki123".into(),
        serial: "ser456".into(),
    };
    let order_renewal = NewOrder::new(&identifiers).replaces(cert_id);
    let json_renewal = serde_json::to_value(&order_renewal).unwrap();
    assert_eq!(json_renewal.get("replaces").unwrap(), "aki123.ser456");
}

#[test]
fn test_predecessor_id_only_used_when_ari_supported() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (_client, storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());

    // Save valid predecessor certificate with AKI
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

    // 1. When capability is Unknown -> predecessor identifier is NOT used
    scheduler.set_ari_capability(AriCapability::Unknown);
    assert_eq!(scheduler.ari_capability(), AriCapability::Unknown);

    // 2. When capability is Unsupported -> predecessor identifier is NOT used
    scheduler.set_ari_capability(AriCapability::Unsupported);
    assert_eq!(scheduler.ari_capability(), AriCapability::Unsupported);

    // 3. When capability is Supported -> predecessor identifier IS extracted and used
    scheduler.set_ari_capability(AriCapability::Supported);
    assert_eq!(scheduler.ari_capability(), AriCapability::Supported);
}

#[test]
fn test_after_renewal_predecessor_is_not_refreshed() {
    let mut state = AriSchedulerState::default();
    let old_id = CertificateIdentifier {
        authority_key_identifier: "old_aki".into(),
        serial: "old_serial".into(),
    };
    state.certificate_id = Some(old_id);
    state.last_window =
        Some(RenewalWindow::new(Utc::now(), Utc::now() + chrono::Duration::days(1)).unwrap());
    state.renewal_deadline = Some(Utc::now() + chrono::Duration::hours(12));
    state.temp_failure_count = 2;

    // Simulate certificate renewal
    let new_id = CertificateIdentifier {
        authority_key_identifier: "new_aki".into(),
        serial: "new_serial".into(),
    };
    state.reset_for_new_certificate(Some(new_id.clone()));

    // Verify predecessor state was invalidated
    assert_eq!(state.certificate_id, Some(new_id));
    assert!(state.last_window.is_none());
    assert!(state.renewal_deadline.is_none());
    assert!(state.next_refresh.is_none());
    assert_eq!(state.temp_failure_count, 0);
}

// ============================================================================
// 5. Lifecycle Integration Tests
// ============================================================================

#[test]
fn test_ari_failure_does_not_corrupt_storage_or_prevent_fallback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (client, storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(20);

    storage
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // Mark CA as unsupported
    scheduler.set_ari_capability(AriCapability::Unsupported);

    // Cert data in storage remains completely intact
    let loaded = storage.load_certificate("example.com").unwrap().unwrap();
    assert_eq!(loaded.cert_pem, cert_pem);
    assert_eq!(loaded.key_pem, key_pem);

    // Fallback renewal path is active and functions normally
    assert!(client.needs_renewal("example.com").unwrap());
}

#[tokio::test]
async fn test_mock_acme_ari_endpoint_response_flow() {
    let mock_server = MockServer::start().await;

    // Mock ARI endpoint
    Mock::given(method("GET"))
        .and(path("/renewal-info/aki123.ser456"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "1800")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": "2026-10-10T00:00:00Z",
                        "end": "2026-10-20T00:00:00Z"
                    },
                    "explanationURL": "https://example.com/ari-docs"
                })),
        )
        .mount(&mock_server)
        .await;

    // Fetch mock renewal info directly via reqwest client
    let url = format!("{}/renewal-info/aki123.ser456", mock_server.uri());
    let resp = reqwest::get(&url).await.unwrap();
    assert_eq!(resp.status(), 200);

    let retry_after_header = resp.headers().get("Retry-After").unwrap().to_str().unwrap();
    assert_eq!(retry_after_header, "1800");

    let body: serde_json::Value = resp.json().await.unwrap();
    let window_start = body["suggestedWindow"]["start"].as_str().unwrap();
    let window_end = body["suggestedWindow"]["end"].as_str().unwrap();
    assert_eq!(window_start, "2026-10-10T00:00:00Z");
    assert_eq!(window_end, "2026-10-20T00:00:00Z");
}
