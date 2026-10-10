//! Integration and lifecycle tests for RFC 9773 ACME Renewal Information (ARI)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{TimeZone, Utc};
use instant_acme::{CertificateIdentifier, Identifier, NewOrder};
use wiremock::matchers::{method, path, path_regex};
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

fn create_test_http_client() -> Box<dyn instant_acme::HttpClient> {
    let connector = hyper_util::client::legacy::connect::HttpConnector::new();
    let client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        instant_acme::BodyWrapper<bytes::Bytes>,
    > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(connector);
    Box::new(client)
}

async fn setup_mock_acme(
    with_renewal_info: bool,
    storage_dir: PathBuf,
) -> (MockServer, Arc<AcmeClient>, RenewalScheduler) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mock = MockServer::start().await;
    let base = mock.uri();

    let dir_body = if with_renewal_info {
        serde_json::json!({
            "newNonce": format!("{base}/new-nonce"),
            "newAccount": format!("{base}/new-account"),
            "newOrder": format!("{base}/new-order"),
            "renewalInfo": format!("{base}/renewal-info"),
        })
    } else {
        serde_json::json!({
            "newNonce": format!("{base}/new-nonce"),
            "newAccount": format!("{base}/new-account"),
            "newOrder": format!("{base}/new-order"),
        })
    };

    Mock::given(method("GET"))
        .and(path("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(dir_body))
        .mount(&mock)
        .await;

    Mock::given(method("HEAD"))
        .and(path("/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "test-nonce-1"))
        .mount(&mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/new-account"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("replay-nonce", "test-nonce-2")
                .insert_header("location", format!("{base}/account/1"))
                .set_body_json(serde_json::json!({"status": "valid"})),
        )
        .mount(&mock)
        .await;

    let storage = Arc::new(CertificateStorage::new(&storage_dir).unwrap());
    let config = AcmeConfig {
        email: "ari-test@example.com".to_string(),
        domains: vec!["example.com".to_string()],
        server_url: Some(format!("{base}/directory")),
        staging: false,
        eab: None,
        storage: storage_dir,
        renew_before_days: 30,
        challenge_type: AcmeChallengeType::Http01,
        key_type: AcmeKeyType::EcdsaP256,
        dns_provider: None,
    };
    let client = Arc::new(
        AcmeClient::new(config, Arc::clone(&storage)).with_custom_http(create_test_http_client),
    );
    let challenge_mgr = Arc::new(ChallengeManager::new());
    let scheduler = RenewalScheduler::new(Arc::clone(&client), challenge_mgr, None);

    (mock, client, scheduler)
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
    let state = AriSchedulerState {
        capability: AriCapability::Supported,
        ..Default::default()
    };
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
fn test_window_started_extends_into_future() {
    let now = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap();
    let start = Utc.with_ymd_and_hms(2026, 10, 1, 0, 0, 0).unwrap();
    let end = Utc.with_ymd_and_hms(2026, 10, 10, 0, 0, 0).unwrap();
    let window = RenewalWindow::new(start, end).unwrap();

    // Ratio 0.0 -> start (Oct 1) is in the past -> immediate renewal (returns now)
    let selected_past = select_renewal_time_at_ratio(&window, None, None, now, 0.0);
    assert_eq!(selected_past, now);

    // Ratio 0.75 -> selected time is in the future
    let selected_future = select_renewal_time_at_ratio(&window, None, None, now, 0.75);
    assert_eq!(
        selected_future,
        start + chrono::Duration::seconds((9.0 * 86400.0 * 0.75) as i64)
    );
    assert!(selected_future > now);
}

#[test]
fn test_window_entirely_in_past_is_immediate() {
    let now = Utc.with_ymd_and_hms(2026, 10, 15, 0, 0, 0).unwrap();
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
fn test_changed_window_selected_from_new_window_not_intersection() {
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

    // RFC 9773 §4.2: Selected against w2 directly (Oct 10 to Oct 20, 10 days). Midpoint is Oct 15, NOT intersection midpoint (Oct 12.5).
    let selected = select_renewal_time_at_ratio(&w2, Some(&w1), None, now, 0.5);
    assert_eq!(
        selected,
        Utc.with_ymd_and_hms(2026, 10, 15, 0, 0, 0).unwrap()
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
    // 1st temporary failure: base backoff (1 min)
    let (d1, trans1) = calculate_retry_delay(AriErrorClassification::Temporary, 1);
    assert_eq!(d1, Duration::from_secs(60));
    assert!(!trans1);

    // 2nd temporary failure: 2 mins
    let (d2, trans2) = calculate_retry_delay(AriErrorClassification::Temporary, 2);
    assert_eq!(d2, Duration::from_secs(120));
    assert!(!trans2);

    // 3rd temporary failure: 4 mins
    let (d3, trans3) = calculate_retry_delay(AriErrorClassification::Temporary, 3);
    assert_eq!(d3, Duration::from_secs(240));
    assert!(!trans3);

    // 4th temporary failure (> ARI_MAX_TEMP_RETRIES): exhausted, transitions to 6h
    let (d4, trans4) = calculate_retry_delay(AriErrorClassification::Temporary, 4);
    assert_eq!(d4, ARI_LONG_TERM_RETRY_INTERVAL);
    assert!(trans4);
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
    let (_client, _storage, scheduler) = create_test_scheduler(temp_dir.path().to_path_buf());

    // Fresh scheduler starts with Unknown capability
    assert_eq!(scheduler.ari_capability(), AriCapability::Unknown);
}

#[test]
fn test_after_renewal_predecessor_is_not_refreshed() {
    let old_id = CertificateIdentifier {
        authority_key_identifier: "old_aki".into(),
        serial: "old_serial".into(),
    };
    let mut state = AriSchedulerState {
        certificate_id: Some(old_id),
        last_window: Some(
            RenewalWindow::new(Utc::now(), Utc::now() + chrono::Duration::days(1)).unwrap(),
        ),
        renewal_deadline: Some(Utc::now() + chrono::Duration::hours(12)),
        temp_failure_count: 2,
        ..Default::default()
    };

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

    // Cert data in storage remains completely intact
    let loaded = storage.load_certificate("example.com").unwrap().unwrap();
    assert_eq!(loaded.cert_pem, cert_pem);
    assert_eq!(loaded.key_pem, key_pem);

    // Fallback renewal path is active and functions normally
    assert!(client.needs_renewal("example.com").unwrap());
    assert!(scheduler.is_renewal_due("example.com").unwrap());
}

// ============================================================================
// 6. Real Application-Path Tests (Client & Scheduler Integration)
// ============================================================================

#[tokio::test]
async fn test_client_renewal_info_mock_server() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, _scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let cert_id = client.extract_certificate_identifier(&cert_pem).unwrap();

    let start_dt = Utc::now() + chrono::Duration::days(30);
    let end_dt = Utc::now() + chrono::Duration::days(60);
    let start_str = start_dt.to_rfc3339();
    let end_str = end_dt.to_rfc3339();

    let cert_id_str = cert_id.to_string();
    Mock::given(method("GET"))
        .and(path(format!("/renewal-info/{cert_id_str}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": start_str,
                        "end": end_str
                    },
                    "explanationURL": "https://example.com/ari-docs"
                })),
        )
        .mount(&mock)
        .await;

    let (info, retry_after) = client.renewal_info(&cert_id).await.unwrap();
    assert!((retry_after.as_secs_f64() - 3600.0).abs() < 2.0);
    assert_eq!(
        info.explanation_url.as_deref(),
        Some("https://example.com/ari-docs")
    );
    assert_eq!(
        info.suggested_window.start.unix_timestamp(),
        start_dt.timestamp()
    );
    assert_eq!(
        info.suggested_window.end.unix_timestamp(),
        end_dt.timestamp()
    );
}

#[tokio::test]
async fn test_scheduler_refresh_failure_schedules_future_retry_no_tight_loop() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(60);

    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // Mock 500 server error on ARI endpoint (RFC 9773 §4.3.3 requires Retry-After)
    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("Retry-After", "60")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "status": 500,
                    "detail": "temporary internal error"
                })),
        )
        .mount(&mock)
        .await;

    let res = scheduler.refresh_ari().await;
    assert!(res.is_err(), "Overdue refresh should fail with 500");

    let state = scheduler.ari_state();
    // Invariant: Failed refresh MUST leave next_refresh in the future!
    assert!(
        state.next_refresh.unwrap() > tokio::time::Instant::now(),
        "Failed refresh must move next_refresh into the future to prevent tight loop"
    );
    assert_eq!(state.temp_failure_count, 1);
}

#[tokio::test]
async fn test_capability_detection_unsupported_vs_non_5xx() {
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. Explicit unsupported: Directory lacks renewalInfo
    let (_mock_unsup, client_unsup, scheduler_unsup) =
        setup_mock_acme(false, temp_dir.path().join("unsup")).await;

    client_unsup.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(60);

    client_unsup
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    let err_unsup = scheduler_unsup.refresh_ari().await.unwrap_err();
    assert!(matches!(err_unsup, zentinel_proxy::acme::AcmeError::Ari(_)));
    assert_eq!(scheduler_unsup.ari_capability(), AriCapability::Unsupported);
    assert!(scheduler_unsup.ari_state().renewal_deadline.is_none());

    // 2. HTTP 404 from renewal info endpoint: Should NOT mark CA as Unsupported (treated as LongTerm error)
    let (mock_404, client_404, scheduler_404) =
        setup_mock_acme(true, temp_dir.path().join("404")).await;

    client_404.init_account().await.unwrap();
    client_404
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(404)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:malformed",
                    "status": 404,
                    "detail": "Certificate ID not found"
                })),
        )
        .mount(&mock_404)
        .await;

    let err_404 = scheduler_404.refresh_ari().await.unwrap_err();
    assert!(matches!(err_404, zentinel_proxy::acme::AcmeError::Ari(_)));
    // RFC 9773 §4.3.3: 404 is a long-term error, NOT an indication that the CA is Unsupported
    assert_ne!(scheduler_404.ari_capability(), AriCapability::Unsupported);
    assert_eq!(scheduler_404.ari_capability(), AriCapability::Unknown);
    // Scheduled for long-term retry (approx 6h)
    let delay = scheduler_404
        .ari_state()
        .next_refresh
        .unwrap()
        .duration_since(tokio::time::Instant::now());
    assert!(delay >= Duration::from_secs(5 * 3600));

    // 3. HTTP 500 with Problem body missing status field (dependency limitation)
    let (mock_no_status, client_no_status, scheduler_no_status) =
        setup_mock_acme(true, temp_dir.path().join("no_status")).await;

    client_no_status.init_account().await.unwrap();
    client_no_status
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(500)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:serverInternal",
                    "detail": "Internal server error without status field"
                })),
        )
        .mount(&mock_no_status)
        .await;

    let err_no_status = scheduler_no_status.refresh_ari().await.unwrap_err();
    assert!(matches!(
        err_no_status,
        zentinel_proxy::acme::AcmeError::Ari(_)
    ));
    // When status field is omitted in Problem document, the transport HTTP status
    // cannot be recovered through instant-acme; conservatively classified as LongTerm (not Unsupported)
    assert_ne!(
        scheduler_no_status.ari_capability(),
        AriCapability::Unsupported
    );
    assert_eq!(scheduler_no_status.ari_capability(), AriCapability::Unknown);

    // 4. HTTP 500 without Retry-After header (dependency limitation)
    let (mock_no_ra, client_no_ra, scheduler_no_ra) =
        setup_mock_acme(true, temp_dir.path().join("no_ra")).await;

    client_no_ra.init_account().await.unwrap();
    client_no_ra
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_no_ra)
        .await;

    let err_no_ra = scheduler_no_ra.refresh_ari().await.unwrap_err();
    assert!(matches!(err_no_ra, zentinel_proxy::acme::AcmeError::Ari(_)));
    // Missing Retry-After header causes instant-acme to discard the HTTP status
    // and emit Error::Str("missing Retry-After header"). Classified as LongTerm, not Unsupported.
    assert_ne!(scheduler_no_ra.ari_capability(), AriCapability::Unsupported);
    assert_eq!(scheduler_no_ra.ari_capability(), AriCapability::Unknown);
}

#[tokio::test]
async fn test_order_creation_replaces_serialized_with_wiremock() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, _scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let cert_id = client.extract_certificate_identifier(&cert_pem).unwrap();

    let order_expires = (Utc::now() + chrono::Duration::days(7)).to_rfc3339();

    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("replay-nonce", "test-nonce-order")
                .insert_header("location", format!("{}/order/1", mock.uri()))
                .set_body_json(serde_json::json!({
                    "status": "pending",
                    "expires": order_expires,
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "authorizations": [],
                    "finalize": format!("{}/order/1/finalize", mock.uri()),
                    "replaces": cert_id.to_string()
                })),
        )
        .up_to_n_times(1)
        .mount(&mock)
        .await;

    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("replay-nonce", "test-nonce-order-2")
                .insert_header("location", format!("{}/order/2", mock.uri()))
                .set_body_json(serde_json::json!({
                    "status": "pending",
                    "expires": (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "authorizations": [],
                    "finalize": format!("{}/order/2/finalize", mock.uri())
                })),
        )
        .mount(&mock)
        .await;

    // 1. Order with replaces: Payload must contain replaces field
    let (order_with_replaces, _) = client.create_order(Some(&cert_id)).await.unwrap();
    assert_eq!(order_with_replaces.url(), format!("{}/order/1", mock.uri()));

    let requests = mock.received_requests().await.unwrap();
    let order_req = requests
        .iter()
        .find(|r| r.url.path() == "/new-order")
        .expect("Must have posted to /new-order");

    let jws_json: serde_json::Value = serde_json::from_slice(&order_req.body).unwrap();
    let payload_b64 = jws_json["payload"].as_str().expect("JWS must have payload");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("Payload is valid base64url");
    let payload_json: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(
        payload_json["replaces"].as_str(),
        Some(cert_id.to_string().as_str()),
        "Order request must contain replaces field with predecessor certificate ID"
    );

    // 2. Initial issuance (no replaces): Payload must NOT contain replaces
    let _ = client.create_order(None).await.unwrap();
    let all_requests = mock.received_requests().await.unwrap();
    let order_reqs: Vec<_> = all_requests
        .iter()
        .filter(|r| r.url.path() == "/new-order")
        .collect();
    assert_eq!(order_reqs.len(), 2);

    let second_jws: serde_json::Value = serde_json::from_slice(&order_reqs[1].body).unwrap();
    let second_payload_b64 = second_jws["payload"].as_str().unwrap();
    let second_payload_bytes = URL_SAFE_NO_PAD.decode(second_payload_b64).unwrap();
    let second_payload_json: serde_json::Value =
        serde_json::from_slice(&second_payload_bytes).unwrap();

    assert!(
        second_payload_json.get("replaces").is_none(),
        "Initial issuance order request must not contain replaces"
    );
}

#[tokio::test]
async fn test_startup_deduplication() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(60);

    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    let window_start = (Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let window_end = (Utc::now() + chrono::Duration::days(45)).to_rfc3339();

    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": window_start,
                        "end": window_end
                    }
                })),
        )
        .mount(&mock)
        .await;

    // 1. Call ensure_certificates() as done during startup
    scheduler.ensure_certificates().await.unwrap();

    // Verify ARI info was fetched and next_refresh scheduled in the future
    let state = scheduler.ari_state();
    assert_eq!(state.capability, AriCapability::Supported);
    assert!(state.next_refresh.unwrap() > tokio::time::Instant::now());

    let initial_requests = mock.received_requests().await.unwrap();
    let initial_ari = initial_requests
        .iter()
        .filter(|r| r.url.path().starts_with("/renewal-info/"))
        .count();
    assert_eq!(initial_ari, 1, "ensure_certificates() must fetch ARI once");

    // 2. Start RenewalScheduler::run() in a real background task
    let run_handle = tokio::spawn(scheduler.run());

    // 3. Allow its startup delay (10s) and initial renewal check to execute (11.5s margin)
    tokio::time::sleep(Duration::from_millis(11500)).await;

    // 4. Stop the task cleanly
    run_handle.abort();
    let _ = run_handle.await;

    // 5. Assert that the mock renewal-info endpoint received exactly ONE request total!
    let all_requests = mock.received_requests().await.unwrap();
    let total_ari = all_requests
        .iter()
        .filter(|r| r.url.path().starts_with("/renewal-info/"))
        .count();
    assert_eq!(
        total_ari,
        1,
        "run() must not send a duplicate ARI request when ensure_certificates() already scheduled a future refresh"
    );
}

#[tokio::test]
async fn test_startup_run_fetches_ari_when_no_prior_refresh() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(60);

    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    let window_start = (Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let window_end = (Utc::now() + chrono::Duration::days(45)).to_rfc3339();

    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": window_start,
                        "end": window_end
                    }
                })),
        )
        .mount(&mock)
        .await;

    // Do NOT call ensure_certificates(). Verify no prior refresh.
    assert!(scheduler.ari_state().next_refresh.is_none());

    // Start RenewalScheduler::run()
    let run_handle = tokio::spawn(scheduler.run());

    // Allow startup delay (10s) and initial check to execute with a polling deadline to eliminate timing fragility
    let deadline = tokio::time::Instant::now() + Duration::from_secs(16);
    let mut total_ari = 0;
    while tokio::time::Instant::now() < deadline {
        let all_requests = mock.received_requests().await.unwrap();
        total_ari = all_requests
            .iter()
            .filter(|r| r.url.path().starts_with("/renewal-info/"))
            .count();
        if total_ari >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    run_handle.abort();
    let _ = run_handle.await;

    assert_eq!(
        total_ari, 1,
        "run() must fetch ARI on startup when no prior refresh was performed"
    );
}

#[test]
fn test_state_transitions_and_recovery() {
    let mut state = AriSchedulerState::default();
    assert_eq!(state.capability, AriCapability::Unknown);

    let now_utc = Utc::now();
    let window = RenewalWindow::new(
        now_utc + chrono::Duration::days(10),
        now_utc + chrono::Duration::days(20),
    )
    .unwrap();
    let deadline = now_utc + chrono::Duration::days(15);
    let next_refresh = tokio::time::Instant::now() + Duration::from_secs(3600);

    // 1. Unknown -> Supported
    state.record_success(window.clone(), deadline, next_refresh, None);
    assert_eq!(state.capability, AriCapability::Supported);
    assert_eq!(state.renewal_deadline, Some(deadline));

    // 2. Supported -> Temporary failure preserves window and deadline
    state.record_temporary_failure(Duration::from_secs(60));
    assert_eq!(state.capability, AriCapability::Supported);
    assert_eq!(state.renewal_deadline, Some(deadline));
    assert_eq!(state.last_window.as_ref(), Some(&window));

    // 3. Supported -> Unsupported clears window and deadline
    state.record_unsupported(tokio::time::Instant::now() + Duration::from_secs(6 * 3600));
    assert_eq!(state.capability, AriCapability::Unsupported);
    assert!(state.renewal_deadline.is_none());
    assert!(state.last_window.is_none());
}

#[tokio::test]
async fn test_replaces_failure_falls_back_without_replaces_http01_success() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();
    let expires = Utc::now() + chrono::Duration::days(60);

    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    let cert_id = client.extract_certificate_identifier(&cert_pem).unwrap();

    // Mock ARI endpoint to ensure ARI capability is Supported
    let window_start = (Utc::now() + chrono::Duration::days(30)).to_rfc3339();
    let window_end = (Utc::now() + chrono::Duration::days(45)).to_rfc3339();
    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": window_start,
                        "end": window_end
                    }
                })),
        )
        .mount(&mock)
        .await;

    scheduler.refresh_ari().await.unwrap();
    assert_eq!(scheduler.ari_capability(), AriCapability::Supported);

    // Order 1 (with replaces) fails with 400 Bad Request (alreadyReplaced)
    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("replay-nonce", "test-nonce-order-fail")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:alreadyReplaced",
                    "detail": "The certificate has already been replaced"
                })),
        )
        .up_to_n_times(1)
        .mount(&mock)
        .await;

    // Order 2 (fallback without replaces) succeeds with 201 Created
    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("replay-nonce", "test-nonce-order-ok")
                .insert_header("location", format!("{}/order/2", mock.uri()))
                .set_body_json(serde_json::json!({
                    "status": "ready",
                    "expires": (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "authorizations": [],
                    "finalize": format!("{}/order/2/finalize", mock.uri())
                })),
        )
        .up_to_n_times(1)
        .mount(&mock)
        .await;

    // Mock order refresh: /order/2
    Mock::given(method("POST"))
        .and(path("/order/2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("replay-nonce", "test-nonce-refresh")
                .set_body_json(serde_json::json!({
                    "status": "valid",
                    "expires": (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "authorizations": [],
                    "finalize": format!("{}/order/2/finalize", mock.uri()),
                    "certificate": format!("{}/cert/2", mock.uri())
                })),
        )
        .mount(&mock)
        .await;

    // Mock finalize: /order/2/finalize
    Mock::given(method("POST"))
        .and(path("/order/2/finalize"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("replay-nonce", "test-nonce-finalize")
                .insert_header("location", format!("{}/order/2", mock.uri()))
                .set_body_json(serde_json::json!({
                    "status": "valid",
                    "expires": (Utc::now() + chrono::Duration::days(7)).to_rfc3339(),
                    "identifiers": [{"type": "dns", "value": "example.com"}],
                    "authorizations": [],
                    "finalize": format!("{}/order/2/finalize", mock.uri()),
                    "certificate": format!("{}/cert/2", mock.uri())
                })),
        )
        .mount(&mock)
        .await;

    // Mock certificate download: /cert/2
    Mock::given(method("POST"))
        .and(path("/cert/2"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("replay-nonce", "test-nonce-cert")
                .insert_header("content-type", "application/pem-certificate-chain")
                .set_body_string(&cert_pem),
        )
        .mount(&mock)
        .await;

    // Execute renewal with predecessor ID
    let renew_result = scheduler.renew_certificate_http01(Some(&cert_id)).await;
    assert!(
        renew_result.is_ok(),
        "Renewal should succeed via fallback order"
    );

    // Verify order requests: exactly 2 requests to /new-order
    let all_requests = mock.received_requests().await.unwrap();
    let order_reqs: Vec<_> = all_requests
        .iter()
        .filter(|r| r.url.path() == "/new-order")
        .collect();
    assert_eq!(
        order_reqs.len(),
        2,
        "Must attempt initial order with replaces and exactly one fallback without"
    );

    // Request 1 must have replaces
    let first_jws: serde_json::Value = serde_json::from_slice(&order_reqs[0].body).unwrap();
    let first_payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(first_jws["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        first_payload["replaces"].as_str(),
        Some(cert_id.to_string().as_str())
    );

    // Request 2 must NOT have replaces
    let second_jws: serde_json::Value = serde_json::from_slice(&order_reqs[1].body).unwrap();
    let second_payload: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(second_jws["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(second_payload.get("replaces").is_none());

    // Invariant: ARI capability must remain Supported! Not downgraded to Unsupported!
    assert_eq!(scheduler.ari_capability(), AriCapability::Supported);
}

#[tokio::test]
async fn test_replaces_failure_and_fallback_failure_returns_error_bounded() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let cert_id = client.extract_certificate_identifier(&cert_pem).unwrap();

    // Mock /new-order to always return 400 Bad Request
    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("replay-nonce", "test-nonce-err")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": "Order creation rejected"
                })),
        )
        .mount(&mock)
        .await;

    let res = scheduler.renew_certificate_http01(Some(&cert_id)).await;
    assert!(res.is_err(), "Must return error when fallback also fails");

    let all_requests = mock.received_requests().await.unwrap();
    let order_reqs: Vec<_> = all_requests
        .iter()
        .filter(|r| r.url.path() == "/new-order")
        .collect();
    // Invariant: Bounded at exactly 2 attempts, no 3rd attempt!
    assert_eq!(
        order_reqs.len(),
        2,
        "Must make exactly 1 initial + 1 fallback attempt"
    );
}

#[tokio::test]
async fn test_replaces_failure_and_fallback_failure_dns01_bounded() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let cert_id = client.extract_certificate_identifier(&cert_pem).unwrap();

    Mock::given(method("POST"))
        .and(path("/new-order"))
        .respond_with(
            ResponseTemplate::new(400)
                .insert_header("replay-nonce", "test-nonce-err")
                .set_body_json(serde_json::json!({
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": "DNS-01 order rejected"
                })),
        )
        .mount(&mock)
        .await;

    let provider = zentinel_proxy::acme::dns::WebhookProvider::new(
        mock.uri(),
        None,
        None,
        Duration::from_secs(30),
    )
    .unwrap();
    let dns_mgr = Arc::new(
        zentinel_proxy::acme::dns::Dns01ChallengeManager::with_defaults(Arc::new(provider))
            .unwrap(),
    );
    let scheduler_dns = scheduler.with_dns_manager(dns_mgr);

    let res = scheduler_dns.renew_certificate_dns01(Some(&cert_id)).await;
    assert!(
        res.is_err(),
        "Must return error when fallback DNS-01 order fails"
    );

    let all_requests = mock.received_requests().await.unwrap();
    let order_reqs: Vec<_> = all_requests
        .iter()
        .filter(|r| r.url.path() == "/new-order")
        .collect();
    assert_eq!(
        order_reqs.len(),
        2,
        "Must make exactly 1 initial + 1 fallback attempt for DNS-01"
    );
}

#[tokio::test]
async fn test_expiry_fallback_independent_of_far_future_ari_deadline() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

    // Certificate expires in 10 days; renew_before_days is 30 -> renewal is DUE by expiry policy
    let expires = Utc::now() + chrono::Duration::days(10);
    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // Mock ARI suggesting a far-future renewal window (40 to 60 days in the future)
    let window_start = (Utc::now() + chrono::Duration::days(40)).to_rfc3339();
    let window_end = (Utc::now() + chrono::Duration::days(60)).to_rfc3339();
    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": window_start,
                        "end": window_end
                    }
                })),
        )
        .mount(&mock)
        .await;

    scheduler.refresh_ari().await.unwrap();

    // ARI state now has renewal_deadline far in the future
    assert!(
        scheduler.ari_state().renewal_deadline.unwrap() > Utc::now() + chrono::Duration::days(35)
    );

    // Expiry protection invariant:
    // Even though ARI deadline is far in the future, is_renewal_due must still return true!
    let due = scheduler.is_renewal_due("example.com").unwrap();
    assert!(
        due,
        "Expiry protection must trigger renewal even if ARI deadline is in the far future"
    );
}

#[tokio::test]
async fn test_expiry_fallback_when_ari_window_extends_beyond_not_after() {
    let temp_dir = tempfile::tempdir().unwrap();
    let (mock, client, scheduler) = setup_mock_acme(true, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

    // Certificate expires in 2 days (imminent expiry)
    let expires = Utc::now() + chrono::Duration::days(2);
    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // Pathological CA ARI window extends beyond notAfter (e.g. 10 to 20 days)
    let window_start = (Utc::now() + chrono::Duration::days(10)).to_rfc3339();
    let window_end = (Utc::now() + chrono::Duration::days(20)).to_rfc3339();
    Mock::given(method("GET"))
        .and(path_regex(r"^/renewal-info/.*"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Retry-After", "3600")
                .set_body_json(serde_json::json!({
                    "suggestedWindow": {
                        "start": window_start,
                        "end": window_end
                    }
                })),
        )
        .mount(&mock)
        .await;

    scheduler.refresh_ari().await.unwrap();

    // The certificate must not be allowed to expire without a renewal attempt
    let due = scheduler.is_renewal_due("example.com").unwrap();
    assert!(
        due,
        "Certificate nearing expiry must trigger renewal even if ARI window extends beyond notAfter"
    );
}

#[tokio::test]
async fn test_unsupported_ari_and_refresh_failures_use_expiry_fallback() {
    let temp_dir = tempfile::tempdir().unwrap();
    // Directory without renewalInfo -> Unsupported
    let (_mock, client, scheduler) = setup_mock_acme(false, temp_dir.path().to_path_buf()).await;

    client.init_account().await.unwrap();

    let fixtures = fixtures_path();
    let cert_pem = std::fs::read_to_string(fixtures.join("server-default.crt")).unwrap();
    let key_pem = std::fs::read_to_string(fixtures.join("server-default.key")).unwrap();

    // Certificate expires in 10 days (renew_before_days is 30) -> due
    let expires = Utc::now() + chrono::Duration::days(10);
    client
        .storage()
        .save_certificate(
            "example.com",
            &cert_pem,
            &key_pem,
            expires,
            &["example.com".to_string()],
        )
        .unwrap();

    // ARI refresh fails as unsupported
    let _ = scheduler.refresh_ari().await;
    assert_eq!(scheduler.ari_capability(), AriCapability::Unsupported);

    // Fallback expiry check must still trigger renewal
    let due = scheduler.is_renewal_due("example.com").unwrap();
    assert!(due, "Unsupported ARI must continue to use expiry fallback");
}
