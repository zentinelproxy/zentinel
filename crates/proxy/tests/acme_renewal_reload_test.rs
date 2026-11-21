//! A renewed ACME certificate has to reach the listeners that serve it.
//!
//! The renewal scheduler is created while ACME is initialized, which is before
//! any listener has built its certificate resolver. These tests build the
//! scheduler first and the listeners afterwards, in that order, and assert on
//! the certificate a client actually receives in a TLS handshake after a
//! renewal has written new files to the ACME storage -- with no SIGHUP and no
//! rebuild of the listener's `ServerConfig`.
//!
//! No ACME server is involved: a renewal is a new `cert.pem` / `key.pem` pair
//! in the storage directory, which is what the scheduler's own save step does.
//!
//! The fixture certificates are signed by the test CA and carry
//! `DNS:localhost`, so the client verifies them for real.

use std::fs::File;
use std::io::BufReader;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use chrono::Utc;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use zentinel_config::server::{AcmeChallengeType, AcmeConfig, AcmeKeyType};
use zentinel_config::{SniCertificate, TlsConfig};
use zentinel_proxy::acme::{AcmeClient, CertificateStorage, ChallengeManager, RenewalScheduler};
use zentinel_proxy::tls::{
    build_server_config_with_resolver, CertificateReloader, HotReloadableSniResolver,
};

/// Pick the crypto provider explicitly, as `main.rs` does at startup.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("installing the aws-lc-rs crypto provider");
    });
}

/// Register the TLS metrics once for the whole test binary. Tests run on
/// several threads and a second concurrent registration is refused.
fn init_tls_metrics_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        zentinel_proxy::tls_metrics::init_tls_metrics().expect("registering TLS metrics");
    });
}

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/tls")
}

fn load_certs(name: &str) -> Vec<CertificateDer<'static>> {
    let path = fixtures_path().join(name);
    let file = File::open(&path).unwrap_or_else(|e| panic!("opening {}: {e}", path.display()));
    rustls_pemfile::certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
}

fn verifying_client() -> ClientConfig {
    let mut roots = RootCertStore::empty();
    for cert in load_certs("ca.crt") {
        roots.add(cert).expect("adding test CA to root store");
    }
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Complete one handshake against `server_config` and return the certificate
/// the client was served.
fn served_der(server_config: &Arc<ServerConfig>, sni: &str) -> CertificateDer<'static> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binding loopback listener");
    let addr = listener.local_addr().expect("reading listener address");

    let server_config = Arc::clone(server_config);
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accepting connection");
        let mut conn = ServerConnection::new(server_config).expect("creating server connection");
        while conn.is_handshaking() {
            conn.complete_io(&mut socket)
                .expect("server side of the handshake");
        }
    });

    let server_name = ServerName::try_from(sni.to_string()).expect("parsing server name");
    let mut conn = ClientConnection::new(Arc::new(verifying_client()), server_name)
        .expect("creating client connection");
    let mut socket = TcpStream::connect(addr).expect("connecting to the test listener");
    while conn.is_handshaking() {
        conn.complete_io(&mut socket)
            .expect("client side of the handshake");
    }
    let served = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .expect("the server presented a certificate")
        .clone()
        .into_owned();

    server.join().expect("server thread");
    served
}

/// Fixtures a handshake can serve in these tests.
const FIXTURES: [&str; 3] = ["server-default", "server-api", "server-wildcard"];

/// Assert that a handshake for `sni` is served the fixture certificate `stem`,
/// naming the certificate that was served instead when it is not.
fn assert_serves(server_config: &Arc<ServerConfig>, sni: &str, stem: &str, why: &str) {
    let der = served_der(server_config, sni);
    let served = FIXTURES
        .iter()
        .find(|candidate| load_certs(&format!("{candidate}.crt"))[0] == der)
        .copied()
        .unwrap_or("an unrecognised certificate");
    assert_eq!(served, stem, "{why} (SNI {sni})");
}

fn acme_config(storage: &Path, domain: &str) -> AcmeConfig {
    AcmeConfig {
        email: "ops@example.com".to_string(),
        domains: vec![domain.to_string()],
        server_url: None,
        staging: true,
        eab: None,
        storage: storage.to_path_buf(),
        renew_before_days: 30,
        challenge_type: AcmeChallengeType::Http01,
        key_type: AcmeKeyType::EcdsaP256,
        dns_provider: None,
    }
}

fn tls_config(acme: Option<AcmeConfig>) -> TlsConfig {
    TlsConfig {
        cert_folders: Vec::new(),
        allow_sni_overlaps: false,
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
        acme,
    }
}

/// Write a fixture certificate into the ACME storage the way a completed
/// issuance does, replacing whatever the domain had.
fn store_certificate(storage: &CertificateStorage, domains: &[&str], stem: &str) {
    let cert_pem = std::fs::read_to_string(fixtures_path().join(format!("{stem}.crt"))).unwrap();
    let key_pem = std::fs::read_to_string(fixtures_path().join(format!("{stem}.key"))).unwrap();
    let domains: Vec<String> = domains.iter().map(|d| d.to_string()).collect();
    storage
        .save_certificate(
            &domains[0],
            &cert_pem,
            &key_pem,
            Utc::now() + chrono::Duration::days(90),
            &domains,
        )
        .expect("saving the certificate to ACME storage");
}

/// One ACME-managed certificate: its storage, and the scheduler that renews it.
struct AcmeCertificate {
    config: AcmeConfig,
    storage: Arc<CertificateStorage>,
    scheduler: RenewalScheduler,
}

impl AcmeCertificate {
    /// Create the scheduler the way `initialize_acme` does: handed the shared
    /// reloader, before any listener exists.
    fn new(dir: &Path, domain: &str, reloader: &Arc<CertificateReloader>) -> Self {
        let config = acme_config(dir, domain);
        let storage = Arc::new(CertificateStorage::new(dir).expect("creating ACME storage"));
        let client = Arc::new(AcmeClient::new(config.clone(), Arc::clone(&storage)));
        let scheduler = RenewalScheduler::new(
            client,
            Arc::new(ChallengeManager::new()),
            Some(Arc::clone(reloader)),
        );
        Self {
            config,
            storage,
            scheduler,
        }
    }
}

/// Build a listener's resolver and `ServerConfig` and register the resolver
/// with the shared reloader, as `run_server` does for each HTTPS listener.
fn start_listener(
    reloader: &CertificateReloader,
    listener_id: &str,
    config: &TlsConfig,
) -> Arc<ServerConfig> {
    let resolver = Arc::new(
        HotReloadableSniResolver::from_config(config.clone(), listener_id)
            .expect("building the listener's resolver"),
    );
    reloader.register(listener_id, Arc::clone(&resolver));
    Arc::new(
        build_server_config_with_resolver(config, resolver).expect("building the server config"),
    )
}

/// The behaviour this change fixes: the listener kept serving the certificate
/// it started with after a renewal, until a SIGHUP.
#[test]
fn renewed_certificate_is_served_without_a_reload_signal() {
    install_crypto_provider();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    // ACME is initialized first: the scheduler exists and the certificate has
    // been issued before any listener has built its resolver.
    let acme = AcmeCertificate::new(dir.path(), "a.example", &reloader);
    store_certificate(&acme.storage, &["a.example"], "server-default");

    let server_config =
        start_listener(&reloader, "https-a", &tls_config(Some(acme.config.clone())));
    assert_serves(
        &server_config,
        "localhost",
        "server-default",
        "the issued certificate should be served before any renewal",
    );

    // Renewal writes new files; the scheduler then applies them.
    store_certificate(&acme.storage, &["a.example"], "server-api");
    acme.scheduler.apply_renewed_certificate();

    assert_serves(
        &server_config,
        "localhost",
        "server-api",
        "the renewed certificate should be served by the running listener",
    );
}

/// An ACME block inside an `sni` entry renews its own certificate; the
/// listener's default certificate is left as it was.
#[test]
fn renewed_sni_certificate_is_served_for_its_hostname() {
    install_crypto_provider();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    let acme = AcmeCertificate::new(dir.path(), "api.example.com", &reloader);
    store_certificate(&acme.storage, &["api.example.com"], "server-api");

    let mut config = tls_config(None);
    config.cert_file = Some(fixtures_path().join("server-default.crt"));
    config.key_file = Some(fixtures_path().join("server-default.key"));
    config.additional_certs = vec![SniCertificate {
        hostnames: vec![],
        priority_hostnames: vec![],
        cert_file: None,
        key_file: None,
        acme: Some(acme.config.clone()),
    }];
    let server_config = start_listener(&reloader, "https-sni", &config);

    assert_serves(
        &server_config,
        "api.example.com",
        "server-api",
        "the issued SNI certificate should be served before any renewal",
    );

    store_certificate(&acme.storage, &["api.example.com"], "server-wildcard");
    acme.scheduler.apply_renewed_certificate();

    assert_serves(
        &server_config,
        "api.example.com",
        "server-wildcard",
        "the SNI certificate should be replaced by the renewed one",
    );
    assert_serves(
        &server_config,
        "localhost",
        "server-default",
        "the default certificate is not part of this renewal",
    );
}

/// Every listener that uses the renewed certificate gets it, and a listener
/// that uses a different one is not re-read.
#[test]
fn renewal_reaches_each_listener_that_serves_the_certificate() {
    install_crypto_provider();
    let dir_a = tempfile::tempdir().expect("creating temp dir");
    let dir_b = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    let acme_a = AcmeCertificate::new(dir_a.path(), "a.example", &reloader);
    let acme_b = AcmeCertificate::new(dir_b.path(), "b.example", &reloader);
    store_certificate(&acme_a.storage, &["a.example"], "server-default");
    store_certificate(&acme_b.storage, &["b.example"], "server-default");

    // Two listeners share the renewed certificate; a third has its own.
    let config_a = tls_config(Some(acme_a.config.clone()));
    let first = start_listener(&reloader, "https-a1", &config_a);
    let second = start_listener(&reloader, "https-a2", &config_a);
    let other = start_listener(
        &reloader,
        "https-b",
        &tls_config(Some(acme_b.config.clone())),
    );

    store_certificate(&acme_a.storage, &["a.example"], "server-api");
    // Files under the other certificate's storage change too, but its renewal
    // has not been applied.
    store_certificate(&acme_b.storage, &["b.example"], "server-wildcard");
    acme_a.scheduler.apply_renewed_certificate();

    for (name, server_config) in [("https-a1", &first), ("https-a2", &second)] {
        assert_serves(
            server_config,
            "localhost",
            "server-api",
            &format!("listener {name} should serve the renewed certificate"),
        );
    }
    assert_serves(
        &other,
        "localhost",
        "server-default",
        "a listener using another certificate is not reloaded by this renewal",
    );
}

/// A listener that cannot load the renewed files keeps serving its previous
/// certificate, and the failure is counted.
#[test]
fn failed_reload_after_renewal_keeps_the_previous_certificate_and_is_counted() {
    install_crypto_provider();
    init_tls_metrics_once();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    let acme = AcmeCertificate::new(dir.path(), "a.example", &reloader);
    store_certificate(&acme.storage, &["a.example"], "server-default");
    // Unique per test: the metric registry is shared by the whole test binary.
    let listener_id = "https-failed-reload";
    let server_config = start_listener(
        &reloader,
        listener_id,
        &tls_config(Some(acme.config.clone())),
    );
    let failures_before = reload_count(listener_id, "failure");

    // A renewal that left an unreadable certificate behind.
    let cert_path = dir.path().join("domains/a.example/cert.pem");
    std::fs::write(&cert_path, b"").expect("truncating the stored certificate");
    acme.scheduler.apply_renewed_certificate();

    assert_serves(
        &server_config,
        "localhost",
        "server-default",
        "the previous certificate should still be served",
    );
    assert_eq!(
        reload_count(listener_id, "failure"),
        failures_before + 1,
        "zentinel_tls_reload_total{{result=\"failure\"}} should count the failed reload"
    );
}

/// A listener serving an ACME `sni` certificate must not drop that name to the
/// default certificate because the renewed files cannot be read: the reload
/// fails, the previous certificates stay in use, and the failure is counted.
/// A SIGHUP reload takes the same path.
#[test]
fn unreadable_renewed_sni_certificate_fails_the_reload_and_keeps_the_previous_one() {
    install_crypto_provider();
    init_tls_metrics_once();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    let acme = AcmeCertificate::new(dir.path(), "api.example.com", &reloader);
    store_certificate(&acme.storage, &["api.example.com"], "server-api");

    let mut config = tls_config(None);
    config.cert_file = Some(fixtures_path().join("server-default.crt"));
    config.key_file = Some(fixtures_path().join("server-default.key"));
    config.additional_certs = vec![SniCertificate {
        hostnames: vec![],
        priority_hostnames: vec![],
        cert_file: None,
        key_file: None,
        acme: Some(acme.config.clone()),
    }];
    let listener_id = "https-sni-unreadable";
    let server_config = start_listener(&reloader, listener_id, &config);
    let failures_before = reload_count(listener_id, "failure");
    let successes_before = reload_count(listener_id, "success");

    // The renewal left an unreadable certificate behind.
    let cert_path = dir.path().join("domains/api.example.com/cert.pem");
    std::fs::write(&cert_path, b"").expect("truncating the stored certificate");

    acme.scheduler.apply_renewed_certificate();
    assert_eq!(
        reload_count(listener_id, "failure"),
        failures_before + 1,
        "the failed reload should be counted"
    );
    assert_eq!(
        reload_count(listener_id, "success"),
        successes_before,
        "a reload that lost a served certificate must not count as a success"
    );
    assert_serves(
        &server_config,
        "api.example.com",
        "server-api",
        "the SNI name should keep its previous certificate",
    );

    // SIGHUP reloads every registered listener through the same path.
    let (reloaded, failures) = reloader.reload_all();
    assert_eq!(reloaded, 0);
    assert_eq!(
        failures.len(),
        1,
        "the failure should be reported: {failures:?}"
    );
    assert_serves(
        &server_config,
        "api.example.com",
        "server-api",
        "the SNI name should still have its previous certificate after a SIGHUP reload",
    );
}

/// An ACME `sni` certificate that has not been issued yet is skipped when the
/// listener starts. A reload that still finds it missing has lost nothing, so
/// it is not a failure and the rest of the listener keeps reloading.
#[test]
fn reload_with_an_sni_certificate_that_was_never_issued_is_not_a_failure() {
    install_crypto_provider();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let reloader = Arc::new(CertificateReloader::new());

    // Nothing is stored for api.example.com.
    let acme = AcmeCertificate::new(dir.path(), "api.example.com", &reloader);

    let mut config = tls_config(None);
    config.cert_file = Some(fixtures_path().join("server-default.crt"));
    config.key_file = Some(fixtures_path().join("server-default.key"));
    config.additional_certs = vec![SniCertificate {
        hostnames: vec![],
        priority_hostnames: vec![],
        cert_file: None,
        key_file: None,
        acme: Some(acme.config.clone()),
    }];
    let server_config = start_listener(&reloader, "https-sni-pending", &config);
    assert_serves(
        &server_config,
        "localhost",
        "server-default",
        "the default certificate is served while the SNI certificate is pending",
    );

    let (reloaded, failures) = reloader.reload_all();
    assert_eq!(reloaded, 1);
    assert!(failures.is_empty(), "unexpected failures: {failures:?}");

    // Once issued, the next reload picks it up.
    store_certificate(&acme.storage, &["api.example.com"], "server-api");
    acme.scheduler.apply_renewed_certificate();
    assert_serves(
        &server_config,
        "api.example.com",
        "server-api",
        "the issued SNI certificate should be served after the reload",
    );
}

/// Which listeners count as serving a certificate is decided by the ACME
/// block's storage directory and primary domain, not by its other settings.
#[test]
fn a_listener_serves_the_certificate_named_by_storage_and_primary_domain() {
    install_crypto_provider();
    let dir = tempfile::tempdir().expect("creating temp dir");
    let other_dir = tempfile::tempdir().expect("creating temp dir");
    let storage = CertificateStorage::new(dir.path()).expect("creating ACME storage");
    store_certificate(&storage, &["a.example", "www.a.example"], "server-default");

    let config = acme_config(dir.path(), "a.example");
    let resolver = HotReloadableSniResolver::from_config(tls_config(Some(config.clone())), "root")
        .expect("building the listener's resolver");
    assert!(resolver.serves_acme_certificate(&config));

    // Same storage and primary domain; other names on the same certificate and
    // other settings do not change which certificate it is.
    let mut same_certificate = config.clone();
    same_certificate.domains = vec!["a.example".to_string(), "www.a.example".to_string()];
    same_certificate.renew_before_days = 10;
    assert!(resolver.serves_acme_certificate(&same_certificate));

    assert!(
        !resolver.serves_acme_certificate(&acme_config(dir.path(), "b.example")),
        "another primary domain in the same storage is another certificate"
    );
    assert!(
        !resolver.serves_acme_certificate(&acme_config(other_dir.path(), "a.example")),
        "the same domain in another storage directory is another certificate"
    );

    // A listener with no ACME block serves none.
    let mut manual = tls_config(None);
    manual.cert_file = Some(fixtures_path().join("server-default.crt"));
    manual.key_file = Some(fixtures_path().join("server-default.key"));
    let manual_resolver = HotReloadableSniResolver::from_config(manual, "manual")
        .expect("building the listener's resolver");
    assert!(!manual_resolver.serves_acme_certificate(&config));

    // With nothing registered for the certificate, nothing is reloaded and
    // nothing fails.
    let reloader = CertificateReloader::new();
    reloader.register("manual", Arc::new(manual_resolver));
    let (reloaded, failures) = reloader.reload_acme_certificate(&config);
    assert_eq!(reloaded, 0);
    assert!(failures.is_empty(), "unexpected failures: {failures:?}");
}

/// Current value of `zentinel_tls_reload_total` for one listener and result.
fn reload_count(listener_id: &str, result: &str) -> u64 {
    let families = prometheus::gather();
    let Some(family) = families
        .iter()
        .find(|f| f.name() == "zentinel_tls_reload_total")
    else {
        return 0;
    };
    family
        .metric
        .iter()
        .filter(|m| {
            let has = |name: &str, value: &str| {
                m.label
                    .iter()
                    .any(|l| l.name() == name && l.value() == value)
            };
            has("listener", listener_id) && has("result", result)
        })
        .map(|m| m.counter.value() as u64)
        .sum()
}
