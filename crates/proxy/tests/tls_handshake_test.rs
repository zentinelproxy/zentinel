//! TLS handshake tests.
//!
//! `tls_sni_test.rs` covers certificate resolution thoroughly, but every one of
//! those tests calls the resolver directly. None of them proves the resolver is
//! reached during a handshake, which is exactly where per-SNI certificate
//! selection used to be lost: the settings were parsed, validated, and then
//! dropped, because the listener built its own rustls config.
//!
//! These tests run real TLS handshakes over a loopback socket and assert on
//! what the client actually observed -- which certificate it was served,
//! whether its own certificate was demanded, and which protocol version and
//! cipher suite were negotiated. They fail if TLS settings stop reaching the
//! handshake, regardless of how faithfully the config layer parses them.
//!
//! All fixture certificates are signed by the same test CA and carry
//! `DNS:localhost`, so the client can verify them for real rather than
//! disabling verification, which would weaken what these tests prove.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use zentinel_config::{SniCertificate, TlsConfig};
use zentinel_proxy::tls::{build_server_config, CertificateReloader, HotReloadableSniResolver};

/// Pick the crypto provider explicitly, as `main.rs` does at startup.
///
/// Feature unification leaves both `ring` (via pingora-rustls) and `aws-lc-rs`
/// (via this crate) enabled, so rustls refuses to guess a process-level
/// default. Every test that touches rustls has to install one first.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("installing the aws-lc-rs crypto provider");
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

fn load_key(name: &str) -> PrivateKeyDer<'static> {
    let path = fixtures_path().join(name);
    let file = File::open(&path).unwrap_or_else(|e| panic!("opening {}: {e}", path.display()));
    rustls_pemfile::private_key(&mut BufReader::new(file))
        .unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()))
        .unwrap_or_else(|| panic!("no private key in {}", path.display()))
}

fn test_ca_roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in load_certs("ca.crt") {
        roots.add(cert).expect("adding test CA to root store");
    }
    roots
}

fn base_tls_config() -> TlsConfig {
    let fixtures = fixtures_path();
    TlsConfig {
        cert_folders: Vec::new(),
        allow_sni_overlaps: false,
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

fn sni_certificate(hostname: &str, stem: &str) -> SniCertificate {
    let fixtures = fixtures_path();
    SniCertificate {
        hostnames: vec![hostname.to_string()],
        priority_hostnames: vec![],
        cert_file: Some(fixtures.join(format!("{stem}.crt"))),
        key_file: Some(fixtures.join(format!("{stem}.key"))),
        acme: None,
    }
}

/// What the client observed about a completed handshake.
struct HandshakeOutcome {
    peer_certificates: Vec<CertificateDer<'static>>,
    protocol_version: Option<rustls::ProtocolVersion>,
    cipher_suite: Option<rustls::CipherSuite>,
    handshake_kind: Option<rustls::HandshakeKind>,
}

/// Marker the server sends once it considers the connection established.
const SERVER_GREETING: &[u8] = b"zentinel-test-ok";

fn to_tls_error(e: std::io::Error) -> rustls::Error {
    // A rejected handshake surfaces as an I/O error wrapping the rustls error,
    // or as a plain transport error once the peer has closed. Prefer the
    // rustls error when there is one.
    match e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        Some(tls_err) => tls_err.clone(),
        None => rustls::Error::General(e.to_string()),
    }
}

/// Run one handshake against a server built from `server_config`, presenting
/// `sni` as the server name. Returns what the client saw, or the client-side
/// error if the connection was rejected.
///
/// The server accepts one connection and, on success, sends [`SERVER_GREETING`].
/// The client requires that greeting, which is what makes rejection detectable:
/// under TLS 1.3 a server rejects a missing client certificate *after* the
/// client has sent its Finished message, so the client believes it is done
/// handshaking and only learns otherwise on its next read. Testing the
/// handshake alone would report an mTLS-rejected connection as successful.
fn handshake(
    server_config: ServerConfig,
    sni: &str,
    client_config: ClientConfig,
) -> Result<HandshakeOutcome, rustls::Error> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("binding loopback listener");
    let addr = listener.local_addr().expect("reading listener address");

    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accepting connection");
        let mut conn =
            ServerConnection::new(Arc::new(server_config)).expect("creating server connection");
        while conn.is_handshaking() {
            if conn.complete_io(&mut socket).is_err() {
                // Rejected, or the client went away. Either way the client's
                // view is what the tests assert on.
                return;
            }
        }
        if conn.writer().write_all(SERVER_GREETING).is_ok() {
            let _ = conn.complete_io(&mut socket);
        }
    });

    let server_name = ServerName::try_from(sni.to_string()).expect("parsing server name");
    let mut conn = ClientConnection::new(Arc::new(client_config), server_name)
        .expect("creating client connection");
    let mut socket = TcpStream::connect(addr).expect("connecting to test server");

    let outcome = (|| {
        while conn.is_handshaking() {
            conn.complete_io(&mut socket).map_err(to_tls_error)?;
        }

        // Read the greeting. This is where a post-handshake rejection lands.
        let mut greeting = vec![0u8; SERVER_GREETING.len()];
        rustls::Stream::new(&mut conn, &mut socket)
            .read_exact(&mut greeting)
            .map_err(to_tls_error)?;
        assert_eq!(greeting, SERVER_GREETING, "unexpected server greeting");

        Ok(HandshakeOutcome {
            peer_certificates: conn
                .peer_certificates()
                .map(|certs| certs.to_vec())
                .unwrap_or_default(),
            protocol_version: conn.protocol_version(),
            cipher_suite: conn.negotiated_cipher_suite().map(|s| s.suite()),
            handshake_kind: conn.handshake_kind(),
        })
    })();

    let _ = server.join();
    outcome
}

fn verifying_client() -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(test_ca_roots())
        .with_no_client_auth()
}

/// The core of issue #303: the certificate served must depend on the SNI name
/// the client sent. Before per-SNI selection was wired into the listener,
/// every one of these cases returned the default certificate.
#[test]
fn sni_hostname_selects_the_matching_certificate() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.additional_certs = vec![
        sni_certificate("api.example.com", "server-api"),
        sni_certificate("secure.example.com", "server-secure"),
    ];

    // "localhost" matches no configured SNI certificate, so it exercises the
    // default-certificate fallback. It verifies because every fixture carries
    // DNS:localhost.
    let cases = [
        ("api.example.com", "server-api.crt"),
        ("secure.example.com", "server-secure.crt"),
        ("localhost", "server-default.crt"),
    ];

    for (sni, expected_cert) in cases {
        let server_config =
            build_server_config(&config, "sni-test").expect("building server config");
        let outcome = handshake(server_config, sni, verifying_client())
            .unwrap_or_else(|e| panic!("handshake for SNI {sni} failed: {e}"));

        assert_eq!(
            outcome.peer_certificates.first(),
            load_certs(expected_cert).first(),
            "SNI {sni} should have been served {expected_cert}"
        );
    }
}

/// A wildcard certificate has to be selected by the handshake too, not only by
/// the resolver in isolation.
#[test]
fn wildcard_certificate_is_served_for_a_matching_subdomain() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.additional_certs = vec![sni_certificate("*.example.com", "server-wildcard")];

    let server_config = build_server_config(&config, "wildcard-test").expect("building config");
    let outcome = handshake(server_config, "anything.example.com", verifying_client())
        .expect("handshake should succeed");

    assert_eq!(
        outcome.peer_certificates.first(),
        load_certs("server-wildcard.crt").first(),
        "a subdomain should be served the wildcard certificate"
    );
}

/// `client-auth` used to parse and then do nothing, which is the worst
/// possible failure mode for an access control setting: the operator believes
/// connections are authenticated when any client can connect.
#[test]
fn client_auth_requires_a_client_certificate() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.client_auth = true;
    config.ca_file = Some(fixtures_path().join("ca.crt"));

    let server_config = build_server_config(&config, "mtls-test").expect("building config");
    let result = handshake(server_config, "localhost", verifying_client());

    assert!(
        result.is_err(),
        "a client with no certificate must not complete an mTLS handshake"
    );
}

/// The other half: a client presenting a certificate from the configured CA
/// must be admitted. Without this, the test above would also pass if mTLS were
/// broken in a way that rejected everyone.
#[test]
fn client_auth_admits_a_certificate_from_the_configured_ca() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.client_auth = true;
    config.ca_file = Some(fixtures_path().join("ca.crt"));

    let client_config = ClientConfig::builder()
        .with_root_certificates(test_ca_roots())
        .with_client_auth_cert(load_certs("client.crt"), load_key("client.key"))
        .expect("building client config with client certificate");

    let server_config = build_server_config(&config, "mtls-test").expect("building config");
    let outcome = handshake(server_config, "localhost", client_config)
        .expect("a client certificate signed by the configured CA should be accepted");

    assert_eq!(
        outcome.peer_certificates.first(),
        load_certs("server-default.crt").first()
    );
}

/// `max-version` has to constrain the handshake, not just the config struct.
#[test]
fn max_version_caps_the_negotiated_protocol_version() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.max_version = Some(zentinel_common::types::TlsVersion::Tls12);

    let server_config = build_server_config(&config, "version-test").expect("building config");
    let outcome = handshake(server_config, "localhost", verifying_client())
        .expect("handshake should succeed");

    assert_eq!(
        outcome.protocol_version,
        Some(rustls::ProtocolVersion::TLSv1_2),
        "a TLS 1.3 capable client should have been held to TLS 1.2"
    );
}

/// A client that will only speak a version the server has excluded must fail
/// rather than silently negotiating something else.
#[test]
fn min_version_rejects_a_client_below_the_floor() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.min_version = zentinel_common::types::TlsVersion::Tls13;

    let tls12_only_client =
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(test_ca_roots())
            .with_no_client_auth();

    let server_config = build_server_config(&config, "version-test").expect("building config");
    let result = handshake(server_config, "localhost", tls12_only_client);

    assert!(
        result.is_err(),
        "a TLS 1.2 only client must be rejected when min-version is TLS 1.3"
    );
}

/// A `min-version` above the `max-version` leaves no protocol to offer. The
/// config must be refused, not widened to every version.
#[test]
fn an_empty_version_range_is_an_error() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.min_version = zentinel_common::types::TlsVersion::Tls13;
    config.max_version = Some(zentinel_common::types::TlsVersion::Tls12);

    let err = build_server_config(&config, "version-test")
        .expect_err("min-version TLS1.3 with max-version TLS1.2 enables no protocol version");

    let message = err.to_string();
    assert!(
        message.contains("min-version") && message.contains("max-version"),
        "the error should name both settings: {message}"
    );
    assert!(
        message.contains("'version-test'"),
        "the error should name the listener: {message}"
    );
}

/// What `session-resumption` does: the second connection from a client that
/// kept its session state is resumed, over TLS 1.2 (session ID) and TLS 1.3
/// (ticket), and is a full handshake again once the setting is off.
fn second_handshake_kind(
    resumption: bool,
    min: zentinel_common::types::TlsVersion,
    max: zentinel_common::types::TlsVersion,
) -> Option<rustls::HandshakeKind> {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.min_version = min;
    config.max_version = Some(max);
    config.session_resumption = resumption;

    // Clones share the session cache, as one listener's connections do.
    let server_config = build_server_config(&config, "resumption-test").expect("building config");
    let client_config = verifying_client();

    let first = handshake(server_config.clone(), "localhost", client_config.clone())
        .expect("first handshake should succeed");
    assert_eq!(first.handshake_kind, Some(rustls::HandshakeKind::Full));

    handshake(server_config, "localhost", client_config)
        .expect("second handshake should succeed")
        .handshake_kind
}

#[test]
fn session_resumption_resumes_a_tls_12_session() {
    use zentinel_common::types::TlsVersion::Tls12;
    assert_eq!(
        second_handshake_kind(true, Tls12, Tls12),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert_eq!(
        second_handshake_kind(false, Tls12, Tls12),
        Some(rustls::HandshakeKind::Full)
    );
}

#[test]
fn session_resumption_resumes_a_tls_13_session() {
    use zentinel_common::types::TlsVersion::Tls13;
    assert_eq!(
        second_handshake_kind(true, Tls13, Tls13),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert_eq!(
        second_handshake_kind(false, Tls13, Tls13),
        Some(rustls::HandshakeKind::Full)
    );
}

/// Certificate hot-reload, end to end.
///
/// This is the invariant that makes reload work at all: the resolver installed
/// in the `ServerConfig` has to be the same object `CertificateReloader`
/// refreshes. If a listener were built with its own separate resolver, every
/// assertion below would still hold for the *reloader* while connections kept
/// being served the original certificate -- reload would appear to succeed and
/// change nothing.
///
/// Note the `ServerConfig` is built once and reused across both handshakes,
/// exactly as a running listener holds one config for its lifetime.
#[test]
fn reloading_certificates_changes_what_a_live_config_serves() {
    install_crypto_provider();

    let dir = tempfile::tempdir().expect("creating temp dir");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");

    let install = |stem: &str| {
        std::fs::copy(fixtures_path().join(format!("{stem}.crt")), &cert_path).expect("copy cert");
        std::fs::copy(fixtures_path().join(format!("{stem}.key")), &key_path).expect("copy key");
    };
    install("server-default");

    let mut config = base_tls_config();
    config.cert_file = Some(cert_path.clone());
    config.key_file = Some(key_path.clone());

    let resolver = Arc::new(
        HotReloadableSniResolver::from_config(config.clone(), "reload-test")
            .expect("building hot-reloadable resolver"),
    );
    let reloader = CertificateReloader::new();
    reloader.register("reload-test", resolver.clone());

    let server_config = zentinel_proxy::tls::build_server_config_with_resolver(&config, resolver)
        .expect("building server config");

    let before = handshake(server_config.clone(), "localhost", verifying_client())
        .expect("handshake before reload");
    assert_eq!(
        before.peer_certificates.first(),
        load_certs("server-default.crt").first(),
        "the original certificate should be served before any reload"
    );

    // Renewal: same paths, different certificate.
    install("server-api");
    let (reloaded, failures) = reloader.reload_all();
    assert_eq!(reloaded, 1, "one listener should have reloaded");
    assert!(
        failures.is_empty(),
        "reload reported failures: {failures:?}"
    );

    let after =
        handshake(server_config, "localhost", verifying_client()).expect("handshake after reload");
    assert_eq!(
        after.peer_certificates.first(),
        load_certs("server-api.crt").first(),
        "the reloaded certificate should be served without rebuilding the config"
    );
}

/// A reload that cannot read its certificates must not take the listener down
/// or start serving nothing -- the previous certificate stays in use.
#[test]
fn a_failed_reload_keeps_serving_the_previous_certificate() {
    install_crypto_provider();

    let dir = tempfile::tempdir().expect("creating temp dir");
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::copy(fixtures_path().join("server-default.crt"), &cert_path).expect("copy cert");
    std::fs::copy(fixtures_path().join("server-default.key"), &key_path).expect("copy key");

    let mut config = base_tls_config();
    config.cert_file = Some(cert_path.clone());
    config.key_file = Some(key_path.clone());

    let resolver = Arc::new(
        HotReloadableSniResolver::from_config(config.clone(), "reload-failure")
            .expect("building hot-reloadable resolver"),
    );
    let reloader = CertificateReloader::new();
    reloader.register("reload-failure", resolver.clone());

    let server_config = zentinel_proxy::tls::build_server_config_with_resolver(&config, resolver)
        .expect("building server config");

    // A truncated certificate file, as a half-written renewal would leave.
    std::fs::write(&cert_path, b"").expect("truncating cert");
    let (reloaded, failures) = reloader.reload_all();
    assert_eq!(
        reloaded, 0,
        "a broken certificate must not count as reloaded"
    );
    assert_eq!(failures.len(), 1, "the failure should be reported");

    let after = handshake(server_config, "localhost", verifying_client())
        .expect("connections should still be served after a failed reload");
    assert_eq!(
        after.peer_certificates.first(),
        load_certs("server-default.crt").first(),
        "the previous certificate should still be in use"
    );
}

/// Cipher suite selection reaching the handshake, asserted on the suite the
/// client actually negotiated.
#[test]
fn configured_cipher_suite_is_the_one_negotiated() {
    install_crypto_provider();
    let mut config = base_tls_config();
    config.min_version = zentinel_common::types::TlsVersion::Tls13;
    config.cipher_suites = vec!["TLS_CHACHA20_POLY1305_SHA256".to_string()];

    let server_config = build_server_config(&config, "cipher-test").expect("building config");
    let outcome = handshake(server_config, "localhost", verifying_client())
        .expect("handshake should succeed");

    assert_eq!(
        outcome.cipher_suite,
        Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        "the single configured cipher suite should have been negotiated"
    );
}
