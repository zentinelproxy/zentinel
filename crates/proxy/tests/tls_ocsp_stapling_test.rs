//! OCSP stapling end to end (#590).
//!
//! `ocsp-stapling` used to parse and do nothing: `OcspStapler` was never
//! constructed, so no handshake ever carried a staple. These tests stand up a
//! real, independent OCSP responder (`openssl ocsp`), let the listener's
//! resolver fetch from it the way the background refresher does, and then run
//! a real TLS handshake and look at what the client received.
//!
//! The staple the client receives is checked by OpenSSL, not by our own parser:
//! `openssl ocsp -respin` verifies the responder's signature and reports the
//! certificate status. A test that only re-parsed the bytes with the code under
//! test could not catch a request or parser that agrees with itself and with
//! nothing else.
//!
//! Requires the `openssl` command-line tool (present on CI's Ubuntu runners and
//! on macOS). It fails, rather than skips, without it: a silently skipped test
//! is how this feature went untested.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, ServerConnection,
};
use zentinel_config::TlsConfig;
use zentinel_proxy::tls::{build_server_config_with_resolver, HotReloadableSniResolver};

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // Show the stapler's own logs when a test fails.
        let _ = tracing_subscriber::fmt()
            .with_env_filter("zentinel_proxy=debug")
            .with_test_writer()
            .try_init();
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("installing the aws-lc-rs crypto provider");
    });
}

fn openssl(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("running openssl: the openssl CLI is required for the OCSP tests");
    assert!(
        out.status.success(),
        "openssl {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// How the responder should describe the leaf certificate.
#[derive(Clone, Copy)]
enum LeafStatus {
    Valid,
    Revoked,
}

/// A throwaway CA, a leaf whose AIA points at `ocsp_port`, and the files an
/// `openssl ocsp` responder needs.
struct Pki {
    dir: tempfile::TempDir,
    ocsp_port: u16,
}

impl Pki {
    fn new(status: LeafStatus) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ocsp_port = free_port();
        let d = dir.path();

        openssl(
            d,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "ca.key",
            ],
        );
        openssl(
            d,
            &[
                "req",
                "-x509",
                "-new",
                "-key",
                "ca.key",
                "-out",
                "ca.crt",
                "-days",
                "2",
                "-subj",
                "/CN=Zentinel OCSP Test CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign,digitalSignature",
            ],
        );
        openssl(
            d,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "leaf.key",
            ],
        );
        openssl(
            d,
            &[
                "req",
                "-new",
                "-key",
                "leaf.key",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
        std::fs::write(
            d.join("leaf.ext"),
            format!(
                "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
                 basicConstraints=CA:FALSE\n\
                 extendedKeyUsage=serverAuth\n\
                 authorityInfoAccess=OCSP;URI:http://127.0.0.1:{ocsp_port}/\n"
            ),
        )
        .unwrap();
        openssl(
            d,
            &[
                "x509",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "ca.crt",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "leaf.crt",
                "-days",
                "2",
                "-extfile",
                "leaf.ext",
            ],
        );

        // The chain the listener serves: leaf, then issuer.
        let chain = [
            std::fs::read_to_string(d.join("leaf.crt")).unwrap(),
            std::fs::read_to_string(d.join("ca.crt")).unwrap(),
        ]
        .concat();
        std::fs::write(d.join("chain.crt"), chain).unwrap();

        // openssl's responder database: one line per certificate.
        let serial = openssl(d, &["x509", "-in", "leaf.crt", "-noout", "-serial"]);
        let serial = serial.trim().trim_start_matches("serial=").to_string();
        let line = match status {
            LeafStatus::Valid => format!("V\t301231235959Z\t\t{serial}\tunknown\t/CN=localhost\n"),
            LeafStatus::Revoked => {
                format!("R\t301231235959Z\t250101000000Z\t{serial}\tunknown\t/CN=localhost\n")
            }
        };
        std::fs::write(d.join("index.txt"), line).unwrap();

        Self { dir, ocsp_port }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn tls_config(&self, ocsp_stapling: bool) -> TlsConfig {
        TlsConfig {
            cert_folders: Vec::new(),
            allow_sni_overlaps: false,
            cert_file: Some(self.path("chain.crt")),
            key_file: Some(self.path("leaf.key")),
            additional_certs: vec![],
            ca_file: None,
            min_version: zentinel_common::types::TlsVersion::Tls12,
            max_version: None,
            cipher_suites: vec![],
            client_auth: false,
            ocsp_stapling,
            session_resumption: true,
            acme: None,
        }
    }

    /// Start `openssl ocsp` on the port the leaf's AIA names.
    ///
    /// Readiness is read from the responder's own "waiting for OCSP client
    /// connections" line rather than probed with a connection: the responder
    /// is single-threaded, and an empty probe connection wedges it until it
    /// times out.
    fn start_responder(&self) -> Responder {
        use std::io::BufRead;

        let mut child = Command::new("openssl")
            .args([
                "ocsp",
                "-index",
                "index.txt",
                "-port",
                &self.ocsp_port.to_string(),
                "-rsigner",
                "ca.crt",
                "-rkey",
                "ca.key",
                "-CA",
                "ca.crt",
                "-nmin",
                "60",
                "-ignore_err",
            ])
            .current_dir(self.dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("starting openssl ocsp responder");

        let stderr = child.stderr.take().unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let mut ready_tx = Some(ready_tx);
            for line in std::io::BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if line.contains("waiting for OCSP client connections") {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("OCSP responder did not start");
        Responder(child)
    }

    /// Have OpenSSL check a stapled response: signature and status.
    fn openssl_check(&self, staple: &[u8]) -> String {
        std::fs::write(self.path("stapled.der"), staple).unwrap();
        openssl(
            self.dir.path(),
            &[
                // The request used SHA-256 CertID hashes; openssl defaults to
                // SHA-1 when matching, so it must be told.
                "ocsp",
                "-respin",
                "stapled.der",
                "-CAfile",
                "ca.crt",
                "-issuer",
                "ca.crt",
                "-sha256",
                "-cert",
                "leaf.crt",
            ],
        )
    }
}

struct Responder(Child);

impl Drop for Responder {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Verifies the server for real and records the stapled OCSP response.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<WebPkiServerVerifier>,
    staple: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.staple.lock().unwrap() = Some(ocsp_response.to_vec());
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Handshake against `resolver` and return the OCSP staple the client saw
/// (empty when none was sent). Fails the test if the handshake fails.
fn staple_seen_by_client(
    pki: &Pki,
    resolver: Arc<HotReloadableSniResolver>,
    version: &'static rustls::SupportedProtocolVersion,
) -> Vec<u8> {
    let server_config =
        build_server_config_with_resolver(&pki.tls_config(true), resolver).expect("server config");

    let mut roots = RootCertStore::empty();
    let ca_pem = std::fs::read(pki.path("ca.crt")).unwrap();
    for cert in rustls_pemfile::certs(&mut &ca_pem[..]) {
        roots.add(cert.unwrap()).unwrap();
    }
    let staple = Arc::new(Mutex::new(None));
    let verifier = RecordingVerifier {
        inner: WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .unwrap(),
        staple: staple.clone(),
    };
    let client_config = ClientConfig::builder_with_protocol_versions(&[version])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut conn = ServerConnection::new(Arc::new(server_config)).unwrap();
        while conn.is_handshaking() {
            if conn.complete_io(&mut socket).is_err() {
                return;
            }
        }
        if conn.writer().write_all(b"ok").is_ok() {
            let _ = conn.complete_io(&mut socket);
        }
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut socket = TcpStream::connect(addr).unwrap();
    let mut greeting = [0u8; 2];
    rustls::Stream::new(&mut conn, &mut socket)
        .read_exact(&mut greeting)
        .expect("handshake must succeed whether or not a staple is available");
    assert_eq!(&greeting, b"ok");
    server.join().unwrap();

    let seen = staple.lock().unwrap().clone();
    seen.expect("verifier was called")
}

fn resolver_for(pki: &Pki, ocsp_stapling: bool) -> Arc<HotReloadableSniResolver> {
    Arc::new(
        HotReloadableSniResolver::from_config(pki.tls_config(ocsp_stapling), "https-test")
            .expect("loading certificates"),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_good_response_is_fetched_and_stapled_to_the_handshake() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Valid);
    let _responder = pki.start_responder();

    let resolver = resolver_for(&pki, true);
    let summary = resolver.refresh_ocsp().await;
    assert_eq!(summary.fetched, 1, "{summary:?}");
    assert_eq!(summary.failed, 0, "{summary:?}");
    assert_eq!(summary.stapled, 1, "{summary:?}");

    for version in [&rustls::version::TLS13, &rustls::version::TLS12] {
        let staple = staple_seen_by_client(&pki, resolver.clone(), version);
        assert!(
            !staple.is_empty(),
            "client requested status over {version:?} but no OCSP response was stapled"
        );
        let report = pki.openssl_check(&staple);
        assert!(report.contains("Response verify OK"), "{report}");
        assert!(report.contains("leaf.crt: good"), "{report}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_refresh_does_not_refetch_a_fresh_response() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Valid);
    let _responder = pki.start_responder();

    let resolver = resolver_for(&pki, true);
    assert_eq!(resolver.refresh_ocsp().await.fetched, 1);
    let again = resolver.refresh_ocsp().await;
    assert_eq!(again.fetched, 0, "{again:?}");
    assert_eq!(again.stapled, 1, "{again:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stapling_disabled_sends_no_staple() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Valid);
    let _responder = pki.start_responder();

    let resolver = resolver_for(&pki, false);
    let summary = resolver.refresh_ocsp().await;
    assert_eq!(summary.fetched, 0, "{summary:?}");
    let staple = staple_seen_by_client(&pki, resolver, &rustls::version::TLS13);
    assert!(staple.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_responder_never_fails_the_handshake() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Valid);
    // No responder started: the AIA URL points at a closed port.

    let resolver = resolver_for(&pki, true);
    let summary = resolver.refresh_ocsp().await;
    assert_eq!(summary.fetched, 1, "{summary:?}");
    assert_eq!(summary.failed, 1, "{summary:?}");
    assert_eq!(summary.stapled, 0, "{summary:?}");

    let staple = staple_seen_by_client(&pki, resolver.clone(), &rustls::version::TLS13);
    assert!(staple.is_empty());

    // Once the responder is back, the next forced refresh staples.
    let _responder = pki.start_responder();
    let summary = resolver.force_refresh_ocsp().await;
    assert_eq!(summary.stapled, 1, "{summary:?}");
    let staple = staple_seen_by_client(&pki, resolver, &rustls::version::TLS13);
    assert!(pki.openssl_check(&staple).contains("leaf.crt: good"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_status_is_never_stapled() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Revoked);
    let _responder = pki.start_responder();

    let resolver = resolver_for(&pki, true);
    let summary = resolver.refresh_ocsp().await;
    assert_eq!(summary.failed, 1, "{summary:?}");
    assert_eq!(summary.stapled, 0, "{summary:?}");
    let staple = staple_seen_by_client(&pki, resolver, &rustls::version::TLS13);
    assert!(staple.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_reload_keeps_the_staple_of_an_unchanged_certificate() {
    install_crypto_provider();
    let pki = Pki::new(LeafStatus::Valid);
    let _responder = pki.start_responder();

    let resolver = resolver_for(&pki, true);
    assert_eq!(resolver.refresh_ocsp().await.stapled, 1);

    // SIGHUP with the same files on disk.
    resolver.reload().expect("reload");
    let staple = staple_seen_by_client(&pki, resolver, &rustls::version::TLS13);
    assert!(pki.openssl_check(&staple).contains("leaf.crt: good"));
}
