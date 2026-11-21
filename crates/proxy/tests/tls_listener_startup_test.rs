//! A TLS listener that cannot be built stops startup, and `zentinel test`
//! reports the same configuration.
//!
//! When a listener's certificate or key could not be loaded -- a file that
//! does not exist, a file that is not PEM -- startup used to log an error,
//! leave that listener out and carry on. With a single TLS listener the
//! process kept running without listening on its port, and `zentinel test`
//! accepted the configuration.
//!
//! These tests run the real binary against a plain listener and a TLS
//! listener, both on loopback, and break the TLS listener's files in each
//! way the startup path can fail.

#![cfg(unix)]

use std::fs::File;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a started process gets before the test gives up on it.
const STARTUP_DEADLINE: Duration = Duration::from_secs(60);

const TLS_LISTENER_ID: &str = "edge-tls";

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tls")
}

/// A port the OS has just handed out and that is free again.
///
/// The tests of this file run in parallel and a port is only bound by the
/// proxy a moment later, so no port is handed out twice: two tests that were
/// given the same one would see each other's listeners.
fn free_port() -> u16 {
    static HANDED_OUT: Mutex<Vec<u16>> = Mutex::new(Vec::new());
    loop {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut handed_out = HANDED_OUT.lock().unwrap();
        if !handed_out.contains(&port) {
            handed_out.push(port);
            return port;
        }
    }
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `cert-file` and `key-file` lines for a `tls` block.
fn cert_and_key(cert: &Path, key: &Path) -> String {
    format!(
        "cert-file \"{}\"\nkey-file \"{}\"\n",
        cert.display(),
        key.display()
    )
}

fn good_cert_and_key() -> String {
    cert_and_key(
        &fixtures().join("server-default.crt"),
        &fixtures().join("server-default.key"),
    )
}

/// An `acme` block that stores under `dir` and names a CA that is not there:
/// if the proxy ever tried to reach it, the attempt would fail at once.
fn acme_block(dir: &Path) -> String {
    acme_block_for_ca(dir, free_port())
}

/// An `acme` block that stores under `dir` and names a CA on `ca_port`.
fn acme_block_for_ca(dir: &Path, ca_port: u16) -> String {
    format!(
        "acme {{\nemail \"admin@example.com\"\ndomains \"a.example\"\nstorage \"{}\"\n\
         server-url \"https://127.0.0.1:{ca_port}/directory\"\n}}\n",
        dir.join("acme").display(),
    )
}

/// A way for the TLS listener's files to be unusable.
#[derive(Clone, Copy, Debug)]
enum Fault {
    MissingCertificate,
    MissingKey,
    CertificateNotPem,
    KeyNotPem,
    MissingSniCertificate,
    MissingClientCa,
    /// A `protocol "h2"` listener, which is built like an `https` one.
    Http2MissingCertificate,
    /// A listener, of the given protocol, whose default certificate ACME
    /// would issue, but whose `sni` certificate is a file that does not exist.
    AcmeListenerMissingSniCertificate(&'static str),
}

impl Fault {
    fn protocol(self) -> &'static str {
        match self {
            Fault::Http2MissingCertificate => "h2",
            Fault::AcmeListenerMissingSniCertificate(protocol) => protocol,
            _ => "https",
        }
    }

    /// The body of the listener's `tls` block, written for `dir`, and the
    /// file an error is expected to name.
    fn tls_block(self, dir: &Path) -> (String, PathBuf) {
        let fixtures = fixtures();
        let (good_cert, good_key) = (
            fixtures.join("server-default.crt"),
            fixtures.join("server-default.key"),
        );
        let not_pem = |name: &str| {
            let path = dir.join(name);
            std::fs::write(&path, "this is not a PEM file\n").unwrap();
            path
        };
        let missing_sni = |dir: &Path| {
            let culprit = dir.join("missing-sni.crt");
            let block = format!(
                "sni {{\nhostnames \"a.example\"\n{}}}\n",
                cert_and_key(&culprit, &dir.join("missing-sni.key")),
            );
            (block, culprit)
        };
        match self {
            Fault::MissingCertificate | Fault::Http2MissingCertificate => {
                let culprit = dir.join("missing.crt");
                (cert_and_key(&culprit, &good_key), culprit)
            }
            Fault::MissingKey => {
                let culprit = dir.join("missing.key");
                (cert_and_key(&good_cert, &culprit), culprit)
            }
            Fault::CertificateNotPem => {
                let culprit = not_pem("not-a-certificate.crt");
                (cert_and_key(&culprit, &good_key), culprit)
            }
            Fault::KeyNotPem => {
                let culprit = not_pem("not-a-key.key");
                (cert_and_key(&good_cert, &culprit), culprit)
            }
            Fault::MissingSniCertificate => {
                let (sni, culprit) = missing_sni(dir);
                (format!("{}{sni}", good_cert_and_key()), culprit)
            }
            Fault::MissingClientCa => {
                let culprit = dir.join("missing-ca.crt");
                (
                    format!(
                        "{}client-auth #true\nca-file \"{}\"\n",
                        good_cert_and_key(),
                        culprit.display()
                    ),
                    culprit,
                )
            }
            Fault::AcmeListenerMissingSniCertificate(_) => {
                let (sni, culprit) = missing_sni(dir);
                (format!("{}{sni}", acme_block(dir)), culprit)
            }
        }
    }
}

/// One TLS listener of a fixture.
struct TlsListener {
    id: &'static str,
    protocol: &'static str,
    /// The body of its `tls` block.
    block: String,
}

/// A configuration with a plain listener and one or more TLS listeners.
struct Fixture {
    dir: tempfile::TempDir,
    config: PathBuf,
    plain_port: u16,
    /// The port of the first TLS listener.
    tls_port: u16,
}

impl Fixture {
    /// `listeners` is given the fixture's directory and returns the TLS
    /// listeners.
    fn new(listeners: impl FnOnce(&Path) -> Vec<TlsListener>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listeners = listeners(dir.path());
        let config = dir.path().join("zentinel.kdl");
        let (plain_port, backend_port) = (free_port(), free_port());
        let mut tls_ports = Vec::new();
        let mut tls_listeners = String::new();
        for listener in &listeners {
            let port = free_port();
            tls_ports.push(port);
            tls_listeners.push_str(&format!(
                r#"
    listener "{id}" {{
        address "127.0.0.1:{port}"
        protocol "{protocol}"
        tls {{
{block}
        }}
    }}"#,
                id = listener.id,
                protocol = listener.protocol,
                block = listener.block,
            ));
        }
        std::fs::write(
            &config,
            format!(
                r#"
system {{
    worker-threads 1
    pid-file "{pid_file}"
}}
listeners {{
    listener "edge-plain" {{
        address "127.0.0.1:{plain_port}"
        protocol "http"
    }}{tls_listeners}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
upstreams {{
    upstream "backend" {{
        // Never connected to: only the listeners matter here.
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
                pid_file = dir.path().join("zentinel.pid").display(),
            ),
        )
        .unwrap();
        Self {
            dir,
            config,
            plain_port,
            tls_port: tls_ports[0],
        }
    }

    /// A fixture with one TLS listener, with a valid certificate.
    fn healthy() -> Self {
        Self::new(|_| {
            vec![TlsListener {
                id: TLS_LISTENER_ID,
                protocol: "https",
                block: good_cert_and_key(),
            }]
        })
    }

    /// A fixture whose TLS listener has `fault`, and the file the error
    /// should name.
    fn faulty(fault: Fault) -> (Self, PathBuf) {
        let mut culprit = PathBuf::new();
        let fixture = Self::new(|dir| {
            let (block, file) = fault.tls_block(dir);
            culprit = file;
            vec![TlsListener {
                id: TLS_LISTENER_ID,
                protocol: fault.protocol(),
                block,
            }]
        });
        (fixture, culprit)
    }

    /// `zentinel test`: the process output and all its text.
    fn run_config_test(&self) -> (Output, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("test")
            .arg("-c")
            .arg(&self.config)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output, text)
    }

    /// Start the proxy with `args` before `-c`. Its output goes to files, so
    /// a process that is still running never blocks on a full pipe.
    fn start(&self, args: &[&str]) -> Started {
        let stdout = self.dir.path().join("proxy.stdout");
        let stderr = self.dir.path().join("proxy.stderr");
        let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .args(args)
            .arg("-c")
            .arg(&self.config)
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        Started {
            child: KillOnDrop(child),
            stdout,
            stderr,
            pid_file: self.dir.path().join("zentinel.pid"),
        }
    }
}

/// Whether something accepts connections on `port`.
fn accepts(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).is_ok()
}

struct Started {
    child: KillOnDrop,
    stdout: PathBuf,
    stderr: PathBuf,
    pid_file: PathBuf,
}

impl Drop for Started {
    /// A daemon the proxy forked is not the child this test holds.
    fn drop(&mut self) {
        let pid = std::fs::read_to_string(&self.pid_file)
            .ok()
            .and_then(|s| s.trim().parse::<libc::pid_t>().ok());
        if let Some(pid) = pid {
            // SAFETY: plain kill(2) on the pid the proxy wrote.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// What the log says once startup is over and the proxy is about to serve.
const STARTED: &str = "Zentinel proxy started successfully";

/// What the log says when a listener is registered.
const LISTENING: &str = "listening on";

/// What a started proxy did.
enum Outcome {
    Exited(ExitStatus),
    /// Startup finished: the proxy went on to serve.
    Started,
    TimedOut,
}

impl Started {
    /// Poll until the proxy exits or logs that it has started. The log is
    /// read rather than a port probed, because another process on the machine
    /// can be listening on a port this test was handed a moment ago.
    fn wait(&mut self) -> Outcome {
        let deadline = Instant::now() + STARTUP_DEADLINE;
        while Instant::now() < deadline {
            if let Some(status) = self.child.0.try_wait().unwrap() {
                return Outcome::Exited(status);
            }
            if self.log().contains(STARTED) {
                return Outcome::Started;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Outcome::TimedOut
    }

    /// Everything the process has written so far.
    fn log(&self) -> String {
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}",
            std::fs::read_to_string(&self.stdout).unwrap_or_default(),
            std::fs::read_to_string(&self.stderr).unwrap_or_default()
        )
    }
}

/// The error must say which listener, where, and which file.
fn assert_names_the_listener_and_file(text: &str, fixture: &Fixture, culprit: &Path, what: &str) {
    for needle in [
        TLS_LISTENER_ID.to_string(),
        format!("127.0.0.1:{}", fixture.tls_port),
        culprit.display().to_string(),
    ] {
        assert!(
            text.contains(&needle),
            "{what}: the output does not mention {needle:?}:\n{text}"
        );
    }
}

/// What the log says when ACME initialization starts.
const ACME_INITIALIZATION: &str = "Initializing ACME";

fn check_startup_stops(fault: Fault) {
    let (fixture, culprit) = Fixture::faulty(fault);
    let mut proxy = fixture.start(&[]);
    let what = format!("{fault:?}");

    match proxy.wait() {
        Outcome::Exited(status) => {
            assert!(!status.success(), "{what}: exited with {status}");
            let log = proxy.log();
            assert_names_the_listener_and_file(&log, &fixture, &culprit, &what);
            assert!(
                !log.contains(ACME_INITIALIZATION),
                "{what}: ACME was initialized before the listener was checked:\n{log}"
            );
            // No listener, the plain one included, had been registered.
            assert!(
                !log.contains(LISTENING),
                "{what}: a listener was registered before startup stopped:\n{log}"
            );
        }
        Outcome::Started => panic!(
            "{what}: the proxy started although TLS listener '{TLS_LISTENER_ID}' \
             could not be built:\n{}",
            proxy.log()
        ),
        Outcome::TimedOut => panic!("{what}: still starting after the deadline"),
    }
}

fn check_config_test_reports(fault: Fault) {
    let (fixture, culprit) = Fixture::faulty(fault);
    let what = format!("{fault:?}");

    let (output, text) = fixture.run_config_test();

    assert!(
        !output.status.success(),
        "{what}: `zentinel test` accepted the configuration:\n{text}"
    );
    assert!(
        !text.contains("test is successful"),
        "{what}: `zentinel test` reported success:\n{text}"
    );
    assert_names_the_listener_and_file(&text, &fixture, &culprit, &what);
}

/// One module per fault: each gets its own startup and `zentinel test` test.
macro_rules! fault_tests {
    ($($module:ident => $fault:expr),* $(,)?) => {$(
        mod $module {
            use super::*;

            #[test]
            fn startup_stops_when_a_tls_listener_cannot_be_built() {
                check_startup_stops($fault);
            }

            #[test]
            fn config_test_reports_a_tls_listener_that_cannot_be_built() {
                check_config_test_reports($fault);
            }
        }
    )*};
}

fault_tests! {
    missing_certificate_file => Fault::MissingCertificate,
    missing_key_file => Fault::MissingKey,
    certificate_file_that_is_not_pem => Fault::CertificateNotPem,
    key_file_that_is_not_pem => Fault::KeyNotPem,
    missing_sni_certificate_file => Fault::MissingSniCertificate,
    missing_client_ca_file => Fault::MissingClientCa,
    h2_listener_with_a_missing_certificate_file => Fault::Http2MissingCertificate,
    acme_listener_with_a_missing_sni_certificate_file =>
        Fault::AcmeListenerMissingSniCertificate("https"),
    acme_h2_listener_with_a_missing_sni_certificate_file =>
        Fault::AcmeListenerMissingSniCertificate("h2"),
}

/// A manual certificate that is missing must stop startup before ACME is
/// initialized: otherwise every restart of a configuration with a typo in a
/// path would go to the CA first.
#[test]
fn a_missing_certificate_stops_startup_before_acme_initialization() {
    let mut culprit = PathBuf::new();
    let fixture = Fixture::new(|dir| {
        culprit = dir.join("missing.crt");
        vec![
            TlsListener {
                id: TLS_LISTENER_ID,
                protocol: "https",
                block: cert_and_key(&culprit, &fixtures().join("server-default.key")),
            },
            TlsListener {
                id: "edge-acme",
                protocol: "https",
                block: acme_block(dir),
            },
        ]
    });
    let mut proxy = fixture.start(&[]);

    let Outcome::Exited(status) = proxy.wait() else {
        panic!("the proxy did not stop:\n{}", proxy.log());
    };
    let log = proxy.log();
    assert!(!status.success(), "exited with {status}");
    assert_names_the_listener_and_file(&log, &fixture, &culprit, "ordering");
    assert!(
        !log.contains(ACME_INITIALIZATION),
        "ACME was initialized before the certificate was checked:\n{log}"
    );
}

/// With `--daemon` the proxy forks early. A TLS listener that cannot be built
/// must stop it before that, so that the shell that started it is told.
#[test]
fn daemon_mode_stops_in_the_foreground_when_a_tls_listener_cannot_be_built() {
    let (fixture, culprit) = Fixture::faulty(Fault::MissingCertificate);
    let mut launcher = fixture.start(&["-d"]);

    let Outcome::Exited(status) = launcher.wait() else {
        panic!("the proxy did not exit:\n{}", launcher.log());
    };
    let log = launcher.log();
    assert!(
        !status.success(),
        "the launcher exited with {status} although a TLS listener cannot be built:\n{log}"
    );
    assert_names_the_listener_and_file(&log, &fixture, &culprit, "daemon");
    assert!(!launcher.pid_file.exists(), "a daemon was started:\n{log}");
}

#[test]
fn a_tls_listener_that_can_be_built_still_starts() {
    let fixture = Fixture::healthy();
    let mut proxy = fixture.start(&[]);

    assert!(
        matches!(proxy.wait(), Outcome::Started),
        "the proxy did not start:\n{}",
        proxy.log()
    );
    let deadline = Instant::now() + STARTUP_DEADLINE;
    while !(accepts(fixture.plain_port) && accepts(fixture.tls_port)) {
        assert!(
            proxy.child.0.try_wait().unwrap().is_none(),
            "the proxy exited:\n{}",
            proxy.log()
        );
        assert!(
            Instant::now() < deadline,
            "the listeners never came up:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn config_test_accepts_a_tls_listener_that_can_be_built() {
    let fixture = Fixture::healthy();

    let (output, text) = fixture.run_config_test();

    assert!(output.status.success(), "{text}");
    assert!(text.contains("test is successful"), "{text}");
}

/// The default certificate of a TLS listener that ACME manages is issued
/// while the proxy starts, so it need not exist when the configuration is
/// tested.
fn check_config_test_does_not_require_acme_certificates(protocol: &'static str) {
    let fixture = Fixture::new(|dir| {
        vec![TlsListener {
            id: TLS_LISTENER_ID,
            protocol,
            block: acme_block(dir),
        }]
    });

    let (output, text) = fixture.run_config_test();

    assert!(output.status.success(), "{protocol}: {text}");
}

#[test]
fn config_test_does_not_require_acme_certificates_to_exist_yet() {
    check_config_test_does_not_require_acme_certificates("https");
}

#[test]
fn config_test_does_not_require_acme_certificates_to_exist_yet_for_an_h2_listener() {
    check_config_test_does_not_require_acme_certificates("h2");
}

/// A TLS listener's `acme` block is acted on whichever of `https` and `h2` the
/// listener uses: ACME is initialized for it, and when issuing the first
/// certificate fails, startup stops there.
fn check_startup_stops_when_the_first_acme_certificate_cannot_be_issued(protocol: &'static str) {
    let fixture = Fixture::new(|dir| {
        vec![TlsListener {
            id: TLS_LISTENER_ID,
            protocol,
            block: acme_block(dir),
        }]
    });
    let mut proxy = fixture.start(&[]);

    let Outcome::Exited(status) = proxy.wait() else {
        panic!("{protocol}: the proxy did not stop:\n{}", proxy.log());
    };
    let log = proxy.log();
    assert!(!status.success(), "{protocol}: exited with {status}\n{log}");
    assert!(
        log.contains(ACME_INITIALIZATION),
        "{protocol}: ACME was not initialized for the listener:\n{log}"
    );
    assert!(
        log.contains("ACME initialization failed"),
        "{protocol}: startup did not stop at ACME initialization:\n{log}"
    );
}

#[test]
fn startup_stops_when_the_first_acme_certificate_of_an_https_listener_cannot_be_issued() {
    check_startup_stops_when_the_first_acme_certificate_cannot_be_issued("https");
}

#[test]
fn startup_stops_when_the_first_acme_certificate_of_an_h2_listener_cannot_be_issued() {
    check_startup_stops_when_the_first_acme_certificate_cannot_be_issued("h2");
}

/// A stand-in for the CA that only counts the connections made to it and
/// closes each one at once. The proxy treats that as a transient failure, so a
/// listener whose certificate is already stored still starts.
struct FakeCa {
    port: u16,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeCa {
    fn start() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let port = free_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (connections, stop) = (Arc::clone(&connections), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok(_) => {
                            connections.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    }
                }
            })
        };
        Self {
            port,
            connections,
            stop,
            thread: Some(thread),
        }
    }

    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Drop for FakeCa {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Put the fixture certificate where an `acme` block for `a.example` that
/// stores under `dir` keeps the one it has issued.
fn store_issued_certificate(dir: &Path) {
    let storage = zentinel_proxy::acme::CertificateStorage::new(&dir.join("acme")).unwrap();
    storage
        .save_certificate(
            "a.example",
            &std::fs::read_to_string(fixtures().join("server-default.crt")).unwrap(),
            &std::fs::read_to_string(fixtures().join("server-default.key")).unwrap(),
            chrono::Utc::now() + chrono::Duration::days(90),
            &["a.example".to_string()],
        )
        .unwrap();
}

/// What a client offering `h2` and `http/1.1` sees of a TLS handshake.
struct Handshake {
    /// The DER of the certificate the listener presents.
    certificate: Vec<u8>,
    /// The application protocol the listener selected.
    alpn: Option<Vec<u8>>,
}

fn handshake_with(port: u16) -> Handshake {
    use rustls::pki_types::ServerName;

    let mut roots = rustls::RootCertStore::empty();
    let ca = std::fs::File::open(fixtures().join("ca.crt")).unwrap();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca)) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut connection = rustls::ClientConnection::new(
        std::sync::Arc::new(client_config),
        ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    while connection.is_handshaking() {
        connection.complete_io(&mut tcp).unwrap();
    }
    Handshake {
        certificate: connection.peer_certificates().unwrap()[0].as_ref().to_vec(),
        alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
    }
}

/// An `acme` block on a TLS listener is acted on: the proxy initializes ACME
/// for it, which contacts the CA, and the listener serves the certificate
/// kept in the block's storage and negotiates HTTP/2 with it.
fn check_stored_acme_certificate_is_served(protocol: &'static str) {
    let ca = FakeCa::start();
    let fixture = Fixture::new(|dir| {
        store_issued_certificate(dir);
        vec![TlsListener {
            id: TLS_LISTENER_ID,
            protocol,
            block: acme_block_for_ca(dir, ca.port),
        }]
    });
    let mut proxy = fixture.start(&[]);

    assert!(
        matches!(proxy.wait(), Outcome::Started),
        "{protocol}: the proxy did not start:\n{}",
        proxy.log()
    );
    let deadline = Instant::now() + STARTUP_DEADLINE;
    while !accepts(fixture.tls_port) {
        assert!(
            proxy.child.0.try_wait().unwrap().is_none(),
            "{protocol}: the proxy exited:\n{}",
            proxy.log()
        );
        assert!(
            Instant::now() < deadline,
            "{protocol}: the listener never came up:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    assert!(
        ca.connections() > 0,
        "{protocol}: the proxy never contacted the CA of the listener's acme block:\n{}",
        proxy.log()
    );
    let stored = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(fixtures().join("server-default.crt")).unwrap(),
    ))
    .next()
    .unwrap()
    .unwrap();
    let handshake = handshake_with(fixture.tls_port);
    assert_eq!(
        handshake.certificate,
        stored.as_ref(),
        "{protocol}: the listener does not serve the stored certificate"
    );
    assert_eq!(
        handshake.alpn.as_deref(),
        Some(&b"h2"[..]),
        "{protocol}: the listener does not negotiate HTTP/2"
    );
}

#[test]
fn an_https_listener_with_acme_initializes_it_and_serves_the_stored_certificate() {
    check_stored_acme_certificate_is_served("https");
}

#[test]
fn an_h2_listener_with_acme_initializes_it_and_serves_the_stored_certificate() {
    check_stored_acme_certificate_is_served("h2");
}
