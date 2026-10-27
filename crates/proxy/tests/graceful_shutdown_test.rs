//! SIGTERM and SIGINT stop accepting, let the requests in flight finish, and
//! end the process once they have or `graceful-shutdown-timeout-secs` is up.
//!
//! The proxy used to log "draining connections" and call `exit(0)` at once,
//! so a request in flight when `systemctl restart` ran was cut off.
//!
//! Also covered: a signal during startup (nothing is serving, so it ends the
//! process at once and no listener ever accepts), a second signal while
//! draining (ends the process at once), a signal while startup waits on a
//! silent agent, a TLS handshake that straddles the signal, and the same
//! drain in a daemon started with `-d`.
//!
//! Runs the real binary against a backend that answers slowly.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend that waits `delay` before it answers 200 "ok".
fn slow_backend(delay: Duration) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind backend");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                std::thread::sleep(delay);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    port
}

/// Send one request on a new connection, from a thread, and report what came
/// back: the status line's code and the body, or `None` if the connection was
/// cut before a response.
fn request_in_background(proxy: u16) -> mpsc::Receiver<Option<(u16, String)>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let mut stream = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .ok()?;
            stream
                .write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
                .ok()?;
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            let code = response.split_whitespace().nth(1)?.parse().ok()?;
            let body = response.rsplit("\r\n\r\n").next()?.to_string();
            Some((code, body))
        })();
        let _ = tx.send(result);
    });
    rx
}

struct Proxy {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Proxy {
    fn start(config: &Path, port: u16) -> Self {
        let mut proxy = Self::spawn(config);
        proxy.wait_for("Zentinel proxy started successfully");
        // The line is logged before the listeners are bound.
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        proxy
    }

    /// Start the process and return at once, while it is still starting.
    fn spawn(config: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let (tx, lines) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            lines,
            log: Vec::new(),
        }
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let found = line.contains(needle);
                    self.log.push(line);
                    if found {
                        return;
                    }
                }
                Err(_) => {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        panic!(
                            "the proxy exited ({status:?}) before {needle:?}; log:\n{}",
                            self.log.join("\n")
                        );
                    }
                }
            }
        }
        panic!("never saw {needle:?}; log:\n{}", self.log.join("\n"));
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    /// Wait for the process to exit, returning how it did and when.
    fn wait_exit(&mut self, within: Duration) -> (ExitStatus, Instant) {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return (status, Instant::now());
            }
            assert!(
                Instant::now() < deadline,
                "the proxy was still running {within:?} after the signal; log:\n{}",
                self.log.join("\n")
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(dir: &Path, proxy: u16, backend: u16, timeout_secs: u64) -> std::path::PathBuf {
    let config = dir.join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{
    worker-threads 1
    graceful-shutdown-timeout-secs {timeout_secs}
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{proxy}"
        protocol "http"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
        ),
    )
    .unwrap();
    config
}

/// A request that takes 2 s is half done when the signal arrives. It must
/// finish with its 200, a connection opened during the drain must be refused,
/// and the process must then exit 0 well before the 20 s timeout.
fn in_flight_request_finishes(sig: libc::c_int) {
    let backend = slow_backend(Duration::from_secs(2));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(700));
    let signalled = Instant::now();
    proxy.signal(sig);

    std::thread::sleep(Duration::from_millis(500));
    let refused = TcpStream::connect_timeout(
        &([127, 0, 0, 1], proxy_port).into(),
        Duration::from_millis(500),
    );
    assert!(
        refused.is_err(),
        "a connection was accepted during the drain"
    );

    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some((200, "ok".to_string())),
        "the request in flight was cut off; log:\n{}",
        proxy.log.join("\n")
    );
    assert!(status.success(), "{status:?}");
    let took = exited - signalled;
    assert!(
        took >= Duration::from_millis(1200) && took < Duration::from_secs(10),
        "exited {took:?} after the signal; the request needed about 1.3 s more"
    );
}

#[test]
fn sigterm_lets_the_request_in_flight_finish() {
    in_flight_request_finishes(libc::SIGTERM);
}

#[test]
fn sigint_lets_the_request_in_flight_finish() {
    in_flight_request_finishes(libc::SIGINT);
}

#[test]
fn an_idle_proxy_exits_at_once() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 30),
        proxy_port,
    );

    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);
    let (status, exited) = proxy.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "{status:?}");
    assert!(
        exited - signalled < Duration::from_secs(5),
        "an idle proxy took {:?} to exit with a 30 s timeout",
        exited - signalled
    );
}

#[test]
fn a_request_that_outlasts_the_timeout_is_cut_off_at_the_timeout() {
    let backend = slow_backend(Duration::from_secs(30));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 2),
        proxy_port,
    );

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(500));
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);

    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    let took = exited - signalled;
    assert!(status.success(), "{status:?}");
    assert!(
        took >= Duration::from_millis(1800) && took < Duration::from_secs(6),
        "exited {took:?} after the signal, with a 2 s timeout"
    );
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        None,
        "the request should have been cut off"
    );
}

/// The signal comes while the proxy is still starting, after it has taken
/// over SIGTERM but before Pingora's own handlers exist. Nothing is serving,
/// so there is nothing to drain: the process ends at once with 0, and no
/// listener ever accepts. The 30 s timeout must not matter.
#[test]
fn a_signal_during_startup_stops_at_once_and_never_accepts() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::spawn(&write_config(dir.path(), proxy_port, backend, 30));

    proxy.wait_for("Bootstrap done");
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);

    let mut accepted = false;
    let (status, exited) = loop {
        accepted |= TcpStream::connect_timeout(
            &([127, 0, 0, 1], proxy_port).into(),
            Duration::from_millis(50),
        )
        .is_ok();
        if let Some(status) = proxy.child.try_wait().unwrap() {
            break (status, Instant::now());
        }
        assert!(
            signalled.elapsed() < Duration::from_secs(10),
            "still running {:?} after a signal during startup; log:\n{}",
            signalled.elapsed(),
            proxy.log.join("\n")
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "{status:?}");
    assert!(
        exited - signalled < Duration::from_secs(3),
        "exited {:?} after the signal",
        exited - signalled
    );
    assert!(!accepted, "a connection was accepted after the signal");
}

/// An agent that accepts the connection and never answers the handshake keeps
/// the proxy in startup for up to its connect timeout plus 5 s (#606). A
/// signal in that wait stops the proxy at once, long before the wait is over,
/// and nothing listens or accepts. The agents are connected while the proxy is
/// built, before the signal thread exists, so the signal takes its default
/// action and ends the process (the status is the signal itself, which
/// systemd counts as a clean stop for SIGTERM).
fn startup_waiting_on_a_silent_agent_stops_at_once(sig: libc::c_int) {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();

    // A mute agent: it holds every connection it accepts and says nothing.
    let socket = dir.path().join("mute.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let (accepted_tx, accepted) = mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
            let _ = accepted_tx.send(());
        }
    });

    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{
    worker-threads 1
    graceful-shutdown-timeout-secs 30
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{proxy_port}"
        protocol "http"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
agents {{
    agent "mute" type="custom" {{
        unix-socket "{}"
        events "request_headers"
        timeout-ms 500
        connect-timeout-ms 25000
    }}
}}
filters {{
    filter "mute" {{
        type "agent"
        agent "mute"
        failure-mode "open"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "mute"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            socket.display()
        ),
    )
    .unwrap();

    let mut proxy = Proxy::spawn(&config);
    // The proxy is now inside the agent's handshake, which would last 25 s.
    accepted
        .recv_timeout(Duration::from_secs(30))
        .expect("the proxy never connected to the agent");
    let signalled = Instant::now();
    proxy.signal(sig);

    let mut accepted_any = false;
    let status = loop {
        accepted_any |= TcpStream::connect_timeout(
            &([127, 0, 0, 1], proxy_port).into(),
            Duration::from_millis(50),
        )
        .is_ok();
        if let Some(status) = proxy.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            signalled.elapsed() < Duration::from_secs(5),
            "still running {:?} after a signal while startup waited on a silent agent",
            signalled.elapsed()
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(
        status.success() || status.signal() == Some(sig),
        "{status:?}"
    );
    assert!(
        signalled.elapsed() < Duration::from_secs(3),
        "exited {:?} after the signal",
        signalled.elapsed()
    );
    assert!(!accepted_any, "a connection was accepted after the signal");
}

#[test]
fn sigterm_while_startup_waits_on_a_silent_agent_stops_at_once() {
    startup_waiting_on_a_silent_agent_stops_at_once(libc::SIGTERM);
}

#[test]
fn sigint_while_startup_waits_on_a_silent_agent_stops_at_once() {
    startup_waiting_on_a_silent_agent_stops_at_once(libc::SIGINT);
}

/// The first signal drains and the second ends the process at once, with a
/// WARN that names how many connections were open.
fn second_signal_forces_exit(first: libc::c_int, second: libc::c_int, gap: Duration) {
    let backend = slow_backend(Duration::from_secs(30));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(500));
    proxy.signal(first);

    // Still draining: a request is open and the timeout is 20 s away.
    std::thread::sleep(gap);
    assert!(
        proxy.child.try_wait().unwrap().is_none(),
        "the first signal ended the process; log:\n{}",
        proxy.log.join("\n")
    );

    let signalled = Instant::now();
    proxy.signal(second);
    let (status, exited) = proxy.wait_exit(Duration::from_secs(10));
    assert!(
        exited - signalled < Duration::from_secs(3),
        "exited {:?} after the second signal",
        exited - signalled
    );
    assert_eq!(status.code(), Some(1), "{status:?}");
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        None,
        "the request should have been cut off"
    );

    // Drain the rest of the output, then look for the WARN.
    while let Ok(line) = proxy.lines.recv_timeout(Duration::from_millis(500)) {
        proxy.log.push(line);
    }
    let warn = proxy
        .log
        .iter()
        .find(|line| line.contains("while draining, exiting at once"))
        .unwrap_or_else(|| {
            panic!(
                "no WARN for the second signal; log:\n{}",
                proxy.log.join("\n")
            )
        });
    // The log is coloured: drop the escape sequences before matching fields.
    let plain: String = {
        let mut out = String::new();
        let mut chars = warn.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    assert!(plain.contains("WARN"), "{plain}");
    assert!(plain.contains("open_connections=1"), "{plain}");
}

#[test]
fn a_second_sigterm_while_draining_exits_at_once() {
    second_signal_forces_exit(libc::SIGTERM, libc::SIGTERM, Duration::from_millis(1500));
}

#[test]
fn ctrl_c_after_a_sigterm_exits_at_once() {
    second_signal_forces_exit(libc::SIGTERM, libc::SIGINT, Duration::from_millis(1500));
}

#[test]
fn two_sigints_exit_at_once() {
    second_signal_forces_exit(libc::SIGINT, libc::SIGINT, Duration::from_millis(1500));
}

/// A config whose access and error logs buffer 1 MiB, so nothing reaches the
/// files until the process flushes them. `/dead` is routed to a port nobody
/// listens on, which is what puts a line in the error log.
fn write_buffered_log_config(
    dir: &Path,
    proxy: u16,
    backend: u16,
    dead: u16,
    access: &Path,
    error: &Path,
) -> std::path::PathBuf {
    let config = dir.join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{
    worker-threads 1
    graceful-shutdown-timeout-secs 20
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{proxy}"
        protocol "http"
    }}
}}
routes {{
    route "dead" {{
        matches {{ path-prefix "/dead" }}
        upstream "dead"
    }}
    route "served" {{
        matches {{ path-prefix "/served" }}
        upstream "backend"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
    upstream "dead" {{
        target "127.0.0.1:{dead}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
    logging {{
        access-log {{
            enabled #true
            file "{access}"
            format "json"
            buffer-size 1048576
        }}
        error-log {{
            enabled #true
            file "{error}"
            buffer-size 1048576
        }}
    }}
}}
"#,
            access = access.display(),
            error = error.display(),
        ),
    )
    .unwrap();
    config
}

/// The access and error lines of requests served before the signal are still
/// buffered when the signal arrives (1 MiB buffers, nothing written yet). The
/// drain ends in `exit(0)`, which runs no destructors, so the lines are in the
/// files only if the process flushed them first.
fn buffered_logs_are_written_before_exit(sig: libc::c_int) {
    let backend = slow_backend(Duration::ZERO);
    let dead = free_port();
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let access = dir.path().join("access.log");
    let error = dir.path().join("error.log");
    let mut proxy = Proxy::start(
        &write_buffered_log_config(dir.path(), proxy_port, backend, dead, &access, &error),
        proxy_port,
    );

    for path in ["/served-before-the-signal", "/dead/unreachable"] {
        let mut stream = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(response.starts_with("HTTP/1.1 "), "{path}: {response:?}");
    }
    // The lines are only in the buffers: if they were written through, this
    // test would pass whether or not the exit path flushes.
    assert_eq!(std::fs::read_to_string(&access).unwrap(), "");
    assert_eq!(std::fs::read_to_string(&error).unwrap(), "");

    proxy.signal(sig);
    let (status, _) = proxy.wait_exit(Duration::from_secs(15));
    assert!(status.success(), "{status:?}");

    let access_log = std::fs::read_to_string(&access).unwrap();
    assert!(
        access_log.contains("/served-before-the-signal")
            && access_log.contains("/dead/unreachable"),
        "the access log lost its buffered lines at exit: {access_log:?}; log:\n{}",
        proxy.log.join("\n")
    );
    let error_log = std::fs::read_to_string(&error).unwrap();
    assert!(
        error_log.contains("Failed to connect to upstream peer"),
        "the error log lost its buffered line at exit: {error_log:?}; log:\n{}",
        proxy.log.join("\n")
    );
}

#[test]
fn sigterm_writes_the_buffered_logs_before_exiting() {
    buffered_logs_are_written_before_exit(libc::SIGTERM);
}

#[test]
fn sigint_writes_the_buffered_logs_before_exiting() {
    buffered_logs_are_written_before_exit(libc::SIGINT);
}

/// A TLS listener, with the test CA's server certificate for `localhost`.
fn write_tls_config(dir: &Path, proxy: u16, backend: u16, timeout_secs: u64) -> std::path::PathBuf {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tls");
    let config = dir.join("zentinel-tls.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{
    worker-threads 1
    graceful-shutdown-timeout-secs {timeout_secs}
}}
listeners {{
    listener "https" {{
        address "127.0.0.1:{proxy}"
        protocol "https"
        tls {{
            cert-file "{cert}"
            key-file "{key}"
        }}
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            cert = fixtures.join("server-default.crt").display(),
            key = fixtures.join("server-default.key").display(),
        ),
    )
    .unwrap();
    config
}

fn tls_client() -> (rustls::ClientConnection, ()) {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/tls/ca.crt");
    let mut reader = BufReader::new(std::fs::File::open(ca).unwrap());
    for cert in rustls_pemfile::certs(&mut reader) {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (
        rustls::ClientConnection::new(std::sync::Arc::new(config), "localhost".try_into().unwrap())
            .unwrap(),
        (),
    )
}

/// A client has connected to the TLS listener but has not started the
/// handshake when the signal arrives. The handshake is not a connection yet,
/// and used to be dropped with the process; now the drain waits for it, so it
/// completes and its request is answered.
#[test]
fn a_tls_handshake_that_straddles_the_signal_is_not_reset() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_tls_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    let tcp = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);
    std::thread::sleep(Duration::from_millis(1000));
    assert!(
        proxy.child.try_wait().unwrap().is_none(),
        "the process ended with a handshake pending; log:\n{}",
        proxy.log.join("\n")
    );

    // The request goes out in the same flight as the client's Finished, as a
    // TLS 1.3 client's does: the proxy finds it already waiting once the
    // handshake is over. (A connection with nothing to say yet is closed
    // by Pingora once the shutdown has started.)
    let (mut conn, ()) = tls_client();
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    conn.writer()
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    let read = (|| -> std::io::Result<()> {
        while conn.is_handshaking() || conn.wants_write() {
            conn.complete_io(&mut tcp)?;
        }
        rustls::Stream::new(&mut conn, &mut tcp).read_to_string(&mut response)?;
        Ok(())
    })();
    while let Ok(line) = proxy.lines.recv_timeout(Duration::from_millis(300)) {
        proxy.log.push(line);
    }
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the handshake was reset or the request refused: {response:?} {read:?}\nlog:\n{}",
        proxy.log.join("\n")
    );

    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    assert!(status.success(), "{status:?}");
    assert!(exited - signalled < Duration::from_secs(8));
}

/// A connection that never starts its handshake does not hold the shutdown
/// for long: the wait for handshakes is capped.
#[test]
fn a_stalled_tls_connection_does_not_hold_the_shutdown_for_long() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_tls_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    let _stalled = TcpStream::connect(("127.0.0.1", proxy_port)).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);
    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    assert!(status.success(), "{status:?}");
    let took = exited - signalled;
    assert!(
        took < Duration::from_secs(8),
        "a stalled handshake held the shutdown for {took:?} of a 20 s timeout"
    );
}

/// A client that connects and goes away (a TCP health check) leaves nothing
/// to wait for: the shutdown is as quick as on an idle proxy.
#[test]
fn an_abandoned_tls_connection_does_not_delay_the_shutdown() {
    let backend = slow_backend(Duration::ZERO);
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let mut proxy = Proxy::start(
        &write_tls_config(dir.path(), proxy_port, backend, 20),
        proxy_port,
    );

    drop(TcpStream::connect(("127.0.0.1", proxy_port)).unwrap());
    std::thread::sleep(Duration::from_millis(300));
    let signalled = Instant::now();
    proxy.signal(libc::SIGTERM);
    let (status, exited) = proxy.wait_exit(Duration::from_secs(15));
    assert!(status.success(), "{status:?}");
    assert!(
        exited - signalled < Duration::from_secs(2),
        "an abandoned connection delayed the shutdown by {:?}",
        exited - signalled
    );
}

/// No grace window: a second SIGTERM 0.2 s after the first (what a unit with
/// both `ExecStop=kill -TERM` and `KillSignal` produces) also forces the exit.
#[test]
fn two_sigterms_0_2_s_apart_force_the_exit() {
    second_signal_forces_exit(libc::SIGTERM, libc::SIGTERM, Duration::from_millis(200));
}

/// A proxy started with `-d`: the launcher forks and exits, the daemon is
/// found through its pid file, and its output goes to a file.
struct DaemonProxy {
    pid_file: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl DaemonProxy {
    fn start(dir: &Path, proxy_port: u16, backend: u16, timeout_secs: u64) -> Self {
        let pid_file = dir.join("zentinel.pid");
        let config = write_config(dir, proxy_port, backend, timeout_secs);
        let text = std::fs::read_to_string(&config).unwrap().replacen(
            "worker-threads 1",
            &format!("worker-threads 1\n    pid-file \"{}\"", pid_file.display()),
            1,
        );
        std::fs::write(&config, text).unwrap();
        let log = dir.join("daemon.log");
        let out = std::fs::File::create(&log).unwrap();
        let mut launcher = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-d")
            .arg("-c")
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap();
        let daemon = Self { pid_file, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while launcher.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "the launcher never exited");
            std::thread::sleep(Duration::from_millis(50));
        }
        while !(daemon.pid().is_some_and(alive)
            && TcpStream::connect(("127.0.0.1", proxy_port)).is_ok())
        {
            assert!(
                Instant::now() < deadline,
                "the daemon never listened; log:\n{}",
                daemon.output()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        daemon
    }

    fn pid(&self) -> Option<libc::pid_t> {
        std::fs::read_to_string(&self.pid_file)
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: plain kill(2) on the daemon's pid.
        assert_eq!(unsafe { libc::kill(self.pid().unwrap(), sig) }, 0);
    }

    fn wait_gone(&self, within: Duration) -> Instant {
        let pid = self.pid().unwrap();
        let deadline = Instant::now() + within;
        while alive(pid) {
            assert!(
                Instant::now() < deadline,
                "the daemon was still running {within:?} after the signal; log:\n{}",
                self.output()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Instant::now()
    }
}

impl Drop for DaemonProxy {
    fn drop(&mut self) {
        if let Some(pid) = self.pid() {
            // SAFETY: plain kill(2) on the daemon's pid.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// A daemon drains like a proxy in the foreground (#573).
#[test]
fn a_daemon_lets_the_request_in_flight_finish() {
    let backend = slow_backend(Duration::from_secs(2));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let daemon = DaemonProxy::start(dir.path(), proxy_port, backend, 20);

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(700));
    let signalled = Instant::now();
    daemon.signal(libc::SIGTERM);
    let gone = daemon.wait_gone(Duration::from_secs(15));
    assert_eq!(
        response.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some((200, "ok".to_string())),
        "the request in flight was cut off; log:\n{}",
        daemon.output()
    );
    assert!(
        gone - signalled >= Duration::from_millis(1200),
        "the daemon left {:?} after the signal, before the request was done",
        gone - signalled
    );
    assert!(daemon.output().contains("All connections drained"));
}

#[test]
fn a_second_sigterm_ends_a_draining_daemon_at_once() {
    let backend = slow_backend(Duration::from_secs(30));
    let proxy_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let daemon = DaemonProxy::start(dir.path(), proxy_port, backend, 20);

    let response = request_in_background(proxy_port);
    std::thread::sleep(Duration::from_millis(500));
    daemon.signal(libc::SIGTERM);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        daemon.pid().is_some_and(alive),
        "the first signal ended the daemon; log:\n{}",
        daemon.output()
    );

    let signalled = Instant::now();
    daemon.signal(libc::SIGTERM);
    let gone = daemon.wait_gone(Duration::from_secs(10));
    assert!(gone - signalled < Duration::from_secs(3));
    assert_eq!(response.recv_timeout(Duration::from_secs(5)).unwrap(), None);
    let log = daemon.output();
    assert!(log.contains("while draining, exiting at once"), "{log}");
    assert!(log.contains("open_connections"), "{log}");
}
