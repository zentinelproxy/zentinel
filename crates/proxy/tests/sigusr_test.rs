//! SIGUSR1 reopens the log files; SIGUSR2 is ignored. Neither ends the process.
//!
//! Both signals terminate a process by default, and nothing handled them, so
//! the `kill -USR1` of a logrotate `postrotate` script stopped the proxy.
//!
//! Runs the real binary: a request is logged, the log is moved away the way
//! logrotate does, SIGUSR1 is sent, and the next request must land in a new
//! file at the original path.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A port the kernel just handed out for 127.0.0.1. It is released before the
/// proxy binds it, so `start_proxy` retries when someone else takes it first.
fn ephemeral_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind an ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

/// Start a backend on a port of its own choosing and return that port. The
/// listener is never released, so this cannot race.
fn backend() -> u16 {
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
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
    port
}

fn get(proxy: u16, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.split_whitespace().nth(1)?.parse().ok()
}

struct Proxy {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Proxy {
    fn try_start(config: &Path, port: u16) -> Result<Self, String> {
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
        let mut proxy = Self {
            child,
            lines,
            log: Vec::new(),
        };
        proxy.try_wait_for("Zentinel proxy started successfully")?;
        // The line is logged before the listeners are bound.
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            if let Some(status) = proxy.child.try_wait().unwrap() {
                return Err(format!(
                    "the proxy exited ({status:?}) before it listened; log:\n{}",
                    proxy.drain_log()
                ));
            }
            if Instant::now() > deadline {
                return Err("the proxy never listened".to_string());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(proxy)
    }

    fn drain_log(&mut self) -> String {
        while let Ok(line) = self.lines.try_recv() {
            self.log.push(line);
        }
        self.log.join("\n")
    }

    fn wait_for(&mut self, needle: &str) {
        if let Err(message) = self.try_wait_for(needle) {
            panic!("{message}");
        }
    }

    /// Read the proxy's output until a line contains `needle`.
    fn try_wait_for(&mut self, needle: &str) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match self.lines.recv_timeout(Duration::from_millis(100)) {
                Ok(line) => {
                    let found = line.contains(needle);
                    self.log.push(line);
                    if found {
                        return Ok(());
                    }
                }
                Err(_) => {
                    if let Some(status) = self.child.try_wait().unwrap() {
                        return Err(format!(
                            "the proxy exited ({status:?}) before {needle:?}; log:\n{}",
                            self.drain_log()
                        ));
                    }
                }
            }
        }
        Err(format!("never saw {needle:?}; log:\n{}", self.drain_log()))
    }

    fn signal(&self, sig: libc::c_int) {
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, sig) },
            0
        );
    }

    fn assert_alive(&mut self, after: &str) {
        let status = self.child.try_wait().unwrap();
        assert!(
            status.is_none(),
            "the proxy exited ({status:?}) after {after}; log:\n{}",
            self.log.join("\n")
        );
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Write the config for a fresh port and start the proxy on it. Another process
/// can take the port between the probe and the bind, so a proxy that dies
/// before it listens is tried again on a new port.
fn start_proxy(dir: &Path, backend_port: u16, access: &Path) -> (Proxy, u16) {
    let config = dir.join("zentinel.kdl");
    let mut last = String::new();
    for _ in 0..5 {
        let proxy_port = ephemeral_port();
        std::fs::write(
            &config,
            format!(
                r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{proxy_port}"
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
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
    logging {{
        access-log {{
            enabled #true
            file "{access}"
            format "json"
            buffer-size 1
        }}
        // The default error log is under /var/log/zentinel, which the test
        // cannot rely on being writable; one log that fails to open leaves
        // the manager without any log (#574).
        error-log {{
            enabled #true
            file "{error}"
        }}
    }}
}}
"#,
                access = access.display(),
                error = dir.join("error.log").display(),
            ),
        )
        .unwrap();
        match Proxy::try_start(&config, proxy_port) {
            Ok(proxy) => return (proxy, proxy_port),
            Err(message) => last = message,
        }
    }
    panic!("the proxy would not start on 5 ports; last attempt:\n{last}");
}

#[test]
fn sigusr1_reopens_the_logs_and_sigusr2_is_ignored() {
    let backend_port = backend();

    let dir = tempfile::tempdir().unwrap();
    let access = dir.path().join("access.log");
    let rotated = dir.path().join("access.log.1");

    let (mut proxy, proxy_port) = start_proxy(dir.path(), backend_port, &access);

    assert_eq!(get(proxy_port, "/before"), Some(200));
    std::fs::rename(&access, &rotated).unwrap();

    proxy.signal(libc::SIGUSR2);
    proxy.wait_for("Received SIGUSR2");
    proxy.assert_alive("SIGUSR2");

    proxy.signal(libc::SIGUSR1);
    proxy.wait_for("Log files reopened");
    proxy.assert_alive("SIGUSR1");

    assert_eq!(get(proxy_port, "/after"), Some(200));
    // A proxy with `buffer-size 1` writes through, but give it a moment.
    let deadline = Instant::now() + Duration::from_secs(5);
    let new = loop {
        let new = std::fs::read_to_string(&access).unwrap_or_default();
        if new.contains("/after") || Instant::now() > deadline {
            break new;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let old = std::fs::read_to_string(&rotated).unwrap();
    assert!(old.contains("/before") && !old.contains("/after"), "{old}");
    assert!(new.contains("/after") && !new.contains("/before"), "{new}");
}
