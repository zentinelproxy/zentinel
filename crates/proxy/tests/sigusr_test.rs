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

fn free_port(range: std::ops::Range<u16>) -> u16 {
    range
        .into_iter()
        .find(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok())
        .expect("a free port")
}

fn backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind backend");
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
    fn start(config: &Path, port: u16) -> Self {
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
        proxy.wait_for("Zentinel proxy started successfully");
        // The line is logged before the listeners are bound.
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        proxy
    }

    /// Read the proxy's output until a line contains `needle`.
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

#[test]
fn sigusr1_reopens_the_logs_and_sigusr2_is_ignored() {
    let backend_port = free_port(19960..19970);
    backend(backend_port);
    let proxy_port = free_port(19970..19980);

    let dir = tempfile::tempdir().unwrap();
    let access = dir.path().join("access.log");
    let rotated = dir.path().join("access.log.1");
    let config = dir.path().join("zentinel.kdl");
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
            file "{}"
            format "json"
            buffer-size 1
        }}
    }}
}}
"#,
            access.display()
        ),
    )
    .unwrap();

    let mut proxy = Proxy::start(&config, proxy_port);

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
