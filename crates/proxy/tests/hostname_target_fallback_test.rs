//! A hostname target without a health check must not be stuck on a dead
//! first address (#554).
//!
//! `localhost` resolves to `::1` first on many systems. With a backend that
//! only listens on `127.0.0.1` and `target "localhost:<port>"`, every request
//! used to dial `[::1]` and fail with 503. The proxy now passes over an
//! address that refused the connection and retries on the name's next one.
//!
//! Runs the real binary against a real IPv4-only socket. Where `localhost`
//! resolves to IPv4 only there is no dead address and the test passes
//! trivially; it says so on stderr.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A port from a small fixed range with nothing on either loopback address.
fn free_port(range: std::ops::Range<u16>, skip: u16) -> u16 {
    range
        .filter(|&port| port != skip)
        .find(|&port| {
            TcpListener::bind(("127.0.0.1", port)).is_ok()
                && TcpStream::connect_timeout(
                    &SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
                    Duration::from_millis(50),
                )
                .is_err()
        })
        .expect("a free port")
}

/// An HTTP backend on 127.0.0.1 only, answering 200 to everything.
fn ipv4_only_backend(port: u16) {
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

fn status_of_get(proxy: u16) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.split_whitespace().nth(1)?.parse().ok()
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn localhost_target_reaches_an_ipv4_only_backend_without_a_health_check() {
    let backend = free_port(19524..19530, 0);
    ipv4_only_backend(backend);
    let proxy = free_port(19530..19536, backend);

    let resolved: Vec<SocketAddr> = ("localhost", backend)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    if resolved.first().is_none_or(SocketAddr::is_ipv4) {
        eprintln!(
            "note: localhost resolves to {resolved:?} here; the dead-first-address case is not exercised"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
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
        target "localhost:{backend}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
        ),
    )
    .unwrap();

    let _child = KillOnDrop(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", proxy)).is_err() {
        assert!(
            Instant::now() < deadline,
            "the proxy never started listening"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let statuses: Vec<Option<u16>> = (0..10).map(|_| status_of_get(proxy)).collect();
    assert!(
        statuses.iter().all(|s| *s == Some(200)),
        "requests to `localhost:{backend}` failed (localhost -> {resolved:?}): {statuses:?}"
    );
}
