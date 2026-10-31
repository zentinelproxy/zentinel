//! `h2c #true` on an upstream (#614): HTTP/2 over cleartext TCP with prior
//! knowledge.
//!
//! Runs the real binary against a real HTTP/2 server (the `h2` crate) on a
//! plain socket. Before, a plain upstream was always spoken to over HTTP/1.1,
//! whatever its `http-version` said. The backend answers with the HTTP
//! version it saw, so the test reads the protocol from the response body.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A port nothing listens on yet.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An HTTP/2-only backend that answers every request, after `delay`, with
/// 200 and the request's HTTP version as the body. Returns the number of TCP
/// connections it has accepted.
fn h2c_backend(listener: TcpListener, delay: Duration) -> Arc<AtomicUsize> {
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        continue;
                    };
                    counted.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let Ok(mut connection) = h2::server::handshake(socket).await else {
                            return;
                        };
                        while let Some(Ok((request, mut respond))) = connection.accept().await {
                            tokio::spawn(async move {
                                tokio::time::sleep(delay).await;
                                let version = format!("{:?}", request.version());
                                let response = http::Response::builder()
                                    .status(200)
                                    .header("content-length", version.len())
                                    .body(())
                                    .unwrap();
                                if let Ok(mut body) = respond.send_response(response, false) {
                                    let _ = body.send_data(bytes::Bytes::from(version), true);
                                }
                            });
                        }
                    });
                }
            });
    });
    connections
}

/// An HTTP/1.1-only backend answering 200 to every request it can read.
fn http1_backend(listener: TcpListener) {
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
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nHTTP/1.1",
                );
            });
        }
    });
}

/// GET / over HTTP/1.1 through the proxy: the status and the body.
fn get(proxy: u16) -> (Option<u16>, String) {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", proxy)) else {
        return (None, String::new());
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok());
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    (status, body)
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the proxy on `proxy` with one upstream on `backend` whose block body
/// is `upstream_settings`.
fn start_proxy(
    dir: &tempfile::TempDir,
    proxy: u16,
    backend: u16,
    upstream_settings: &str,
) -> KillOnDrop {
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
        target "127.0.0.1:{backend}"
        {upstream_settings}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
        ),
    )
    .unwrap();

    let child = KillOnDrop(
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
    child
}

#[test]
fn an_h2c_upstream_is_spoken_to_over_http2() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = listener.local_addr().unwrap().port();
    h2c_backend(listener, Duration::ZERO);
    let proxy = free_port();
    let dir = tempfile::tempdir().unwrap();
    let _proxy = start_proxy(&dir, proxy, backend, "h2c #true");

    for _ in 0..3 {
        assert_eq!(get(proxy), (Some(200), "HTTP/2.0".to_string()));
    }
}

/// Prior knowledge means no fallback: an h2c upstream that only speaks
/// HTTP/1.1 fails the request instead of being spoken to over HTTP/1.1.
#[test]
fn an_h2c_upstream_never_falls_back_to_http1() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = listener.local_addr().unwrap().port();
    http1_backend(listener);
    let proxy = free_port();
    let dir = tempfile::tempdir().unwrap();
    let _proxy = start_proxy(&dir, proxy, backend, "h2c #true");

    let (status, body) = get(proxy);
    assert_ne!(status, Some(200), "served over HTTP/1.1: {body}");
    assert!(
        status.is_some_and(|s| s >= 500),
        "expected a gateway error, got {status:?}"
    );
}

/// `max-h2-streams` reaches the connection: concurrent requests share one
/// HTTP/2 connection instead of opening one each. It was parsed and never
/// applied, so Pingora's default of one stream per connection held.
#[test]
fn concurrent_requests_share_an_h2c_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = listener.local_addr().unwrap().port();
    let connections = h2c_backend(listener, Duration::from_millis(800));
    let proxy = free_port();
    let dir = tempfile::tempdir().unwrap();
    let _proxy = start_proxy(
        &dir,
        proxy,
        backend,
        "h2c #true\n        http-version { max-h2-streams 100 }",
    );

    // Open the connection first, so the concurrent requests find it pooled.
    assert_eq!(get(proxy), (Some(200), "HTTP/2.0".to_string()));
    assert_eq!(connections.load(Ordering::SeqCst), 1);

    let requests: Vec<_> = (0..8)
        .map(|_| std::thread::spawn(move || get(proxy)))
        .collect();
    for request in requests {
        assert_eq!(request.join().unwrap(), (Some(200), "HTTP/2.0".to_string()));
    }
    let opened = connections.load(Ordering::SeqCst);
    assert!(
        opened <= 3,
        "8 concurrent requests opened {opened} HTTP/2 connections in all"
    );
}
