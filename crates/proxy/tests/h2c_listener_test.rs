//! `protocol "h2c"` on a listener (#614): HTTP/2 over cleartext TCP with
//! prior knowledge, and nothing else.
//!
//! Runs the real binary with an h2c listener and a plain `http` listener in
//! front of one HTTP/1.1 backend. A prior-knowledge HTTP/2 client (the `h2`
//! crate) is served on the h2c listener; an HTTP/1.1 client there gets a 505
//! instead of being served. The `http` listener is unaffected: it keeps
//! serving HTTP/1.1 and does not start accepting HTTP/2.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An HTTP/1.1 backend answering 200 `ok` to every request.
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
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
            });
        }
    });
}

/// GET / over HTTP/1.1: the status line's code and the body.
fn http1_get(port: u16) -> (Option<u16>, String) {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
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

/// GET / with HTTP/2 prior knowledge: the status and body, or the error.
fn h2c_get(port: u16) -> Result<(u16, String), String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let attempt = async {
                let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let (client, connection) = h2::client::handshake(tcp)
                    .await
                    .map_err(|e| format!("handshake: {e}"))?;
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let mut client = client.ready().await.map_err(|e| format!("ready: {e}"))?;
                let request = http::Request::builder()
                    .uri(format!("http://127.0.0.1:{port}/"))
                    .body(())
                    .unwrap();
                let (response, _) = client
                    .send_request(request, true)
                    .map_err(|e| format!("send: {e}"))?;
                let response = response.await.map_err(|e| format!("response: {e}"))?;
                let status = response.status().as_u16();
                let mut body = response.into_body();
                let mut bytes = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.map_err(|e| format!("body: {e}"))?;
                    let _ = body.flow_control().release_capacity(chunk.len());
                    bytes.extend_from_slice(&chunk);
                }
                Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
            };
            tokio::time::timeout(Duration::from_secs(10), attempt)
                .await
                .unwrap_or_else(|_| Err("timed out".to_string()))
        })
}

struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Proxy {
    h2c: u16,
    http: u16,
    _child: KillOnDrop,
    _dir: tempfile::TempDir,
}

fn start_proxy() -> Proxy {
    start_proxy_with("")
}

/// `extra` is appended to the config as top-level nodes.
fn start_proxy_with(extra: &str) -> Proxy {
    let backend_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = backend_listener.local_addr().unwrap().port();
    http1_backend(backend_listener);
    let (h2c, http) = (free_port(), free_port());

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "internal" {{
        address "127.0.0.1:{h2c}"
        protocol "h2c"
    }}
    listener "plain" {{
        address "127.0.0.1:{http}"
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
{extra}
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
    for port in [h2c, http] {
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "the proxy never started listening on {port}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Proxy {
        h2c,
        http,
        _child: child,
        _dir: dir,
    }
}

#[test]
fn an_h2c_listener_serves_http2_with_prior_knowledge() {
    let proxy = start_proxy();
    for _ in 0..3 {
        assert_eq!(h2c_get(proxy.h2c), Ok((200, "ok".to_string())));
    }
}

/// No fallback: an HTTP/1.1 client is told the listener speaks h2c only,
/// rather than served.
#[test]
fn an_h2c_listener_refuses_http1_with_a_505() {
    let proxy = start_proxy();
    let (status, body) = http1_get(proxy.h2c);
    assert_eq!(status, Some(505), "{body}");
    assert!(body.contains("h2c"), "{body}");
}

/// The h2c listener's service is separate, so the `http` listener is as
/// before: HTTP/1.1 is served, HTTP/2 with prior knowledge is not.
#[test]
fn a_plain_http_listener_beside_it_is_unchanged() {
    let proxy = start_proxy();
    assert_eq!(http1_get(proxy.http), (Some(200), "ok".to_string()));
    assert!(
        h2c_get(proxy.http).is_err(),
        "the http listener accepted HTTP/2 with prior knowledge"
    );
}

/// The h2c listener has an app of its own, but its connections count against
/// the same limits as every other listener's.
#[test]
fn h2c_connections_count_against_the_shared_connection_limit() {
    let proxy = start_proxy_with("limits { max-total-connections 1 }");

    // The startup probes may still hold the slot for a moment.
    let deadline = Instant::now() + Duration::from_secs(10);
    while http1_get(proxy.http).0 != Some(200) {
        assert!(Instant::now() < deadline, "the http listener never served");
        std::thread::sleep(Duration::from_millis(100));
    }

    // One established HTTP/2 connection on the h2c listener takes the only
    // slot, and keeps it until told to close.
    let held = hold_h2c_connection(proxy.h2c);
    assert_eq!(
        http1_get(proxy.http).0,
        None,
        "the http listener admitted a second connection past max-total-connections 1"
    );

    drop(held);
    let deadline = Instant::now() + Duration::from_secs(10);
    while http1_get(proxy.http).0 != Some(200) {
        assert!(Instant::now() < deadline, "the slot was never given back");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// An HTTP/2 connection to `port` with its handshake done, kept open until
/// the returned sender is dropped.
fn hold_h2c_connection(port: u16) -> std::sync::mpsc::Sender<()> {
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .unwrap();
                let (client, connection) = h2::client::handshake(tcp).await.unwrap();
                let driver = tokio::spawn(connection);
                // The server's SETTINGS have arrived once the client is ready.
                let _client = client.ready().await.unwrap();
                ready_tx.send(()).unwrap();
                let _ = tokio::task::spawn_blocking(move || released.recv()).await;
                driver.abort();
            });
    });
    ready
        .recv_timeout(Duration::from_secs(10))
        .expect("the h2c connection was established");
    release
}
