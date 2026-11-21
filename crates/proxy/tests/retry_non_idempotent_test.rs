//! A request whose method is not idempotent is not sent to the upstream a
//! second time after an error that happened once it may have been sent.
//!
//! When the upstream accepts a request and then drops the connection without
//! answering, the proxy cannot tell whether the upstream acted on it. A `GET`
//! may be sent again. A `POST` may be sent again only on a route whose
//! `retry-policy` says `retry-non-idempotent`. A request whose body was larger
//! than the proxy's retry buffer cannot be sent again whatever its method,
//! because the body cannot be replayed.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Larger than the 64 KiB retry buffer the proxy uses by default.
const LARGE_BODY_BYTES: usize = 128 * 1024;

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend that counts the requests it is sent.
struct Backend {
    port: u16,
    /// Requests whose header it has read.
    received: Arc<AtomicUsize>,
    /// Requests it closed the connection of without answering.
    dropped: Arc<AtomicUsize>,
}

/// Reads the header of a request and returns the length of its body.
fn read_head(reader: &mut BufReader<TcpStream>) -> Option<usize> {
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return None;
    }
    let mut content_length = 0usize;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return None;
        }
        if line == "\r\n" {
            return Some(content_length);
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
}

/// With `drop_every_request` the backend closes the connection of every
/// request without answering. Without it, it answers the first request of a
/// connection with a 200 and keeps the connection open, and closes it without
/// answering when a second request arrives on it, as an upstream does with a
/// connection it timed out.
fn spawn_backend(drop_every_request: bool) -> Backend {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let (received_counter, dropped_counter) = (received.clone(), dropped.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (received_counter, dropped_counter) =
                (received_counter.clone(), dropped_counter.clone());
            std::thread::spawn(move || {
                // A request that arrives without its whole body must not
                // hold this thread for long.
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut answered = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut requests_on_connection = 0;
                while let Some(content_length) = read_head(&mut reader) {
                    received_counter.fetch_add(1, Ordering::SeqCst);
                    let mut body = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body);
                    if drop_every_request || requests_on_connection > 0 {
                        dropped_counter.fetch_add(1, Ordering::SeqCst);
                        // Dropped on return: the connection closes with no
                        // response.
                        return;
                    }
                    requests_on_connection += 1;
                    let _ = answered.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                }
            });
        }
    });
    Backend {
        port,
        received,
        dropped,
    }
}

struct Proxy {
    child: Child,
    port: u16,
    metrics_port: u16,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, port: u16, metrics_port: u16, config: &str) -> Proxy {
        let path = dir.join("zentinel.kdl");
        std::fs::write(&path, config).unwrap();
        let log = dir.join("zentinel.log");
        let log_file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::from(log_file.try_clone().unwrap()))
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap();
        let proxy = Proxy {
            child,
            port,
            metrics_port,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err()
            || TcpStream::connect(("127.0.0.1", metrics_port)).is_err()
        {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
        proxy
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits for `text` to appear in the log; the log is written by another
    /// process, so it may trail the answer the client got.
    fn wait_for_log(&self, text: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self.log().contains(text) {
            assert!(
                Instant::now() < deadline,
                "the log never said {text:?}; log:\n{}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The value of `zentinel_upstream_retries_refused_total` for `reason`, 0
    /// if there is no such series.
    fn retries_refused(&self, reason: &str) -> u64 {
        let mut stream = TcpStream::connect(("127.0.0.1", self.metrics_port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        write!(
            stream,
            "GET /metrics HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        let series = format!("zentinel_upstream_retries_refused_total{{reason=\"{reason}\"}}");
        String::from_utf8_lossy(&raw)
            .lines()
            .find_map(|line| line.strip_prefix(series.as_str()))
            .and_then(|value| value.trim().parse::<f64>().ok())
            .map_or(0, |value| value as u64)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Sends one request with a body of `body_len` bytes and returns the status
/// of the answer, 0 if there was none.
fn send(port: u16, method: &str, body_len: usize) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let head = format!(
        "{method} /item HTTP/1.1\r\nHost: a.example\r\nContent-Length: {body_len}\r\n\
         Connection: close\r\n\r\n"
    );
    // The proxy may answer before the whole body is written; that is not
    // what these tests look at.
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&vec![b'a'; body_len]);
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    String::from_utf8_lossy(&raw)
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn config(port: u16, metrics_port: u16, backend: u16, retry_policy: &str) -> String {
    format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        {retry_policy}
    }}
}}
observability {{
    metrics {{
        enabled #true
        address "127.0.0.1:{metrics_port}"
        path "/metrics"
    }}
}}
"#
    )
}

fn start_proxy(dir: &Path, backend: &Backend, retry_policy: &str) -> Proxy {
    let (port, metrics_port) = (free_port(), free_port());
    Proxy::start(
        dir,
        port,
        metrics_port,
        &config(port, metrics_port, backend.port, retry_policy),
    )
}

/// A `retry-policy` with a short backoff. `max-attempts` is left out, so its
/// default of 3 applies.
fn retry_policy(retry_non_idempotent: &str) -> String {
    format!(
        r#"retry-policy {{
            backoff "1ms"
            max-backoff "1ms"
            {retry_non_idempotent}
        }}"#
    )
}

#[test]
fn a_post_is_not_sent_again_after_the_upstream_dropped_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(dir.path(), &backend, "");

    let status = send(proxy.port, "POST", 6);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        1,
        "a POST the upstream had received was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    proxy.wait_for_log("non_idempotent_method");
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 1);
}

#[test]
fn a_get_is_sent_again_after_the_upstream_dropped_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(dir.path(), &backend, "");

    let status = send(proxy.port, "GET", 0);

    let received = backend.received.load(Ordering::SeqCst);
    assert!(
        received >= 2,
        "a GET the upstream had received was not sent again (received {received}); log:\n{}",
        proxy.log()
    );
    assert!(
        (500..600).contains(&status),
        "status {status}; log:\n{}",
        proxy.log()
    );
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
}

#[test]
fn a_query_request_is_not_sent_again_after_the_upstream_dropped_the_connection() {
    // QUERY is not an idempotent method of RFC 9110.
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(dir.path(), &backend, "");

    let status = send(proxy.port, "QUERY", 6);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        1,
        "a QUERY the upstream had received was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
}

#[test]
fn a_post_is_sent_again_on_a_route_that_allows_it() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(
        dir.path(),
        &backend,
        &retry_policy("retry-non-idempotent #true"),
    );

    let status = send(proxy.port, "POST", 6);

    let received = backend.received.load(Ordering::SeqCst);
    assert!(
        received >= 2,
        "a POST was not sent again although the route allows it (received {received}); log:\n{}",
        proxy.log()
    );
    assert!(
        (500..600).contains(&status),
        "status {status}; log:\n{}",
        proxy.log()
    );
    assert_eq!(proxy.retries_refused("non_idempotent_method"), 0);
}

#[test]
fn a_post_is_not_sent_again_on_a_route_whose_retry_policy_does_not_allow_it() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(dir.path(), &backend, &retry_policy(""));

    let status = send(proxy.port, "POST", 6);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        1,
        "a POST the upstream had received was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
}

/// The usual case: the upstream closed a connection the proxy kept for reuse,
/// and the proxy finds out when it sends a request on it.
#[test]
fn a_post_on_a_reused_connection_that_the_upstream_dropped_is_not_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(false);
    let proxy = start_proxy(dir.path(), &backend, "");

    // The first request opens a connection and the upstream answers it; a
    // later one is sent on that connection, which the upstream then drops.
    for sent in 1..=20 {
        let dropped_before = backend.dropped.load(Ordering::SeqCst);
        let status = send(proxy.port, "POST", 6);
        if backend.dropped.load(Ordering::SeqCst) > dropped_before {
            assert_eq!(
                status,
                502,
                "a POST dropped on a reused connection was sent again; log:\n{}",
                proxy.log()
            );
            assert_eq!(
                backend.received.load(Ordering::SeqCst),
                sent,
                "a POST dropped on a reused connection was sent again; log:\n{}",
                proxy.log()
            );
            return;
        }
        assert_eq!(status, 200, "log:\n{}", proxy.log());
    }
    panic!("no request was ever sent on a reused connection");
}

#[test]
fn a_put_whose_body_exceeded_the_retry_buffer_is_not_sent_again() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(true);
    let proxy = start_proxy(dir.path(), &backend, "");

    let status = send(proxy.port, "PUT", LARGE_BODY_BYTES);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        1,
        "a request whose body could not be replayed was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    proxy.wait_for_log("retry_buffer_truncated");
    assert_eq!(proxy.retries_refused("retry_buffer_truncated"), 1);
}
