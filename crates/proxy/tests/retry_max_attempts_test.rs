//! A route's `retry-policy` `max-attempts` bounds how often a request is sent
//! to the upstream, whatever made the proxy try again.
//!
//! `max-attempts` counts the first try. It already limited the retries made on
//! a retryable status code. It also limits the retries made after an error:
//! an upstream that accepts a request and drops the connection without
//! answering, and a target name whose first address refuses the connection.
//! A route without a `retry-policy` has no limit of its own, and the limit of
//! the underlying server (16 attempts) applies.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often the underlying server tries a request in all, whatever the
/// route says.
const SERVER_ATTEMPT_LIMIT: usize = 16;

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

/// What a backend does with the requests it reads.
#[derive(Clone, Copy)]
enum Mode {
    /// Close the connection of every request without answering.
    DropEveryRequest,
    /// Answer every request with a 200.
    Answer,
    /// Answer the first request of a connection with a 200 and keep the
    /// connection open. Close it without answering when a second request
    /// arrives on it, as an upstream does with a connection it timed out.
    DropSecondRequestOfConnection,
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

/// Serves `listener` as `mode` says.
fn serve(listener: TcpListener, mode: Mode) -> Backend {
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
                    let drop_it = match mode {
                        Mode::DropEveryRequest => true,
                        Mode::Answer => false,
                        Mode::DropSecondRequestOfConnection => requests_on_connection > 0,
                    };
                    if drop_it {
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

fn spawn_backend(mode: Mode) -> Backend {
    serve(TcpListener::bind(("127.0.0.1", 0)).unwrap(), mode)
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

fn config(port: u16, metrics_port: u16, target: &str, retry_policy: &str) -> String {
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
        target "{target}"
        // The breaker must not open before max-attempts stops the retries.
        circuit-breaker {{
            failure-threshold 1000
            success-threshold 1
            timeout-seconds 300
        }}
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

fn start_proxy(dir: &Path, target: &str, retry_policy: &str) -> Proxy {
    let (port, metrics_port) = (free_port(), free_port());
    Proxy::start(
        dir,
        port,
        metrics_port,
        &config(port, metrics_port, target, retry_policy),
    )
}

/// A `retry-policy` with `max_attempts` and a short backoff.
fn retry_policy(max_attempts: u32, extra: &str) -> String {
    format!(
        r#"retry-policy {{
            max-attempts {max_attempts}
            backoff "1ms"
            max-backoff "1ms"
            {extra}
        }}"#
    )
}

/// The upstream accepts the request and drops the connection without
/// answering. The proxy sends the request again until the route's
/// `max-attempts` is used up, and then answers with the error.
fn assert_sent_exactly(method: &str, max_attempts: u32, extra: &str) {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Mode::DropEveryRequest);
    let proxy = start_proxy(
        dir.path(),
        &format!("127.0.0.1:{}", backend.port),
        &retry_policy(max_attempts, extra),
    );

    let status = send(proxy.port, method, 6);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        max_attempts as usize,
        "{method} with max-attempts {max_attempts} was not sent exactly that many times; log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    proxy.wait_for_log("Not retrying a request that may have been sent to the upstream");
    assert_eq!(proxy.retries_refused("max_attempts"), 1);
}

#[test]
fn a_get_is_sent_max_attempts_times_after_the_upstream_dropped_the_connection() {
    assert_sent_exactly("GET", 3, "");
}

#[test]
fn a_put_is_sent_max_attempts_times_after_the_upstream_dropped_the_connection() {
    assert_sent_exactly("PUT", 2, "");
}

#[test]
fn max_attempts_of_one_sends_the_request_once() {
    assert_sent_exactly("GET", 1, "");
}

#[test]
fn a_post_that_the_route_allows_to_be_sent_again_is_sent_max_attempts_times() {
    assert_sent_exactly("POST", 3, "retry-non-idempotent #true");
}

/// Without a `retry-policy` nothing in the route bounds the attempts, so the
/// limit of the underlying server applies.
#[test]
fn a_route_without_a_retry_policy_is_not_bounded_by_max_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let backend = spawn_backend(Mode::DropEveryRequest);
    let proxy = start_proxy(dir.path(), &format!("127.0.0.1:{}", backend.port), "");

    let status = send(proxy.port, "GET", 0);

    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        SERVER_ATTEMPT_LIMIT,
        "log:\n{}",
        proxy.log()
    );
    assert_eq!(status, 502, "log:\n{}", proxy.log());
    assert_eq!(proxy.retries_refused("max_attempts"), 0);
}

/// A backend listening on 127.0.0.1 only, and `target "localhost:<port>"`.
/// Where `localhost` resolves to `::1` first, the first attempt dials an
/// address that refuses the connection, and a second attempt reaches the
/// backend. Returns the answer's status, the number of requests the backend
/// received and the proxy, or `None` where `localhost` has no dead first
/// address to try.
fn request_to_localhost_target(dir: &Path, max_attempts: u32) -> Option<(u16, usize, Proxy)> {
    // A port with a listener on 127.0.0.1 and nothing on ::1.
    let listener = (0..20).find_map(|_| {
        let listener = TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = listener.local_addr().ok()?.port();
        TcpStream::connect_timeout(
            &SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port)),
            Duration::from_millis(50),
        )
        .is_err()
        .then_some(listener)
    })?;
    let port = listener.local_addr().unwrap().port();
    let resolved: Vec<SocketAddr> = ("localhost", port)
        .to_socket_addrs()
        .map(Iterator::collect)
        .unwrap_or_default();
    if resolved.first().is_none_or(SocketAddr::is_ipv4) {
        eprintln!(
            "note: localhost resolves to {resolved:?} here; the dead-first-address case is not exercised"
        );
        return None;
    }
    let backend = serve(listener, Mode::Answer);
    let proxy = start_proxy(
        dir,
        &format!("localhost:{port}"),
        &retry_policy(max_attempts, ""),
    );
    let status = send(proxy.port, "GET", 0);
    Some((status, backend.received.load(Ordering::SeqCst), proxy))
}

/// Trying the next address of a target name is another attempt at the
/// request, so a `max-attempts` of 1 leaves it out.
#[test]
fn another_address_of_a_target_name_counts_as_an_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let Some((status, received, proxy)) = request_to_localhost_target(dir.path(), 1) else {
        return;
    };
    assert_ne!(
        status,
        200,
        "the request was sent to a second address although max-attempts is 1; log:\n{}",
        proxy.log()
    );
    assert_eq!(received, 0);
    proxy.wait_for_log("Not retrying on another address of the target");
    assert_eq!(proxy.retries_refused("max_attempts"), 1);
}

#[test]
fn another_address_of_a_target_name_is_tried_while_attempts_remain() {
    let dir = tempfile::tempdir().unwrap();
    let Some((status, received, proxy)) = request_to_localhost_target(dir.path(), 2) else {
        return;
    };
    assert_eq!(status, 200, "log:\n{}", proxy.log());
    assert_eq!(received, 1);
    assert_eq!(proxy.retries_refused("max_attempts"), 0);
}

/// The proxy sends a GET on a connection it kept for reuse, which the upstream
/// closed while it was idle, and finds out. Returns the status of the GET that
/// ran into it, how many requests were sent by then, and the proxy.
fn get_on_a_reused_connection_the_upstream_closed(
    dir: &Path,
    max_attempts: u32,
) -> (u16, usize, Backend, Proxy) {
    let backend = spawn_backend(Mode::DropSecondRequestOfConnection);
    let proxy = start_proxy(
        dir,
        &format!("127.0.0.1:{}", backend.port),
        &retry_policy(max_attempts, ""),
    );
    // The first request opens a connection and the upstream answers it; a
    // later one is sent on that connection, which the upstream then drops.
    for sent in 1..=20 {
        let dropped_before = backend.dropped.load(Ordering::SeqCst);
        let status = send(proxy.port, "GET", 0);
        if backend.dropped.load(Ordering::SeqCst) > dropped_before {
            return (status, sent, backend, proxy);
        }
        assert_eq!(status, 200, "log:\n{}", proxy.log());
    }
    panic!("no request was ever sent on a reused connection");
}

/// `max-attempts 1` asks for no retry, and that includes the one a request
/// gets when a connection kept for reuse turns out to be closed.
#[test]
fn max_attempts_of_one_does_not_retry_on_a_reused_connection_the_upstream_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (status, sent, backend, proxy) =
        get_on_a_reused_connection_the_upstream_closed(dir.path(), 1);

    assert_eq!(
        status,
        502,
        "a GET dropped on a reused connection was sent again; log:\n{}",
        proxy.log()
    );
    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        sent,
        "a GET dropped on a reused connection was sent again; log:\n{}",
        proxy.log()
    );
    proxy.wait_for_log("Not retrying a request that may have been sent to the upstream");
    assert_eq!(proxy.retries_refused("max_attempts"), 1);
}

#[test]
fn max_attempts_of_two_retries_on_a_reused_connection_the_upstream_closed() {
    let dir = tempfile::tempdir().unwrap();
    let (status, sent, backend, proxy) =
        get_on_a_reused_connection_the_upstream_closed(dir.path(), 2);

    assert_eq!(status, 200, "log:\n{}", proxy.log());
    assert_eq!(
        backend.received.load(Ordering::SeqCst),
        sent + 1,
        "log:\n{}",
        proxy.log()
    );
    assert_eq!(proxy.retries_refused("max_attempts"), 0);
}
