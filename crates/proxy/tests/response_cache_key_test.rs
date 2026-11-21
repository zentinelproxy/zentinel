//! The response cache key, end to end against the real binary.
//!
//! A cached response must only be returned for a request that the same route
//! would answer the same way: the key covers the route, the host, the path and
//! the query. The upstreams here are plain listeners on `127.0.0.1` that count
//! the requests they receive, so a cache hit shows up as a request that never
//! reached them.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A request as the upstream received it: method and `Host` header.
type Seen = Arc<Mutex<Vec<(String, String)>>>;

/// An upstream that answers every request with `"<name> <host> #<n>"`, where
/// `n` counts the requests it has received, and a `max-age` the proxy honors.
struct Backend {
    port: u16,
    seen: Seen,
}

impl Backend {
    fn start(name: &'static str) -> Backend {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Seen = Arc::default();
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let recorded = Arc::clone(&recorded);
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        return;
                    }
                    let method = request_line
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_string();
                    let mut host = String::new();
                    let mut line = String::new();
                    while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty()
                    {
                        if let Some((n, v)) = line.split_once(':') {
                            if n.trim().eq_ignore_ascii_case("host") {
                                host = v.trim().to_string();
                            }
                        }
                        line.clear();
                    }
                    let n = {
                        let mut recorded = recorded.lock().unwrap();
                        recorded.push((method.clone(), host.clone()));
                        recorded.len()
                    };
                    let body = format!("{name} {host} #{n}");
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nCache-Control: max-age=60\r\n\
                         Connection: close\r\n\r\n",
                        body.len()
                    );
                    if method != "HEAD" {
                        let _ = stream.write_all(body.as_bytes());
                    }
                });
            }
        });
        Backend { port, seen }
    }

    /// How many requests have reached this upstream.
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    /// The methods this upstream has received, in order.
    fn methods(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(method, _)| method.clone())
            .collect()
    }

    /// The `Host` headers this upstream has received, in order.
    fn hosts(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, host)| host.clone())
            .collect()
    }
}

/// The proxy process, and the directory holding its config (kept alive).
struct Proxy(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

/// Start the proxy with `routes` (KDL for the body of the `routes` block) and
/// `upstreams` (KDL for the body of the `upstreams` block).
fn start(upstreams: &str, routes: &str) -> (u16, Proxy) {
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let config = format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
upstreams {{
{upstreams}
}}
routes {{
{routes}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    );
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config).unwrap();
    let proxy = Proxy(
        Command::new(env!("CARGO_BIN_EXE_zentinel"))
            .arg("-c")
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        dir,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    (port, proxy)
}

/// A route that caches successful responses, sending everything to `upstream`.
fn caching_route(id: &str, extra_match: &str, upstream: &str) -> String {
    format!(
        r#"
    route "{id}" {{
        matches {{
            path-prefix "/"
            {extra_match}
        }}
        upstream "{upstream}"
        cache {{
            enabled #true
            default-ttl-secs 60
        }}
    }}"#
    )
}

fn upstream_block(id: &str, port: u16) -> String {
    format!(
        r#"
    upstream "{id}" {{
        target "127.0.0.1:{port}"
    }}"#
    )
}

/// Send one request; returns the status and the body.
fn request(port: u16, method: &str, host: &str, path: &str, extra: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

fn get(port: u16, host: &str, path: &str) -> (u16, String) {
    request(port, "GET", host, path, "")
}

/// Repeat a request until one is answered without reaching `backend`, that is,
/// from the cache, and return that response's body.
///
/// A response is written to the cache while it streams to the client, so a
/// request sent right after the first one can still be a miss. Asking again
/// until the upstream is no longer reached waits for the entry to be complete
/// without a fixed delay, and gives up after five seconds.
fn until_cached(
    port: u16,
    backend: &Backend,
    method: &str,
    host: &str,
    path: &str,
    extra: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let before = backend.count();
        let (status, body) = request(port, method, host, path, extra);
        assert_eq!(status, 200, "{method} {host}{path}");
        if backend.count() == before {
            return body;
        }
        assert!(
            Instant::now() < deadline,
            "{method} {host}{path} was never served from the cache"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn requests_for_different_hosts_do_not_share_a_cached_response() {
    let backend = Backend::start("up");
    let (port, _proxy) = start(
        &upstream_block("backend", backend.port),
        &caching_route("site", "", "backend"),
    );

    let body_a = until_cached(port, &backend, "GET", "a.example", "/a:b?x=1", "");
    assert!(body_a.starts_with("up a.example #"), "{body_a}");

    // Same path and query, other host: answered by the upstream, not the cache.
    let before = backend.count();
    let (status, body_b) = get(port, "b.example", "/a:b?x=1");
    assert_eq!(status, 200);
    assert!(
        body_b.starts_with("up b.example #"),
        "served the other host's response: {body_b}"
    );
    assert_eq!(backend.count(), before + 1);
    let body_b = until_cached(port, &backend, "GET", "b.example", "/a:b?x=1", "");
    assert!(body_b.starts_with("up b.example #"), "{body_b}");

    // Each host is then served from its own entry.
    let before = backend.count();
    assert_eq!(get(port, "a.example", "/a:b?x=1").1, body_a);
    assert_eq!(get(port, "b.example", "/a:b?x=1").1, body_b);
    assert_eq!(
        backend.count(),
        before,
        "a repeat request reached the upstream"
    );
}

#[test]
fn spellings_of_one_host_share_a_cached_response() {
    let backend = Backend::start("up");
    let (port, _proxy) = start(
        &upstream_block("backend", backend.port),
        &caching_route("site", "", "backend"),
    );

    let first = until_cached(port, &backend, "GET", "example.com", "/page", "");
    assert!(first.starts_with("up example.com #"), "{first}");

    let before = backend.count();
    for host in ["Example.COM", "example.com:8080", "example.com."] {
        let (status, body) = get(port, host, "/page");
        assert_eq!(
            (status, body.as_str()),
            (200, first.as_str()),
            "host {host}"
        );
    }
    assert_eq!(
        backend.count(),
        before,
        "a spelling of the host missed the cache"
    );
    assert!(backend.hosts().iter().all(|host| host == "example.com"));
}

#[test]
fn a_repeat_request_for_the_same_host_is_served_from_the_cache() {
    let backend = Backend::start("up");
    let (port, _proxy) = start(
        &upstream_block("backend", backend.port),
        &caching_route("site", "", "backend"),
    );

    let first = until_cached(port, &backend, "GET", "example.com", "/page", "");
    let before = backend.count();
    let (status, second) = get(port, "example.com", "/page");
    assert_eq!((status, second.as_str()), (200, first.as_str()));
    assert_eq!(backend.count(), before);

    // A different path or query is a different entry.
    get(port, "example.com", "/other");
    get(port, "example.com", "/page?q=1");
    assert_eq!(backend.count(), before + 2);
}

#[test]
fn head_is_answered_from_the_entry_of_get() {
    let backend = Backend::start("up");
    let (port, _proxy) = start(
        &upstream_block("backend", backend.port),
        &caching_route("site", "", "backend"),
    );

    until_cached(port, &backend, "GET", "example.com", "/page", "");

    let before = backend.count();
    let (status, head_body) = request(port, "HEAD", "example.com", "/page", "");
    assert_eq!((status, head_body.as_str()), (200, ""));
    assert_eq!(backend.count(), before, "HEAD did not use the entry of GET");
}

#[test]
fn head_fills_the_entry_that_get_is_answered_from() {
    let backend = Backend::start("up");
    let (port, _proxy) = start(
        &upstream_block("backend", backend.port),
        &caching_route("site", "", "backend"),
    );

    let (status, head_body) = request(port, "HEAD", "example.com", "/page", "");
    assert_eq!((status, head_body.as_str()), (200, ""));
    // Once HEAD is answered from the cache, the entry is complete.
    until_cached(port, &backend, "HEAD", "example.com", "/page", "");

    let before = backend.count();
    let (status, body) = get(port, "example.com", "/page");
    assert_eq!(status, 200);
    assert!(
        body.starts_with("up example.com #"),
        "the entry filled by HEAD has no body: {body:?}"
    );
    assert_eq!(
        backend.count(),
        before,
        "GET after HEAD reached the upstream"
    );
    assert!(
        backend.methods().iter().all(|method| method == "GET"),
        "HEAD reached the upstream as {:?}",
        backend.methods()
    );
}

#[test]
fn routes_matching_the_same_host_and_path_do_not_share_a_cached_response() {
    let alpha = Backend::start("alpha");
    let beta = Backend::start("beta");
    let upstreams = format!(
        "{}{}",
        upstream_block("alpha-up", alpha.port),
        upstream_block("beta-up", beta.port)
    );
    let routes = format!(
        "{}{}",
        caching_route("alpha", r#"header "X-Route" "alpha""#, "alpha-up"),
        caching_route("beta", r#"header "X-Route" "beta""#, "beta-up"),
    );
    let (port, _proxy) = start(&upstreams, &routes);
    let via_alpha = "X-Route: alpha\r\n";
    let via_beta = "X-Route: beta\r\n";

    let from_alpha = until_cached(port, &alpha, "GET", "example.com", "/page", via_alpha);
    assert!(
        from_alpha.starts_with("alpha example.com #"),
        "{from_alpha}"
    );

    // Same host, path and query; the other route answers it from its upstream.
    let (status, from_beta) = request(port, "GET", "example.com", "/page", via_beta);
    assert_eq!(status, 200);
    assert!(
        from_beta.starts_with("beta example.com #"),
        "served the other route's response: {from_beta}"
    );
    let from_beta = until_cached(port, &beta, "GET", "example.com", "/page", via_beta);
    assert!(from_beta.starts_with("beta example.com #"), "{from_beta}");

    // Each route is then served from its own entry.
    let before = (alpha.count(), beta.count());
    let again = request(port, "GET", "example.com", "/page", via_alpha);
    assert_eq!(again.1, from_alpha);
    let again = request(port, "GET", "example.com", "/page", via_beta);
    assert_eq!(again.1, from_beta);
    assert_eq!((alpha.count(), beta.count()), before);
}
