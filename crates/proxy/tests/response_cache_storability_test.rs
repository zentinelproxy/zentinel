//! Which responses the response cache stores and serves, end to end against
//! the real binary: `Authorization`, `Set-Cookie` and `Vary`, and very long
//! `Cache-Control` lifetimes.
//!
//! The backend counts the requests that reach it. A response counts as stored
//! when a repeated request is answered without a new request reaching the
//! backend, and as not stored when every repeated request reaches it. A stored
//! response is polled for against a deadline, because the store may land a
//! moment after the first response; nothing waits a fixed time for it.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zentinel_agent_protocol::v2::server::AgentHandlerV2;
use zentinel_agent_protocol::v2::uds_server::UdsAgentServerV2;
use zentinel_agent_protocol::v2::AgentCapabilities;
use zentinel_agent_protocol::{AgentResponse, EventType, HeaderOp, RequestHeadersEvent};

/// How long to wait for the proxy to listen, or for a response to appear in the cache.
const DEADLINE: Duration = Duration::from_secs(30);

const AUTH: (&str, &str) = ("Authorization", "Bearer token.example");

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// What the backend answers for `path`: extra response headers and a body.
/// `request` holds the headers of the request being answered, by lowercased name.
fn reply(
    path: &str,
    request: &HashMap<String, String>,
) -> (Vec<(&'static str, &'static str)>, String) {
    let lang = request
        .get("accept-language")
        .map_or("none", String::as_str);
    let accept = request.get("accept").map_or("none", String::as_str);
    match path {
        "/plain" => (vec![], "plain".into()),
        "/public" => (
            vec![("Cache-Control", "public, max-age=60")],
            "public".into(),
        ),

        // These are requested with `Authorization`.
        "/auth-none-1" | "/auth-none-2" => (vec![], "auth".into()),
        "/auth-max-age" => (vec![("Cache-Control", "max-age=60")], "auth".into()),
        "/auth-public" => (vec![("Cache-Control", "public, max-age=60")], "auth".into()),
        "/auth-s-maxage" => (vec![("Cache-Control", "s-maxage=60")], "auth".into()),
        "/auth-must-revalidate" => (
            vec![("Cache-Control", "max-age=60, must-revalidate")],
            "auth".into(),
        ),

        "/cookie" => (
            vec![("Set-Cookie", "sid=1.example; Path=/")],
            "cookie".into(),
        ),
        "/cookie-public" => (
            vec![
                ("Cache-Control", "public, max-age=60"),
                ("Set-Cookie", "sid=1.example; Path=/"),
            ],
            "cookie".into(),
        ),

        // Whether the request reached the backend with `Authorization`.
        "/auth-echo" | "/agent-probe" => (
            vec![],
            if request.contains_key("authorization") {
                "with-auth".into()
            } else {
                "no-auth".into()
            },
        ),

        // The first line allows storing, the second does not.
        "/cc-two-lines" => (
            vec![
                ("Cache-Control", "public, max-age=60"),
                ("Cache-Control", "private"),
            ],
            "two-lines".into(),
        ),

        "/vary-lang" => (vec![("Vary", "Accept-Language")], lang.into()),
        "/vary-two" => (
            // Two field lines, one name each.
            vec![("Vary", "Accept-Language"), ("Vary", "Accept")],
            format!("{lang}|{accept}"),
        ),
        "/vary-star" => (vec![("Vary", "*")], "star".into()),

        // `u64::MAX` seconds cannot be added to the current time. The others
        // are above 2^31 seconds, the longest lifetime the cache applies, and
        // check that the response is still stored.
        "/max-age-u64-max" => (
            vec![("Cache-Control", "max-age=18446744073709551615")],
            "lifetime".into(),
        ),
        "/s-maxage-u64-max" => (
            vec![("Cache-Control", "public, s-maxage=18446744073709551615")],
            "lifetime".into(),
        ),
        "/max-age-2-pow-31-plus-1" => (
            vec![("Cache-Control", "max-age=2147483649")],
            "lifetime".into(),
        ),
        "/max-age-beyond-u64" => (
            vec![("Cache-Control", "max-age=99999999999999999999999")],
            "lifetime".into(),
        ),
        _ => (vec![], "unknown".into()),
    }
}

/// An HTTP backend that records how many requests each path received.
#[derive(Clone)]
struct Backend {
    hits: Arc<Mutex<HashMap<String, usize>>>,
}

impl Backend {
    /// Serve on `listener`, which stays open from the moment it was bound.
    fn spawn(listener: TcpListener) -> Self {
        let backend = Backend {
            hits: Arc::new(Mutex::new(HashMap::new())),
        };
        let hits = Arc::clone(&backend.hits);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let hits = Arc::clone(&hits);
                std::thread::spawn(move || serve(stream, &hits));
            }
        });
        backend
    }

    fn hits(&self, path: &str) -> usize {
        self.hits.lock().unwrap().get(path).copied().unwrap_or(0)
    }
}

fn serve(mut stream: TcpStream, hits: &Mutex<HashMap<String, usize>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut request = HashMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).is_ok_and(|n| n == 0) || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            request.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    // Count before answering, so a client that has read the response can
    // rely on the count including its own request.
    *hits.lock().unwrap().entry(path.clone()).or_insert(0) += 1;

    let (headers, body) = reply(&path, &request);
    let mut head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let _ = stream.write_all(format!("{head}\r\n{body}").as_bytes());
}

// ---------------------------------------------------------------------------
// Proxy
// ---------------------------------------------------------------------------

struct Proxy {
    port: u16,
    /// The disk cache directory, when the disk backend is in use.
    disk: Option<PathBuf>,
    child: Child,
    // Held so the config (and any disk cache directory) outlives the process.
    _dir: tempfile::TempDir,
    // Runs the agent, when there is one.
    _runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free port picked by the OS. The proxy's listener port has to be named in
/// its config, so it is released here and bound again by the proxy.
fn os_picked_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An agent that removes `Authorization` from every request headers event.
struct StripAuthorization;

#[async_trait::async_trait]
impl AgentHandlerV2 for StripAuthorization {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("strip-authorization", "Strip Authorization", "0.1.0")
            .with_event(EventType::RequestHeaders)
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow().add_request_header(HeaderOp::Remove {
            name: "Authorization".to_string(),
        })
    }
}

/// Start a backend and a proxy with response caching on for every route.
/// `storage` is `"memory"`, `"disk"` or `"hybrid"`.
fn start(storage: &str) -> (Proxy, Backend) {
    launch(storage, false)
}

/// Like [`start`], with the route's requests going through an agent that
/// removes `Authorization` before the response is cached.
fn start_with_agent() -> (Proxy, Backend) {
    launch("memory", true)
}

fn launch(storage: &str, with_agent: bool) -> (Proxy, Backend) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = Backend::spawn(listener);

    let port = os_picked_port();
    let dir = tempfile::tempdir().unwrap();
    let disk = (storage != "memory").then(|| dir.path().join("cache"));
    let cache_block = match &disk {
        Some(disk) => {
            std::fs::create_dir_all(disk).unwrap();
            format!(
                "cache {{\n    enabled #true\n    backend \"{storage}\"\n    disk-path \"{}\"\n}}",
                disk.display()
            )
        }
        None => String::new(),
    };
    let mut runtime = None;
    let (agents_block, route_filters) = if with_agent {
        let socket = dir.path().join("agent.sock");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let server = UdsAgentServerV2::new(
            "strip-authorization",
            socket.clone(),
            Box::new(StripAuthorization),
        );
        rt.spawn(async move {
            let _ = server.run().await;
        });
        let deadline = Instant::now() + DEADLINE;
        while !socket.exists() {
            assert!(Instant::now() < deadline, "the agent never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
        runtime = Some(rt);
        (
            format!(
                r#"
agents {{
    agent "strip-authorization" type="custom" {{
        unix-socket "{}"
        events "request_headers"
        timeout-ms 2000
        failure-mode "closed"
    }}
}}
filters {{
    filter "strip-authorization" {{
        type "agent"
        agent "strip-authorization"
        failure-mode "closed"
    }}
}}"#,
                socket.display()
            ),
            r#"filters "strip-authorization""#,
        )
    } else {
        (String::new(), "")
    };
    let config = format!(
        r#"
system {{ worker-threads 2 }}
{cache_block}
{agents_block}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
routes {{
    route "metrics" {{
        priority "high"
        matches {{ path "/_metrics" }}
        builtin-handler "metrics"
    }}
    route "cached" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        {route_filters}
        cache {{
            enabled #true
            default-ttl-secs 60
        }}
    }}
}}
upstreams {{
    upstream "backend" {{
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    );
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let proxy = Proxy {
        port,
        disk,
        child,
        _dir: dir,
        _runtime: runtime,
    };
    let deadline = Instant::now() + DEADLINE;
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "the proxy never listened");
        std::thread::sleep(Duration::from_millis(100));
    }
    (proxy, backend)
}

/// The number of cache entries (`.meta` files) under `dir`.
fn entries_on_disk(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .map(|path| {
            if path.is_dir() {
                entries_on_disk(&path)
            } else {
                usize::from(path.extension().is_some_and(|ext| ext == "meta"))
            }
        })
        .sum()
}

/// GET `path` with the given extra request headers; returns the body.
fn get(proxy: &Proxy, path: &str, headers: &[(&str, &str)]) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: cache.example\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "GET {path} did not answer 200: {head}"
    );
    body.to_string()
}

/// How many responses the proxy has counted as not stored for `reason`,
/// on the route `cached`, from its metrics route.
fn not_stored_total(proxy: &Proxy, reason: &str) -> u64 {
    get(proxy, "/_metrics", &[])
        .lines()
        .filter(|line| line.starts_with("zentinel_cache_not_stored_total{"))
        .filter(|line| line.contains(&format!("reason=\"{reason}\"")))
        .filter(|line| line.contains("route=\"cached\""))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .sum::<f64>() as u64
}

/// Repeat the request until one is answered without reaching the backend.
fn wait_until_stored(proxy: &Proxy, backend: &Backend, path: &str, headers: &[(&str, &str)]) {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let before = backend.hits(path);
        get(proxy, path, headers);
        if backend.hits(path) == before {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{path} was never served from the cache"
        );
    }
}

/// Send each request in turn; every one must reach the backend, so no
/// response from an earlier one may have been stored and served.
fn assert_not_stored(proxy: &Proxy, backend: &Backend, path: &str, requests: &[&[(&str, &str)]]) {
    for (i, headers) in requests.iter().enumerate() {
        let before = backend.hits(path);
        get(proxy, path, headers);
        assert_eq!(
            backend.hits(path),
            before + 1,
            "request {} to {path} ({headers:?}) was served from the cache",
            i + 1
        );
    }
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

#[test]
fn response_to_a_request_with_authorization_is_not_stored_without_an_explicit_allowance() {
    let (proxy, backend) = start("memory");
    // The cache works for this response, so the cases below are not a cache that is off.
    get(&proxy, "/plain", &[]);
    wait_until_stored(&proxy, &backend, "/plain", &[]);

    // Neither a later request without `Authorization` nor another with it
    // may be answered with the response to the first.
    assert_not_stored(&proxy, &backend, "/auth-none-1", &[&[AUTH], &[]]);
    assert_not_stored(&proxy, &backend, "/auth-none-2", &[&[AUTH], &[AUTH]]);
    // `max-age` alone does not allow a shared cache to reuse it.
    assert_not_stored(&proxy, &backend, "/auth-max-age", &[&[AUTH], &[AUTH]]);

    // Each response that carried `Authorization` in its request and was not
    // stored is counted: 1 + 2 + 2.
    assert_eq!(not_stored_total(&proxy, "authorization"), 5);
}

#[test]
fn authorization_that_an_agent_removed_still_counts_as_sent_by_the_client() {
    let (proxy, backend) = start_with_agent();
    // Wait until the agent is consulted: the backend then sees no `Authorization`.
    let deadline = Instant::now() + DEADLINE;
    while get(&proxy, "/agent-probe", &[AUTH]) != "no-auth" {
        assert!(Instant::now() < deadline, "the agent was never consulted");
    }

    // The backend is answering a request without `Authorization`, but the
    // client sent one, so the response is not stored.
    assert_eq!(get(&proxy, "/auth-echo", &[AUTH]), "no-auth");
    assert_not_stored(&proxy, &backend, "/auth-echo", &[&[AUTH], &[AUTH], &[]]);
}

#[test]
fn response_to_a_request_with_authorization_is_stored_when_the_response_allows_it() {
    let (proxy, backend) = start("memory");
    for path in ["/auth-public", "/auth-s-maxage", "/auth-must-revalidate"] {
        get(&proxy, path, &[AUTH]);
        wait_until_stored(&proxy, &backend, path, &[AUTH]);
        // Stored for every request, as the response allows.
        let before = backend.hits(path);
        assert_eq!(get(&proxy, path, &[]), "auth");
        assert_eq!(backend.hits(path), before, "{path} reached the backend");
    }
}

// ---------------------------------------------------------------------------
// Set-Cookie
// ---------------------------------------------------------------------------

#[test]
fn response_with_set_cookie_is_not_stored() {
    let (proxy, backend) = start("memory");
    get(&proxy, "/plain", &[]);
    wait_until_stored(&proxy, &backend, "/plain", &[]);

    assert_not_stored(&proxy, &backend, "/cookie", &[&[], &[], &[]]);
    // Not even when the response says it is public.
    assert_not_stored(&proxy, &backend, "/cookie-public", &[&[], &[], &[]]);

    assert_eq!(not_stored_total(&proxy, "set_cookie"), 6);
}

// ---------------------------------------------------------------------------
// Vary
// ---------------------------------------------------------------------------

fn vary_keeps_variants_apart(storage: &str) {
    let (proxy, backend) = start(storage);
    let en: &[(&str, &str)] = &[("Accept-Language", "en")];
    let fr: &[(&str, &str)] = &[("Accept-Language", "fr")];
    let path = "/vary-lang";

    assert_eq!(get(&proxy, path, en), "en");
    wait_until_stored(&proxy, &backend, path, en);

    // A request whose `Accept-Language` differs is not answered with the
    // stored `en` response: it reaches the backend and gets its own.
    let before = backend.hits(path);
    assert_eq!(get(&proxy, path, fr), "fr");
    assert_eq!(
        backend.hits(path),
        before + 1,
        "the `fr` request was served from the `en` entry"
    );
    wait_until_stored(&proxy, &backend, path, fr);

    // So does a request without the header.
    let before = backend.hits(path);
    assert_eq!(get(&proxy, path, &[]), "none");
    assert_eq!(
        backend.hits(path),
        before + 1,
        "a request without `Accept-Language` was served from another entry"
    );
    wait_until_stored(&proxy, &backend, path, &[]);

    // Each variant is now served from the cache, and only to its own requests.
    let before = backend.hits(path);
    assert_eq!(get(&proxy, path, en), "en");
    assert_eq!(get(&proxy, path, fr), "fr");
    assert_eq!(get(&proxy, path, &[]), "none");
    assert_eq!(
        backend.hits(path),
        before,
        "a stored variant was not reused"
    );

    // One entry per variant, so the disk backend was the one in use.
    if let (Some(disk), "disk") = (&proxy.disk, storage) {
        assert_eq!(entries_on_disk(disk), 3);
    }
}

#[test]
fn vary_keeps_variants_apart_in_memory() {
    vary_keeps_variants_apart("memory");
}

#[test]
fn vary_keeps_variants_apart_on_disk() {
    vary_keeps_variants_apart("disk");
}

#[test]
fn vary_keeps_variants_apart_on_hybrid() {
    vary_keeps_variants_apart("hybrid");
}

#[test]
fn vary_on_two_field_lines_uses_both_names() {
    let (proxy, backend) = start("memory");
    let path = "/vary-two";
    let a: &[(&str, &str)] = &[("Accept-Language", "en"), ("Accept", "text/a")];
    let b: &[(&str, &str)] = &[("Accept-Language", "en"), ("Accept", "text/b")];

    assert_eq!(get(&proxy, path, a), "en|text/a");
    wait_until_stored(&proxy, &backend, path, a);

    // Same `Accept-Language`, different `Accept`: a different variant.
    let before = backend.hits(path);
    assert_eq!(get(&proxy, path, b), "en|text/b");
    assert_eq!(backend.hits(path), before + 1);
}

#[test]
fn response_with_vary_star_is_not_stored() {
    let (proxy, backend) = start("memory");
    get(&proxy, "/plain", &[]);
    wait_until_stored(&proxy, &backend, "/plain", &[]);

    assert_not_stored(&proxy, &backend, "/vary-star", &[&[], &[], &[]]);

    assert_eq!(not_stored_total(&proxy, "vary_any"), 3);
}

// ---------------------------------------------------------------------------
// Cache-Control on more than one line
// ---------------------------------------------------------------------------

#[test]
fn a_later_cache_control_line_that_forbids_storing_is_honored() {
    let (proxy, backend) = start("memory");
    get(&proxy, "/plain", &[]);
    wait_until_stored(&proxy, &backend, "/plain", &[]);

    // The first line has `public, max-age=60`, the second `private`.
    assert_not_stored(&proxy, &backend, "/cc-two-lines", &[&[], &[], &[]]);
}

// ---------------------------------------------------------------------------
// Everything else is stored as before
// ---------------------------------------------------------------------------

#[test]
fn responses_without_these_headers_are_stored() {
    let (proxy, backend) = start("memory");
    for path in ["/plain", "/public"] {
        get(&proxy, path, &[]);
        wait_until_stored(&proxy, &backend, path, &[]);
    }
}

// ---------------------------------------------------------------------------
// Very long lifetimes
// ---------------------------------------------------------------------------

/// `u64::MAX` seconds overflows when added to the current time, which used to
/// panic in the request handler (and stops a release build). The other
/// lifetimes are above 2^31 seconds, the longest the cache applies: they
/// check the boundary.
fn a_very_long_cache_lifetime_does_not_stop_the_proxy(storage: &str) {
    let (mut proxy, backend) = start(storage);
    for path in [
        "/max-age-u64-max",
        "/s-maxage-u64-max",
        "/max-age-2-pow-31-plus-1",
        "/max-age-beyond-u64",
    ] {
        // The first response is the one whose lifetime is calculated.
        assert_eq!(get(&proxy, path, &[]), "lifetime");
        // It is stored, and served from the cache.
        wait_until_stored(&proxy, &backend, path, &[]);
    }

    // The proxy is still running and answers other requests.
    assert!(
        proxy.child.try_wait().unwrap().is_none(),
        "the proxy exited"
    );
    assert_eq!(get(&proxy, "/plain", &[]), "plain");
}

#[test]
fn a_very_long_cache_lifetime_does_not_stop_the_proxy_in_memory() {
    a_very_long_cache_lifetime_does_not_stop_the_proxy("memory");
}

#[test]
fn a_very_long_cache_lifetime_does_not_stop_the_proxy_on_disk() {
    a_very_long_cache_lifetime_does_not_stop_the_proxy("disk");
}
