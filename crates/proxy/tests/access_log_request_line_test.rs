//! The request line of an access log entry: the query string and the protocol
//! version.
//!
//! Runs the real binary with an `http` listener and an `h2c` listener in front
//! of one HTTP/1.1 backend, with the access log written through
//! (`buffer-size 1`) to a file in a temp dir. A request's own access log line
//! must carry the query string it was sent with and the HTTP version it was
//! sent over, in both the `json` and the `combined` format.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
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

/// One request over HTTP/1.x on `port`; the status code of the answer.
fn http1_get(port: u16, version: &str, target: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {target} {version}\r\nHost: a.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response.split_whitespace().nth(1)?.parse().ok()
}

/// One request over HTTP/2 with prior knowledge on `port`; the status code.
fn h2c_get(port: u16, target: &str) -> Result<u16, String> {
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
                    .uri(format!("http://a.example:{port}{target}"))
                    .body(())
                    .unwrap();
                let (response, _) = client
                    .send_request(request, true)
                    .map_err(|e| format!("send: {e}"))?;
                let response = response.await.map_err(|e| format!("response: {e}"))?;
                let status = response.status().as_u16();
                let mut body = response.into_body();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.map_err(|e| format!("body: {e}"))?;
                    let _ = body.flow_control().release_capacity(chunk.len());
                }
                Ok(status)
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
    http: u16,
    h2c: u16,
    access_log: PathBuf,
    _child: KillOnDrop,
    _dir: tempfile::TempDir,
}

/// A proxy whose access log is in `format` (`json` or `combined`).
fn start_proxy(format: &str) -> Proxy {
    start_proxy_with(format, "")
}

/// As `start_proxy`, with `access_log_extra` added to the `access-log` block.
fn start_proxy_with(format: &str, access_log_extra: &str) -> Proxy {
    let backend_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let backend = backend_listener.local_addr().unwrap().port();
    http1_backend(backend_listener);
    let (http, h2c) = (free_port(), free_port());

    let dir = tempfile::tempdir().unwrap();
    let access_log = dir.path().join("access.log");
    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "plain" {{
        address "127.0.0.1:{http}"
        protocol "http"
    }}
    listener "internal" {{
        address "127.0.0.1:{h2c}"
        protocol "h2c"
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
    logging {{
        access-log {{
            enabled #true
            file "{access}"
            format "{format}"
            buffer-size 1
            {access_log_extra}
        }}
    }}
}}
"#,
            access = access_log.display(),
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
    for port in [http, h2c] {
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                Instant::now() < deadline,
                "the proxy never started listening on {port}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    Proxy {
        http,
        h2c,
        access_log,
        _child: child,
        _dir: dir,
    }
}

/// The lines of the access log once it holds `count` of them.
fn access_log_lines(path: &Path, count: usize) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        if lines.len() >= count || Instant::now() >= deadline {
            return lines;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The one JSON access log entry whose `path` is `path`.
fn json_entry(lines: &[String], path: &str) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = lines
        .iter()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .unwrap_or_else(|e| panic!("{line:?}: {e}"))
        })
        .filter(|entry| entry["path"] == path)
        .collect();
    assert_eq!(entries.len(), 1, "entries for {path}: {lines:?}");
    entries.into_iter().next().unwrap()
}

/// The quoted request line of the one `combined` entry that contains `needle`.
fn request_line(lines: &[String], needle: &str) -> String {
    let matching: Vec<&String> = lines.iter().filter(|l| l.contains(needle)).collect();
    assert_eq!(matching.len(), 1, "entries with {needle}: {lines:?}");
    let line = matching[0];
    let start = line.find('"').expect("an opening quote") + 1;
    let end = start + line[start..].find('"').expect("a closing quote");
    line[start..end].to_string()
}

#[test]
fn json_access_log_records_the_query_string() {
    let proxy = start_proxy("json");
    assert_eq!(
        http1_get(proxy.http, "HTTP/1.1", "/search?q=caf%C3%A9&page=2"),
        Some(200)
    );
    assert_eq!(http1_get(proxy.http, "HTTP/1.1", "/plain"), Some(200));

    let lines = access_log_lines(&proxy.access_log, 2);
    let with_query = json_entry(&lines, "/search");
    assert_eq!(
        with_query["query"], "q=caf%C3%A9&page=2",
        "the query string of the request is missing: {lines:?}"
    );
    let without_query = json_entry(&lines, "/plain");
    assert!(
        without_query.get("query").is_none(),
        "a request without a query string has a query in its entry: {lines:?}"
    );
}

#[test]
fn combined_access_log_records_the_path_and_query_in_the_request_line() {
    let proxy = start_proxy("combined");
    assert_eq!(
        http1_get(proxy.http, "HTTP/1.1", "/search?q=a.example&page=2"),
        Some(200)
    );
    assert_eq!(http1_get(proxy.http, "HTTP/1.1", "/plain"), Some(200));

    let lines = access_log_lines(&proxy.access_log, 2);
    assert_eq!(
        request_line(&lines, "/search"),
        "GET /search?q=a.example&page=2 HTTP/1.1"
    );
    assert_eq!(request_line(&lines, "/plain"), "GET /plain HTTP/1.1");
}

#[test]
fn combined_access_log_records_an_http_1_0_request_as_http_1_0() {
    let proxy = start_proxy("combined");
    assert_eq!(http1_get(proxy.http, "HTTP/1.0", "/one-zero"), Some(200));

    let lines = access_log_lines(&proxy.access_log, 1);
    assert_eq!(
        request_line(&lines, "/one-zero"),
        "GET /one-zero HTTP/1.0",
        "an HTTP/1.0 request was logged under another protocol: {lines:?}"
    );
}

#[test]
fn combined_access_log_records_an_http_2_request_as_http_2() {
    let proxy = start_proxy("combined");
    assert_eq!(h2c_get(proxy.h2c, "/two?x=1"), Ok(200));

    let lines = access_log_lines(&proxy.access_log, 1);
    assert_eq!(
        request_line(&lines, "/two"),
        "GET /two?x=1 HTTP/2.0",
        "an HTTP/2 request was logged under another protocol: {lines:?}"
    );
}

#[test]
fn json_access_log_leaves_out_the_query_when_the_field_is_off() {
    let proxy = start_proxy_with("json", "fields { query #false }");
    assert_eq!(
        http1_get(proxy.http, "HTTP/1.1", "/search?q=a.example&page=2"),
        Some(200)
    );

    let lines = access_log_lines(&proxy.access_log, 1);
    let entry = json_entry(&lines, "/search");
    assert!(
        entry.get("query").is_none(),
        "the query string was logged with `query #false`: {lines:?}"
    );
    // The other fields are as before.
    assert_eq!(entry["method"], "GET");
    assert_eq!(entry["status"], 200);
}

#[test]
fn combined_access_log_leaves_out_the_query_when_the_field_is_off() {
    let proxy = start_proxy_with("combined", "fields { query #false }");
    assert_eq!(
        http1_get(proxy.http, "HTTP/1.1", "/search?q=a.example&page=2"),
        Some(200)
    );
    assert_eq!(h2c_get(proxy.h2c, "/two?x=1"), Ok(200));

    let lines = access_log_lines(&proxy.access_log, 2);
    assert_eq!(request_line(&lines, "/search"), "GET /search HTTP/1.1");
    assert_eq!(request_line(&lines, "/two"), "GET /two HTTP/2.0");
    assert!(
        !lines.iter().any(|line| line.contains("a.example")),
        "the query string was logged with `query #false`: {lines:?}"
    );
}
