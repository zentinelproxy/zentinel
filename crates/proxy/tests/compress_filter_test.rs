//! The `compress` filter, end to end against the real binary (#591).
//!
//! Before #591 the filter switched Pingora's compression module on after the
//! module had already passed over the response header, and the module
//! panicked on the first body chunk: every response the filter applied to
//! reached the client empty or truncated. Its `algorithms` list was also never
//! read, so it could not restrict or order the codings used.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn page() -> String {
    format!(
        "<html><body>{}</body></html>",
        "zentinel compress filter #591 ".repeat(300)
    )
}

fn free_ports(range: std::ops::Range<u16>) -> (u16, u16) {
    let mut free = range
        .clone()
        .filter(|&port| TcpListener::bind(("127.0.0.1", port)).is_ok());
    (
        free.next().expect("a free port"),
        free.next()
            .unwrap_or_else(|| panic!("two free ports in {range:?}")),
    )
}

/// A backend answering every request with [`page`] as uncompressed HTML.
fn spawn_backend(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok() && line != "\r\n" && !line.is_empty() {
                    line.clear();
                }
                let body = page();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
}

/// The proxy process, and the directory holding its config (kept alive).
struct Proxy(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the proxy with a compress filter whose body is `filter_settings`.
fn start(ports: std::ops::Range<u16>, filter_settings: &str) -> (u16, Proxy) {
    let (port, backend) = free_ports(ports);
    spawn_backend(backend);
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
    upstream "backend" {{
        target "127.0.0.1:{backend}"
    }}
}}
filters {{
    filter "compress" {{
        type "compress"
        {filter_settings}
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "compress"
    }}
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

struct Response {
    status: u16,
    content_encoding: Option<String>,
    vary: Option<String>,
    body: Vec<u8>,
}

/// GET / with the given `Accept-Encoding`, reading the whole response.
fn get(port: u16, accept_encoding: Option<&str>) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let accept = accept_encoding
        .map(|ae| format!("Accept-Encoding: {ae}\r\n"))
        .unwrap_or_default();
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{accept}\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no complete response: {:?}", String::from_utf8_lossy(&raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let rest = &raw[split + 4..];
    let header = |name: &str| {
        head.lines().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    };
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = if header("transfer-encoding").is_some_and(|te| te.contains("chunked")) {
        dechunk(rest)
    } else {
        rest.to_vec()
    };
    Response {
        status,
        content_encoding: header("content-encoding"),
        vary: header("vary"),
        body,
    }
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = data
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("chunk size line");
        let size_text = String::from_utf8_lossy(&data[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap().trim(), 16)
            .expect("chunk size");
        data = &data[line_end + 2..];
        if size == 0 {
            return out;
        }
        assert!(data.len() >= size + 2, "truncated chunk");
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// The body as the client would read it after undoing `Content-Encoding`.
fn decoded(resp: &Response) -> String {
    let bytes = match resp.content_encoding.as_deref() {
        None => resp.body.clone(),
        Some("gzip") => {
            let mut out = Vec::new();
            flate2::read::GzDecoder::new(&resp.body[..])
                .read_to_end(&mut out)
                .expect("valid gzip");
            out
        }
        Some(other) => panic!("cannot decode {other}"),
    };
    String::from_utf8(bytes).expect("utf-8 page")
}

/// Before the fix this response came back empty or truncated.
#[test]
fn compressed_responses_arrive_whole() {
    let (port, _proxy) = start(19810..19816, r#"algorithms "gzip" "zstd""#);
    for _ in 0..5 {
        let resp = get(port, Some("gzip"));
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_encoding.as_deref(), Some("gzip"));
        assert!(resp.body.len() < page().len(), "not compressed");
        assert_eq!(decoded(&resp), page());
        assert!(
            resp.vary
                .as_deref()
                .is_some_and(|v| v.to_ascii_lowercase().contains("accept-encoding")),
            "Vary: Accept-Encoding missing"
        );
    }
}

/// #591: a gzip-only filter against a client that prefers br.
#[test]
fn gzip_only_filter_never_produces_brotli() {
    let (port, _proxy) = start(19816..19822, r#"algorithms "gzip""#);

    let resp = get(port, Some("br, gzip"));
    assert_eq!(resp.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(decoded(&resp), page());

    // A client that takes only codings the filter does not allow gets the
    // page uncompressed.
    let resp = get(port, Some("br, zstd"));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_encoding, None);
    assert_eq!(decoded(&resp), page());
}

/// The configured order wins among the codings the client accepts.
#[test]
fn configured_order_is_the_preference() {
    let (port, _proxy) = start(19822..19828, r#"algorithms "zstd" "gzip""#);

    let resp = get(port, Some("gzip, zstd"));
    assert_eq!(resp.content_encoding.as_deref(), Some("zstd"));
    // A zstd frame, smaller than the page (no zstd decoder among the test
    // dependencies; gzip below is decoded in full).
    assert!(resp.body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]));
    assert!(resp.body.len() < page().len());

    // q=0 refuses zstd, so the next configured coding is used.
    let resp = get(port, Some("zstd;q=0, gzip"));
    assert_eq!(resp.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(decoded(&resp), page());
}

/// Brotli is never produced: Pingora's encoder does not finish the stream,
/// so clients could not decode it. The next listed coding is used.
#[test]
fn brotli_is_skipped() {
    let (port, _proxy) = start(19834..19840, r#"algorithms "br" "gzip""#);

    let resp = get(port, Some("br, gzip"));
    assert_eq!(resp.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(decoded(&resp), page());

    let resp = get(port, Some("br"));
    assert_eq!(resp.content_encoding, None);
    assert_eq!(decoded(&resp), page());
}

/// Without `algorithms` the filter offers gzip; without `Accept-Encoding`
/// nothing is compressed.
#[test]
fn defaults() {
    let (port, _proxy) = start(19828..19834, "");

    let resp = get(port, Some("br, zstd, gzip"));
    assert_eq!(resp.content_encoding.as_deref(), Some("gzip"));
    assert_eq!(decoded(&resp), page());

    let resp = get(port, Some("br"));
    assert_eq!(resp.content_encoding, None);
    assert_eq!(decoded(&resp), page());

    let resp = get(port, None);
    assert_eq!(resp.content_encoding, None);
    assert_eq!(decoded(&resp), page());
}
