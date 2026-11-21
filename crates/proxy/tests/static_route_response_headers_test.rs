//! Route response-header policies and response filters on static routes,
//! end to end against the real binary (#682).
//!
//! A static route writes its response in `request_filter`, so the response
//! never passes through `response_filter`, where `policies.response-headers`
//! and the route's response filters (Headers, CORS) were applied. Files were
//! served without the headers the route configured.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The proxy process, and the directory holding its config and files (kept alive).
struct Proxy(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start() -> (u16, Proxy) {
    let port = (19970..19980)
        .find(|&p| TcpListener::bind(("127.0.0.1", p)).is_ok())
        .expect("a free port in 19970..19980");
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("www");
    std::fs::create_dir_all(root.join(".well-known")).unwrap();
    std::fs::write(root.join(".well-known/sable"), r#"{"ok":true}"#).unwrap();
    std::fs::write(root.join("page.html"), "<p>hi</p>").unwrap();
    let root = root.display();
    let config = format!(
        r#"
system {{ worker-threads 2 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
filters {{
    filter "cors" {{
        type "cors"
        allow-origins "https://chat.example"
        allow-methods "GET"
    }}
    filter "tag" {{
        type "headers"
        phase "response"
        set {{
            "X-Filter" "applied"
        }}
    }}
}}
routes {{
    route "well-known" {{
        matches {{ path-prefix "/.well-known/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
        policies {{
            response-headers {{
                set {{
                    "Content-Type" "application/json"
                    "Access-Control-Allow-Origin" "*"
                }}
                add {{
                    "X-Added" "yes"
                }}
            }}
        }}
    }}
    route "site" {{
        matches {{ path-prefix "/" }}
        service-type "static"
        static-files {{
            root "{root}"
        }}
        filters "cors" "tag"
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

/// GET `path` with an `Origin` header; returns the status and response head.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nOrigin: https://chat.example\r\n\
         Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let head = raw.split("\r\n\r\n").next().unwrap_or_default().to_string();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, head)
}

fn header(head: &str, name: &str) -> Vec<String> {
    head.lines()
        .skip(1)
        .filter_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
        .collect()
}

#[test]
fn static_routes_apply_response_header_policies_and_filters() {
    let (port, _proxy) = start();

    // The configuration from #682: `set` replaces the guessed content type.
    let (status, head) = get(port, "/.well-known/sable");
    assert_eq!(status, 200, "{head}");
    assert_eq!(
        header(&head, "content-type"),
        ["application/json"],
        "{head}"
    );
    assert_eq!(
        header(&head, "access-control-allow-origin"),
        ["*"],
        "{head}"
    );
    assert_eq!(header(&head, "x-added"), ["yes"], "{head}");

    // Route filters run too: the response-phase Headers filter and CORS.
    let (status, head) = get(port, "/page.html");
    assert_eq!(status, 200, "{head}");
    assert_eq!(header(&head, "x-filter"), ["applied"], "{head}");
    assert_eq!(
        header(&head, "access-control-allow-origin"),
        ["https://chat.example"],
        "{head}"
    );
}
