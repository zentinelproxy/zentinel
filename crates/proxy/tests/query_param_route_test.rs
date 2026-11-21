//! Query-parameter route conditions, end to end against the real binary.
//!
//! A route with a `query-param` condition has to match on the request's query
//! string. These tests run the real binary in front of two local backends, one
//! behind the query-parameter routes and one behind a catch-all route, and
//! check from the response which backend a request reached.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Bind a free port chosen by the OS, keeping the listener bound.
fn bind_any() -> TcpListener {
    TcpListener::bind(("127.0.0.1", 0)).expect("bind a free port")
}

/// A backend answering every request with `<name> <request target>`.
fn backend(listener: TcpListener, name: &'static str) -> u16 {
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    return;
                }
                // Drain the headers.
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let target = request_line.split(' ').nth(1).unwrap_or("?");
                let body = format!("{name} {target}");
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    port
}

/// `GET target` on `port`: the status and the body.
fn get(port: u16, target: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {target} HTTP/1.1\r\nHost: test.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    (status, body)
}

/// The proxy process, and the directory holding its config (kept alive).
struct Proxy(Child, #[allow(dead_code)] tempfile::TempDir);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Poll until `cond` holds, for up to 30 s.
fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// Start the proxy with two query-parameter routes in front of a catch-all.
///
/// `versioned` carries a query-parameter condition with a value, `flagged` one
/// without a value. Both are more specific than the catch-all, which sends
/// everything else to the `default` backend.
fn start() -> (u16, Proxy) {
    let queried = bind_any();
    let default = bind_any();
    let queried = backend(queried, "queried");
    let default = backend(default, "default");

    // The proxy's own port: released just before it binds it.
    let port = bind_any().local_addr().unwrap().port();

    let config = format!(
        r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{ address "127.0.0.1:{port}"; protocol "http"; }}
}}
upstreams {{
    upstream "queried" {{ target "127.0.0.1:{queried}"; }}
    upstream "default" {{ target "127.0.0.1:{default}"; }}
}}
routes {{
    route "versioned" {{
        matches {{
            path-prefix "/api"
            query-param "version" "v2"
        }}
        upstream "queried"
    }}
    route "flagged" {{
        matches {{
            path-prefix "/flag"
            query-param "beta"
        }}
        upstream "queried"
    }}
    route "encoded" {{
        matches {{
            path-prefix "/encoded"
            query-param "a" "b=c"
        }}
        upstream "queried"
    }}
    route "catch-all" {{
        matches {{ path-prefix "/"; }}
        upstream "default"
    }}
}}
observability {{
    metrics {{ enabled #false; }}
}}
"#
    );

    let dir = tempfile::tempdir().unwrap();
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
    wait_for("the proxy to serve", || {
        TcpStream::connect(("127.0.0.1", port)).is_ok() && get(port, "/ready").0 == 200
    });
    (port, proxy)
}

#[test]
fn a_query_parameter_condition_matches_on_the_requests_query() {
    let (port, _proxy) = start();

    // The condition holds: the more specific route is served, and the query
    // string still reaches its backend.
    assert_eq!(
        get(port, "/api/items?version=v2"),
        (200, "queried /api/items?version=v2".into())
    );

    // The parameter is absent, or has another value: the catch-all is served.
    assert_eq!(get(port, "/api/items"), (200, "default /api/items".into()));
    assert_eq!(
        get(port, "/api/items?version=v1"),
        (200, "default /api/items?version=v1".into())
    );
    assert_eq!(
        get(port, "/api/items?other=v2"),
        (200, "default /api/items?other=v2".into())
    );
}

#[test]
fn a_query_parameter_condition_does_not_depend_on_where_the_parameter_sits() {
    let (port, _proxy) = start();

    // Other parameters before, after and around the one that matters.
    for target in [
        "/api/items?version=v2&page=1",
        "/api/items?page=1&version=v2",
        "/api/items?a=1&version=v2&b=2",
    ] {
        assert_eq!(
            get(port, target),
            (200, format!("queried {target}")),
            "{target}"
        );
    }
}

#[test]
fn a_query_parameter_is_percent_decoded_before_it_is_compared() {
    let (port, _proxy) = start();

    // `%32` is `2`, and `%76ersion` is `version`.
    for target in ["/api/items?version=v%32", "/api/items?%76ersion=v2"] {
        assert_eq!(
            get(port, target),
            (200, format!("queried {target}")),
            "{target}"
        );
    }
}

#[test]
fn a_condition_without_a_value_matches_when_the_parameter_is_present() {
    let (port, _proxy) = start();

    // Present, with a value, with an empty value, and with no `=` at all.
    for target in ["/flag?beta=1", "/flag?beta=", "/flag?beta"] {
        assert_eq!(
            get(port, target),
            (200, format!("queried {target}")),
            "{target}"
        );
    }
    // Absent.
    assert_eq!(get(port, "/flag"), (200, "default /flag".into()));
    assert_eq!(
        get(port, "/flag?alpha=1"),
        (200, "default /flag?alpha=1".into())
    );
}

#[test]
fn a_cached_route_decision_follows_the_query_of_each_request() {
    let (port, _proxy) = start();

    // The same path, alternating between a query that matches and one that
    // does not: a route remembered for one must not be served for the other.
    for round in 0..3 {
        assert_eq!(
            get(port, "/api/items?version=v2"),
            (200, "queried /api/items?version=v2".into()),
            "round {round}"
        );
        assert_eq!(
            get(port, "/api/items?version=v1"),
            (200, "default /api/items?version=v1".into()),
            "round {round}"
        );
    }
}

/// `a=b%3Dc` is the parameter `a` with the value `b=c`; `a%3Db=c` is the
/// parameter `a=b` with the value `c`. Decoded and written naively one after
/// the other, both read `a=b=c`, so a route remembered for one must not be
/// served for the other.
const VALUE_WITH_EQUALS: &str = "/encoded?a=b%3Dc";
const NAME_WITH_EQUALS: &str = "/encoded?a%3Db=c";

#[test]
fn a_cached_route_is_not_served_to_a_query_that_decodes_to_the_same_text() {
    let (port, _proxy) = start();

    // The query that satisfies the condition first, then the one that does not.
    for round in 0..2 {
        assert_eq!(
            get(port, VALUE_WITH_EQUALS),
            (200, format!("queried {VALUE_WITH_EQUALS}")),
            "round {round}"
        );
        assert_eq!(
            get(port, NAME_WITH_EQUALS),
            (200, format!("default {NAME_WITH_EQUALS}")),
            "round {round}"
        );
    }
}

#[test]
fn a_cached_fallthrough_is_not_served_to_a_query_that_decodes_to_the_same_text() {
    let (port, _proxy) = start();

    // The same two queries, in the other order: the one that does not satisfy
    // the condition is remembered first.
    for round in 0..2 {
        assert_eq!(
            get(port, NAME_WITH_EQUALS),
            (200, format!("default {NAME_WITH_EQUALS}")),
            "round {round}"
        );
        assert_eq!(
            get(port, VALUE_WITH_EQUALS),
            (200, format!("queried {VALUE_WITH_EQUALS}")),
            "round {round}"
        );
    }
}
