//! Namespace and service routes are served, end to end (#548).
//!
//! Until #548 a service's routes were served on no listener at all, a
//! namespace's only on a top-level listener bound to it with `namespace`, and
//! a route naming its namespace's own upstream got `500 "Upstream pool not
//! found"`. This runs the real binary against local backends and checks, over
//! HTTP, which listener serves which route and which backend answers, before
//! and after a SIGHUP.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Ports this test may use. The proxy's listeners need fixed ports, and the
/// backends take theirs from the same small range.
const PORTS: std::ops::Range<u16> = 19480..19500;

/// Bind `n` free ports from [`PORTS`], keeping the listeners bound.
fn bind_ports(n: usize) -> Vec<TcpListener> {
    let found: Vec<TcpListener> = PORTS
        .filter_map(|port| TcpListener::bind(("127.0.0.1", port)).ok())
        .take(n)
        .collect();
    assert_eq!(found.len(), n, "{n} free ports in {PORTS:?}");
    found
}

/// A backend answering every request with `<name> <path>`.
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
                let path = request_line.split(' ').nth(1).unwrap_or("?");
                let body = format!("{name} {path}");
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

/// `GET path` on `port`: the status and the body.
fn get(port: u16, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
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

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(public: u16, internal: u16, pay: u16, b: &Backends, api_prefix: &str) -> String {
    format!(
        r#"
system {{ worker-threads 1 }}
listeners {{
    listener "public" {{ address "127.0.0.1:{public}"; protocol "http"; }}
    listener "internal" {{ address "127.0.0.1:{internal}"; protocol "http"; namespace "internal"; }}
}}
upstreams {{
    upstream "shared" {{ target "127.0.0.1:{shared}"; }}
}}
routes {{
    route "health" {{
        priority "critical"
        matches {{ path "/health"; }}
        builtin-handler "health"
    }}
    route "global" {{
        matches {{ path-prefix "/global"; }}
        upstream "shared"
    }}
}}
namespace "api" {{
    upstreams {{
        upstream "backend" {{ target "127.0.0.1:{api}"; }}
    }}
    routes {{
        route "main" {{
            matches {{ path-prefix "{api_prefix}"; }}
            upstream "backend"
        }}
        route "auth" {{
            matches {{ path-prefix "/auth/"; }}
            upstream "shared"
        }}
    }}
    service "users" {{
        upstreams {{
            upstream "backend" {{ target "127.0.0.1:{users}"; }}
        }}
        routes {{
            route "list" {{
                matches {{ path-prefix "/users/"; }}
                upstream "backend"
            }}
        }}
    }}
    service "pay" {{
        listener {{
            id "pay-http"
            address "127.0.0.1:{pay}"
            protocol "http"
        }}
        upstreams {{
            upstream "backend" {{ target "127.0.0.1:{pay_backend}"; }}
        }}
        routes {{
            route "checkout" {{
                matches {{ path-prefix "/"; }}
                upstream "backend"
            }}
        }}
    }}
}}
namespace "internal" {{
    upstreams {{
        upstream "backend" {{ target "127.0.0.1:{internal_backend}"; }}
    }}
    routes {{
        route "secret" {{
            matches {{ path-prefix "/"; }}
            upstream "backend"
        }}
    }}
}}
observability {{
    metrics {{ enabled #false; }}
}}
"#,
        shared = b.shared,
        api = b.api,
        users = b.users,
        pay_backend = b.pay,
        internal_backend = b.internal,
    )
}

struct Backends {
    shared: u16,
    api: u16,
    users: u16,
    pay: u16,
    internal: u16,
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

#[test]
fn namespace_and_service_routes_are_served_on_the_right_listeners() {
    let mut ports = bind_ports(8);
    let b = Backends {
        shared: backend(ports.pop().unwrap(), "shared"),
        api: backend(ports.pop().unwrap(), "api"),
        users: backend(ports.pop().unwrap(), "users"),
        pay: backend(ports.pop().unwrap(), "pay"),
        internal: backend(ports.pop().unwrap(), "internal"),
    };
    // The proxy's own ports: released just before it binds them.
    let proxy_ports: Vec<u16> = ports
        .drain(..)
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    let (public, internal, pay) = (proxy_ports[0], proxy_ports[1], proxy_ports[2]);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(public, internal, pay, &b, "/api/")).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let proxy = Proxy(child);
    wait_for("the proxy to serve", || {
        TcpStream::connect(("127.0.0.1", public)).is_ok()
            && TcpStream::connect(("127.0.0.1", pay)).is_ok()
            && get(public, "/health").0 == 200
    });

    // The global listener serves the global routes, and the routes of the
    // namespace and service that have no listener of their own. Each route
    // reaches the upstream its scope resolves: the namespace's own, the
    // service's (shadowing the namespace's of the same name), or a global one.
    assert_eq!(get(public, "/global/1"), (200, "shared /global/1".into()));
    assert_eq!(get(public, "/api/1"), (200, "api /api/1".into()));
    assert_eq!(get(public, "/users/7"), (200, "users /users/7".into()));
    assert_eq!(get(public, "/auth/x"), (200, "shared /auth/x".into()));
    // Neither a namespace bound to its own listener nor a service with one
    // is served on the global listener.
    assert_eq!(get(public, "/anything").0, 404);

    // The service's own listener serves only the service's routes.
    assert_eq!(get(pay, "/api/1"), (200, "pay /api/1".into()));
    assert_eq!(get(pay, "/health"), (200, "pay /health".into()));

    // A top-level listener bound with `namespace` serves that namespace, with
    // its namespace-local upstream (this was a 500 before #548).
    assert_eq!(get(internal, "/api/1"), (200, "internal /api/1".into()));

    // SIGHUP rebuilds the scoped routes.
    std::fs::write(&path, config(public, internal, pay, &b, "/v2/")).unwrap();
    // SAFETY: plain kill(2) on our own child's pid.
    assert_eq!(
        unsafe { libc::kill(proxy.0.id() as libc::pid_t, libc::SIGHUP) },
        0
    );
    wait_for("the reloaded namespace route", || {
        get(public, "/v2/1") == (200, "api /v2/1".into())
    });
    assert_eq!(get(public, "/api/1").0, 404);
    assert_eq!(get(public, "/users/7"), (200, "users /users/7".into()));
}
