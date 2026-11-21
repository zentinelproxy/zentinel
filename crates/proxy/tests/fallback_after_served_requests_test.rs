//! A route falls back when every target of its upstream fails its health
//! check, whether or not the upstream has answered requests before.
//!
//! `has_healthy_targets` reads the load balancer's table of per-target
//! health. A request the upstream had answered used to add a row to that table
//! under the upstream's id instead of a target's address, a row no health check
//! ever sets to unhealthy. From then on the table always held a healthy row, so
//! a route with an `on-health-failure` fallback kept its primary upstream while
//! all of its targets failed their checks, and the client got a 503.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A backend that answers `GET /health` with 200 while `healthy` is set and
/// with 503 otherwise, and every other request with 200 and `name` as the body.
struct Backend {
    port: u16,
    healthy: Arc<AtomicBool>,
    /// Requests other than `GET /health` it has answered.
    served: Arc<AtomicUsize>,
}

fn spawn_backend(name: &'static str) -> Backend {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let healthy = Arc::new(AtomicBool::new(true));
    let served = Arc::new(AtomicUsize::new(0));
    let (healthy_flag, served_counter) = (healthy.clone(), served.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (healthy_flag, served_counter) = (healthy_flag.clone(), served_counter.clone());
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                let probe = line.starts_with("GET /health ");
                loop {
                    line.clear();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let (status, body) = if probe {
                    if healthy_flag.load(Ordering::SeqCst) {
                        ("200 OK", "ok")
                    } else {
                        ("503 Service Unavailable", "down")
                    }
                } else {
                    served_counter.fetch_add(1, Ordering::SeqCst);
                    ("200 OK", name)
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
        }
    });
    Backend {
        port,
        healthy,
        served,
    }
}

struct Proxy {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Proxy {
    fn start(dir: &Path, port: u16, config: &str) -> Proxy {
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
        let proxy = Proxy { child, port, log };
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(Instant::now() < deadline, "the proxy never listened");
            std::thread::sleep(Duration::from_millis(100));
        }
        proxy
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn get(port: u16) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET /item HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    (status, body.to_string())
}

fn config(port: u16, primary: u16, standby: u16) -> String {
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
    upstream "primary" {{
        target "127.0.0.1:{primary}"
        health-check {{
            type "http" {{
                path "/health"
            }}
            interval-secs 1
            timeout-secs 1
            healthy-threshold 1
            unhealthy-threshold 1
        }}
    }}
    upstream "standby" {{
        target "127.0.0.1:{standby}"
    }}
}}
routes {{
    route "all" {{
        matches {{ path-prefix "/" }}
        upstream "primary"
        fallback {{
            triggers {{
                on-health-failure #true
            }}
            fallback-upstream "standby" {{
            }}
        }}
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

#[test]
fn a_route_falls_back_once_every_target_fails_its_health_check() {
    let dir = tempfile::tempdir().unwrap();
    let primary = spawn_backend("primary");
    let standby = spawn_backend("standby");
    let port = free_port();
    let proxy = Proxy::start(dir.path(), port, &config(port, primary.port, standby.port));

    // The primary answers, so the upstream has served requests by the time
    // its targets start failing their checks.
    for _ in 0..3 {
        let (status, body) = get(proxy.port);
        assert_eq!(
            (status, body.as_str()),
            (200, "primary"),
            "log:\n{}",
            proxy.log()
        );
    }
    assert!(primary.served.load(Ordering::SeqCst) >= 3);

    primary.healthy.store(false, Ordering::SeqCst);

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let last = get(proxy.port);
        if last == (200, "standby".to_string()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the route never fell back to the standby after the primary failed its \
             health check; last answer {last:?}; log:\n{}",
            proxy.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(standby.served.load(Ordering::SeqCst) >= 1);
}
