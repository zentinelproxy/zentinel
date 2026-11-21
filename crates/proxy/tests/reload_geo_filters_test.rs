//! A reload brings the geo filters up to date with the new configuration.
//!
//! The geo filters were registered once, at startup. A filter a reload added
//! was never registered, so it did not apply to the routes naming it; a filter
//! whose `countries`, `action` or database a reload changed kept its old
//! settings; and a reload naming a database that does not open was accepted.
//! This runs the real binary over HTTP, with databases written by the test,
//! and reloads with SIGHUP.
//!
//! The client is always `127.0.0.1`. Each database says that every IPv4
//! address is in one country, so a filter's verdict on the client follows from
//! its `countries` and the database it names.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The proxy's port is released just before it binds it, so the tests run one
/// at a time.
static SERIAL: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// A MaxMind database file
// ---------------------------------------------------------------------------

fn string(s: &str) -> Vec<u8> {
    assert!(s.len() < 29);
    let mut out = vec![0x40 | s.len() as u8];
    out.extend_from_slice(s.as_bytes());
    out
}

fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    assert!(entries.len() < 29);
    let mut out = vec![0xE0 | entries.len() as u8];
    for (key, value) in entries {
        out.extend(string(key));
        out.extend_from_slice(value);
    }
    out
}

fn uint16(n: u16) -> Vec<u8> {
    let mut out = vec![0xA2];
    out.extend_from_slice(&n.to_be_bytes());
    out
}

fn uint32(n: u32) -> Vec<u8> {
    let mut out = vec![0xC4];
    out.extend_from_slice(&n.to_be_bytes());
    out
}

/// An extended type: the control byte carries the size, the next byte the
/// type minus 7.
fn uint64(n: u64) -> Vec<u8> {
    let mut out = vec![0x08, 0x02];
    out.extend_from_slice(&n.to_be_bytes());
    out
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
    assert!(items.len() < 29);
    let mut out = vec![items.len() as u8, 0x04];
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A database that says every IPv4 address is in `country`.
///
/// Its search tree is one node whose two records both point at the one record
/// of the data section.
fn country_database(country: &str) -> Vec<u8> {
    const NODE_COUNT: u32 = 1;
    // A record past the node count points into the data section, after the
    // 16 bytes that separate the two.
    let record = (NODE_COUNT + 16).to_be_bytes();

    let mut file = Vec::new();
    file.extend_from_slice(&record[1..]);
    file.extend_from_slice(&record[1..]);
    file.extend_from_slice(&[0; 16]);
    file.extend(map(&[("country", map(&[("iso_code", string(country))]))]));
    file.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
    file.extend(map(&[
        ("binary_format_major_version", uint16(2)),
        ("binary_format_minor_version", uint16(0)),
        ("build_epoch", uint64(1_700_000_000)),
        ("database_type", string("Test-Country")),
        ("description", map(&[])),
        ("ip_version", uint16(4)),
        ("languages", array(&[string("en")])),
        ("node_count", uint32(NODE_COUNT)),
        ("record_size", uint16(24)),
    ]));
    file
}

fn write_database(dir: &Path, name: &str, country: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, country_database(country)).unwrap();
    path
}

#[test]
fn the_test_database_says_every_ipv4_address_is_in_its_country() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_database(dir.path(), "country.mmdb", "US");

    let reader = maxminddb::Reader::open_readfile(&path).expect("the database opens");
    for ip in ["127.0.0.1", "10.20.30.40", "203.0.113.7"] {
        let record = reader
            .lookup(ip.parse().unwrap())
            .unwrap()
            .decode::<maxminddb::geoip2::Country>()
            .unwrap()
            .expect("the address has a record");
        assert_eq!(record.country.iso_code, Some("US"), "{ip}");
    }
}

// ---------------------------------------------------------------------------
// The proxy under test
// ---------------------------------------------------------------------------

/// `n` listeners on ports the OS picked, kept bound.
fn free_ports(n: usize) -> Vec<TcpListener> {
    (0..n)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)).expect("bind"))
        .collect()
}

/// A backend answering 200 `ok` to every request.
fn backend(listener: TcpListener) -> u16 {
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                while reader.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                );
            });
        }
    });
    port
}

/// `GET /` on `port`: the status, or 0 when there is no answer.
fn get(port: u16) -> u16 {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let _ = write!(
        stream,
        "GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    );
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

struct Proxy {
    child: Child,
    /// Everything the proxy printed.
    log: Arc<Mutex<Vec<String>>>,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Proxy {
    fn sighup(&self) {
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGHUP) },
            0
        );
    }

    fn log(&self) -> String {
        self.log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .join("\n")
    }
}

/// Collect the lines of `stream` into `log` until it closes, so the proxy
/// never blocks on a full pipe.
fn collect(stream: impl Read + Send + 'static, log: &Arc<Mutex<Vec<String>>>) {
    let log = Arc::clone(log);
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            log.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);
        }
    });
}

fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

fn start(path: &Path, listen: u16) -> Proxy {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    collect(child.stdout.take().unwrap(), &log);
    collect(child.stderr.take().unwrap(), &log);
    let proxy = Proxy { child, log };
    wait_for("the proxy to serve", || {
        TcpStream::connect(("127.0.0.1", listen)).is_ok()
    });
    proxy
}

/// The geo filter `region`, as the configuration declares it.
struct Geo<'a> {
    database: &'a Path,
    action: &'a str,
    countries: &'a str,
}

/// A configuration with one route to the backend, which names the geo filter
/// `region` when there is one.
fn config(listen: u16, backend: u16, geo: Option<&Geo>) -> String {
    let (filters, route_filters) = match geo {
        Some(Geo {
            database,
            action,
            countries,
        }) => (
            format!(
                r#"filters {{
    filter "region" {{
        type "geo"
        database-path "{database}"
        action "{action}"
        countries {countries}
        on-failure "closed"
    }}
}}"#,
                database = database.display()
            ),
            r#"filters "region""#,
        ),
        None => (String::new(), ""),
    };
    format!(
        r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{ address "127.0.0.1:{listen}"; protocol "http"; }}
}}
{filters}
upstreams {{
    upstream "app" {{ target "127.0.0.1:{backend}"; }}
}}
routes {{
    route "app" {{
        matches {{ path-prefix "/"; }}
        upstream "app"
        {route_filters}
    }}
}}
observability {{
    metrics {{ enabled #false; }}
}}
"#
    )
}

/// Rewrite the configuration and SIGHUP.
fn reload(proxy: &Proxy, path: &Path, new_config: &str) {
    std::fs::write(path, new_config).unwrap();
    proxy.sighup();
}

#[test]
fn a_reload_applies_added_and_changed_geo_filters() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ports = free_ports(2);
    let backend = backend(ports.pop().unwrap());
    let listen = ports.pop().unwrap().local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let us = write_database(dir.path(), "us.mmdb", "US");
    let de = write_database(dir.path(), "de.mmdb", "DE");

    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, config(listen, backend, None)).unwrap();
    let proxy = start(&path, listen);
    assert_eq!(get(listen), 200, "no filter yet");

    // The reload adds the filter, and its route's `filters`: the database
    // says the client is in the US, which the filter blocks.
    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &us,
                action: "block",
                countries: r#""US""#,
            }),
        ),
    );
    wait_for("the filter added by the reload to block the client", || {
        get(listen) == 403
    });

    // The same filter, now blocking another country: the client passes.
    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &us,
                action: "block",
                countries: r#""DE""#,
            }),
        ),
    );
    wait_for("the changed countries to let the client through", || {
        get(listen) == 200
    });

    // The same countries on another database, which says the client is in
    // Germany: blocked again.
    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &de,
                action: "block",
                countries: r#""DE""#,
            }),
        ),
    );
    wait_for("the changed database to block the client", || {
        get(listen) == 403
    });

    // The same filter as an allowlist of the country the database says: the
    // client passes.
    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &de,
                action: "allow",
                countries: r#""DE""#,
            }),
        ),
    );
    wait_for("the changed action to let the client through", || {
        get(listen) == 200
    });

    assert_eq!(get(listen), 200, "{}", proxy.log());
}

#[test]
fn a_reload_naming_a_geo_database_that_does_not_open_is_rejected() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut ports = free_ports(2);
    let backend = backend(ports.pop().unwrap());
    let listen = ports.pop().unwrap().local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let us = write_database(dir.path(), "us.mmdb", "US");
    let missing = dir.path().join("missing-country.mmdb");

    let path = dir.path().join("zentinel.kdl");
    std::fs::write(
        &path,
        config(
            listen,
            backend,
            Some(&Geo {
                database: &us,
                action: "block",
                countries: r#""US""#,
            }),
        ),
    )
    .unwrap();
    let proxy = start(&path, listen);
    assert_eq!(get(listen), 403, "the filter blocks the client");

    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &missing,
                action: "block",
                countries: r#""DE""#,
            }),
        ),
    );
    wait_for("the reload to be rejected or applied", || {
        let log = proxy.log();
        log.contains("REJECTED") || log.contains("Configuration reload completed successfully")
    });
    let log = proxy.log();
    assert!(
        !log.contains("Configuration reload completed successfully"),
        "a reload naming a database that does not open was applied; log:\n{log}"
    );
    // Neither is in the log before the reload: the startup lines say
    // `filter_id=region`, and the file does not appear in the configuration
    // the proxy started with.
    for expected in ["filter 'region'", &missing.display().to_string()] {
        assert!(
            log.contains(expected),
            "the rejection does not mention {expected}; log:\n{log}"
        );
    }
    assert_eq!(
        get(listen),
        403,
        "the proxy did not keep serving the previous configuration"
    );

    // A reload with a database that opens is applied afterwards.
    reload(
        &proxy,
        &path,
        &config(
            listen,
            backend,
            Some(&Geo {
                database: &us,
                action: "log-only",
                countries: r#""US""#,
            }),
        ),
    );
    wait_for("the next reload to be applied", || get(listen) == 200);
}
