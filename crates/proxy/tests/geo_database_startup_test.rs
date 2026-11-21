//! A geo filter whose database cannot be opened stops startup.
//!
//! The filter is only registered once its database is open. A filter that
//! failed to register used to be logged and skipped, and startup went on
//! without it. Startup now fails instead, and says which filter and which
//! file. `zentinel test` and `zentinel validate` open the same databases, so a
//! configuration that passes them does not stop startup on one.

#![cfg(unix)]

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A port the OS had free a moment ago. The proxy is expected to exit before it
/// binds anything, so a clash would not change the outcome.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

/// A configuration with two geo filters whose databases do not exist, written
/// into `dir`. Returns its path, the listener port, and the two database paths.
fn write_config(dir: &Path) -> (PathBuf, u16, [PathBuf; 2]) {
    let databases = [
        dir.join("missing-country.mmdb"),
        dir.join("missing-city.mmdb"),
    ];
    let config = dir.join("zentinel.kdl");
    let listener_port = free_port();
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{listener_port}"
        protocol "http"
    }}
}}
filters {{
    filter "region-block" {{
        type "geo"
        database-path "{country}"
        action "block"
        countries "RU" "CN"
    }}
    filter "city-allow" {{
        type "geo"
        database-path "{city}"
        action "allow"
        countries "US"
    }}
}}
routes {{
    route "default" {{
        matches {{ path-prefix "/" }}
        upstream "backend"
        filters "region-block"
    }}
}}
upstreams {{
    upstream "backend" {{
        // Never connected to: the proxy is not expected to get this far.
        target "127.0.0.1:{backend_port}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            country = databases[0].display(),
            city = databases[1].display(),
            backend_port = free_port(),
        ),
    )
    .unwrap();
    (config, listener_port, databases)
}

/// What is expected in the output when databases are missing: both filters and
/// both files, and the filters in the order of their ids.
fn assert_names_both_filters(output: &str, databases: &[PathBuf; 2]) {
    for expected in [
        "region-block",
        "city-allow",
        &databases[0].display().to_string(),
        &databases[1].display().to_string(),
    ] {
        assert!(
            output.contains(expected),
            "the error does not mention {expected}; {output}"
        );
    }
    let listing = &output[output
        .find("cannot be used")
        .expect("the error lists the filters")..];
    assert!(
        listing.find("city-allow") < listing.find("region-block"),
        "the filters are not listed in the order of their ids; {output}"
    );
}

/// Run `zentinel <args>`, which is expected to finish on its own, and return
/// whether it succeeded with everything it printed.
fn run_to_completion(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.success(),
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn a_geo_filter_whose_database_is_missing_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let (config, listener_port, databases) = write_config(dir.path());

    let stdout_path = dir.path().join("stdout.log");
    let stderr_path = dir.path().join("stderr.log");
    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();

    // Wait for the process to exit, or for the listener to come up, which
    // means startup went on without the filter.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut exited = false;
    let mut listening = false;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        if TcpStream::connect(("127.0.0.1", listener_port)).is_ok() {
            listening = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // A no-op for a process that has exited; `wait` then returns its status.
    let _ = child.kill();
    let status = child.wait().unwrap();

    let output = format!(
        "stdout:\n{}\nstderr:\n{}",
        std::fs::read_to_string(&stdout_path).unwrap_or_default(),
        std::fs::read_to_string(&stderr_path).unwrap_or_default()
    );

    assert!(
        !listening,
        "the proxy started listening although the databases of its geo filters are missing; {output}"
    );
    assert!(
        exited,
        "the proxy neither exited nor listened within 30s; {output}"
    );
    assert!(
        !status.success(),
        "the proxy exited with {status} although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}

#[test]
fn test_fails_for_a_geo_filter_whose_database_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _, databases) = write_config(dir.path());

    let (success, output) = run_to_completion(&["test", "-c", config.to_str().unwrap()]);

    assert!(
        !success,
        "`zentinel test` passed although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}

#[test]
fn validate_fails_for_a_geo_filter_whose_database_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (config, _, databases) = write_config(dir.path());

    let (success, output) = run_to_completion(&[
        "validate",
        "-c",
        config.to_str().unwrap(),
        "--skip-network",
        "--skip-agents",
        "--skip-certs",
    ]);

    assert!(
        !success,
        "`zentinel validate` passed although a geo database is missing; {output}"
    );
    assert_names_both_filters(&output, &databases);
}
