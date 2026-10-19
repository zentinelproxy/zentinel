//! A SIGHUP that arrives while the proxy is still starting must not kill it.
//!
//! SIGHUP terminates a process by default, and the reload handler is only
//! installed once the configuration is loaded and the proxy built. A deploy
//! script that reloads right after starting the proxy used to kill it instead.
//!
//! The signal is sent as soon as the proxy prints its first log line, which
//! is after SIGHUP is taken over but well before the rest of startup is done.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// A free port from a small fixed range, so the test stays clear of ports
/// other local services are likely to use.
fn free_port() -> u16 {
    (19940..19950)
        .find(|&port| std::net::TcpListener::bind(("127.0.0.1", port)).is_ok())
        .expect("a free port in 19940..19950")
}

#[test]
fn sighup_during_startup_is_applied_once_ready() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        format!(
            r#"
system {{ worker-threads 1 }}
listeners {{
    listener "http" {{
        address "127.0.0.1:{}"
        protocol "http"
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
        target "127.0.0.1:{}"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
            free_port(),
            // Never connected to: only the listener is bound.
            19949
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;

    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut sent = false;
    let mut reloaded = false;
    let mut log = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                if !sent {
                    // SAFETY: plain kill(2) on our own child's pid.
                    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
                    sent = true;
                }
                reloaded |= line.contains("Configuration reloaded successfully");
                log.push(line);
                if reloaded {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    let status = child.try_wait().unwrap();
    let _ = child.kill();
    let _ = child.wait();

    assert!(sent, "the proxy never logged anything");
    assert!(
        status.is_none(),
        "the proxy exited ({status:?}) after an early SIGHUP; log:\n{}",
        log.join("\n")
    );
    assert!(
        reloaded,
        "an early SIGHUP was not applied once the proxy was ready; log:\n{}",
        log.join("\n")
    );
}
