//! A broken stdout/stderr pipe must not stop SIGTERM from stopping the proxy.
//!
//! With output piped into a reader that has exited (`zentinel 2>&1 | head`
//! after `head` is done, or a dead log shipper), every log write fails with
//! EPIPE. tracing-subscriber reports a failed write with `eprintln!`, which
//! panics when stderr is broken too, so the thread that logged died. The
//! signal thread logs on SIGTERM, so it died before passing the signal on, and
//! the proxy kept running (#576).

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigterm_stops_the_proxy_when_its_output_pipe_is_closed() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("zentinel.kdl");
    std::fs::write(
        &config,
        r#"
system { worker-threads 1 }
listeners {
    listener "http" {
        // Port 0: the OS picks a free port, so parallel runs cannot clash.
        address "127.0.0.1:0"
        protocol "http"
    }
}
routes {
    route "default" {
        matches { path-prefix "/" }
        upstream "backend"
    }
}
upstreams {
    upstream "backend" {
        // Never connected to.
        target "127.0.0.1:9"
    }
}
observability {
    metrics { enabled #false }
}
"#,
    )
    .unwrap();

    // stdout and stderr share one pipe, as with `2>&1 |`.
    let (reader, writer) = std::io::pipe().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-c")
        .arg(&config)
        .stdout(Stdio::from(writer.try_clone().unwrap()))
        .stderr(Stdio::from(writer))
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;

    // Read until the shutdown signal handlers are installed, then close the
    // pipe. Every later log write fails with EPIPE.
    let mut log = Vec::new();
    let mut ready = false;
    for line in BufReader::new(reader).lines() {
        let Ok(line) = line else { break };
        ready = line.contains("Graceful shutdown enabled");
        log.push(line);
        if ready {
            break;
        }
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!(
            "the proxy did not finish starting; log:\n{}",
            log.join("\n")
        );
    }

    // Let the proxy hit the broken pipe before the signal arrives.
    std::thread::sleep(Duration::from_millis(500));
    // SAFETY: plain kill(2) on our own child's pid.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        status.is_some(),
        "the proxy was still running 20s after SIGTERM with its output pipe closed"
    );
}
