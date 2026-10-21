//! A daemon must answer SIGHUP and SIGTERM like a proxy in the foreground.
//!
//! Pingora used to fork inside `run_forever`, after the proxy had started its
//! runtime and the thread that reads signals. A fork keeps only the calling
//! thread, so the daemon reloaded nothing on SIGHUP and ignored SIGTERM until
//! Pingora's own 300-second grace period ran out (#573).
//!
//! Each test starts the binary in daemon mode -- with `-d`, or with
//! `system { daemon #true }` -- and checks the effect of each signal on the
//! process named by the pid file. The daemon keeps the launcher's stdout and
//! stderr, so both go to a file the test can read once the launcher is gone.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A port the OS has just handed out and that is free again.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(port: u16, pid_file: &Path, path: &str, daemon_in_config: bool) -> String {
    format!(
        r#"
system {{
    worker-threads 1
    daemon {daemon}
    pid-file "{pid_file}"
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
routes {{
    route "probe" {{
        matches {{ path "{path}"; }}
        builtin-handler "health"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#,
        daemon = if daemon_in_config { "#true" } else { "#false" },
        pid_file = pid_file.display(),
    )
}

/// The status of `GET path`, or 0 if nothing answered.
fn status(port: u16, path: &str) -> u16 {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return 0;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    if write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
    )
    .is_err()
    {
        return 0;
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn read_pid(pid_file: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

/// Kills the daemon, whatever happens to the test.
struct Daemon {
    pid_file: PathBuf,
    log: PathBuf,
}

impl Daemon {
    fn pid(&self) -> libc::pid_t {
        read_pid(&self.pid_file).expect("the pid file names a process")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: plain kill(2) on the daemon's pid.
        assert_eq!(unsafe { libc::kill(self.pid(), signal) }, 0);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(pid) = read_pid(&self.pid_file) {
            // SAFETY: plain kill(2) on the daemon's pid.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// Start the proxy as a daemon. Returns once the launcher has exited and the
/// daemon serves `/v1`.
fn start_daemon(dir: &Path, cli_flag: bool) -> (Daemon, PathBuf, u16) {
    let port = free_port();
    let pid_file = dir.join("zentinel.pid");
    let config_path = dir.join("zentinel.kdl");
    std::fs::write(&config_path, config(port, &pid_file, "/v1", !cli_flag)).unwrap();

    let log = dir.join("daemon.log");
    let out = std::fs::File::create(&log).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_zentinel"));
    if cli_flag {
        command.arg("-d");
    }
    let mut launcher = command
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::from(out))
        .spawn()
        .unwrap();
    let daemon = Daemon {
        pid_file: pid_file.clone(),
        log,
    };

    let mut exit = None;
    wait_until(Duration::from_secs(20), || {
        exit = launcher.try_wait().unwrap();
        exit.is_some()
    });
    let Some(exit) = exit else {
        let _ = launcher.kill();
        let _ = launcher.wait();
        panic!(
            "the launcher did not exit; is it daemonizing at all? log:\n{}",
            daemon.log()
        );
    };
    assert!(
        exit.success(),
        "launcher exited with {exit}; log:\n{}",
        daemon.log()
    );

    assert!(
        wait_until(Duration::from_secs(20), || read_pid(&pid_file)
            .is_some_and(alive)),
        "the pid file does not name a live process; log:\n{}",
        daemon.log()
    );
    assert_ne!(
        daemon.pid() as u32,
        launcher.id(),
        "the daemon is a new process"
    );
    assert!(
        wait_until(Duration::from_secs(30), || status(port, "/v1") == 200),
        "the daemon does not serve /v1; log:\n{}",
        daemon.log()
    );
    (daemon, config_path, port)
}

fn signals_work_in_the_daemon(cli_flag: bool) {
    let dir = tempfile::tempdir().unwrap();
    let (daemon, config_path, port) = start_daemon(dir.path(), cli_flag);
    let pid = daemon.pid();

    // SIGHUP: the changed route is served.
    std::fs::write(
        &config_path,
        config(port, &daemon.pid_file, "/v2", !cli_flag),
    )
    .unwrap();
    daemon.signal(libc::SIGHUP);
    assert!(
        wait_until(Duration::from_secs(15), || status(port, "/v2") == 200
            && status(port, "/v1") == 404),
        "SIGHUP did not reload the daemon's configuration; log:\n{}",
        daemon.log()
    );
    assert!(daemon.log().contains("Configuration reloaded successfully"));

    // SIGTERM: the daemon exits, without waiting out Pingora's grace period.
    daemon.signal(libc::SIGTERM);
    assert!(
        wait_until(Duration::from_secs(5), || !alive(pid)),
        "the daemon is still running 5s after SIGTERM; log:\n{}",
        daemon.log()
    );
}

#[test]
fn daemon_from_the_command_line_answers_signals() {
    signals_work_in_the_daemon(true);
}

#[test]
fn daemon_from_the_config_answers_signals() {
    signals_work_in_the_daemon(false);
}

/// A configuration that does not load is reported by the command that was
/// run, not by a daemon nobody is watching.
#[test]
fn broken_config_fails_in_the_foreground() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("zentinel.kdl");
    std::fs::write(&config_path, "listeners {\n").unwrap();

    let mut launcher = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("-d")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut exit = None;
    wait_until(Duration::from_secs(20), || {
        exit = launcher.try_wait().unwrap();
        exit.is_some()
    });
    let Some(exit) = exit else {
        let _ = launcher.kill();
        let _ = launcher.wait();
        panic!("the launcher kept running with a broken configuration");
    };
    let mut stderr = String::new();
    launcher
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();

    assert!(!exit.success(), "a broken configuration exited {exit}");
    assert!(
        stderr.contains("Failed to load configuration file"),
        "stderr: {stderr}"
    );
}
