//! A configuration path that was given must name a configuration that loads.
//!
//! The path comes from `--config` or `ZENTINEL_CONFIG`. When nothing existed
//! there, the proxy wrote the embedded default configuration to that path and
//! started with it, and when the write failed it started with the embedded
//! default anyway. A mistyped path therefore started a proxy with a
//! configuration the operator never wrote.
//!
//! The proxy now stops with a non-zero exit code and an error that names the
//! path and the reason, and it creates nothing. Giving no path at all is
//! unchanged: that still starts with the embedded default.
//!
//! Each test runs the real binary. A proxy that keeps running instead of
//! stopping is killed as soon as something appears at a path that must stay
//! empty, or when the refusal deadline passes.
//!
//! A binary without the change does not stop: it listens on the embedded
//! default configuration's ports (`0.0.0.0:8080` and `0.0.0.0:9090`) until it
//! is killed. That is why the refusal deadline is short. With the change a
//! refusal takes a few milliseconds.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs::{File, Permissions};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// How long a refusal may take before it counts as "did not stop".
const REFUSAL_DEADLINE: Duration = Duration::from_secs(10);

/// How long a proxy that should start may take to listen. Longer than a
/// refusal: this one has to bring up a listener, and the machine may be busy.
const STARTUP_DEADLINE: Duration = Duration::from_secs(20);

/// What a run of the binary left behind.
struct Run {
    /// `None` when the proxy had to be killed: it was still running at the
    /// deadline, or something had appeared at a watched path.
    status: Option<ExitStatus>,
    /// Standard output and standard error, in one stream.
    output: String,
}

/// Run the binary with `args`, with `ZENTINEL_CONFIG` set to `env_config` or
/// removed, and stop it early if any path in `watch` comes into existence.
fn run_zentinel(args: &[&OsStr], env_config: Option<&Path>, watch: &[&Path]) -> Run {
    let scratch = tempfile::tempdir().unwrap();
    let output_path = scratch.path().join("output.log");
    let output_file = File::create(&output_path).unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_zentinel"));
    command
        .args(args)
        .env_remove("ZENTINEL_CONFIG")
        .stdin(Stdio::null())
        .stdout(output_file.try_clone().unwrap())
        .stderr(output_file);
    if let Some(path) = env_config {
        command.env("ZENTINEL_CONFIG", path);
    }
    let mut child = command.spawn().unwrap();

    let deadline = Instant::now() + REFUSAL_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if watch.iter().any(|path| path.exists()) || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    Run {
        status,
        output: std::fs::read_to_string(&output_path).unwrap_or_default(),
    }
}

/// The run stopped with a failure whose message contains `named` and `reason`.
fn assert_refused(run: &Run, named: &str, reason: &str) {
    let Some(status) = run.status else {
        panic!(
            "the proxy did not stop; it was still running, or had created \
             something, when it was killed. output:\n{}",
            run.output
        );
    };
    assert!(
        !status.success(),
        "the proxy exited with {status:?}; output:\n{}",
        run.output
    );
    assert!(
        run.output.contains(named),
        "the error does not contain {named:?}; output:\n{}",
        run.output
    );
    assert!(
        run.output.contains(reason),
        "the error does not give the reason {reason:?}; output:\n{}",
        run.output
    );
}

/// `assert_refused` for an error that names `path`.
fn assert_refused_path(run: &Run, path: &Path, reason: &str) {
    assert_refused(run, path.to_str().unwrap(), reason);
}

const NO_SUCH_FILE: &str = "No such file or directory";

#[test]
fn config_path_from_the_command_line_that_does_not_exist_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.kdl");

    let run = run_zentinel(&["--config".as_ref(), path.as_os_str()], None, &[&path]);

    assert_refused_path(&run, &path, NO_SUCH_FILE);
    assert!(!path.exists(), "a file was created at {}", path.display());
}

#[test]
fn config_path_from_the_environment_that_does_not_exist_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.kdl");

    let run = run_zentinel(&[], Some(&path), &[&path]);

    assert_refused_path(&run, &path, NO_SUCH_FILE);
    assert!(!path.exists(), "a file was created at {}", path.display());
}

#[test]
fn empty_config_path_from_the_environment_stops_startup() {
    // `ZENTINEL_CONFIG=` is what a Compose `${VAR:-}` or an `env` file line
    // with no value produces. It is a path, and an empty one names nothing.
    let run = run_zentinel(&[], Some(Path::new("")), &[]);

    assert_refused(&run, "configuration file ''", NO_SUCH_FILE);
}

#[test]
fn run_subcommand_with_a_config_path_that_does_not_exist_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.kdl");

    let run = run_zentinel(
        &["run".as_ref(), "--config".as_ref(), path.as_os_str()],
        None,
        &[&path],
    );

    assert_refused_path(&run, &path, NO_SUCH_FILE);
    assert!(!path.exists(), "a file was created at {}", path.display());
}

#[test]
fn directories_above_a_missing_config_path_are_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let missing_dir = dir.path().join("etc").join("zentinel");
    let path = missing_dir.join("zentinel.kdl");

    let run = run_zentinel(
        &["--config".as_ref(), path.as_os_str()],
        None,
        &[&missing_dir],
    );

    assert_refused_path(&run, &path, NO_SUCH_FILE);
    assert!(
        !dir.path().join("etc").exists(),
        "directories were created for {}",
        path.display()
    );
}

#[test]
fn config_path_that_is_a_dangling_symlink_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.kdl");
    let link = dir.path().join("zentinel.kdl");
    symlink(&target, &link).unwrap();

    let run = run_zentinel(&["--config".as_ref(), link.as_os_str()], None, &[&target]);

    assert_refused_path(&run, &link, NO_SUCH_FILE);
    assert!(
        !target.exists(),
        "a file was created through the symlink at {}",
        target.display()
    );
}

#[test]
fn config_check_subcommands_report_a_config_path_that_does_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("absent.kdl");

    for args in [
        vec!["test".as_ref(), "--config".as_ref(), path.as_os_str()],
        vec!["validate".as_ref(), "--config".as_ref(), path.as_os_str()],
        vec!["lint".as_ref(), "--config".as_ref(), path.as_os_str()],
        vec!["--test".as_ref(), "--config".as_ref(), path.as_os_str()],
    ] {
        let run = run_zentinel(&args, None, &[&path]);

        assert_refused_path(&run, &path, NO_SUCH_FILE);
        assert!(
            !path.exists(),
            "{args:?} created a file at {}",
            path.display()
        );
    }
}

/// Puts a directory's permissions back when dropped, so the temporary
/// directory can be removed whatever the test did.
struct Restore(PathBuf, u32);

impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, Permissions::from_mode(self.1));
    }
}

/// Whether `path` can still be opened. Permission bits do not stop a process
/// with elevated privileges, and a test that relies on them has nothing to
/// check there.
fn permissions_do_not_apply(path: &Path) -> bool {
    match File::open(path) {
        Ok(_) => {
            eprintln!(
                "skipping: {} can be opened although its permissions forbid it",
                path.display()
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn config_path_in_a_directory_that_cannot_be_searched_is_reported_with_its_reason() {
    let dir = tempfile::tempdir().unwrap();
    let locked = dir.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let path = locked.join("zentinel.kdl");
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&locked, Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(locked.clone(), 0o755);
    if permissions_do_not_apply(&path) {
        return;
    }

    let run = run_zentinel(&["--config".as_ref(), path.as_os_str()], None, &[]);

    assert_refused_path(&run, &path, "Permission denied");
}

#[test]
fn config_file_that_cannot_be_read_stops_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zentinel.kdl");
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o000)).unwrap();
    let _restore = Restore(path.clone(), 0o600);
    if permissions_do_not_apply(&path) {
        return;
    }

    let run = run_zentinel(&["--config".as_ref(), path.as_os_str()], None, &[]);

    assert_refused_path(&run, &path, "Permission denied");
    std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "",
        "the unreadable file was rewritten"
    );
}

/// A port the OS has just handed out and that is free again.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A configuration with one listener on `port`.
fn listening_config(port: u16) -> String {
    format!(
        r#"
system {{
    worker-threads 1
}}
listeners {{
    listener "http" {{
        address "127.0.0.1:{port}"
        protocol "http"
    }}
}}
routes {{
    route "probe" {{
        matches {{ path "/probe" }}
        builtin-handler "health"
    }}
}}
observability {{
    metrics {{ enabled #false }}
}}
"#
    )
}

/// Start the binary on `config_path` and report whether it is running and
/// accepting connections on `port` before the startup deadline.
fn starts_and_listens(config_path: &Path, port: u16) -> bool {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zentinel"))
        .arg("--config")
        .arg(config_path)
        .env_remove("ZENTINEL_CONFIG")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + STARTUP_DEADLINE;
    let mut listening = false;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            // The port was only free a moment ago, so something else may
            // have taken it. The answer counts only if the proxy is still up.
            listening = child.try_wait().unwrap().is_none();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    listening
}

#[test]
fn config_file_that_exists_is_loaded_and_left_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("zentinel.kdl");
    let port = free_port();
    let text = listening_config(port);
    std::fs::write(&path, &text).unwrap();

    assert!(
        starts_and_listens(&path, port),
        "the proxy did not listen on the port its configuration names"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
}

#[test]
fn config_directory_that_exists_is_loaded_and_left_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let config_dir = dir.path().join("zentinel.d");
    std::fs::create_dir(&config_dir).unwrap();
    let file = config_dir.join("zentinel.kdl");
    let port = free_port();
    let text = listening_config(port);
    std::fs::write(&file, &text).unwrap();

    assert!(
        starts_and_listens(&config_dir, port),
        "the proxy did not listen on the port its configuration directory names"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    assert_eq!(
        std::fs::read_dir(&config_dir).unwrap().count(),
        1,
        "files were added to the configuration directory"
    );
}
