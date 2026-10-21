//! Daemon mode: fork before any thread exists, drop privileges before serving.
//!
//! Daemon mode used to be left to Pingora, which forks inside
//! `Server::run_forever`. By then Zentinel had already started its tokio
//! runtime -- agents, health checks, the reload task, the metrics server --
//! and the thread that reads SIGHUP/SIGTERM. `fork()` keeps only the calling
//! thread, so in the daemon none of that existed: SIGHUP and SIGTERM did
//! nothing and no background task ever ran (#573).
//!
//! The proxy now daemonizes itself at the start of `run_server`, while the
//! process still has a single thread, and tells Pingora not to fork again.
//! The steps Pingora took when it forked are kept, split in two:
//!
//! - [`DaemonPlan::daemonize`] does what Pingora did at the fork: umask
//!   `0o007`, the old pid file moved aside to `<pid file>.old` (which a `-u`
//!   upgrade relies on), a locked pid file naming the daemon, stdout and
//!   stderr kept.
//! - [`DaemonPlan::drop_privileges`] does what Pingora did after it: switch to
//!   `system { user group }`. It is called right before
//!   `Server::run_forever`, where Pingora used to drop them, so the
//!   configuration, TLS keys and log files are still opened as the user that
//!   started the proxy, and listeners are bound after the switch, as before.
//!
//! Only a daemon drops privileges; a proxy in the foreground never did.

use anyhow::{Context, Result};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use zentinel_config::{Config, ServerConfig};

/// The pid file Pingora writes when `system { pid-file }` is not set.
///
/// Read from Pingora's own defaults so the two cannot drift apart.
fn default_pid_file() -> PathBuf {
    PathBuf::from(pingora_core::server::configuration::ServerConf::default().pid_file)
}

/// Whether to run as a daemon: `-d`, or `system { daemon #true }` (#527).
///
/// There is no way to switch daemon mode off from the command line, as there
/// was none before.
pub fn daemon_requested(from_cli: bool, server: &ServerConfig) -> bool {
    from_cli || server.daemon
}

/// What the daemon needs to know from the configuration, read before the fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonPlan {
    /// Where the daemon's pid is written.
    pub pid_file: PathBuf,
    /// `system { user }`, switched to before serving.
    pub user: Option<String>,
    /// `system { group }`, switched to before serving.
    pub group: Option<String>,
    /// Whether daemon mode came from `-d` rather than the configuration.
    pub from_cli: bool,
}

impl DaemonPlan {
    /// The plan for a configuration that asks for daemon mode, `None` otherwise.
    pub fn for_server(from_cli: bool, server: &ServerConfig) -> Option<Self> {
        daemon_requested(from_cli, server).then(|| Self {
            pid_file: server.pid_file.clone().unwrap_or_else(default_pid_file),
            user: server.user.clone(),
            group: server.group.clone(),
            from_cli,
        })
    }

    /// Decide on daemon mode and, if it is on, check the configuration first.
    ///
    /// The configuration is loaded and validated the way `zentinel test` and
    /// `ZentinelProxy::new` do it. A configuration that does not load is
    /// reported here, in the foreground, with a non-zero exit -- once the
    /// process has forked, the shell that started it has already been told it
    /// succeeded.
    ///
    /// Without `-d`, a configuration that does not load cannot say whether it
    /// wanted a daemon. The proxy then stays in the foreground and
    /// `ZentinelProxy::new` reports the error, exactly as it did before.
    pub fn prepare(config_path: Option<&str>, from_cli: bool) -> Result<Option<Self>> {
        let loaded = match config_path {
            Some(path) => Config::from_file(path).context("Failed to load configuration file"),
            None => Config::default_embedded().context("Failed to load embedded configuration"),
        };
        let config = match loaded {
            Ok(config) => config,
            Err(e) if from_cli => return Err(e),
            Err(_) => return Ok(None),
        };
        let Some(plan) = Self::for_server(from_cli, &config.server) else {
            return Ok(None);
        };
        config
            .validate()
            .context("Configuration validation failed")?;
        Ok(Some(plan))
    }

    /// Fork into the background. Returns in the daemon only; the process that
    /// called it exits.
    ///
    /// Must be called while the process has a single thread: any other thread
    /// does not exist in the daemon.
    pub fn daemonize(&self) -> Result<()> {
        warn_if_threads_exist();

        move_old_pid(&self.pid_file);

        // The daemon stays in the current directory instead of moving to `/`:
        // the configuration is read after the fork now, so relative paths --
        // `-c zentinel.kdl`, certificate and log paths -- have to resolve as
        // they do in the foreground. `system { working-directory }` is applied
        // by `run_server` later, at the same point as in the foreground.
        let cwd = std::env::current_dir().context("Failed to read the current directory")?;

        let daemonize = daemonix::Daemonize::new()
            // Allow the same group to access files, but not everyone else.
            .umask(0o007)
            .pid_file(&self.pid_file)
            .working_directory(cwd)
            .stdout(daemonix::Stdio::keep())
            .stderr(daemonix::Stdio::keep());

        match daemonize.execute() {
            daemonix::Outcome::Parent(Ok(parent)) => {
                // The first child exits as soon as it has forked the daemon.
                std::process::exit(if parent.first_child_exit_code == 0 {
                    0
                } else {
                    1
                })
            }
            daemonix::Outcome::Parent(Err(e)) => Err(e).context("Failed to start the daemon"),
            daemonix::Outcome::Child(Ok(_)) => Ok(()),
            daemonix::Outcome::Child(Err(e)) => Err(e).with_context(|| {
                format!("Daemon setup failed (pid file {})", self.pid_file.display())
            }),
        }
    }

    /// Switch to `system { user group }`, as Pingora did when it daemonized.
    ///
    /// The order is Pingora's: the pid file is handed to the user, the
    /// supplementary groups are set from the user's entry, then the group and
    /// finally the user are changed. As with Pingora, a `user` without a
    /// `group` leaves the group id alone.
    ///
    /// The tokio runtimes and the signal thread exist by now. That is fine:
    /// `setgid`/`setuid` change the credentials of every thread -- on macOS
    /// and the BSDs they belong to the process, and on Linux glibc and musl
    /// apply them to all threads of the process.
    pub fn drop_privileges(&self) -> Result<()> {
        if self.user.is_none() && self.group.is_none() {
            return Ok(());
        }
        let user = self.user.as_deref().map(lookup_user).transpose()?;
        // A `user` without a `group` switches to that user's primary group, as
        // nginx does. Pingora left the group alone, so the process kept root's
        // group after dropping to the user.
        let gid = match self.group.as_deref() {
            Some(group) => Some(lookup_group(group)?),
            None => user.as_ref().map(|user| user.primary_gid),
        };

        if let Some(ref user) = user {
            // `-1` leaves that id unchanged.
            let owner_gid = gid.unwrap_or(libc::gid_t::MAX);
            let path = CString::new(self.pid_file.as_os_str().as_encoded_bytes())
                .context("pid file path contains a NUL byte")?;
            // SAFETY: `path` is a valid C string; chown(2) only reads it.
            if unsafe { libc::chown(path.as_ptr(), user.uid, owner_gid) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!(
                        "Failed to hand the pid file {} to user '{}'",
                        self.pid_file.display(),
                        user.name.to_string_lossy()
                    )
                });
            }

            // SAFETY: `user.name` is a valid C string; initgroups(3) only reads it.
            // Its result is not checked, as Pingora did not check it either.
            unsafe {
                libc::initgroups(user.name.as_ptr(), user.primary_gid as _);
            }
        }

        if let Some(gid) = gid {
            // SAFETY: setgid(2) takes a plain id.
            if unsafe { libc::setgid(gid) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("Failed to switch to group id {gid}"));
            }
        }

        if let Some(ref user) = user {
            // SAFETY: setuid(2) takes a plain id.
            if unsafe { libc::setuid(user.uid) } != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("Failed to switch to user '{}'", user.name.to_string_lossy())
                });
            }
        }

        tracing::info!(
            user = ?self.user,
            group = ?self.group,
            "Dropped privileges"
        );
        Ok(())
    }
}

/// Rename an existing pid file to `<pid file>.old`, as Pingora does before it
/// writes its own. A `-u` upgrade starts the new process while the old one is
/// still running.
pub fn move_old_pid(path: &Path) {
    if !path.exists() {
        return;
    }
    let old = old_pid_path(path);
    if let Err(e) = std::fs::rename(path, &old) {
        tracing::error!(
            from = %path.display(),
            to = %old.display(),
            error = %e,
            "Failed to rename the old pid file"
        );
    }
}

fn old_pid_path(path: &Path) -> PathBuf {
    let mut old = path.as_os_str().to_owned();
    old.push(".old");
    PathBuf::from(old)
}

struct UserEntry {
    name: CString,
    uid: libc::uid_t,
    primary_gid: libc::gid_t,
}

fn lookup_user(name: &str) -> Result<UserEntry> {
    let name = CString::new(name).with_context(|| format!("user '{name}' contains a NUL byte"))?;
    // SAFETY: `name` is a valid C string. getpwnam(3) returns null or a pointer
    // to a static entry, which is read at once and not kept.
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };
    if entry.is_null() {
        anyhow::bail!("user '{}' not found", name.to_string_lossy());
    }
    // SAFETY: checked for null above.
    let (uid, primary_gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };
    Ok(UserEntry {
        name,
        uid,
        primary_gid,
    })
}

fn lookup_group(name: &str) -> Result<libc::gid_t> {
    let cname =
        CString::new(name).with_context(|| format!("group '{name}' contains a NUL byte"))?;
    // SAFETY: as in `lookup_user`, for getgrnam(3).
    let entry = unsafe { libc::getgrnam(cname.as_ptr()) };
    if entry.is_null() {
        anyhow::bail!("group '{name}' not found");
    }
    // SAFETY: checked for null above.
    Ok(unsafe { (*entry).gr_gid })
}

/// Threads alive at the fork are lost in the daemon. Nothing starts one
/// before `run_server` daemonizes; this says so loudly if that changes.
fn warn_if_threads_exist() {
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let threads = status
            .lines()
            .find_map(|line| line.strip_prefix("Threads:"))
            .and_then(|n| n.trim().parse::<u32>().ok());
        if let Some(n) = threads.filter(|&n| n > 1) {
            tracing::warn!(
                threads = n,
                "Daemonizing with more than one thread; all but this one are lost in the daemon"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_mode_comes_from_the_flag_or_the_config() {
        let mut server = Config::default_for_testing().server;
        for (flag, config, expected) in [
            (false, false, false),
            (true, false, true),
            (false, true, true),
            (true, true, true),
        ] {
            server.daemon = config;
            assert_eq!(
                daemon_requested(flag, &server),
                expected,
                "flag {flag}, config {config}"
            );
            assert_eq!(DaemonPlan::for_server(flag, &server).is_some(), expected);
        }
    }

    #[test]
    fn plan_uses_the_configured_pid_file_or_pingoras_default() {
        let mut server = Config::default_for_testing().server;
        server.pid_file = None;
        server.user = Some("nobody".into());
        let plan = DaemonPlan::for_server(true, &server).unwrap();
        assert_eq!(plan.pid_file, PathBuf::from("/tmp/pingora.pid"));
        assert_eq!(plan.user.as_deref(), Some("nobody"));
        assert!(plan.from_cli);

        server.pid_file = Some("/run/zentinel.pid".into());
        server.daemon = true;
        let plan = DaemonPlan::for_server(false, &server).unwrap();
        assert_eq!(plan.pid_file, PathBuf::from("/run/zentinel.pid"));
        assert!(!plan.from_cli);
    }

    #[test]
    fn old_pid_file_is_moved_aside() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("zentinel.pid");
        move_old_pid(&pid); // no file: nothing to do
        assert!(!old_pid_path(&pid).exists());

        std::fs::write(&pid, "42\n").unwrap();
        move_old_pid(&pid);
        assert!(!pid.exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("zentinel.pid.old")).unwrap(),
            "42\n"
        );
    }

    #[test]
    fn prepare_reports_a_broken_config_only_when_daemonizing() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.kdl");
        std::fs::write(&broken, "listeners {\n").unwrap();
        let broken = broken.to_str().unwrap();

        assert!(DaemonPlan::prepare(Some(broken), true).is_err());
        // In the foreground the proxy reports it, as before.
        assert!(DaemonPlan::prepare(Some(broken), false).unwrap().is_none());
    }

    #[test]
    fn prepare_validates_when_the_config_asks_for_a_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.kdl");
        // Parses, but the listener address is not a socket address (#520).
        std::fs::write(
            &path,
            r#"
system { daemon #true }
listeners { listener "http" { address "not-an-address"; protocol "http"; } }
"#,
        )
        .unwrap();
        let path = path.to_str().unwrap();
        assert!(Config::from_file(path).is_ok());
        assert!(DaemonPlan::prepare(Some(path), false).is_err());
    }

    #[test]
    fn dropping_nothing_is_a_no_op() {
        let plan = DaemonPlan {
            pid_file: "/nonexistent/zentinel.pid".into(),
            user: None,
            group: None,
            from_cli: true,
        };
        plan.drop_privileges().unwrap();
    }

    #[test]
    fn unknown_user_and_group_are_errors() {
        assert!(lookup_user("zentinel-no-such-user-573").is_err());
        assert!(lookup_group("zentinel-no-such-group-573").is_err());
        assert_eq!(lookup_user("root").unwrap().uid, 0);
    }
}
