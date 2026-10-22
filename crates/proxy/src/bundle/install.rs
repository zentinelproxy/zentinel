//! Agent installation logic
//!
//! Handles placing downloaded binaries in the correct locations. What the
//! agents are started with, and how the proxy is wired to them, is in
//! [`super::setup`].

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during installation
#[derive(Debug, Error)]
pub enum InstallError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Installation directory does not exist: {0}")]
    DirNotFound(String),

    #[error("Failed to create directory: {0}")]
    CreateDir(String),
}

/// Installation paths configuration
#[derive(Debug, Clone)]
pub struct InstallPaths {
    /// Directory for agent binaries
    pub bin_dir: PathBuf,

    /// Directory for files `bundle install` writes for the proxy (the
    /// generated `agents.kdl`) and for files agents need (`--config`,
    /// `--script`), which the user creates.
    pub config_dir: PathBuf,

    /// Directory the Unix-socket agents listen in. The generated KDL and the
    /// agents' `--socket` both point here.
    pub socket_dir: PathBuf,

    /// Directory for systemd service files (Linux only)
    pub systemd_dir: Option<PathBuf>,

    /// Whether this is a system-wide install (requires root)
    pub system_wide: bool,
}

impl InstallPaths {
    /// Get default system-wide installation paths
    pub fn system() -> Self {
        Self {
            bin_dir: PathBuf::from("/usr/local/bin"),
            config_dir: PathBuf::from("/etc/zentinel/agents"),
            socket_dir: PathBuf::from(SYSTEM_SOCKET_DIR),
            systemd_dir: Some(PathBuf::from("/etc/systemd/system")),
            system_wide: true,
        }
    }

    /// Get user-local installation paths
    pub fn user() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        Self {
            bin_dir: PathBuf::from(&home).join(".local/bin"),
            config_dir: PathBuf::from(&home).join(".config/zentinel/agents"),
            // Not $XDG_RUNTIME_DIR: the path is written into the proxy's KDL,
            // so it must be the same in every session, and nothing (no
            // systemd RuntimeDirectory=) recreates it after a logout.
            socket_dir: PathBuf::from(&home).join(".local/state/zentinel/run"),
            systemd_dir: Some(PathBuf::from(&home).join(".config/systemd/user")),
            system_wide: false,
        }
    }

    /// Get paths for a custom prefix
    pub fn with_prefix(prefix: &Path) -> Self {
        Self {
            bin_dir: prefix.join("bin"),
            config_dir: prefix.join("etc/zentinel/agents"),
            socket_dir: prefix.join("run/zentinel"),
            systemd_dir: Some(prefix.join("lib/systemd/system")),
            system_wide: false,
        }
    }

    /// Determine the best installation paths based on current user
    pub fn detect() -> Self {
        // Check if we're root
        #[cfg(unix)]
        {
            if unsafe { libc::geteuid() } == 0 {
                return Self::system();
            }
        }

        // Every directory the install will create must be writable, not just
        // the binary one. Checking `bin_dir` alone chose a system-wide install
        // and then failed on `/etc/zentinel/agents`, which is the error users
        // actually saw.
        let system_paths = Self::system();
        if system_paths.all_writable() {
            return system_paths;
        }

        // Fall back to user paths
        Self::user()
    }

    /// Whether every directory this install would create is writable.
    ///
    /// Deliberately the same set [`Self::ensure_dirs`] creates: a check that
    /// covers fewer paths than the operation is a check that passes and then
    /// fails.
    pub fn all_writable(&self) -> bool {
        is_writable(&self.bin_dir)
            && is_writable(&self.config_dir)
            && is_writable(&self.socket_dir)
            && self
                .systemd_dir
                .as_ref()
                .map(|d| is_writable(d))
                .unwrap_or(true)
    }

    /// Ensure all directories exist
    pub fn ensure_dirs(&self) -> Result<(), InstallError> {
        create_dir_if_missing(&self.bin_dir)?;
        create_dir_if_missing(&self.config_dir)?;
        create_socket_dir(&self.socket_dir, self.system_wide)?;
        if let Some(ref systemd_dir) = self.systemd_dir {
            create_dir_if_missing(systemd_dir)?;
        }
        Ok(())
    }
}

/// Where a system-wide install's agents listen.
///
/// Not `/run/zentinel`: that is the proxy unit's `RuntimeDirectory=`, which
/// systemd deletes whenever the proxy stops, so agent sockets in it would
/// vanish on every proxy restart while the agents kept running. The agent
/// units declare this directory with `RuntimeDirectoryPreserve=yes` instead.
#[cfg(target_os = "linux")]
pub const SYSTEM_SOCKET_DIR: &str = "/run/zentinel-agents";
/// Where a system-wide install's agents listen (no `/run` on macOS).
#[cfg(not(target_os = "linux"))]
pub const SYSTEM_SOCKET_DIR: &str = "/var/run/zentinel-agents";

/// Create the socket directory.
///
/// User and prefix installs get `0700`: the agents and the proxy run as the
/// installing user, and nobody else should reach the agents. A system-wide
/// one gets `0750`; its agent units run as `zentinel` and systemd re-owns the
/// directory to them on start (`RuntimeDirectory=`).
fn create_socket_dir(path: &Path, system_wide: bool) -> Result<(), InstallError> {
    let existed = path.exists();
    create_dir_if_missing(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !existed {
            let mode = if system_wide { 0o750 } else { 0o700 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (existed, system_wide);
    }
    Ok(())
}

/// Whether **this process** can create entries in `path`.
///
/// The obvious implementation is wrong, and was here:
///
/// ```ignore
/// std::fs::metadata(path).map(|m| !m.permissions().readonly())
/// ```
///
/// On Unix `Permissions::readonly()` is `mode & 0o222 == 0` — it answers "can
/// *anyone* write to this?", not "can *I*?". A root-owned `drwxr-xr-x`
/// directory has the owner write bit set, so that returned `true` for every
/// user on the system. `/usr/local/bin` is exactly such a directory on a
/// standard install, which meant [`InstallPaths::detect`] chose a system-wide
/// install for every non-root user and then failed creating `/etc/zentinel/agents`.
/// The user-local fallback below it was unreachable.
///
/// `access(2)` asks the question actually being asked, and answers it for the
/// real user rather than by inspecting mode bits.
fn is_writable(path: &Path) -> bool {
    if !path.exists() {
        // Not there yet: we can create it if we can write to its parent.
        return match path.parent() {
            Some(parent) => is_writable(parent),
            None => false,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // W_OK | X_OK: creating an entry needs write *and* search on a directory.
        unsafe { libc::access(c_path.as_ptr(), libc::W_OK | libc::X_OK) == 0 }
    }

    #[cfg(not(unix))]
    {
        std::fs::metadata(path)
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    }
}

/// Create a directory if it doesn't exist
fn create_dir_if_missing(path: &Path) -> Result<(), InstallError> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                InstallError::PermissionDenied(path.display().to_string())
            } else {
                InstallError::CreateDir(format!("{}: {}", path.display(), e))
            }
        })?;
    }
    Ok(())
}

/// Install a binary to the target directory
pub fn install_binary(source: &Path, dest_dir: &Path, name: &str) -> Result<PathBuf, InstallError> {
    let dest_path = dest_dir.join(name);

    tracing::info!(
        source = %source.display(),
        dest = %dest_path.display(),
        "Installing binary"
    );

    // Copy the file
    std::fs::copy(source, &dest_path)?;

    // Set permissions (executable)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&dest_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&dest_path, perms)?;
    }

    Ok(dest_path)
}

/// Uninstall a binary
pub fn uninstall_binary(bin_dir: &Path, name: &str) -> Result<bool, InstallError> {
    let path = bin_dir.join(name);

    if path.exists() {
        tracing::info!(path = %path.display(), "Removing binary");
        std::fs::remove_file(&path)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if a binary is installed and get its version
pub fn get_installed_version(bin_dir: &Path, binary_name: &str) -> Option<String> {
    let path = bin_dir.join(binary_name);

    if !path.exists() {
        return None;
    }

    // Try to run the binary with --version
    let output = std::process::Command::new(&path)
        .arg("--version")
        .output()
        .ok()?;

    if !output.status.success() {
        // Binary exists but doesn't support --version
        return Some("unknown".to_string());
    }

    // Parse version from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_version_output(&stdout)
}

/// Parse version from command output
fn parse_version_output(output: &str) -> Option<String> {
    // Common patterns:
    // "zentinel-waf-agent 0.2.0"
    // "version 0.2.0"
    // "0.2.0"

    for line in output.lines() {
        let line = line.trim();

        // Look for semver-like pattern
        for word in line.split_whitespace() {
            if word
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && word.contains('.')
            {
                // Remove any trailing metadata (e.g., "0.2.0-beta" -> "0.2.0")
                let version = word.split('-').next().unwrap_or(word);
                let version = version.split('+').next().unwrap_or(version);
                return Some(version.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_output() {
        assert_eq!(
            parse_version_output("zentinel-waf-agent 0.2.0"),
            Some("0.2.0".to_string())
        );
        assert_eq!(
            parse_version_output("version 1.0.0"),
            Some("1.0.0".to_string())
        );
        assert_eq!(parse_version_output("0.3.1"), Some("0.3.1".to_string()));
        assert_eq!(
            parse_version_output("0.2.0-beta+build123"),
            Some("0.2.0".to_string())
        );
        assert_eq!(parse_version_output("no version here"), None);
    }

    #[test]
    fn test_parse_version_multiline() {
        let output = "zentinel-waf-agent\nversion: 0.2.0\nbuilt with rustc";
        assert_eq!(parse_version_output(output), Some("0.2.0".to_string()));
    }

    #[test]
    fn test_parse_version_with_v_prefix() {
        // Version number must start with digit, so "v0.2.0" wouldn't match
        assert_eq!(
            parse_version_output("version v0.2.0"),
            None // v0.2.0 starts with 'v', not a digit
        );
        // Test with version number not in parentheses
        assert_eq!(
            parse_version_output("myapp v0.2.0 version 0.2.0"),
            Some("0.2.0".to_string())
        );
    }

    /// The exact defect this replaced, constructed rather than assumed.
    ///
    /// Mode `0o522` is the distinguishing case: the group and other write bits
    /// are set, so `mode & 0o222 != 0` and the old `readonly()` check called it
    /// writable — but the *owner* has only `r-x`, so the process running this
    /// test cannot actually create anything in it.
    ///
    /// The previous version of this test asserted that `/usr/local/bin` is not
    /// writable, which is an assumption about the machine rather than a
    /// property of the code: on a GitHub runner that directory *is* writable by
    /// the build user, and the test failed there for a correct reason. This one
    /// holds anywhere.
    #[test]
    #[cfg(unix)]
    fn a_directory_others_may_write_but_we_may_not_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return; // root bypasses permission checks entirely
        }

        let dir =
            std::env::temp_dir().join(format!("zentinel-writable-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o522)).expect("set mode");

        let mode = std::fs::metadata(&dir)
            .expect("metadata")
            .permissions()
            .mode();
        assert_ne!(
            mode & 0o222,
            0,
            "the old check would have called this writable"
        );
        assert!(
            !is_writable(&dir),
            "a directory we cannot write must not be reported writable"
        );

        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A directory we own is writable, so the check is not simply always-false.
    #[test]
    fn a_directory_we_own_is_writable() {
        let dir = std::env::temp_dir();
        assert!(is_writable(&dir), "temp dir should be writable: {dir:?}");
    }

    /// A path that does not exist yet is writable if its parent is, since that
    /// is where it would be created.
    #[test]
    fn a_missing_directory_defers_to_its_parent() {
        let missing = std::env::temp_dir().join("zentinel-install-check-does-not-exist");
        assert!(is_writable(&missing));
    }

    /// Whatever `detect()` returns must be usable.
    ///
    /// Asserted as an invariant rather than as "must be user-local": on a
    /// machine where the system paths genuinely are writable, choosing them is
    /// correct. What must never happen is `detect()` handing back paths that
    /// `ensure_dirs` will then fail on, which is the bug users hit.
    #[test]
    fn detect_never_returns_paths_it_cannot_create() {
        let paths = InstallPaths::detect();
        assert!(
            paths.all_writable(),
            "detect() returned paths it cannot actually create: {paths:?}"
        );
    }

    /// The writability check must cover the same directories the install
    /// creates. Checking only `bin_dir` is what let a doomed install start.
    #[test]
    fn all_writable_covers_every_directory_ensure_dirs_creates() {
        let user = InstallPaths::user();
        assert!(user.all_writable(), "the user fallback must be usable");
    }

    #[test]
    fn test_install_paths_system() {
        let paths = InstallPaths::system();
        assert!(paths.system_wide);
        assert_eq!(paths.bin_dir, PathBuf::from("/usr/local/bin"));
        assert_eq!(paths.config_dir, PathBuf::from("/etc/zentinel/agents"));
        assert_eq!(
            paths.systemd_dir,
            Some(PathBuf::from("/etc/systemd/system"))
        );
    }

    #[test]
    fn test_install_paths_user() {
        let paths = InstallPaths::user();
        assert!(!paths.system_wide);
        assert!(paths.bin_dir.to_string_lossy().contains(".local"));
        assert!(paths.config_dir.to_string_lossy().contains(".config"));
    }

    #[test]
    fn test_install_paths_with_prefix() {
        let paths = InstallPaths::with_prefix(Path::new("/opt/zentinel"));
        assert!(!paths.system_wide);
        assert_eq!(paths.bin_dir, PathBuf::from("/opt/zentinel/bin"));
        assert_eq!(
            paths.config_dir,
            PathBuf::from("/opt/zentinel/etc/zentinel/agents")
        );
    }

    #[test]
    fn test_install_binary() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("source");
        let dest_dir = temp.path().join("dest");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::create_dir_all(&dest_dir).unwrap();

        // Create source binary
        let source_path = source_dir.join("test-binary");
        std::fs::write(&source_path, "binary content").unwrap();

        let result = install_binary(&source_path, &dest_dir, "test-binary");
        assert!(result.is_ok());

        let installed = result.unwrap();
        assert!(installed.exists());
        assert_eq!(installed.file_name().unwrap(), "test-binary");
    }

    #[test]
    fn test_uninstall_binary_exists() {
        let temp = tempfile::tempdir().unwrap();
        let binary_path = temp.path().join("test-binary");
        std::fs::write(&binary_path, "content").unwrap();

        let result = uninstall_binary(temp.path(), "test-binary");
        assert!(result.is_ok());
        assert!(result.unwrap()); // true = was removed
        assert!(!binary_path.exists());
    }

    #[test]
    fn test_uninstall_binary_not_exists() {
        let temp = tempfile::tempdir().unwrap();

        let result = uninstall_binary(temp.path(), "nonexistent");
        assert!(result.is_ok());
        assert!(!result.unwrap()); // false = wasn't there
    }

    #[test]
    fn test_install_paths_ensure_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let paths = InstallPaths {
            bin_dir: temp.path().join("bin"),
            config_dir: temp.path().join("config"),
            socket_dir: temp.path().join("run"),
            systemd_dir: Some(temp.path().join("systemd")),
            system_wide: false,
        };

        assert!(!paths.bin_dir.exists());
        assert!(!paths.config_dir.exists());

        let result = paths.ensure_dirs();
        assert!(result.is_ok());

        assert!(paths.bin_dir.exists());
        assert!(paths.config_dir.exists());
        assert!(paths.socket_dir.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&paths.socket_dir)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "user socket dir must be private");
        }
        assert!(paths.systemd_dir.as_ref().unwrap().exists());
    }

    #[test]
    fn test_install_error_display() {
        let err = InstallError::PermissionDenied("/root".to_string());
        assert!(err.to_string().contains("/root"));

        let err = InstallError::DirNotFound("/missing".to_string());
        assert!(err.to_string().contains("/missing"));
    }

    #[test]
    fn test_get_installed_version_not_exists() {
        let temp = tempfile::tempdir().unwrap();
        let result = get_installed_version(temp.path(), "nonexistent");
        assert!(result.is_none());
    }
}
