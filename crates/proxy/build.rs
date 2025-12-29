//! Build script for sentinel-proxy
//!
//! Captures version information from git for display in --version output.

use std::process::Command;

fn main() {
    // Get the latest git tag (CalVer release version)
    let calver = Command::new("git")
        .args(["describe", "--tags", "--abbrev=0"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "dev".to_string());

    // Get the short commit hash
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Check if working directory is dirty
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let dirty_suffix = if dirty { "-dirty" } else { "" };

    // Export for use in main.rs
    println!("cargo:rustc-env=SENTINEL_CALVER={}", calver);
    println!("cargo:rustc-env=SENTINEL_COMMIT={}{}", commit, dirty_suffix);

    // Rebuild if git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}
