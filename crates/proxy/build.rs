//! Build script for zentinel-proxy
//!
//! - Captures version information from git for display in --version output.
//! - Copies bundle-versions.lock to OUT_DIR so it's available via include_str!
//!   when published to crates.io (the workspace-relative path doesn't survive cargo publish).

use std::process::Command;

fn main() {
    // Copy bundle-versions.lock to OUT_DIR for crates.io compatibility
    copy_bundle_lock();
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
    println!("cargo:rustc-env=ZENTINEL_CALVER={}", calver);
    println!("cargo:rustc-env=ZENTINEL_COMMIT={}{}", commit, dirty_suffix);

    // Rebuild if git state changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/tags");
}

/// Copy bundle-versions.lock to OUT_DIR.
///
/// When building from the workspace (local dev or CI), the file lives at the
/// workspace root (../../../../bundle-versions.lock relative to src/bundle/).
/// When building from a crates.io download, that path doesn't exist because
/// cargo publish only packages files within the crate directory.
///
/// This function finds the file in either location and copies it to OUT_DIR,
/// where lock.rs can reliably include_str! it.
fn copy_bundle_lock() {
    use std::path::PathBuf;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let dest = out_dir.join("bundle-versions.lock");

    // Try workspace root first (4 levels up from crates/proxy/src/bundle/)
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_path = manifest_dir.join("../../bundle-versions.lock");

    // Fallback: bundled copy inside the crate (for crates.io)
    let crate_path = manifest_dir.join("bundle-versions.lock");

    let source = if workspace_path.exists() {
        workspace_path
    } else if crate_path.exists() {
        crate_path
    } else {
        // If neither exists, write a minimal fallback so compilation succeeds.
        // The `bundle` subcommand will still work via fetch_latest().
        let fallback = r#"[bundle]
version = "0.0.0"

[agents]

[repositories]
"#;
        std::fs::write(&dest, fallback).expect("Failed to write fallback bundle-versions.lock");
        println!("cargo:rerun-if-changed=bundle-versions.lock");
        return;
    };

    std::fs::copy(&source, &dest).expect("Failed to copy bundle-versions.lock to OUT_DIR");
    println!("cargo:rerun-if-changed={}", source.display());
}
