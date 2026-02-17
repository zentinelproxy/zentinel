//! Bundle command module
//!
//! Provides functionality to fetch and install bundled agents from their
//! respective GitHub releases based on a version lock file.
//!
//! # Overview
//!
//! The bundle command allows users to install a curated set of Zentinel agents
//! that are tested to work together. Versions are coordinated via a lock file
//! that pins compatible versions.
//!
//! # Usage
//!
//! ```bash
//! zentinel bundle install          # Download and install all bundled agents
//! zentinel bundle install --dry-run    # Preview what would be installed
//! zentinel bundle status           # Show installed vs expected versions
//! zentinel bundle list             # List available agents in the bundle
//! zentinel bundle uninstall        # Remove installed agents
//! ```
//!
//! # Lock File
//!
//! The `bundle-versions.lock` file defines which agent versions are included:
//!
//! ```toml
//! [bundle]
//! version = "26.01_1"
//!
//! [agents]
//! waf = "0.2.0"
//! ratelimit = "0.2.0"
//! denylist = "0.2.0"
//!
//! [repositories]
//! waf = "zentinelproxy/zentinel-agent-waf"
//! ratelimit = "zentinelproxy/zentinel-agent-ratelimit"
//! denylist = "zentinelproxy/zentinel-agent-denylist"
//! ```

mod commands;
mod fetch;
mod install;
mod lock;
mod status;

pub use commands::{run_bundle_command, BundleArgs, BundleCommand};
pub use lock::BundleLock;
