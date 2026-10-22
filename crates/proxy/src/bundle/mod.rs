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
//! waf = "0.4.0"
//! zentinelsec = "0.4.0"
//!
//! [repositories]
//! waf = "zentinelproxy/zentinel-agent-waf"
//! zentinelsec = "zentinelproxy/zentinel-agent-zentinelsec"
//!
//! [transports]            # optional; agents not listed use "uds"
//! zentinelsec = "grpc"
//!
//! [grpc_ports]            # required for each "grpc" agent
//! zentinelsec = 50151
//! ```
//!
//! What an installed agent is started with, and the `agents.kdl` that wires
//! the proxy to it, are generated together in `setup.rs`.

mod commands;
mod fetch;
mod install;
mod lock;
mod setup;
mod status;

pub use commands::{run_bundle_command, BundleArgs, BundleCommand};
pub use lock::BundleLock;
