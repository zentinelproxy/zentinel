//! Bundle CLI command handlers
//!
//! Implements the `zentinel bundle` subcommand and its subcommands.

use crate::bundle::fetch::{detect_arch, detect_os, download_agent};
use crate::bundle::install::{install_binary, uninstall_binary, InstallPaths};
use crate::bundle::lock::{retired_reason, AgentInfo, BundleLock};
use crate::bundle::setup::{
    generate_agents_kdl, generate_systemd_unit, is_legacy_generated_config, launch_command,
    required_file_path, systemd_unit_name, write_generated, Endpoint, AGENTS_KDL,
};
use crate::bundle::status::BundleStatus;
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Bundle command arguments
#[derive(Args, Debug)]
pub struct BundleArgs {
    #[command(subcommand)]
    pub command: BundleCommand,
}

/// Bundle subcommands
#[derive(Subcommand, Debug)]
pub enum BundleCommand {
    /// Install bundled agents
    Install {
        /// Specific agent to install (installs all if not specified)
        agent: Option<String>,

        /// Preview what would be installed without making changes
        #[arg(long, short = 'n')]
        dry_run: bool,

        /// Force reinstallation even if already installed
        #[arg(long, short = 'f')]
        force: bool,

        /// Also write a systemd unit per agent (system units for a root
        /// install, user units otherwise)
        #[arg(long)]
        systemd: bool,

        /// Custom installation prefix
        #[arg(long)]
        prefix: Option<PathBuf>,

        /// Skip checksum verification
        #[arg(long)]
        skip_verify: bool,
    },

    /// Show status of installed agents
    Status {
        /// Show detailed output
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// List available agents in the bundle
    List {
        /// Show detailed information
        #[arg(long, short = 'v')]
        verbose: bool,
    },

    /// Uninstall bundled agents
    Uninstall {
        /// Specific agent to uninstall (uninstalls all if not specified)
        agent: Option<String>,

        /// Preview what would be uninstalled
        #[arg(long, short = 'n')]
        dry_run: bool,
    },

    /// Check for updates to bundled agents
    Update {
        /// Actually perform the update
        #[arg(long)]
        apply: bool,
    },
}

/// Run the bundle command
pub fn run_bundle_command(args: BundleArgs) -> Result<()> {
    // Load the embedded lock file
    let lock = BundleLock::embedded().context("Failed to load bundle lock file")?;

    match args.command {
        BundleCommand::Install {
            agent,
            dry_run,
            force,
            systemd,
            prefix,
            skip_verify,
        } => cmd_install(&lock, agent, dry_run, force, systemd, prefix, skip_verify),

        BundleCommand::Status { verbose } => cmd_status(&lock, verbose),

        BundleCommand::List { verbose } => cmd_list(&lock, verbose),

        BundleCommand::Uninstall { agent, dry_run } => cmd_uninstall(&lock, agent, dry_run),

        BundleCommand::Update { apply } => cmd_update(&lock, apply),
    }
}

/// Install command implementation
fn cmd_install(
    lock: &BundleLock,
    agent: Option<String>,
    dry_run: bool,
    force: bool,
    install_systemd: bool,
    prefix: Option<PathBuf>,
    skip_verify: bool,
) -> Result<()> {
    let paths = match prefix {
        Some(p) => InstallPaths::with_prefix(&p),
        None => InstallPaths::detect(),
    };

    println!("Zentinel Bundle Installer");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Bundle version: {}", lock.bundle.version);
    println!("Platform:       {}-{}", detect_os(), detect_arch());
    println!("Install path:   {}", paths.bin_dir.display());
    println!("Sockets:        {}", paths.socket_dir.display());
    println!("Config:         {}", paths.config_dir.display());
    if paths.system_wide {
        println!("Mode:           system-wide (requires root)");
    } else {
        println!("Mode:           user-local");
    }
    println!();

    // Get agents to install
    let agents: Vec<_> = match &agent {
        Some(name) => vec![find_agent(lock, name)?],
        None => lock.agents(),
    };

    if agents.is_empty() {
        println!("No agents to install.");
        return Ok(());
    }

    // Check current status
    let status = BundleStatus::check(lock, &paths);

    if dry_run {
        println!("[DRY RUN] Would install the following agents:");
        println!();
        for agent in &agents {
            let agent_status = status.agents.iter().find(|a| a.name == agent.name);

            let action = match agent_status {
                Some(s) if s.status == crate::bundle::status::Status::UpToDate && !force => {
                    "skip (already installed)"
                }
                Some(s) if s.status == crate::bundle::status::Status::Outdated => "upgrade",
                _ => "install",
            };

            println!(
                "  {} {} -> {} ({})",
                agent.name,
                agent.version,
                paths.bin_dir.display(),
                action
            );
            println!("      start: {}", launch_command(agent, &paths));
        }
        println!();
        println!(
            "Would write {}",
            paths.config_dir.join(AGENTS_KDL).display()
        );
        return Ok(());
    }

    // Ensure directories exist
    paths
        .ensure_dirs()
        .context("Failed to create installation directories")?;

    // Create temporary directory for downloads
    let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

    // Create async runtime for downloads
    let rt = tokio::runtime::Runtime::new()?;

    // Install each agent
    let mut installed = 0;
    let mut skipped = 0;
    let mut failed = 0;
    // Agents that are in place after this run (installed now or already up to
    // date): the ones to print start commands and write units for.
    let mut ready: Vec<&AgentInfo> = Vec::new();

    for agent in &agents {
        let agent_status = status.agents.iter().find(|a| a.name == agent.name);

        // Skip if already installed (unless forced)
        if !force {
            if let Some(s) = agent_status {
                if s.status == crate::bundle::status::Status::UpToDate {
                    println!(
                        "  [skip] {} {} (already installed)",
                        agent.name, agent.version
                    );
                    skipped += 1;
                    ready.push(agent);
                    continue;
                }
            }
        }

        print!("  Installing {} {}...", agent.name, agent.version);

        // Download
        let download_result =
            rt.block_on(async { download_agent(agent, temp_dir.path(), !skip_verify).await });

        let download = match download_result {
            Ok(d) => d,
            Err(e) => {
                println!(" FAILED");
                eprintln!("    Error: {}", e);
                failed += 1;
                continue;
            }
        };

        // Install binary
        if let Err(e) = install_binary(&download.binary_path, &paths.bin_dir, &agent.binary_name) {
            println!(" FAILED");
            eprintln!("    Error installing binary: {}", e);
            failed += 1;
            continue;
        }

        let checksum_status = if download.checksum_verified {
            "verified"
        } else {
            "unverified"
        };

        println!(
            " OK ({} KB, {})",
            download.archive_size / 1024,
            checksum_status
        );
        installed += 1;
        ready.push(agent);
    }

    let units = if install_systemd {
        write_systemd_units(&ready, &paths)?
    } else {
        Vec::new()
    };
    let kdl_path = write_agents_kdl(lock, &paths)?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Installed: {} | Skipped: {} | Failed: {}",
        installed, skipped, failed
    );

    if !ready.is_empty() {
        print_next_steps(&ready, &paths, &units, kdl_path.as_deref());
    }

    if failed > 0 {
        anyhow::bail!("{} agent(s) failed to install", failed);
    }

    Ok(())
}

/// Look an agent up by name, explaining retired agents instead of calling
/// them unknown.
fn find_agent(lock: &BundleLock, name: &str) -> Result<AgentInfo> {
    if let Some(agent) = lock.agent(name) {
        return Ok(agent);
    }
    if let Some(reason) = retired_reason(name) {
        anyhow::bail!("{} is no longer part of the bundle: {}", name, reason);
    }
    anyhow::bail!(
        "Unknown agent: {} (`zentinel bundle list` shows the bundled agents)",
        name
    )
}

/// Write one systemd unit per agent; returns the unit names written.
fn write_systemd_units(agents: &[&AgentInfo], paths: &InstallPaths) -> Result<Vec<String>> {
    let Some(ref dir) = paths.systemd_dir else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    for agent in agents {
        let name = systemd_unit_name(agent);
        let path = dir.join(&name);
        write_generated(&path, &generate_systemd_unit(agent, paths))
            .with_context(|| format!("Failed to write {}", path.display()))?;
        names.push(name);
    }
    Ok(names)
}

/// Write `agents.kdl` for every bundled agent whose binary is installed, so
/// installing agents one at a time still leaves one complete block.
fn write_agents_kdl(lock: &BundleLock, paths: &InstallPaths) -> Result<Option<PathBuf>> {
    let present: Vec<AgentInfo> = lock
        .agents()
        .into_iter()
        .filter(|a| paths.bin_dir.join(&a.binary_name).exists())
        .collect();
    if present.is_empty() {
        return Ok(None);
    }
    let path = paths.config_dir.join(AGENTS_KDL);
    write_generated(
        &path,
        &generate_agents_kdl(&present, paths, &lock.bundle.version),
    )
    .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(Some(path))
}

/// Tell the user how to start what was installed and wire it into the proxy.
fn print_next_steps(
    agents: &[&AgentInfo],
    paths: &InstallPaths,
    units: &[String],
    kdl_path: Option<&std::path::Path>,
) {
    println!();
    if let Some(kdl_path) = kdl_path {
        println!("Proxy configuration: {}", kdl_path.display());
        println!("  Add this line to zentinel.kdl, then route traffic through the agents");
        println!("  with `filter` blocks (see the comments in that file):");
        println!("    include \"{}\"", kdl_path.display());
        println!();
    }

    if !units.is_empty() {
        let (ctl, dir_note) = if paths.system_wide {
            ("sudo systemctl", None)
        } else if paths.systemd_dir == crate::bundle::install::InstallPaths::user().systemd_dir {
            ("systemctl --user", None)
        } else {
            (
                "systemctl --user",
                paths.systemd_dir.as_ref().map(|d| {
                    format!(
                        "  # user units: link them from {} into ~/.config/systemd/user first",
                        d.display()
                    )
                }),
            )
        };
        println!("To start the agents:");
        if let Some(note) = dir_note {
            println!("{note}");
        }
        println!("  {ctl} daemon-reload");
        println!("  {ctl} enable --now {}", units.join(" "));
    } else {
        println!("To start the agents (or rerun with --systemd for service units):");
        for agent in agents {
            println!("  {}", launch_command(agent, paths));
        }
    }

    for agent in agents {
        if let Some(problem) = Endpoint::for_agent(agent, paths).problem() {
            println!();
            println!("Warning: {}: {}", agent.name, problem);
        }
        if let Some(path) = required_file_path(agent, paths) {
            let legacy = std::fs::read_to_string(&path)
                .map(|c| is_legacy_generated_config(&c))
                .unwrap_or(false);
            if !path.exists() || legacy {
                println!();
                println!(
                    "Note: {} does not start without {}, in the agent's own format{}.",
                    agent.name,
                    path.display(),
                    if legacy {
                        " (the file there was written by an earlier `bundle install` and is not one)"
                    } else {
                        ""
                    }
                );
                println!(
                    "  See https://github.com/{}#configuration",
                    agent.repository
                );
            }
            continue;
        }
        let legacy = paths.config_dir.join(format!("{}.yaml", agent.name));
        if std::fs::read_to_string(&legacy)
            .map(|c| is_legacy_generated_config(&c))
            .unwrap_or(false)
        {
            println!();
            println!(
                "Note: {} was written by an earlier `bundle install`; no agent reads it. You can delete it.",
                legacy.display()
            );
        }
    }
}

/// Status command implementation
fn cmd_status(lock: &BundleLock, verbose: bool) -> Result<()> {
    let paths = InstallPaths::detect();
    let status = BundleStatus::check(lock, &paths);

    println!("{}", status.display());

    if verbose {
        println!();
        println!("Paths:");
        println!("  Binaries: {}", paths.bin_dir.display());
        println!("  Configs:  {}", paths.config_dir.display());
        if let Some(ref sd) = paths.systemd_dir {
            println!("  Systemd:  {}", sd.display());
        }
    }

    Ok(())
}

/// List command implementation
fn cmd_list(lock: &BundleLock, verbose: bool) -> Result<()> {
    println!("Zentinel Bundle Agents");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Bundle version: {}", lock.bundle.version);
    println!();

    for agent in lock.agents() {
        println!("  {} v{}", agent.name, agent.version);
        if verbose {
            println!("    Repository: {}", agent.repository);
            println!("    Binary:     {}", agent.binary_name);
            println!(
                "    Transport:  {}",
                match agent.transport {
                    crate::bundle::lock::Transport::Uds => "unix socket (--socket)".to_string(),
                    crate::bundle::lock::Transport::Grpc { port } =>
                        format!("gRPC (--grpc-address 127.0.0.1:{port})"),
                }
            );
            if let Some(req) = &agent.required_file {
                println!("    Needs:      {} {}", req.flag, req.file);
            }
            println!(
                "    URL:        {}",
                agent.download_url(detect_os(), detect_arch())
            );
            println!();
        }
    }

    if !verbose {
        println!();
        println!("Use --verbose for more details");
    }

    Ok(())
}

/// Uninstall command implementation
fn cmd_uninstall(lock: &BundleLock, agent: Option<String>, dry_run: bool) -> Result<()> {
    let paths = InstallPaths::detect();

    println!("Zentinel Bundle Uninstaller");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // A retired agent is no longer in the lock, but a binary installed
    // earlier may still be there to remove.
    if let Some(name) = agent.as_deref().filter(|n| retired_reason(n).is_some()) {
        let binary = format!("zentinel-{}-agent", name);
        let path = paths.bin_dir.join(&binary);
        if dry_run {
            if path.exists() {
                println!("[DRY RUN] Would uninstall:");
                println!("  {} ({})", name, path.display());
            }
        } else if uninstall_binary(&paths.bin_dir, &binary)? {
            println!("  Removed {}", name);
        } else {
            println!("  {} is not installed in {}", name, paths.bin_dir.display());
        }
        return Ok(());
    }

    let agents: Vec<_> = match &agent {
        Some(name) => vec![find_agent(lock, name)?],
        None => lock.agents(),
    };

    if dry_run {
        println!("[DRY RUN] Would uninstall:");
        for agent in &agents {
            let bin_path = paths.bin_dir.join(&agent.binary_name);
            if bin_path.exists() {
                println!("  {} ({})", agent.name, bin_path.display());
            }
        }
        return Ok(());
    }

    let mut removed = 0;
    for agent in &agents {
        if uninstall_binary(&paths.bin_dir, &agent.binary_name)? {
            println!("  Removed {}", agent.name);
            removed += 1;
        }
    }

    println!();
    println!("Removed {} agent(s)", removed);
    println!();
    println!(
        "Note: Configuration files in {} were preserved",
        paths.config_dir.display()
    );

    Ok(())
}

/// Update command implementation
fn cmd_update(current_lock: &BundleLock, apply: bool) -> Result<()> {
    println!("Checking for bundle updates...");
    println!();

    // Fetch latest lock file
    let rt = tokio::runtime::Runtime::new()?;
    let latest_lock = rt
        .block_on(BundleLock::fetch_latest())
        .context("Failed to fetch latest bundle versions")?;

    println!("Current bundle: {}", current_lock.bundle.version);
    println!("Latest bundle:  {}", latest_lock.bundle.version);
    println!();

    // Compare versions
    let mut updates_available = false;
    println!("{:<15} {:<12} {:<12}", "Agent", "Current", "Latest");
    println!("{}", "─".repeat(40));

    for (name, latest_version) in &latest_lock.agents {
        let current_version = current_lock
            .agents
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or("-");
        let is_update = current_version != latest_version;

        if is_update {
            updates_available = true;
            println!(
                "{:<15} {:<12} {:<12} ←",
                name, current_version, latest_version
            );
        } else {
            println!(
                "{:<15} {:<12} {:<12}",
                name, current_version, latest_version
            );
        }
    }

    if !updates_available {
        println!();
        println!("All agents are up to date.");
        return Ok(());
    }

    println!();
    if apply {
        println!("To update, run: zentinel bundle install --force");
    } else {
        println!("Updates are available. Run with --apply to update.");
        println!("  zentinel bundle update --apply");
    }

    Ok(())
}
