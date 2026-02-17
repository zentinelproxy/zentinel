//! Bundle CLI command handlers
//!
//! Implements the `zentinel bundle` subcommand and its subcommands.

use crate::bundle::fetch::{detect_arch, detect_os, download_agent};
use crate::bundle::install::{
    generate_default_config, generate_systemd_service, install_binary, install_config,
    install_systemd_service, uninstall_binary, InstallPaths,
};
use crate::bundle::lock::BundleLock;
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

        /// Also install systemd service files
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
    if paths.system_wide {
        println!("Mode:           system-wide (requires root)");
    } else {
        println!("Mode:           user-local");
    }
    println!();

    // Get agents to install
    let agents: Vec<_> = match &agent {
        Some(name) => {
            let agent_info = lock
                .agent(name)
                .ok_or_else(|| anyhow::anyhow!("Unknown agent: {}", name))?;
            vec![agent_info]
        }
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
        }
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

        // Install config
        let config_content = generate_default_config(&agent.name);
        let config_path = install_config(&paths.config_dir, &agent.name, &config_content, force)
            .context("Failed to install config")?;

        // Install systemd service if requested
        if install_systemd {
            if let Some(ref systemd_dir) = paths.systemd_dir {
                let bin_path = paths.bin_dir.join(&agent.binary_name);
                let service_content =
                    generate_systemd_service(&agent.name, &bin_path, &config_path);
                install_systemd_service(systemd_dir, &agent.name, &service_content)
                    .context("Failed to install systemd service")?;
            }
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
    }

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "Installed: {} | Skipped: {} | Failed: {}",
        installed, skipped, failed
    );

    if installed > 0 {
        println!();
        println!("To start the agents:");
        if paths.system_wide && install_systemd {
            println!("  sudo systemctl daemon-reload");
            println!("  sudo systemctl start zentinel.target");
        } else {
            println!("  # Add agent endpoints to your zentinel.kdl config");
            println!("  # See: https://zentinelproxy.io/docs/bundle");
        }
    }

    if failed > 0 {
        anyhow::bail!("{} agent(s) failed to install", failed);
    }

    Ok(())
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

    let agents: Vec<_> = match &agent {
        Some(name) => {
            let agent_info = lock
                .agent(name)
                .ok_or_else(|| anyhow::anyhow!("Unknown agent: {}", name))?;
            vec![agent_info]
        }
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
