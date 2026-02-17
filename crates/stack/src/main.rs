//! zentinel-stack: All-in-one launcher for Zentinel proxy and agents
//!
//! Spawns and manages Zentinel proxy along with configured agents as child processes.
//! Designed for development and simple production deployments.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

/// zentinel-stack: All-in-one launcher for Zentinel proxy and agents
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to zentinel configuration file
    #[arg(short, long, default_value = "zentinel.kdl")]
    config: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info", env = "RUST_LOG")]
    log_level: String,

    /// Start only the proxy (agents managed externally)
    #[arg(long)]
    proxy_only: bool,

    /// Start only agents (proxy managed externally)
    #[arg(long)]
    agents_only: bool,

    /// Validate configuration and exit
    #[arg(long)]
    dry_run: bool,

    /// Shutdown timeout in seconds
    #[arg(long, default_value = "30")]
    shutdown_timeout: u64,

    /// Startup timeout in seconds (wait for agents to be ready)
    #[arg(long, default_value = "10")]
    startup_timeout: u64,
}

/// Agent configuration for zentinel-stack
#[derive(Debug, Clone)]
struct AgentConfig {
    id: String,
    command: Vec<String>,
    restart_policy: RestartPolicy,
    restart_delay_ms: u64,
    max_restarts: u32,
    env: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

/// Managed process state
struct ManagedProcess {
    config: AgentConfig,
    child: Option<Child>,
    restart_count: u32,
    running: bool,
}

impl ManagedProcess {
    fn new(config: AgentConfig) -> Self {
        Self {
            config,
            child: None,
            restart_count: 0,
            running: false,
        }
    }

    async fn start(&mut self) -> Result<()> {
        if self.config.command.is_empty() {
            return Ok(()); // External agent, don't manage
        }

        let (program, args) = self.config.command.split_first().context("Empty command")?;

        info!(
            agent = %self.config.id,
            command = %program,
            "Starting agent"
        );

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Set environment variables
        for (key, value) in &self.config.env {
            cmd.env(key, value);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn agent '{}': {}", self.config.id, program))?;

        let pid = child.id().unwrap_or(0);
        info!(
            agent = %self.config.id,
            pid = pid,
            "Agent started"
        );

        self.child = Some(child);
        self.running = true;

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(ref mut child) = self.child {
            info!(agent = %self.config.id, "Stopping agent");

            // Try graceful shutdown first
            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                }
            }

            // Wait for graceful shutdown
            tokio::select! {
                _ = sleep(Duration::from_secs(5)) => {
                    warn!(agent = %self.config.id, "Agent didn't stop gracefully, killing");
                    let _ = child.kill().await;
                }
                result = child.wait() => {
                    debug!(agent = %self.config.id, ?result, "Agent stopped");
                }
            }
        }

        self.child = None;
        self.running = false;

        Ok(())
    }

    async fn check_and_restart(&mut self, shutdown: &AtomicBool) -> Result<bool> {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(false);
        }

        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process exited
                    self.running = false;
                    let should_restart = match self.config.restart_policy {
                        RestartPolicy::Always => true,
                        RestartPolicy::OnFailure => !status.success(),
                        RestartPolicy::Never => false,
                    };

                    if should_restart {
                        if self.config.max_restarts > 0
                            && self.restart_count >= self.config.max_restarts
                        {
                            error!(
                                agent = %self.config.id,
                                restarts = self.restart_count,
                                max = self.config.max_restarts,
                                "Max restarts exceeded"
                            );
                            return Ok(false);
                        }

                        warn!(
                            agent = %self.config.id,
                            status = ?status,
                            restart_count = self.restart_count,
                            "Agent exited, restarting"
                        );

                        sleep(Duration::from_millis(self.config.restart_delay_ms)).await;
                        self.restart_count += 1;
                        self.child = None;
                        self.start().await?;
                        return Ok(true);
                    } else {
                        info!(
                            agent = %self.config.id,
                            status = ?status,
                            "Agent exited (no restart)"
                        );
                        return Ok(false);
                    }
                }
                Ok(None) => {
                    // Still running
                    return Ok(true);
                }
                Err(e) => {
                    error!(agent = %self.config.id, error = %e, "Failed to check process status");
                    return Ok(false);
                }
            }
        }

        Ok(false)
    }
}

/// Helper to get string from first entry
fn get_first_string(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Helper to get string from child node
fn get_child_string(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.children()
        .and_then(|c| c.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Helper to get integer from child node
fn get_child_int(node: &kdl::KdlNode, name: &str) -> Option<i64> {
    node.children()
        .and_then(|c| c.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer())
        .map(|v| v as i64)
}

/// Parse agent configurations from the zentinel config
fn parse_agent_configs(config_path: &PathBuf) -> Result<Vec<AgentConfig>> {
    // Read and parse the KDL config
    let content = std::fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config: {:?}", config_path))?;

    let doc: kdl::KdlDocument = content.parse().context("Failed to parse KDL config")?;

    let mut agents = Vec::new();

    // Find agents section
    if let Some(agents_node) = doc.get("agents") {
        if let Some(children) = agents_node.children() {
            for node in children.nodes() {
                if node.name().value() == "agent" {
                    // Get agent ID from first argument
                    let id = get_first_string(node).unwrap_or_else(|| "unknown".to_string());

                    // Parse command if present
                    let mut command = Vec::new();
                    if let Some(node_children) = node.children() {
                        if let Some(cmd_node) = node_children.get("command") {
                            for entry in cmd_node.entries() {
                                if let Some(s) = entry.value().as_string() {
                                    command.push(s.to_string());
                                }
                            }
                        }
                    }

                    // Parse restart policy
                    let restart_policy = get_child_string(node, "restart-policy")
                        .map(|s| match s.as_str() {
                            "always" => RestartPolicy::Always,
                            "on-failure" => RestartPolicy::OnFailure,
                            "never" => RestartPolicy::Never,
                            _ => RestartPolicy::OnFailure,
                        })
                        .unwrap_or(RestartPolicy::OnFailure);

                    // Parse restart delay
                    let restart_delay_ms =
                        get_child_int(node, "restart-delay-ms").unwrap_or(1000) as u64;

                    // Parse max restarts
                    let max_restarts = get_child_int(node, "max-restarts").unwrap_or(0) as u32;

                    // Parse environment
                    let mut env = HashMap::new();
                    if let Some(node_children) = node.children() {
                        if let Some(env_node) = node_children.get("env") {
                            if let Some(env_children) = env_node.children() {
                                for env_entry in env_children.nodes() {
                                    let key = env_entry.name().value().to_string();
                                    if let Some(value_str) = get_first_string(env_entry) {
                                        // Expand environment variables
                                        let expanded = if value_str.starts_with("${")
                                            && value_str.ends_with("}")
                                        {
                                            let var_name = &value_str[2..value_str.len() - 1];
                                            std::env::var(var_name).unwrap_or_default()
                                        } else {
                                            value_str
                                        };
                                        env.insert(key, expanded);
                                    }
                                }
                            }
                        }
                    }

                    if !command.is_empty() {
                        agents.push(AgentConfig {
                            id,
                            command,
                            restart_policy,
                            restart_delay_ms,
                            max_restarts,
                            env,
                        });
                    }
                }
            }
        }
    }

    Ok(agents)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .with_target(true)
        .json()
        .init();

    info!(
        config = ?args.config,
        version = env!("CARGO_PKG_VERSION"),
        "Starting zentinel-stack"
    );

    // Parse configuration
    let agent_configs = parse_agent_configs(&args.config)?;

    info!(
        agent_count = agent_configs.len(),
        "Parsed {} agent(s) with commands",
        agent_configs.len()
    );

    // Dry run - just validate and exit
    if args.dry_run {
        info!("Configuration valid, exiting (dry-run mode)");
        for agent in &agent_configs {
            info!(
                agent = %agent.id,
                command = ?agent.command,
                restart_policy = ?agent.restart_policy,
                "Agent configuration"
            );
        }
        return Ok(());
    }

    // Set up shutdown handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    // Handle signals
    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler");
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }

        shutdown_clone.store(true, Ordering::Relaxed);
    });

    // Start agents
    let mut agents: Vec<ManagedProcess> = Vec::new();

    if !args.proxy_only {
        for config in agent_configs {
            let mut process = ManagedProcess::new(config);
            if let Err(e) = process.start().await {
                error!(error = %e, "Failed to start agent");
                // Continue with other agents
            }
            agents.push(process);
        }

        // Wait for agents to be ready
        info!(
            timeout = args.startup_timeout,
            "Waiting for agents to be ready"
        );
        sleep(Duration::from_secs(args.startup_timeout.min(5))).await;
    }

    // Start proxy
    let mut proxy: Option<Child> = None;

    if !args.agents_only {
        info!(config = ?args.config, "Starting Zentinel proxy");

        let proxy_child = Command::new("zentinel")
            .arg("--config")
            .arg(&args.config)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn Zentinel proxy")?;

        let pid = proxy_child.id().unwrap_or(0);
        info!(pid = pid, "Zentinel proxy started");
        proxy = Some(proxy_child);
    }

    // Main monitoring loop
    info!("zentinel-stack running, press Ctrl+C to stop");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Check proxy
        if let Some(ref mut p) = proxy {
            match p.try_wait() {
                Ok(Some(status)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        info!("Proxy stopped during shutdown");
                    } else {
                        error!(status = ?status, "Proxy exited unexpectedly");
                        // Initiate shutdown
                        shutdown.store(true, Ordering::Relaxed);
                    }
                    break;
                }
                Ok(None) => {
                    // Still running
                }
                Err(e) => {
                    error!(error = %e, "Failed to check proxy status");
                }
            }
        }

        // Check agents
        if !args.proxy_only {
            for agent in &mut agents {
                if let Err(e) = agent.check_and_restart(&shutdown).await {
                    error!(agent = %agent.config.id, error = %e, "Agent check failed");
                }
            }
        }

        sleep(Duration::from_millis(500)).await;
    }

    // Shutdown sequence
    info!("Initiating shutdown");

    // Stop proxy first
    if let Some(ref mut p) = proxy {
        info!("Stopping proxy");
        #[cfg(unix)]
        {
            if let Some(pid) = p.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(args.shutdown_timeout)) => {
                warn!("Proxy didn't stop gracefully, killing");
                let _ = p.kill().await;
            }
            result = p.wait() => {
                info!(?result, "Proxy stopped");
            }
        }
    }

    // Stop agents
    if !args.proxy_only {
        for agent in &mut agents {
            if let Err(e) = agent.stop().await {
                error!(agent = %agent.config.id, error = %e, "Failed to stop agent");
            }
        }
    }

    info!("zentinel-stack shutdown complete");
    Ok(())
}
