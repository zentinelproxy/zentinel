//! Sentinel Proxy - Main entry point
//!
//! A security-first reverse proxy built on Pingora with sleepable ops at the edge.

// Use jemalloc as the global allocator for better performance
// jemalloc is optimized for multi-threaded allocation-heavy workloads
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pingora::prelude::*;
use std::sync::Arc;
use tracing::{error, info, warn};

use sentinel_config::Config;
use sentinel_proxy::{ReloadTrigger, SignalManager, SignalType, SentinelProxy};

/// Version string combining Cargo semver and CalVer release tag
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (release ",
    env!("SENTINEL_CALVER"),
    ", commit ",
    env!("SENTINEL_COMMIT"),
    ")"
);

/// Sentinel - A security-first reverse proxy built on Pingora
#[derive(Parser, Debug)]
#[command(name = "sentinel")]
#[command(author, version = VERSION, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file path
    #[arg(short = 'c', long = "config", env = "SENTINEL_CONFIG")]
    config: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,

    /// Enable verbose logging (debug level)
    #[arg(long = "verbose")]
    verbose: bool,

    /// Run in daemon mode (background)
    #[arg(short = 'd', long = "daemon")]
    daemon: bool,

    /// Upgrade from a running instance
    #[arg(short = 'u', long = "upgrade")]
    upgrade: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate configuration file and exit
    Test {
        /// Configuration file to test
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Run the proxy server (default)
    Run {
        /// Configuration file path
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle test flag or test subcommand
    if cli.test {
        return test_config(cli.config.as_deref());
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::Test { config }) => {
            return test_config(config.as_deref().or(cli.config.as_deref()));
        }
        Some(Commands::Run { config }) => {
            return run_server(
                config.or(cli.config),
                cli.verbose,
                cli.daemon,
                cli.upgrade,
            );
        }
        None => {
            // Default: run the server
            return run_server(cli.config, cli.verbose, cli.daemon, cli.upgrade);
        }
    }
}

/// Test configuration file and exit
fn test_config(config_path: Option<&str>) -> Result<()> {
    // Initialize minimal logging for config test
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    let config = match config_path {
        Some(path) => {
            info!("Testing configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Testing embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Validate the configuration
    config.validate().context("Configuration validation failed")?;

    // Additional validation checks
    let route_count = config.routes.len();
    let upstream_count = config.upstreams.len();
    let listener_count = config.listeners.len();

    info!("Configuration test successful:");
    info!("  - {} listener(s)", listener_count);
    info!("  - {} route(s)", route_count);
    info!("  - {} upstream(s)", upstream_count);

    // Check for potential issues
    for route in &config.routes {
        if let Some(ref upstream) = route.upstream {
            if !config.upstreams.contains_key(upstream) {
                warn!(
                    "Route '{}' references undefined upstream '{}'",
                    route.id, upstream
                );
            }
        }
    }

    println!("sentinel: configuration file {} test is successful",
        config_path.unwrap_or("(embedded)"));

    Ok(())
}

/// Run the proxy server
fn run_server(
    config_path: Option<String>,
    verbose: bool,
    daemon: bool,
    upgrade: bool,
) -> Result<()> {
    // Initialize logging based on verbose flag
    let log_level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level))
        )
        .init();

    // Build Pingora options
    let mut pingora_opt = Opt::default();
    pingora_opt.daemon = daemon;
    pingora_opt.upgrade = upgrade;
    // Note: We'll configure threads via ServerConf after loading our config

    // Get config path with priority: CLI arg > env var > None (embedded default)
    let effective_config_path = config_path
        .or_else(|| std::env::var("SENTINEL_CONFIG").ok());

    // Handle config file creation/loading
    let effective_config_path = match effective_config_path {
        Some(path) => {
            let config_path = std::path::Path::new(&path);
            if config_path.exists() {
                info!("Loading configuration from: {}", path);
                Some(path)
            } else {
                // Config file doesn't exist - create it with default content
                info!("Configuration file not found: {}", path);
                if let Err(e) = create_default_config_file(config_path) {
                    warn!("Failed to create default config file: {}", e);
                    info!("Using embedded default configuration instead");
                    None
                } else {
                    info!("Created default configuration at: {}", path);
                    Some(path)
                }
            }
        }
        None => {
            info!("No configuration specified, using embedded default configuration");
            None
        }
    };

    // Create signal manager for cross-thread communication
    let signal_manager = Arc::new(SignalManager::new());

    // Setup signal handlers (runs in separate thread)
    setup_signal_handlers(signal_manager.sender());

    // Create runtime for async initialization and signal handling
    let runtime = tokio::runtime::Runtime::new()?;

    // Create proxy with configuration
    let proxy = runtime.block_on(async {
        SentinelProxy::new(effective_config_path.as_deref()).await
    })?;

    // Get config manager for reload operations
    let config_manager = proxy.config_manager.clone();

    // Get initial config for server setup
    let config = proxy.config_manager.current();

    // Configure Pingora ServerConf with our settings
    let worker_threads = if config.server.worker_threads > 0 {
        config.server.worker_threads
    } else {
        num_cpus::get() // Default to CPU count
    };

    // Create Pingora ServerConf with performance settings
    let mut pingora_conf = pingora::server::configuration::ServerConf::default();
    pingora_conf.threads = worker_threads;
    pingora_conf.work_stealing = true;
    pingora_conf.upstream_keepalive_pool_size = 256; // Increase from default 128

    info!(
        worker_threads = worker_threads,
        upstream_pool_size = pingora_conf.upstream_keepalive_pool_size,
        "Configuring Pingora server"
    );

    // Create Pingora server with our configuration
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), pingora_conf);
    server.bootstrap();

    // Create proxy service
    let mut proxy_service = http_proxy_service(&server.configuration, proxy);

    // Configure listening addresses from config
    for listener in &config.listeners {
        match listener.protocol {
            sentinel_config::ListenerProtocol::Http => {
                proxy_service.add_tcp(&listener.address);
                info!("HTTP listening on: {}", listener.address);
            }
            sentinel_config::ListenerProtocol::Https => {
                match &listener.tls {
                    Some(tls_config) => {
                        let cert_path = tls_config.cert_file.to_string_lossy();
                        let key_path = tls_config.key_file.to_string_lossy();

                        // Validate certificate files exist
                        if !tls_config.cert_file.exists() {
                            error!(
                                listener_id = %listener.id,
                                cert_file = %cert_path,
                                "TLS certificate file not found"
                            );
                            continue;
                        }
                        if !tls_config.key_file.exists() {
                            error!(
                                listener_id = %listener.id,
                                key_file = %key_path,
                                "TLS key file not found"
                            );
                            continue;
                        }

                        match proxy_service.add_tls(&listener.address, &cert_path, &key_path) {
                            Ok(()) => {
                                info!(
                                    listener_id = %listener.id,
                                    address = %listener.address,
                                    cert_file = %cert_path,
                                    min_tls_version = ?tls_config.min_version,
                                    client_auth = tls_config.client_auth,
                                    "HTTPS listening on: {}", listener.address
                                );
                            }
                            Err(e) => {
                                error!(
                                    listener_id = %listener.id,
                                    address = %listener.address,
                                    error = %e,
                                    "Failed to configure TLS listener"
                                );
                            }
                        }
                    }
                    None => {
                        error!(
                            listener_id = %listener.id,
                            address = %listener.address,
                            "HTTPS listener requires TLS configuration"
                        );
                    }
                }
            }
            _ => {
                warn!("Unsupported protocol: {:?}", listener.protocol);
            }
        }
    }

    // Add proxy service to server
    server.add_service(proxy_service);

    // Enable auto-reload file watching if configured
    let auto_reload_enabled = config.server.auto_reload;
    let has_config_file = effective_config_path.is_some();

    if auto_reload_enabled && has_config_file {
        let config_manager_watch = config_manager.clone();
        runtime.spawn(async move {
            if let Err(e) = config_manager_watch.start_watching().await {
                error!("Failed to start config file watcher: {}", e);
                error!("Auto-reload disabled, use SIGHUP for manual reload");
            }
        });
    } else if auto_reload_enabled && !has_config_file {
        warn!("auto-reload enabled but no config file specified (using embedded config)");
        warn!("Auto-reload requires a config file path");
    }

    // Spawn signal handler task in the runtime
    let signal_manager_clone = signal_manager.clone();
    runtime.spawn(async move {
        run_signal_handler(signal_manager_clone, config_manager).await;
    });

    info!("Sentinel proxy started successfully");
    info!("Configuration hot reload enabled (SIGHUP)");
    if auto_reload_enabled && has_config_file {
        info!("Auto-reload enabled (watching config file)");
    }
    info!("Graceful shutdown enabled (SIGTERM/SIGINT)");

    // Run server forever
    server.run_forever();
}

/// Setup OS signal handlers
///
/// Registers handlers for SIGTERM, SIGINT, and SIGHUP and forwards them
/// to the async runtime via the signal manager.
fn setup_signal_handlers(signal_tx: std::sync::mpsc::Sender<SignalType>) {
    use signal_hook::consts::signal::*;
    use signal_hook::iterator::Signals;
    use std::thread;

    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGHUP]).expect("Failed to register signal handlers");

    thread::spawn(move || {
        for sig in signals.forever() {
            let signal_type = match sig {
                SIGTERM | SIGINT => {
                    info!("Received shutdown signal ({}), initiating graceful shutdown",
                        if sig == SIGTERM { "SIGTERM" } else { "SIGINT" });
                    SignalType::Shutdown
                }
                SIGHUP => {
                    info!("Received SIGHUP, triggering configuration reload");
                    SignalType::Reload
                }
                _ => continue,
            };

            if signal_tx.send(signal_type).is_err() {
                // Channel closed, runtime is shutting down
                break;
            }

            // For shutdown, we also need to exit after sending
            if signal_type == SignalType::Shutdown {
                // Give the async handler time to process
                thread::sleep(std::time::Duration::from_secs(5));
                // Force exit if graceful shutdown takes too long
                error!("Graceful shutdown timeout, forcing exit");
                std::process::exit(1);
            }
        }
    });
}

/// Create a default configuration file at the specified path
///
/// Creates parent directories if needed and writes the embedded default config.
fn create_default_config_file(path: &std::path::Path) -> Result<()> {
    use std::fs;
    use sentinel_config::DEFAULT_CONFIG_KDL;

    // Create parent directories if they don't exist
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }
    }

    // Write the default config
    fs::write(path, DEFAULT_CONFIG_KDL.trim_start())
        .with_context(|| format!("Failed to write default config to: {:?}", path))?;

    Ok(())
}

/// Async signal handler task
///
/// Receives signals from the signal manager and performs the appropriate action.
async fn run_signal_handler(
    signal_manager: Arc<SignalManager>,
    config_manager: Arc<sentinel_proxy::ConfigManager>,
) {
    loop {
        // Use spawn_blocking to wait for signals without blocking the async runtime
        let signal_manager_clone = signal_manager.clone();
        let signal = tokio::task::spawn_blocking(move || {
            signal_manager_clone.recv_blocking()
        }).await;

        match signal {
            Ok(Some(SignalType::Reload)) => {
                info!("Processing configuration reload request");
                match config_manager.reload(ReloadTrigger::Signal).await {
                    Ok(()) => {
                        info!("Configuration reloaded successfully");
                    }
                    Err(e) => {
                        error!("Configuration reload failed: {}", e);
                        error!("Continuing with previous configuration");
                    }
                }
            }
            Ok(Some(SignalType::Shutdown)) => {
                info!("Processing graceful shutdown request");
                // Note: Connection draining is handled by Pingora's internal mechanisms
                // We give it a moment to start draining, then the signal thread will force exit
                info!("Shutdown initiated, draining connections...");
                // Exit cleanly - Pingora will handle connection draining
                std::process::exit(0);
            }
            Ok(None) => {
                // Channel closed
                info!("Signal channel closed, stopping signal handler");
                break;
            }
            Err(e) => {
                error!("Signal handler task panicked: {}", e);
                break;
            }
        }
    }
}
