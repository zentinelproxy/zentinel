// Allow field reassignment for Pingora's Opt/ServerConf structs
#![allow(clippy::field_reassign_with_default)]

//! Zentinel Proxy - Main entry point
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
use tracing::{debug, error, info, warn};

use zentinel_config::server::{AcmeChallengeType, AcmeConfig};
use zentinel_config::Config;
use zentinel_proxy::acme::{
    AcmeClient, AcmeError, CertificateStorage, ChallengeManager, RenewalScheduler,
};
use zentinel_proxy::bundle::{run_bundle_command, BundleArgs};
use zentinel_proxy::tls::{self, CertificateReloader, HotReloadableSniResolver};
use zentinel_proxy::{ReloadTrigger, SignalManager, SignalType, ZentinelProxy};

/// Version string combining Cargo semver and CalVer release tag
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (release ",
    env!("ZENTINEL_CALVER"),
    ", commit ",
    env!("ZENTINEL_COMMIT"),
    ")"
);

/// Zentinel - A security-first reverse proxy built on Pingora
#[derive(Parser, Debug)]
#[command(name = "zentinel")]
#[command(author, version = VERSION, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Configuration file, or a directory of KDL files read as one configuration
    #[arg(short = 'c', long = "config", env = "ZENTINEL_CONFIG")]
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
        /// Configuration file (or directory) to test
        #[arg(short = 'c', long = "config")]
        config: Option<String>,

        /// Fail if any setting is being ignored (unknown keys, run-together
        /// lines, values that fall back to a default)
        #[arg(long = "strict")]
        strict: bool,
    },
    /// Run the proxy server (default)
    Run {
        /// Configuration file (or directory)
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },
    /// Validate configuration with connectivity checks
    Validate {
        /// Configuration file (or directory) to validate
        #[arg(short = 'c', long = "config")]
        config: Option<String>,

        /// Skip network connectivity checks
        #[arg(long = "skip-network")]
        skip_network: bool,

        /// Skip agent connectivity checks
        #[arg(long = "skip-agents")]
        skip_agents: bool,

        /// Skip certificate validation
        #[arg(long = "skip-certs")]
        skip_certs: bool,
    },
    /// Lint configuration for best practices
    Lint {
        /// Configuration file (or directory) to lint
        #[arg(short = 'c', long = "config")]
        config: Option<String>,
    },

    /// Manage bundled agents (install, status, update)
    Bundle(BundleArgs),
}

fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    // This must be done before Pingora initializes its TLS contexts
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();

    // Handle test flag or test subcommand
    if cli.test {
        return test_config(cli.config.as_deref(), false);
    }

    // Handle subcommands
    match cli.command {
        Some(Commands::Test { config, strict }) => {
            test_config(config.as_deref().or(cli.config.as_deref()), strict)
        }
        Some(Commands::Run { config }) => {
            run_server(config.or(cli.config), cli.verbose, cli.daemon, cli.upgrade)
        }
        Some(Commands::Validate {
            config,
            skip_network,
            skip_agents,
            skip_certs,
        }) => validate_config(
            config.as_deref().or(cli.config.as_deref()),
            skip_network,
            skip_agents,
            skip_certs,
        ),
        Some(Commands::Lint { config }) => lint_config(config.as_deref().or(cli.config.as_deref())),
        Some(Commands::Bundle(args)) => {
            // Initialize minimal logging for bundle commands
            tracing_subscriber::fmt()
                .with_target(false)
                .with_level(true)
                .init();
            run_bundle_command(args)
        }
        None => {
            // Default: run the server
            run_server(cli.config, cli.verbose, cli.daemon, cli.upgrade)
        }
    }
}

/// Test configuration file and exit
///
/// Also prints every setting that is being ignored -- the findings of the
/// unknown-key check that `lint` runs, without lint's best-practice advice.
/// `test` is what operators run before a reload, so a typo'd key reported
/// only by `lint` reached almost nobody. The findings are warnings and leave
/// the exit code alone, since such configs have always passed; `strict` makes
/// them fatal.
fn test_config(config_path: Option<&str>, strict: bool) -> Result<()> {
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
    config
        .validate()
        .context("Configuration validation failed")?;

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

    let ignored = ignored_settings(config_path);
    for message in &ignored {
        println!("  ⚠  {}", message);
    }
    if strict && !ignored.is_empty() {
        anyhow::bail!(
            "configuration file {} has {} setting(s) that are being ignored (--strict)",
            config_path.unwrap_or("(embedded)"),
            ignored.len()
        );
    }

    println!(
        "zentinel: configuration file {} test is successful",
        config_path.unwrap_or("(embedded)")
    );

    Ok(())
}

/// Settings in the configuration file that no parser applies.
///
/// This needs the source text rather than the parsed config: by the time a
/// `Config` exists, keys no parser recognised have already been dropped. So it
/// is only meaningful for a configuration read from files, and the embedded
/// default yields nothing.
///
/// Every file the configuration is read from is checked -- the files of a
/// directory, and whatever `include` pulls in. Only the named file used to be,
/// so `test --strict` passed a typo in any included file. When there is more
/// than one file, each warning starts with the file it is in.
fn ignored_settings(config_path: Option<&str>) -> Vec<String> {
    let Some(path) = config_path else {
        return Vec::new();
    };
    let read = || -> Result<Vec<(std::path::PathBuf, String)>> {
        Config::source_files(path)?
            .into_iter()
            .map(|file| {
                let text = std::fs::read_to_string(&file)
                    .with_context(|| format!("Failed to read {}", file.display()))?;
                Ok((file, text))
            })
            .collect()
    };
    match read() {
        Ok(sources) => {
            let mut result = zentinel_config::validate::ValidationResult::new();
            if let [(_, source)] = sources.as_slice() {
                zentinel_config::validate::unknown_keys::check_unknown_keys(source, &mut result);
            } else {
                zentinel_config::validate::unknown_keys::check_unknown_keys_in_files(
                    &sources,
                    &mut result,
                );
            }
            result.warnings.into_iter().map(|w| w.message).collect()
        }
        Err(e) => {
            warn!(path = %path, error = %e, "Could not re-read config to check for ignored settings");
            Vec::new()
        }
    }
}

/// Validate configuration with connectivity checks
fn validate_config(
    config_path: Option<&str>,
    skip_network: bool,
    skip_agents: bool,
    skip_certs: bool,
) -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Load configuration
    let config = match config_path {
        Some(path) => {
            info!("Validating configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Validating embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Schema validation (sync)
    config
        .validate()
        .context("Configuration schema validation failed")?;

    println!("✓ Configuration schema valid");

    // Runtime validation (async)
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        use zentinel_config::validate::*;

        let opts = ValidationOpts {
            skip_network,
            skip_agents,
            skip_certs,
        };

        let mut result = ValidationResult::new();

        // Network validation
        if !opts.skip_network {
            println!("Checking upstream connectivity...");
            result.merge(network::validate_upstreams(&config).await);
        }

        // Certificate validation
        if !opts.skip_certs {
            println!("Validating TLS certificates...");
            result.merge(certs::validate_certificates(&config).await);
        }

        // Agent validation
        if !opts.skip_agents {
            println!("Checking agent connectivity...");
            result.merge(agents::validate_agents(&config).await);
        }

        result
    });

    // Print results
    if result.errors.is_empty() {
        println!("✓ All validation checks passed");

        if !result.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &result.warnings {
                println!("  ⚠  {}", warning.message);
            }
        }

        std::process::exit(0);
    } else {
        println!("✗ Validation failed\n");
        println!("Errors:");
        for error in &result.errors {
            println!("  ✗ {}", error.message);
        }

        if !result.warnings.is_empty() {
            println!("\nWarnings:");
            for warning in &result.warnings {
                println!("  ⚠  {}", warning.message);
            }
        }

        std::process::exit(1);
    }
}

/// Lint configuration for best practices
fn lint_config(config_path: Option<&str>) -> Result<()> {
    // Initialize minimal logging
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Load configuration
    let config = match config_path {
        Some(path) => {
            info!("Linting configuration file: {}", path);
            Config::from_file(path).context("Failed to load configuration file")?
        }
        None => {
            info!("Linting embedded default configuration");
            Config::default_embedded().context("Failed to load embedded configuration")?
        }
    };

    // Schema validation first
    config
        .validate()
        .context("Configuration schema validation failed")?;

    // Lint for best practices
    let mut result = zentinel_config::validate::lint::lint_config(&config);

    for message in ignored_settings(config_path) {
        result.add_warning(zentinel_config::validate::ValidationWarning::new(message));
    }

    // Print results
    if result.warnings.is_empty() {
        println!("✓ No best practice issues found");
        std::process::exit(0);
    } else {
        println!(
            "⚠  Configuration has {} best practice warnings:\n",
            result.warnings.len()
        );
        for warning in &result.warnings {
            println!("  ⚠  {}", warning.message);
        }

        // Lint exits with 0 even with warnings (they're recommendations)
        std::process::exit(0);
    }
}

/// State produced by ACME initialization, used to wire components into the proxy
struct AcmeState {
    /// Challenge manager for HTTP-01 challenge handling
    challenge_manager: Arc<ChallengeManager>,
    /// Renewal schedulers (one per ACME configuration block)
    schedulers: Vec<RenewalScheduler>,
}

/// Initialize ACME for all listeners and SNI certificates that have ACME configured
///
/// This function:
/// 1. Creates storage, client, and challenge manager for each ACME configuration
/// 2. Initializes (or loads) the ACME account with Let's Encrypt
/// 3. Obtains initial certificates if they don't exist yet
/// 4. Returns the ACME state for wiring into the proxy and background schedulers
///
/// For HTTP-01 challenges during initial issuance, a temporary HTTP server is
/// spawned to serve challenge responses (since Pingora isn't running yet).
async fn initialize_acme(
    config: &Config,
    sni_resolver: Option<Arc<HotReloadableSniResolver>>,
) -> Result<Option<AcmeState>, AcmeError> {
    // Collect all ACME configurations from listeners and SNI blocks
    let mut acme_configs: Vec<(String, AcmeConfig)> = Vec::new();

    for listener in &config.listeners {
        if listener.protocol == zentinel_config::ListenerProtocol::Https {
            if let Some(ref tls) = listener.tls {
                // Root-level ACME
                if let Some(ref acme) = tls.acme {
                    acme_configs.push((format!("listener '{}' (root)", listener.id), acme.clone()));
                }

                // SNI-level ACME
                for (i, sni) in tls.additional_certs.iter().enumerate() {
                    if let Some(ref acme) = sni.acme {
                        acme_configs.push((
                            format!("listener '{}' (sni cert #{})", listener.id, i),
                            acme.clone(),
                        ));
                    }
                }
            }
        }
    }

    if acme_configs.is_empty() {
        return Ok(None);
    }

    info!(
        config_count = acme_configs.len(),
        "Initializing ACME certificate management for multiple configurations"
    );

    // Shared challenge manager for all HTTP-01 challenges on this proxy instance
    let challenge_manager = Arc::new(ChallengeManager::new());
    let mut schedulers = Vec::new();

    for (description, acme_config) in acme_configs {
        info!(
            source = %description,
            domains = ?acme_config.domains,
            staging = acme_config.staging,
            challenge_type = ?acme_config.challenge_type,
            "Initializing ACME for {}", description
        );

        // Create storage
        let storage = Arc::new(CertificateStorage::new(&acme_config.storage)?);

        // Create client and renewal scheduler first so that even if
        // init_account transiently fails, the pushed scheduler already
        // carries the DNS manager and the background RenewalScheduler can
        // retry with full context.
        let acme_client = Arc::new(AcmeClient::new(acme_config.clone(), Arc::clone(&storage)));
        let mut scheduler = RenewalScheduler::new(
            Arc::clone(&acme_client),
            Arc::clone(&challenge_manager),
            sni_resolver.clone(),
        );

        // If DNS-01, set up DNS challenge manager
        if acme_config.challenge_type == AcmeChallengeType::Dns01 {
            if let Some(ref dns_config) = acme_config.dns_provider {
                let provider = zentinel_proxy::acme::dns::create_provider(dns_config)?;

                let mut nameservers: Vec<std::net::IpAddr> = dns_config
                    .propagation
                    .nameservers
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if nameservers.is_empty() {
                    // Fall back to the same public resolvers that
                    // PropagationConfig::default() uses. hickory 0.26's
                    // ResolverConfig::default() yields zero nameservers
                    // (not resolv.conf / 127.0.0.11); lookups then fail
                    // with "no connections available", which check_record
                    // swallows as not-propagated. Explicitly logged to
                    // satisfy "No implicit behavior".
                    tracing::info!(
                        "propagation nameservers not configured, falling back to public resolvers 8.8.8.8, 1.1.1.1, 9.9.9.9"
                    );
                    nameservers =
                        zentinel_proxy::acme::dns::PropagationConfig::default().nameservers;
                }

                let propagation_config = zentinel_proxy::acme::dns::PropagationConfig {
                    initial_delay: std::time::Duration::from_secs(
                        dns_config.propagation.initial_delay_secs,
                    ),
                    check_interval: std::time::Duration::from_secs(
                        dns_config.propagation.check_interval_secs,
                    ),
                    timeout: std::time::Duration::from_secs(dns_config.propagation.timeout_secs),
                    nameservers,
                };

                let dns_manager = Arc::new(zentinel_proxy::acme::dns::Dns01ChallengeManager::new(
                    provider,
                    propagation_config,
                )?);
                scheduler = scheduler.with_dns_manager(dns_manager);
            }
        }

        // Initialize ACME account. init_account already retries transient
        // Connect/TLS EOF with exponential backoff. If it still fails,
        // keep the proxy ready only for renewals (cert already present)
        // and let the background RenewalScheduler retry. For first
        // issuance (no cert files yet) the listener would remain
        // unbound because hot-reload only swaps certs on live
        // listeners, so fail fast instead of deferring silently.
        let primary_domain_for_account = acme_config.domains.first().cloned();
        if let Err(e) = acme_client.init_account().await {
            use zentinel_proxy::acme::is_retryable_acme_error;
            if is_retryable_acme_error(&e) {
                let has_cert = primary_domain_for_account
                    .as_deref()
                    .and_then(|d| storage.certificate_paths(d))
                    .is_some();
                if has_cert {
                    tracing::warn!(
                        source = %description,
                        error = %e,
                        "ACME account init transient failure, proxy will stay ready and retry in background (renewal)"
                    );
                    schedulers.push(scheduler);
                    continue;
                }
                tracing::error!(
                    source = %description,
                    error = %e,
                    "ACME account init transient failure during first issuance, failing fast (no cert to serve)"
                );
                return Err(e);
            } else {
                return Err(e);
            }
        }

        // Check if initial certificate issuance is needed
        let primary_domain = acme_config.domains.first().ok_or_else(|| {
            AcmeError::OrderCreation(format!("No domains configured for ACME in {}", description))
        })?;

        if acme_client.needs_renewal(primary_domain)? {
            // Issuance at startup: defer only for renewals (cert
            // already present). First issuance with no cert files
            // cannot be deferred — the HTTPS listener is skipped when
            // cert files are absent (ACME certificate files not found,
            // continue) and hot-reload never re-adds a listener.
            let issuance_result: Result<(), AcmeError> = async {
                info!(
                    source = %description,
                    domain = %primary_domain,
                    "Initial certificate issuance required"
                );
                match acme_config.challenge_type {
                    AcmeChallengeType::Http01 => {
                        let http_addr = config
                            .listeners
                            .iter()
                            .find(|l| l.protocol == zentinel_config::ListenerProtocol::Http)
                            .map(|l| l.address.clone())
                            .unwrap_or_else(|| "0.0.0.0:80".to_string());
                        info!(
                            address = %http_addr,
                            "Starting temporary HTTP challenge server for initial certificate acquisition"
                        );
                        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
                        let cm_clone = Arc::clone(&challenge_manager);
                        let _server_handle = tokio::spawn(async move {
                            zentinel_proxy::acme::challenge_server::run_challenge_server(
                                &http_addr,
                                cm_clone,
                                shutdown_rx,
                            )
                            .await
                        });
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        let result = scheduler.ensure_certificates().await;
                        let _ = shutdown_tx.send(true);
                        result
                    }
                    AcmeChallengeType::Dns01 => scheduler.ensure_certificates().await,
                }
            }
            .await;
            if let Err(e) = issuance_result {
                use zentinel_proxy::acme::is_retryable_acme_error;
                if is_retryable_acme_error(&e) {
                    let has_cert = storage.certificate_paths(primary_domain).is_some();
                    if has_cert {
                        tracing::warn!(
                            source = %description,
                            domain = %primary_domain,
                            error = %e,
                            "Initial ACME renewal transient failure, deferring to background renewal"
                        );
                    } else {
                        tracing::error!(
                            source = %description,
                            domain = %primary_domain,
                            error = %e,
                            "Initial ACME issuance transient failure during first issuance, failing fast (no cert to serve)"
                        );
                        return Err(e);
                    }
                } else {
                    return Err(e);
                }
            }
        }

        schedulers.push(scheduler);
    }

    Ok(Some(AcmeState {
        challenge_manager,
        schedulers,
    }))
}

/// Messages produced before the log subscriber exists.
///
/// Config discovery runs before logging is configured, because
/// `logging { timestamps }` must be known to build the subscriber and a
/// subscriber can only be installed once. Those messages are the ones that
/// explain which configuration file the proxy actually chose, so they are held
/// here and emitted the moment logging is up rather than dropped.
///
/// Bounded by construction: config discovery emits at most a handful of lines
/// and runs exactly once.
#[derive(Default)]
struct StartupLog(Vec<(tracing::Level, String)>);

impl StartupLog {
    fn info(&mut self, message: String) {
        self.0.push((tracing::Level::INFO, message));
    }

    fn warn(&mut self, message: String) {
        self.0.push((tracing::Level::WARN, message));
    }

    /// Emit everything buffered, in the order it happened.
    fn emit(self) {
        for (level, message) in self.0 {
            match level {
                tracing::Level::WARN => warn!("{message}"),
                _ => info!("{message}"),
            }
        }
    }
}

/// Read the logging configuration the subscriber needs.
///
/// This parses the configuration a second time — `ZentinelProxy::new` parses it
/// again for real — because the subscriber has to exist before the proxy is
/// built. It happens once at startup and buys the ability to honour
/// `logging { timestamps }` at all.
///
/// A configuration that fails to parse here is not reported as an error: the
/// proxy is about to load the same file and will fail with a far better message
/// than this function could. Defaults are used so that failure is still logged.
fn resolve_logging_config(
    config_path: Option<&str>,
    startup_log: &mut StartupLog,
) -> zentinel_config::LoggingConfig {
    let parsed = match config_path {
        Some(path) => zentinel_config::Config::from_file(path).ok(),
        None => zentinel_config::Config::default_embedded().ok(),
    };

    match parsed {
        Some(config) => config.observability.logging,
        None => {
            startup_log.warn(
                "Could not read logging configuration; using defaults until the \
                 configuration is loaded"
                    .to_string(),
            );
            zentinel_config::LoggingConfig::default()
        }
    }
}

/// Install the log subscriber.
///
/// `timestamps` comes from `logging { timestamps }`. Turning it off is for
/// environments whose log transport stamps arrival time itself — systemd
/// journal, Docker, most log shippers — where a second timestamp on every line
/// is noise.
fn init_logging(verbose: bool, timestamps: bool) {
    let log_level = if verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level));

    // The two branches differ in the formatter's type, so they cannot be
    // collapsed into one builder expression.
    if timestamps {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .without_time()
            .init();
    }
}

/// Pingora's command-line options, from the CLI flags and the config.
///
/// `system { daemon #true }` was parsed and never read: only `-d` started a
/// daemon (#527). Either now does. There is no way to switch daemon mode off
/// from the command line, as there was none before.
fn pingora_options(daemon: bool, upgrade: bool, server: &zentinel_config::ServerConfig) -> Opt {
    let mut opt = Opt::default();
    opt.daemon = daemon || server.daemon;
    opt.upgrade = upgrade;
    opt
}

/// Run the proxy server
fn run_server(
    config_path: Option<String>,
    verbose: bool,
    daemon: bool,
    upgrade: bool,
) -> Result<()> {
    // Logging is started further down, once the configuration has been read:
    // `logging { timestamps }` has to be known before the subscriber is built,
    // and a subscriber can only be installed once.
    //
    // Config discovery happens before that point and is exactly the diagnostic
    // you want when the proxy loads a file you did not expect, so those messages
    // are buffered here and emitted as soon as the subscriber exists rather than
    // being lost.
    let mut startup_log = StartupLog::default();

    // Take over SIGHUP before anything slow. Its default disposition
    // terminates the process, and the handler proper is only installed once
    // the configuration is loaded, the proxy built and its listeners set up --
    // so a reload sent by a deploy script or config-management run right
    // after start used to kill the proxy instead.
    //
    // Registering it here queues the signal instead: the iterator holds it
    // until the signal thread starts, and the reload channel holds that until
    // the reload task runs, so an early SIGHUP is applied once the proxy is
    // ready. SIGTERM and SIGINT keep their default disposition until then:
    // stopping a proxy that has not started yet should stay immediate.
    let signals = signal_hook::iterator::Signals::new([signal_hook::consts::signal::SIGHUP])
        .context("Failed to register the SIGHUP handler")?;

    // Get config path with priority: CLI arg > env var > None (embedded default)
    let effective_config_path = config_path.or_else(|| std::env::var("ZENTINEL_CONFIG").ok());

    // Handle config file creation/loading
    let effective_config_path = match effective_config_path {
        Some(path) => {
            let config_path = std::path::Path::new(&path);
            if config_path.exists() {
                startup_log.info(format!("Loading configuration from: {path}"));
                Some(path)
            } else {
                // Config file doesn't exist - create it with default content
                startup_log.info(format!("Configuration file not found: {path}"));
                if let Err(e) = create_default_config_file(config_path) {
                    startup_log.warn(format!("Failed to create default config file: {e}"));
                    startup_log.info("Using embedded default configuration instead".to_string());
                    None
                } else {
                    startup_log.info(format!("Created default configuration at: {path}"));
                    Some(path)
                }
            }
        }
        None => {
            startup_log.info(
                "No configuration specified, using embedded default configuration".to_string(),
            );
            None
        }
    };

    // The subscriber can be built now that the configuration is known.
    let logging = resolve_logging_config(effective_config_path.as_deref(), &mut startup_log);
    init_logging(verbose, logging.timestamps);
    startup_log.emit();

    // Create signal manager for cross-thread communication
    let signal_manager = Arc::new(SignalManager::new());

    // Create runtime for async initialization and signal handling
    let runtime = tokio::runtime::Runtime::new()?;

    // Create proxy with configuration
    let mut proxy =
        runtime.block_on(async { ZentinelProxy::new(effective_config_path.as_deref()).await })?;

    // Get config manager for reload operations
    let config_manager = proxy.config_manager.clone();

    // Get initial config for server setup
    let config = proxy.config_manager.current();

    // Start the standalone Prometheus metrics server if enabled.
    // `observability.metrics.address` is a dedicated listener, separate from the
    // data-plane listeners, so the scrape endpoint is never exposed to client
    // traffic by accident.
    {
        let metrics_cfg = config.observability.metrics.clone();
        if metrics_cfg.enabled {
            let cache_stats = Some(proxy.http_cache_stats());
            runtime.spawn(async move {
                zentinel_proxy::metrics_server::run_metrics_server(
                    metrics_cfg.address,
                    metrics_cfg.path,
                    cache_stats,
                )
                .await;
            });
        } else {
            info!("Metrics server disabled (observability.metrics.enabled = false)");
        }
    }

    // Setup signal handlers (runs in separate thread, needs config for shutdown timeout)
    setup_signal_handlers(
        signals,
        signal_manager.sender(),
        config.server.graceful_shutdown_timeout_secs,
    );

    // Initialize ACME if any listener has it configured
    let acme_state = runtime
        .block_on(async { initialize_acme(&config, None).await })
        .context("ACME initialization failed")?;

    // Wire ACME components into the proxy
    if let Some(ref state) = acme_state {
        proxy.acme_challenges = Some(Arc::clone(&state.challenge_manager));
        proxy.acme_clients = state
            .schedulers
            .iter()
            .map(|s| Arc::clone(s.client()))
            .collect();
    }

    // Initialize OpenTelemetry tracer if configured and enabled.
    //
    // The block's presence used to be the only switch, so `enabled #false` was
    // read by nothing and tracing started anyway. It is honoured here, and the
    // skip is logged: an operator who turned tracing off should be able to see
    // that it took effect.
    if let Some(ref tracing_config) = config.observability.tracing {
        if !tracing_config.enabled {
            info!("Distributed tracing disabled by configuration (tracing.enabled)");
        } else {
            match zentinel_proxy::otel::init_tracer(tracing_config) {
                Ok(()) => {
                    info!(
                        backend = ?tracing_config.backend,
                        sampling_rate = tracing_config.sampling_rate,
                        service_name = %tracing_config.service_name,
                        "OpenTelemetry tracing enabled"
                    );
                }
                Err(e) => {
                    warn!("Failed to initialize OpenTelemetry tracer: {}", e);
                    warn!("Distributed tracing will be disabled");
                }
            }
        }
    }

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

    // Wire server config → Pingora ServerConf
    pingora_conf.graceful_shutdown_timeout_seconds =
        Some(config.server.graceful_shutdown_timeout_secs);
    if let Some(ref pid_path) = config.server.pid_file {
        pingora_conf.pid_file = pid_path.to_string_lossy().to_string();
    }
    if let Some(ref user) = config.server.user {
        pingora_conf.user = Some(user.clone());
    }
    if let Some(ref group) = config.server.group {
        pingora_conf.group = Some(group.clone());
    }

    info!(
        worker_threads = worker_threads,
        upstream_pool_size = pingora_conf.upstream_keepalive_pool_size,
        graceful_shutdown_timeout_secs = config.server.graceful_shutdown_timeout_secs,
        pid_file = ?config.server.pid_file,
        user = ?config.server.user,
        group = ?config.server.group,
        "Configuring Pingora server"
    );

    // Change working directory if configured (before bootstrap)
    if let Some(ref work_dir) = config.server.working_directory {
        std::env::set_current_dir(work_dir).with_context(|| {
            format!(
                "Failed to change working directory to '{}'",
                work_dir.display()
            )
        })?;
        info!(path = %work_dir.display(), "Changed working directory");
    }

    // Pingora's `add_tcp`/`add_tls*` take a string and panic at bind time if it
    // is not a socket address (#520). Config validation already rejects such
    // listeners; this check keeps any config that reaches here by another path
    // from turning into a panic instead of an error.
    for listener in &config.listeners {
        if let Err(message) = zentinel_config::validation::check_listen_address(&listener.address) {
            anyhow::bail!("Listener '{}': {}", listener.id, message);
        }
    }

    // Create Pingora server with our configuration
    let pingora_opt = pingora_options(daemon, upgrade, &config.server);
    if pingora_opt.daemon {
        info!(from_cli = daemon, "Running as a daemon");
    }
    let mut server = Server::new_with_opt_and_conf(Some(pingora_opt), pingora_conf);
    server.bootstrap();

    // Determine keepalive request limit from listeners (use the most restrictive)
    let keepalive_request_limit = config
        .listeners
        .iter()
        .filter_map(|l| l.keepalive_max_requests)
        .min();

    // Create proxy service with server options (Pingora 0.8.0 builder pattern)
    let mut server_options = pingora_core::apps::HttpServerOptions::default();
    server_options.keepalive_request_limit = keepalive_request_limit;
    let mut proxy_service = pingora_proxy::ProxyServiceBuilder::new(&server.configuration, proxy)
        .name("Zentinel Proxy")
        .server_options(server_options)
        .build();

    // Tracks the certificate resolver of every TLS listener, so SIGHUP can
    // refresh certificates from disk without restarting the process.
    let cert_reloader = Arc::new(CertificateReloader::new());

    // Configure listening addresses from config
    for listener in &config.listeners {
        match listener.protocol {
            zentinel_config::ListenerProtocol::Http => {
                proxy_service.add_tcp(&listener.address);
                info!("HTTP listening on: {}", listener.address);
            }
            // `h2` is served by the HTTPS path: that listener already
            // advertises h2 through ALPN, so the two are the same socket setup.
            // They used to differ only in that `h2` fell through to a catch-all
            // and bound nothing at all (#377).
            zentinel_config::ListenerProtocol::Https | zentinel_config::ListenerProtocol::Http2 => {
                match &listener.tls {
                    Some(tls_config) => {
                        // Determine certificate paths: manual or ACME-managed
                        let (cert_path, key_path) = if let (Some(ref cert), Some(ref key)) =
                            (&tls_config.cert_file, &tls_config.key_file)
                        {
                            // Manual certificates specified
                            (cert.clone(), key.clone())
                        } else if let Some(ref acme_config) = tls_config.acme {
                            // ACME-managed certificates
                            let acme_storage = &acme_config.storage;
                            let primary_domain = acme_config
                                .domains
                                .first()
                                .ok_or_else(|| {
                                    error!(
                                        listener_id = %listener.id,
                                        "ACME configuration has no domains"
                                    );
                                })
                                .unwrap_or(&"default".to_string())
                                .clone();

                            let cert_path = acme_storage
                                .join("domains")
                                .join(&primary_domain)
                                .join("cert.pem");
                            let key_path = acme_storage
                                .join("domains")
                                .join(&primary_domain)
                                .join("key.pem");

                            // If certs still don't exist after ACME init, something went wrong
                            if !cert_path.exists() || !key_path.exists() {
                                error!(
                                    listener_id = %listener.id,
                                    address = %listener.address,
                                    domains = ?acme_config.domains,
                                    cert_path = %cert_path.display(),
                                    "ACME certificate files not found after initialization"
                                );
                                continue;
                            }

                            (cert_path, key_path)
                        } else {
                            error!(
                                listener_id = %listener.id,
                                "TLS configuration requires either cert-file/key-file or acme block"
                            );
                            continue;
                        };

                        let cert_path_str = cert_path.to_string_lossy();
                        let key_path_str = key_path.to_string_lossy();

                        // Validate certificate files exist
                        if !cert_path.exists() {
                            error!(
                                listener_id = %listener.id,
                                cert_file = %cert_path_str,
                                "TLS certificate file not found"
                            );
                            continue;
                        }
                        if !key_path.exists() {
                            error!(
                                listener_id = %listener.id,
                                key_file = %key_path_str,
                                "TLS key file not found"
                            );
                            continue;
                        }

                        // Build the certificate resolver first and keep a handle
                        // on it. The resolver installed in the ServerConfig has
                        // to be the same object the reloader refreshes, or a
                        // reload updates something no live connection consults.
                        let sni_resolver = match HotReloadableSniResolver::from_config(
                            tls_config.clone(),
                            listener.id.clone(),
                        ) {
                            Ok(r) => Arc::new(r),
                            Err(e) => {
                                error!(
                                    listener_id = %listener.id,
                                    error = %e,
                                    "Failed to load TLS certificates for listener"
                                );
                                continue;
                            }
                        };

                        // Everything the operator configured -- SNI certificates,
                        // client auth, protocol versions, cipher suites, session
                        // resumption -- is expressed here and handed to the
                        // listener as a complete rustls ServerConfig.
                        let server_config = match tls::build_server_config_with_resolver(
                            tls_config,
                            sni_resolver.clone(),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                error!(
                                    listener_id = %listener.id,
                                    error = %e,
                                    "Failed to build TLS configuration for listener"
                                );
                                continue;
                            }
                        };

                        let mut tls_settings =
                            match pingora::listeners::tls::TlsSettings::with_server_config(
                                server_config,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!(
                                        listener_id = %listener.id,
                                        error = %e,
                                        "Failed to create TLS settings"
                                    );
                                    continue;
                                }
                            };
                        tls_settings.enable_h2();

                        cert_reloader.register(&listener.id, sni_resolver.clone());

                        // Folders configured to reload on their own get a
                        // watcher or a timer. Without this the `reload-mode`
                        // setting would parse and do nothing, which is the
                        // failure mode this listener was just fixed for.
                        spawn_cert_folder_reloaders(
                            &runtime,
                            &listener.id,
                            tls_config,
                            sni_resolver,
                        );

                        proxy_service.add_tls_with_settings(&listener.address, None, tls_settings);
                        info!(
                            listener_id = %listener.id,
                            address = %listener.address,
                            cert_file = %cert_path_str,
                            acme_enabled = tls_config.acme.is_some(),
                            sni_cert_count = tls_config.additional_certs.len(),
                            client_auth = tls_config.client_auth,
                            "HTTPS (h2+http/1.1) listening on: {}", listener.address
                        );
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
            // Config validation rejects h3 before startup, so this is
            // unreachable for a parsed config. Erroring rather than warning
            // means a Config built in code cannot silently produce a listener
            // that binds nothing — which is what the old catch-all did.
            zentinel_config::ListenerProtocol::Http3 => {
                error!(
                    listener_id = %listener.id,
                    address = %listener.address,
                    "HTTP/3 is not implemented; refusing to start rather than \
                     binding nothing. Use protocol \"https\" (which negotiates \
                     HTTP/2 via ALPN) until QUIC support lands."
                );
                return Err(anyhow::anyhow!(
                    "Listener '{}' requests HTTP/3, which is not implemented",
                    listener.id
                ));
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

    // Spawn ACME renewal schedulers as background tasks
    if let Some(state) = acme_state {
        let scheduler_count = state.schedulers.len();
        for scheduler in state.schedulers {
            runtime.spawn(async move {
                scheduler.run().await;
            });
        }
        info!(
            count = scheduler_count,
            "ACME certificate renewal schedulers started"
        );
    }

    // Spawn signal handler task in the runtime
    let signal_manager_clone = signal_manager.clone();
    let cert_reloader_clone = cert_reloader.clone();
    runtime.spawn(async move {
        run_signal_handler(signal_manager_clone, config_manager, cert_reloader_clone).await;
    });

    info!("Zentinel proxy started successfully");
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
/// Adds SIGTERM and SIGINT to `signals` (registered for SIGHUP at the start of
/// `run_server`) and forwards all three to the async runtime via the signal
/// manager. A SIGHUP that arrived during startup is delivered now.
fn setup_signal_handlers(
    mut signals: signal_hook::iterator::Signals,
    signal_tx: std::sync::mpsc::Sender<SignalType>,
    graceful_shutdown_timeout_secs: u64,
) {
    use signal_hook::consts::signal::*;
    use std::thread;

    for sig in [SIGTERM, SIGINT] {
        signals
            .add_signal(sig)
            .expect("Failed to register signal handlers");
    }

    thread::spawn(move || {
        for sig in signals.forever() {
            let signal_type = match sig {
                SIGTERM | SIGINT => {
                    info!(
                        "Received shutdown signal ({}), initiating graceful shutdown",
                        if sig == SIGTERM { "SIGTERM" } else { "SIGINT" }
                    );
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

            // For shutdown, wait for graceful shutdown to complete before force-exiting
            if signal_type == SignalType::Shutdown {
                // Wait for the configured graceful shutdown timeout plus a small buffer
                let force_exit_secs = graceful_shutdown_timeout_secs.saturating_add(5);
                thread::sleep(std::time::Duration::from_secs(force_exit_secs));
                // Force exit if graceful shutdown takes too long
                error!(
                    timeout_secs = force_exit_secs,
                    "Graceful shutdown timeout exceeded, forcing exit"
                );
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
    use zentinel_config::DEFAULT_CONFIG_KDL;

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

/// Start a reload task for each certificate folder that asks for one.
///
/// `off` folders are left alone: they still rescan on SIGHUP, because the
/// resolver rebuilds from configuration and the scan is part of that.
fn spawn_cert_folder_reloaders(
    runtime: &tokio::runtime::Runtime,
    listener_id: &str,
    tls_config: &zentinel_config::TlsConfig,
    resolver: Arc<HotReloadableSniResolver>,
) {
    use zentinel_config::CertFolderReloadMode;

    for folder in &tls_config.cert_folders {
        match folder.reload_mode {
            CertFolderReloadMode::Off => continue,
            CertFolderReloadMode::Interval => {
                info!(
                    listener_id = %listener_id,
                    cert_folder = %folder.cert_folder.display(),
                    interval_secs = folder.reload_interval.as_secs(),
                    "Certificate folder will be rescanned on a timer"
                );
                let resolver = resolver.clone();
                let listener_id = listener_id.to_string();
                let path = folder.cert_folder.clone();
                let interval = folder.reload_interval;
                runtime.spawn(async move {
                    let mut ticker = tokio::time::interval(interval);
                    // The first tick fires immediately; the folder was just
                    // scanned, so skip it.
                    ticker.tick().await;
                    loop {
                        ticker.tick().await;
                        reload_folder(&resolver, &listener_id, &path, "interval");
                    }
                });
            }
            CertFolderReloadMode::Watch => {
                info!(
                    listener_id = %listener_id,
                    cert_folder = %folder.cert_folder.display(),
                    "Certificate folder will be rescanned when it changes"
                );
                let resolver = resolver.clone();
                let listener_id = listener_id.to_string();
                let path = folder.cert_folder.clone();
                let interval = folder.reload_interval;
                runtime.spawn(async move {
                    watch_cert_folder(resolver, listener_id, path, interval).await;
                });
            }
        }
    }
}

/// Rescan one listener's certificates, logging the outcome.
fn reload_folder(
    resolver: &HotReloadableSniResolver,
    listener_id: &str,
    path: &std::path::Path,
    trigger: &str,
) {
    match resolver.reload() {
        Ok(()) => {
            debug!(
                listener_id = %listener_id,
                cert_folder = %path.display(),
                trigger = trigger,
                "Certificates reloaded"
            );
        }
        Err(e) => {
            // The previous certificates stay in use. Reporting matters more
            // than retrying: a folder that has gone bad will keep failing, and
            // silence would look identical to a folder that never changes.
            error!(
                listener_id = %listener_id,
                cert_folder = %path.display(),
                trigger = trigger,
                error = %e,
                "Certificate reload failed; continuing with the previous certificates"
            );
        }
    }
}

/// Watch a folder and rescan when it changes, falling back to a timer.
///
/// Filesystem watching is not available everywhere, and a network filesystem
/// may report nothing at all. Rather than leave the operator with a folder
/// that silently never reloads, a failed watcher degrades to the configured
/// interval and says so.
async fn watch_cert_folder(
    resolver: Arc<HotReloadableSniResolver>,
    listener_id: String,
    path: std::path::PathBuf,
    fallback_interval: std::time::Duration,
) {
    use notify::{RecursiveMode, Watcher};

    let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);
    let watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            // A full rescan follows, so one signal is enough however many
            // events arrived; a full channel already means one is pending.
            let _ = tx.try_send(());
        }
    });

    let mut watcher = match watcher {
        Ok(w) => w,
        Err(e) => {
            warn!(
                listener_id = %listener_id,
                cert_folder = %path.display(),
                error = %e,
                interval_secs = fallback_interval.as_secs(),
                "Could not create a filesystem watcher; falling back to interval rescans"
            );
            return interval_fallback(resolver, listener_id, path, fallback_interval).await;
        }
    };

    if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
        warn!(
            listener_id = %listener_id,
            cert_folder = %path.display(),
            error = %e,
            interval_secs = fallback_interval.as_secs(),
            "Could not watch the certificate folder; falling back to interval rescans"
        );
        return interval_fallback(resolver, listener_id, path, fallback_interval).await;
    }

    // Certificates are often written as several files in quick succession —
    // a key then a certificate. Waiting briefly after the first event avoids
    // rescanning midway through and reading a pair that is not yet complete.
    const SETTLE: std::time::Duration = std::time::Duration::from_millis(500);

    while rx.recv().await.is_some() {
        tokio::time::sleep(SETTLE).await;
        while rx.try_recv().is_ok() {}
        reload_folder(&resolver, &listener_id, &path, "watch");
    }

    // The watcher is dropped when this task ends; keep it alive until then.
    drop(watcher);
}

/// Timer-driven rescans, used directly and as the watch fallback.
async fn interval_fallback(
    resolver: Arc<HotReloadableSniResolver>,
    listener_id: String,
    path: std::path::PathBuf,
    interval: std::time::Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        ticker.tick().await;
        reload_folder(&resolver, &listener_id, &path, "interval-fallback");
    }
}

/// Async signal handler task
///
/// Receives signals from the signal manager and performs the appropriate action.
async fn run_signal_handler(
    signal_manager: Arc<SignalManager>,
    config_manager: Arc<zentinel_proxy::ConfigManager>,
    cert_reloader: Arc<CertificateReloader>,
) {
    loop {
        // Use spawn_blocking to wait for signals without blocking the async runtime
        let signal_manager_clone = signal_manager.clone();
        let signal =
            tokio::task::spawn_blocking(move || signal_manager_clone.recv_blocking()).await;

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

                // Certificates are reloaded independently of the configuration:
                // a renewed certificate changes the file on disk without
                // changing a byte of config, so a config reload alone would
                // never pick it up. A listener whose reload fails keeps serving
                // its previous certificate.
                let (reloaded, failures) = cert_reloader.reload_all();
                for (listener_id, e) in &failures {
                    error!(
                        listener_id = %listener_id,
                        error = %e,
                        "TLS certificate reload failed, keeping previous certificates"
                    );
                }
                if reloaded > 0 || !failures.is_empty() {
                    info!(
                        reloaded = reloaded,
                        failed = failures.len(),
                        "TLS certificates reloaded"
                    );
                }
            }
            Ok(Some(SignalType::Shutdown)) => {
                info!("Processing graceful shutdown request");
                // Shutdown OpenTelemetry tracer to flush pending spans
                zentinel_proxy::otel::shutdown_tracer();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `zentinel test` reports what `lint` reports as ignored (#523).
    #[test]
    fn ignored_settings_reads_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("typo.kdl");
        std::fs::write(
            &path,
            "listeners { listener \"l\" { adress \"127.0.0.1:1\"; } }\n",
        )
        .unwrap();
        let ignored = ignored_settings(path.to_str());
        assert_eq!(ignored.len(), 1, "{ignored:?}");
        assert!(ignored[0].contains("'adress'") && ignored[0].contains("is being ignored"));

        assert!(ignored_settings(None).is_empty());
    }

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
                pingora_options(flag, false, &server).daemon,
                expected,
                "flag {flag}, config {config}"
            );
        }
    }
}
