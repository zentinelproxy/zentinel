//! Configuration hot reload module for Zentinel proxy.
//!
//! This module implements zero-downtime configuration reloading with validation,
//! atomic swaps, and rollback support for production reliability.
//!
//! ## Submodules
//!
//! - `coordinator`: Graceful reload coordination and request draining
//! - `signals`: OS signal handling (SIGHUP, SIGTERM)
//! - `validators`: Runtime configuration validators

mod coordinator;
pub mod diff;
mod signals;
mod validators;

pub use coordinator::GracefulReloadCoordinator;
pub use signals::{SignalManager, SignalType};
pub use validators::{RouteValidator, UpstreamValidator};

// Re-export for use by proxy initialization

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

use zentinel_common::errors::{ZentinelError, ZentinelResult};
use zentinel_config::Config;

use crate::logging::{AuditLogEntry, SharedLogManager};
use crate::tls::CertificateReloader;

// ============================================================================
// Reload Events and Types
// ============================================================================

/// Reload event types
#[derive(Debug, Clone)]
pub enum ReloadEvent {
    /// Configuration reload started
    Started {
        timestamp: Instant,
        trigger: ReloadTrigger,
    },
    /// Configuration validated successfully
    Validated { timestamp: Instant },
    /// Configuration applied successfully
    Applied { timestamp: Instant, version: String },
    /// Configuration reload failed
    Failed { timestamp: Instant, error: String },
    /// Configuration rolled back
    RolledBack { timestamp: Instant, reason: String },
}

/// Reload trigger source
#[derive(Debug, Clone)]
pub enum ReloadTrigger {
    /// Manual reload via API
    Manual,
    /// File change detected
    FileChange,
    /// Signal received (SIGHUP)
    Signal,
    /// Scheduled reload
    Scheduled,
    /// Gateway API controller reconciliation
    GatewayApi,
}

// ============================================================================
// Traits
// ============================================================================

/// Configuration validator trait
#[async_trait::async_trait]
pub trait ConfigValidator: Send + Sync {
    /// Validate configuration before applying
    async fn validate(&self, config: &Config) -> ZentinelResult<()>;

    /// Validator name for logging
    fn name(&self) -> &str;
}

/// Reload hook trait for custom actions
#[async_trait::async_trait]
pub trait ReloadHook: Send + Sync {
    /// Called before reload starts
    async fn pre_reload(&self, old_config: &Config, new_config: &Config) -> ZentinelResult<()>;

    /// Called after successful reload
    async fn post_reload(&self, old_config: &Config, new_config: &Config);

    /// Called on reload failure
    async fn on_failure(&self, config: &Config, error: &ZentinelError);

    /// Hook name for logging
    fn name(&self) -> &str;
}

// ============================================================================
// Reload Statistics
// ============================================================================

/// Reload statistics
#[derive(Default)]
pub struct ReloadStats {
    /// Total reload attempts
    pub total_reloads: std::sync::atomic::AtomicU64,
    /// Successful reloads
    pub successful_reloads: std::sync::atomic::AtomicU64,
    /// Failed reloads
    pub failed_reloads: std::sync::atomic::AtomicU64,
    /// Rollbacks performed
    pub rollbacks: std::sync::atomic::AtomicU64,
    /// Current config version (incremented on each successful reload)
    pub config_version: std::sync::atomic::AtomicU64,
    /// Last successful reload time
    pub last_success: RwLock<Option<Instant>>,
    /// Last failure time
    pub last_failure: RwLock<Option<Instant>>,
    /// Average reload duration
    pub avg_duration_ms: RwLock<f64>,
}

// ============================================================================
// Configuration Manager
// ============================================================================

/// What the files of a configuration contained when it was last read.
///
/// Covers every file loading the configuration reads -- the entry file, its
/// includes, or every file of a configuration directory -- by content, so
/// that auto-reload reloads once per change however many times it is told
/// about it, and notices a change to any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceSignature {
    /// Each file read, with a hash of its content (`None` if unreadable).
    files: Vec<(PathBuf, Option<u64>)>,
}

impl SourceSignature {
    /// Read the files of the configuration at `config_path`.
    ///
    /// The list of files comes from expanding the configuration's includes.
    /// When that fails (a file mid-edit does not parse), the files of the
    /// last signature are read instead, with the entry file, so a fix to an
    /// included file is still seen.
    fn read(config_path: &Path, previous: Option<&SourceSignature>) -> Self {
        let paths = Config::source_files(config_path).unwrap_or_else(|_| {
            let mut paths = vec![config_path.to_path_buf()];
            for (path, _) in previous.map(|p| p.files.as_slice()).unwrap_or_default() {
                if !paths.contains(path) {
                    paths.push(path.clone());
                }
            }
            paths
        });
        let files = paths
            .into_iter()
            .map(|path| {
                let digest = std::fs::read(&path).ok().map(|content| {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    content.hash(&mut hasher);
                    hasher.finish()
                });
                (path, digest)
            })
            .collect();
        Self { files }
    }
}

/// Configuration manager with hot reload support
pub struct ConfigManager {
    /// Current active configuration
    current_config: Arc<ArcSwap<Config>>,
    /// Previous configuration for rollback
    previous_config: Arc<RwLock<Option<Arc<Config>>>>,
    /// Configuration file path
    config_path: PathBuf,
    /// File watcher for auto-reload (uses RwLock for interior mutability)
    watcher: Arc<RwLock<Option<notify::RecommendedWatcher>>>,
    /// Reload event broadcaster
    reload_tx: broadcast::Sender<ReloadEvent>,
    /// Reload statistics
    stats: Arc<ReloadStats>,
    /// Validation hooks
    validators: Arc<RwLock<Vec<Box<dyn ConfigValidator>>>>,
    /// Reload hooks
    reload_hooks: Arc<RwLock<Vec<Box<dyn ReloadHook>>>>,
    /// Certificate reloader for TLS hot-reload
    cert_reloader: Arc<CertificateReloader>,
    /// Serializes reload operations so only one runs at a time
    reload_mutex: Arc<Mutex<()>>,
    /// The configuration's files as the last reload read them; auto-reload
    /// reloads only when they differ.
    source_signature: Arc<std::sync::Mutex<Option<SourceSignature>>>,
}

impl ConfigManager {
    /// Create new configuration manager
    pub async fn new(
        config_path: impl AsRef<Path>,
        initial_config: Config,
    ) -> ZentinelResult<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let (reload_tx, _) = broadcast::channel(100);

        info!(
            config_path = %config_path.display(),
            route_count = initial_config.routes.len(),
            upstream_count = initial_config.upstreams.len(),
            listener_count = initial_config.listeners.len(),
            "Initializing configuration manager"
        );

        trace!(
            config_path = %config_path.display(),
            "Creating ArcSwap for configuration"
        );

        Ok(Self {
            // The proxy runs the lowered configuration (#548); lowering is
            // idempotent, so a caller that already lowered it loses nothing.
            current_config: Arc::new(ArcSwap::from_pointee(initial_config.lower_scopes())),
            previous_config: Arc::new(RwLock::new(None)),
            config_path,
            watcher: Arc::new(RwLock::new(None)),
            reload_tx,
            stats: Arc::new(ReloadStats::default()),
            validators: Arc::new(RwLock::new(Vec::new())),
            reload_hooks: Arc::new(RwLock::new(Vec::new())),
            cert_reloader: Arc::new(CertificateReloader::new()),
            reload_mutex: Arc::new(Mutex::new(())),
            source_signature: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Get the certificate reloader for registering TLS listeners
    pub fn cert_reloader(&self) -> Arc<CertificateReloader> {
        Arc::clone(&self.cert_reloader)
    }

    /// Get current configuration
    pub fn current(&self) -> Arc<Config> {
        self.current_config.load_full()
    }

    /// Start watching configuration file for changes
    ///
    /// When enabled, the proxy will automatically reload configuration
    /// when the config file is modified. Also watches the config file's
    /// parent directory to catch included files in multi-file configs.
    pub async fn start_watching(&self) -> ZentinelResult<()> {
        // Check if already watching
        if self.watcher.read().await.is_some() {
            warn!("File watcher already active, skipping");
            return Ok(());
        }

        let config_path = self.config_path.clone();

        // What the running configuration was read from, for auto-reload to
        // compare against.
        {
            let mut signature = self
                .source_signature
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if signature.is_none() {
                *signature = Some(SourceSignature::read(&config_path, None));
            }
        }

        // Use a notify channel to signal that a relevant file changed.
        // We use a tokio::sync::Notify instead of an mpsc channel — multiple
        // rapid events coalesce into a single notification automatically.
        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_sender = Arc::clone(&notify);

        let watched_path = config_path.clone();
        let mut watcher =
            notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
                match event {
                    Ok(event) => {
                        if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                            // Check if the event is for a .kdl file or our config file
                            let dominated = event.paths.iter().any(|p| {
                                p == &watched_path || p.extension().is_some_and(|ext| ext == "kdl")
                            });
                            if dominated {
                                notify_sender.notify_one();
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "File watcher error");
                    }
                }
            })
            .map_err(|e| ZentinelError::Config {
                message: format!("Failed to create file watcher: {}", e),
                source: None,
            })?;

        // A directory configuration (`-c <dir>`) is every file under it, so
        // the directory itself is what to watch. Watching its parent, as for a
        // file, would watch everything next to it -- all of `/etc`.
        let is_directory = config_path.is_dir();

        // Watch the config file itself
        watcher
            .watch(
                &config_path,
                if is_directory {
                    RecursiveMode::Recursive
                } else {
                    RecursiveMode::NonRecursive
                },
            )
            .map_err(|e| ZentinelError::Config {
                message: format!("Failed to watch config file: {}", e),
                source: None,
            })?;

        // Also watch the config file's parent directory to catch included files.
        // Multi-file configs use `include "routes/*.kdl"` — those files live
        // alongside or under the main config directory.
        if let Some(parent) = config_path.parent().filter(|_| !is_directory) {
            if let Err(e) = watcher.watch(parent, RecursiveMode::Recursive) {
                warn!(
                    path = %parent.display(),
                    error = %e,
                    "Could not watch config directory for included files, \
                     only the main config file will trigger auto-reload"
                );
            } else {
                debug!(
                    path = %parent.display(),
                    "Watching config directory recursively for included file changes"
                );
            }
        }

        // Store watcher using interior mutability
        *self.watcher.write().await = Some(watcher);

        // Spawn event handler task with proper debounce
        let manager = Arc::new(self.clone_for_task());
        let config_path_log = self.config_path.clone();
        tokio::spawn(async move {
            loop {
                // Wait for at least one file change notification
                notify.notified().await;

                // Debounce: wait for changes to settle. If more notifications
                // arrive during this window, we consume them and keep waiting
                // until no new changes arrive for 200ms.
                while let Ok(()) =
                    tokio::time::timeout(Duration::from_millis(200), notify.notified()).await
                {
                    // Another change arrived within the window, keep waiting
                    trace!("Debounce: additional file change, resetting timer");
                }

                // The poll below may already have reloaded this change, and
                // an event for a file the configuration does not read changes
                // nothing; either way there is nothing to do.
                if let Err(e) = manager.reload_if_changed(ReloadTrigger::FileChange).await {
                    error!(error = %e, "Auto-reload failed, continuing with current configuration");
                }
            }
        });

        // Spawn a fallback polling loop. inotify can miss rename-based atomic
        // writes on some filesystems (emptyDir, overlayfs), and the watcher
        // above does not see included files outside the entry file's
        // directory. Every second the poll compares the content of every file
        // the configuration reads -- includes too -- with what the last
        // reload read, so a change the watcher already reloaded is not
        // reloaded a second time.
        let poll_manager = Arc::new(self.clone_for_task());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Err(e) = poll_manager
                    .reload_if_changed(ReloadTrigger::FileChange)
                    .await
                {
                    error!(error = %e, "Poll-triggered reload failed");
                }
            }
        });

        info!(
            config_file = %self.config_path.display(),
            "Auto-reload enabled: watching for configuration changes (with poll fallback)"
        );
        Ok(())
    }

    /// Reload configuration
    ///
    /// Only one reload runs at a time. If a reload is already in progress
    /// (from file watcher, SIGHUP, or manual trigger), this call waits
    /// for it to finish before starting.
    pub async fn reload(&self, trigger: ReloadTrigger) -> ZentinelResult<()> {
        // Serialize reloads — only one at a time
        let _reload_guard = self.reload_mutex.lock().await;
        let signature = SourceSignature::read(&self.config_path, self.signature().as_ref());
        self.reload_locked(trigger, signature).await
    }

    /// Reload if a file the configuration reads has changed since the last
    /// reload read it; otherwise do nothing.
    ///
    /// Auto-reload hears about one edit from the file watcher, often more
    /// than once, and from the poll fallback. Comparing content rather than
    /// counting events makes that one reload. Returns whether it reloaded.
    pub async fn reload_if_changed(&self, trigger: ReloadTrigger) -> ZentinelResult<bool> {
        let _reload_guard = self.reload_mutex.lock().await;
        let previous = self.signature();
        let signature = SourceSignature::read(&self.config_path, previous.as_ref());
        if previous.as_ref() == Some(&signature) {
            trace!("Configuration files unchanged, not reloading");
            return Ok(false);
        }
        info!(
            files = signature.files.len(),
            "Configuration file changed, triggering reload"
        );
        self.reload_locked(trigger, signature).await.map(|()| true)
    }

    /// The last reload's view of the configuration's files.
    fn signature(&self) -> Option<SourceSignature> {
        self.source_signature
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The body of [`Self::reload`], run with the reload lock held.
    ///
    /// `signature` is the files as read just before the configuration is: a
    /// failed reload records it too, so a broken file is reported once, and
    /// the next edit reloads again.
    async fn reload_locked(
        &self,
        trigger: ReloadTrigger,
        signature: SourceSignature,
    ) -> ZentinelResult<()> {
        *self
            .source_signature
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(signature);

        let start = Instant::now();
        let reload_num = self
            .stats
            .total_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        info!(
            trigger = ?trigger,
            reload_num = reload_num,
            config_path = %self.config_path.display(),
            "Starting configuration reload"
        );

        // Notify reload started
        let _ = self.reload_tx.send(ReloadEvent::Started {
            timestamp: Instant::now(),
            trigger: trigger.clone(),
        });

        trace!(
            config_path = %self.config_path.display(),
            "Reading configuration file"
        );

        // Load new configuration
        let new_config = match Config::from_file(&self.config_path) {
            Ok(config) => {
                debug!(
                    route_count = config.routes.len(),
                    upstream_count = config.upstreams.len(),
                    listener_count = config.listeners.len(),
                    "Configuration file parsed successfully"
                );
                config
            }
            Err(e) => {
                let error_msg = format!("Failed to load configuration: {}", e);
                error!(
                    config_path = %self.config_path.display(),
                    error = %e,
                    "Failed to load configuration file"
                );
                self.stats
                    .failed_reloads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                *self.stats.last_failure.write().await = Some(Instant::now());

                let _ = self.reload_tx.send(ReloadEvent::Failed {
                    timestamp: Instant::now(),
                    error: error_msg.clone(),
                });

                return Err(ZentinelError::Config {
                    message: error_msg,
                    source: None,
                });
            }
        };

        trace!("Starting configuration validation");

        // Validate new configuration BEFORE applying
        // This is critical - invalid configs must never be loaded
        if let Err(e) = self.validate_config(&new_config).await {
            error!(
                error = %e,
                "Configuration validation failed - new configuration REJECTED"
            );
            self.stats
                .failed_reloads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *self.stats.last_failure.write().await = Some(Instant::now());

            let _ = self.reload_tx.send(ReloadEvent::Failed {
                timestamp: Instant::now(),
                error: e.to_string(),
            });

            return Err(e);
        }

        // Run the lowered configuration: namespace and service resources at
        // the top level under their qualified ids (#548). Lowered before the
        // comparisons below, so it is compared with the lowered old one.
        let (new_config, scope_problems) = new_config.lower_scopes_reporting();
        for problem in scope_problems
            .iter()
            .chain(&crate::routing::unservable_scoped_routes(&new_config))
        {
            warn!("{problem}");
        }

        info!(
            route_count = new_config.routes.len(),
            upstream_count = new_config.upstreams.len(),
            "Configuration validation passed, applying new configuration"
        );

        let _ = self.reload_tx.send(ReloadEvent::Validated {
            timestamp: Instant::now(),
        });

        // Get current config for rollback
        let old_config = self.current_config.load_full();

        trace!(
            old_routes = old_config.routes.len(),
            new_routes = new_config.routes.len(),
            "Preparing configuration swap"
        );

        // Listeners are bound at startup and are NOT hot-reloadable. Say so
        // loudly instead of silently ignoring the change.
        let old_listeners = serde_json::to_value(&old_config.listeners).ok();
        let new_listeners = serde_json::to_value(&new_config.listeners).ok();
        if old_listeners != new_listeners {
            warn!(
                "Listener configuration changed in the new config, but listeners \
                 (addresses, ports, TLS bindings) are NOT applied by hot reload. \
                 The proxy continues serving on the previously bound listeners; \
                 restart zentinel to apply listener changes."
            );
        }
        if serde_json::to_value(&old_config.server).ok()
            != serde_json::to_value(&new_config.server).ok()
        {
            warn!(
                "system/server configuration changed in the new config, but \
                 worker threads and process-level settings are NOT applied by \
                 hot reload; restart zentinel to apply them."
            );
        }

        // Run pre-reload hooks
        let hooks = self.reload_hooks.read().await;
        for hook in hooks.iter() {
            trace!(hook_name = %hook.name(), "Running pre-reload hook");
            if let Err(e) = hook.pre_reload(&old_config, &new_config).await {
                warn!(
                    hook_name = %hook.name(),
                    error = %e,
                    "Pre-reload hook failed"
                );
                // Continue with reload despite hook failure
            }
        }
        drop(hooks);

        // Save previous config for rollback
        trace!("Saving previous configuration for potential rollback");
        *self.previous_config.write().await = Some(old_config.clone());

        // Apply new configuration atomically
        trace!("Applying new configuration atomically");
        self.current_config.store(Arc::new(new_config.clone()));

        // Run post-reload hooks
        let hooks = self.reload_hooks.read().await;
        for hook in hooks.iter() {
            trace!(hook_name = %hook.name(), "Running post-reload hook");
            hook.post_reload(&old_config, &new_config).await;
        }
        drop(hooks);

        // Update statistics
        let duration = start.elapsed();
        let successful_count = self
            .stats
            .successful_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        *self.stats.last_success.write().await = Some(Instant::now());

        // Update average duration
        {
            let mut avg = self.stats.avg_duration_ms.write().await;
            let total = successful_count as f64;
            *avg = (*avg * (total - 1.0) + duration.as_millis() as f64) / total;
        }

        // Increment config version
        let new_version = self
            .stats
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;

        let _ = self.reload_tx.send(ReloadEvent::Applied {
            timestamp: Instant::now(),
            version: format!("v{}", new_version),
        });

        // Reload TLS certificates (hot-reload)
        // This picks up any certificate file changes without restart
        let (cert_success, cert_errors) = self.cert_reloader.reload_all();
        if !cert_errors.is_empty() {
            for (listener_id, error) in &cert_errors {
                error!(
                    listener_id = %listener_id,
                    error = %error,
                    "TLS certificate reload failed for listener"
                );
            }
        }

        info!(
            duration_ms = duration.as_millis(),
            successful_reloads = successful_count,
            route_count = new_config.routes.len(),
            upstream_count = new_config.upstreams.len(),
            cert_reload_success = cert_success,
            cert_reload_errors = cert_errors.len(),
            "Configuration reload completed successfully"
        );

        Ok(())
    }

    /// Apply a programmatically-generated configuration directly.
    ///
    /// This is the same as `reload()` but accepts a `Config` instead of
    /// reading from disk. Used by the Gateway API controller to push
    /// translated Kubernetes resources into the proxy without file I/O.
    ///
    /// Runs the full validation → hooks → atomic swap → hooks pipeline.
    /// Apply one incremental change to the live configuration.
    ///
    /// Clones the current configuration, applies the single change, and hands
    /// the result to [`apply_config`](Self::apply_config) -- so validation,
    /// the atomic swap, event emission and rollback all behave exactly as they
    /// do for a full reload. The difference is only in how the new
    /// configuration was produced.
    ///
    /// The change is rejected before anything is swapped if it does not apply:
    /// adding a route that exists, removing a target that does not. Reporting
    /// success for those would tell the caller their proxy is in a state it is
    /// not in.
    pub async fn apply_change(&self, change: diff::ConfigChange) -> ZentinelResult<()> {
        let summary = change.summary();
        let mut next = (*self.current()).clone();

        if let Err(e) = change.apply_to(&mut next) {
            warn!(change = %summary, error = %e, "Rejected configuration change");
            return Err(e);
        }

        info!(change = %summary, "Applying configuration change");
        self.apply_config(next, ReloadTrigger::Manual).await
    }

    pub async fn apply_config(
        &self,
        new_config: Config,
        trigger: ReloadTrigger,
    ) -> ZentinelResult<()> {
        // Serialize reloads — only one at a time
        let _reload_guard = self.reload_mutex.lock().await;

        let start = Instant::now();
        let reload_num = self
            .stats
            .total_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        info!(
            trigger = ?trigger,
            reload_num = reload_num,
            routes = new_config.routes.len(),
            upstreams = new_config.upstreams.len(),
            listeners = new_config.listeners.len(),
            "Applying programmatic configuration"
        );

        let _ = self.reload_tx.send(ReloadEvent::Started {
            timestamp: Instant::now(),
            trigger,
        });

        // Validate
        if let Err(e) = self.validate_config(&new_config).await {
            error!(error = %e, "Programmatic configuration validation failed");
            self.stats
                .failed_reloads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            *self.stats.last_failure.write().await = Some(Instant::now());

            let _ = self.reload_tx.send(ReloadEvent::Failed {
                timestamp: Instant::now(),
                error: e.to_string(),
            });

            return Err(e);
        }

        let _ = self.reload_tx.send(ReloadEvent::Validated {
            timestamp: Instant::now(),
        });

        // Lowered like a configuration loaded from a file (#548); a no-op on
        // one that already is, such as `apply_change`'s.
        let new_config = new_config.lower_scopes();

        // Get current config for rollback and hooks
        let old_config = self.current_config.load_full();

        // Run pre-reload hooks
        let hooks = self.reload_hooks.read().await;
        for hook in hooks.iter() {
            if let Err(e) = hook.pre_reload(&old_config, &new_config).await {
                warn!(hook_name = %hook.name(), error = %e, "Pre-reload hook failed");
            }
        }
        drop(hooks);

        // Save previous config for rollback
        *self.previous_config.write().await = Some(old_config.clone());

        // Atomic swap
        self.current_config.store(Arc::new(new_config.clone()));

        // Run post-reload hooks
        let hooks = self.reload_hooks.read().await;
        for hook in hooks.iter() {
            hook.post_reload(&old_config, &new_config).await;
        }
        drop(hooks);

        // Update statistics
        let duration = start.elapsed();
        let successful_count = self
            .stats
            .successful_reloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        *self.stats.last_success.write().await = Some(Instant::now());

        {
            let mut avg = self.stats.avg_duration_ms.write().await;
            let total = successful_count as f64;
            *avg = (*avg * (total - 1.0) + duration.as_millis() as f64) / total;
        }

        let new_version = self
            .stats
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;

        let _ = self.reload_tx.send(ReloadEvent::Applied {
            timestamp: Instant::now(),
            version: format!("v{}", new_version),
        });

        // Reload TLS certificates
        let (cert_success, cert_errors) = self.cert_reloader.reload_all();
        if !cert_errors.is_empty() {
            for (listener_id, error) in &cert_errors {
                error!(
                    listener_id = %listener_id,
                    error = %error,
                    "TLS certificate reload failed for listener"
                );
            }
        }

        info!(
            duration_ms = duration.as_millis(),
            successful_reloads = successful_count,
            route_count = new_config.routes.len(),
            upstream_count = new_config.upstreams.len(),
            cert_reload_success = cert_success,
            cert_reload_errors = cert_errors.len(),
            "Programmatic configuration applied successfully"
        );

        Ok(())
    }

    /// Get a handle to the underlying ArcSwap for direct reads.
    ///
    /// Used by the Gateway API controller to share the same config store.
    pub fn config_store(&self) -> Arc<ArcSwap<Config>> {
        Arc::clone(&self.current_config)
    }

    /// Rollback to previous configuration
    pub async fn rollback(&self, reason: String) -> ZentinelResult<()> {
        info!(
            reason = %reason,
            "Starting configuration rollback"
        );

        let previous = self.previous_config.read().await.clone();

        if let Some(prev_config) = previous {
            trace!(
                route_count = prev_config.routes.len(),
                "Found previous configuration for rollback"
            );

            // Validate previous config (should always pass)
            trace!("Validating previous configuration");
            if let Err(e) = self.validate_config(&prev_config).await {
                error!(
                    error = %e,
                    "Previous configuration validation failed during rollback"
                );
                return Err(e);
            }

            // Apply previous configuration
            trace!("Applying previous configuration");
            self.current_config.store(prev_config.clone());
            let rollback_count = self
                .stats
                .rollbacks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                + 1;

            let _ = self.reload_tx.send(ReloadEvent::RolledBack {
                timestamp: Instant::now(),
                reason: reason.clone(),
            });

            info!(
                reason = %reason,
                rollback_count = rollback_count,
                route_count = prev_config.routes.len(),
                "Configuration rolled back successfully"
            );
            Ok(())
        } else {
            warn!("No previous configuration available for rollback");
            Err(ZentinelError::Config {
                message: "No previous configuration available".to_string(),
                source: None,
            })
        }
    }

    /// Validate configuration
    async fn validate_config(&self, config: &Config) -> ZentinelResult<()> {
        trace!(
            route_count = config.routes.len(),
            upstream_count = config.upstreams.len(),
            "Starting configuration validation"
        );

        // Built-in validation
        trace!("Running built-in config validation");
        config.validate()?;

        // Run custom validators
        let validators = self.validators.read().await;
        trace!(
            validator_count = validators.len(),
            "Running custom validators"
        );
        for validator in validators.iter() {
            trace!(validator_name = %validator.name(), "Running validator");
            validator.validate(config).await.map_err(|e| {
                error!(
                    validator_name = %validator.name(),
                    error = %e,
                    "Validator failed"
                );
                e
            })?;
        }

        debug!(
            route_count = config.routes.len(),
            upstream_count = config.upstreams.len(),
            "Configuration validation passed"
        );

        Ok(())
    }

    /// Add configuration validator
    pub async fn add_validator(&self, validator: Box<dyn ConfigValidator>) {
        info!("Adding configuration validator: {}", validator.name());
        self.validators.write().await.push(validator);
    }

    /// Add reload hook
    pub async fn add_hook(&self, hook: Box<dyn ReloadHook>) {
        info!("Adding reload hook: {}", hook.name());
        self.reload_hooks.write().await.push(hook);
    }

    /// Subscribe to reload events
    pub fn subscribe(&self) -> broadcast::Receiver<ReloadEvent> {
        self.reload_tx.subscribe()
    }

    /// Get reload statistics
    pub fn stats(&self) -> &ReloadStats {
        &self.stats
    }

    /// Create a lightweight clone for async tasks
    fn clone_for_task(&self) -> ConfigManager {
        ConfigManager {
            current_config: Arc::clone(&self.current_config),
            previous_config: Arc::clone(&self.previous_config),
            config_path: self.config_path.clone(),
            watcher: self.watcher.clone(),
            reload_tx: self.reload_tx.clone(),
            stats: Arc::clone(&self.stats),
            validators: Arc::clone(&self.validators),
            reload_hooks: Arc::clone(&self.reload_hooks),
            cert_reloader: Arc::clone(&self.cert_reloader),
            reload_mutex: Arc::clone(&self.reload_mutex),
            source_signature: Arc::clone(&self.source_signature),
        }
    }
}

// ============================================================================
// Audit Reload Hook
// ============================================================================

/// Reload hook that logs configuration changes to the audit log.
pub struct AuditReloadHook {
    log_manager: SharedLogManager,
}

impl AuditReloadHook {
    /// Create a new audit reload hook with the given log manager.
    pub fn new(log_manager: SharedLogManager) -> Self {
        Self { log_manager }
    }
}

#[async_trait::async_trait]
impl ReloadHook for AuditReloadHook {
    async fn pre_reload(&self, old_config: &Config, new_config: &Config) -> ZentinelResult<()> {
        // Log that reload is starting
        let trace_id = uuid::Uuid::new_v4().to_string();
        let audit_entry = AuditLogEntry::config_change(
            &trace_id,
            "reload_started",
            format!(
                "Configuration reload starting: {} routes -> {} routes, {} upstreams -> {} upstreams",
                old_config.routes.len(),
                new_config.routes.len(),
                old_config.upstreams.len(),
                new_config.upstreams.len()
            ),
        );
        self.log_manager.log_audit(&audit_entry);
        Ok(())
    }

    async fn post_reload(&self, old_config: &Config, new_config: &Config) {
        // Log successful reload
        let trace_id = uuid::Uuid::new_v4().to_string();
        let audit_entry = AuditLogEntry::config_change(
            &trace_id,
            "reload_success",
            format!(
                "Configuration reload successful: {} routes, {} upstreams, {} listeners",
                new_config.routes.len(),
                new_config.upstreams.len(),
                new_config.listeners.len()
            ),
        )
        .with_metadata("old_routes", old_config.routes.len().to_string())
        .with_metadata("new_routes", new_config.routes.len().to_string())
        .with_metadata("old_upstreams", old_config.upstreams.len().to_string())
        .with_metadata("new_upstreams", new_config.upstreams.len().to_string());
        self.log_manager.log_audit(&audit_entry);
    }

    async fn on_failure(&self, config: &Config, error: &ZentinelError) {
        // Log failed reload
        let trace_id = uuid::Uuid::new_v4().to_string();
        let audit_entry = AuditLogEntry::config_change(
            &trace_id,
            "reload_failed",
            format!("Configuration reload failed: {}", error),
        )
        .with_metadata("current_routes", config.routes.len().to_string())
        .with_metadata("current_upstreams", config.upstreams.len().to_string());
        self.log_manager.log_audit(&audit_entry);
    }

    fn name(&self) -> &str {
        "audit_reload_hook"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_config_reload_rejects_invalid_config() {
        // Create valid initial config
        let initial_config = Config::default_for_testing();
        let initial_routes = initial_config.routes.len();

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        // Write INVALID config (not valid KDL)
        std::fs::write(&config_path, "this is not valid KDL { {{{{ broken").unwrap();

        // Create config manager with valid initial config
        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // Verify initial config is loaded
        assert_eq!(manager.current().routes.len(), initial_routes);

        // Attempt reload with invalid config - should fail
        let result = manager.reload(ReloadTrigger::Manual).await;
        assert!(result.is_err(), "Reload should fail for invalid config");

        // Verify original config is STILL loaded (not replaced)
        assert_eq!(
            manager.current().routes.len(),
            initial_routes,
            "Original config should be preserved after failed reload"
        );

        // Verify failure was recorded in stats
        assert_eq!(
            manager
                .stats()
                .failed_reloads
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Failed reload should be recorded"
        );
    }

    #[tokio::test]
    async fn test_config_reload_accepts_valid_config() {
        // Create valid initial config
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        // Create a static files directory for the test
        let static_dir = temp_dir.path().join("static");
        std::fs::create_dir_all(&static_dir).unwrap();

        // Write a valid config with upstream
        let valid_config = r#"
server {
    worker-threads 4
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

routes {
    route "api" {
        priority "high"
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
    }
}
"#;
        std::fs::write(&config_path, valid_config).unwrap();

        // Create config manager
        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // Reload should succeed with valid config
        let result = manager.reload(ReloadTrigger::Manual).await;
        assert!(
            result.is_ok(),
            "Reload should succeed for valid config: {:?}",
            result.err()
        );

        // Verify success was recorded
        assert_eq!(
            manager
                .stats()
                .successful_reloads
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Successful reload should be recorded"
        );
    }

    /// A configuration directory split the way `config/example-multi-file`
    /// is: an entry file including the routes, which live in their own file.
    fn write_config_directory(dir: &Path, route_prefix: &str) {
        std::fs::create_dir_all(dir.join("routes")).unwrap();
        std::fs::write(
            dir.join("zentinel.kdl"),
            r#"
system {
    worker-threads 1
}
listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}
upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
include "routes/*.kdl"
"#,
        )
        .unwrap();
        std::fs::write(
            dir.join("routes/api.kdl"),
            format!(
                "routes {{\n    route \"api\" {{\n        matches {{\n            path-prefix \"{route_prefix}\"\n        }}\n        upstream \"backend\"\n    }}\n}}\n"
            ),
        )
        .unwrap();
    }

    fn api_prefix(manager: &ConfigManager) -> String {
        format!("{:?}", manager.current().routes[0].matches)
    }

    /// #541: reloading (SIGHUP, the admin endpoint) a configuration loaded
    /// from a directory re-reads every file of it.
    #[tokio::test]
    async fn reload_rereads_a_configuration_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("conf");
        write_config_directory(&dir, "/v1/");
        let initial = Config::from_file(&dir).unwrap();
        let manager = ConfigManager::new(&dir, initial).await.unwrap();
        assert!(api_prefix(&manager).contains("/v1/"));

        write_config_directory(&dir, "/v2/");
        manager
            .reload(ReloadTrigger::Signal)
            .await
            .expect("reloading a directory should succeed");

        assert!(
            api_prefix(&manager).contains("/v2/"),
            "{}",
            api_prefix(&manager)
        );
    }

    /// #541: auto-reload watches the directory, so editing any file in it
    /// takes effect.
    #[tokio::test]
    async fn auto_reload_watches_a_configuration_directory() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("conf");
        write_config_directory(&dir, "/v1/");
        let initial = Config::from_file(&dir).unwrap();
        let manager = ConfigManager::new(&dir, initial).await.unwrap();
        manager.start_watching().await.unwrap();

        write_config_directory(&dir, "/v2/");

        let deadline = Instant::now() + Duration::from_secs(10);
        while !api_prefix(&manager).contains("/v2/") {
            assert!(
                Instant::now() < deadline,
                "a change in the directory was not picked up: {}",
                api_prefix(&manager)
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn reloads(manager: &ConfigManager) -> u64 {
        manager
            .stats()
            .total_reloads
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn wait_for_prefix(manager: &ConfigManager, prefix: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !api_prefix(manager).contains(prefix) {
            assert!(
                Instant::now() < deadline,
                "the change was not picked up: {}",
                api_prefix(manager)
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// #553: one edit is one reload. The file watcher and the poll fallback
    /// both notice it; the second to look finds the files as the first
    /// reload read them, and does nothing.
    #[tokio::test]
    async fn auto_reload_reloads_once_per_edit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("conf");
        write_config_directory(&dir, "/v1/");
        let entry = dir.join("zentinel.kdl");
        let initial = Config::from_file(&entry).unwrap();
        let manager = ConfigManager::new(&entry, initial).await.unwrap();
        manager.start_watching().await.unwrap();
        // Let the watcher settle so the writes above are not reported late.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let before = reloads(&manager);

        write_config_directory(&dir, "/v2/");
        wait_for_prefix(&manager, "/v2/").await;
        // Past the watcher's debounce and at least two poll rounds.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert_eq!(reloads(&manager) - before, 1, "one edit, one reload");

        // Unchanged files are not reloaded, whatever asks.
        assert!(!manager
            .reload_if_changed(ReloadTrigger::FileChange)
            .await
            .unwrap());
        assert_eq!(reloads(&manager) - before, 1);
    }

    /// #553: the poll fallback reads every file the configuration reads.
    /// Before, it fingerprinted only the entry file, so a change to an
    /// included file the watcher missed was never picked up. A file outside
    /// the entry file's directory is never seen by the watcher, which makes
    /// the poll the only way to see it.
    #[tokio::test]
    async fn auto_reload_sees_an_included_file_the_watcher_does_not() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("conf");
        let shared = temp_dir.path().join("shared");
        write_config_directory(&dir, "/v1/");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::rename(dir.join("routes/api.kdl"), shared.join("api.kdl")).unwrap();
        let entry = dir.join("zentinel.kdl");
        let text = std::fs::read_to_string(&entry)
            .unwrap()
            .replace("include \"routes/*.kdl\"", "include \"../shared/api.kdl\"");
        std::fs::write(&entry, text).unwrap();

        let initial = Config::from_file(&entry).unwrap();
        let manager = ConfigManager::new(&entry, initial).await.unwrap();
        assert!(api_prefix(&manager).contains("/v1/"));
        manager.start_watching().await.unwrap();

        // Same length, so neither length nor the entry file changes.
        let routes = std::fs::read_to_string(shared.join("api.kdl"))
            .unwrap()
            .replace("/v1/", "/v2/");
        std::fs::write(shared.join("api.kdl"), routes).unwrap();
        wait_for_prefix(&manager, "/v2/").await;
    }

    // ========================================================================
    // Concurrent Reload Tests
    // ========================================================================

    /// Helper to create a valid config file with a specified route count
    fn write_config_with_routes(path: &Path, route_count: usize) {
        let mut routes = String::new();
        for i in 0..route_count {
            routes.push_str(&format!(
                r#"
    route "route{i}" {{
        priority "medium"
        matches {{
            path-prefix "/route{i}/"
        }}
        upstream "backend"
    }}
"#
            ));
        }

        let config = format!(
            r#"
server {{
    worker-threads 4
}}

listeners {{
    listener "http" {{
        address "0.0.0.0:8080"
        protocol "http"
    }}
}}

upstreams {{
    upstream "backend" {{
        target "127.0.0.1:3000"
    }}
}}

routes {{
{routes}
}}
"#
        );

        std::fs::write(path, config).unwrap();
    }

    #[tokio::test]
    async fn test_concurrent_config_reads_during_reload() {
        // Test that config reads don't block or panic during reload
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        write_config_with_routes(&config_path, 5);

        let manager = Arc::new(
            ConfigManager::new(&config_path, initial_config)
                .await
                .unwrap(),
        );

        // Spawn multiple readers that continuously read config
        let mut readers = Vec::new();
        for _ in 0..10 {
            let manager_clone = Arc::clone(&manager);
            readers.push(tokio::spawn(async move {
                let mut read_count = 0;
                for _ in 0..100 {
                    let config = manager_clone.current();
                    // Access config to ensure it's valid
                    let _ = config.routes.len();
                    read_count += 1;
                    tokio::task::yield_now().await;
                }
                read_count
            }));
        }

        // Simultaneously trigger reload
        let manager_reload = Arc::clone(&manager);
        let reload_handle =
            tokio::spawn(async move { manager_reload.reload(ReloadTrigger::Manual).await });

        // Wait for all readers and the reload
        let mut total_reads = 0;
        for reader in readers {
            total_reads += reader.await.unwrap();
        }

        let reload_result = reload_handle.await.unwrap();
        assert!(reload_result.is_ok(), "Reload should succeed");
        assert_eq!(total_reads, 1000, "All reads should complete");
    }

    #[tokio::test]
    async fn test_multiple_concurrent_reloads() {
        // Test that multiple simultaneous reloads don't cause panics or corruption
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        write_config_with_routes(&config_path, 3);

        let manager = Arc::new(
            ConfigManager::new(&config_path, initial_config)
                .await
                .unwrap(),
        );

        // Trigger multiple reloads concurrently
        let mut reload_handles = Vec::new();
        for i in 0..5 {
            let manager_clone = Arc::clone(&manager);
            let trigger = if i % 2 == 0 {
                ReloadTrigger::Manual
            } else {
                ReloadTrigger::Signal
            };
            reload_handles.push(tokio::spawn(
                async move { manager_clone.reload(trigger).await },
            ));
        }

        // All reloads should complete (some may fail due to racing, but no panics)
        let mut success_count = 0;
        for handle in reload_handles {
            if handle.await.unwrap().is_ok() {
                success_count += 1;
            }
        }

        // At least one reload should succeed
        assert!(success_count >= 1, "At least one reload should succeed");

        // Stats should reflect all attempts
        let total = manager
            .stats()
            .total_reloads
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(total, 5, "All reload attempts should be counted");
    }

    #[tokio::test]
    async fn test_config_visibility_after_reload() {
        // Test that new config is immediately visible after reload completes
        let initial_config = Config::default_for_testing();
        let initial_route_count = initial_config.routes.len();

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        // Start with 2 routes
        write_config_with_routes(&config_path, 2);

        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // Verify initial config
        assert_eq!(manager.current().routes.len(), initial_route_count);

        // Reload to get 2 routes from file
        manager.reload(ReloadTrigger::Manual).await.unwrap();
        assert_eq!(manager.current().routes.len(), 2);

        // Update file to 5 routes and reload
        write_config_with_routes(&config_path, 5);
        manager.reload(ReloadTrigger::Manual).await.unwrap();
        assert_eq!(
            manager.current().routes.len(),
            5,
            "New config should be visible immediately after reload"
        );

        // Update file to 1 route and reload
        write_config_with_routes(&config_path, 1);
        manager.reload(ReloadTrigger::Manual).await.unwrap();
        assert_eq!(
            manager.current().routes.len(),
            1,
            "Config changes should be visible after each reload"
        );
    }

    #[tokio::test]
    async fn test_rapid_successive_reloads() {
        // Test rapid-fire reloads don't cause issues
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        write_config_with_routes(&config_path, 3);

        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // Perform 20 rapid reloads
        for i in 0..20 {
            // Alternate between different route counts
            write_config_with_routes(&config_path, (i % 5) + 1);
            let result = manager.reload(ReloadTrigger::Manual).await;
            assert!(result.is_ok(), "Reload {} should succeed", i);
        }

        // Verify final state
        let stats = manager.stats();
        assert_eq!(
            stats
                .successful_reloads
                .load(std::sync::atomic::Ordering::Relaxed),
            20,
            "All 20 reloads should succeed"
        );
        assert_eq!(
            stats
                .failed_reloads
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "No reloads should fail"
        );
    }

    #[tokio::test]
    async fn test_rollback_preserves_previous_config() {
        // Test that rollback correctly restores previous configuration
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        // Start with 3 routes
        write_config_with_routes(&config_path, 3);

        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // First reload to establish baseline
        manager.reload(ReloadTrigger::Manual).await.unwrap();
        assert_eq!(manager.current().routes.len(), 3);

        // Second reload with 5 routes
        write_config_with_routes(&config_path, 5);
        manager.reload(ReloadTrigger::Manual).await.unwrap();
        assert_eq!(manager.current().routes.len(), 5);

        // Rollback should restore 3 routes
        manager
            .rollback("Testing rollback".to_string())
            .await
            .unwrap();
        assert_eq!(
            manager.current().routes.len(),
            3,
            "Rollback should restore previous config"
        );

        // Verify rollback was recorded
        assert_eq!(
            manager
                .stats()
                .rollbacks
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Rollback should be recorded in stats"
        );
    }

    #[tokio::test]
    async fn test_reload_events_broadcast() {
        // Test that reload events are properly broadcast to subscribers
        let initial_config = Config::default_for_testing();
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.kdl");

        write_config_with_routes(&config_path, 2);

        let manager = ConfigManager::new(&config_path, initial_config)
            .await
            .unwrap();

        // Subscribe to reload events
        let mut receiver = manager.subscribe();

        // Trigger reload
        manager.reload(ReloadTrigger::Manual).await.unwrap();

        // Collect events (non-blocking with timeout)
        let mut events = Vec::new();
        while let Ok(Ok(event)) =
            tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await
        {
            events.push(event);
        }

        // Verify we received the expected events
        assert!(
            events.len() >= 2,
            "Should receive at least Started and Applied/Validated events"
        );

        // Check for Started event
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReloadEvent::Started { .. })),
            "Should receive Started event"
        );

        // Check for Applied event (successful reload)
        assert!(
            events
                .iter()
                .any(|e| matches!(e, ReloadEvent::Applied { .. })),
            "Should receive Applied event on success"
        );
    }

    #[tokio::test]
    async fn test_graceful_coordinator_with_reload() {
        // Test that GracefulReloadCoordinator correctly tracks requests during reload
        let coordinator = GracefulReloadCoordinator::new(Duration::from_secs(5));

        // Simulate requests starting
        coordinator.inc_requests();
        coordinator.inc_requests();
        coordinator.inc_requests();
        assert_eq!(coordinator.active_count(), 3);

        // Simulate one request completing during reload prep
        coordinator.dec_requests();
        assert_eq!(coordinator.active_count(), 2);

        // Start drain in background
        let coord_clone = Arc::new(coordinator);
        let coord_for_drain = Arc::clone(&coord_clone);
        let drain_handle = tokio::spawn(async move { coord_for_drain.wait_for_drain().await });

        // Simulate remaining requests completing
        tokio::time::sleep(Duration::from_millis(50)).await;
        coord_clone.dec_requests();
        tokio::time::sleep(Duration::from_millis(50)).await;
        coord_clone.dec_requests();

        // Drain should complete successfully
        let drained = drain_handle.await.unwrap();
        assert!(drained, "All requests should drain successfully");
    }

    #[tokio::test]
    async fn test_graceful_coordinator_drain_timeout() {
        // Test that drain times out correctly when requests don't complete
        let coordinator = GracefulReloadCoordinator::new(Duration::from_millis(200));

        // Simulate stuck requests
        coordinator.inc_requests();
        coordinator.inc_requests();

        // Start drain - should timeout
        let drained = coordinator.wait_for_drain().await;
        assert!(!drained, "Drain should timeout with stuck requests");
        assert_eq!(
            coordinator.active_count(),
            2,
            "Requests should still be tracked"
        );
    }
}
