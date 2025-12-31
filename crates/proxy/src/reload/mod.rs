//! Configuration hot reload module for Sentinel proxy.
//!
//! This module implements zero-downtime configuration reloading with validation,
//! atomic swaps, and rollback support for production reliability.
//!
//! ## Submodules
//!
//! - [`coordinator`]: Graceful reload coordination and request draining
//! - [`signals`]: OS signal handling (SIGHUP, SIGTERM)
//! - [`validators`]: Runtime configuration validators

mod coordinator;
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
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, trace, warn};

use sentinel_common::errors::{SentinelError, SentinelResult};
use sentinel_config::Config;

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
}

// ============================================================================
// Traits
// ============================================================================

/// Configuration validator trait
#[async_trait::async_trait]
pub trait ConfigValidator: Send + Sync {
    /// Validate configuration before applying
    async fn validate(&self, config: &Config) -> SentinelResult<()>;

    /// Validator name for logging
    fn name(&self) -> &str;
}

/// Reload hook trait for custom actions
#[async_trait::async_trait]
pub trait ReloadHook: Send + Sync {
    /// Called before reload starts
    async fn pre_reload(&self, old_config: &Config, new_config: &Config) -> SentinelResult<()>;

    /// Called after successful reload
    async fn post_reload(&self, old_config: &Config, new_config: &Config);

    /// Called on reload failure
    async fn on_failure(&self, config: &Config, error: &SentinelError);

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
}

impl ConfigManager {
    /// Create new configuration manager
    pub async fn new(
        config_path: impl AsRef<Path>,
        initial_config: Config,
    ) -> SentinelResult<Self> {
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
            current_config: Arc::new(ArcSwap::from_pointee(initial_config)),
            previous_config: Arc::new(RwLock::new(None)),
            config_path,
            watcher: Arc::new(RwLock::new(None)),
            reload_tx,
            stats: Arc::new(ReloadStats::default()),
            validators: Arc::new(RwLock::new(Vec::new())),
            reload_hooks: Arc::new(RwLock::new(Vec::new())),
            cert_reloader: Arc::new(CertificateReloader::new()),
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
    /// when the config file is modified.
    pub async fn start_watching(&self) -> SentinelResult<()> {
        // Check if already watching
        if self.watcher.read().await.is_some() {
            warn!("File watcher already active, skipping");
            return Ok(());
        }

        let config_path = self.config_path.clone();

        // Create file watcher
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        let mut watcher =
            notify::recommended_watcher(move |event: Result<Event, notify::Error>| {
                if let Ok(event) = event {
                    let _ = tx.blocking_send(event);
                }
            })
            .map_err(|e| SentinelError::Config {
                message: format!("Failed to create file watcher: {}", e),
                source: None,
            })?;

        // Watch config file
        watcher
            .watch(&config_path, RecursiveMode::NonRecursive)
            .map_err(|e| SentinelError::Config {
                message: format!("Failed to watch config file: {}", e),
                source: None,
            })?;

        // Store watcher using interior mutability
        *self.watcher.write().await = Some(watcher);

        // Spawn event handler task
        let manager = Arc::new(self.clone_for_task());
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    info!("Configuration file changed, triggering reload");

                    // Debounce rapid changes
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    if let Err(e) = manager.reload(ReloadTrigger::FileChange).await {
                        error!("Auto-reload failed: {}", e);
                        error!("Continuing with current configuration");
                    }
                }
            }
        });

        info!(
            "Auto-reload enabled: watching configuration file {:?}",
            self.config_path
        );
        Ok(())
    }

    /// Reload configuration
    pub async fn reload(&self, trigger: ReloadTrigger) -> SentinelResult<()> {
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

                return Err(SentinelError::Config {
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

    /// Rollback to previous configuration
    pub async fn rollback(&self, reason: String) -> SentinelResult<()> {
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
            Err(SentinelError::Config {
                message: "No previous configuration available".to_string(),
                source: None,
            })
        }
    }

    /// Validate configuration
    async fn validate_config(&self, config: &Config) -> SentinelResult<()> {
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
    async fn pre_reload(&self, old_config: &Config, new_config: &Config) -> SentinelResult<()> {
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

    async fn on_failure(&self, config: &Config, error: &SentinelError) {
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
}
