//! Embedded mode: run the gateway controller alongside a Zentinel proxy.
//!
//! In embedded mode, the controller pushes translated config directly
//! into the proxy's `ConfigManager` via `apply_config()`, bypassing
//! the file-based bridge. This is the lowest-latency integration path,
//! but requires the proxy crate as a dependency.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │              Single Process                  │
//! │                                              │
//! │  ┌─────────────────┐  ┌──────────────────┐  │
//! │  │   Controller    │  │  Zentinel Proxy   │  │
//! │  │                 │  │                   │  │
//! │  │  Reconcilers    │  │  Pingora runtime  │  │
//! │  │  Translator ────┼──►  ConfigManager    │  │
//! │  │                 │  │  apply_config()   │  │
//! │  └─────────────────┘  └──────────────────┘  │
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! The embedded bridge connects the translator's output to the proxy's
//! `ConfigManager`. After each `rebuild()`, the translated `Config` is
//! pushed to the proxy through `apply_config()`, which triggers the full
//! validation, hook, and atomic swap pipeline.
//!
//! ```rust,ignore
//! use zentinel_gateway::embedded::ConfigBridge;
//!
//! // Create the bridge with a reference to the proxy's config manager
//! let bridge = ConfigBridge::new(config_manager.clone());
//!
//! // The translator calls the bridge after each rebuild
//! bridge.push(new_config).await?;
//! ```
//!
//! # Limitations
//!
//! - Pingora listeners must be configured before `run_forever()`. Gateway
//!   listener changes require a proxy restart (not just a config reload).
//! - The proxy and controller share a tokio runtime. The controller's
//!   reconciliation work runs on the same thread pool as request handling.
//! - For production deployments, the two-container sidecar pattern
//!   (via `ConfigWriter`) provides better isolation.

use tracing::{debug, info};

use zentinel_config::Config;

/// Bridge between the gateway controller and the proxy's ConfigManager.
///
/// This trait abstracts the config push mechanism so the translator
/// can work with either the file-based bridge or the embedded bridge.
#[async_trait::async_trait]
pub trait ConfigSink: Send + Sync {
    /// Push a new config to the sink.
    async fn push(&self, config: &Config) -> Result<(), String>;
}

/// File-based config sink (writes KDL to disk for the sidecar proxy).
pub struct FileSink {
    writer: crate::config_writer::ConfigWriter,
}

impl FileSink {
    pub fn new(writer: crate::config_writer::ConfigWriter) -> Self {
        Self { writer }
    }
}

#[async_trait::async_trait]
impl ConfigSink for FileSink {
    async fn push(&self, config: &Config) -> Result<(), String> {
        self.writer
            .write(config)
            .map_err(|e| format!("Failed to write config: {e}"))
    }
}

/// In-process config sink that calls `ConfigManager::apply_config()`.
///
/// This is used in embedded mode where the controller and proxy
/// share the same process. The `ConfigManager` reference is obtained
/// from the proxy's `ZentinelProxy` instance.
///
/// # Example
///
/// ```rust,ignore
/// // In the proxy's main(), after creating ZentinelProxy:
/// let config_manager = proxy.config_manager.clone();
/// let sink = EmbeddedSink::new(config_manager);
///
/// // Pass to the gateway controller
/// let controller = GatewayController::new().await?;
/// // controller would use sink.push() after each rebuild
/// ```
pub struct EmbeddedSink {
    /// The apply function, stored as a boxed async closure.
    /// This avoids a direct dependency on `zentinel-proxy` crate.
    apply_fn: Box<
        dyn Fn(Config) -> futures::future::BoxFuture<'static, Result<(), String>> + Send + Sync,
    >,
}

impl EmbeddedSink {
    /// Create a new embedded sink with a config apply function.
    ///
    /// The function should call `ConfigManager::apply_config()` on the
    /// proxy's config manager. This indirection avoids coupling the
    /// gateway crate directly to the proxy crate.
    pub fn new<F, Fut>(apply_fn: F) -> Self
    where
        F: Fn(Config) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self {
            apply_fn: Box::new(move |config| Box::pin(apply_fn(config))),
        }
    }
}

#[async_trait::async_trait]
impl ConfigSink for EmbeddedSink {
    async fn push(&self, config: &Config) -> Result<(), String> {
        info!("Pushing config to embedded proxy via apply_config()");
        (self.apply_fn)(config.clone()).await
    }
}

/// Placeholder for when no sink is configured (config only stored in ArcSwap).
pub struct NullSink;

#[async_trait::async_trait]
impl ConfigSink for NullSink {
    async fn push(&self, _config: &Config) -> Result<(), String> {
        debug!("NullSink: config not pushed (no sink configured)");
        Ok(())
    }
}
