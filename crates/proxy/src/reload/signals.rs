//! Signal handling for configuration reload and shutdown.
//!
//! Bridges OS signals with the async runtime for graceful handling of
//! SIGHUP (reload), SIGUSR1 (reopen logs) and SIGTERM/SIGINT (shutdown).

use std::sync::{mpsc, Arc, Mutex};
use tracing::{debug, trace};

/// Signal type for cross-thread communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    /// Reload configuration (SIGHUP)
    Reload,
    /// Graceful shutdown (SIGTERM/SIGINT)
    Shutdown,
    /// Reopen the log files (SIGUSR1)
    ReopenLogs,
}

/// Signal manager for handling OS signals with async integration
///
/// Bridges thread-based signal handlers with the async runtime using channels.
pub struct SignalManager {
    /// Sender for signal notifications
    tx: mpsc::Sender<SignalType>,
    /// Receiver for signal notifications (wrapped for async)
    rx: Arc<Mutex<mpsc::Receiver<SignalType>>>,
}

impl SignalManager {
    /// Create a new signal manager
    pub fn new() -> Self {
        debug!("Creating signal manager");
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Get a sender for use in signal handlers
    pub fn sender(&self) -> mpsc::Sender<SignalType> {
        trace!("Cloning signal sender for handler");
        self.tx.clone()
    }

    /// Receive the next signal (blocking)
    ///
    /// This should be called from an async context using spawn_blocking
    pub fn recv_blocking(&self) -> Option<SignalType> {
        trace!("Waiting for signal (blocking)");
        let signal = self.rx.lock().ok()?.recv().ok();
        if let Some(ref s) = signal {
            debug!(signal = ?s, "Received signal");
        }
        signal
    }

    /// Try to receive a signal without blocking
    pub fn try_recv(&self) -> Option<SignalType> {
        let signal = self.rx.lock().ok()?.try_recv().ok();
        if let Some(ref s) = signal {
            debug!(signal = ?s, "Received signal (non-blocking)");
        }
        signal
    }
}

impl Default for SignalManager {
    fn default() -> Self {
        Self::new()
    }
}
