//! Signal handling for configuration reload and shutdown.
//!
//! Bridges OS signals with the async runtime for graceful handling of
//! SIGHUP (reload) and SIGTERM/SIGINT (shutdown).

use std::sync::{mpsc, Arc, Mutex};

/// Signal type for cross-thread communication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalType {
    /// Reload configuration (SIGHUP)
    Reload,
    /// Graceful shutdown (SIGTERM/SIGINT)
    Shutdown,
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
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Get a sender for use in signal handlers
    pub fn sender(&self) -> mpsc::Sender<SignalType> {
        self.tx.clone()
    }

    /// Receive the next signal (blocking)
    ///
    /// This should be called from an async context using spawn_blocking
    pub fn recv_blocking(&self) -> Option<SignalType> {
        self.rx.lock().ok()?.recv().ok()
    }

    /// Try to receive a signal without blocking
    pub fn try_recv(&self) -> Option<SignalType> {
        self.rx.lock().ok()?.try_recv().ok()
    }
}

impl Default for SignalManager {
    fn default() -> Self {
        Self::new()
    }
}
