//! Graceful reload coordination.
//!
//! Handles request draining and shutdown coordination for zero-downtime reloads.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Graceful reload coordinator
///
/// Tracks active requests and coordinates draining during configuration
/// reloads or graceful shutdown.
pub struct GracefulReloadCoordinator {
    /// Active requests counter
    active_requests: Arc<AtomicUsize>,
    /// Maximum wait time for draining
    max_drain_time: Duration,
    /// Shutdown flag
    shutdown_requested: Arc<AtomicBool>,
}

impl GracefulReloadCoordinator {
    /// Create new coordinator
    pub fn new(max_drain_time: Duration) -> Self {
        Self {
            active_requests: Arc::new(AtomicUsize::new(0)),
            max_drain_time,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Increment active request count
    pub fn inc_requests(&self) {
        self.active_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active request count
    pub fn dec_requests(&self) {
        self.active_requests.fetch_sub(1, Ordering::Relaxed);
    }

    /// Wait for active requests to drain
    ///
    /// Returns `true` if all requests drained within the timeout,
    /// `false` if timeout was reached with requests still active.
    pub async fn wait_for_drain(&self) -> bool {
        let start = Instant::now();

        while self.active_requests.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > self.max_drain_time {
                warn!(
                    "Drain timeout reached, {} requests still active",
                    self.active_requests.load(Ordering::Relaxed)
                );
                return false;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!("All requests drained successfully");
        true
    }

    /// Get active request count
    pub fn active_count(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    /// Request shutdown
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graceful_coordinator() {
        let coordinator = GracefulReloadCoordinator::new(Duration::from_secs(1));

        // Simulate active requests
        coordinator.inc_requests();
        coordinator.inc_requests();
        assert_eq!(coordinator.active_count(), 2);

        coordinator.dec_requests();
        assert_eq!(coordinator.active_count(), 1);

        coordinator.dec_requests();
        assert_eq!(coordinator.active_count(), 0);

        // Test drain
        let drained = coordinator.wait_for_drain().await;
        assert!(drained);
    }

    #[tokio::test]
    async fn test_graceful_coordinator_shutdown_flag() {
        let coordinator = GracefulReloadCoordinator::new(Duration::from_secs(1));

        assert!(!coordinator.is_shutdown_requested());

        coordinator.request_shutdown();

        assert!(coordinator.is_shutdown_requested());
    }
}
