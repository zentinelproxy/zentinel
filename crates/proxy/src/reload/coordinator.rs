//! Graceful reload coordination.
//!
//! Handles request draining and shutdown coordination for zero-downtime reloads.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

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
        debug!(
            max_drain_time_secs = max_drain_time.as_secs(),
            "Creating graceful reload coordinator"
        );
        Self {
            active_requests: Arc::new(AtomicUsize::new(0)),
            max_drain_time,
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Increment active request count
    pub fn inc_requests(&self) {
        let count = self.active_requests.fetch_add(1, Ordering::Relaxed) + 1;
        trace!(active_requests = count, "Request started");
    }

    /// Decrement active request count
    pub fn dec_requests(&self) {
        let prev = self.active_requests.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            // Counter was already 0 — restore and warn
            self.active_requests.fetch_add(1, Ordering::Relaxed);
            warn!("Attempted to decrement active request count below zero");
            return;
        }
        trace!(active_requests = prev - 1, "Request completed");
    }

    /// Wait for active requests to drain
    ///
    /// Returns `true` if all requests drained within the timeout,
    /// `false` if timeout was reached with requests still active.
    pub async fn wait_for_drain(&self) -> bool {
        let start = Instant::now();
        let initial_count = self.active_requests.load(Ordering::Relaxed);

        info!(
            active_requests = initial_count,
            max_drain_time_secs = self.max_drain_time.as_secs(),
            "Starting request drain"
        );

        let mut last_logged_count = initial_count;

        while self.active_requests.load(Ordering::Relaxed) > 0 {
            if start.elapsed() > self.max_drain_time {
                let remaining = self.active_requests.load(Ordering::Relaxed);
                warn!(
                    remaining_requests = remaining,
                    elapsed_secs = start.elapsed().as_secs(),
                    "Drain timeout reached, requests still active"
                );
                return false;
            }

            let current_count = self.active_requests.load(Ordering::Relaxed);
            if current_count != last_logged_count {
                debug!(
                    remaining_requests = current_count,
                    elapsed_ms = start.elapsed().as_millis(),
                    "Draining requests"
                );
                last_logged_count = current_count;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!(
            elapsed_ms = start.elapsed().as_millis(),
            initial_requests = initial_count,
            "All requests drained successfully"
        );
        true
    }

    /// Get active request count
    pub fn active_count(&self) -> usize {
        self.active_requests.load(Ordering::Relaxed)
    }

    /// Request shutdown
    pub fn request_shutdown(&self) {
        info!(
            active_requests = self.active_requests.load(Ordering::Relaxed),
            "Shutdown requested"
        );
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
