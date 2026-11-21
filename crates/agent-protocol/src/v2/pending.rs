//! Bookkeeping for agent calls that are waiting for a response.
//!
//! A call registers a response channel under its correlation id, sends its
//! event and waits. The connection's reader task completes the call by taking
//! the channel out of the registry when the response arrives.
//!
//! Callers drop calls at any point: an outer timeout, a request that is
//! cancelled. [`PendingCall`] removes the registration when it is dropped, and
//! [`InFlight`] gives its count back, so what a call registered does not depend
//! on how far the call got.
//!
//! The registry sits behind a `parking_lot::Mutex` rather than a
//! `tokio::sync::Mutex` because `Drop` cannot await. Removing the entry with
//! `try_lock` skips the removal when the lock is busy, and spawning a task to
//! remove it later needs a runtime at the point of the drop. The lock is held
//! for one map operation at a time and never across an await point.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::AgentResponse;

/// How a wait for a response ended without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitError {
    /// No response arrived within the timeout.
    TimedOut,
    /// The registration was removed, or the connection ended, while waiting.
    Closed,
}

struct Entry {
    /// Tells this registration apart from a later one under the same
    /// correlation id.
    token: u64,
    sender: oneshot::Sender<AgentResponse>,
}

/// The calls on one connection that are waiting for a response, by
/// correlation id.
#[derive(Default)]
pub(crate) struct PendingCalls {
    entries: Mutex<HashMap<String, Entry>>,
    next_token: AtomicU64,
}

impl PendingCalls {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a call under `correlation_id`.
    ///
    /// The registration lasts until the response is delivered or the returned
    /// [`PendingCall`] is dropped, whichever comes first. A call already
    /// registered under the same id loses its registration and its wait ends
    /// with [`WaitError::Closed`].
    pub(crate) fn register<'a>(&'a self, correlation_id: &'a str) -> PendingCall<'a> {
        let (sender, receiver) = oneshot::channel();
        let token = self.next_token.fetch_add(1, Ordering::Relaxed);
        let replaced = self
            .entries
            .lock()
            .insert(correlation_id.to_string(), Entry { token, sender });
        // Dropped here, after the lock: it wakes the replaced call's wait.
        drop(replaced);
        PendingCall {
            calls: self,
            correlation_id,
            token,
            receiver,
            settled: false,
        }
    }

    /// Deliver `response` to the call waiting under `correlation_id`.
    ///
    /// Returns `false` when no call is waiting: it timed out or its caller
    /// dropped it before the response arrived.
    pub(crate) fn complete(&self, correlation_id: &str, response: AgentResponse) -> bool {
        let entry = self.entries.lock().remove(correlation_id);
        match entry {
            Some(entry) => {
                // The receiver may have gone in the meantime; nothing to do.
                let _ = entry.sender.send(response);
                true
            }
            None => false,
        }
    }

    /// Remove whatever is registered under `correlation_id`; its wait ends
    /// with [`WaitError::Closed`].
    pub(crate) fn remove(&self, correlation_id: &str) {
        let removed = self.entries.lock().remove(correlation_id);
        drop(removed);
    }

    /// Remove every registration; every wait ends with [`WaitError::Closed`].
    pub(crate) fn clear(&self) {
        let removed = std::mem::take(&mut *self.entries.lock());
        drop(removed);
    }

    /// The correlation ids of the calls now waiting.
    pub(crate) fn correlation_ids(&self) -> Vec<String> {
        self.entries.lock().keys().cloned().collect()
    }

    /// Remove the registration with `token`, if it is still the one under
    /// `correlation_id`. A newer call with the same id keeps its own.
    fn remove_registration(&self, correlation_id: &str, token: u64) {
        let removed = {
            let mut entries = self.entries.lock();
            if entries
                .get(correlation_id)
                .is_some_and(|entry| entry.token == token)
            {
                entries.remove(correlation_id)
            } else {
                None
            }
        };
        // Dropped here, after the lock is released.
        drop(removed);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

/// A call's registration in [`PendingCalls`], removed when this is dropped.
///
/// Hold it from registration until the call is over. Dropping it at any point,
/// including while [`PendingCall::wait`] is pending, leaves nothing registered.
#[must_use = "the registration is removed as soon as this is dropped"]
pub(crate) struct PendingCall<'a> {
    calls: &'a PendingCalls,
    correlation_id: &'a str,
    token: u64,
    receiver: oneshot::Receiver<AgentResponse>,
    /// The registration has already left the registry: the response was
    /// delivered, or `remove` or `clear` took it.
    settled: bool,
}

impl PendingCall<'_> {
    /// Wait up to `timeout` for the response.
    ///
    /// # Cancel Safety
    ///
    /// Cancel safe: dropping the future removes the registration.
    pub(crate) async fn wait(mut self, timeout: Duration) -> Result<AgentResponse, WaitError> {
        match tokio::time::timeout(timeout, &mut self.receiver).await {
            Ok(Ok(response)) => {
                self.settled = true;
                Ok(response)
            }
            Ok(Err(_)) => {
                self.settled = true;
                Err(WaitError::Closed)
            }
            Err(_) => Err(WaitError::TimedOut),
        }
    }
}

impl Drop for PendingCall<'_> {
    fn drop(&mut self) {
        if !self.settled {
            self.calls
                .remove_registration(self.correlation_id, self.token);
        }
    }
}

/// Counts a call as in flight until it is dropped.
#[must_use = "the call stops counting as in flight as soon as this is dropped"]
pub(crate) struct InFlight<'a>(&'a AtomicU64);

impl<'a> InFlight<'a> {
    pub(crate) fn enter(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(counter)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropping_a_call_removes_its_registration() {
        let calls = PendingCalls::new();

        let call = calls.register("cid-1");
        assert_eq!(calls.len(), 1);
        drop(call);

        assert_eq!(calls.len(), 0);
    }

    #[tokio::test]
    async fn dropping_a_waiting_call_removes_its_registration() {
        let calls = PendingCalls::new();

        let waiting = calls.register("cid-1").wait(Duration::from_secs(30));
        // Poll it once so that it is waiting, then drop it.
        tokio::select! {
            biased;
            _ = waiting => unreachable!("nothing answers"),
            _ = std::future::ready(()) => {}
        }

        assert_eq!(calls.len(), 0);
    }

    #[tokio::test]
    async fn a_response_reaches_the_waiting_call_and_leaves_no_registration() {
        let calls = PendingCalls::new();
        let call = calls.register("cid-1");

        assert!(calls.complete("cid-1", AgentResponse::default_allow()));

        call.wait(Duration::from_secs(30))
            .await
            .expect("the response was delivered");
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn a_response_for_a_dropped_call_is_reported_as_unclaimed() {
        let calls = PendingCalls::new();
        drop(calls.register("cid-1"));

        assert!(!calls.complete("cid-1", AgentResponse::default_allow()));
    }

    #[tokio::test]
    async fn a_timed_out_call_removes_its_registration() {
        let calls = PendingCalls::new();

        let result = calls.register("cid-1").wait(Duration::ZERO).await;

        assert_eq!(result.unwrap_err(), WaitError::TimedOut);
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn dropping_an_older_call_keeps_the_registration_that_replaced_it() {
        let calls = PendingCalls::new();
        let older = calls.register("cid-1");
        let newer = calls.register("cid-1");

        drop(older);

        assert_eq!(calls.len(), 1);
        assert!(calls.complete("cid-1", AgentResponse::default_allow()));
        drop(newer);
    }

    #[tokio::test]
    async fn clear_ends_every_wait_and_dropping_afterwards_is_harmless() {
        let calls = PendingCalls::new();
        let call = calls.register("cid-1");

        calls.clear();

        let result = call.wait(Duration::from_secs(30)).await;
        assert_eq!(result.unwrap_err(), WaitError::Closed);
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn the_correlation_ids_are_those_of_the_calls_waiting() {
        let calls = PendingCalls::new();
        let first = calls.register("cid-1");
        let _second = calls.register("cid-2");
        drop(first);

        assert_eq!(calls.correlation_ids(), vec!["cid-2".to_string()]);
    }

    #[test]
    fn in_flight_counts_until_dropped() {
        let counter = AtomicU64::new(0);

        let first = InFlight::enter(&counter);
        let second = InFlight::enter(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), 2);

        drop(first);
        drop(second);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }
}
