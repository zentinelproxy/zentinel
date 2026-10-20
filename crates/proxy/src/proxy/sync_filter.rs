//! Waiting for an agent call from one of Pingora's synchronous filters.
//!
//! `response_body_filter` (and every other body filter Pingora offers on the
//! response side) is a plain `fn`, but agent calls are async. Those filters
//! used to call `tokio::task::block_in_place` + `Handle::block_on`
//! unconditionally, which panics on a current-thread runtime and outside any
//! runtime -- the failure #551 removed from consistent hashing.
//!
//! [`wait_for`] only blocks where blocking is sound: on a multi-thread
//! runtime, where `block_in_place` hands the worker's other tasks to another
//! thread first. Anywhere else it does not run the call and says so, and the
//! caller treats that like a failed agent call (the response passes through,
//! as it does when an agent errors or times out). Blocking a current-thread
//! runtime's only thread instead would deadlock: the agent connection's I/O
//! is driven by that same thread.

use std::future::Future;

use tokio::runtime::{Handle, RuntimeFlavor};

/// The current runtime cannot block on an agent call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CannotBlock;

impl std::fmt::Display for CannotBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("agent call skipped: a synchronous filter can only wait for it on a multi-thread tokio runtime")
    }
}

/// Run `fut` to completion from synchronous code inside the proxy, if the
/// current runtime allows it. See the module documentation.
pub(crate) fn wait_for<F: Future>(fut: F) -> Result<F::Output, CannotBlock> {
    let handle = Handle::try_current().map_err(|_| CannotBlock)?;
    match handle.runtime_flavor() {
        RuntimeFlavor::MultiThread => Ok(tokio::task::block_in_place(|| handle.block_on(fut))),
        _ => Err(CannotBlock),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn waits_on_a_multi_thread_runtime() {
        let got = wait_for(async {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            7
        });
        assert_eq!(got, Ok(7));
    }

    /// `block_in_place` panics here; this used to take the worker down.
    #[tokio::test(flavor = "current_thread")]
    async fn does_not_panic_on_a_current_thread_runtime() {
        assert_eq!(wait_for(async { 7 }), Err(CannotBlock));
    }

    #[test]
    fn does_not_panic_outside_a_runtime() {
        assert_eq!(wait_for(async { 7 }), Err(CannotBlock));
    }
}
