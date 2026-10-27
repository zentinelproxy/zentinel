//! Graceful shutdown on SIGTERM and SIGINT.
//!
//! Both signals stop the listeners from accepting, let the connections
//! already open finish, and end the process once none are left or
//! `graceful-shutdown-timeout-secs` has passed, whichever comes first.
//!
//! Pingora does the first step itself: on SIGTERM it tells the listeners to
//! stop accepting and the open connections to close after their current
//! request. It then sleeps for `grace_period_seconds` whether or not anything
//! is still open, and stops its runtimes without waiting for the work in
//! them. [`drain`] is the part that watches the connections, so the process
//! can end as soon as they are gone, and not before. It ends the process
//! itself, within the timeout, so Pingora's own sleep (300 s by default, which
//! `-u` upgrades still use for the old process) never gets to run out. A
//! timeout above 300 s would let it, and cut the drain short, so
//! [`pingora_grace_period_seconds`] stretches the sleep then. It does so from
//! 291 s, to keep the watchdog ahead of it with a margin.
//!
//! # Where a shutdown request comes from
//!
//! [`ShutdownRequest`] is the one place that records "a shutdown was
//! requested". The signal thread in `main.rs` (signal-hook, installed before
//! the configuration is read, so a signal during startup is not lost) sets it.
//! [`ZentinelShutdownSignals`] waits on it instead of registering handlers of
//! its own, so Pingora is told to stop whenever the signal arrived, including
//! in the gap before Pingora's main loop starts. A second request while a
//! drain is running ends the process at once, with no grace window: a unit
//! that sends SIGTERM twice (`ExecStop=kill -TERM` plus `KillSignal`) cuts its
//! own drain short.
//!
//! # The other signals
//!
//! SIGTERM and SIGINT are the only ones that shut the proxy down. They share
//! the signal thread with SIGHUP (reload the configuration), SIGUSR1 (reopen
//! the log files) and SIGUSR2 (ignored; registered only so that its default
//! disposition, terminating the process, does not apply). While a drain runs
//! they are not acted on: the task that reloads and reopens is the one waiting
//! for the drain, so they neither cut it short nor extend it.
//!
//! # Not covered yet
//!
//! The SIGQUIT hand-over (#126: Pingora's grace period and
//! `graceful-shutdown-timeout-secs` are still separate) does not go through
//! [`drain`]. Daemon mode does: the process forks before the signal thread and
//! the runtime exist (#573), so a daemon drains like a foreground proxy.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_core::server::{ExecutionPhase, ShutdownSignal, ShutdownSignalWatch};
use tokio::sync::{broadcast, watch};
use tokio::time::sleep;
use zentinel_common::limits::ConnectionLimiter;

use crate::connection_limit::HandshakeTracker;

/// How long after `graceful-shutdown-timeout-secs` the watchdog in `main.rs`
/// forces the process out if the drain itself has hung.
pub const FORCE_EXIT_MARGIN_SECS: u64 = 5;

/// How long Pingora sleeps after a graceful shutdown starts when
/// `grace_period_seconds` is not set (`EXIT_TIMEOUT` in
/// `zentinel-pingora-core`'s `server/mod.rs`).
const PINGORA_DEFAULT_GRACE_SECS: u64 = 300;

/// The `grace_period_seconds` to give Pingora for a drain of
/// `graceful_shutdown_timeout_secs`, or `None` to leave its default.
///
/// Pingora's `run()` sleeps for this long and then returns, which ends the
/// process with status 0. The drain ends the process at the timeout, and the
/// watchdog [`FORCE_EXIT_MARGIN_SECS`] after that, so the sleep has to outlast
/// both: with the default 300 s it does for any timeout up to 290 s. Above
/// 300 s `run()` would return first and cut the drain short; from 291 s to
/// 300 s the drain still ends first, but the watchdog would not be ahead of
/// `run()`. One margin more than the watchdog's keeps the watchdog's status
/// (1) from racing `run()`'s.
pub fn pingora_grace_period_seconds(graceful_shutdown_timeout_secs: u64) -> Option<u64> {
    let needed = graceful_shutdown_timeout_secs.saturating_add(2 * FORCE_EXIT_MARGIN_SECS);
    (needed > PINGORA_DEFAULT_GRACE_SECS).then_some(needed)
}

/// Give Pingora the shutdown settings for `graceful_shutdown_timeout_secs`.
pub fn configure_pingora_shutdown(
    conf: &mut pingora_core::server::configuration::ServerConf,
    graceful_shutdown_timeout_secs: u64,
) {
    conf.graceful_shutdown_timeout_seconds = Some(graceful_shutdown_timeout_secs);
    conf.grace_period_seconds = pingora_grace_period_seconds(graceful_shutdown_timeout_secs);
}

/// How often the open connections are counted while draining.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// How long a TLS handshake that has not finished is still waited for. A
/// handshake takes a few round trips; one that has taken longer than this is
/// not going to produce a request worth holding the shutdown for.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(5);

/// How a drain ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Drained {
    /// The listeners stopped and no connection was left open, after this
    /// long. Also reported when the timeout ran out at the moment the last
    /// connection closed.
    Complete(Duration),
    /// The timeout passed with this many connections (at least one) still
    /// open, counting TLS handshakes in progress.
    TimedOut { open: usize },
    /// The timeout passed before Pingora reported that the listeners had
    /// stopped accepting, so an empty count proves nothing. `open` is what was
    /// counted at that point.
    ListenersNotStopped { open: usize },
}

/// What a shutdown signal means, given the ones before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requested {
    /// The first request: start draining.
    Drain,
    /// A later request while draining: end the process now.
    Force,
}

/// The single record of "a shutdown was requested".
///
/// Set from the signal thread, read by [`ZentinelShutdownSignals`] (for
/// Pingora) and by `main` (to skip the drain when nothing is serving yet).
pub struct ShutdownRequest {
    requested: watch::Sender<bool>,
    first: AtomicBool,
    serving: AtomicBool,
    open: OnceLock<Box<dyn Fn() -> (usize, usize) + Send + Sync>>,
}

impl ShutdownRequest {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            requested: watch::channel(false).0,
            first: AtomicBool::new(false),
            serving: AtomicBool::new(false),
            open: OnceLock::new(),
        })
    }

    /// Record a shutdown signal. The first drains, any later one forces.
    pub fn request(&self) -> Requested {
        if self.first.swap(true, Ordering::SeqCst) {
            Requested::Force
        } else {
            self.requested.send_replace(true);
            Requested::Drain
        }
    }

    pub fn is_requested(&self) -> bool {
        *self.requested.borrow()
    }

    /// Say that the listeners are about to be started, so a shutdown request
    /// from here on goes through Pingora and [`drain`]. Before this nothing
    /// accepts connections and there is nothing to drain.
    pub fn mark_serving(&self) {
        self.serving.store(true, Ordering::SeqCst);
    }

    pub fn is_serving(&self) -> bool {
        self.serving.load(Ordering::SeqCst)
    }

    /// Where to read the open connection count from, for the log line of a
    /// forced exit: `(connections, handshakes in progress)`.
    pub fn count_open_with(&self, count: impl Fn() -> (usize, usize) + Send + Sync + 'static) {
        let _ = self.open.set(Box::new(count));
    }

    /// `(connections, handshakes in progress)`, zero before the proxy is built.
    pub fn open(&self) -> (usize, usize) {
        self.open.get().map_or((0, 0), |count| count())
    }

    /// Resolves once a shutdown has been requested, at any time before or
    /// after this is called.
    pub async fn wait(&self) {
        let _ = self
            .requested
            .subscribe()
            .wait_for(|requested| *requested)
            .await;
    }
}

/// SIGTERM and SIGINT both mean a graceful shutdown. Pingora's own watcher
/// treats SIGINT as a fast shutdown that stops without waiting for anything,
/// which is not what `server.md` promises for it. SIGQUIT keeps its Pingora
/// meaning: hand the listening sockets to a new process (`-u`) and then
/// shut down gracefully.
///
/// SIGTERM and SIGINT are not registered here: the signal thread took them
/// at startup and reports them through the [`ShutdownRequest`], which this
/// waits on. A request made before Pingora's main loop started is seen at once.
pub struct ZentinelShutdownSignals {
    pub request: Arc<ShutdownRequest>,
}

#[async_trait]
impl ShutdownSignalWatch for ZentinelShutdownSignals {
    async fn recv(&self) -> ShutdownSignal {
        use tokio::signal::unix::{signal, SignalKind};

        let mut quit = signal(SignalKind::quit()).expect("register SIGQUIT");

        tokio::select! {
            _ = quit.recv() => ShutdownSignal::GracefulUpgrade,
            _ = self.request.wait() => ShutdownSignal::GracefulTerminate,
        }
    }
}

/// Wait until the listeners have stopped accepting and no connection is
/// open, or until `timeout` has passed.
///
/// `phases` is the server's execution phase channel, subscribed before the
/// server was started so that a phase announced before this call is still
/// queued. Pingora reports `GracefulTerminate` after it has told
/// the listeners to stop; counting before that could find the proxy empty a
/// moment before one more connection is accepted.
///
/// The count has to be zero twice in a row, so that a connection accepted
/// just before the listener closed, and not yet counted, is not missed.
pub async fn drain(
    connections: &ConnectionLimiter,
    handshakes: &HandshakeTracker,
    phases: &mut broadcast::Receiver<ExecutionPhase>,
    timeout: Duration,
) -> Drained {
    let start = Instant::now();
    let deadline = start + timeout;

    let stopped_accepting = async {
        loop {
            match phases.recv().await {
                Ok(
                    ExecutionPhase::GracefulTerminate
                    | ExecutionPhase::ShutdownStarted
                    | ExecutionPhase::ShutdownGracePeriod,
                ) => break,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                // The server is gone, so nothing is accepting.
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    let stopped = tokio::time::timeout(timeout, stopped_accepting)
        .await
        .is_ok();

    let mut empty_polls = 0;
    loop {
        // A handshake in progress will become a connection, so it is waited
        // for; a connection holds its slot from the end of the handshake.
        let open = connections.total() + handshakes.in_progress(HANDSHAKE_WAIT);
        if open == 0 {
            empty_polls += 1;
            if empty_polls == 2 {
                return Drained::Complete(start.elapsed());
            }
        } else {
            empty_polls = 0;
        }
        let now = Instant::now();
        if now >= deadline {
            return match (open, stopped) {
                (_, false) => Drained::ListenersNotStopped { open },
                (0, true) => Drained::Complete(start.elapsed()),
                (open, true) => Drained::TimedOut { open },
            };
        }
        sleep(POLL_INTERVAL.min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pingora_keeps_its_default_sleep_for_timeouts_it_already_outlasts() {
        for timeout in [1, 30, 60, 290] {
            assert_eq!(pingora_grace_period_seconds(timeout), None, "{timeout}");
        }
    }

    #[test]
    fn pingora_sleeps_past_the_watchdog_for_longer_timeouts() {
        for timeout in [291, 300, 301, 600, 86_400] {
            let grace = pingora_grace_period_seconds(timeout).unwrap();
            assert!(
                grace > timeout + FORCE_EXIT_MARGIN_SECS && grace > PINGORA_DEFAULT_GRACE_SECS,
                "{timeout}: {grace}"
            );
        }
        assert_eq!(pingora_grace_period_seconds(600), Some(610));
        assert_eq!(pingora_grace_period_seconds(u64::MAX), Some(u64::MAX));
    }

    #[test]
    fn the_server_conf_is_built_from_the_configured_timeout() {
        use pingora_core::server::configuration::ServerConf;
        let built = |timeout| {
            let mut conf = ServerConf::default();
            configure_pingora_shutdown(&mut conf, timeout);
            (
                conf.graceful_shutdown_timeout_seconds,
                conf.grace_period_seconds,
            )
        };
        // The default leaves Pingora's own sleep alone.
        assert_eq!(built(30), (Some(30), None));
        assert_eq!(built(600), (Some(600), Some(610)));
    }

    fn announced(phase: ExecutionPhase) -> broadcast::Receiver<ExecutionPhase> {
        let (tx, rx) = broadcast::channel(8);
        tx.send(phase).unwrap();
        // Keep the sender alive for the test by leaking it into the receiver's
        // lifetime: a dropped sender reads as a closed channel, which also
        // ends the wait, and that is not what these tests are about.
        std::mem::forget(tx);
        rx
    }

    #[tokio::test]
    async fn an_idle_proxy_is_drained_at_once() {
        let connections = ConnectionLimiter::new();
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_secs(30),
        )
        .await;
        match outcome {
            Drained::Complete(took) => assert!(took < Duration::from_secs(1), "{took:?}"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn waits_for_an_open_connection_to_close() {
        let connections = ConnectionLimiter::new();
        let permit = connections.try_acquire(None, None, None).unwrap();
        tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            drop(permit);
        });
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_secs(30),
        )
        .await;
        match outcome {
            Drained::Complete(took) => assert!(
                took >= Duration::from_millis(300) && took < Duration::from_secs(5),
                "{took:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn gives_up_at_the_timeout_with_connections_still_open() {
        let connections = ConnectionLimiter::new();
        let _held = connections.try_acquire(None, None, None).unwrap();
        let start = Instant::now();
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::from_millis(300),
        )
        .await;
        assert_eq!(outcome, Drained::TimedOut { open: 1 });
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn does_not_count_before_the_listeners_have_stopped() {
        let connections = ConnectionLimiter::new();
        let (tx, mut rx) = broadcast::channel(8);
        let announce = tokio::spawn(async move {
            sleep(Duration::from_millis(300)).await;
            tx.send(ExecutionPhase::GracefulTerminate).unwrap();
            tx
        });
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut rx,
            Duration::from_secs(30),
        )
        .await;
        match outcome {
            Drained::Complete(took) => assert!(took >= Duration::from_millis(300), "{took:?}"),
            other => panic!("{other:?}"),
        }
        let _ = announce.await;
    }

    #[tokio::test]
    async fn an_expired_timeout_with_nothing_open_is_complete_not_timed_out() {
        let connections = ConnectionLimiter::new();
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut announced(ExecutionPhase::GracefulTerminate),
            Duration::ZERO,
        )
        .await;
        assert!(matches!(outcome, Drained::Complete(_)), "{outcome:?}");
    }

    #[tokio::test]
    async fn a_timeout_before_the_listeners_stopped_says_so() {
        let connections = ConnectionLimiter::new();
        // No phase is ever announced; the sender stays alive.
        let (_tx, mut rx) = broadcast::channel(8);
        let outcome = drain(
            &connections,
            &HandshakeTracker::default(),
            &mut rx,
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(outcome, Drained::ListenersNotStopped { open: 0 });
    }

    #[test]
    fn the_first_request_drains_and_any_later_one_forces() {
        let request = ShutdownRequest::new();
        assert!(!request.is_requested());
        assert_eq!(request.request(), Requested::Drain);
        assert!(request.is_requested());
        assert_eq!(request.request(), Requested::Force);
        assert_eq!(request.request(), Requested::Force);
    }

    #[tokio::test]
    async fn pingora_is_told_even_if_the_request_came_first() {
        let request = ShutdownRequest::new();
        request.request();
        let signals = ZentinelShutdownSignals {
            request: request.clone(),
        };
        let got = tokio::time::timeout(Duration::from_secs(1), signals.recv())
            .await
            .expect("a request made before recv() is seen at once");
        assert!(matches!(got, ShutdownSignal::GracefulTerminate));
    }

    #[tokio::test]
    async fn pingora_is_told_when_the_request_comes_later() {
        let request = ShutdownRequest::new();
        let signals = ZentinelShutdownSignals {
            request: request.clone(),
        };
        let waiting = tokio::spawn(async move { signals.recv().await });
        sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        request.request();
        let got = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(got, ShutdownSignal::GracefulTerminate));
    }
}
