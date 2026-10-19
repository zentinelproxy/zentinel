//! `limits { max-total-connections, max-connections-per-client }`.
//!
//! Pingora's accept-time `ConnectionFilter` sees a connection open but is never
//! told when it closes, so it cannot keep a count (#527, #542). What does see
//! both ends is the app's `ServerApp::process_new`: Pingora calls it once per
//! accepted connection (after the TLS handshake), and the HTTP app runs every
//! request on that connection inside it -- the HTTP/1 keep-alive loop and the
//! whole HTTP/2 session both live there -- returning only when the connection
//! is done. [`ConnectionLimitedApp`] wraps the proxy app and holds a
//! [`ConnectionPermit`] across that call, so the slot is released exactly when
//! the connection ends, whichever way it ends.
//!
//! The client is the TCP peer. Behind a load balancer every connection comes
//! from the balancer, so a per-client limit there limits the balancer;
//! `trusted-proxies` cannot help, because no request (and so no
//! `X-Forwarded-For`) has been read when the connection is counted.

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use tracing::warn;

use zentinel_common::limits::{ConnectionLimiter, ConnectionPermit};

use crate::proxy::listener_addr::canonical_ip;

/// The two connection limits in force, read for each new connection so a
/// config reload applies to the next one. `None` is unlimited.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionLimits {
    pub max_total: Option<usize>,
    pub max_per_client: Option<usize>,
}

impl ConnectionLimits {
    pub fn from_limits(limits: &zentinel_common::limits::Limits) -> Self {
        Self {
            max_total: limits.max_total_connections,
            max_per_client: limits.max_connections_per_client,
        }
    }
}

type LimitsSource = Arc<dyn Fn() -> ConnectionLimits + Send + Sync>;

/// A [`ServerApp`] that counts the connections it serves and closes any that
/// would exceed the configured limits before the wrapped app sees them.
pub struct ConnectionLimitedApp<A> {
    inner: Arc<A>,
    limiter: Arc<ConnectionLimiter>,
    limits: LimitsSource,
}

impl<A> ConnectionLimitedApp<A> {
    pub fn new(
        inner: A,
        limiter: Arc<ConnectionLimiter>,
        limits: impl Fn() -> ConnectionLimits + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            limiter,
            limits: Arc::new(limits),
        }
    }

    /// Take a slot for a connection from `peer`, or log why there is none.
    fn admit(&self, peer: Option<IpAddr>) -> Option<ConnectionPermit> {
        let limits = (self.limits)();
        match self
            .limiter
            .try_acquire(peer, limits.max_total, limits.max_per_client)
        {
            Ok(permit) => Some(permit),
            Err(refusal) => {
                warn!(
                    client_ip = peer.map(|ip| ip.to_string()).unwrap_or_default(),
                    reason = %refusal,
                    "Connection refused: connection limit reached"
                );
                None
            }
        }
    }
}

/// The connection's peer IP, with IPv4-mapped IPv6 collapsed so a dual-stack
/// listener counts one client once. `None` for a Unix socket peer.
fn peer_ip(stream: &Stream) -> Option<IpAddr> {
    let digest = stream.get_socket_digest()?;
    let addr = digest.peer_addr()?.as_inet()?;
    Some(canonical_ip(addr.ip()))
}

#[async_trait]
impl<A> ServerApp for ConnectionLimitedApp<A>
where
    A: ServerApp + Send + Sync + 'static,
{
    async fn process_new(
        self: &Arc<Self>,
        stream: Stream,
        shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        // Dropping the stream closes the connection. Nothing has been read
        // from it, so there is no request to answer with a status code.
        let _permit = self.admit(peer_ip(&stream))?;
        self.inner.process_new(stream, shutdown).await
    }

    async fn cleanup(&self) {
        self.inner.cleanup().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingora_core::protocols::{GetSocketDigest, SocketDigest};
    use std::os::unix::io::AsRawFd;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, oneshot};

    /// Stands in for the HTTP app: reports each connection it was given and
    /// keeps it open until the test says the connection is done.
    struct HoldingApp {
        started: mpsc::UnboundedSender<oneshot::Sender<()>>,
    }

    #[async_trait]
    impl ServerApp for HoldingApp {
        async fn process_new(
            self: &Arc<Self>,
            _stream: Stream,
            _shutdown: &ShutdownWatch,
        ) -> Option<Stream> {
            let (done_tx, done_rx) = oneshot::channel();
            self.started.send(done_tx).unwrap();
            let _ = done_rx.await;
            None
        }
    }

    /// An accepted loopback connection, as Pingora hands it to the app.
    async fn accepted(listener: &TcpListener) -> (Stream, TcpStream) {
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let fd = server.as_raw_fd();
        let mut stream = pingora_core::protocols::l4::stream::Stream::from(server);
        stream.set_socket_digest(SocketDigest::from_raw_fd(fd));
        (Box::new(stream), client)
    }

    #[tokio::test]
    async fn a_connection_holds_its_slot_until_the_app_is_done_with_it() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let limiter = ConnectionLimiter::new();
        let app = Arc::new(ConnectionLimitedApp::new(
            HoldingApp {
                started: started_tx,
            },
            Arc::clone(&limiter),
            || ConnectionLimits {
                max_total: None,
                max_per_client: Some(2),
            },
        ));
        let (_tx, shutdown) = tokio::sync::watch::channel(false);

        let mut running = Vec::new();
        let mut clients = Vec::new();
        for _ in 0..2 {
            let (stream, client) = accepted(&listener).await;
            clients.push(client);
            let (app, shutdown) = (Arc::clone(&app), shutdown.clone());
            running.push(tokio::spawn(async move {
                app.process_new(stream, &shutdown).await
            }));
        }
        let first_done = started_rx.recv().await.unwrap();
        let second_done = started_rx.recv().await.unwrap();
        assert_eq!(limiter.total(), 2);

        // A third connection from the same address is closed unseen.
        let (stream, _client) = accepted(&listener).await;
        assert!(app.process_new(stream, &shutdown).await.is_none());
        assert!(started_rx.try_recv().is_err(), "the app saw the connection");
        assert_eq!(limiter.total(), 2);

        // The slot comes back when the connection ends, not before.
        first_done.send(()).unwrap();
        running.remove(0).await.unwrap();
        assert_eq!(limiter.total(), 1);

        let (stream, _client) = accepted(&listener).await;
        let (app2, shutdown2) = (Arc::clone(&app), shutdown.clone());
        let third = tokio::spawn(async move { app2.process_new(stream, &shutdown2).await });
        let third_done = started_rx.recv().await.unwrap();
        assert_eq!(limiter.total(), 2);

        second_done.send(()).unwrap();
        third_done.send(()).unwrap();
        running.remove(0).await.unwrap();
        third.await.unwrap();
        assert_eq!(limiter.total(), 0);
        assert_eq!(limiter.tracked_clients(), 0);
    }

    #[tokio::test]
    async fn an_app_task_that_is_dropped_still_releases_its_slot() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let limiter = ConnectionLimiter::new();
        let app = Arc::new(ConnectionLimitedApp::new(
            HoldingApp {
                started: started_tx,
            },
            Arc::clone(&limiter),
            || ConnectionLimits {
                max_total: Some(1),
                max_per_client: None,
            },
        ));
        let (_tx, shutdown) = tokio::sync::watch::channel(false);

        let (stream, _client) = accepted(&listener).await;
        let (app2, shutdown2) = (Arc::clone(&app), shutdown.clone());
        let task = tokio::spawn(async move { app2.process_new(stream, &shutdown2).await });
        let _done = started_rx.recv().await.unwrap();
        assert_eq!(limiter.total(), 1);

        // e.g. the runtime shutting down mid-connection.
        task.abort();
        let _ = task.await;
        assert_eq!(limiter.total(), 0);
    }
}
