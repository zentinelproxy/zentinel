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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::protocols::Stream;
use pingora_core::server::ShutdownWatch;
use tracing::warn;

use zentinel_common::limits::{ConnectionLimiter, ConnectionPermit};
use zentinel_config::Config;

use crate::proxy::listener_addr::{canonical_ip, listener_for_addr};

/// The connection limits in force for one new connection, read from the
/// current config for each connection so a reload applies to the next one.
/// `None` is unlimited.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionLimits {
    pub max_total: Option<usize>,
    pub max_per_client: Option<usize>,
    /// Set when the connection arrived on a listener bound to a namespace.
    pub namespace: Option<NamespaceConnectionLimits>,
}

/// A namespace's own connection limits. The namespace's connections are the
/// ones on listeners bound to it, since those serve only its routes; they
/// count against these and against the global limits both, so the smaller
/// of each pair is what binds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceConnectionLimits {
    pub id: String,
    pub max_total: Option<usize>,
    pub max_per_client: Option<usize>,
}

impl ConnectionLimits {
    /// The global limits alone.
    pub fn from_limits(limits: &zentinel_common::limits::Limits) -> Self {
        Self {
            max_total: limits.max_total_connections,
            max_per_client: limits.max_connections_per_client,
            namespace: None,
        }
    }

    /// The limits for a connection accepted on local address `local`.
    pub fn for_connection(config: &Config, local: Option<SocketAddr>) -> Self {
        let mut limits = Self::from_limits(&config.limits);
        limits.namespace = local
            .and_then(|local| listener_for_addr(&config.listeners, local))
            .and_then(|listener| listener.namespace.as_ref())
            .map(|id| {
                let scoped = config
                    .namespaces
                    .iter()
                    .find(|ns| &ns.id == id)
                    .and_then(|ns| ns.limits.as_ref());
                NamespaceConnectionLimits {
                    id: id.clone(),
                    max_total: scoped.and_then(|l| l.max_total_connections),
                    max_per_client: scoped.and_then(|l| l.max_connections_per_client),
                }
            });
        limits
    }
}

type LimitsSource = Arc<dyn Fn(Option<SocketAddr>) -> ConnectionLimits + Send + Sync>;

/// A [`ServerApp`] that counts the connections it serves and closes any that
/// would exceed the configured limits before the wrapped app sees them.
pub struct ConnectionLimitedApp<A> {
    inner: Arc<A>,
    limiter: Arc<ConnectionLimiter>,
    /// One counter per namespace that has had a connection. Like the global
    /// one it counts whether or not a limit is set, so a reload that adds a
    /// limit sees the connections already open.
    namespaces: parking_lot::Mutex<HashMap<String, Arc<ConnectionLimiter>>>,
    limits: LimitsSource,
}

/// The slots one connection holds: the global one, and its namespace's.
type Permits = (ConnectionPermit, Option<ConnectionPermit>);

impl<A> ConnectionLimitedApp<A> {
    /// `limits` is given the connection's local address and returns the
    /// limits that apply to it.
    pub fn new(
        inner: A,
        limiter: Arc<ConnectionLimiter>,
        limits: impl Fn(Option<SocketAddr>) -> ConnectionLimits + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            limiter,
            namespaces: parking_lot::Mutex::new(HashMap::new()),
            limits: Arc::new(limits),
        }
    }

    /// Connections open in `namespace` (on listeners bound to it).
    pub fn namespace_connections(&self, namespace: &str) -> usize {
        self.namespaces
            .lock()
            .get(namespace)
            .map_or(0, |limiter| limiter.total())
    }

    /// Take the slots for a connection from `peer`, or log why there are none.
    fn admit(&self, peer: Option<IpAddr>, local: Option<SocketAddr>) -> Option<Permits> {
        let limits = (self.limits)(local);
        let refused = |scope: &str, refusal| {
            warn!(
                client_ip = peer.map(|ip| ip.to_string()).unwrap_or_default(),
                scope = scope,
                reason = %refusal,
                "Connection refused: connection limit reached"
            );
        };
        let global = match self
            .limiter
            .try_acquire(peer, limits.max_total, limits.max_per_client)
        {
            Ok(permit) => permit,
            Err(refusal) => {
                refused("global", refusal);
                return None;
            }
        };
        let Some(ns) = limits.namespace else {
            return Some((global, None));
        };
        let limiter = Arc::clone(self.namespaces.lock().entry(ns.id.clone()).or_default());
        match limiter.try_acquire(peer, ns.max_total, ns.max_per_client) {
            Ok(scoped) => Some((global, Some(scoped))),
            Err(refusal) => {
                refused(&ns.id, refusal);
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

/// The local address the connection was accepted on, which identifies its
/// listener.
fn local_addr(stream: &Stream) -> Option<SocketAddr> {
    let digest = stream.get_socket_digest()?;
    digest.local_addr()?.as_inet().copied()
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
        let _permits = self.admit(peer_ip(&stream), local_addr(&stream))?;
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
            |_| ConnectionLimits {
                max_per_client: Some(2),
                ..Default::default()
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
            |_| ConnectionLimits {
                max_total: Some(1),
                ..Default::default()
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

    /// #542: a connection on a namespace-bound listener is the namespace's,
    /// and its limits come from the namespace's `limits` block as well as
    /// the global one.
    #[test]
    fn a_connection_on_a_namespace_listener_gets_the_namespace_limits() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners {
                listener "public" { address "0.0.0.0:19790"; }
                listener "tenant" { address "127.0.0.1:19791"; namespace "tenant"; }
            }
            limits { max-total-connections 100 }
            namespace "tenant" {
                limits { max-connections-per-client 3 }
            }
            "#,
        )
        .unwrap();

        let tenant = ConnectionLimits::for_connection(&config, "127.0.0.1:19791".parse().ok());
        assert_eq!(tenant.max_total, Some(100));
        assert_eq!(tenant.max_per_client, None);
        assert_eq!(
            tenant.namespace,
            Some(NamespaceConnectionLimits {
                id: "tenant".to_string(),
                max_total: None,
                max_per_client: Some(3),
            })
        );

        // A wildcard listener resolves from the concrete local address.
        let public = ConnectionLimits::for_connection(&config, "10.1.2.3:19790".parse().ok());
        assert_eq!(public.max_total, Some(100));
        assert_eq!(public.namespace, None);
    }

    #[tokio::test]
    async fn the_namespace_limit_refuses_and_releases_both_counts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (started_tx, mut started_rx) = mpsc::unbounded_channel();
        let limiter = ConnectionLimiter::new();
        let app = Arc::new(ConnectionLimitedApp::new(
            HoldingApp {
                started: started_tx,
            },
            Arc::clone(&limiter),
            |_| ConnectionLimits {
                namespace: Some(NamespaceConnectionLimits {
                    id: "ns".to_string(),
                    max_total: Some(1),
                    max_per_client: None,
                }),
                ..Default::default()
            },
        ));
        let (_tx, shutdown) = tokio::sync::watch::channel(false);

        let (stream, _c1) = accepted(&listener).await;
        let (app2, shutdown2) = (Arc::clone(&app), shutdown.clone());
        let first = tokio::spawn(async move { app2.process_new(stream, &shutdown2).await });
        let done = started_rx.recv().await.unwrap();
        assert_eq!((limiter.total(), app.namespace_connections("ns")), (1, 1));

        let (stream, _c2) = accepted(&listener).await;
        assert!(app.process_new(stream, &shutdown).await.is_none());
        // The global slot taken before the namespace refused is given back.
        assert_eq!((limiter.total(), app.namespace_connections("ns")), (1, 1));

        done.send(()).unwrap();
        first.await.unwrap();
        assert_eq!((limiter.total(), app.namespace_connections("ns")), (0, 0));
    }
}
