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
//! from the balancer, and no request (so no `X-Forwarded-For`) has been read
//! when the connection is counted, so the real clients cannot be told apart.
//! A peer in the listener's `trusted-proxies` is therefore exempt from
//! `max-connections-per-client`: it carries many clients by definition, and
//! counting it as one would cap all of them together (an existing install
//! with the old starter's `max-connections-per-client 100` behind a balancer
//! would otherwise be limited to 100 connections in total on upgrade).
//! `max-total-connections` still counts it.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use pingora_core::apps::ServerApp;
use pingora_core::listeners::PreTlsProcess;
use pingora_core::protocols::l4::stream::Stream as L4Stream;
use pingora_core::protocols::{GetSocketDigest, SocketDigest, Stream};
use pingora_core::server::ShutdownWatch;
use tracing::warn;

use zentinel_common::ids::Scope;
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
    /// Set when the connection arrived on a listener bound to a namespace,
    /// or to one of its services.
    pub namespace: Option<NamespaceConnectionLimits>,
    /// Set when the connection arrived on a service's own listener. Its `id`
    /// is `ns:svc`.
    pub service: Option<NamespaceConnectionLimits>,
}

/// A namespace's (or service's) own connection limits. The namespace's
/// connections are the ones on listeners bound to it or to its services, since
/// those serve only its routes; they count against these and against the
/// global limits both, so the smallest of each is what binds. A connection on
/// a service's listener also counts against the service's limits.
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
            service: None,
        }
    }

    /// The limits for a connection from `peer`, accepted on local address
    /// `local`.
    pub fn for_connection(
        config: &Config,
        peer: Option<IpAddr>,
        local: Option<SocketAddr>,
    ) -> Self {
        let mut limits = Self::from_limits(&config.limits);
        let listener = local.and_then(|local| listener_for_addr(&config.listeners, local));
        let scope = listener.map(|l| l.scope()).unwrap_or_default();
        let blocks = config.scope_limits(&scope);
        let scoped = |s: &Scope, id: String| {
            let block = blocks.iter().find(|(b, _)| b == s).map(|(_, l)| *l);
            NamespaceConnectionLimits {
                id,
                max_total: block.and_then(|l| l.max_total_connections),
                max_per_client: block.and_then(|l| l.max_connections_per_client),
            }
        };
        if let Some(ns) = scope.namespace() {
            limits.namespace = Some(scoped(&Scope::Namespace(ns.to_string()), ns.to_string()));
        }
        if let Some(svc) = scope.service() {
            let id = format!("{}:{svc}", scope.namespace().unwrap_or_default());
            limits.service = Some(scoped(&scope, id));
        }
        let trusted_peer = peer.is_some_and(|ip| {
            listener.is_some_and(|l| l.trusted_proxies.iter().any(|cidr| cidr.contains(ip)))
        });
        if trusted_peer {
            limits.max_per_client = None;
            for scoped in [limits.namespace.as_mut(), limits.service.as_mut()]
                .into_iter()
                .flatten()
            {
                scoped.max_per_client = None;
            }
        }
        limits
    }
}

/// One line per listener where a per-client connection limit applies but
/// no `trusted-proxies` is set, for the startup log.
///
/// Informational, not a lint finding: the limit is applied as written, and
/// is right for clients that connect directly. Behind a load balancer it is
/// not, and nothing at runtime can tell the two apart.
pub fn per_client_limit_notes(config: &Config) -> Vec<String> {
    config
        .listeners
        .iter()
        .filter(|listener| listener.trusted_proxies.is_empty())
        .filter_map(|listener| {
            let limit = config
                .scope_limits(&listener.scope())
                .into_iter()
                .filter_map(|(_, l)| l.max_connections_per_client)
                .chain(config.limits.max_connections_per_client)
                .min()?;
            Some(format!(
                "Listener '{}' limits each client to {limit} connections, counted by TCP \
                 peer address. Behind a load balancer or NAT the balancer counts as one \
                 client; list it in the listener's trusted-proxies to exempt it from \
                 max-connections-per-client.",
                listener.id
            ))
        })
        .collect()
}

/// TLS connections that have been accepted but have not finished their
/// handshake.
///
/// [`ConnectionLimitedApp`] counts a connection only once its handshake is
/// done, because that is when Pingora hands it to `process_new`. For
/// `max-connections-per-client` that is the right moment, and this does not
/// change it. A graceful shutdown needs the earlier moment too: a handshake
/// that straddles the signal turns into a request, and ending the process
/// resets it. So the tracker is only read by the drain, and takes no part in
/// any limit.
///
/// A connection is entered by Pingora's pre-TLS hook, which runs on the raw
/// TCP stream before the handshake (plain HTTP listeners have no handshake and
/// do not call it), and removed when the handshaken connection reaches
/// `process_new`. A handshake that fails is not reported to anyone, so each
/// entry holds only a weak reference to the connection's socket digest: when
/// Pingora drops the failed connection the entry dies with it.
#[derive(Default)]
pub struct HandshakeTracker {
    pending: parking_lot::Mutex<Vec<(Weak<SocketDigest>, Instant)>>,
}

impl HandshakeTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Handshakes that began less than `within` ago and have neither finished
    /// nor failed.
    pub fn in_progress(&self, within: Duration) -> usize {
        let mut pending = self.pending.lock();
        pending.retain(|(digest, _)| digest.strong_count() > 0);
        pending
            .iter()
            .filter(|(_, began)| began.elapsed() < within)
            .count()
    }

    fn began(&self, digest: &Arc<SocketDigest>) {
        let mut pending = self.pending.lock();
        pending.retain(|(digest, _)| digest.strong_count() > 0);
        pending.push((Arc::downgrade(digest), Instant::now()));
    }

    fn finished(&self, digest: &Arc<SocketDigest>) {
        let target = Arc::downgrade(digest);
        self.pending
            .lock()
            .retain(|(entry, _)| !entry.ptr_eq(&target) && entry.strong_count() > 0);
    }
}

#[async_trait]
impl PreTlsProcess for HandshakeTracker {
    async fn process(&self, stream: &mut L4Stream) -> pingora_core::Result<()> {
        if let Some(digest) = stream.get_socket_digest() {
            self.began(&digest);
        }
        Ok(())
    }
}

type LimitsSource =
    Arc<dyn Fn(Option<IpAddr>, Option<SocketAddr>) -> ConnectionLimits + Send + Sync>;

/// A [`ServerApp`] that counts the connections it serves and closes any that
/// would exceed the configured limits before the wrapped app sees them.
pub struct ConnectionLimitedApp<A> {
    inner: Arc<A>,
    limiter: Arc<ConnectionLimiter>,
    /// One counter per namespace (keyed by its id) and per service (keyed by
    /// `ns:svc`) that has had a connection. Like the global one it counts
    /// whether or not a limit is set, so a reload that adds a limit sees the
    /// connections already open.
    namespaces: parking_lot::Mutex<HashMap<String, Arc<ConnectionLimiter>>>,
    limits: LimitsSource,
    handshakes: Option<Arc<HandshakeTracker>>,
}

/// The slots one connection holds: the global one, and its namespace's and
/// service's.
type Permits = (ConnectionPermit, Vec<ConnectionPermit>);

impl<A> ConnectionLimitedApp<A> {
    /// `limits` is given the connection's peer IP and local address and
    /// returns the limits that apply to it.
    pub fn new(
        inner: A,
        limiter: Arc<ConnectionLimiter>,
        limits: impl Fn(Option<IpAddr>, Option<SocketAddr>) -> ConnectionLimits + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(inner),
            limiter,
            namespaces: parking_lot::Mutex::new(HashMap::new()),
            limits: Arc::new(limits),
            handshakes: None,
        }
    }

    /// Tell `tracker` when a connection's handshake is over, so it stops
    /// being counted as one in progress.
    pub fn with_handshakes(mut self, tracker: Arc<HandshakeTracker>) -> Self {
        self.handshakes = Some(tracker);
        self
    }

    /// Connections open in `namespace` (on listeners bound to it), or in a
    /// service when given `ns:svc`.
    pub fn namespace_connections(&self, namespace: &str) -> usize {
        self.namespaces
            .lock()
            .get(namespace)
            .map_or(0, |limiter| limiter.total())
    }

    /// Take the slots for a connection from `peer`, or log why there are none.
    fn admit(&self, peer: Option<IpAddr>, local: Option<SocketAddr>) -> Option<Permits> {
        let limits = (self.limits)(peer, local);
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
        let mut scoped_permits = Vec::new();
        for scope in [limits.namespace, limits.service].into_iter().flatten() {
            let limiter = Arc::clone(self.namespaces.lock().entry(scope.id.clone()).or_default());
            match limiter.try_acquire(peer, scope.max_total, scope.max_per_client) {
                Ok(permit) => scoped_permits.push(permit),
                Err(refusal) => {
                    // The slots already taken are given back on drop.
                    refused(&scope.id, refusal);
                    return None;
                }
            }
        }
        Some((global, scoped_permits))
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
        let permits = self.admit(peer_ip(&stream), local_addr(&stream));
        // The connection now holds its slot (or has been refused), so it is
        // no longer in between; at no point is it in neither count.
        if let (Some(tracker), Some(digest)) = (&self.handshakes, stream.get_socket_digest()) {
            tracker.finished(&digest);
        }
        let _permits = permits?;
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
            |_, _| ConnectionLimits {
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
            |_, _| ConnectionLimits {
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

        let tenant =
            ConnectionLimits::for_connection(&config, None, "127.0.0.1:19791".parse().ok());
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
        let public = ConnectionLimits::for_connection(&config, None, "10.1.2.3:19790".parse().ok());
        assert_eq!(public.max_total, Some(100));
        assert_eq!(public.namespace, None);
    }

    /// #548: a connection on a service's own listener counts against the
    /// service's limits and its namespace's.
    #[test]
    fn a_connection_on_a_service_listener_gets_the_service_and_namespace_limits() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners { listener "public" { address "0.0.0.0:19790"; } }
            namespace "tenant" {
                limits { max-total-connections 20 }
                service "pay" {
                    limits { max-connections-per-client 2 }
                    listener {
                        id "pay"
                        address "127.0.0.1:19794"
                    }
                }
            }
            "#,
        )
        .unwrap()
        .lower_scopes();

        let pay = ConnectionLimits::for_connection(&config, None, "127.0.0.1:19794".parse().ok());
        assert_eq!(
            pay.namespace,
            Some(NamespaceConnectionLimits {
                id: "tenant".to_string(),
                max_total: Some(20),
                max_per_client: None,
            })
        );
        assert_eq!(
            pay.service,
            Some(NamespaceConnectionLimits {
                id: "tenant:pay".to_string(),
                max_total: None,
                max_per_client: Some(2),
            })
        );
        let public = ConnectionLimits::for_connection(&config, None, "10.0.0.1:19790".parse().ok());
        assert_eq!((public.namespace, public.service), (None, None));
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
            |_, _| ConnectionLimits {
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

    /// A balancer in `trusted-proxies` carries many clients, so
    /// `max-connections-per-client` does not count it as one;
    /// `max-total-connections` still does.
    #[test]
    fn a_trusted_proxy_peer_is_exempt_from_the_per_client_limit_only() {
        let config = Config::from_kdl(
            r#"
            schema-version "1.0"
            system { worker-threads 1 }
            listeners {
                listener "lb" {
                    address "127.0.0.1:19792"
                    trusted-proxies "10.0.0.0/8"
                    namespace "tenant"
                }
                listener "direct" { address "127.0.0.1:19793"; }
            }
            limits {
                max-connections-per-client 2
                max-total-connections 50
            }
            namespace "tenant" {
                limits { max-connections-per-client 1 }
            }
            "#,
        )
        .unwrap();
        let balancer = "10.1.2.3".parse().ok();
        let lb = "127.0.0.1:19792".parse().ok();

        let trusted = ConnectionLimits::for_connection(&config, balancer, lb);
        assert_eq!(trusted.max_per_client, None);
        assert_eq!(trusted.max_total, Some(50));
        assert_eq!(trusted.namespace.unwrap().max_per_client, None);

        let untrusted = ConnectionLimits::for_connection(&config, "192.0.2.9".parse().ok(), lb);
        assert_eq!(untrusted.max_per_client, Some(2));
        assert_eq!(untrusted.namespace.unwrap().max_per_client, Some(1));

        // Trust is per listener.
        let direct =
            ConnectionLimits::for_connection(&config, balancer, "127.0.0.1:19793".parse().ok());
        assert_eq!(direct.max_per_client, Some(2));

        let notes = per_client_limit_notes(&config);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("'direct'") && notes[0].contains("trusted-proxies"));
    }
}
