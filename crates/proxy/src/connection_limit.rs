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
use pingora_core::protocols::{GetSocketDigest, Peek, SocketDigest, Stream};
use pingora_core::server::ShutdownWatch;
use tracing::{debug, warn};

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
/// Pingora drops the failed connection the entry no longer counts.
///
/// Entries are keyed by the address of the digest, so `began` and `finished`
/// are O(1) on the accept path. The address cannot be reused while an entry
/// exists: a `Weak` keeps the allocation reserved even after the last `Arc`
/// is gone. Entries of failed handshakes are swept when the map has doubled
/// since the last sweep, which keeps the cost per accept constant on average
/// and the dead entries within twice the live count at the last sweep (at
/// least 64).
#[derive(Default)]
pub struct HandshakeTracker {
    pending: parking_lot::Mutex<Pending>,
}

/// Below this many entries a sweep is not worth its cost.
const MIN_SWEEP_AT: usize = 64;

#[derive(Default)]
struct Pending {
    entries: HashMap<usize, (Weak<SocketDigest>, Instant)>,
    /// The size at which the next `began` sweeps out dead entries first.
    sweep_at: usize,
}

impl HandshakeTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Handshakes that began less than `within` ago and have neither finished
    /// nor failed.
    pub fn in_progress(&self, within: Duration) -> usize {
        // Only the drain calls this, every poll interval, so it may walk
        // every entry.
        let mut pending = self.pending.lock();
        pending
            .entries
            .retain(|_, (digest, _)| digest.strong_count() > 0);
        pending
            .entries
            .values()
            .filter(|(_, began)| began.elapsed() < within)
            .count()
    }

    fn began(&self, digest: &Arc<SocketDigest>) {
        let mut pending = self.pending.lock();
        if pending.entries.len() >= pending.sweep_at.max(MIN_SWEEP_AT) {
            pending
                .entries
                .retain(|_, (digest, _)| digest.strong_count() > 0);
            pending.sweep_at = pending.entries.len().saturating_mul(2).max(MIN_SWEEP_AT);
        }
        pending.entries.insert(
            Arc::as_ptr(digest) as usize,
            (Arc::downgrade(digest), Instant::now()),
        );
    }

    fn finished(&self, digest: &Arc<SocketDigest>) {
        self.pending
            .lock()
            .entries
            .remove(&(Arc::as_ptr(digest) as usize));
    }

    /// Entries held, live or not, for the tests.
    #[cfg(test)]
    fn entries(&self) -> usize {
        self.pending.lock().entries.len()
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
    namespaces: Arc<parking_lot::Mutex<HashMap<String, Arc<ConnectionLimiter>>>>,
    limits: LimitsSource,
    handshakes: Option<Arc<HandshakeTracker>>,
    /// Set for the h2c listeners' app: how long a connection has to send the
    /// HTTP/2 connection preface before it is refused.
    h2_preface: Option<Duration>,
}

/// What a client speaking HTTP/2 with prior knowledge sends first (RFC 9113
/// section 3.4).
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The answer to a client that opened an h2c connection with anything else:
/// most likely HTTP/1.1, which can read it.
const H2C_ONLY_RESPONSE: &[u8] = b"HTTP/1.1 505 HTTP Version Not Supported\r\n\
    Content-Type: text/plain\r\n\
    Content-Length: 60\r\n\
    Connection: close\r\n\
    \r\n\
    This listener speaks HTTP/2 with prior knowledge (h2c) only\n";

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
            namespaces: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            limits: Arc::new(limits),
            handshakes: None,
            h2_preface: None,
        }
    }

    /// The same limits around another app: connections through either count
    /// against one global, namespace and service total, and the same
    /// handshake tracker. For listeners that need an app of their own.
    pub fn sibling<B>(&self, inner: B) -> ConnectionLimitedApp<B> {
        ConnectionLimitedApp {
            inner: Arc::new(inner),
            limiter: Arc::clone(&self.limiter),
            namespaces: Arc::clone(&self.namespaces),
            limits: Arc::clone(&self.limits),
            handshakes: self.handshakes.clone(),
            h2_preface: None,
        }
    }

    /// Refuse every connection that does not open with the HTTP/2 connection
    /// preface within `timeout`. A client that sent something else gets a
    /// `505` it can read if it speaks HTTP/1.1; one that sent too little in
    /// time is closed. Pingora's own h2c mode instead falls back to HTTP/1.1.
    pub fn requiring_h2_preface(mut self, timeout: Duration) -> Self {
        self.h2_preface = Some(timeout);
        self
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

/// Whether `stream` starts with the HTTP/2 preface, leaving the bytes for
/// the app to read. `None` when the connection ended or `timeout` passed
/// before 24 bytes arrived; `Some(false)` after answering anything else with
/// a 505. A stream that cannot peek is left to Pingora, which then insists on
/// HTTP/2 as well.
async fn opens_with_h2_preface(stream: &mut Stream, timeout: Duration) -> Option<bool> {
    use tokio::io::AsyncWriteExt;

    let peer = peer_ip(stream).map(|ip| ip.to_string()).unwrap_or_default();
    let mut buf = [0u8; H2_PREFACE.len()];
    match tokio::time::timeout(timeout, stream.try_peek(&mut buf)).await {
        Ok(Ok(true)) if &buf == H2_PREFACE => Some(true),
        Ok(Ok(false)) => Some(true),
        Ok(Ok(true)) => {
            warn!(
                client_ip = %peer,
                "Connection refused: h2c listener received something other than the \
                 HTTP/2 preface (HTTP/1.1?); answered 505"
            );
            let _ = stream.write_all(H2C_ONLY_RESPONSE).await;
            let _ = stream.flush().await;
            Some(false)
        }
        Ok(Err(e)) => {
            debug!(client_ip = %peer, error = %e, "h2c connection ended before the preface");
            None
        }
        Err(_) => {
            warn!(
                client_ip = %peer,
                timeout_ms = timeout.as_millis() as u64,
                "Connection refused: h2c listener did not receive the HTTP/2 preface in time"
            );
            None
        }
    }
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
        let mut stream = stream;
        if let Some(timeout) = self.h2_preface {
            if !opens_with_h2_preface(&mut stream, timeout).await? {
                return None;
            }
        }
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

    fn digest() -> Arc<SocketDigest> {
        Arc::new(SocketDigest::from_raw_fd(-1))
    }

    #[test]
    fn handshakes_are_counted_from_began_until_finished() {
        let tracker = HandshakeTracker::default();
        let (a, b) = (digest(), digest());
        let wait = Duration::from_secs(60);
        assert_eq!(tracker.in_progress(wait), 0);
        tracker.began(&a);
        tracker.began(&b);
        assert_eq!(tracker.in_progress(wait), 2);
        tracker.finished(&a);
        assert_eq!(tracker.in_progress(wait), 1);
        // A second `finished`, or one for a connection never entered, changes
        // nothing.
        tracker.finished(&a);
        tracker.finished(&digest());
        assert_eq!(tracker.in_progress(wait), 1);
        tracker.finished(&b);
        assert_eq!(tracker.in_progress(wait), 0);
    }

    #[test]
    fn a_handshake_that_fails_stops_counting_when_its_connection_is_dropped() {
        let tracker = HandshakeTracker::default();
        let wait = Duration::from_secs(60);
        let (kept, failed) = (digest(), digest());
        tracker.began(&kept);
        tracker.began(&failed);
        assert_eq!(tracker.in_progress(wait), 2);
        drop(failed);
        assert_eq!(tracker.in_progress(wait), 1);
        tracker.finished(&kept);
        assert_eq!(tracker.in_progress(wait), 0);
    }

    #[test]
    fn a_handshake_older_than_the_wait_is_not_counted() {
        let tracker = HandshakeTracker::default();
        let d = digest();
        tracker.began(&d);
        assert_eq!(tracker.in_progress(Duration::ZERO), 0);
        assert_eq!(tracker.in_progress(Duration::from_secs(60)), 1);
    }

    /// Many connections entering and leaving, interleaved, keep the count
    /// exact; those that fail are dropped without `finished`.
    #[test]
    fn the_count_stays_exact_over_many_interleaved_handshakes() {
        let tracker = HandshakeTracker::default();
        let wait = Duration::from_secs(60);
        let mut open: std::collections::VecDeque<Arc<SocketDigest>> = Default::default();
        // Connections whose handshake finished stay alive, so only `finished`
        // can take them out of the count.
        let mut finished_alive = Vec::new();
        let mut expected = 0usize;
        for i in 0..20_000usize {
            let d = digest();
            tracker.began(&d);
            open.push_back(d);
            expected += 1;
            // Finish the oldest two of every three, fail (drop) every third
            // one, so entries leave in each of the two ways and out of order.
            if i % 3 == 2 {
                let first = open.pop_front().unwrap();
                tracker.finished(&first);
                finished_alive.push(first);
                let second = open.pop_front().unwrap();
                drop(second);
                expected -= 2;
            }
            if i % 997 == 0 {
                assert_eq!(tracker.in_progress(wait), expected, "at {i}");
            }
        }
        assert_eq!(tracker.in_progress(wait), expected);
        for d in open.drain(..) {
            tracker.finished(&d);
        }
        assert_eq!(tracker.in_progress(wait), 0);
        assert_eq!(tracker.entries(), 0);
    }

    /// Handshakes that fail are never reported, so nothing but the sweep in
    /// `began` removes them: the map must not grow without bound when
    /// nothing reads it.
    #[test]
    fn failed_handshakes_are_swept_without_the_drain_reading_them() {
        let tracker = HandshakeTracker::default();
        let live: Vec<_> = (0..10).map(|_| digest()).collect();
        for d in &live {
            tracker.began(d);
        }
        for _ in 0..50_000 {
            let failed = digest();
            tracker.began(&failed);
            drop(failed);
        }
        assert!(
            tracker.entries() <= 2 * live.len() + 2 * MIN_SWEEP_AT,
            "{} entries held",
            tracker.entries()
        );
        assert_eq!(tracker.in_progress(Duration::from_secs(60)), live.len());
    }

    /// The tracker takes no part in any limit: a refused connection is
    /// taken out of the handshake count as well.
    #[tokio::test]
    async fn a_refused_connection_leaves_the_handshake_count() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (started_tx, _started_rx) = mpsc::unbounded_channel();
        let tracker = HandshakeTracker::new();
        let app = Arc::new(
            ConnectionLimitedApp::new(
                HoldingApp {
                    started: started_tx,
                },
                ConnectionLimiter::new(),
                |_, _| ConnectionLimits {
                    max_total: Some(0),
                    ..Default::default()
                },
            )
            .with_handshakes(Arc::clone(&tracker)),
        );
        let (_tx, shutdown) = tokio::sync::watch::channel(false);
        let (stream, _client) = accepted(&listener).await;
        // Held here, so the entry is live unless `process_new` removes it.
        let digest = stream.get_socket_digest().unwrap();
        tracker.began(&digest);
        assert_eq!(tracker.in_progress(Duration::from_secs(60)), 1);
        assert!(app.process_new(stream, &shutdown).await.is_none());
        assert_eq!(tracker.in_progress(Duration::from_secs(60)), 0);
        drop(digest);
    }
}
