//! The `ca-cert`, `client-cert` and `client-key` options of an agent's `grpc`
//! transport must reach the connection.
//!
//! Each test starts a real gRPC agent server with a certificate from
//! `tests/fixtures/tls/` and connects to it through [`AgentPool`] and
//! [`AgentClientV2`].

use async_trait::async_trait;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentClientV2, AgentHandlerV2, AgentPool, AgentTlsOptions, GrpcAgentServerV2,
};

const TIMEOUT: Duration = Duration::from_secs(5);

struct Handler;

#[async_trait]
impl AgentHandlerV2 for Handler {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new("tls-test", "TLS Test Agent", "1.0.0")
    }
}

/// rustls cannot choose a provider on its own here; the proxy installs one at
/// startup, so the tests do the same.
fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

/// Start an agent server. `tls` is `None` for plaintext, otherwise the server
/// certificate is `server-default` (SAN: localhost, 127.0.0.1) and, with
/// `require_client_cert`, clients must present one signed by the test CA.
async fn start_agent(tls: bool, require_client_cert: bool) -> SocketAddr {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut builder = Server::builder();
    if tls {
        let mut config = ServerTlsConfig::new().identity(Identity::from_pem(
            read("server-default.crt"),
            read("server-default.key"),
        ));
        if require_client_cert {
            config = config.client_ca_root(Certificate::from_pem(read("ca.crt")));
        }
        builder = builder.tls_config(config).unwrap();
    }
    let service = GrpcAgentServerV2::new("tls-test", Box::new(Handler)).into_service();
    tokio::spawn(async move {
        let _ = builder
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await;
    });
    addr
}

fn ca_only() -> AgentTlsOptions {
    AgentTlsOptions {
        ca_cert: Some(fixture("ca.crt")),
        ..Default::default()
    }
}

fn mtls() -> AgentTlsOptions {
    AgentTlsOptions {
        ca_cert: Some(fixture("ca.crt")),
        client_cert: Some(fixture("client.crt")),
        client_key: Some(fixture("client.key")),
    }
}

async fn handshake(endpoint: &str, tls: Option<&AgentTlsOptions>) -> Result<(), String> {
    install_crypto_provider();
    let client = AgentClientV2::new_with_tls("a", endpoint, TIMEOUT, tls)
        .await
        .map_err(|e| e.to_string())?;
    client.connect().await.map_err(|e| e.to_string())
}

#[tokio::test]
async fn ca_cert_is_used_to_verify_the_agent() {
    let addr = start_agent(true, false).await;
    let endpoint = format!("https://localhost:{}", addr.port());

    handshake(&endpoint, Some(&ca_only())).await.unwrap();
}

#[tokio::test]
async fn an_untrusted_agent_certificate_is_refused() {
    let addr = start_agent(true, false).await;
    let endpoint = format!("https://localhost:{}", addr.port());

    // The server's CA is not in the system trust store.
    assert!(handshake(&endpoint, None).await.is_err());

    // A CA that did not sign the agent's certificate.
    let wrong = AgentTlsOptions {
        ca_cert: Some(fixture("untrusted.crt")),
        ..Default::default()
    };
    assert!(handshake(&endpoint, Some(&wrong)).await.is_err());
}

#[tokio::test]
async fn client_certificate_is_presented_for_mtls() {
    let addr = start_agent(true, true).await;
    let endpoint = format!("https://localhost:{}", addr.port());

    handshake(&endpoint, Some(&mtls())).await.unwrap();
    assert!(
        handshake(&endpoint, Some(&ca_only())).await.is_err(),
        "an agent that requires a client certificate must refuse a client without one"
    );
}

#[tokio::test]
async fn tls_options_are_never_applied_to_a_plaintext_endpoint() {
    // A plaintext agent is listening. TLS is configured, so the connection must
    // not be made: before, the options were dropped and this connected.
    let addr = start_agent(false, false).await;
    let endpoint = format!("http://127.0.0.1:{}", addr.port());

    handshake(&endpoint, None).await.unwrap();
    let err = handshake(&endpoint, Some(&ca_only())).await.unwrap_err();
    assert!(err.contains("not https://"), "{err}");
}

#[tokio::test]
async fn an_https_endpoint_does_not_fall_back_to_plaintext() {
    let addr = start_agent(false, false).await;
    let endpoint = format!("https://localhost:{}", addr.port());

    assert!(handshake(&endpoint, Some(&ca_only())).await.is_err());
}

#[tokio::test]
async fn unreadable_or_incomplete_tls_options_fail_to_build() {
    let missing = AgentTlsOptions {
        ca_cert: Some(fixture("does-not-exist.crt")),
        ..Default::default()
    };
    let err = handshake("https://localhost:1", Some(&missing))
        .await
        .unwrap_err();
    assert!(err.contains("does-not-exist.crt"), "{err}");

    let half = AgentTlsOptions {
        ca_cert: Some(fixture("ca.crt")),
        client_cert: Some(fixture("client.crt")),
        client_key: None,
    };
    let err = handshake("https://localhost:1", Some(&half))
        .await
        .unwrap_err();
    assert!(err.contains("together"), "{err}");
}

#[tokio::test]
async fn pool_connects_with_tls_and_refuses_bad_options_up_front() {
    let addr = start_agent(true, true).await;
    let endpoint = format!("https://localhost:{}", addr.port());

    install_crypto_provider();
    let pool = AgentPool::new();
    pool.add_agent_with_tls("secure", &endpoint, Some(mtls()))
        .await
        .unwrap();
    assert!(pool.is_agent_healthy("secure"));

    // Bad options are an error from add_agent, not an unhealthy agent that is
    // retried forever (and bypassed under failure-mode "open").
    let plaintext = format!("http://127.0.0.1:{}", addr.port());
    assert!(pool
        .add_agent_with_tls("bad", &plaintext, Some(ca_only()))
        .await
        .is_err());
    assert!(pool.agent_ids().iter().all(|id| id != "bad"));
    pool.shutdown().await.unwrap();
}
