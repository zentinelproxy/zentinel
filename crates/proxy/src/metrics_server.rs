//! Standalone HTTP server that exposes Prometheus metrics.
//!
//! When `observability.metrics.enabled` is set, the proxy binds a dedicated
//! HTTP listener on `observability.metrics.address` and serves the Prometheus
//! exposition format at `observability.metrics.path` (default `/metrics`).
//!
//! This is intentionally separate from the data-plane listeners so that the
//! scrape endpoint can be bound to an internal address and is never exposed to
//! client traffic by accident. The body is produced by the same renderer used
//! by the builtin `/metrics` route handler, so both surfaces are identical.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::builtin_handlers::{render_prometheus_metrics, PROMETHEUS_CONTENT_TYPE};
use crate::cache::HttpCacheStats;

/// Maximum request size to read. Scrape requests are tiny; this bounds the
/// per-connection buffer so a misbehaving client cannot force large allocations.
const MAX_REQUEST_SIZE: usize = 8192;

/// Run the standalone Prometheus metrics server.
///
/// Binds `addr` and serves the metrics body at `path`. A binding failure is
/// logged loudly and the metrics endpoint is left disabled, but it never takes
/// the proxy down — metrics are auxiliary and must not worsen an on-call.
///
/// This function runs until the process exits.
pub async fn run_metrics_server(
    addr: String,
    path: String,
    cache_stats: Option<Arc<HttpCacheStats>>,
) {
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(
                address = %addr,
                error = %e,
                "Failed to bind metrics server; metrics endpoint disabled"
            );
            return;
        }
    };

    info!(address = %addr, path = %path, "Metrics server listening");

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                let path = path.clone();
                let cache_stats = cache_stats.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_connection(&mut stream, &path, cache_stats.as_ref()).await
                    {
                        debug!(peer = %peer, error = %e, "Metrics server connection error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "Metrics server accept error");
            }
        }
    }
}

/// Handle a single HTTP connection on the metrics server.
async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    metrics_path: &str,
    cache_stats: Option<&Arc<HttpCacheStats>>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST_SIZE];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the request line: "GET /metrics?foo=bar HTTP/1.1"
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace();
    let _method = request_line.next().unwrap_or("");
    let raw_target = request_line.next().unwrap_or("/");
    let req_path = raw_target.split('?').next().unwrap_or(raw_target);

    let response = if req_path == metrics_path {
        match render_prometheus_metrics(cache_stats) {
            Ok(body) => http_response("200 OK", PROMETHEUS_CONTENT_TYPE, &body),
            Err(e) => {
                error!(error = %e, "Failed to encode Prometheus metrics");
                http_response(
                    "500 Internal Server Error",
                    "text/plain; charset=utf-8",
                    format!("# ERROR: Failed to encode metrics: {}\n", e).as_bytes(),
                )
            }
        }
    } else if req_path == "/" {
        // A tiny landing page so an operator hitting the address in a browser
        // is pointed at the metrics path instead of getting a bare 404.
        let body = format!(
            "<html><head><title>Zentinel Metrics</title></head>\
             <body><h1>Zentinel Metrics</h1>\
             <p><a href=\"{path}\">{path}</a></p></body></html>",
            path = metrics_path
        );
        http_response("200 OK", "text/html; charset=utf-8", body.as_bytes())
    } else {
        http_response("404 Not Found", "text/plain; charset=utf-8", b"Not Found\n")
    };

    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

/// Build a raw HTTP/1.1 response with `Connection: close`.
fn http_response(status: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        status = status,
        content_type = content_type,
        len = body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn read_response(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn serves_metrics_at_configured_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_connection(&mut stream, "/metrics", None)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("text/plain; version=0.0.4"));
        assert!(response.contains("zentinel_up 1"));
        assert!(response.contains("zentinel_build_info"));
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_connection(&mut stream, "/metrics", None)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;

        assert!(response.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[tokio::test]
    async fn root_path_serves_landing_page() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_connection(&mut stream, "/metrics", None)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("text/html"));
        assert!(response.contains("/metrics"));
    }

    #[tokio::test]
    async fn respects_custom_metrics_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handle_connection(&mut stream, "/internal/metrics", None)
                .await
                .unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /internal/metrics?x=1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let response = read_response(&mut client).await;

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("zentinel_up 1"));
    }
}
