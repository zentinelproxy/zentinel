//! Zentinel Gateway API Controller binary.
//!
//! Runs as a standalone Kubernetes controller that watches Gateway API
//! resources and translates them into Zentinel proxy configuration.
//!
//! Supports leader election for HA deployments and exposes Prometheus
//! metrics on a configurable port.

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use anyhow::Result;
use prometheus::Registry;
use std::net::SocketAddr;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use zentinel_gateway::{
    ControllerMetrics, GatewayController, LeaderElectionConfig, LeaderElector,
};

/// Metrics server port (configurable via METRICS_PORT env var).
const DEFAULT_METRICS_PORT: u16 = 9090;

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider (required before any TLS operations)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Write bootstrap config IMMEDIATELY so the proxy sidecar can start.
    // This must happen before any async work since both containers start
    // simultaneously in a pod.
    if let Ok(config_path) = std::env::var("CONFIG_OUTPUT_PATH") {
        let path = std::path::PathBuf::from(&config_path);
        if !path.exists() {
            zentinel_gateway::config_writer::write_bootstrap_config(&path)
                .expect("Failed to write bootstrap config");
        }
    }

    // Initialize logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("zentinel_gateway=info,kube=warn")),
        )
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Zentinel Gateway API controller"
    );

    // Set up Prometheus metrics
    let registry = Registry::new();
    let metrics = match ControllerMetrics::new(&registry) {
        Ok(m) => {
            info!("Prometheus metrics registered");
            Some(m)
        }
        Err(e) => {
            warn!(error = %e, "Failed to register metrics, continuing without");
            None
        }
    };

    // Start metrics HTTP server
    let metrics_port: u16 = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_METRICS_PORT);

    let metrics_addr: SocketAddr = ([0, 0, 0, 0], metrics_port).into();
    let metrics_server = start_metrics_server(metrics_addr, registry);
    tokio::spawn(metrics_server);
    info!(addr = %metrics_addr, "Metrics server started");

    // Set up leader election
    let leader_enabled = std::env::var("LEADER_ELECTION")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let mut controller = GatewayController::new().await?;

    // Enable config file output for proxy sidecar
    if let Ok(config_path) = std::env::var("CONFIG_OUTPUT_PATH") {
        info!(path = %config_path, "Config output to file enabled");
        controller = controller.with_config_output(std::path::PathBuf::from(config_path));
    }

    // Install signal handler for graceful shutdown
    let ctrl_c = tokio::signal::ctrl_c();

    if leader_enabled {
        let client = kube::Client::try_default().await?;
        let config = LeaderElectionConfig::default();
        let elector = LeaderElector::new(client, config);

        info!("Leader election enabled");

        // Update leader gauge
        if let Some(ref m) = metrics {
            let flag = elector.leader_flag();
            let gauge = m.is_leader.clone();
            tokio::spawn(async move {
                loop {
                    gauge.set(if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        1
                    } else {
                        0
                    });
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            });
        }

        tokio::select! {
            result = controller.run() => {
                if let Err(e) = result {
                    error!(error = %e, "Controller exited with error");
                    std::process::exit(1);
                }
            }
            result = elector.run() => {
                if let Err(e) = result {
                    error!(error = %e, "Leader election exited with error");
                    std::process::exit(1);
                }
            }
            _ = ctrl_c => {
                info!("Received shutdown signal, exiting");
            }
        }
    } else {
        info!("Leader election disabled (single-replica mode)");

        tokio::select! {
            result = controller.run() => {
                if let Err(e) = result {
                    error!(error = %e, "Controller exited with error");
                    std::process::exit(1);
                }
            }
            _ = ctrl_c => {
                info!("Received shutdown signal, exiting");
            }
        }
    }

    Ok(())
}

/// Start a minimal HTTP server for Prometheus metrics scraping.
async fn start_metrics_server(addr: SocketAddr, registry: Registry) {
    use hyper::body::Bytes;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use prometheus::Encoder;

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, addr = %addr, "Failed to bind metrics server");
            return;
        }
    };

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "Metrics server accept error");
                continue;
            }
        };

        let registry = registry.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                let registry = registry.clone();
                async move {
                    if req.uri().path() == "/metrics" {
                        let encoder = prometheus::TextEncoder::new();
                        let metric_families = registry.gather();
                        let mut buffer = Vec::new();
                        encoder.encode(&metric_families, &mut buffer).unwrap();
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .header("Content-Type", encoder.format_type())
                                .body(http_body_util::Full::new(Bytes::from(buffer)))
                                .unwrap(),
                        )
                    } else {
                        Ok(Response::builder()
                            .status(404)
                            .body(http_body_util::Full::new(Bytes::from("Not Found")))
                            .unwrap())
                    }
                }
            });

            let io = hyper_util::rt::TokioIo::new(stream);
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
            {
                error!(error = %e, "Metrics connection error");
            }
        });
    }
}
