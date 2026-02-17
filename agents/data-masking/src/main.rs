//! Data Masking Agent for Zentinel
//!
//! This agent provides PII protection with:
//! - Reversible tokenization (request-scoped)
//! - Format-preserving encryption (FF1-style)
//! - Pattern-based detection and masking
//! - Support for JSON, XML, and form-urlencoded content

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;

use zentinel_agent_protocol::{AgentServer, GrpcAgentServer};
use zentinel_data_masking_agent::{DataMaskingAgent, DataMaskingConfig};

/// Data Masking Agent command-line arguments.
#[derive(Parser, Debug)]
#[command(
    name = "zentinel-data-masking-agent",
    author,
    version,
    about = "Data masking agent for Zentinel - tokenization, FPE, and pattern-based PII protection"
)]
struct Args {
    /// Unix socket path to listen on (mutually exclusive with --grpc).
    #[arg(short, long, env = "DATA_MASKING_SOCKET", conflicts_with = "grpc")]
    socket: Option<PathBuf>,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051").
    #[arg(short, long, env = "DATA_MASKING_GRPC", conflicts_with = "socket")]
    grpc: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(short, long, env = "DATA_MASKING_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Path to configuration file (JSON).
    #[arg(short, long, env = "DATA_MASKING_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

    // Initialize tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    // Load configuration
    let config = if let Some(ref config_path) = args.config {
        let content = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {:?}", config_path))?;
        serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {:?}", config_path))?
    } else {
        DataMaskingConfig::default()
    };

    // Create agent
    let agent =
        Box::new(DataMaskingAgent::new(config).context("Failed to create data masking agent")?);

    // Determine transport mode
    match (&args.socket, &args.grpc) {
        (Some(socket), None) => {
            info!(
                version = env!("CARGO_PKG_VERSION"),
                socket = ?socket,
                "Starting data masking agent (Unix socket)"
            );

            let server = AgentServer::new("data-masking-agent", socket, agent);

            info!("Data masking agent ready and listening on Unix socket");

            server
                .run()
                .await
                .context("Failed to run data masking agent server")?;
        }
        (None, Some(grpc_addr)) => {
            info!(
                version = env!("CARGO_PKG_VERSION"),
                grpc = %grpc_addr,
                "Starting data masking agent (gRPC)"
            );

            let server = GrpcAgentServer::new("data-masking-agent", agent);
            let addr = grpc_addr
                .parse()
                .context("Invalid gRPC address format (expected host:port)")?;

            info!("Data masking agent ready and listening on gRPC");

            server
                .run(addr)
                .await
                .context("Failed to run data masking agent gRPC server")?;
        }
        (None, None) => {
            // Default to Unix socket if neither specified
            let socket = PathBuf::from("/tmp/data-masking-agent.sock");
            info!(
                version = env!("CARGO_PKG_VERSION"),
                socket = ?socket,
                "Starting data masking agent (Unix socket, default)"
            );

            let server = AgentServer::new("data-masking-agent", socket, agent);

            info!("Data masking agent ready and listening on Unix socket");

            server
                .run()
                .await
                .context("Failed to run data masking agent server")?;
        }
        (Some(_), Some(_)) => {
            // This shouldn't happen due to clap's conflicts_with
            unreachable!("Cannot specify both --socket and --grpc");
        }
    }

    Ok(())
}
