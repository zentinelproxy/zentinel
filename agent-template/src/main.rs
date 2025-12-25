//! {{project-name}} - {{description}}
//!
//! A Sentinel agent that processes HTTP requests/responses.

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, Decision, HeaderOp,
    RequestHeadersEvent,
};
use std::path::PathBuf;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

/// {{description}}
#[derive(Parser, Debug)]
#[command(name = "{{project-name}}")]
#[command(about = "{{description}}")]
struct Args {
    /// Path to Unix socket for agent communication
    #[arg(short, long, env = "AGENT_SOCKET", default_value = "/tmp/{{project-name}}.sock")]
    socket: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "AGENT_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

/// Main agent handler
struct MyAgent {
    // Add your agent state here
}

impl MyAgent {
    fn new() -> Self {
        Self {
            // Initialize your agent state
        }
    }
}

#[async_trait]
impl AgentHandler for MyAgent {
    /// Handle incoming request headers
    ///
    /// This is called for every request before it reaches the upstream.
    /// Return a decision to allow, block, or redirect the request.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let method = &event.method;
        let path = &event.path;
        let client_ip = &event.metadata.client_ip;

        debug!(
            method = %method,
            path = %path,
            client_ip = %client_ip,
            "Processing request"
        );

        // Example: Block requests to /admin from non-localhost
        if path.starts_with("/admin") && !client_ip.starts_with("127.") {
            warn!(path = %path, client_ip = %client_ip, "Blocking admin access");
            return AgentResponse {
                decision: Decision::Block {
                    status: 403,
                    body: Some("Access denied".to_string()),
                    headers: None,
                },
                request_headers: vec![],
                response_headers: vec![],
                routing_metadata: Default::default(),
                audit: AuditMetadata {
                    tags: vec!["blocked".to_string(), "admin-access".to_string()],
                    rule_ids: vec!["ADMIN_BLOCK_001".to_string()],
                    reason_codes: vec!["UNAUTHORIZED_ADMIN_ACCESS".to_string()],
                    ..Default::default()
                },
            };
        }

        // Allow the request and add a custom header
        AgentResponse {
            decision: Decision::Allow,
            request_headers: vec![HeaderOp::Set {
                name: "X-Processed-By".to_string(),
                value: "{{project-name}}".to_string(),
            }],
            response_headers: vec![],
            routing_metadata: Default::default(),
            audit: AuditMetadata::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&args.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    info!(
        socket = %args.socket.display(),
        "Starting {{project-name}}"
    );

    // Create and run the agent server
    let agent = MyAgent::new();
    let server = AgentServer::new(
        "{{project-name}}",
        args.socket,
        Box::new(agent),
    );

    server.run().await?;

    Ok(())
}
