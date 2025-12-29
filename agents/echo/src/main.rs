//! Echo Agent - Reference implementation for Sentinel external agents
//!
//! This agent demonstrates the agent protocol by echoing request information
//! back as headers and providing detailed audit metadata.

use anyhow::{Context, Result};
use async_trait::async_trait;
use clap::Parser;
use std::path::PathBuf;
use tracing::{debug, info};

use sentinel_agent_protocol::{
    AgentHandler, AgentResponse, AgentServer, AuditMetadata, GrpcAgentServer, HeaderOp,
    RequestBodyChunkEvent, RequestCompleteEvent, RequestHeadersEvent, ResponseBodyChunkEvent,
    ResponseHeadersEvent,
};

/// Echo agent command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Unix socket path to listen on (mutually exclusive with --grpc)
    #[arg(
        short,
        long,
        env = "ECHO_AGENT_SOCKET",
        conflicts_with = "grpc"
    )]
    socket: Option<PathBuf>,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051")
    #[arg(
        short,
        long,
        env = "ECHO_AGENT_GRPC",
        conflicts_with = "socket"
    )]
    grpc: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, env = "ECHO_AGENT_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Add prefix to all echo headers
    #[arg(short, long, env = "ECHO_AGENT_PREFIX", default_value = "X-Echo-")]
    prefix: String,

    /// Enable verbose mode (adds more headers)
    #[arg(short, long, env = "ECHO_AGENT_VERBOSE")]
    verbose: bool,
}

/// Echo agent implementation
struct EchoAgent {
    /// Header prefix for echo headers
    prefix: String,
    /// Verbose mode flag
    verbose: bool,
    /// Request counter for tracking
    request_count: std::sync::atomic::AtomicU64,
}

impl EchoAgent {
    /// Create new echo agent
    fn new(prefix: String, verbose: bool) -> Self {
        Self {
            prefix,
            verbose,
            request_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Generate echo header name
    fn header_name(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }
}

#[async_trait]
impl AgentHandler for EchoAgent {
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        let request_num = self
            .request_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;

        debug!(
            correlation_id = %event.metadata.correlation_id,
            method = %event.method,
            uri = %event.uri,
            request_num = request_num,
            "Processing request headers"
        );

        let mut response = AgentResponse::default_allow();

        // Add basic echo headers
        response = response
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Agent"),
                value: "echo-agent/1.0".to_string(),
            })
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Correlation-Id"),
                value: event.metadata.correlation_id.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Request-Num"),
                value: request_num.to_string(),
            })
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Method"),
                value: event.method.clone(),
            })
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Path"),
                value: event.uri.clone(),
            });

        // Add verbose headers if enabled
        if self.verbose {
            response = response
                .add_request_header(HeaderOp::Set {
                    name: self.header_name("Client-Ip"),
                    value: event.metadata.client_ip.clone(),
                })
                .add_request_header(HeaderOp::Set {
                    name: self.header_name("Timestamp"),
                    value: event.metadata.timestamp.clone(),
                });

            // Echo interesting request headers
            if let Some(user_agent) = event.headers.get("user-agent").and_then(|v| v.first()) {
                response = response.add_request_header(HeaderOp::Set {
                    name: self.header_name("User-Agent"),
                    value: user_agent.clone(),
                });
            }

            if let Some(content_type) = event.headers.get("content-type").and_then(|v| v.first()) {
                response = response.add_request_header(HeaderOp::Set {
                    name: self.header_name("Content-Type"),
                    value: content_type.clone(),
                });
            }

            // Add header count
            response = response.add_request_header(HeaderOp::Set {
                name: self.header_name("Header-Count"),
                value: event.headers.len().to_string(),
            });
        }

        // Add audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["echo".to_string(), "request_headers".to_string()];
        audit.custom.insert(
            "request_num".to_string(),
            serde_json::Value::Number(request_num.into()),
        );
        audit.custom.insert(
            "method".to_string(),
            serde_json::Value::String(event.method),
        );
        audit
            .custom
            .insert("uri".to_string(), serde_json::Value::String(event.uri));

        response.with_audit(audit)
    }

    async fn on_request_body_chunk(&self, event: RequestBodyChunkEvent) -> AgentResponse {
        debug!(
            correlation_id = %event.correlation_id,
            data_size = event.data.len(),
            is_last = event.is_last,
            "Processing request body chunk"
        );

        let mut response = AgentResponse::default_allow();

        // Add body info headers
        response = response
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Body-Chunk-Size"),
                value: event.data.len().to_string(),
            })
            .add_request_header(HeaderOp::Set {
                name: self.header_name("Body-Last-Chunk"),
                value: event.is_last.to_string(),
            });

        if let Some(total_size) = event.total_size {
            response = response.add_request_header(HeaderOp::Set {
                name: self.header_name("Body-Total-Size"),
                value: total_size.to_string(),
            });
        }

        // Add audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["echo".to_string(), "request_body".to_string()];
        audit.custom.insert(
            "chunk_size".to_string(),
            serde_json::Value::Number(event.data.len().into()),
        );

        response.with_audit(audit)
    }

    async fn on_response_headers(&self, event: ResponseHeadersEvent) -> AgentResponse {
        debug!(
            correlation_id = %event.correlation_id,
            status = event.status,
            "Processing response headers"
        );

        let mut response = AgentResponse::default_allow();

        // Add response echo headers
        response = response
            .add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Status"),
                value: event.status.to_string(),
            })
            .add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Correlation-Id"),
                value: event.correlation_id.clone(),
            });

        if self.verbose {
            // Echo response header count
            response = response.add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Header-Count"),
                value: event.headers.len().to_string(),
            });

            // Echo content-type if present
            if let Some(content_type) = event.headers.get("content-type").and_then(|v| v.first()) {
                response = response.add_response_header(HeaderOp::Set {
                    name: self.header_name("Response-Content-Type"),
                    value: content_type.clone(),
                });
            }
        }

        // Add audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["echo".to_string(), "response_headers".to_string()];
        audit.custom.insert(
            "status".to_string(),
            serde_json::Value::Number(event.status.into()),
        );

        response.with_audit(audit)
    }

    async fn on_response_body_chunk(&self, event: ResponseBodyChunkEvent) -> AgentResponse {
        debug!(
            correlation_id = %event.correlation_id,
            data_size = event.data.len(),
            is_last = event.is_last,
            "Processing response body chunk"
        );

        let mut response = AgentResponse::default_allow();

        // Add response body info headers
        response = response
            .add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Body-Chunk-Size"),
                value: event.data.len().to_string(),
            })
            .add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Body-Last-Chunk"),
                value: event.is_last.to_string(),
            });

        if let Some(total_size) = event.total_size {
            response = response.add_response_header(HeaderOp::Set {
                name: self.header_name("Response-Body-Total-Size"),
                value: total_size.to_string(),
            });
        }

        // Add audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["echo".to_string(), "response_body".to_string()];
        audit.custom.insert(
            "chunk_size".to_string(),
            serde_json::Value::Number(event.data.len().into()),
        );

        response.with_audit(audit)
    }

    async fn on_request_complete(&self, event: RequestCompleteEvent) -> AgentResponse {
        info!(
            correlation_id = %event.correlation_id,
            status = event.status,
            duration_ms = event.duration_ms,
            "Request completed"
        );

        let mut response = AgentResponse::default_allow();

        // Add completion headers
        response = response.add_response_header(HeaderOp::Set {
            name: self.header_name("Request-Complete"),
            value: "true".to_string(),
        });

        if self.verbose {
            response = response
                .add_response_header(HeaderOp::Set {
                    name: self.header_name("Request-Duration-Ms"),
                    value: event.duration_ms.to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: self.header_name("Request-Body-Size"),
                    value: event.request_body_size.to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: self.header_name("Response-Body-Size"),
                    value: event.response_body_size.to_string(),
                })
                .add_response_header(HeaderOp::Set {
                    name: self.header_name("Upstream-Attempts"),
                    value: event.upstream_attempts.to_string(),
                });

            if let Some(ref error) = event.error {
                response = response.add_response_header(HeaderOp::Set {
                    name: self.header_name("Request-Error"),
                    value: error.clone(),
                });
            }
        }

        // Add comprehensive audit metadata
        let mut audit = AuditMetadata::default();
        audit.tags = vec!["echo".to_string(), "request_complete".to_string()];
        audit.custom.insert(
            "correlation_id".to_string(),
            serde_json::Value::String(event.correlation_id),
        );
        audit.custom.insert(
            "status".to_string(),
            serde_json::Value::Number(event.status.into()),
        );
        audit.custom.insert(
            "duration_ms".to_string(),
            serde_json::Value::Number(event.duration_ms.into()),
        );
        audit.custom.insert(
            "request_body_size".to_string(),
            serde_json::Value::Number(event.request_body_size.into()),
        );
        audit.custom.insert(
            "response_body_size".to_string(),
            serde_json::Value::Number(event.response_body_size.into()),
        );

        response.with_audit(audit)
    }
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

    // Determine transport mode
    match (&args.socket, &args.grpc) {
        (Some(socket), None) => {
            info!(
                version = env!("CARGO_PKG_VERSION"),
                socket = ?socket,
                prefix = %args.prefix,
                verbose = args.verbose,
                "Starting echo agent (Unix socket)"
            );

            let agent = Box::new(EchoAgent::new(args.prefix, args.verbose));
            let server = AgentServer::new("echo-agent", socket, agent);

            info!("Echo agent ready and listening on Unix socket");

            server
                .run()
                .await
                .context("Failed to run echo agent server")?;
        }
        (None, Some(grpc_addr)) => {
            info!(
                version = env!("CARGO_PKG_VERSION"),
                grpc = %grpc_addr,
                prefix = %args.prefix,
                verbose = args.verbose,
                "Starting echo agent (gRPC)"
            );

            let agent = Box::new(EchoAgent::new(args.prefix, args.verbose));
            let server = GrpcAgentServer::new("echo-agent", agent);
            let addr = grpc_addr
                .parse()
                .context("Invalid gRPC address format (expected host:port)")?;

            info!("Echo agent ready and listening on gRPC");

            server
                .run(addr)
                .await
                .context("Failed to run echo agent gRPC server")?;
        }
        (None, None) => {
            // Default to Unix socket if neither specified
            let socket = PathBuf::from("/tmp/echo-agent.sock");
            info!(
                version = env!("CARGO_PKG_VERSION"),
                socket = ?socket,
                prefix = %args.prefix,
                verbose = args.verbose,
                "Starting echo agent (Unix socket, default)"
            );

            let agent = Box::new(EchoAgent::new(args.prefix, args.verbose));
            let server = AgentServer::new("echo-agent", socket, agent);

            info!("Echo agent ready and listening on Unix socket");

            server
                .run()
                .await
                .context("Failed to run echo agent server")?;
        }
        (Some(_), Some(_)) => {
            // This shouldn't happen due to clap's conflicts_with
            unreachable!("Cannot specify both --socket and --grpc");
        }
    }

    Ok(())
}
