//! Build script for zentinel-agent-protocol
//!
//! Compiles Protocol Buffer definitions for gRPC support.
//! - v1: proto/agent.proto
//! - v2: proto/agent_v2.proto

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile v1 agent protocol
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto/"])?;

    // Compile v2 agent protocol
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent_v2.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=proto/agent.proto");
    println!("cargo:rerun-if-changed=proto/agent_v2.proto");

    Ok(())
}
