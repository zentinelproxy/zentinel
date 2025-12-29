//! Build script for sentinel-agent-protocol
//!
//! Compiles Protocol Buffer definitions for gRPC support.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile the agent protocol proto file
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/agent.proto"], &["proto/"])?;

    // Rerun if proto files change
    println!("cargo:rerun-if-changed=proto/agent.proto");

    Ok(())
}
