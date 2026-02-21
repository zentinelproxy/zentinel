//! Static configuration topology analysis for Zentinel reverse proxy.
//!
//! This crate analyzes a Zentinel `Config` and produces a topology graph
//! showing listeners, routes, filter chains, agents, and upstreams along
//! with heuristic warnings about common misconfigurations.
//!
//! # Usage
//!
//! ```ignore
//! use zentinel_config_inspect::{inspect, render};
//!
//! let config = zentinel_config::Config::from_str(kdl_source)?;
//! let topology = inspect(&config);
//!
//! // Render as Mermaid flowchart
//! let mermaid = render::mermaid::render(&topology);
//! println!("{mermaid}");
//!
//! // Check for warnings
//! for warning in &topology.warnings {
//!     eprintln!("[{}] {}: {}", warning.severity, warning.code, warning.message);
//! }
//! ```

pub mod graph;
pub mod heuristics;
pub mod render;
pub mod shadow;

use zentinel_config::Config;

pub use graph::{
    AgentNode, Edge, FilterNode, ListenerNode, NodeRef, RouteNode, Topology, UpstreamNode,
};
pub use heuristics::{Severity, Warning};

/// Inspect a configuration and produce a topology with heuristic warnings.
pub fn inspect(config: &Config) -> Topology {
    let mut topology = graph::build_topology(config);
    let warnings = heuristics::analyze(config, &topology);
    topology.warnings = warnings;
    topology
}
