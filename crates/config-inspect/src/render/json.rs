//! JSON renderer for topology graphs.
//!
//! Produces a JSON representation of the topology suitable for
//! custom web-based renderers or programmatic consumption.

use crate::graph::Topology;

/// Render a topology as pretty-printed JSON.
pub fn render(topology: &Topology) -> String {
    serde_json::to_string_pretty(topology).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize topology: {}\"}}", e)
    })
}

/// Render a topology as compact JSON.
pub fn render_compact(topology: &Topology) -> String {
    serde_json::to_string(topology).unwrap_or_else(|e| {
        format!("{{\"error\": \"Failed to serialize topology: {}\"}}", e)
    })
}
