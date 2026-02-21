//! Plain text renderer for terminal output.
//!
//! Produces a human-readable summary of the topology with
//! sections for each component type.

use crate::graph::Topology;
use crate::heuristics::Severity;

/// Render a topology as a text summary for terminal display.
pub fn render(topology: &Topology) -> String {
    let mut out = String::with_capacity(2048);

    // Header
    out.push_str("Zentinel Configuration Topology\n");
    out.push_str(&"=".repeat(40));
    out.push('\n');

    // Listeners
    out.push_str(&format!("\nListeners ({})\n", topology.listeners.len()));
    out.push_str(&"-".repeat(30));
    out.push('\n');
    for l in &topology.listeners {
        let tls = if l.tls { " [TLS]" } else { "" };
        out.push_str(&format!("  {} -> {}{}\n", l.id, l.address, tls));
    }

    // Routes
    out.push_str(&format!("\nRoutes ({})\n", topology.routes.len()));
    out.push_str(&"-".repeat(30));
    out.push('\n');
    for r in &topology.routes {
        let extras = if r.has_circuit_breaker || r.has_retry || r.websocket {
            let mut flags = Vec::new();
            if r.has_circuit_breaker { flags.push("CB"); }
            if r.has_retry { flags.push("retry"); }
            if r.websocket { flags.push("WS"); }
            format!(" [{}]", flags.join(", "))
        } else {
            String::new()
        };
        out.push_str(&format!(
            "  {} [{}] {} {}{}\n",
            r.id, r.priority, r.service_type, r.match_summary, extras
        ));
    }

    // Filter chains per route
    let routes_with_filters: Vec<_> = topology
        .routes
        .iter()
        .filter(|r| {
            topology
                .edges
                .iter()
                .any(|e| e.from == crate::graph::NodeRef::Route(r.id.clone()))
        })
        .collect();

    if !routes_with_filters.is_empty() {
        out.push_str("\nFilter Chains\n");
        out.push_str(&"-".repeat(30));
        out.push('\n');
        for route in &topology.routes {
            let filter_edges: Vec<_> = topology
                .edges
                .iter()
                .filter(|e| {
                    e.from == crate::graph::NodeRef::Route(route.id.clone())
                        && matches!(e.to, crate::graph::NodeRef::Filter(_))
                })
                .collect();
            if !filter_edges.is_empty() {
                let chain: Vec<String> = filter_edges
                    .iter()
                    .map(|e| match &e.to {
                        crate::graph::NodeRef::Filter(id) => id.clone(),
                        _ => "?".to_string(),
                    })
                    .collect();
                out.push_str(&format!("  {} -> {}\n", route.id, chain.join(" -> ")));
            }
        }
    }

    // Agents
    if !topology.agents.is_empty() {
        out.push_str(&format!("\nAgents ({})\n", topology.agents.len()));
        out.push_str(&"-".repeat(30));
        out.push('\n');
        for a in &topology.agents {
            out.push_str(&format!(
                "  {} [{}] {} ({}ms, {})\n",
                a.id, a.agent_type, a.transport, a.timeout_ms, a.failure_mode
            ));
        }
    }

    // Upstreams
    if !topology.upstreams.is_empty() {
        out.push_str(&format!("\nUpstreams ({})\n", topology.upstreams.len()));
        out.push_str(&"-".repeat(30));
        out.push('\n');
        for u in &topology.upstreams {
            let hc = if u.has_health_check { " [HC]" } else { "" };
            out.push_str(&format!(
                "  {} ({}, {}){}\n",
                u.id,
                u.targets.join(", "),
                u.load_balancing,
                hc
            ));
        }
    }

    // Warnings
    if !topology.warnings.is_empty() {
        out.push_str(&format!("\nWarnings ({})\n", topology.warnings.len()));
        out.push_str(&"-".repeat(30));
        out.push('\n');
        for w in &topology.warnings {
            let icon = match w.severity {
                Severity::Error => "x",
                Severity::Warn => "!",
                Severity::Info => "i",
            };
            out.push_str(&format!("  [{}] {}: {}\n", icon, w.code, w.message));
        }
    }

    out
}
