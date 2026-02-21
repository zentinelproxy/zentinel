//! Graphviz DOT renderer.
//!
//! Produces a DOT graph that can be rendered with Graphviz:
//!   zentinel-inspect config.kdl --format dot | dot -Tpng -o topology.png
//!   zentinel-inspect config.kdl --format dot | dot -Tsvg -o topology.svg

use crate::graph::{NodeRef, Topology};

/// Render a topology as a Graphviz DOT digraph.
pub fn render(topology: &Topology) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("digraph zentinel {\n");
    out.push_str("    rankdir=LR;\n");
    out.push_str("    fontname=\"Helvetica\";\n");
    out.push_str("    node [fontname=\"Helvetica\", fontsize=10];\n");
    out.push_str("    edge [fontname=\"Helvetica\", fontsize=9];\n\n");

    // Listeners cluster
    if !topology.listeners.is_empty() {
        out.push_str("    subgraph cluster_listeners {\n");
        out.push_str("        label=\"Listeners\";\n");
        out.push_str("        style=dashed;\n");
        out.push_str("        color=\"#666666\";\n");
        for l in &topology.listeners {
            let tls = if l.tls { " [TLS]" } else { "" };
            out.push_str(&format!(
                "        L_{} [label=\"{}\\n{}{}\", shape=invhouse, style=filled, fillcolor=\"#e3f2fd\"];\n",
                sanitize(&l.id),
                escape(&l.id),
                escape(&l.address),
                tls,
            ));
        }
        out.push_str("    }\n\n");
    }

    // Routes cluster
    if !topology.routes.is_empty() {
        out.push_str("    subgraph cluster_routes {\n");
        out.push_str("        label=\"Routes\";\n");
        out.push_str("        style=dashed;\n");
        out.push_str("        color=\"#666666\";\n");
        for r in &topology.routes {
            let mut extras = Vec::new();
            if r.has_circuit_breaker {
                extras.push("CB");
            }
            if r.has_retry {
                extras.push("Retry");
            }
            if r.websocket {
                extras.push("WS");
            }
            let extras_str = if extras.is_empty() {
                String::new()
            } else {
                format!("\\n[{}]", extras.join(", "))
            };
            out.push_str(&format!(
                "        R_{} [label=\"{}\\n{}\\n[{}]{}\", shape=diamond, style=filled, fillcolor=\"#fff9c4\"];\n",
                sanitize(&r.id),
                escape(&r.id),
                escape(&r.match_summary),
                r.priority,
                extras_str,
            ));
        }
        out.push_str("    }\n\n");
    }

    // Filters cluster
    if !topology.filters.is_empty() {
        out.push_str("    subgraph cluster_filters {\n");
        out.push_str("        label=\"Filters\";\n");
        out.push_str("        style=dashed;\n");
        out.push_str("        color=\"#666666\";\n");
        for f in &topology.filters {
            let fm = f
                .failure_mode
                .as_ref()
                .map(|m| format!("\\n[{}]", m))
                .unwrap_or_default();
            out.push_str(&format!(
                "        F_{} [label=\"{}\\n({}){}\", shape=parallelogram, style=filled, fillcolor=\"#f3e5f5\"];\n",
                sanitize(&f.id),
                escape(&f.id),
                f.filter_type,
                fm,
            ));
        }
        out.push_str("    }\n\n");
    }

    // Agents cluster
    if !topology.agents.is_empty() {
        out.push_str("    subgraph cluster_agents {\n");
        out.push_str("        label=\"Agents\";\n");
        out.push_str("        style=dashed;\n");
        out.push_str("        color=\"#666666\";\n");
        for a in &topology.agents {
            out.push_str(&format!(
                "        A_{} [label=\"{}\\n{}\\n{}\", shape=component, style=filled, fillcolor=\"#e8f5e9\"];\n",
                sanitize(&a.id),
                escape(&a.id),
                a.agent_type,
                escape(&a.transport),
            ));
        }
        out.push_str("    }\n\n");
    }

    // Upstreams cluster
    if !topology.upstreams.is_empty() {
        out.push_str("    subgraph cluster_upstreams {\n");
        out.push_str("        label=\"Upstreams\";\n");
        out.push_str("        style=dashed;\n");
        out.push_str("        color=\"#666666\";\n");
        for u in &topology.upstreams {
            let targets: String = u
                .targets
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join("\\n");
            let more = if u.targets.len() > 3 {
                format!("\\n+{} more", u.targets.len() - 3)
            } else {
                String::new()
            };
            let hc = if u.has_health_check { " [HC]" } else { "" };
            out.push_str(&format!(
                "        U_{} [label=\"{}\\n{}{}\\n{}{}\", shape=cylinder, style=filled, fillcolor=\"#fce4ec\"];\n",
                sanitize(&u.id),
                escape(&u.id),
                targets,
                more,
                u.load_balancing,
                hc,
            ));
        }
        out.push_str("    }\n\n");
    }

    // Edges
    out.push_str("    // Edges\n");
    for edge in &topology.edges {
        let from = node_ref_id(&edge.from);
        let to = node_ref_id(&edge.to);
        match &edge.label {
            Some(label) => {
                out.push_str(&format!("    {} -> {} [label=\"{}\"];\n", from, to, label))
            }
            None => out.push_str(&format!("    {} -> {};\n", from, to)),
        }
    }

    // Warnings as comments
    if !topology.warnings.is_empty() {
        out.push('\n');
        for w in &topology.warnings {
            out.push_str(&format!(
                "    // [{severity}] {code}: {msg}\n",
                severity = w.severity,
                code = w.code,
                msg = w.message,
            ));
        }
    }

    out.push_str("}\n");
    out
}

fn node_ref_id(nr: &NodeRef) -> String {
    match nr {
        NodeRef::Listener(id) => format!("L_{}", sanitize(id)),
        NodeRef::Route(id) => format!("R_{}", sanitize(id)),
        NodeRef::Filter(id) => format!("F_{}", sanitize(id)),
        NodeRef::Agent(id) => format!("A_{}", sanitize(id)),
        NodeRef::Upstream(id) => format!("U_{}", sanitize(id)),
    }
}

fn sanitize(id: &str) -> String {
    id.replace(['-', '.', '/', ' '], "_")
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
