//! Mermaid flowchart renderer.
//!
//! Produces a Mermaid diagram that can be embedded in Markdown, GitHub READMEs,
//! or rendered with the Mermaid CLI/live editor.

use crate::graph::{NodeRef, Topology};

/// Render a topology as a Mermaid flowchart.
pub fn render(topology: &Topology) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("flowchart LR\n");

    // Subgraph: Listeners
    if !topology.listeners.is_empty() {
        out.push_str("    subgraph Listeners\n");
        for l in &topology.listeners {
            let tls_badge = if l.tls { " 🔒" } else { "" };
            out.push_str(&format!(
                "        L_{id}[\"fa:fa-plug {addr}{tls}\"]\n",
                id = sanitize(&l.id),
                addr = l.address,
                tls = tls_badge,
            ));
        }
        out.push_str("    end\n\n");
    }

    // Subgraph: Routes
    if !topology.routes.is_empty() {
        out.push_str("    subgraph Routes\n");
        for r in &topology.routes {
            let extras = build_route_extras(r);
            out.push_str(&format!(
                "        R_{id}{{\"{id}\\n{match_summary}{extras}\"}}\n",
                id = sanitize(&r.id),
                match_summary = escape_mermaid(&r.match_summary),
                extras = extras,
            ));
        }
        out.push_str("    end\n\n");
    }

    // Subgraph: Filters
    if !topology.filters.is_empty() {
        out.push_str("    subgraph Filters\n");
        for f in &topology.filters {
            let fm = f
                .failure_mode
                .as_ref()
                .map(|m| format!("\\n[{}]", m))
                .unwrap_or_default();
            out.push_str(&format!(
                "        F_{id}[/\"{id}\\n({filter_type}){fm}\"/]\n",
                id = sanitize(&f.id),
                filter_type = f.filter_type,
                fm = fm,
            ));
        }
        out.push_str("    end\n\n");
    }

    // Subgraph: Agents
    if !topology.agents.is_empty() {
        out.push_str("    subgraph Agents\n");
        for a in &topology.agents {
            out.push_str(&format!(
                "        A_{id}([\"{id}\\n{agent_type}\\n{transport}\"])\n",
                id = sanitize(&a.id),
                agent_type = a.agent_type,
                transport = escape_mermaid(&a.transport),
            ));
        }
        out.push_str("    end\n\n");
    }

    // Subgraph: Upstreams
    if !topology.upstreams.is_empty() {
        out.push_str("    subgraph Upstreams\n");
        for u in &topology.upstreams {
            let targets = u
                .targets
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if u.targets.len() > 3 {
                format!("+{} more", u.targets.len() - 3)
            } else {
                String::new()
            };
            let hc = if u.has_health_check { " ✓HC" } else { "" };
            out.push_str(&format!(
                "        U_{id}[[\"{id}\\n{targets}{more}\\n{lb}{hc}\"]]\n",
                id = sanitize(&u.id),
                targets = escape_mermaid(&targets),
                more = more,
                lb = u.load_balancing,
                hc = hc,
            ));
        }
        out.push_str("    end\n\n");
    }

    // Edges
    for edge in &topology.edges {
        let from = node_ref_id(&edge.from);
        let to = node_ref_id(&edge.to);
        match &edge.label {
            Some(label) => out.push_str(&format!("    {from} -->|{label}| {to}\n")),
            None => out.push_str(&format!("    {from} --> {to}\n")),
        }
    }

    // Warnings as comments
    if !topology.warnings.is_empty() {
        out.push('\n');
        out.push_str("    %% Warnings:\n");
        for w in &topology.warnings {
            out.push_str(&format!("    %% [{severity}] {code}: {msg}\n",
                severity = w.severity,
                code = w.code,
                msg = w.message,
            ));
        }
    }

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

fn build_route_extras(r: &crate::graph::RouteNode) -> String {
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
    if extras.is_empty() {
        String::new()
    } else {
        format!("\\n[{}]", extras.join(", "))
    }
}

/// Sanitize an ID for use as a Mermaid node identifier.
fn sanitize(id: &str) -> String {
    id.replace(['-', '.', '/'], "_")
}

/// Escape special characters for Mermaid label strings.
fn escape_mermaid(s: &str) -> String {
    s.replace('"', "'").replace('<', "‹").replace('>', "›")
}
