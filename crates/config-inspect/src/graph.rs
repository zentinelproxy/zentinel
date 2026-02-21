//! Topology graph construction from parsed configuration.

use serde::Serialize;
use zentinel_config::{
    AgentConfig, AgentTransport, Config, Filter, FilterConfig, ListenerConfig, RouteConfig,
    UpstreamConfig,
};

use crate::heuristics::Warning;

// ============================================================================
// Topology Types
// ============================================================================

/// Complete topology of a Zentinel configuration.
#[derive(Debug, Clone, Serialize)]
pub struct Topology {
    pub listeners: Vec<ListenerNode>,
    pub routes: Vec<RouteNode>,
    pub filters: Vec<FilterNode>,
    pub agents: Vec<AgentNode>,
    pub upstreams: Vec<UpstreamNode>,
    pub edges: Vec<Edge>,
    pub warnings: Vec<Warning>,
}

/// A network listener (entry point).
#[derive(Debug, Clone, Serialize)]
pub struct ListenerNode {
    pub id: String,
    pub address: String,
    pub protocol: String,
    pub tls: bool,
}

/// A routing rule.
#[derive(Debug, Clone, Serialize)]
pub struct RouteNode {
    pub id: String,
    pub priority: String,
    pub match_summary: String,
    pub service_type: String,
    pub has_circuit_breaker: bool,
    pub has_retry: bool,
    pub websocket: bool,
}

/// A named filter instance.
#[derive(Debug, Clone, Serialize)]
pub struct FilterNode {
    pub id: String,
    pub filter_type: String,
    pub failure_mode: Option<String>,
}

/// An external processing agent.
#[derive(Debug, Clone, Serialize)]
pub struct AgentNode {
    pub id: String,
    pub agent_type: String,
    pub transport: String,
    pub events: Vec<String>,
    pub failure_mode: String,
    pub timeout_ms: u64,
}

/// An upstream backend pool.
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamNode {
    pub id: String,
    pub targets: Vec<String>,
    pub load_balancing: String,
    pub has_health_check: bool,
}

/// A directed edge between two nodes in the topology.
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: NodeRef,
    pub to: NodeRef,
    pub label: Option<String>,
}

/// Reference to a node in the topology graph.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
#[serde(tag = "type", content = "id")]
pub enum NodeRef {
    Listener(String),
    Route(String),
    Filter(String),
    Agent(String),
    Upstream(String),
}

// ============================================================================
// Graph Construction
// ============================================================================

/// Build a topology graph from a parsed configuration.
pub fn build_topology(config: &Config) -> Topology {
    let listeners = build_listener_nodes(&config.listeners);
    let routes = build_route_nodes(&config.routes);
    let filters = build_filter_nodes(&config.filters);
    let agents = build_agent_nodes(&config.agents);
    let upstreams = build_upstream_nodes(&config.upstreams);
    let edges = build_edges(config);

    Topology {
        listeners,
        routes,
        filters,
        agents,
        upstreams,
        edges,
        warnings: Vec::new(),
    }
}

fn build_listener_nodes(listeners: &[ListenerConfig]) -> Vec<ListenerNode> {
    listeners
        .iter()
        .map(|l| ListenerNode {
            id: l.id.clone(),
            address: l.address.clone(),
            protocol: format!("{:?}", l.protocol),
            tls: l.tls.is_some(),
        })
        .collect()
}

fn build_route_nodes(routes: &[RouteConfig]) -> Vec<RouteNode> {
    routes
        .iter()
        .map(|r| RouteNode {
            id: r.id.clone(),
            priority: format!("{:?}", r.priority),
            match_summary: summarize_matches(&r.matches),
            service_type: format!("{:?}", r.service_type),
            has_circuit_breaker: r.circuit_breaker.is_some(),
            has_retry: r.retry_policy.is_some(),
            websocket: r.websocket,
        })
        .collect()
}

fn build_filter_nodes(
    filters: &std::collections::HashMap<String, FilterConfig>,
) -> Vec<FilterNode> {
    let mut nodes: Vec<_> = filters
        .values()
        .map(|fc| {
            let failure_mode = match &fc.filter {
                Filter::Agent(a) => a.failure_mode.as_ref().map(|fm| format!("{:?}", fm)),
                _ => None,
            };
            FilterNode {
                id: fc.id.clone(),
                filter_type: fc.filter.type_name().to_string(),
                failure_mode,
            }
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes
}

fn build_agent_nodes(agents: &[AgentConfig]) -> Vec<AgentNode> {
    agents
        .iter()
        .map(|a| AgentNode {
            id: a.id.clone(),
            agent_type: format!("{:?}", a.agent_type),
            transport: summarize_transport(&a.transport),
            events: a.events.iter().map(|e| format!("{:?}", e)).collect(),
            failure_mode: format!("{:?}", a.failure_mode),
            timeout_ms: a.timeout_ms,
        })
        .collect()
}

fn build_upstream_nodes(
    upstreams: &std::collections::HashMap<String, UpstreamConfig>,
) -> Vec<UpstreamNode> {
    let mut nodes: Vec<_> = upstreams
        .iter()
        .map(|(id, u)| UpstreamNode {
            id: id.clone(),
            targets: u
                .targets
                .iter()
                .map(|t| {
                    if t.weight != 1 {
                        format!("{} (w={})", t.address, t.weight)
                    } else {
                        t.address.clone()
                    }
                })
                .collect(),
            load_balancing: format!("{:?}", u.load_balancing),
            has_health_check: u.health_check.is_some(),
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes
}

fn build_edges(config: &Config) -> Vec<Edge> {
    let mut edges = Vec::new();

    // Listener → Route: all listeners connect to all routes
    // (In practice, routes are matched by conditions, not assigned to listeners,
    //  so we show the relationship as "listener serves routes")
    for listener in &config.listeners {
        for route in &config.routes {
            edges.push(Edge {
                from: NodeRef::Listener(listener.id.clone()),
                to: NodeRef::Route(route.id.clone()),
                label: None,
            });
        }
    }

    // Route → Filter chain (ordered)
    for route in &config.routes {
        for (i, filter_id) in route.filters.iter().enumerate() {
            edges.push(Edge {
                from: NodeRef::Route(route.id.clone()),
                to: NodeRef::Filter(filter_id.clone()),
                label: Some(format!("{}", i + 1)),
            });
        }
    }

    // Route → Upstream
    for route in &config.routes {
        if let Some(upstream_id) = &route.upstream {
            edges.push(Edge {
                from: NodeRef::Route(route.id.clone()),
                to: NodeRef::Upstream(upstream_id.clone()),
                label: None,
            });
        }
    }

    // Filter (agent type) → Agent
    for fc in config.filters.values() {
        if let Filter::Agent(agent_filter) = &fc.filter {
            edges.push(Edge {
                from: NodeRef::Filter(fc.id.clone()),
                to: NodeRef::Agent(agent_filter.agent.clone()),
                label: None,
            });
        }
    }

    edges
}

// ============================================================================
// Summarization Helpers
// ============================================================================

fn summarize_matches(matches: &[zentinel_config::MatchCondition]) -> String {
    use zentinel_config::MatchCondition;

    if matches.is_empty() {
        return "* (catch-all)".to_string();
    }

    let parts: Vec<String> = matches
        .iter()
        .map(|m| match m {
            MatchCondition::PathPrefix(p) => format!("{p}*"),
            MatchCondition::Path(p) => p.clone(),
            MatchCondition::PathRegex(r) => format!("~{r}"),
            MatchCondition::Host(h) => format!("host:{h}"),
            MatchCondition::Header { name, value } => match value {
                Some(v) => format!("{name}={v}"),
                None => format!("{name}:*"),
            },
            MatchCondition::Method(methods) => methods.join(","),
            MatchCondition::QueryParam { name, value } => match value {
                Some(v) => format!("?{name}={v}"),
                None => format!("?{name}"),
            },
        })
        .collect();

    parts.join(" + ")
}

fn summarize_transport(transport: &AgentTransport) -> String {
    match transport {
        AgentTransport::UnixSocket { path } => format!("uds://{}", path.display()),
        AgentTransport::Grpc { address, .. } => format!("grpc://{address}"),
        AgentTransport::Http { url, .. } => url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::MatchCondition;

    #[test]
    fn summarize_empty_matches_is_catch_all() {
        assert_eq!(summarize_matches(&[]), "* (catch-all)");
    }

    #[test]
    fn summarize_path_prefix() {
        let matches = vec![MatchCondition::PathPrefix("/api/v2".into())];
        assert_eq!(summarize_matches(&matches), "/api/v2*");
    }

    #[test]
    fn summarize_compound_match() {
        let matches = vec![
            MatchCondition::Host("api.example.com".into()),
            MatchCondition::PathPrefix("/api".into()),
            MatchCondition::Method(vec!["GET".into(), "POST".into()]),
        ];
        assert_eq!(
            summarize_matches(&matches),
            "host:api.example.com + /api* + GET,POST"
        );
    }
}
