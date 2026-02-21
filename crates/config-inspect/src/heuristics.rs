//! Static analysis heuristics for configuration quality.

use std::collections::HashSet;

use serde::Serialize;
use zentinel_config::{AgentType, Config, FailureMode, Filter};

use crate::graph::Topology;
use crate::shadow::find_shadowed_routes;

// ============================================================================
// Warning Types
// ============================================================================

/// Severity level for a heuristic warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warn,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "ERROR"),
            Severity::Warn => write!(f, "WARN"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

/// A heuristic warning about the configuration.
#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub context: Vec<String>,
}

// ============================================================================
// Analysis
// ============================================================================

/// Run all heuristic analyses on a configuration.
pub fn analyze(config: &Config, topology: &Topology) -> Vec<Warning> {
    let mut warnings = Vec::new();

    check_orphan_upstreams(config, &mut warnings);
    check_orphan_agents(config, &mut warnings);
    check_orphan_filters(config, &mut warnings);
    check_no_health_check(config, &mut warnings);
    check_fail_open_security(config, &mut warnings);
    check_single_target(config, &mut warnings);
    check_catch_all_priority(config, &mut warnings);
    check_shadowed_routes(config, &mut warnings);

    // Sort: errors first, then warnings, then info
    warnings.sort_by_key(|w| match w.severity {
        Severity::Error => 0,
        Severity::Warn => 1,
        Severity::Info => 2,
    });

    let _ = topology; // Used for future graph-based analysis
    warnings
}

/// Upstreams defined but not referenced by any route.
fn check_orphan_upstreams(config: &Config, warnings: &mut Vec<Warning>) {
    let referenced: HashSet<&str> = config
        .routes
        .iter()
        .filter_map(|r| r.upstream.as_deref())
        .collect();

    for upstream_id in config.upstreams.keys() {
        if !referenced.contains(upstream_id.as_str()) {
            warnings.push(Warning {
                severity: Severity::Warn,
                code: "ORPHAN_UPSTREAM".to_string(),
                message: format!("Upstream '{}' is defined but not referenced by any route", upstream_id),
                context: vec![upstream_id.clone()],
            });
        }
    }
}

/// Agents defined but not referenced by any filter.
fn check_orphan_agents(config: &Config, warnings: &mut Vec<Warning>) {
    let referenced: HashSet<&str> = config
        .filters
        .values()
        .filter_map(|fc| match &fc.filter {
            Filter::Agent(a) => Some(a.agent.as_str()),
            _ => None,
        })
        .collect();

    for agent in &config.agents {
        if !referenced.contains(agent.id.as_str()) {
            warnings.push(Warning {
                severity: Severity::Warn,
                code: "ORPHAN_AGENT".to_string(),
                message: format!("Agent '{}' is defined but not referenced by any filter", agent.id),
                context: vec![agent.id.clone()],
            });
        }
    }
}

/// Filters defined but not referenced by any route.
fn check_orphan_filters(config: &Config, warnings: &mut Vec<Warning>) {
    let referenced: HashSet<&str> = config
        .routes
        .iter()
        .flat_map(|r| r.filters.iter().map(|f| f.as_str()))
        .collect();

    for filter_id in config.filters.keys() {
        if !referenced.contains(filter_id.as_str()) {
            warnings.push(Warning {
                severity: Severity::Info,
                code: "ORPHAN_FILTER".to_string(),
                message: format!("Filter '{}' is defined but not referenced by any route", filter_id),
                context: vec![filter_id.clone()],
            });
        }
    }
}

/// Upstreams with multiple targets but no health check.
fn check_no_health_check(config: &Config, warnings: &mut Vec<Warning>) {
    for (id, upstream) in &config.upstreams {
        if upstream.targets.len() > 1 && upstream.health_check.is_none() {
            warnings.push(Warning {
                severity: Severity::Info,
                code: "NO_HEALTH_CHECK".to_string(),
                message: format!(
                    "Upstream '{}' has {} targets but no health check configured",
                    id,
                    upstream.targets.len()
                ),
                context: vec![id.clone()],
            });
        }
    }
}

/// Security-critical agents (auth, waf) with failure_mode=open.
fn check_fail_open_security(config: &Config, warnings: &mut Vec<Warning>) {
    for agent in &config.agents {
        let is_security_agent = matches!(agent.agent_type, AgentType::Auth | AgentType::Waf);
        let is_fail_open = matches!(agent.failure_mode, FailureMode::Open);

        if is_security_agent && is_fail_open {
            warnings.push(Warning {
                severity: Severity::Warn,
                code: "FAIL_OPEN_SECURITY".to_string(),
                message: format!(
                    "Security agent '{}' ({:?}) is configured with failure_mode=open — \
                     requests will bypass {} when the agent is unavailable",
                    agent.id,
                    agent.agent_type,
                    match agent.agent_type {
                        AgentType::Auth => "authentication",
                        AgentType::Waf => "WAF protection",
                        _ => "security checks",
                    }
                ),
                context: vec![agent.id.clone()],
            });
        }
    }
}

/// Upstreams with only one target (no redundancy).
fn check_single_target(config: &Config, warnings: &mut Vec<Warning>) {
    for (id, upstream) in &config.upstreams {
        if upstream.targets.len() == 1 {
            warnings.push(Warning {
                severity: Severity::Info,
                code: "SINGLE_TARGET".to_string(),
                message: format!(
                    "Upstream '{}' has only one target ({}) — no redundancy",
                    id, upstream.targets[0].address
                ),
                context: vec![id.clone()],
            });
        }
    }
}

/// Catch-all routes (no match conditions) that aren't lowest priority.
fn check_catch_all_priority(config: &Config, warnings: &mut Vec<Warning>) {
    use zentinel_config::routes::ServiceType;
    use zentinel_common::types::Priority;

    for route in &config.routes {
        if route.matches.is_empty()
            && !matches!(route.service_type, ServiceType::Builtin)
            && !matches!(route.priority, Priority::Low)
        {
            warnings.push(Warning {
                severity: Severity::Warn,
                code: "CATCH_ALL_NOT_LAST".to_string(),
                message: format!(
                    "Route '{}' has no match conditions (catch-all) but priority={:?} — \
                     it may shadow lower-priority routes. Set priority to Low.",
                    route.id, route.priority
                ),
                context: vec![route.id.clone()],
            });
        }
    }
}

/// Routes that are shadowed by higher-priority routes.
fn check_shadowed_routes(config: &Config, warnings: &mut Vec<Warning>) {
    let shadowed = find_shadowed_routes(&config.routes);
    for (shadowed_id, shadowing_id, reason) in shadowed {
        warnings.push(Warning {
            severity: Severity::Warn,
            code: "SHADOW_ROUTE".to_string(),
            message: format!(
                "Route '{}' is shadowed by higher-priority route '{}': {}",
                shadowed_id, shadowing_id, reason
            ),
            context: vec![shadowed_id, shadowing_id],
        });
    }
}
