//! Zentinel Configuration Simulator
//!
//! A WASM-compatible simulation engine for Zentinel proxy configurations.
//! This crate enables in-browser config validation and route decision tracing
//! without running the actual proxy.
//!
//! # Features
//!
//! - **Config Validation**: Parse and validate KDL configurations with rich error messages
//! - **Route Simulation**: Determine which route matches a given request
//! - **Decision Tracing**: Explain why a route matched (or didn't match)
//! - **Policy Preview**: Show applied policies, timeouts, and limits
//! - **Upstream Selection**: Simulate load balancer behavior (deterministic)
//! - **Agent Hooks**: Visualize which agents would fire and in what order
//!
//! # WASM Usage
//!
//! This crate is designed to compile to WebAssembly. Use the `zentinel-playground-wasm`
//! crate for JavaScript bindings.

pub mod agents;
mod matcher;
pub mod stateful;
mod trace;
mod types;
mod upstream;

pub use matcher::{RouteMatcher, RouteMatchError};
pub use trace::{MatchStep, MatchStepResult, ConditionDetail};
pub use types::{
    AgentHook, AppliedPolicies, MatchedRoute, RouteDecision, SimulatedRequest,
    UpstreamSelection, ValidationError, ValidationResult, ValidationSeverity, Warning,
};
pub use upstream::{simulate_upstream_selection, LoadBalancerSimulation};
pub use stateful::{
    simulate_sequence, CacheSnapshot, CircuitBreakerSnapshot, FinalState, RequestResult,
    SimulationSummary, StatefulSimulationResult, StateTransition, TimestampedRequest,
    TokenBucketSnapshot,
};
pub use agents::{
    simulate_with_agents, AgentChainStep, AgentDecision, AgentSimulationResult, AuditEntry,
    AuditInfo, BlockResponse, ChallengeInfo, HeaderMutation, MockAgentResponse, TransformedRequest,
};

use zentinel_config::Config;

/// Validate a KDL configuration string
///
/// Returns a `ValidationResult` containing any errors, warnings, and the
/// normalized/effective configuration if parsing succeeded.
pub fn validate(kdl_config: &str) -> ValidationResult {
    match Config::from_kdl(kdl_config) {
        Ok(config) => {
            let mut warnings = Vec::new();

            // Check for common misconfigurations
            warnings.extend(lint_config(&config));

            ValidationResult {
                valid: true,
                errors: Vec::new(),
                warnings,
                effective_config: Some(config),
            }
        }
        Err(e) => {
            let error = ValidationError {
                message: e.to_string(),
                severity: ValidationSeverity::Error,
                location: None,
                hint: None,
            };

            ValidationResult {
                valid: false,
                errors: vec![error],
                warnings: Vec::new(),
                effective_config: None,
            }
        }
    }
}

/// Simulate routing a request through the configuration
///
/// Returns a `RouteDecision` containing:
/// - The matched route (if any)
/// - A trace of which routes were evaluated and why they matched/didn't match
/// - Applied policies from the matched route
/// - Simulated upstream selection
/// - Which agent hooks would fire
pub fn simulate(config: &Config, request: &SimulatedRequest) -> RouteDecision {
    // Build route matcher
    // Note: default_route is per-listener, not global. For simulation, we don't use a default.
    let matcher = match RouteMatcher::new(&config.routes, None) {
        Ok(m) => m,
        Err(e) => {
            return RouteDecision {
                matched_route: None,
                match_trace: Vec::new(),
                applied_policies: None,
                upstream_selection: None,
                agent_hooks: Vec::new(),
                warnings: vec![Warning {
                    code: "MATCHER_ERROR".to_string(),
                    message: format!("Failed to compile route matcher: {}", e),
                }],
            };
        }
    };

    // Perform route matching with trace
    let (matched_route, match_trace) = matcher.match_with_trace(request);

    // Extract policies and build response
    let (applied_policies, upstream_selection, agent_hooks, warnings) =
        if let Some(ref route) = matched_route {
            let policies = extract_policies(route, config);
            let upstream = route
                .upstream
                .as_ref()
                .and_then(|id| simulate_upstream_selection(config, id, request));
            let hooks = extract_agent_hooks(route, config);
            let warns = generate_warnings(route, config, request);

            (Some(policies), upstream, hooks, warns)
        } else {
            (None, None, Vec::new(), Vec::new())
        };

    RouteDecision {
        matched_route,
        match_trace,
        applied_policies,
        upstream_selection,
        agent_hooks,
        warnings,
    }
}

/// Get the effective/normalized configuration with all defaults applied
pub fn get_effective_config(config: &Config) -> serde_json::Value {
    serde_json::to_value(config).unwrap_or(serde_json::Value::Null)
}

// ============================================================================
// Internal helpers
// ============================================================================

/// Lint configuration for common issues
fn lint_config(config: &Config) -> Vec<Warning> {
    let mut warnings = Vec::new();

    // Check for routes without upstreams (unless static/builtin)
    for route in &config.routes {
        use zentinel_config::ServiceType;

        if route.upstream.is_none()
            && route.static_files.is_none()
            && route.service_type != ServiceType::Builtin
            && route.service_type != ServiceType::Static
        {
            warnings.push(Warning {
                code: "ROUTE_NO_UPSTREAM".to_string(),
                message: format!("Route '{}' has no upstream defined", route.id),
            });
        }
    }

    // Check for undefined upstream references
    for route in &config.routes {
        if let Some(ref upstream) = route.upstream {
            if !config.upstreams.contains_key(upstream) {
                warnings.push(Warning {
                    code: "UNDEFINED_UPSTREAM".to_string(),
                    message: format!(
                        "Route '{}' references undefined upstream '{}'",
                        route.id, upstream
                    ),
                });
            }
        }
    }

    // Check for duplicate route IDs
    let mut seen_ids = std::collections::HashSet::new();
    for route in &config.routes {
        if !seen_ids.insert(&route.id) {
            warnings.push(Warning {
                code: "DUPLICATE_ROUTE_ID".to_string(),
                message: format!("Duplicate route ID: '{}'", route.id),
            });
        }
    }

    warnings
}

/// Extract applied policies from a matched route
fn extract_policies(route: &MatchedRoute, config: &Config) -> AppliedPolicies {
    // Find the full route config
    let route_config = config.routes.iter().find(|r| r.id == route.id);

    if let Some(rc) = route_config {
        AppliedPolicies {
            timeout_secs: rc.policies.timeout_secs,
            max_body_size: rc.policies.max_body_size.map(|b| b.to_string()),
            failure_mode: format!("{:?}", rc.policies.failure_mode).to_lowercase(),
            rate_limit: rc.policies.rate_limit.as_ref().map(|rl| types::RateLimitInfo {
                requests_per_second: rl.requests_per_second,
                burst: rl.burst,
                key: format!("{:?}", rl.key),
            }),
            cache: rc.policies.cache.as_ref().map(|c| types::CacheInfo {
                enabled: c.enabled,
                ttl_secs: c.default_ttl_secs,
            }),
            buffer_requests: rc.policies.buffer_requests,
            buffer_responses: rc.policies.buffer_responses,
        }
    } else {
        AppliedPolicies::default()
    }
}

/// Extract agent hooks from route configuration
fn extract_agent_hooks(route: &MatchedRoute, config: &Config) -> Vec<AgentHook> {
    let mut hooks = Vec::new();

    // Find the full route config
    let route_config = config.routes.iter().find(|r| r.id == route.id);

    if let Some(rc) = route_config {
        // Get filters from route
        for filter_id in &rc.filters {
            // Look up filter in config (filters is HashMap<String, FilterConfig>)
            if let Some(filter_config) = config.filters.get(filter_id) {
                // Check if it's an agent filter
                if let zentinel_config::Filter::Agent(agent_filter) = &filter_config.filter {
                    // Find agent config
                    let agent_config = config.agents.iter().find(|a| a.id == agent_filter.agent);

                    hooks.push(AgentHook {
                        agent_id: agent_filter.agent.clone(),
                        hook: "on_request_headers".to_string(),
                        timeout_ms: agent_filter.timeout_ms.unwrap_or(
                            agent_config.map(|a| a.timeout_ms).unwrap_or(1000)
                        ),
                        failure_mode: agent_filter.failure_mode
                            .map(|fm| format!("{:?}", fm).to_lowercase())
                            .unwrap_or_else(|| "closed".to_string()),
                        body_inspection: None,
                    });
                }
            }
        }

        // WAF creates hooks if enabled
        if rc.waf_enabled {
            if let Some(ref waf_config) = config.waf {
                // WAF uses a dedicated agent - we'll use "waf" as the conventional agent ID
                hooks.push(AgentHook {
                    agent_id: "waf".to_string(),
                    hook: "on_request_headers".to_string(),
                    timeout_ms: 500, // Default WAF timeout
                    failure_mode: "closed".to_string(), // WAF should fail closed by default
                    body_inspection: None,
                });

                if waf_config.body_inspection.inspect_request_body {
                    hooks.push(AgentHook {
                        agent_id: "waf".to_string(),
                        hook: "on_request_body".to_string(),
                        timeout_ms: 1000,
                        failure_mode: "closed".to_string(),
                        body_inspection: Some(types::BodyInspectionInfo {
                            enabled: true,
                            max_bytes: waf_config.body_inspection.max_inspection_bytes,
                        }),
                    });
                }
            }
        }
    }

    hooks
}

/// Generate warnings for potential issues with the request/route combination
fn generate_warnings(
    route: &MatchedRoute,
    config: &Config,
    request: &SimulatedRequest,
) -> Vec<Warning> {
    let mut warnings = Vec::new();

    // Find the full route config
    let route_config = config.routes.iter().find(|r| r.id == route.id);

    if let Some(rc) = route_config {
        // Shadow config on POST without body buffering
        if let Some(ref shadow) = rc.shadow {
            if !shadow.buffer_body
                && ["POST", "PUT", "PATCH"].contains(&request.method.as_str())
            {
                warnings.push(Warning {
                    code: "SHADOW_NO_BODY_BUFFER".to_string(),
                    message: format!(
                        "Shadow config on {} route without buffer_body=true; request bodies won't be mirrored",
                        request.method
                    ),
                });
            }
        }

        // WebSocket inspection without WebSocket enabled
        if rc.websocket_inspection && !rc.websocket {
            warnings.push(Warning {
                code: "WEBSOCKET_INSPECTION_WITHOUT_WEBSOCKET".to_string(),
                message: "websocket_inspection is enabled but websocket is disabled".to_string(),
            });
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_config() {
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
            routes {
                route "api" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:8080"
                }
            }
        "#;

        let result = validate(kdl);
        assert!(result.valid, "Config should be valid: {:?}", result.errors);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_config() {
        let kdl = r#"
            server { invalid_field 123 }
        "#;

        let result = validate(kdl);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_simulate_basic_route() {
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
            routes {
                route "api" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "backend"
                }
                route "static" {
                    matches {
                        path-prefix "/static"
                    }
                    upstream "static-backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:8080"
                }
                upstream "static-backend" {
                    target "127.0.0.1:8081"
                }
            }
        "#;

        let result = validate(kdl);
        assert!(result.valid, "Config should be valid: {:?}", result.errors);

        let config = result.effective_config.unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");
        let decision = simulate(&config, &request);

        assert!(decision.matched_route.is_some());
        assert_eq!(decision.matched_route.unwrap().id, "api");
    }

    #[test]
    fn test_simulate_no_match() {
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
            routes {
                route "api" {
                    matches {
                        path-prefix "/api"
                    }
                    upstream "backend"
                }
            }
            upstreams {
                upstream "backend" {
                    target "127.0.0.1:8080"
                }
            }
        "#;

        let result = validate(kdl);
        assert!(result.valid, "Config should be valid: {:?}", result.errors);

        let config = result.effective_config.unwrap();
        let request = SimulatedRequest::new("GET", "example.com", "/other/path");
        let decision = simulate(&config, &request);

        assert!(
            decision.matched_route.is_none(),
            "Expected no match but got: {:?}",
            decision.matched_route
        );
        assert!(!decision.match_trace.is_empty()); // Should have trace showing why no match
    }
}
