//! Route shadow detection.
//!
//! Detects when a higher-priority route's match conditions are a superset
//! of a lower-priority route, making the lower route unreachable.

use zentinel_common::types::Priority;
use zentinel_config::{MatchCondition, RouteConfig};

/// Find routes that are shadowed by higher-priority routes.
///
/// Returns a list of `(shadowed_route_id, shadowing_route_id, reason)`.
pub fn find_shadowed_routes(routes: &[RouteConfig]) -> Vec<(String, String, String)> {
    let mut results = Vec::new();

    // Sort routes by priority (highest first), preserving definition order within same priority
    let mut sorted: Vec<&RouteConfig> = routes.iter().collect();
    sorted.sort_by(|a, b| priority_rank(&b.priority).cmp(&priority_rank(&a.priority)));

    // For each route, check if any higher-priority route shadows it
    for (i, route) in sorted.iter().enumerate() {
        for higher in &sorted[..i] {
            // Same priority routes don't shadow each other (evaluated in definition order)
            if priority_rank(&higher.priority) == priority_rank(&route.priority) {
                continue;
            }

            if let Some(reason) = is_shadowed_by(route, higher) {
                results.push((route.id.clone(), higher.id.clone(), reason));
                break; // Only report first shadow
            }
        }
    }

    results
}

/// Check if `route` is shadowed by `higher`.
///
/// Returns `Some(reason)` if `higher` matches a superset of what `route` matches.
fn is_shadowed_by(route: &RouteConfig, higher: &RouteConfig) -> Option<String> {
    // A catch-all route (no conditions) shadows everything below it
    if higher.matches.is_empty() {
        return Some("catch-all route matches all requests".to_string());
    }

    // If the lower route has no conditions (catch-all), it can't be shadowed
    // by a route with conditions
    if route.matches.is_empty() {
        return None;
    }

    // Check if every condition in the higher route is satisfied by (or is a superset of)
    // the conditions in the lower route.
    // For path-based shadowing: /api/* shadows /api/users/*
    let path_shadow = check_path_shadow(&route.matches, &higher.matches);
    if let Some(reason) = path_shadow {
        // Also check that the higher route doesn't have additional restrictive conditions
        // that the lower route doesn't have
        let higher_has_extra = has_extra_restrictions(higher, route);
        if !higher_has_extra {
            return Some(reason);
        }
    }

    None
}

/// Check if higher route's path conditions shadow the lower route's path conditions.
fn check_path_shadow(
    lower_matches: &[MatchCondition],
    higher_matches: &[MatchCondition],
) -> Option<String> {
    let lower_paths = extract_paths(lower_matches);
    let higher_paths = extract_paths(higher_matches);

    // If higher has no path conditions, it matches all paths
    if higher_paths.is_empty() {
        return None; // Other conditions may restrict it
    }

    for (lower_type, lower_path) in &lower_paths {
        for (higher_type, higher_path) in &higher_paths {
            if path_is_superset(higher_type, higher_path, lower_type, lower_path) {
                return Some(format!(
                    "{} '{}' is a superset of {} '{}'",
                    higher_type, higher_path, lower_type, lower_path
                ));
            }
        }
    }

    None
}

/// Check if the higher route has conditions that the lower route doesn't,
/// which would mean it's more restrictive (not a true shadow).
fn has_extra_restrictions(higher: &RouteConfig, lower: &RouteConfig) -> bool {
    let higher_has_host = higher.matches.iter().any(|m| matches!(m, MatchCondition::Host(_)));
    let lower_has_host = lower.matches.iter().any(|m| matches!(m, MatchCondition::Host(_)));
    let higher_has_method = higher.matches.iter().any(|m| matches!(m, MatchCondition::Method(_)));
    let lower_has_method = lower.matches.iter().any(|m| matches!(m, MatchCondition::Method(_)));
    let higher_has_header = higher.matches.iter().any(|m| matches!(m, MatchCondition::Header { .. }));
    let lower_has_header = lower.matches.iter().any(|m| matches!(m, MatchCondition::Header { .. }));

    // If higher route has a condition type that lower doesn't, it's more restrictive
    (higher_has_host && !lower_has_host)
        || (higher_has_method && !lower_has_method)
        || (higher_has_header && !lower_has_header)
}

/// Extract path-type conditions from match conditions.
fn extract_paths(matches: &[MatchCondition]) -> Vec<(&'static str, &str)> {
    matches
        .iter()
        .filter_map(|m| match m {
            MatchCondition::PathPrefix(p) => Some(("path-prefix", p.as_str())),
            MatchCondition::Path(p) => Some(("path", p.as_str())),
            _ => None,
        })
        .collect()
}

/// Check if `higher_path` is a superset of `lower_path`.
fn path_is_superset(
    higher_type: &str,
    higher_path: &str,
    lower_type: &str,
    lower_path: &str,
) -> bool {
    match (higher_type, lower_type) {
        // prefix /api shadows prefix /api/users
        ("path-prefix", "path-prefix") => lower_path.starts_with(higher_path),
        // prefix /api shadows exact /api/users
        ("path-prefix", "path") => lower_path.starts_with(higher_path),
        // exact /api/users shadows exact /api/users
        ("path", "path") => lower_path == higher_path,
        // exact path can't shadow a prefix
        ("path", "path-prefix") => false,
        _ => false,
    }
}

fn priority_rank(p: &Priority) -> u8 {
    match p {
        Priority::Critical => 3,
        Priority::High => 2,
        Priority::Normal => 1,
        Priority::Low => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(id: &str, priority: Priority, matches: Vec<MatchCondition>) -> RouteConfig {
        RouteConfig {
            id: id.to_string(),
            priority,
            matches,
            upstream: Some("backend".to_string()),
            service_type: zentinel_config::routes::ServiceType::default(),
            policies: zentinel_config::routes::RoutePolicies::default(),
            filters: vec![],
            builtin_handler: None,
            waf_enabled: false,
            circuit_breaker: None,
            retry_policy: None,
            static_files: None,
            api_schema: None,
            inference: None,
            error_pages: None,
            websocket: false,
            websocket_inspection: false,
            shadow: None,
            fallback: None,
        }
    }

    #[test]
    fn prefix_shadows_longer_prefix() {
        let routes = vec![
            route("api", Priority::High, vec![MatchCondition::PathPrefix("/api".into())]),
            route("api-users", Priority::Normal, vec![MatchCondition::PathPrefix("/api/users".into())]),
        ];
        let shadowed = find_shadowed_routes(&routes);
        assert_eq!(shadowed.len(), 1);
        assert_eq!(shadowed[0].0, "api-users");
        assert_eq!(shadowed[0].1, "api");
    }

    #[test]
    fn same_priority_does_not_shadow() {
        let routes = vec![
            route("api", Priority::Normal, vec![MatchCondition::PathPrefix("/api".into())]),
            route("api-users", Priority::Normal, vec![MatchCondition::PathPrefix("/api/users".into())]),
        ];
        let shadowed = find_shadowed_routes(&routes);
        assert!(shadowed.is_empty());
    }

    #[test]
    fn extra_host_restriction_prevents_shadow() {
        let routes = vec![
            route(
                "api-internal",
                Priority::High,
                vec![
                    MatchCondition::PathPrefix("/api".into()),
                    MatchCondition::Host("internal.example.com".into()),
                ],
            ),
            route("api", Priority::Normal, vec![MatchCondition::PathPrefix("/api".into())]),
        ];
        let shadowed = find_shadowed_routes(&routes);
        assert!(shadowed.is_empty());
    }
}
