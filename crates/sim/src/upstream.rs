//! Upstream selection simulation
//!
//! Simulates load balancer behavior to show which upstream target
//! would be selected for a given request.

use zentinel_common::types::LoadBalancingAlgorithm;
use zentinel_config::{Config, UpstreamConfig};
use xxhash_rust::xxh3::xxh3_64;

use crate::types::{SimulatedRequest, UpstreamSelection};

/// Simulation state for load balancers that need position tracking
#[derive(Debug, Default)]
pub struct LoadBalancerSimulation {
    /// Current position for round-robin (per upstream)
    round_robin_position: std::collections::HashMap<String, usize>,
    /// Random seed for weighted selection
    seed: u64,
}

impl LoadBalancerSimulation {
    /// Create a new simulation with default state
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a simulation with a specific seed for reproducibility
    pub fn with_seed(seed: u64) -> Self {
        Self {
            round_robin_position: std::collections::HashMap::new(),
            seed,
        }
    }
}

/// Simulate upstream selection for a request
///
/// Returns which target would be selected based on the load balancer
/// algorithm configured for the upstream.
pub fn simulate_upstream_selection(
    config: &Config,
    upstream_id: &str,
    request: &SimulatedRequest,
) -> Option<UpstreamSelection> {
    // Find the upstream config (upstreams is HashMap<String, UpstreamConfig>)
    let upstream = config.upstreams.get(upstream_id)?;

    // Get list of targets
    let targets = get_targets(upstream);
    if targets.is_empty() {
        return Some(UpstreamSelection {
            upstream_id: upstream_id.to_string(),
            selected_target: "(no targets configured)".to_string(),
            load_balancer: format!("{:?}", upstream.load_balancing).to_lowercase(),
            selection_reason: "No targets available".to_string(),
            health_status: "unknown".to_string(),
        });
    }

    // Simulate selection based on algorithm
    let (selected_index, reason) = select_target(upstream, &targets, request);
    let selected_target = &targets[selected_index];

    Some(UpstreamSelection {
        upstream_id: upstream_id.to_string(),
        selected_target: selected_target.address.clone(),
        load_balancer: format!("{:?}", upstream.load_balancing).to_lowercase(),
        selection_reason: reason,
        health_status: "healthy".to_string(), // Simulated - assume healthy
    })
}

/// Target information for selection
struct TargetInfo {
    address: String,
    weight: u32,
}

/// Get targets from upstream config
fn get_targets(upstream: &UpstreamConfig) -> Vec<TargetInfo> {
    upstream
        .targets
        .iter()
        .map(|target| TargetInfo {
            address: target.address.clone(),
            weight: target.weight,
        })
        .collect()
}

/// Select a target based on the load balancer algorithm
fn select_target(
    upstream: &UpstreamConfig,
    targets: &[TargetInfo],
    request: &SimulatedRequest,
) -> (usize, String) {
    match upstream.load_balancing {
        LoadBalancingAlgorithm::RoundRobin => {
            // For simulation, use hash of request as position
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();
            (
                index,
                format!(
                    "Round robin: position {} of {} (simulated from request hash)",
                    index + 1,
                    targets.len()
                ),
            )
        }

        LoadBalancingAlgorithm::Random => {
            // Use request hash for deterministic "random"
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();
            (
                index,
                format!(
                    "Random: selected index {} (deterministic from request hash)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::Weighted => {
            // Weighted selection based on weights
            let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
            if total_weight == 0 {
                return (0, "Weighted: all weights are zero, using first target".to_string());
            }

            let hash = xxh3_64(request.cache_key().as_bytes());
            let pick = (hash % total_weight as u64) as u32;

            let mut cumulative = 0;
            for (i, target) in targets.iter().enumerate() {
                cumulative += target.weight;
                if pick < cumulative {
                    return (
                        i,
                        format!(
                            "Weighted: target {} has weight {}/{} ({:.1}% probability)",
                            i,
                            target.weight,
                            total_weight,
                            (target.weight as f64 / total_weight as f64) * 100.0
                        ),
                    );
                }
            }

            (0, "Weighted: fallback to first target".to_string())
        }

        LoadBalancingAlgorithm::LeastConnections => {
            // Can't simulate actual connections, use round-robin equivalent
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();
            (
                index,
                format!(
                    "Least connections: simulated as position {} (actual selection depends on runtime connection counts)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::ConsistentHash => {
            // Hash based on client IP or path
            let hash_key = request
                .headers
                .get("x-forwarded-for")
                .or(request.headers.get("x-real-ip"))
                .cloned()
                .unwrap_or_else(|| request.cache_key());

            let hash = xxh3_64(hash_key.as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Consistent hash: key '{}' hashes to target {} (same key always routes to same target)",
                    truncate_for_display(&hash_key, 30),
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::IpHash => {
            // IP-based hash (similar to consistent hash but simpler)
            let hash_key = request
                .headers
                .get("x-forwarded-for")
                .or(request.headers.get("x-real-ip"))
                .cloned()
                .unwrap_or_else(|| "127.0.0.1".to_string());

            let hash = xxh3_64(hash_key.as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "IP hash: client IP '{}' hashes to target {}",
                    truncate_for_display(&hash_key, 15),
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::PowerOfTwoChoices => {
            // Power of 2 choices - pick 2 random, choose "better" one
            let hash = xxh3_64(request.cache_key().as_bytes());
            let choice1 = (hash as usize) % targets.len();
            let choice2 = ((hash >> 32) as usize) % targets.len();
            let selected = choice1.min(choice2);

            (
                selected,
                format!(
                    "P2C: randomly picked targets {} and {}, selected {} (would pick lower latency in production)",
                    choice1, choice2, selected
                ),
            )
        }

        LoadBalancingAlgorithm::Adaptive => {
            // Adaptive load balancing - can't simulate without metrics
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Adaptive: simulated as index {} (actual selection uses real-time latency metrics)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::LeastTokensQueued => {
            // Token-based load balancing for inference workloads
            // Can't simulate actual token queues, use round-robin equivalent
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Least tokens queued: simulated as index {} (actual selection uses token queue depths)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::Maglev => {
            // Maglev consistent hashing - Google's algorithm
            // Uses the same key as consistent hash for simulation
            let hash_key = request
                .headers
                .get("x-forwarded-for")
                .or(request.headers.get("x-real-ip"))
                .cloned()
                .unwrap_or_else(|| request.cache_key());

            let hash = xxh3_64(hash_key.as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Maglev: key '{}' maps to target {} (minimal disruption on backend changes)",
                    truncate_for_display(&hash_key, 30),
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::LocalityAware => {
            // Locality-aware prefers same zone, but we can't simulate zones
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Locality-aware: simulated as index {} (actual selection prefers same-zone targets)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::PeakEwma => {
            // Peak EWMA uses latency metrics - can't simulate
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Peak EWMA: simulated as index {} (actual selection uses latency EWMA metrics)",
                    index
                ),
            )
        }

        LoadBalancingAlgorithm::DeterministicSubset => {
            // Deterministic subsetting for large clusters
            // Hash to select a subset, then pick from that subset
            let hash = xxh3_64(request.cache_key().as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Deterministic subset: simulated as index {} (actual selection uses subset of {} targets)",
                    index,
                    targets.len()
                ),
            )
        }

        LoadBalancingAlgorithm::WeightedLeastConnections => {
            // Weighted least connections combines weights with connection counts
            let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
            if total_weight == 0 {
                return (0, "Weighted least connections: all weights zero, using first target".to_string());
            }

            let hash = xxh3_64(request.cache_key().as_bytes());
            let pick = (hash % total_weight as u64) as u32;

            let mut cumulative = 0;
            for (i, target) in targets.iter().enumerate() {
                cumulative += target.weight;
                if pick < cumulative {
                    return (
                        i,
                        format!(
                            "Weighted least connections: target {} (weight {}/{}, actual also considers active connections)",
                            i,
                            target.weight,
                            total_weight
                        ),
                    );
                }
            }

            (0, "Weighted least connections: fallback to first target".to_string())
        }

        LoadBalancingAlgorithm::Sticky => {
            // Sticky sessions based on cookie or header
            // Similar to IP hash but uses session identifier
            let hash_key = request
                .headers
                .get("cookie")
                .or(request.headers.get("x-session-id"))
                .or(request.headers.get("x-forwarded-for"))
                .cloned()
                .unwrap_or_else(|| request.cache_key());

            let hash = xxh3_64(hash_key.as_bytes());
            let index = (hash as usize) % targets.len();

            (
                index,
                format!(
                    "Sticky: session key hashes to target {} (same session always routes to same target)",
                    index
                ),
            )
        }
    }
}

/// Truncate a string for display, adding ellipsis if needed
fn truncate_for_display(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zentinel_config::UpstreamTarget;

    fn create_upstream(targets: Vec<&str>, algorithm: LoadBalancingAlgorithm) -> UpstreamConfig {
        UpstreamConfig {
            id: "test".to_string(),
            targets: targets
                .into_iter()
                .map(|addr| UpstreamTarget {
                    address: addr.to_string(),
                    weight: 1,
                    max_requests: None,
                    metadata: Default::default(),
                })
                .collect(),
            load_balancing: algorithm,
            health_check: None,
            connection_pool: Default::default(),
            timeouts: Default::default(),
            tls: None,
            http_version: Default::default(),
        }
    }

    fn create_test_config_with_upstream(upstream: UpstreamConfig) -> Config {
        // Create a minimal config via KDL parsing
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
        "#;
        let mut config = Config::from_kdl(kdl).expect("Failed to create test config");
        config.upstreams.insert("backend".to_string(), upstream);
        config
    }

    fn create_empty_test_config() -> Config {
        let kdl = r#"
            server { }
            listeners {
                listener "http" {
                    address "0.0.0.0:8080"
                }
            }
        "#;
        Config::from_kdl(kdl).expect("Failed to create test config")
    }

    #[test]
    fn test_round_robin_selection() {
        let upstream = create_upstream(
            vec!["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
            LoadBalancingAlgorithm::RoundRobin,
        );

        let config = create_test_config_with_upstream(upstream);

        let request = SimulatedRequest::new("GET", "example.com", "/api/users");
        let selection = simulate_upstream_selection(&config, "backend", &request);

        assert!(selection.is_some());
        let sel = selection.unwrap();
        assert_eq!(sel.upstream_id, "backend");
        assert!(sel.selection_reason.contains("Round robin"));
    }

    #[test]
    fn test_consistent_hash_same_request() {
        let upstream = create_upstream(
            vec!["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"],
            LoadBalancingAlgorithm::ConsistentHash,
        );

        let config = create_test_config_with_upstream(upstream);

        let request = SimulatedRequest::new("GET", "example.com", "/api/users");

        // Same request should always select same target
        let sel1 = simulate_upstream_selection(&config, "backend", &request).unwrap();
        let sel2 = simulate_upstream_selection(&config, "backend", &request).unwrap();

        assert_eq!(sel1.selected_target, sel2.selected_target);
    }

    #[test]
    fn test_weighted_selection() {
        let mut upstream = create_upstream(
            vec!["10.0.0.1:8080", "10.0.0.2:8080"],
            LoadBalancingAlgorithm::Weighted,
        );

        // First target has weight 9, second has weight 1
        upstream.targets[0].weight = 9;
        upstream.targets[1].weight = 1;

        let config = create_test_config_with_upstream(upstream);

        let request = SimulatedRequest::new("GET", "example.com", "/api/users");
        let selection = simulate_upstream_selection(&config, "backend", &request);

        assert!(selection.is_some());
        let sel = selection.unwrap();
        assert!(sel.selection_reason.contains("Weighted"));
    }

    #[test]
    fn test_missing_upstream() {
        let config = create_empty_test_config();
        let request = SimulatedRequest::new("GET", "example.com", "/api/users");

        let selection = simulate_upstream_selection(&config, "nonexistent", &request);
        assert!(selection.is_none());
    }
}
