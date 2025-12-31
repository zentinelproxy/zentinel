//! Upstream KDL parsing.

use anyhow::Result;
use std::collections::HashMap;
use tracing::trace;

use sentinel_common::types::{HealthCheckType, LoadBalancingAlgorithm};

use crate::upstreams::*;

use super::helpers::{get_first_arg_string, get_int_entry};

/// Parse upstreams configuration block
pub fn parse_upstreams(node: &kdl::KdlNode) -> Result<HashMap<String, UpstreamConfig>> {
    trace!("Parsing upstreams configuration block");
    let mut upstreams = HashMap::new();

    if let Some(children) = node.children() {
        for child in children.nodes() {
            if child.name().value() == "upstream" {
                let id = get_first_arg_string(child).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Upstream requires an ID argument, e.g., upstream \"backend\" {{ ... }}"
                    )
                })?;

                trace!(upstream_id = %id, "Parsing upstream");

                // Parse targets
                let mut targets = Vec::new();
                if let Some(upstream_children) = child.children() {
                    for target_node in upstream_children.nodes() {
                        if target_node.name().value() == "target" {
                            if let Some(address) = get_first_arg_string(target_node) {
                                let weight = target_node
                                    .entries()
                                    .iter()
                                    .find(|e| e.name().map(|n| n.value()) == Some("weight"))
                                    .and_then(|e| e.value().as_integer())
                                    .map(|v| v as u32)
                                    .unwrap_or(1);

                                trace!(
                                    upstream_id = %id,
                                    address = %address,
                                    weight = weight,
                                    "Parsed target"
                                );

                                targets.push(UpstreamTarget {
                                    address,
                                    weight,
                                    max_requests: None,
                                    metadata: HashMap::new(),
                                });
                            }
                        }
                    }
                }

                if targets.is_empty() {
                    return Err(anyhow::anyhow!(
                        "Upstream '{}' requires at least one target, e.g., target \"127.0.0.1:8081\"",
                        id
                    ));
                }

                // Parse load balancing algorithm
                let load_balancing = child
                    .children()
                    .and_then(|c| {
                        c.nodes()
                            .iter()
                            .find(|n| n.name().value() == "load-balancing")
                    })
                    .and_then(get_first_arg_string)
                    .map(|s| parse_load_balancing(&s))
                    .unwrap_or(LoadBalancingAlgorithm::RoundRobin);

                // Parse health check configuration
                let health_check = child
                    .children()
                    .and_then(|c| {
                        c.nodes()
                            .iter()
                            .find(|n| n.name().value() == "health-check")
                    })
                    .and_then(|n| parse_health_check(n).ok());

                if health_check.is_some() {
                    trace!(
                        upstream_id = %id,
                        "Parsed health check configuration"
                    );
                }

                // Parse HTTP version configuration
                let http_version = child
                    .children()
                    .and_then(|c| {
                        c.nodes()
                            .iter()
                            .find(|n| n.name().value() == "http-version")
                    })
                    .map(parse_http_version)
                    .unwrap_or_default();

                if http_version.max_version >= 2 {
                    trace!(
                        upstream_id = %id,
                        max_version = http_version.max_version,
                        "HTTP/2 enabled for upstream"
                    );
                }

                // Parse connection pool configuration
                let connection_pool = child
                    .children()
                    .and_then(|c| {
                        c.nodes()
                            .iter()
                            .find(|n| n.name().value() == "connection-pool")
                    })
                    .map(parse_connection_pool)
                    .unwrap_or_default();

                // Parse timeouts configuration
                let timeouts = child
                    .children()
                    .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "timeouts"))
                    .map(parse_upstream_timeouts)
                    .unwrap_or_default();

                trace!(
                    upstream_id = %id,
                    target_count = targets.len(),
                    load_balancing = ?load_balancing,
                    has_health_check = health_check.is_some(),
                    http_version = http_version.max_version,
                    max_connections = connection_pool.max_connections,
                    connect_timeout = timeouts.connect_secs,
                    "Parsed upstream"
                );

                upstreams.insert(
                    id.clone(),
                    UpstreamConfig {
                        id,
                        targets,
                        load_balancing,
                        health_check,
                        connection_pool,
                        timeouts,
                        tls: None,
                        http_version,
                    },
                );
            }
        }
    }

    trace!(
        upstream_count = upstreams.len(),
        "Finished parsing upstreams"
    );
    Ok(upstreams)
}

/// Parse load balancing algorithm from string
fn parse_load_balancing(s: &str) -> LoadBalancingAlgorithm {
    match s.to_lowercase().as_str() {
        "round_robin" | "roundrobin" => LoadBalancingAlgorithm::RoundRobin,
        "least_connections" | "leastconnections" => LoadBalancingAlgorithm::LeastConnections,
        "weighted" => LoadBalancingAlgorithm::Weighted,
        "ip_hash" | "iphash" => LoadBalancingAlgorithm::IpHash,
        "random" => LoadBalancingAlgorithm::Random,
        "consistent_hash" | "consistenthash" => LoadBalancingAlgorithm::ConsistentHash,
        "power_of_two_choices" | "p2c" => LoadBalancingAlgorithm::PowerOfTwoChoices,
        "adaptive" => LoadBalancingAlgorithm::Adaptive,
        _ => LoadBalancingAlgorithm::RoundRobin,
    }
}

/// Parse HTTP version configuration
///
/// Example KDL:
/// ```kdl
/// http-version {
///     min-version 1
///     max-version 2
///     h2-ping-interval 30
///     max-h2-streams 100
/// }
/// ```
fn parse_http_version(node: &kdl::KdlNode) -> HttpVersionConfig {
    // Helper to get integer value from a child node's first argument
    let get_child_int = |name: &str| -> Option<i128> {
        node.children()
            .and_then(|c| c.nodes().iter().find(|n| n.name().value() == name))
            .and_then(|n| n.entries().first())
            .and_then(|e| e.value().as_integer())
    };

    let min_version = get_child_int("min-version").map(|v| v as u8).unwrap_or(1);

    let max_version = get_child_int("max-version").map(|v| v as u8).unwrap_or(2); // Default to HTTP/2 support

    let h2_ping_interval_secs = get_child_int("h2-ping-interval")
        .map(|v| v as u64)
        .unwrap_or(0);

    let max_h2_streams = get_child_int("max-h2-streams")
        .map(|v| v as usize)
        .unwrap_or(100);

    HttpVersionConfig {
        min_version,
        max_version,
        h2_ping_interval_secs,
        max_h2_streams,
    }
}

/// Parse connection pool configuration
///
/// Example KDL:
/// ```kdl
/// connection-pool {
///     max-connections 100
///     max-idle 20
///     idle-timeout 60
///     max-lifetime 3600
/// }
/// ```
fn parse_connection_pool(node: &kdl::KdlNode) -> ConnectionPoolConfig {
    let max_connections = get_int_entry(node, "max-connections")
        .map(|v| v as usize)
        .unwrap_or(100);

    let max_idle = get_int_entry(node, "max-idle")
        .map(|v| v as usize)
        .unwrap_or(20);

    let idle_timeout_secs = get_int_entry(node, "idle-timeout")
        .map(|v| v as u64)
        .unwrap_or(60);

    let max_lifetime_secs = get_int_entry(node, "max-lifetime").map(|v| v as u64);

    ConnectionPoolConfig {
        max_connections,
        max_idle,
        idle_timeout_secs,
        max_lifetime_secs,
    }
}

/// Parse upstream timeouts configuration
///
/// Example KDL:
/// ```kdl
/// timeouts {
///     connect 10
///     request 60
///     read 30
///     write 30
/// }
/// ```
fn parse_upstream_timeouts(node: &kdl::KdlNode) -> UpstreamTimeouts {
    let connect_secs = get_int_entry(node, "connect")
        .map(|v| v as u64)
        .unwrap_or(10);

    let request_secs = get_int_entry(node, "request")
        .map(|v| v as u64)
        .unwrap_or(60);

    let read_secs = get_int_entry(node, "read").map(|v| v as u64).unwrap_or(30);

    let write_secs = get_int_entry(node, "write").map(|v| v as u64).unwrap_or(30);

    UpstreamTimeouts {
        connect_secs,
        request_secs,
        read_secs,
        write_secs,
    }
}

/// Parse health check configuration
fn parse_health_check(node: &kdl::KdlNode) -> Result<HealthCheck> {
    // Parse health check type
    let check_type = node
        .children()
        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "type"))
        .map(|type_node| {
            let type_name = get_first_arg_string(type_node).unwrap_or_else(|| "tcp".to_string());
            match type_name.to_lowercase().as_str() {
                "http" => {
                    // Parse HTTP health check options
                    let path = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "path"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "/health".to_string());

                    let expected_status = type_node
                        .children()
                        .and_then(|c| {
                            c.nodes()
                                .iter()
                                .find(|n| n.name().value() == "expected-status")
                        })
                        .and_then(get_first_arg_string)
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(200);

                    let host = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "host"))
                        .and_then(get_first_arg_string);

                    HealthCheckType::Http {
                        path,
                        expected_status,
                        host,
                    }
                }
                "grpc" => {
                    let service = type_node
                        .children()
                        .and_then(|c| c.nodes().iter().find(|n| n.name().value() == "service"))
                        .and_then(get_first_arg_string)
                        .unwrap_or_else(|| "grpc.health.v1.Health".to_string());
                    HealthCheckType::Grpc { service }
                }
                _ => HealthCheckType::Tcp,
            }
        })
        .unwrap_or(HealthCheckType::Tcp);

    // Parse other health check settings
    let interval_secs = get_int_entry(node, "interval-secs").unwrap_or(10) as u64;
    let timeout_secs = get_int_entry(node, "timeout-secs").unwrap_or(5) as u64;
    let healthy_threshold = get_int_entry(node, "healthy-threshold").unwrap_or(2) as u32;
    let unhealthy_threshold = get_int_entry(node, "unhealthy-threshold").unwrap_or(3) as u32;

    Ok(HealthCheck {
        check_type,
        interval_secs,
        timeout_secs,
        healthy_threshold,
        unhealthy_threshold,
    })
}
