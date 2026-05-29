//! KDL parsing helper functions.
//!
//! Common utilities for extracting values from KDL nodes.

use std::collections::HashMap;

use crate::upstreams::UpstreamTarget;

/// Convert a byte offset to line and column numbers (1-indexed)
pub fn offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in content.chars().enumerate() {
        if i >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Helper to get a string entry from a KDL node
pub fn get_string_entry(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Helper to get an integer entry from a KDL node
pub fn get_int_entry(node: &kdl::KdlNode, name: &str) -> Option<i128> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer())
}

/// Helper to get a boolean entry from a KDL node
pub fn get_bool_entry(node: &kdl::KdlNode, name: &str) -> Option<bool> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool())
}

/// Helper to get a float entry from a KDL node
pub fn get_float_entry(node: &kdl::KdlNode, name: &str) -> Option<f64> {
    node.children()
        .and_then(|children| children.get(name))
        .and_then(|n| n.entries().first())
        .and_then(|e| {
            // Try as float first, then as integer converted to float
            e.value()
                .as_float()
                .or_else(|| e.value().as_integer().map(|i| i as f64))
        })
}

/// Helper to get the first argument of a node as a string
pub fn get_first_arg_string(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Read a named property entry as a string (e.g. `address="host:port"`).
fn named_string_entry(node: &kdl::KdlNode, name: &str) -> Option<String> {
    node.entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some(name))
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}

/// Read a named property entry as an integer (e.g. `weight=2`).
fn named_int_entry(node: &kdl::KdlNode, name: &str) -> Option<i128> {
    node.entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some(name))
        .and_then(|e| e.value().as_integer())
}

/// Resolve an `address` given as a property (`address="x"`) or child node (`address "x"`).
fn target_address_field(node: &kdl::KdlNode) -> Option<String> {
    named_string_entry(node, "address").or_else(|| get_string_entry(node, "address"))
}

/// Resolve a single `target` node's address and weight across every accepted form.
fn parse_single_target(node: &kdl::KdlNode) -> Option<UpstreamTarget> {
    // Address: first positional arg, else an `address` property/child node.
    let address = get_first_arg_string(node).or_else(|| target_address_field(node))?;

    // Weight: `weight=N` property, else `weight N` child node; defaults to 1.
    let weight = named_int_entry(node, "weight")
        .or_else(|| get_int_entry(node, "weight"))
        .map(|v| v as u32)
        .unwrap_or(1);

    Some(UpstreamTarget {
        address,
        weight,
        max_requests: None,
        metadata: HashMap::new(),
    })
}

/// Parse upstream targets from an `upstream` node.
///
/// Shared by the single-file and multi-file parsers so both accept the same
/// syntax — the divergence here was the root cause of zentinelproxy/zentinel#254.
/// Every form below is accepted:
///
/// ```kdl
/// // Shorthand: address as the first argument
/// target "127.0.0.1:8081"
/// target "127.0.0.1:8082" weight=2
///
/// // Block form: address (and weight) as child nodes or properties
/// target { address "127.0.0.1:8081"; weight 2 }
/// target address="127.0.0.1:8081" weight=2
///
/// // Wrapped in a `targets` block
/// targets {
///     target "127.0.0.1:8081"
///     target { address "127.0.0.1:8082" weight=2 }
/// }
///
/// // Single-target shorthand on the upstream itself
/// address "127.0.0.1:8081"
/// ```
///
/// Targets without a resolvable address are skipped (rather than silently
/// defaulted), so a misconfigured upstream surfaces as "no targets" during
/// validation instead of pointing at a bogus address.
pub fn parse_upstream_targets(upstream: &kdl::KdlNode) -> Vec<UpstreamTarget> {
    let mut targets = Vec::new();

    if let Some(children) = upstream.children() {
        for node in children.nodes() {
            match node.name().value() {
                "target" => {
                    if let Some(target) = parse_single_target(node) {
                        targets.push(target);
                    }
                }
                "targets" => {
                    if let Some(target_children) = node.children() {
                        for target_node in target_children.nodes() {
                            if target_node.name().value() == "target" {
                                if let Some(target) = parse_single_target(target_node) {
                                    targets.push(target);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Single-target shorthand: `address "host:port"` directly on the upstream.
    if targets.is_empty() {
        if let Some(address) = target_address_field(upstream) {
            targets.push(UpstreamTarget {
                address,
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            });
        }
    }

    targets
}
