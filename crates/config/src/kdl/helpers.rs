//! KDL parsing helper functions.
//!
//! Common utilities for extracting values from KDL nodes.

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

/// Helper to get the first argument of a node as a string
pub fn get_first_arg_string(node: &kdl::KdlNode) -> Option<String> {
    node.entries()
        .first()
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string())
}
