//! KDL parsing helper functions.
//!
//! Common utilities for extracting values from KDL nodes.

use std::collections::HashMap;

use crate::upstreams::UpstreamTarget;

use anyhow::Result;

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

/// A child node written more than once in a block that reads it once.
///
/// Reading a child by name takes the first one, so a second `filters` or
/// `timeouts` in the same block used to be dropped without a word. The parser
/// refuses the document instead, and says which node it was.
///
/// [`parse_kdl_document`](super::parse_kdl_document) adds where in the document
/// the node is (see [`locate_duplicate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DuplicateNode {
    /// The repeated node's name.
    pub(crate) name: String,
    /// How many times it is written.
    pub(crate) count: usize,
    /// Byte offset of the second copy in the parsed text, when the node
    /// carries a position.
    pub(crate) offset: Option<usize>,
    /// Where the copies are, e.g. `in routes > route "api"`; `None` until the
    /// position has been resolved.
    pub(crate) location: Option<String>,
}

impl std::fmt::Display for DuplicateNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Duplicate node '{}'", self.name)?;
        if let Some(location) = &self.location {
            write!(f, " {}", location)?;
        }
        write!(
            f,
            ": it is written {} times, but only one of them would take effect. Combine them \
             into a single '{}' node, or remove the extra ones.",
            self.count, self.name
        )
    }
}

impl std::error::Error for DuplicateNode {}

/// Say where in `doc` a [`DuplicateNode`] error is, when `error` is one.
///
/// The nodes carry their byte offsets in the text that was parsed, so the
/// enclosing blocks can be found from the offset alone, however deep the
/// parser that noticed the repeat was. That is the one place that knows the
/// whole document, which is why no parser has to name its own position.
/// Any other error is returned as it is.
pub(crate) fn locate_duplicate(error: anyhow::Error, doc: &kdl::KdlDocument) -> anyhow::Error {
    let Some(duplicate) = error.downcast_ref::<DuplicateNode>() else {
        return error;
    };
    let Some(offset) = duplicate.offset else {
        return error;
    };
    let mut trail = Vec::new();
    let Some(blocks) = blocks_around(doc, offset, &mut trail) else {
        return error;
    };
    let location = if blocks.is_empty() {
        "at the top level".to_string()
    } else {
        format!("in {}", blocks.join(" > "))
    };
    DuplicateNode {
        location: Some(location),
        ..duplicate.clone()
    }
    .into()
}

/// The blocks that enclose the node at `offset`, outermost first, each named
/// as written: `route "api"`.
fn blocks_around(
    children: &kdl::KdlDocument,
    offset: usize,
    trail: &mut Vec<String>,
) -> Option<Vec<String>> {
    for node in children.nodes() {
        if node.span().offset() == offset {
            return Some(trail.clone());
        }
        if let Some(inner) = node.children() {
            let label = match get_first_arg_string(node) {
                Some(id) => format!("{} \"{}\"", node.name().value(), id),
                None => node.name().value().to_string(),
            };
            trail.push(label);
            if let Some(found) = blocks_around(inner, offset, trail) {
                return Some(found);
            }
            trail.pop();
        }
    }
    None
}

/// The only child of `children` named `name`.
///
/// Returns `Ok(None)` when there is none.
///
/// # Errors
///
/// [`DuplicateNode`] when more than one child has that name. Every read of a
/// child that a block takes once goes through here, instead of
/// `KdlDocument::get`, which returns the first and never mentions the rest.
pub(crate) fn get_unique<'a>(
    children: &'a kdl::KdlDocument,
    name: &str,
) -> Result<Option<&'a kdl::KdlNode>> {
    get_unique_in_nodes(children.nodes(), name)
}

/// [`get_unique`] over a slice of sibling nodes.
pub(crate) fn get_unique_in_nodes<'a>(
    nodes: &'a [kdl::KdlNode],
    name: &str,
) -> Result<Option<&'a kdl::KdlNode>> {
    let mut matching = nodes.iter().filter(|n| n.name().value() == name);
    let Some(first) = matching.next() else {
        return Ok(None);
    };
    let Some(second) = matching.next() else {
        return Ok(Some(first));
    };
    Err(DuplicateNode {
        name: name.to_string(),
        count: 2 + matching.count(),
        offset: Some(second.span().offset()).filter(|o| *o > 0),
        location: None,
    }
    .into())
}

/// Fail when two children of `children` share a name.
///
/// For blocks whose children are keyed by their own name, such as the header
/// names inside `set { X-A "1" }`: the later of two entries with one name
/// replaced the earlier, without a word.
///
/// # Errors
///
/// [`DuplicateNode`] for the first name that is written more than once.
pub(crate) fn reject_repeated_names(children: &kdl::KdlDocument) -> Result<()> {
    reject_repeated(children, |_| true)
}

/// Fail when two children of `children` share a name that `is_single` accepts.
///
/// For a block that is read by walking its children and acting on each by
/// name, where a name written twice sets one value twice and keeps the last.
/// `is_single` names the children that hold one value; the ones that add to a
/// list when repeated, such as an agent's `events`, are left out.
///
/// # Errors
///
/// [`DuplicateNode`] for the first such name that is written more than once.
pub(crate) fn reject_repeated(
    children: &kdl::KdlDocument,
    is_single: impl Fn(&str) -> bool,
) -> Result<()> {
    let nodes = children.nodes();
    for (i, node) in nodes.iter().enumerate() {
        let name = node.name().value();
        if is_single(name) && nodes[..i].iter().any(|n| n.name().value() == name) {
            // Reports every copy, not only the second one.
            return get_unique_in_nodes(nodes, name).map(|_| ());
        }
    }
    Ok(())
}

/// Fail when two children of `children`, which are header names, are the same
/// header.
///
/// Header names do not differ by case, so `X-A` and `x-a` are one header and
/// the later of the two used to replace the earlier. The error names the first
/// spelling.
///
/// # Errors
///
/// [`DuplicateNode`] for the first header that is written more than once.
pub(crate) fn reject_repeated_header_names(children: &kdl::KdlDocument) -> Result<()> {
    let nodes = children.nodes();
    for (i, node) in nodes.iter().enumerate() {
        let name = node.name().value();
        if nodes[..i]
            .iter()
            .any(|n| n.name().value().eq_ignore_ascii_case(name))
        {
            let copies: Vec<&kdl::KdlNode> = nodes
                .iter()
                .filter(|n| n.name().value().eq_ignore_ascii_case(name))
                .collect();
            return Err(DuplicateNode {
                name: copies
                    .first()
                    .map_or(name, |first| first.name().value())
                    .to_string(),
                count: copies.len(),
                offset: Some(node.span().offset()).filter(|o| *o > 0),
                location: None,
            }
            .into());
        }
    }
    Ok(())
}

/// The only child of `parent` named `name`; see [`get_unique`].
pub(crate) fn get_unique_child<'a>(
    parent: &'a kdl::KdlNode,
    name: &str,
) -> Result<Option<&'a kdl::KdlNode>> {
    match parent.children() {
        Some(children) => get_unique(children, name),
        None => Ok(None),
    }
}

/// Helper to get a string entry from a KDL node
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once.
pub fn get_string_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<String>> {
    Ok(get_unique_child(node, name)?
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_string())
        .map(|s| s.to_string()))
}

/// Helper to get an integer entry from a KDL node
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once.
pub fn get_int_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<i128>> {
    Ok(get_unique_child(node, name)?
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_integer()))
}

/// Helper to get a boolean entry from a KDL node
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once.
pub fn get_bool_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<bool>> {
    Ok(get_unique_child(node, name)?
        .and_then(|n| n.entries().first())
        .and_then(|e| e.value().as_bool()))
}

/// Helper to get a float entry from a KDL node
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once.
pub fn get_float_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<f64>> {
    Ok(get_unique_child(node, name)?
        .and_then(|n| n.entries().first())
        .and_then(|e| {
            // Try as float first, then as integer converted to float
            e.value()
                .as_float()
                .or_else(|| e.value().as_integer().map(|i| i as f64))
        }))
}

/// An integer setting under its documented name, or else under its alias.
///
/// # Errors
///
/// [`DuplicateNode`] when the name that is read is written more than once.
pub(crate) fn get_int_entry_or(
    node: &kdl::KdlNode,
    name: &str,
    alias: &str,
) -> Result<Option<i128>> {
    match get_int_entry(node, name)? {
        Some(value) => Ok(Some(value)),
        None => get_int_entry(node, alias),
    }
}

/// A boolean setting under its documented name, or else under its alias.
///
/// # Errors
///
/// [`DuplicateNode`] when the name that is read is written more than once.
pub(crate) fn get_bool_entry_or(
    node: &kdl::KdlNode,
    name: &str,
    alias: &str,
) -> Result<Option<bool>> {
    match get_bool_entry(node, name)? {
        Some(value) => Ok(Some(value)),
        None => get_bool_entry(node, alias),
    }
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
fn target_address_field(node: &kdl::KdlNode) -> Result<Option<String>> {
    match named_string_entry(node, "address") {
        Some(address) => Ok(Some(address)),
        None => get_string_entry(node, "address"),
    }
}

/// Resolve a single `target` node's address and weight across every accepted form.
fn parse_single_target(node: &kdl::KdlNode) -> Result<Option<UpstreamTarget>> {
    // Address: first positional arg, else an `address` property/child node.
    let address = match get_first_arg_string(node) {
        Some(address) => Some(address),
        None => target_address_field(node)?,
    };
    let Some(address) = address else {
        return Ok(None);
    };

    // Weight: `weight=N` property, else `weight N` child node; defaults to 1.
    let weight = match named_int_entry(node, "weight") {
        Some(weight) => Some(weight),
        None => get_int_entry(node, "weight")?,
    }
    .map(|v| v as u32)
    .unwrap_or(1);

    Ok(Some(UpstreamTarget {
        address,
        weight,
        max_requests: None,
        metadata: HashMap::new(),
    }))
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
///
/// # Errors
///
/// [`DuplicateNode`] when a `target` writes its `address` or `weight` child
/// more than once, or the upstream writes the shorthand `address` more than once.
pub fn parse_upstream_targets(upstream: &kdl::KdlNode) -> Result<Vec<UpstreamTarget>> {
    let mut targets = Vec::new();

    if let Some(children) = upstream.children() {
        for node in children.nodes() {
            match node.name().value() {
                "target" => {
                    if let Some(target) = parse_single_target(node)? {
                        targets.push(target);
                    }
                }
                "targets" => {
                    if let Some(target_children) = node.children() {
                        for target_node in target_children.nodes() {
                            if target_node.name().value() == "target" {
                                if let Some(target) = parse_single_target(target_node)? {
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
        if let Some(address) = target_address_field(upstream)? {
            targets.push(UpstreamTarget {
                address,
                weight: 1,
                max_requests: None,
                metadata: HashMap::new(),
            });
        }
    }

    Ok(targets)
}

/// Tries to parse a u32 from a kdlnode, and makes sure it is non-zero
pub fn extract_u32_with_limits(node: &kdl::KdlNode) -> Result<u32> {
    let first_value = match node.entries().first() {
        Some(v) => v,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to parse u32 for key {} but did not find a value",
                node.name()
            ))
        }
    };
    let u32_val = match first_value.value().as_integer() {
        Some(v) => u32::try_from(v).map_err(anyhow::Error::msg)?,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to convert value in {} to u32, but failed",
                node.name()
            ))
        }
    };

    if u32_val == 0 {
        return Err(anyhow::anyhow!("Implausible value for {}", node.name()));
    }

    Ok(u32_val)
}

/// Tries to parse a u32 from a kdlnode, and makes sure it is non-zero
pub fn extract_u64_with_limits(node: &kdl::KdlNode) -> Result<u64> {
    let first_value = match node.entries().first() {
        Some(v) => v,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to parse u64 for key {} but did not find a value",
                node.name()
            ))
        }
    };
    let u64_val = match first_value.value().as_integer() {
        Some(v) => u64::try_from(v).map_err(anyhow::Error::msg)?,
        None => {
            return Err(anyhow::anyhow!(
                "Tried to convert value in {} to u64, but failed",
                node.name()
            ))
        }
    };

    if u64_val == 0 {
        return Err(anyhow::anyhow!("Implausible value for {}", node.name()));
    }

    Ok(u64_val)
}

/// Suggest the closest candidate for a (probably misspelled) input.
///
/// Returns `Some(candidate)` when a candidate is within a small edit distance
/// of the input (scaled with input length), so error messages can offer a
/// "did you mean" hint. Returns `None` when nothing is plausibly close.
pub fn did_you_mean<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    // Allow more typo distance for longer inputs; at least 1, at most 3.
    let max_distance = (input.len() / 4).clamp(1, 3);

    candidates
        .iter()
        .map(|c| (edit_distance(input, c), *c))
        .filter(|(d, _)| *d <= max_distance)
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

/// Edit distance between two strings (over `char`s).
///
/// Optimal-string-alignment variant of Levenshtein: insertions, deletions,
/// and substitutions cost 1, and an adjacent transposition ("hots" → "host")
/// also costs 1, which matches how config keys are typically mistyped.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    // rows[i][j] = distance between a[..i] and b[..j]
    let mut rows: Vec<Vec<usize>> = vec![(0..=b.len()).collect()];

    for (i, ca) in a.iter().enumerate() {
        let mut row = vec![0usize; b.len() + 1];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution_cost = if ca == cb { 0 } else { 1 };
            let mut d = (rows[i][j] + substitution_cost) // substitute
                .min(rows[i][j + 1] + 1) // delete
                .min(row[j] + 1); // insert
            if i > 0 && j > 0 && *ca == b[j - 1] && a[i - 1] == *cb {
                d = d.min(rows[i - 1][j - 1] + 1); // transpose
            }
            row[j + 1] = d;
        }
        rows.push(row);
    }

    rows[a.len()][b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_distance_basics() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("path_prefix", "path-prefix"), 1);
        // Adjacent transposition costs 1 (OSA variant)
        assert_eq!(edit_distance("hots", "host"), 1);
    }

    #[test]
    fn did_you_mean_suggests_close_candidates() {
        let candidates = ["path", "path-prefix", "path-regex", "host", "method"];
        assert_eq!(
            did_you_mean("path_prefix", &candidates),
            Some("path-prefix")
        );
        assert_eq!(did_you_mean("hots", &candidates), Some("host"));
        assert_eq!(did_you_mean("pth", &candidates), Some("path"));
    }

    #[test]
    fn did_you_mean_rejects_distant_candidates() {
        let candidates = ["path", "host", "method"];
        assert_eq!(did_you_mean("upstream", &candidates), None);
        assert_eq!(did_you_mean("zzzzzz", &candidates), None);
    }

    fn parse(text: &str) -> kdl::KdlDocument {
        text.parse().expect("KDL parses")
    }

    fn duplicate_of(error: anyhow::Error) -> DuplicateNode {
        error
            .downcast::<DuplicateNode>()
            .expect("the error is a DuplicateNode")
    }

    #[test]
    fn get_unique_finds_a_single_node() {
        let doc = parse("a 1\nb 2\n");
        let node = get_unique(&doc, "b").unwrap().expect("b is there");
        assert_eq!(node.name().value(), "b");
    }

    #[test]
    fn get_unique_finds_nothing_when_the_name_is_absent() {
        let doc = parse("a 1\n");
        assert!(get_unique(&doc, "b").unwrap().is_none());
    }

    #[test]
    fn get_unique_refuses_a_name_written_twice() {
        let doc = parse("a 1\nb 2\na 3\na 4\n");
        let duplicate = duplicate_of(get_unique(&doc, "a").unwrap_err());
        assert_eq!(duplicate.name, "a");
        assert_eq!(duplicate.count, 3);
        assert_eq!(duplicate.location, None);
    }

    #[test]
    fn get_unique_child_reads_the_children_of_a_node() {
        let doc = parse("route \"r\" {\n  filters \"a\"\n  filters \"b\"\n  priority 1\n}\n");
        let route = &doc.nodes()[0];
        assert!(get_unique_child(route, "priority").unwrap().is_some());
        assert!(get_unique_child(route, "upstream").unwrap().is_none());
        assert!(get_unique_child(route, "filters").is_err());
    }

    #[test]
    fn get_unique_child_of_a_node_without_children_is_none() {
        let doc = parse("route \"r\"\n");
        assert!(get_unique_child(&doc.nodes()[0], "filters")
            .unwrap()
            .is_none());
    }

    #[test]
    fn the_scalar_helpers_refuse_a_name_written_twice() {
        let doc = parse(
            "n {\n  s \"x\"\n  s \"y\"\n  i 1\n  i 2\n  b #true\n  b #false\n  f 1.5\n  f 2.5\n}\n",
        );
        let node = &doc.nodes()[0];
        assert!(get_string_entry(node, "s").is_err());
        assert!(get_int_entry(node, "i").is_err());
        assert!(get_bool_entry(node, "b").is_err());
        assert!(get_float_entry(node, "f").is_err());
        assert_eq!(get_string_entry(node, "absent").unwrap(), None);
    }

    #[test]
    fn the_scalar_helpers_read_a_single_node() {
        let doc = parse("n {\n  s \"x\"\n  i 7\n  b #true\n  f 1.5\n}\n");
        let node = &doc.nodes()[0];
        assert_eq!(get_string_entry(node, "s").unwrap().as_deref(), Some("x"));
        assert_eq!(get_int_entry(node, "i").unwrap(), Some(7));
        assert_eq!(get_bool_entry(node, "b").unwrap(), Some(true));
        assert_eq!(get_float_entry(node, "f").unwrap(), Some(1.5));
    }

    #[test]
    fn an_alias_is_read_when_the_documented_name_is_absent() {
        let doc = parse("n {\n  idle-timeout 30\n  flag-alias #true\n}\n");
        let node = &doc.nodes()[0];
        assert_eq!(
            get_int_entry_or(node, "idle-timeout-secs", "idle-timeout").unwrap(),
            Some(30)
        );
        assert_eq!(
            get_bool_entry_or(node, "flag", "flag-alias").unwrap(),
            Some(true)
        );
    }

    #[test]
    fn reject_repeated_ignores_names_it_is_not_asked_about() {
        let doc = parse("events \"a\"\nevents \"b\"\ntimeout 1\n");
        reject_repeated(&doc, |name| name != "events").unwrap();
        let duplicate = duplicate_of(reject_repeated(&doc, |_| true).unwrap_err());
        assert_eq!(duplicate.name, "events");
    }

    #[test]
    fn reject_repeated_names_accepts_distinct_names() {
        reject_repeated_names(&parse("a 1\nb 2\nc 3\n")).unwrap();
    }

    #[test]
    fn locate_duplicate_names_the_enclosing_blocks() {
        let doc = parse(
            "routes {\n  route \"api\" {\n    policies {\n      timeout-secs 1\n      timeout-secs 2\n    }\n  }\n}\n",
        );
        let policies = get_unique_child(&doc.nodes()[0], "route")
            .unwrap()
            .and_then(|r| get_unique_child(r, "policies").unwrap())
            .expect("policies block");
        let error = get_unique_child(policies, "timeout-secs").unwrap_err();
        let located = duplicate_of(locate_duplicate(error, &doc));
        assert_eq!(
            located.location.as_deref(),
            Some("in routes > route \"api\" > policies")
        );
    }

    #[test]
    fn locate_duplicate_says_so_for_the_top_level() {
        let doc = parse("limits 1\nlimits 2\n");
        let error = get_unique(&doc, "limits").unwrap_err();
        let located = duplicate_of(locate_duplicate(error, &doc));
        assert_eq!(located.location.as_deref(), Some("at the top level"));
    }

    #[test]
    fn locate_duplicate_passes_other_errors_through() {
        let doc = parse("a 1\n");
        let error = anyhow::anyhow!("something else");
        assert_eq!(locate_duplicate(error, &doc).to_string(), "something else");
    }

    #[test]
    fn a_duplicate_without_a_position_is_reported_without_one() {
        let duplicate = DuplicateNode {
            name: "filters".to_string(),
            count: 2,
            offset: None,
            location: None,
        };
        let doc = parse("a 1\n");
        let error = locate_duplicate(duplicate.clone().into(), &doc);
        assert_eq!(error.to_string(), duplicate.to_string());
        assert!(error.to_string().starts_with("Duplicate node 'filters': "));
    }
}
