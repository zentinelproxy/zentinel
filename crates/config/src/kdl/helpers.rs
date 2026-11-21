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
/// the node is (see [`locate_error`]).
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

/// What a setting that takes a string reads as, for [`WrongValueType`].
pub(crate) const EXPECT_STRING: &str = "a string (in quotes)";
/// What a setting that takes an integer reads as, for [`WrongValueType`].
pub(crate) const EXPECT_INTEGER: &str = "an integer (without quotes)";
/// What a setting that takes a number reads as, for [`WrongValueType`].
pub(crate) const EXPECT_NUMBER: &str = "a number (without quotes)";
/// What a setting that takes a boolean reads as, for [`WrongValueType`].
pub(crate) const EXPECT_BOOL: &str = "#true or #false (without quotes)";

/// What [`WrongValueType`] says was found in place of an argument that was
/// written as `name=value`.
const FOUND_PROPERTY: &str = "a property written as name=value";

/// A setting written with a value of a type it does not take.
///
/// `max-connections-per-client "100"` is a string where a count is wanted, and
/// `client-auth "true"` a string where a boolean is. Such a value used to be
/// read as if the node were absent, so the setting's default applied and the
/// document loaded. The parser refuses it instead, and says what the setting
/// takes and what type was written. The value itself is left out of the
/// message: it is as likely to be a quoted secret as a number.
///
/// [`parse_kdl_document`](super::parse_kdl_document) adds where in the document
/// the node is (see [`locate_error`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WrongValueType {
    /// The setting: the name of the node, or of the property on it.
    pub(crate) name: String,
    /// What the setting takes, e.g. `an integer (without quotes)`.
    pub(crate) expected: &'static str,
    /// The type that was written, e.g. `a string`; `None` when the node has no
    /// value at all.
    pub(crate) found: Option<&'static str>,
    /// Byte offset of the node that carries the value in the parsed text, when
    /// the node carries a position.
    pub(crate) offset: Option<usize>,
    /// Where the node is, e.g. `in routes > route "api"`; `None` until the
    /// position has been resolved.
    pub(crate) location: Option<String>,
}

impl std::fmt::Display for WrongValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wrong value type for '{}'", self.name)?;
        if let Some(location) = &self.location {
            write!(f, " {}", location)?;
        }
        write!(
            f,
            ": expected {}, found {}.",
            self.expected,
            self.found.unwrap_or("no value")
        )
    }
}

impl std::error::Error for WrongValueType {}

/// A setting written with an integer outside the range it takes.
///
/// `default-ttl-secs -1` is an integer, so it passes for a duration, but it is
/// not one a `u64` can hold, and `port 70000` is not one a port can. Such a value
/// used to be cut down to the width of the setting's type without a word:
/// `-1` read as `18446744073709551615`, and `70000` as `4464`. The parser
/// refuses it instead, and says which setting it was, what was written, and
/// what the setting takes.
///
/// [`parse_kdl_document`](super::parse_kdl_document) adds where in the document
/// the node is (see [`locate_error`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IntegerOutOfRange {
    /// The setting: the name of the node, or of the property on it.
    pub(crate) name: String,
    /// The integer that was written.
    pub(crate) value: i128,
    /// The least value the setting takes.
    pub(crate) min: i128,
    /// The greatest value the setting takes.
    pub(crate) max: i128,
    /// Byte offset of the node that carries the value in the parsed text, when
    /// the node carries a position.
    pub(crate) offset: Option<usize>,
    /// Where the node is, e.g. `in routes > route "api"`; `None` until the
    /// position has been resolved.
    pub(crate) location: Option<String>,
}

impl std::fmt::Display for IntegerOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Value out of range for '{}'", self.name)?;
        if let Some(location) = &self.location {
            write!(f, " {}", location)?;
        }
        write!(
            f,
            ": {} is not between {} and {}.",
            self.value, self.min, self.max
        )
    }
}

impl std::error::Error for IntegerOutOfRange {}

/// An integer type that a setting is stored in, and the range it covers.
///
/// Reading a setting as one of these refuses a value that does not fit, where
/// `as` would keep its low bits. The range is that of the type on the platform
/// that runs the parser, which for `usize` is its pointer width.
pub(crate) trait IntSetting: Copy + TryFrom<i128> {
    /// The least value of the type.
    const MIN: i128;
    /// The greatest value of the type.
    const MAX: i128;
}

macro_rules! int_setting {
    ($($ty:ty),* $(,)?) => {
        $(
            impl IntSetting for $ty {
                const MIN: i128 = <$ty>::MIN as i128;
                const MAX: i128 = <$ty>::MAX as i128;
            }
        )*
    };
}

int_setting!(u8, u16, u32, u64, usize, i32);

/// The values of an HTTP status code.
const HTTP_STATUS_MIN: i128 = 100;
/// The greatest value of an HTTP status code.
const HTTP_STATUS_MAX: i128 = 599;

/// The error for `value`, written for `name` on `node`, outside `min..=max`.
pub(crate) fn out_of_range(
    node: &kdl::KdlNode,
    name: &str,
    value: i128,
    min: i128,
    max: i128,
) -> anyhow::Error {
    IntegerOutOfRange {
        name: name.to_string(),
        value,
        min,
        max,
        offset: Some(node.span().offset()).filter(|o| *o > 0),
        location: None,
    }
    .into()
}

/// `value`, which is the setting `name` on `node`, in the type `T`, within
/// `min..=max` where that is narrower than the type.
///
/// # Errors
///
/// [`IntegerOutOfRange`] when the value is outside the range, which is
/// reported as the part of `min..=max` that the type covers.
pub(crate) fn int_setting_in<T: IntSetting>(
    node: &kdl::KdlNode,
    name: &str,
    value: i128,
    min: i128,
    max: i128,
) -> Result<T> {
    let (min, max) = (min.max(T::MIN), max.min(T::MAX));
    if value < min || value > max {
        return Err(out_of_range(node, name, value, min, max));
    }
    T::try_from(value).map_err(|_| out_of_range(node, name, value, min, max))
}

/// `value`, which is the setting `name` on `node`, in the type `T`.
///
/// # Errors
///
/// [`IntegerOutOfRange`] when the value does not fit the type.
pub(crate) fn int_setting<T: IntSetting>(
    node: &kdl::KdlNode,
    name: &str,
    value: i128,
) -> Result<T> {
    int_setting_in(node, name, value, T::MIN, T::MAX)
}

/// An HTTP status code: `value`, which is the setting `name` on `node`.
///
/// # Errors
///
/// [`IntegerOutOfRange`] when the value is not from 100 to 599.
pub(crate) fn http_status(node: &kdl::KdlNode, name: &str, value: i128) -> Result<u16> {
    int_setting_in(node, name, value, HTTP_STATUS_MIN, HTTP_STATUS_MAX)
}

/// The type of a value as it reads in a [`WrongValueType`].
fn found_type(value: &kdl::KdlValue) -> &'static str {
    match value {
        kdl::KdlValue::String(_) => "a string",
        kdl::KdlValue::Integer(_) => "an integer",
        kdl::KdlValue::Float(_) => "a number",
        kdl::KdlValue::Bool(_) => "a boolean",
        kdl::KdlValue::Null => "#null",
    }
}

fn wrong_value_type(
    node: &kdl::KdlNode,
    name: &str,
    expected: &'static str,
    found: Option<&'static str>,
) -> anyhow::Error {
    WrongValueType {
        name: name.to_string(),
        expected,
        found,
        offset: Some(node.span().offset()).filter(|o| *o > 0),
        location: None,
    }
    .into()
}

/// One value, read with `convert`; `#null` is no value, and reads as `None`.
fn read_value<T>(
    node: &kdl::KdlNode,
    name: &str,
    expected: &'static str,
    value: &kdl::KdlValue,
    convert: impl FnOnce(&kdl::KdlValue) -> Option<T>,
) -> Result<Option<T>> {
    if value.is_null() {
        return Ok(None);
    }
    convert(value)
        .map(Some)
        .ok_or_else(|| wrong_value_type(node, name, expected, Some(found_type(value))))
}

/// The first value of `node`, read with `convert`.
///
/// `convert` returns `None` for a value of a type the setting does not take.
/// A node with no value at all is refused too, since there is nothing to read.
/// `#null` is a value that says there is none, and reads as `Ok(None)`, as it
/// always has: the setting keeps its default.
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or `convert` refuses it.
pub(crate) fn node_value<T>(
    node: &kdl::KdlNode,
    expected: &'static str,
    convert: impl FnOnce(&kdl::KdlValue) -> Option<T>,
) -> Result<Option<T>> {
    let name = node.name().value();
    let Some(entry) = node.entries().first() else {
        return Err(wrong_value_type(node, name, expected, None));
    };
    read_value(node, name, expected, entry.value(), convert)
}

/// The first value of `node` as a string; see [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not a string.
pub(crate) fn node_string(node: &kdl::KdlNode) -> Result<Option<String>> {
    node_value(node, EXPECT_STRING, |v| v.as_string().map(str::to_string))
}

/// The first value of `node` as an integer; see [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not an integer.
pub(crate) fn node_int(node: &kdl::KdlNode) -> Result<Option<i128>> {
    node_value(node, EXPECT_INTEGER, |v| v.as_integer())
}

/// The first value of `node` as an integer that fits `T`; see [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not an
/// integer, and [`IntegerOutOfRange`] when the integer does not fit `T`.
pub(crate) fn node_int_as<T: IntSetting>(node: &kdl::KdlNode) -> Result<Option<T>> {
    node_int(node)?
        .map(|value| int_setting(node, node.name().value(), value))
        .transpose()
}

/// The first value of `node` as an HTTP status code; see [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not an
/// integer, and [`IntegerOutOfRange`] when the integer is not from 100 to 599.
pub(crate) fn node_status(node: &kdl::KdlNode) -> Result<Option<u16>> {
    node_int(node)?
        .map(|value| http_status(node, node.name().value(), value))
        .transpose()
}

/// The first value of `node` as a boolean; see [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not a boolean.
pub(crate) fn node_bool(node: &kdl::KdlNode) -> Result<Option<bool>> {
    node_value(node, EXPECT_BOOL, |v| v.as_bool())
}

/// The first value of `node` as a number, where an integer counts; see
/// [`node_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the node has no value or its value is not a number.
pub(crate) fn node_number(node: &kdl::KdlNode) -> Result<Option<f64>> {
    node_value(node, EXPECT_NUMBER, number_of)
}

/// A KDL number as a float; an integer counts.
pub(crate) fn number_of(value: &kdl::KdlValue) -> Option<f64> {
    value
        .as_float()
        .or_else(|| value.as_integer().map(|i| i as f64))
}

/// Run a reader on the child of `parent` named `name`, when there is one.
fn read_child<T>(
    parent: &kdl::KdlNode,
    name: &str,
    read: impl FnOnce(&kdl::KdlNode) -> Result<Option<T>>,
) -> Result<Option<T>> {
    match get_unique_child(parent, name)? {
        Some(child) => read(child),
        None => Ok(None),
    }
}

/// Every argument of `node`, read with `convert`.
///
/// For a node that lists values, such as `domains "a.example" "b.example"`. A
/// value of another type used to be left out of the list without a word, and
/// so was one written as `name=value`. A `#null` is left out, as before.
///
/// # Errors
///
/// [`WrongValueType`] for the first entry that is a property or that
/// `convert` refuses.
pub(crate) fn node_args<T>(
    node: &kdl::KdlNode,
    expected: &'static str,
    convert: impl Fn(&kdl::KdlValue) -> Option<T>,
) -> Result<Vec<T>> {
    let name = node.name().value();
    let mut values = Vec::new();
    for entry in node.entries() {
        if entry.name().is_some() {
            return Err(wrong_value_type(node, name, expected, Some(FOUND_PROPERTY)));
        }
        values.extend(read_value(node, name, expected, entry.value(), &convert)?);
    }
    Ok(values)
}

/// Every argument of `node` as a string; see [`node_args`].
///
/// # Errors
///
/// [`WrongValueType`] for the first entry that is not a string.
pub(crate) fn string_args(node: &kdl::KdlNode) -> Result<Vec<String>> {
    node_args(node, EXPECT_STRING, |v| v.as_string().map(str::to_string))
}

/// Every argument of `node` as an integer; see [`node_args`].
///
/// # Errors
///
/// [`WrongValueType`] for the first entry that is not an integer.
pub(crate) fn int_args(node: &kdl::KdlNode) -> Result<Vec<i128>> {
    node_args(node, EXPECT_INTEGER, |v| v.as_integer())
}

/// Every argument of `node` as an HTTP status code; see [`node_args`].
///
/// # Errors
///
/// [`WrongValueType`] for the first entry that is not an integer, and
/// [`IntegerOutOfRange`] for the first integer that is not from 100 to 599.
pub(crate) fn status_args(node: &kdl::KdlNode) -> Result<Vec<u16>> {
    int_args(node)?
        .into_iter()
        .map(|value| http_status(node, node.name().value(), value))
        .collect()
}

/// Every string argument of every child of `parent` named `name`.
///
/// For a list that may be split over several nodes, such as an ACME block's
/// `domains`. Returns an empty list when there is no such child.
///
/// # Errors
///
/// [`WrongValueType`] for the first entry that is not a string.
pub(crate) fn string_args_of_children(parent: &kdl::KdlNode, name: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    if let Some(children) = parent.children() {
        for child in children.nodes().iter().filter(|n| n.name().value() == name) {
            values.extend(string_args(child)?);
        }
    }
    Ok(values)
}

/// The entry at `index` of `node`, as a string, where it may be absent.
///
/// For a node that takes a second, optional value, such as
/// `header "X-Mode" "fast"`. Returns `Ok(None)` when the node has fewer
/// entries, or the entry is `#null`. The entry is read whether it is written
/// as an argument or as `name=value`, as it always has been: the docs write
/// `header name="X-Mode" value="fast"`.
///
/// # Errors
///
/// [`WrongValueType`] when the entry is there and is not a string.
pub(crate) fn string_arg_at(node: &kdl::KdlNode, index: usize) -> Result<Option<String>> {
    let Some(entry) = node.entries().get(index) else {
        return Ok(None);
    };
    read_value(
        node,
        node.name().value(),
        EXPECT_STRING,
        entry.value(),
        |v| v.as_string().map(str::to_string),
    )
}

/// The property `name` of `node` (`weight=2`), read with `convert`.
///
/// Returns `Ok(None)` when the node has no such property, or it is `#null`.
///
/// # Errors
///
/// [`WrongValueType`] when `convert` refuses the value.
pub(crate) fn property_value<T>(
    node: &kdl::KdlNode,
    name: &str,
    expected: &'static str,
    convert: impl FnOnce(&kdl::KdlValue) -> Option<T>,
) -> Result<Option<T>> {
    let Some(entry) = node
        .entries()
        .iter()
        .find(|e| e.name().map(|n| n.value()) == Some(name))
    else {
        return Ok(None);
    };
    read_value(node, name, expected, entry.value(), convert)
}

/// The property `name` of `node` as a string; see [`property_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the property is not a string.
pub(crate) fn property_string(node: &kdl::KdlNode, name: &str) -> Result<Option<String>> {
    property_value(node, name, EXPECT_STRING, |v| {
        v.as_string().map(str::to_string)
    })
}

/// The property `name` of `node` as an integer; see [`property_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the property is not an integer.
pub(crate) fn property_int(node: &kdl::KdlNode, name: &str) -> Result<Option<i128>> {
    property_value(node, name, EXPECT_INTEGER, |v| v.as_integer())
}

/// The property `name` of `node` as an integer that fits `T`; see
/// [`property_value`].
///
/// # Errors
///
/// [`WrongValueType`] when the property is not an integer, and
/// [`IntegerOutOfRange`] when the integer does not fit `T`.
pub(crate) fn property_int_as<T: IntSetting>(node: &kdl::KdlNode, name: &str) -> Result<Option<T>> {
    property_int(node, name)?
        .map(|value| int_setting(node, name, value))
        .transpose()
}

/// Say where in `doc` a [`DuplicateNode`], [`WrongValueType`] or
/// [`IntegerOutOfRange`] error is, when `error` is one.
///
/// The nodes carry their byte offsets in the text that was parsed, so the
/// enclosing blocks can be found from the offset alone, however deep the
/// parser that noticed the problem was. That is the one place that knows the
/// whole document, which is why no parser has to name its own position.
/// Any other error is returned as it is.
pub(crate) fn locate_error(error: anyhow::Error, doc: &kdl::KdlDocument) -> anyhow::Error {
    if let Some(duplicate) = error.downcast_ref::<DuplicateNode>() {
        let Some(location) = duplicate.offset.and_then(|o| describe_location(doc, o)) else {
            return error;
        };
        return DuplicateNode {
            location: Some(location),
            ..duplicate.clone()
        }
        .into();
    }
    if let Some(wrong) = error.downcast_ref::<WrongValueType>() {
        let Some(location) = wrong.offset.and_then(|o| describe_location(doc, o)) else {
            return error;
        };
        return WrongValueType {
            location: Some(location),
            ..wrong.clone()
        }
        .into();
    }
    if let Some(range) = error.downcast_ref::<IntegerOutOfRange>() {
        let Some(location) = range.offset.and_then(|o| describe_location(doc, o)) else {
            return error;
        };
        return IntegerOutOfRange {
            location: Some(location),
            ..range.clone()
        }
        .into();
    }
    error
}

/// Where the node at `offset` is in `doc`: `in routes > route "api"`, or `at the
/// top level`; `None` when no node starts there.
fn describe_location(doc: &kdl::KdlDocument, offset: usize) -> Option<String> {
    let mut trail = Vec::new();
    let blocks = blocks_around(doc, offset, &mut trail)?;
    Some(if blocks.is_empty() {
        "at the top level".to_string()
    } else {
        format!("in {}", blocks.join(" > "))
    })
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
/// Returns `Ok(None)` when the node has no child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once, and
/// [`WrongValueType`] when it is written with no value or one that is not a
/// string.
pub fn get_string_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<String>> {
    read_child(node, name, node_string)
}

/// Helper to get an integer entry from a KDL node
///
/// Returns `Ok(None)` when the node has no child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once, and
/// [`WrongValueType`] when it is written with no value or one that is not an
/// integer.
pub fn get_int_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<i128>> {
    read_child(node, name, node_int)
}

/// An integer entry of a KDL node, in the type `T` it is stored in.
///
/// Returns `Ok(None)` when the node has no child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once,
/// [`WrongValueType`] when it is written with no value or one that is not an
/// integer, and [`IntegerOutOfRange`] when the integer does not fit `T`. The
/// value used to be cut down to the width of `T`, so `-1` read as the largest
/// value of an unsigned type.
pub(crate) fn get_int_entry_as<T: IntSetting>(
    node: &kdl::KdlNode,
    name: &str,
) -> Result<Option<T>> {
    read_child(node, name, node_int_as::<T>)
}

/// An unsigned 8-bit entry; see [`get_int_entry_as`].
pub(crate) fn get_u8_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<u8>> {
    get_int_entry_as(node, name)
}

/// An unsigned 16-bit entry; see [`get_int_entry_as`].
pub(crate) fn get_u16_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<u16>> {
    get_int_entry_as(node, name)
}

/// An unsigned 32-bit entry; see [`get_int_entry_as`].
pub(crate) fn get_u32_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<u32>> {
    get_int_entry_as(node, name)
}

/// An unsigned 64-bit entry; see [`get_int_entry_as`].
pub(crate) fn get_u64_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<u64>> {
    get_int_entry_as(node, name)
}

/// A pointer-sized unsigned entry; see [`get_int_entry_as`].
pub(crate) fn get_usize_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<usize>> {
    get_int_entry_as(node, name)
}

/// An HTTP status code entry of a KDL node.
///
/// Returns `Ok(None)` when the node has no child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once,
/// [`WrongValueType`] when it is written with no value or one that is not an
/// integer, and [`IntegerOutOfRange`] when the integer is not from 100 to 599.
pub(crate) fn get_status_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<u16>> {
    read_child(node, name, node_status)
}

/// Helper to get a boolean entry from a KDL node
///
/// Returns `Ok(None)` when the node has no child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once, and
/// [`WrongValueType`] when it is written with no value or one that is not a
/// boolean.
pub fn get_bool_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<bool>> {
    read_child(node, name, node_bool)
}

/// Helper to get a float entry from a KDL node
///
/// An integer is read as a float. Returns `Ok(None)` when the node has no
/// child `name`, or its value is `#null`.
///
/// # Errors
///
/// [`DuplicateNode`] when `name` is written more than once, and
/// [`WrongValueType`] when it is written with no value or one that is not a
/// number.
pub fn get_float_entry(node: &kdl::KdlNode, name: &str) -> Result<Option<f64>> {
    read_child(node, name, node_number)
}

/// An integer setting under its documented name, or else under its alias, in
/// the type `T` it is stored in.
///
/// # Errors
///
/// [`DuplicateNode`] when the name that is read is written more than once, and
/// the errors of [`get_int_entry_as`].
pub(crate) fn get_int_entry_or_as<T: IntSetting>(
    node: &kdl::KdlNode,
    name: &str,
    alias: &str,
) -> Result<Option<T>> {
    match get_int_entry_as(node, name)? {
        Some(value) => Ok(Some(value)),
        None => get_int_entry_as(node, alias),
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

/// The first argument of a node as a string.
///
/// For a setting written as `name "value"`, such as `failure-mode "closed"`.
/// Returns `Ok(None)` for `#null`, which says there is no value; the setting
/// keeps its default.
///
/// # Errors
///
/// [`WrongValueType`] when the node has no argument, when its argument is
/// written as `name=value` (`failure-mode mode="closed"`), or when the
/// argument is not a string. Each of these used to read as no argument, so
/// the setting's default applied.
pub(crate) fn get_arg_string(node: &kdl::KdlNode) -> Result<Option<String>> {
    let name = node.name().value();
    match node.entries().iter().find(|e| e.name().is_none()) {
        Some(entry) => read_value(node, name, EXPECT_STRING, entry.value(), |v| {
            v.as_string().map(str::to_string)
        }),
        None if node.entries().is_empty() => Err(wrong_value_type(node, name, EXPECT_STRING, None)),
        None => Err(wrong_value_type(
            node,
            name,
            EXPECT_STRING,
            Some(FOUND_PROPERTY),
        )),
    }
}

/// The first argument of the only child of `parent` named `name`, as a string.
///
/// For an optional setting written as `name "value"`. Returns `Ok(None)` when
/// there is no such child; see [`get_arg_string`].
///
/// # Errors
///
/// [`DuplicateNode`] when the child is written more than once, and
/// [`WrongValueType`] as [`get_arg_string`].
pub(crate) fn get_unique_arg_string(parent: &kdl::KdlNode, name: &str) -> Result<Option<String>> {
    read_child(parent, name, get_arg_string)
}

/// Resolve an `address` given as a property (`address="x"`) or child node (`address "x"`).
fn target_address_field(node: &kdl::KdlNode) -> Result<Option<String>> {
    match property_string(node, "address")? {
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
    let weight = match property_int_as(node, "weight")? {
        Some(weight) => Some(weight),
        None => get_u32_entry(node, "weight")?,
    }
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
            get_int_entry_or_as::<u64>(node, "idle-timeout-secs", "idle-timeout").unwrap(),
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
        let located = duplicate_of(locate_error(error, &doc));
        assert_eq!(
            located.location.as_deref(),
            Some("in routes > route \"api\" > policies")
        );
    }

    #[test]
    fn locate_duplicate_says_so_for_the_top_level() {
        let doc = parse("limits 1\nlimits 2\n");
        let error = get_unique(&doc, "limits").unwrap_err();
        let located = duplicate_of(locate_error(error, &doc));
        assert_eq!(located.location.as_deref(), Some("at the top level"));
    }

    #[test]
    fn locate_duplicate_passes_other_errors_through() {
        let doc = parse("a 1\n");
        let error = anyhow::anyhow!("something else");
        assert_eq!(locate_error(error, &doc).to_string(), "something else");
    }

    fn wrong_type_of(error: anyhow::Error) -> WrongValueType {
        error
            .downcast::<WrongValueType>()
            .expect("the error is a WrongValueType")
    }

    #[test]
    fn the_scalar_helpers_refuse_a_value_of_another_type() {
        let doc = parse("n {\n  s 5\n  i \"5\"\n  b \"true\"\n  f \"1.5\"\n  i2 1.5\n}\n");
        let node = &doc.nodes()[0];

        let wrong = wrong_type_of(get_string_entry(node, "s").unwrap_err());
        assert_eq!(wrong.name, "s");
        assert_eq!(wrong.expected, EXPECT_STRING);
        assert_eq!(wrong.found, Some("an integer"));

        let wrong = wrong_type_of(get_int_entry(node, "i").unwrap_err());
        assert_eq!(wrong.expected, EXPECT_INTEGER);
        assert_eq!(wrong.found, Some("a string"));

        let wrong = wrong_type_of(get_bool_entry(node, "b").unwrap_err());
        assert_eq!(wrong.expected, EXPECT_BOOL);
        assert_eq!(wrong.found, Some("a string"));

        let wrong = wrong_type_of(get_float_entry(node, "f").unwrap_err());
        assert_eq!(wrong.expected, EXPECT_NUMBER);

        // A number with a fraction is not an integer.
        let wrong = wrong_type_of(get_int_entry(node, "i2").unwrap_err());
        assert_eq!(wrong.found, Some("a number"));
    }

    #[test]
    fn a_float_helper_reads_an_integer() {
        let doc = parse("n {\n  f 2\n}\n");
        assert_eq!(get_float_entry(&doc.nodes()[0], "f").unwrap(), Some(2.0));
    }

    #[test]
    fn a_scalar_helper_refuses_a_node_without_a_value() {
        let doc = parse("n {\n  s\n}\n");
        let wrong = wrong_type_of(get_string_entry(&doc.nodes()[0], "s").unwrap_err());
        assert_eq!(wrong.found, None);
        assert!(wrong.to_string().ends_with("found no value."));
    }

    #[test]
    fn a_wrong_value_type_says_what_was_expected_and_found() {
        let doc = parse("n {\n  max-connections-per-client \"100\"\n}\n");
        let error = get_int_entry(&doc.nodes()[0], "max-connections-per-client").unwrap_err();
        assert_eq!(
            error.to_string(),
            "Wrong value type for 'max-connections-per-client': expected an integer \
             (without quotes), found a string."
        );
    }

    #[test]
    fn get_arg_string_reads_the_first_argument() {
        let doc = parse("a \"x\"\nb #null\nc 5\n");
        let nodes = doc.nodes();
        assert_eq!(get_arg_string(&nodes[0]).unwrap().as_deref(), Some("x"));
        // `#null` says there is no value.
        assert_eq!(get_arg_string(&nodes[1]).unwrap(), None);
        let wrong = wrong_type_of(get_arg_string(&nodes[2]).unwrap_err());
        assert_eq!(wrong.found, Some("an integer"));
    }

    #[test]
    fn get_arg_string_refuses_a_node_without_an_argument() {
        let doc = parse("a\nb mode=\"closed\"\nc mode=\"closed\" \"open\"\n");
        let nodes = doc.nodes();
        let wrong = wrong_type_of(get_arg_string(&nodes[0]).unwrap_err());
        assert_eq!(wrong.found, None);
        // A property is not an argument, and is not read as one.
        let wrong = wrong_type_of(get_arg_string(&nodes[1]).unwrap_err());
        assert_eq!(wrong.found, Some(FOUND_PROPERTY));
        // With an argument beside it, the argument is the value.
        assert_eq!(get_arg_string(&nodes[2]).unwrap().as_deref(), Some("open"));
    }

    #[test]
    fn a_null_is_read_as_no_value() {
        let doc = parse("n {\n  s #null\n  i #null\n  b #null\n  f #null\n}\nt weight=#null\n");
        let node = &doc.nodes()[0];
        assert_eq!(get_string_entry(node, "s").unwrap(), None);
        assert_eq!(get_int_entry(node, "i").unwrap(), None);
        assert_eq!(get_bool_entry(node, "b").unwrap(), None);
        assert_eq!(get_float_entry(node, "f").unwrap(), None);
        assert_eq!(property_int(&doc.nodes()[1], "weight").unwrap(), None);
    }

    #[test]
    fn string_args_reads_every_argument_and_refuses_another_type() {
        let doc = parse("a \"x\" \"y\" #null\nb \"x\" 3\nc\nd \"x\" key=\"y\"\n");
        let nodes = doc.nodes();
        assert_eq!(string_args(&nodes[0]).unwrap(), vec!["x", "y"]);
        let wrong = wrong_type_of(string_args(&nodes[1]).unwrap_err());
        assert_eq!(wrong.name, "b");
        assert_eq!(wrong.found, Some("an integer"));
        assert!(string_args(&nodes[2]).unwrap().is_empty());
        // A property is not one of the values, and is not left out of the list.
        let wrong = wrong_type_of(string_args(&nodes[3]).unwrap_err());
        assert_eq!(wrong.found, Some(FOUND_PROPERTY));
    }

    #[test]
    fn a_wrong_value_type_does_not_repeat_the_value() {
        let doc = parse("n {\n  token \"hunter2\"\n}\n");
        let error = get_int_entry(&doc.nodes()[0], "token").unwrap_err();
        assert!(!error.to_string().contains("hunter2"), "{error}");
        let error = string_args(&parse("token 7").nodes()[0]).unwrap_err();
        assert!(!error.to_string().contains('7'), "{error}");
    }

    #[test]
    fn string_args_of_children_joins_the_nodes_of_that_name() {
        let doc = parse("n {\n  domains \"a\"\n  other 1\n  domains \"b\" \"c\"\n}\n");
        let node = &doc.nodes()[0];
        assert_eq!(
            string_args_of_children(node, "domains").unwrap(),
            vec!["a", "b", "c"]
        );
        assert!(string_args_of_children(node, "absent").unwrap().is_empty());
    }

    #[test]
    fn a_property_of_another_type_is_refused() {
        let doc = parse("t weight=2 name=\"x\" other=1\n");
        let node = &doc.nodes()[0];
        assert_eq!(property_int(node, "weight").unwrap(), Some(2));
        assert_eq!(property_string(node, "name").unwrap().as_deref(), Some("x"));
        assert_eq!(property_string(node, "absent").unwrap(), None);
        assert!(property_string(node, "weight").is_err());
        assert!(property_int(node, "name").is_err());
    }

    #[test]
    fn string_arg_at_reads_an_optional_second_argument() {
        let doc = parse("a \"x\" \"y\"\nb \"x\"\nc \"x\" 7\n");
        let nodes = doc.nodes();
        assert_eq!(string_arg_at(&nodes[0], 1).unwrap().as_deref(), Some("y"));
        assert_eq!(string_arg_at(&nodes[1], 1).unwrap(), None);
        assert!(string_arg_at(&nodes[2], 1).is_err());
    }

    #[test]
    fn locate_error_names_the_enclosing_blocks_of_a_wrong_value_type() {
        let doc = parse(
            "routes {\n  route \"api\" {\n    policies {\n      timeout-secs \"1\"\n    }\n  }\n}\n",
        );
        let policies = get_unique_child(&doc.nodes()[0], "route")
            .unwrap()
            .and_then(|r| get_unique_child(r, "policies").unwrap())
            .expect("policies block");
        let error = get_int_entry(policies, "timeout-secs").unwrap_err();
        let located = wrong_type_of(locate_error(error, &doc));
        assert_eq!(
            located.location.as_deref(),
            Some("in routes > route \"api\" > policies")
        );
        assert_eq!(
            located.to_string(),
            "Wrong value type for 'timeout-secs' in routes > route \"api\" > policies: \
             expected an integer (without quotes), found a string."
        );
    }

    #[test]
    fn locate_error_says_so_for_a_wrong_value_type_at_the_top_level() {
        let doc = parse("system {\n  daemon #true\n}\nschema-version 1\n");
        let error = node_string(&doc.nodes()[1]).unwrap_err();
        let located = wrong_type_of(locate_error(error, &doc));
        assert_eq!(located.location.as_deref(), Some("at the top level"));
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
        let error = locate_error(duplicate.clone().into(), &doc);
        assert_eq!(error.to_string(), duplicate.to_string());
        assert!(error.to_string().starts_with("Duplicate node 'filters': "));
    }

    fn out_of_range_of(error: anyhow::Error) -> IntegerOutOfRange {
        error
            .downcast::<IntegerOutOfRange>()
            .expect("the error is an IntegerOutOfRange")
    }

    /// The node of `source`, whose entries are read by name.
    fn read<T>(
        source: &str,
        read: impl Fn(&kdl::KdlNode, &str) -> Result<Option<T>>,
    ) -> Result<Option<T>> {
        let doc = parse(source);
        read(&doc.nodes()[0], "n")
    }

    #[test]
    fn an_unsigned_entry_takes_zero_and_the_largest_value_of_its_type() {
        assert_eq!(read("p {\n n 0\n}\n", get_u8_entry).unwrap(), Some(0));
        assert_eq!(
            read("p {\n n 255\n}\n", get_u8_entry).unwrap(),
            Some(u8::MAX)
        );
        assert_eq!(
            read("p {\n n 65535\n}\n", get_u16_entry).unwrap(),
            Some(u16::MAX)
        );
        assert_eq!(
            read("p {\n n 4294967295\n}\n", get_u32_entry).unwrap(),
            Some(u32::MAX)
        );
        assert_eq!(
            read("p {\n n 18446744073709551615\n}\n", get_u64_entry).unwrap(),
            Some(u64::MAX)
        );
        assert_eq!(
            read("p {\n n 18446744073709551615\n}\n", get_usize_entry).unwrap(),
            Some(usize::MAX)
        );
    }

    #[test]
    fn an_unsigned_entry_refuses_a_negative_value() {
        let source = "p {\n n -1\n}\n";
        let ranges = [
            (
                get_u8_entry(&parse(source).nodes()[0], "n").map(|_| ()),
                u8::MAX as i128,
            ),
            (
                get_u16_entry(&parse(source).nodes()[0], "n").map(|_| ()),
                u16::MAX as i128,
            ),
            (
                get_u32_entry(&parse(source).nodes()[0], "n").map(|_| ()),
                u32::MAX as i128,
            ),
            (
                get_u64_entry(&parse(source).nodes()[0], "n").map(|_| ()),
                u64::MAX as i128,
            ),
            (
                get_usize_entry(&parse(source).nodes()[0], "n").map(|_| ()),
                usize::MAX as i128,
            ),
        ];
        for (result, max) in ranges {
            let error = out_of_range_of(result.unwrap_err());
            assert_eq!(error.name, "n");
            assert_eq!((error.value, error.min, error.max), (-1, 0, max));
        }
    }

    #[test]
    fn an_unsigned_entry_refuses_one_more_than_the_largest_value_of_its_type() {
        let error = out_of_range_of(read("p {\n n 256\n}\n", get_u8_entry).unwrap_err());
        assert_eq!((error.value, error.min, error.max), (256, 0, 255));
        let error = out_of_range_of(read("p {\n n 65536\n}\n", get_u16_entry).unwrap_err());
        assert_eq!((error.value, error.min, error.max), (65536, 0, 65535));
        let error = out_of_range_of(read("p {\n n 4294967296\n}\n", get_u32_entry).unwrap_err());
        assert_eq!(
            (error.value, error.min, error.max),
            (4_294_967_296, 0, 4_294_967_295)
        );
        let error =
            out_of_range_of(read("p {\n n 18446744073709551616\n}\n", get_u64_entry).unwrap_err());
        assert_eq!(
            (error.value, error.min, error.max),
            (18_446_744_073_709_551_616, 0, 18_446_744_073_709_551_615)
        );
    }

    #[test]
    fn an_unsigned_entry_refuses_an_integer_wider_than_64_bits() {
        // 2^100 and 2^64 + 5 keep only their low bits under `as`: 0 and 5.
        for source in [
            "p {\n n 1267650600228229401496703205376\n}\n",
            "p {\n n 18446744073709551621\n}\n",
        ] {
            let error = out_of_range_of(read(source, get_u64_entry).unwrap_err());
            assert_eq!(error.name, "n");
            assert!(error.value > i128::from(u64::MAX));
        }
    }

    #[test]
    fn a_signed_entry_takes_the_whole_range_of_its_type() {
        let i32_entry = |source: &str| get_int_entry_as::<i32>(&parse(source).nodes()[0], "n");
        assert_eq!(
            i32_entry("p {\n n -2147483648\n}\n").unwrap(),
            Some(i32::MIN)
        );
        assert_eq!(
            i32_entry("p {\n n 2147483647\n}\n").unwrap(),
            Some(i32::MAX)
        );
        let error = out_of_range_of(i32_entry("p {\n n -2147483649\n}\n").unwrap_err());
        assert_eq!((error.min, error.max), (-2_147_483_648, 2_147_483_647));
        assert!(i32_entry("p {\n n 2147483648\n}\n").is_err());
    }

    #[test]
    fn an_entry_that_is_absent_or_null_reads_as_none_whatever_the_type() {
        assert_eq!(read("p {\n m 1\n}\n", get_u16_entry).unwrap(), None);
        assert_eq!(read("p {\n n #null\n}\n", get_u16_entry).unwrap(), None);
        assert_eq!(read("p {\n n #null\n}\n", get_status_entry).unwrap(), None);
    }

    #[test]
    fn an_unsigned_entry_still_refuses_a_value_of_another_type() {
        let wrong = wrong_type_of(read("p {\n n \"5\"\n}\n", get_u32_entry).unwrap_err());
        assert_eq!(wrong.expected, EXPECT_INTEGER);
        assert_eq!(wrong.found, Some("a string"));
        let wrong = wrong_type_of(read("p {\n n 1.5\n}\n", get_u32_entry).unwrap_err());
        assert_eq!(wrong.found, Some("a number"));
    }

    #[test]
    fn a_status_entry_takes_100_to_599() {
        for (value, ok) in [
            (-1, false),
            (0, false),
            (99, false),
            (100, true),
            (404, true),
            (599, true),
            (600, false),
            (1000, false),
            (65535, false),
            (65536, false),
            (70000, false),
        ] {
            let result = read(&format!("p {{\n n {value}\n}}\n"), get_status_entry);
            if ok {
                assert_eq!(result.unwrap(), Some(u16::try_from(value).unwrap()));
            } else {
                let error = out_of_range_of(result.unwrap_err());
                assert_eq!(
                    (error.value, error.min, error.max),
                    (value, 100, 599),
                    "{value}"
                );
            }
        }
    }

    #[test]
    fn status_args_refuses_the_first_code_outside_100_to_599() {
        let doc = parse("codes 200 404 599\n");
        assert_eq!(status_args(&doc.nodes()[0]).unwrap(), vec![200, 404, 599]);
        let doc = parse("codes 200 1000 70000\n");
        let error = out_of_range_of(status_args(&doc.nodes()[0]).unwrap_err());
        assert_eq!((error.name.as_str(), error.value), ("codes", 1000));
        let doc = parse("codes 200 \"404\"\n");
        assert!(status_args(&doc.nodes()[0]).is_err());
    }

    #[test]
    fn a_range_narrower_than_the_type_is_the_one_reported() {
        let doc = parse("n 5\n");
        let node = &doc.nodes()[0];
        assert_eq!(int_setting_in::<u8>(node, "n", 5, 1, 10).unwrap(), 5);
        let error = out_of_range_of(int_setting_in::<u8>(node, "n", 11, 1, 10).unwrap_err());
        assert_eq!((error.min, error.max), (1, 10));
    }

    #[test]
    fn a_range_wider_than_the_type_is_cut_to_the_type() {
        let doc = parse("n 5\n");
        let node = &doc.nodes()[0];
        let error = out_of_range_of(int_setting_in::<u8>(node, "n", 300, -5, 1000).unwrap_err());
        assert_eq!((error.min, error.max), (0, 255));
    }

    #[test]
    fn a_property_is_read_as_the_type_it_is_stored_in() {
        let doc = parse("target weight=2\ntarget weight=-1\ntarget weight=4294967296\ntarget\n");
        let nodes = doc.nodes();
        assert_eq!(
            property_int_as::<u32>(&nodes[0], "weight").unwrap(),
            Some(2)
        );
        let error = out_of_range_of(property_int_as::<u32>(&nodes[1], "weight").unwrap_err());
        assert_eq!((error.name.as_str(), error.value), ("weight", -1));
        assert!(property_int_as::<u32>(&nodes[2], "weight").is_err());
        assert_eq!(property_int_as::<u32>(&nodes[3], "weight").unwrap(), None);
    }

    #[test]
    fn a_node_value_is_read_as_the_type_it_is_stored_in() {
        let doc = parse("n 7\nn -7\n");
        assert_eq!(node_int_as::<u64>(&doc.nodes()[0]).unwrap(), Some(7));
        assert!(node_int_as::<u64>(&doc.nodes()[1]).is_err());
        assert_eq!(node_int_as::<i32>(&doc.nodes()[1]).unwrap(), Some(-7));
    }

    #[test]
    fn the_alias_of_a_setting_is_range_checked_too() {
        let doc = parse("n {\n  idle-timeout -5\n}\n");
        let error =
            get_int_entry_or_as::<u64>(&doc.nodes()[0], "idle-timeout-secs", "idle-timeout")
                .unwrap_err();
        let error = out_of_range_of(error);
        assert_eq!((error.name.as_str(), error.value), ("idle-timeout", -5));
    }

    #[test]
    fn the_out_of_range_error_names_the_setting_the_value_and_the_range() {
        let doc = parse(
            "routes {\n  route \"api\" {\n    cache {\n      default-ttl-secs -1\n    }\n  }\n}\n",
        );
        let cache = get_unique_child(&doc.nodes()[0], "route")
            .unwrap()
            .and_then(|r| get_unique_child(r, "cache").unwrap())
            .expect("cache block");
        let error = get_u64_entry(cache, "default-ttl-secs").unwrap_err();
        assert_eq!(
            error.to_string(),
            "Value out of range for 'default-ttl-secs': -1 is not between 0 and 18446744073709551615."
        );
        let located = out_of_range_of(locate_error(error, &doc));
        assert_eq!(
            located.location.as_deref(),
            Some("in routes > route \"api\" > cache")
        );
        assert_eq!(
            located.to_string(),
            "Value out of range for 'default-ttl-secs' in routes > route \"api\" > cache: \
             -1 is not between 0 and 18446744073709551615."
        );
    }

    #[test]
    fn an_out_of_range_error_without_a_position_is_reported_without_one() {
        let range = IntegerOutOfRange {
            name: "port".to_string(),
            value: 70000,
            min: 0,
            max: 65535,
            offset: None,
            location: None,
        };
        let doc = parse("a 1\n");
        let error = locate_error(range.clone().into(), &doc);
        assert_eq!(error.to_string(), range.to_string());
        assert_eq!(
            error.to_string(),
            "Value out of range for 'port': 70000 is not between 0 and 65535."
        );
    }

    #[test]
    fn an_upstream_target_weight_that_does_not_fit_u32_is_an_error() {
        let doc = parse("upstream \"u\" {\n  target \"a.example:80\" weight=4294967296\n}\n");
        assert!(parse_upstream_targets(&doc.nodes()[0]).is_err());
        let doc = parse("upstream \"u\" {\n  target \"a.example:80\" weight=-1\n}\n");
        assert!(parse_upstream_targets(&doc.nodes()[0]).is_err());
        let doc = parse("upstream \"u\" {\n  target \"a.example:80\" weight=4294967295\n}\n");
        assert_eq!(
            parse_upstream_targets(&doc.nodes()[0]).unwrap()[0].weight,
            u32::MAX
        );
    }
}
