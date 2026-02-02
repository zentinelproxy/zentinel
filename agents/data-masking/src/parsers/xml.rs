//! XML parser with simple XPath-like field access.

use crate::errors::MaskingError;
use crate::parsers::{BodyParser, FieldAccessor};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use std::any::Any;
use std::collections::HashMap;
use std::io::Cursor;

/// XML body parser.
pub struct XmlParser;

impl BodyParser for XmlParser {
    fn parse(&self, body: &[u8]) -> Result<Box<dyn FieldAccessor>, MaskingError> {
        let doc = parse_xml(body)?;
        Ok(Box::new(XmlAccessor { doc }))
    }

    fn serialize(&self, accessor: &dyn FieldAccessor) -> Result<Vec<u8>, MaskingError> {
        let xml_accessor = accessor
            .as_any()
            .downcast_ref::<XmlAccessor>()
            .ok_or_else(|| MaskingError::Serialization("type mismatch".to_string()))?;
        serialize_xml(&xml_accessor.doc)
    }
}

/// Simple XML document representation.
#[derive(Debug, Clone)]
pub struct XmlDocument {
    root: Option<XmlElement>,
}

/// XML element with children and text content.
#[derive(Debug, Clone)]
pub struct XmlElement {
    name: String,
    attributes: HashMap<String, String>,
    children: Vec<XmlNode>,
}

/// XML node (element or text).
#[derive(Debug, Clone)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

/// XML field accessor.
pub struct XmlAccessor {
    doc: XmlDocument,
}

impl FieldAccessor for XmlAccessor {
    fn get(&self, path: &str) -> Option<String> {
        let segments = parse_xpath(path);
        self.doc.root.as_ref().and_then(|root| get_element_text(root, &segments))
    }

    fn set(&mut self, path: &str, value: String) -> Result<(), MaskingError> {
        let segments = parse_xpath(path);
        if let Some(ref mut root) = self.doc.root {
            set_element_text(root, &segments, value)
        } else {
            Err(MaskingError::FieldAccess("no root element".to_string()))
        }
    }

    fn find_paths(&self, pattern: &str) -> Vec<String> {
        let mut results = Vec::new();
        if let Some(ref root) = self.doc.root {
            find_matching_paths(root, pattern, &format!("/{}", root.name), &mut results);
        }
        results
    }

    fn all_values(&self) -> Vec<(String, String)> {
        let mut results = Vec::new();
        if let Some(ref root) = self.doc.root {
            collect_all_text(root, &format!("/{}", root.name), &mut results);
        }
        results
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Parse XML bytes into document.
fn parse_xml(data: &[u8]) -> Result<XmlDocument, MaskingError> {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);

    let root = parse_element(&mut reader)?;
    Ok(XmlDocument { root })
}

/// Parse a single XML element recursively.
fn parse_element<R: std::io::BufRead>(reader: &mut Reader<R>) -> Result<Option<XmlElement>, MaskingError> {
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| {
                        (
                            String::from_utf8_lossy(a.key.as_ref()).to_string(),
                            String::from_utf8_lossy(&a.value).to_string(),
                        )
                    })
                    .collect();

                let children = parse_children(reader, &name)?;

                return Ok(Some(XmlElement {
                    name,
                    attributes,
                    children,
                }));
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| {
                        (
                            String::from_utf8_lossy(a.key.as_ref()).to_string(),
                            String::from_utf8_lossy(&a.value).to_string(),
                        )
                    })
                    .collect();

                return Ok(Some(XmlElement {
                    name,
                    attributes,
                    children: Vec::new(),
                }));
            }
            Ok(Event::Eof) => return Ok(None),
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) => {
                // Skip declarations, comments, processing instructions
            }
            Err(e) => return Err(MaskingError::InvalidXml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }
}

/// Parse children of an element until its end tag.
fn parse_children<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    parent_name: &str,
) -> Result<Vec<XmlNode>, MaskingError> {
    let mut children = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| {
                        (
                            String::from_utf8_lossy(a.key.as_ref()).to_string(),
                            String::from_utf8_lossy(&a.value).to_string(),
                        )
                    })
                    .collect();

                let inner_children = parse_children(reader, &name)?;
                children.push(XmlNode::Element(XmlElement {
                    name,
                    attributes,
                    children: inner_children,
                }));
            }
            Ok(Event::Empty(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let attributes = e
                    .attributes()
                    .filter_map(|a| a.ok())
                    .map(|a| {
                        (
                            String::from_utf8_lossy(a.key.as_ref()).to_string(),
                            String::from_utf8_lossy(&a.value).to_string(),
                        )
                    })
                    .collect();

                children.push(XmlNode::Element(XmlElement {
                    name,
                    attributes,
                    children: Vec::new(),
                }));
            }
            Ok(Event::Text(e)) => {
                let text = e.decode().map_err(|e| MaskingError::InvalidXml(e.to_string()))?;
                if !text.trim().is_empty() {
                    children.push(XmlNode::Text(text.to_string()));
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == parent_name {
                    return Ok(children);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(MaskingError::InvalidXml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }

    Ok(children)
}

/// Serialize XML document back to bytes.
fn serialize_xml(doc: &XmlDocument) -> Result<Vec<u8>, MaskingError> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    if let Some(ref root) = doc.root {
        write_element(&mut writer, root)?;
    }

    Ok(writer.into_inner().into_inner())
}

/// Write an element and its children.
fn write_element<W: std::io::Write>(
    writer: &mut Writer<W>,
    element: &XmlElement,
) -> Result<(), MaskingError> {
    let mut start = BytesStart::new(&element.name);
    for (key, value) in &element.attributes {
        start.push_attribute((key.as_str(), value.as_str()));
    }

    if element.children.is_empty() {
        writer
            .write_event(Event::Empty(start))
            .map_err(|e| MaskingError::Serialization(e.to_string()))?;
    } else {
        writer
            .write_event(Event::Start(start))
            .map_err(|e| MaskingError::Serialization(e.to_string()))?;

        for child in &element.children {
            match child {
                XmlNode::Element(e) => write_element(writer, e)?,
                XmlNode::Text(t) => {
                    writer
                        .write_event(Event::Text(BytesText::new(t)))
                        .map_err(|e| MaskingError::Serialization(e.to_string()))?;
                }
            }
        }

        writer
            .write_event(Event::End(BytesEnd::new(&element.name)))
            .map_err(|e| MaskingError::Serialization(e.to_string()))?;
    }

    Ok(())
}

/// Parse simple XPath into segments.
fn parse_xpath(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Get text content at path.
fn get_element_text(element: &XmlElement, segments: &[String]) -> Option<String> {
    if segments.is_empty() {
        // Get text content of this element
        for child in &element.children {
            if let XmlNode::Text(t) = child {
                return Some(t.clone());
            }
        }
        return None;
    }

    if segments[0] != element.name {
        return None;
    }

    if segments.len() == 1 {
        // This is the target element
        for child in &element.children {
            if let XmlNode::Text(t) = child {
                return Some(t.clone());
            }
        }
        return None;
    }

    // Look for matching child
    for child in &element.children {
        if let XmlNode::Element(e) = child {
            if e.name == segments[1] {
                return get_element_text(e, &segments[1..]);
            }
        }
    }

    None
}

/// Set text content at path.
fn set_element_text(element: &mut XmlElement, segments: &[String], value: String) -> Result<(), MaskingError> {
    if segments.is_empty() {
        return Err(MaskingError::FieldAccess("empty path".to_string()));
    }

    if segments[0] != element.name {
        return Err(MaskingError::FieldAccess(format!(
            "path mismatch: expected {}, got {}",
            segments[0], element.name
        )));
    }

    if segments.len() == 1 {
        // Set text content of this element
        element.children.retain(|c| !matches!(c, XmlNode::Text(_)));
        element.children.push(XmlNode::Text(value));
        return Ok(());
    }

    // Look for matching child
    for child in &mut element.children {
        if let XmlNode::Element(e) = child {
            if e.name == segments[1] {
                return set_element_text(e, &segments[1..], value);
            }
        }
    }

    Err(MaskingError::FieldAccess(format!(
        "element not found: {}",
        segments[1]
    )))
}

/// Find all paths matching the pattern.
fn find_matching_paths(element: &XmlElement, pattern: &str, current_path: &str, results: &mut Vec<String>) {
    if element.name == pattern || pattern == "*" {
        results.push(current_path.to_string());
    }

    for child in &element.children {
        if let XmlNode::Element(e) = child {
            let child_path = format!("{}/{}", current_path, e.name);
            find_matching_paths(e, pattern, &child_path, results);
        }
    }
}

/// Collect all text content with paths.
fn collect_all_text(element: &XmlElement, path: &str, results: &mut Vec<(String, String)>) {
    for child in &element.children {
        match child {
            XmlNode::Text(t) => {
                results.push((path.to_string(), t.clone()));
            }
            XmlNode::Element(e) => {
                let child_path = format!("{}/{}", path, e.name);
                collect_all_text(e, &child_path, results);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_parse_and_get() {
        let parser = XmlParser;
        let xml = b"<user><name>John</name><ssn>123-45-6789</ssn></user>";

        let accessor = parser.parse(xml).unwrap();
        assert_eq!(accessor.get("/user/name"), Some("John".to_string()));
        assert_eq!(accessor.get("/user/ssn"), Some("123-45-6789".to_string()));
    }

    #[test]
    fn test_xml_set() {
        let parser = XmlParser;
        let xml = b"<user><ssn>123-45-6789</ssn></user>";

        let mut accessor = parser.parse(xml).unwrap();
        accessor.set("/user/ssn", "MASKED".to_string()).unwrap();

        assert_eq!(accessor.get("/user/ssn"), Some("MASKED".to_string()));
    }

    #[test]
    fn test_xml_serialize() {
        let parser = XmlParser;
        let xml = b"<root><value>test</value></root>";

        let accessor = parser.parse(xml).unwrap();
        let serialized = parser.serialize(accessor.as_ref()).unwrap();
        let result = String::from_utf8(serialized).unwrap();

        assert!(result.contains("test"));
    }
}
