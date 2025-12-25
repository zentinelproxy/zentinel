//! Lua script loading and management
//!
//! This module handles loading Lua scripts from disk, parsing their metadata,
//! and managing their execution context.

use anyhow::{anyhow, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::Stream;
use mlua::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use sentinel_agent_protocol::{AgentRequest, BodyChunk};

/// Lua script with metadata
#[derive(Debug, Clone)]
pub struct LuaScript {
    /// Script name
    pub name: String,
    /// Script source code
    pub source: String,
    /// Compiled bytecode (cached)
    pub bytecode: Option<Vec<u8>>,
    /// Script metadata
    pub metadata: ScriptMetadata,
    /// Hook type
    pub hook_type: HookType,
    /// Processing mode
    pub processing_mode: ProcessingMode,
    /// Path patterns this script applies to
    pub path_patterns: Vec<String>,
    /// Compiled regex patterns
    pub path_regexes: Vec<Regex>,
    /// HTTP method patterns
    pub method_patterns: Vec<String>,
    /// Script priority (lower executes first)
    pub priority: i32,
    /// Script capabilities
    pub capabilities: ScriptCapabilities,
}

impl LuaScript {
    /// Load script from file
    pub async fn load_from_file(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read script file: {:?}", path))?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        // Parse metadata from script header
        let metadata = Self::parse_metadata(&source)?;

        // Parse hook type from metadata or filename
        let hook_type = metadata
            .hook
            .as_ref()
            .and_then(|h| HookType::from_str(h))
            .unwrap_or_else(|| Self::infer_hook_type(&name));

        // Parse processing mode
        let processing_mode = metadata
            .processing
            .as_ref()
            .map(|p| ProcessingMode::from_str(p))
            .unwrap_or(ProcessingMode::Auto);

        // Compile path patterns to regex
        let path_regexes = metadata
            .paths
            .iter()
            .filter_map(|p| {
                match Self::compile_path_pattern(p) {
                    Ok(regex) => Some(regex),
                    Err(e) => {
                        warn!("Invalid path pattern '{}': {}", p, e);
                        None
                    }
                }
            })
            .collect();

        // Determine capabilities
        let capabilities = Self::analyze_capabilities(&source);

        Ok(Self {
            name,
            source,
            bytecode: None,
            metadata: metadata.clone(),
            hook_type,
            processing_mode,
            path_patterns: metadata.paths.clone(),
            path_regexes,
            method_patterns: metadata.methods.clone(),
            priority: metadata.priority.unwrap_or(100),
            capabilities,
        })
    }

    /// Parse metadata from Lua script comments
    fn parse_metadata(source: &str) -> Result<ScriptMetadata> {
        let mut metadata = ScriptMetadata::default();

        // Look for metadata in initial comments
        for line in source.lines().take(50) {
            let line = line.trim();
            if !line.starts_with("--") {
                break;
            }

            let comment = line.trim_start_matches('-').trim();
            if let Some((key, value)) = comment.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "name" => metadata.name = Some(value.to_string()),
                    "version" => metadata.version = Some(value.to_string()),
                    "author" => metadata.author = Some(value.to_string()),
                    "description" => metadata.description = Some(value.to_string()),
                    "hook" => metadata.hook = Some(value.to_string()),
                    "processing" => metadata.processing = Some(value.to_string()),
                    "path" | "paths" => {
                        metadata.paths = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                    }
                    "method" | "methods" => {
                        metadata.methods = value
                            .split(',')
                            .map(|s| s.trim().to_uppercase())
                            .collect();
                    }
                    "priority" => {
                        metadata.priority = value.parse().ok();
                    }
                    "requires" => {
                        metadata.requires = value
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                    }
                    _ => {}
                }
            }
        }

        // Set defaults if not specified
        if metadata.paths.is_empty() {
            metadata.paths.push("*".to_string());
        }
        if metadata.methods.is_empty() {
            metadata.methods.push("*".to_string());
        }

        Ok(metadata)
    }

    /// Infer hook type from filename
    fn infer_hook_type(name: &str) -> HookType {
        if name.contains("request_header") {
            HookType::RequestHeaders
        } else if name.contains("request_body") {
            HookType::RequestBody
        } else if name.contains("response_header") {
            HookType::ResponseHeaders
        } else if name.contains("response_body") {
            HookType::ResponseBody
        } else {
            HookType::Complete
        }
    }

    /// Compile path pattern to regex
    fn compile_path_pattern(pattern: &str) -> Result<Regex> {
        let regex_pattern = pattern
            .replace("**", ".+")
            .replace("*", "[^/]+")
            .replace("/", "\\/");

        Regex::new(&format!("^{}$", regex_pattern))
            .with_context(|| format!("Invalid path pattern: {}", pattern))
    }

    /// Analyze script capabilities
    fn analyze_capabilities(source: &str) -> ScriptCapabilities {
        ScriptCapabilities {
            requires_full_body: source.contains("on_request_body")
                || source.contains("on_response_body"),
            supports_streaming: source.contains("on_request_body_chunk")
                || source.contains("on_response_body_chunk"),
            modifies_headers: source.contains("add_header")
                || source.contains("remove_header")
                || source.contains("set_header"),
            modifies_body: source.contains("transform_body")
                || source.contains("replace_body"),
            requires_json: source.contains("json.decode")
                || source.contains("json.encode"),
            requires_crypto: source.contains("crypto.")
                || source.contains("hmac.")
                || source.contains("sha"),
        }
    }

    /// Check if script matches request
    pub fn matches(&self, path: &str, method: &str) -> bool {
        // Check method
        let method_matches = self.method_patterns.contains(&"*".to_string())
            || self.method_patterns.contains(&method.to_uppercase());

        if !method_matches {
            return false;
        }

        // Check path
        if self.path_patterns.contains(&"*".to_string()) {
            return true;
        }

        self.path_regexes.iter().any(|regex| regex.is_match(path))
    }

    /// Compile script to bytecode
    pub fn compile(&mut self, lua: &Lua) -> Result<()> {
        let chunk = lua.load(&self.source);
        let bytecode = chunk.into_function()?.dump();
        self.bytecode = Some(bytecode);
        Ok(())
    }
}

/// Script metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScriptMetadata {
    pub name: Option<String>,
    pub version: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub hook: Option<String>,
    pub processing: Option<String>,
    pub paths: Vec<String>,
    pub methods: Vec<String>,
    pub priority: Option<i32>,
    pub requires: Vec<String>,
}

/// Hook type - when the script runs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookType {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Complete,
}

impl HookType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "request_headers" | "req_headers" => Some(Self::RequestHeaders),
            "request_body" | "req_body" => Some(Self::RequestBody),
            "response_headers" | "resp_headers" => Some(Self::ResponseHeaders),
            "response_body" | "resp_body" => Some(Self::ResponseBody),
            "complete" | "all" => Some(Self::Complete),
            _ => None,
        }
    }
}

/// Processing mode - how the script processes data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessingMode {
    /// Process data as a stream (chunk by chunk)
    Streaming,
    /// Buffer all data before processing
    Buffered { max_size: usize },
    /// Automatically decide based on content
    Auto,
}

impl ProcessingMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "streaming" | "stream" => Self::Streaming,
            "buffered" | "buffer" => Self::Buffered {
                max_size: 10 * 1024 * 1024, // 10MB default
            },
            _ => Self::Auto,
        }
    }
}

/// Script capabilities detected from analysis
#[derive(Debug, Clone, Default)]
pub struct ScriptCapabilities {
    pub requires_full_body: bool,
    pub supports_streaming: bool,
    pub modifies_headers: bool,
    pub modifies_body: bool,
    pub requires_json: bool,
    pub requires_crypto: bool,
}

/// Script execution context
#[derive(Debug, Clone)]
pub struct ScriptContext {
    pub request: AgentRequest,
    pub request_body: Option<BodyStream>,
    pub response: Option<ResponseData>,
    pub response_body: Option<BodyStream>,
    pub mutations: Vec<ContextMutation>,
    pub metadata: HashMap<String, String>,
    pub start_time: Instant,
}

impl ScriptContext {
    pub fn from_request(request: AgentRequest) -> Self {
        Self {
            request,
            request_body: None,
            response: None,
            response_body: None,
            mutations: Vec::new(),
            metadata: HashMap::new(),
            start_time: Instant::now(),
        }
    }

    pub fn add_request_header(&mut self, name: String, value: String) {
        self.mutations.push(ContextMutation::AddHeader {
            target: HeaderTarget::Request,
            name,
            value,
        });
    }

    pub fn remove_request_header(&mut self, name: &str) {
        self.mutations.push(ContextMutation::RemoveHeader {
            target: HeaderTarget::Request,
            name: name.to_string(),
        });
    }

    pub fn add_response_header(&mut self, name: String, value: String) {
        self.mutations.push(ContextMutation::AddHeader {
            target: HeaderTarget::Response,
            name,
            value,
        });
    }

    pub fn remove_response_header(&mut self, name: &str) {
        self.mutations.push(ContextMutation::RemoveHeader {
            target: HeaderTarget::Response,
            name: name.to_string(),
        });
    }
}

/// Response data
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub status: u16,
    pub headers: HashMap<String, String>,
}

/// Body stream for chunked processing
pub struct BodyStream {
    chunks: Arc<RwLock<Vec<Bytes>>>,
    current_index: usize,
    is_complete: bool,
    is_chunked: bool,
    total_size: Option<usize>,
}

impl BodyStream {
    pub fn new(is_chunked: bool) -> Self {
        Self {
            chunks: Arc::new(RwLock::new(Vec::new())),
            current_index: 0,
            is_complete: false,
            is_chunked,
            total_size: None,
        }
    }

    pub fn is_chunked(&self) -> bool {
        self.is_chunked
    }

    pub fn size(&self) -> Option<usize> {
        self.total_size
    }

    pub async fn add_chunk(&self, chunk: Bytes) {
        self.chunks.write().await.push(chunk);
    }

    pub async fn next_chunk(&mut self) -> Result<Option<Bytes>> {
        let chunks = self.chunks.read().await;
        if self.current_index < chunks.len() {
            let chunk = chunks[self.current_index].clone();
            self.current_index += 1;
            Ok(Some(chunk))
        } else if self.is_complete {
            Ok(None)
        } else {
            // Wait for more chunks
            Ok(None)
        }
    }

    pub fn replace_current_chunk(&mut self, data: &[u8]) {
        if self.current_index > 0 {
            let index = self.current_index - 1;
            if let Ok(mut chunks) = self.chunks.try_write() {
                if index < chunks.len() {
                    chunks[index] = Bytes::from(data.to_vec());
                }
            }
        }
    }

    pub fn drop_current_chunk(&mut self) {
        if self.current_index > 0 {
            let index = self.current_index - 1;
            if let Ok(mut chunks) = self.chunks.try_write() {
                if index < chunks.len() {
                    chunks.remove(index);
                    self.current_index -= 1;
                }
            }
        }
    }

    pub async fn buffer_all(&mut self) -> Result<Bytes> {
        let chunks = self.chunks.read().await;
        let mut buffer = BytesMut::new();
        for chunk in chunks.iter() {
            buffer.extend_from_slice(chunk);
        }
        Ok(buffer.freeze())
    }

    pub fn replace_all(&mut self, data: &[u8]) {
        if let Ok(mut chunks) = self.chunks.try_write() {
            chunks.clear();
            chunks.push(Bytes::from(data.to_vec()));
        }
        self.current_index = 0;
    }

    pub fn mark_complete(&mut self) {
        self.is_complete = true;
    }
}

/// Context mutation
#[derive(Debug, Clone)]
pub enum ContextMutation {
    AddHeader {
        target: HeaderTarget,
        name: String,
        value: String,
    },
    RemoveHeader {
        target: HeaderTarget,
        name: String,
    },
    SetPath {
        path: String,
    },
    SetBody {
        target: BodyTarget,
        body: Bytes,
    },
}

/// Header target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderTarget {
    Request,
    Response,
}

/// Body target
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyTarget {
    Request,
    Response,
}
