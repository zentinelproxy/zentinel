//! Sentinel Lua Agent - Scriptable request/response filtering with Luau
//!
//! This agent provides a powerful Lua scripting interface for custom request/response
//! processing with support for streaming, chunked transfers, and hot reload.

use anyhow::{anyhow, Context, Result};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::{Stream, StreamExt};
use mlua::prelude::*;
use moka::future::Cache;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use sentinel_agent_protocol::{
    AgentRequest, AgentResponse, BodyChunk, Decision, Header as ProtoHeader, Mutation,
};
use sentinel_common::config::ByteSize;

mod config;
mod sandbox;
mod script;
mod stdlib;

use crate::config::{LuaAgentConfig, ScriptConfig};
use crate::sandbox::{LuaSandbox, ResourceLimits};
use crate::script::{LuaScript, ProcessingMode, ScriptContext};
use crate::stdlib::LuaStdLib;

/// Maximum number of Lua VMs in the pool
const MAX_VM_POOL_SIZE: usize = 100;

/// Maximum script execution time
const DEFAULT_SCRIPT_TIMEOUT: Duration = Duration::from_millis(50);

/// Lua agent service
pub struct LuaAgent {
    config: Arc<LuaAgentConfig>,
    scripts: Arc<ArcSwap<ScriptRegistry>>,
    vm_pool: Arc<LuaVmPool>,
    script_cache: Arc<Cache<String, Arc<CompiledScript>>>,
    metrics: Arc<Metrics>,
    watcher: Option<RecommendedWatcher>,
    reload_tx: mpsc::Sender<PathBuf>,
}

impl LuaAgent {
    /// Create a new Lua agent
    pub async fn new(config: LuaAgentConfig) -> Result<Self> {
        info!("Initializing Lua agent with config: {:?}", config);

        // Create VM pool
        let vm_pool = Arc::new(LuaVmPool::new(
            config.vm_pool_size.min(MAX_VM_POOL_SIZE),
            config.resource_limits.clone(),
        )?);

        // Create script cache
        let script_cache = Arc::new(
            Cache::builder()
                .max_capacity(config.script_cache_size)
                .time_to_live(Duration::from_secs(config.script_cache_ttl))
                .build(),
        );

        // Load initial scripts
        let scripts = Arc::new(ArcSwap::new(Arc::new(
            ScriptRegistry::load_from_directory(&config.script_directory).await?,
        )));

        // Set up hot reload if enabled
        let (reload_tx, mut reload_rx) = mpsc::channel(100);
        let watcher = if config.hot_reload {
            let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        for path in event.paths {
                            if path.extension().map_or(false, |ext| ext == "lua") {
                                let _ = reload_tx.blocking_send(path);
                            }
                        }
                    }
                }
            })?;
            watcher.watch(&config.script_directory, RecursiveMode::Recursive)?;
            Some(watcher)
        } else {
            None
        };

        let agent = Self {
            config: Arc::new(config),
            scripts: scripts.clone(),
            vm_pool,
            script_cache,
            metrics: Arc::new(Metrics::default()),
            watcher,
            reload_tx,
        };

        // Spawn reload handler
        let scripts_clone = scripts.clone();
        let config_clone = agent.config.clone();
        tokio::spawn(async move {
            while let Some(path) = reload_rx.recv().await {
                info!("Reloading scripts due to change in: {:?}", path);
                match ScriptRegistry::load_from_directory(&config_clone.script_directory).await {
                    Ok(registry) => {
                        scripts_clone.store(Arc::new(registry));
                        info!("Scripts reloaded successfully");
                    }
                    Err(e) => error!("Failed to reload scripts: {}", e),
                }
            }
        });

        Ok(agent)
    }

    /// Process a request through Lua scripts
    pub async fn process_request(&self, request: AgentRequest) -> Result<AgentResponse> {
        let start = Instant::now();
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

        // Get applicable scripts for this request
        let scripts = self.get_applicable_scripts(&request);
        if scripts.is_empty() {
            return Ok(AgentResponse {
                decision: Decision::Allow,
                mutations: vec![],
                metadata: HashMap::new(),
            });
        }

        // Acquire a VM from the pool
        let vm = self.vm_pool.acquire().await?;

        // Create script context
        let mut context = ScriptContext::from_request(request);

        // Process each script in order
        for script in scripts {
            let result = timeout(
                self.config.script_timeout,
                self.execute_script(&vm, &script, &mut context),
            )
            .await;

            match result {
                Ok(Ok(decision)) => {
                    if decision != Decision::Allow {
                        self.metrics.requests_blocked.fetch_add(1, Ordering::Relaxed);
                        return Ok(self.create_response(decision, context));
                    }
                }
                Ok(Err(e)) => {
                    error!("Script execution error: {}", e);
                    self.metrics.script_errors.fetch_add(1, Ordering::Relaxed);
                    if self.config.fail_open {
                        warn!("Failing open due to script error");
                    } else {
                        return Ok(self.create_error_response(e));
                    }
                }
                Err(_) => {
                    error!("Script execution timeout");
                    self.metrics.script_timeouts.fetch_add(1, Ordering::Relaxed);
                    if self.config.fail_open {
                        warn!("Failing open due to timeout");
                    } else {
                        return Ok(self.create_timeout_response());
                    }
                }
            }
        }

        // Record metrics
        let duration = start.elapsed();
        self.metrics
            .processing_time_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);

        Ok(self.create_response(Decision::Allow, context))
    }

    /// Execute a single script
    async fn execute_script(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<Decision> {
        // Check if script needs buffering
        let needs_buffering = match &script.processing_mode {
            ProcessingMode::Streaming => false,
            ProcessingMode::Buffered { max_size } => {
                if let Some(body) = &context.request_body {
                    body.is_chunked() || body.size() > *max_size
                } else {
                    false
                }
            }
            ProcessingMode::Auto => {
                // Auto-detect based on script capabilities
                script.capabilities.requires_full_body
            }
        };

        // Set up the Lua environment
        vm.lua.scope(|scope| {
            // Create request table
            let request_table = vm.lua.create_table()?;
            request_table.set("method", context.request.method.clone())?;
            request_table.set("path", context.request.path.clone())?;
            request_table.set("headers", self.headers_to_lua(&vm.lua, &context.request.headers)?)?;

            // Create response table if processing response
            let response_table = if let Some(response) = &context.response {
                let table = vm.lua.create_table()?;
                table.set("status", response.status)?;
                table.set("headers", self.headers_to_lua(&vm.lua, &response.headers)?)?;
                Some(table)
            } else {
                None
            };

            // Set up globals
            vm.lua.globals().set("request", request_table)?;
            if let Some(resp_table) = response_table {
                vm.lua.globals().set("response", resp_table)?;
            }

            // Execute appropriate hook functions
            match &script.hook_type {
                HookType::RequestHeaders => {
                    self.execute_request_headers_hook(&vm, script, context)?;
                }
                HookType::RequestBody => {
                    if needs_buffering {
                        self.execute_buffered_request_body_hook(&vm, script, context).await?;
                    } else {
                        self.execute_streaming_request_body_hook(&vm, script, context).await?;
                    }
                }
                HookType::ResponseHeaders => {
                    self.execute_response_headers_hook(&vm, script, context)?;
                }
                HookType::ResponseBody => {
                    if needs_buffering {
                        self.execute_buffered_response_body_hook(&vm, script, context).await?;
                    } else {
                        self.execute_streaming_response_body_hook(&vm, script, context).await?;
                    }
                }
                HookType::Complete => {
                    self.execute_complete_hook(&vm, script, context)?;
                }
            }

            // Extract decision from Lua
            let decision: String = vm.lua.globals().get("_decision").unwrap_or("allow".to_string());
            Ok(self.parse_decision(&decision))
        })
    }

    /// Execute request headers hook
    fn execute_request_headers_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_request_headers")?;

        // Call the hook function
        let result: LuaValue = func.call(())?;

        // Process mutations
        if let LuaValue::Table(mutations) = result {
            for pair in mutations.pairs::<String, LuaValue>() {
                let (key, value) = pair?;
                match key.as_str() {
                    "add_header" => {
                        if let LuaValue::Table(header) = value {
                            let name: String = header.get("name")?;
                            let value: String = header.get("value")?;
                            context.add_request_header(name, value);
                        }
                    }
                    "remove_header" => {
                        if let LuaValue::String(name) = value {
                            context.remove_request_header(&name.to_str()?);
                        }
                    }
                    "set_path" => {
                        if let LuaValue::String(path) = value {
                            context.request.path = path.to_str()?.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Execute streaming request body hook
    async fn execute_streaming_request_body_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_request_body_chunk")?;

        if let Some(body) = &mut context.request_body {
            // Process each chunk
            while let Some(chunk) = body.next_chunk().await? {
                let lua_chunk = vm.lua.create_string(&chunk)?;
                let result: LuaValue = func.call(lua_chunk)?;

                // Handle chunk transformation
                if let LuaValue::String(transformed) = result {
                    body.replace_current_chunk(transformed.as_bytes());
                } else if let LuaValue::Nil = result {
                    // Drop this chunk
                    body.drop_current_chunk();
                }
            }
        }

        Ok(())
    }

    /// Execute buffered request body hook
    async fn execute_buffered_request_body_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_request_body")?;

        if let Some(body) = &mut context.request_body {
            // Buffer the entire body
            let full_body = body.buffer_all().await?;
            let lua_body = vm.lua.create_string(&full_body)?;

            let result: LuaValue = func.call(lua_body)?;

            // Handle body transformation
            if let LuaValue::String(transformed) = result {
                body.replace_all(transformed.as_bytes());
            }
        }

        Ok(())
    }

    /// Execute response headers hook
    fn execute_response_headers_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_response_headers")?;

        let result: LuaValue = func.call(())?;

        if let LuaValue::Table(mutations) = result {
            for pair in mutations.pairs::<String, LuaValue>() {
                let (key, value) = pair?;
                match key.as_str() {
                    "add_header" => {
                        if let LuaValue::Table(header) = value {
                            let name: String = header.get("name")?;
                            let value: String = header.get("value")?;
                            context.add_response_header(name, value);
                        }
                    }
                    "remove_header" => {
                        if let LuaValue::String(name) = value {
                            context.remove_response_header(&name.to_str()?);
                        }
                    }
                    "set_status" => {
                        if let LuaValue::Integer(status) = value {
                            if let Some(response) = &mut context.response {
                                response.status = status as u16;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Execute streaming response body hook
    async fn execute_streaming_response_body_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_response_body_chunk")?;

        if let Some(body) = &mut context.response_body {
            while let Some(chunk) = body.next_chunk().await? {
                let lua_chunk = vm.lua.create_string(&chunk)?;
                let result: LuaValue = func.call(lua_chunk)?;

                if let LuaValue::String(transformed) = result {
                    body.replace_current_chunk(transformed.as_bytes());
                } else if let LuaValue::Nil = result {
                    body.drop_current_chunk();
                }
            }
        }

        Ok(())
    }

    /// Execute buffered response body hook
    async fn execute_buffered_response_body_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_response_body")?;

        if let Some(body) = &mut context.response_body {
            let full_body = body.buffer_all().await?;
            let lua_body = vm.lua.create_string(&full_body)?;

            let result: LuaValue = func.call(lua_body)?;

            if let LuaValue::String(transformed) = result {
                body.replace_all(transformed.as_bytes());
            }
        }

        Ok(())
    }

    /// Execute complete hook (has access to everything)
    fn execute_complete_hook(
        &self,
        vm: &LuaVm,
        script: &LuaScript,
        context: &mut ScriptContext,
    ) -> Result<()> {
        let func: LuaFunction = vm.lua.globals().get("on_complete")?;
        let result: LuaValue = func.call(())?;

        // Process comprehensive mutations
        if let LuaValue::Table(mutations) = result {
            self.process_complete_mutations(mutations, context)?;
        }

        Ok(())
    }

    /// Convert headers to Lua table
    fn headers_to_lua(&self, lua: &Lua, headers: &HashMap<String, String>) -> Result<LuaTable> {
        let table = lua.create_table()?;
        for (key, value) in headers {
            table.set(key.clone(), value.clone())?;
        }
        Ok(table)
    }

    /// Get applicable scripts for a request
    fn get_applicable_scripts(&self, request: &AgentRequest) -> Vec<Arc<LuaScript>> {
        self.scripts
            .load()
            .get_matching_scripts(&request.path, &request.method)
    }

    /// Parse decision string from Lua
    fn parse_decision(&self, decision: &str) -> Decision {
        match decision.to_lowercase().as_str() {
            "allow" => Decision::Allow,
            "deny" | "block" => Decision::Deny,
            "challenge" => Decision::Challenge,
            _ => Decision::Allow,
        }
    }

    /// Create response from context
    fn create_response(&self, decision: Decision, context: ScriptContext) -> AgentResponse {
        let mutations = context
            .mutations
            .into_iter()
            .map(|m| match m {
                ContextMutation::AddHeader { name, value } => {
                    Mutation::AddHeader(ProtoHeader { name, value })
                }
                ContextMutation::RemoveHeader { name } => Mutation::RemoveHeader(name),
                ContextMutation::SetPath { path } => Mutation::SetPath(path),
                ContextMutation::SetBody { body } => Mutation::SetBody(body),
            })
            .collect();

        AgentResponse {
            decision,
            mutations,
            metadata: context.metadata,
        }
    }

    /// Create error response
    fn create_error_response(&self, error: anyhow::Error) -> AgentResponse {
        AgentResponse {
            decision: Decision::Deny,
            mutations: vec![],
            metadata: HashMap::from([
                ("error".to_string(), error.to_string()),
                ("type".to_string(), "script_error".to_string()),
            ]),
        }
    }

    /// Create timeout response
    fn create_timeout_response(&self) -> AgentResponse {
        AgentResponse {
            decision: Decision::Deny,
            mutations: vec![],
            metadata: HashMap::from([
                ("error".to_string(), "Script execution timeout".to_string()),
                ("type".to_string(), "timeout".to_string()),
            ]),
        }
    }

    /// Process mutations from complete hook
    fn process_complete_mutations(
        &self,
        mutations: LuaTable,
        context: &mut ScriptContext,
    ) -> Result<()> {
        for pair in mutations.pairs::<String, LuaValue>() {
            let (key, value) = pair?;
            match key.as_str() {
                "request_headers" => {
                    if let LuaValue::Table(headers) = value {
                        context.request.headers.clear();
                        for header_pair in headers.pairs::<String, String>() {
                            let (name, value) = header_pair?;
                            context.request.headers.insert(name, value);
                        }
                    }
                }
                "response_headers" => {
                    if let LuaValue::Table(headers) = value {
                        if let Some(response) = &mut context.response {
                            response.headers.clear();
                            for header_pair in headers.pairs::<String, String>() {
                                let (name, value) = header_pair?;
                                response.headers.insert(name, value);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Lua VM wrapper
struct LuaVm {
    lua: Lua,
    created_at: Instant,
    execution_count: AtomicUsize,
}

impl LuaVm {
    fn new(limits: &ResourceLimits) -> Result<Self> {
        let lua = unsafe { Lua::unsafe_new() };

        // Apply sandboxing
        LuaSandbox::apply(&lua, limits)?;

        // Load standard library
        LuaStdLib::load(&lua)?;

        Ok(Self {
            lua,
            created_at: Instant::now(),
            execution_count: AtomicUsize::new(0),
        })
    }

    fn increment_execution(&self) {
        self.execution_count.fetch_add(1, Ordering::Relaxed);
    }

    fn should_recreate(&self, max_executions: usize, max_age: Duration) -> bool {
        self.execution_count.load(Ordering::Relaxed) > max_executions
            || self.created_at.elapsed() > max_age
    }
}

/// Lua VM pool for performance
struct LuaVmPool {
    vms: Arc<Vec<Arc<RwLock<LuaVm>>>>,
    semaphore: Arc<Semaphore>,
    limits: ResourceLimits,
}

impl LuaVmPool {
    fn new(size: usize, limits: ResourceLimits) -> Result<Self> {
        let mut vms = Vec::with_capacity(size);
        for _ in 0..size {
            vms.push(Arc::new(RwLock::new(LuaVm::new(&limits)?)));
        }

        Ok(Self {
            vms: Arc::new(vms),
            semaphore: Arc::new(Semaphore::new(size)),
            limits,
        })
    }

    async fn acquire(&self) -> Result<LuaVmGuard> {
        let permit = self.semaphore.acquire().await?;

        // Find an available VM
        for vm_lock in self.vms.iter() {
            if let Ok(vm) = vm_lock.try_write() {
                // Check if VM needs recreation
                if vm.should_recreate(1000, Duration::from_secs(300)) {
                    *vm = LuaVm::new(&self.limits)?;
                }
                vm.increment_execution();

                return Ok(LuaVmGuard {
                    vm: vm_lock.clone(),
                    _permit: permit,
                });
            }
        }

        Err(anyhow!("No available VMs in pool"))
    }
}

/// Guard for VM lease
struct LuaVmGuard {
    vm: Arc<RwLock<LuaVm>>,
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl std::ops::Deref for LuaVmGuard {
    type Target = LuaVm;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.vm.data_ptr() }
    }
}

/// Script registry
#[derive(Debug, Clone)]
struct ScriptRegistry {
    scripts: Vec<Arc<LuaScript>>,
    by_path: HashMap<String, Vec<Arc<LuaScript>>>,
}

impl ScriptRegistry {
    async fn load_from_directory(dir: &Path) -> Result<Self> {
        let mut scripts = Vec::new();
        let mut by_path = HashMap::new();

        // Walk directory for .lua files
        for entry in walkdir::WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                if let Some(ext) = entry.path().extension() {
                    if ext == "lua" {
                        match LuaScript::load_from_file(entry.path()).await {
                            Ok(script) => {
                                let script = Arc::new(script);
                                scripts.push(script.clone());

                                // Index by path pattern
                                for pattern in &script.path_patterns {
                                    by_path
                                        .entry(pattern.clone())
                                        .or_insert_with(Vec::new)
                                        .push(script.clone());
                                }
                            }
                            Err(e) => {
                                warn!("Failed to load script {:?}: {}", entry.path(), e);
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} Lua scripts", scripts.len());

        Ok(Self { scripts, by_path })
    }

    fn get_matching_scripts(&self, path: &str, method: &str) -> Vec<Arc<LuaScript>> {
        let mut matching = Vec::new();

        for script in &self.scripts {
            if script.matches(path, method) {
                matching.push(script.clone());
            }
        }

        // Sort by priority
        matching.sort_by_key(|s| s.priority);
        matching
    }
}

/// Compiled script cache entry
struct CompiledScript {
    bytecode: Vec<u8>,
    metadata: ScriptMetadata,
    compiled_at: Instant,
}

/// Script metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScriptMetadata {
    name: String,
    version: String,
    author: Option<String>,
    description: Option<String>,
    hook_type: HookType,
    processing_mode: ProcessingMode,
    path_patterns: Vec<String>,
    method_patterns: Vec<String>,
    priority: i32,
}

/// Hook type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum HookType {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Complete,
}

/// Context mutation
#[derive(Debug, Clone)]
enum ContextMutation {
    AddHeader { name: String, value: String },
    RemoveHeader { name: String },
    SetPath { path: String },
    SetBody { body: Bytes },
}

/// Metrics
#[derive(Debug, Default)]
struct Metrics {
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    script_errors: AtomicU64,
    script_timeouts: AtomicU64,
    processing_time_ms: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    vm_recreations: AtomicU64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,lua_agent=debug")
        .json()
        .init();

    info!("Starting Sentinel Lua Agent");

    // Load configuration
    let config = LuaAgentConfig::from_file("config/lua-agent.kdl")
        .await
        .context("Failed to load configuration")?;

    // Create agent
    let agent = Arc::new(LuaAgent::new(config.clone()).await?);

    // Start Unix socket server
    let listener = UnixListener::bind(&config.socket_path)?;
    info!("Lua agent listening on {:?}", config.socket_path);

    while let Ok((stream, _)) = listener.accept().await {
        let agent = agent.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, agent).await {
                error!("Connection error: {}", e);
            }
        });
    }

    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    agent: Arc<LuaAgent>,
) -> Result<()> {
    let mut buf = vec![0; 65536];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        // Deserialize request
        let request: AgentRequest = rmp_serde::from_slice(&buf[..n])?;

        // Process through Lua
        let response = agent.process_request(request).await?;

        // Serialize and send response
        let response_bytes = rmp_serde::to_vec(&response)?;
        stream.write_all(&response_bytes).await?;
    }

    Ok(())
}
