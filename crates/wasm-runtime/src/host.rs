//! WASM agent host bindings and instance management.
//!
//! This module provides the actual implementation of WASM agent execution using
//! the Wasmtime Component Model. Agents implementing the `zentinel:agent` world
//! can be loaded and called through this interface.

use crate::component::{
    agent_info_from_wit, agent_response_from_wit, headers_to_wit, request_metadata_to_wit, Agent,
};
use crate::config::WasmResourceLimits;
use crate::error::WasmRuntimeError;
use parking_lot::Mutex;
use zentinel_agent_protocol::{AgentResponse, RequestMetadata};
use std::collections::HashMap;
use tracing::{debug, instrument, warn};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Information about a loaded WASM agent.
#[derive(Debug, Clone)]
pub struct WasmAgentInfo {
    /// Agent identifier
    pub agent_id: String,
    /// Human-readable name
    pub name: String,
    /// Version string
    pub version: String,
    /// Supported event types
    pub supported_events: Vec<String>,
    /// Maximum body size the agent can inspect
    pub max_body_size: u64,
    /// Whether agent supports streaming
    pub supports_streaming: bool,
}

/// State stored in the Wasmtime store.
pub struct AgentState {
    /// Fuel consumed in current call
    fuel_consumed: u64,
    /// Agent configuration (JSON)
    #[allow(dead_code)]
    config: String,
    /// Whether agent is configured
    #[allow(dead_code)]
    configured: bool,
    /// WASI context for the component
    wasi_ctx: WasiCtx,
    /// Resource table for WASI
    resource_table: ResourceTable,
}

impl WasiView for AgentState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

/// A loaded WASM agent instance.
pub struct WasmAgentInstance {
    /// Agent information
    info: WasmAgentInfo,
    /// Wasmtime store with state
    store: Mutex<Store<AgentState>>,
    /// The instantiated agent component
    agent: Agent,
    /// Resource limits
    limits: WasmResourceLimits,
}

impl WasmAgentInstance {
    /// Create a new WASM agent instance from a compiled component.
    pub(crate) fn new(
        engine: &Engine,
        component: &Component,
        limits: WasmResourceLimits,
        config_json: &str,
    ) -> Result<Self, WasmRuntimeError> {
        // Build WASI context
        let wasi_ctx = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();

        // Create store with state
        let state = AgentState {
            fuel_consumed: 0,
            config: config_json.to_string(),
            configured: false,
            wasi_ctx,
            resource_table: ResourceTable::new(),
        };
        let mut store = Store::new(engine, state);

        // Configure fuel metering
        store.set_fuel(limits.max_fuel)?;

        // Create linker and add WASI
        let mut linker = Linker::new(engine);
        wasmtime_wasi::p2::add_to_linker_sync(&mut linker)
            .map_err(|e| WasmRuntimeError::Internal(format!("failed to add WASI: {}", e)))?;

        // Instantiate the component
        let agent = Agent::instantiate(&mut store, component, &linker)
            .map_err(|e| WasmRuntimeError::Instantiation(e.to_string()))?;

        // Get agent info
        let info = Self::call_get_info(&mut store, &agent)?;

        // Configure agent
        Self::call_configure(&mut store, &agent, config_json)?;
        store.data_mut().configured = true;

        Ok(Self {
            info,
            store: Mutex::new(store),
            agent,
            limits,
        })
    }

    /// Call get_info to retrieve agent information.
    fn call_get_info(
        store: &mut Store<AgentState>,
        agent: &Agent,
    ) -> Result<WasmAgentInfo, WasmRuntimeError> {
        let handler = agent.zentinel_agent_handler();
        let wit_info = handler
            .call_get_info(store)
            .map_err(|e| WasmRuntimeError::FunctionCall(format!("get_info failed: {}", e)))?;

        Ok(agent_info_from_wit(wit_info))
    }

    /// Call configure to initialize the agent.
    fn call_configure(
        store: &mut Store<AgentState>,
        agent: &Agent,
        config_json: &str,
    ) -> Result<(), WasmRuntimeError> {
        debug!(config_len = config_json.len(), "configuring WASM agent");

        let handler = agent.zentinel_agent_handler();
        handler
            .call_configure(store, config_json)
            .map_err(|e| WasmRuntimeError::FunctionCall(format!("configure failed: {}", e)))?
            .map_err(WasmRuntimeError::Configuration)?;

        Ok(())
    }

    /// Get agent information.
    pub fn info(&self) -> &WasmAgentInfo {
        &self.info
    }

    /// Get agent ID.
    pub fn agent_id(&self) -> &str {
        &self.info.agent_id
    }

    /// Process request headers.
    #[instrument(skip(self, headers), fields(agent_id = %self.info.agent_id))]
    pub fn on_request_headers(
        &self,
        metadata: &RequestMetadata,
        method: &str,
        uri: &str,
        headers: &HashMap<String, Vec<String>>,
    ) -> Result<AgentResponse, WasmRuntimeError> {
        let mut store = self.store.lock();

        // Reset fuel for this call
        store.set_fuel(self.limits.max_fuel)?;

        debug!(
            method = method,
            uri = uri,
            header_count = headers.len(),
            "processing request headers in WASM agent"
        );

        // Convert types
        let wit_metadata = request_metadata_to_wit(metadata);
        let wit_headers = headers_to_wit(headers);

        // Call the WASM function
        let handler = self.agent.zentinel_agent_handler();
        let wit_response = handler
            .call_on_request_headers(&mut *store, &wit_metadata, method, uri, &wit_headers)
            .map_err(|e| {
                WasmRuntimeError::FunctionCall(format!("on_request_headers failed: {}", e))
            })?;

        // Track fuel consumption
        let remaining = store.get_fuel().unwrap_or(0);
        let consumed = self.limits.max_fuel.saturating_sub(remaining);
        store.data_mut().fuel_consumed = consumed;

        // Convert response
        Ok(agent_response_from_wit(wit_response))
    }

    /// Process request body chunk.
    #[instrument(skip(self, data), fields(agent_id = %self.info.agent_id))]
    pub fn on_request_body(
        &self,
        correlation_id: &str,
        data: &[u8],
        chunk_index: u32,
        is_last: bool,
    ) -> Result<AgentResponse, WasmRuntimeError> {
        let mut store = self.store.lock();
        store.set_fuel(self.limits.max_fuel)?;

        debug!(
            correlation_id = correlation_id,
            chunk_index = chunk_index,
            data_len = data.len(),
            is_last = is_last,
            "processing request body in WASM agent"
        );

        // Call the WASM function
        let handler = self.agent.zentinel_agent_handler();
        let wit_response = handler
            .call_on_request_body(&mut *store, correlation_id, data, chunk_index, is_last)
            .map_err(|e| {
                WasmRuntimeError::FunctionCall(format!("on_request_body failed: {}", e))
            })?;

        // Track fuel consumption
        let remaining = store.get_fuel().unwrap_or(0);
        let consumed = self.limits.max_fuel.saturating_sub(remaining);
        store.data_mut().fuel_consumed = consumed;

        Ok(agent_response_from_wit(wit_response))
    }

    /// Process response headers.
    #[instrument(skip(self, headers), fields(agent_id = %self.info.agent_id))]
    pub fn on_response_headers(
        &self,
        correlation_id: &str,
        status: u16,
        headers: &HashMap<String, Vec<String>>,
    ) -> Result<AgentResponse, WasmRuntimeError> {
        let mut store = self.store.lock();
        store.set_fuel(self.limits.max_fuel)?;

        debug!(
            correlation_id = correlation_id,
            status = status,
            header_count = headers.len(),
            "processing response headers in WASM agent"
        );

        // Convert headers
        let wit_headers = headers_to_wit(headers);

        // Call the WASM function
        let handler = self.agent.zentinel_agent_handler();
        let wit_response = handler
            .call_on_response_headers(&mut *store, correlation_id, status, &wit_headers)
            .map_err(|e| {
                WasmRuntimeError::FunctionCall(format!("on_response_headers failed: {}", e))
            })?;

        // Track fuel consumption
        let remaining = store.get_fuel().unwrap_or(0);
        let consumed = self.limits.max_fuel.saturating_sub(remaining);
        store.data_mut().fuel_consumed = consumed;

        Ok(agent_response_from_wit(wit_response))
    }

    /// Process response body chunk.
    #[instrument(skip(self, data), fields(agent_id = %self.info.agent_id))]
    pub fn on_response_body(
        &self,
        correlation_id: &str,
        data: &[u8],
        chunk_index: u32,
        is_last: bool,
    ) -> Result<AgentResponse, WasmRuntimeError> {
        let mut store = self.store.lock();
        store.set_fuel(self.limits.max_fuel)?;

        debug!(
            correlation_id = correlation_id,
            chunk_index = chunk_index,
            data_len = data.len(),
            is_last = is_last,
            "processing response body in WASM agent"
        );

        // Call the WASM function
        let handler = self.agent.zentinel_agent_handler();
        let wit_response = handler
            .call_on_response_body(&mut *store, correlation_id, data, chunk_index, is_last)
            .map_err(|e| {
                WasmRuntimeError::FunctionCall(format!("on_response_body failed: {}", e))
            })?;

        // Track fuel consumption
        let remaining = store.get_fuel().unwrap_or(0);
        let consumed = self.limits.max_fuel.saturating_sub(remaining);
        store.data_mut().fuel_consumed = consumed;

        Ok(agent_response_from_wit(wit_response))
    }

    /// Health check.
    pub fn health_check(&self) -> Result<String, WasmRuntimeError> {
        let mut store = self.store.lock();
        store.set_fuel(self.limits.max_fuel)?;

        let lifecycle = self.agent.zentinel_agent_lifecycle();
        lifecycle
            .call_health_check(&mut *store)
            .map_err(|e| WasmRuntimeError::FunctionCall(format!("health_check failed: {}", e)))?
            .map_err(WasmRuntimeError::AgentError)
    }

    /// Graceful shutdown.
    pub fn shutdown(&self) {
        debug!(agent_id = %self.info.agent_id, "shutting down WASM agent");

        let mut store = self.store.lock();
        if let Err(e) = store.set_fuel(self.limits.max_fuel) {
            warn!(error = %e, "failed to set fuel for shutdown");
            return;
        }

        let lifecycle = self.agent.zentinel_agent_lifecycle();
        if let Err(e) = lifecycle.call_shutdown(&mut *store) {
            warn!(error = %e, "WASM agent shutdown failed");
        }
    }

    /// Get fuel consumed in last call.
    pub fn last_fuel_consumed(&self) -> u64 {
        self.store.lock().data().fuel_consumed
    }
}

/// Builder for creating WASM agent instances.
pub struct WasmAgentBuilder {
    agent_id: String,
    config_json: String,
    limits: WasmResourceLimits,
}

impl WasmAgentBuilder {
    /// Create a new builder.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            config_json: "{}".to_string(),
            limits: WasmResourceLimits::default(),
        }
    }

    /// Set agent configuration (JSON).
    pub fn config(mut self, config_json: impl Into<String>) -> Self {
        self.config_json = config_json.into();
        self
    }

    /// Set resource limits.
    pub fn limits(mut self, limits: WasmResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Build the agent instance from a Component.
    pub fn build(
        self,
        engine: &Engine,
        component: &Component,
    ) -> Result<WasmAgentInstance, WasmRuntimeError> {
        WasmAgentInstance::new(engine, component, self.limits, &self.config_json)
    }
}

/// Create a component-model-enabled Wasmtime engine.
pub fn create_component_engine(fuel_enabled: bool) -> Result<Engine, WasmRuntimeError> {
    let mut config = Config::new();
    config.wasm_component_model(true);

    if fuel_enabled {
        config.consume_fuel(true);
    }

    // Sync execution for now
    config.async_support(false);

    // Cranelift optimizations
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);

    Engine::new(&config).map_err(|e| WasmRuntimeError::EngineCreation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_info() {
        let info = WasmAgentInfo {
            agent_id: "test".to_string(),
            name: "Test Agent".to_string(),
            version: "1.0.0".to_string(),
            supported_events: vec!["request_headers".to_string()],
            max_body_size: 1024,
            supports_streaming: false,
        };

        assert_eq!(info.agent_id, "test");
        assert!(!info.supports_streaming);
    }

    #[test]
    fn test_builder() {
        let builder = WasmAgentBuilder::new("my-agent")
            .config(r#"{"key": "value"}"#)
            .limits(WasmResourceLimits::strict());

        assert_eq!(builder.agent_id, "my-agent");
    }

    #[test]
    fn test_create_component_engine() {
        // Test that we can create an engine with fuel enabled
        let engine = create_component_engine(true);
        assert!(engine.is_ok());

        // Test that we can create an engine without fuel
        let engine = create_component_engine(false);
        assert!(engine.is_ok());
    }
}
