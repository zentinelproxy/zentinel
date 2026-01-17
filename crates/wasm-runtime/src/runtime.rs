//! WASM agent runtime management.

use crate::config::WasmAgentConfig;
use crate::error::WasmRuntimeError;
use crate::host::{create_component_engine, WasmAgentBuilder, WasmAgentInfo, WasmAgentInstance};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};
use wasmtime::component::Component;
use wasmtime::Engine;

/// The WASM agent runtime.
///
/// Manages the Wasmtime engine, compiled components, and agent instances.
pub struct WasmAgentRuntime {
    /// Wasmtime engine
    engine: Engine,
    /// Runtime configuration
    config: WasmAgentConfig,
    /// Compiled components cache (module_id -> Component)
    components: RwLock<HashMap<String, Component>>,
    /// Active agent instances (agent_id -> Instance)
    agents: RwLock<HashMap<String, Arc<WasmAgentInstance>>>,
    /// Shutdown flag
    shutdown: std::sync::atomic::AtomicBool,
}

impl WasmAgentRuntime {
    /// Create a new WASM runtime with the given configuration.
    pub fn new(config: WasmAgentConfig) -> Result<Self, WasmRuntimeError> {
        let engine = create_component_engine(config.fuel_enabled)?;

        info!(
            fuel_enabled = config.fuel_enabled,
            epoch_enabled = config.epoch_enabled,
            max_memory = config.limits.max_memory,
            "WASM runtime initialized"
        );

        Ok(Self {
            engine,
            config,
            components: RwLock::new(HashMap::new()),
            agents: RwLock::new(HashMap::new()),
            shutdown: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Get the Wasmtime engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get runtime configuration.
    pub fn config(&self) -> &WasmAgentConfig {
        &self.config
    }

    /// Compile a WASM component from bytes.
    ///
    /// The bytes should be a valid WebAssembly Component Model binary.
    #[instrument(skip(self, wasm_bytes))]
    pub fn compile_component(
        &self,
        component_id: &str,
        wasm_bytes: &[u8],
    ) -> Result<(), WasmRuntimeError> {
        debug!(
            component_id = component_id,
            size = wasm_bytes.len(),
            "compiling WASM component"
        );

        // Validate module size
        if wasm_bytes.len() > self.config.limits.max_function_size * 10 {
            return Err(WasmRuntimeError::InvalidModule(format!(
                "component too large: {} bytes",
                wasm_bytes.len()
            )));
        }

        // Compile component
        let component = Component::new(&self.engine, wasm_bytes)
            .map_err(|e| WasmRuntimeError::Compilation(e.to_string()))?;

        // Cache compiled component
        self.components
            .write()
            .insert(component_id.to_string(), component);

        info!(component_id = component_id, "WASM component compiled and cached");
        Ok(())
    }

    /// Compile a WASM component from a file.
    #[instrument(skip(self, path))]
    pub fn compile_component_file(
        &self,
        component_id: &str,
        path: impl AsRef<Path>,
    ) -> Result<(), WasmRuntimeError> {
        let path = path.as_ref();
        debug!(
            component_id = component_id,
            path = %path.display(),
            "loading WASM component from file"
        );

        let wasm_bytes = std::fs::read(path)?;
        self.compile_component(component_id, &wasm_bytes)
    }

    /// Load and instantiate an agent from a compiled component.
    #[instrument(skip(self, config_json))]
    pub fn load_agent(
        &self,
        agent_id: &str,
        component_id: &str,
        config_json: &str,
    ) -> Result<Arc<WasmAgentInstance>, WasmRuntimeError> {
        if self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(WasmRuntimeError::Shutdown);
        }

        // Get compiled component
        let components = self.components.read();
        let component = components.get(component_id).ok_or_else(|| {
            WasmRuntimeError::InvalidModule(format!("component not found: {}", component_id))
        })?;

        // Check instance limit
        let agent_count = self.agents.read().len();
        if agent_count >= self.config.max_instances as usize {
            return Err(WasmRuntimeError::ResourceLimit(format!(
                "maximum agent instances reached: {}",
                self.config.max_instances
            )));
        }

        // Create agent instance
        let instance = WasmAgentBuilder::new(agent_id)
            .config(config_json)
            .limits(self.config.limits.clone())
            .build(&self.engine, component)?;

        let instance = Arc::new(instance);

        // Register agent
        self.agents
            .write()
            .insert(agent_id.to_string(), Arc::clone(&instance));

        info!(
            agent_id = agent_id,
            component_id = component_id,
            "WASM agent loaded"
        );

        Ok(instance)
    }

    /// Load an agent directly from WASM bytes (compiles and loads).
    #[instrument(skip(self, wasm_bytes, config_json))]
    pub fn load_agent_from_bytes(
        &self,
        agent_id: &str,
        wasm_bytes: &[u8],
        config_json: &str,
    ) -> Result<Arc<WasmAgentInstance>, WasmRuntimeError> {
        // Use agent_id as component_id for simplicity
        self.compile_component(agent_id, wasm_bytes)?;
        self.load_agent(agent_id, agent_id, config_json)
    }

    /// Get an agent by ID.
    pub fn get_agent(&self, agent_id: &str) -> Option<Arc<WasmAgentInstance>> {
        self.agents.read().get(agent_id).cloned()
    }

    /// List all loaded agents.
    pub fn list_agents(&self) -> Vec<WasmAgentInfo> {
        self.agents
            .read()
            .values()
            .map(|a| a.info().clone())
            .collect()
    }

    /// Unload an agent.
    #[instrument(skip(self))]
    pub fn unload_agent(&self, agent_id: &str) -> bool {
        let removed = self.agents.write().remove(agent_id);
        if let Some(agent) = removed {
            agent.shutdown();
            info!(agent_id = agent_id, "WASM agent unloaded");
            true
        } else {
            false
        }
    }

    /// Unload a compiled component.
    pub fn unload_component(&self, component_id: &str) -> bool {
        self.components.write().remove(component_id).is_some()
    }

    /// Get runtime statistics.
    pub fn stats(&self) -> WasmRuntimeStats {
        WasmRuntimeStats {
            compiled_modules: self.components.read().len(),
            active_agents: self.agents.read().len(),
            max_instances: self.config.max_instances as usize,
        }
    }

    /// Shutdown the runtime.
    pub fn shutdown(&self) {
        info!("shutting down WASM runtime");
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // Shutdown all agents
        let agents: Vec<_> = self.agents.write().drain().collect();
        for (agent_id, agent) in agents {
            debug!(agent_id = agent_id, "shutting down agent");
            agent.shutdown();
        }

        // Clear components
        self.components.write().clear();

        info!("WASM runtime shutdown complete");
    }
}

impl Drop for WasmAgentRuntime {
    fn drop(&mut self) {
        if !self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            self.shutdown();
        }
    }
}

/// Runtime statistics.
#[derive(Debug, Clone)]
pub struct WasmRuntimeStats {
    /// Number of compiled components in cache
    pub compiled_modules: usize,
    /// Number of active agent instances
    pub active_agents: usize,
    /// Maximum allowed instances
    pub max_instances: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_runtime() {
        let config = WasmAgentConfig::minimal();
        let runtime = WasmAgentRuntime::new(config).unwrap();
        assert_eq!(runtime.stats().compiled_modules, 0);
        assert_eq!(runtime.stats().active_agents, 0);
    }

    #[test]
    fn test_runtime_shutdown() {
        let config = WasmAgentConfig::minimal();
        let runtime = WasmAgentRuntime::new(config).unwrap();

        runtime.shutdown();

        assert_eq!(runtime.stats().compiled_modules, 0);
        assert_eq!(runtime.stats().active_agents, 0);
    }
}
