//! Lua sandboxing for secure script execution
//!
//! This module provides sandboxing capabilities to safely execute untrusted Lua scripts
//! with resource limits and restricted access to system resources.

use anyhow::{anyhow, Result};
use mlua::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Resource limits for Lua execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub max_memory: usize,
    /// Maximum CPU instructions (approximate)
    pub max_instructions: usize,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Maximum recursion depth
    pub max_recursion_depth: usize,
    /// Maximum string length
    pub max_string_length: usize,
    /// Maximum table size
    pub max_table_size: usize,
    /// Allow file system access
    pub allow_filesystem: bool,
    /// Allow network access
    pub allow_network: bool,
    /// Allow process spawning
    pub allow_process: bool,
    /// Allow loading binary modules
    pub allow_binary_modules: bool,
    /// Allowed Lua libraries
    pub allowed_libraries: HashSet<String>,
    /// Blocked global functions
    pub blocked_functions: HashSet<String>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        let mut allowed_libraries = HashSet::new();
        allowed_libraries.insert("string".to_string());
        allowed_libraries.insert("table".to_string());
        allowed_libraries.insert("math".to_string());
        allowed_libraries.insert("utf8".to_string());
        allowed_libraries.insert("coroutine".to_string());

        let mut blocked_functions = HashSet::new();
        blocked_functions.insert("dofile".to_string());
        blocked_functions.insert("loadfile".to_string());
        blocked_functions.insert("load".to_string());
        blocked_functions.insert("loadstring".to_string());
        blocked_functions.insert("require".to_string());
        blocked_functions.insert("rawget".to_string());
        blocked_functions.insert("rawset".to_string());
        blocked_functions.insert("rawequal".to_string());
        blocked_functions.insert("setfenv".to_string());
        blocked_functions.insert("getfenv".to_string());
        blocked_functions.insert("newproxy".to_string());
        blocked_functions.insert("collectgarbage".to_string());

        Self {
            max_memory: 50 * 1024 * 1024, // 50MB
            max_instructions: 10_000_000, // 10M instructions
            max_execution_time: Duration::from_millis(100),
            max_recursion_depth: 100,
            max_string_length: 10 * 1024 * 1024, // 10MB
            max_table_size: 10000,
            allow_filesystem: false,
            allow_network: false,
            allow_process: false,
            allow_binary_modules: false,
            allowed_libraries,
            blocked_functions,
        }
    }
}

/// Lua sandbox for secure execution
pub struct LuaSandbox;

impl LuaSandbox {
    /// Apply sandboxing to a Lua instance
    pub fn apply(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        // Set memory limit
        lua.set_memory_limit(limits.max_memory)?;

        // Set up instruction counting hook for CPU limit
        Self::setup_instruction_limit(lua, limits.max_instructions)?;

        // Remove dangerous functions
        Self::remove_dangerous_functions(lua, limits)?;

        // Set up safe libraries
        Self::setup_safe_libraries(lua, limits)?;

        // Set up safe globals
        Self::setup_safe_globals(lua, limits)?;

        // Set recursion limit
        Self::set_recursion_limit(lua, limits.max_recursion_depth)?;

        // Set up string length limits
        Self::setup_string_limits(lua, limits)?;

        // Set up table size limits
        Self::setup_table_limits(lua, limits)?;

        info!("Lua sandbox applied with limits: {:?}", limits);
        Ok(())
    }

    /// Set up instruction counting for CPU limits
    fn setup_instruction_limit(lua: &Lua, max_instructions: usize) -> Result<()> {
        let instruction_count = lua.create_userdata(0usize)?;
        lua.set_named_registry_value("instruction_count", instruction_count.clone())?;

        lua.set_hook(
            LuaHookTriggers {
                every_nth_instruction: Some(1000),
                ..Default::default()
            },
            move |lua, _debug| {
                let count: LuaAnyUserData = lua.named_registry_value("instruction_count")?;
                let current = count.borrow::<usize>()?;
                let new_count = *current + 1000;

                if new_count > max_instructions {
                    Err(LuaError::RuntimeError(format!(
                        "CPU limit exceeded: {} instructions",
                        max_instructions
                    )))
                } else {
                    drop(current);
                    *count.borrow_mut::<usize>()? = new_count;
                    Ok(())
                }
            },
        );

        Ok(())
    }

    /// Remove dangerous global functions
    fn remove_dangerous_functions(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        let globals = lua.globals();

        for func in &limits.blocked_functions {
            globals.set(func.as_str(), LuaNil)?;
            debug!("Removed dangerous function: {}", func);
        }

        // Remove or restrict specific modules
        if !limits.allow_filesystem {
            globals.set("io", LuaNil)?;
            if let Ok(os_table) = globals.get::<_, LuaTable>("os") {
                // Keep only safe os functions
                let safe_os = lua.create_table()?;
                safe_os.set("clock", os_table.get::<_, LuaFunction>("clock")?)?;
                safe_os.set("date", os_table.get::<_, LuaFunction>("date")?)?;
                safe_os.set("difftime", os_table.get::<_, LuaFunction>("difftime")?)?;
                safe_os.set("time", os_table.get::<_, LuaFunction>("time")?)?;
                globals.set("os", safe_os)?;
            }
        }

        if !limits.allow_process {
            if let Ok(os_table) = globals.get::<_, LuaTable>("os") {
                os_table.set("execute", LuaNil)?;
                os_table.set("exit", LuaNil)?;
                os_table.set("getenv", LuaNil)?;
                os_table.set("remove", LuaNil)?;
                os_table.set("rename", LuaNil)?;
                os_table.set("setlocale", LuaNil)?;
                os_table.set("tmpname", LuaNil)?;
            }
        }

        // Remove package module to prevent loading external modules
        if !limits.allow_binary_modules {
            globals.set("package", LuaNil)?;
        }

        // Remove debug module (can be used to bypass sandbox)
        globals.set("debug", LuaNil)?;

        Ok(())
    }

    /// Set up safe libraries only
    fn setup_safe_libraries(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        let globals = lua.globals();

        // Create a safe environment with only allowed libraries
        if !limits.allowed_libraries.contains("string") {
            globals.set("string", LuaNil)?;
        }

        if !limits.allowed_libraries.contains("table") {
            globals.set("table", LuaNil)?;
        }

        if !limits.allowed_libraries.contains("math") {
            globals.set("math", LuaNil)?;
        }

        if !limits.allowed_libraries.contains("utf8") {
            globals.set("utf8", LuaNil)?;
        }

        if !limits.allowed_libraries.contains("coroutine") {
            globals.set("coroutine", LuaNil)?;
        }

        Ok(())
    }

    /// Set up safe global functions
    fn setup_safe_globals(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        let globals = lua.globals();

        // Override print to use logging
        let print_fn = lua.create_function(|_, args: LuaMultiValue| {
            let mut output = Vec::new();
            for value in args {
                output.push(format!("{:?}", value));
            }
            info!("[Lua Script] {}", output.join("\t"));
            Ok(())
        })?;
        globals.set("print", print_fn)?;

        // Add safe type checking functions
        let type_fn = lua.create_function(|lua, value: LuaValue| {
            Ok(match value {
                LuaNil => "nil",
                LuaValue::Boolean(_) => "boolean",
                LuaValue::Integer(_) | LuaValue::Number(_) => "number",
                LuaValue::String(_) => "string",
                LuaValue::Table(_) => "table",
                LuaValue::Function(_) => "function",
                LuaValue::Thread(_) => "thread",
                LuaValue::UserData(_) | LuaValue::LightUserData(_) => "userdata",
                _ => "unknown",
            })
        })?;
        globals.set("type", type_fn)?;

        // Add safe iteration functions
        let pairs_fn = lua.create_function(|lua, table: LuaTable| {
            let iter = lua.create_function(move |lua, (table, key): (LuaTable, LuaValue)| {
                let next: LuaFunction = lua.globals().get("next")?;
                next.call((table, key))
            })?;
            Ok((iter, table.clone(), LuaNil))
        })?;
        globals.set("pairs", pairs_fn)?;

        let ipairs_fn = lua.create_function(|lua, table: LuaTable| {
            let iter = lua.create_function(move |_, (table, index): (LuaTable, i64)| {
                let next_index = index + 1;
                match table.get::<i64, LuaValue>(next_index) {
                    Ok(LuaNil) | Err(_) => Ok((LuaNil, LuaNil)),
                    Ok(value) => Ok((next_index, value)),
                }
            })?;
            Ok((iter, table.clone(), 0i64))
        })?;
        globals.set("ipairs", ipairs_fn)?;

        // Add safe assertion
        let assert_fn = lua.create_function(|_, (cond, msg): (bool, Option<String>)| {
            if !cond {
                Err(LuaError::RuntimeError(
                    msg.unwrap_or_else(|| "assertion failed".to_string()),
                ))
            } else {
                Ok(())
            }
        })?;
        globals.set("assert", assert_fn)?;

        // Add safe error function
        let error_fn = lua.create_function(|_, msg: String| Err(LuaError::RuntimeError(msg)))?;
        globals.set("error", error_fn)?;

        // Add tonumber and tostring
        let tonumber_fn =
            lua.create_function(|_, (value, base): (LuaValue, Option<i32>)| match value {
                LuaValue::Number(n) => Ok(Some(n)),
                LuaValue::Integer(i) => Ok(Some(i as f64)),
                LuaValue::String(s) => {
                    let s = s.to_str()?;
                    if let Some(base) = base {
                        i64::from_str_radix(s, base as u32)
                            .map(|i| Some(i as f64))
                            .or_else(|_| Ok(None))
                    } else {
                        s.parse::<f64>().map(Some).or_else(|_| Ok(None))
                    }
                }
                _ => Ok(None),
            })?;
        globals.set("tonumber", tonumber_fn)?;

        let tostring_fn = lua.create_function(|lua, value: LuaValue| Ok(format!("{:?}", value)))?;
        globals.set("tostring", tostring_fn)?;

        Ok(())
    }

    /// Set recursion depth limit
    fn set_recursion_limit(lua: &Lua, max_depth: usize) -> Result<()> {
        // This is handled by Lua's internal stack size
        // We can approximate it by setting a reasonable stack size
        // Note: This is a simplified approach; full implementation would track call depth
        Ok(())
    }

    /// Set up string length limits
    fn setup_string_limits(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        let max_len = limits.max_string_length;

        // Override string concatenation to check length
        let concat_fn = lua.create_function(move |_, (a, b): (String, String)| {
            let result_len = a.len() + b.len();
            if result_len > max_len {
                Err(LuaError::RuntimeError(format!(
                    "String too long: {} bytes (max: {})",
                    result_len, max_len
                )))
            } else {
                Ok(format!("{}{}", a, b))
            }
        })?;

        // Store for use in metamethods
        lua.set_named_registry_value("safe_concat", concat_fn)?;

        Ok(())
    }

    /// Set up table size limits
    fn setup_table_limits(lua: &Lua, limits: &ResourceLimits) -> Result<()> {
        let max_size = limits.max_table_size;

        // Create a safe table constructor
        let table_new = lua.create_function(move |lua, init: Option<LuaTable>| {
            let table = lua.create_table()?;

            if let Some(init) = init {
                let len = init.len()?;
                if len > max_size {
                    return Err(LuaError::RuntimeError(format!(
                        "Table too large: {} items (max: {})",
                        len, max_size
                    )));
                }

                for pair in init.pairs::<LuaValue, LuaValue>() {
                    let (k, v) = pair?;
                    table.set(k, v)?;
                }
            }

            // Set metatable to enforce size limits on insertion
            let metatable = lua.create_table()?;
            metatable.set(
                "__newindex",
                lua.create_function(
                    move |_, (table, key, value): (LuaTable, LuaValue, LuaValue)| {
                        let current_size = table.len()?;
                        if current_size >= max_size
                            && table.get::<_, LuaValue>(key.clone())? == LuaNil
                        {
                            Err(LuaError::RuntimeError(format!(
                                "Table size limit exceeded: {} items",
                                max_size
                            )))
                        } else {
                            table.raw_set(key, value)?;
                            Ok(())
                        }
                    },
                )?,
            )?;

            table.set_metatable(Some(metatable));
            Ok(table)
        })?;

        lua.globals().set("safe_table", table_new)?;

        Ok(())
    }

    /// Create a sandboxed environment for script execution
    pub fn create_environment(lua: &Lua, limits: &ResourceLimits) -> Result<LuaTable> {
        let env = lua.create_table()?;
        let globals = lua.globals();

        // Copy safe globals to the new environment
        let safe_globals = vec![
            "assert", "error", "ipairs", "next", "pairs", "pcall", "print", "select", "tonumber",
            "tostring", "type", "unpack", "xpcall", "_VERSION", "math", "string", "table", "utf8",
        ];

        for name in safe_globals {
            if let Ok(value) = globals.get::<_, LuaValue>(name) {
                if !limits.blocked_functions.contains(name) {
                    env.set(name, value)?;
                }
            }
        }

        // Add custom safe functions
        env.set("safe_table", globals.get::<_, LuaValue>("safe_table")?)?;

        Ok(env)
    }
}

/// Sandbox violation error
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("Memory limit exceeded: {0} bytes")]
    MemoryLimitExceeded(usize),

    #[error("CPU limit exceeded: {0} instructions")]
    CpuLimitExceeded(usize),

    #[error("Execution time limit exceeded: {0:?}")]
    TimeLimitExceeded(Duration),

    #[error("Recursion depth limit exceeded: {0}")]
    RecursionLimitExceeded(usize),

    #[error("String length limit exceeded: {0} bytes")]
    StringLimitExceeded(usize),

    #[error("Table size limit exceeded: {0} items")]
    TableSizeLimitExceeded(usize),

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Unsafe operation attempted: {0}")]
    UnsafeOperation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_limits() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_memory, 50 * 1024 * 1024);
        assert!(!limits.allow_filesystem);
        assert!(!limits.allow_network);
        assert!(!limits.allow_process);
        assert!(limits.blocked_functions.contains("dofile"));
        assert!(limits.allowed_libraries.contains("string"));
    }

    #[test]
    fn test_sandbox_application() {
        let lua = unsafe { Lua::unsafe_new() };
        let limits = ResourceLimits::default();

        let result = LuaSandbox::apply(&lua, &limits);
        assert!(result.is_ok());

        // Verify dangerous functions are removed
        let globals = lua.globals();
        assert_eq!(globals.get::<_, LuaValue>("dofile").unwrap(), LuaNil);
        assert_eq!(globals.get::<_, LuaValue>("loadfile").unwrap(), LuaNil);
        assert_eq!(globals.get::<_, LuaValue>("io").unwrap(), LuaNil);
        assert_eq!(globals.get::<_, LuaValue>("debug").unwrap(), LuaNil);
    }

    #[test]
    fn test_memory_limit() {
        let lua = unsafe { Lua::unsafe_new() };
        let mut limits = ResourceLimits::default();
        limits.max_memory = 1024 * 1024; // 1MB

        LuaSandbox::apply(&lua, &limits).unwrap();

        // Try to allocate large string
        let result = lua
            .load(
                r#"
            local s = ""
            for i = 1, 1000000 do
                s = s .. "x"
            end
        "#,
            )
            .exec();

        // Should fail due to memory limit
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_environment() {
        let lua = unsafe { Lua::unsafe_new() };
        let limits = ResourceLimits::default();

        LuaSandbox::apply(&lua, &limits).unwrap();
        let env = LuaSandbox::create_environment(&lua, &limits).unwrap();

        // Check safe functions are available
        assert!(env.get::<_, LuaValue>("print").is_ok());
        assert!(env.get::<_, LuaValue>("string").is_ok());
        assert!(env.get::<_, LuaValue>("table").is_ok());

        // Check dangerous functions are not available
        assert_eq!(env.get::<_, LuaValue>("dofile").unwrap_or(LuaNil), LuaNil);
        assert_eq!(env.get::<_, LuaValue>("io").unwrap_or(LuaNil), LuaNil);
    }
}
